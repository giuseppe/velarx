// SPDX-License-Identifier: Apache-2.0
//! The image volume API of the trait ([`StorageDriver::image_volume_create`],
//! [`StorageDriver::mounts`], [`Capabilities::volume`]) and a test-only
//! driver that has volumes, [`VolumeFake`]: it wraps a driver, gives the
//! containers per-container volumes (a directory in the bundle, handed over as a
//! descriptor, a new one at each call) and declares the ways of mapping ids it is
//! given, so that the engine's handling of descriptors and of the mapping is
//! tested with a driver that makes them (no driver of the product does yet), as
//! root and as a user.  The cases run on every driver, and say what a driver
//! that has no volumes, or makes them of its layers, does.

use super::*;
use crate::forward_storage_driver;

/// How a driver's image mounts map ids (none: it has no image mounts).
fn volume_ways(c: &Capabilities) -> Prefs<IdmapWay> {
    c.volume.map_or(Prefs::NONE, |v| v.idmap)
}

/// Whether the driver makes a copy of the image for each container's mount
/// when it is created (it maps the ids as it copies): such a mount is gone
/// with the container and is `Missing` when it was never made.
fn copies(c: &Capabilities) -> bool {
    volume_ways(c).contains(IdmapWay::AtCopy)
}

/// A driver with image volumes made of another driver, for tests: the root
/// file system and everything else is the wrapped driver's.
pub struct VolumeFake {
    inner: Arc<dyn StorageDriver>,
    caps: Capabilities,
    /// The root file system is a `MountFd` of the container's layer (a
    /// directory descriptor here), not what the wrapped driver says.
    root_fd: bool,
    /// The descriptors are detached mounts (`open_tree(OPEN_TREE_CLONE)` of the
    /// directories), as a monitor attaches them: [`VolumeFake::detached`].
    detached: bool,
}

/// What the fake keeps in a bundle for the volumes of its container.
const FAKE_DIR: &str = "volume-fake";

impl VolumeFake {
    /// `inner` with image volumes that it maps the ids of
    /// by `ways` (empty: it cannot, and refuses a mapping).  With `root_fd` the
    /// root file system is a descriptor too.
    pub fn new(inner: Arc<dyn StorageDriver>, ways: Prefs<IdmapWay>, root_fd: bool) -> Self {
        let caps = Capabilities {
            volume: Some(MountCaps { idmap: ways }),
            ..inner.capabilities().clone()
        };
        Self {
            inner,
            caps,
            root_fd,
            detached: false,
        }
    }

    /// The descriptors it gives are detached mounts of the directories, which
    /// a monitor can attach: for the tests that start a container from them.
    /// Needs `CAP_SYS_ADMIN` over the mount namespace (root, or a user and
    /// mount namespace of the test's own).
    pub fn detached(mut self) -> Self {
        self.detached = true;
        self
    }

    /// The directory of image volume `index` of the container `w`, once made
    /// (where a test puts what the volume shows).
    pub fn volume_dir(w: &Writable, index: u32) -> PathBuf {
        Self::dir(w, index)
    }

    fn dir(w: &Writable, index: u32) -> PathBuf {
        w.bundle().join(FAKE_DIR).join(index.to_string())
    }

    /// The descriptor handed over for the directory `fd`: itself, or a
    /// detached mount of it.
    fn hand(&self, fd: std::os::fd::OwnedFd) -> DriverResult<std::os::fd::OwnedFd> {
        if !self.detached {
            return Ok(fd);
        }
        use rustix::mount::OpenTreeFlags;
        rustix::mount::open_tree(
            &fd,
            "",
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_EMPTY_PATH,
        )
        .map_err(|e| DriverError::io(self.name(), e.into()))
    }

    fn index(&self, m: &MountRequest<'_>) -> DriverResult<u32> {
        match m.purpose {
            Purpose::Volume { index } => Ok(index),
            Purpose::Root => Err(DriverError::storage(
                self.name(),
                "an image volume is asked for a root file system",
            )),
        }
    }

    /// Who maps the ids of a volume: nobody when there is no mapping, the
    /// monitor when that is the first way the driver has and it may, else the
    /// driver (the copy), and a refusal for a driver with no way.
    fn idmap_of(&self, m: &MountRequest<'_>) -> DriverResult<IdmapDone> {
        if m.mapping.is_none() {
            return Ok(IdmapDone::None);
        }
        let way = volume_ways(&self.caps)
            .iter()
            .find(|w| *w != IdmapWay::MonitorMount || m.idmap_mount);
        match way {
            Some(IdmapWay::MonitorMount) => Ok(IdmapDone::Mount),
            Some(_) => Ok(IdmapDone::Applied),
            None => Err(DriverError::of(
                self.name(),
                DriverErrorKind::Unsupported,
                "the fake maps no ids of an image volume",
            )),
        }
    }

    fn volume(&self, w: &Writable, m: &MountRequest<'_>) -> DriverResult<Rootfs> {
        let index = self.index(m)?;
        let idmap = self.idmap_of(m)?;
        let dir = Self::dir(w, index);
        let fd = rustix::fs::open(
            &dir,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|e| match e {
            rustix::io::Errno::NOENT => DriverError::missing(
                self.name(),
                None,
                format!(
                    "the image volume {index} of the container {} was never made",
                    w.id()
                ),
                Remedy::RecreateContainer,
            ),
            e => DriverError::io(self.name(), e.into()),
        })?;
        Ok(Rootfs {
            plan: RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
                server: false,
                fd_index: 0,
                idmap: idmap == IdmapDone::Mount,
            }),
            fd: Some(self.hand(fd)?),
            idmap,
            label: LabelDone::None,
            verity: crate::VerityDone::None,
            measured: Vec::new(),
            server: None,
        })
    }

    fn root(&self, w: &Writable, m: &MountRequest<'_>) -> DriverResult<Rootfs> {
        if !self.root_fd {
            let one = MountsRequest {
                root: Some(m.clone()),
                volumes: Vec::new(),
            };
            return self
                .inner
                .mounts(&one)?
                .root
                .ok_or_else(|| DriverError::storage(self.name(), "the driver gave no root"));
        }
        Ok(Rootfs {
            plan: RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            }),
            fd: Some(self.hand(self.inner.writable_root(w)?)?),
            idmap: if m.mapping.is_some() {
                IdmapDone::Applied
            } else {
                IdmapDone::None
            },
            label: LabelDone::None,
            verity: crate::VerityDone::None,
            measured: Vec::new(),
            server: None,
        })
    }
}

forward_storage_driver! {
    impl StorageDriver for VolumeFake {
        inner: inner;
        forward: [name graph_name graph_data status pull has_layers repair remake_staged read_objects open_object objects_in_order remove_image image_view leftovers check collect writable_paths writable_root writable_size writable_exists diff changes apply stopped_view is_root_of usage lock_unused_layers];
        fn image_volume_create(&self, req: &MountRequest<'_>) -> DriverResult<Planned> {
            let index = self.index(req)?;
            // (a mapping it cannot honour is refused now, not at a start)
            let idmap = self.idmap_of(req)?;
            let dir = Self::dir(req.container, index);
            std::fs::create_dir_all(&dir).map_err(|e| DriverError::io(self.name(), e))?;
            std::fs::write(dir.join("image"), &req.image.id)
                .map_err(|e| DriverError::io(self.name(), e))?;
            Ok(Planned {
                plan: RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
                    server: false,
                    fd_index: 0,
                    idmap: idmap == IdmapDone::Mount,
                }),
                idmap,
                label: LabelDone::None,
            })
        }

        fn mounts(&self, req: &MountsRequest<'_>) -> DriverResult<Mounts> {
            Ok(Mounts {
                root: req
                    .root
                    .as_ref()
                    .map(|m| self.root(m.container, m))
                    .transpose()?,
                volumes: req
                    .volumes
                    .iter()
                    .map(|m| self.volume(m.container, m))
                    .collect::<DriverResult<_>>()?,
            })
        }

        fn writable_remove(&self, w: &Writable) -> DriverResult<()> {
            self.inner.writable_remove(w)?;
            match velarx_base::tree::remove_dir_all(w.bundle().join(FAKE_DIR)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(DriverError::io(self.name(), e))
                }
                _ => Ok(()),
            }
        }

        fn capabilities(&self) -> &Capabilities {
            &self.caps
        }
        fn writable_create(
            &self,
            w: &Writable,
            owner: Option<(u32, u32)>,
            opts: &WritableOptions,
            base: Option<&MountRequest<'_>>,
        ) -> DriverResult<Option<Planned>> {
            let planned = self.inner.writable_create(w, owner, opts, base)?;
            if !self.root_fd {
                return Ok(planned);
            }
            // (the root is a descriptor of the layer at every start: what the
            // create says is that plan, as `root` answers it)
            Ok(base.map(|m| Planned {
                plan: RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
                    server: false,
                    fd_index: 0,
                    idmap: false,
                }),
                idmap: if m.mapping.is_some() {
                    IdmapDone::Applied
                } else {
                    IdmapDone::None
                },
                label: LabelDone::None,
            }))
        }
    }
}

/// `factory`'s driver wrapped in a [`VolumeFake`]: for the drivers that have no
/// volumes, so that the suite runs on one that does.
pub fn with_volumes(factory: Factory, ways: Prefs<IdmapWay>, root_fd: bool) -> Factory {
    let factory = Arc::new(factory);
    Box::new(move |dir| {
        let made = factory(dir);
        Box::pin(async move {
            let mut s = made.await;
            s.driver = Arc::new(VolumeFake::new(s.driver, ways, root_fd));
            s
        })
    })
}

// The cases

/// A container made of an image, and what its mounts are asked with.
struct World {
    _tmp: tempfile::TempDir,
    s: Subject,
    img: ImageRecord,
    layers: Vec<LayerRecord>,
    w: Writable,
}

impl World {
    async fn new(f: &Factory, case: &str) -> Option<Self> {
        let tmp = tempfile::tempdir().unwrap();
        let s = subject(f, case, tmp.path()).await?;
        let base = store_layer(&s, base_layer()).await;
        let layers = records(&s, &[&base]).await;
        let img = image("img", &[&base]);
        let w = Writable::new("c1", s.dir.join("bundles/c1"));
        create_over(&s, &w, &img, &layers);
        Some(Self {
            _tmp: tmp,
            s,
            img,
            layers,
            w,
        })
    }

    fn ask<'a>(
        &'a self,
        purpose: Purpose,
        mapping: Option<&'a velarx_fuse::IdTranslate>,
        idmap_mount: bool,
    ) -> MountRequest<'a> {
        MountRequest {
            translate: mapping.or(Some(crate::conformance::identity_translate())),
            container: &self.w,
            purpose,
            image: &self.img,
            layers: &self.layers,
            mapping,
            idmap_mount,
            label: None,
            verity: VerityAsk::Off,
            volatile: false,
        }
    }

    fn volume<'a>(&'a self, index: u32) -> MountRequest<'a> {
        self.ask(Purpose::Volume { index }, None, false)
    }

    fn create(&self, m: MountRequest<'_>) -> DriverResult<Planned> {
        self.s.driver.image_volume_create(&m)
    }

    fn mounts(
        &self,
        root: Option<MountRequest<'_>>,
        volumes: Vec<MountRequest<'_>>,
    ) -> DriverResult<Mounts> {
        self.s.driver.mounts(&MountsRequest { root, volumes })
    }
}

fn mapping(size: u32) -> velarx_fuse::IdTranslate {
    let one = || {
        vec![velarx_proto::pod::IdMapping {
            container_id: 0,
            host_id: 100_000,
            size,
        }]
    };
    velarx_fuse::IdTranslate {
        uid: one(),
        gid: one(),
        squash: false,
    }
}

/// What every answer is, whatever the driver: a descriptor exactly for a mount,
/// a directory, closed on exec; only a root is a `Directory`.
fn check_answer(r: &Rootfs, root: bool) {
    assert_eq!(
        r.fd.is_some(),
        matches!(r.plan, RootfsPlan::MountFd(_)),
        "a descriptor exactly for a mount-fd plan: {r:?}"
    );
    if let Some(fd) = &r.fd {
        assert!(is_dir_fd(fd), "a directory");
        assert!(cloexec(fd), "O_CLOEXEC");
    }
    if !root {
        assert!(
            !matches!(r.plan, RootfsPlan::Directory(_)),
            "only a root file system is a directory: {r:?}"
        );
    }
}

pub async fn image_volumes_are_what_the_capabilities_say(f: &Factory) {
    let Some(x) = World::new(f, "image_volumes_are_what_the_capabilities_say").await else {
        return;
    };
    let d = &x.s.driver;
    let c = d.capabilities();
    let asked = x.create(x.volume(0));
    match c.volume {
        None => {
            assert!(volume_ways(c).is_empty(), "no volume, no way to map");
            let e = expect_err(asked, "a volume of a driver that has none");
            assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
            of_driver(&x.s, &e);
            // (an image mount at a start is refused the same way)
            let e = expect_err(
                x.mounts(None, vec![x.volume(0)]),
                "the mount of a volume of a driver that has none",
            );
            assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
            // the creation left nothing in the bundle
            assert!(!x.w.bundle().join(FAKE_DIR).exists());
        }
        Some(_) => {
            let planned = asked.expect("a volume of a driver that has them");
            // a request for a root is not a volume's
            let e = expect_err(
                x.create(x.ask(Purpose::Root, None, false)),
                "a volume asked as a root",
            );
            assert!(!matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
            let m = x.mounts(None, vec![x.volume(0)]).expect("its mount");
            assert!(m.root.is_none(), "no root was asked");
            assert_eq!(m.volumes.len(), 1);
            check_answer(&m.volumes[0], false);
            // what the create said the mount would be is what every start
            // gives (the engine wrote the plan and counted the descriptors
            // from it)
            assert_eq!(m.volumes[0].planned(), planned, "the plan of the create");
            let again = x.mounts(None, vec![x.volume(0)]).expect("its mount");
            assert_eq!(again.volumes[0].planned(), planned, "and of the next start");
        }
    }
}

pub async fn image_volume_create_is_idempotent(f: &Factory) {
    let Some(x) = World::new(f, "image_volume_create_is_idempotent").await else {
        return;
    };
    if x.s.driver.capabilities().volume.is_none() {
        skip!(
            "image_volume_create_is_idempotent",
            "the driver has no volumes"
        );
    }
    for _ in 0..3 {
        x.create(x.volume(0)).expect("made again without harm");
    }
    x.create(x.volume(1)).unwrap();
    let before = x.mounts(None, vec![x.volume(0), x.volume(1)]).unwrap();
    x.create(x.volume(0)).unwrap();
    let after = x.mounts(None, vec![x.volume(0), x.volume(1)]).unwrap();
    // the same two volumes, in the same kinds of plan
    for (a, b) in before.volumes.iter().zip(&after.volumes) {
        assert_eq!(a.plan, b.plan);
        assert_eq!(a.idmap, b.idmap);
    }
}

/// An image mount asked with a label says where the label is, the same at
/// create and at every start: `MountContext` or `Files` (the files carry it,
/// which is read back through the descriptor of the mount), or `None` when the
/// driver cannot (the engine then refuses the container: it cannot label the
/// files of an image mount itself).  With no label asked nothing is done.
pub async fn an_image_mount_label_is_what_the_answer_says(f: &Factory) {
    const LABEL: &str = "system_u:object_r:container_file_t:s0:c1,c2";
    let case = "an_image_mount_label_is_what_the_answer_says";
    let Some(x) = World::new(f, case).await else {
        return;
    };
    if x.s.driver.capabilities().volume.is_none() {
        skip!(case, "the driver has no volumes");
    }
    let ask = || MountRequest {
        label: Some(LABEL),
        ..x.volume(0)
    };
    let planned = match x.create(ask()) {
        Ok(p) => p,
        // (a host that does not let this user put a label on a file)
        Err(e) if matches!(e.kind, DriverErrorKind::LabelRefused) => {
            skip!(case, "this host refuses the label: {}", e.message())
        }
        Err(e) => panic!("a volume asked with a label: {e}"),
    };
    let plain = x.create(x.volume(1)).expect("a volume asked with none");
    assert_eq!(plain.label, LabelDone::None, "no label asked, none done");
    let m = x
        .mounts(None, vec![ask(), x.volume(1)])
        .expect("their mounts");
    assert_eq!(
        m.volumes[0].label, planned.label,
        "the start gives what the create said"
    );
    assert_eq!(m.volumes[1].label, LabelDone::None);
    if planned.label != LabelDone::Files {
        return;
    }
    let fd = m.volumes[0].fd.as_ref().expect("a mount descriptor");
    let mut seen = 0;
    for path in ["", "etc", "etc/os-release"] {
        let p = velarx_sys::fd::proc_path(fd).join(path);
        let mut v = [0u8; 256];
        match rustix::fs::lgetxattr(&p, "security.selinux", &mut v) {
            Ok(n) => {
                let got = String::from_utf8_lossy(&v[..n]);
                assert_eq!(
                    got.trim_end_matches('\0'),
                    LABEL,
                    "the label of {path:?} in the mount"
                );
                seen += 1;
            }
            // (a file system with no SELinux attributes: nothing to read
            // back; a file without the attribute where it can have one was
            // not labelled, and fails below)
            Err(rustix::io::Errno::OPNOTSUPP) => {}
            Err(e) => panic!("the label of {path:?}: {e}"),
        }
    }
    assert!(
        seen == 0 || seen == 3,
        "the label is on all the files or none: {seen} of 3"
    );
}

pub async fn mounts_gives_a_new_descriptor_at_each_call(f: &Factory) {
    let Some(x) = World::new(f, "mounts_gives_a_new_descriptor_at_each_call").await else {
        return;
    };
    if x.s.driver.capabilities().volume.is_none() {
        skip!(
            "mounts_gives_a_new_descriptor_at_each_call",
            "the driver has no volumes"
        );
    }
    x.create(x.volume(0)).unwrap();
    x.create(x.volume(2)).unwrap();
    let asked = || {
        x.mounts(
            Some(x.ask(Purpose::Root, None, false)),
            vec![x.volume(0), x.volume(2)],
        )
        .expect("the mounts")
    };
    let first = asked();
    let mut held = Vec::new();
    let mut all = vec![first];
    // (a start, a stop and a start, an engine that was restarted, a restore)
    for _ in 0..3 {
        all.push(asked());
    }
    let plans: Vec<_> = all
        .iter()
        .map(|m| {
            let root = m.root.as_ref().expect("the root that was asked");
            check_answer(root, true);
            assert_eq!(m.volumes.len(), 2, "one answer for each volume, in order");
            m.volumes.iter().for_each(|v| check_answer(v, false));
            (
                root.plan.clone(),
                m.volumes.iter().map(|v| v.plan.clone()).collect::<Vec<_>>(),
            )
        })
        .collect();
    // the same ask gives the same plans
    assert!(plans.windows(2).all(|p| p[0] == p[1]), "{plans:?}");
    for m in all {
        held.extend(m.root.into_iter().chain(m.volumes).filter_map(|r| r.fd));
    }
    let raw: HashSet<_> = held.iter().map(std::os::fd::AsRawFd::as_raw_fd).collect();
    assert_eq!(
        raw.len(),
        held.len(),
        "a descriptor of its own at every call"
    );
    // with no root asked there is none (a container of a `--rootfs`)
    let m = x.mounts(None, vec![x.volume(0)]).unwrap();
    assert!(m.root.is_none() && m.volumes.len() == 1);
    // nothing asked, nothing given
    let m = x.mounts(None, vec![]).unwrap();
    assert!(m.root.is_none() && m.volumes.is_empty());
}

pub async fn removing_a_container_removes_its_volumes(f: &Factory) {
    let Some(x) = World::new(f, "removing_a_container_removes_its_volumes").await else {
        return;
    };
    let c = x.s.driver.capabilities();
    if c.volume.is_none() {
        skip!(
            "removing_a_container_removes_its_volumes",
            "the driver has no volumes"
        );
    }
    x.create(x.volume(0)).unwrap();
    x.create(x.volume(1)).unwrap();
    // another container's volume is not this one's
    let other = Writable::new("c2", x.s.dir.join("bundles/c2"));
    create_over(&x.s, &other, &x.img, &x.layers);
    x.s.driver
        .image_volume_create(&MountRequest {
            container: &other,
            ..x.volume(0)
        })
        .unwrap();
    x.mounts(None, vec![x.volume(0), x.volume(1)])
        .expect("made");
    x.s.driver.writable_remove(&x.w).unwrap();
    if copies(c) {
        // a volume that is gone is `Missing`, and says to make the container
        // again: nothing of the container is left
        for v in [0, 1] {
            let e = expect_err(x.mounts(None, vec![x.volume(v)]), "a removed volume");
            assert!(
                matches!(e.kind, DriverErrorKind::Missing { remedy } if remedy == Remedy::RecreateContainer),
                "{e:?}"
            );
        }
        let m =
            x.s.driver
                .mounts(&MountsRequest {
                    root: None,
                    volumes: vec![MountRequest {
                        container: &other,
                        ..x.volume(0)
                    }],
                })
                .expect("the volume of another container stays");
        assert_eq!(m.volumes.len(), 1);
    }
    // (removed again: nothing is an error)
    x.s.driver.writable_remove(&x.w).unwrap();
    x.s.driver.writable_remove(&other).unwrap();
}

pub async fn a_volume_that_was_not_made_is_missing(f: &Factory) {
    let Some(x) = World::new(f, "a_volume_that_was_not_made_is_missing").await else {
        return;
    };
    if !copies(x.s.driver.capabilities()) {
        skip!(
            "a_volume_that_was_not_made_is_missing",
            "the driver makes no copy for a volume"
        );
    }
    x.create(x.volume(0)).unwrap();
    let e = expect_err(
        x.mounts(None, vec![x.volume(0), x.volume(1)]),
        "a volume that was not made",
    );
    assert!(
        matches!(e.kind, DriverErrorKind::Missing { remedy } if remedy == Remedy::RecreateContainer),
        "{e:?}"
    );
    of_driver(&x.s, &e);
}

pub async fn the_idmap_of_a_mount_is_what_was_asked(f: &Factory) {
    let Some(x) = World::new(f, "the_idmap_of_a_mount_is_what_was_asked").await else {
        return;
    };
    let c = x.s.driver.capabilities().clone();
    if c.volume.is_none() {
        skip!(
            "the_idmap_of_a_mount_is_what_was_asked",
            "the driver has no volumes"
        );
    }
    let map = mapping(65_536);
    let may_mount = |ways: Prefs<IdmapWay>| ways.contains(IdmapWay::MonitorMount);
    // (a request: root and volume 0, with or without a mapping and the right to
    // put it on a mount)
    let answers = |mapped: bool, idmap_mount: bool| -> DriverResult<(IdmapDone, IdmapDone)> {
        let m = mapped.then_some(&map);
        let a = x.mounts(
            Some(x.ask(Purpose::Root, m, idmap_mount)),
            vec![x.ask(Purpose::Volume { index: 0 }, m, idmap_mount)],
        )?;
        let root = a.root.unwrap();
        let vol = &a.volumes[0];
        // the plan agrees with who maps
        for (r, ways) in [(&root, c.root.idmap), (vol, volume_ways(&c))] {
            let plan_maps = matches!(r.plan, RootfsPlan::MountFd(f) if f.idmap);
            assert_eq!(plan_maps, r.idmap == IdmapDone::Mount, "{r:?}");
            if r.idmap == IdmapDone::Mount {
                assert!(
                    idmap_mount,
                    "a mapping put on a mount that was not allowed: {r:?}"
                );
                assert!(
                    may_mount(ways),
                    "an idmap the driver does not declare: {r:?}"
                );
            }
        }
        Ok((root.idmap, vol.idmap))
    };
    x.create(x.volume(0)).unwrap();
    // no mapping: nothing is mapped, however much the driver could
    assert_eq!(
        answers(false, false).unwrap(),
        (IdmapDone::None, IdmapDone::None)
    );
    // a mapping that the monitor may not put on a mount: the driver maps, or
    // refuses, never `None` and never `Mount`
    let volumes_map = !volume_ways(&c).is_empty();
    let creates = x.create(x.ask(Purpose::Volume { index: 0 }, Some(&map), false));
    if volumes_map {
        creates.expect("a mapping the driver has a way to apply");
    } else if copies(&c) {
        let e = expect_err(creates, "a mapping a copy cannot apply");
        assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
    }
    if volumes_map && !c.root.idmap.is_empty() {
        let (r, v) = answers(true, false).expect("a mapping the driver can apply");
        assert_ne!(r, IdmapDone::None);
        assert_ne!(v, IdmapDone::None);
        assert_ne!(r, IdmapDone::Mount);
        assert_ne!(v, IdmapDone::Mount);
        // and with the right to: what the driver says first
        let (r, v) = answers(true, true).expect("a mapping on a mount that may be");
        assert_ne!((r, v), (IdmapDone::None, IdmapDone::None));
        let first_maps = |ways: Prefs<IdmapWay>| ways.first() == Some(IdmapWay::MonitorMount);
        assert_eq!(v == IdmapDone::Mount, first_maps(volume_ways(&c)));
    } else if !volumes_map {
        // a driver with volumes and no way to map them refuses the mapping
        let e = expect_err(
            answers(true, false),
            "a mapping for volumes that cannot be mapped",
        );
        assert!(matches!(e.kind, DriverErrorKind::Unsupported), "{e:?}");
    }
}

/// What a driver that copies its images (`IdmapWay::AtCopy`, with a copy of
/// the image as the volume) hands over: the files of the image, owned by the
/// ids of the container's mapping (root only: a user cannot give them), and a
/// mount that cannot be written through (`EROFS` for a file made, a file
/// written, a file removed, a mode changed, whoever asks).  Not part of
/// [`volume_conformance_suite`] (the [`VolumeFake`] has no image in its
/// volumes), and false when the descriptor is not the root of a mount, which a
/// process that may not mount cannot make: the read-only part could not run.
pub async fn a_volume_has_the_image_mapped_and_is_read_only(f: &Factory) -> bool {
    use rustix::fs::{openat, unlinkat, AtFlags, Mode, OFlags};
    let Some(x) = World::new(f, "a_volume_has_the_image_mapped_and_is_read_only").await else {
        return false;
    };
    assert!(copies(x.s.driver.capabilities()), "a driver that copies");
    let map = mapping(65_536);
    let ask = || x.ask(Purpose::Volume { index: 0 }, Some(&map), false);
    x.create(ask()).expect("the copy, mapped as it is made");
    let m = x.mounts(None, vec![ask()]).expect("its mount");
    let v = &m.volumes[0];
    check_answer(v, false);
    assert_eq!(v.idmap, IdmapDone::Applied, "the copy was made mapped");
    let fd = v.fd.as_ref().expect("a descriptor");
    let read = |path: &str| -> String {
        let f = openat(fd, path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
            .unwrap_or_else(|e| panic!("{path} is in the image: {e}"));
        std::io::read_to_string(std::fs::File::from(f)).unwrap()
    };
    assert_eq!(read("etc/os-release"), "base", "the files of the image");
    assert_eq!(read("etc/hard"), "base", "a hard link of it");
    let at = |path: &str| {
        rustix::fs::statat(fd, path, AtFlags::SYMLINK_NOFOLLOW)
            .unwrap_or_else(|e| panic!("{path}: {e}"))
    };
    assert_eq!(
        rustix::fs::readlinkat(fd, "etc/link", Vec::new()).unwrap(),
        c"os-release".to_owned(),
        "a link is a link"
    );
    if is_root() {
        // (the image is owned by root: the root of the container, host id 100000)
        for path in [".", "etc", "etc/os-release", "usr/lib/big", "etc/link"] {
            let st = at(path);
            assert_eq!(
                (st.st_uid, st.st_gid),
                (100_000, 100_000),
                "the owner of {path} is the container's"
            );
        }
    }
    // read-only: only a mount that is one can be checked
    if rustix::fs::fstatvfs(fd)
        .map(|s| !s.f_flag.contains(rustix::fs::StatVfsMountFlags::RDONLY))
        .unwrap_or(true)
    {
        return false;
    }
    let erofs = |what: &str, r: Result<(), rustix::io::Errno>| {
        assert_eq!(r, Err(rustix::io::Errno::ROFS), "{what}");
    };
    erofs(
        "a file made",
        openat(
            fd,
            "etc/new",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o644),
        )
        .map(drop),
    );
    erofs(
        "a file written",
        openat(fd, "etc/os-release", OFlags::WRONLY, Mode::empty()).map(drop),
    );
    erofs("a file removed", unlinkat(fd, "etc/old", AtFlags::empty()));
    erofs(
        "a directory made",
        rustix::fs::mkdirat(fd, "newdir", Mode::from_raw_mode(0o755)),
    );
    erofs(
        "a mode changed",
        rustix::fs::chmodat(
            fd,
            "etc/os-release",
            Mode::from_raw_mode(0o777),
            AtFlags::empty(),
        ),
    );
    // the copy under the bundle is not read-only (the mount is): the engine
    // can remove it with its container
    x.s.driver.writable_remove(&x.w).unwrap();
    true
}

/// The cases of the volume API, for a suite that wants these only (a driver
/// wrapped in a [`VolumeFake`]).
#[macro_export]
macro_rules! volume_conformance_suite {
    ($factory:expr) => {
        $crate::volume_conformance_suite_with!($crate::conformance_cases; $factory);
    };
}

/// [`volume_conformance_suite!`] with the macro `$cases` making the tests of
/// the cases (see [`conformance_suite_with!`](crate::conformance_suite_with)).
#[macro_export]
macro_rules! volume_conformance_suite_with {
    ($cases:path; $factory:expr) => {
        $cases! {
            $factory;
            image_volumes_are_what_the_capabilities_say,
            image_volume_create_is_idempotent,
            an_image_mount_label_is_what_the_answer_says,
            mounts_gives_a_new_descriptor_at_each_call,
            removing_a_container_removes_its_volumes,
            a_volume_that_was_not_made_is_missing,
            the_idmap_of_a_mount_is_what_was_asked,
        }
    };
}
