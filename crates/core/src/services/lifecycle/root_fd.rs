// SPDX-License-Identifier: Apache-2.0
//! The descriptors and plans of the root file system and of the image mounts
//! (`--mount type=image`) of a container at a start: what the storage driver
//! answers to [`velarx_graph::StorageDriver::mounts`], checked, and written
//! in the bundle for the monitor to read.
//!
//! The monitor uses a descriptor (`RootfsPlan::MountFd`) once, for the start of
//! the monitor that got it.  So the engine never keeps one: at every start of a
//! container (a start after a stop, a restore, a start by an engine that was
//! restarted, a container that is made in its monitor again) it asks the driver
//! once for the root and all the image mounts, and passes the descriptors that
//! come with the answer.  The plan files of the bundle say what the engine
//! needs to go on across a restart of its process (that the root is a
//! descriptor the driver hands over); they hold no descriptor and no path of a
//! mount, and every start writes all of them again from the answer, so a plan
//! of an earlier start, or of another kind of driver, is never read.
//!
//! Every answer is checked before the monitor sees it (fail closed): a
//! descriptor exactly for a mount plan, the kind of plan a purpose may have
//! (a volume is never a directory), and the mapping: `Mount` only when the
//! engine allowed the monitor to put it on the mount and the plan says it
//! does, `None` never when a mapping was asked, and `Applied` never when none
//! was.

use super::{ContainerError, ContainerResult};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use velarx_fuse::plan::RootfsPlan;
use velarx_graph::{IdmapDone, LabelDone, MountRequest, Mounts, Rootfs, VerityAsk, VerityDone};

fn invalid(why: String) -> ContainerError {
    ContainerError::InvalidArgument(why)
}

/// What the engine asked of one mount, for the check of the answer.
#[derive(Debug, Clone, Copy)]
pub(in crate::services) struct Ask<'a> {
    /// The container has a user namespace of its own: a mapping was asked.
    pub mapped: bool,
    /// The monitor may put the mapping on the mount.
    pub idmap_mount: bool,
    /// An SELinux label was asked for: the mount may carry it.
    pub label: bool,
    /// The digests are enforced, with those accepted for each layer: a
    /// mount the driver hands over must carry that enforcement.
    pub verity: VerityAsk<'a>,
}

impl<'a> From<&MountRequest<'a>> for Ask<'a> {
    fn from(m: &MountRequest<'a>) -> Self {
        Self {
            mapped: m.mapping.is_some(),
            idmap_mount: m.idmap_mount,
            label: m.label.is_some(),
            verity: m.verity,
        }
    }
}

/// Whether the monitor may put the container's id mapping on a mount: the
/// container has a user namespace of its own (`mapped`; one that runs with the
/// engine's ids has no mapping to put, and the engine's translation of it is the
/// identity of the ids it was granted, which would show every other id as the
/// overflow id) and the engine is root of the initial user namespace (a host
/// file system takes no idmapped mount from anyone else).
pub(in crate::services) fn may_idmap_mounts(mapped: bool) -> bool {
    mapped && velarx_base::ids::rootful().unwrap_or(false)
}

/// Whether the plan of the bundle says that the root file system is a mount
/// descriptor that the driver gives at each start.
pub(in crate::services) fn wants_fd(bundle: &Path) -> ContainerResult<bool> {
    match velarx_fuse::plan::read(bundle, "")? {
        Some(RootfsPlan::MountFd(m)) => {
            // (an index no monitor gets is no plan, whoever wrote the file)
            m.validate().map_err(|why| {
                invalid(format!(
                    "{}: {why}",
                    velarx_fuse::plan::file(bundle, "").display()
                ))
            })?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// One more image mount of a container at its create, `planned` as the driver
/// says it will be: a mount the driver hands over as a descriptor is counted in
/// `count`, and one more than a monitor takes is refused now, before the
/// container exists, not at every start.
pub(in crate::services) fn count_volume_fd(
    driver: &str,
    planned: &velarx_graph::Planned,
    count: &mut usize,
) -> ContainerResult<()> {
    if !matches!(planned.plan, RootfsPlan::MountFd(_)) {
        return Ok(());
    }
    *count += 1;
    if *count > velarx_fuse::plan::MAX_VOLUME_FDS as usize {
        return Err(invalid(format!(
            "--mount type=image: the storage driver {driver} hands over the image mounts as mount descriptors, and a container has at most {} of them",
            velarx_fuse::plan::MAX_VOLUME_FDS
        )));
    }
    Ok(())
}

/// An image mount carries the label that was asked, or the driver says it
/// does not: the engine cannot label the files of an image mount itself (all
/// it gets of the mount is a read-only clone at each start), so a mount that
/// is not labelled would be a container that cannot read it.  Failed closed,
/// naming the driver.
fn volume_label(driver: &str, what: &str, ask_label: bool, done: LabelDone) -> ContainerResult<()> {
    if ask_label && done == LabelDone::None {
        return Err(invalid(format!(
            "the storage driver {driver} does not put the container's SELinux label on the {what}, and the engine cannot label it afterwards (the container could not read it): use a driver that labels image mounts (a mount with `context=`, or labelled files), or run the container without a label"
        )));
    }
    Ok(())
}

/// The label of an image mount at its create: the driver's `planned` carries
/// what was asked (`label`) or the create is refused.
pub(in crate::services) fn require_volume_label(
    driver: &str,
    planned: &velarx_graph::Planned,
    label: Option<&str>,
) -> ContainerResult<()> {
    volume_label(driver, "image mount", label.is_some(), planned.label)
}

/// The plan of an answer as the monitor reads it: the driver's, with the
/// mapping the monitor puts on the mount said by the answer (`Mount`, and no
/// other) and whether a server's pidfd follows the mount's descriptor (the
/// answer has one), whatever flags the driver set in its plan.
pub(in crate::services) fn plan_of(
    plan: &RootfsPlan,
    idmap: IdmapDone,
    server: bool,
) -> RootfsPlan {
    match plan {
        RootfsPlan::MountFd(m) => RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
            idmap: idmap == IdmapDone::Mount,
            server,
            ..*m
        }),
        other => other.clone(),
    }
}

/// The descriptors a mount of the answer is passed with: its own, then its
/// server's pidfd if it has one (the monitor finds it after the mount's).
fn with_server(fd: OwnedFd, server: Option<OwnedFd>) -> Vec<Arc<OwnedFd>> {
    std::iter::once(fd).chain(server).map(Arc::new).collect()
}

/// The answer's mapping against what was asked.
fn check_idmap(
    short: &str,
    driver: &str,
    what: &str,
    ask: &Ask,
    r: &Rootfs,
) -> ContainerResult<()> {
    if r.label != LabelDone::None && !ask.label {
        return Err(invalid(format!(
            "container {short}: the storage driver {driver} says it put an SELinux label on the {what}, and none was asked"
        )));
    }
    let plan_maps = matches!(&r.plan, RootfsPlan::MountFd(m) if m.idmap);
    match r.idmap {
        IdmapDone::Mount if !ask.idmap_mount => Err(invalid(format!(
            "container {short}: the storage driver {driver} left the id mapping of the {what} to the monitor, which it was not asked to do (the container has no user namespace of its own, or the engine is not root of the initial one)"
        ))),
        IdmapDone::Mount if !plan_maps => Err(invalid(format!(
            "container {short}: the storage driver {driver} left the id mapping of the {what} to the monitor, and its plan does not ask the monitor to put one on the mount"
        ))),
        IdmapDone::None if ask.mapped => Err(invalid(format!(
            "container {short}: the container has a user namespace and the storage driver {driver} maps no ids of its {what}: the files would show the owners of the image"
        ))),
        IdmapDone::Applied if !ask.mapped => Err(invalid(format!(
            "container {short}: the storage driver {driver} says it mapped the ids of the {what}, and no mapping was asked (the container has no user namespace of its own)"
        ))),
        IdmapDone::Applied | IdmapDone::None if plan_maps => Err(invalid(format!(
            "container {short}: the plan of the {what} of the storage driver {driver} asks the monitor to map the ids, and the driver says it did"
        ))),
        _ => Ok(()),
    }
}

/// What enforces the digests of an accepted mount, for the chain of trust and
/// the monitor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Enforcement {
    pub verity: VerityDone,
    /// With `verity` not `None`: the digest measured on the EROFS image of
    /// each layer, the lowest first.
    pub measured: Vec<String>,
}

/// What a mount that was checked (`check_verity`) enforces.
fn enforcement(r: &Rootfs) -> Enforcement {
    Enforcement {
        verity: r.verity,
        measured: r.measured.clone(),
    }
}

/// What a start passes on of the checked answer of the driver: the
/// descriptors for the monitor, and what enforces the digests of the root
/// and of each image mount (in the order they were asked).
#[derive(Debug)]
pub struct Accepted {
    pub fds: Vec<Arc<OwnedFd>>,
    pub root: Option<Enforcement>,
    pub volumes: Vec<Enforcement>,
}

/// The answer's enforcement of the digests against what was asked, and its
/// serving process.  A mount the driver hands over as a descriptor carries
/// the enforcement when the digests are enforced: the monitor cannot measure
/// what it did not mount, so a mount that says none is refused, and the
/// digests the driver says it measured must be some the manifest's lists
/// accept, layer by layer (the engine does not take a bare claim).  A plan
/// the monitor mounts itself (a directory) has no digest to measure.
fn check_verity(
    short: &str,
    driver: &str,
    what: &str,
    ask: &Ask,
    r: &Rootfs,
) -> ContainerResult<()> {
    let hands_over = matches!(r.plan, RootfsPlan::MountFd(_));
    // (the server is passed to the monitor after the descriptor of the
    // mount it serves: no mount, no place for it)
    if r.server.is_some() && !(hands_over && r.fd.is_some()) {
        return Err(invalid(format!(
            "container {short}: the storage driver {driver} gave a process that serves the {what}, which is no mount descriptor it hands over: the monitor takes the pidfd of a server with the mount it serves"
        )));
    }
    match (ask.verity, r.verity) {
        (VerityAsk::Off, VerityDone::None) if r.measured.is_empty() => Ok(()),
        (VerityAsk::Off, _) => Err(invalid(format!(
            "container {short}: the storage driver {driver} says it enforced the digests of the {what}, and they are not enforced"
        ))),
        (VerityAsk::Enforce { .. }, VerityDone::None) if hands_over => Err(invalid(format!(
            "container {short}: the digests are enforced and the storage driver {driver} hands over the {what} as a mount that enforces none: the monitor cannot check what it did not mount"
        ))),
        (VerityAsk::Enforce { .. }, VerityDone::None) if r.measured.is_empty() => {
            Ok(())
        }
        (VerityAsk::Enforce { .. }, VerityDone::None) => Err(invalid(format!(
            "container {short}: the storage driver {driver} gave digests it measured for the {what}, and says it enforces none"
        ))),
        (VerityAsk::Enforce { .. }, _) if !hands_over => Err(invalid(format!(
            "container {short}: the storage driver {driver} says it enforced the digests of the {what}, whose plan is one the monitor mounts"
        ))),
        // (a mount checked when a file is opened is checked by the process
        // that serves it, and it gave none: nothing would check the files)
        (VerityAsk::Enforce { .. }, VerityDone::OnOpen) if r.server.is_none() => {
            Err(invalid(format!(
                "container {short}: the storage driver {driver} says a process that serves the {what} checks its digests, and gave none"
            )))
        }
        (VerityAsk::Enforce { accepted, .. }, _) => {
            if r.measured.len() != accepted.len() {
                return Err(invalid(format!(
                    "container {short}: the storage driver {driver} measured {} images for the {what}, which has {} layers",
                    r.measured.len(),
                    accepted.len()
                )));
            }
            if let Some(n) = r
                .measured
                .iter()
                .zip(accepted)
                .position(|(got, ok)| !ok.contains(got))
            {
                return Err(invalid(format!(
                    "container {short}: the storage driver {driver} measured the image of layer {} of the {what} as {}, which the digests of the manifest do not accept ({})",
                    n + 1,
                    r.measured[n],
                    accepted[n].join(", ")
                )));
            }
            Ok(())
        }
    }
}

/// The descriptors of the image mounts of a container, after the `first`
/// descriptors already passed (the root file system's): `volumes` are the
/// answers of the driver for this start, by the index of each among the image
/// mounts and with what was asked, and the plan written for the monitor to
/// read in `imagevol/N.rootfs.json` is the answer's: a mount names the place
/// the descriptor has in the list (which depends on whether the root file
/// system has one).  Every mount must be what the monitor can
/// attach, with its descriptor: a volume it cannot is a start that fails
/// here, not one that runs without it.  At most
/// [`velarx_fuse::plan::MAX_VOLUME_FDS`] descriptors.
pub(in crate::services) fn accept_volumes(
    bundle: &Path,
    container: &str,
    driver: &str,
    first: usize,
    mut volumes: Vec<(usize, Ask, Rootfs)>,
) -> ContainerResult<Vec<Arc<OwnedFd>>> {
    let short = &container[..container.len().min(12)];
    volumes.sort_by_key(|(n, _, _)| *n);
    if let Some(w) = volumes.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(invalid(format!(
            "container {short}: the storage driver {driver} gave image mount {} twice",
            w[0].0
        )));
    }
    let descriptors = volumes.iter().filter(|(_, _, r)| r.fd.is_some()).count();
    if descriptors > velarx_fuse::plan::MAX_VOLUME_FDS as usize {
        return Err(invalid(format!(
            "container {short}: the storage driver {driver} gave {descriptors} image mounts as mount descriptors, and a monitor gets at most {}",
            velarx_fuse::plan::MAX_VOLUME_FDS
        )));
    }
    let mut fds = Vec::new();
    let mut plans = Vec::new();
    for (n, ask, r) in volumes {
        check_idmap(short, driver, &format!("image mount {n}"), &ask, &r)?;
        check_verity(short, driver, &format!("image mount {n}"), &ask, &r)?;
        volume_label(driver, &format!("image mount {n}"), ask.label, r.label)
            .map_err(|e| invalid(format!("container {short}: {e}")))?;
        let plan = plan_of(&r.plan, r.idmap, r.server.is_some());
        match (plan, r.fd) {
            (RootfsPlan::MountFd(m), Some(fd)) => {
                let place = first + fds.len();
                let mount = velarx_fuse::plan::MountFd {
                    fd_index: u32::try_from(place).unwrap_or(u32::MAX),
                    ..m
                };
                if mount.validate().is_err() {
                    return Err(invalid(format!(
                        "container {short}: no place for the mount descriptor of image mount {n}"
                    )));
                }
                plans.push((n, RootfsPlan::MountFd(mount)));
                fds.extend(with_server(fd, r.server));
            }
            (RootfsPlan::MountFd(_), None) => {
                return Err(invalid(format!(
                    "container {short}: image mount {n} is a mount that the storage driver {driver} hands over at each start, and it gave none this time: remove the container and create it again"
                )))
            }
            (RootfsPlan::Directory(_), _) => {
                return Err(invalid(format!(
                    "container {short}: the storage driver {driver} gave image mount {n} as a directory: only a root file system may be one, an image mount is a mount descriptor"
                )))
            }
        }
    }
    let dir = bundle.join("imagevol");
    if !plans.is_empty() {
        std::fs::create_dir_all(&dir)?;
    }
    for (n, plan) in &plans {
        velarx_fuse::plan::write(&dir, &format!("{n}."), plan)?;
    }
    Ok(fds)
}

/// The descriptors to pass to the monitor for the root `fresh` that the driver
/// `driver` made for this start, and the plan written in the bundle for the
/// monitor to read (its index may have changed).  `expects_fd` is whether the
/// plan of the bundle says `mount-fd`: the driver must still give a mount then,
/// and must not when it does not say so; a plan of another kind is a bundle and
/// a driver that do not go together (the store was changed, or the driver
/// was), and the start fails rather than running the container on a root the
/// plan file did not say.
pub(in crate::services) fn accept_root(
    bundle: &Path,
    container: &str,
    driver: &str,
    expects_fd: bool,
    ask: &Ask,
    fresh: Rootfs,
) -> ContainerResult<Vec<Arc<OwnedFd>>> {
    let short = &container[..container.len().min(12)];
    check_idmap(short, driver, "root file system", ask, &fresh)?;
    check_verity(short, driver, "root file system", ask, &fresh)?;
    let plan = plan_of(&fresh.plan, fresh.idmap, fresh.server.is_some());
    let server = fresh.server;
    let fds = match (&plan, fresh.fd, expects_fd) {
        (RootfsPlan::MountFd(m), Some(fd), true) => {
            // (the monitor gets the root's descriptor first)
            if m.fd_index != 0 {
                return Err(invalid(format!(
                    "container {short}: the storage driver {driver} gave the root file system as the mount descriptor {}, and only one is passed to the monitor (the index must be 0)",
                    m.fd_index
                )));
            }
            with_server(fd, server)
        }
        (RootfsPlan::MountFd(_), None, _) => {
            return Err(invalid(format!(
                "container {short}: the root file system is a mount that the storage driver {driver} hands over at each start, and it gave none this time: the container cannot start (the driver was changed, or it cannot make the mount again); remove the container and create it again"
            )))
        }
        (RootfsPlan::MountFd(_), Some(_), false) => {
            return Err(invalid(format!(
                "container {short}: its bundle says that the root file system is not a mount that the storage driver {driver} hands over, and the driver now makes one: the store was modified or the driver was changed; remove the container and create it again"
            )))
        }
        (_, Some(_), _) => {
            return Err(invalid(format!(
                "container {short}: the storage driver {driver} gave a mount descriptor with a root file system plan that does not use one"
            )))
        }
        (_, None, true) => {
            return Err(invalid(format!(
                "container {short}: its bundle says that the root file system is a mount that the storage driver {driver} hands over at each start, and the driver now makes another kind of plan: the store was modified or the driver was changed; remove the container and create it again"
            )))
        }
        (_, None, false) => Vec::new(),
    };
    velarx_fuse::plan::write(bundle, "", &plan)?;
    Ok(fds)
}

/// Everything a start asked of the driver (`root`: the root file system with
/// whether the plan of the bundle says it is a mount; none for a `--rootfs` or
/// a root nothing is asked of, `volumes`: the image mounts by index) checked and
/// written in the bundle, and the descriptors for the monitor, the root's
/// first, then the volumes' in the order of their index.
pub(in crate::services) fn accept_mounts(
    bundle: &Path,
    container: &str,
    driver: &str,
    root: Option<(&Ask, bool)>,
    volumes: &[(usize, Ask)],
    answer: Mounts,
) -> ContainerResult<Accepted> {
    let short = &container[..container.len().min(12)];
    let wrong = |what: &str| {
        invalid(format!(
            "container {short}: the storage driver {driver} answered {what}"
        ))
    };
    if answer.volumes.len() != volumes.len() {
        return Err(wrong(&format!(
            "{} image mounts for the {} asked",
            answer.volumes.len(),
            volumes.len()
        )));
    }
    let root_enforced = answer.root.as_ref().map(enforcement);
    let volumes_enforced = answer.volumes.iter().map(enforcement).collect();
    let mut fds = match (root, answer.root) {
        (None, None) => Vec::new(),
        (Some((ask, expects_fd)), Some(r)) => {
            accept_root(bundle, container, driver, expects_fd, ask, r)?
        }
        (Some(_), None) => return Err(wrong("no root file system, which was asked")),
        (None, Some(_)) => return Err(wrong("a root file system, which was not asked")),
    };
    let vols = volumes
        .iter()
        .zip(answer.volumes)
        .map(|((n, ask), r)| (*n, *ask, r))
        .collect();
    let more = accept_volumes(bundle, container, driver, fds.len(), vols)?;
    fds.extend(more);
    Ok(Accepted {
        fds,
        root: root_enforced,
        volumes: volumes_enforced,
    })
}

/// What a start has to ask the driver for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::services) struct Needs {
    /// The root file system: its plan is a mount the driver hands over.
    /// Never for a `--rootfs`, whose root is the user's directory.
    pub expects_fd: bool,
}

/// What a start asks of the driver, given the bundle's plan of the root and the
/// number of image mounts of the container: none (`None`) when the root is
/// nothing the driver hands over and the container has no image mount.  **The
/// image mounts are asked for whatever the root is** (a `--rootfs` or a
/// directory root as well as a mount): the mounts the driver makes for them
/// are descriptors of this start, written in the bundle whatever the plan of
/// the root is.
pub(in crate::services) fn needs(
    bundle: &Path,
    from_layers: bool,
    image_mounts: usize,
) -> ContainerResult<Option<Needs>> {
    let expects_fd = from_layers && wants_fd(bundle)?;
    Ok((expects_fd || image_mounts > 0).then_some(Needs { expects_fd }))
}

/// The one call of a start: the driver's answer for `root` and `volumes` (the
/// image mounts, in the order of their index), checked and written in the
/// bundle, and the descriptors for the monitor.  `root` carries whether the
/// plan of the bundle says the root is a mount.
pub fn start_mounts(
    driver: &dyn velarx_graph::StorageDriver,
    bundle: &Path,
    container: &velarx_graph::Writable,
    root: Option<(MountRequest<'_>, bool)>,
    volumes: Vec<MountRequest<'_>>,
) -> ContainerResult<Accepted> {
    let root_ask = root
        .as_ref()
        .map(|(m, expects_fd)| (Ask::from(m), *expects_fd));
    let volume_asks: Vec<_> = volumes
        .iter()
        .enumerate()
        .map(|(n, v)| (n, Ask::from(v)))
        .collect();
    let answer = driver
        .mounts(&velarx_graph::MountsRequest {
            root: root.map(|(m, _)| m),
            volumes,
        })
        .map_err(velarx_types::ImageError::from)?;
    accept_mounts(
        bundle,
        container.id(),
        driver.name(),
        root_ask.as_ref().map(|(a, e)| (a, *e)),
        &volume_asks,
        answer,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd};
    use velarx_fuse::plan::{Directory, MountFd};
    use velarx_graph::IdmapDone;

    /// A container with no user namespace of its own.
    const PLAIN: Ask = Ask {
        verity: VerityAsk::Off,
        mapped: false,
        idmap_mount: false,
        label: false,
    };

    /// What a driver gives: a new descriptor of the directory `root` at every
    /// call (a driver that mounts gives a new detached clone, which needs a
    /// privilege the unit tests do not take: the plan and the descriptor are
    /// what is looked at here).
    fn driver_root(root: &Path) -> Rootfs {
        let fd = rustix::fs::open(
            root,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        Rootfs {
            plan: RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            }),
            fd: Some(fd),
            idmap: IdmapDone::None,
            label: velarx_graph::LabelDone::None,
            verity: velarx_graph::VerityDone::None,
            measured: Vec::new(),
            server: None,
        }
    }

    fn bundle(plan: &RootfsPlan) -> tempfile::TempDir {
        let b = tempfile::tempdir().unwrap();
        velarx_fuse::plan::write(b.path(), "", plan).unwrap();
        b
    }

    /// An image mount that is not labelled while a label was asked is refused,
    /// at create and at a start, naming the driver; with the label done (the
    /// mount's `context=`, the files), or none asked, it is accepted.
    #[test]
    fn an_image_mount_that_is_not_labelled_is_refused() {
        let planned = |label| velarx_graph::Planned {
            plan: RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            }),
            idmap: IdmapDone::None,
            label,
        };
        let none = planned(LabelDone::None);
        let e = require_volume_label("vfs", &none, Some("system_u:object_r:container_file_t:s0"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("driver vfs") && e.contains("SELinux label"),
            "{e}"
        );
        require_volume_label("vfs", &none, None).unwrap();
        for done in [LabelDone::Files, LabelDone::MountContext] {
            require_volume_label("vfs", &planned(done), Some("l")).unwrap();
        }
        // and at a start
        let d = tempfile::tempdir().unwrap();
        let b = bundle(&RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        }));
        let asked = Ask {
            label: true,
            ..PLAIN
        };
        let e = accept_volumes(
            b.path(),
            "0123456789abcdef",
            "vfs",
            0,
            vec![(0, asked, driver_root(d.path()))],
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("does not put the container's SELinux label"),
            "{e}"
        );
        let mut labelled = driver_root(d.path());
        labelled.label = LabelDone::Files;
        accept_volumes(
            b.path(),
            "0123456789abcdef",
            "vfs",
            0,
            vec![(0, asked, labelled)],
        )
        .unwrap();
    }

    #[test]
    fn only_a_mount_fd_plan_asks_the_driver() {
        let none = tempfile::tempdir().unwrap();
        assert!(!wants_fd(none.path()).unwrap(), "a --rootfs has no plan");
        let dir = bundle(&RootfsPlan::Directory(Directory {
            beneath: "/b".into(),
            path: "r".into(),
        }));
        assert!(!wants_fd(dir.path()).unwrap());
        let m = bundle(&RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        }));
        assert!(wants_fd(m.path()).unwrap());
        // an index no monitor gets is an error that names it
        let beyond = bundle(&RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 99,
            idmap: false,
        }));
        let e = wants_fd(beyond.path()).unwrap_err().to_string();
        assert!(e.contains("fd_index 99"), "{e}");
    }

    #[test]
    fn every_start_has_a_descriptor_of_its_own() {
        let root = tempfile::tempdir().unwrap();
        let b = bundle(&RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        }));
        let mut seen = Vec::new();
        // start, stop, start again, an engine that knows nothing of the
        // earlier ones (only the bundle), a restore: each asks the driver
        for _ in 0..4 {
            assert!(wants_fd(b.path()).unwrap());
            let fds = accept_root(
                b.path(),
                "0123456789abcdef",
                "test",
                true,
                &PLAIN,
                driver_root(root.path()),
            )
            .unwrap();
            assert_eq!(fds.len(), 1);
            seen.push(fds);
        }
        // (descriptors that are all open at once are different ones)
        let mut raw: Vec<_> = seen
            .iter()
            .map(|f| std::os::fd::AsRawFd::as_raw_fd(&*f[0]))
            .collect();
        raw.sort_unstable();
        raw.dedup();
        assert_eq!(raw.len(), 4);
        for f in &seen {
            let st = rustix::fs::fstat(f[0].as_fd()).unwrap();
            assert_eq!(
                rustix::fs::FileType::from_raw_mode(st.st_mode),
                rustix::fs::FileType::Directory
            );
        }
        // the plan the monitor reads is the one the driver made now
        assert_eq!(
            velarx_fuse::plan::read(b.path(), "").unwrap(),
            Some(RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 0,
                idmap: false
            }))
        );
    }

    /// A bundle with the plan of a kind this version does not have (a
    /// `composefs` plan, made by an engine before the storage driver handed
    /// the root over as a mount) is invalid: the start fails, naming the file
    /// and the kind, and nothing is written.
    #[test]
    fn a_composefs_plan_in_a_bundle_is_invalid() {
        let b = tempfile::tempdir().unwrap();
        let file = velarx_fuse::plan::file(b.path(), "");
        std::fs::write(&file, br#"{"kind":"composefs","layers":[],"image_id":"i"}"#).unwrap();
        for e in [
            wants_fd(b.path()).unwrap_err().to_string(),
            needs(b.path(), true, 0).unwrap_err().to_string(),
        ] {
            assert!(e.contains("rootfs.json") && e.contains("composefs"), "{e}");
        }
        let root = tempfile::tempdir().unwrap();
        // (a driver answer does not repair it: the bundle is read first)
        assert!(needs(b.path(), true, 2).is_err());
        assert!(std::fs::read(&file)
            .unwrap()
            .starts_with(b"{\"kind\":\"composefs\""));
        drop(root);
    }

    /// A root that was a mount of the driver is a mount at every start: a
    /// driver that now answers another kind of plan is refused, and the
    /// bundle keeps the plan it has.
    #[test]
    fn a_mount_of_the_driver_cannot_become_another_kind_of_plan() {
        let was = RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        });
        let b = bundle(&was);
        let answer = Rootfs {
            plan: RootfsPlan::Directory(Directory {
                beneath: "/b".into(),
                path: "r".into(),
            }),
            fd: None,
            idmap: IdmapDone::None,
            label: LabelDone::None,
            verity: velarx_graph::VerityDone::None,
            measured: Vec::new(),
            server: None,
        };
        let e = accept_root(b.path(), "c", "test", true, &PLAIN, answer)
            .unwrap_err()
            .to_string();
        assert!(e.contains("another kind of plan"), "{e}");
        assert_eq!(velarx_fuse::plan::read(b.path(), "").unwrap(), Some(was));
    }

    #[test]
    fn a_driver_that_gives_no_descriptor_is_said() {
        let b = bundle(&RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        }));
        let e = accept_root(
            b.path(),
            "0123456789abcdef",
            "test",
            true,
            &PLAIN,
            Rootfs {
                plan: RootfsPlan::MountFd(MountFd {
                    server: false,
                    fd_index: 0,
                    idmap: false,
                }),
                fd: None,
                idmap: IdmapDone::None,
                label: velarx_graph::LabelDone::None,
                verity: velarx_graph::VerityDone::None,
                measured: Vec::new(),
                server: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("container 0123456789ab"), "{e}");
        assert!(e.contains("storage driver test"), "{e}");
        assert!(e.contains("gave none"), "{e}");
        assert!(
            e.contains("remove the container and create it again"),
            "{e}"
        );
    }

    #[test]
    fn a_descriptor_the_plan_does_not_name_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let b = bundle(&RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        }));
        let mut r = driver_root(root.path());
        r.plan = RootfsPlan::Directory(Directory {
            beneath: "/b".into(),
            path: "r".into(),
        });
        let e = accept_root(b.path(), "c", "test", true, &PLAIN, r)
            .unwrap_err()
            .to_string();
        assert!(e.contains("does not use one"), "{e}");
        let mut r = driver_root(root.path());
        r.plan = RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 1,
            idmap: false,
        });
        let e = accept_root(b.path(), "c", "test", true, &PLAIN, r)
            .unwrap_err()
            .to_string();
        assert!(e.contains("must be 0"), "{e}");
        // (nothing was written over the plan)
        assert_eq!(
            velarx_fuse::plan::read(b.path(), "").unwrap(),
            Some(RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 0,
                idmap: false
            }))
        );
    }

    #[test]
    fn a_driver_that_makes_another_kind_of_plan_is_refused() {
        let b = bundle(&RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        }));
        let dir = RootfsPlan::Directory(Directory {
            beneath: "/b".into(),
            path: "r".into(),
        });
        let e = accept_root(b.path(), "c", "test", true, &PLAIN, Rootfs::from(dir))
            .unwrap_err()
            .to_string();
        assert!(e.contains("now makes another kind of plan"), "{e}");
        assert!(e.contains("create it again"), "{e}");
        // (the plan of the bundle is as it was)
        assert_eq!(
            velarx_fuse::plan::read(b.path(), "").unwrap(),
            Some(RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 0,
                idmap: false
            }))
        );
    }

    fn volume(plan: MountFd, root: &Path) -> Rootfs {
        let mut r = driver_root(root);
        r.idmap = if plan.idmap {
            IdmapDone::Mount
        } else {
            IdmapDone::None
        };
        r.plan = RootfsPlan::MountFd(plan);
        r
    }

    /// `accept_volumes` for a container whose mapping the monitor may put on a
    /// mount when the answer says so.
    fn accept_volumes_t(
        bundle: &Path,
        container: &str,
        driver: &str,
        first: usize,
        v: Vec<(usize, Rootfs)>,
    ) -> ContainerResult<Vec<Arc<OwnedFd>>> {
        let ask = Ask {
            label: false,
            mapped: false,
            idmap_mount: true,
            verity: VerityAsk::Off,
        };
        accept_volumes(
            bundle,
            container,
            driver,
            first,
            v.into_iter().map(|(n, r)| (n, ask, r)).collect(),
        )
    }

    #[test]
    fn image_mounts_get_the_places_after_the_root_in_the_order_of_their_index() {
        let root = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        // (the driver answers in any order, and names any place: the engine
        // numbers them by the list it passes)
        let vols = vec![
            (
                2,
                volume(
                    MountFd {
                        server: false,
                        fd_index: 9,
                        idmap: true,
                    },
                    root.path(),
                ),
            ),
            (
                0,
                volume(
                    MountFd {
                        server: false,
                        fd_index: 9,
                        idmap: false,
                    },
                    root.path(),
                ),
            ),
        ];
        let fds = accept_volumes_t(b.path(), "0123456789abcdef", "test", 1, vols).unwrap();
        assert_eq!(fds.len(), 2);
        let read = |n: usize| {
            velarx_fuse::plan::read(&b.path().join("imagevol"), &format!("{n}."))
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            read(0),
            RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 1,
                idmap: false
            })
        );
        assert_eq!(
            read(2),
            RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 2,
                idmap: true
            })
        );
        // a root that is not a mount has no descriptor: the first place is 0
        let b2 = tempfile::tempdir().unwrap();
        let one = vec![(
            0,
            volume(
                MountFd {
                    server: false,
                    fd_index: 5,
                    idmap: false,
                },
                root.path(),
            ),
        )];
        accept_volumes_t(b2.path(), "c", "test", 0, one).unwrap();
        assert_eq!(
            velarx_fuse::plan::read(&b2.path().join("imagevol"), "0.").unwrap(),
            Some(RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 0,
                idmap: false
            }))
        );
    }

    #[test]
    fn an_image_mount_that_is_not_a_usable_descriptor_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let plain = MountFd {
            server: false,
            fd_index: 1,
            idmap: false,
        };
        let e = |v: Vec<(usize, Rootfs)>, first: usize| {
            accept_volumes_t(b.path(), "0123456789abcdef", "test", first, v)
                .unwrap_err()
                .to_string()
        };
        let dir = Rootfs::from(RootfsPlan::Directory(Directory {
            beneath: "/b".into(),
            path: "r".into(),
        }));
        assert!(e(vec![(0, dir)], 1).contains("only a root file system may be one"));
        let none = Rootfs {
            plan: RootfsPlan::MountFd(plain),
            fd: None,
            idmap: IdmapDone::None,
            label: velarx_graph::LabelDone::None,
            verity: velarx_graph::VerityDone::None,
            measured: Vec::new(),
            server: None,
        };
        let msg = e(vec![(0, none)], 1);
        assert!(
            msg.contains("gave none") && msg.contains("create it again"),
            "{msg}"
        );
        let twice = vec![
            (1, volume(plain, root.path())),
            (1, volume(plain, root.path())),
        ];
        assert!(e(twice, 1).contains("image mount 1 twice"));
        let sixteen: Vec<_> = (0..16).map(|n| (n, volume(plain, root.path()))).collect();
        let msg = e(sixteen, 1);
        assert!(msg.contains("at most 15"), "{msg}");
        let fifteen: Vec<_> = (0..15).map(|n| (n, volume(plain, root.path()))).collect();
        assert_eq!(
            accept_volumes_t(b.path(), "c", "test", 1, fifteen)
                .unwrap()
                .len(),
            15
        );
        // (no place left in the monitor's 32)
        let two = vec![
            (0, volume(plain, root.path())),
            (1, volume(plain, root.path())),
        ];
        assert!(e(two, 31).contains("no place"));
        // a mount with a server takes the place after its own for the pidfd
        let served = |n: usize| {
            let mut r = volume(plain, root.path());
            r.server = Some(
                rustix::fs::open(
                    root.path(),
                    rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .unwrap(),
            );
            (n, r)
        };
        let fds = accept_volumes_t(b.path(), "c", "test", 1, vec![served(0), served(1)]).unwrap();
        assert_eq!(fds.len(), 4, "a mount and a pidfd, twice");
        let plans: Vec<_> = (0..2)
            .map(|n| velarx_fuse::plan::read(&b.path().join("imagevol"), &format!("{n}.")).unwrap())
            .collect();
        assert_eq!(
            plans,
            [
                Some(RootfsPlan::MountFd(MountFd {
                    fd_index: 1,
                    idmap: false,
                    server: true
                })),
                Some(RootfsPlan::MountFd(MountFd {
                    fd_index: 3,
                    idmap: false,
                    server: true
                })),
            ],
            "the second mount is after the first one's pidfd"
        );
        let e = e(vec![served(0)], 31);
        assert!(e.contains("no place"), "the pidfd needs a place too: {e}");
    }

    // the engine's start with a driver that has image volumes

    use crate::storage_driver::conformance::VolumeFake;
    use crate::storage_driver::{
        DriverParts, IdmapWay, Prefs, Purpose, StorageDriver, VerityAsk, Writable, WritableOptions,
    };
    use velarx_db::{Database, ImageRecord};
    use velarx_graph::MountsRequest;
    use velarx_types::digest::{Algorithm, Digest};

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn image() -> ImageRecord {
        ImageRecord {
            id: "img".into(),
            manifest_digest: Digest::of(Algorithm::Sha256, b"manifest"),
            config_digest: Digest::of(Algorithm::Sha256, b"config"),
            manifest: "{}".into(),
            config: "{}".into(),
            created_at: String::new(),
            is_lazy: false,
        }
    }

    fn mapping() -> velarx_fuse::IdTranslate {
        let one = || {
            vec![velarx_proto::pod::IdMapping {
                container_id: 0,
                host_id: 100_000,
                size: 65_536,
            }]
        };
        velarx_fuse::IdTranslate {
            uid: one(),
            gid: one(),
            squash: false,
        }
    }

    /// A container, its bundle and the test driver (the vfs driver with the
    /// volumes of a test-only wrapper: the root is a descriptor of the layer
    /// with `root_fd`, the directory of the copy without).
    struct Start {
        _dir: tempfile::TempDir,
        driver: Arc<dyn StorageDriver>,
        bundle: std::path::PathBuf,
        w: Writable,
        image: ImageRecord,
    }

    impl Start {
        async fn new(ways: Prefs<IdmapWay>, root_fd: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let db = Database::open(dir.path().join("db")).await.unwrap();
            let store =
                Arc::new(velarx_storage::FileStore::new(dir.path().join("objects")).unwrap());
            let vfs = velarx_vfs::VfsDriver::new(DriverParts {
                db,
                store,
                staging_dir: dir.path().join("staging"),
                fsverity: velarx_storage::VerityMode::Off,
            });
            let driver: Arc<dyn StorageDriver> =
                Arc::new(VolumeFake::new(Arc::new(vfs), ways, root_fd));
            let bundle = dir.path().join("bundle");
            std::fs::create_dir_all(&bundle).unwrap();
            let w = Writable::new(ID, &bundle);
            driver
                .writable_create(&w, None, &WritableOptions::default(), None)
                .unwrap();
            Self {
                _dir: dir,
                driver,
                bundle,
                w,
                image: image(),
            }
        }

        fn ask<'a>(
            &'a self,
            purpose: Purpose,
            mapping: Option<&'a velarx_fuse::IdTranslate>,
            idmap_mount: bool,
        ) -> MountRequest<'a> {
            MountRequest {
                translate: None,
                container: &self.w,
                purpose,
                image: &self.image,
                layers: &[],
                mapping,
                idmap_mount,
                label: None,
                verity: VerityAsk::Off,
                volatile: false,
            }
        }

        /// What `create` does: the driver makes the volumes, and the plans of
        /// the root and of each volume are written from the answer (the
        /// descriptors are dropped: the start asks again).
        fn create(&self, volumes: u32, root_plan: bool) {
            for n in 0..volumes {
                self.driver
                    .image_volume_create(&self.ask(Purpose::Volume { index: n }, None, false))
                    .unwrap();
            }
            let answer = self
                .driver
                .mounts(&MountsRequest {
                    root: root_plan.then(|| self.ask(Purpose::Root, None, false)),
                    volumes: (0..volumes)
                        .map(|n| self.ask(Purpose::Volume { index: n }, None, false))
                        .collect(),
                })
                .unwrap();
            if let Some(r) = &answer.root {
                velarx_fuse::plan::write(&self.bundle, "", &plan_of(&r.plan, r.idmap, false))
                    .unwrap();
            }
            std::fs::create_dir_all(self.bundle.join("imagevol")).unwrap();
            for (n, v) in answer.volumes.iter().enumerate() {
                velarx_fuse::plan::write(
                    &self.bundle.join("imagevol"),
                    &format!("{n}."),
                    &plan_of(&v.plan, v.idmap, false),
                )
                .unwrap();
            }
        }

        /// What `fresh_mounts` does for a container of `volumes` image mounts
        /// (root: made of layers, or a `--rootfs` when not), with the mapping
        /// the container has and what the monitor may do with it.
        fn start(
            &self,
            volumes: u32,
            from_layers: bool,
            mapping: Option<&velarx_fuse::IdTranslate>,
            idmap_mount: bool,
        ) -> ContainerResult<Vec<Arc<OwnedFd>>> {
            let Some(needs) = needs(&self.bundle, from_layers, volumes as usize)? else {
                return Ok(Vec::new());
            };
            let root = needs.expects_fd.then(|| {
                (
                    self.ask(Purpose::Root, mapping, idmap_mount),
                    needs.expects_fd,
                )
            });
            let vols = (0..volumes)
                .map(|n| self.ask(Purpose::Volume { index: n }, mapping, idmap_mount))
                .collect();
            start_mounts(&*self.driver, &self.bundle, &self.w, root, vols).map(|a| a.fds)
        }

        fn plan(&self, volume: Option<u32>) -> Option<RootfsPlan> {
            match volume {
                None => velarx_fuse::plan::read(&self.bundle, ""),
                Some(n) => velarx_fuse::plan::read(&self.bundle.join("imagevol"), &format!("{n}.")),
            }
            .unwrap()
        }
    }

    fn mount_plan(index: u32, idmap: bool) -> Option<RootfsPlan> {
        Some(RootfsPlan::MountFd(MountFd {
            server: false,
            fd_index: index,
            idmap,
        }))
    }

    /// Create, start, stop, start again, an engine that was restarted (it knows
    /// only the bundle), a restore: each start has a root and two volumes, each
    /// with a descriptor of its own, the root's first and then the volumes' in
    /// the order of their index, and the plans the monitor reads say where.
    #[tokio::test]
    async fn every_start_has_a_new_descriptor_for_the_root_and_each_volume() {
        let x = Start::new(Prefs::new(&[IdmapWay::AtCopy]), true).await;
        x.create(2, true);
        let mut held = Vec::new();
        for _ in 0..5 {
            let fds = x.start(2, true, None, false).expect("a start");
            assert_eq!(fds.len(), 3, "the root and the two volumes");
            assert_eq!(x.plan(None), mount_plan(0, false));
            assert_eq!(x.plan(Some(0)), mount_plan(1, false));
            assert_eq!(x.plan(Some(1)), mount_plan(2, false));
            for f in &fds {
                let st = rustix::fs::fstat(f.as_fd()).unwrap();
                assert_eq!(
                    rustix::fs::FileType::from_raw_mode(st.st_mode),
                    rustix::fs::FileType::Directory
                );
            }
            held.extend(fds);
        }
        // (all open at once: all different)
        let mut raw: Vec<_> = held.iter().map(|f| f.as_raw_fd()).collect();
        raw.sort_unstable();
        raw.dedup();
        assert_eq!(raw.len(), 15, "a descriptor of its own at each start");
    }

    /// The image mounts are asked for whatever the root is: a root that is a
    /// directory of the driver, a `--rootfs` (the early return of the first
    /// version asked for them only when the root was a descriptor too).  They
    /// are numbered from 0 when the root has no descriptor.
    #[tokio::test]
    async fn the_volumes_are_asked_for_whatever_the_root_is() {
        let x = Start::new(Prefs::new(&[IdmapWay::AtCopy]), false).await;
        x.create(2, true);
        assert!(
            matches!(x.plan(None), Some(RootfsPlan::Directory(_))),
            "the root of this driver is a directory"
        );
        let root_plan = x.plan(None);
        let needs_of = |layers| needs(&x.bundle, layers, 2).unwrap();
        assert_eq!(needs_of(true), Some(Needs { expects_fd: false }));
        assert_eq!(
            needs_of(false),
            Some(Needs { expects_fd: false }),
            "a --rootfs has image mounts too"
        );
        // nothing to ask: a root that is no descriptor and no image mount
        assert_eq!(needs(&x.bundle, true, 0).unwrap(), None);
        for from_layers in [true, false] {
            let fds = x.start(2, from_layers, None, false).unwrap();
            assert_eq!(fds.len(), 2, "one descriptor for each volume");
            assert_eq!(x.plan(Some(0)), mount_plan(0, false));
            assert_eq!(x.plan(Some(1)), mount_plan(1, false));
            assert_eq!(x.plan(None), root_plan, "the root's plan is not touched");
        }
        // no image mounts and a directory root: no call at all
        assert!(x.start(0, true, None, false).unwrap().is_empty());
    }

    /// A root that is a mount of the driver is asked at every start; never a
    /// `--rootfs`, and not a root of another kind.  Its image mounts are asked
    /// at every start all the same, numbered from 0, and a plan of the root that
    /// is not asked is not touched.
    #[tokio::test]
    async fn a_mount_root_has_its_volumes_asked() {
        let x = Start::new(Prefs::new(&[IdmapWay::AtCopy]), true).await;
        x.create(2, true);
        let asked = |layers, n| needs(&x.bundle, layers, n).unwrap();
        assert_eq!(asked(true, 2), Some(Needs { expects_fd: true }));
        assert_eq!(asked(true, 0), Some(Needs { expects_fd: true }));
        assert_eq!(asked(false, 0), None, "never a --rootfs");
        let fds = x.start(2, true, None, false).unwrap();
        assert_eq!(fds.len(), 3);
        assert_eq!(x.plan(None), mount_plan(0, false));
        assert_eq!(x.plan(Some(0)), mount_plan(1, false));
        assert_eq!(x.plan(Some(1)), mount_plan(2, false));
    }

    /// A container with no user namespace of its own asks for no mapping (the
    /// engine's translation of it is the identity of the ids it was granted,
    /// which is no mapping to put on a mount): nothing is mapped, and the plans
    /// say the monitor puts nothing on the mounts, whatever the driver can.
    #[tokio::test]
    async fn a_container_without_a_user_namespace_gets_no_idmap() {
        let x = Start::new(
            Prefs::new(&[IdmapWay::MonitorMount, IdmapWay::AtCopy]),
            true,
        )
        .await;
        x.create(2, true);
        let fds = x.start(2, true, None, false).unwrap();
        assert_eq!(fds.len(), 3);
        for plan in [x.plan(None), x.plan(Some(0)), x.plan(Some(1))] {
            assert!(
                matches!(plan, Some(RootfsPlan::MountFd(m)) if !m.idmap),
                "{plan:?}"
            );
        }
    }

    /// With a user namespace of its own the driver maps: by the monitor
    /// (`idmap: true` in the plan of each volume, and only of the volumes: the
    /// root of the test driver is mapped by the driver) when the engine allows
    /// it and the driver prefers it, by itself when the engine does not (rootless).
    #[tokio::test]
    async fn the_idmap_result_is_what_the_plan_says() {
        let map = mapping();
        let x = Start::new(
            Prefs::new(&[IdmapWay::MonitorMount, IdmapWay::AtCopy]),
            true,
        )
        .await;
        x.create(2, true);
        x.start(2, true, Some(&map), true).unwrap();
        assert_eq!(x.plan(None), mount_plan(0, false));
        assert_eq!(x.plan(Some(0)), mount_plan(1, true));
        assert_eq!(x.plan(Some(1)), mount_plan(2, true));
        // an engine that is not root of the initial user namespace: the driver
        // applies the mapping itself, and the monitor puts none
        x.start(2, true, Some(&map), false).unwrap();
        assert_eq!(x.plan(Some(0)), mount_plan(1, false));
        assert_eq!(x.plan(Some(1)), mount_plan(2, false));
        // a driver with no way to map the ids of a volume: refused at create
        let none = Start::new(Prefs::new(&[]), true).await;
        let e = none
            .driver
            .image_volume_create(&none.ask(Purpose::Volume { index: 0 }, Some(&map), false))
            .unwrap_err();
        assert!(matches!(e.kind, velarx_graph::DriverErrorKind::Unsupported));
    }

    /// The plan files of an earlier start are never read: each start writes
    /// every volume's again.  A volume of an earlier start (a mount with an
    /// idmap) becomes the mount of this start.
    #[tokio::test]
    async fn the_plans_of_an_earlier_start_are_written_again() {
        let x = Start::new(Prefs::new(&[IdmapWay::AtCopy]), false).await;
        x.create(2, true);
        let dir = x.bundle.join("imagevol");
        for (n, index, idmap) in [("0.", 5, false), ("1.", 7, true)] {
            velarx_fuse::plan::write(
                &dir,
                n,
                &RootfsPlan::MountFd(MountFd {
                    server: false,
                    fd_index: index,
                    idmap,
                }),
            )
            .unwrap();
        }
        x.start(2, true, None, false).unwrap();
        assert_eq!(x.plan(Some(0)), mount_plan(0, false));
        assert_eq!(x.plan(Some(1)), mount_plan(1, false));
    }

    /// The image mounts a driver hands over as descriptors are counted at
    /// create: one more than a monitor takes is refused there, and the other
    /// kinds of plan are not counted.
    #[test]
    fn too_many_descriptor_volumes_are_refused_at_create() {
        let fd = velarx_graph::Planned {
            plan: RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            }),
            idmap: IdmapDone::None,
            label: LabelDone::None,
        };
        let dir = velarx_graph::Planned {
            plan: RootfsPlan::Directory(Directory {
                beneath: "/".into(),
                path: "x".into(),
            }),
            ..fd.clone()
        };
        let mut n = 0;
        for _ in 0..velarx_fuse::plan::MAX_VOLUME_FDS {
            count_volume_fd("d", &fd, &mut n).unwrap();
            count_volume_fd("d", &dir, &mut n).unwrap();
        }
        assert_eq!(n, velarx_fuse::plan::MAX_VOLUME_FDS as usize);
        let e = count_volume_fd("d", &fd, &mut n).unwrap_err().to_string();
        assert!(
            e.contains(&format!("at most {}", velarx_fuse::plan::MAX_VOLUME_FDS))
                && e.contains("storage driver d"),
            "{e}"
        );
    }

    /// A label that the driver says is on a mount while none was asked is
    /// refused; one that was asked is taken, however it was put.
    #[test]
    fn a_label_that_was_not_asked_is_refused() {
        let b = tempfile::tempdir().unwrap();
        let plan = MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        };
        let with = |label: LabelDone| {
            let mut r = volume(plan, std::path::Path::new("/"));
            r.label = label;
            r
        };
        let asked = Ask {
            label: true,
            ..PLAIN
        };
        for done in [LabelDone::MountContext, LabelDone::Files] {
            let msg = accept_volumes(b.path(), ID, "test", 1, vec![(0, PLAIN, with(done))])
                .unwrap_err()
                .to_string();
            assert!(msg.contains("none was asked"), "{msg}");
            accept_volumes(b.path(), ID, "test", 1, vec![(0, asked, with(done))]).unwrap();
        }
        // (an asked label that the driver did not put anywhere is the
        // engine's to put on the files of a root, but not of an image mount,
        // which it cannot label: refused)
        let msg = accept_volumes(
            b.path(),
            ID,
            "test",
            1,
            vec![(0, asked, with(LabelDone::None))],
        )
        .unwrap_err()
        .to_string();
        assert!(
            msg.contains("does not put the container's SELinux label"),
            "{msg}"
        );
    }

    /// With the digests enforced a mount the driver hands over must say that
    /// it enforces them, with the digest it measured on every layer, each
    /// one the manifest accepts; a plan the monitor mounts (a directory) states none.
    /// A driver that enforces what was not asked, or hands over a process
    /// that serves what is no mount descriptor, is refused.
    #[test]
    fn a_mount_handed_over_for_enforced_digests_carries_what_it_measured() {
        let b = tempfile::tempdir().unwrap();
        let plan = MountFd {
            server: false,
            fd_index: 0,
            idmap: false,
        };
        let lists = vec![
            vec!["sha256:a1".to_string(), "sha256:a2".to_string()],
            vec!["sha256:b1".to_string()],
        ];
        let enforced = Ask {
            verity: VerityAsk::Enforce {
                accepted: &lists,
                chain: None,
            },
            ..PLAIN
        };
        let kernel = |measured: &[&str]| {
            let mut r = volume(plan, std::path::Path::new("/"));
            r.verity = VerityDone::Kernel;
            r.measured = measured.iter().map(|m| m.to_string()).collect();
            r
        };
        let accept = |ask: Ask, r: Rootfs| {
            accept_volumes(b.path(), ID, "test", 1, vec![(0, ask, r)]).map_err(|e| e.to_string())
        };
        accept(enforced, kernel(&["sha256:a2", "sha256:b1"])).unwrap();
        // not enforced: nothing is said
        let e = accept(PLAIN, kernel(&["sha256:a1", "sha256:b1"])).unwrap_err();
        assert!(e.contains("they are not enforced"), "{e}");
        // a mount that enforces none while they are
        let e = accept(enforced, volume(plan, std::path::Path::new("/"))).unwrap_err();
        assert!(e.contains("enforces none"), "{e}");
        // a digest the manifest does not accept, a layer missing
        let e = accept(enforced, kernel(&["sha256:a1", "sha256:zz"])).unwrap_err();
        assert!(
            e.contains("layer 2") && e.contains("sha256:zz") && e.contains("do not accept"),
            "{e}"
        );
        let e = accept(enforced, kernel(&["sha256:a1"])).unwrap_err();
        assert!(e.contains("measured 1 images"), "{e}");
        // a plan the monitor mounts (a directory) has no digest to measure
        let check = |ask: Ask, r: &Rootfs| {
            check_verity(ID, "test", "root file system", &ask, r).map_err(|e| e.to_string())
        };
        let directory = || {
            Rootfs::from(RootfsPlan::Directory(Directory {
                beneath: "/b".into(),
                path: "r".into(),
            }))
        };
        check(enforced, &directory()).unwrap();
        let mut said = directory();
        said.verity = VerityDone::Kernel;
        let e = check(enforced, &said).unwrap_err();
        assert!(e.contains("the monitor mounts"), "{e}");
        // checked on open, with no process that checks
        let mut on_open = kernel(&["sha256:a1", "sha256:b1"]);
        on_open.verity = VerityDone::OnOpen;
        let e = accept(enforced, on_open).unwrap_err();
        assert!(e.contains("gave none"), "{e}");
        // checked on open by the process that serves the mount: it is taken
        // with the digests it measured, as the kernel's check is
        let server = || {
            rustix::fs::open(
                "/",
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap()
        };
        let mut on_open = kernel(&["sha256:a1", "sha256:b1"]);
        on_open.verity = VerityDone::OnOpen;
        on_open.server = Some(server());
        accept(enforced, on_open).unwrap();
        let mut on_open = kernel(&["sha256:a1", "sha256:zz"]);
        on_open.verity = VerityDone::OnOpen;
        on_open.server = Some(server());
        let e = accept(enforced, on_open).unwrap_err();
        assert!(e.contains("do not accept"), "{e}");
        // and not when the digests are not enforced
        let mut on_open = kernel(&[]);
        on_open.verity = VerityDone::OnOpen;
        on_open.server = Some(server());
        let e = accept(PLAIN, on_open).unwrap_err();
        assert!(e.contains("they are not enforced"), "{e}");
        // a process that serves what the monitor mounts itself: there is no
        // descriptor for the pidfd to follow
        let mut served = directory();
        served.server = Some(server());
        let e = check(PLAIN, &served).unwrap_err();
        assert!(e.contains("no mount descriptor"), "{e}");
    }

    /// The root file system that a server serves is passed with the pidfd of
    /// the server next, and the plan the monitor reads says so; a root
    /// without a server is passed as before.
    #[test]
    fn the_pidfd_of_a_server_follows_the_mount_it_serves() {
        let root = tempfile::tempdir().unwrap();
        let pidfd = || {
            rustix::fs::open(
                root.path(),
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .unwrap()
        };
        for server in [false, true] {
            let b = bundle(&RootfsPlan::MountFd(MountFd {
                fd_index: 0,
                idmap: false,
                server: false,
            }));
            let mut r = driver_root(root.path());
            r.server = server.then(pidfd);
            let fds = accept_root(b.path(), ID, "test", true, &PLAIN, r).unwrap();
            assert_eq!(fds.len(), 1 + usize::from(server));
            let plan = velarx_fuse::plan::read(b.path(), "").unwrap();
            assert_eq!(
                plan,
                Some(RootfsPlan::MountFd(MountFd {
                    fd_index: 0,
                    idmap: false,
                    server
                })),
                "server {server}"
            );
        }
    }

    /// What the engine refuses in an answer, with the reason.
    #[test]
    fn an_answer_that_contradicts_the_request_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let e = |ask: Ask, r: Rootfs| {
            accept_volumes(b.path(), ID, "test", 1, vec![(0, ask, r)])
                .unwrap_err()
                .to_string()
        };
        let mapped = Ask {
            verity: VerityAsk::Off,
            mapped: true,
            idmap_mount: true,
            label: false,
        };
        // the monitor is left to map when it was not allowed to
        let mut r = volume(
            MountFd {
                server: false,
                fd_index: 0,
                idmap: true,
            },
            root.path(),
        );
        let msg = e(PLAIN, r);
        assert!(msg.contains("which it was not asked to do"), "{msg}");
        // a mapping asked and none done
        r = volume(
            MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            },
            root.path(),
        );
        let msg = e(mapped, r);
        assert!(msg.contains("maps no ids"), "{msg}");
        // `mount` with a plan that puts no idmap on the mount
        let mut r = volume(
            MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            },
            root.path(),
        );
        r.idmap = IdmapDone::Mount;
        let msg = e(mapped, r);
        assert!(msg.contains("does not ask the monitor"), "{msg}");
        // a plan that maps and an answer that says the driver did
        let mut r = volume(
            MountFd {
                server: false,
                fd_index: 0,
                idmap: true,
            },
            root.path(),
        );
        r.idmap = IdmapDone::Applied;
        let msg = e(mapped, r);
        assert!(msg.contains("asks the monitor to map"), "{msg}");
        // a mapping said done when none was asked
        let mut r = volume(
            MountFd {
                server: false,
                fd_index: 0,
                idmap: false,
            },
            root.path(),
        );
        r.idmap = IdmapDone::Applied;
        let msg = e(PLAIN, r);
        assert!(msg.contains("no mapping was asked"), "{msg}");
        // nothing was written
        assert!(!b.path().join("imagevol").exists());
        // the root has the same rules
        let r = volume(
            MountFd {
                server: false,
                fd_index: 0,
                idmap: true,
            },
            root.path(),
        );
        let msg = accept_root(b.path(), ID, "test", true, &PLAIN, r)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("root file system"), "{msg}");
    }

    /// A descriptor of the driver, and whether it is closed (the read end of a
    /// pipe sees its end only when every write end is closed).
    fn tracked() -> (OwnedFd, impl Fn(bool) -> bool) {
        use rustix::pipe::PipeFlags;
        let (r, w) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK).unwrap();
        // (a test that runs at the same time and forks holds a copy of the
        // write end until its child execs: a close is waited for a while, an
        // open end is told at once)
        (w, move |wait: bool| {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                if matches!(rustix::io::read(&r, &mut [0u8; 1]), Ok(0)) {
                    return true;
                }
                if !wait || std::time::Instant::now() > until {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        })
    }

    fn with_fd(plan: RootfsPlan, fd: OwnedFd) -> Rootfs {
        Rootfs {
            plan,
            fd: Some(fd),
            idmap: IdmapDone::None,
            label: velarx_graph::LabelDone::None,
            verity: velarx_graph::VerityDone::None,
            measured: Vec::new(),
            server: None,
        }
    }

    /// An answer that is refused closes every descriptor that came with it:
    /// the ones of mounts already accepted (the root, an earlier volume) and
    /// the ones not looked at yet.
    #[test]
    fn a_refused_answer_closes_every_descriptor() {
        let b = tempfile::tempdir().unwrap();
        let mount = |i| {
            RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: i,
                idmap: false,
            })
        };
        // fewer answers than asked
        let (root, root_closed) = tracked();
        let (v0, v0_closed) = tracked();
        let answer = Mounts {
            root: Some(with_fd(mount(0), root)),
            volumes: vec![with_fd(mount(0), v0)],
        };
        let asked = [(0, PLAIN), (1, PLAIN)];
        accept_mounts(b.path(), ID, "test", Some((&PLAIN, true)), &asked, answer).unwrap_err();
        assert!(root_closed(true) && v0_closed(true));
        // the root and the first volume accepted, the second refused (a
        // directory), the third not looked at
        let (root, root_closed) = tracked();
        let (v0, v0_closed) = tracked();
        let (v1, v1_closed) = tracked();
        let (v2, v2_closed) = tracked();
        let answer = Mounts {
            root: Some(with_fd(mount(0), root)),
            volumes: vec![
                with_fd(mount(0), v0),
                with_fd(
                    RootfsPlan::Directory(Directory {
                        beneath: "/b".into(),
                        path: "r".into(),
                    }),
                    v1,
                ),
                with_fd(mount(0), v2),
            ],
        };
        let asked = [(0, PLAIN), (1, PLAIN), (2, PLAIN)];
        let e = accept_mounts(b.path(), ID, "test", Some((&PLAIN, true)), &asked, answer)
            .unwrap_err()
            .to_string();
        assert!(e.contains("as a directory"), "{e}");
        assert!(root_closed(true) && v0_closed(true) && v1_closed(true) && v2_closed(true));
        // a root refused: the volumes go too
        let (root, root_closed) = tracked();
        let (v0, v0_closed) = tracked();
        let mut r = with_fd(
            RootfsPlan::MountFd(MountFd {
                server: false,
                fd_index: 0,
                idmap: true,
            }),
            root,
        );
        r.idmap = IdmapDone::Mount;
        let answer = Mounts {
            root: Some(r),
            volumes: vec![with_fd(mount(0), v0)],
        };
        accept_mounts(
            b.path(),
            ID,
            "test",
            Some((&PLAIN, true)),
            &[(0, PLAIN)],
            answer,
        )
        .unwrap_err();
        assert!(root_closed(true) && v0_closed(true));
        // (and an accepted answer keeps them open, for the monitor)
        let (root, root_closed) = tracked();
        let answer = Mounts {
            root: Some(with_fd(mount(0), root)),
            volumes: Vec::new(),
        };
        let fds = accept_mounts(b.path(), ID, "test", Some((&PLAIN, true)), &[], answer).unwrap();
        assert!(!root_closed(false));
        drop(fds);
        assert!(root_closed(true));
    }

    /// The answer must have as many mounts as were asked, and a root only when
    /// it was asked.
    #[test]
    fn the_answer_has_what_was_asked() {
        let root = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ask = &[(0, PLAIN)];
        let none = || Mounts::default();
        let e = |root_ask: Option<(&Ask, bool)>, volumes: &[(usize, Ask)], a: Mounts| {
            accept_mounts(b.path(), ID, "test", root_ask, volumes, a)
                .unwrap_err()
                .to_string()
        };
        assert!(e(None, ask, none()).contains("0 image mounts for the 1 asked"));
        assert!(e(Some((&PLAIN, true)), &[], none()).contains("no root file system"));
        let with_root = Mounts {
            root: Some(driver_root(root.path())),
            volumes: Vec::new(),
        };
        assert!(e(None, &[], with_root).contains("which was not asked"));
    }

    /// A container without a user namespace of its own never gets an idmapped
    /// mount, whoever the engine is.
    #[test]
    fn only_a_container_with_its_own_user_namespace_may_have_a_mount_idmapped() {
        assert!(!may_idmap_mounts(false));
        assert_eq!(
            may_idmap_mounts(true),
            velarx_base::ids::rootful().unwrap_or(false)
        );
    }
}
