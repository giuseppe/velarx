// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::io;

/// The uid and gid mappings of a container's user namespace; empty ones
/// when it has none.  They always travel together.
#[derive(Clone, Copy)]
pub(super) struct IdMaps<'a> {
    pub uid: &'a [IdMapping],
    pub gid: &'a [IdMapping],
}

impl IdMaps<'_> {
    /// The host ids of the container's root, when both are mapped.
    fn host_root(&self) -> Option<(u32, u32)> {
        velarx_base::idmap::to_parent(self.uid, 0).zip(velarx_base::idmap::to_parent(self.gid, 0))
    }
}

/// The user of a container: `--user`, else the `User` of the image; `:GID`
/// (the runAsGroup of a pod without runAsUser) is the user of the image with
/// that group.
pub(super) fn effective_user(requested: &str, image: &str) -> String {
    match requested.strip_prefix(':') {
        _ if requested.is_empty() => image.to_string(),
        Some(group) => {
            let user = image
                .split(':')
                .next()
                .filter(|u| !u.is_empty())
                .unwrap_or("0");
            format!("{user}:{group}")
        }
        None => requested.to_string(),
    }
}

/// The labels of a container: the image's under the user's, as podman's
/// containers carry them; the unit `auto-update` restarts is never an
/// image's.
pub(super) fn container_labels(
    image: &HashMap<String, String>,
    requested: &std::collections::BTreeMap<String, String>,
) -> HashMap<String, String> {
    image
        .iter()
        .filter(|(k, _)| k.as_str() != "PODMAN_SYSTEMD_UNIT")
        .chain(requested)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// A file of the bundle that is bind mounted on `dest` in the container.
/// The files of the bundle mounted on /etc/hosts, /etc/hostname and
/// /etc/resolv.conf.
pub const ETC_HOSTS: &str = "hosts";

pub const ETC_HOSTNAME: &str = "hostname";

pub const ETC_RESOLV: &str = "resolv.conf";

/// Whether the container keeps the /etc/resolv.conf of its image, as
/// podman's: one with no network (`--network none`) has no name server to
/// be given, and it takes no DNS settings.
pub fn keeps_image_resolv_conf(req: &CreateContainerRequest) -> bool {
    req.has_network_mode(&NetworkMode::Off)
}

/// The /etc files of the container whose network namespace a new one joins.
pub(super) struct InheritedEtc {
    /// Its bundle
    dir: PathBuf,
    /// Its resolv.conf, to copy
    resolv_text: Option<String>,
    /// The new container mounts its files instead of copies
    share_resolv: bool,
    share_hosts: bool,
}

/// Where the /etc/hosts of a container is: the file of its bundle.
pub(super) fn hosts_file(bundle_path: &Path) -> Option<(PathBuf, &'static str)> {
    bundle_path
        .join(ETC_HOSTS)
        .exists()
        .then(|| (bundle_path.to_path_buf(), ETC_HOSTS))
}

/// `rel` below `base`, without following a link out of it.
pub(super) fn open_beneath(
    base: &Path,
    rel: &str,
    flags: rustix::fs::OFlags,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    let dir = rustix::fs::open(
        base,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(velarx_sys::fs::openat2_retry(
        dir.as_fd(),
        rel,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )?)
}

/// The user of a new container, resolved with the passwd and group files of
/// its image, and the entries the image lacks for it (`None`: no change).
pub(super) struct ContainerUser {
    pub(super) user: crate::container::userspec::ResolvedUser,
    pub(super) passwd: Option<String>,
    pub(super) group: Option<String>,
}

/// `identity` is the name and home of the passwd entry for a user the
/// image lacks (`--userns=keep-id` gives those of the user on the host).
pub(super) fn resolve_container_user(
    passwd: &str,
    group: &str,
    config: &ContainerConfig,
    req: &CreateContainerRequest,
    identity: Option<(&str, &str)>,
) -> Result<ContainerUser, crate::container::userspec::UserError> {
    use crate::container::userspec;
    let user = userspec::resolve_user_groups(
        passwd,
        group,
        &config.user,
        &config.group_add,
        config.groups_strict,
    )?;
    let wants_entries =
        !config.user.is_empty() || req.passwd_entry.is_some() || req.group_entry.is_some();
    let (passwd, group) = if wants_entries && !req.no_passwd {
        let opts = userspec::EntryOptions {
            passwd_template: req.passwd_entry.as_deref(),
            group_template: req.group_entry.as_deref(),
            identity,
        };
        userspec::added_entries(passwd, group, &user, &config.working_dir, &opts)?
    } else {
        (None, None)
    };
    Ok(ContainerUser {
        user,
        passwd,
        group,
    })
}

/// [`resolve_container_user`], but a user or group the image has no entry
/// for is not an error here: podman makes the container and its start says
/// so.  The error is given back, and the user is then root.  (Not inlined: a
/// create is a large future already.)
#[inline(never)]
pub(super) fn resolve_container_user_later(
    passwd: &str,
    group: &str,
    config: &ContainerConfig,
    req: &CreateContainerRequest,
    identity: Option<(&str, &str)>,
) -> ContainerResult<(ContainerUser, Option<String>)> {
    use crate::container::userspec::UserError;
    match resolve_container_user(passwd, group, config, req, identity) {
        Err(e @ (UserError::NoUser(_) | UserError::NoGroup(_))) => {
            let mut plain = config.clone();
            plain.user.clear();
            plain.group_add.clear();
            let user = resolve_container_user(passwd, group, &plain, req, identity)?;
            Ok((user, Some(e.to_string())))
        }
        other => Ok((other?, None)),
    }
}

/// The root file system an entry is written into, as podman edits the
/// `/etc/passwd` of a container that is not read-only: the container's
/// writable root, so that the file is the container's own (not a bind
/// mount, `adduser` can rename over it) and `diff` and `commit` see it.
///
/// The root is the descriptor the driver gives (`StorageDriver::writable_root`):
/// every name is opened relative to it, beneath it, without following a link
/// (`openat2`), so no path of the host is resolved while the files are
/// written, and a link that the container's image or a racing process put at
/// `/etc` leads nowhere.
pub(super) struct WritableRoot<'a> {
    pub(super) view: &'a dyn velarx_fuse::view::ImageTree,
    pub(super) translate: &'a velarx_fuse::IdTranslate,
    /// The root of the driver's writable layer.
    pub(super) root: std::os::fd::BorrowedFd<'a>,
}

/// `/etc` of the root, as the image has it: opened, or made with the mode and
/// owner of the image's when the layer has none yet (the directory of the
/// writable layer is the merged one: as in the image).
fn etc_in_root(
    root: &WritableRoot<'_>,
    dir: &velarx_storage::TocEntry,
) -> ContainerResult<std::os::fd::OwnedFd> {
    use rustix::fs::{Mode, RawMode};
    use velarx_sys::fs::{open_beneath, Beneath, BeneathError};
    let etc = Path::new("etc");
    match open_beneath(root.root, etc, Beneath::Directory) {
        Ok(fd) => return Ok(fd),
        Err(BeneathError::Errno(rustix::io::Errno::NOENT)) => {}
        Err(e) => return Err(io::Error::from(e).into()),
    }
    let mode = dir.mode & 0o7777;
    match rustix::fs::mkdirat(root.root, etc, Mode::from_raw_mode(mode as RawMode)) {
        // (made meanwhile: it is the directory the next open finds)
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(io::Error::from(e).into()),
    }
    let fd = open_beneath(root.root, etc, Beneath::Directory).map_err(io::Error::from)?;
    // (`mkdirat` takes the umask off: the image's mode is the mode)
    rustix::fs::fchmod(&fd, Mode::from_raw_mode(mode as RawMode)).map_err(io::Error::from)?;
    let (u, g) = owner_of(root, dir);
    rustix::fs::fchown(
        &fd,
        u.map(rustix::fs::Uid::from_raw),
        g.map(rustix::fs::Gid::from_raw),
    )
    .map_err(io::Error::from)?;
    Ok(fd)
}

/// The owner of a file of the image on the host, as the container's mapping
/// has it.
fn owner_of(root: &WritableRoot<'_>, e: &velarx_storage::TocEntry) -> (Option<u32>, Option<u32>) {
    (
        velarx_base::idmap::to_parent(&root.translate.uid, e.uid),
        velarx_base::idmap::to_parent(&root.translate.gid, e.gid),
    )
}

/// Write `content` as `/etc/<name>` in the writable root of the container
/// when the image has a regular file there (its mode and owner stay): false
/// when it has not, or `/etc` is not a directory (a link, ...), and the
/// file is bind mounted.
fn write_in_upper(root: &WritableRoot<'_>, name: &str, content: &str) -> ContainerResult<bool> {
    use rustix::fs::{Mode, OFlags, RawMode, ResolveFlags};
    use velarx_storage::TocEntryType;
    let entry = |path: &str, kind: TocEntryType| {
        let node = root.view.resolve(path).and_then(|n| root.view.node(n))?;
        (node.entry.entry_type == kind).then_some(node.entry)
    };
    let (Some(dir), Some(file)) = (
        entry("etc", TocEntryType::Dir),
        entry(&format!("etc/{name}"), TocEntryType::Reg),
    ) else {
        return Ok(false);
    };
    let etc = etc_in_root(root, &dir)?;
    // (the name is one component: no link, no way out of `/etc`; a fifo
    // without a reader is `ENXIO` instead of a wait, a terminal does not
    // become the engine's, and what is not a regular file is refused before
    // a byte is written)
    let fd = velarx_sys::fs::openat2_retry(
        etc.as_fd(),
        name,
        OFlags::WRONLY
            | OFlags::CREATE
            | OFlags::TRUNC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::NOCTTY
            | OFlags::CLOEXEC,
        Mode::from_raw_mode((file.mode & 0o7777) as RawMode),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?;
    let st = rustix::fs::fstat(&fd).map_err(io::Error::from)?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(io::Error::other(format!(
            "/etc/{name} of the root file system is not a regular file"
        ))
        .into());
    }
    let mut f = fs::File::from(fd);
    std::io::Write::write_all(&mut f, content.as_bytes())?;
    let (u, g) = owner_of(root, &file);
    rustix::fs::fchown(
        &f,
        u.map(rustix::fs::Uid::from_raw),
        g.map(rustix::fs::Gid::from_raw),
    )
    .map_err(io::Error::from)?;
    Ok(true)
}

/// Write what the container lacks for its user (passwd and group entries,
/// /etc/localtime) in the bundle; the files are mounted before the mounts
/// of the user, which can replace them.  With a `root` (a writable root
/// file system), the passwd and group files are changed in it instead.
pub(super) fn add_user_files(
    config: &mut ContainerConfig,
    bundle_path: &Path,
    user: ContainerUser,
    localtime: Option<(&str, &[u8])>,
    root: Option<&WritableRoot<'_>>,
) -> ContainerResult<()> {
    let mut mounts = Vec::new();
    for (name, content) in [("passwd", user.passwd), ("group", user.group)] {
        if let Some(c) = content {
            if let Some(root) = root {
                if write_in_upper(root, name, &c)? {
                    continue;
                }
            }
            let dest = format!("/etc/{name}");
            mounts.push(bundle_file_mount(
                bundle_path,
                name,
                c.as_bytes(),
                &dest,
                false,
            )?);
        }
    }
    if let Some((zone, data)) = localtime {
        let linked = match root {
            Some(root) if zone != "local" => link_localtime_in_upper(root, zone)?,
            _ => false,
        };
        if !linked {
            mounts.push(bundle_file_mount(
                bundle_path,
                "localtime",
                data,
                "/etc/localtime",
                true,
            )?);
        }
    }
    config.process_user = Some(user.user);
    config.mounts.splice(0..0, mounts);
    Ok(())
}

/// `/etc/localtime` of a container with `--tz ZONE`, as podman makes it when
/// the image has the zone file: a link to it in the upper directory of the
/// container (false when it has not, or `/etc` is not a directory, and the
/// zone file of the host is bind mounted).
fn link_localtime_in_upper(root: &WritableRoot<'_>, zone: &str) -> ContainerResult<bool> {
    use velarx_storage::TocEntryType;
    let entry = |path: &str, kind: TocEntryType| {
        let node = root.view.resolve(path).and_then(|n| root.view.node(n))?;
        (node.entry.entry_type == kind).then_some(node.entry)
    };
    let (Some(dir), Some(_)) = (
        entry("etc", TocEntryType::Dir),
        root.view
            .resolve_following(&format!("usr/share/zoneinfo/{zone}"))
            .and_then(|n| root.view.node(n))
            .filter(|n| n.entry.entry_type == TocEntryType::Reg),
    ) else {
        return Ok(false);
    };
    let etc = etc_in_root(root, &dir)?;
    match rustix::fs::unlinkat(&etc, "localtime", rustix::fs::AtFlags::empty()) {
        Err(e) if e != rustix::io::Errno::NOENT => return Err(io::Error::from(e).into()),
        _ => {}
    }
    rustix::fs::symlinkat(format!("../usr/share/zoneinfo/{zone}"), &etc, "localtime")
        .map_err(io::Error::from)?;
    Ok(true)
}

/// The names of the user and group `uid:gid` on the host, for
/// `--userns=keep-id`.
pub(super) fn host_identity(uid: u32, gid: u32) -> Option<(String, String)> {
    let name_of = |file: &str, id: u32| -> Option<String> {
        std::fs::read_to_string(file).ok()?.lines().find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 3 && f[2].parse::<u32>().ok() == Some(id)).then(|| f[0].to_string())
        })
    };
    Some((name_of("/etc/passwd", uid)?, name_of("/etc/group", gid)?))
}

/// `/run/.containerenv`, which tools look for to know they run in a
/// container: empty for an unprivileged container (nothing about the host
/// leaks), the engine, name, id, image and whether it is rootless for a
/// privileged one, as podman writes it.  Not when the user mounts it, or a
/// /run of their own (a tmpfs of the engine is fine).
pub(super) fn add_containerenv(
    config: &mut ContainerConfig,
    bundle_path: &Path,
    image: &str,
    image_id: &str,
) -> ContainerResult<()> {
    let user_run = config.mounts.iter().any(|m| {
        m.target == "/run/.containerenv"
            || (m.target == "/run" && m.mount_type.as_deref() != Some("tmpfs"))
    });
    if user_run {
        return Ok(());
    }
    let content = if config.privileged {
        let rootless =
            !rustix::process::geteuid().is_root() || crate::userns::rootless::in_user_namespace()?;
        format!(
            "engine=\"velarx-{}\"\nname=\"{}\"\nid=\"{}\"\nimage=\"{}\"\nimageid=\"{}\"\nrootless={}\n",
            env!("CARGO_PKG_VERSION"),
            config.name.as_deref().unwrap_or(""),
            config.id,
            image,
            image_id,
            u8::from(rootless)
        )
    } else {
        String::new()
    };
    let mut m = bundle_file_mount(
        bundle_path,
        "containerenv",
        content.as_bytes(),
        "/run/.containerenv",
        config.read_only_rootfs,
    )?;
    if config.read_only_rootfs {
        m.options
            .extend(["nosuid", "noexec", "nodev"].map(String::from));
    }
    // after a tmpfs on /run of the user, which would hide it
    config.mounts.push(m);
    Ok(())
}

/// The zone file of `--tz` (`local` is the zone of the host), read now: the
/// container gets a copy.
pub(super) fn read_zoneinfo(tz: &str) -> ContainerResult<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    const ZONEINFO: &str = "/usr/share/zoneinfo";
    const MAX_ZONE_FILE: u64 = 1 << 20;
    let bad =
        |why: &str| ContainerError::InvalidArgument(format!("invalid timezone `{tz}`: {why}"));
    let (dir, name) = if tz == "local" {
        ("/etc", "localtime")
    } else {
        let valid = !tz.is_empty()
            && !tz.starts_with('/')
            && tz
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != "..")
            && tz
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_+-.".contains(&b));
        if !valid {
            return Err(bad("not a zone name"));
        }
        (ZONEINFO, tz)
    };
    let dirfd = rustix::fs::open(
        dir,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| bad(&e.to_string()))?;
    // /etc/localtime is a link into the zone files: it may leave /etc.
    let resolve = if tz == "local" {
        ResolveFlags::NO_MAGICLINKS
    } else {
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS
    };
    let fd = velarx_sys::fs::openat2_retry(
        dirfd.as_fd(),
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        resolve,
    )
    .map_err(|e| bad(&e.to_string()))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| bad(&e.to_string()))?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile {
        return Err(bad("not a zone file"));
    }
    let mut data = Vec::new();
    File::from(fd)
        .take(MAX_ZONE_FILE + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_ZONE_FILE || !data.starts_with(b"TZif") {
        return Err(bad("not a zone file"));
    }
    Ok(data)
}

/// What the root file system of a container is asked with at create, owned so
/// that the blocking pool may take it.
pub(super) struct RootAsk {
    pub mapping: Option<velarx_fuse::IdTranslate>,
    /// How the owners of the files are shown (the mapping, else the ids the
    /// engine has): the driver refuses owners outside it at the create
    /// already, as at each start.
    pub translate: velarx_fuse::IdTranslate,
    pub idmap_mount: bool,
    pub label: Option<String>,
    /// The digests accepted for each layer, when they are enforced.
    pub accepted: Option<Vec<Vec<String>>>,
    pub volatile: bool,
}

impl RootAsk {
    fn request<'a>(
        &'a self,
        container: &'a Writable,
        image: &'a velarx_db::ImageRecord,
        layers: &'a [LayerRecord],
    ) -> velarx_graph::MountRequest<'a> {
        velarx_graph::MountRequest {
            container,
            purpose: velarx_graph::Purpose::Root,
            image,
            layers,
            mapping: self.mapping.as_ref(),
            translate: Some(&self.translate),
            idmap_mount: self.idmap_mount,
            label: self.label.as_deref(),
            verity: match &self.accepted {
                Some(accepted) => velarx_graph::VerityAsk::Enforce {
                    accepted,
                    chain: None,
                },
                None => velarx_graph::VerityAsk::Off,
            },
            volatile: self.volatile,
        }
    }
}

impl ContainerService {
    /// How the owners of an image become ids of the daemon's namespace: those
    /// of the container's own user namespace, else the ids the daemon has.
    pub fn translation(
        &self,
        uid_mappings: &[IdMapping],
        gid_mappings: &[IdMapping],
    ) -> velarx_fuse::IdTranslate {
        let own_ns = !uid_mappings.is_empty();
        let ids = self.userns_manager.ids();
        let identity = |g: velarx_base::idmap::IdSet| -> Vec<IdMapping> {
            g.intervals()
                .iter()
                .map(|&(s, e)| IdMapping {
                    container_id: s as u32,
                    host_id: s as u32,
                    size: (e - s) as u32,
                })
                .collect()
        };
        velarx_fuse::IdTranslate {
            uid: if own_ns {
                uid_mappings.to_vec()
            } else {
                identity(ids.granted(false))
            },
            gid: if own_ns {
                gid_mappings.to_vec()
            } else {
                identity(ids.granted(true))
            },
            squash: self.userns_manager.squash_unmapped_owners(),
        }
    }

    /// The directory of the socket that a container in `--sdnotify=container`
    /// mode sends to (`/run/notify` in it): made before the monitor binds
    /// the socket in it, with the label of the container's files, so that
    /// the socket gets it too and the container may send (as podman).
    pub(crate) fn prepare_notify_dir(
        &self,
        id: &str,
        config: &ContainerConfig,
    ) -> ContainerResult<()> {
        use crate::container::selinux;
        if config.sdnotify != "container" {
            return Ok(());
        }
        let dir = self
            .mon_dir(id)
            .join(velarx_wire::monitor::proto::NOTIFY_DIR);
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        let Some(s) = config.selinux.as_ref().filter(|_| selinux::enabled()) else {
            return Ok(());
        };
        if let (_, Some(label)) = selinux::labels(s, config.privileged, selinux::Contexts::host()) {
            selinux::relabel_path(&dir, &label, &[]).map_err(|e| {
                ContainerError::InvalidArgument(format!("cannot relabel {}: {e}", dir.display()))
            })?;
        }
        Ok(())
    }

    /// The image of a container made from a directory: it has no layers
    /// and is not listed.
    pub(super) async fn rootfs_image(&self) -> ContainerResult<velarx_db::ImageRecord> {
        let image = velarx_db::ImageRecord {
            id: velarx_db::ROOTFS_IMAGE_ID.into(),
            manifest_digest: velarx_types::digest::Digest::empty(velarx_types::digest::Algorithm::Sha256),
            config_digest: velarx_types::digest::Digest::empty(velarx_types::digest::Algorithm::Sha256),
            manifest: "{}".into(),
            config: r#"{"architecture":"amd64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":[]}}"#.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            is_lazy: false,
        };
        self.db.insert_image(&image).await?;
        Ok(image)
    }

    /// The directories of the bundle for a root file system that is a
    /// directory (the monitor mounts it where the bundle's `rootfs` is).
    pub(super) fn setup_rootfs_dir(
        &self,
        id: &str,
        bundle_path: &Path,
        dir: &crate::container::RootfsDir,
        maps: IdMaps<'_>,
    ) -> ContainerResult<()> {
        if dir.overlay {
            // (the layer over the directory is an overlay's upper directory)
            if !self.storage().capabilities().overlay_upper {
                return Err(ContainerError::InvalidArgument(format!(
                    "--rootfs {}:O needs a storage driver whose writable layer is an overlay's upper directory; the driver of this store is {}",
                    dir.path.display(),
                    self.storage().name()
                )));
            }
            self.storage()
                .writable_create(
                    &Writable::new(id, bundle_path),
                    maps.host_root(),
                    &WritableOptions::default(),
                    None,
                )
                .map_err(|e| ContainerError::Io(e.into_io()))?;
        }
        Ok(())
    }

    /// The writable layer of a container made of an image: the driver makes
    /// it from the layers (a driver that copies them copies them here, on the
    /// blocking pool), owned by the root of the container's user namespace.
    /// The answer is what the root file system will be (the plan the engine
    /// writes in the bundle), and the files of the root get the container's
    /// label when one is asked for and the mount does not carry it.
    pub(super) async fn make_writable(
        &self,
        id: &str,
        bundle_path: &Path,
        image: &velarx_db::ImageRecord,
        layers: &[LayerRecord],
        maps: IdMaps<'_>,
        ask: RootAsk,
    ) -> ContainerResult<Option<velarx_graph::Planned>> {
        let io_err = |m: String| ContainerError::Io(std::io::Error::other(m));
        // The root of the merged tree is the root of the upper directory:
        // the root of the container must own it.
        let owner = if maps.uid.is_empty() {
            None
        } else {
            let root = |maps: &[IdMapping], what: &str| {
                velarx_base::idmap::to_parent(maps, 0).ok_or_else(|| {
                    io_err(format!("the {what} 0 is not mapped in the user namespace"))
                })
            };
            Some((root(maps.uid, "uid")?, root(maps.gid, "gid")?))
        };
        let (driver, writable) = (self.storage().clone(), Writable::new(id, bundle_path));
        let (image, layers) = (image.clone(), layers.to_vec());
        tokio::task::spawn_blocking(move || {
            let planned = driver
                .writable_create(
                    &writable,
                    owner,
                    &WritableOptions::default(),
                    Some(&ask.request(&writable, &image, &layers)),
                )
                .map_err(|e| match e.kind {
                    velarx_graph::DriverErrorKind::Io(_) => ContainerError::Io(e.into_io()),
                    // (what the driver says of the image, a lost artifact of
                    // a layer among it, is an error of the image: the create
                    // looks for the damage and says to pull it again)
                    _ => ContainerError::Image(e.into()),
                })?;
            // A root file system whose mount does not carry the container's
            // label (a copy of the image, which no mount gives the label as
            // the `context=` of an overlay does) gets it on its files now
            // (as podman's vfs driver), or a confined container could not
            // read the files of its own root.
            if let (Some(l), Some(velarx_graph::LabelDone::None)) =
                (&ask.label, planned.as_ref().map(|p| p.label))
            {
                let root = driver
                    .writable_root(&writable)
                    .map_err(|e| ContainerError::Io(e.into_io()))?;
                crate::container::selinux::relabel_root(&root, l).map_err(|e| {
                    ContainerError::InvalidArgument(format!(
                        "cannot relabel the root file system of the container: {e}"
                    ))
                })?;
            }
            Ok(planned)
        })
        .await
        .map_err(|e| io_err(e.to_string()))?
    }

    /// The root file system of a container, written down for its monitor:
    /// the plan of the mount the storage driver makes at each start (the
    /// kernel's overlay of the layers, or the image server's over a FUSE file
    /// system of them) and the monitor attaches (see `monitor::image`).  The
    /// mounts belong to the monitor's mount namespace, so the container outlives
    /// the daemon, as root and rootless.
    pub(super) fn setup_rootfs(&self, rootfs_path: &Path) -> ContainerResult<()> {
        fs::create_dir_all(rootfs_path)?;
        Ok(())
    }

    /// The /etc files of the container a new one shares its network
    /// namespace with (`--network container:ID`, the members of a pod): it
    /// resolves as the container whose namespace it is in (and can have no DNS
    /// settings of its own: `dns_conflict`).  `mapped`: the new container has
    /// a user namespace of its own, whose root cannot own those files.
    pub(super) async fn inherited_etc(
        &self,
        req: &CreateContainerRequest,
        mapped: bool,
    ) -> ContainerResult<Option<InheritedEtc>> {
        use std::os::unix::fs::MetadataExt;
        let NetworkMode::Container(target) = &req.network_mode else {
            return Ok(None);
        };
        let rec = self
            .db
            .get_container(target)
            .await
            .map_err(|_| ContainerError::NotFound(target.to_string()))?;
        let dir = self.bundle_dir(&rec.id);
        // (files the donor gave to the root of its user namespace are not
        // ours to share with a container that has another)
        let ours = |name: &str| {
            fs::symlink_metadata(dir.join(name))
                .is_ok_and(|m| m.is_file() && m.uid() == rustix::process::geteuid().as_raw())
        };
        Ok(Some(InheritedEtc {
            resolv_text: fs::read_to_string(dir.join(ETC_RESOLV)).ok(),
            share_resolv: !mapped && ours(ETC_RESOLV),
            share_hosts: !mapped && ours(ETC_HOSTS),
            dir,
        }))
    }

    /// /etc/resolv.conf, /etc/hostname and /etc/hosts: files of the bundle
    /// that are bind mounted, as podman's, so that they are not in the
    /// layer of the container (commit, export) and stay when it restarts.
    /// A mount of the user on one of them replaces it.  Returns the mounts.
    pub(super) fn setup_etc_files(
        &self,
        bundle_path: &Path,
        config: &ContainerConfig,
        req: &CreateContainerRequest,
        provider_dns: Option<std::net::Ipv4Addr>,
        net: Option<&crate::network::engine::EtcInfo>,
        inherited: Option<InheritedEtc>,
    ) -> ContainerResult<Vec<MountConfig>> {
        use crate::services::network::{build_resolv_conf, host_resolv_conf, ResolvParams};
        let read_text = |p: &str| fs::read_to_string(p).ok();
        let user_mounts = |dest: &str| config.mounts.iter().any(|m| m.target == dest);
        let mut mounts = Vec::new();

        let shared_resolv = inherited
            .as_ref()
            .filter(|i| i.share_resolv)
            .map(|i| i.dir.join(ETC_RESOLV));
        let resolv_content =
            if let Some(text) = inherited.as_ref().and_then(|i| i.resolv_text.clone()) {
                text
            } else if req.has_network_mode(&NetworkMode::Host) {
                // the servers, search domains and options of the host's
                // resolv.conf, as podman (a host that has none gives an
                // empty one; a lone `.` search is none)
                let host = match fs::read_to_string("/etc/resolv.conf") {
                    Ok(text) => text,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(e) => {
                        return Err(ContainerError::Io(std::io::Error::new(
                            e.kind(),
                            format!("reading /etc/resolv.conf: {e}"),
                        )))
                    }
                };
                build_resolv_conf(&ResolvParams {
                    host: &host,
                    nameservers: req.dns.clone(),
                    search: req.dns_search.clone(),
                    options: req.dns_options.clone(),
                    host_netns: true,
                    ..ResolvParams::default()
                })
            } else if let Some(dns) = provider_dns {
                // only the name server of a network provider, which resolves the
                // names of the containers of its network and forwards the others
                // (as podman with the name server of a netavark network)
                build_resolv_conf(&ResolvParams {
                    host: &host_resolv_conf(false, read_text),
                    nameservers: vec![dns.to_string()],
                    search: req.dns_search.clone(),
                    keep_host_search: true,
                    options: req.dns_options.clone(),
                    ..ResolvParams::default()
                })
            } else {
                // The servers the user gives, else those the network setup
                // gives (the DNS server of a bridge network, the forwarder of
                // pasta) and the host's.
                let etc = net.cloned().unwrap_or(crate::network::engine::EtcInfo {
                    keep_host_servers: true,
                    ..Default::default()
                });
                let own_dns = !req.dns.is_empty();
                build_resolv_conf(&ResolvParams {
                    host: &host_resolv_conf(false, read_text),
                    nameservers: if own_dns {
                        req.dns.clone()
                    } else {
                        etc.nameservers
                    },
                    keep_host_servers: !own_dns && etc.keep_host_servers,
                    search: if !req.dns_search.is_empty() {
                        req.dns_search.clone()
                    } else if own_dns {
                        Vec::new()
                    } else {
                        etc.search
                    },
                    keep_host_search: req.dns_search.is_empty(),
                    options: req.dns_options.clone(),
                    ipv6: etc.ipv6,
                    host_netns: false,
                })
            };

        let linked = shared_resolv.as_ref().and_then(|donor| {
            linked_file_mount(bundle_path, ETC_RESOLV, donor, "/etc/resolv.conf")
        });
        if !keeps_image_resolv_conf(req) && !user_mounts("/etc/resolv.conf") {
            mounts.push(match linked {
                Some(mount) => mount,
                None => bundle_file_mount(
                    bundle_path,
                    ETC_RESOLV,
                    resolv_content.as_bytes(),
                    "/etc/resolv.conf",
                    false,
                )?,
            });
        }
        if !req.no_hostname && !user_mounts("/etc/hostname") {
            mounts.push(bundle_file_mount(
                bundle_path,
                ETC_HOSTNAME,
                format!("{}\n", config.hostname).as_bytes(),
                "/etc/hostname",
                false,
            )?);
        }
        // (--add-host is the member's own: it has its file then)
        let shared_hosts = inherited
            .as_ref()
            .filter(|i| i.share_hosts && req.add_hosts.is_empty())
            .map(|i| i.dir.join(ETC_HOSTS));
        let linked = shared_hosts
            .as_ref()
            .and_then(|donor| linked_file_mount(bundle_path, ETC_HOSTS, donor, "/etc/hosts"));
        if let (Some(mount), false, false) = (linked, req.no_hosts, user_mounts("/etc/hosts")) {
            mounts.push(mount);
        } else if !req.no_hosts && !user_mounts("/etc/hosts") {
            let hosts_content = self.hosts_content(config, req, net, &[])?;
            mounts.push(bundle_file_mount(
                bundle_path,
                ETC_HOSTS,
                hosts_content.as_bytes(),
                "/etc/hosts",
                false,
            )?);
        }
        // (podman's: with a read-only root the files are read-only too)
        if req.read_only_rootfs {
            for m in &mut mounts {
                m.options
                    .extend(["ro", "nosuid", "noexec", "nodev"].map(String::from));
            }
        }
        // the same files below the directories that are roots too
        let chrooted: Vec<MountConfig> = req
            .chroot_dirs
            .iter()
            .flat_map(|dir| {
                mounts.iter().map(move |m| MountConfig {
                    target: format!("{}{}", dir.trim_end_matches('/'), m.target),
                    ..m.clone()
                })
            })
            .collect();
        mounts.extend(chrooted);
        Ok(mounts)
    }

    /// /etc/hosts, in podman's order: --add-host, the base file, localhost,
    /// host.containers.internal, the host name and the name of the
    /// container on its address (on the loopback with no network of its
    /// own); a name that is above is not added again.
    pub(super) fn hosts_content(
        &self,
        config: &ContainerConfig,
        req: &CreateContainerRequest,
        net: Option<&crate::network::engine::EtcInfo>,
        ips: &[std::net::IpAddr],
    ) -> ContainerResult<String> {
        use crate::services::network::HostsConfig;
        let mut hosts = HostsConfig::new();
        let name = req.name.as_deref();
        // The host as the network of the container reaches it, else (no
        // network of its own) the address the host goes out with, as podman.
        let host = net
            .and_then(|n| n.host_address.clone())
            .or_else(|| crate::network::engine::outbound_address().map(|a| a.to_string()));
        if let Some(host) = &host {
            hosts.add_host(host, "host.containers.internal host.docker.internal");
        }
        match ips.split_first() {
            Some((ip, more)) => {
                for ip in std::iter::once(ip).chain(more) {
                    hosts.add_container(&ip.to_string(), &config.hostname, name);
                }
            }
            None if config_has_network_mode(config, &NetworkMode::Host) => {}
            None => {
                let own = net.and_then(|n| n.address.clone());
                hosts.add_container(
                    own.as_deref().unwrap_or("127.0.0.1"),
                    &config.hostname,
                    name,
                );
            }
        }
        let base = match req.hosts_file.as_deref() {
            Some("none") => None,
            Some("image") => {
                if let Some(text) = &req.hosts_image {
                    hosts.add_base(text);
                }
                None
            }
            Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
            _ => self.base_hosts_file.clone(),
        };
        if let Some(base) = &base {
            match std::fs::read_to_string(base) {
                Ok(text) => hosts.add_base(&text),
                // (a host without /etc/hosts is no error, as podman's)
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && base == Path::new("/etc/hosts") => {}
                Err(e) => warn!("Cannot read the base hosts file {}: {e}", base.display()),
            }
        }
        hosts
            .add_extra_hosts(&req.add_hosts, host.as_deref())
            .map_err(ContainerError::InvalidArgument)?;
        Ok(hosts.generate_hosts())
    }

    /// The address of the container changed (it took a pooled network
    /// namespace): the entry of its host name in its /etc/hosts gets IP.
    /// Nothing when there is no such file (`--no-hosts`) or entry.
    pub(crate) fn update_hosts_address(
        &self,
        bundle_path: &Path,
        hostname: &str,
        ip: &str,
    ) -> ContainerResult<()> {
        use std::io::Read;
        let Some((base, rel)) = hosts_file(bundle_path) else {
            return Ok(());
        };
        let Ok(fd) = open_beneath(&base, rel, rustix::fs::OFlags::RDONLY) else {
            return Ok(());
        };
        // The engine wrote the file, from base_hosts_file (blocklists of
        // the host are megabytes): the limit only bounds what a container
        // that grew its own file makes the engine read.
        const MAX_HOSTS: u64 = 64 << 20;
        let mut content = String::new();
        std::fs::File::from(fd)
            .take(MAX_HOSTS + 1)
            .read_to_string(&mut content)?;
        if content.len() as u64 > MAX_HOSTS {
            return Err(std::io::Error::other(format!(
                "{}: the /etc/hosts of the container is larger than {} MiB, its address cannot be updated",
                base.join(rel).display(),
                MAX_HOSTS >> 20
            ))
            .into());
        }
        use crate::services::network::HostsConfig;
        match HostsConfig::with_new_address(&content, hostname, ip) {
            Some(new) => self.rewrite_hosts(bundle_path, &new),
            None => Ok(()),
        }
    }

    /// Replace the content of the /etc/hosts of a container in place: a
    /// running container sees it through its bind mount (its owner and
    /// mode stay).
    pub(super) fn rewrite_hosts(&self, bundle_path: &Path, content: &str) -> ContainerResult<()> {
        use std::io::Write;
        let Some((base, rel)) = hosts_file(bundle_path) else {
            return Ok(());
        };
        let fd = open_beneath(
            &base,
            rel,
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::TRUNC,
        )
        .map_err(|e| std::io::Error::other(format!("Failed to update hosts: {e}")))?;
        std::fs::File::from(fd).write_all(content.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod label_tests {
    use super::*;

    #[test]
    fn an_image_cannot_name_the_unit_of_its_container() {
        let l = |p: &[(&str, &str)]| {
            p.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>()
        };
        let image = l(&[("PODMAN_SYSTEMD_UNIT", "sshd.service"), ("a", "image")]);
        let got = container_labels(&image, &l(&[("a", "user")]).into_iter().collect());
        assert_eq!(got, l(&[("a", "user")]));
        let got = container_labels(
            &image,
            &l(&[("PODMAN_SYSTEMD_UNIT", "app.service")])
                .into_iter()
                .collect(),
        );
        assert_eq!(got["PODMAN_SYSTEMD_UNIT"], "app.service");
        assert_eq!(got["a"], "image");
    }
}

/// The files the engine writes into the root of a writable layer, by the
/// descriptor of the driver: the same files as when it wrote them through the
/// path (`by_path`, the code as it was), and nothing outside the root.
#[cfg(test)]
mod root_fd_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use velarx_fuse::MergedView;
    use velarx_storage::{Toc, TocEntry};

    fn entry(name: &str, kind: &str, mode: u32) -> TocEntry {
        serde_json::from_value(serde_json::json!({
            "name": name, "type": kind, "mode": mode, "uid": 0, "gid": 0,
        }))
        .unwrap()
    }

    /// An image with /etc/passwd, /etc/group and a zone file.
    fn image(with_etc: bool) -> MergedView {
        let mut entries = vec![entry("usr", "dir", 0o755)];
        if with_etc {
            entries.extend([
                entry("etc", "dir", 0o750),
                entry("etc/passwd", "reg", 0o640),
                entry("etc/group", "reg", 0o600),
            ]);
        }
        entries.extend([
            entry("usr/share", "dir", 0o755),
            entry("usr/share/zoneinfo", "dir", 0o755),
            entry("usr/share/zoneinfo/Europe", "dir", 0o755),
            entry("usr/share/zoneinfo/Europe/Berlin", "reg", 0o644),
        ]);
        let toc = Toc {
            version: 1,
            entries,
            tar_split_digest: None,
        };
        MergedView::new(&[&toc]).unwrap()
    }

    /// The root of the container is the current user, as with a user
    /// namespace that maps the root to it.
    fn translate() -> velarx_fuse::IdTranslate {
        let map = |id: u32| {
            vec![velarx_proto::pod::IdMapping {
                container_id: 0,
                host_id: id,
                size: 1,
            }]
        };
        velarx_fuse::IdTranslate {
            uid: map(rustix::process::getuid().as_raw()),
            gid: map(rustix::process::getgid().as_raw()),
            squash: false,
        }
    }

    fn open(dir: &Path) -> std::os::fd::OwnedFd {
        use rustix::fs::{Mode, OFlags};
        rustix::fs::open(
            dir,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    /// The code that wrote through the path of the host, before the descriptor.
    mod by_path {
        use super::*;
        pub fn write(
            view: &MergedView,
            translate: &velarx_fuse::IdTranslate,
            upper: &Path,
            name: &str,
            content: &str,
        ) -> bool {
            use std::os::unix::fs::OpenOptionsExt;
            use velarx_fuse::view::ImageTree;
            let entry = |path: &str, kind: velarx_storage::TocEntryType| {
                let node = view.resolve(path).and_then(|n| view.node(n))?;
                (node.entry.entry_type == kind).then_some(node.entry)
            };
            let (Some(dir), Some(file)) = (
                entry("etc", velarx_storage::TocEntryType::Dir),
                entry(&format!("etc/{name}"), velarx_storage::TocEntryType::Reg),
            ) else {
                return false;
            };
            let owner = |e: &velarx_storage::TocEntry| {
                (
                    velarx_base::idmap::to_parent(&translate.uid, e.uid),
                    velarx_base::idmap::to_parent(&translate.gid, e.gid),
                )
            };
            let etc = upper.join("etc");
            if !etc.is_dir() {
                fs::create_dir_all(&etc).unwrap();
                fs::set_permissions(&etc, fs::Permissions::from_mode(dir.mode & 0o7777)).unwrap();
                let (u, g) = owner(&dir);
                std::os::unix::fs::chown(&etc, u, g).unwrap();
            }
            let path = etc.join(name);
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(file.mode & 0o7777)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut f, content.as_bytes()).unwrap();
            let (u, g) = owner(&file);
            std::os::unix::fs::chown(&path, u, g).unwrap();
            true
        }
    }

    /// What a directory holds: path, kind, mode, owner, content.
    fn snapshot(dir: &Path) -> Vec<String> {
        fn walk(base: &Path, p: &Path, out: &mut Vec<String>) {
            let mut names: Vec<_> = fs::read_dir(p).unwrap().flatten().collect();
            names.sort_by_key(|e| e.file_name());
            for e in names {
                let m = fs::symlink_metadata(e.path()).unwrap();
                let rel = e.path().strip_prefix(base).unwrap().display().to_string();
                let body = if m.is_file() {
                    String::from_utf8_lossy(&fs::read(e.path()).unwrap()).into_owned()
                } else if m.is_symlink() {
                    fs::read_link(e.path()).unwrap().display().to_string()
                } else {
                    String::new()
                };
                out.push(format!(
                    "{rel} {:o} {}:{} {body:?}",
                    m.mode(),
                    m.uid(),
                    m.gid()
                ));
                if m.is_dir() {
                    walk(base, &e.path(), out);
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out
    }

    #[test]
    fn the_files_are_those_the_path_wrote() {
        let (view, tr) = (image(true), translate());
        for (name, text) in [
            ("passwd", "root:x:0:0::/:/bin/sh\nu:x:1:1::/:/bin/sh\n"),
            ("group", "root:x:0:\n"),
        ] {
            let (path_dir, by_fd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            assert!(by_path::write(&view, &tr, path_dir.path(), name, text));
            let fd = open(by_fd.path());
            let root = WritableRoot {
                view: &view,
                translate: &tr,
                root: std::os::fd::AsFd::as_fd(&fd),
            };
            assert!(write_in_upper(&root, name, text).unwrap());
            assert_eq!(snapshot(path_dir.path()), snapshot(by_fd.path()), "{name}");
            // (and it is what the image's file says)
            let m = fs::metadata(by_fd.path().join("etc").join(name)).unwrap();
            let want = if name == "passwd" { 0o640 } else { 0o600 };
            assert_eq!(m.mode() & 0o7777, want);
            assert_eq!(
                fs::metadata(by_fd.path().join("etc")).unwrap().mode() & 0o7777,
                0o750,
                "/etc as the image has it"
            );
        }
    }

    #[test]
    fn a_file_of_etc_that_the_layer_has_is_written_over_and_etc_is_left() {
        let (view, tr) = (image(true), translate());
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("etc")).unwrap();
        fs::set_permissions(dir.path().join("etc"), fs::Permissions::from_mode(0o711)).unwrap();
        fs::write(
            dir.path().join("etc/passwd"),
            "a much longer old content than the new one\n",
        )
        .unwrap();
        let fd = open(dir.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        assert!(write_in_upper(&root, "passwd", "new\n").unwrap());
        assert_eq!(
            fs::read_to_string(dir.path().join("etc/passwd")).unwrap(),
            "new\n"
        );
        assert_eq!(
            fs::metadata(dir.path().join("etc")).unwrap().mode() & 0o7777,
            0o711,
            "the directory of the layer keeps its mode"
        );
    }

    #[test]
    fn an_image_without_the_file_writes_nothing() {
        let (view, tr) = (image(false), translate());
        let dir = tempfile::tempdir().unwrap();
        let fd = open(dir.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        assert!(!write_in_upper(&root, "passwd", "x").unwrap());
        assert!(!link_localtime_in_upper(&root, "Europe/Berlin").unwrap());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_link_in_the_root_leads_nowhere() {
        let (view, tr) = (image(true), translate());
        let outside = tempfile::tempdir().unwrap();
        // /etc is a link to a directory outside the root
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("etc")).unwrap();
        let fd = open(dir.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        assert!(write_in_upper(&root, "passwd", "x").is_err());
        assert!(link_localtime_in_upper(&root, "Europe/Berlin").is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
        // the file is a link to a file outside the root
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("etc")).unwrap();
        let target = outside.path().join("victim");
        fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("etc/passwd")).unwrap();
        let fd = open(dir.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        assert!(write_in_upper(&root, "passwd", "x").is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "untouched");
        // (the root as a path is renamed away: the descriptor still names it)
        let moved = dir.path().with_extension("moved");
        fs::rename(dir.path(), &moved).unwrap();
        assert!(write_in_upper(&root, "group", "g\n").unwrap());
        assert_eq!(fs::read_to_string(moved.join("etc/group")).unwrap(), "g\n");
        assert!(!dir.path().exists());
        fs::remove_dir_all(&moved).unwrap();
        // (the tempdir's drop finds nothing: it ignores that)
        fs::create_dir(dir.path()).unwrap();
    }

    /// A link that stays in the root is not followed either (the old path
    /// followed it): `/etc` a link to `usr`, `/etc/passwd` a link to a file of
    /// the root and `/etc/group` one to a file of `/etc`; nothing is written
    /// through them.
    #[test]
    fn a_link_inside_the_root_is_not_followed() {
        let (view, tr) = (image(true), translate());
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("usr")).unwrap();
        std::os::unix::fs::symlink("usr", dir.path().join("etc")).unwrap();
        let fd = open(dir.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        assert!(write_in_upper(&root, "passwd", "x").is_err());
        assert!(link_localtime_in_upper(&root, "Europe/Berlin").is_err());
        assert_eq!(fs::read_dir(dir.path().join("usr")).unwrap().count(), 0);
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("etc")).unwrap();
        fs::write(dir.path().join("victim"), "untouched").unwrap();
        fs::write(dir.path().join("etc/shadow"), "untouched").unwrap();
        std::os::unix::fs::symlink("../victim", dir.path().join("etc/passwd")).unwrap();
        std::os::unix::fs::symlink("shadow", dir.path().join("etc/group")).unwrap();
        let fd = open(dir.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        assert!(write_in_upper(&root, "passwd", "x").is_err());
        assert!(write_in_upper(&root, "group", "x").is_err());
        for f in ["victim", "etc/shadow"] {
            assert_eq!(
                fs::read_to_string(dir.path().join(f)).unwrap(),
                "untouched",
                "{f}"
            );
        }
    }

    /// What is at the name and is not a regular file is refused, without a
    /// wait for a reader of a fifo.
    #[test]
    fn a_special_file_at_the_name_is_refused() {
        let (view, tr) = (image(true), translate());
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("etc")).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.path().join("etc/passwd"),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o666),
            0,
        )
        .unwrap();
        fs::create_dir(dir.path().join("etc/group")).unwrap();
        let fd = open(dir.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        assert!(write_in_upper(&root, "passwd", "x").is_err());
        assert!(write_in_upper(&root, "group", "x").is_err());
        // (a device, as root: opened, then refused before it is written; on
        // a file system of the host that allows devices, /tmp has `nodev`)
        if rustix::process::geteuid().is_root() {
            let dir = tempfile::tempdir_in("/var/tmp").unwrap();
            let nodev = rustix::fs::statvfs(dir.path())
                .unwrap()
                .f_flag
                .contains(rustix::fs::StatVfsMountFlags::NODEV);
            fs::create_dir(dir.path().join("etc")).unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                dir.path().join("etc/passwd"),
                rustix::fs::FileType::CharacterDevice,
                rustix::fs::Mode::from_raw_mode(0o666),
                rustix::fs::makedev(1, 3),
            )
            .unwrap();
            let fd = open(dir.path());
            let root = WritableRoot {
                view: &view,
                translate: &tr,
                root: std::os::fd::AsFd::as_fd(&fd),
            };
            let e = write_in_upper(&root, "passwd", "x")
                .unwrap_err()
                .to_string();
            assert!(nodev || e.contains("not a regular file"), "{e}");
        }
    }

    /// The owner of `/etc` and of the file is the owner of the image's, as the
    /// container's mapping puts it on the host (root: an id that is not the
    /// test's own, so a write that kept the creator would be seen).
    #[test]
    fn the_owner_is_the_mapped_owner_of_the_image() {
        if !rustix::process::geteuid().is_root() {
            eprintln!("SKIPPED: only root gives a file to another owner");
            return;
        }
        let view = image(true);
        let map = |host_id: u32| {
            vec![velarx_proto::pod::IdMapping {
                container_id: 0,
                host_id,
                size: 65536,
            }]
        };
        let tr = velarx_fuse::IdTranslate {
            uid: map(100_000),
            gid: map(200_000),
            squash: false,
        };
        let (path_dir, by_fd) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        assert!(by_path::write(
            &view,
            &tr,
            path_dir.path(),
            "passwd",
            "root:x:0:0::/:/bin/sh\n"
        ));
        let fd = open(by_fd.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        assert!(write_in_upper(&root, "passwd", "root:x:0:0::/:/bin/sh\n").unwrap());
        assert!(link_localtime_in_upper(&root, "Europe/Berlin").unwrap());
        for p in ["etc", "etc/passwd"] {
            let m = fs::metadata(by_fd.path().join(p)).unwrap();
            assert_eq!((m.uid(), m.gid()), (100_000, 200_000), "{p}");
        }
        // (the link is made by the engine, as before: its owner is not set)
        fs::remove_file(by_fd.path().join("etc/localtime")).unwrap();
        assert_eq!(snapshot(path_dir.path()), snapshot(by_fd.path()));
    }

    #[test]
    fn localtime_is_a_link_in_the_root() {
        let (view, tr) = (image(true), translate());
        let dir = tempfile::tempdir().unwrap();
        let fd = open(dir.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        // (a file that was there is replaced)
        fs::create_dir(dir.path().join("etc")).unwrap();
        fs::write(dir.path().join("etc/localtime"), "old").unwrap();
        assert!(link_localtime_in_upper(&root, "Europe/Berlin").unwrap());
        assert_eq!(
            fs::read_link(dir.path().join("etc/localtime")).unwrap(),
            Path::new("../usr/share/zoneinfo/Europe/Berlin")
        );
        // twice: the same
        assert!(link_localtime_in_upper(&root, "Europe/Berlin").unwrap());
        // a zone the image lacks is none
        assert!(!link_localtime_in_upper(&root, "Nowhere/Land").unwrap());
    }

    /// An image read from a mount: a directory laid out as a hostile image.
    fn mounted(dir: &Path) -> velarx_fuse::MountedImage {
        velarx_fuse::MountedImage::new(open(dir)).unwrap()
    }

    #[test]
    fn the_entries_are_written_from_a_mounted_image_and_never_through_its_links() {
        let tr = translate();
        let (image, upper) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "host").unwrap();
        fs::create_dir_all(image.path().join("etc")).unwrap();
        fs::create_dir_all(image.path().join("usr/share/zoneinfo/Europe")).unwrap();
        fs::write(image.path().join("etc/group"), "root:x:0:\n").unwrap();
        // /etc/passwd leads to a file of the host
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            image.path().join("etc/passwd"),
        )
        .unwrap();
        fs::write(
            image.path().join("usr/share/zoneinfo/Europe/Berlin"),
            "TZif",
        )
        .unwrap();
        std::os::unix::fs::symlink("Europe/Berlin", image.path().join("usr/share/zoneinfo/CET"))
            .unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret"),
            image.path().join("usr/share/zoneinfo/Evil"),
        )
        .unwrap();
        let view = mounted(image.path());
        let fd = open(upper.path());
        let root = WritableRoot {
            view: &view,
            translate: &tr,
            root: std::os::fd::AsFd::as_fd(&fd),
        };
        // a regular file of the image is written over, in the layer
        assert!(write_in_upper(&root, "group", "root:x:0:\nme:x:5:\n").unwrap());
        assert_eq!(
            fs::read_to_string(upper.path().join("etc/group")).unwrap(),
            "root:x:0:\nme:x:5:\n"
        );
        // a link is not a regular file: the entries are mounted instead
        assert!(!write_in_upper(&root, "passwd", "me:x:5:5::/:/bin/sh\n").unwrap());
        assert!(!upper.path().join("etc/passwd").exists());
        assert_eq!(
            fs::read_to_string(outside.path().join("secret")).unwrap(),
            "host"
        );
        // the zone is found through a link of the image, not through one
        // that leaves it
        assert!(link_localtime_in_upper(&root, "CET").unwrap());
        assert!(!link_localtime_in_upper(&root, "Evil").unwrap());
    }
}
