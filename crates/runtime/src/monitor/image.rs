// SPDX-License-Identifier: Apache-2.0
//! The root file system of a container, set up by its monitor.
//!
//! The mounts of a container's root file system and of its image mounts are
//! the storage driver's: it makes them (the kernel mounts the EROFS images of
//! the layers, or its image server serves them, `crate::imageserver`) and the
//! engine hands the monitor the detached mounts as descriptors, which the
//! monitor attaches (`RootfsPlan::MountFd`, `mount_fd`).  A driver that
//! copies the layers makes a directory, which the monitor makes the root
//! (`RootfsPlan::Directory`).  The monitor mounts nothing of the image
//! itself, and reads no path of a store.

use super::config::{ImageConfig, OverlayVolume, SubpathVolume};
use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "fuse")]
mod mount_fd;
#[cfg(feature = "fuse")]
pub(crate) mod stubs;

#[cfg(feature = "fuse")]
mod imp {
    use super::*;
    use velarx_fuse::erofs_tree::Stubs;
    use velarx_fuse::plan::{RootfsPlan, VerityDone};
    use velarx_wire::chain::Chain;

    /// The mounts of a container's root file system.
    pub struct Rootfs {
        /// The root file system, when there is one to unmount.
        rootfs: Option<PathBuf>,
        /// The mounts of images, bound where the OCI mounts expect them.
        bound: Vec<PathBuf>,
    }

    fn io_err(e: impl std::fmt::Display) -> io::Error {
        io::Error::other(e.to_string())
    }

    /// How the root file system or an image mount is made: the plan from the
    /// bundle's `rootfs.json` (`RootfsPlan`), written by the engine at create
    /// and checked here against what the engine's own configuration says
    /// (`enforce`, `verity`).
    fn read_spec(
        path: &Path,
        (enforce, verity): (bool, VerityDone),
        chain: &Chain,
    ) -> io::Result<RootfsPlan> {
        let data = std::fs::read(path).map_err(|e| {
            chain.broken(|| ("bundle".into(), path.display().to_string(), e.to_string()));
            io::Error::new(e.kind(), format!("{}: {e}", path.display()))
        })?;
        let plan = RootfsPlan::from_slice(&data).map_err(|e| {
            chain.broken(|| ("bundle".into(), "json".into(), "invalid".into()));
            io_err(format!("{}: {e}", path.display()))
        })?;
        match plan {
            RootfsPlan::Directory(d) => {
                check_directory_plan(&d, path, enforce, chain).map(|()| RootfsPlan::Directory(d))
            }
            RootfsPlan::MountFd(m) => check_mount_fd_plan(&m, path, (enforce, verity), chain)
                .map(|()| RootfsPlan::MountFd(m)),
        }
    }

    /// The plan of the `mount-fd` kind: a mount the driver made states no
    /// digest, so an enforced start is refused unless the engine says (in the
    /// configuration it wrote at this start, after it checked the driver's
    /// answer) that the driver measured the images and made a mount that
    /// enforces them (`verity`); and the index must be one a monitor can have
    /// got (the descriptor itself is checked when it is attached).
    fn check_mount_fd_plan(
        m: &velarx_fuse::plan::MountFd,
        path: &Path,
        (enforce, verity): (bool, VerityDone),
        chain: &Chain,
    ) -> io::Result<()> {
        if enforce && verity == VerityDone::None {
            chain.broken(|| ("bundle".into(), "mount-fd".into(), "enforced".into()));
            return Err(io_err(format!(
                "the digests are enforced and the root file system of {} is a mount of the storage driver, which states none",
                path.display()
            )));
        }
        if let Err(why) = m.validate() {
            chain.broken(|| ("bundle".into(), "mount-fd".into(), "invalid".into()));
            return Err(io_err(format!(
                "{}: the mount-fd plan is refused: {why}",
                path.display()
            )));
        }
        Ok(())
    }

    /// The plan of the `directory` kind: a directory has no digest to enforce,
    /// so an enforced start is refused (as one of a `--rootfs` directory), and
    /// the two parts must be ones the engine could have written: an absolute
    /// `beneath` and a relative `path`, without `.`, `..` or empty components
    /// (the base and the way down are checked again when they are opened).
    fn check_directory_plan(
        d: &velarx_fuse::plan::Directory,
        path: &Path,
        enforce: bool,
        chain: &Chain,
    ) -> io::Result<()> {
        if enforce {
            chain.broken(|| ("bundle".into(), "directory".into(), "enforced".into()));
            return Err(io_err(format!(
                "the digests are enforced and the root file system of {} is a directory, which states none",
                path.display()
            )));
        }
        if let Err(why) = d.validate() {
            chain.broken(|| ("bundle".into(), "directory".into(), "invalid".into()));
            return Err(io_err(format!(
                "{}: the directory plan is refused: {why}",
                path.display()
            )));
        }
        Ok(())
    }

    /// The chain of trust of an image the engine hands over: the links it
    /// checked, and the ones the monitor does, in the debug log.
    fn chain_of(
        plan: &Option<super::super::config::ChainPlan>,
        scope: impl FnOnce() -> String,
    ) -> Chain {
        match plan {
            Some(p) => {
                let chain = Chain::resume(&scope(), p.total, p.done, &p.trail, &p.layers);
                if p.fuse_layers > 0 {
                    chain.files_by_fuse(p.fuse_layers);
                }
                chain
            }
            None => Chain::off(),
        }
    }

    /// The link of a mount that failed after its checks.
    fn mount_failed() -> velarx_wire::chain::Broken {
        ("overlay".into(), "mounted".into(), "error".into())
    }

    pub fn mount(cfg: &ImageConfig, run_dir: &Path) -> io::Result<Rootfs> {
        let root_chain = chain_of(&cfg.chain, String::new);
        let volume_chains: Vec<Chain> = cfg
            .image_mounts
            .iter()
            .map(|v| chain_of(&v.chain, || format!("image mount {}: ", v.destination)))
            .collect();
        // On an error the Drop of `rootfs` undoes what was mounted.
        let mut rootfs = Rootfs {
            rootfs: None,
            bound: Vec::new(),
        };
        let root = match cfg.mount_rootfs {
            true => Some(
                read_spec(&cfg.spec, (cfg.enforce, cfg.verity), &root_chain)
                    .inspect_err(|_| root_chain.broken(mount_failed))?,
            ),
            false => None,
        };
        let volumes = cfg
            .image_mounts
            .iter()
            .zip(&volume_chains)
            .map(|(v, chain)| {
                read_spec(&v.spec, (cfg.enforce, v.verity), chain)
                    .inspect_err(|_| chain.broken(mount_failed))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let fd_volumes = split_mount_fd_volumes(cfg, root.as_ref(), volumes)?;
        // (the root an earlier start attached is not this one)
        velarx_wire::monitor::rootid::forget(run_dir);
        match root {
            Some(RootfsPlan::MountFd(plan)) => {
                mount_fd_root(&plan, cfg, &mut rootfs, &root_chain)?;
                // A root that is a descriptor is recognised by the engine
                // through what the monitor attached, not through the driver: a
                // driver may make a new mount at every start.
                velarx_wire::monitor::rootid::record(run_dir, &cfg.rootfs)?;
            }
            Some(RootfsPlan::Directory(plan)) => {
                mount_directory_root(&plan, cfg, &mut rootfs)?;
                // The same for a directory: what the monitor attached.
                velarx_wire::monitor::rootid::record(run_dir, &cfg.rootfs)?;
            }
            None => {}
        }
        if let Some(dir) = &cfg.rootfs_dir {
            mount_rootfs_dir(dir, cfg)?;
            rootfs.rootfs = Some(cfg.rootfs.clone());
        }
        mount_fd_volumes(cfg, run_dir, &mut rootfs, &fd_volumes, &volume_chains)?;
        for v in &cfg.overlay_volumes {
            mount_overlay_volume(v, cfg)?;
            rootfs.bound.push(v.target.clone());
        }
        for v in &cfg.subpath_volumes {
            mount_subpath_volume(v)?;
            rootfs.bound.push(v.target.clone());
        }
        Ok(rootfs)
    }

    /// The image mounts that are mount descriptors, with their place among
    /// the image mounts.  What the monitor refuses before it mounts anything:
    /// an image mount that is not one (a directory: only a root file system
    /// is, and no driver of that kind makes the layers of an image mount),
    /// more than 15 (the first of the 16 descriptors is the root file
    /// system's), a descriptor named twice, and the root file system's.
    fn split_mount_fd_volumes(
        cfg: &ImageConfig,
        root: Option<&RootfsPlan>,
        volumes: Vec<RootfsPlan>,
    ) -> io::Result<Vec<(usize, velarx_fuse::plan::MountFd)>> {
        let name = |i: usize| {
            cfg.image_mounts
                .get(i)
                .map_or(i.to_string(), |v| v.destination.clone())
        };
        let mut fds = Vec::new();
        for (i, plan) in volumes.into_iter().enumerate() {
            match plan {
                RootfsPlan::MountFd(m) => fds.push((i, m)),
                RootfsPlan::Directory(_) => {
                    return Err(io_err(format!(
                        "image mount {}: its plan is a directory, and an image mount (`--mount type=image`) needs a storage driver that mounts layers",
                        name(i)
                    )))
                }
            }
        }
        if fds.len() > velarx_fuse::plan::MAX_VOLUME_FDS as usize {
            return Err(io_err(format!(
                "{} image mounts are mount descriptors, and a monitor gets at most {} (the first of its {} descriptors is the root file system's)",
                fds.len(),
                velarx_fuse::plan::MAX_VOLUME_FDS,
                velarx_fuse::plan::MAX_MOUNT_FDS
            )));
        }
        let mut seen: Vec<(u32, String)> = Vec::new();
        if let Some(RootfsPlan::MountFd(r)) = root {
            seen.push((r.fd_index, "the root file system".to_string()));
        }
        for (i, m) in &fds {
            if let Some((_, who)) = seen.iter().find(|(n, _)| *n == m.fd_index) {
                return Err(io_err(format!(
                    "image mount {} names the mount descriptor {}, which {who} names too: each mount has a descriptor of its own",
                    name(*i),
                    m.fd_index
                )));
            }
            seen.push((m.fd_index, format!("image mount {}", name(*i))));
        }
        Ok(fds)
    }

    /// The image mounts that are mount descriptors, attached at the target
    /// of each (`mount_fd::attach_volume`): read only and `nodev`, with the
    /// container's id mapping when the plan says `idmap`.
    fn mount_fd_volumes(
        cfg: &ImageConfig,
        run_dir: &Path,
        rootfs: &mut Rootfs,
        volumes: &[(usize, velarx_fuse::plan::MountFd)],
        chains: &[Chain],
    ) -> io::Result<()> {
        for (i, plan) in volumes {
            let v = &cfg.image_mounts[*i];
            let what = format!("image mount {}", v.destination);
            let userns = || mapping_userns(cfg);
            let way = super::mount_fd::Way {
                what: &what,
                read_only: true,
                idmap: plan.idmap.then_some(&userns as &super::mount_fd::Idmap<'_>),
                kernel_verity: v.verity != VerityDone::None,
                on_open: v.verity == VerityDone::OnOpen,
                server: plan.server,
                in_cgroup: cfg.servers_in_cgroup,
            };
            let staging = run_dir.join(format!("mfd{i}"));
            if v.subpath.is_some() {
                rootfs.bound.push(staging.clone());
            }
            super::mount_fd::attach_volume(
                &super::mount_fd::HELD,
                plan.fd_index,
                (&v.target, &staging),
                v.subpath.as_deref(),
                &way,
            )
            .inspect_err(|_| chains[*i].broken(mount_failed))?;
            mounted_by_the_driver(&chains[*i], v.verity);
            rootfs.bound.push(v.target.clone());
            tracing::info!(
                "image mount {}: mount descriptor {} of the storage driver{}",
                v.destination,
                plan.fd_index,
                if plan.idmap { ", idmapped" } else { "" }
            );
        }
        Ok(())
    }

    /// The last links of the chain of an image whose mount the driver made
    /// and whose digests it enforced (`verity`), once the monitor attached
    /// it: the engine said the links of the layers the driver measured, and
    /// the monitor found the enforcement on the mount it attached.  Nothing
    /// to say for a mount that enforces none (the digests are not enforced,
    /// so the chain is off).
    fn mounted_by_the_driver(chain: &Chain, verity: VerityDone) {
        match verity {
            VerityDone::None => return,
            // (the overlay checks the digests of the files it opens; where it
            // cannot, the server of the mount does, and the chain says which)
            VerityDone::Kernel | VerityDone::OnOpen => chain.overlay("require"),
        }
        chain.complete();
    }

    /// The user namespace of the container's id mapping, for a mount whose
    /// plan says `idmap`: a container with no mapping has none to put.
    fn mapping_userns(cfg: &ImageConfig) -> io::Result<std::os::fd::OwnedFd> {
        let t = cfg
            .translate
            .as_ref()
            .filter(|t| !t.uid.is_empty() && !t.gid.is_empty())
            .ok_or_else(|| io_err("the container has no id mapping to put on the mount"))?;
        crate::imagemount::holder_userns(t)
    }

    /// The directory of the plan as the file system at `target`: a clone of
    /// its mount, taken from the descriptor of a directory that was opened
    /// under checks (what is mounted is that directory, not a path that
    /// could be changed meanwhile).  The clone is `nodev`, as the overlay of
    /// a composefs root (a device node of the directory opens nothing
    /// through it; whether the root the container sees keeps the flag is up
    /// to the runtime, see the threat model), and private: it is not a peer of the mount it was taken from, so what is
    /// mounted below the root of the container does not show in the
    /// directory on the host, and the other way round.
    ///
    /// The plan is data the monitor, which is privileged, reads from a file,
    /// so it does not name a directory to mount but a base and a way down:
    /// `beneath` is opened without following a link (`NO_SYMLINKS`, no magic
    /// link of `/proc`) and must be a directory of the monitor's user or of
    /// root that no one else can write (a writable base would let its writer
    /// put in it what the way down then leads through), and `path` is opened
    /// from that descriptor with `RESOLVE_BENEATH` (no `..`, no absolute
    /// link, no way out), `NO_SYMLINKS` and `NO_MAGICLINKS`, and
    /// `NO_XDEV`: the root of a container of a driver that copies is a
    /// directory of the file system of its base, so a mount on the way (a bind
    /// mount of another tree put there) is refused, not crossed.  The parents
    /// of `beneath` are not walked: the descriptor of `beneath` is what is
    /// held, a parent that changes afterwards changes nothing, and the homes
    /// of users and `/var/tmp` are not owned by the user alone.
    /// The directory `path` below the descriptor `base`, the kernel's own
    /// rules on the way (whatever the syntax check let through): no `..` or
    /// absolute link out of it, no link, no magic link, no mount crossed.
    fn open_below(
        base: std::os::fd::BorrowedFd<'_>,
        path: &Path,
    ) -> rustix::io::Result<std::os::fd::OwnedFd> {
        use rustix::fs::{OFlags, ResolveFlags};
        velarx_sys::fs::openat2_retry(
            base,
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
    }

    fn mount_directory(plan: &velarx_fuse::plan::Directory, target: &Path) -> io::Result<()> {
        use rustix::fs::{OFlags, ResolveFlags};
        use rustix::mount::{move_mount, open_tree, MoveMountFlags, OpenTreeFlags};
        use std::os::fd::AsFd;
        let dir = plan.beneath.join(&plan.path);
        plan.validate()
            .map_err(|why| io_err(format!("the directory plan is refused: {why}")))?;
        if dir.starts_with(target) || target.starts_with(&dir) {
            return Err(io_err(format!(
                "the root file system {} and its mount point {} are one in the other",
                dir.display(),
                target.display()
            )));
        }
        let base = velarx_sys::fs::openat2_retry(
            rustix::fs::CWD,
            &plan.beneath,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|e| {
            io_err(format!(
                "base {} of the root file system: {e}",
                plan.beneath.display()
            ))
        })?;
        let st = rustix::fs::fstat(&base)
            .map_err(|e| io_err(format!("base {}: {e}", plan.beneath.display())))?;
        let me = rustix::process::geteuid().as_raw();
        if st.st_uid != me && st.st_uid != 0 {
            return Err(io_err(format!(
                "base {} of the root file system belongs to user {}, not to this user ({me}) or root",
                plan.beneath.display(),
                st.st_uid
            )));
        }
        if st.st_mode & 0o022 != 0 {
            return Err(io_err(format!(
                "base {} of the root file system can be written by its group or others (mode {:o})",
                plan.beneath.display(),
                st.st_mode & 0o7777
            )));
        }
        let fd = open_below(base.as_fd(), &plan.path)
            .map_err(|e| io_err(format!("root file system {}: {e}", dir.display())))?;
        // (not recursive: what is mounted below the directory, by its driver
        // or anyone, does not come with it; a directory root is the files of
        // one file system, and only the monitor mounts in it)
        let tree = open_tree(
            &fd,
            "",
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_EMPTY_PATH,
        )
        .map_err(|e| io_err(format!("open_tree of {} failed: {e}", dir.display())))?;
        velarx_sys::mount::setattr_fd_recursive(
            tree.as_fd(),
            &velarx_sys::mount::MountAttr {
                attr_set: libc::MOUNT_ATTR_NODEV,
                propagation: libc::MS_PRIVATE,
                ..Default::default()
            },
        )
        .map_err(|e| io_err(format!("mount_setattr of {} failed: {e}", dir.display())))?;
        velarx_fuse::detach_stale(target)?;
        std::fs::create_dir_all(target)?;
        move_mount(
            tree.as_fd(),
            "",
            rustix::fs::CWD,
            target,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .map_err(|e| io_err(format!("move_mount failed: {e}")))
    }

    /// The directory as the root file system: a clone of its mount, opened
    /// without following a link, moved to the bundle's `rootfs` (what is bound
    /// is the directory that was opened and checked, not a path that could be
    /// changed in between).
    fn mount_directory_root(
        plan: &velarx_fuse::plan::Directory,
        cfg: &ImageConfig,
        rootfs: &mut Rootfs,
    ) -> io::Result<()> {
        mount_directory(plan, &cfg.rootfs)?;
        rootfs.rootfs = Some(cfg.rootfs.clone());
        tracing::info!(
            "root file system: directory {}",
            plan.beneath.join(&plan.path).display()
        );
        Ok(())
    }

    /// The mount the engine passed as the root file system, attached where
    /// the bundle's `rootfs` is (`mount_fd::attach_held`).
    fn mount_fd_root(
        plan: &velarx_fuse::plan::MountFd,
        cfg: &ImageConfig,
        rootfs: &mut Rootfs,
        chain: &Chain,
    ) -> io::Result<()> {
        let userns = || mapping_userns(cfg);
        let way = super::mount_fd::Way {
            what: "root file system",
            read_only: false,
            idmap: plan.idmap.then_some(&userns as &super::mount_fd::Idmap<'_>),
            kernel_verity: cfg.verity != VerityDone::None,
            on_open: cfg.verity == VerityDone::OnOpen,
            server: plan.server,
            in_cgroup: cfg.servers_in_cgroup,
        };
        super::mount_fd::attach_held(&super::mount_fd::HELD, plan.fd_index, &cfg.rootfs, &way)
            .inspect_err(|_| chain.broken(mount_failed))?;
        mounted_by_the_driver(chain, cfg.verity);
        rootfs.rootfs = Some(cfg.rootfs.clone());
        tracing::info!(
            "root file system: mount descriptor {} of the storage driver{}",
            plan.fd_index,
            if plan.idmap { ", idmapped" } else { "" }
        );
        Ok(())
    }

    /// A directory as the root file system: bound where the runtime expects
    /// it, or under the container's overlay (the directory is never written);
    /// with an idmapped mount of it first when the container asked for one.
    fn mount_rootfs_dir(
        dir: &crate::monitor::config::RootfsMount,
        cfg: &ImageConfig,
    ) -> io::Result<()> {
        use rustix::mount::{move_mount, MoveMountFlags};
        use std::os::fd::AsFd;
        // (kept until the file system is mounted)
        let mut mapped = None;
        let mut lower = dir.path.clone();
        if !dir.uid_mappings.is_empty() {
            let tuples = |maps: &[crate::container::IdMapping]| -> Vec<(u32, u32, u32)> {
                maps.iter()
                    .map(|m| (m.container_id, m.host_id, m.size))
                    .collect()
            };
            let userns = crate::userns::create_userns_for_idmap(
                &tuples(&dir.uid_mappings),
                &tuples(&dir.gid_mappings),
            )?;
            let fd = crate::userns::create_idmapped_mount_fd(&dir.path, userns.as_fd()).map_err(
                |e| {
                    io_err(format!(
                        "failed to create idmapped mount of {}: {e}",
                        dir.path.display()
                    ))
                },
            )?;
            lower = velarx_sys::fd::proc_path(&fd);
            mapped = Some(fd);
        }
        if dir.overlay {
            // (podman mounts the overlay of a `--rootfs` directory without it)
            return mount_overlay(&[lower.to_string_lossy().into_owned()], cfg);
        }
        velarx_fuse::detach_stale(&cfg.rootfs)?;
        std::fs::create_dir_all(&cfg.rootfs)?;
        match &mapped {
            Some(fd) => move_mount(
                fd.as_fd(),
                "",
                rustix::fs::CWD,
                &cfg.rootfs,
                MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
            )
            .map_err(io_err),
            None => rustix::mount::mount_bind_recursive(&dir.path, &cfg.rootfs).map_err(io_err),
        }
    }

    /// `lowerdir` takes `:` and `,` as separators: escape them.
    fn escape_lower(p: &Path) -> String {
        let mut out = String::new();
        for c in p.to_string_lossy().chars() {
            if matches!(c, ':' | ',' | '\\') {
                out.push('\\');
            }
            out.push(c);
        }
        out
    }

    /// A directory or a file of a volume (or of a host directory): looked
    /// up inside the volume, and what was looked up is what is mounted (a
    /// clone of the mount at that descriptor), so another container of the
    /// volume that swaps it for a link cannot lead the mount out of it.
    fn mount_subpath_volume(v: &SubpathVolume) -> io::Result<()> {
        use rustix::fs::FileType;
        use rustix::mount::{move_mount, open_tree, MoveMountFlags, OpenTreeFlags};
        let fail = |what: &str, e: rustix::io::Errno| io_err(format!("{what} failed: {e}"));
        let root = crate::fsdir::open_dir(&v.volume)
            .map_err(|e| io_err(format!("{}: {e}", v.volume.display())))?;
        let found =
            crate::fsdir::open_path_in_root(std::os::fd::AsFd::as_fd(&root), &v.subpath)?
                .ok_or_else(|| io_err(format!("{} has no {}", v.volume.display(), v.subpath)))?;
        let is_dir = FileType::from_raw_mode(rustix::fs::fstat(&found).map_err(io_err)?.st_mode)
            == FileType::Directory;
        let tree = open_tree(
            &found,
            "",
            OpenTreeFlags::OPEN_TREE_CLONE
                | OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_EMPTY_PATH
                | OpenTreeFlags::AT_RECURSIVE,
        )
        .map_err(|e| fail("open_tree", e))?;
        velarx_fuse::detach_stale(&v.target)?;
        // the mount point (in the bundle) is of the kind of what is mounted,
        // which may not be the kind it had at the previous start
        match std::fs::symlink_metadata(&v.target) {
            Ok(m) if m.is_dir() && !is_dir => std::fs::remove_dir(&v.target)?,
            Ok(m) if !m.is_dir() && is_dir => std::fs::remove_file(&v.target)?,
            _ => {}
        }
        if is_dir {
            std::fs::create_dir_all(&v.target)?;
        } else {
            if let Some(parent) = v.target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(&v.target)?;
        }
        move_mount(
            &tree,
            "",
            rustix::fs::CWD,
            &v.target,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .map_err(|e| fail("move_mount", e))
    }

    /// An overlay volume: the lower layer as the user gave it (never written
    /// to), an upper layer that is new at each start unless the user gave
    /// it, mounted where the OCI mount expects it.
    fn mount_overlay_volume(v: &OverlayVolume, cfg: &ImageConfig) -> io::Result<()> {
        use rustix::mount::{
            fsconfig_create, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, move_mount,
            FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags,
        };
        use std::os::fd::AsFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let lower = std::fs::metadata(&v.lower)?;
        if !lower.is_dir() {
            return Err(io_err(format!("{} is not a directory", v.lower.display())));
        }
        if v.discard {
            // what the previous run wrote is gone
            for d in [&v.upper, &v.work] {
                match velarx_base::tree::remove_dir_all_confined(d) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                    _ => {}
                }
            }
        }
        let new_upper = !v.upper.exists();
        std::fs::create_dir_all(&v.upper)?;
        std::fs::create_dir_all(&v.work)?;
        if new_upper && v.discard {
            // the root of the overlay is the upper's: the mode of the lower,
            // the owner the root of the container
            std::fs::set_permissions(
                &v.upper,
                std::fs::Permissions::from_mode(lower.mode() & 0o7777),
            )?;
            if let Some((uid, gid)) = v.owner {
                std::os::unix::fs::chown(&v.upper, Some(uid), Some(gid))?;
            }
        }
        velarx_fuse::detach_stale(&v.target)?;
        std::fs::create_dir_all(&v.target)?;
        let fail = |what: &str, e: rustix::io::Errno| io_err(format!("{what} failed: {e}"));
        let fs_fd = fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)
            .map_err(|e| fail("fsopen(overlay)", e))?;
        let lowers = escape_lower(&v.lower);
        fsconfig_set_string(fs_fd.as_fd(), "lowerdir", lowers.as_str())
            .map_err(|e| fail("fsconfig(lowerdir)", e))?;
        for (key, path) in [("upperdir", &v.upper), ("workdir", &v.work)] {
            let value = path.to_string_lossy();
            fsconfig_set_string(fs_fd.as_fd(), key, value.as_ref())
                .map_err(|e| fail(&format!("fsconfig({key})"), e))?;
        }
        if cfg.userxattr {
            fsconfig_set_flag(fs_fd.as_fd(), "userxattr")
                .map_err(|e| fail("fsconfig(userxattr)", e))?;
        }
        if let Some(label) = &cfg.mount_label {
            // the container may use the files whatever the label of the
            // lower layer, which is not relabeled
            fsconfig_set_string(fs_fd.as_fd(), "context", label.as_str())
                .map_err(|e| fail("fsconfig(context)", e))?;
        }
        fsconfig_create(fs_fd.as_fd()).map_err(|e| fail("fsconfig_create", e))?;
        let mount_fd = fsmount(
            fs_fd.as_fd(),
            FsMountFlags::FSMOUNT_CLOEXEC,
            MountAttrFlags::MOUNT_ATTR_NODEV | MountAttrFlags::MOUNT_ATTR_NOSUID,
        )
        .map_err(|e| fail("fsmount", e))?;
        move_mount(
            mount_fd.as_fd(),
            "",
            rustix::fs::CWD,
            &v.target,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .map_err(|e| fail("move_mount", e))
    }

    /// The overlay of the container over the lower layers `lowers` (a
    /// `--rootfs` directory), at its root file system (`RootOverlay`),
    /// attached at the bundle's `rootfs`.
    fn mount_overlay(lowers: &[String], cfg: &ImageConfig) -> io::Result<()> {
        use rustix::mount::{move_mount, MoveMountFlags};
        use std::os::fd::AsFd;
        let (upper, work) = cfg.writable_dirs();
        std::fs::create_dir_all(&upper)?;
        // The overlay of a previous run that was left behind.
        velarx_fuse::detach_stale(&cfg.rootfs)?;
        std::fs::create_dir_all(&cfg.rootfs)?;
        let mount_fd = crate::imagemount::writable_overlay(&crate::imagemount::RootOverlay {
            lowers,
            datas: &[],
            upper: &upper,
            work: &work,
            verity: None,
            userxattr: cfg.userxattr,
            volatile: false,
            stubs: Stubs::Every,
            label: cfg.mount_label.as_deref(),
        })?;
        move_mount(
            mount_fd.as_fd(),
            "",
            rustix::fs::CWD,
            &cfg.rootfs,
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .map_err(|e| io_err(format!("move_mount failed: {e}")))?;
        crate::imagemount::mtab_link(mount_fd.as_fd())
            .map_err(|e| io_err(format!("creating /etc/mtab failed: {e}")))
    }

    impl Drop for Rootfs {
        /// Unmount what was bound, then the root file system.
        fn drop(&mut self) {
            for target in self.bound.drain(..) {
                velarx_fuse::unmount_or_detach(&target);
            }
            if let Some(rootfs) = &self.rootfs {
                velarx_fuse::unmount_or_detach(rootfs);
            }
        }
    }

    #[cfg(test)]
    mod directory_plan_tests {
        use super::*;
        use velarx_fuse::plan::Directory;

        fn plan(beneath: impl AsRef<Path>, path: &str) -> Directory {
            Directory {
                beneath: beneath.as_ref().into(),
                path: path.into(),
            }
        }

        #[test]
        fn a_directory_plan_is_an_absolute_base_and_a_plain_relative_path() {
            let file = Path::new("/b/rootfs.json");
            let chain = Chain::off();
            check_directory_plan(&plan("/var/lib/c/1", "vfs/root"), file, false, &chain).unwrap();
            for (beneath, path) in [
                ("/", "etc"),
                ("/", ""),
                ("var/lib", "root"),
                ("", "root"),
                ("/a/../b", "root"),
                ("/a/./b", "root"),
                ("/var/lib", "/etc"),
                ("/var/lib", ""),
                ("/var/lib", ".."),
                ("/var/lib", "../x"),
                ("/var/lib", "a/../b"),
                ("/var/lib", "a/./b"),
                ("/var/lib", "a//b"),
                ("/var/lib", "a/"),
            ] {
                let e = check_directory_plan(&plan(beneath, path), file, false, &chain)
                    .unwrap_err()
                    .to_string();
                assert!(e.contains("rootfs.json"), "{beneath} {path}: {e}");
                assert!(e.contains("plan is refused"), "{beneath} {path}: {e}");
            }
        }

        #[test]
        fn a_directory_states_no_digest_so_an_enforced_start_is_refused() {
            let e = check_directory_plan(
                &plan("/var/lib/c/1", "root"),
                Path::new("/b/rootfs.json"),
                true,
                &Chain::off(),
            )
            .unwrap_err();
            assert!(e.to_string().contains("enforced"), "{e}");
        }

        /// The directory is what the target shows, its files are the
        /// container's (written through the mount: they are the directory's),
        /// a link in the way is not followed, and the mount is the monitor's
        /// own (a namespace of the test's child).
        #[test]
        fn the_directory_is_mounted_as_the_root_without_following_links() {
            velarx_base::testing::in_child(|| {
                use rustix::thread::UnshareFlags;
                let uid = rustix::process::getuid().as_raw();
                let gid = rustix::process::getgid().as_raw();
                let root = rustix::process::geteuid().is_root();
                let flags = if root {
                    UnshareFlags::NEWNS
                } else {
                    UnshareFlags::NEWNS | UnshareFlags::NEWUSER
                };
                if velarx_sys::ns::unshare(flags).is_err() {
                    eprintln!("SKIPPED: no mount namespace for this user");
                    return;
                }
                if !root {
                    std::fs::write("/proc/self/setgroups", "deny").unwrap();
                    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).unwrap();
                    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).unwrap();
                }
                rustix::mount::mount_change(
                    "/",
                    rustix::mount::MountPropagationFlags::PRIVATE
                        | rustix::mount::MountPropagationFlags::REC,
                )
                .unwrap();
                let d = tempfile::tempdir().unwrap();
                // a shared mount holds the directory, as `/` on a host of
                // systemd
                rustix::mount::mount(
                    "tmpfs",
                    d.path(),
                    "tmpfs",
                    rustix::mount::MountFlags::empty(),
                    None,
                )
                .unwrap();
                rustix::mount::mount_change(d.path(), rustix::mount::MountPropagationFlags::SHARED)
                    .unwrap();
                // (the root of a new tmpfs is 1777: a base others can write
                // is refused)
                std::fs::set_permissions(
                    d.path(),
                    std::os::unix::fs::PermissionsExt::from_mode(0o755),
                )
                .unwrap();
                let (copy, target) = (d.path().join("copy"), d.path().join("rootfs"));
                std::fs::create_dir_all(copy.join("etc")).unwrap();
                std::fs::write(copy.join("etc/os"), "image").unwrap();
                // a mount below the directory (its driver's, or anyone's)
                // does not come with it
                std::fs::create_dir_all(copy.join("sub")).unwrap();
                rustix::mount::mount(
                    "tmpfs",
                    copy.join("sub"),
                    "tmpfs",
                    rustix::mount::MountFlags::empty(),
                    None,
                )
                .unwrap();
                std::fs::write(copy.join("sub/mounted"), "x").unwrap();
                mount_directory(&plan(d.path(), "copy"), &target).unwrap();
                assert!(target.join("sub").is_dir());
                assert!(
                    !target.join("sub/mounted").exists(),
                    "a mount below the directory came with it"
                );
                // nodev, as a composefs root, and no peer of the mount of the
                // directory: what is mounted in one is not in the other
                let table = velarx_sys::statmount::table().unwrap();
                let mount = |p: &Path| {
                    table
                        .iter()
                        .rfind(|m| m.point.as_deref() == Some(p))
                        .unwrap_or_else(|| panic!("{} is not mounted", p.display()))
                };
                let (src, dst) = (mount(d.path()), mount(&target));
                assert!(dst.attr & libc::MOUNT_ATTR_NODEV != 0, "{dst:?}");
                assert_ne!(src.peer_group, 0, "{src:?}");
                assert_ne!(src.peer_group, dst.peer_group, "{src:?}\n{dst:?}");
                std::fs::create_dir_all(target.join("mnt")).unwrap();
                rustix::mount::mount(
                    "tmpfs",
                    target.join("mnt"),
                    "tmpfs",
                    rustix::mount::MountFlags::empty(),
                    None,
                )
                .unwrap();
                std::fs::write(target.join("mnt/only-here"), "x").unwrap();
                assert!(
                    !copy.join("mnt/only-here").exists(),
                    "the mount went to the host"
                );
                assert_eq!(
                    std::fs::read_to_string(target.join("etc/os")).unwrap(),
                    "image"
                );
                std::fs::write(target.join("etc/new"), "written").unwrap();
                assert_eq!(
                    std::fs::read_to_string(copy.join("etc/new")).unwrap(),
                    "written"
                );
                // each refusal below makes nothing: not the mount point,
                // not a directory above it
                let mut n = 0;
                let mut refused = |p: &Directory, why: &str| {
                    n += 1;
                    let at = d.path().join(format!("t{n}/deeper"));
                    let e = mount_directory(p, &at).unwrap_err().to_string();
                    assert!(e.contains(why), "{p:?}: {e} (wanted {why:?})");
                    assert!(
                        !d.path().join(format!("t{n}")).exists(),
                        "{p:?}: nothing made for a refusal"
                    );
                };
                let base = d.path();
                // the base: a directory below the host's `/`
                refused(&plan("/", "etc"), "beneath is `/`");
                refused(&plan("/", "usr"), "beneath is `/`");
                // a path that is not relative, or leaves the base
                refused(&plan(base, "/"), "not relative");
                refused(&plan(base, "/usr"), "not relative");
                refused(&plan(base, ""), "empty");
                refused(&plan(base, ".."), "component");
                refused(&plan(base, "copy/../.."), "component");
                refused(&plan(base, "./copy"), "component");
                // a link as the directory, as a component of it, or to a place
                // outside the base, is refused, not followed
                std::os::unix::fs::symlink("copy", base.join("link")).unwrap();
                std::os::unix::fs::symlink("/usr", base.join("outside")).unwrap();
                std::os::unix::fs::symlink("../..", base.join("copy/up")).unwrap();
                refused(&plan(base, "link"), "root file system");
                refused(&plan(base, "link/etc"), "root file system");
                refused(&plan(base, "outside"), "root file system");
                refused(&plan(base, "outside/bin"), "root file system");
                refused(&plan(base, "copy/up"), "root file system");
                refused(&plan(base, "copy/up/usr"), "root file system");
                // a file, and a path that is not there (the error names it)
                refused(&plan(base, "copy/etc/os"), "root file system");
                refused(&plan(base, "none"), "none");
                // a magic link of /proc on the way, in the base or in the path
                let dfd =
                    rustix::fs::open(&copy, rustix::fs::OFlags::PATH, rustix::fs::Mode::empty())
                        .unwrap();
                let magic = velarx_sys::fd::proc_str(&dfd);
                assert!(Path::new(&magic).join("etc/os").exists());
                refused(&plan(&magic, "etc"), "base");
                refused(&plan(format!("{magic}/etc"), "."), "component");
                refused(&plan(base, "../proc/self/cwd"), "component");
                // the base: a file, a link (or a link on the way to it), a
                // directory that is not there
                refused(&plan(copy.join("etc/os"), "x"), "base");
                refused(&plan(base.join("link"), "etc"), "base");
                refused(&plan(base.join("link/etc"), "os"), "base");
                refused(&plan(base.join("none"), "etc"), "base");
                // the base of another owner (a directory of the host that is
                // not this user's, or, as root, one given to another user) ...
                if root {
                    let other = base.join("other");
                    std::fs::create_dir_all(other.join("copy")).unwrap();
                    std::os::unix::fs::chown(&other, Some(12345), Some(12345)).unwrap();
                    refused(&plan(&other, "copy"), "belongs to user 12345");
                } else {
                    refused(&plan("/usr", "bin"), "belongs to user");
                }
                // ... a base the group or others can write (or, a base that is
                // not writable by them is fine, whatever its other bits)
                for mode in [0o777, 0o775, 0o757, 0o770 | 0o002] {
                    let w = base.join(format!("w{mode:o}"));
                    std::fs::create_dir_all(w.join("copy")).unwrap();
                    std::fs::set_permissions(
                        &w,
                        std::os::unix::fs::PermissionsExt::from_mode(mode),
                    )
                    .unwrap();
                    refused(&plan(&w, "copy"), "written by its group or others");
                }
                let ok = base.join("ok");
                std::fs::create_dir_all(ok.join("copy")).unwrap();
                std::fs::set_permissions(&ok, std::os::unix::fs::PermissionsExt::from_mode(0o750))
                    .unwrap();
                mount_directory(&plan(&ok, "copy"), &base.join("rootfs2")).unwrap();
                rustix::mount::unmount(base.join("rootfs2"), rustix::mount::UnmountFlags::DETACH)
                    .unwrap();
                // a mount on the way (a bind mount of another tree put in the
                // copy, or the copy itself being a mount) is not crossed
                std::fs::create_dir_all(copy.join("bound")).unwrap();
                rustix::mount::mount_bind("/usr", copy.join("bound")).unwrap();
                assert!(copy.join("bound/bin").exists());
                refused(&plan(base, "copy/bound"), "root file system");
                refused(&plan(base, "copy/bound/bin"), "root file system");
                std::fs::create_dir_all(base.join("m")).unwrap();
                rustix::mount::mount_bind(&copy, base.join("m")).unwrap();
                refused(&plan(base, "m"), "root file system");
                // the root and its mount point are not one in the other
                for (dir, at) in [
                    (plan(base, "copy"), copy.join("etc")),
                    (plan(base, "copy/etc"), copy.clone()),
                    (plan(base, "copy"), copy.clone()),
                    (plan(&copy, "etc"), copy.join("etc")),
                ] {
                    let e = mount_directory(&dir, &at).unwrap_err();
                    assert!(e.to_string().contains("one in the other"), "{e}");
                }
                drop(dfd);
                rustix::mount::unmount(d.path(), rustix::mount::UnmountFlags::DETACH).unwrap();
            });
        }

        /// A writer of the base that swaps a link for a component of the
        /// way down while the monitor opens it (an atomic exchange of a
        /// directory and a link to a directory outside the base, in a loop)
        /// never gets the outside mounted: each mount is the directory of the
        /// plan or a refusal.
        #[test]
        fn a_link_swapped_in_on_the_way_is_never_mounted() {
            velarx_base::testing::in_child(|| {
                use rustix::fs::{renameat_with, RenameFlags, CWD};
                use rustix::thread::UnshareFlags;
                use std::sync::atomic::{AtomicBool, Ordering};
                let uid = rustix::process::getuid().as_raw();
                let gid = rustix::process::getgid().as_raw();
                let root = rustix::process::geteuid().is_root();
                let flags = if root {
                    UnshareFlags::NEWNS
                } else {
                    UnshareFlags::NEWNS | UnshareFlags::NEWUSER
                };
                if velarx_sys::ns::unshare(flags).is_err() {
                    eprintln!("SKIPPED: no mount namespace for this user");
                    return;
                }
                if !root {
                    std::fs::write("/proc/self/setgroups", "deny").unwrap();
                    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).unwrap();
                    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).unwrap();
                }
                rustix::mount::mount_change(
                    "/",
                    rustix::mount::MountPropagationFlags::PRIVATE
                        | rustix::mount::MountPropagationFlags::REC,
                )
                .unwrap();
                let d = tempfile::tempdir().unwrap();
                std::fs::set_permissions(
                    d.path(),
                    std::os::unix::fs::PermissionsExt::from_mode(0o755),
                )
                .unwrap();
                let base = d.path().join("base");
                let outside = d.path().join("outside");
                for (dir, what) in [
                    (base.join("a/root"), "plan"),
                    (outside.join("root"), "outside"),
                ] {
                    std::fs::create_dir_all(dir.join("etc")).unwrap();
                    std::fs::write(dir.join("etc/os"), what).unwrap();
                }
                std::fs::set_permissions(
                    &base,
                    std::os::unix::fs::PermissionsExt::from_mode(0o755),
                )
                .unwrap();
                // the swaps: `a` (a component on the way) and `a/root` (the
                // last one) are exchanged with links to the outside
                std::os::unix::fs::symlink(&outside, base.join("la")).unwrap();
                std::os::unix::fs::symlink(outside.join("root"), base.join("a/lroot")).unwrap();
                let stop = std::sync::Arc::new(AtomicBool::new(false));
                let swapper = {
                    let (stop, base) = (stop.clone(), base.clone());
                    std::thread::spawn(move || {
                        let mut n = 0u64;
                        while !stop.load(Ordering::Relaxed) {
                            let (x, y) = if n.is_multiple_of(2) {
                                (base.join("a/root"), base.join("a/lroot"))
                            } else {
                                (base.join("a"), base.join("la"))
                            };
                            renameat_with(CWD, &x, CWD, &y, RenameFlags::EXCHANGE).unwrap();
                            renameat_with(CWD, &x, CWD, &y, RenameFlags::EXCHANGE).unwrap();
                            n += 1;
                        }
                        n
                    })
                };
                let target = d.path().join("rootfs");
                let (mut mounted, mut refused) = (0, 0);
                for _ in 0..2000 {
                    match mount_directory(&plan(&base, "a/root"), &target) {
                        Ok(()) => {
                            mounted += 1;
                            assert_eq!(
                                std::fs::read_to_string(target.join("etc/os")).unwrap(),
                                "plan"
                            );
                            rustix::mount::unmount(&target, rustix::mount::UnmountFlags::DETACH)
                                .unwrap();
                        }
                        Err(_) => refused += 1,
                    }
                }
                stop.store(true, Ordering::Relaxed);
                let swaps = swapper.join().unwrap();
                eprintln!("{mounted} mounted, {refused} refused, {swaps} swaps");
                assert!(swaps > 0 && refused > 0, "the race was not run");
            });
        }

        /// The open below the base holds without the syntax check: `..`,
        /// an absolute path and a way that leaves the base are refused by
        /// the kernel (`RESOLVE_BENEATH`), not only by `Directory::validate`.
        #[test]
        fn the_open_below_the_base_cannot_leave_it() {
            let d = tempfile::tempdir().unwrap();
            let base = d.path().join("base");
            std::fs::create_dir_all(base.join("a/root")).unwrap();
            std::fs::create_dir_all(d.path().join("outside")).unwrap();
            let fd = rustix::fs::open(
                &base,
                rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
                rustix::fs::Mode::empty(),
            )
            .unwrap();
            use std::os::fd::AsFd;
            open_below(fd.as_fd(), Path::new("a/root")).unwrap();
            open_below(fd.as_fd(), Path::new("a/../a/root")).unwrap();
            for bad in ["..", "../outside", "a/../../outside", "/", "/tmp"] {
                assert_eq!(
                    open_below(fd.as_fd(), Path::new(bad)).unwrap_err(),
                    rustix::io::Errno::XDEV,
                    "{bad}"
                );
            }
        }

        /// A `rootfs.json` of the kind `directory` without `beneath` (the
        /// layout of the first vfs) names any directory of the host: it is
        /// refused, by the name of the file and with what to do.
        #[test]
        fn a_plan_file_without_beneath_is_refused_by_name_with_the_remedy() {
            let d = tempfile::tempdir().unwrap();
            let file = d.path().join("rootfs.json");
            let read = || read_spec(&file, (false, VerityDone::None), &Chain::off());
            std::fs::write(&file, br#"{"kind":"directory","path":"/"}"#).unwrap();
            let e = read().unwrap_err().to_string();
            assert!(e.contains(file.to_str().unwrap()), "{e}");
            assert!(e.contains("no `beneath`"), "{e}");
            assert!(
                e.contains("remove the container and create it again"),
                "{e}"
            );
            // a plan with both parts is read, and `/` as its base is refused
            std::fs::write(
                &file,
                br#"{"kind":"directory","beneath":"/b","path":"vfs/root"}"#,
            )
            .unwrap();
            assert!(matches!(read().unwrap(), RootfsPlan::Directory(_)));
            std::fs::write(&file, br#"{"kind":"directory","beneath":"/","path":"etc"}"#).unwrap();
            let e = read().unwrap_err().to_string();
            assert!(
                e.contains(file.to_str().unwrap()) && e.contains("`/`"),
                "{e}"
            );
        }

        #[test]
        fn an_image_mount_that_is_a_directory_is_refused() {
            let cfg: ImageConfig = serde_json::from_value(serde_json::json!({
                "spec": "/b/rootfs.json", "overlay": "/b/overlay", "rootfs": "/b/rootfs",
                "image_mounts": [{"spec": "/b/0.rootfs.json", "target": "/b/0", "destination": "/v0"}],
            }))
            .unwrap();
            let dir = RootfsPlan::Directory(plan("/b", "r"));
            let e = split_mount_fd_volumes(&cfg, None, vec![dir])
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("image mount /v0") && e.contains("type=image"),
                "{e}"
            );
        }
    }

    #[cfg(test)]
    mod subpath_volume_tests {
        use super::*;

        /// A directory or a file of a volume (or of a host directory) is
        /// looked up inside it: a link that points at `/` or at a host path
        /// shows the root of the volume, or nothing, never the host.
        #[test]
        fn a_link_in_the_volume_does_not_lead_out_of_it() {
            velarx_base::testing::in_child(|| {
                use rustix::thread::UnshareFlags;
                let uid = rustix::process::getuid().as_raw();
                let gid = rustix::process::getgid().as_raw();
                let root = rustix::process::geteuid().is_root();
                let flags = if root {
                    UnshareFlags::NEWNS
                } else {
                    UnshareFlags::NEWNS | UnshareFlags::NEWUSER
                };
                // (no skip: the test fails where it cannot be run)
                velarx_sys::ns::unshare(flags)
                    .expect("a mount namespace (and a user namespace) for this test");
                if !root {
                    std::fs::write("/proc/self/setgroups", "deny").unwrap();
                    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1")).unwrap();
                    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1")).unwrap();
                }
                rustix::mount::mount_change(
                    "/",
                    rustix::mount::MountPropagationFlags::PRIVATE
                        | rustix::mount::MountPropagationFlags::REC,
                )
                .unwrap();
                let d = tempfile::tempdir().unwrap();
                let volume = d.path().join("volume");
                std::fs::create_dir_all(volume.join("a/b")).unwrap();
                std::fs::write(volume.join("a/b/file"), "inside").unwrap();
                std::fs::write(volume.join("marker"), "root of the volume").unwrap();
                std::os::unix::fs::symlink("/", volume.join("to-root")).unwrap();
                std::os::unix::fs::symlink("/usr", volume.join("to-usr")).unwrap();
                std::os::unix::fs::symlink("a/b/file", volume.join("to-file")).unwrap();
                std::os::unix::fs::symlink("/etc/passwd", volume.join("to-passwd")).unwrap();
                let mount = |sub: &str, n: u32| {
                    let target = d.path().join(format!("t{n}"));
                    let v = SubpathVolume {
                        volume: volume.clone(),
                        subpath: sub.into(),
                        target: target.clone(),
                    };
                    mount_subpath_volume(&v).map(|()| target)
                };
                // an ordinary sub path is that directory
                let at = mount("a", 0).unwrap();
                assert_eq!(
                    std::fs::read_to_string(at.join("b/file")).unwrap(),
                    "inside"
                );
                // `/` is the root of the volume, not of the host
                let at = mount("to-root", 1).unwrap();
                assert!(at.join("marker").exists() && !at.join("etc").exists());
                // a host path is looked up in the volume, where it is not
                let e = mount("to-usr", 2).unwrap_err().to_string();
                assert!(e.contains("has no to-usr"), "{e}");
                // a file is mounted on a file, also through a link inside
                let at = mount("a/b/file", 3).unwrap();
                assert_eq!(std::fs::read_to_string(&at).unwrap(), "inside");
                let at = mount("to-file", 4).unwrap();
                assert_eq!(std::fs::read_to_string(&at).unwrap(), "inside");
                // ... and a link to a host file is not the host's
                assert!(mount("to-passwd", 5).is_err());
                // the next start mounts what the sub path is now: a
                // directory where a file was (the mount point follows)
                let at = d.path().join("t3");
                rustix::mount::unmount(&at, rustix::mount::UnmountFlags::DETACH).unwrap();
                std::fs::remove_file(volume.join("a/b/file")).unwrap();
                std::fs::create_dir(volume.join("a/b/file")).unwrap();
                std::fs::write(volume.join("a/b/file/in"), "now a directory").unwrap();
                let at = mount("a/b/file", 3).unwrap();
                assert_eq!(
                    std::fs::read_to_string(at.join("in")).unwrap(),
                    "now a directory"
                );
            });
        }
    }

    #[cfg(test)]
    mod mount_fd_plan_tests {
        use super::*;

        fn read(json: &str, enforce: bool) -> io::Result<RootfsPlan> {
            let d = tempfile::tempdir().unwrap();
            let file = d.path().join("rootfs.json");
            std::fs::write(&file, json).unwrap();
            read_spec(&file, (enforce, VerityDone::None), &Chain::off())
        }

        #[test]
        fn a_mount_fd_plan_is_read_with_its_index_only() {
            let plan = read(r#"{"kind":"mount-fd","fd_index":3}"#, false).unwrap();
            assert_eq!(
                plan,
                RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
                    server: false,
                    fd_index: 3,
                    idmap: false
                })
            );
            // an index no monitor can have got, a plan without one, and a
            // descriptor number in the place of the index are errors that
            // name the file
            for bad in [
                r#"{"kind":"mount-fd","fd_index":32}"#,
                r#"{"kind":"mount-fd"}"#,
                r#"{"kind":"mount-fd","fd":3}"#,
            ] {
                let e = read(bad, false).unwrap_err().to_string();
                assert!(e.contains("rootfs.json"), "{bad}: {e}");
            }
        }

        #[test]
        fn a_mount_states_no_digest_so_an_enforced_start_is_refused() {
            let e = read(r#"{"kind":"mount-fd","fd_index":0}"#, true)
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("enforced") && e.contains("storage driver"),
                "{e}"
            );
        }

        /// An enforced start takes a mount of the storage driver when the
        /// engine's own configuration says the driver enforced the digests
        /// (it measured the images, or its server checks the files); a plan
        /// file cannot say it.
        #[test]
        fn a_mount_is_taken_for_enforced_digests_when_the_engine_says_it_enforces_them() {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("rootfs.json");
            std::fs::write(&file, br#"{"kind":"mount-fd","fd_index":0}"#).unwrap();
            for (verity, enforce, ok) in [
                (VerityDone::None, true, false),
                (VerityDone::Kernel, true, true),
                (VerityDone::OnOpen, true, true),
                (VerityDone::None, false, true),
            ] {
                let got = read_spec(&file, (enforce, verity), &Chain::off());
                assert_eq!(got.is_ok(), ok, "{verity:?} enforced {enforce}: {got:?}");
            }
        }

        fn cfg(n: usize) -> ImageConfig {
            let v = |i: usize| serde_json::json!({"spec": format!("/b/{i}.rootfs.json"), "target": format!("/b/{i}"), "destination": format!("/v{i}")});
            serde_json::from_value(serde_json::json!({
                "spec": "/b/rootfs.json", "overlay": "/b/overlay", "rootfs": "/b/rootfs",
                "image_mounts": (0..n).map(v).collect::<Vec<_>>(),
            }))
            .unwrap()
        }

        fn fd(i: u32) -> RootfsPlan {
            RootfsPlan::MountFd(velarx_fuse::plan::MountFd {
                server: false,
                fd_index: i,
                idmap: false,
            })
        }

        fn dir() -> RootfsPlan {
            RootfsPlan::Directory(velarx_fuse::plan::Directory {
                beneath: "/b".into(),
                path: "r".into(),
            })
        }

        #[test]
        fn the_image_mounts_that_are_descriptors_keep_their_place() {
            let fds =
                split_mount_fd_volumes(&cfg(3), Some(&fd(0)), vec![fd(1), fd(3), fd(2)]).unwrap();
            assert_eq!(
                fds.iter()
                    .map(|(i, m)| (*i, m.fd_index))
                    .collect::<Vec<_>>(),
                [(0, 1), (1, 3), (2, 2)]
            );
        }

        #[test]
        fn a_descriptor_is_named_once_and_there_are_at_most_fifteen() {
            let e = |root: Option<RootfsPlan>, v: Vec<RootfsPlan>| {
                let n = v.len();
                split_mount_fd_volumes(&cfg(n), root.as_ref(), v)
                    .unwrap_err()
                    .to_string()
            };
            let e1 = e(Some(fd(0)), vec![fd(0)]);
            assert!(
                e1.contains("image mount /v0")
                    && e1.contains("descriptor 0")
                    && e1.contains("the root file system"),
                "{e1}"
            );
            let e2 = e(None, vec![fd(1), fd(2), fd(1)]);
            assert!(
                e2.contains("image mount /v2") && e2.contains("image mount /v0"),
                "{e2}"
            );
            // (a root that is not a mount names no descriptor)
            split_mount_fd_volumes(&cfg(1), Some(&dir()), vec![fd(0)]).unwrap();
            let max = (1..=15).map(fd).collect::<Vec<_>>();
            split_mount_fd_volumes(&cfg(15), Some(&fd(0)), max).unwrap();
            let sixteen = (0..16).map(fd).collect::<Vec<_>>();
            let e3 = e(None, sixteen);
            assert!(
                e3.contains("16 image mounts") && e3.contains("at most 15"),
                "{e3}"
            );
        }
    }
}

#[cfg(not(feature = "fuse"))]
mod imp {
    use super::*;

    pub struct Rootfs;

    pub fn mount(_cfg: &ImageConfig, _run_dir: &Path) -> io::Result<Rootfs> {
        Err(io::Error::other("built without FUSE"))
    }
}

pub use imp::{mount, Rootfs};

/// Keep the descriptors the engine passed for the root file systems (the
/// monitor's, for its life: each is attached once, by the plan that names it).
#[cfg(feature = "fuse")]
pub fn keep_mount_fds(fds: Vec<Option<std::os::fd::OwnedFd>>) {
    mount_fd::HELD.keep(fds);
}

#[cfg(not(feature = "fuse"))]
pub fn keep_mount_fds(_fds: Vec<Option<std::os::fd::OwnedFd>>) {}

/// The root file system bound where the runtime can reach it from the user
/// namespace of the container (see `userns::rootless::public_rootfs`),
/// unbound when it is dropped.
pub struct PublicRoot(PathBuf);

/// Set once the monitor has a mount namespace of its own.
pub static PRIVATE_MOUNTS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Take a mount namespace of the monitor's own, a slave of the current one
/// (the mounts of the host still reach the containers), so that what the
/// monitor mounts stays in it and goes away with it.  Before any thread.
pub fn private_mount_namespace() -> io::Result<()> {
    velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNS)?;
    rustix::mount::mount_change(
        "/",
        rustix::mount::MountPropagationFlags::DOWNSTREAM
            | rustix::mount::MountPropagationFlags::REC,
    )
    .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    PRIVATE_MOUNTS.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

impl PublicRoot {
    /// Bind `rootfs` on `public`, below a directory of the user that anyone
    /// may traverse and nobody list.  A root monitor first takes a mount
    /// namespace of its own: the bind is seen by nobody else.
    pub fn bind(rootfs: &Path, public: &Path) -> io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        let err = |e: rustix::io::Errno| io::Error::from_raw_os_error(e.raw_os_error());
        if rustix::process::geteuid().is_root()
            && !crate::userns::rootless::in_user_namespace().map_err(io::Error::other)?
            && !PRIVATE_MOUNTS.load(std::sync::atomic::Ordering::Relaxed)
        {
            velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNS)?;
            rustix::mount::mount_change(
                "/",
                rustix::mount::MountPropagationFlags::DOWNSTREAM
                    | rustix::mount::MountPropagationFlags::REC,
            )
            .map_err(err)?;
        }
        let base = public
            .parent()
            .ok_or_else(|| io::Error::other("invalid public root file system path"))?;
        match std::fs::DirBuilder::new().mode(0o711).create(base) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        crate::userns::rootless::check_public_base(base, rustix::process::geteuid().as_raw())?;
        let st = std::fs::symlink_metadata(base)?;
        if st.mode() & 0o7777 != 0o711 {
            std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o711))?;
        }
        match std::fs::DirBuilder::new().mode(0o700).create(public) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        rustix::mount::mount_bind(rootfs, public).map_err(err)?;
        Ok(Self(public.to_path_buf()))
    }
}

impl Drop for PublicRoot {
    fn drop(&mut self) {
        use rustix::mount::{unmount, UnmountFlags};
        if unmount(&self.0, UnmountFlags::empty()).is_err() {
            let _ = unmount(&self.0, UnmountFlags::DETACH);
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}
