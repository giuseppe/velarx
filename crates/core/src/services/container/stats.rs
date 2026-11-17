// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_db::RecordState;

/// The bytes of the files below `path`, links not followed (a link is a
/// link: the copy of an image in the bundle may hold one to a directory of
/// the host, or to itself).
fn dir_size(path: &Path) -> u64 {
    velarx_base::tree::usage(
        path,
        &velarx_base::tree::Measure {
            lenient: true,
            ..Default::default()
        },
    )
    .map_or(0, |u| u.file_bytes.saturating_add(u.other_bytes))
}

impl ContainerService {
    /// Calculate the size of a container's bundle directory
    pub(super) fn calculate_container_size(&self, container_id: &str) -> u64 {
        let bundle_path = self.bundle_dir(container_id);
        if !bundle_path.exists() {
            return 0;
        }

        dir_size(&bundle_path)
    }

    /// Get container resource statistics
    pub async fn get_stats(&self, id: &str) -> ContainerResult<ContainerStats> {
        let container = self.db.get_container(id).await?;
        // its process is in the cgroup of whatever started it, whose usage
        // is not the container's
        if !has_own_cgroup(&container) {
            return Err(ContainerError::InvalidArgument(format!(
                "container {} has no cgroup of its own (--cgroups=disabled): no stats",
                container.id
            )));
        }

        let nets = networks(&container)?;
        // The cgroup it was made in: wherever the engine made it (the
        // server's tree, a systemd scope, a split unit).  A container that
        // does not run has none.
        let cgroup_stats = match container
            .pid
            .filter(|p| *p > 0 && container.state == RecordState::Running)
        {
            Some(_) => match Self::own_cgroup_dir(&container)? {
                Some(dir) => crate::services::cgroup::stats_at(&dir)
                    .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?,
                // (made without one: it is in the cgroup of its monitor)
                None => {
                    return Err(ContainerError::InvalidArgument(format!(
                        "container {} has no cgroup of its own (it runs in the cgroup of its \
                         monitor): no stats",
                        container.id
                    )))
                }
            },
            None => Default::default(),
        };
        let memory_percent = match cgroup_stats.memory_limit {
            Some(limit) if limit > 0 => (cgroup_stats.memory_usage as f64 / limit as f64) * 100.0,
            _ => 0.0,
        };
        Ok(ContainerStats {
            name: container.name,
            id: container.id,
            // CPU times are in microseconds, convert to nanoseconds
            cpu_percent: 0.0, // Would need time delta for accurate percentage
            cpu_usage_ns: cgroup_stats.cpu_usage_usec * 1000,
            cpu_user_ns: cgroup_stats.cpu_user_usec * 1000,
            cpu_system_ns: cgroup_stats.cpu_system_usec * 1000,
            cpu_periods: cgroup_stats.cpu_periods,
            cpu_throttled_periods: cgroup_stats.cpu_throttled_periods,
            cpu_throttled_ns: cgroup_stats.cpu_throttled_usec * 1000,
            memory_usage: cgroup_stats.memory_usage,
            memory_limit: cgroup_stats.memory_limit,
            memory_percent,
            memory_anon: cgroup_stats.memory_anon,
            memory_file: cgroup_stats.memory_file,
            memory_swap: cgroup_stats.memory_swap_usage,
            memory_swap_limit: cgroup_stats.memory_swap_limit,
            memory_working_set: cgroup_stats
                .memory_usage
                .saturating_sub(cgroup_stats.memory_inactive_file),
            page_faults: cgroup_stats.page_faults,
            major_page_faults: cgroup_stats.major_page_faults,
            io_read_bytes: cgroup_stats.io_read_bytes,
            io_write_bytes: cgroup_stats.io_write_bytes,
            pids: cgroup_stats.pids_current,
            pids_limit: cgroup_stats.pids_limit,
            networks: nets,
            pressure: cgroup_stats.pressure,
        })
    }

    /// The directory of the cgroup the container was made in (its recorded
    /// `linux.cgroupsPath`), when it has one of its own: not with
    /// `--cgroups=disabled` (its process is in the cgroup of whatever
    /// started it) nor when it was made in the cgroup of its monitor.  For a
    /// container that runs (a systemd path is found from its process).
    pub(super) fn own_cgroup_dir(
        container: &velarx_db::ContainerRecord,
    ) -> ContainerResult<Option<PathBuf>> {
        let config = stored_config(container)?;
        let Some(path) = config
            .cgroups_path
            .filter(|_| config.cgroups != velarx_wire::request::CgroupsMode::Disabled)
        else {
            return Ok(None);
        };
        crate::services::cgroup::container_dir(&path, container.pid.unwrap_or(0))
            .map(Some)
            .map_err(|e| ContainerError::Io(std::io::Error::other(e)))
    }

    /// The processes of the cgroup of the container and of those below it
    /// (exec sessions included, and what its processes moved below); none
    /// for a container with no cgroup of its own or that does not run.
    pub(super) fn cgroup_pids(
        container: &velarx_db::ContainerRecord,
    ) -> ContainerResult<Vec<String>> {
        if !container.pid.is_some_and(|p| p > 0) {
            return Ok(Vec::new());
        }
        Ok(Self::own_cgroup_dir(container)?
            .map(|dir| crate::services::cgroup::procs_below(&dir))
            .unwrap_or_default())
    }
}

/// The interfaces of the network namespace of a running container.
fn networks(
    container: &ContainerRecord,
) -> ContainerResult<std::collections::BTreeMap<String, velarx_wire::wire::NetworkCounters>> {
    match container
        .pid
        .filter(|p| *p > 0 && container.state == RecordState::Running)
    {
        Some(pid) => read_net_dev(Path::new(&format!("/proc/{pid}/net/dev"))),
        None => Ok(Default::default()),
    }
}

/// The counters in the file `path` (`/proc/PID/net/dev`): none when the
/// process ended meanwhile, an error when it cannot be read.
fn read_net_dev(
    path: &Path,
) -> ContainerResult<std::collections::BTreeMap<String, velarx_wire::wire::NetworkCounters>> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(velarx_wire::wire::NetworkCounters::parse_net_dev(&t)),
        // (the process ended meanwhile)
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(rustix::io::Errno::SRCH.raw_os_error()) =>
        {
            Ok(Default::default())
        }
        Err(e) => Err(ContainerError::Io(std::io::Error::new(
            e.kind(),
            format!("reading {}: {e}", path.display()),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_size_of_a_bundle_counts_its_files_and_links_and_follows_none() {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path();
        std::fs::create_dir_all(t.join("a/b")).unwrap();
        std::fs::write(t.join("a/f"), "12345").unwrap();
        std::fs::write(t.join("a/b/g"), "123").unwrap();
        // (a link to a directory of the host, and to itself: a link of 4 bytes)
        std::os::unix::fs::symlink("/usr", t.join("a/host")).unwrap();
        assert_eq!(dir_size(t), 8 + 4);
        assert_eq!(dir_size(&t.join("nothing")), 0);
    }

    #[test]
    fn network_counters_fail_loudly() {
        let dir = tempfile::tempdir().unwrap();
        // an ended process has none; a file that cannot be read is an error
        assert!(read_net_dev(&dir.path().join("gone")).unwrap().is_empty());
        assert!(read_net_dev(dir.path()).is_err());
        let dev = dir.path().join("dev");
        std::fs::write(
            &dev,
            "Inter-|   Receive\n face |bytes\n  eth0: 1 2 0 0 0 0 0 0 3 4 0 0 0 0 0 0\n",
        )
        .unwrap();
        assert!(read_net_dev(&dev).unwrap().contains_key("eth0"));
    }

    /// A link is a link: one to a directory of the host, or to its own
    /// directory (the copy of an image in a bundle may hold either), adds
    /// the size of the link and nothing of where it leads, and is not a loop.
    #[test]
    fn the_size_of_a_bundle_follows_no_link() {
        let t = tempfile::tempdir().unwrap();
        let (outside, bundle) = (t.path().join("outside"), t.path().join("bundle"));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("big"), vec![0u8; 100_000]).unwrap();
        std::fs::create_dir_all(bundle.join("d")).unwrap();
        std::fs::write(bundle.join("d/f"), vec![0u8; 10]).unwrap();
        std::os::unix::fs::symlink(&outside, bundle.join("d/out")).unwrap();
        std::os::unix::fs::symlink(".", bundle.join("d/loop")).unwrap();
        let size = dir_size(&bundle);
        assert!(
            (10..1000).contains(&size),
            "10 bytes and two short links: {size}"
        );
    }
}
