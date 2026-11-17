// SPDX-License-Identifier: Apache-2.0
//! What the daemon tells a monitor: the file `monitor.json` of its run
//! directory.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use velarx_wire::monitor::logfmt::Limits;

pub use velarx_wire::wire::LogDriver;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default)]
    pub driver: LogDriver,
    /// The other drivers the output goes to too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also: Vec<LogDriver>,
    /// The log file of the `k8s-file` driver.
    pub path: PathBuf,
    /// The directory of the allowlist (`log_path_allowlist`) that `path`
    /// is in: it is opened below it, without following symbolic links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_dir: Option<PathBuf>,
    #[serde(default)]
    pub max_size: u64,
    #[serde(default)]
    pub max_files: u32,
    #[serde(default)]
    pub global_max: u64,
    /// Compress the rotated files
    #[serde(default)]
    pub compress: bool,
    /// `SYSLOG_IDENTIFIER` and `CONTAINER_TAG` of the journal records.
    #[serde(default)]
    pub tag: Option<String>,
    /// Fields of the journal records: the container's name, its image and
    /// its labels.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl LogConfig {
    pub fn limits(&self) -> Limits {
        Limits {
            max_size: self.max_size,
            max_files: self.max_files,
            global_max: self.global_max,
            compress: self.compress,
        }
    }
}

/// The root file system of a container, which the monitor mounts: the
/// images of the layers of the image, mounted by the kernel or served by a
/// FUSE file system of the monitor, under an overlay with the container's
/// own upper layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageConfig {
    /// How the images of the layers are mounted (the bundle's
    /// `rootfs.json`, `velarx_fuse::plan::RootfsPlan`).
    pub spec: PathBuf,
    /// The directory of the overlay in the bundle (what a configuration
    /// without `upper` and `work` has them in: `upper` and `work`).
    pub overlay: PathBuf,
    /// The upper directory of the overlay of the root file system, where the
    /// storage driver has the writable layer of the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper: Option<PathBuf>,
    /// The work directory of the overlay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<PathBuf>,
    pub rootfs: PathBuf,
    /// Mount the root file system (an image mount alone needs none).
    #[serde(default = "yes")]
    pub mount_rootfs: bool,
    /// The digests are enforced: an image without fs-verity, a file system
    /// that cannot measure it, an overlay that cannot check the files, and
    /// files the store lacks are errors, and the overlay has
    /// `verity=require`.
    #[serde(default)]
    pub enforce: bool,
    /// The engine logs at debug: with `enforce` the monitor logs at debug
    /// too, and says each link of the chain of an enforced image it checks
    /// (`verity chain:` lines of its log, which the engine repeats in its
    /// own).
    #[serde(default)]
    pub debug: bool,
    /// The links of the chain of trust the engine checked, for the monitor
    /// to go on from (only with `debug`, for an enforced image).
    #[serde(default)]
    pub chain: Option<ChainPlan>,
    /// What enforces the digests of the root file system when it is a mount
    /// the storage driver handed over (`mount-fd`), as the engine checked the
    /// driver's answer: with `enforce`, the monitor mounts nothing it could
    /// measure, so a mount descriptor is refused unless this says the driver
    /// did (`kernel`: the monitor then looks at the overlay it attached).
    #[serde(default)]
    pub verity: velarx_fuse::plan::VerityDone,
    /// The root file system is this directory (`--rootfs`).
    #[serde(default)]
    pub rootfs_dir: Option<RootfsMount>,
    /// The owners of the files are shown as these ids: a user namespace of
    /// the container, or the ids of the daemon's.  Also the users of that
    /// namespace may then look at the file system (`allow_other`).
    #[serde(default)]
    pub translate: Option<velarx_fuse::IdTranslate>,
    /// The processes that serve the mounts the storage driver handed over
    /// (`MountFd::server`) go to the cgroup of the monitor.  False for a
    /// container with `--cgroups=disabled`, which touches no cgroup.
    #[serde(default)]
    pub servers_in_cgroup: bool,
    /// The overlay uses the extended attributes of unprivileged mounts.
    #[serde(default = "yes")]
    pub userxattr: bool,
    /// The SELinux context of the files of the root file system (`context=`)
    #[serde(default)]
    pub mount_label: Option<String>,
    /// Images that are mounted in the container (`--mount type=image`).
    #[serde(default)]
    pub image_mounts: Vec<ImageVolume>,
    /// Overlay volumes (`-v SRC:DST:O`).
    #[serde(default)]
    pub overlay_volumes: Vec<OverlayVolume>,
    /// Directories of volumes (`--mount type=volume,...,subpath=`).
    #[serde(default)]
    pub subpath_volumes: Vec<SubpathVolume>,
}

impl ImageConfig {
    /// The upper and the work directory of the overlay of the root file
    /// system.
    pub fn writable_dirs(&self) -> (PathBuf, PathBuf) {
        (
            self.upper
                .clone()
                .unwrap_or_else(|| self.overlay.join("upper")),
            self.work
                .clone()
                .unwrap_or_else(|| self.overlay.join("work")),
        )
    }
}

fn yes() -> bool {
    true
}

/// A directory that is the root file system: bound, or under the container's
/// overlay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RootfsMount {
    pub path: PathBuf,
    pub overlay: bool,
    /// The mounts is idmapped: the ids of the directory and the ids they
    /// become (the parent ids of the container's namespace).
    #[serde(default)]
    pub uid_mappings: Vec<crate::container::IdMapping>,
    #[serde(default)]
    pub gid_mappings: Vec<crate::container::IdMapping>,
}

/// A directory of a volume, looked up inside it (a link cannot lead out of
/// it) and mounted at `target` from what was looked up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubpathVolume {
    pub volume: PathBuf,
    pub subpath: String,
    pub target: PathBuf,
}

/// An overlay volume: `lower` under an upper layer, mounted at `target`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OverlayVolume {
    pub lower: PathBuf,
    pub upper: PathBuf,
    pub work: PathBuf,
    pub target: PathBuf,
    /// The upper layer is the container's: emptied at each start
    #[serde(default)]
    pub discard: bool,
    /// The owner a new upper layer gets (the root of the container)
    #[serde(default)]
    pub owner: Option<(u32, u32)>,
}

/// An image mounted in a container: its layers are served and bound at `target`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageVolume {
    /// How the images of its layers are mounted (`imagevol/N.rootfs.json`).
    pub spec: PathBuf,
    /// A directory of the image, looked up inside it.
    pub subpath: Option<String>,
    /// Where it is bound: the source of the OCI mount.
    pub target: PathBuf,
    /// Where it is mounted in the container (the debug log names it).
    #[serde(default)]
    pub destination: String,
    #[serde(default)]
    pub chain: Option<ChainPlan>,
    /// What enforces its digests (`ImageConfig::verity`).
    #[serde(default)]
    pub verity: velarx_fuse::plan::VerityDone,
}

/// Where the chain of trust of an image is when the engine hands it to the
/// monitor (`velarx_wire::chain::Chain::resume`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainPlan {
    /// The links of the chain in all.
    pub total: usize,
    /// The links the engine checked.
    pub done: usize,
    /// The digests of those links, in order.
    pub trail: Vec<String>,
    /// The layers whose EROFS images the engine's storage driver measured
    /// (a mount it hands over as a descriptor): the layer, from 1, its blob
    /// and the digest measured.
    #[serde(default)]
    pub layers: Vec<(usize, String, String)>,
    /// The last layer whose files the server of the mount checks (from 2; 0:
    /// none), where the overlay follows the stubs of the lowest layer only.
    #[serde(default)]
    pub fuse_layers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub id: String,
    /// Where the root file system is bound for the runtime, which the user
    /// namespace of the container could not reach in the bundle.
    #[serde(default)]
    pub public_rootfs: Option<PathBuf>,
    /// The OCI runtime and the options that go before its command.
    pub runtime: PathBuf,
    #[serde(default)]
    pub runtime_args: Vec<String>,
    pub runtime_root: PathBuf,
    /// The soft limit of open files the runtime and what it starts get, the
    /// container's and its `exec` commands' when the spec has no rlimit of
    /// its own: the limit the engine had from its user before it raised its
    /// own (none: the monitor's own).
    #[serde(default)]
    pub open_files: Option<u64>,
    /// Create the container with `--no-new-keyring`: it keeps the session
    /// keyring of the monitor (`[containers] keyring = false`).
    #[serde(default)]
    pub no_new_keyring: bool,
    /// The runtime takes `create --config` (a restart spec that is not the
    /// bundle's; else it gets a bundle of its own).
    #[serde(default)]
    pub create_config: bool,
    pub bundle: PathBuf,
    #[serde(default)]
    pub tty: bool,
    /// What `exec --user` gives the user besides its own group: the
    /// container's `--group-add`, and the groups of the image that list it
    /// unless `groups_strict` (`exec::exec_process`).
    #[serde(default)]
    pub group_add: Vec<String>,
    #[serde(default)]
    pub groups_strict: bool,
    /// The environment of the container names a HOME (the image's, `--env`):
    /// else the engine added the home of the container's user, which is not
    /// the home of another user an exec runs as.
    #[serde(default)]
    pub env_has_home: bool,
    /// Keep the stdin of the container open for attach clients.
    #[serde(default)]
    pub stdin_open: bool,
    /// Where the runtime hands the terminal to the monitor (a short path).
    #[serde(default)]
    pub console_socket: Option<PathBuf>,
    #[serde(default)]
    pub log: LogConfig,
    /// How long after the exit of the container to wait for the rest of its
    /// output, in milliseconds.
    #[serde(default = "default_drain_ms")]
    pub drain_ms: u64,
    /// How long a client may refuse the output before it is dropped, in
    /// milliseconds.  The container waits for it meanwhile.
    #[serde(default = "default_stall_ms")]
    pub client_stall_ms: u64,
    /// Kill the container after it ran for this many seconds.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub health: Option<velarx_proto::health::Healthcheck>,
    /// The signal that stops the container, and the time it has to obey
    /// (for a health check that stops it).
    #[serde(default = "default_stop_signal")]
    pub stop_signal: i32,
    /// What the monitor does with the sd_notify protocol, and the socket of
    /// the service manager it talks to.
    #[serde(default)]
    pub sdnotify: super::notify::SdNotify,
    /// The restart policy, which the monitor applies.
    #[serde(default)]
    pub restart: super::restart::RestartConfig,
    #[serde(default = "default_stop_timeout")]
    pub stop_timeout_secs: u64,
    /// The root file system and the images to serve and mount before the
    /// container is created.
    #[serde(default)]
    pub image: Option<ImageConfig>,
    /// The published host ports (`-p`, bridge networks) that the monitor
    /// keeps bound while the container lives, so that no service of the
    /// host takes them and the DNAT of the firewall does not hide one.
    #[serde(default)]
    pub hold_ports: Vec<String>,
    /// What the monitor records and releases when its container runs,
    /// exits and goes (`monitor::settle`): its store, its events, its
    /// network, its files.  None: nothing is recorded (the tests of the
    /// monitor).
    #[serde(default)]
    pub settle: Option<crate::settle::SettlePlan>,
    /// Go on in a child and let the process that started the monitor exit
    /// at once: under a service manager, the monitor is then the manager's
    /// child (see `server::leave_parent`).
    #[serde(default)]
    pub leave_parent: bool,
    /// The descriptors the monitor was passed besides its first connection
    /// (`--varlink-fd`), by their numbers: computed once by the engine.
    #[serde(default)]
    pub fds: velarx_base::spawn::InheritedFds,
    /// Which of them (0 is the container's 3) the container does not get:
    /// the gaps of `run --preserve-fd`.
    #[serde(default)]
    pub preserve_holes: Vec<u32>,
    /// The SELinux label of the socket that the container sends its
    /// sd_notify messages to: the container's own process label, which may
    /// send to a socket of its type (and not to one of the monitor's).
    #[serde(default)]
    pub notify_label: Option<String>,
    /// Mount in a mount namespace of the monitor's own, a slave of the one
    /// it was started in: what it mounts (the root file system, image and
    /// overlay volumes) is seen by nobody else and goes away with it.  Off
    /// for a container whose mounts must reach the host (`rshared`).
    #[serde(default)]
    pub private_mounts: bool,
    /// The container goes with its exit (`--rm`): the exit plan it starts
    /// with, which `Update` changes.
    #[serde(default)]
    pub auto_remove: bool,
    /// `--pidfile`: written with the pid of the init process at each
    /// creation of the container
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_file: Option<PathBuf>,
    /// `--conmon-pidfile`: written with the monitor's own pid when it
    /// starts, before it answers (a `Type=forking` unit reads it once the
    /// command returned)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor_pid_file: Option<PathBuf>,
}

fn default_stop_signal() -> i32 {
    15
}

fn default_stop_timeout() -> u64 {
    10
}

fn default_stall_ms() -> u64 {
    30_000
}

fn default_drain_ms() -> u64 {
    1000
}

impl MonitorConfig {
    pub fn read(dir: &std::path::Path) -> std::io::Result<Self> {
        let data = std::fs::read(dir.join(velarx_wire::monitor::proto::CONFIG_FILE))?;
        serde_json::from_slice(&data).map_err(std::io::Error::other)
    }

    pub fn write(&self, dir: &std::path::Path) -> std::io::Result<()> {
        let data = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        velarx_base::atomic_file::write(
            &dir.join(velarx_wire::monitor::proto::CONFIG_FILE),
            &data,
            0o666,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_of_log_drivers() {
        assert_eq!(
            LogDriver::parse_list("k8s-file, syslog").unwrap(),
            vec![LogDriver::K8sFile, LogDriver::Syslog]
        );
        assert_eq!(
            LogDriver::parse_list("passthrough").unwrap(),
            vec![LogDriver::Passthrough]
        );
        for bad in ["", "x", "syslog,syslog", "journald,none"] {
            assert!(LogDriver::parse_list(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn config_survives_a_round_trip_and_defaults_apply() {
        let dir = tempfile::tempdir().unwrap();
        let cfg: MonitorConfig = serde_json::from_str(
            r#"{"id":"abc","runtime":"/usr/bin/crun","runtime_root":"/r","bundle":"/b"}"#,
        )
        .unwrap();
        assert_eq!(cfg.drain_ms, 1000);
        assert_eq!(cfg.log.driver, LogDriver::K8sFile);
        cfg.write(dir.path()).unwrap();
        let back = MonitorConfig::read(dir.path()).unwrap();
        assert_eq!(back.id, "abc");
    }

    /// A configuration written before the storage driver named the upper
    /// and work directories (a container started by an older engine) has
    /// them in `overlay`; a newer one has them as the driver gave them.
    #[test]
    fn the_writable_directories_of_old_and_new_configurations() {
        let old = serde_json::json!({
            "spec": "/b/rootfs.json", "overlay": "/b/overlay", "rootfs": "/b/rootfs",
        });
        let image: ImageConfig = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(
            image.writable_dirs(),
            ("/b/overlay/upper".into(), "/b/overlay/work".into())
        );
        // (and written back without the fields it did not have)
        let back = serde_json::to_value(&image).unwrap();
        assert!(back.get("upper").is_none() && back.get("work").is_none());
        let mut new = old;
        new["upper"] = "/d/u".into();
        new["work"] = "/d/w".into();
        let image: ImageConfig = serde_json::from_value(new).unwrap();
        assert_eq!(image.writable_dirs(), ("/d/u".into(), "/d/w".into()));
    }

    #[test]
    fn drivers_by_name() {
        assert_eq!(LogDriver::parse("journald"), Some(LogDriver::Journald));
        assert_eq!(LogDriver::parse("k8s-file"), Some(LogDriver::K8sFile));
        assert_eq!(LogDriver::parse("syslog"), Some(LogDriver::Syslog));
        assert_eq!(LogDriver::parse("gelf"), None);
    }
}
