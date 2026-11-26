// SPDX-License-Identifier: Apache-2.0
use super::*;

/// The mounts and the user namespace of a container: `run` and `create`
/// share them.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct MountArgs {
    /// Bind mount a volume
    #[arg(long, short)]
    pub volume: Vec<String>,

    /// Mount the volumes of another container, CONTAINER[:ro|:rw]
    #[arg(long, value_name = "CONTAINER[:OPTIONS]")]
    pub volumes_from: Vec<String>,

    /// Mount a tmpfs
    #[arg(long)]
    pub tmpfs: Vec<String>,

    /// Attach a filesystem mount (type=bind|volume|tmpfs|image,...)
    #[arg(long)]
    pub mount: Vec<String>,

    /// What to do with the volumes of the image: bind (an anonymous
    /// volume each, the default), tmpfs or ignore
    #[arg(long)]
    pub image_volume: Option<String>,

    /// User namespace to use
    #[arg(long)]
    pub userns: Option<String>,

    /// UID map for user namespace
    #[arg(long)]
    pub uidmap: Vec<String>,

    /// GID map for user namespace
    #[arg(long)]
    pub gidmap: Vec<String>,

    /// Name of range in /etc/subuid
    #[arg(long)]
    pub subuidname: Option<String>,

    /// Name of range in /etc/subgid
    #[arg(long)]
    pub subgidname: Option<String>,
}

/// What `create` and `run` take: the container they make.
#[derive(clap::Args, Clone, Debug)]
pub struct CreateArgs {
    /// Assign a name to the container
    #[arg(long)]
    pub name: Option<String>,

    #[command(flatten)]
    pub storage: MountArgs,

    /// Keep STDIN open even if not attached
    #[arg(long, short = 'i', action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true, default_value_t = false)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY
    #[arg(long, short, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true, default_value_t = false)]
    pub tty: bool,

    /// Set environment variables
    #[arg(long, short, allow_hyphen_values = true)]
    pub env: Vec<String>,

    /// Read environment variables from file
    #[arg(long)]
    pub env_file: Vec<String>,

    /// Pass the environment of this command to the container
    #[arg(long)]
    pub env_host: bool,

    /// Pass the proxy variables of this command (http_proxy, https_proxy,
    /// ftp_proxy, no_proxy and their capitals) to the container
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1,
          default_missing_value = "true", require_equals = true)]
    pub http_proxy: bool,

    /// How many times a failed pull of the image is tried again
    #[arg(long, value_name = "N")]
    pub retry: Option<u32>,

    /// The time between the tries of --retry (default: 1s)
    #[arg(long, value_name = "DURATION")]
    pub retry_delay: Option<String>,

    /// Working directory inside the container
    #[arg(long, short)]
    pub workdir: Option<String>,

    /// Give extended privileges to container
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true, default_value_t = false)]
    pub privileged: bool,

    /// Make containers root filesystem read-only
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true, default_value_t = false)]
    pub read_only: bool,

    /// Automatically remove container when it exits
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true)]
    pub rm: Option<bool>,

    /// Remove the image after the exit of the container, unless another
    /// container uses it (implies --rm)
    #[arg(long)]
    pub rmi: bool,

    /// Container hostname
    #[arg(long, short = 'h')]
    pub hostname: Option<String>,

    /// Add the passwd entry of a user of the host (name or UID, a list)
    #[arg(long, value_delimiter = ',', value_name = "NAME")]
    pub hostuser: Vec<String>,

    /// The base of /etc/hosts: a path, none or image
    #[arg(long, value_name = "PATH|none|image")]
    pub hosts_file: Option<String>,

    /// Directories of the container that are roots too: the files the
    /// engine mounts in the root are mounted in them as well (a list)
    #[arg(long, value_delimiter = ',', value_name = "PATH")]
    pub chrootdirs: Vec<String>,

    /// The Intel RDT class of service of the container
    #[arg(long, value_name = "CLASS")]
    pub rdt_class: Option<String>,

    /// Where the seccomp profile comes from: default, or image (the label
    /// io.containers.seccomp.profile of the image)
    #[arg(long, value_name = "POLICY")]
    pub seccomp_policy: Option<String>,

    /// Add GPUs: all, or the names of the devices of the CDI class
    /// nvidia.com/gpu (a list)
    #[arg(long, value_name = "ENTRY", value_delimiter = ',')]
    pub gpus: Vec<String>,

    /// Attach to stdin, stdout or stderr (all of them by default)
    #[arg(long, short = 'a', value_name = "STREAM", value_parser = parse_attach_stream)]
    pub attach: Vec<String>,

    /// Make the container an init container of its pod (always|once): it
    /// runs to its end before the other containers when the pod starts
    #[arg(long, value_name = "TYPE")]
    pub init_ctr: Option<String>,

    /// Taken as podman takes it, with an error: velarx pulls no encrypted
    /// image
    #[arg(long, hide = true, allow_hyphen_values = true)]
    pub decryption_key: Vec<String>,

    /// A Docker specific option, ignored
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true, default_value_t = false)]
    pub disable_content_trust: bool,

    /// Set custom DNS servers
    #[arg(long)]
    pub dns: Vec<String>,

    /// Set custom DNS search domains
    #[arg(long)]
    pub dns_search: Vec<String>,

    /// Set custom DNS options
    #[arg(long, alias = "dns-opt")]
    pub dns_option: Vec<String>,

    /// Add custom host-to-IP mapping (host[;host]:ip, ip may be host-gateway)
    #[arg(long)]
    pub add_host: Vec<String>,

    /// Connect a container to a network (can be specified multiple times);
    /// NAME:ip=,ip6=,mac=,alias=,interface_name= gives that network its own
    /// address, MAC address, aliases and interface name
    #[arg(long, visible_alias = "net")]
    pub network: Vec<String>,

    /// Add network-scoped alias for the container
    #[arg(long)]
    pub network_alias: Vec<String>,

    /// Specify a static IPv4 address for the container
    #[arg(long)]
    pub ip: Option<String>,

    /// Specify a static IPv6 address for the container
    #[arg(long)]
    pub ip6: Option<String>,

    /// Publish a container's port to the host
    #[arg(long, short = 'p')]
    pub publish: Vec<String>,

    /// Publish all exposed ports to random ports
    #[arg(long, short = 'P')]
    pub publish_all: bool,

    /// Memory limit (format: <number>[<unit>])
    #[arg(long, short = 'm')]
    pub memory: Option<String>,

    /// Memory soft limit
    #[arg(long)]
    pub memory_reservation: Option<String>,

    /// Swap limit equal to memory plus swap
    #[arg(long)]
    pub memory_swap: Option<String>,

    /// Number of CPUs
    #[arg(long)]
    pub cpus: Option<f64>,

    /// CPU shares (relative weight)
    #[arg(long, short = 'c')]
    pub cpu_shares: Option<u64>,

    /// Limit the CPU CFS quota
    #[arg(long)]
    pub cpu_quota: Option<i64>,

    /// Limit the CPU CFS period
    #[arg(long)]
    pub cpu_period: Option<u64>,

    /// CPUs in which to allow execution (0-3, 0,1)
    #[arg(long)]
    pub cpuset_cpus: Option<String>,

    /// Memory nodes in which to allow execution
    #[arg(long)]
    pub cpuset_mems: Option<String>,

    /// Tune container pids limit (-1 for unlimited)
    #[arg(long)]
    pub pids_limit: Option<i64>,

    /// Add a host device to the container: HOST[:CONTAINER][:PERMISSIONS], or
    /// a CDI device, vendor.com/class=name, from the spec files of
    /// the configuration's `[containers] cdi_spec_dirs` (/etc/cdi, /var/run/cdi)
    #[arg(long)]
    pub device: Vec<String>,

    /// Add a rule to the cgroup allowed devices list
    #[arg(long)]
    pub device_cgroup_rule: Vec<String>,

    /// Add capabilities to the container
    #[arg(long)]
    pub cap_add: Vec<String>,

    /// Drop capabilities from the container
    #[arg(long)]
    pub cap_drop: Vec<String>,

    /// Security options: seccomp=PROFILE|unconfined, seccomp-bpf=FILE (a
    /// compiled filter, e.g. from easyseccomp), no-new-privileges[=BOOL],
    /// apparmor=, label=, mask=PATHS, unmask=PATHS|ALL, proc-opts=,
    /// systempaths=unconfined, verity=enforce (the digests of the EROFS
    /// images of the layers in the manifest are enforced at every start),
    /// verity=off (the chain of trust held by default, from the digest the
    /// container was made from or an accepted signature down to the files, is
    /// not held; refused where the digests or signatures are required)
    #[arg(long)]
    pub security_opt: Vec<String>,

    /// Ulimit options
    #[arg(long)]
    pub ulimit: Vec<String>,

    /// Restart policy ("no"|"on-failure"|"always"|"unless-stopped")
    #[arg(long)]
    pub restart: Option<String>,

    /// Run an init binary inside the container
    #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true, default_value_t = false)]
    pub init: bool,

    /// Path to the container-init binary
    #[arg(long)]
    pub init_path: Option<String>,

    /// Username or UID
    #[arg(long, short = 'u')]
    pub user: Option<String>,

    /// Add additional groups
    #[arg(long, value_delimiter = ',')]
    pub group_add: Vec<String>,

    /// Override the default ENTRYPOINT
    #[arg(long)]
    pub entrypoint: Option<String>,

    /// Set metadata on container
    #[arg(long, short = 'l')]
    pub label: Vec<String>,

    /// Read in a file of labels
    #[arg(long)]
    pub label_file: Vec<String>,

    /// Add annotations to container
    #[arg(long)]
    pub annotation: Vec<String>,

    /// Size of /dev/shm
    #[arg(long)]
    pub shm_size: Option<String>,

    /// Disable OOM Killer
    #[arg(long)]
    pub oom_kill_disable: bool,

    /// Tune the host's OOM preferences (-1000 to 1000)
    #[arg(long)]
    pub oom_score_adj: Option<i32>,

    /// Signal to stop a container
    #[arg(long)]
    pub stop_signal: Option<String>,

    /// Timeout to stop a container
    #[arg(long)]
    pub stop_timeout: Option<u32>,

    /// Set a healthcheck command
    #[arg(long)]
    pub health_cmd: Option<String>,

    /// Set an interval for the healthcheck
    #[arg(long)]
    pub health_interval: Option<String>,

    /// Set healthcheck timeout
    #[arg(long)]
    pub health_timeout: Option<String>,

    /// Set healthcheck start period
    #[arg(long)]
    pub health_start_period: Option<String>,

    /// Set healthcheck retries
    #[arg(long)]
    pub health_retries: Option<u32>,

    /// Action to take when healthcheck fails (none, kill, restart, stop)
    #[arg(long)]
    pub health_on_failure: Option<String>,

    /// A check that runs until the container has started; the regular
    /// one begins once it passed (needs --health-cmd)
    #[arg(long)]
    pub health_startup_cmd: Option<String>,

    /// The interval of the startup check (default 30s)
    #[arg(long)]
    pub health_startup_interval: Option<String>,

    /// Failures of the startup check after which the container is
    /// restarted (default 0: never)
    #[arg(long)]
    pub health_startup_retries: Option<u32>,

    /// Successes of the startup check before the regular check begins
    /// (default 0: one)
    #[arg(long)]
    pub health_startup_success: Option<u32>,

    /// The timeout of the startup check (default 30s)
    #[arg(long)]
    pub health_startup_timeout: Option<String>,

    /// Where the results of the checks go: local (the state of the
    /// container), events_logger, or a directory
    #[arg(long)]
    pub health_log_destination: Option<String>,

    /// How many results are kept (default 5, 0: no limit)
    #[arg(long)]
    pub health_max_log_count: Option<u32>,

    /// How many characters of each result's output are kept (default
    /// 500, 0: no limit)
    #[arg(long)]
    pub health_max_log_size: Option<u32>,

    /// Disable healthchecks on container
    #[arg(long)]
    pub no_healthcheck: bool,

    #[command(flatten)]
    pub spec: SpecArgs,

    /// PID namespace to use
    #[arg(long)]
    pub pid: Option<String>,

    /// IPC namespace to use
    #[arg(long)]
    pub ipc: Option<String>,

    /// UTS namespace to use
    #[arg(long)]
    pub uts: Option<String>,

    /// Cgroup namespace to use
    #[arg(long)]
    pub cgroupns: Option<String>,

    /// Sysctl options
    #[arg(long)]
    pub sysctl: Vec<String>,

    /// Run container in systemd mode
    #[arg(long)]
    pub systemd: Option<String>,

    /// Set timezone in container
    #[arg(long)]
    pub tz: Option<String>,

    /// Set umask in container
    #[arg(long)]
    pub umask: Option<String>,

    /// Block IO weight (10-1000)
    #[arg(long)]
    pub blkio_weight: Option<u16>,

    /// Block IO weight of a device, DEVICE:WEIGHT
    #[arg(long, value_name = "DEVICE:WEIGHT")]
    pub blkio_weight_device: Vec<String>,

    /// Limit read rate from a device (bytes/sec)
    #[arg(long)]
    pub device_read_bps: Vec<String>,

    /// Limit write rate to a device (bytes/sec)
    #[arg(long)]
    pub device_write_bps: Vec<String>,

    /// Limit read rate from a device (IO/sec)
    #[arg(long)]
    pub device_read_iops: Vec<String>,

    /// Limit write rate to a device (IO/sec)
    #[arg(long)]
    pub device_write_iops: Vec<String>,

    /// Write the container ID to a file
    #[arg(long)]
    pub cidfile: Option<String>,

    /// Optional parent cgroup
    #[arg(long)]
    pub cgroup_parent: Option<String>,

    /// Expose a port
    #[arg(long)]
    pub expose: Vec<String>,

    /// Container MAC address
    #[arg(long)]
    pub mac_address: Option<String>,

    /// Logging driver for the container
    #[arg(long)]
    pub log_driver: Option<String>,

    /// Logging driver options
    #[arg(long)]
    pub log_opt: Vec<String>,

    /// Maximum container runtime before it is killed
    #[arg(long)]
    pub timeout: Option<u32>,

    /// How the sd_notify protocol is handled: container (the container
    /// sends it, the monitor forwards the allowed messages), conmon
    /// (the monitor says that the container runs), healthy (when its health
    /// check first passes) or ignore
    #[arg(long, value_parser = ["container", "conmon", "healthy", "ignore"])]
    pub sdnotify: Option<String>,

    /// Where the container and its monitor go: enabled (a cgroup of its
    /// own), disabled (no cgroup is made for anything the command starts:
    /// the container, its monitor and its helpers stay in the cgroup of
    /// the command, the OCI runtime is told as well; a resource limit or
    /// --cgroup-parent is an error), no-conmon (the monitor stays
    /// where it is started), split (for a command, the cgroup of the caller,
    /// a systemd unit's, is split in two: one for the monitor, one for the
    /// container; for the engine service, the default: the container is
    /// `[POD-ID/]CTR-ID/container` next to the `engine` cgroup the service
    /// split at its start, its monitor in `runtime` beside it; an error where
    /// the service has no delegated cgroup), scope (enabled, a systemd scope of
    /// its own for a container of the engine service, outside the engine's
    /// unit); enabled is `split` for the service unless [containers] cgroups
    /// is scope
    #[arg(long, value_parser = ["enabled", "scope", "disabled", "no-conmon", "split"])]
    pub cgroups: Option<String>,

    /// Run container in an existing pod
    #[arg(long)]
    pub pod: Option<String>,

    /// Read the pod ID from the file (its first line)
    #[arg(long, value_name = "FILE")]
    pub pod_id_file: Option<PathBuf>,

    /// Replace existing container with same name
    #[arg(long)]
    pub replace: bool,

    /// Do not create /etc/hosts
    #[arg(long)]
    pub no_hosts: bool,

    /// Allow running with lazy-pulled image (files fetched on-demand)
    #[arg(long)]
    pub lazy: bool,

    /// Pull policy: always, missing, never or newer (true is always, false is never)
    #[arg(
        long,
        default_value = "missing",
        value_parser = parse_pull_policy
    )]
    pub pull: PullPolicy,

    /// The platform of the image, OS/ARCH[/VARIANT] (pulled when the one of
    /// the store is another)
    #[arg(long)]
    pub platform: Option<String>,

    /// The OS of the image, instead of the one of the machine
    #[arg(long)]
    pub os: Option<String>,

    /// The architecture of the image, instead of the one of the machine
    #[arg(long)]
    pub arch: Option<String>,

    /// The variant of the architecture of the image
    #[arg(long)]
    pub variant: Option<String>,

    /// Verify the TLS certificates of the registry when the image is pulled
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub tls_verify: bool,

    /// Add a secret: name[,type=mount|env][,target=...][,uid=...][,gid=...][,mode=...]
    #[arg(long)]
    pub secret: Vec<String>,

    /// The image argument is the root file system of the container, a
    /// directory (PATH[:O] for a writable overlay on it)
    #[arg(long)]
    pub rootfs: bool,

    /// Image to run
    pub image: String,

    /// Command to run
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,

    /// cgroup v2 settings of the container (KEY=VALUE)
    #[arg(long)]
    pub cgroup_conf: Vec<String>,

    /// Say nothing of the pull of the image
    #[arg(long, short)]
    pub quiet: bool,

    /// Taken and ignored, as podman: kernel memory limits are gone
    #[arg(long, hide = true)]
    pub kernel_memory: Option<String>,

    /// How the pull of the image authenticates
    #[command(flatten)]
    pub access: RegistryAccessArgs,
}

impl CreateArgs {
    /// Whether the runtime places the container in a cgroup by what is asked
    /// (resource limits, a parent slice, a pod's), not in the scope made in
    /// advance for it (`services::scope`), which would have to be cancelled.
    pub fn needs_cgroup_placement(&self) -> bool {
        self.memory.is_some()
            || self.memory_reservation.is_some()
            || self.memory_swap.is_some()
            || self.cpus.is_some()
            || self.cpu_shares.is_some()
            || self.cpu_quota.is_some()
            || self.cpu_period.is_some()
            || self.cpuset_cpus.is_some()
            || self.cpuset_mems.is_some()
            || self.pids_limit.is_some()
            || self.blkio_weight.is_some()
            || !self.blkio_weight_device.is_empty()
            || !self.device_read_bps.is_empty()
            || !self.device_write_bps.is_empty()
            || !self.device_read_iops.is_empty()
            || !self.device_write_iops.is_empty()
            || !self.cgroup_conf.is_empty()
            || self.cgroup_parent.is_some()
            || self.pod.is_some()
    }
}

/// `stats --interval`: whole seconds, at least one (podman's words).
fn parse_stats_interval(s: &str) -> Result<u64, String> {
    match s.parse::<i64>() {
        Ok(n) if n >= 1 => Ok(n as u64),
        Ok(_) => Err("invalid interval, must be a positive number greater zero".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// How `stats` shows what it reads.
#[derive(clap::Args, Clone, Debug)]
pub struct StatsView {
    /// Seconds between the reports
    #[arg(long, short = 'i', default_value_t = 5, value_name = "SECONDS", value_parser = parse_stats_interval)]
    pub interval: u64,
    /// Do not clear the terminal between the reports
    #[arg(long)]
    pub no_reset: bool,
    /// Do not truncate the IDs
    #[arg(long)]
    pub no_trunc: bool,
}

/// The limits `container clone` changes in the new container.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct CloneArgs {
    /// Block IO weight (relative weight) accepts a weight value between 10
    /// and 1000
    #[arg(long)]
    pub blkio_weight: Option<u64>,
    /// Block IO weight (relative device weight)
    #[arg(long, value_name = "DEVICE_NAME:WEIGHT")]
    pub blkio_weight_device: Vec<String>,
    /// Limit the CPU CFS (Completely Fair Scheduler) period
    #[arg(long)]
    pub cpu_period: Option<u64>,
    /// Limit the CPU CFS (Completely Fair Scheduler) quota
    #[arg(long, allow_negative_numbers = true)]
    pub cpu_quota: Option<i64>,
    /// CPU shares (relative weight)
    #[arg(long, short = 'c')]
    pub cpu_shares: Option<u64>,
    /// Number of CPUs; 0 means no limit
    #[arg(long)]
    pub cpus: Option<f64>,
    /// CPUs in which to allow execution (0-3, 0,1)
    #[arg(long)]
    pub cpuset_cpus: Option<String>,
    /// Memory nodes in which to allow execution (0-3, 0,1); only effective
    /// on NUMA systems
    #[arg(long)]
    pub cpuset_mems: Option<String>,
    /// Limit read rate (bytes per second) from a device
    #[arg(long)]
    pub device_read_bps: Vec<String>,
    /// Limit write rate (bytes per second) to a device
    #[arg(long)]
    pub device_write_bps: Vec<String>,
    /// Memory limit (number and unit: b, k, m or g)
    #[arg(long, short = 'm')]
    pub memory: Option<String>,
    /// Memory soft limit
    #[arg(long)]
    pub memory_reservation: Option<String>,
    /// Swap limit equal to memory plus swap: -1 to enable unlimited swap
    #[arg(long, allow_negative_numbers = true)]
    pub memory_swap: Option<String>,
}

impl CloneArgs {
    /// The settings given, as the ones of `update`.
    pub fn as_update(&self) -> UpdateArgs {
        UpdateArgs {
            cpus: self.cpus,
            cpu_shares: self.cpu_shares,
            cpu_period: self.cpu_period,
            cpu_quota: self.cpu_quota,
            cpuset_cpus: self.cpuset_cpus.clone(),
            cpuset_mems: self.cpuset_mems.clone(),
            memory: self.memory.clone(),
            memory_reservation: self.memory_reservation.clone(),
            memory_swap: self.memory_swap.clone(),
            blkio_weight: self.blkio_weight,
            blkio_weight_device: self.blkio_weight_device.clone(),
            device_read_bps: self.device_read_bps.clone(),
            device_write_bps: self.device_write_bps.clone(),
            ..Default::default()
        }
    }

    /// Whether any limit is given.
    pub fn is_empty(&self) -> bool {
        self.as_update() == UpdateArgs::default()
    }
}

/// What `update` changes.
#[derive(clap::Args, Clone, Debug, Default, PartialEq)]
pub struct UpdateArgs {
    #[arg(long)]
    pub cpus: Option<f64>,
    #[arg(long, short = 'c')]
    pub cpu_shares: Option<u64>,
    #[arg(long)]
    pub cpu_period: Option<u64>,
    #[arg(long)]
    pub cpu_quota: Option<i64>,
    #[arg(long)]
    pub cpuset_cpus: Option<String>,
    #[arg(long)]
    pub cpuset_mems: Option<String>,
    #[arg(long, short = 'm')]
    pub memory: Option<String>,
    #[arg(long)]
    pub memory_reservation: Option<String>,
    #[arg(long)]
    pub memory_swap: Option<String>,
    #[arg(long)]
    pub pids_limit: Option<i64>,
    /// Set environment variables for the next start, NAME=VALUE
    #[arg(long, short, allow_hyphen_values = true)]
    pub env: Vec<String>,
    /// Unset environment variables for the next start
    #[arg(long)]
    pub unsetenv: Vec<String>,
    /// no, always, on-failure[:N], unless-stopped
    #[arg(long)]
    pub restart: Option<String>,
    /// Block IO weight, between 10 and 1000
    #[arg(long)]
    pub blkio_weight: Option<u64>,
    /// Block IO weight of a device, DEVICE:WEIGHT
    #[arg(long, value_name = "DEVICE:WEIGHT")]
    pub blkio_weight_device: Vec<String>,
    /// Limit read rate (bytes per second) from a device, DEVICE:RATE
    #[arg(long)]
    pub device_read_bps: Vec<String>,
    /// Limit write rate (bytes per second) to a device, DEVICE:RATE
    #[arg(long)]
    pub device_write_bps: Vec<String>,
    /// Limit read rate (IO per second) from a device, DEVICE:RATE
    #[arg(long)]
    pub device_read_iops: Vec<String>,
    /// Limit write rate (IO per second) to a device, DEVICE:RATE
    #[arg(long)]
    pub device_write_iops: Vec<String>,
    /// Ulimit options, for the next start
    #[arg(long, value_delimiter = ',')]
    pub ulimit: Vec<String>,
    /// Disable the health checks
    #[arg(long)]
    pub no_healthcheck: bool,
    #[arg(long, allow_hyphen_values = true)]
    pub health_cmd: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_interval: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_log_destination: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_max_log_count: Option<u64>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_max_log_size: Option<u64>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_on_failure: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_retries: Option<u64>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_start_period: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_startup_cmd: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_startup_interval: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_startup_retries: Option<u64>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_startup_success: Option<u64>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_startup_timeout: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    pub health_timeout: Option<String>,
}

/// How podman's lifecycle commands choose their containers, besides by
/// name: `--latest`, `--cidfile`, `--filter`.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct Targets {
    /// The container made last
    #[arg(long, short = 'l')]
    pub latest: bool,
    /// Read the ID of a container from this file
    #[arg(long)]
    pub cidfile: Vec<String>,
    /// The containers that match (KEY=VALUE, as ps --filter)
    #[arg(long)]
    pub filter: Vec<String>,
}

#[derive(Subcommand, Clone)]
pub enum ContainerCommands {
    #[command(about = "Create a container", disable_help_flag = true)]
    Create {
        /// Print help
        #[arg(long, action = clap::ArgAction::HelpLong)]
        help: Option<bool>,
        #[command(flatten)]
        create: Box<CreateArgs>,
    },

    #[command(about = "Start a container")]
    Start {
        /// Attach to the container's output and wait for it to exit
        #[arg(long, short)]
        attach: bool,
        /// Keep STDIN open (with --attach)
        #[arg(long, short = 'i')]
        interactive: bool,
        /// Keys that detach from the container (default ctrl-p,ctrl-q)
        #[arg(long)]
        detach_keys: Option<String>,
        /// Forward the signals this command gets to the container (with --attach)
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        sig_proxy: bool,
        /// Start every container that is not running
        #[arg(long)]
        all: bool,
        /// With --all, only the containers that match: should-start-on-boot=true
        /// (a restart policy of always, or unless-stopped and not stopped by
        /// its user: what velarx-restart.service starts at boot)
        #[arg(long, short = 'f')]
        filter: Vec<String>,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        /// The digest (sha256:... or sha512:...) of the manifest of the image the
        /// container is made from (not of an index), of an image mounted in it
        /// too (repeat): the start holds the images
        /// to it (refused where the digests are not held: --security-opt
        /// verity=off, [storage] verity_chain = "off", an image no digest or
        /// signature vouches for, a store without fs-verity)
        #[arg(long, value_name = "DIGEST")]
        verify_image: Vec<String>,
        /// Start as the service manager does at boot, not as a user: the
        /// images of a container made from a digest are held to the digest
        /// recorded in it
        #[arg(long, hide = true, conflicts_with = "verify_image")]
        service: bool,
        containers: Vec<String>,
    },

    #[command(about = "Stop a container", mut_arg("filter", |a| a.short('f')))]
    Stop {
        /// Seconds to wait before SIGKILL (default: the container's stop timeout)
        #[arg(long, short, allow_negative_numbers = true, value_parser = parse_time_u32, visible_alias = "timeout")]
        time: Option<u32>,
        /// Stop every running container
        #[arg(long, short)]
        all: bool,
        /// Stop as the service manager does at shutdown, not as a user: an
        /// unless-stopped container starts again at the next boot
        #[arg(long, hide = true)]
        service: bool,
        /// Do not fail on a container that does not exist
        #[arg(long, short = 'i')]
        ignore: bool,
        #[command(flatten)]
        targets: Targets,
        containers: Vec<String>,
    },

    #[command(about = "Restart a container", mut_arg("filter", |a| a.short('f')))]
    Restart {
        /// Seconds to wait before SIGKILL (default: the container's stop timeout)
        #[arg(long, short, allow_negative_numbers = true, value_parser = parse_time_u32)]
        time: Option<u32>,
        /// Restart every container
        #[arg(long, short)]
        all: bool,
        /// With --all, only the running containers
        #[arg(long)]
        running: bool,
        /// As `start --verify-image`
        #[arg(long, value_name = "DIGEST")]
        verify_image: Vec<String>,
        #[command(flatten)]
        targets: Targets,
        containers: Vec<String>,
    },

    #[command(about = "Kill a container")]
    Kill {
        #[arg(long, short, default_value = "SIGKILL", allow_hyphen_values = true)]
        signal: String,
        /// Kill every running container
        #[arg(long, short)]
        all: bool,
        #[command(flatten)]
        targets: Targets,
        containers: Vec<String>,
    },

    #[command(about = "Remove a container")]
    Rm {
        #[arg(long, short)]
        force: bool,
        #[arg(long, short)]
        volumes: bool,
        /// Do not fail on a container that does not exist
        #[arg(long, short = 'i')]
        ignore: bool,
        /// Remove every container
        #[arg(long, short)]
        all: bool,
        /// Remove the containers that depend on it first
        #[arg(long)]
        depend: bool,
        /// Seconds a running container has to obey its stop signal before it
        /// is killed (with --force; default: its stop timeout, 0: killed at
        /// once, negative: no limit)
        #[arg(long, short, allow_negative_numbers = true, value_parser = parse_time_u64)]
        time: Option<u64>,
        #[command(flatten)]
        targets: Targets,
        containers: Vec<String>,
    },

    #[command(about = "Remove all stopped containers")]
    Prune {
        /// Do not prompt for confirmation
        #[arg(long, short)]
        force: bool,
        /// Filter containers (e.g., "until=24h", "label=env=test")
        #[arg(long)]
        filter: Vec<String>,
    },

    #[command(about = "List containers", visible_aliases = ["ls", "ps"])]
    List {
        #[arg(long, short)]
        all: bool,
        #[command(flatten)]
        out: report::PsOutput,
        #[command(flatten)]
        ps: report::PsArgs,
    },

    #[command(about = "Check if a container exists (exit 0) or not (exit 1)")]
    Exists {
        /// Also the containers of other tools in the storage (velarx's store
        /// has none: the answer is the same)
        #[arg(long)]
        external: bool,
        container: String,
    },

    #[command(about = "Create the runtime's container of a container, without starting it")]
    Init {
        /// Every container that was created and not started
        #[arg(long, short)]
        all: bool,
        #[command(flatten)]
        targets: Targets,
        containers: Vec<String>,
    },

    #[command(about = "List the ports a container publishes, or the host's of one of them")]
    Port {
        /// The ports of all the containers
        #[arg(long, short)]
        all: bool,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        container: Option<String>,
        /// A port of the container (`80`, `80/tcp`)
        private: Option<String>,
    },

    #[command(about = "Show container details")]
    Inspect {
        /// Go template of each container, or `json`
        #[arg(long, short)]
        format: Option<String>,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        /// The sizes of the files of the containers (SizeRw, SizeRootFs)
        #[arg(long, short)]
        size: bool,
        containers: Vec<String>,
    },

    #[command(about = "Execute a command in a container")]
    Exec {
        #[arg(long, short = 'i')]
        interactive: bool,
        #[arg(long, short)]
        tty: bool,
        #[arg(long, short)]
        env: Vec<String>,
        #[arg(long, short)]
        workdir: Option<String>,
        /// User (and group) to run the command as: UID[:GID] or a name
        #[arg(long, short = 'u')]
        user: Option<String>,
        /// Give the command extended privileges
        #[arg(long)]
        privileged: bool,
        /// Kill the command (and what it started) after this many seconds
        #[arg(long)]
        timeout: Option<u64>,
        /// Run the command in the background
        #[arg(long, short)]
        detach: bool,
        /// Read environment variables from a file
        #[arg(long)]
        env_file: Vec<String>,
        /// Keys that detach from the command, which goes on (default
        /// ctrl-p,ctrl-q with --tty)
        #[arg(long)]
        detach_keys: Option<String>,
        /// Act on the container made last: the first argument is then the
        /// command
        #[arg(long, short = 'l')]
        latest: bool,
        /// Read the ID of the container from this file: the first argument
        /// is then the command
        #[arg(long)]
        cidfile: Option<String>,
        /// Run it without a session of the engine, as the commands with a
        /// terminal do: the engine neither records it nor buffers its output
        #[arg(long)]
        no_session: bool,
        /// Pass N additional file descriptors (3 to 2+N) of this command to
        /// the command (at most 16)
        #[arg(long, value_name = "N", default_value_t = 0)]
        preserve_fds: u32,
        /// Pass the file descriptors FD1[,FD2,...] of this command to the
        /// command; may be repeated
        #[arg(long, value_name = "FD", value_delimiter = ',')]
        preserve_fd: Vec<u32>,
        container: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    #[command(about = "Write the root file system of a container as a tar")]
    Export {
        /// Write it to this file, not to the standard output
        #[arg(long, short)]
        output: Option<PathBuf>,
        container: String,
    },

    #[command(
        about = "Mount the root file system of containers and print where; without one, list the mounted containers"
    )]
    Mount {
        /// Mount all containers (only those that run can be: velarx
        /// mounts the root of a running container)
        #[arg(long, short)]
        all: bool,
        /// `json` or a Go template of the list of the mounted containers
        #[arg(long)]
        format: Option<String>,
        /// Act on the container made last
        #[arg(long, short)]
        latest: bool,
        /// Do not truncate the IDs of the list
        #[arg(long)]
        no_trunc: bool,
        containers: Vec<String>,
    },

    #[command(about = "Unmount the root file system of containers", alias = "umount")]
    Unmount {
        /// Unmount all of the currently mounted containers
        #[arg(long, short)]
        all: bool,
        /// Unmount even if other processes mounted it too (velarx's mounts
        /// are not counted: it always does)
        #[arg(long, short)]
        force: bool,
        /// Act on the container made last
        #[arg(long, short)]
        latest: bool,
        containers: Vec<String>,
    },

    #[command(about = "Change the resource limits or restart policy of a container")]
    Update {
        #[command(flatten)]
        set: Box<UpdateArgs>,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        container: Option<String>,
    },

    #[command(about = "Clone an existing container")]
    Clone {
        #[command(flatten)]
        set: Box<CloneArgs>,
        /// Destroy the original container
        #[arg(long)]
        destroy: bool,
        /// Force the existing container to be destroyed
        #[arg(long, short)]
        force: bool,
        /// Assign a name to the container
        #[arg(long)]
        name: Option<String>,
        /// Run the container in an existing pod
        #[arg(long)]
        pod: Option<String>,
        /// Run the new container
        #[arg(long)]
        run: bool,
        /// With --run, the digest (sha256:... or sha512:...) of the image the new container
        /// is made from, of an image mounted in it too (repeat): as `start
        /// --verify-image`
        #[arg(long, value_name = "DIGEST", requires = "run")]
        verify_image: Vec<String>,
        container: String,
        /// The name of the new container (CONTAINER-clone without)
        new_name: Option<String>,
        /// The image of the new container (the one of the original without)
        image: Option<String>,
    },

    #[command(about = "Attach to a container")]
    Attach {
        /// Keys that detach from the container (default ctrl-p,ctrl-q)
        #[arg(long)]
        detach_keys: Option<String>,
        /// Do not attach STDIN
        #[arg(long)]
        no_stdin: bool,
        /// Forward the signals this command gets to the container
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        sig_proxy: bool,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        container: Option<String>,
    },

    #[command(about = "Fetch container logs")]
    Logs {
        #[arg(long, short)]
        follow: bool,
        /// The last lines only (-1: all of them)
        #[arg(long, allow_negative_numbers = true)]
        tail: Option<i64>,
        #[arg(long, short)]
        timestamps: bool,
        /// Show logs since timestamp (RFC3339, Unix timestamp, or relative like "1h", "30m", "2d")
        #[arg(long, allow_hyphen_values = true)]
        since: Option<String>,
        /// Show logs until timestamp (RFC3339, Unix timestamp, or relative like "1h", "30m", "2d")
        #[arg(long, allow_hyphen_values = true)]
        until: Option<String>,
        /// With several containers, each line starts with the name of its
        /// container (else its ID)
        #[arg(long, short)]
        names: bool,
        /// Each container's lines in a color of its own
        #[arg(long)]
        color: bool,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        containers: Vec<String>,
    },

    #[command(about = "Open the log file of a running container again after it was rotated")]
    ReopenLog { container: String },

    #[command(about = "Wait for container to exit")]
    Wait {
        /// Wait for one of these instead of the exit (configured, created,
        /// exited, healthy, initialized, next-exit, not-running, paused,
        /// removed, removing, running, stopped, stopping, unhealthy); the
        /// exit code, -1 for a condition that is no exit
        #[arg(long, value_delimiter = ',')]
        condition: Vec<String>,
        /// Do not fail on a container that does not exist (-1)
        #[arg(long)]
        ignore: bool,
        /// The polling interval (a duration, or milliseconds), ignored: velarx
        /// follows the events of the container and does not poll
        #[arg(long, short = 'i', default_value = "250ms", allow_hyphen_values = true)]
        interval: String,
        /// The first container that meets a condition: its exit code alone
        #[arg(long)]
        exit_first_match: bool,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        containers: Vec<String>,
    },

    #[command(about = "Copy files/folders between a container and the local filesystem")]
    Cp {
        /// The files given to a container belong to its user (else they keep
        /// the owners of the archive)
        #[arg(long, short = 'a', default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        archive: bool,
        /// A directory may replace what is not one in the destination, and
        /// the other way round
        #[arg(long)]
        overwrite: bool,
        /// Source path (CONTAINER:SRC_PATH or SRC_PATH)
        src: String,
        /// Destination path (CONTAINER:DEST_PATH or DEST_PATH)
        dest: String,
    },

    #[command(about = "Display a live stream of container resource usage statistics")]
    Stats {
        /// Show all containers (default shows just running)
        #[arg(long, short)]
        all: bool,
        /// Disable streaming stats and only pull the first result
        #[arg(long)]
        no_stream: bool,
        /// Pretty-print output
        #[arg(long)]
        format: Option<String>,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        #[command(flatten)]
        view: StatsView,
        /// Containers to show stats for
        containers: Vec<String>,
    },

    #[command(about = "Display the running processes of a container")]
    Top {
        /// Act on the container made last: all the arguments are then ps
        /// options
        #[arg(long, short = 'l')]
        latest: bool,
        /// Container ID or name
        #[arg(allow_hyphen_values = true)]
        container: Option<String>,
        /// ps options
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        ps_args: Vec<String>,
    },

    #[command(about = "Pause all processes within one or more containers", mut_arg("filter", |a| a.short('f')))]
    Pause {
        /// Pause every running container
        #[arg(long, short)]
        all: bool,
        #[command(flatten)]
        targets: Targets,
        containers: Vec<String>,
    },

    #[command(about = "Show what a container changed in its image")]
    Diff {
        /// `json`: {"changed": [...], "added": [...], "deleted": [...]}
        #[arg(long)]
        format: Option<String>,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        /// Container name or ID
        container: Option<String>,
    },

    #[command(about = "Unpause all processes within one or more containers", mut_arg("filter", |a| a.short('f')))]
    Unpause {
        /// Unpause every paused container
        #[arg(long, short)]
        all: bool,
        #[command(flatten)]
        targets: Targets,
        containers: Vec<String>,
    },

    #[command(about = "Rename a container")]
    Rename {
        /// Current container name
        container: String,
        /// New container name
        new_name: String,
    },

    #[command(about = "Create and run a container", disable_help_flag = true)]
    Run {
        /// Print help
        #[arg(long, action = clap::ArgAction::HelpLong)]
        help: Option<bool>,
        #[command(flatten)]
        create: Box<CreateArgs>,

        /// Run container in background and print container ID
        #[arg(long, short, action = clap::ArgAction::Set, num_args = 0..=1, default_missing_value = "true", require_equals = true, default_value_t = false)]
        detach: bool,

        /// This process is the monitor of the container: no
        /// velarx-monitor process is started, the command waits for the
        /// container (not with --detach)
        #[arg(long, conflicts_with = "detach")]
        no_monitor: bool,

        /// Keys that detach from the container (default ctrl-p,ctrl-q)
        #[arg(long)]
        detach_keys: Option<String>,

        /// Forward the signals this command gets to the container
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
        sig_proxy: bool,

        /// Pass N additional file descriptors (3 to 2+N) of this command to
        /// the container
        #[arg(long, value_name = "N", default_value_t = 0)]
        preserve_fds: u32,

        /// Pass the file descriptors FD1[,FD2,...] of this command to the
        /// container; may be repeated
        #[arg(long, value_name = "FD", value_delimiter = ',')]
        preserve_fd: Vec<u32>,
    },

    #[command(about = "Checkpoint one or more running containers (CRIU, through the runtime)")]
    Checkpoint(Box<checkpoint::CheckpointArgs>),

    #[command(about = "Restore one or more containers from their checkpoint")]
    Restore(Box<checkpoint::RestoreArgs>),
}

/// The pid files of a container, for `Type=forking` units.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct PidFileArgs {
    /// Write the pid of the container's init process to this file
    #[arg(long)]
    pub pidfile: Option<String>,

    /// Write the pid of the container's monitor to this file (what a
    /// `Type=forking` unit takes as its main process)
    #[arg(long)]
    pub conmon_pidfile: Option<String>,
}

impl PidFileArgs {
    /// The paths, made absolute against the current directory.
    pub fn absolute(&self) -> anyhow::Result<(Option<String>, Option<String>)> {
        let abs = |p: &Option<String>| -> anyhow::Result<Option<String>> {
            match p.as_deref() {
                None => Ok(None),
                Some("") => Err(anyhow::anyhow!("a pid file path is empty")),
                Some(p) if p.starts_with('/') => Ok(Some(p.to_string())),
                Some(p) => Ok(Some(
                    std::env::current_dir()?
                        .join(p)
                        .to_string_lossy()
                        .into_owned(),
                )),
            }
        };
        Ok((abs(&self.pidfile)?, abs(&self.conmon_pidfile)?))
    }
}

/// Options of `container run` that only shape the OCI spec.
#[derive(clap::Args, Debug, Clone)]
pub struct SpecArgs {
    /// The /etc/passwd entry added for a user the image lacks
    /// ($USERNAME, $UID, $GID, $NAME, $HOME)
    #[arg(long)]
    pub passwd_entry: Option<String>,

    /// The /etc/group entry added for a group the image lacks
    /// ($GROUPNAME, $GID, $USERNAME)
    #[arg(long)]
    pub group_entry: Option<String>,

    /// Add entries to /etc/passwd and /etc/group for a user the image lacks
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub passwd: bool,

    /// Unset a default environment variable or one of the image
    #[arg(long)]
    pub unsetenv: Vec<String>,

    /// Unset all the default environment variables and those of the image
    #[arg(long)]
    pub unsetenv_all: bool,

    /// Preprocess an environment variable: KEY=VALUE with ${KEY} expanded
    #[arg(long)]
    pub env_merge: Vec<String>,

    /// The execution domain of the process (LINUX or LINUX32)
    #[arg(long)]
    pub personality: Option<String>,

    /// The propagation of the root file system mount
    #[arg(long)]
    pub rootfs_propagation: Option<String>,

    /// With --read-only, tmpfs on /tmp, /var/tmp and /run
    #[arg(
        long,
        default_value_t = true,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true"
    )]
    pub read_only_tmpfs: bool,

    /// Do not create /etc/hostname
    #[arg(long)]
    pub no_hostname: bool,

    /// Containers started before this one (a list)
    #[arg(long, value_delimiter = ',')]
    pub requires: Vec<String>,

    /// Size of the tmpfs mounts of systemd mode (/run, /run/lock, /tmp,
    /// /var/log/journal)
    #[arg(long)]
    pub shm_size_systemd: Option<String>,

    #[command(flatten)]
    pub pidfiles: PidFileArgs,
}
