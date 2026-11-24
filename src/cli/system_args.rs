// SPDX-License-Identifier: Apache-2.0
use super::*;

#[derive(Subcommand, Clone)]
pub enum NetworkCommands {
    #[command(about = "Create a network")]
    Create {
        /// Do not fail if the network exists
        #[arg(long)]
        ignore: bool,
        #[arg(long, short, default_value = "bridge")]
        driver: String,
        /// The subnet: one IPv4 and one IPv6 at most
        #[arg(long)]
        subnet: Vec<String>,
        /// The gateway of the subnet given in the same position
        #[arg(long)]
        gateway: Vec<String>,
        /// Set driver specific options (key=value)
        #[arg(long, short = 'o')]
        opt: Vec<String>,
        /// Set metadata on the network (key=value)
        #[arg(long)]
        label: Vec<String>,
        /// Name of the network interface (the bridge)
        #[arg(long)]
        interface_name: Option<String>,
        /// IP address management driver (host-local)
        #[arg(long)]
        ipam_driver: Option<String>,
        /// Restrict external access of the network: the containers reach
        /// each other only
        #[arg(long)]
        internal: bool,
        /// Enable IPv6 (dual stack): an IPv6 subnet is picked unless one
        /// is given
        #[arg(long)]
        ipv6: bool,
        /// Disable the DNS server of the network (container names)
        #[arg(long)]
        disable_dns: bool,
        /// DNS servers for the names that are not containers
        #[arg(long)]
        dns: Vec<String>,
        /// Allocate container addresses from a range (CIDR or FIRST-LAST)
        #[arg(long)]
        ip_range: Option<String>,
        /// Static routes of the containers: DESTINATION,GATEWAY[,METRIC]
        #[arg(long)]
        route: Vec<String>,
        name: String,
    },

    #[command(about = "List networks", alias = "ls")]
    List {
        #[command(flatten)]
        out: report::ListOutput,
    },

    #[command(about = "Check if a network exists (exit 0) or not (exit 1)")]
    Exists { network: String },

    #[command(about = "Show network details")]
    Inspect {
        /// Go template of each network, or `json`
        #[arg(long, short)]
        format: Option<String>,
        #[arg(required = true)]
        networks: Vec<String>,
    },

    #[command(about = "Remove a network", alias = "rm")]
    Remove {
        /// Remove the containers that use the network; a network that is not
        /// there is no error
        #[arg(long, short)]
        force: bool,
        /// Seconds the containers that use a network removed with --force
        /// have to obey their stop signal before they are killed (default:
        /// their stop timeouts, 0: killed at once, negative: no limit)
        #[arg(long, short, allow_negative_numbers = true, value_parser = parse_time_u64)]
        time: Option<u64>,
        #[arg(required = true)]
        networks: Vec<String>,
    },

    #[command(about = "Remove the networks no container uses")]
    Prune {
        /// Do not ask for confirmation (there is none)
        #[arg(long, short)]
        force: bool,
        /// Only the networks of these filters (label=, label!=, until=)
        #[arg(long)]
        filter: Vec<String>,
    },

    #[command(about = "Change the DNS servers of a network")]
    Update {
        /// Add a DNS server
        #[arg(long)]
        dns_add: Vec<String>,
        /// Remove a DNS server
        #[arg(long)]
        dns_drop: Vec<String>,
        network: String,
    },

    #[command(about = "Connect a container to a network")]
    Connect {
        /// Set a static IPv4 address for this container network
        #[arg(long)]
        ip: Option<String>,
        /// Set a static IPv6 address for this container network
        #[arg(long)]
        ip6: Option<String>,
        /// Set a static MAC address for this container network
        #[arg(long)]
        mac_address: Option<String>,
        /// Network scoped alias for the container
        #[arg(long)]
        alias: Vec<String>,
        network: String,
        container: String,
    },

    #[command(about = "Reload firewall rules for one or more containers")]
    Reload {
        /// Reload network configuration of all containers
        #[arg(long, short)]
        all: bool,
        /// Act on the latest container velarx is aware of
        #[arg(long, short)]
        latest: bool,
        containers: Vec<String>,
    },

    #[command(about = "Disconnect a container from a network")]
    Disconnect {
        #[arg(long, short)]
        force: bool,
        network: String,
        container: String,
    },
}

#[derive(Subcommand, Clone)]
pub enum RegistryCommands {
    #[command(about = "Log in to a container registry")]
    Login {
        /// Username for authentication
        #[arg(long, short)]
        username: Option<String>,
        /// Password for authentication (use --password-stdin for security)
        #[arg(long, short)]
        password: Option<String>,
        /// Read password from stdin
        #[arg(long)]
        password_stdin: bool,
        /// The auth file to write (default: $REGISTRY_AUTH_FILE or
        /// $XDG_RUNTIME_DIR/velarx/auth/auth.json;
        /// /run/velarx/auth/auth.json for root)
        #[arg(long)]
        authfile: Option<PathBuf>,
        /// A Docker-compatible config file to update instead
        #[arg(long)]
        compat_auth_file: Option<PathBuf>,
        /// Take the password from a secret (its name is the user name unless
        /// there is one)
        #[arg(long)]
        secret: Option<String>,
        /// Verify the TLS certificates of the registry; `--tls-verify=false`
        /// also accepts plain HTTP
        #[arg(
            long,
            default_value_t = true,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true"
        )]
        tls_verify: bool,
        /// Directory of the certificates of the registry
        #[arg(long)]
        cert_dir: Option<PathBuf>,
        /// Print the user name logged in to the server, and log in to nothing
        #[arg(long)]
        get_login: bool,
        /// Say what file is used
        #[arg(long, short)]
        verbose: bool,
        /// Registry server (default: docker.io)
        server: Option<String>,
    },

    #[command(about = "Log out from a container registry")]
    Logout {
        /// Remove credentials for all registries
        #[arg(long, short)]
        all: bool,
        /// The auth file to change
        #[arg(long)]
        authfile: Option<PathBuf>,
        /// A Docker-compatible config file to change instead
        #[arg(long)]
        compat_auth_file: Option<PathBuf>,
        /// Registry server (default: docker.io)
        server: Option<String>,
    },
}

/// The limits of the cgroup of a pod, with the names and the meaning of
/// podman's `pod create` flags.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct PodResourceArgs {
    /// Memory limit of the pod (a number with b, k, m or g)
    #[arg(long, short = 'm')]
    pub memory: Option<String>,
    /// Memory and swap together, as --memory
    #[arg(long)]
    pub memory_swap: Option<String>,
    /// Number of CPUs of the pod (a quota of the period; 0 is no limit)
    #[arg(long)]
    pub cpus: Option<f64>,
    /// CPUs in which the pod may run (0-3, 0,1)
    #[arg(long)]
    pub cpuset_cpus: Option<String>,
    /// Memory nodes in which the pod may run
    #[arg(long)]
    pub cpuset_mems: Option<String>,
    /// CPU shares (relative weight)
    #[arg(long, short = 'c')]
    pub cpu_shares: Option<u64>,
    /// The CFS period in microseconds (velarx's own flag for a pod)
    #[arg(long)]
    pub cpu_period: Option<u64>,
    /// The CFS quota in microseconds per period (velarx's own flag for a pod)
    #[arg(long)]
    pub cpu_quota: Option<i64>,
    /// Block IO weight (10 to 1000)
    #[arg(long)]
    pub blkio_weight: Option<String>,
    /// Weight of a block device, DEVICE:WEIGHT
    #[arg(long, value_name = "DEVICE_NAME:WEIGHT")]
    pub blkio_weight_device: Vec<String>,
    /// Limit the read rate (bytes per second) of a device, DEVICE:RATE
    #[arg(long)]
    pub device_read_bps: Vec<String>,
    /// Limit the write rate (bytes per second) of a device, DEVICE:RATE
    #[arg(long)]
    pub device_write_bps: Vec<String>,
}

/// How podman's pod commands choose their pods, besides by name.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct PodTargets {
    /// Every pod
    #[arg(long, short)]
    pub all: bool,
    /// The pod made last
    #[arg(long, short = 'l')]
    pub latest: bool,
}

/// The `--latest` of the commands that take one pod, or a few.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct PodLatest {
    /// The pod made last
    #[arg(long, short = 'l')]
    pub latest: bool,
}

#[derive(Subcommand, Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "parsed once into one value; boxing a clap variant means a struct of its own for each"
)]
pub enum PodCommands {
    #[command(about = "Create a new pod", disable_help_flag = true)]
    Create {
        /// Print help
        #[arg(long, action = clap::ArgAction::HelpLong)]
        help: Option<bool>,
        /// Pod name (or --name; a name is made without one)
        #[arg(conflicts_with = "name_opt")]
        name: Option<String>,
        /// Make the infra container of the pod (--infra=false: the pod has
        /// none and its containers share no namespace; without it, a pod
        /// that shares none has none)
        #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1,
              default_missing_value = "true", require_equals = true)]
        infra: Option<bool>,
        /// Pod name
        #[arg(long = "name", short = 'n', id = "name_opt", value_name = "NAME")]
        name_opt: Option<String>,
        /// Set the pod hostname
        #[arg(long, short = 'h')]
        hostname: Option<String>,
        /// Connect the pod to a network
        #[arg(long)]
        network: Vec<String>,
        /// Set custom DNS servers for the pod
        #[arg(long)]
        dns: Vec<String>,
        /// Set custom DNS search domains for the pod
        #[arg(long)]
        dns_search: Vec<String>,
        /// Set custom DNS options for the pod
        #[arg(long, alias = "dns-opt")]
        dns_option: Vec<String>,
        /// Add custom host-to-IP mapping (host:ip)
        #[arg(long)]
        add_host: Vec<String>,
        /// Publish a port (hostPort:containerPort/protocol)
        #[arg(long, short = 'p')]
        publish: Vec<String>,
        /// Share PID namespace among containers
        #[arg(long)]
        share_pid: bool,
        /// User namespace to use
        #[arg(long)]
        userns: Option<String>,
        /// Infra container image
        #[arg(long)]
        infra_image: Option<String>,
        /// Set metadata on pod
        #[arg(long, short = 'l')]
        label: Vec<String>,
        /// Replace a pod with the same name
        #[arg(long)]
        replace: bool,
        /// Name of the infra container
        #[arg(long)]
        infra_name: Option<String>,
        /// What the pod does when all its containers exit: continue or stop
        #[arg(long)]
        exit_policy: Option<String>,
        /// Write the pid of the infra container's monitor to this file
        #[arg(long)]
        infra_conmon_pidfile: Option<String>,
        /// The namespaces the containers share: ipc,net,uts (default),
        /// pid, cgroup, none; `+pid` adds to the default
        #[arg(long)]
        share: Option<String>,
        /// What the infra container runs
        #[arg(long)]
        infra_command: Option<String>,
        /// The user ID mappings of the pod's user namespace (CONTAINER:HOST:SIZE)
        #[arg(long)]
        uidmap: Vec<String>,
        /// The group ID mappings of the pod's user namespace
        #[arg(long)]
        gidmap: Vec<String>,
        /// Kernel parameters of the namespaces the pod shares (NAME=VALUE)
        #[arg(long)]
        sysctl: Vec<String>,
        /// The size of /dev/shm (e.g. 64m)
        #[arg(long)]
        shm_size: Option<String>,
        /// A volume mounted in every container of the pod
        #[arg(long, short = 'v')]
        volume: Vec<String>,
        /// The restart policy of the containers of the pod
        #[arg(long)]
        restart: Option<String>,
        /// The cgroup the pod's containers go below
        #[arg(long)]
        cgroup_parent: Option<String>,
        /// The cgroups of the infra container, as `run --cgroups`: disabled
        /// makes no cgroup for the pod, its infra or its members (they stay
        /// in the cgroup of the command that starts them; --cgroup-parent and
        /// limits are then an error); default: `[containers] cgroups` of the
        /// configuration, else split for the engine service (the pod is
        /// `POD-ID` next to `engine`, its members `POD-ID/CTR-ID`); scope
        /// (enabled) puts the cgroups of the pod's containers in systemd scopes,
        /// as for `run`: the infra container and every member have it
        #[arg(long, value_parser = ["enabled", "scope", "disabled", "no-conmon", "split"])]
        cgroups: Option<String>,
        /// Security options of the infra container
        #[arg(long)]
        security_opt: Vec<String>,
        /// The address of the pod on its network
        #[arg(long)]
        ip: Option<String>,
        /// The IPv6 address of the pod on its network
        #[arg(long)]
        ip6: Option<String>,
        /// A name of the pod on its networks
        #[arg(long)]
        network_alias: Vec<String>,
        /// Add a host device to the pod: HOST[:CONTAINER][:PERMISSIONS], or a CDI name
        #[arg(long)]
        device: Vec<String>,
        /// GPU devices to add to the pod (`all`), made through CDI (nvidia.com/gpu)
        #[arg(long)]
        gpus: Vec<String>,
        /// Mount the volumes of these containers in the pod: CONTAINER[:OPTIONS]
        #[arg(long)]
        volumes_from: Vec<String>,
        /// Base of /etc/hosts: a path, `none` or `image`
        #[arg(long)]
        hosts_file: Option<String>,
        /// Leave /etc/hosts of the containers alone
        #[arg(long)]
        no_hosts: bool,
        /// Do not create /etc/hostname
        #[arg(long)]
        no_hostname: bool,
        /// The MAC address of the pod on its network
        #[arg(long)]
        mac_address: Option<String>,
        /// The PID namespace of the pod: host or private
        #[arg(long)]
        pid: Option<String>,
        /// The UTS namespace of the pod: host or private
        #[arg(long)]
        uts: Option<String>,
        /// Name of the range of /etc/subuid for the user namespace of the pod
        #[arg(long)]
        subuidname: Option<String>,
        /// Name of the range of /etc/subgid for the user namespace of the pod
        #[arg(long)]
        subgidname: Option<String>,
        /// Whether the containers enter the cgroup of the pod (default true)
        #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1,
              default_missing_value = "true", require_equals = true)]
        share_parent: Option<bool>,
        /// Write the ID of the pod to this file
        #[arg(long)]
        pod_id_file: Option<String>,
        /// Read labels (KEY=VALUE, one a line) from this file
        #[arg(long)]
        label_file: Vec<String>,
        /// The size of the tmpfs mounts of systemd mode (/run, /run/lock)
        #[arg(long)]
        shm_size_systemd: Option<String>,
        #[command(flatten)]
        limits: PodResourceArgs,
    },

    #[command(about = "Replace the limits of the cgroup of a pod; none takes them away")]
    Update {
        #[command(flatten)]
        limits: PodResourceArgs,
        pod: String,
    },

    #[command(about = "List pods", visible_aliases = ["ls", "ps"])]
    List {
        /// Accepted: all the pods are listed
        #[arg(long, short)]
        all: bool,
        #[command(flatten)]
        out: report::ListOutput,
        #[command(flatten)]
        ps: report::PodPsArgs,
    },

    #[command(about = "Restart one or more pods")]
    Restart {
        /// The digest (sha256:... or sha512:...) of an image of the containers of the pod
        /// (repeat): every container whose digests are enforced is started
        /// held to the one that names its image, as `start --verify-image`
        /// does (refused where the digests are not held: --security-opt
        /// verity=off, [storage] verity_chain = "off", an image no digest or
        /// signature vouches for, a store without fs-verity); the
        /// infra container needs none
        #[arg(long, value_name = "DIGEST")]
        verify_image: Vec<String>,
        #[command(flatten)]
        targets: PodTargets,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(
        about = "Create a copy of an existing pod and of its containers",
        disable_help_flag = true
    )]
    Clone {
        /// Print help
        #[arg(long, action = clap::ArgAction::HelpLong)]
        help: Option<bool>,
        /// Remove the pod that is copied
        #[arg(long)]
        destroy: bool,
        /// Start the new pod
        #[arg(long)]
        start: bool,
        /// Name of the new pod (else the second argument)
        #[arg(long, short = 'n')]
        name: Option<String>,
        /// Set the hostname of the new pod
        #[arg(long, short = 'h')]
        hostname: Option<String>,
        /// Name of the infra container of the new pod
        #[arg(long)]
        infra_name: Option<String>,
        /// Labels added to those of the pod
        #[arg(long, short = 'l')]
        label: Vec<String>,
        /// Read labels from this file
        #[arg(long)]
        label_file: Vec<String>,
        /// The cgroup the containers of the new pod go below
        #[arg(long)]
        cgroup_parent: Option<String>,
        /// Add a host device to the new pod: HOST[:CONTAINER][:PERMISSIONS], or a CDI name
        #[arg(long)]
        device: Vec<String>,
        /// Add GPU devices to the new pod (`all`), made through CDI (nvidia.com/gpu)
        #[arg(long)]
        gpus: Vec<String>,
        /// Group ID mappings of the new pod: CONTAINER:HOST:SIZE (replace those of the pod)
        #[arg(long)]
        gidmap: Vec<String>,
        /// User ID mappings of the new pod: CONTAINER:HOST:SIZE (replace those of the pod)
        #[arg(long)]
        uidmap: Vec<String>,
        /// The command of the infra container of the new pod
        #[arg(long)]
        infra_command: Option<String>,
        /// Write the PID of the conmon of the infra container of the new pod to this file
        #[arg(long)]
        infra_conmon_pidfile: Option<String>,
        /// The PID namespace of the new pod: host or private
        #[arg(long)]
        pid: Option<String>,
        /// The UTS namespace of the new pod: host or private
        #[arg(long)]
        uts: Option<String>,
        /// The user namespace of the new pod
        #[arg(long)]
        userns: Option<String>,
        /// The restart policy of the containers of the new pod
        #[arg(long)]
        restart: Option<String>,
        /// Add security options to the infra container of the new pod
        #[arg(long)]
        security_opt: Vec<String>,
        /// The size of /dev/shm of the new pod
        #[arg(long)]
        shm_size: Option<String>,
        /// The size of the tmpfs mounts of systemd mode of the new pod
        #[arg(long)]
        shm_size_systemd: Option<String>,
        /// Name of the range of /etc/subgid for the user namespace of the new pod
        #[arg(long)]
        subgidname: Option<String>,
        /// Name of the range of /etc/subuid for the user namespace of the new pod
        #[arg(long)]
        subuidname: Option<String>,
        /// Set a sysctl in the new pod: NAME=VALUE
        #[arg(long)]
        sysctl: Vec<String>,
        /// Add a volume to the new pod
        #[arg(long, short = 'v')]
        volume: Vec<String>,
        /// Mount the volumes of these containers in the new pod: CONTAINER[:OPTIONS]
        #[arg(long)]
        volumes_from: Vec<String>,
        #[command(flatten)]
        limits: PodResourceArgs,
        /// The pod to copy, and the name of the copy
        #[arg(required = true, num_args = 1..=2)]
        pods: Vec<String>,
    },

    #[command(about = "Display detailed information on one or more pods")]
    Inspect {
        /// Go template of each pod, or `json`
        #[arg(long, short)]
        format: Option<String>,
        #[command(flatten)]
        latest: PodLatest,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(about = "Start one or more pods")]
    Start {
        /// The digest (sha256:... or sha512:...) of an image of the containers of the pod
        /// (repeat): every container whose digests are enforced is started
        /// held to the one that names its image, as `start --verify-image`
        /// does (refused where the digests are not held: --security-opt
        /// verity=off, [storage] verity_chain = "off", an image no digest or
        /// signature vouches for, a store without fs-verity); the
        /// infra container needs none
        #[arg(long, value_name = "DIGEST")]
        verify_image: Vec<String>,
        #[command(flatten)]
        targets: PodTargets,
        /// Read the pod ID from the file
        #[arg(long)]
        pod_id_file: Vec<String>,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(about = "Stop one or more pods")]
    Stop {
        /// Seconds to wait for pod to stop before killing
        #[arg(long, short, allow_negative_numbers = true, value_parser = parse_time_u32, default_value = "10")]
        time: u32,
        /// Do not fail on a pod that does not exist
        #[arg(long, short = 'i')]
        ignore: bool,
        #[command(flatten)]
        targets: PodTargets,
        /// Read the pod ID from the file
        #[arg(long)]
        pod_id_file: Vec<String>,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(about = "Kill one or more pods")]
    Kill {
        /// Signal to send
        #[arg(long, short, default_value = "SIGKILL", allow_hyphen_values = true)]
        signal: String,
        #[command(flatten)]
        targets: PodTargets,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(about = "Pause one or more pods")]
    Pause {
        #[command(flatten)]
        targets: PodTargets,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(about = "Unpause one or more pods")]
    Unpause {
        #[command(flatten)]
        targets: PodTargets,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(about = "Remove one or more pods")]
    Rm {
        /// Force removal even if pod is running
        #[arg(long, short)]
        force: bool,
        /// Do not fail on a pod that does not exist
        #[arg(long, short = 'i')]
        ignore: bool,
        #[command(flatten)]
        targets: PodTargets,
        /// Read the pod ID from the file (the file is removed with the pod)
        #[arg(long)]
        pod_id_file: Vec<String>,
        /// Seconds the containers of a running pod have to obey their stop
        /// signal before they are killed (with --force; default: their stop
        /// timeouts, 0: killed at once, negative: no limit)
        #[arg(long, short, allow_negative_numbers = true, value_parser = parse_time_u32)]
        time: Option<u32>,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(about = "Display a live stream of pod resource usage statistics")]
    Stats {
        #[command(flatten)]
        targets: PodTargets,
        /// Go template of each row, or `json`
        #[arg(long, allow_hyphen_values = true)]
        format: Option<String>,
        /// Print the first sample only
        #[arg(long)]
        no_stream: bool,
        /// Do not clear the screen between the samples
        #[arg(long)]
        no_reset: bool,
        /// Pod names or IDs
        pods: Vec<String>,
    },

    #[command(about = "Display the running processes in a pod")]
    Top {
        #[command(flatten)]
        latest: PodLatest,
        /// Pod name or ID, then ps(1) format descriptors or arguments
        #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
        args: Vec<String>,
    },

    #[command(about = "Remove all stopped pods")]
    Prune {
        /// Do not prompt for confirmation
        #[arg(long, short)]
        force: bool,
    },

    #[command(about = "Check if a pod exists")]
    Exists {
        /// Pod name or ID
        pod: String,
    },

    #[command(about = "Fetch logs for pod with one or more containers")]
    Logs {
        #[command(flatten)]
        latest: PodLatest,
        /// Pod name or ID
        pod: Option<String>,
        /// Follow log output, until the containers (the infra container
        /// too) have exited
        #[arg(long, short)]
        follow: bool,
        /// Show logs since TIMESTAMP (e.g. 2013-01-02T13:23:37Z) or relative (e.g. 42m, 1h)
        #[arg(long, value_name = "TIMESTAMP")]
        since: Option<String>,
        /// Show logs until TIMESTAMP (e.g. 2013-01-02T13:23:37Z) or relative
        #[arg(long, value_name = "TIMESTAMP")]
        until: Option<String>,
        /// Output the specified number of LINES at the end of the log of
        /// each container (-1: all of it)
        #[arg(long, default_value_t = -1, allow_negative_numbers = true, value_name = "LINES")]
        tail: i64,
        /// Output the timestamps in the log
        #[arg(long, short)]
        timestamps: bool,
        /// Output container names instead of container IDs in the log
        #[arg(long, short)]
        names: bool,
        /// Output the containers within a pod with different colors in the log
        #[arg(long)]
        color: bool,
        /// Filter logs by container name or id which belongs to pod
        #[arg(long, short)]
        container: Vec<String>,
    },
}

#[derive(Subcommand, Clone)]
pub enum VolumeCommands {
    #[command(about = "Create a volume")]
    Create {
        /// Do not fail if the volume exists
        #[arg(long)]
        ignore: bool,
        /// Volume name (a random one if omitted)
        name: Option<String>,
        /// Set volume driver (default: local)
        #[arg(long, short, default_value = "local")]
        driver: String,
        /// Set metadata for a volume
        #[arg(long, short)]
        label: Vec<String>,
        /// Set driver-specific options (type, device, o, uid, gid, size)
        #[arg(long, short)]
        opt: Vec<String>,
        /// Owner (user id) of the volume
        #[arg(long)]
        uid: Option<u32>,
        /// Group id of the volume
        #[arg(long)]
        gid: Option<u32>,
    },

    #[command(about = "Write the content of a volume as a tar")]
    Export {
        /// Volume name
        name: String,
        /// Write to this file instead of standard output
        #[arg(long, short)]
        output: Option<String>,
    },

    #[command(about = "Extract a tar into a volume")]
    Import {
        /// Volume name
        name: String,
        /// The tar file, `-` for standard input
        file: String,
    },

    #[command(about = "Mount a volume (if its options need it) and print where it is")]
    Mount {
        /// Volume name
        name: String,
    },

    #[command(about = "Unmount a volume that was mounted")]
    Unmount {
        /// Volume name
        name: String,
    },

    #[command(about = "List volumes", visible_alias = "ls")]
    List {
        /// Accepted: all the volumes are listed, in use or not
        #[arg(long, short)]
        all: bool,
        #[command(flatten)]
        out: report::ListOutput,
    },

    #[command(about = "Check if a volume exists (exit 0) or not (exit 1)")]
    Exists { volume: String },

    #[command(about = "Display detailed information on one or more volumes")]
    Inspect {
        /// Go template of each volume, or `json`
        #[arg(long, short)]
        format: Option<String>,
        /// Inspect all volumes
        #[arg(long, short)]
        all: bool,
        /// Volume names
        volumes: Vec<String>,
    },

    #[command(about = "Remove one or more volumes", alias = "rm")]
    Remove {
        /// Force removal
        #[arg(long, short)]
        force: bool,
        /// Remove every volume
        #[arg(long, short)]
        all: bool,
        /// Seconds the containers that use a volume removed with --force
        /// have to obey their stop signal before they are killed (default:
        /// their stop timeouts, 0: killed at once, negative: no limit)
        #[arg(long, short, allow_negative_numbers = true, value_parser = parse_time_u64)]
        time: Option<u64>,
        /// Volume names
        volumes: Vec<String>,
    },

    #[command(about = "Reload all volumes from volume plugins")]
    Reload,

    #[command(about = "Remove unused volumes")]
    Prune {
        /// Do not prompt for confirmation
        #[arg(long, short)]
        force: bool,
        /// Only the volumes of these filters (label=, label!=, until=)
        #[arg(long)]
        filter: Vec<String>,
    },
}

#[derive(Subcommand, Clone)]
pub enum SystemCommands {
    /// Start the engine again (its configuration read again); the
    /// containers go on, the clients reconnect
    #[command(about = "Restart the engine")]
    Restart,

    #[command(about = "Show velarx disk usage")]
    Df {
        /// Show detailed information
        #[arg(long, short)]
        verbose: bool,
        /// Go template of each row (Type, Total, Active, Size, Reclaimable), or `json`
        #[arg(long, allow_hyphen_values = true)]
        format: Option<String>,
    },

    #[command(about = "Remove unused data")]
    Prune {
        /// Remove all unused containers, networks, images (not just dangling ones)
        #[arg(long, short)]
        all: bool,
        /// Remove all unused volumes
        #[arg(long)]
        volumes: bool,
        /// Remove the containers of builds that are gone (a build that was
        /// killed), whatever their state
        #[arg(long)]
        build: bool,
        /// Remove only what the store holds that no image, container or
        /// volume uses (`system gc`); nothing else, no prompt
        #[arg(long)]
        external: bool,
        /// Do not prompt for confirmation
        #[arg(long, short)]
        force: bool,
        /// Filter images and containers by labels
        #[arg(long)]
        filter: Vec<String>,
    },

    #[command(about = "Run storage garbage collection")]
    Gc {
        /// Preview what would be deleted without actually deleting
        #[arg(long)]
        dry_run: bool,
        /// Garbage collect unreferenced files (default: true, use --no-files to disable)
        #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
        files: bool,
        /// Garbage collect unreferenced layers (default: true, use --no-layers to disable)
        #[arg(long, default_value = "true", action = clap::ArgAction::Set)]
        layers: bool,
    },

    /// The stores the storage service holds for the user ([storage]
    /// driver = "varlink"), also those of an engine whose store-id file was
    /// lost: they are named by nobody and never collected until they are
    /// dropped.
    #[command(about = "List the stores of the storage service, or drop one")]
    Stores {
        /// Drop the store with this id and everything it holds (the store of
        /// this engine and a store with a container or a pull are refused)
        #[arg(long, value_name = "ID")]
        drop: Option<String>,
    },

    #[command(about = "Display system-wide information")]
    Info {
        /// Go template of the information, or `json`
        #[arg(long, short)]
        format: Option<String>,
    },

    #[command(about = "Return low-level information on velarx objects")]
    Inspect {
        /// Object type (container, image, network, volume, pod, all)
        #[arg(long, short, default_value = "all")]
        r#type: String,
        /// Go template of each object, or `json`
        #[arg(long, short)]
        format: Option<String>,
        /// The container made last
        #[arg(long, short = 'l')]
        latest: bool,
        /// The sizes of the files of the containers (SizeRw, SizeRootFs)
        #[arg(long, short)]
        size: bool,
        /// Object IDs or names
        objects: Vec<String>,
    },

    /// Look at every image of the store: its record, its layers and their
    /// tables of contents, its files (present, of their size and, unless
    /// --quick, of their content: the sha256 and the fs-verity digest are
    /// computed again) and its composefs image (read-only, parses, has the
    /// id it states, is the one its layers make); and at the store: objects
    /// no row names, rows of files that are gone, temporary files, staging
    /// directories of nothing.  Nothing is printed when all is well, and
    /// damage ends the command with status 125.
    ///
    /// --repair makes the composefs images of an image again, enables
    /// fs-verity on the whole objects that lack it where the store requires
    /// it, removes the leftovers and removes the images whose files are damaged or gone
    /// (pull them again), except those a container uses; --force with it
    /// removes those containers too, and the image (a running container
    /// is not removed).  --max is the age of the leftovers to remove; the
    /// time to spend is --timeout: the images not reached are the ones
    /// checked most recently, and the next check starts with those not
    /// checked for the longest.
    ///
    /// `fsck` is another name for the command, and --fix for --repair.
    #[command(
        about = "Check the consistency of the images and the store",
        alias = "fsck"
    )]
    Check {
        /// Skip reading the content of the files and of the composefs images
        #[arg(long, short)]
        quick: bool,
        /// Make again what can be made from the store, enable fs-verity on
        /// the whole objects that lack it where the store requires it,
        /// remove the images that are damaged and not in use
        #[arg(long, short, alias = "fix")]
        repair: bool,
        /// With --repair: remove the containers that use a damaged image
        /// too, and the image
        #[arg(long, short, alias = "repair-lossy")]
        force: bool,
        /// Maximum allowed age of unreferenced files of the store: older
        /// ones are leftovers (24h, 1h30m; default: check_leftover_age_secs
        /// of the configuration)
        #[arg(long, short, value_name = "DURATION")]
        max: Option<String>,
        /// Stop starting the check of an image after this long (10s, 2m, 1h)
        #[arg(long, value_name = "DURATION")]
        timeout: Option<String>,
        /// Output format: text (lines) or json (a report)
        #[arg(long, default_value = "text")]
        format: String,
    },
}

#[derive(Subcommand, Clone)]
pub enum HealthcheckCommands {
    #[command(about = "Run the healthcheck for a container")]
    Run {
        /// Container name or ID
        container: String,
    },

    #[command(about = "List all containers with their healthcheck status")]
    Ls {
        /// Show all containers (default shows just those with healthchecks)
        #[arg(long, short)]
        all: bool,
    },

    #[command(about = "Display health check history for a container")]
    Inspect {
        /// Container name or ID
        container: String,
    },
}
