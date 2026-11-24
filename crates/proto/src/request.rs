// SPDX-License-Identifier: Apache-2.0
//! The request to create a container: the same type for the command line
//! (which builds it), the API (which decodes it), the services and the
//! definition of the engine (`ContainerCreate`).

pub use crate::modes::{
    cgroup_mode_word, CgroupMode, CgroupsMode, ModeError, NetworkMode, NsMode, UsernsChoice,
    PROVIDER_PREFIX,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The `sha256:<hex>` and `sha512:<hex>` digests of the references in `texts`
/// (`NAME@sha256:...`, `NAME:TAG@sha512:...`, or an option holding one,
/// `source=NAME@sha256:...`), in order, once each.
pub fn typed_digests<'a>(texts: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for text in texts {
        let mut rest = text;
        while let Some(at) = rest.find('@') {
            rest = &rest[at + 1..];
            // (the algorithm, and the exact number of hex digits it has)
            let (algorithm, digits) = match rest {
                r if r.starts_with("sha256:") => ("sha256:", 64),
                r if r.starts_with("sha512:") => ("sha512:", 128),
                _ => continue,
            };
            let digest = &rest[..rest.len().min(algorithm.len() + digits)];
            let hex = &digest[algorithm.len()..];
            if hex.len() == digits && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                if !out.iter().any(|d| d == digest) {
                    out.push(digest.to_string());
                }
                rest = &rest[digest.len()..];
            }
        }
    }
    out
}

impl CreateContainerRequest {
    /// Whether the container is made in the network mode `wanted`.
    pub fn has_network_mode(&self, wanted: &NetworkMode) -> bool {
        NetworkMode::has(&self.networks, &self.network_mode, wanted)
    }

    /// The digests the command that made the request typed: those of its
    /// image and of the images mounted in it.  They are what an enforced
    /// start holds the images to.
    pub fn typed_digests(&self) -> Vec<String> {
        typed_digests(
            std::iter::once(self.image.as_str())
                .chain(self.mount.iter().map(String::as_str))
                .chain(self.image_mounts.iter().map(|m| m.image.as_str()))
                .chain(
                    self.mounts
                        .iter()
                        .filter_map(|m| m.image.as_ref())
                        .map(|i| i.image.as_str()),
                ),
        )
    }

    /// The request without the values of its secrets: the variables the
    /// API added for them and the files of `secrets_dir` it mounts.
    pub fn without_secret_values(&self, secrets_dir: &std::path::Path) -> Self {
        let mut r = self.clone();
        r.secrets.clear();
        r.env.retain(|e| !self.secret_env.contains(e));
        r.mounts
            .retain(|m| !std::path::Path::new(&m.source).starts_with(secrets_dir));
        r
    }

    /// The request as it can be asked again: the secrets it resolved by
    /// name, without their values (none when the container ID uses none).
    pub fn with_secrets_by_name(&self, secrets_dir: Option<&std::path::Path>) -> Self {
        let Some(dir) = secrets_dir else {
            return self.clone();
        };
        let mut r = self.without_secret_values(dir);
        r.secrets = self.resolved_secrets.clone();
        r
    }
}

/// What a container is made with: the one creation record of the command
/// line, the CRI and the REST API.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateContainerRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub image: String,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// The entrypoint of the image is dropped and its command kept (Docker's
    /// `"Entrypoint": []`); `[""]` in `entrypoint` drops both
    #[serde(default)]
    pub reset_entrypoint: bool,
    #[serde(default)]
    pub working_dir: String,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub group_add: Vec<String>,
    /// The command line that made the container (podman's `CreateCommand`)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub create_command: Vec<String>,
    /// The groups of the process are its group and `group_add` only, not
    /// those the image's /etc/group gives the user (the CRI's `Strict`
    /// supplemental groups policy)
    #[serde(default)]
    pub groups_strict: bool,
    /// `--passwd-entry`: the entry added for a user the image lacks
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passwd_entry: Option<String>,
    /// `--group-entry`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_entry: Option<String>,
    /// `--passwd=false`: no entries are added
    #[serde(default)]
    pub no_passwd: bool,
    /// `--unsetenv`: variables of the image and the defaults to drop
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsetenv: Vec<String>,
    /// `--unsetenv-all`
    #[serde(default)]
    pub unsetenv_all: bool,
    /// `--env-merge`: `KEY=VALUE` where VALUE may use `${KEY}` of the image
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_merge: Vec<String>,
    /// `--personality`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personality: Option<String>,
    /// `--hosts-file`: the base of /etc/hosts, a path, `none` or `image`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts_file: Option<String>,
    /// The /etc/hosts of the image, read by the engine for `--hosts-file=image`
    #[serde(skip)]
    pub hosts_image: Option<String>,
    /// `--chrootdirs`: the files the engine mounts in the root are mounted
    /// below these directories too
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chroot_dirs: Vec<String>,
    /// `--hostuser`: users of the host (names or ids) whose /etc/passwd
    /// entries the container gets
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host_users: Vec<String>,
    /// `--rdt-class`: the class of service of Intel RDT
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdt_class: Option<String>,
    /// `--seccomp-policy`: `default`, or `image` (the profile named by the
    /// label `io.containers.seccomp.profile` of the image)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_policy: Option<String>,
    /// `--rootfs-propagation`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_propagation: Option<String>,
    /// `--read-only-tmpfs=false`
    #[serde(default)]
    pub no_read_only_tmpfs: bool,
    /// `--no-hostname`: no /etc/hostname
    #[serde(default)]
    pub no_hostname: bool,
    /// `--no-healthcheck`: not even the one of the image
    #[serde(default)]
    pub no_healthcheck: bool,
    /// `--requires`: containers started before this one
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// `--shm-size-systemd`: the size of the tmpfs of systemd mode
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shm_size_systemd: Option<u64>,
    /// `--pidfile`: where the monitor writes the pid of the init process
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pidfile: Option<String>,
    /// `--conmon-pidfile`: where the monitor writes its own pid
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conmon_pidfile: Option<String>,
    /// The container whose SELinux label this one shares (the infra
    /// container of its pod), set by the engine, never by a client
    #[serde(skip)]
    pub selinux_share_with: Option<String>,
    #[serde(default)]
    pub mounts: Vec<MountConfig>,
    /// `-v` as typed
    #[serde(default)]
    pub volumes: Vec<String>,
    /// `--mount` as typed
    #[serde(default)]
    pub mount: Vec<String>,
    /// Bind mounts as values (a path may hold any character, which the
    /// text of `-v` cannot say)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind_mounts: Vec<BindMountRequest>,
    /// Mounts of an image as values
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_mounts: Vec<ImageMountRequest>,
    /// `bind` (default), `tmpfs` or `ignore`: what to do with the `VOLUME`s of the image
    #[serde(default)]
    pub image_volume: String,
    #[serde(default)]
    pub tmpfs: Vec<String>,
    #[serde(default)]
    pub read_only_rootfs: bool,
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub cap_add: Vec<String>,
    #[serde(default)]
    pub cap_drop: Vec<String>,
    /// Capabilities in every set of the process, the ambient one too
    #[serde(default)]
    pub cap_ambient: Vec<String>,
    #[serde(default)]
    pub userns_mode: UsernsChoice,
    #[serde(default)]
    pub uid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub gid_mappings: Vec<IdMapping>,
    /// `--uidmap` as typed (`[+ug]CONTAINER:[@]PARENT[:SIZE]`)
    #[serde(default)]
    pub uidmap: Vec<String>,
    /// `--gidmap` as typed (`[+ug]CONTAINER:[@]PARENT[:SIZE]`)
    #[serde(default)]
    pub gidmap: Vec<String>,
    #[serde(default)]
    pub subuidname: Option<String>,
    #[serde(default)]
    pub subgidname: Option<String>,
    #[serde(default)]
    pub tty: bool,
    #[serde(default)]
    pub stdin_open: bool,
    /// Security options
    #[serde(default)]
    pub security_opt: SecurityOptions,
    /// `--security-opt` as given, applied over `security_opt`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_opts: Vec<String>,
    /// Resource limits
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceLimits>,
    /// Health check configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<crate::health::Healthcheck>,
    /// Restart policy
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<RestartPolicy>,
    /// Network mode (bridge, host, none, container:id)
    #[serde(default)]
    pub network_mode: NetworkMode,
    /// Network names to connect to
    #[serde(default)]
    pub networks: Vec<String>,
    /// Network aliases
    #[serde(default)]
    pub network_aliases: Vec<String>,
    /// The annotations of the pod, for the CNI plugins of the network (the
    /// infra container of a Kubernetes pod; not annotations of the
    /// container)
    #[serde(default)]
    pub cni_annotations: BTreeMap<String, String>,
    /// The subnets the node gives its pods, for the CNI plugins that ask
    /// for `ipRanges`
    #[serde(default)]
    pub cni_ip_ranges: Vec<String>,
    /// DNS servers
    #[serde(default)]
    pub dns: Vec<String>,
    /// DNS search domains
    #[serde(default)]
    pub dns_search: Vec<String>,
    /// DNS options
    #[serde(default)]
    pub dns_options: Vec<String>,
    /// Custom host-to-IP mappings
    #[serde(default)]
    pub add_hosts: Vec<String>,
    /// Port mappings (host:container)
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    /// Exposed ports
    #[serde(default)]
    pub expose: Vec<String>,
    /// Every exposed port, of the image too, on a free host port (`-P`)
    #[serde(default)]
    pub publish_all: bool,
    /// Static IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Static IPv6 address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip6_address: Option<String>,
    /// MAC address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    /// Stop signal
    #[serde(default)]
    pub stop_signal: String,
    /// Stop timeout in seconds
    #[serde(default)]
    pub stop_timeout: Option<u32>,
    /// OOM score adjustment
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i32>,
    /// Disable OOM killer
    #[serde(default)]
    pub oom_kill_disable: bool,
    /// PID limit
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<i64>,
    /// Shared memory size
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<u64>,
    /// Sysctls
    #[serde(default)]
    pub sysctls: BTreeMap<String, String>,
    /// Ulimits
    #[serde(default)]
    pub ulimits: Vec<Ulimit>,
    /// Log configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_config: Option<LogConfig>,
    /// Devices to add to container
    #[serde(default)]
    pub devices: Vec<DeviceMapping>,
    /// Device cgroup rules
    #[serde(default)]
    pub device_cgroup_rules: Vec<String>,
    /// Run an init process
    #[serde(default)]
    pub init: bool,
    /// Path to init binary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_path: Option<String>,
    /// PID namespace mode
    #[serde(default)]
    pub pid_mode: NsMode,
    /// IPC namespace mode
    #[serde(default)]
    pub ipc_mode: NsMode,
    /// UTS namespace mode
    #[serde(default)]
    pub uts_mode: NsMode,
    /// Cgroup namespace mode
    #[serde(default)]
    pub cgroupns_mode: NsMode,
    /// Cgroup parent
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_parent: Option<String>,
    /// Timezone
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// Umask
    #[serde(skip_serializing_if = "Option::is_none")]
    pub umask: Option<String>,
    /// Automatically remove container on exit
    #[serde(default)]
    pub auto_remove: bool,
    /// `--rmi`: its image is removed with it, unless another container
    /// uses it
    #[serde(default)]
    pub auto_remove_image: bool,
    /// The root file system may lose what it holds in a crash (the overlay
    /// is mounted `volatile`): a container that is thrown away.  `--rm` has
    /// it already; a build step sets it, as its upper layer is read as soon
    /// as the step ends.
    #[serde(default)]
    pub volatile: bool,
    /// Maximum container runtime in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    /// `--systemd`: `true`, `false` or `always`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd: Option<String>,
    /// Container cidfile path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cidfile: Option<String>,
    /// Pod to join
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// The OCI runtime to make the container with: a name of `[runtimes]`,
    /// or the default one (none, its name or its path); never another path
    /// or a name in PATH.  A member of a pod takes the pod's
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Replace existing container with same name
    #[serde(default)]
    pub replace: bool,
    /// Do not create /etc/hosts
    #[serde(default)]
    pub no_hosts: bool,
    /// Allow running with lazy-pulled image (files fetched on-demand)
    #[serde(default)]
    pub lazy: bool,
    /// Secrets to add; the API layer turns them into mounts and variables
    #[serde(default)]
    pub secrets: Vec<SecretRef>,
    /// Set by the engine, never by a client: the secrets the API resolved
    /// into `env` and `mounts` (the request kept in the bundle has none)
    #[serde(skip)]
    pub resolved_secrets: Vec<SecretRef>,
    /// Set by the engine, never by a client: the variables the API added for
    /// the secrets (the request kept in the bundle has none)
    #[serde(skip)]
    pub secret_env: Vec<String>,
    /// The SELinux level wanted (a restored container's: its processes
    /// keep their labels), taken only when no container's level overlaps
    /// it, else one is allocated
    #[serde(skip)]
    pub preferred_selinux_level: Option<String>,
    /// `image` is the directory of the root file system (`PATH[:O]`)
    #[serde(default)]
    pub rootfs: bool,
    /// sd_notify: `container`, `conmon` or `ignore`
    #[serde(default)]
    pub sdnotify: String,
    /// `--cgroups`: enabled, scope, disabled, no-conmon or split
    #[serde(default)]
    pub cgroups: CgroupsMode,
    /// `scope` of a pod's members, set by the pod service (none: the
    /// engine's default); not an option (a create that sets it is
    /// refused): `--cgroups=scope` is resolved into it when the
    /// container is made
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::modes::cgroup_mode_word"
    )]
    pub cgroup_mode: Option<CgroupMode>,
    /// `run --no-monitor`: the process that runs the engine monitors the
    /// container; only the engine that it split from can do it.
    #[serde(default)]
    pub no_monitor: bool,
}

/// Security options for container
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestSecurityOptions"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityOptions {
    /// Disable seccomp
    #[serde(default)]
    pub seccomp_unconfined: bool,
    /// Custom seccomp profile path or JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp_profile: Option<String>,
    /// SELinux label for the container
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_label: Option<String>,
    /// SELinux user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_user: Option<String>,
    /// SELinux role
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_role: Option<String>,
    /// SELinux type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_type: Option<String>,
    /// SELinux level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_level: Option<String>,
    /// `label=files`: the files of a privileged container are labelled
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub selinux_files: bool,
    /// AppArmor profile
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apparmor_profile: Option<String>,
    /// Disable AppArmor
    #[serde(default)]
    pub apparmor_unconfined: bool,
    /// No new privileges
    #[serde(default)]
    pub no_new_privileges: bool,
    /// Mask paths (hidden from container)
    #[serde(default)]
    pub mask_paths: Vec<String>,
    /// Read-only paths
    #[serde(default)]
    pub readonly_paths: Vec<String>,
    /// Procfs mount options
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proc_opts: Option<String>,
    /// Paths unmasked (`ALL` for all) of the masked and read-only ones
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmask_paths: Vec<String>,
    /// `label=filetype:TYPE`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selinux_filetype: Option<String>,
    /// `seccomp-bpf=PATH`: a compiled BPF filter
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seccomp_bpf: Option<String>,
    /// `signature=check|require`: kept in the container.  `check` judges the
    /// whole signature policy (`reject` included) at create and at every
    /// start by the engine, and runs an image the policy accepts without a
    /// signature; `require` also refuses an image no signature rule of the
    /// policy accepted a signature of.  Without it the signature rules of
    /// the policy are judged at create only (`reject` refuses pulls)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// `verity=enforce`: the layers of the image (and of the images
    /// mounted in the container) must be the images whose fs-verity digests
    /// the manifest states, at every start
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verity_enforce: bool,
    /// `verity=off`: the chain of trust the engine holds by default is not
    /// held for this container (refused where signatures or digests are
    /// required)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verity_off: bool,
}

impl SecurityOptions {
    /// Apply one `--security-opt` (podman's forms, `=` or the legacy `:`
    /// after the key); an unknown form is an error.
    pub fn apply(&mut self, opt: &str) -> Result<(), String> {
        let (key, value) = match opt.split_once(['=', ':']) {
            Some((k, v)) => (k, Some(v)),
            None => (opt, None),
        };
        let paths = |v: &str| -> Result<Vec<String>, String> {
            v.split(':')
                .map(|p| match p {
                    "ALL" => Ok(p.to_string()),
                    p if p.starts_with('/') => Ok(p.to_string()),
                    p => Err(format!("invalid path `{p}` in the security option `{opt}`")),
                })
                .collect()
        };
        match (key, value) {
            ("no-new-privileges", None | Some("true")) => self.no_new_privileges = true,
            ("no-new-privileges", Some("false")) => self.no_new_privileges = false,
            ("seccomp", Some("unconfined")) => {
                self.seccomp_unconfined = true;
                self.seccomp_profile = None;
            }
            ("seccomp", Some(p)) if !p.is_empty() => {
                self.seccomp_unconfined = false;
                self.seccomp_profile = Some(p.to_string());
            }
            ("apparmor", Some("unconfined")) => self.apparmor_unconfined = true,
            ("apparmor", Some(p)) if !p.is_empty() => self.apparmor_profile = Some(p.to_string()),
            ("label", Some("disable")) => self.selinux_label = Some("disable".into()),
            ("label", Some("nested")) => {
                return Err(
                    "label=nested is not supported (it unmasks /sys/fs/selinux and mounts a \
                     writable selinuxfs, which a container of velarx does not get)"
                        .into(),
                )
            }
            ("label", Some("files")) => self.selinux_files = true,
            ("label", Some(v)) => match v.split_once(':') {
                Some(("user", x)) => self.selinux_user = Some(x.to_string()),
                Some(("role", x)) => self.selinux_role = Some(x.to_string()),
                Some(("type", x)) => self.selinux_type = Some(x.to_string()),
                Some(("level", x)) => self.selinux_level = Some(x.to_string()),
                Some(("filetype", x)) => self.selinux_filetype = Some(x.to_string()),
                _ => return Err(format!("invalid security option `{opt}`")),
            },
            ("mask", Some(v)) if !v.is_empty() => {
                let p = paths(v)?;
                if p.iter().any(|x| x == "ALL") {
                    return Err(format!("invalid security option `{opt}`"));
                }
                self.mask_paths.extend(p);
            }
            ("unmask", Some(v)) if !v.is_empty() => self.unmask_paths.extend(paths(v)?),
            ("systempaths", Some("unconfined")) => self.unmask_paths.push("ALL".into()),
            ("proc-opts", Some(v)) if !v.is_empty() => self.proc_opts = Some(v.to_string()),
            ("verity", Some("enforce")) if !self.verity_off => self.verity_enforce = true,
            ("verity", Some("off")) if !self.verity_enforce => self.verity_off = true,
            ("verity", Some("enforce" | "off")) => {
                return Err("--security-opt verity=enforce and verity=off contradict".into())
            }
            ("verity", v) => {
                return Err(format!(
                    "invalid --security-opt verity value {:?}, must be \"enforce\" or \"off\"",
                    v.unwrap_or_default()
                ))
            }
            ("seccomp-bpf", Some(p)) if p.starts_with('/') => {
                self.seccomp_bpf = Some(p.to_string())
            }
            ("signature", Some(v @ ("check" | "require"))) => {
                // (it can be tightened, never loosened, by a later one too)
                if self.signature.as_deref() != Some("require") {
                    self.signature = Some(v.to_string());
                }
            }
            ("signature", v) => {
                return Err(format!(
                    "invalid --security-opt signature value {:?}, must be \"check\" or \"require\"",
                    v.unwrap_or_default()
                ))
            }
            _ => return Err(format!("unsupported security option `{opt}`")),
        }
        Ok(())
    }
}

/// Resource limits for container
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestResources"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// CPU quota in microseconds per period
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<i64>,
    /// CPU period in microseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_period: Option<u64>,
    /// CPU shares (relative weight)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_shares: Option<u64>,
    /// CPU set (e.g., "0-2,4")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_cpus: Option<String>,
    /// Memory set (e.g., "0-1")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_mems: Option<String>,
    /// Memory limit in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<i64>,
    /// Memory + swap limit in bytes (-1 for unlimited)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swap: Option<i64>,
    /// Memory reservation (soft limit) in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_reservation: Option<i64>,
    /// Block IO weight
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_weight: Option<u16>,
    /// Block IO weight devices
    #[serde(default)]
    pub blkio_weight_device: Vec<WeightDevice>,
    /// Block IO read bandwidth limits
    #[serde(default)]
    pub blkio_device_read_bps: Vec<ThrottleDevice>,
    /// Block IO write bandwidth limits
    #[serde(default)]
    pub blkio_device_write_bps: Vec<ThrottleDevice>,
    /// Block IO read IOPS limits
    #[serde(default)]
    pub blkio_device_read_iops: Vec<ThrottleDevice>,
    /// Block IO write IOPS limits
    #[serde(default)]
    pub blkio_device_write_iops: Vec<ThrottleDevice>,
    /// Device read BPS limit (e.g., "/dev/sda:1mb")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_read_bps: Option<String>,
    /// Device write BPS limit (e.g., "/dev/sda:1mb")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_write_bps: Option<String>,
    /// Device read IOPS limit (e.g., "/dev/sda:1000")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_read_iops: Option<String>,
    /// Device write IOPS limit (e.g., "/dev/sda:1000")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_write_iops: Option<String>,
    /// Shared memory size (shm-size) in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<u64>,
    /// Cgroup v2 arbitrary configuration (KEY=VALUE pairs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_conf: Option<std::collections::BTreeMap<String, String>>,
    /// Hugepage limits: page size (`2MB`) and bytes
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hugepage_limits: Vec<HugepageLimit>,
}

impl ResourceLimits {
    /// Whether these are limits of a cgroup (the size of /dev/shm is not).
    pub fn need_cgroup(&self) -> bool {
        self.cpu_quota.is_some()
            || self.cpu_period.is_some()
            || self.cpu_shares.is_some()
            || self.cpuset_cpus.is_some()
            || self.cpuset_mems.is_some()
            || self.memory.is_some()
            || self.memory_swap.is_some()
            || self.memory_reservation.is_some()
            || self.blkio_weight.is_some()
            || !self.blkio_weight_device.is_empty()
            || !self.blkio_device_read_bps.is_empty()
            || !self.blkio_device_write_bps.is_empty()
            || !self.blkio_device_read_iops.is_empty()
            || !self.blkio_device_write_iops.is_empty()
            || self.device_read_bps.is_some()
            || self.device_write_bps.is_some()
            || self.device_read_iops.is_some()
            || self.device_write_iops.is_some()
            || self.cgroup_conf.as_ref().is_some_and(|c| !c.is_empty())
            || !self.hugepage_limits.is_empty()
    }
}

/// A limit of the hugepages of one size.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestHugepageLimit"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HugepageLimit {
    pub page_size: String,
    pub limit: u64,
}

/// The major and minor numbers of a block device.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestDeviceNumbers"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceNumbers {
    pub major: u64,
    pub minor: u64,
}

/// The user and the group that own a file.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestOwner"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

/// Block IO weight device
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightDevice {
    /// The device node; empty when `device` names the device
    pub path: String,
    pub weight: u16,
    /// Major and minor numbers of the block device
    #[serde(default)]
    pub device: Option<DeviceNumbers>,
}

/// Block IO throttle device
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleDevice {
    pub path: String,
    pub rate: u64,
}

pub use crate::pod::RestartPolicy;

/// A cgroup device rule (`--device-cgroup-rule 'c 1:3 rwm'`).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestDeviceRule"))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRule {
    /// `a`, `b` or `c`
    pub typ: String,
    /// None: any
    pub major: Option<i64>,
    pub minor: Option<i64>,
    /// Some of `rwm`
    pub access: String,
}

/// `--device-cgroup-rule 'TYPE MAJOR:MINOR ACCESS'` (`*` for any number).
pub fn parse_device_rule(s: &str) -> Result<DeviceRule, String> {
    let f: Vec<&str> = s.split_whitespace().collect();
    let [typ, nums, access] = f[..] else {
        return Err(format!(
            "invalid device cgroup rule requires type, major:Minor, and access rules: \"{s}\""
        ));
    };
    if !matches!(typ, "a" | "b" | "c") {
        return Err(format!("invalid device type in device-access-add: {typ}"));
    }
    if let Some(c) = access.chars().find(|c| !"rwm".contains(*c)) {
        return Err(format!("invalid device access in device-access-add: {c}"));
    }
    if access.is_empty() {
        return Err(format!(
            "invalid device cgroup rule requires type, major:Minor, and access rules: \"{s}\""
        ));
    }
    let (maj, min) = nums.split_once(':').unwrap_or((nums, "*"));
    let num = |n: &str| -> Result<Option<i64>, String> {
        match n {
            "*" => Ok(None),
            n => n
                .parse::<u32>()
                .map(|v| Some(v.into()))
                .map_err(|_| format!("strconv.ParseUint: parsing \"{n}\": invalid syntax")),
        }
    };
    Ok(DeviceRule {
        typ: typ.to_string(),
        major: num(maj)?,
        minor: num(min)?,
        access: access.to_string(),
    })
}

/// Port mapping
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestPortMapping"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Container port
    pub container_port: u16,
    /// Host port (optional, auto-assigned if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_port: Option<u16>,
    /// Host IP to bind to
    #[serde(default)]
    pub host_ip: String,
    /// Protocol (tcp, udp)
    #[serde(default = "default_protocol")]
    pub protocol: String,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

/// What the RUN steps of a build take from the command line
/// (`build --volume`, `--add-host`, `--dns`, `--cap-add`, `--security-opt`,
/// `--ulimit`, `--device`, `--shm-size`...).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BuildRun {
    pub volumes: Vec<String>,
    pub add_hosts: Vec<String>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_options: Vec<String>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub security_opts: Vec<String>,
    pub ulimits: Vec<Ulimit>,
    pub devices: Vec<DeviceMapping>,
    pub shm_size: Option<u64>,
    /// `--group-add`
    pub group_add: Vec<String>,
    /// `--no-hosts`
    pub no_hosts: bool,
    /// `--no-hostname`
    pub no_hostname: bool,
    /// `--memory`, `--cpu-*`, `--cpuset-*` (none: no limit)
    pub resources: Option<ResourceLimits>,
    pub cgroup_parent: Option<String>,
    /// `--ipc`: the IPC namespace mode of `run`
    pub ipc: NsMode,
    /// `--pid`: the PID namespace mode of `run`
    pub pid: NsMode,
    /// `--uts`: the UTS namespace mode of `run`
    pub uts: NsMode,
    /// `--cgroupns`: the cgroup namespace mode of `run`
    pub cgroupns: NsMode,
    /// `--userns`: the user namespace mode of `run`
    pub userns: UsernsChoice,
    /// `--userns-uid-map` (`CONTAINER:HOST:SIZE`)
    pub uidmap: Vec<String>,
    /// `--userns-gid-map` (`CONTAINER:HOST:SIZE`)
    pub gidmap: Vec<String>,
    /// `--userns-uid-map-user`
    pub subuidname: Option<String>,
    /// `--userns-gid-map-group`
    pub subgidname: Option<String>,
}

/// Ulimit configuration
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestUlimit"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ulimit {
    pub name: String,
    pub soft: u64,
    pub hard: u64,
}

/// Log configuration
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestLogConfig"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log driver (json-file, syslog, journald, none)
    #[serde(rename = "type")]
    pub driver: String,
    /// Log driver options
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

/// Device mapping
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestDevice"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMapping {
    /// Path on host
    pub path_on_host: String,
    /// Path in container
    pub path_in_container: String,
    /// Cgroup permissions (r, w, m)
    #[serde(default = "default_device_cgroup_permissions")]
    pub cgroup_permissions: String,
}

/// The annotation that makes a container an init container of its pod
/// (podman's), with the type `once` or `always`.
pub const INIT_TYPE_ANNOTATION: &str = "io.podman.annotations.init.container.type";

/// `--init-ctr TYPE` of a container in `pod`: the type checked, in podman's
/// words.
pub fn init_container_type(kind: &str, pod: Option<&str>) -> Result<&'static str, String> {
    if pod.is_none_or(str::is_empty) {
        return Err("must specify pod value with init-ctr".into());
    }
    match kind {
        "once" => Ok("once"),
        "always" => Ok("always"),
        _ => Err("init-ctr value must be 'always' or 'once'".into()),
    }
}

/// `--volumes-from CONTAINER[:OPTIONS]`: the destination and the `-v`
/// value of each volume and bind mount of the user that the inspect of the
/// container lists (a tmpfs is not a volume).  OPTIONS, as podman's, are `z`, `ro` and `rw`, which
/// replace the options of the mounts; without them the mounts keep theirs.
pub fn volumes_from_args(
    mounts: &[crate::workload::ContainerMount],
    options: &str,
) -> Result<Vec<(String, String)>, String> {
    let (mut ro_rw, mut z) = (false, false);
    if !options.is_empty() {
        for o in options.split(',') {
            match o {
                "z" if z => return Err("cannot set :z more than once in mount options".into()),
                "z" => z = true,
                "ro" | "rw" if ro_rw => {
                    return Err("cannot set ro or rw options more than once".into())
                }
                "ro" | "rw" => ro_rw = true,
                o => {
                    return Err(format!(
                        "invalid option {o:?} specified - volumes from another container can only use z,ro,rw options"
                    ))
                }
            }
        }
    }
    // the options a `-v` takes again
    const KEPT: [&str; 13] = [
        "ro", "noexec", "nosuid", "nodev", "exec", "suid", "dev", "shared", "rshared", "slave",
        "rslave", "U", "idmap",
    ];
    let mut out = Vec::new();
    for m in mounts {
        use crate::workload::MountKind;
        let source = match m.kind {
            MountKind::Volume => &m.name,
            MountKind::Bind => &m.source,
            MountKind::Tmpfs | MountKind::Image => continue,
        };
        let dest = &m.destination;
        let opts: Vec<&str> = if options.is_empty() {
            let mut o: Vec<&str> = m
                .options
                .iter()
                .map(String::as_str)
                .filter(|o| KEPT.contains(o) || o.starts_with("idmap="))
                .collect();
            if m.read_only && !o.contains(&"ro") {
                o.insert(0, "ro");
            }
            o
        } else {
            options.split(',').collect()
        };
        let dest = format!("/{}", dest.trim_matches('/'));
        let arg = if opts.is_empty() {
            format!("{source}:{dest}")
        } else {
            format!("{source}:{dest}:{}", opts.join(","))
        };
        out.push((dest, arg));
    }
    Ok(out)
}

impl Ulimit {
    /// `NAME=SOFT[:HARD]`, in podman's words when it is not.
    pub fn parse(s: &str) -> Result<Self, String> {
        let bad = |why: String| {
            format!("ulimit option {s:?} requires name=SOFT:HARD, failed to be parsed: {why}")
        };
        let invalid = || bad(format!("invalid ulimit argument: {s}"));
        let (name, limits) = s.split_once('=').ok_or_else(invalid)?;
        let (soft_str, hard_str) = limits.split_once(':').unwrap_or((limits, limits));
        let value = |v: &str| limit_value(v).ok_or_else(invalid);
        let (soft, hard) = (value(soft_str)?, value(hard_str)?);
        // (an unlimited soft limit under a hard one has words of its own)
        if soft == u64::MAX && hard != u64::MAX {
            return Err(bad(format!(
                "ulimit soft limit must be less than or equal to hard limit: soft: -1 (unlimited), hard: {hard_str}"
            )));
        }
        if soft > hard {
            return Err(bad(format!(
                "ulimit soft limit must be less than or equal to hard limit: {soft_str} > {hard_str}"
            )));
        }
        Ok(Self {
            name: name.to_string(),
            soft,
            hard,
        })
    }
}

impl DeviceMapping {
    /// `HOST[:CONTAINER[:PERMISSIONS]]`, or a CDI device name.
    pub fn parse(s: &str) -> Self {
        // not a path: a CDI device, whose name may hold a `:`
        if !s.starts_with('/') {
            return Self::cdi(s);
        }
        let parts: Vec<&str> = s.split(':').collect();
        Self {
            path_on_host: parts[0].to_string(),
            path_in_container: parts.get(1).unwrap_or(&parts[0]).to_string(),
            cgroup_permissions: parts.get(2).unwrap_or(&"rwm").to_string(),
        }
    }

    /// A CDI device (`vendor.com/class=name`): the name alone, where a path
    /// would be, for the engine to resolve from its spec directories.
    pub fn cdi(name: &str) -> Self {
        Self {
            path_on_host: name.to_string(),
            path_in_container: String::new(),
            cgroup_permissions: default_device_cgroup_permissions(),
        }
    }
}

fn default_device_cgroup_permissions() -> String {
    "rwm".to_string()
}

impl Default for CreateContainerRequest {
    fn default() -> Self {
        Self {
            id: None,
            name: None,
            image: String::new(),
            command: Vec::new(),
            entrypoint: Vec::new(),
            reset_entrypoint: false,
            working_dir: String::new(),
            env: Vec::new(),
            labels: BTreeMap::new(),
            annotations: BTreeMap::new(),
            hostname: String::new(),
            user: String::new(),
            group_add: Vec::new(),
            create_command: Vec::new(),
            groups_strict: false,
            passwd_entry: None,
            group_entry: None,
            no_passwd: false,
            unsetenv: Vec::new(),
            unsetenv_all: false,
            env_merge: Vec::new(),
            personality: None,
            hosts_file: None,
            hosts_image: None,
            chroot_dirs: Vec::new(),
            host_users: Vec::new(),
            rdt_class: None,
            seccomp_policy: None,
            rootfs_propagation: None,
            no_read_only_tmpfs: false,
            no_hostname: false,
            no_healthcheck: false,
            requires: Vec::new(),
            shm_size_systemd: None,
            pidfile: None,
            conmon_pidfile: None,
            selinux_share_with: None,
            mounts: Vec::new(),
            volumes: Vec::new(),
            mount: Vec::new(),
            bind_mounts: Vec::new(),
            image_mounts: Vec::new(),
            image_volume: String::new(),
            tmpfs: Vec::new(),
            read_only_rootfs: false,
            privileged: false,
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
            cap_ambient: Vec::new(),
            userns_mode: UsernsChoice::Host,
            uid_mappings: Vec::new(),
            gid_mappings: Vec::new(),
            uidmap: Vec::new(),
            gidmap: Vec::new(),
            subuidname: None,
            subgidname: None,
            tty: false,
            stdin_open: false,
            security_opt: SecurityOptions::default(),
            security_opts: Vec::new(),
            resources: None,
            healthcheck: None,
            restart_policy: None,
            network_mode: NetworkMode::Unset,
            networks: Vec::new(),
            network_aliases: Vec::new(),
            cni_annotations: BTreeMap::new(),
            cni_ip_ranges: Vec::new(),
            dns: Vec::new(),
            dns_search: Vec::new(),
            dns_options: Vec::new(),
            add_hosts: Vec::new(),
            ports: Vec::new(),
            expose: Vec::new(),
            publish_all: false,
            ip_address: None,
            ip6_address: None,
            mac_address: None,
            stop_signal: String::new(),
            stop_timeout: None,
            oom_score_adj: None,
            oom_kill_disable: false,
            pids_limit: None,
            shm_size: None,
            sysctls: BTreeMap::new(),
            ulimits: Vec::new(),
            log_config: None,
            devices: Vec::new(),
            device_cgroup_rules: Vec::new(),
            init: false,
            init_path: None,
            pid_mode: NsMode::Default,
            ipc_mode: NsMode::Default,
            uts_mode: NsMode::Default,
            cgroupns_mode: NsMode::Default,
            cgroup_parent: None,
            timezone: None,
            umask: None,
            auto_remove: false,
            auto_remove_image: false,
            volatile: false,
            timeout: None,
            systemd: None,
            cidfile: None,
            pod: None,
            runtime: None,
            replace: false,
            no_hosts: false,
            lazy: false,
            secrets: Vec::new(),
            resolved_secrets: Vec::new(),
            secret_env: Vec::new(),
            preferred_selinux_level: None,
            rootfs: false,
            sdnotify: String::new(),
            cgroups: CgroupsMode::Unset,
            cgroup_mode: None,
            no_monitor: false,
        }
    }
}

/// Mount configuration for container volumes
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestMount"))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MountConfig {
    /// Source path on host
    pub source: String,
    /// Destination path in container (target)
    pub target: String,
    /// Mount type (bind, volume, tmpfs, etc.)
    #[serde(default)]
    pub mount_type: Option<String>,
    /// Mount options
    #[serde(default)]
    pub options: Vec<String>,
    /// The named volume that is the source
    #[serde(default)]
    pub volume: Option<String>,
    /// Only this directory of the volume
    #[serde(default)]
    pub subpath: Option<String>,
    /// The source is (a directory of) an image
    #[serde(default)]
    pub image: Option<ImageMountConfig>,
    /// `U`: the source is given to the user of the container
    #[serde(default)]
    pub chown: bool,
    /// Do not copy the content of the image in a new volume
    #[serde(default)]
    pub nocopy: bool,
    /// `z` or `Z`
    #[serde(default)]
    pub relabel: Option<String>,
    /// `idmap` or `idmap=uids=..;gids=..` as given
    #[serde(default)]
    pub idmap: Option<String>,
    /// The mappings of an idmapped mount, once worked out
    #[serde(default)]
    pub uid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub gid_mappings: Vec<IdMapping>,
    /// `O`: an overlay with the source as its lower layer
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay: Option<OverlayMountConfig>,
    /// The directory of the volume whose `subpath` is mounted, once the
    /// container is created: the monitor looks the sub path up in it at
    /// each start, the source is then where it mounts it
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subpath_root: Option<String>,
    /// A secret file of the container: its owner, ids of the container
    /// (`--secret ...,uid=,gid=`), given through the user namespace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_owner: Option<Owner>,
    /// The engine added it (its files of the bundle, the init binary, the
    /// notify socket): the inspect does not list it
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub engine: bool,
}

/// An overlay volume (`-v SRC:DST:O`): the source is the lower layer, the
/// container writes to an upper layer that is its own (discarded when it
/// stops) or the user's (`upperdir=`, `workdir=`).
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct OverlayMountConfig {
    #[serde(default)]
    pub upperdir: Option<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    /// The lower layer (the source given), once the container is created;
    /// the source of the mount is then where the monitor mounts the overlay
    #[serde(default)]
    pub lower: Option<String>,
    /// The owner of a new upper layer: the root of the container
    #[serde(default)]
    pub owner: Option<Owner>,
}

/// A directory or file of the host bind-mounted in a container.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BindMountRequest {
    /// The absolute path on the host
    pub source: String,
    /// The absolute path in the container
    pub target: String,
    /// The options, one each, as the options of `-v` (`ro`, `rslave`, `rro`,
    /// `z`, `idmap=...`)
    #[serde(default)]
    pub options: Vec<String>,
}

/// An image (or a directory of it) to mount, read-only, in a container.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageMountRequest {
    pub image: String,
    /// The absolute path in the container
    pub target: String,
    pub subpath: Option<String>,
}

/// An image (or a directory of it) mounted in a container.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageMountConfig {
    /// the name given, then the id of the image
    pub image: String,
    pub subpath: Option<String>,
    /// read-write: changes go to a private layer
    pub rw: bool,
    /// The digest the image was named by (`NAME@sha256:...`): what an
    /// enforced start verifies the image from
    #[serde(default)]
    pub digest: Option<String>,
}

pub use crate::pod::IdMapping;

/// A secret a container uses (`--secret`): a file at `target` (default
/// `/run/secrets/NAME`), or with `env` the variable `target`.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[cfg_attr(feature = "proxy", zlink(rename = "RequestSecret"))]
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecretRef {
    pub name: String,
    #[serde(default)]
    pub env: bool,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    /// 0 is 0444
    #[serde(default)]
    pub mode: u32,
}

impl SecretRef {
    /// `name[,type=mount|env][,target=T][,uid=N][,gid=N][,mode=OCTAL]`
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut parts = s.split(',');
        let name = parts.next().unwrap_or_default();
        if name.is_empty() || name.contains('=') {
            return Err(format!("invalid secret `{s}`: the name comes first"));
        }
        let mut r = Self {
            name: name.to_string(),
            ..Default::default()
        };
        for opt in parts {
            let (k, v) = opt
                .split_once('=')
                .ok_or_else(|| format!("invalid secret option `{opt}`"))?;
            let num = |v: &str, radix| {
                u32::from_str_radix(v, radix).map_err(|_| format!("invalid secret {k} `{v}`"))
            };
            match k {
                "type" => {
                    r.env = match v {
                        "mount" => false,
                        "env" => true,
                        _ => return Err(format!("invalid secret type `{v}`")),
                    }
                }
                "target" => r.target = v.to_string(),
                "uid" => r.uid = num(v, 10)?,
                "gid" => r.gid = num(v, 10)?,
                "mode" => r.mode = num(v, 8)?,
                _ => return Err(format!("invalid secret option `{k}`")),
            }
        }
        Ok(r)
    }
}

/// A limit of `--ulimit`: a number, `-1` or `unlimited`.
pub fn limit_value(s: &str) -> Option<u64> {
    match s {
        "-1" | "unlimited" => Some(u64::MAX),
        _ => s.parse().ok(),
    }
}

#[cfg(test)]
mod volumes_from_tests {
    use super::typed_digests;

    #[test]
    fn the_digests_of_a_command_are_those_of_its_references() {
        let (a, b) = ("ab".repeat(32), "cd".repeat(32));
        let got = typed_digests([
            format!("quay.io/x/y@sha256:{a}").as_str(),
            format!("type=image,source=z:1@sha256:{b},destination=/i").as_str(),
            format!("again@sha256:{a}").as_str(),
            "no/digest:tag",
            "short@sha256:ab",
            &format!("upper@sha256:{}", a.to_uppercase()),
        ]);
        assert_eq!(got, [format!("sha256:{a}"), format!("sha256:{b}")]);
        // a sha512 is typed with its 128 digits; one of 64 is none
        let long = "ef".repeat(64);
        let got = typed_digests([
            format!("r.io/x:1@sha512:{long}").as_str(),
            format!("r.io/y@sha512:{a}").as_str(),
            format!("r.io/z@sha512:{}", long.to_uppercase()).as_str(),
        ]);
        assert_eq!(got, [format!("sha512:{long}")]);
    }

    use super::volumes_from_args;
    use crate::workload::{ContainerMount, MountKind};

    fn args(mounts: &[ContainerMount], options: &str) -> Result<Vec<String>, String> {
        volumes_from_args(mounts, options).map(|v| v.into_iter().map(|(_, a)| a).collect())
    }

    fn mount(kind: MountKind, source: &str, dest: &str, ro: bool, opts: &[&str]) -> ContainerMount {
        ContainerMount {
            kind,
            name: if kind == MountKind::Volume {
                source.into()
            } else {
                String::new()
            },
            source: source.into(),
            destination: dest.into(),
            read_only: ro,
            options: opts.iter().map(|o| o.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn the_volumes_and_binds_of_the_user_are_taken() {
        let info = [
            mount(
                MountKind::Volume,
                "v",
                "/v",
                false,
                &["rbind", "rw", "rprivate", "noexec"],
            ),
            mount(
                MountKind::Bind,
                "/host",
                "/b/",
                true,
                &["rbind", "ro", "rprivate"],
            ),
            mount(MountKind::Tmpfs, "", "/t", false, &[]),
            // the hosts file of another container, bound by the user
            mount(MountKind::Bind, "/s/bundles/def/hosts", "/h", false, &[]),
        ];
        assert_eq!(
            volumes_from_args(&info, "").unwrap(),
            [
                ("/v".to_string(), "v:/v:noexec".to_string()),
                ("/b".to_string(), "/host:/b:ro".to_string()),
                ("/h".to_string(), "/s/bundles/def/hosts:/h".to_string()),
            ]
        );
        // the options asked replace those of the mounts, as podman's
        assert_eq!(
            args(&info, "ro").unwrap(),
            ["v:/v:ro", "/host:/b:ro", "/s/bundles/def/hosts:/h:ro"]
        );
        assert_eq!(
            args(&info, "rw,z").unwrap(),
            ["v:/v:rw,z", "/host:/b:rw,z", "/s/bundles/def/hosts:/h:rw,z"]
        );
    }

    #[test]
    fn podman_s_options_only() {
        let info = [];
        let e = args(&info, "Z").unwrap_err();
        assert_eq!(
            e,
            "invalid option \"Z\" specified - volumes from another container can only use z,ro,rw options"
        );
        assert!(args(&info, "ro,rw")
            .unwrap_err()
            .contains("ro or rw options more than once"));
        assert!(args(&info, "z,z")
            .unwrap_err()
            .contains(":z more than once"));
        assert!(args(&info, "ro,z").is_ok());
    }
}
