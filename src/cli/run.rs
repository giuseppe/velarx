// SPDX-License-Identifier: Apache-2.0
//! `container run` and the commands around the life of a container, as the
//! client does them through the API: shared by the thin client and by the
//! engine, which serves the API to itself when it runs a container without
//! a server.

use crate::cli::{ContainerCommands, PullPolicy};
use crate::client::{self, EngineClient};
use velarx_proto::engine::Condition;
use velarx_proto::health::{Healthcheck, OnFailure, StartupHealthcheck};
use velarx_proto::workload::RunState;
use velarx_wire::request::{NetworkMode, UsernsChoice};

/// What `attach_session` is asked.
pub struct AttachRequest {
    pub tty: bool,
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    pub detach_keys: Option<String>,
    pub sig_proxy: bool,
    pub start: bool,
}

/// The detach keys of an attach or exec: those of the command line, else
/// with a terminal those of the configuration (`[containers] detach_keys`), else
/// the monitor client's default (ctrl-p,ctrl-q with a terminal).  Bad keys
/// are refused here, before anything starts.
pub fn detach_keys(flag: Option<String>, tty: bool) -> anyhow::Result<Option<String>> {
    let keys = match flag {
        Some(k) => Some(k),
        None if tty => super::config()?.containers.detach_keys,
        None => None,
    };
    if let Some(k) = &keys {
        velarx_proto::stream::parse_detach_keys(k)
            .map_err(|e| anyhow::anyhow!("invalid detach keys {k:?}: {e}"))?;
    }
    Ok(keys)
}

/// Relay the standard streams to a container, through the engine; the exit
/// code of the container (0 when the user detached).
pub fn attach_session(client: &EngineClient, id: &str, req: AttachRequest) -> anyhow::Result<i32> {
    use super::attach::{relay, terminal_size, Relay};
    let (height, width) = terminal_size()
        .filter(|_| req.tty)
        .map_or((None, None), |(h, w)| {
            (Some(i64::from(h)), Some(i64::from(w)))
        });
    let opts = velarx_proto::engine::AttachOptions {
        stdout: req.stdout,
        stderr: req.stderr,
        logs: false,
        stream: true,
        stdin: req.stdin,
        detach_keys: detach_keys(req.detach_keys, req.tty)?,
        stdin_once: false,
        stdin_keep_open: false,
        start: req.start,
        height,
        width,
    };
    let opened = client.open_attach(id, opts)?;
    let tty = opened.session.tty();
    let ended = relay(
        opened,
        Relay {
            tty,
            input: req.stdin,
            sig_proxy: req.sig_proxy,
            resize: &|rows, cols| {
                let _ = client.resize_container(id, rows, cols);
            },
            // (a container gets Kill: a session has no signal of its own; a
            // container that does not run any more is the end the session
            // is about to say)
            signal: &|sig| {
                let _ = client.kill_container(id, &sig.to_string());
            },
        },
    )?;
    match (ended.detached, ended.exit) {
        (true, _) => Ok(0),
        (false, Some(code)) => Ok(exit_code(code)),
        // The session ended without a word: the engine knows.
        (false, None) => Ok(exit_code(client.wait_condition(id, &[], 0)?)),
    }
}

/// An exit code the engine answers, as a process has it.
pub fn exit_code(code: i64) -> i32 {
    i32::try_from(code).unwrap_or(-1)
}

/// Run `op` on every name and print the ones it succeeded on.  A resource
/// that does not exist is skipped with `ignore`; any other failure is
/// reported, the remaining names are still handled, and the command fails.
pub fn each_named(
    names: &[String],
    ignore: bool,
    op: impl FnMut(&str) -> client::ClientResult<()>,
) -> anyhow::Result<()> {
    each_named_as(names, ignore, &Statuses::RM, op)
}

/// A signal of `kill -s`, checked as podman checks it before any container
/// is looked up: a number from 1 to 64, or a name of the table the engine
/// uses, with or without SIG (a leading dash is taken).  What the server
/// gets: the number, or SIGNAME.
pub fn check_signal(signal: &str) -> anyhow::Result<String> {
    let s = signal.strip_prefix('-').unwrap_or(signal);
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return match s.parse::<u64>() {
            Ok(0) => anyhow::bail!("invalid signal: {s}"),
            Ok(n @ 1..=64) => Ok(n.to_string()),
            _ => anyhow::bail!("valid signals are 1 through 64"),
        };
    }
    let upper = s.to_ascii_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    if velarx_wire::monitor::sys::parse_signal(name).is_none() {
        anyhow::bail!("invalid signal: {s}");
    }
    Ok(format!("SIG{name}"))
}

/// What podman says and exits with when a command on several names fails.
pub struct Statuses {
    /// podman's message for a name that is not there
    pub not_found: fn(&str) -> String,
    /// the status when the only failures are names that are not there
    pub missing: i32,
    /// when one of them is in a state that does not allow it (409)
    pub conflict: i32,
    /// for the other errors
    pub other: i32,
    /// the names are all looked up before anything is done (podman's volume
    /// rm): the missing ones are said first, and a state that did not allow
    /// it decides over them
    pub lookup_first: bool,
}

impl Statuses {
    /// container rm: 1 for the missing, 2 for a state that does not allow it
    pub const RM: Statuses = Statuses {
        not_found: |n| format!("no container with ID or name \"{n}\" found: no such container"),
        missing: 1,
        conflict: 2,
        other: 125,
        lookup_first: false,
    };
    /// stop, kill...: 125
    pub const CONTAINER: Statuses = Statuses {
        not_found: |n| format!("no container with name or ID \"{n}\" found: no such container"),
        missing: 125,
        conflict: 125,
        other: 125,
        lookup_first: false,
    };
    pub const POD_RM: Statuses = Statuses {
        not_found: |n| format!("no pod with name or ID {n} found: no such pod"),
        missing: 1,
        conflict: 125,
        other: 125,
        lookup_first: false,
    };
    pub const POD: Statuses = Statuses {
        not_found: |n| format!("no pod with name or ID {n} found: no such pod"),
        missing: 125,
        conflict: 125,
        other: 125,
        lookup_first: false,
    };
    pub const VOLUME_RM: Statuses = Statuses {
        not_found: |n| format!("no volume with name \"{n}\" found: no such volume"),
        missing: 1,
        conflict: 2,
        other: 125,
        lookup_first: true,
    };
}

/// `op` on each of `items` in order: a failure is given to `failed` and the
/// next item goes on, a signal that ended the command
/// ([`client::ClientError::Interrupted`]) ends the loop at once, so that the
/// next item is not started and the command ends with 128 plus the signal.
/// Every loop over names that change the state goes through this.
pub fn each_item<T>(
    items: impl IntoIterator<Item = T>,
    mut op: impl FnMut(&T) -> client::ClientResult<()>,
    mut failed: impl FnMut(T, client::ClientError),
) -> anyhow::Result<()> {
    for item in items {
        match op(&item) {
            Ok(()) => {}
            Err(e) if e.is_interrupted() => return Err(e.into()),
            Err(e) => failed(item, e),
        }
    }
    Ok(())
}

/// `op` on each of `names`, each printed when it succeeds, with podman's
/// messages and exit status (`statuses`) for the failures: each is said,
/// the last one is the error of the command.  `ignore`: a name that is not
/// there is no failure.
pub fn each_named_as(
    names: &[String],
    ignore: bool,
    statuses: &Statuses,
    mut op: impl FnMut(&str) -> client::ClientResult<()>,
) -> anyhow::Result<()> {
    each_named_printing(names, ignore, statuses, |name| {
        op(name).map(|()| vec![name.to_string()])
    })
}

/// The most calls of a [`each_named_parallel`] that run at once.
const PARALLEL_CALLS: usize = 16;

/// [`each_named_printing`] where `op` runs on all the names at once (podman's
/// `stop` and `rm` of several containers work in parallel, so that the stop
/// timeouts of the containers that ignore the signal do not add up); what is
/// printed and said is in the order of the names.
pub fn each_named_parallel(
    names: &[String],
    ignore: bool,
    statuses: &Statuses,
    op: impl Fn(&str) -> client::ClientResult<Vec<String>> + Sync,
) -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let (next, interrupted) = (AtomicUsize::new(0), AtomicBool::new(false));
    let slots: Vec<std::sync::Mutex<Option<client::ClientResult<Vec<String>>>>> =
        names.iter().map(|_| Default::default()).collect();
    std::thread::scope(|s| {
        for _ in 0..names.len().min(PARALLEL_CALLS) {
            s.spawn(|| loop {
                // (a signal that ended a call starts no other)
                if interrupted.load(Ordering::Relaxed) {
                    return;
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(name) = names.get(i) else { return };
                let result = op(name);
                if matches!(&result, Err(e) if e.is_interrupted()) {
                    interrupted.store(true, Ordering::Relaxed);
                }
                *slots[i].lock().unwrap() = Some(result);
            });
        }
    });
    // (the names after an interrupted one were not started: the loop ends
    // at that one)
    let mut results = slots.into_iter().map(|s| s.into_inner().unwrap());
    each_named_printing(names, ignore, statuses, |_| {
        results
            .next()
            .flatten()
            .unwrap_or(Err(client::ClientError::Interrupted(libc::SIGINT)))
    })
}

/// [`each_named_as`] where `op` says what to print when it succeeds (the
/// containers a `rm --depend` removed).
pub fn each_named_printing(
    names: &[String],
    ignore: bool,
    statuses: &Statuses,
    mut op: impl FnMut(&str) -> client::ClientResult<Vec<String>>,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    let (mut missing, mut conflict) = (0, 0);
    let ended = each_item(
        names,
        |name| match op(name) {
            Ok(lines) => {
                for line in lines {
                    println!("{line}");
                }
                Ok(())
            }
            Err(e) if ignore && e.is_not_found() => Ok(()),
            Err(e) => Err(e),
        },
        |name, e| {
            let message = if e.is_not_found() {
                missing += 1;
                (statuses.not_found)(name)
            } else {
                // (podman's messages name what they are about)
                conflict += usize::from(e.is_conflict());
                e.to_string()
            };
            errors.push((e.is_not_found(), message));
        },
    );
    if let Err(e) = ended {
        for (_, e) in &errors {
            eprintln!("Error: {e}");
        }
        return Err(e);
    }
    if statuses.lookup_first {
        errors.sort_by_key(|(missing, _)| !missing);
    }
    let Some((_, last)) = errors.pop() else {
        return Ok(());
    };
    for (_, e) in &errors {
        eprintln!("Error: {e}");
    }
    // podman's: a missing name decides, then a state that did not allow it
    let status = if conflict > 0 && statuses.lookup_first {
        statuses.conflict
    } else if missing > 0 {
        statuses.missing
    } else if conflict > 0 {
        statuses.conflict
    } else {
        statuses.other
    };
    Err(Failed {
        status,
        message: last,
    }
    .into())
}

/// The error of a run whose container could not be started, with podman's
/// status for it (`define.ExitCode`): 127 when the engine says the command
/// to run is not found, 126 for anything else that stopped it from starting
/// (a runtime that could not run it, the container removed meanwhile by
/// someone else: podman's 126 for "no such container" too).
pub fn not_started(e: &client::ClientError) -> Failed {
    Failed {
        status: if e.is(Condition::CommandNotFound) {
            127
        } else {
            126
        },
        message: e.to_string(),
    }
}

/// Whether the engine says the container could not be started (its runtime
/// refused it, its user or working directory is not there, its command is
/// not found), which `run` exits 126 or 127 for.
fn is_not_started(e: &client::ClientError) -> bool {
    e.is(Condition::NotStarted) || e.is(Condition::CommandNotFound)
}

/// The error `e` of an exec, with podman's status 255 when the state of
/// the container did not allow it.
pub fn exec_failure(e: client::ClientError) -> anyhow::Error {
    if e.is(Condition::InvalidState) {
        Failed {
            status: 255,
            message: e.to_string(),
        }
        .into()
    } else {
        e.into()
    }
}

/// An error of a command with the exit status podman gives it, when that
/// is not the 125 of the other errors.
#[derive(Debug)]
pub struct Failed {
    pub status: i32,
    pub message: String,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failed {}

/// Arguments for running a container with all its options
pub struct RunContainerArgs {
    pub storage: crate::cli::MountArgs,
    pub name: Option<String>,
    pub detach_keys: Option<String>,
    pub sig_proxy: bool,
    pub detach: bool,
    /// The process that runs the engine is the monitor (`--no-monitor`):
    /// the container is made and left waiting for that process to attach.
    pub no_monitor: bool,
    pub interactive: bool,
    pub tty: bool,
    pub env: Vec<String>,
    pub env_file: Vec<String>,
    /// `--env-host`: the environment of the caller goes to the container
    pub env_host: bool,
    /// `--http-proxy`: its proxy variables go to the container (podman's
    /// default)
    pub http_proxy: bool,
    /// `--retry`, `--retry-delay`: the pull of the image
    pub retry: Option<u32>,
    pub retry_delay: Option<String>,
    pub workdir: Option<String>,
    pub privileged: bool,
    pub read_only: bool,
    pub rm: bool,
    pub rmi: bool,
    pub hostname: Option<String>,
    pub hostuser: Vec<String>,
    pub hosts_file: Option<String>,
    pub chrootdirs: Vec<String>,
    pub rdt_class: Option<String>,
    pub seccomp_policy: Option<String>,
    pub gpus: Vec<String>,
    pub attach: Vec<String>,
    pub decryption_key: Vec<String>,
    pub init_ctr: Option<String>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub dns_option: Vec<String>,
    pub add_host: Vec<String>,
    pub network: Vec<String>,
    pub network_alias: Vec<String>,
    pub ip: Option<String>,
    pub ip6: Option<String>,
    pub publish: Vec<String>,
    pub memory: Option<String>,
    pub memory_reservation: Option<String>,
    pub memory_swap: Option<String>,
    pub cpus: Option<f64>,
    pub cpu_shares: Option<u64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
    pub cpuset_cpus: Option<String>,
    pub cpuset_mems: Option<String>,
    pub pids_limit: Option<i64>,
    pub device: Vec<String>,
    pub device_cgroup_rule: Vec<String>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub security_opt: Vec<String>,
    pub ulimit: Vec<String>,
    pub restart: Option<String>,
    pub init: bool,
    pub init_path: Option<String>,
    pub user: Option<String>,
    pub group_add: Vec<String>,
    pub entrypoint: Option<String>,
    pub label: Vec<String>,
    pub label_file: Vec<String>,
    pub annotation: Vec<String>,
    pub shm_size: Option<String>,
    pub oom_kill_disable: bool,
    pub oom_score_adj: Option<i32>,
    pub stop_signal: Option<String>,
    pub stop_timeout: Option<u32>,
    pub health_cmd: Option<String>,
    pub health_interval: Option<String>,
    pub health_timeout: Option<String>,
    pub health_start_period: Option<String>,
    pub health_retries: Option<u32>,
    pub no_healthcheck: bool,
    pub health_on_failure: Option<String>,
    pub health_startup_cmd: Option<String>,
    pub health_startup_interval: Option<String>,
    pub health_startup_retries: Option<u32>,
    pub health_startup_success: Option<u32>,
    pub health_startup_timeout: Option<String>,
    pub health_log_destination: Option<String>,
    pub health_max_log_count: Option<u32>,
    pub health_max_log_size: Option<u32>,
    pub pid: Option<String>,
    pub ipc: Option<String>,
    pub uts: Option<String>,
    pub cgroupns: Option<String>,
    pub sysctl: Vec<String>,
    pub systemd: Option<String>,
    pub tz: Option<String>,
    pub umask: Option<String>,
    pub blkio_weight: Option<u16>,
    pub blkio_weight_device: Vec<String>,
    pub device_read_bps: Vec<String>,
    pub device_write_bps: Vec<String>,
    pub device_read_iops: Vec<String>,
    pub device_write_iops: Vec<String>,
    pub cidfile: Option<String>,
    pub cgroup_parent: Option<String>,
    pub expose: Vec<String>,
    /// `-P`: every exposed port on a free host port
    pub publish_all: bool,
    pub mac_address: Option<String>,
    pub log_driver: Option<String>,
    pub log_opt: Vec<String>,
    pub timeout: Option<u32>,
    pub sdnotify: Option<String>,
    pub cgroups: Option<String>,
    pub pod: Option<String>,
    pub pod_id_file: Option<std::path::PathBuf>,
    pub replace: bool,
    pub no_hosts: bool,
    pub lazy: bool,
    pub pull: PullPolicy,
    /// `OS/ARCH[/VARIANT]` of `--platform`, `--os`, `--arch`, `--variant`
    /// (or podman's error for them)
    pub platform: Result<Option<String>, String>,
    pub tls_verify: bool,
    pub secret: Vec<String>,
    pub rootfs: bool,
    pub spec: super::SpecArgs,
    pub image: String,
    pub command: Vec<String>,
    /// cgroup v2 settings (KEY=VALUE)
    pub cgroup_conf: Vec<String>,
    /// `create`: the container is made, not started
    pub create_only: bool,
    /// Nothing said of the pull of the image
    pub quiet: bool,
    /// `--kernel-memory` was given (a no-op, with podman's warning)
    pub kernel_memory: bool,
    /// `--authfile`, `--creds`, `--cert-dir` of the pull
    pub access: super::RegistryAccessArgs,
}

/// The unit of a container started by systemd (`PODMAN_SYSTEMD_UNIT` is set
/// by Quadlet units) is recorded in a label, which `auto-update` restarts.
pub fn add_systemd_unit_label(labels: &mut std::collections::HashMap<String, String>) {
    if let Some(unit) = std::env::var("PODMAN_SYSTEMD_UNIT")
        .ok()
        .filter(|u| !u.is_empty())
    {
        labels.entry("PODMAN_SYSTEMD_UNIT".into()).or_insert(unit);
    }
}

pub fn parse_secrets(specs: &[String]) -> anyhow::Result<Vec<velarx_wire::request::SecretRef>> {
    specs
        .iter()
        .map(|s| velarx_wire::request::SecretRef::parse(s).map_err(anyhow::Error::msg))
        .collect()
}

/// `--security-opt` for the daemon, which checks them: a seccomp profile
/// given by path is read here, the path is the client's.
pub fn security_opts(opts: Vec<String>) -> anyhow::Result<Vec<String>> {
    opts.into_iter()
        .map(|o| match o.split_once(['=', ':']) {
            Some(("seccomp", p)) if p != "unconfined" && !p.starts_with('{') => {
                const MAX: u64 = 4 << 20;
                let json = velarx_base::conf::read_config_file(std::path::Path::new(p), MAX)
                    .map_err(|e| anyhow::anyhow!("cannot read the seccomp profile `{p}`: {e}"))?;
                Ok(format!("seccomp={json}"))
            }
            // the daemon reads the filter: the path must not depend on the
            // directory of the client
            Some(("seccomp-bpf", p)) => {
                let abs = std::fs::canonicalize(p)
                    .map_err(|e| anyhow::anyhow!("seccomp-bpf `{p}`: {e}"))?;
                Ok(format!("seccomp-bpf={}", abs.display()))
            }
            _ => Ok(o),
        })
        .collect()
}

/// The memory+swap limit of `--memory MEMORY` and `--memory-swap SWAP`
/// (None: not given), as podman's `LimitToSwap`: a memory limit without
/// `--memory-swap` allows as much swap as memory (twice the limit in all),
/// and `--memory-swap 0` with a memory limit is no swap.  Only the
/// frontends of podman's CLI and libpod API do it: not the CRI, not a build.
pub fn swap_of(memory: Option<i64>, swap: Option<i64>) -> Option<i64> {
    match (memory.filter(|m| *m > 0), swap) {
        (Some(m), None) => Some(m.saturating_mul(2)),
        (Some(_), Some(0)) => Some(0),
        (_, Some(0)) => None,
        (_, s) => s,
    }
}

/// A size in podman's syntax (`RAMInBytes` of go-units, with its words for
/// what it refuses): a number, decimals allowed, then an optional space and
/// unit `b`, `k`, `m`, `g`, `t` or `p` (powers of 1024, any case, with an
/// optional `i` and `b`: `1.5g`, `512 MiB`); `-1` is "no limit" where a flag
/// takes it.
pub fn parse_memory_size(s: &str) -> anyhow::Result<i64> {
    if s.trim() == "-1" {
        return Ok(-1);
    }
    velarx_proto::size::ram_in_bytes(s.trim()).map_err(|e| anyhow::anyhow!("{e}"))
}

/// A `-p` mapping, `[[IP:][HOST[-END]]:]CONTAINER[-END][/PROTO]`, one entry
/// per port; the host port is picked by the daemon when it is omitted.
pub fn parse_port_mapping(s: &str) -> anyhow::Result<Vec<velarx_wire::request::PortMapping>> {
    // (an empty -p publishes nothing, as podman's)
    if s.is_empty() {
        return Ok(Vec::new());
    }
    let p = velarx_wire::addr::PortSpec::parse(s).map_err(|e| anyhow::anyhow!(e))?;
    Ok(p.mappings())
}

/// The `--ulimit` options of a run: `host` is the limits of the host, which
/// the container has without being told; as podman, it overrides the
/// others, wherever it is in the list.
pub fn parse_ulimits(list: &[String]) -> anyhow::Result<Vec<velarx_wire::request::Ulimit>> {
    if list.iter().any(|u| u == "host") {
        return Ok(Vec::new());
    }
    list.iter().map(|u| parse_ulimit(u)).collect()
}

/// Parse ulimit string (e.g., "nofile=1024:2048")
pub fn parse_ulimit(s: &str) -> anyhow::Result<velarx_wire::request::Ulimit> {
    velarx_wire::request::Ulimit::parse(s).map_err(anyhow::Error::msg)
}

/// `-e KEY=VALUE`, or `-e KEY` for the value the caller has (nothing when
/// it has none), or `-e PREFIX*` for those of the caller's variables whose
/// names start with PREFIX (podman's: a `*` only at the end).
fn inherit_env(e: &str) -> Vec<String> {
    if e.contains('=') {
        return vec![e.to_string()];
    }
    if let Some(prefix) = e.strip_suffix('*') {
        let mut vars: Vec<String> = std::env::vars()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        vars.sort();
        return vars;
    }
    std::env::var(e)
        .ok()
        .map(|v| format!("{e}={v}"))
        .into_iter()
        .collect()
}

/// `--blkio-weight-device DEVICE:WEIGHT`.
pub fn parse_weight_device(s: &str) -> anyhow::Result<velarx_wire::request::WeightDevice> {
    let bad = || anyhow::anyhow!("invalid weight device `{s}`: DEVICE:WEIGHT");
    let (path, weight) = s.rsplit_once(':').ok_or_else(bad)?;
    if path.is_empty() {
        return Err(bad());
    }
    Ok(velarx_wire::request::WeightDevice {
        path: path.to_string(),
        weight: weight
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid weight `{weight}` of {path}"))?,
        device: None,
    })
}

/// `--device-read-bps PATH:RATE` and the like (a size, or a number for IOPS).
fn throttles(
    v: &[String],
    iops: bool,
) -> anyhow::Result<Vec<velarx_wire::request::ThrottleDevice>> {
    v.iter()
        .map(|s| {
            let bad = || anyhow::anyhow!("invalid device limit `{s}`");
            let (path, rate) = s.rsplit_once(':').ok_or_else(bad)?;
            let rate = if iops {
                rate.parse().map_err(|_| bad())?
            } else {
                velarx_wire::options::parse_size(rate).ok_or_else(bad)?
            };
            Ok(velarx_wire::request::ThrottleDevice {
                path: path.to_string(),
                rate,
            })
        })
        .collect()
}

/// Parse device mapping string (e.g., "/dev/sda:/dev/sda:rwm", or a CDI
/// device, "vendor.com/class=name")
pub fn parse_device(s: &str) -> velarx_wire::request::DeviceMapping {
    velarx_wire::request::DeviceMapping::parse(s)
}

/// Parse key=value string into tuple
pub fn parse_key_value(s: &str) -> (String, String) {
    if let Some((k, v)) = s.split_once('=') {
        (k.to_string(), v.to_string())
    } else {
        (s.to_string(), String::new())
    }
}

/// Read environment variables from file
pub fn read_env_file(path: &str) -> anyhow::Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

/// `--health-interval` as podman reads it (MakeHealthCheckFromCli): `disable`
/// is "0", and a zero interval is no timer, the checks of `healthcheck run`
/// only.  Returns the interval and whether it is disabled.
fn health_interval(arg: Option<&str>) -> anyhow::Result<(u64, bool)> {
    match arg {
        None => Ok((30_000_000_000, false)),
        Some("disable") => Ok((0, true)),
        Some(i) => parse_duration_ns(i).map(|n| (n, n == 0)),
    }
}

/// `--health-timeout` and `--health-startup-timeout` as podman reads them
/// (MakeHealthCheckFromCli): 30 s when not given, 0 refused.
fn health_timeout(arg: Option<&str>) -> anyhow::Result<u64> {
    match arg.map(parse_duration_ns).transpose()? {
        None => Ok(30_000_000_000),
        Some(0) => anyhow::bail!("healthcheck-timeout must be at least 1 second"),
        Some(n) => Ok(n),
    }
}

/// A duration as a Go duration (`1h30m`, `5s`) or whole seconds, in
/// nanoseconds.
pub fn parse_duration_ns(s: &str) -> anyhow::Result<u64> {
    let s = s.trim().to_lowercase();
    let ns = match s.parse::<u64>() {
        Ok(secs) => secs.checked_mul(1_000_000_000),
        Err(_) => {
            velarx_proto::duration::parse_go_duration_ns(&s).and_then(|n| u64::try_from(n).ok())
        }
    };
    ns.ok_or_else(|| anyhow::anyhow!("invalid duration `{s}`"))
}

/// The variables of the caller's environment `vars` that go to the
/// container: all of them with `--env-host`, else the proxy variables with
/// `--http-proxy`; none that `given` (-e, --env-file) sets.
pub fn host_env(
    all: bool,
    proxy: bool,
    vars: impl Iterator<Item = (String, String)>,
    given: &[String],
) -> Vec<String> {
    const PROXY: [&str; 8] = [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "ftp_proxy",
        "FTP_PROXY",
        "no_proxy",
        "NO_PROXY",
    ];
    let set = |k: &str| {
        given
            .iter()
            .any(|e| e.split_once('=').map_or(e.as_str(), |(n, _)| n) == k)
    };
    vars.filter(|(k, _)| all || (proxy && PROXY.contains(&k.as_str())))
        .filter(|(k, _)| !set(k))
        .map(|(k, v)| format!("{k}={v}"))
        .collect()
}

/// The mode `text` of the option `flag`.
fn mode_of<T: std::str::FromStr<Err = velarx_wire::request::ModeError>>(
    flag: &str,
    text: &str,
) -> anyhow::Result<T> {
    text.parse().map_err(|e| anyhow::anyhow!("{flag}: {e}"))
}

/// The mode of the option `flag`, the default for none.
pub(crate) fn opt_mode<T: Default + std::str::FromStr<Err = velarx_wire::request::ModeError>>(
    flag: &str,
    text: Option<String>,
) -> anyhow::Result<T> {
    text.map_or(Ok(T::default()), |t| mode_of(flag, &t))
}

/// The user namespace of a container: `--userns`, else `$PODMAN_USERNS`
/// (podman's, for a container that is not in a pod).
fn userns_default(flag: Option<String>, in_pod: bool, env: Option<String>) -> Option<String> {
    flag.or_else(|| env.filter(|e| !e.is_empty() && !in_pod))
}

/// `--pod-id-file`: the pod is the first line of the file (podman's
/// `ReadPodIDFile`); an empty first line means no pod, as in podman. Not
/// with `--pod`.
fn pod_from_id_file(
    pod: Option<&str>,
    path: Option<&std::path::Path>,
) -> anyhow::Result<Option<String>> {
    let Some(path) = path else { return Ok(None) };
    if pod.is_some() {
        anyhow::bail!("cannot specify both --pod and --pod-id-file");
    }
    let content =
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading pod ID file: {e}"))?;
    let id = content.split('\n').next().unwrap_or_default();
    Ok((!id.is_empty()).then(|| id.to_string()))
}

/// `container run`: the exit code of the container in the foreground, 0
/// with `--detach`.
pub fn run_container(
    daemon_client: &EngineClient,
    mut args: RunContainerArgs,
) -> anyhow::Result<i32> {
    // podman's options that exclude each other, before anything is done
    for (set, first, second) in [
        (
            args.cpu_period.is_some() && args.cpus.is_some(),
            "--cpu-period",
            "--cpus",
        ),
        (
            args.cpu_quota.is_some() && args.cpus.is_some(),
            "--cpu-quota",
            "--cpus",
        ),
        (
            args.no_hosts && !args.add_host.is_empty(),
            "--no-hosts",
            "--add-host",
        ),
    ] {
        if set {
            anyhow::bail!("{first} and {second} cannot be set together");
        }
    }
    let platform = args.platform.clone().map_err(anyhow::Error::msg)?;
    if !args.rootfs {
        args.image =
            super::transport::image_for_run(daemon_client, &args.image, platform.as_deref())?;
    }
    if args.rmi && !args.rm {
        anyhow::bail!("the --rmi option does not work without --rm");
    }
    // (podman's words, and its test of the option as it was typed: `--rm`
    // allows `on-failure` but not `on-failure:3`)
    let policy = args.restart.as_deref();
    let restarts = !matches!(policy, None | Some("" | "no" | "on-failure"));
    if args.rm && restarts {
        anyhow::bail!(
            r#"the --rm option conflicts with --restart, when the restartPolicy is not "" and "no""#
        );
    }
    if args.kernel_memory {
        eprintln!("The --kernel-memory flag is no longer supported. This flag is a noop.");
    }
    if !args.decryption_key.is_empty() {
        anyhow::bail!("--decryption-key is not supported: velarx pulls no encrypted image");
    }
    let init_ctr = args
        .init_ctr
        .as_deref()
        .map(|kind| velarx_wire::request::init_container_type(kind, args.pod.as_deref()))
        .transpose()
        .map_err(anyhow::Error::msg)?;
    if args.create_only && !args.attach.is_empty() {
        anyhow::bail!("--attach has no effect on create: `velarx start --attach` attaches");
    }
    // (a relative base hosts file is the caller's, as podman opens it)
    if let Some(f) = args.hosts_file.take() {
        args.hosts_file = Some(match f.as_str() {
            "" | "none" | "image" => f,
            _ if f.starts_with('/') => f,
            _ => std::env::current_dir()?.join(&f).display().to_string(),
        });
    }
    // podman checks the stop signal as kill checks its signal
    if let Some(s) = args.stop_signal.take() {
        args.stop_signal = Some(check_signal(&s)?);
    }
    let secrets = parse_secrets(&args.secret)?;
    let mut cidfile = args
        .cidfile
        .as_deref()
        .map(client::policy::CidFile::create_at)
        .transpose()?;
    let retry = client::policy::retry_of(args.retry, args.retry_delay.as_deref())
        .map_err(anyhow::Error::msg)?;
    // the pulls, the first and the one after an "image not found", with
    // --authfile, --creds and --cert-dir
    let access =
        super::commands::commands_registry_access(daemon_client, &args.access, &args.image, false)?;
    // the progress bars of a pull on a terminal, its warnings
    let shown: Option<Box<client::policy::ShowPull>> =
        Some(Box::new(super::commands::pull_showing_progress));
    // `--pull=missing` (the default): the image is asked for by the create,
    // and pulled only when the server does not have it (a round trip less)
    let pull_when_missing =
        !args.rootfs && args.pull == crate::cli::PullPolicy::Missing && platform.is_none();
    let ask = client::policy::EnsureImage {
        image: &args.image,
        policy: args.pull,
        pull: client::PullOptions {
            tls_verify: args.tls_verify,
            platform: platform.as_deref(),
            access: &access,
            retry,
            sources: None,
        },
        quiet: args.quiet,
        show: shown.as_deref(),
        lazy: args.lazy,
    };
    if !args.rootfs && !pull_when_missing {
        client::policy::ensure_image_with(daemon_client, &ask)?;
    }
    let image_missing = |e: &client::ClientError| pull_when_missing && e.is(Condition::NoSuchImage);
    let pull = || client::policy::ensure_image_with(daemon_client, &ask);

    // the caller's (--env-host), its proxy variables (--http-proxy), then -e
    // and --env-file over them; `-e KEY` takes the caller's value
    let mut given = Vec::new();
    for e in &args.env {
        given.extend(inherit_env(e));
    }
    for env_file in &args.env_file {
        given.extend(read_env_file(env_file)?.iter().flat_map(|e| inherit_env(e)));
    }
    let mut env = host_env(args.env_host, args.http_proxy, std::env::vars(), &given);
    env.extend(given);
    let sdnotify = args.sdnotify.clone().unwrap_or_else(|| {
        // The engine took it from its environment already.
        match std::env::var_os("NOTIFY_SOCKET").or_else(velarx_wire::sdnotify::notify_socket) {
            Some(s) if !s.is_empty() => "container".to_string(),
            _ => String::new(),
        }
    });
    add_watchdog_env(&mut env, &sdnotify, velarx_wire::sdnotify::watchdog_usec());

    let mut labels = std::collections::HashMap::new();
    for l in &args.label {
        let (k, v) = parse_key_value(l);
        labels.insert(k, v);
    }
    for label_file in &args.label_file {
        let content = std::fs::read_to_string(label_file)?;
        for line in content.lines() {
            if !line.is_empty() && !line.starts_with('#') {
                let (k, v) = parse_key_value(line);
                labels.insert(k, v);
            }
        }
    }

    add_systemd_unit_label(&mut labels);

    let mut annotations = std::collections::HashMap::new();
    for a in &args.annotation {
        let (k, v) = parse_key_value(a);
        annotations.insert(k, v);
    }
    if let Some(kind) = init_ctr {
        annotations.insert(
            velarx_wire::request::INIT_TYPE_ANNOTATION.to_string(),
            kind.to_string(),
        );
    }

    let mut sysctls = std::collections::HashMap::new();
    for s in &args.sysctl {
        let (k, v) = parse_key_value(s);
        sysctls.insert(k, v);
    }

    let mut ports = Vec::new();
    for p in &args.publish {
        ports.extend(parse_port_mapping(p)?);
    }
    let network_mode = args
        .network
        .first()
        .map_or(NetworkMode::Unset, |n| NetworkMode::parse(n));
    // as podman: the network modes without ports of their own drop them,
    // and say so
    if !ports.is_empty() {
        if let Some(mode) = network_mode.without_ports() {
            eprintln!(
                "Port mappings have been discarded because \"{mode}\" network namespace mode does not support them"
            );
            ports.clear();
        }
    }

    let ulimits = parse_ulimits(&args.ulimit)?;

    let devices: Vec<_> = args
        .device
        .iter()
        .cloned()
        .chain(args.gpus.iter().map(|g| format!("nvidia.com/gpu={g}")))
        .map(|d| parse_device(&d))
        .collect();

    let security_opts = security_opts(args.security_opt)?;

    // (a limit of 0 is none, as podman's)
    let sized = |v: &Option<String>| -> anyhow::Result<Option<i64>> {
        Ok(match v {
            Some(m) => Some(
                parse_memory_size(m)
                    .map_err(|e| anyhow::anyhow!("invalid value for memory: {e}"))?,
            )
            .filter(|n| *n != 0),
            None => None,
        })
    };
    let resources = if sized(&args.memory)?.is_some()
        || args.cpu_quota.is_some_and(|n| n != 0)
        || args.cpu_shares.is_some_and(|n| n != 0)
        || args.cpus.is_some()
        || args.cpu_period.is_some_and(|n| n != 0)
        || args.cpuset_cpus.is_some()
        || args.cpuset_mems.is_some()
        || sized(&args.memory_swap)?.is_some()
        || sized(&args.memory_reservation)?.is_some()
        || args.blkio_weight.is_some()
        || !args.blkio_weight_device.is_empty()
        || !args.device_read_bps.is_empty()
        || !args.device_write_bps.is_empty()
        || !args.device_read_iops.is_empty()
        || !args.device_write_iops.is_empty()
        || !args.cgroup_conf.is_empty()
    {
        let mut res = velarx_wire::request::ResourceLimits {
            memory: sized(&args.memory)?,
            memory_swap: swap_of(
                sized(&args.memory)?,
                args.memory_swap
                    .as_deref()
                    .map(parse_memory_size)
                    .transpose()?,
            ),
            memory_reservation: sized(&args.memory_reservation)?,
            cpu_quota: args.cpu_quota.filter(|n| *n != 0),
            cpu_shares: args.cpu_shares.filter(|n| *n != 0),
            cpu_period: args.cpu_period.filter(|n| *n != 0),
            cpuset_cpus: args.cpuset_cpus.clone(),
            cpuset_mems: args.cpuset_mems.clone(),
            blkio_weight: args.blkio_weight,
            ..Default::default()
        };
        for d in &args.blkio_weight_device {
            res.blkio_weight_device.push(parse_weight_device(d)?);
        }
        res.blkio_device_read_bps = throttles(&args.device_read_bps, false)?;
        res.blkio_device_write_bps = throttles(&args.device_write_bps, false)?;
        res.blkio_device_read_iops = throttles(&args.device_read_iops, true)?;
        res.blkio_device_write_iops = throttles(&args.device_write_iops, true)?;
        if !args.cgroup_conf.is_empty() {
            let mut conf = std::collections::HashMap::new();
            for c in &args.cgroup_conf {
                let (k, v) = c
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("invalid --cgroup-conf `{c}`: KEY=VALUE"))?;
                conf.insert(k.to_string(), v.to_string());
            }
            res.cgroup_conf = Some(conf.into_iter().collect());
        }
        if let Some(cpus) = args.cpus {
            let period = res.cpu_period.unwrap_or(100_000);
            res.cpu_period = Some(period);
            res.cpu_quota = Some((cpus * period as f64) as i64);
        }
        Some(res)
    } else {
        None
    };

    let on_failure = |a: Option<&str>| -> anyhow::Result<OnFailure> {
        a.map_or(Ok(OnFailure::None), |a| {
            OnFailure::parse(a).ok_or_else(|| anyhow::anyhow!("invalid on-failure action: {a}"))
        })
    };
    let healthcheck = if let Some(ref cmd) = args.health_cmd {
        let (interval, interval_disabled) = health_interval(args.health_interval.as_deref())?;
        let timeout = health_timeout(args.health_timeout.as_deref())?;
        let start_period = if let Some(ref sp) = args.health_start_period {
            parse_duration_ns(sp)?
        } else {
            0
        };
        let startup = match &args.health_startup_cmd {
            Some(cmd) => Some(StartupHealthcheck {
                test: vec!["CMD-SHELL".to_string(), cmd.clone()],
                interval_ns: args
                    .health_startup_interval
                    .as_deref()
                    .map(parse_duration_ns)
                    .transpose()?
                    .unwrap_or(30_000_000_000),
                timeout_ns: health_timeout(args.health_startup_timeout.as_deref())?,
                retries: args.health_startup_retries.unwrap_or(0),
                successes: args.health_startup_success.unwrap_or(0),
            }),
            None => None,
        };
        Some(Healthcheck {
            test: vec!["CMD-SHELL".to_string(), cmd.clone()],
            interval_ns: interval,
            interval_disabled,
            timeout_ns: timeout,
            start_period_ns: start_period,
            start_interval_ns: 0,
            retries: match args.health_retries.unwrap_or(3) {
                0 => anyhow::bail!("healthcheck-retries must be greater than 0"),
                n => n,
            },
            on_failure: on_failure(args.health_on_failure.as_deref())?,
            startup,
            // a directory of the command's, made absolute for the daemon
            log_destination: match args.health_log_destination.as_deref() {
                None => String::new(),
                Some(d @ ("local" | "events_logger")) => d.to_string(),
                Some(d) => std::path::absolute(d)?.to_string_lossy().into_owned(),
            },
            max_log_count: args.health_max_log_count,
            max_log_size: args.health_max_log_size,
        })
    } else {
        let startup_only = args.health_startup_cmd.is_some()
            || args.health_log_destination.is_some()
            || args.health_max_log_count.is_some()
            || args.health_max_log_size.is_some();
        if startup_only {
            anyhow::bail!(
                "--health-startup-* and --health-log-*/--health-max-log-* need a health check (--health-cmd)"
            );
        }
        // (the HEALTHCHECK of the image, when it has one, takes the action)
        match on_failure(args.health_on_failure.as_deref())? {
            OnFailure::None => None,
            action => Some(Healthcheck {
                on_failure: action,
                ..Default::default()
            }),
        }
    };

    let restart_policy = args
        .restart
        .as_deref()
        .map(parse_restart_policy)
        .transpose()?;

    let log_config = (args.log_driver.is_some() || !args.log_opt.is_empty()).then(|| {
        let mut config = std::collections::HashMap::new();
        for opt in &args.log_opt {
            let (k, v) = parse_key_value(opt);
            config.insert(k, v);
        }
        velarx_wire::request::LogConfig {
            driver: args.log_driver.clone().unwrap_or_default(),
            config: config.into_iter().collect(),
        }
    });

    let shm_size = if let Some(ref s) = args.shm_size {
        Some(parse_memory_size(s)? as u64)
    } else {
        None
    };

    let (pidfile, conmon_pidfile) = args.spec.pidfiles.absolute()?;
    // the volumes of --volumes-from first: a mount of the command at the
    // same destination replaces one
    let volumes = {
        let mut v = volumes_from(
            daemon_client,
            &args.storage.volumes_from,
            &taken_destinations(
                &args.storage.volume,
                &args.storage.tmpfs,
                &args.storage.mount,
            ),
        )?;
        v.extend(absolute_volumes(&args.storage.volume)?);
        v
    };
    let from_file = pod_from_id_file(args.pod.as_deref(), args.pod_id_file.as_deref())?;
    // `--pod new:NAME`: the pod is made for the container, as podman's
    let new_pod = args
        .pod
        .as_deref()
        .and_then(|p| p.strip_prefix("new:"))
        .map(str::to_string);
    let pod = match &new_pod {
        Some(name) => {
            if name.is_empty() {
                anyhow::bail!("--pod new: needs the name of the pod");
            }
            let mut spec =
                velarx_proto::podgen::spec_of(velarx_proto::podgen::Generator::named(name))
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            // (the container shares the UTS namespace of the pod: the name
            // it was given is the pod's)
            spec.hostname = args.hostname.take();
            daemon_client.create_pod(&spec)?;
            Some(name.to_string())
        }
        None => args.pod.clone().or(from_file),
    };
    // a pod made for the container goes when the container is not made
    let forget_pod = || {
        if let Some(name) = &new_pod {
            let _ = daemon_client.remove_pod(name, true, None);
        }
    };
    let shm_size_systemd = match args.spec.shm_size_systemd {
        Some(ref s) => Some(parse_memory_size(s)? as u64),
        None => None,
    };

    let req = client::CreateContainerRequest {
        create_command: std::env::args().collect(),
        name: args.name,
        image: if args.rootfs {
            absolute_rootfs(&args.image)
        } else {
            args.image.clone()
        },
        command: args.command.clone(),
        entrypoint: match args.entrypoint {
            // a JSON array, as podman takes it
            Some(e) if e.starts_with('[') => serde_json::from_str(&e)
                .map_err(|err| anyhow::anyhow!("invalid --entrypoint `{e}`: {err}"))?,
            Some(e) => vec![e],
            None => Vec::new(),
        },
        working_dir: args.workdir.unwrap_or_default(),
        env,
        labels: labels.into_iter().collect(),
        annotations: annotations.into_iter().collect(),
        hostname: args.hostname.unwrap_or_default(),
        host_users: args.hostuser,
        hosts_file: args.hosts_file,
        chroot_dirs: args.chrootdirs,
        rdt_class: args.rdt_class,
        seccomp_policy: args.seccomp_policy,
        user: args.user.unwrap_or_default(),
        group_add: args.group_add,
        passwd_entry: args.spec.passwd_entry,
        group_entry: args.spec.group_entry,
        no_passwd: !args.spec.passwd,
        unsetenv: args.spec.unsetenv,
        unsetenv_all: args.spec.unsetenv_all,
        env_merge: args.spec.env_merge,
        personality: args.spec.personality,
        rootfs_propagation: args.spec.rootfs_propagation,
        no_read_only_tmpfs: !args.spec.read_only_tmpfs,
        no_hostname: args.spec.no_hostname,
        no_healthcheck: args.no_healthcheck,
        requires: args.spec.requires,
        shm_size_systemd,
        pidfile,
        conmon_pidfile,
        tmpfs: args.storage.tmpfs,
        volumes,
        mount: args.storage.mount,
        image_volume: args.storage.image_volume.unwrap_or_default(),
        tty: args.tty,
        stdin_open: args.interactive,
        privileged: args.privileged,
        read_only_rootfs: args.read_only,
        cap_add: args.cap_add,
        cap_drop: args.cap_drop,
        userns_mode: userns_default(
            args.storage.userns,
            pod.is_some(),
            std::env::var("PODMAN_USERNS").ok(),
        )
        .map(|u| mode_of::<UsernsChoice>("--userns", &u))
        .transpose()?
        .unwrap_or_default(),
        uid_mappings: Vec::new(),
        gid_mappings: Vec::new(),
        uidmap: args.storage.uidmap,
        gidmap: args.storage.gidmap,
        subuidname: args.storage.subuidname,
        subgidname: args.storage.subgidname,
        network_mode,
        networks: args.network,
        network_aliases: args.network_alias,
        cni_annotations: Default::default(),
        cni_ip_ranges: Vec::new(),
        dns: args.dns,
        dns_search: args.dns_search,
        dns_options: args.dns_option,
        add_hosts: args.add_host,
        ports,
        expose: args.expose,
        publish_all: args.publish_all,
        ip_address: args.ip,
        ip6_address: args.ip6,
        mac_address: args.mac_address,
        stop_signal: args.stop_signal.unwrap_or_default(),
        stop_timeout: args.stop_timeout,
        oom_score_adj: args.oom_score_adj,
        oom_kill_disable: args.oom_kill_disable,
        pids_limit: args.pids_limit,
        shm_size,
        sysctls: sysctls.into_iter().collect(),
        ulimits,
        devices,
        device_cgroup_rules: args.device_cgroup_rule,
        init: args.init,
        init_path: args.init_path,
        pid_mode: opt_mode("--pid", args.pid)?,
        ipc_mode: opt_mode("--ipc", args.ipc)?,
        uts_mode: opt_mode("--uts", args.uts)?,
        cgroupns_mode: opt_mode("--cgroupns", args.cgroupns)?,
        cgroup_parent: args.cgroup_parent,
        timezone: args.tz,
        umask: args.umask,
        auto_remove: args.rm,
        auto_remove_image: args.rmi,
        timeout: args.timeout,
        systemd: args.systemd,
        cidfile: args
            .cidfile
            .as_deref()
            .map(|f| std::path::absolute(f).map(|p| p.to_string_lossy().into_owned()))
            .transpose()?,
        pod,
        replace: args.replace,
        no_hosts: args.no_hosts,
        resources,
        healthcheck,
        restart_policy,
        security_opts,
        log_config,
        lazy: args.lazy,
        secrets,
        rootfs: args.rootfs,
        // Under a service manager the container notifies it, as with podman.
        sdnotify,
        cgroups: opt_mode("--cgroups", args.cgroups.clone())?,
        no_monitor: args.no_monitor,
        // podman's global --runtime: the container keeps it, as it was given
        // (the later commands of the container use it)
        runtime: std::env::var(velarx_config::ENV_RUNTIME)
            .ok()
            .filter(|r| !r.is_empty()),
        ..Default::default()
    };

    let create = || {
        let made = match daemon_client.create_container(&req) {
            Err(e) if image_missing(&e) => {
                pull()?;
                daemon_client.create_container(&req)
            }
            r => r,
        };
        if made.is_err() {
            forget_pod();
        }
        made
    };
    if args.create_only {
        let result = create()?;
        if let Some(f) = cidfile.as_mut() {
            f.write(&result.id)?;
        }
        println!("{}", result.id);
        return Ok(0);
    }

    if args.detach {
        // (podman finds no user or group of the container when it starts it)
        let result = create().map_err(|e| {
            if e.is(Condition::NotStarted) {
                anyhow::Error::from(not_started(&e))
            } else {
                e.into()
            }
        })?;
        let id = result.id.clone();
        if let Some(f) = cidfile.as_mut() {
            f.write(&id)?;
        }
        if let Err(e) =
            daemon_client.start_container(&id, client::Verify::Run(&req.typed_digests()))
        {
            if args.rm {
                let _ = daemon_client.remove_container_podman(
                    &id,
                    &client::RemoveContainer {
                        force: true,
                        ..Default::default()
                    },
                );
            }
            return Err(not_started(&e).into());
        }
        println!("{}", id);
        return Ok(0);
    }

    // Foreground: the monitor starts the container once this client is
    // attached, so that no output is missed.
    let started = match daemon_client.create_and_run_container(&req) {
        Err(e) if image_missing(&e) => {
            pull()?;
            daemon_client.create_and_run_container(&req)
        }
        r => r,
    }
    .map_err(|e| {
        // the runtime could not start it; any other error is of the
        // creation
        if is_not_started(&e) {
            anyhow::Error::from(not_started(&e))
        } else {
            forget_pod();
            anyhow::Error::from(e)
        }
    })?;
    if let Some(f) = cidfile.as_mut() {
        f.write(&started.id)?;
    }
    if args.no_monitor {
        // The process that monitors it attaches (`monitor::inproc`).
        return Ok(0);
    }
    // (attached to the standard input alone, there is no output of the
    // container to see: the command says which one it is, as podman's)
    if !args.attach.is_empty() && !args.attach.iter().any(|a| a == "stdout" || a == "stderr") {
        println!("{}", started.id);
    }
    let code = attach_session(
        daemon_client,
        &started.id,
        AttachRequest {
            tty: args.tty,
            stdin: args.interactive,
            stdout: args.attach.is_empty() || args.attach.iter().any(|a| a == "stdout"),
            stderr: args.attach.is_empty() || args.attach.iter().any(|a| a == "stderr"),
            detach_keys: args.detach_keys.clone(),
            sig_proxy: args.sig_proxy,
            start: true,
        },
    )?;
    if args.rmi {
        // as podman's run: once the container is gone, the image by the
        // name of the command (another name of it is untagged only)
        let _ = daemon_client.wait_condition(
            &started.id,
            &[velarx_proto::wait::WaitCondition::Removed],
            0,
        );
        if let Err(e) = daemon_client.remove_image(&args.image, false) {
            if e.is_conflict() {
                eprintln!("Warning: image is in use by a container: it is not removed");
            } else if !e.is_not_found() {
                // (the engine removed it already otherwise)
                eprintln!("Warning: {e}");
            }
        }
    }
    Ok(code)
}

/// `--restart POLICY[:RETRIES]` as podman's `ParseRestartPolicy` and
/// `ValidateRestartPolicy` take it: `never` is `no`, retries only with
/// `on-failure`, and a policy that podman does not have is an error.
pub(crate) fn parse_restart_policy(
    policy: &str,
) -> anyhow::Result<velarx_wire::request::RestartPolicy> {
    let parts: Vec<&str> = policy.split(':').collect();
    let (name, retries) = match parts[..] {
        [name] => (
            if name.eq_ignore_ascii_case("never") {
                "no"
            } else {
                name
            },
            0,
        ),
        [name, count] => {
            if !name.eq_ignore_ascii_case("on-failure") {
                anyhow::bail!(
                    "restart policy retries can only be specified with on-failure restart policy"
                );
            }
            // (Go's words for a number that does not parse)
            let n: i64 = count.parse().map_err(|_| {
                anyhow::anyhow!(
                    "parsing restart policy retry count: strconv.Atoi: parsing {count:?}: invalid syntax"
                )
            })?;
            if n < 0 {
                anyhow::bail!("must specify restart policy retry count as a number greater than 0");
            }
            (name, u32::try_from(n).unwrap_or(u32::MAX))
        }
        _ => anyhow::bail!("invalid restart policy: may specify retries at most once"),
    };
    if !matches!(
        name,
        "none" | "no" | "on-failure" | "always" | "unless-stopped"
    ) {
        anyhow::bail!("\"{name}\" is not a valid restart policy: invalid argument");
    }
    Ok(velarx_wire::request::RestartPolicy {
        name: name.to_string(),
        maximum_retry_count: retries,
    })
}

/// The destinations of the mounts of the command (`-v`, `--tmpfs`,
/// `--mount`): those of `--volumes-from` give way to them.
fn taken_destinations(
    volumes: &[String],
    tmpfs: &[String],
    mounts: &[String],
) -> std::collections::HashSet<String> {
    let clean = |d: &str| format!("/{}", d.trim_matches('/'));
    let mut out = std::collections::HashSet::new();
    for v in volumes {
        let mut parts = v.split(':');
        let first = parts.next().unwrap_or_default();
        out.insert(clean(parts.next().unwrap_or(first)));
    }
    for t in tmpfs {
        out.insert(clean(t.split(':').next().unwrap_or_default()));
    }
    for m in mounts {
        for kv in m.split(',') {
            if let Some((k, v)) = kv.split_once('=') {
                if matches!(k, "target" | "dst" | "destination") {
                    out.insert(clean(v));
                }
            }
        }
    }
    out
}

/// `--volumes-from CONTAINER[:OPTIONS]`: the volumes and bind mounts of
/// the containers as `-v` values (a later container replaces an earlier
/// one), but those at the destinations `taken` by the command.
pub fn volumes_from(
    client: &EngineClient,
    list: &[String],
    taken: &std::collections::HashSet<String>,
) -> anyhow::Result<Vec<String>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for entry in list {
        let (name, options) = entry.split_once(':').unwrap_or((entry, ""));
        let info = client.inspect_container(name).map_err(|e| {
                if e.is_not_found() {
                    anyhow::anyhow!(
                        "looking up container \"{name}\" for volumes-from: no container with name or ID \"{name}\" found: no such container"
                    )
                } else {
                    anyhow::anyhow!("{e}")
                }
            })?;
        for (dest, arg) in velarx_wire::request::volumes_from_args(&info.mounts, options)
            .map_err(anyhow::Error::msg)?
        {
            if taken.contains(&dest) {
                continue;
            }
            out.retain(|(d, _)| *d != dest);
            out.push((dest, arg));
        }
    }
    Ok(out.into_iter().map(|(_, a)| a).collect())
}

/// `-v` values with relative host paths made absolute: the daemon does not
/// know the directory of the command.
pub fn absolute_volumes(volumes: &[String]) -> anyhow::Result<Vec<String>> {
    volumes
        .iter()
        .map(|v| {
            let (source, rest) = match v.split_once(':') {
                Some((s, r)) => (s, Some(r)),
                None => (v.as_str(), None),
            };
            if rest.is_none() || !(source.starts_with('.') || source.starts_with('~')) {
                return Ok(v.clone());
            }
            let path = if let Some(home) = source.strip_prefix('~') {
                let h = std::env::var_os("HOME")
                    .ok_or_else(|| anyhow::anyhow!("HOME is not set, cannot expand `{source}`"))?;
                std::path::Path::new(&h).join(home.trim_start_matches('/'))
            } else {
                std::env::current_dir()?.join(source)
            };
            let path = path.canonicalize().unwrap_or(path);
            Ok(format!("{}:{}", path.display(), rest.unwrap_or_default()))
        })
        .collect()
}

impl RunContainerArgs {
    /// The arguments of `container run`; any other command is given back.
    pub fn from_command(cmd: ContainerCommands) -> Result<Self, Box<ContainerCommands>> {
        match cmd {
            ContainerCommands::Run {
                create,
                detach,
                no_monitor,
                detach_keys,
                sig_proxy,
                ..
            } => Ok(Self::from_args(
                *create,
                detach,
                no_monitor,
                detach_keys,
                sig_proxy,
                false,
            )),
            ContainerCommands::Create { create, .. } => {
                Ok(Self::from_args(*create, false, false, None, true, true))
            }
            other => Err(Box::new(other)),
        }
    }

    fn from_args(
        create: super::CreateArgs,
        detach: bool,
        no_monitor: bool,
        detach_keys: Option<String>,
        sig_proxy: bool,
        create_only: bool,
    ) -> Self {
        let super::CreateArgs {
            name,
            storage,
            interactive,
            tty,
            env,
            env_file,
            env_host,
            http_proxy,
            retry,
            retry_delay,
            workdir,
            privileged,
            read_only,
            rm,
            rmi,
            hostname,
            hostuser,
            hosts_file,
            chrootdirs,
            rdt_class,
            seccomp_policy,
            gpus,
            attach,
            decryption_key,
            init_ctr,
            dns,
            dns_search,
            dns_option,
            add_host,
            network,
            network_alias,
            ip,
            ip6,
            publish,
            publish_all,
            memory,
            memory_reservation,
            memory_swap,
            cpus,
            cpu_shares,
            cpu_quota,
            cpu_period,
            cpuset_cpus,
            cpuset_mems,
            pids_limit,
            device,
            device_cgroup_rule,
            cap_add,
            cap_drop,
            security_opt,
            ulimit,
            restart,
            init,
            init_path,
            user,
            group_add,
            entrypoint,
            label,
            label_file,
            annotation,
            shm_size,
            oom_kill_disable,
            oom_score_adj,
            stop_signal,
            stop_timeout,
            health_cmd,
            health_interval,
            health_timeout,
            health_start_period,
            health_retries,
            health_on_failure,
            health_startup_cmd,
            health_startup_interval,
            health_startup_retries,
            health_startup_success,
            health_startup_timeout,
            health_log_destination,
            health_max_log_count,
            health_max_log_size,
            no_healthcheck,
            spec,
            pid,
            ipc,
            uts,
            cgroupns,
            sysctl,
            systemd,
            tz,
            umask,
            blkio_weight,
            blkio_weight_device,
            device_read_bps,
            device_write_bps,
            device_read_iops,
            device_write_iops,
            cidfile,
            cgroup_parent,
            expose,
            mac_address,
            log_driver,
            log_opt,
            timeout,
            sdnotify,
            cgroups,
            pod,
            pod_id_file,
            replace,
            no_hosts,
            lazy,
            pull,
            platform,
            os,
            arch,
            variant,
            tls_verify,
            secret,
            rootfs,
            image,
            command,
            cgroup_conf,
            quiet,
            kernel_memory,
            disable_content_trust: _,
            access,
        } = create;
        RunContainerArgs {
            name,
            storage,
            detach_keys,
            sig_proxy,
            detach,
            no_monitor,
            interactive,
            tty,
            env,
            env_file,
            env_host,
            http_proxy,
            retry,
            retry_delay,
            workdir,
            privileged,
            read_only,
            // (--rmi implies --rm; --rm=false with it is refused at the run)
            rm: rm.unwrap_or(rmi),
            rmi,
            hostname,
            hostuser,
            hosts_file,
            chrootdirs,
            rdt_class,
            seccomp_policy,
            gpus,
            attach,
            decryption_key,
            init_ctr,
            dns,
            dns_search,
            dns_option,
            add_host,
            network,
            network_alias,
            ip,
            ip6,
            publish,
            memory,
            memory_reservation,
            memory_swap,
            cpus,
            cpu_shares,
            cpu_quota,
            cpu_period,
            cpuset_cpus,
            cpuset_mems,
            pids_limit,
            device,
            device_cgroup_rule,
            cap_add,
            cap_drop,
            security_opt,
            ulimit,
            restart,
            init,
            init_path,
            user,
            group_add,
            entrypoint,
            label,
            label_file,
            annotation,
            shm_size,
            oom_kill_disable,
            oom_score_adj,
            stop_signal,
            stop_timeout,
            health_cmd,
            health_interval,
            health_timeout,
            health_start_period,
            health_retries,
            health_on_failure,
            health_startup_cmd,
            health_startup_interval,
            health_startup_retries,
            health_startup_success,
            health_startup_timeout,
            health_log_destination,
            health_max_log_count,
            health_max_log_size,
            no_healthcheck,
            pid,
            ipc,
            uts,
            cgroupns,
            sysctl,
            systemd,
            tz,
            umask,
            blkio_weight,
            blkio_weight_device,
            device_read_bps,
            device_write_bps,
            device_read_iops,
            device_write_iops,
            cidfile,
            cgroup_parent,
            expose,
            publish_all,
            mac_address,
            log_driver,
            log_opt,
            timeout,
            sdnotify,
            cgroups,
            pod,
            pod_id_file,
            replace,
            no_hosts,
            lazy,
            pull,
            platform: super::platform_of(platform, os, arch, variant),
            tls_verify,
            secret,
            rootfs,
            spec,
            image,
            command,
            cgroup_conf,
            create_only,
            quiet,
            kernel_memory: kernel_memory.is_some(),
            access,
        }
    }
}

/// The containers of a command that takes `--latest` (podman's `-l`): those
/// named, or the container made last, not both.
pub fn named_or_latest(
    client: &EngineClient,
    latest: bool,
    named: Vec<String>,
) -> anyhow::Result<Vec<String>> {
    named_or_latest_of(client, client::Kind::Container, latest, named)
}

/// `named_or_latest` of the objects of `kind` (containers or pods).
pub fn named_or_latest_of(
    client: &EngineClient,
    kind: client::Kind,
    latest: bool,
    named: Vec<String>,
) -> anyhow::Result<Vec<String>> {
    if !latest {
        return Ok(named);
    }
    let what = if kind == client::Kind::Pod {
        "pods"
    } else {
        "containers"
    };
    if !named.is_empty() {
        anyhow::bail!("--latest and {what} cannot be used together");
    }
    let list = client.podman_list(kind, true, &[])?;
    let newest = list
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| Some((super::report::created_ns(&c["Created"]), c["Id"].as_str()?)))
        .max_by_key(|(created, _)| *created);
    match newest {
        Some((_, id)) => Ok(vec![id.to_string()]),
        None if kind == client::Kind::Pod => anyhow::bail!("no such pod"),
        None => anyhow::bail!("no such container"),
    }
}

/// How a pod command chose its pods.
#[derive(Debug, PartialEq)]
enum PodSelection {
    Named,
    IdFiles,
    All,
    Latest,
}

/// podman's `CheckAllLatestAndIDFile`: the pods are named, or exactly one of
/// `--all`, `--latest` and the pod ID files says which they are.
fn pod_selection(
    named: bool,
    targets: &super::PodTargets,
    id_files: bool,
) -> anyhow::Result<PodSelection> {
    let (all, latest) = (targets.all, targets.latest);
    if id_files && (all || latest) {
        anyhow::bail!("--all, --latest, and --pod-id-file cannot be used together");
    }
    if all && latest {
        anyhow::bail!("--all and --latest cannot be used together");
    }
    if all && named {
        anyhow::bail!("no arguments are needed with --all");
    }
    if named && latest {
        anyhow::bail!("--latest and containers cannot be used together");
    }
    if named && id_files {
        anyhow::bail!("no arguments are needed with --latest or --pod-id-file");
    }
    Ok(if named {
        PodSelection::Named
    } else if id_files {
        PodSelection::IdFiles
    } else if all {
        PodSelection::All
    } else if latest {
        PodSelection::Latest
    } else {
        anyhow::bail!("you must provide at least one name or id");
    })
}

/// Which pods a pod command acts on: those named, or exactly one of `--all`
/// (an empty list selects nothing), `--latest` and the pod ID files (the
/// first line of each).
pub fn select_pods(
    client: &EngineClient,
    named: Vec<String>,
    targets: &super::PodTargets,
    id_files: &[String],
) -> anyhow::Result<Vec<String>> {
    match pod_selection(!named.is_empty(), targets, !id_files.is_empty())? {
        PodSelection::Named => Ok(named),
        PodSelection::IdFiles => pod_id_files(id_files),
        PodSelection::All => {
            let list = client.podman_list(client::Kind::Pod, true, &[])?;
            Ok(list
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|p| p["Id"].as_str().map(str::to_string))
                .collect())
        }
        PodSelection::Latest => named_or_latest_of(client, client::Kind::Pod, true, named),
    }
}

/// The pod IDs in the first lines of the files.
pub fn pod_id_files(files: &[String]) -> anyhow::Result<Vec<String>> {
    files
        .iter()
        .map(|f| match std::fs::read_to_string(f) {
            Ok(text) => Ok(text.lines().next().unwrap_or_default().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                anyhow::bail!("reading pod ID file: open {f}: no such file or directory")
            }
            Err(e) => anyhow::bail!("reading pod ID file: open {f}: {e}"),
        })
        .collect()
}

/// Which containers a lifecycle command acts on: those named, or
/// those of exactly one of `all` (with `state`: only those in one of these
/// states), `--latest`, `--cidfile` and `--filter`.  `ignore`: a cidfile
/// that is not there selects nothing.
pub fn select(
    client: &EngineClient,
    named: Vec<String>,
    all: bool,
    targets: &super::Targets,
    ignore: bool,
    state: &[&str],
) -> anyhow::Result<Vec<String>> {
    let filtered = !targets.filter.is_empty();
    let modes = [
        !named.is_empty(),
        all || filtered,
        targets.latest,
        !targets.cidfile.is_empty(),
    ];
    if modes.iter().filter(|m| **m).count() > 1 {
        anyhow::bail!("give the containers, or one of --all (--filter), --latest and --cidfile");
    }
    if !named.is_empty() {
        return Ok(named);
    }
    if !targets.cidfile.is_empty() {
        let mut ids = Vec::new();
        for f in &targets.cidfile {
            match std::fs::read_to_string(f) {
                Ok(id) if !id.trim().is_empty() => ids.push(id.trim().to_string()),
                Ok(_) => anyhow::bail!("{f}: no container ID in the file"),
                Err(e) if ignore && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    anyhow::bail!("reading CIDFile: open {f}: no such file or directory")
                }
                Err(e) => anyhow::bail!("reading CIDFile: open {f}: {e}"),
            }
        }
        return Ok(ids);
    }
    if !(all || filtered || targets.latest) {
        anyhow::bail!("you must provide at least one name or id");
    }
    let list = client.podman_list(client::Kind::Container, true, &targets.filter)?;
    let mut found: Vec<(i64, String, String)> = list
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| state.is_empty() || c["State"].as_str().is_some_and(|s| state.contains(&s)))
        .filter_map(|c| {
            let id = c["Id"].as_str()?.to_string();
            let name = c["Names"][0].as_str().unwrap_or(&id).to_string();
            Some((super::report::created_ns(&c["Created"]), id, name))
        })
        .collect();
    if targets.latest {
        found.sort_by_key(|(created, _, _)| *created);
        return match found.pop() {
            Some((_, id, _)) => Ok(vec![id]),
            None => anyhow::bail!("no containers to act on with --latest"),
        };
    }
    // (by ID, as podman prints them)
    Ok(found.into_iter().map(|(_, id, _)| id).collect())
}

/// `cmd` with the containers it acts on named (see `select`), for the
/// commands that choose them by --all, --latest, --cidfile or --filter.
pub fn resolve_targets(
    client: &EngineClient,
    cmd: ContainerCommands,
) -> anyhow::Result<ContainerCommands> {
    use ContainerCommands as C;
    let none = super::Targets::default();
    Ok(match cmd {
        C::Stop {
            time,
            all,
            service,
            ignore,
            targets,
            containers,
        } if !all => C::Stop {
            time,
            all,
            service,
            ignore,
            containers: select(client, containers, false, &targets, ignore, &[])?,
            targets: none,
        },
        C::Restart {
            time,
            all,
            running,
            verify_image,
            targets,
            containers,
        } => C::Restart {
            time,
            verify_image,
            containers: select(
                client,
                containers,
                all,
                &targets,
                false,
                if running { &["running"] } else { &[] },
            )?,
            all: false,
            running: false,
            targets: none,
        },
        C::Kill {
            signal,
            all,
            targets,
            containers,
        } => C::Kill {
            signal,
            containers: select(
                client,
                containers,
                all,
                &targets,
                false,
                &["running", "paused"],
            )?,
            all: false,
            targets: none,
        },
        C::Rm {
            force,
            volumes,
            ignore,
            all,
            depend,
            time,
            targets,
            containers,
        } => C::Rm {
            force,
            volumes,
            // podman's -f: a container that is not there is no error; nor is
            // one that went with the pod of an infra container
            ignore: ignore || force || all,
            // (the infra container of a pod goes with its pod)
            depend: depend || all,
            time,
            containers: select(client, containers, all, &targets, ignore, &[])?,
            all: false,
            targets: none,
        },
        C::Pause {
            all,
            targets,
            containers,
        } => C::Pause {
            containers: select(client, containers, all, &targets, false, &["running"])?,
            all: false,
            targets: none,
        },
        C::Unpause {
            all,
            targets,
            containers,
        } => C::Unpause {
            containers: select(client, containers, all, &targets, false, &["paused"])?,
            all: false,
            targets: none,
        },
        C::Init {
            all,
            targets,
            containers,
        } => C::Init {
            containers: select(
                client,
                containers,
                all,
                &targets,
                false,
                &["created", "configured"],
            )?,
            all: false,
            targets: none,
        },
        C::Wait {
            condition,
            ignore,
            interval,
            exit_first_match,
            latest,
            containers,
        } => C::Wait {
            condition,
            ignore,
            interval,
            exit_first_match,
            containers: select(
                client,
                containers,
                false,
                &super::Targets {
                    latest,
                    ..Default::default()
                },
                ignore,
                &[],
            )?,
            latest: false,
        },
        other => other,
    })
}

/// `rm`: through the libpod API when it asks for what only it does (the
/// dependents first, a time to stop), each removed container printed.
pub fn remove(
    client: &EngineClient,
    containers: &[String],
    force: bool,
    volumes: bool,
    ignore: bool,
    depend: bool,
    time: Option<u64>,
) -> anyhow::Result<()> {
    if !depend && time.is_none() {
        let opts = client::RemoveContainer {
            force,
            volumes,
            ..Default::default()
        };
        return each_named_parallel(containers, ignore, &Statuses::RM, |c| {
            client
                .remove_container_podman(c, &opts)
                .map(|_| vec![c.to_string()])
        });
    }
    let opts = client::RemoveContainer {
        force,
        volumes,
        ignore,
        depend,
        timeout: time,
    };
    each_named_parallel(containers, ignore, &Statuses::RM, |c| {
        client.remove_container_podman(c, &opts)
    })
}

/// What `wait` was asked.
pub struct WaitArgs<'a> {
    /// podman's names of the conditions (none: the exit)
    pub conditions: &'a [String],
    /// podman's `--interval`
    pub interval: &'a str,
    pub ignore: bool,
    pub exit_first_match: bool,
}

/// `wait`: podman's; the exit code of each container, one line each, in
/// the order given (-1 for one not there, with `ignore`).  The containers
/// are waited for one after the other; with `exit_first_match`, at once,
/// and the first that meets a condition is the answer.
pub fn wait_condition(
    client: &EngineClient,
    containers: &[String],
    args: &WaitArgs<'_>,
) -> anyhow::Result<()> {
    use velarx_proto::wait::{parse_interval, WaitCondition};
    let conditions = WaitCondition::parse_all(args.conditions).map_err(anyhow::Error::msg)?;
    let interval = parse_interval(args.interval, true)
        .ok_or_else(|| anyhow::anyhow!("invalid duration {:?} for --interval", args.interval))?;
    if containers.is_empty() {
        anyhow::bail!("wait requires a name, id, or the --latest flag");
    }
    let one = |c: &str| match client.wait_condition(c, &conditions, interval) {
        Ok(code) => Ok(code),
        Err(e) if args.ignore && e.is_not_found() => Ok(-1),
        Err(e) => Err(e),
    };
    if args.exit_first_match && containers.len() > 1 {
        let (tx, rx) = std::sync::mpsc::channel();
        return std::thread::scope(|s| {
            for c in containers {
                let tx = tx.clone();
                s.spawn(move || {
                    let _ = tx.send(one(c));
                });
            }
            match rx.recv() {
                Ok(Ok(code)) => {
                    println!("{code}");
                    std::process::exit(0)
                }
                // (the process ends: the other waits end with it)
                Ok(Err(crate::client::ClientError::Interrupted(signal))) => {
                    std::process::exit(128 + signal)
                }
                Ok(Err(e)) => {
                    eprintln!("Error: {e}");
                    std::process::exit(125)
                }
                Err(_) => Ok(()),
            }
        });
    }
    for c in containers {
        match one(c) {
            Ok(code) => println!("{code}"),
            Err(e) if e.is_interrupted() => return Err(e.into()),
            Err(e) => anyhow::bail!("{e}"),
        }
    }
    Ok(())
}

/// podman's check of what `start` is told to start.
pub fn check_start_args(
    latest: bool,
    all: bool,
    filter: &[String],
    containers: &[String],
) -> anyhow::Result<()> {
    if containers.is_empty() && !latest && !all && filter.is_empty() {
        anyhow::bail!("start requires at least one argument");
    }
    if all && latest {
        anyhow::bail!("--all and --latest cannot be used together");
    }
    Ok(())
}

/// What `start` starts: the containers named, those of `--all`, and with
/// `--filter` only those that match (podman's filters of `ps`; the names
/// given are kept as they are, the others are said by their IDs).
pub fn start_targets(
    client: &EngineClient,
    all: bool,
    filter: &[String],
    containers: Vec<String>,
    attach: bool,
) -> anyhow::Result<Vec<String>> {
    if all && !containers.is_empty() {
        anyhow::bail!("either start all containers or the container(s) provided in the arguments");
    }
    if all && attach {
        anyhow::bail!("--all takes no --attach");
    }
    if filter.is_empty() {
        return if all {
            containers_to_start(client, filter)
        } else {
            Ok(containers)
        };
    }
    // velarx's own filter, what velarx-restart.service starts at boot
    if filter
        .iter()
        .all(|f| f.starts_with("should-start-on-boot="))
    {
        if !containers.is_empty() {
            anyhow::bail!("--filter should-start-on-boot takes no container");
        }
        return containers_to_start(client, filter);
    }
    let list = client.podman_list(client::Kind::Container, true, filter)?;
    let matching: Vec<(String, Vec<String>, String)> = list
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            let names = c["Names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|n| n.as_str().map(str::to_string))
                .collect();
            Some((
                c["Id"].as_str()?.to_string(),
                names,
                c["State"].as_str().unwrap_or_default().to_string(),
            ))
        })
        .collect();
    if containers.is_empty() {
        return Ok(matching
            .into_iter()
            .filter(|(_, _, state)| state != "running")
            .map(|(id, _, _)| id)
            .collect());
    }
    Ok(containers
        .into_iter()
        .filter(|c| {
            matching
                .iter()
                .any(|(id, names, _)| id.starts_with(c.as_str()) || names.iter().any(|n| n == c))
        })
        .collect())
}

/// The containers `start --all [--filter ...]` starts: every one that does
/// not run (the start of a paused one fails), and with
/// `should-start-on-boot=true` (the only filter) those that a boot starts
/// again (see `services::boot::should_start_on_boot`).
pub fn containers_to_start(
    client: &EngineClient,
    filters: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut on_boot = false;
    for f in filters {
        match f.as_str() {
            "should-start-on-boot=true" => on_boot = true,
            "should-start-on-boot=false" => {}
            other => anyhow::bail!("unknown filter `{other}` (should-start-on-boot=true)"),
        }
    }
    let filters: Vec<String> = on_boot
        .then(|| "should-start-on-boot=true".to_string())
        .into_iter()
        .collect();
    Ok(client
        .list_containers(true, &filters, false, false)?
        .into_iter()
        .filter(|c| c.state != RunState::Running)
        .map(|c| c.id)
        .collect())
}

/// Stop a container, saying the warning of the engine if it has one (the
/// stop signal did not stop it in time).
pub fn stop(
    client: &EngineClient,
    id: &str,
    timeout: Option<u32>,
    service: bool,
) -> client::ClientResult<()> {
    if let Some(w) = client.stop_container_with(id, timeout, service)? {
        client::warn(&w);
    }
    Ok(())
}

/// The containers `stop --all` stops: every one that runs, and the `--rm`
/// ones that do not, which podman's stop removes.
pub fn containers_to_stop(client: &EngineClient) -> anyhow::Result<Vec<String>> {
    Ok(client
        .list_containers(true, &[], false, false)?
        .into_iter()
        .filter(|c| matches!(c.state, RunState::Running | RunState::Paused) || c.host.auto_remove)
        .map(|c| c.id)
        .collect())
}

/// A container that notifies the unit (`--sdnotify=container`) learns the
/// unit's watchdog period, as `sd_watchdog_enabled` reads it, unless
/// `-e WATCHDOG_USEC=...` set it.
fn add_watchdog_env(env: &mut Vec<String>, sdnotify: &str, usec: Option<String>) {
    if sdnotify != "container" || env.iter().any(|e| e.starts_with("WATCHDOG_USEC=")) {
        return;
    }
    if let Some(usec) = usec {
        env.push(format!("WATCHDOG_USEC={usec}"));
    }
}

/// Whether this process runs in a systemd service, whose cgroup the
/// monitors of its containers then belong to: the service manager waits for
/// a notification (`NOTIFY_SOCKET`), or this process is in the cgroup of a
/// service it was started for (`INVOCATION_ID`, podman's test).  The
/// cgroup is checked as well because `INVOCATION_ID` is inherited by
/// everything a service starts and is set in scopes too (a login session,
/// `systemd-run --scope`), whose processes do not belong to a unit that
/// supervises them.
pub fn in_unit() -> bool {
    let set = |v: &str| std::env::var_os(v).is_some_and(|v| !v.is_empty());
    set("NOTIFY_SOCKET")
        || (set("INVOCATION_ID")
            && std::fs::read_to_string("/proc/self/cgroup").is_ok_and(|c| in_service_cgroup(&c)))
}

/// Whether the cgroup v2 line of a `/proc/self/cgroup` text is a service's.
fn in_service_cgroup(proc_cgroup: &str) -> bool {
    velarx_base::cgroup::path_in(proc_cgroup)
        .and_then(|path| path.rsplit('/').next())
        .is_some_and(|leaf| leaf.ends_with(".service"))
}

/// Whether the service manager gave this process what only its own process
/// tree can pass on: a notification socket (`NOTIFY_SOCKET`) or the sockets
/// of a socket activation (`LISTEN_FDS`).
pub fn from_manager() -> bool {
    let set = |v: &str| std::env::var_os(v).is_some_and(|v| !v.is_empty());
    set("NOTIFY_SOCKET") || set("LISTEN_FDS")
}

/// The container commands that the engine (`velarx container`)
/// runs without the engine service.
pub fn engine_handles(cmd: &ContainerCommands) -> bool {
    matches!(
        cmd,
        ContainerCommands::Run { .. }
            | ContainerCommands::Start { .. }
            | ContainerCommands::Stop { .. }
            | ContainerCommands::Kill { .. }
            | ContainerCommands::Rm { .. }
            | ContainerCommands::List { .. }
    )
}

/// Where the client sends a container command.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// To the engine service.
    Api,
    /// To the engine, in this process tree (`velarx container ...`).
    Engine,
}

/// Where a container command goes: to the engine when it runs in a systemd
/// unit (the unit supervises the container), when it wants what only the
/// caller's own process tree can give (the `NOTIFY_SOCKET`, the output), or
/// when no engine service answers; else to the server.  `unit`: see `in_unit`;
/// `from_manager`: the service manager gave this process what only it can
/// pass on (see `from_manager`); `explicit_socket`: the user named the
/// server (`--socket`); `server_up`: it answers.
pub fn route(
    cmd: &ContainerCommands,
    unit: bool,
    from_manager: bool,
    explicit_socket: bool,
    server_up: bool,
) -> Result<Route, String> {
    if !engine_handles(cmd) {
        return Ok(Route::Api);
    }
    let starts = matches!(
        cmd,
        ContainerCommands::Run { .. } | ContainerCommands::Start { .. }
    );
    let no_monitor = matches!(
        cmd,
        ContainerCommands::Run {
            no_monitor: true,
            ..
        }
    );
    let wants_descriptors = matches!(
        cmd,
        ContainerCommands::Run { preserve_fds, preserve_fd, .. }
            if *preserve_fds > 0 || !preserve_fd.is_empty()
    );
    let wants_caller = match cmd {
        ContainerCommands::Run {
            create,
            preserve_fds,
            preserve_fd,
            ..
        } => {
            from_manager
                || no_monitor
                || create.cgroups.as_deref() == Some("split")
                || create.sdnotify.as_deref().is_some_and(|m| m != "ignore")
                || create.log_driver.as_deref() == Some("passthrough")
                || *preserve_fds > 0
                || !preserve_fd.is_empty()
        }
        _ => false,
    };
    if explicit_socket {
        if no_monitor {
            return Err(
                "--no-monitor runs the container from this process: it does not go through \
                 the engine service, run the command without --socket"
                    .into(),
            );
        }
        if starts && wants_descriptors {
            return Err(
                "--preserve-fds and --preserve-fd pass descriptors of this process: they do not \
                 go through the engine service, run the command without --socket"
                    .into(),
            );
        }
        // The server never takes the notification socket or the sockets of
        // a client.
        if starts && from_manager {
            return Err(
                "a container started by a systemd unit that waits for its notification \
                 or passes it sockets is supervised by the unit: the engine service cannot \
                 do that, run the command without --socket"
                    .into(),
            );
        }
        return Ok(Route::Api);
    }
    if (starts && (unit || wants_caller)) || !server_up {
        return Ok(Route::Engine);
    }
    Ok(Route::Api)
}

/// `PATH[:OPTIONS]` of `--rootfs` with an absolute PATH (the server may not
/// run where the command does).
fn absolute_rootfs(spec: &str) -> String {
    let (path, opts) = match spec.rsplit_once(':') {
        Some((p, o)) if !o.is_empty() && !o.contains('/') => (p, Some(o)),
        _ => (spec, None),
    };
    let path = std::path::absolute(path).unwrap_or_else(|_| path.into());
    match opts {
        Some(o) => format!("{}:{o}", path.display()),
        None => path.display().to_string(),
    }
}

/// podman's words for a container that could not start (its runtime
/// failed, a workdir it lacks...): `start` quotes the ID, `start --attach`
/// does not.  A container that is not there keeps its own error.
pub fn start_failure(
    client: &EngineClient,
    e: client::ClientError,
    container: &str,
    quoted: bool,
) -> client::ClientError {
    // (podman wraps every failure of the start of a container it found)
    if !matches!(e, client::ClientError::Api { .. }) || e.is_not_found() {
        return e;
    }
    let id = client
        .inspect_container(container)
        .map_or_else(|_| container.to_string(), |c| c.id);
    in_start_failure(e, &if quoted { format!("{id:?}") } else { id })
}

/// The error `e` of the start of the container `id`, in podman's words: its
/// status and its condition stay.
fn in_start_failure(e: client::ClientError, id: &str) -> client::ClientError {
    match e {
        client::ClientError::Api {
            status,
            message,
            condition,
        } => client::ClientError::Api {
            status,
            message: format!("unable to start container {id}: {message}"),
            condition,
        },
        e => e,
    }
}

#[cfg(test)]
mod pod_tests {
    use super::*;

    fn targets(all: bool, latest: bool) -> crate::cli::PodTargets {
        crate::cli::PodTargets { all, latest }
    }

    #[test]
    fn pods_are_named_or_one_of_all_latest_and_the_files() {
        let sel = |named, t, files| pod_selection(named, &t, files).map_err(|e| e.to_string());
        assert_eq!(
            sel(true, targets(false, false), false),
            Ok(PodSelection::Named)
        );
        assert_eq!(
            sel(false, targets(true, false), false),
            Ok(PodSelection::All)
        );
        assert_eq!(
            sel(false, targets(false, true), false),
            Ok(PodSelection::Latest)
        );
        assert_eq!(
            sel(false, targets(false, false), true),
            Ok(PodSelection::IdFiles)
        );
        for (named, t, files, error) in [
            (
                false,
                targets(false, false),
                false,
                "you must provide at least one name or id",
            ),
            (
                true,
                targets(true, false),
                false,
                "no arguments are needed with --all",
            ),
            (
                false,
                targets(true, true),
                false,
                "--all and --latest cannot be used together",
            ),
            (
                true,
                targets(false, true),
                false,
                "--latest and containers cannot be used together",
            ),
            (
                true,
                targets(false, false),
                true,
                "no arguments are needed with --latest or --pod-id-file",
            ),
            (
                false,
                targets(false, true),
                true,
                "--all, --latest, and --pod-id-file cannot be used together",
            ),
        ] {
            assert_eq!(sel(named, t, files), Err(error.to_string()));
        }
    }

    #[test]
    fn a_pod_id_file_has_its_first_line() {
        let dir = std::env::temp_dir().join(format!("pod-id-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("id");
        std::fs::write(&file, "abc123\nignored\n").unwrap();
        let name = file.to_string_lossy().to_string();
        assert_eq!(
            pod_id_files(std::slice::from_ref(&name)).unwrap(),
            ["abc123"]
        );
        let missing = format!("{name}.none");
        assert_eq!(
            pod_id_files(std::slice::from_ref(&missing))
                .unwrap_err()
                .to_string(),
            format!("reading pod ID file: open {missing}: no such file or directory")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod tests {
    /// The health durations of run: whole seconds, or Go's durations (which
    /// the old parser refused when they had two units), never an overflow.
    #[test]
    fn a_run_duration_is_seconds_or_a_go_duration() {
        let ns = |s| super::parse_duration_ns(s).ok();
        assert_eq!(ns("10"), Some(10_000_000_000));
        assert_eq!(ns("0"), Some(0));
        assert_eq!(ns("1h30m"), Some(5_400_000_000_000));
        assert_eq!(ns("1.5s"), Some(1_500_000_000));
        assert_eq!(ns("500ms"), Some(500_000_000));
        assert_eq!(ns(" 2S "), Some(2_000_000_000));
        for bad in ["", "1d", "-1s", "18446744073709551615", "99999999999999h"] {
            assert_eq!(ns(bad), None, "{bad}");
        }
    }

    /// podman's MakeHealthCheckFromCli: `disable` is "0", a zero interval
    /// is no timer.
    #[test]
    fn a_zero_health_interval_is_no_timer() {
        use super::health_interval;
        assert_eq!(health_interval(None).unwrap(), (30_000_000_000, false));
        assert_eq!(health_interval(Some("disable")).unwrap(), (0, true));
        assert_eq!(health_interval(Some("0")).unwrap(), (0, true));
        assert_eq!(health_interval(Some("0s")).unwrap(), (0, true));
        assert_eq!(health_interval(Some("5s")).unwrap(), (5_000_000_000, false));
        assert!(health_interval(Some("soon")).is_err());
        use super::health_timeout;
        assert_eq!(health_timeout(None).unwrap(), 30_000_000_000);
        assert_eq!(health_timeout(Some("2s")).unwrap(), 2_000_000_000);
        for zero in ["0", "0s"] {
            let e = health_timeout(Some(zero)).unwrap_err().to_string();
            assert_eq!(e, "healthcheck-timeout must be at least 1 second");
        }
    }

    #[test]
    fn a_fifo_is_no_seccomp_profile() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        velarx_base::testing::make_fifo(&fifo);
        let opt = format!("seccomp={}", fifo.display());
        let r =
            velarx_base::testing::returns_within(std::time::Duration::from_secs(10), move || {
                super::security_opts(vec![opt])
            });
        assert!(r.is_err());
    }

    #[test]
    fn podman_userns_is_the_default_of_a_container_outside_a_pod() {
        let env = || Some("keep-id".to_string());
        assert_eq!(super::userns_default(None, false, env()), env());
        assert_eq!(super::userns_default(None, true, env()), None);
        let host = Some("host".to_string());
        assert_eq!(super::userns_default(host.clone(), false, env()), host);
        assert_eq!(super::userns_default(None, false, None), None);
        assert_eq!(
            super::userns_default(None, false, Some(String::new())),
            None
        );
    }

    use super::*;

    #[test]
    fn memory_alone_allows_as_much_swap() {
        // podman's LimitToSwap: no --memory-swap, memory + swap = 2x
        assert_eq!(swap_of(Some(3 << 20), None), Some(6 << 20));
        // --memory-swap wins, -1 too (unlimited), 0 is no swap
        assert_eq!(swap_of(Some(3 << 20), Some(9 << 20)), Some(9 << 20));
        assert_eq!(swap_of(Some(3 << 20), Some(-1)), Some(-1));
        assert_eq!(swap_of(Some(3 << 20), Some(0)), Some(0));
        // no memory limit: what was given (0 is none)
        assert_eq!(swap_of(None, None), None);
        assert_eq!(swap_of(None, Some(0)), None);
        assert_eq!(swap_of(Some(-1), None), None);
    }

    #[test]
    fn sizes_are_read_as_podman_reads_them() {
        for (text, bytes) in [
            ("1048576", 1 << 20),
            ("512m", 512 << 20),
            ("2GB", 2 << 30),
            ("1.5g", 3 << 29),
            ("512 MiB", 512 << 20),
            ("1t", 1 << 40),
            ("1024b", 1024),
            ("  64k ", 64 << 10),
            ("-1", -1),
        ] {
            assert_eq!(parse_memory_size(text).unwrap(), bytes, "{text}");
        }
        // (go's ParseFloat reads "1." and ".5")
        assert_eq!(parse_memory_size("1.").unwrap(), 1);
        assert_eq!(parse_memory_size(".5m").unwrap(), 1 << 19);
        // go-units' words
        for bad in ["", "abc", "-5m"] {
            let e = parse_memory_size(bad).unwrap_err().to_string();
            assert_eq!(e, format!("invalid size: '{bad}'"));
        }
        for (bad, why) in [
            ("1x", "invalid suffix: 'x'"),
            ("1mbb", "invalid suffix: 'mbb'"),
            ("1kx", "invalid suffix: 'kx'"),
            (
                "1.2.3",
                "strconv.ParseFloat: parsing \"1.2.3\": invalid syntax",
            ),
        ] {
            assert_eq!(parse_memory_size(bad).unwrap_err().to_string(), why);
        }
    }

    #[test]
    fn pod_id_file_is_read_as_podman_does() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("pod.id");
        assert_eq!(pod_from_id_file(None, None).unwrap(), None);
        std::fs::write(&f, "abc123\nrest\n").unwrap();
        assert_eq!(
            pod_from_id_file(None, Some(&f)).unwrap().as_deref(),
            Some("abc123")
        );
        std::fs::write(&f, "abc123").unwrap();
        assert_eq!(
            pod_from_id_file(None, Some(&f)).unwrap().as_deref(),
            Some("abc123")
        );
        // podman: an empty file means no pod
        std::fs::write(&f, "").unwrap();
        assert_eq!(pod_from_id_file(None, Some(&f)).unwrap(), None);
        let e = pod_from_id_file(Some("p"), Some(&f))
            .unwrap_err()
            .to_string();
        assert_eq!(e, "cannot specify both --pod and --pod-id-file");
        let e = pod_from_id_file(None, Some(&dir.path().join("none")))
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("reading pod ID file: "), "{e}");
    }

    #[test]
    fn ulimits_are_refused_in_podmans_words() {
        let u = parse_ulimit("nofile=1024:2048").unwrap();
        assert_eq!((u.name.as_str(), u.soft, u.hard), ("nofile", 1024, 2048));
        assert_eq!(parse_ulimit("nproc=-1").unwrap().soft, u64::MAX);
        assert!(parse_ulimits(&["host".to_string()]).unwrap().is_empty());
        assert!(parse_ulimits(&["host".into(), "nofile=1:2".into()])
            .unwrap()
            .is_empty());
        assert!(parse_ulimits(&["nofile=1:2".into(), "host".into()])
            .unwrap()
            .is_empty());
        assert_eq!(parse_ulimits(&["nofile=1:2".into()]).unwrap().len(), 1);
        let err = |s: &str| parse_ulimit(s).unwrap_err().to_string();
        assert_eq!(
            err("nofile:1024:1024"),
            "ulimit option \"nofile:1024:1024\" requires name=SOFT:HARD, failed to be parsed: invalid ulimit argument: nofile:1024:1024"
        );
        assert!(err("nofile=2048:1024")
            .ends_with("ulimit soft limit must be less than or equal to hard limit: 2048 > 1024"));
    }

    #[test]
    fn container_gets_the_watchdog_period_of_the_unit() {
        let usec = || Some("30000000".to_string());
        let mut env = vec!["A=1".to_string()];
        add_watchdog_env(&mut env, "container", usec());
        assert_eq!(env, ["A=1", "WATCHDOG_USEC=30000000"]);
        let mut env = vec!["WATCHDOG_USEC=5".to_string()];
        add_watchdog_env(&mut env, "container", usec());
        assert_eq!(env, ["WATCHDOG_USEC=5"]);
        for mode in ["", "conmon", "healthy", "ignore"] {
            let mut env = Vec::new();
            add_watchdog_env(&mut env, mode, usec());
            assert!(env.is_empty());
        }
        let mut env = Vec::new();
        add_watchdog_env(&mut env, "container", None);
        assert!(env.is_empty());
    }

    #[test]
    fn an_option_given_twice_takes_its_last_value() {
        let run = cmd(&[
            "run",
            "--tz=UTC",
            "--tz",
            "local",
            "--log-driver",
            "none",
            "--log-driver",
            "journald",
            "img",
        ]);
        let a = RunContainerArgs::from_command(run).unwrap_or_else(|_| panic!());
        assert_eq!(a.tz.as_deref(), Some("local"));
        assert_eq!(a.log_driver.as_deref(), Some("journald"));
        // podman's booleans take a value
        let run = cmd(&[
            "run",
            "-t=false",
            "--rm=false",
            "-it",
            "-d=true",
            "--privileged=false",
            "img",
        ]);
        let a = RunContainerArgs::from_command(run).unwrap_or_else(|_| panic!());
        assert!(a.tty && a.interactive && a.detach && !a.rm && !a.privileged);
        let run = cmd(&["run", "--rm", "-t", "img", "true"]);
        let a = RunContainerArgs::from_command(run).unwrap_or_else(|_| panic!());
        assert!(a.rm && a.tty && !a.interactive);
        assert_eq!(a.command, ["true"]);
        // (the lists add up)
        let run = cmd(&["run", "-e", "A=1", "-e", "B=2", "img"]);
        let a = RunContainerArgs::from_command(run).unwrap_or_else(|_| panic!());
        assert_eq!(a.env, ["A=1", "B=2"]);
    }

    #[test]
    fn a_negative_number_after_an_option_is_its_value() {
        let run_args =
            |a: &[&str]| RunContainerArgs::from_command(cmd(a)).unwrap_or_else(|_| panic!("{a:?}"));
        let a = run_args(&[
            "run",
            "--pids-limit",
            "-1",
            "--memory-swap",
            "-1",
            "--oom-score-adj",
            "-500",
            "--cpu-quota",
            "-1",
            "--rm",
            "img",
            "-5",
        ]);
        assert_eq!(a.pids_limit, Some(-1));
        assert_eq!(a.memory_swap.as_deref(), Some("-1"));
        assert_eq!(a.oom_score_adj, Some(-500));
        assert_eq!(a.cpu_quota, Some(-1));
        // (the command after the image is the container's)
        assert!(a.rm);
        assert_eq!(a.command, ["-5"]);
        // the other forms
        let a = run_args(&["create", "--pids-limit=-1", "--oom-score-adj=-3", "img"]);
        assert_eq!((a.pids_limit, a.oom_score_adj), (Some(-1), Some(-3)));
        // a flag that is not a number still is a flag
        assert!(crate::cli::parse_for_test([
            "velarx",
            "container",
            "run",
            "--pids-limit",
            "-x",
            "img"
        ])
        .is_err());
    }

    #[test]
    fn pull_takes_its_value_after_a_space() {
        use crate::cli::PullPolicy::*;
        let run_args =
            |a: &[&str]| RunContainerArgs::from_command(cmd(a)).unwrap_or_else(|_| panic!("{a:?}"));
        for (words, policy) in [
            (&["run", "--pull", "never", "img"][..], Never),
            (&["run", "--pull=never", "img"], Never),
            (&["run", "--pull", "always", "img"], Always),
            (&["run", "--pull", "newer", "img"], Newer),
            (&["run", "--pull", "MISSING", "img"], Missing),
            (&["run", "--pull", "false", "img"], Never),
            (&["run", "--pull=", "img"], Missing),
            (&["run", "img"], Missing),
        ] {
            let a = run_args(words);
            assert_eq!((a.pull, a.image.as_str()), (policy, "img"), "{words:?}");
        }
        // podman: a policy it does not know is refused, and a bare --pull
        // takes the image as its value
        assert!(
            crate::cli::parse_for_test(["velarx", "container", "run", "--pull", "img"]).is_err()
        );
        assert!(crate::cli::parse_for_test(["velarx", "container", "run", "--pull"]).is_err());
    }

    #[test]
    fn sig_proxy_is_a_boolean_that_takes_a_value_after_an_equals_sign() {
        let run_args =
            |a: &[&str]| RunContainerArgs::from_command(cmd(a)).unwrap_or_else(|_| panic!("{a:?}"));
        let a = run_args(&["run", "--sig-proxy", "img", "true"]);
        assert!(a.sig_proxy);
        assert_eq!(a.image, "img");
        let a = run_args(&["run", "--sig-proxy=false", "img"]);
        assert!(!a.sig_proxy);
    }

    #[test]
    fn values_with_a_dash_do_not_swallow_flags_or_the_command() {
        let run_args =
            |a: &[&str]| RunContainerArgs::from_command(cmd(a)).unwrap_or_else(|_| panic!("{a:?}"));
        // the command after the image is the container's, dashes and all
        let a = run_args(&["run", "-e", "A=1", "--rm", "img", "-c", "x"]);
        assert_eq!(
            (a.image.as_str(), a.command.as_slice(), a.rm),
            ("img", &["-c".to_string(), "x".into()][..], true)
        );
        let a = run_args(&["run", "--rm", "-t", "img", "ls", "-la", "--rm"]);
        assert_eq!(a.command, ["ls", "-la", "--rm"]);
        assert!(a.tty && a.rm);
        let a = run_args(&["run", "img", "--", "-x"]);
        assert_eq!(a.command, ["-x"]);
        let a = run_args(&[
            "run",
            "--name",
            "n",
            "-v",
            "/a:/b",
            "--cpu-shares",
            "2",
            "img",
            "-v",
        ]);
        assert_eq!(
            (a.name.as_deref(), a.command.as_slice()),
            (Some("n"), &["-v".to_string()][..])
        );
        let a = run_args(&["run", "--name=n", "-di", "-c2", "img", "sh", "-c", "exit 3"]);
        assert_eq!(a.command, ["sh", "-c", "exit 3"]);
        // the booleans that take a value (=VALUE only) leave the next
        // argument alone
        let a = run_args(&["run", "-t", "img", "true"]);
        assert!(a.tty);
        assert_eq!(
            (a.image.as_str(), a.command.as_slice()),
            ("img", &["true".to_string()][..])
        );
        let a = run_args(&["run", "-d", "--rm", "--privileged", "img"]);
        assert!(a.detach && a.rm && a.privileged);
        assert_eq!(a.image, "img");
        let a = run_args(&["run", "-it", "--tty=false", "img"]);
        assert!(a.interactive && !a.tty);
        // a value of -e that starts with a dash is the value, as pflag takes it
        let a = run_args(&["run", "-e", "-=", "img"]);
        assert_eq!(a.env, ["-="]);
        // exec: the command after the container
        match cmd(&["exec", "-i", "c", "ls", "-la"]) {
            ContainerCommands::Exec {
                container,
                command,
                interactive,
                ..
            } => {
                assert_eq!(
                    (container.as_str(), command.as_slice(), interactive),
                    ("c", &["ls".to_string(), "-la".into()][..], true)
                );
            }
            _ => panic!("not exec"),
        }
        // logs: a time in the future, and the flag after it
        match cmd(&["logs", "--since", "-1s", "-f", "c"]) {
            ContainerCommands::Logs {
                since,
                follow,
                containers,
                ..
            } => {
                assert_eq!(
                    (since.as_deref(), follow, containers.as_slice()),
                    (Some("-1s"), true, &["c".to_string()][..])
                );
            }
            _ => panic!("not logs"),
        }
        match cmd(&["logs", "--tail", "-1", "c"]) {
            ContainerCommands::Logs {
                tail, containers, ..
            } => assert_eq!((tail, containers.len()), (Some(-1), 1)),
            _ => panic!("not logs"),
        }
        // a format that starts with dashes, and the flags after it
        match cmd(&["list", "--format", "--{{.ID}}--", "-a"]) {
            ContainerCommands::List { all, out, .. } => {
                assert!(all);
                assert_eq!(out.format.as_deref(), Some("--{{.ID}}--"));
            }
            _ => panic!("not list"),
        }
        // kill -s -1 is the signal; the container follows
        match cmd(&["kill", "-s", "-INT", "c"]) {
            ContainerCommands::Kill {
                signal, containers, ..
            } => {
                assert_eq!(
                    (signal.as_str(), containers.as_slice()),
                    ("-INT", &["c".to_string()][..])
                );
            }
            _ => panic!("not kill"),
        }
    }

    #[test]
    fn signals_as_podman_checks_them() {
        assert_eq!(check_signal("1").unwrap(), "1");
        assert_eq!(check_signal("-1").unwrap(), "1");
        assert_eq!(check_signal("64").unwrap(), "64");
        assert_eq!(check_signal("-INT").unwrap(), "SIGINT");
        assert_eq!(check_signal("fpe").unwrap(), "SIGFPE");
        assert_eq!(check_signal("CLD").unwrap(), "SIGCLD");
        assert_eq!(check_signal("-SIGUSR1").unwrap(), "SIGUSR1");
        assert_eq!(check_signal("SIGRTMIN+3").unwrap(), "SIGRTMIN+3");
        for (bad, msg) in [
            ("0", "invalid signal: 0"),
            ("-0", "invalid signal: 0"),
            ("SIGBADSIG", "invalid signal: SIGBADSIG"),
            ("SIG", "invalid signal: SIG"),
            ("-BADSIG", "invalid signal: BADSIG"),
            ("-", "invalid signal: "),
            ("%%", "invalid signal: %%"),
            ("65", "valid signals are 1 through 64"),
            ("-65", "valid signals are 1 through 64"),
            ("99999999999999999999999", "valid signals are 1 through 64"),
        ] {
            assert_eq!(check_signal(bad).unwrap_err().to_string(), msg, "{bad}");
        }
    }

    #[test]
    fn the_options_of_podman_run_that_velarx_got_for_parity() {
        let args = |a: &[&str]| {
            RunContainerArgs::from_command(cmd(a)).unwrap_or_else(|_| panic!("not a run"))
        };
        // -h is the host name (the help is --help)
        let a = args(&["run", "-h", "web", "img"]);
        assert_eq!(a.hostname.as_deref(), Some("web"));
        assert_eq!(
            args(&["run", "-hweb", "img"]).hostname.as_deref(),
            Some("web")
        );
        let help = crate::cli::parse_for_test(["velarx", "container", "run", "--help"]).err();
        assert_eq!(
            help.map(|e| e.kind()),
            Some(clap::error::ErrorKind::DisplayHelp)
        );
        let a = args(&[
            "run",
            "-a",
            "STDOUT",
            "-a",
            "stderr",
            "--gpus",
            "all",
            "--gpus=1",
            "--gpus=2,3",
            "--hostuser",
            "bob,1000",
            "--chrootdirs",
            "/a,/b",
            "--hosts-file",
            "none",
            "--rdt-class",
            "gold",
            "--seccomp-policy",
            "image",
            "--blkio-weight-device",
            "/dev/sda:100",
            "--disable-content-trust",
            "img",
        ]);
        assert_eq!(a.attach, ["stdout", "stderr"]);
        assert_eq!(a.gpus, ["all", "1", "2", "3"]);
        assert_eq!(a.hostuser, ["bob", "1000"]);
        assert_eq!(a.chrootdirs, ["/a", "/b"]);
        assert_eq!(a.hosts_file.as_deref(), Some("none"));
        assert_eq!(a.rdt_class.as_deref(), Some("gold"));
        assert_eq!(a.seccomp_policy.as_deref(), Some("image"));
        assert_eq!(a.blkio_weight_device, ["/dev/sda:100"]);
        let bad =
            crate::cli::parse_for_test(["velarx", "container", "run", "-a", "x", "img"]).err();
        assert_eq!(
            bad.map(|e| e.kind()),
            Some(clap::error::ErrorKind::ValueValidation)
        );
        for argv in [
            ["velarx", "stats", "--interval", "0"],
            ["velarx", "container", "stats", "-i0"],
        ] {
            let e = crate::cli::parse_for_test(argv)
                .err()
                .expect("an interval of 0");
            assert!(e
                .to_string()
                .contains("invalid interval, must be a positive number greater zero"));
        }
        let w = parse_weight_device("/dev/sda:100").unwrap();
        assert_eq!((w.path.as_str(), w.weight), ("/dev/sda", 100));
        assert!(parse_weight_device("/dev/sda").is_err());
        assert!(parse_weight_device(":5").is_err());
        assert!(parse_weight_device("/dev/sda:x").is_err());
    }

    #[test]
    fn the_short_forms_of_podman_are_velarx_s() {
        use crate::cli::{parse_for_test, Commands};
        let ok = |a: &[&str]| {
            let argv = ["velarx"].iter().chain(a);
            parse_for_test(argv)
                .unwrap_or_else(|e| panic!("{a:?}: {e}"))
                .command
        };
        for verb in ["start", "stop", "restart", "pause", "unpause"] {
            let all = if verb == "start" { "--all" } else { "-a" };
            let Commands::Container(_) = ok(&["container", verb, all, "-f", "label=x"]) else {
                panic!("not a container command")
            };
        }
        ok(&["image", "commit", "-s", "c", "i"]);
        ok(&["image", "push", "-f", "oci", "i"]);
        ok(&[
            "image",
            "push",
            "--force-compression",
            "--compression-level=3",
            "i",
        ]);
        ok(&["image", "search", "--list-tags", "--limit", "3", "r/t"]);
        ok(&["image", "tree", "--whatrequires", "i"]);
        ok(&["manifest", "rm", "-i", "l"]);
        ok(&[
            "manifest",
            "push",
            "--add-compression",
            "zstd,gzip",
            "-f",
            "oci",
            "l",
        ]);
        ok(&["network", "create", "-o", "mtu=1400", "n"]);
        ok(&["secret", "ls", "-n"]);
        ok(&["secret", "inspect", "-f", "json", "s"]);
        ok(&["pod", "create", "-h", "web", "p"]);
    }

    #[test]
    fn the_ways_to_choose_containers() {
        // (no request is made: the client's socket is never used)
        let client = client::EngineClient::new(std::path::Path::new("/")).unwrap();
        let t = |latest, cidfile: &[&str], filter: &[&str]| crate::cli::Targets {
            latest,
            cidfile: cidfile.iter().map(|s| s.to_string()).collect(),
            filter: filter.iter().map(|s| s.to_string()).collect(),
        };
        let named = vec!["a".to_string()];
        assert_eq!(
            select(
                &client,
                named.clone(),
                false,
                &t(false, &[], &[]),
                false,
                &[]
            )
            .unwrap(),
            named
        );
        assert!(select(
            &client,
            named.clone(),
            true,
            &t(false, &[], &[]),
            false,
            &[]
        )
        .is_err());
        assert!(select(
            &client,
            named.clone(),
            false,
            &t(true, &[], &[]),
            false,
            &[]
        )
        .is_err());
        assert!(select(
            &client,
            named,
            false,
            &t(false, &[], &["name=x"]),
            false,
            &[]
        )
        .is_err());
        assert!(select(&client, vec![], true, &t(true, &[], &[]), false, &[]).is_err());
        let e = select(&client, vec![], false, &t(false, &[], &[]), false, &[]).unwrap_err();
        assert!(
            e.to_string()
                .contains("you must provide at least one name or id"),
            "{e}"
        );

        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("cid");
        std::fs::write(&f, "abc123\n").unwrap();
        let fs = f.to_str().unwrap();
        let missing = dir.path().join("nosuch");
        let ms = missing.to_str().unwrap();
        assert_eq!(
            select(&client, vec![], false, &t(false, &[fs], &[]), false, &[]).unwrap(),
            ["abc123"]
        );
        assert_eq!(
            select(&client, vec![], false, &t(false, &[fs, ms], &[]), true, &[]).unwrap(),
            ["abc123"]
        );
        assert!(select(&client, vec![], false, &t(false, &[ms], &[]), false, &[]).is_err());
        std::fs::write(&f, "").unwrap();
        assert!(select(&client, vec![], false, &t(false, &[fs], &[]), false, &[]).is_err());
    }

    #[test]
    fn a_loop_over_names_stops_at_the_signal_and_goes_on_at_a_failure() {
        let names = ["a", "b", "c", "d"].map(String::from);
        let api = |status| client::ClientError::api(status, "x".into());
        let (mut tried, mut failed) = (Vec::new(), Vec::new());
        let r = each_item(
            &names,
            |n| {
                tried.push(n.to_string());
                match n.as_str() {
                    "a" => Err(api(500)),
                    "c" => Err(client::ClientError::Interrupted(libc::SIGTERM)),
                    _ => Ok(()),
                }
            },
            |n, _| failed.push(n.to_string()),
        );
        let e = r.unwrap_err();
        assert!(
            matches!(
                e.downcast_ref(),
                Some(client::ClientError::Interrupted(libc::SIGTERM))
            ),
            "{e:?}"
        );
        assert_eq!(tried, ["a", "b", "c"]);
        assert_eq!(failed, ["a"]);
    }

    #[test]
    fn test_a_run_not_started_exits_as_podman_s() {
        let st =
            |c: Condition, m: &str| not_started(&client::ClientError::refused(c, m.into())).status;
        assert_eq!(st(Condition::CommandNotFound, "any words"), 127);
        // the container removed by another command while it starts is not a
        // command that is not found; podman exits 126 for it
        assert_eq!(st(Condition::NotStarted, "executable file not found"), 126);
        assert_eq!(
            not_started(&client::ClientError::api(404, "no such container".into())).status,
            126
        );
    }

    #[test]
    fn a_failed_start_keeps_its_status_and_its_condition() {
        let e = in_start_failure(
            client::ClientError::refused(Condition::InvalidState, "paused".into()),
            "\"c1\"",
        );
        assert!(e.is(Condition::InvalidState));
        assert!(e.is_conflict());
        assert_eq!(e.to_string(), "unable to start container \"c1\": paused");
        let e = in_start_failure(
            client::ClientError::refused(Condition::CommandNotFound, "x".into()),
            "c1",
        );
        assert!(e.is(Condition::CommandNotFound));
        assert_eq!(not_started(&e).status, 127);
    }

    #[test]
    fn only_the_conditions_of_a_container_that_did_not_start_exit_126_or_127() {
        let e = |c: Condition| client::ClientError::refused(c, "x".into());
        assert!(is_not_started(&e(Condition::NotStarted)));
        assert!(is_not_started(&e(Condition::CommandNotFound)));
        // (words of a runtime in the message of another condition, or of a
        // plain status, are not the condition)
        for m in [
            "crun: x: OCI runtime error",
            "workdir \"/x\" does not exist on container c",
            "unable to find user x: no matching entries in passwd file",
            "image not found: x",
        ] {
            assert!(
                !is_not_started(&client::ClientError::api(400, m.into())),
                "{m}"
            );
            assert!(
                !is_not_started(&client::ClientError::refused(
                    Condition::InvalidArgument,
                    m.into()
                )),
                "{m}"
            );
        }
    }

    fn cmd(args: &[&str]) -> ContainerCommands {
        let argv = ["velarx", "container"].iter().chain(args);
        match crate::cli::parse_for_test(argv).unwrap().command {
            crate::cli::Commands::Container(c) => c,
            _ => panic!("not a container command"),
        }
    }

    #[test]
    fn a_unit_runs_its_containers_in_the_engine() {
        let run = cmd(&["run", "-d", "img"]);
        assert_eq!(route(&run, true, true, false, true), Ok(Route::Engine));
        assert_eq!(route(&run, true, false, false, true), Ok(Route::Engine));
        let start = cmd(&["start", "c"]);
        assert_eq!(route(&start, true, true, false, true), Ok(Route::Engine));
        // Stopping and removing work either way: the server if it is there.
        let rm = cmd(&["rm", "-f", "c"]);
        assert_eq!(route(&rm, true, true, false, true), Ok(Route::Api));
        assert_eq!(route(&rm, true, true, false, false), Ok(Route::Engine));
    }

    #[test]
    fn the_environment_of_the_caller() {
        let vars = || {
            [
                ("PATH", "/bin"),
                ("https_proxy", "http://p:3128"),
                ("NO_PROXY", "x"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
        };
        assert_eq!(
            host_env(false, true, vars(), &[]),
            ["https_proxy=http://p:3128", "NO_PROXY=x"]
        );
        assert_eq!(host_env(false, false, vars(), &[]), Vec::<String>::new());
        // what -e sets is not taken from the caller
        assert_eq!(
            host_env(
                true,
                true,
                vars(),
                &["PATH=/usr/bin".into(), "NO_PROXY".into()]
            ),
            ["https_proxy=http://p:3128"]
        );
        let args = crate::cli::parse_for_test([
            "velarx",
            "container",
            "run",
            "--env-host",
            "--http-proxy=false",
            "--retry",
            "2",
            "--retry-delay",
            "5s",
            "img",
        ])
        .unwrap();
        let crate::cli::Commands::Container(c) = args.command else {
            panic!()
        };
        let a = RunContainerArgs::from_command(c).unwrap_or_else(|_| panic!());
        assert!(a.env_host && !a.http_proxy);
        assert_eq!((a.retry, a.retry_delay.as_deref()), (Some(2), Some("5s")));
    }

    #[test]
    fn no_monitor_is_for_the_engine_in_the_foreground() {
        let run = cmd(&["run", "--no-monitor", "img"]);
        assert_eq!(route(&run, false, false, false, true), Ok(Route::Engine));
        assert_eq!(route(&run, false, false, false, false), Ok(Route::Engine));
        assert!(route(&run, false, false, true, true).is_err());
        let argv = ["velarx", "container", "run", "-d", "--no-monitor", "img"];
        assert!(crate::cli::parse_for_test(argv).is_err(), "-d is refused");
    }

    #[test]
    fn preserved_descriptors_are_the_engines() {
        for args in [
            &["run", "--preserve-fds", "2", "img"][..],
            &["run", "--preserve-fd", "3,5", "--preserve-fd", "7", "img"][..],
        ] {
            let c = cmd(args);
            assert_eq!(route(&c, false, false, false, true), Ok(Route::Engine));
            let err = route(&c, false, false, true, true).unwrap_err();
            assert!(err.contains("--socket"), "{err}");
        }
        let c = cmd(&["run", "--preserve-fd", "3,5", "--preserve-fd", "7", "img"]);
        let ContainerCommands::Run { preserve_fd, .. } = c else {
            panic!()
        };
        assert_eq!(preserve_fd, [3, 5, 7]);
        let c = cmd(&["run", "img"]);
        assert_eq!(route(&c, false, false, false, true), Ok(Route::Api));
        assert!(crate::cli::parse_for_test([
            "velarx",
            "container",
            "run",
            "--preserve-fds",
            "-1",
            "img"
        ])
        .is_err());
        assert!(crate::cli::parse_for_test([
            "velarx",
            "container",
            "run",
            "--preserve-fd",
            "x",
            "img"
        ])
        .is_err());
    }

    #[test]
    fn a_unit_does_not_send_its_notification_to_a_server() {
        let err = route(&cmd(&["run", "img"]), true, true, true, true).unwrap_err();
        assert!(err.contains("--socket"), "{err}");
        let stop = cmd(&["stop", "c"]);
        assert_eq!(route(&stop, true, true, true, true), Ok(Route::Api));
        // A unit that waits for no notification may name a server.
        let run = cmd(&["run", "img"]);
        assert_eq!(route(&run, true, false, true, true), Ok(Route::Api));
    }

    #[test]
    fn what_only_the_caller_can_give_goes_to_the_engine() {
        for args in [
            &["run", "--sdnotify=conmon", "img"][..],
            &["run", "--log-driver=passthrough", "img"][..],
        ] {
            let c = cmd(args);
            assert_eq!(route(&c, false, false, false, true), Ok(Route::Engine));
            // A named server answers (and refuses) itself.
            assert_eq!(route(&c, false, false, true, true), Ok(Route::Api));
        }
        let ignore = cmd(&["run", "--sdnotify=ignore", "img"]);
        assert_eq!(route(&ignore, false, false, false, true), Ok(Route::Api));
        // Sockets of a socket activation outside a service too.
        let run = cmd(&["run", "img"]);
        assert_eq!(route(&run, false, true, false, true), Ok(Route::Engine));
    }

    #[test]
    fn a_service_is_a_unit_a_scope_is_not() {
        let cg = |p: &str| format!("0::{p}\n");
        assert!(in_service_cgroup(&cg("/system.slice/web.service")));
        assert!(in_service_cgroup(&cg(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/web.service"
        )));
        assert!(!in_service_cgroup(&cg(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/run-p1-i2.scope"
        )));
        assert!(!in_service_cgroup(&cg(
            "/user.slice/user-1000.slice/session-3.scope"
        )));
        assert!(!in_service_cgroup("12:pids:/system.slice/web.service\n"));
    }

    #[test]
    fn without_a_server_the_engine_runs_what_it_can() {
        let run = cmd(&["run", "img"]);
        assert_eq!(route(&run, false, false, false, false), Ok(Route::Engine));
        assert_eq!(route(&run, false, false, false, true), Ok(Route::Api));
        let inspect = cmd(&["inspect", "c"]);
        assert_eq!(route(&inspect, false, false, false, false), Ok(Route::Api));
    }

    #[test]
    fn a_restart_policy_is_podmans() {
        let ok = |p: &str| parse_restart_policy(p).map(|r| (r.name, r.maximum_retry_count));
        assert_eq!(ok("always").unwrap(), ("always".into(), 0));
        assert_eq!(ok("never").unwrap(), ("no".into(), 0));
        assert_eq!(ok("on-failure:3").unwrap(), ("on-failure".into(), 3));
        assert_eq!(ok("unless-stopped").unwrap(), ("unless-stopped".into(), 0));
        for bad in [
            "foo",
            "alwasy",
            "unless_stopped",
            "always:3",
            "on-failure:abc",
            "on-failure:-1",
            "on-failure:1:2",
        ] {
            assert!(ok(bad).is_err(), "{bad}");
        }
        assert!(ok("foo")
            .unwrap_err()
            .to_string()
            .contains("\"foo\" is not a valid restart policy"));
    }
}
