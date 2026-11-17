// SPDX-License-Identifier: Apache-2.0
//! The engine without a server: a command with no engine service builds the
//! services of the API for itself ([`Local`]) and calls their operations in
//! its own process, so that the monitors it starts are its descendants.
//!
//! Under systemd this is what makes a unit supervise its container
//! (`velarx container run|start|stop|kill|rm`, [`container_command`]):
//! the monitor is in the unit's cgroup, gets the unit's `NOTIFY_SOCKET` and
//! standard streams, sends `MAINPID` (and `READY`, by `--sdnotify`), and
//! exits with the container's status.  With `-d` this process exits once the
//! container runs; the monitor stays, and records the exit with the exit
//! command when it ends.
//!
//! The commands are the client's (`cli::run`), run on the engine as on a
//! client of the engine service: the engine and the server call the same
//! operations (`api::ops`).

use crate::cli::run::{self, AttachRequest, RunContainerArgs};
use crate::cli::ContainerCommands;
use crate::daemon::Role;
use crate::{api, client};
use velarx_config::Config;
use velarx_wire::sdnotify;

mod local;
pub mod process;
pub mod pull_service;
pub mod signals;
pub use local::Local;
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::Arc;

pub use crate::cli::run::{engine_handles as handles, in_unit};

/// The most workers of the runtime of an engine of this process: it serves one
/// command, and a worker per CPU is a thread to start and to join (a
/// millisecond or more on a big machine) that a command does not use.
const ENGINE_WORKERS: usize = 4;

/// The task that turns what happens to the containers of this process into
/// events, and how the command tells it that it is done.
struct Follower {
    done: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Follower {
    /// The notices sent before are events once this returns: the process
    /// may end (an exit this command recorded is not lost with it).
    fn finish(self, rt: &tokio::runtime::Runtime) {
        let _ = self.done.send(());
        let _ = rt.block_on(self.task);
    }
}

/// What happens to the containers this process follows becomes events.
fn follow_containers(rt: &tokio::runtime::Runtime, state: &Arc<api::AppState>) -> Follower {
    use tokio::sync::broadcast::error::{RecvError, TryRecvError};
    let mut notices = state.container_service.subscribe_notices();
    let state = state.clone();
    let (done, mut ended) = tokio::sync::oneshot::channel::<()>();
    let task = rt.spawn(async move {
        loop {
            tokio::select! {
                biased;
                n = notices.recv() => match n {
                    Ok(n) => api::podman::on_notice(&state, n).await,
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!("{n} notices of the containers were missed");
                    }
                    Err(RecvError::Closed) => return,
                },
                _ = &mut ended => loop {
                    match notices.try_recv() {
                        Ok(n) => api::podman::on_notice(&state, n).await,
                        Err(TryRecvError::Lagged(_)) => continue,
                        Err(_) => return,
                    }
                },
            }
        }
    });
    Follower { done, task }
}

/// The runtime of an engine of this process.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cpus.min(ENGINE_WORKERS))
        .enable_all()
        .build()
}

/// Run a container command in this process; its exit code.  The service
/// manager's variables must have been taken (`sdnotify::take_manager_env`).
/// `activated`: the sockets of the unit's socket activation, for the
/// container of `run`.
pub fn container_command(
    config_path: &Path,
    mut cmd: ContainerCommands,
    activated: Vec<sdnotify::ActivatedFd>,
    preserved: Option<crate::preserve_fds::Taken>,
) -> anyhow::Result<i32> {
    if !handles(&cmd) {
        anyhow::bail!(
            "this command needs the engine service: start it with `velarx varlink` \
             and use `velarx`"
        );
    }
    // `[containers] cgroups` of the configuration is the mode of a
    // container that asks for none: known before anything looks at the
    // mode (the scope asked for in advance, the split, the probe of the
    // manager).  A member of a pod made with `--cgroups=disabled` is
    // disabled too (`PodService`), whatever the configuration says: read
    // from the pod's file before the checks of the run, the pull and any
    // probe.
    let config = load_config(config_path)?;
    if let ContainerCommands::Run { create, .. } | ContainerCommands::Create { create, .. } =
        &mut cmd
    {
        create.cgroups = cgroups_of(&config, create);
    }
    check_run(&cmd)?;
    // The scope of the container, which the manager needs 10-15 ms to make,
    // is asked for now, while the configuration, the image and the bundle
    // are being made (`services::scope`).
    if let ContainerCommands::Run {
        create,
        no_monitor: false,
        ..
    } = &cmd
    {
        if matches!(
            create.cgroups.as_deref(),
            None | Some("") | Some("enabled") | Some("scope") | Some("no-conmon")
        ) && !create.needs_cgroup_placement()
            && !in_unit()
            && velarx_core::services::cgroups_mode::scope_manager_answers()?
            && velarx_core::services::cgroups_mode::systemd_answers()?
        {
            velarx_core::services::scope::begin_early();
        }
    }
    // (a scope asked for in advance that no container took ends with the
    // command, whatever way it ends)
    struct EndEarly;
    impl Drop for EndEarly {
        fn drop(&mut self) {
            velarx_core::services::scope::end_early();
        }
    }
    let _end_early = EndEarly;
    // `run --no-monitor`: this process monitors the container, the engine
    // goes on in a child (before any thread).
    let in_process = match &cmd {
        ContainerCommands::Run {
            no_monitor: true,
            create,
            sig_proxy,
            ..
        } => {
            // (the descriptors the container is passed: the monitor side of
            // the split has copies of those the engine names)
            let held: Vec<std::os::fd::BorrowedFd<'_>> = match &preserved {
                Some(taken) => taken.fds.iter().map(AsFd::as_fd).collect(),
                None => activated.iter().map(|a| a.fd.as_fd()).collect(),
            };
            Some(Arc::new(velarx_runtime::monitor::inproc::split(
                velarx_runtime::monitor::inproc::AttachSpec {
                    tty: create.tty,
                    stdin: create.interactive,
                    sig_proxy: *sig_proxy,
                },
                &held,
            )?))
        }
        _ => None,
    };
    velarx_base::trace::point("engine config");
    // `--preserve-fds` and `--preserve-fd` are not the unit's sockets:
    // those are left out, and the container learns nothing of LISTEN_FDS
    // (it would count descriptors that are not there).
    let (listen_env, listen_fds, preserve_holes) = match preserved {
        Some(taken) => (Vec::new(), taken.fds, taken.holes),
        None => {
            let env = listen_env(&activated);
            if !activated.is_empty() {
                warn_selinux_sockets(&cmd, &activated);
            }
            (
                env,
                activated.into_iter().map(|a| a.fd).collect(),
                Vec::new(),
            )
        }
    };
    let split_cgroup = match &cmd {
        ContainerCommands::Run { create, .. } if create.cgroups.as_deref() == Some("split") => {
            Some(
                velarx_core::services::cgroups_mode::split_own_cgroup().map_err(|e| {
                    anyhow::anyhow!("--cgroups=split: cannot split the cgroup: {e}")
                })?,
            )
        }
        _ => None,
    };
    // `--cgroups=disabled` touches no cgroup and asks no manager.
    let disabled = makes_disabled(&config, &cmd);
    // (nor a cgroup for the workers of an image the command pulls)
    let config = if disabled {
        without_pull_cgroups(config)
    } else {
        config
    };
    // (asked when a container needs it: a member of a pod that is disabled
    // never does)
    let systemd_cgroups = if split_cgroup.is_some() || disabled {
        velarx_core::services::SystemdCgroups::known(false)
    } else {
        velarx_core::services::SystemdCgroups::probe(systemd_cgroups_probe)
    };
    let role = Role::Engine {
        notify_socket: sdnotify::notify_socket(),
        listen_fds: listen_fds.into_iter().map(Arc::new).collect(),
        preserve_holes,
        systemd_cgroups,
        split_cgroup,
        in_process: in_process.clone(),
    };
    let engine = process::start(config, config_path, &role)?;
    velarx_base::trace::point("engine services");
    let service = process::service(engine)?;
    let result = run_command(&service, cmd, listen_env);
    // The container waits for the process that monitors it.
    if let (Some(handoff), Ok(_)) = (&in_process, &result) {
        handoff.attach();
    }
    // The notices of what this process did are events before it goes.
    process::finish();
    velarx_base::trace::point("engine settled");
    // The process ends with the command: its services, its runtime and their
    // threads are not taken down one by one (a few milliseconds of every
    // command), the kernel does it.
    if let Ok(code) = &result {
        velarx_core::services::scope::end_early();
        std::process::exit(*code);
    }
    result
}

/// The configuration of `config_path` for the engine of a command.
pub fn load_config(config_path: &Path) -> anyhow::Result<Arc<Config>> {
    let config = Config::load_or_default(config_path)?;
    config.validate()?;
    Ok(Arc::new(config))
}

/// The `--cgroups` of the container `create` makes: its own, else that of
/// its pod when the pod was made with `--cgroups=disabled` (`PodService`),
/// else the one `[containers] cgroups` gives.  Read from the pod's file,
/// before the engine of the command has services.
fn cgroups_of(config: &Config, create: &crate::cli::CreateArgs) -> Option<String> {
    cgroups_among(config, create.cgroups.as_deref(), create.pod.as_deref())
}

fn cgroups_among(config: &Config, cgroups: Option<&str>, pod: Option<&str>) -> Option<String> {
    if cgroups.is_some() {
        return cgroups.map(str::to_string);
    }
    if let Some(pod) = pod {
        let pods = config.server.root_dir.join("pods");
        if velarx_core::services::stored_pod_cgroups(&pods, pod)
            == Some(velarx_core::services::CgroupsMode::Disabled)
        {
            return Some("disabled".into());
        }
    }
    conf_cgroups(&config.containers.cgroups)
}

/// The `--cgroups` and the pod of the container a command makes (`run` and
/// `create`): what decides whether its engine has cgroups.
pub struct AskedCgroups {
    cgroups: Option<String>,
    pod: Option<String>,
}

impl AskedCgroups {
    /// What `cmd` asks, if it makes a container.
    pub fn of(cmd: &ContainerCommands) -> Option<Self> {
        match cmd {
            ContainerCommands::Run { create, .. } | ContainerCommands::Create { create, .. } => {
                Some(Self {
                    cgroups: create.cgroups.clone(),
                    pod: create.pod.clone(),
                })
            }
            _ => None,
        }
    }
}

/// Whether the container that `asked` describes is made with
/// `--cgroups=disabled`, given or from its pod or the configuration.
pub fn cgroups_disabled(config: &Config, asked: &AskedCgroups) -> bool {
    cgroups_among(config, asked.cgroups.as_deref(), asked.pod.as_deref()).as_deref()
        == Some("disabled")
}

/// Whether `cmd` makes a container with `--cgroups=disabled`, given or
/// from its pod or the configuration.
pub fn makes_disabled(config: &Config, cmd: &ContainerCommands) -> bool {
    AskedCgroups::of(cmd).is_some_and(|asked| cgroups_disabled(config, &asked))
}

/// `config` for the engine of a command that makes a container with
/// `--cgroups=disabled`: the workers of an image it pulls get no cgroup
/// and no scope either, and none is required.
pub fn without_pull_cgroups(config: Arc<Config>) -> Arc<Config> {
    let mut c = (*config).clone();
    c.pull.memory_high_mib = 0;
    c.pull.memory_max_mib = 0;
    c.pull.pids_max = 0;
    c.pull.require_cgroup = false;
    Arc::new(c)
}

/// The `--cgroups` of `run` and `create` that `[containers] cgroups` of
/// the configuration (`conf`) gives a container that sets none: every
/// mode but the default (`split` too: the command splits the caller's
/// cgroup before it makes the container).
fn conf_cgroups(conf: &str) -> Option<String> {
    match conf {
        // (the containers of a command are scopes: the mode is not a choice)
        "" | "enabled" | "scope" => None,
        m => Some(m.to_string()),
    }
}

/// Whether the containers of the engine of a command get scopes from a
/// systemd manager: one answers, and the command is not in a unit.  It
/// connects to the manager: asked only for a container that has cgroups.
pub fn systemd_cgroups_probe() -> Result<bool, velarx_base::ids::IdsError> {
    Ok(!in_unit() && velarx_core::services::cgroups_mode::systemd_answers()?)
}

/// What `run` cannot do without a server, refused before anything is made.
fn check_run(cmd: &ContainerCommands) -> anyhow::Result<()> {
    let ContainerCommands::Run { create, .. } = cmd else {
        return Ok(());
    };
    let crate::cli::CreateArgs {
        network,
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
        blkio_weight,
        blkio_weight_device,
        device_read_bps,
        device_write_bps,
        device_read_iops,
        device_write_iops,
        cgroup_parent,
        cgroups,
        ..
    } = &**create;
    check_networks(network)?;
    if cgroups.as_deref() == Some("disabled") {
        // (its limits are an error of the create, `cgroups_mode::
        // cgroup_settings`, whatever the manager: it is not asked)
        return Ok(());
    }
    if cgroups.as_deref() == Some("split") {
        // Before the split moves anything: it is for a service's own cgroup
        // (not a login session's), and for a container of its own.
        if !in_unit() {
            anyhow::bail!("--cgroups=split splits the cgroup of a systemd service: run it in one");
        }
        // In a split cgroup the container has one of its own.
        return Ok(());
    }
    // Without a scope of its own, the container stays in the cgroup of its
    // monitor (the unit's): the runtime would drop its limits; refused
    // before anything is pulled or made.
    let limited = memory.is_some()
        || memory_reservation.is_some()
        || memory_swap.is_some()
        || cpus.is_some()
        || cpu_shares.is_some()
        || cpu_quota.is_some()
        || cpu_period.is_some()
        || cpuset_cpus.is_some()
        || cpuset_mems.is_some()
        || pids_limit.is_some()
        || blkio_weight.is_some()
        || !blkio_weight_device.is_empty()
        || !device_read_bps.is_empty()
        || !device_write_bps.is_empty()
        || !device_read_iops.is_empty()
        || !device_write_iops.is_empty()
        || cgroup_parent.is_some();
    if limited && (in_unit() || !velarx_core::services::cgroups_mode::systemd_answers()?) {
        anyhow::bail!(velarx_core::services::cgroups_mode::NO_CGROUP);
    }
    Ok(())
}

/// The networks a container can have without a server: the ones that need
/// no state of a server (a container's network namespace and a network
/// provider's do).
fn check_networks(networks: &[String]) -> anyhow::Result<()> {
    for n in networks {
        let mode = n.split_once(':').map_or(n.as_str(), |(m, _)| m);
        // (the namespace of another container is found through its process,
        // whatever process started it: `NetworkEngine::live_netns`)
        if mode == "provider" {
            anyhow::bail!(
                "--network {n} needs the engine service, whose provider serves the network: \
                 name it (--socket, --remote)"
            );
        }
    }
    Ok(())
}

/// The environment of a container that gets the sockets of a unit's socket
/// activation: they are its descriptors 3, 4, ..., and it is the process
/// they are for (`LISTEN_PID=1`, as with podman).
fn listen_env(activated: &[sdnotify::ActivatedFd]) -> Vec<String> {
    if activated.is_empty() {
        return Vec::new();
    }
    let mut env = vec![
        format!("LISTEN_FDS={}", activated.len()),
        "LISTEN_PID=1".into(),
    ];
    if activated.iter().any(|a| a.name.is_some()) {
        let names: Vec<&str> = activated
            .iter()
            .map(|a| a.name.as_deref().unwrap_or("unknown"))
            .collect();
        env.push(format!("LISTEN_FDNAMES={}", names.join(":")));
    }
    env
}

/// SELinux replaces the descriptors that the type of a process may not use
/// with /dev/null when it starts.  A socket of a unit gets the label of the
/// unit's process (systemd makes it from the label of the executable: a
/// velarx labelled `bin_t` runs as `unconfined_service_t`), and the policy
/// lets `container_t` use only the sockets of some types (`init_t`,
/// `container_runtime_t`, the type of podman's executable): the container
/// would get /dev/null as its descriptor 3.  A socket cannot be relabelled
/// once made; the policy is asked for each one and the engine says which
/// socket is withheld and what to do.
fn warn_selinux_sockets(cmd: &ContainerCommands, activated: &[sdnotify::ActivatedFd]) {
    use velarx_runtime::container::selinux;
    let ContainerCommands::Run { create, .. } = cmd else {
        return;
    };
    if !selinux::enabled() {
        return;
    }
    let mut typ = None;
    for o in &create.security_opt {
        if o == "label=disable" {
            return;
        }
        if let Some(t) = o.strip_prefix("label=type:") {
            typ = Some(t.to_string());
        }
    }
    if create.privileged && typ.is_none() {
        return;
    }
    let contexts = selinux::Contexts::host();
    let typ = typ.unwrap_or_else(|| contexts.typ.clone());
    // The level of a container is one of its own; only its dominance of the
    // socket's counts.
    let process = format!("{}:{}:{typ}:s0:c0,c1", contexts.user, contexts.role);
    for (i, a) in activated.iter().enumerate() {
        let fd = a.fd.as_fd();
        let (Some(label), Some(class)) = (selinux::fd_label(fd), selinux::socket_class(fd)) else {
            continue;
        };
        if selinux::allowed(&process, &label, class, &["read", "write"]) == Some(false) {
            tracing::warn!("{}", withheld_socket(i, a.name.as_deref(), &label, &typ));
        }
    }
}

fn withheld_socket(index: usize, name: Option<&str>, label: &str, container_type: &str) -> String {
    format!(
        "the SELinux policy does not let {container_type} use the socket {} of the unit \
         (labelled {label}): the container gets /dev/null instead of it.  Label the executable \
         of the unit as podman's (container_runtime_exec_t, so that the sockets get a type the \
         containers may use), or run the container with --security-opt label=disable",
        name.map_or_else(|| format!("#{}", index + 3), |n| format!("`{n}`")),
    )
}

fn run_command(
    client: &client::EngineClient,
    cmd: ContainerCommands,
    listen_env: Vec<String>,
) -> anyhow::Result<i32> {
    let cmd = match RunContainerArgs::from_command(cmd) {
        Ok(mut args) => {
            args.env.extend(listen_env);
            return run::run_container(client, args);
        }
        Err(cmd) => *cmd,
    };
    let cmd = run::resolve_targets(client, cmd)?;
    match cmd {
        ContainerCommands::Start {
            attach,
            interactive,
            detach_keys,
            sig_proxy,
            all,
            filter,
            latest,
            verify_image,
            service,
            containers,
        } => {
            let verify = if service {
                client::Verify::Service
            } else {
                client::Verify::Option(&verify_image)
            };
            run::check_start_args(latest, all, &filter, &containers)?;
            let containers = run::named_or_latest(client, latest, containers)?;
            let containers = run::start_targets(client, all, &filter, containers, attach)?;
            if attach {
                let [c] = containers.as_slice() else {
                    anyhow::bail!("--attach takes exactly one container");
                };
                let started = client
                    .start_container_attached(c, verify)
                    .map_err(|e| run::start_failure(client, e, c, false))?;
                let tty = client.inspect_container(c)?.tty;
                return run::attach_session(
                    client,
                    &started.id,
                    AttachRequest {
                        tty,
                        stdin: interactive,
                        stdout: true,
                        stderr: true,
                        detach_keys,
                        sig_proxy,
                        start: true,
                    },
                );
            }
            for c in containers {
                client
                    .start_container(&c, verify)
                    .map_err(|e| run::start_failure(client, e, &c, true))?;
                println!("{}", c);
            }
        }
        ContainerCommands::Stop {
            time,
            all,
            service,
            ignore,
            containers,
            ..
        } => {
            let containers = if all {
                run::containers_to_stop(client)?
            } else {
                containers
            };
            run::each_named_parallel(&containers, ignore, &run::Statuses::CONTAINER, |c| {
                run::stop(client, c, time, service).map(|()| vec![c.to_string()])
            })?
        }
        ContainerCommands::Kill {
            signal, containers, ..
        } => {
            let signal = run::check_signal(&signal)?;
            run::each_named_parallel(&containers, false, &run::Statuses::CONTAINER, |c| {
                client
                    .kill_container(c, &signal)
                    .map(|()| vec![c.to_string()])
            })?
        }
        ContainerCommands::Rm {
            force,
            volumes,
            ignore,
            depend,
            time,
            containers,
            ..
        } => run::remove(client, &containers, force, volumes, ignore, depend, time)?,
        ContainerCommands::List { all, out, ps } => {
            crate::cli::report::containers(client, all, &out.into(), &ps)?
        }
        _ => anyhow::bail!("this command needs the engine service"),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_warning_names_the_socket_and_the_fix() {
        let w = withheld_socket(
            0,
            Some("web"),
            "system_u:system_r:unconfined_service_t:s0",
            "container_t",
        );
        assert!(w.contains("socket `web`") && w.contains("unconfined_service_t"));
        assert!(w.contains("container_runtime_exec_t") && w.contains("label=disable"));
        assert!(withheld_socket(1, None, "x", "t").contains("socket #4"));
        assert!(!w.contains("   "), "{w}");
        assert!(w.contains("of the unit (labelled"), "{w}");
    }

    use super::*;

    #[test]
    fn what_asks_for_a_cgroup_placement() {
        let create = |extra: &[&str]| {
            let argv = ["velarx", "container", "run"]
                .into_iter()
                .chain(extra.iter().copied())
                .chain(["img"]);
            match crate::cli::parse_for_test(argv).unwrap().command {
                crate::cli::Commands::Container(ContainerCommands::Run { create, .. }) => create,
                _ => panic!("not a run"),
            }
        };
        assert!(!create(&[]).needs_cgroup_placement());
        for given in [
            &["--memory", "1g"][..],
            &["--device-read-bps", "/dev/null:1mb"],
            &["--cgroup-parent", "x.slice"],
            &["--pids-limit", "5"],
        ] {
            assert!(create(given).needs_cgroup_placement(), "{given:?}");
        }
    }

    #[test]
    fn the_cgroups_of_the_configuration_for_run_and_create() {
        assert_eq!(conf_cgroups(""), None);
        assert_eq!(conf_cgroups("enabled"), None);
        for m in ["disabled", "no-conmon", "split"] {
            assert_eq!(conf_cgroups(m).as_deref(), Some(m));
        }
    }

    /// `run` and `create` of a container with `--cgroups=disabled`, given
    /// or from `[containers] cgroups`, give the workers of what they pull
    /// no cgroup; other commands and modes keep the limits.
    #[test]
    fn a_disabled_container_pulls_without_a_cgroup() {
        let cmd = |args: &[&str]| {
            let argv = ["velarx", "container"].iter().chain(args).copied();
            match crate::cli::parse_for_test(argv).unwrap().command {
                crate::cli::Commands::Container(c) => c,
                _ => panic!("not a container command"),
            }
        };
        let config = Config::default();
        for args in [
            &["create", "--cgroups=disabled", "i"][..],
            &["run", "--cgroups=disabled", "i"],
        ] {
            assert!(makes_disabled(&config, &cmd(args)), "{args:?}");
        }
        for args in [
            &["create", "i"][..],
            &["create", "--cgroups=enabled", "i"],
            &["run", "--cgroups=split", "i"],
            &["rm", "i"],
        ] {
            assert!(!makes_disabled(&config, &cmd(args)), "{args:?}");
        }
        let mut conf = Config::default();
        conf.containers.cgroups = "disabled".into();
        assert!(makes_disabled(&conf, &cmd(&["create", "i"])));
        assert!(!makes_disabled(
            &conf,
            &cmd(&["create", "--cgroups=enabled", "i"])
        ));
        let pull = without_pull_cgroups(Arc::new(Config::default()))
            .pull
            .clone();
        assert_eq!(
            (pull.memory_high_mib, pull.memory_max_mib, pull.pids_max),
            (0, 0, 0)
        );
        assert!(!pull.require_cgroup);
    }

    #[test]
    fn networks_without_a_server() {
        for ok in [
            vec![],
            vec!["none".to_string()],
            vec!["host".to_string()],
            vec!["pasta".to_string()],
            vec!["pasta:--ipv4-only".to_string()],
            vec!["slirp4netns".to_string()],
            vec!["bridge".to_string()],
            vec!["container:abc".to_string()],
        ] {
            assert!(check_networks(&ok).is_ok(), "{ok:?}");
        }
        let err = check_networks(&["provider:x".to_string()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("engine service"), "{err}");
    }
}
