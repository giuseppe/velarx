// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_proto::engine::{PodmanHealthUpdate, UpdateBlockIo, UpdateDevice, UpdateSpec};

/// The one container a command takes: the one named, or with `--latest` the
/// container made last.
pub(super) fn one_container(
    client: &client::EngineClient,
    latest: bool,
    named: Option<String>,
) -> anyhow::Result<String> {
    let named: Vec<String> = named.into_iter().collect();
    match cli::run::named_or_latest(client, latest, named)?.pop() {
        Some(c) => Ok(c),
        None => anyhow::bail!("requires at least 1 arg(s), only received 0"),
    }
}

/// podman's checks of `--all`, `--latest` and the names
/// (`CheckAllLatestAndIDFile`); `none_is_all`: no name is a command of its
/// own (mount lists the mounted containers).
pub(super) fn all_latest_or_named(
    all: bool,
    latest: bool,
    named: &[String],
    none_is_all: bool,
) -> anyhow::Result<()> {
    if all && latest {
        anyhow::bail!("--all and --latest cannot be used together");
    }
    if all && !named.is_empty() {
        anyhow::bail!("no arguments are needed with --all");
    }
    if latest && !named.is_empty() {
        anyhow::bail!("--latest and containers cannot be used together");
    }
    if !none_is_all && named.is_empty() && !all && !latest {
        anyhow::bail!("you must provide at least one name or id");
    }
    Ok(())
}

/// `op` on each container: the failures are said, the last one is the
/// error (125), as podman's mount and unmount.
pub(super) fn each_container(
    containers: &[String],
    mut op: impl FnMut(&str) -> client::ClientResult<()>,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    cli::run::each_item(containers, |c| op(c), |_, e| errors.push(e))?;
    let Some(last) = errors.pop() else {
        return Ok(());
    };
    for e in errors {
        eprintln!("Error: {e}");
    }
    Err(cli::run::Failed {
        status: 125,
        message: last.to_string(),
    }
    .into())
}

/// What `update` asks for the settings SET.
pub(super) fn update_request(set: cli::UpdateArgs) -> anyhow::Result<UpdateSpec> {
    let cli::UpdateArgs {
        cpus,
        cpu_shares,
        cpu_period,
        cpu_quota,
        cpuset_cpus,
        cpuset_mems,
        memory,
        memory_reservation,
        memory_swap,
        pids_limit,
        env,
        unsetenv,
        restart,
        blkio_weight,
        blkio_weight_device,
        device_read_bps,
        device_write_bps,
        device_read_iops,
        device_write_iops,
        ulimit,
        no_healthcheck,
        health_cmd,
        health_interval,
        health_log_destination,
        health_max_log_count,
        health_max_log_size,
        health_on_failure,
        health_retries,
        health_start_period,
        health_startup_cmd,
        health_startup_interval,
        health_startup_retries,
        health_startup_success,
        health_startup_timeout,
        health_timeout,
    } = set;
    let size = |v: &Option<String>| v.as_deref().map(parse_memory_size).transpose();
    let (period, quota) = match cpus {
        Some(c) => {
            let p = cpu_period.unwrap_or(100_000);
            (Some(p), Some((c * p as f64) as i64))
        }
        None => (cpu_period, cpu_quota),
    };
    let memory_limit = size(&memory)?;
    // DEVICE:VALUE lists, as podman's update takes them
    let devices = |key: &str, list: &[String]| -> anyhow::Result<Vec<UpdateDevice>> {
        list.iter()
            .map(|d| {
                let (path, value) = d
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("invalid argument {d:?}: it is DEVICE:VALUE"))?;
                let value = match key {
                    "weight" => value
                        .parse::<u64>()
                        .map_err(|_| anyhow::anyhow!("invalid weight {value:?} of {path}"))?,
                    // (podman's words: IOPS are a number, not a size)
                    "iops" => value
                        .parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "invalid rate for device: {d}. The correct format is \
                                 <device-path>:<number>. Number must be a positive integer"
                            )
                        })?,
                    _ => parse_memory_size(value)? as u64,
                };
                Ok(UpdateDevice {
                    path: Some(path.to_string()),
                    value,
                    ..Default::default()
                })
            })
            .collect()
    };
    let ulimits = if ulimit.is_empty() {
        None
    } else {
        // (`host`: none, those of the host)
        let host = ulimit.iter().any(|u| u == "host");
        let mut limits = Vec::new();
        for u in ulimit.iter().filter(|_| !host) {
            let l = cli::run::parse_ulimit(u)?;
            limits.push(velarx_proto::request::Ulimit {
                name: l.name,
                soft: l.soft,
                hard: l.hard,
            });
        }
        Some(limits)
    };
    let health = PodmanHealthUpdate {
        no_healthcheck,
        health_cmd,
        health_interval,
        health_retries,
        health_timeout,
        health_start_period,
        health_startup_cmd,
        health_startup_interval,
        health_startup_retries,
        health_startup_timeout,
        health_startup_success,
        health_log_destination,
        health_max_log_count,
        health_max_log_size,
        health_on_failure,
    }
    .spec()
    .map_err(anyhow::Error::msg)?;
    Ok(UpdateSpec {
        memory: memory_limit,
        memory_reservation: size(&memory_reservation)?,
        // (podman's update: a memory limit without --memory-swap allows as
        // much swap as memory)
        memory_swap: crate::cli::run::swap_of(memory_limit, size(&memory_swap)?),
        cpu_quota: quota,
        cpu_period: period,
        cpu_shares,
        cpuset_cpus,
        cpuset_mems,
        pids_limit,
        block_io: UpdateBlockIo {
            weight: blkio_weight,
            weight_devices: devices("weight", &blkio_weight_device)?,
            read_bps: devices("bps", &device_read_bps)?,
            write_bps: devices("bps", &device_write_bps)?,
            read_iops: devices("iops", &device_read_iops)?,
            write_iops: devices("iops", &device_write_iops)?,
        },
        env,
        unset_env: unsetenv,
        // (podman's checks, as `run --restart`)
        restart: restart
            .as_deref()
            .map(crate::cli::run::parse_restart_policy)
            .transpose()?,
        ulimits,
        health,
        ..Default::default()
    })
}

/// `mount` without a container: the mounted ones, podman's
/// `ID<TAB>PATH` lines or its JSON.
fn show_mounted(
    client: &client::EngineClient,
    format: Option<&str>,
    no_trunc: bool,
) -> anyhow::Result<()> {
    let json = match format {
        None | Some("") => false,
        Some("json" | "{{json .}}" | "{{ json . }}") => true,
        Some(f) => anyhow::bail!("unknown --format argument: {f:?}"),
    };
    let mounted = client.mounted_containers()?;
    if json {
        let names: std::collections::HashMap<String, Option<String>> = client
            .list_containers(true, &[], false, false)?
            .into_iter()
            .map(|c| (c.id, Some(c.name).filter(|n| !n.is_empty())))
            .collect();
        // (podman's fields, in its order and indent)
        #[derive(serde::Serialize)]
        struct Mounted<'a> {
            id: &'a str,
            #[serde(rename = "Names")]
            names: [&'a str; 1],
            mountpoint: &'a str,
        }
        let out: Vec<Mounted> = mounted
            .iter()
            .map(|(id, path)| Mounted {
                id,
                names: [names.get(id).and_then(|n| n.as_deref()).unwrap_or_default()],
                mountpoint: path,
            })
            .collect();
        let mut buf = Vec::new();
        let fmt = serde_json::ser::PrettyFormatter::with_indent(b" ");
        serde::Serialize::serialize(
            &out,
            &mut serde_json::Serializer::with_formatter(&mut buf, fmt),
        )?;
        println!("{}", String::from_utf8_lossy(&buf));
        return Ok(());
    }
    for (id, path) in mounted {
        let id = if no_trunc {
            &id[..]
        } else {
            &id[..id.len().min(12)]
        };
        println!("{id}\t{path}");
    }
    Ok(())
}

pub(super) fn run_container_command(
    cmd: ContainerCommands,
    inv: &Invocation<'_>,
    startup: &velarx_sys::fd::Startup,
) -> anyhow::Result<()> {
    // The descriptors for the command of an exec are taken first, while
    // nothing of this process holds a number the caller did not pass.
    let preserved = match &cmd {
        ContainerCommands::Exec {
            preserve_fds,
            preserve_fd,
            ..
        } if *preserve_fds > 0 || !preserve_fd.is_empty() => {
            let mut taken = crate::preserve_fds::take(startup, *preserve_fds, preserve_fd)?;
            // (the monitor fills the holes itself: the call carries the
            // caller's descriptors only)
            let mut slot = 0;
            taken.fds.retain(|_| {
                slot += 1;
                !taken.holes.contains(&(slot - 1))
            });
            if taken.fds.len() > velarx_wire::varlink::MAX_FDS {
                anyhow::bail!(
                    "at most {} descriptors can be passed to the command of exec",
                    velarx_wire::varlink::MAX_FDS
                );
            }
            Some(taken)
        }
        _ => None,
    };
    // (the routes to the engine were taken before: `engine_command`)
    let client = get_client(inv)?;
    let cmd = cli::run::resolve_targets(&client, cmd)?;

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
            cli::run::check_start_args(latest, all, &filter, &containers)?;
            let containers = cli::run::named_or_latest(&client, latest, containers)?;
            let containers =
                crate::cli::run::start_targets(&client, all, &filter, containers, attach)?;
            if attach {
                let [c] = containers.as_slice() else {
                    anyhow::bail!("--attach takes exactly one container");
                };
                let started = client
                    .start_container_attached(c, verify)
                    .map_err(|e| cli::run::start_failure(&client, e, c, false))?;
                let tty = client.inspect_container(c)?.tty;
                let code = attach_session(
                    &client,
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
                )?;
                exit_with(code);
            }
            cli::run::each_named_as(&containers, false, &cli::run::Statuses::CONTAINER, |c| {
                client
                    .start_container(c, verify)
                    .map_err(|e| cli::run::start_failure(&client, e, c, true))
            })?
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
                crate::cli::run::containers_to_stop(&client)?
            } else {
                containers
            };
            cli::run::each_named_parallel(
                &containers,
                ignore,
                &cli::run::Statuses::CONTAINER,
                |c| cli::run::stop(&client, c, time, service).map(|()| vec![c.to_string()]),
            )?
        }
        ContainerCommands::Restart {
            time,
            verify_image,
            containers,
            ..
        } => cli::run::each_named_parallel(
            &containers,
            false,
            &cli::run::Statuses::CONTAINER,
            |c| {
                client
                    .restart_container(c, time, &verify_image)
                    .map(|()| vec![c.to_string()])
            },
        )?,
        ContainerCommands::Kill {
            signal, containers, ..
        } => {
            let signal = cli::run::check_signal(&signal)?;
            cli::run::each_named_parallel(
                &containers,
                false,
                &cli::run::Statuses::CONTAINER,
                |c| {
                    client
                        .kill_container(c, &signal)
                        .map(|()| vec![c.to_string()])
                },
            )?
        }
        ContainerCommands::Rm {
            force,
            volumes,
            ignore,
            depend,
            time,
            containers,
            ..
        } => cli::run::remove(&client, &containers, force, volumes, ignore, depend, time)?,
        ContainerCommands::Prune { force, filter } => {
            if !force && !confirm_prune("WARNING! This will remove all non running containers.")? {
                return Ok(());
            }
            // (podman prints the IDs only)
            for id in client.prune_containers(&filter)?.containers_deleted {
                println!("{id}");
            }
        }
        ContainerCommands::List { all, out, ps } => {
            cli::report::containers(&client, all, &out.into(), &ps)?
        }
        ContainerCommands::Exists {
            external: _,
            container,
        } => exit_with(if client.exists(client::Kind::Container, &container)? {
            0
        } else {
            1
        }),
        ContainerCommands::Export { output, container } => {
            // (nothing is shown, as podman's: the archive goes to a file or a
            // pipe a script reads)
            let mut stream = client.export_container(&container)?;
            match output {
                Some(path) => {
                    let mut file = std::fs::File::create(&path)?;
                    if let Err(e) = std::io::copy(&mut stream, &mut file) {
                        let _ = std::fs::remove_file(&path);
                        anyhow::bail!("exporting {container}: {e}");
                    }
                }
                None => {
                    use std::io::IsTerminal;
                    if std::io::stdout().is_terminal() {
                        anyhow::bail!("refusing to write the archive to a terminal, use --output");
                    }
                    to_stdout(&mut stream, &format!("exporting {container}"))?;
                }
            }
        }
        ContainerCommands::Mount {
            all,
            format,
            latest,
            no_trunc,
            containers,
        } => {
            all_latest_or_named(all, latest, &containers, true)?;
            if containers.is_empty() && !all && !latest {
                return show_mounted(&client, format.as_deref(), no_trunc);
            }
            let containers = if all {
                client
                    .list_containers(true, &[], false, false)?
                    .into_iter()
                    .map(|c| c.id)
                    .collect()
            } else {
                cli::run::named_or_latest(&client, latest, containers)?
            };
            each_container(&containers, |c| {
                println!("{}", client.mount_container(c)?);
                Ok(())
            })?;
        }
        ContainerCommands::Unmount {
            all,
            force: _,
            latest,
            containers,
        } => {
            all_latest_or_named(all, latest, &containers, false)?;
            // (podman prints what it was given, and the IDs with --all)
            let containers = if all {
                client
                    .mounted_containers()?
                    .into_iter()
                    .map(|(id, _)| id)
                    .collect()
            } else {
                cli::run::named_or_latest(&client, latest, containers)?
            };
            each_container(&containers, |c| {
                client.unmount_container(c)?;
                println!("{c}");
                Ok(())
            })?;
        }
        ContainerCommands::Clone {
            set,
            destroy,
            force,
            name,
            pod,
            run,
            verify_image,
            container,
            new_name,
            image,
        } => {
            if force && !destroy {
                anyhow::bail!("cannot set --force without --destroy: invalid argument");
            }
            // (as podman: the name given as an argument wins)
            let made = client.clone_container(
                &container,
                new_name.or(name).as_deref(),
                image.as_deref(),
                pod.as_deref(),
            )?;
            if !set.is_empty() {
                client.update_container(&made.id, &update_request(set.as_update())?)?;
            }
            if destroy {
                let opts = client::RemoveContainer {
                    force,
                    ..Default::default()
                };
                client.remove_container_podman(&container, &opts)?;
            }
            if run {
                client.start_container(&made.id, client::Verify::Option(&verify_image))?;
            }
            println!("{}", made.id);
        }
        ContainerCommands::Update {
            set,
            latest,
            container,
        } => {
            let container = one_container(&client, latest, container)?;
            client.update_container(&container, &update_request(*set)?)?;
            println!("{}", client.inspect_container(&container)?.id);
        }
        ContainerCommands::Init { containers, .. } => {
            for c in containers {
                client.init_container(&c)?;
                println!("{c}");
            }
        }
        ContainerCommands::Port {
            all,
            latest,
            container,
            private,
        } => {
            // (with --latest the first argument is the port)
            let (container, private) = if latest {
                (
                    Some(one_container(&client, true, None)?),
                    container.or(private),
                )
            } else {
                (container, private)
            };
            let names: Vec<String> = match (all, container) {
                (true, None) => client
                    .podman_list(client::Kind::Container, false, &[])?
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c["Id"].as_str().map(str::to_string))
                    .collect(),
                (false, Some(c)) => vec![c],
                _ => anyhow::bail!("give one container, or --all"),
            };
            for name in names {
                let c = client.podman_inspect(client::Kind::Container, &name)?;
                // (as podman: only a running container has its ports, one
                // created, paused or stopped lists none, whatever was asked)
                if c.pointer("/State/Status").and_then(|s| s.as_str()) != Some("running") {
                    continue;
                }
                let lines = cli::report::port_lines(&c, private.as_deref());
                if all && !lines.is_empty() {
                    println!(
                        "{}",
                        c["Id"]
                            .as_str()
                            .unwrap_or_default()
                            .chars()
                            .take(12)
                            .collect::<String>()
                    );
                }
                if private.is_some() && lines.is_empty() {
                    eprintln!(
                        "Error: failed to find published port {:?}",
                        private.as_deref().unwrap_or_default()
                    );
                    exit_with(125);
                }
                for l in lines {
                    println!("{l}");
                }
            }
        }
        ContainerCommands::Inspect {
            format: None,
            latest,
            size: false,
            containers,
        } => {
            let containers = inspect_latest(&client, latest, containers, true)?;
            if containers.is_empty() {
                anyhow::bail!("requires at least 1 arg(s), only received 0");
            }
            let mut failed = false;
            for container in containers {
                match client.inspect_container(&container) {
                    Ok(c) => println!("{}", serde_json::to_string_pretty(&c)?),
                    Err(e) => {
                        eprintln!(
                            "Error: {}",
                            cli::report::missing_message(client::Kind::Container, &container, &e)
                        );
                        failed = true;
                    }
                }
            }
            if failed {
                exit_with(125);
            }
        }
        ContainerCommands::Inspect {
            format,
            latest,
            size,
            containers,
        } => {
            let containers = inspect_latest(
                &client,
                latest,
                containers,
                format.as_deref() == Some("json"),
            )?;
            if containers.is_empty() {
                anyhow::bail!("requires at least 1 arg(s), only received 0");
            }
            if !cli::report::inspect(
                &client,
                Some(client::Kind::Container),
                &containers,
                format.as_deref(),
                size,
            )? {
                exit_with(125);
            }
        }
        ContainerCommands::Exec {
            interactive,
            tty,
            env,
            workdir,
            user,
            privileged,
            timeout,
            detach,
            env_file,
            detach_keys,
            latest,
            cidfile,
            no_session,
            container,
            command,
            ..
        } => {
            // (with --latest or --cidfile the first argument is the command)
            let (container, command) = if latest || cidfile.is_some() {
                let mut command = command;
                command.insert(0, container);
                let targets = cli::Targets {
                    latest,
                    cidfile: cidfile.into_iter().collect(),
                    ..Default::default()
                };
                let found = cli::run::select(&client, Vec::new(), false, &targets, false, &[])?;
                let [one] = found.as_slice() else {
                    anyhow::bail!("give one container");
                };
                (one.clone(), command)
            } else {
                (container, command)
            };
            if command.is_empty() {
                anyhow::bail!("must provide a non-empty command to start an exec session");
            }
            let mut env = env;
            for f in &env_file {
                env.extend(cli::run::read_env_file(f)?);
            }
            // a terminal has a type, as podman sets it, unless the
            // container's or the command's environment says it
            if tty && !env.iter().any(|e| e.starts_with("TERM=")) {
                let container_term = client
                    .inspect_container(&container)?
                    .process
                    .env
                    .iter()
                    .any(|e| e.starts_with("TERM="));
                if !container_term {
                    env.push("TERM=xterm".into());
                }
            }
            if interactive || tty || no_session || preserved.is_some() {
                if detach {
                    anyhow::bail!(
                        "--detach cannot be used with --interactive, --tty, --no-session, \
                         --preserve-fd or --preserve-fds"
                    );
                }
                // The streams are those of this process.
                let params = client::ExecParams {
                    command,
                    env,
                    working_dir: workdir,
                    user,
                    tty,
                    privileged,
                    stdin: interactive,
                    detach_keys: cli::run::detach_keys(detach_keys, tty)?,
                    timeout,
                    detach: false,
                };
                let session = client.create_exec(&container, &params)?;
                let (preserved, holes) = preserved.map(|t| (t.fds, t.holes)).unwrap_or_default();
                let size = cli::attach::terminal_size()
                    .filter(|_| tty)
                    .unwrap_or_default();
                let opened = client.open_exec(&session, interactive, size, preserved, holes)?;
                let ended = cli::attach::relay(
                    opened,
                    cli::attach::Relay {
                        tty,
                        input: interactive,
                        // (podman's exec forwards no signal: the command goes
                        // on when its client is interrupted)
                        sig_proxy: false,
                        resize: &|rows, cols| {
                            let _ = client.resize_exec(&session, rows, cols);
                        },
                        signal: &|_| {},
                    },
                )?;
                if ended.detached {
                    // (the command goes on, its session is kept)
                    exit_with(0);
                }
                let code = client.finish_exec(&session)?;
                if timeout.is_some() && code == 124 {
                    eprintln!("Error: the command timed out");
                }
                exit_with(code);
            }
            // (the output as it comes, as podman shows it)
            let result = client.exec_container(
                &container,
                &client::ExecParams {
                    command,
                    env,
                    working_dir: workdir,
                    user,
                    tty,
                    privileged,
                    stdin: false,
                    detach_keys: None,
                    timeout,
                    detach,
                },
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            )?;
            if detach {
                println!("{}", result.session_id);
            }
            if timeout.is_some() && result.exit_code == 124 {
                eprintln!("Error: the command timed out");
            }
            exit_with(result.exit_code);
        }
        ContainerCommands::Attach {
            detach_keys,
            no_stdin,
            sig_proxy,
            latest,
            container,
        } => {
            let container = one_container(&client, latest, container)?;
            let record = client.inspect_container(&container)?;
            // (the REST API's attach waits for the start of a container that
            // is created; the command line's does not)
            if !matches!(
                record.state,
                velarx_proto::workload::RunState::Running
                    | velarx_proto::workload::RunState::Stopping
            ) {
                anyhow::bail!("container {} is not running", record.id);
            }
            let code = attach_session(
                &client,
                &container,
                AttachRequest {
                    tty: record.tty,
                    stdin: !no_stdin && record.stdin,
                    stdout: true,
                    stderr: true,
                    detach_keys,
                    sig_proxy,
                    start: false,
                },
            )?;
            exit_with(code);
        }
        ContainerCommands::Logs {
            follow,
            tail,
            timestamps,
            since,
            until,
            names,
            color,
            latest,
            containers,
        } => {
            let containers = cli::run::named_or_latest(&client, latest, containers)?;
            if containers.is_empty() {
                anyhow::bail!("requires at least 1 arg(s), only received 0");
            }
            let tail = tail.filter(|t| *t >= 0).map(|t| t as usize);
            let opts = LogsOptions {
                follow,
                tail,
                timestamps,
                since,
                until,
                events_logger: velarx_config::Config::load_or_default(&inv.global.config)
                    .ok()
                    .map(|c| c.server.effective_events_logger().to_string()),
            };
            if let ([c], true) = (containers.as_slice(), color) {
                let mut out = PrefixLines::new(String::new(), false, Some(0));
                let mut err = PrefixLines::new(String::new(), true, Some(0));
                show_logs(&client, c, &opts, &mut out, &mut err)?;
            } else if let [c] = containers.as_slice() {
                let (out, err) = (&mut std::io::stdout().lock(), &mut std::io::stderr().lock());
                show_logs(&client, c, &opts, out, err)?;
            } else {
                // podman's: the lines of each container start with its ID
                // (its name with --names), the containers read together
                let client = &client;
                let opts = &opts;
                let failed = std::thread::scope(|scope| {
                    let mut threads = Vec::new();
                    for (n, c) in containers.into_iter().enumerate() {
                        let color = color.then_some(n);
                        let prefix = if names {
                            c.clone()
                        } else {
                            let id = client.inspect_container(&c).map(|v| v.id);
                            id.unwrap_or_else(|_| c.clone()).chars().take(12).collect()
                        };
                        threads.push(scope.spawn(move || -> anyhow::Result<()> {
                            let mut out = PrefixLines::new(prefix.clone(), false, color);
                            let mut err = PrefixLines::new(prefix, true, color);
                            show_logs(client, &c, opts, &mut out, &mut err)
                        }));
                    }
                    let mut failed = None;
                    for t in threads {
                        match t.join() {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => failed = Some(e),
                            Err(_) => failed = Some(anyhow::anyhow!("reading the logs failed")),
                        }
                    }
                    failed
                });
                if let Some(e) = failed {
                    return Err(e);
                }
            }
        }
        ContainerCommands::ReopenLog { container } => {
            client.reopen_container_log(&container)?;
            println!("{}", container);
        }
        ContainerCommands::Wait {
            condition,
            ignore,
            interval,
            exit_first_match,
            containers,
            ..
        } => cli::run::wait_condition(
            &client,
            &containers,
            &cli::run::WaitArgs {
                conditions: &condition,
                interval: &interval,
                ignore,
                exit_first_match,
            },
        )?,
        ContainerCommands::Cp {
            archive,
            overwrite,
            src,
            dest,
        } => cli::cp::run(
            &client,
            &src,
            &dest,
            &client::ArchivePut {
                overwrite,
                chown: archive,
                ..Default::default()
            },
        )?,
        ContainerCommands::Stats {
            all,
            no_stream,
            format,
            latest,
            view,
            containers,
        } => {
            let containers = cli::run::named_or_latest(&client, latest, containers)?;
            run_stats_command(inv, all, no_stream, format, containers, &view)?
        }
        ContainerCommands::Top {
            latest,
            container,
            ps_args,
        } => {
            // (with --latest every argument is a ps option)
            let (container, ps_args) = if latest {
                let mut ps_args = ps_args;
                ps_args.splice(0..0, container);
                (one_container(&client, true, None)?, ps_args)
            } else {
                (one_container(&client, false, container)?, ps_args)
            };
            let result = client.container_top(&container, &ps_args)?;
            let mut text = format!("{}\n", result.titles.join("\t"));
            for proc in &result.processes {
                text.push_str(&format!("{}\n", proc.join("\t")));
            }
            print!("{}", cli::template::align_text(&text));
        }
        ContainerCommands::Diff {
            format,
            latest,
            container,
        } => {
            let container = one_container(&client, latest, container)?;
            print_changes(&client.container_changes(&container)?, format.as_deref())?
        }
        ContainerCommands::Pause { containers, .. } => {
            cli::run::each_named_as(&containers, false, &cli::run::Statuses::CONTAINER, |c| {
                client.pause_container(c)
            })?
        }
        ContainerCommands::Unpause { containers, .. } => {
            cli::run::each_named_as(&containers, false, &cli::run::Statuses::CONTAINER, |c| {
                client.unpause_container(c)
            })?
        }
        ContainerCommands::Rename {
            container,
            new_name,
        } => {
            client.rename_container(&container, &new_name)?;
            println!("{}", new_name);
        }
        cmd @ (ContainerCommands::Run { .. } | ContainerCommands::Create { .. }) => {
            let args = RunContainerArgs::from_command(cmd)
                .map_err(|_| anyhow::anyhow!("not a run command"))?;
            exit_with(run_container(&client, args)?);
        }
        // (velarx-client leaves them to velarx: `main_as`)
        ContainerCommands::Checkpoint(ref args) => cli::checkpoint::checkpoint(&client, args)?,
        ContainerCommands::Restore(ref args) => cli::checkpoint::restore(&client, args)?,
    }

    Ok(())
}

/// Format bytes in a compact form (e.g., "1.5G", "256M")
/// `key=value` arguments; a key alone has an empty value.
pub(super) fn parse_pairs(args: &[String]) -> std::collections::HashMap<String, String> {
    args.iter()
        .map(|a| match a.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (a.clone(), String::new()),
        })
        .collect()
}

/// `diff`: the changes as `C /path` lines, or with `--format json`
/// podman's {"changed": [...], "added": [...], "deleted": [...]}.
pub(super) fn print_changes(
    changes: &[client::FileChange],
    format: Option<&str>,
) -> anyhow::Result<()> {
    match format {
        Some("json") => {
            let mut by: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
            for c in changes {
                let key = match c.letter() {
                    'C' => "changed",
                    'A' => "added",
                    _ => "deleted",
                };
                by.entry(key).or_default().push(&c.path);
            }
            println!("{}", serde_json::to_string_pretty(&by)?);
        }
        Some(_) => anyhow::bail!("only supported value for '--format' is 'json'"),
        None => {
            for change in changes {
                println!("{} {}", change.letter(), change.path);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(f: impl FnOnce(&mut cli::UpdateArgs)) -> anyhow::Result<UpdateSpec> {
        let mut a = cli::UpdateArgs::default();
        f(&mut a);
        update_request(a)
    }

    /// `update` asks for typed changes: sizes in bytes, a memory limit with
    /// the swap podman gives it, devices by path, `host` ulimits as none,
    /// the times of the health check in nanoseconds, a restart policy
    /// checked.
    #[test]
    fn the_flags_of_update_are_a_typed_request() {
        let spec = args(|a| {
            a.memory = Some("48m".into());
            a.cpus = Some(1.5);
            a.pids_limit = Some(50);
            a.blkio_weight = Some(300);
            a.device_read_bps = vec!["/dev/sda:1mb".into()];
            a.device_write_iops = vec!["/dev/sda:100".into()];
            a.ulimit = vec!["nofile=1000:2000".into()];
            a.health_cmd = Some("echo ok".into());
            a.health_interval = Some("7s".into());
            a.health_timeout = Some("disable".into());
            a.restart = Some("on-failure:3".into());
            a.env = vec!["A=1".into()];
        })
        .unwrap();
        assert_eq!(
            (spec.memory, spec.memory_swap),
            (Some(48 << 20), Some(96 << 20))
        );
        assert_eq!(
            (spec.cpu_period, spec.cpu_quota),
            (Some(100_000), Some(150_000))
        );
        assert_eq!(
            (spec.pids_limit, spec.block_io.weight),
            (Some(50), Some(300))
        );
        assert_eq!(
            spec.block_io.read_bps,
            [UpdateDevice {
                path: Some("/dev/sda".into()),
                value: 1 << 20,
                ..Default::default()
            }]
        );
        assert_eq!(spec.block_io.write_iops[0].value, 100);
        let limits = spec.ulimits.unwrap();
        assert_eq!(
            (limits[0].name.as_str(), limits[0].soft, limits[0].hard),
            ("nofile", 1000, 2000)
        );
        let health = spec.health.unwrap();
        assert_eq!(
            (health.cmd.as_deref(), health.interval, health.timeout),
            (Some("echo ok"), Some(7_000_000_000), Some(0))
        );
        let restart = spec.restart.unwrap();
        assert_eq!(
            (restart.name.as_str(), restart.maximum_retry_count),
            ("on-failure", 3)
        );
        assert_eq!(spec.env, ["A=1"]);
        // nothing asked is nothing changed
        assert_eq!(args(|_| {}).unwrap(), UpdateSpec::default());
        // `--ulimit host` is the host's: an empty list, not none
        assert_eq!(
            args(|a| a.ulimit = vec!["host".into()]).unwrap().ulimits,
            Some(vec![])
        );
        // the refusals are podman's, before the engine is asked
        for bad in [
            |a: &mut cli::UpdateArgs| a.device_read_bps = vec!["nodevice".into()],
            |a: &mut cli::UpdateArgs| a.device_read_iops = vec!["/dev/sda:0".into()],
            |a: &mut cli::UpdateArgs| a.health_interval = Some("ten".into()),
            |a: &mut cli::UpdateArgs| a.restart = Some("sometimes".into()),
        ] {
            assert!(args(bad).is_err());
        }
    }
}
