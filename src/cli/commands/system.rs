// SPDX-License-Identifier: Apache-2.0
use super::*;

pub(super) fn run_info(inv: &Invocation<'_>, format: Option<&str>) -> anyhow::Result<()> {
    let system = get_client(inv)?.system_inspect()?;
    if let Some(format) = format {
        // podman's information, as its templates know it
        let socket = get_socket_path(inv.global)?;
        let info = velarx_shape::system::libpod_info(
            &system,
            Some((&socket.to_string_lossy(), socket.exists())),
        );
        return cli::report::info(&info, format);
    }
    // (podman's document as its YAML)
    let socket = get_socket_path(inv.global)?;
    let info = velarx_shape::system::libpod_info(
        &system,
        Some((&socket.to_string_lossy(), socket.exists())),
    );
    print!("{}", cli::report::go_yaml(&info));
    // (as podman warns: the systemd cgroup manager of the configuration
    // cannot be used without the user's manager; lingering off, the
    // default, is only in the document)
    if let Some(s) = system.host.systemd.as_ref().filter(|s| {
        !s.user_manager
            && system.host.cgroup_manager == velarx_proto::system::CgroupManager::Systemd
    }) {
        eprintln!("WARN: {}", s.warning);
    }
    Ok(())
}

pub(super) fn run_health(inv: &Invocation<'_>) -> anyhow::Result<()> {
    let health = server(inv)?.health()?;
    // (velarx's words: the status capitalized)
    let word = |s: velarx_proto::system::ComponentStatus| match s {
        velarx_proto::system::ComponentStatus::Healthy => "Healthy",
        velarx_proto::system::ComponentStatus::Degraded => "Degraded",
        velarx_proto::system::ComponentStatus::Unhealthy => "Unhealthy",
    };
    let shown = serde_json::json!({
        "overall": word(health.overall),
        "components": health.components.iter().map(|c| serde_json::json!({
            "name": c.name,
            "status": word(c.status),
            "message": c.message,
        })).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&shown)?);
    Ok(())
}

pub(super) fn run_healthcheck_command(
    cmd: HealthcheckCommands,
    inv: &Invocation<'_>,
) -> anyhow::Result<()> {
    let client = get_client(inv)?;

    match cmd {
        HealthcheckCommands::Run { container } => {
            // podman's: nothing when it passes, `unhealthy` and 1 when not
            let health = client.healthcheck_run(&container)?;
            if health.status == velarx_proto::health::HealthStatus::Stopped {
                println!("stopped");
                exit_with(1);
            }
            if health.log.last().is_some_and(|r| r.exit_code != 0) {
                println!("unhealthy");
                exit_with(1);
            }
        }
        HealthcheckCommands::Ls { all } => {
            println!(
                "{:<15} {:<30} {:<12} {:>10} {:>20}",
                "CONTAINER ID", "NAME", "STATUS", "FAILURES", "LAST CHECK"
            );
            for c in client.list_containers(all, &[], false, false)? {
                if c.process.healthcheck.is_none() && !all {
                    continue;
                }
                println!(
                    "{:<15} {:<30} {:<12} {:>10} {:>20}",
                    &c.id[..12.min(c.id.len())],
                    health_name(&c),
                    health_status(&c),
                    c.health.as_ref().map_or(0, |h| h.failing_streak),
                    c.health
                        .as_ref()
                        .and_then(|h| h.log.last())
                        .map_or("never".to_string(), |r| {
                            velarx_wire::monitor::logfmt::format_rfc3339_ns(r.end_ns)
                        }),
                );
            }
        }
        HealthcheckCommands::Inspect { container } => {
            let c = client.inspect_container(&container)?;
            println!("Container ID: {}", c.id);
            println!("Container Name: {}", health_name(&c));
            println!("Status: {}", health_status(&c));
            println!(
                "Failure Count: {}",
                c.health.as_ref().map_or(0, |h| h.failing_streak)
            );
            if let Some(config) = &c.process.healthcheck {
                println!("\nHealth Check Config:");
                println!("  Command: {:?}", config.test);
                println!("  Interval: {}ns", config.interval_ns);
                println!("  Timeout: {}ns", config.timeout_ns);
                println!("  Start Period: {}ns", config.start_period_ns);
                println!("  Retries: {}", config.retries);
                if config.on_failure != velarx_proto::health::OnFailure::None {
                    println!("  On Failure: {}", config.on_failure.word());
                }
            }
            let history = c.health.as_ref().map(|h| h.log.as_slice()).unwrap_or(&[]);
            if !history.is_empty() {
                println!("\nHistory:");
                for entry in history.iter().rev().take(5) {
                    println!(
                        "  {} - Exit: {}, Duration: {}ms",
                        velarx_wire::monitor::logfmt::format_rfc3339_ns(entry.start_ns),
                        entry.exit_code,
                        (entry.end_ns.saturating_sub(entry.start_ns) / 1_000_000).max(0)
                    );
                }
            }
        }
    }

    Ok(())
}

/// The name of a container in the lists of the health checks (the start
/// of its ID without one).
fn health_name(c: &velarx_proto::workload::ContainerRecord) -> &str {
    if c.name.is_empty() {
        &c.id[..12.min(c.id.len())]
    } else {
        &c.name
    }
}

/// The health of a container: of its last check, `starting` before one,
/// `none` without a check.
fn health_status(c: &velarx_proto::workload::ContainerRecord) -> &'static str {
    match (&c.health, &c.process.healthcheck) {
        (Some(h), _) => h.status.word(),
        (None, Some(_)) => "starting",
        (None, None) => "none",
    }
}

pub(super) fn run_system_command(cmd: SystemCommands, inv: &Invocation<'_>) -> anyhow::Result<()> {
    let client = get_client(inv)?;

    match cmd {
        SystemCommands::Restart => {
            server(inv)?.restart_server()?;
            println!("The engine service restarts");
        }
        SystemCommands::Df { verbose, format } => {
            cli::report::system_df(&client, verbose, format.as_deref())?;
            if verbose {
                // what velarx's store has besides podman's
                let usage = client.disk_usage(true)?;
                let mut text = String::from("TYPE\tCOUNT\tSIZE\tRECLAIMABLE\n");
                let artifacts = {
                    let mut name = usage.driver.clone();
                    if let Some(first) = name.get_mut(..1) {
                        first.make_ascii_uppercase();
                    }
                    name
                };
                for (kind, s) in [
                    ("Objects", usage.objects.unwrap_or_default()),
                    (artifacts.as_str(), usage.composefs.unwrap_or_default()),
                    // (the lazy pulls in progress, `velarx image pulls`)
                    ("Pulling", usage.pulling.unwrap_or_default()),
                ] {
                    text.push_str(&format!(
                        "{kind}\t{}\t{}\t{}\n",
                        s.count,
                        cli::report::go_size(s.size as f64),
                        s.reclaimable
                            .map_or("-".to_string(), |r| cli::report::go_size(r as f64))
                    ));
                }
                print!(
                    "\nStore space usage:\n\n{}",
                    cli::template::align_text(&text)
                );
            }
        }
        SystemCommands::Prune {
            all,
            volumes,
            build,
            external,
            force,
            filter,
        } => {
            if external {
                if all || volumes || build || !filter.is_empty() {
                    anyhow::bail!("system prune --external cannot be combined with other options");
                }
                client.system_collect(false, true, true)?;
                return Ok(());
            }
            if !force {
                eprintln!("WARNING! This will remove:");
                eprintln!("  - all stopped containers");
                eprintln!("  - all networks not used by at least one container");
                if all {
                    eprintln!("  - all images without at least one container associated to them");
                } else {
                    eprintln!("  - all dangling images");
                }
                if volumes {
                    eprintln!("  - all volumes not used by at least one container");
                }
                if build {
                    eprintln!("  - all build containers");
                }
                eprintln!("Are you sure you want to continue? [y/N] ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let report = client.system_prune(all, volumes, build, &filter)?;
            let images: Vec<&String> = report.images.iter().map(|i| &i.id).collect();
            let volumes: Vec<&String> = report.volumes.iter().map(|v| &v.name).collect();
            for (what, removed) in [
                ("Containers", report.containers.iter().collect::<Vec<_>>()),
                ("Images", images),
                ("Volumes", volumes),
                ("Networks", report.networks.iter().collect()),
            ] {
                if !removed.is_empty() {
                    println!("Deleted {what}:");
                    for id in removed {
                        println!("  {id}");
                    }
                }
            }
            println!("Total reclaimed space: {}", format_bytes(report.reclaimed));
        }
        SystemCommands::Gc {
            dry_run,
            files,
            layers,
        } => {
            let report = client.system_collect(dry_run, files, layers)?;

            if dry_run {
                println!("Dry run - no changes made");
            }
            println!("Garbage collection complete:");
            println!("  Files removed:  {}", report.files_removed);
            println!("  Layers removed: {}", report.layers_removed);
            println!("  Bytes freed:    {}", format_bytes(report.bytes_freed));

            if !report.errors.is_empty() {
                println!("\nErrors encountered:");
                for err in &report.errors {
                    println!("  - {}", err);
                }
            }
        }
        SystemCommands::Stores { drop } => {
            let report = client.system_stores(drop.as_deref())?;
            if let Some(id) = &report.dropped {
                println!("Dropped the store {id}");
            }
            println!("{:<34}{:>12}  LAST OPENED", "STORE", "SIZE");
            for s in &report.stores {
                let last = match s.last_open_ns {
                    0 => "unknown".to_string(),
                    t => velarx_wire::monitor::logfmt::format_rfc3339_ns(t),
                };
                println!(
                    "{:<34}{:>12}  {last}{}",
                    s.store,
                    format_bytes(s.size),
                    if s.current { "  (this engine)" } else { "" }
                );
            }
        }
        SystemCommands::Info { format } => {
            drop(client);
            run_info(inv, format.as_deref())?
        }
        SystemCommands::Inspect {
            r#type,
            format,
            latest,
            size,
            objects,
        } => {
            let Some(kind) = cli::report::kind_of_type(&r#type) else {
                anyhow::bail!("invalid type {type:?}: container, image, volume, network, pod or all", type = r#type);
            };
            // (podman's -l: the pod made last for pods, the container made
            // last for containers and all; none of the volumes and networks)
            let (kind, objects) = if latest {
                match kind {
                    Some(client::Kind::Image) => {
                        anyhow::bail!("latest is not supported for type \"image\"")
                    }
                    Some(client::Kind::Volume | client::Kind::Network) => {
                        println!("[]");
                        return Ok(());
                    }
                    Some(client::Kind::Pod) => (
                        kind,
                        cli::run::named_or_latest_of(&client, client::Kind::Pod, true, objects)?,
                    ),
                    _ => (
                        Some(client::Kind::Container),
                        inspect_latest(
                            &client,
                            true,
                            objects,
                            matches!(format.as_deref(), None | Some("json")),
                        )?,
                    ),
                }
            } else if objects.is_empty() {
                anyhow::bail!("requires at least 1 arg(s), only received 0");
            } else {
                (kind, objects)
            };
            if !cli::report::inspect(&client, kind, &objects, format.as_deref(), size)? {
                exit_with(125);
            }
        }
        SystemCommands::Check {
            quick,
            repair,
            force,
            max,
            timeout,
            format,
        } => {
            let max_age_ms = match max {
                Some(m) => Some(
                    velarx_proto::duration::parse_go_duration(&m)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "invalid argument {m:?} for \"-m, --max\" flag: time: invalid duration {m:?}"
                            )
                        })?
                        .as_millis() as u64,
                ),
                None => None,
            };
            let timeout_ms = match timeout {
                Some(t) => Some(
                    client::policy::parse_duration(&t)
                        .map_err(|e| anyhow::anyhow!("--timeout: {e}"))?
                        .as_millis() as u64,
                ),
                None => None,
            };
            let spec = velarx_proto::system::CheckSpec {
                quick,
                repair,
                repair_lossy: repair && force,
                timeout_ms,
                max_age_ms,
            };
            let report = client.system_check(&spec)?;
            if format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&velarx_shape::system::check(&report))?
                );
            } else {
                print!("{}", check_text(&report));
            }
            if !report.ok() {
                // (objects without the fs-verity the store requires are whole)
                let undamaged = report
                    .problems
                    .iter()
                    .filter(|p| p.open())
                    .all(|p| !velarx_proto::system::kind_damages(&p.kind));
                anyhow::bail!(match (repair || force, undamaged) {
                    (true, true) => "local storage still needs repair after repair attempt",
                    (true, false) => "damage in local storage still present after repair attempt",
                    (false, true) => "local storage needs repair",
                    (false, false) => "damage detected in local storage",
                });
            }
        }
    }

    Ok(())
}

/// The 12 first digits of an image id, as the commands show it.
pub(super) fn short_id(id: &str) -> &str {
    &id[..12.min(id.len())]
}

/// What podman prints of a check that found damage (nothing when it found
/// none): the report of `CheckReport::podman`, a heading per damaged layer,
/// image and container, and a line per thing removed.
pub(super) fn check_text(report: &velarx_proto::system::CheckReport) -> String {
    let shape = velarx_shape::system::check(report);
    let mut out = String::new();
    let damaged = |out: &mut String, key: &str, heading: &str| {
        let Some(map) = shape[key].as_object() else {
            return;
        };
        for (id, errors) in map {
            let errors: Vec<&str> = errors
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| e.as_str())
                .collect();
            if errors.is_empty() {
                continue;
            }
            // (go-multierror's list)
            out.push_str(&format!(
                "{heading} {id}:\n{} error{} occurred:\n\t* {}\n\n",
                errors.len(),
                if errors.len() == 1 { "" } else { "s" },
                errors.join("\n\t* ")
            ));
        }
    };
    damaged(&mut out, "Layers", "Damaged layer");
    for layer in shape["RemovedLayers"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "Deleted damaged layer: {}\n",
            layer.as_str().unwrap_or_default()
        ));
    }
    damaged(&mut out, "Images", "Damaged image");
    for id in shape["RemovedImages"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k)
    {
        out.push_str(&format!("Deleted damaged image: {id}\n"));
    }
    damaged(&mut out, "Containers", "Damaged container");
    for id in shape["RemovedContainers"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k)
    {
        out.push_str(&format!("Deleted damaged container: {id}\n"));
    }
    out
}

pub(super) fn run_events_command(
    inv: &Invocation<'_>,
    since: Option<String>,
    until: Option<String>,
    filter: Vec<String>,
    format: cli::events::Format,
    stream: bool,
) -> anyhow::Result<()> {
    // (podman's times: RFC 3339, seconds since the epoch, how long ago)
    use velarx_proto::time::Toward;
    let now = velarx_shape::time::now_ns();
    let time = |given: Option<String>, what: &str, toward| -> anyhow::Result<Option<i64>> {
        match given.filter(|s| !s.is_empty()) {
            None => Ok(None),
            Some(s) => velarx_proto::time::parse_input_time(&s, now, toward, false)
                .map(Some)
                .ok_or_else(|| {
                    anyhow::anyhow!("failed to parse event filters: invalid {what} `{s}`")
                }),
        }
    };
    let (since, until) = (
        time(since, "since", Toward::Past)?,
        time(until, "until", Toward::Future)?,
    );

    let print = |event: &velarx_proto::workload::Event| -> anyhow::Result<()> {
        use std::io::Write;
        match writeln!(std::io::stdout(), "{}", format.render(event)) {
            // a closed stdout (`| head`) ends the command, as podman's
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => std::process::exit(0),
            r => Ok(r?),
        }
    };

    let client = get_client(inv)?;
    if stream {
        let mut result = Ok(());
        let mut each = |event| {
            result = print(&event);
            result.is_ok()
        };
        client.follow_events(&filter, since, until, &mut each)?;
        return result;
    }
    for event in client.events(&filter, since, until)? {
        print(&event)?;
    }
    Ok(())
}

pub(super) fn run_stats_command(
    inv: &Invocation<'_>,
    all: bool,
    no_stream: bool,
    format: Option<String>,
    containers: Vec<String>,
    view: &cli::StatsView,
) -> anyhow::Result<()> {
    let client = get_client(inv)?;
    let format = format.filter(|f| !f.is_empty());
    // podman's running average of the CPU use of each container
    let mut avg = std::collections::HashMap::new();
    let mut printed = Ok(());
    client.container_stats(
        &containers,
        all,
        !no_stream,
        view.interval.saturating_mul(1000),
        &mut |sample| {
            printed = print_stats(&sample, format.as_deref(), no_stream, view, &mut avg);
            printed.is_ok()
        },
    )?;
    printed
}

/// A sample as `stats` prints it: podman's table, its list (`json`), or a
/// template of its fields.
fn print_stats(
    sample: &[velarx_proto::workload::StatsRecord],
    format: Option<&str>,
    no_stream: bool,
    view: &cli::StatsView,
    avg: &mut std::collections::HashMap<String, (f64, u32)>,
) -> anyhow::Result<()> {
    if !no_stream && !view.no_reset {
        print!("\x1B[2J\x1B[1;1H"); // Clear screen
    }
    let headers = std::collections::HashMap::from([
        ("ID", "ID"),
        ("UpTime", "CPU TIME"),
        ("CPUPerc", "CPU %"),
        ("AVGCPU", "AVG CPU %"),
        ("MemUsage", "MEM USAGE / LIMIT"),
        ("MemUsageBytes", "MEM USAGE / LIMIT"),
        ("MemPerc", "MEM %"),
        ("NetIO", "NET IO"),
        ("BlockIO", "BLOCK IO"),
        ("PIDS", "PIDS"),
    ]);
    let items: Vec<serde_json::Value> = sample
        .iter()
        .map(|s| {
            let (a, n) = avg.entry(s.id.clone()).or_insert((0.0f64, 0u32));
            *a = (*a * f64::from(*n) + s.cpu_percent) / f64::from(*n + 1);
            *n += 1;
            cli::report::stats_fields(s, *a, view.no_trunc)
        })
        .collect();
    match format {
        Some("json") => println!("{}", cli::report::stats_json(&items)?),
        f => {
            let template = f.unwrap_or(
                "table {{.ID}}\t{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDS}}\t{{.UpTime}}\t{{.AVGCPU}}",
            );
            let text = cli::template::format_list(template, &items, &headers)
                .map_err(|e| anyhow::anyhow!("--format: {e}"))?;
            print!("{text}");
        }
    }
    Ok(())
}
