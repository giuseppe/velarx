// SPDX-License-Identifier: Apache-2.0
use super::*;
use velarx_proto::modes::{CgroupMode, CgroupsMode, UsernsChoice};
use velarx_proto::pod::{
    IdMapping, PodAction, PodDnsConfig, PodExitPolicy, PodPortMapping, PodSpec, RestartPolicy,
};

pub(super) fn run_pod_command(cmd: PodCommands, inv: &Invocation<'_>) -> anyhow::Result<()> {
    let client = get_client(inv)?;

    match cmd {
        PodCommands::Create {
            name,
            name_opt,
            infra,
            hostname,
            network,
            dns,
            dns_search,
            dns_option,
            add_host,
            publish,
            share_pid,
            userns,
            infra_image,
            label,
            replace,
            infra_name,
            exit_policy,
            infra_conmon_pidfile,
            share,
            infra_command,
            uidmap,
            gidmap,
            sysctl,
            shm_size,
            volume,
            restart,
            cgroup_parent,
            cgroups,
            security_opt,
            ip,
            ip6,
            network_alias,
            device,
            gpus,
            volumes_from,
            hosts_file,
            no_hosts,
            no_hostname,
            mac_address,
            pid,
            uts,
            subuidname,
            subgidname,
            share_parent,
            pod_id_file,
            label_file,
            shm_size_systemd,
            limits,
            ..
        } => {
            // podman's: a pod that shares no namespace needs no infra
            // container, and what only one can have is refused without it
            let infra = infra.unwrap_or(!matches!(share.as_deref(), Some("none" | "")));
            if !infra {
                let given = [
                    (
                        no_hosts,
                        "cannot specify --no-hosts without an infra container",
                    ),
                    (
                        ip.is_some(),
                        "cannot set --ip without infra container: invalid argument",
                    ),
                    (
                        ip6.is_some(),
                        "cannot set --ip6 without infra container: invalid argument",
                    ),
                    (
                        mac_address.is_some(),
                        "cannot set --mac without infra container: invalid argument",
                    ),
                    (
                        !network_alias.is_empty(),
                        "cannot set --network-alias without infra container: invalid argument",
                    ),
                ];
                if let Some((_, why)) = given.iter().find(|(on, _)| *on) {
                    anyhow::bail!("{why}");
                }
                if let Some(s) = share.as_deref().filter(|s| !matches!(*s, "none" | "")) {
                    anyhow::bail!("cannot set share({s}) namespaces without an infra container");
                }
                if !publish.is_empty() {
                    anyhow::bail!(
                        "you must have an infra container to publish port bindings to the host"
                    );
                }
            }
            // (a relative base hosts file is the caller's, as podman opens it)
            let hosts_file = match hosts_file.as_deref() {
                Some(f) if !matches!(f, "" | "none" | "image") && !f.starts_with('/') => {
                    Some(std::env::current_dir()?.join(f).display().to_string())
                }
                _ => hosts_file,
            };
            let mut spec = PodSpec {
                // (none: the engine names it)
                name: name.or(name_opt).unwrap_or_default(),
                hostname,
                networks: network,
                dns: PodDnsConfig {
                    servers: dns,
                    searches: dns_search,
                    options: dns_option,
                },
                add_hosts: add_host,
                share_pid,
                share_ipc: true,
                share_net: true,
                share_uts: true,
                userns: userns
                    .as_deref()
                    .map(|u| u.parse().map_err(|e| anyhow::anyhow!("--userns: {e}")))
                    .transpose()?,
                // (podman's command line takes the options of the infra
                // container only with one)
                infra_image: infra_image.filter(|_| infra),
                resources: pod_resources(&limits)?,
                labels: pod_labels(&label, &label_file)?.into_iter().collect(),
                infra_name,
                exit_policy: match exit_policy.as_deref() {
                    Some("stop") => PodExitPolicy::Stop,
                    Some("continue") | None => PodExitPolicy::Continue,
                    Some(other) => anyhow::bail!(
                        "running pod create option: invalid pod exit policy: \"{other}\""
                    ),
                },
                infra_conmon_pidfile: cli::PidFileArgs {
                    conmon_pidfile: infra_conmon_pidfile.filter(|_| infra),
                    ..Default::default()
                }
                .absolute()?
                .1,
                infra_command: infra_command
                    .filter(|_| infra)
                    .map(|c| c.split_whitespace().map(str::to_string).collect())
                    .filter(|c: &Vec<String>| !c.is_empty()),
                volumes: volume,
                security_opts: security_opt,
                network_aliases: network_alias,
                cgroup_parent: cgroup_parent.filter(|c| !c.is_empty()),
                cgroups: cgroups
                    .as_deref()
                    .map(|c| c.parse().map_err(|e| anyhow::anyhow!("--cgroups: {e}")))
                    .transpose()?
                    .unwrap_or_default(),
                ip: ip.filter(|i| !i.is_empty()),
                ip6: ip6.filter(|i| !i.is_empty()),
                devices: device
                    .into_iter()
                    .chain(gpus.iter().map(|g| format!("nvidia.com/gpu={g}")))
                    .collect(),
                // (the engine adds their volumes to the pod's)
                volumes_from,
                hosts_file: hosts_file.filter(|h| !h.is_empty()),
                no_hosts,
                no_hostname,
                no_infra: !infra,
                no_share_parent: share_parent == Some(false),
                subuidname: subuidname.filter(|n| !n.is_empty()),
                subgidname: subgidname.filter(|n| !n.is_empty()),
                create_command: std::env::args().collect(),
                ..PodSpec::default()
            };
            for p in &publish {
                for pm in parse_port_mapping(p)? {
                    spec.ports.push(PodPortMapping {
                        container_port: pm.container_port,
                        host_port: pm.host_port,
                        host_ip: (!pm.host_ip.is_empty()).then_some(pm.host_ip),
                        protocol: if pm.protocol.is_empty() {
                            "tcp".to_string()
                        } else {
                            pm.protocol
                        },
                    });
                }
            }
            if let Some(share) = share.as_deref().filter(|_| infra) {
                apply_share(&mut spec, share)?;
            }
            apply_namespaces(&mut spec, pid.as_deref(), uts.as_deref())?;
            if (spec.subuidname.is_some() || spec.subgidname.is_some())
                && (spec.userns.is_some() || !uidmap.is_empty() || !gidmap.is_empty())
            {
                anyhow::bail!(
                    "--userns and --uidmap/--gidmap/--subuidname/--subgidname are mutually exclusive"
                );
            }
            apply_id_maps(&mut spec, &uidmap, &gidmap)?;
            if spec.subuidname.is_some() || spec.subgidname.is_some() {
                spec.userns = Some(UsernsChoice::Private);
            }
            if let Some(mac) = mac_address.as_deref().filter(|m| !m.is_empty()) {
                spec.mac = Some(check_mac(mac)?);
            }
            apply_sysctls(&mut spec, &sysctl)?;
            apply_shm_sizes(&mut spec, shm_size.as_deref(), shm_size_systemd.as_deref())?;
            if let Some(r) = &restart {
                spec.restart_policy = Some(restart_policy(r)?);
            }
            if replace && !spec.name.is_empty() {
                match client.remove_pod(&spec.name, true, None) {
                    Err(e) if !e.is_not_found() => return Err(e.into()),
                    _ => {}
                }
            }

            // (opened first: a pod is not left behind for a file that cannot
            // be; a file that was there is not truncated, nor removed, when
            // the pod is not made)
            let id_file = pod_id_file
                .as_deref()
                .map(|f| {
                    let existed = std::fs::symlink_metadata(f).is_ok();
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(f)
                        .map(|file| (file, existed))
                        .map_err(|e| anyhow::anyhow!("open {f}: {}", io_text(&e)))
                })
                .transpose()?;
            let id = match client.create_pod(&spec) {
                Ok(id) => id,
                Err(e) => {
                    if let (Some(f), Some((_, false))) = (&pod_id_file, &id_file) {
                        let _ = std::fs::remove_file(f);
                    }
                    return Err(e.into());
                }
            };
            if let Some((file, _)) = id_file {
                use std::io::Write;
                file.set_len(0)?;
                (&file).write_all(id.as_bytes())?;
            }
            println!("{id}");
        }
        PodCommands::Clone {
            destroy,
            start,
            name,
            hostname,
            infra_name,
            label,
            label_file,
            cgroup_parent,
            device,
            gpus,
            gidmap,
            uidmap,
            infra_command,
            infra_conmon_pidfile,
            pid,
            uts,
            userns,
            restart,
            security_opt,
            shm_size,
            shm_size_systemd,
            subgidname,
            subuidname,
            sysctl,
            volume,
            volumes_from,
            limits,
            pods,
            ..
        } => {
            let options = CloneOptions {
                cgroup_parent,
                device,
                gpus,
                gidmap,
                uidmap,
                infra_command,
                infra_conmon_pidfile,
                pid,
                uts,
                userns,
                restart,
                security_opt,
                shm_size,
                shm_size_systemd,
                subgidname,
                subuidname,
                sysctl,
                volume,
                volumes_from,
                resources: pod_resources(&limits)?,
            };
            let mut pods = pods.into_iter();
            let pod = pods.next().unwrap_or_default();
            let name = match (name, pods.next()) {
                (Some(_), Some(_)) => anyhow::bail!("cannot set --name and the name argument"),
                (Some(n), None) | (None, Some(n)) => n,
                // (podman's NAME-clone)
                (None, None) => String::new(),
            };
            let id = clone_pod(
                &client,
                &pod,
                name,
                hostname,
                infra_name,
                pod_labels(&label, &label_file)?,
                &options,
            )?;
            if destroy {
                client.remove_pod(&pod, true, None)?;
            }
            if start {
                client.run_pod(&id, PodAction::Start, None, None, &[])?;
            }
            println!("{id}");
        }
        PodCommands::Update { limits, pod } => {
            let id = client.update_pod(&pod, &pod_resources(&limits)?.unwrap_or_default())?;
            println!("{id}");
        }
        PodCommands::List { all: _, out, ps } => cli::report::pods(&client, &out, &ps)?,
        PodCommands::Restart {
            verify_image,
            targets,
            pods,
        } => {
            let all = targets.all;
            let pods = pod_ids(
                &client,
                cli::run::select_pods(&client, pods, &targets, &[])?,
            );
            one_pod_for_digests(&verify_image, all, pods.len())?;
            let mut failed = false;
            cli::run::each_item(
                pods,
                |pod| {
                    client
                        .run_pod(pod, PodAction::Restart, None, None, &verify_image)
                        .map(|()| println!("{pod}"))
                },
                |_, e| {
                    eprintln!("Error: {e}");
                    failed = true;
                },
            )?;
            if failed {
                exit_with(125);
            }
        }
        PodCommands::Inspect {
            format,
            latest,
            pods,
        } => {
            let pods = inspected(&client, latest.latest, pods)?;
            inspect_as_podman(&client, client::Kind::Pod, &pods, format.as_deref())?
        }
        PodCommands::Start {
            verify_image,
            targets,
            pod_id_file,
            pods,
        } => {
            let all = targets.all;
            let pods = cli::run::select_pods(&client, pods, &targets, &pod_id_file)?;
            one_pod_for_digests(&verify_image, all, pods.len())?;
            each_pod(pods, |pod| {
                client.run_pod(pod, PodAction::Start, None, None, &verify_image)
            })?;
        }
        PodCommands::Stop {
            time,
            ignore,
            targets,
            pod_id_file,
            pods,
        } => {
            let pods = cli::run::select_pods(&client, pods, &targets, &pod_id_file)?;
            cli::run::each_named_as(&pods, ignore, &cli::run::Statuses::POD, |p| {
                client.run_pod(p, PodAction::Stop, Some(u64::from(time)), None, &[])
            })?
        }
        PodCommands::Kill {
            signal,
            targets,
            pods,
        } => {
            let signal = cli::run::check_signal(&signal)?;
            let pods = pod_ids(
                &client,
                cli::run::select_pods(&client, pods, &targets, &[])?,
            );
            each_pod(pods, |pod| {
                client.run_pod(pod, PodAction::Kill, None, Some(&signal), &[])
            })?;
        }
        PodCommands::Pause { targets, pods } => {
            let pods = pod_ids(
                &client,
                cli::run::select_pods(&client, pods, &targets, &[])?,
            );
            each_pod(pods, |pod| {
                client.run_pod(pod, PodAction::Pause, None, None, &[])
            })?;
        }
        PodCommands::Unpause { targets, pods } => {
            let pods = pod_ids(
                &client,
                cli::run::select_pods(&client, pods, &targets, &[])?,
            );
            each_pod(pods, |pod| {
                client.run_pod(pod, PodAction::Unpause, None, None, &[])
            })?;
        }
        PodCommands::Rm {
            force,
            ignore,
            targets,
            pod_id_file,
            time,
            pods,
        } => {
            if time.is_some() && !force {
                anyhow::bail!("--force option must be specified to use the --time option");
            }
            // (a forced removal ignores the pods that are not there)
            let ignore = ignore || force;
            // (the time to stop, before the removal kills what is left)
            let remove =
                |p: &str| client.remove_pod(p, force, time.filter(|_| force).map(u64::from));
            let pods = match cli::run::select_pods(&client, pods, &targets, &pod_id_file) {
                Ok(p) => pod_ids(&client, p),
                // (podman's status for no pod to remove)
                Err(e) if targets.latest && e.to_string() == "no such pod" => {
                    eprintln!("Error: no such pod");
                    exit_with(1);
                }
                Err(e) => return Err(e),
            };
            cli::run::each_named_as(&pods, ignore, &cli::run::Statuses::POD_RM, remove)?;
            // a file with the ID of a pod that was removed goes with it
            for file in &pod_id_file {
                std::fs::remove_file(file)?;
            }
        }
        PodCommands::Stats {
            targets,
            format,
            no_stream,
            no_reset,
            pods,
        } => pod_stats(&client, targets, format, no_stream, no_reset, pods)?,
        PodCommands::Top { latest, args } => {
            let (pod, ps_args) = if latest.latest {
                // (with --latest every argument is a descriptor)
                let pod =
                    cli::run::named_or_latest_of(&client, client::Kind::Pod, true, Vec::new())
                        .map_err(|e| {
                            anyhow::anyhow!("unable to look up requested container: {e}")
                        })?;
                (pod.into_iter().next().unwrap_or_default(), args)
            } else {
                let mut args = args.into_iter();
                let Some(pod) = args.next() else {
                    anyhow::bail!("you must provide the name or id of a running pod");
                };
                (pod, args.collect())
            };
            let result = client.pod_top(&pod, &ps_args).map_err(|e| {
                if e.is_not_found() {
                    anyhow::anyhow!(
                        "unable to look up requested container: {}",
                        cli::report::podman_missing_pod(&pod)
                    )
                } else {
                    e.into()
                }
            })?;
            // (a pod with nothing that runs shows nothing, as podman's)
            if result.titles.is_empty() {
                return Ok(());
            }
            let mut text = format!("{}\n", result.titles.join("\t"));
            for proc in &result.processes {
                text.push_str(&format!("{}\n", proc.join("\t")));
            }
            print!("{}", cli::template::align_text(&text));
        }
        PodCommands::Prune { force } => {
            if !force && !confirm_prune("WARNING! This will remove all stopped/exited pods..")? {
                return Ok(());
            }
            let pruned = client.prune_pods()?;
            for id in &pruned {
                println!("Deleted: {}", id);
            }
            println!("Total reclaimed: {} pods", pruned.len());
        }
        PodCommands::Exists { pod } => {
            let exists = client.exists(client::Kind::Pod, &pod)?;
            if exists {
                exit_with(0);
            } else {
                exit_with(1);
            }
        }
        PodCommands::Logs {
            latest,
            pod,
            follow,
            since,
            until,
            tail,
            timestamps,
            names,
            color,
            container,
        } => {
            use std::io::Write;
            let pod = match (latest.latest, pod) {
                (true, None) => {
                    cli::run::named_or_latest_of(&client, client::Kind::Pod, true, Vec::new())?
                        .remove(0)
                }
                (true, Some(_)) => anyhow::bail!("--latest and pods cannot be used together"),
                (false, Some(pod)) => pod,
                (false, None) => anyhow::bail!("specify at least one pod name or ID to log"),
            };
            let tail = u64::try_from(tail).ok();
            let format = cli::podlogs::LineFormat {
                names,
                timestamps,
                color,
            };
            let mut out = std::io::stdout().lock();
            let mut err = std::io::stderr().lock();
            // stderr lines go to stderr, as podman's
            let mut show = |entry: &client::PodLogEntry| {
                let line = cli::podlogs::line(&format, entry);
                if entry.stream == "stderr" {
                    out.flush()?;
                    writeln!(err, "{line}")?;
                    err.flush()
                } else {
                    writeln!(out, "{line}")?;
                    out.flush()
                }
            };
            if follow {
                // a signal ends the command with status 1, as podman's
                velarx_sys::catch::exit_on(libc::SIGINT, 1);
                velarx_sys::catch::exit_on(libc::SIGTERM, 1);
                let mut failed = None;
                client.pod_logs_follow(
                    &pod,
                    since.as_deref(),
                    until.as_deref(),
                    tail,
                    &container,
                    &mut |entry| match show(&entry) {
                        Ok(()) => true,
                        Err(e) => {
                            failed = Some(e);
                            false
                        }
                    },
                )?;
                // (a reader that went away ends the command quietly)
                if let Some(e) = failed.filter(|e| e.kind() != std::io::ErrorKind::BrokenPipe) {
                    return Err(e.into());
                }
            } else {
                let logs =
                    client.pod_logs(&pod, since.as_deref(), until.as_deref(), tail, &container)?;
                for entry in logs {
                    show(&entry)?;
                }
            }
        }
    }

    Ok(())
}

/// The labels of `--label` (`KEY=VALUE`, or `KEY` for an empty value) and
/// of the files of `--label-file` (a line each: `KEY=VALUE`, or `KEY` for
/// the value it has in the environment; empty lines and `#` comments are
/// skipped).
fn pod_labels(
    labels: &[String],
    files: &[String],
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let mut out = std::collections::HashMap::new();
    for file in files {
        let text = std::fs::read_to_string(file).map_err(|e| {
            anyhow::anyhow!("unable to process labels: open {file}: {}", io_text(&e))
        })?;
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_once('=') {
                Some((k, v)) => out.insert(k.to_string(), v.to_string()),
                None => match std::env::var(line) {
                    Ok(v) => out.insert(line.to_string(), v),
                    Err(_) => None,
                },
            };
        }
    }
    for label in labels {
        let (k, v) = label.split_once('=').unwrap_or((label, ""));
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

/// An I/O error as Go says it.
pub(super) fn io_text(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".into(),
        std::io::ErrorKind::PermissionDenied => "permission denied".into(),
        _ => e.to_string(),
    }
}

/// The digests of `--verify-image` are of the images of the containers of
/// one pod: refused for several (each would refuse the digests of the
/// others) and for `--all`, whatever it finds, by name.
fn one_pod_for_digests(verify_image: &[String], all: bool, pods: usize) -> anyhow::Result<()> {
    if !verify_image.is_empty() && (all || pods != 1) {
        anyhow::bail!(
            "--verify-image: the digests are of the images of the containers of one pod: name it, one pod"
        );
    }
    Ok(())
}

/// `op` on each pod, each printed when it succeeded and the failures said
/// (podman's `Error: ` and the error); the command fails (125) when one did.
fn each_pod(
    pods: Vec<String>,
    mut op: impl FnMut(&str) -> client::ClientResult<()>,
) -> anyhow::Result<()> {
    let mut failed = false;
    cli::run::each_item(
        pods,
        |pod| op(pod).map(|()| println!("{pod}")),
        |_, e| {
            eprintln!("Error: {e}");
            failed = true;
        },
    )?;
    if failed {
        exit_with(125);
    }
    Ok(())
}

/// The IDs of `pods`, which kill, pause, unpause, restart and rm print as
/// podman's (a pod that is not there keeps its name, for the error).
fn pod_ids(client: &client::EngineClient, pods: Vec<String>) -> Vec<String> {
    pods.into_iter()
        .map(|p| client.inspect_pod(&p).map(|pod| pod.id).unwrap_or(p))
        .collect()
}

/// The pods `pod inspect` shows: those named, or the one made last.
fn inspected(
    client: &client::EngineClient,
    latest: bool,
    pods: Vec<String>,
) -> anyhow::Result<Vec<String>> {
    if !latest && pods.is_empty() {
        anyhow::bail!("no names or ids specified");
    }
    if latest && !pods.is_empty() {
        anyhow::bail!("--latest and arguments cannot be used together");
    }
    cli::run::named_or_latest_of(client, client::Kind::Pod, latest, pods)
}

/// `pod stats`: the containers of the pods, once or each second.
fn pod_stats(
    client: &client::EngineClient,
    targets: cli::PodTargets,
    format: Option<String>,
    no_stream: bool,
    no_reset: bool,
    pods: Vec<String>,
) -> anyhow::Result<()> {
    use std::io::IsTerminal;
    let given = [!pods.is_empty(), targets.all, targets.latest];
    if given.iter().filter(|g| **g).count() > 1 {
        anyhow::bail!("--all, --latest and arguments cannot be used together");
    }
    let (names, all) = if targets.latest {
        let pod = cli::run::named_or_latest_of(client, client::Kind::Pod, true, Vec::new())
            .map_err(|e| anyhow::anyhow!("unable to get list of pods: {e}"))?;
        (pod, false)
    } else {
        (pods, targets.all)
    };
    let format = format.filter(|f| !f.is_empty());
    let headers = std::collections::HashMap::from([
        ("CPU", "CPU %"),
        ("MemUsage", "MEM USAGE/ LIMIT"),
        ("MemUsageBytes", "MEM USAGE/ LIMIT"),
        ("Mem", "MEM %"),
        ("NetIO", "NET IO"),
        ("BlockIO", "BLOCK IO"),
    ]);
    loop {
        let items = pod_stats_rows(client, &names, all)?;
        if format.as_deref() == Some("json") {
            // (podman indents by five spaces)
            let mut out = Vec::new();
            let mut ser = serde_json::Serializer::with_formatter(
                &mut out,
                serde_json::ser::PrettyFormatter::with_indent(b"     "),
            );
            serde::Serialize::serialize(&items, &mut ser)?;
            println!("{}", String::from_utf8_lossy(&out));
        } else {
            if !no_reset && std::io::stdout().is_terminal() {
                print!("\x1b[2J\x1b[H");
            }
            match &format {
                Some(f) => {
                    if !items.is_empty() {
                        let text = cli::template::format_list(f, &items, &headers)
                            .map_err(anyhow::Error::msg)?;
                        print!("{text}");
                    }
                }
                None => {
                    let mut text =
                        "POD\tCID\tNAME\tCPU %\tMEM USAGE/ LIMIT\tMEM %\tNET IO\tBLOCK IO\tPIDS\n"
                            .to_string();
                    if items.is_empty() {
                        text.push_str("--\t--\t--\t--\t--\t--\t--\t--\t--\n");
                    }
                    for r in &items {
                        let cell = |k: &str| cli::template::text(&r[k]);
                        text.push_str(&format!(
                            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                            cell("Pod"),
                            cell("CID"),
                            cell("Name"),
                            cell("CPU"),
                            cell("MemUsage"),
                            cell("Mem"),
                            cell("NetIO"),
                            cell("BlockIO"),
                            cell("PIDS")
                        ));
                    }
                    print!("{}", cli::template::align_text(&text));
                }
            }
        }
        if no_stream {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// `--share`: which namespaces the members join (`+` adds to the default).
fn apply_share(spec: &mut PodSpec, share: &str) -> anyhow::Result<()> {
    let (add, list) = match share.strip_prefix('+') {
        Some(rest) => (true, rest),
        None => (false, share),
    };
    if !add {
        (
            spec.share_net,
            spec.share_ipc,
            spec.share_uts,
            spec.share_pid,
            spec.share_cgroup,
        ) = (false, false, false, false, false);
    }
    for ns in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
        match ns {
            "net" => spec.share_net = true,
            "ipc" => spec.share_ipc = true,
            "uts" => spec.share_uts = true,
            "pid" => spec.share_pid = true,
            "cgroup" => spec.share_cgroup = true,
            "none" if !add => {}
            other => anyhow::bail!(
                "invalid kernel namespace to share: {other}. Options are: cgroup, ipc, net, pid, uts or none"
            ),
        }
    }
    Ok(())
}

/// `--uidmap` and `--gidmap` (`CONTAINER:HOST:SIZE`): one of them is both
/// without the other, and a private user namespace when `--userns` says
/// none.
fn apply_id_maps(spec: &mut PodSpec, uidmap: &[String], gidmap: &[String]) -> anyhow::Result<()> {
    let maps = |list: &[String]| -> anyhow::Result<Vec<IdMapping>> {
        list.iter()
            .map(|m| {
                let n: Vec<u32> = m
                    .split(':')
                    .map(|x| x.trim().parse::<u32>())
                    .collect::<Result<_, _>>()
                    .map_err(|_| anyhow::anyhow!("invalid ID mapping `{m}`"))?;
                match n[..] {
                    [c, h, s] if s > 0 => Ok(IdMapping {
                        container_id: c,
                        host_id: h,
                        size: s,
                    }),
                    _ => anyhow::bail!("invalid ID mapping `{m}`: CONTAINER:HOST:SIZE"),
                }
            })
            .collect()
    };
    spec.uid_mappings = maps(uidmap)?;
    spec.gid_mappings = maps(gidmap)?;
    if spec.gid_mappings.is_empty() {
        spec.gid_mappings = spec.uid_mappings.clone();
    } else if spec.uid_mappings.is_empty() {
        spec.uid_mappings = spec.gid_mappings.clone();
    }
    if !spec.uid_mappings.is_empty() && spec.userns.is_none() {
        spec.userns = Some(UsernsChoice::Private);
    }
    Ok(())
}

/// `--restart POLICY[:MAX]`: of the members that set none; podman's checks,
/// as `run --restart`.
fn restart_policy(r: &str) -> anyhow::Result<RestartPolicy> {
    let p = crate::cli::run::parse_restart_policy(r)?;
    Ok(RestartPolicy {
        name: p.name,
        maximum_retry_count: p.maximum_retry_count,
    })
}

/// `--sysctl NAME=VALUE`: set in the pod's spec.
fn apply_sysctls(spec: &mut PodSpec, sysctls: &[String]) -> anyhow::Result<()> {
    for kv in sysctls {
        let (k, v) = kv
            .split_once('=')
            .filter(|(k, _)| !k.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("invalid sysctl `{kv}`: NAME=VALUE"))?;
        spec.sysctls.insert(k.trim().to_string(), v.to_string());
    }
    Ok(())
}

/// `--shm-size` and `--shm-size-systemd`.
fn apply_shm_sizes(
    spec: &mut PodSpec,
    shm_size: Option<&str>,
    shm_size_systemd: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(s) = shm_size {
        spec.shm_size = Some(
            velarx_wire::options::parse_size(s)
                .filter(|n| *n > 0)
                .ok_or_else(|| anyhow::anyhow!("invalid shm size `{s}`"))?,
        );
    }
    if let Some(s) = shm_size_systemd {
        spec.shm_size_systemd = Some(
            velarx_wire::options::parse_size(s)
                .ok_or_else(|| anyhow::anyhow!("invalid shm size for systemd `{s}`"))?,
        );
    }
    Ok(())
}

/// `--pid` and `--uts` of a pod: the namespace of the host (which its
/// members are in, not sharing one), or a private one of the pod.
fn apply_namespaces(
    spec: &mut PodSpec,
    pid: Option<&str>,
    uts: Option<&str>,
) -> anyhow::Result<()> {
    for (name, mode) in [("pid", pid), ("uts", uts)] {
        match mode {
            None | Some("" | "private" | "pod") => {}
            Some("host") if name == "pid" => {
                spec.host_pid = true;
                spec.share_pid = false;
            }
            Some("host") => {
                spec.host_uts = true;
                spec.share_uts = false;
            }
            Some(m) => anyhow::bail!(
                "the {name} namespace mode `{m}` is not supported for pods: host or private \
                 (the namespaces of a pod are those of its infra container)"
            ),
        }
    }
    Ok(())
}

/// A MAC address of six hexadecimal pairs, as the pod's network wants it.
fn check_mac(mac: &str) -> anyhow::Result<String> {
    let pairs: Vec<&str> = mac.split([':', '-']).collect();
    if pairs.len() != 6
        || pairs
            .iter()
            .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        anyhow::bail!("address {mac}: invalid MAC address");
    }
    Ok(mac.to_ascii_lowercase().replace('-', ":"))
}

/// The options of `pod create` that `pod clone` applies to the copy, as
/// podman's: what is given replaces the pod's, the devices are added.
#[derive(Default)]
struct CloneOptions {
    cgroup_parent: Option<String>,
    device: Vec<String>,
    gpus: Vec<String>,
    gidmap: Vec<String>,
    uidmap: Vec<String>,
    infra_command: Option<String>,
    infra_conmon_pidfile: Option<String>,
    pid: Option<String>,
    uts: Option<String>,
    userns: Option<String>,
    restart: Option<String>,
    security_opt: Vec<String>,
    shm_size: Option<String>,
    shm_size_systemd: Option<String>,
    subgidname: Option<String>,
    subuidname: Option<String>,
    sysctl: Vec<String>,
    volume: Vec<String>,
    volumes_from: Vec<String>,
    resources: Option<velarx_proto::pod::PodResources>,
}

impl CloneOptions {
    fn apply(&self, spec: &mut PodSpec) -> anyhow::Result<()> {
        let named_ids = self.subuidname.is_some() || self.subgidname.is_some();
        if named_ids
            && (self.userns.is_some() || !self.uidmap.is_empty() || !self.gidmap.is_empty())
        {
            anyhow::bail!(
                "--userns and --uidmap/--gidmap/--subuidname/--subgidname are mutually exclusive"
            );
        }
        if let Some(c) = self.cgroup_parent.as_ref().filter(|c| !c.is_empty()) {
            spec.cgroup_parent = Some(c.clone());
        }
        spec.devices.extend(
            self.device
                .iter()
                .cloned()
                .chain(self.gpus.iter().map(|g| format!("nvidia.com/gpu={g}"))),
        );
        if !self.volume.is_empty() {
            spec.volumes = self.volume.clone();
        }
        if !self.volumes_from.is_empty() {
            spec.volumes_from = self.volumes_from.clone();
        }
        if !self.security_opt.is_empty() {
            spec.security_opts = self.security_opt.clone();
        }
        if !self.sysctl.is_empty() {
            spec.sysctls.clear();
            apply_sysctls(spec, &self.sysctl)?;
        }
        apply_shm_sizes(
            spec,
            self.shm_size.as_deref(),
            self.shm_size_systemd.as_deref(),
        )?;
        apply_namespaces(spec, self.pid.as_deref(), self.uts.as_deref())?;
        if let Some(u) = &self.userns {
            spec.userns = Some(u.parse().map_err(|e| anyhow::anyhow!("--userns: {e}"))?);
        }
        if !self.uidmap.is_empty() || !self.gidmap.is_empty() {
            spec.userns = None;
            apply_id_maps(spec, &self.uidmap, &self.gidmap)?;
        }
        if let Some(n) = self.subuidname.as_ref().filter(|n| !n.is_empty()) {
            spec.subuidname = Some(n.clone());
        }
        if let Some(n) = self.subgidname.as_ref().filter(|n| !n.is_empty()) {
            spec.subgidname = Some(n.clone());
        }
        if named_ids {
            spec.userns = Some(UsernsChoice::Private);
        }
        if let Some(r) = &self.restart {
            spec.restart_policy = Some(restart_policy(r)?);
        }
        if !spec.no_infra {
            if let Some(c) = &self.infra_command {
                spec.infra_command = Some(c.split_whitespace().map(str::to_string).collect())
                    .filter(|c: &Vec<String>| !c.is_empty());
            }
            if let Some(f) = &self.infra_conmon_pidfile {
                spec.infra_conmon_pidfile = cli::PidFileArgs {
                    conmon_pidfile: Some(f.clone()),
                    ..Default::default()
                }
                .absolute()?
                .1;
            }
        }
        if let Some(new) = &self.resources {
            let r = spec.resources.get_or_insert_with(Default::default);
            merge_resources(r, new);
        }
        Ok(())
    }
}

/// The limits `new` sets, over those of `r`.
fn merge_resources(r: &mut velarx_proto::pod::PodResources, new: &velarx_proto::pod::PodResources) {
    macro_rules! set {
        ($($f:ident),*) => {$(
            if new.$f.is_some() {
                r.$f = new.$f.clone();
            }
        )*};
    }
    macro_rules! list {
        ($($f:ident),*) => {$(
            if !new.$f.is_empty() {
                r.$f = new.$f.clone();
            }
        )*};
    }
    set!(
        memory,
        memory_swap,
        cpu_shares,
        cpu_quota,
        cpu_period,
        cpuset_cpus,
        cpuset_mems,
        blkio_weight
    );
    list!(blkio_weight_device, device_read_bps, device_write_bps);
}

/// `pod clone`: a pod made with the spec of `pod`, named `name` (none:
/// podman's NAME-clone, else the first free NAME-cloneN), its hostname,
/// infra name and labels as asked, and a clone of each of its containers
/// (init containers too, as they were made): its id.  The infra container
/// of the copy is named `NAME-clone` after the original's unless asked.
fn clone_pod(
    client: &client::EngineClient,
    pod: &str,
    name: String,
    hostname: Option<String>,
    infra_name: Option<String>,
    labels: std::collections::HashMap<String, String>,
    options: &CloneOptions,
) -> anyhow::Result<String> {
    let record = client.inspect_pod(pod)?;
    let mut spec = record.spec;
    // (the scope the pod was made with is asked again by its
    // `--cgroups`: `cgroup_mode` is what the engine resolved, not an option;
    // a `no-conmon` pod takes the engine's default)
    let placement = spec.cgroup_mode.take();
    if let (CgroupsMode::Unset | CgroupsMode::Enabled, Some(placement)) = (spec.cgroups, placement)
    {
        spec.cgroups = match placement {
            CgroupMode::Scope => CgroupsMode::Scope,
        };
    }
    spec.name = if name.is_empty() {
        let base = format!("{}-clone", record.name);
        let mut n = 0;
        loop {
            let candidate = if n == 0 {
                base.clone()
            } else {
                format!("{base}{n}")
            };
            if !client.exists(client::Kind::Pod, &candidate)? {
                break candidate;
            }
            n += 1;
        }
    } else {
        name
    };
    if hostname.is_some() {
        spec.hostname = hostname;
    }
    spec.infra_name = infra_name.or_else(|| {
        let infra = record.members.iter().find(|m| m.id == record.infra_id)?;
        let mut taken = 0;
        loop {
            let candidate = match taken {
                0 => format!("{}-clone", infra.name),
                n => format!("{}-clone{n}", infra.name),
            };
            if !client.exists(client::Kind::Container, &candidate).ok()? {
                return Some(candidate);
            }
            taken += 1;
        }
    });
    spec.labels.extend(labels);
    options.apply(&mut spec)?;
    let id = client.create_pod(&spec)?;
    for member in record.members.iter().filter(|m| m.id != record.infra_id) {
        if let Err(e) = client.clone_container(&member.id, None, None, Some(&id)) {
            // (a pod that is half a copy is not left behind)
            let _ = client.remove_pod(&id, true, None);
            return Err(e.into());
        }
    }
    Ok(id)
}

/// The rows of `pod stats` (podman's PodStatsReport): a sample of each
/// container of the pods `names` (of all of them without a name).
fn pod_stats_rows(
    client: &client::EngineClient,
    names: &[String],
    all: bool,
) -> anyhow::Result<Vec<serde_json::Value>> {
    if all && !names.is_empty() {
        anyhow::bail!("--all, --latest and arguments cannot be used together");
    }
    let pods = if names.is_empty() {
        client.list_pods(&[])?
    } else {
        let mut pods = Vec::new();
        for n in names {
            pods.push(client.inspect_pod(n).map_err(|e| {
                if e.is_not_found() {
                    anyhow::anyhow!(
                        "unable to get list of pods: {}",
                        cli::report::podman_missing_pod(n)
                    )
                } else {
                    e.into()
                }
            })?);
        }
        pods
    };
    let mut rows = Vec::new();
    for pod in &pods {
        let members: Vec<String> = pod.members.iter().map(|m| m.id.clone()).collect();
        if members.is_empty() {
            continue;
        }
        client.container_stats(&members, true, false, 0, &mut |sample| {
            rows.extend(velarx_shape::stats::pod_rows(&pod.id, &sample));
            true
        })?;
    }
    Ok(rows)
}

/// The limits of the flags of `pod create` and `pod update`: none without
/// a flag.  What podman has and a pod cgroup has not is refused by name.
/// `DEVICE:VALUE` of `--blkio-weight-device`, `--device-read-bps` and
/// `--device-write-bps` as podman reads them: the device is a block device
/// below /dev, looked up now; the value a weight (10 to 1000) or a size.
fn block_limits(
    list: &[String],
    flag: &str,
) -> anyhow::Result<Vec<velarx_proto::pod::PodDeviceLimit>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let weight = flag == "--blkio-weight-device";
    let mut out = Vec::new();
    for d in list {
        let (path, value) = d
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("bad format: {d}"))?;
        if !path.starts_with("/dev/") {
            anyhow::bail!("bad format for device path: {d}");
        }
        let value = if weight {
            value
                .parse::<u64>()
                .ok()
                .filter(|w| *w == 0 || (10..=1000).contains(w))
                .ok_or_else(|| anyhow::anyhow!("invalid weight for device: {d}"))?
        } else {
            parse_memory_size(value)
                .ok()
                .and_then(|r| u64::try_from(r).ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "invalid rate for device: {d}. The correct format is \
                         <device-path>:<number>[<unit>]. Number must be a positive integer. \
                         Unit is optional and can be kb, mb, or gb"
                    )
                })?
        };
        let meta = std::fs::metadata(path).map_err(|e| {
            let why = match e.kind() {
                std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
                _ => e.to_string(),
            };
            let prefix = if weight {
                "bad --blkio-weight-device: "
            } else {
                ""
            };
            anyhow::anyhow!("{prefix}could not parse device {path}: {why}")
        })?;
        if !meta.file_type().is_block_device() {
            anyhow::bail!("{path}: not a block device");
        }
        out.push(velarx_proto::pod::PodDeviceLimit {
            major: rustix::fs::major(meta.rdev()),
            minor: rustix::fs::minor(meta.rdev()),
            value,
            path: path.to_string(),
        });
    }
    Ok(out)
}

fn pod_resources(
    a: &cli::PodResourceArgs,
) -> anyhow::Result<Option<velarx_proto::pod::PodResources>> {
    let size = |flag: &str, v: &Option<String>| {
        v.as_deref()
            .map(|v| {
                parse_memory_size(v).map_err(|e| anyhow::anyhow!("invalid value for {flag}: {e}"))
            })
            .transpose()
    };
    let mut r = velarx_proto::pod::PodResources {
        memory: size("memory", &a.memory)?,
        memory_swap: size("memory-swap", &a.memory_swap)?,
        cpu_shares: a.cpu_shares,
        cpu_quota: a.cpu_quota,
        cpu_period: a.cpu_period,
        cpuset_cpus: a.cpuset_cpus.clone(),
        cpuset_mems: a.cpuset_mems.clone(),
        // (0 is no limit)
        blkio_weight: a
            .blkio_weight
            .as_deref()
            .map(|w| {
                w.parse::<u16>()
                    .map_err(|e| anyhow::anyhow!("invalid value for blkio-weight: {e}"))
            })
            .transpose()?
            .filter(|w| *w != 0),
        blkio_weight_device: block_limits(&a.blkio_weight_device, "--blkio-weight-device")?,
        device_read_bps: block_limits(&a.device_read_bps, "--device-read-bps")?,
        device_write_bps: block_limits(&a.device_write_bps, "--device-write-bps")?,
    };
    // (0, podman's default, is no limit)
    if let Some(cpus) = a.cpus.filter(|c| *c != 0.0) {
        if a.cpu_quota.is_some() {
            anyhow::bail!("--cpus and --cpu-quota both set the CPU quota");
        }
        if cpus.is_nan() || cpus <= 0.0 {
            anyhow::bail!("--cpus has to be positive");
        }
        let period = r.cpu_period.unwrap_or(100_000);
        r.cpu_period = Some(period);
        r.cpu_quota = Some((cpus * period as f64) as i64);
    }
    Ok(Some(r).filter(|r| !r.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_options_of_pod_clone_change_the_copy() {
        let mut spec = PodSpec {
            volumes: vec!["/a:/a".into()],
            sysctls: [("k.a".to_string(), "1".to_string())].into(),
            resources: Some(velarx_proto::pod::PodResources {
                memory: Some(5),
                cpu_shares: Some(7),
                ..Default::default()
            }),
            ..PodSpec::default()
        };
        let options = CloneOptions {
            cgroup_parent: Some("g.slice".into()),
            device: vec!["/dev/null".into()],
            gpus: vec!["all".into()],
            volume: vec!["/b:/b".into()],
            sysctl: vec!["k.b=2".into()],
            pid: Some("host".into()),
            shm_size: Some("10m".into()),
            restart: Some("on-failure:3".into()),
            infra_command: Some("/pause 1".into()),
            uidmap: vec!["0:1:100".into()],
            resources: Some(velarx_proto::pod::PodResources {
                memory: Some(9),
                ..Default::default()
            }),
            ..CloneOptions::default()
        };
        options.apply(&mut spec).unwrap();
        assert_eq!(spec.cgroup_parent.as_deref(), Some("g.slice"));
        assert_eq!(spec.devices, ["/dev/null", "nvidia.com/gpu=all"]);
        assert_eq!(spec.volumes, ["/b:/b"]);
        assert_eq!(spec.sysctls, [("k.b".to_string(), "2".to_string())].into());
        assert!(spec.host_pid && !spec.share_pid);
        assert_eq!(spec.shm_size, Some(10 << 20));
        assert_eq!(spec.restart_policy.unwrap().maximum_retry_count, 3);
        assert_eq!(spec.infra_command.unwrap(), ["/pause", "1"]);
        assert_eq!(spec.uid_mappings, spec.gid_mappings);
        assert!(matches!(spec.userns, Some(UsernsChoice::Private)));
        let r = spec.resources.unwrap();
        assert_eq!((r.memory, r.cpu_shares), (Some(9), Some(7)));

        for bad in [
            CloneOptions {
                subuidname: Some("u".into()),
                userns: Some("host".into()),
                ..CloneOptions::default()
            },
            CloneOptions {
                shm_size: Some("lots".into()),
                ..CloneOptions::default()
            },
            CloneOptions {
                sysctl: vec!["novalue".into()],
                ..CloneOptions::default()
            },
        ] {
            assert!(bad.apply(&mut PodSpec::default()).is_err());
        }
        let mut none = PodSpec::default();
        CloneOptions::default().apply(&mut none).unwrap();
        assert_eq!(none, PodSpec::default());
    }

    #[test]
    fn the_options_of_pod_create_make_the_spec() {
        let mut spec = PodSpec::default();
        apply_namespaces(&mut spec, Some("host"), Some("host")).unwrap();
        assert!(spec.host_pid && spec.host_uts && !spec.share_pid && !spec.share_uts);
        let e = apply_namespaces(&mut PodSpec::default(), Some("ns:/x"), None).unwrap_err();
        assert!(e.to_string().contains("not supported for pods"), "{e}");
        assert_eq!(check_mac("AA-BB-CC-DD-EE-FF").unwrap(), "aa:bb:cc:dd:ee:ff");
        let e = check_mac("zz").unwrap_err();
        assert_eq!(e.to_string(), "address zz: invalid MAC address");
        let mut conflict = PodSpec {
            no_hosts: true,
            add_hosts: vec!["a:1.1.1.1".into()],
            ..Default::default()
        };
        assert!(conflict.check().is_err());
        conflict.add_hosts.clear();
        assert!(conflict.check().is_ok());
    }

    #[test]
    fn the_flags_make_the_limits_of_the_pod() {
        let none = cli::PodResourceArgs::default();
        assert_eq!(pod_resources(&none).unwrap(), None);
        let zero = cli::PodResourceArgs {
            cpus: Some(0.0),
            ..Default::default()
        };
        assert_eq!(pod_resources(&zero).unwrap(), None);
        let bad = cli::PodResourceArgs {
            memory: Some("abc".into()),
            ..Default::default()
        };
        assert_eq!(
            pod_resources(&bad).unwrap_err().to_string(),
            "invalid value for memory: invalid size: 'abc'"
        );
        let a = cli::PodResourceArgs {
            memory: Some("100m".into()),
            memory_swap: Some("1g".into()),
            cpus: Some(0.5),
            cpuset_cpus: Some("0-1".into()),
            cpu_shares: Some(256),
            ..Default::default()
        };
        let r = pod_resources(&a).unwrap().unwrap();
        assert_eq!(r.memory, Some(100 << 20));
        assert_eq!(r.memory_swap, Some(1 << 30));
        assert_eq!((r.cpu_quota, r.cpu_period), (Some(50_000), Some(100_000)));
        assert_eq!(r.cpuset_cpus.as_deref(), Some("0-1"));
        assert_eq!(r.cpu_shares, Some(256));
    }

    #[test]
    fn the_block_io_options_are_read_as_podman_reads_them() {
        let limit = |flag: &str, v: &str| {
            let mut a = cli::PodResourceArgs::default();
            let v = vec![v.to_string()];
            match flag {
                "weight-device" => a.blkio_weight_device = v,
                _ => a.device_read_bps = v,
            }
            pod_resources(&a).map_err(|e| e.to_string())
        };
        for (flag, v, want) in [
            ("read", "/dev/sda", "bad format: /dev/sda"),
            ("read", "sda:1mb", "bad format for device path: sda:1mb"),
            ("read", "/dev/null:1mb", "/dev/null: not a block device"),
            (
                "read",
                "/dev/nosuch:1mb",
                "could not parse device /dev/nosuch: no such file or directory",
            ),
            (
                "weight-device",
                "/dev/nosuch:50",
                "bad --blkio-weight-device: could not parse device /dev/nosuch: no such file or directory",
            ),
            (
                "weight-device",
                "/dev/nosuch:5",
                "invalid weight for device: /dev/nosuch:5",
            ),
        ] {
            assert_eq!(limit(flag, v).unwrap_err(), want, "{v}");
        }
        let e = limit("read", "/dev/nosuch:-1").unwrap_err();
        assert!(
            e.starts_with("invalid rate for device: /dev/nosuch:-1."),
            "{e}"
        );
        let w = |v: &str| cli::PodResourceArgs {
            blkio_weight: Some(v.into()),
            ..Default::default()
        };
        assert_eq!(
            pod_resources(&w("50")).unwrap().unwrap().blkio_weight,
            Some(50)
        );
        // (0 is no limit)
        assert_eq!(pod_resources(&w("0")).unwrap(), None);
        let e = pod_resources(&w("abc")).unwrap_err().to_string();
        assert!(e.starts_with("invalid value for blkio-weight: "), "{e}");
        // a block device of this host, if it has one: its numbers
        let disk = std::fs::read_dir("/sys/block")
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| format!("/dev/{}", e.file_name().to_string_lossy()))
            .find(|p| std::path::Path::new(p).exists());
        if let Some(disk) = disk {
            let r = limit("read", &format!("{disk}:1mb")).unwrap().unwrap();
            assert_eq!(r.device_read_bps[0].value, 1 << 20);
            assert!(r.device_write_bps.is_empty());
        }
    }

    #[test]
    fn the_cpu_options_conflict() {
        let a = cli::PodResourceArgs {
            cpus: Some(1.0),
            cpu_quota: Some(5),
            ..Default::default()
        };
        assert!(pod_resources(&a).is_err());
    }
}
