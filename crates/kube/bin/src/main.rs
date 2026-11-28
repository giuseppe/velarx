// SPDX-License-Identifier: Apache-2.0
//! `velarx-kube play|down|generate|apply`: Kubernetes YAML as pods and
//! containers and back, a frontend of the engine service.
//!
//! The command reads what it needs (the YAML, the kubeconfig, the
//! credentials), starts the engine when nothing serves its socket, decides
//! what to do (`velarx_kube::commands::prepare`), confines itself
//! (`confine.rs`) and does it, all of it through the typed interface of the
//! engine, and, for `apply`, the requests to the API server of a cluster.

mod cli;
mod confine;
mod text;

use anyhow::{bail, Context};
use clap::Parser;
use cli::{Cli, Command};
use confine::Needs;
use std::path::{Path, PathBuf};
use velarx_kube::commands::{self, Access, PlayArgs};
use velarx_kube::engine::Engine;
use velarx_kube::{apply, describe, generate, play, yaml};

fn main() -> std::process::ExitCode {
    let startup = velarx_sys::fd::Startup::take().expect("main is the first to take it");
    velarx_base::buildinfo::set(env!("VELARX_GIT_COMMIT"), env!("VELARX_BUILD_TIME"));
    let cli = Cli::parse();
    if cli.version {
        println!(
            "velarx-kube {} ({})",
            env!("CARGO_PKG_VERSION"),
            env!("VELARX_GIT_COMMIT")
        );
        return std::process::ExitCode::SUCCESS;
    }
    let Some(command) = cli.command.clone() else {
        eprintln!("velarx-kube: a command is needed (play, down, generate, apply); --help says");
        return std::process::ExitCode::from(2);
    };
    // The connections to the engine come through a process forked now (one
    // thread): the confined process looks up no socket by name.
    let socket = match engine_socket(&cli) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e:#}");
            return std::process::ExitCode::from(125);
        }
    };
    let dial = match velarx_sys::connector::Connector::start(&socket) {
        Ok(c) => velarx_proto::connect::Dial::Connector(std::sync::Arc::new(c), socket),
        Err(e) => {
            eprintln!("Error: {e}");
            return std::process::ExitCode::from(125);
        }
    };
    // (no thread but this one: Landlock and seccomp apply to the threads
    // made after them)
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            return std::process::ExitCode::from(125);
        }
    };
    let result = runtime.block_on(run(&cli, command, &startup, dial));
    match result {
        Ok(code) => std::process::ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            std::process::ExitCode::from(125)
        }
    }
}

/// The socket of the engine service.
fn engine_socket(cli: &Cli) -> anyhow::Result<PathBuf> {
    velarx_kube::engine::socket(cli.engine_socket.as_deref(), &cli.config)
        .map_err(|e| anyhow::anyhow!(e))
}

/// Make sure the engine serves its socket, for as long as the command
/// lives: `velarx` next to this binary starts it when nothing does.
async fn keep_engine(
    cli: &Cli,
    socket: &Path,
) -> anyhow::Result<Option<velarx_proto::connect::Kept>> {
    if cli.no_start_engine {
        return Ok(None);
    }
    let exe = std::env::current_exe()?
        .parent()
        .map(|d| d.join("velarx"))
        .filter(|p| p.is_file())
        .context(
            "no `velarx` next to velarx-kube to start the engine with \
             (--no-start-engine if something else does)",
        )?;
    let command = || {
        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("--config").arg(&cli.config);
        cmd.args(["varlink", "--listen-fd", "3", "--time", "0"]);
        cmd
    };
    velarx_proto::connect::keep_engine_async(socket, command)
        .await
        .map(Some)
        .map_err(|e| anyhow::anyhow!(e))
}

/// The YAML of a file, of an http(s) address, or of the standard input for
/// `-`, at most
/// [`yaml::MAX_SIZE`] bytes.
async fn read_yaml(file: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    if velarx_kube::fetch::is_url(file) {
        return velarx_kube::fetch::get(file)
            .await
            .map_err(anyhow::Error::msg);
    }
    let limit = yaml::MAX_SIZE as u64 + 1;
    let mut data = Vec::new();
    if file == "-" {
        std::io::stdin().take(limit).read_to_end(&mut data)?;
    } else {
        std::fs::File::open(file)
            .map_err(|e| anyhow::anyhow!("cannot read {file}: {e}"))?
            .take(limit)
            .read_to_end(&mut data)?;
    }
    if data.len() > yaml::MAX_SIZE {
        bail!("the YAML {file} is larger than 4 MiB");
    }
    Ok(data)
}

fn documents(data: &[u8]) -> anyhow::Result<Vec<serde_json::Value>> {
    let text = std::str::from_utf8(data).map_err(|_| anyhow::anyhow!("the YAML is not UTF-8"))?;
    yaml::parse_documents(text).map_err(|e| anyhow::anyhow!("{e}"))
}

/// `--creds`, `--authfile` and `--cert-dir`, read.
fn access(args: &cli::RegistryAccess) -> anyhow::Result<Access> {
    let mut fixed = velarx_registry::auth::RegistryAccess::default();
    if let Some(c) = &args.creds {
        fixed.creds =
            Some(velarx_registry::Credentials::parse_creds(c).map_err(|e| anyhow::anyhow!(e))?);
    }
    if let Some(dir) = &args.cert_dir {
        fixed.certs = Some(
            velarx_registry::certs::RawCerts::read_dir(dir)
                .map_err(|e| anyhow::anyhow!("--cert-dir `{}`: {e}", dir.display()))?,
        );
    }
    let authfile = match &args.authfile {
        Some(path) => {
            if let Err(e) = std::fs::metadata(path) {
                bail!(
                    "credential file is not accessible: faccessat {}: {}",
                    path.display(),
                    if e.kind() == std::io::ErrorKind::NotFound {
                        "no such file or directory".to_string()
                    } else {
                        e.to_string()
                    }
                );
            }
            Some(velarx_registry::AuthConfig::load_file(path))
        }
        None => None,
    };
    Ok(Access { fixed, authfile })
}

fn split(list: &[String]) -> Vec<String> {
    list.iter()
        .flat_map(|a| a.split(','))
        .filter(|a| !a.is_empty())
        .map(str::to_string)
        .collect()
}

async fn run(
    cli: &Cli,
    command: Command,
    _startup: &velarx_sys::fd::Startup,
    dial: velarx_proto::connect::Dial,
) -> anyhow::Result<u8> {
    if let Command::SelfTest {
        connect_port,
        outside,
    } = command
    {
        let needs = Needs {
            api_port: connect_port,
            // (the probes read the status of every thread)
            read: vec![PathBuf::from("/proc/self")],
        };
        // (a play calls the engine before it confines itself: so does the
        // test, and every thread that call made must be confined too, that
        // is, there is none)
        drop(velarx_proto::connect::connect_via(&dial).await);
        confine::enter(&needs)?;
        let results = confine::probes(&needs, &outside, &dial);
        println!("{}", serde_json::to_string(&results)?);
        return Ok(0);
    }
    let socket = engine_socket(cli)?;
    let _kept = keep_engine(cli, &socket).await?;
    let engine = Engine::dialed(dial);
    let mut needs = Needs::default();
    match command {
        Command::Play {
            replace,
            start,
            network,
            tls_verify,
            log_driver,
            userns,
            annotation,
            log_opt,
            publish,
            configmap,
            ip,
            mac,
            service_container,
            service_exit_code_propagation,
            build,
            context_dir,
            wait,
            publish_all,
            quiet: _,
            no_hosts,
            no_hostname,
            no_pod_prefix,
            seccomp_profile_root,
            access: access_args,
            files,
        } => {
            if context_dir.is_some() && build != Some(true) {
                bail!("--build must be specified when using --context-dir option");
            }
            if files.len() > 1 && files.iter().any(|f| f == "-") {
                bail!("- (the standard input) is the only YAML when it is given");
            }
            let mut data = Vec::new();
            for (n, f) in files.iter().enumerate() {
                if n > 0 {
                    data.extend_from_slice(b"\n---\n");
                }
                data.extend(read_yaml(f).await?);
            }
            // what --wait takes down: the YAML of the files
            let files_docs = documents(&data)?;
            // the ConfigMaps, as more documents of the YAML (as podman's
            // client sends them)
            for f in split(&configmap) {
                data.extend_from_slice(b"\n---\n");
                data.extend(read_yaml(&f).await?);
            }
            let docs = documents(&data)?;
            for o in &log_opt {
                if !o.contains('=') {
                    bail!("invalid --log-opt `{o}`: KEY=VALUE");
                }
            }
            let kv = |list: &[String]| {
                list.iter()
                    .map(|a| {
                        let (k, v) = a.split_once('=').unwrap_or((a.as_str(), ""));
                        (k.to_string(), v.to_string())
                    })
                    .collect::<std::collections::BTreeMap<_, _>>()
            };
            let context_dir = match context_dir {
                Some(d) => std::path::absolute(d)?,
                None => std::env::current_dir()?,
            };
            let args = PlayArgs {
                replace,
                start,
                build,
                context_dir,
                tls_verify,
                static_ips: split(&ip),
                static_macs: split(&mac),
                options: play::Options {
                    networks: split(&network),
                    userns,
                    log_driver,
                    annotations: kv(&annotation),
                    log_options: kv(&log_opt),
                    publish,
                    publish_all,
                    no_hosts,
                    no_hostname,
                    no_pod_prefix,
                    seccomp_profile_root,
                    systemd_unit: std::env::var("PODMAN_SYSTEMD_UNIT")
                        .ok()
                        .filter(|u| !u.is_empty()),
                },
            };
            let access = access(&access_args)?;
            let serving = service_container || wait;
            let signals = if serving { Some(Signals::new()?) } else { None };
            // (connected now: once confined it looks up no socket by name)
            let notify = std::env::var_os("NOTIFY_SOCKET")
                .filter(|s| !s.is_empty() && service_container)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .and_then(|p| {
                    std::os::unix::net::UnixDatagram::unbound()
                        .and_then(|s| s.connect(&p).map(|()| s))
                        .map_err(|e| eprintln!("Warning: cannot notify systemd: {e}"))
                        .ok()
                });
            let prepared = commands::prepare(&engine, &docs, args).await?;
            // (what needs a file or a program is done before: the host paths
            // are made, the credentials read, helpers run)
            prepared.make_host_paths()?;
            let resolved = access.resolve(&engine, &prepared).await?;
            confine::enter(&needs)?;
            if wait {
                println!("Use ctrl+c to clean up or wait for pods to exit");
            }
            let report = commands::play(&engine, &prepared, &resolved).await?;
            print!("{}", text::play(&report));
            if let Some(mut signals) = signals {
                let pods: Vec<String> = report.pods.iter().map(|p| p.id.clone()).collect();
                let containers: Vec<String> = report
                    .pods
                    .iter()
                    .flat_map(|p| p.containers.iter().cloned())
                    .collect();
                let ended = serve(
                    &engine,
                    &pods,
                    &containers,
                    notify.as_ref().filter(|_| service_container),
                    &mut signals,
                )
                .await?;
                if wait {
                    if ended.is_none() {
                        println!();
                    }
                    println!("Cleaning up containers, pods, and volumes...");
                    print!(
                        "{}",
                        text::down(&commands::down(&engine, &files_docs, true).await?)
                    );
                }
                return Ok(ended.map_or(0, |codes| {
                    text::propagated(&service_exit_code_propagation, &codes)
                }));
            }
        }
        Command::Down { force, file } => {
            let docs = documents(&read_yaml(&file).await?)?;
            confine::enter(&needs)?;
            print!(
                "{}",
                text::down(&commands::down(&engine, &docs, force).await?)
            );
        }
        Command::Apply {
            kubeconfig,
            ca_cert_file,
            ns,
            file,
            service,
            names,
        } => {
            let yaml = match (&file, names.is_empty()) {
                (Some(f), true) => String::from_utf8(read_yaml(f).await?)
                    .map_err(|_| anyhow::anyhow!("the YAML is not UTF-8"))?,
                (None, false) => {
                    describe::generate(
                        &engine,
                        &names,
                        &describe::GenerateOptions {
                            kind: generate::Kind::Pod,
                            replicas: 1,
                            service,
                            podman_only: false,
                        },
                    )
                    .await?
                }
                _ => bail!("name a YAML file (--file) or containers, pods and volumes"),
            };
            let opts = apply::ApplyOptions {
                kubeconfig: kubeconfig
                    .map(|k| k.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                ca_cert_file: ca_cert_file.unwrap_or_default(),
                namespace: ns.unwrap_or_default(),
            };
            let request = apply::prepare(&yaml, &opts).map_err(|e| anyhow::anyhow!(e))?;
            needs.api_port = Some(request.port);
            confine::enter(&needs)?;
            apply::send(&request)
                .await
                .map_err(|e| anyhow::anyhow!("error applying YAML to k8s cluster: {e}"))?;
            println!("Deployed!");
        }
        Command::Generate {
            service,
            r#type,
            replicas,
            filename,
            podman_only,
            names,
        } => {
            let kind: generate::Kind = r#type.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            // (the output is opened before: nothing is made once confined)
            let mut out = match &filename {
                Some(f) => Some(
                    std::fs::File::create(f)
                        .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", f.display()))?,
                ),
                None => None,
            };
            confine::enter(&needs)?;
            let yaml = describe::generate(
                &engine,
                &names,
                &describe::GenerateOptions {
                    kind,
                    replicas: replicas.max(1),
                    service,
                    podman_only,
                },
            )
            .await?;
            use std::io::Write;
            match (&mut out, &filename) {
                (Some(file), Some(f)) => file
                    .write_all(yaml.as_bytes())
                    .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", f.display()))?,
                _ => std::io::stdout().write_all(yaml.as_bytes())?,
            }
        }
        Command::SelfTest { .. } => unreachable!("handled above"),
    }
    Ok(0)
}

/// The signals that stop a play that stays (`--wait`, `--service-container`),
/// taken before the process confines itself.
struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
}

impl Signals {
    fn new() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    async fn stop(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.int.recv() => {}
        }
    }
}

/// Tell systemd the service is ready: `READY=1` to the socket of its
/// notification.
fn notify_ready(socket: &std::os::unix::net::UnixDatagram, containers: usize) {
    let status = format!("READY=1\nSTATUS={containers} container(s) running");
    if let Err(e) = socket.send(status.as_bytes()) {
        eprintln!("Warning: cannot notify systemd: {e}");
    }
}

/// `--service-container` and `--wait`: stay while the containers `ids`
/// run (with `notify`, tell systemd they do); their exit codes, none when
/// this process was asked to stop first: then the `pods` are stopped,
/// which ends the waits for their containers.
async fn serve(
    engine: &Engine,
    pods: &[String],
    ids: &[String],
    notify: Option<&std::os::unix::net::UnixDatagram>,
    signals: &mut Signals,
) -> anyhow::Result<Option<Vec<i32>>> {
    let mut waits = tokio::task::JoinSet::new();
    for id in ids {
        let (engine, id) = (engine.clone(), id.clone());
        waits.spawn(async move {
            match engine.container_wait(&id).await {
                Ok(code) => i32::try_from(code).unwrap_or(-1),
                Err(e) => {
                    eprintln!("Error: waiting for container {id}: {e}");
                    255
                }
            }
        });
    }
    if let Some(socket) = notify {
        notify_ready(socket, ids.len());
    }
    let mut codes = Vec::new();
    while codes.len() < ids.len() {
        tokio::select! {
            () = signals.stop() => {
                for p in pods {
                    if let Err(e) = engine.pod_stop(p, commands::STOP_TIMEOUT).await {
                        eprintln!("Error: stopping pod {p}: {e}");
                    }
                }
                return Ok(None);
            }
            done = waits.join_next() => match done {
                Some(Ok(code)) => codes.push(code),
                _ => break,
            },
        }
    }
    Ok(Some(codes))
}
