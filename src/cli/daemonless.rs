// SPDX-License-Identifier: Apache-2.0
use super::*;

/// What a command does when no engine service answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Daemonless {
    /// The engine of the command, in its process, runs it.
    InProcess,
    /// It needs a server that lives on: this is what for.
    NeedsServer(&'static str),
    /// It does not use the engine service (or it is the server, or the engine's
    /// own): there is nothing to run in an engine.
    Standalone(&'static str),
}

/// What `cmd` does with no engine service.  Every command runs in the engine
/// of its own process (the services the server has, built for the command,
/// whose operations it calls) unless it follows what happens after the
/// command ended, or asks about the server itself.  A new command is
/// classified here, and in the test of this module that lists them all.
pub fn daemonless(cmd: &Commands) -> Daemonless {
    use Daemonless::*;
    match cmd {
        Commands::Image(ImageCommands::Trust(_)) => {
            Standalone("it edits the policy and registries.d files")
        }
        Commands::Image(ImageCommands::GenerateSigstoreKey { .. }) => {
            Standalone("it writes the files of a key pair")
        }
        Commands::Image(_)
        | Commands::Container(_)
        | Commands::Volume(_)
        | Commands::Network(_)
        | Commands::Pod(_)
        | Commands::Secret(_)
        | Commands::Manifest(_)
        | Commands::Artifact(_)
        | Commands::Healthcheck(_)
        | Commands::Info { .. }
        | Commands::Stats { .. } => InProcess,
        Commands::System(c) => match c {
            SystemCommands::Df { .. }
            | SystemCommands::Prune { .. }
            | SystemCommands::Gc { .. }
            | SystemCommands::Stores { .. }
            | SystemCommands::Info { .. }
            | SystemCommands::Inspect { .. }
            | SystemCommands::Check { .. } => InProcess,
            SystemCommands::Restart => {
                NeedsServer("`system restart` (it restarts the engine service)")
            }
        },
        // (`--stream` follows what the backend keeps: the journal or the file)
        Commands::Events { .. } => InProcess,
        Commands::AutoUpdate(_) => InProcess,
        Commands::Health => NeedsServer("`health` (it reports the health of the engine service)"),
        Commands::Varlink { .. } => Standalone("it is the engine service"),
        Commands::Kube { .. } => Standalone("it is another program"),
        Commands::Unshare { .. } => Standalone("it joins the namespaces of the rootless user"),
        // (a password of a secret is in the engine's store)
        Commands::Registry(RegistryCommands::Login {
            secret: Some(_), ..
        }) => InProcess,
        Commands::Registry(_) => Standalone("it edits the file of credentials"),
        Commands::Quadlet(_) => Standalone("it links the systemd generators"),
        Commands::Version { .. } => Standalone("it asks the server only if one is named"),
        Commands::Completion { .. } => Standalone("it prints a script"),
    }
}

/// Whether the process that runs `cmd` is in the rootless user's user and
/// mount namespaces (`userns::tree`): the engine of the command, in its
/// process or as the engine service.  The commands that only ask a server, and
/// those that touch no container, have no use for them.
pub fn joins_namespaces(cmd: &Commands) -> bool {
    match daemonless(cmd) {
        Daemonless::InProcess => true,
        Daemonless::NeedsServer(_) => false,
        Daemonless::Standalone(_) => {
            matches!(cmd, Commands::Varlink { .. } | Commands::Unshare { .. })
        }
    }
}

/// Whether the engine of `cmd` (in the process, `joins_namespaces`) may
/// start processes that outlive it, a container's monitor or what the
/// network needs, or lives on itself (the engine service, `unshare`): the
/// process is recorded as a holder of the namespaces from its join on, so
/// that the holder it joined through cannot end, and another command make a
/// second pair of namespaces, before the monitor that holds them is
/// recorded.  The commands that only read write nothing; a command not
/// named here is a holder (a holder too many costs a write, one too few
/// ends the namespaces under what lives in them).
pub fn starts_processes(cmd: &Commands) -> bool {
    match cmd {
        Commands::Container(c) => container_starts_processes(c),
        Commands::Pod(c) => !matches!(c, PodCommands::List { .. }),
        Commands::Network(c) => !matches!(
            c,
            NetworkCommands::List { .. }
                | NetworkCommands::Exists { .. }
                | NetworkCommands::Inspect { .. }
        ),
        Commands::Image(_)
        | Commands::Volume(_)
        | Commands::Secret(_)
        | Commands::Manifest(_)
        | Commands::Artifact(_)
        | Commands::Registry(_)
        | Commands::Info { .. }
        | Commands::Stats { .. }
        | Commands::Events { .. }
        | Commands::System(_) => false,
        // (`healthcheck run` restarts a container whose policy says so)
        _ => true,
    }
}

/// [`starts_processes`] for a container command.
pub fn container_starts_processes(c: &ContainerCommands) -> bool {
    !matches!(
        c,
        ContainerCommands::List { .. }
            | ContainerCommands::Exists { .. }
            | ContainerCommands::Port { .. }
            | ContainerCommands::Inspect { .. }
            | ContainerCommands::Logs { .. }
            | ContainerCommands::ReopenLog { .. }
            | ContainerCommands::Top { .. }
            | ContainerCommands::Diff { .. }
            | ContainerCommands::Stats { .. }
            | ContainerCommands::Wait { .. }
    )
}

#[cfg(test)]
mod daemonless_tests {
    use super::*;

    fn of(args: &[&str]) -> Daemonless {
        let argv = std::iter::once("velarx").chain(args.iter().copied());
        let argv = podman_layout(argv.map(Into::into).collect()).unwrap();
        daemonless(&parse_for_test(argv).unwrap().command)
    }

    #[test]
    fn the_environment_names_the_server() {
        assert_eq!(
            socket_of_host("unix:///run/s.sock"),
            Ok(PathBuf::from("/run/s.sock"))
        );
        assert_eq!(
            socket_of_host("/run/s.sock"),
            Ok(PathBuf::from("/run/s.sock"))
        );
        assert!(socket_of_host("tcp://127.0.0.1:8080").is_err());
        assert!(socket_of_host("ssh://u@h/run/s").is_err());
        assert!(socket_of_host("unix://relative").is_err());
        assert_eq!(socket_from_env(None), None);
        assert_eq!(socket_from_env(Some("".into())), None);
        assert_eq!(
            socket_from_env(Some("/s".into())),
            Some(PathBuf::from("/s"))
        );
    }

    /// `varlink` serves the engine interface, with the socket and
    /// the lifeline a frontend passes; it takes no URI.
    #[test]
    fn the_engine_service_takes_the_descriptors_of_the_frontend_that_starts_it() {
        let cli = parse_for_test([
            "velarx",
            "varlink",
            "--listen-fd",
            "3",
            "--lifeline-fd",
            "4",
            "--time",
            "0",
        ])
        .unwrap();
        let Commands::Varlink {
            time,
            listen_fd,
            lifeline_fd,
            ..
        } = cli.command
        else {
            panic!("not the service");
        };
        assert_eq!(time, Some(0));
        assert_eq!((listen_fd, lifeline_fd), (Some(3), Some(4)));
        // the time is the configuration's unless given
        let cli = parse_for_test(["velarx", "varlink"]).unwrap();
        let Commands::Varlink { time, .. } = cli.command else {
            panic!("not the service");
        };
        assert_eq!(time, None);
        // the engine listens on its socket: no address
        assert!(parse_for_test(["velarx", "varlink", "unix:///x"]).is_err());
        assert!(parse_for_test(["velarx", "varlink", "--engine"]).is_err());
    }

    #[test]
    fn fsck_is_the_check_and_fix_the_repair() {
        let cli = parse_for_test(["velarx", "system", "fsck", "--fix"]).unwrap();
        let Commands::System(SystemCommands::Check { repair, quick, .. }) = cli.command else {
            panic!("fsck is not the check");
        };
        assert!(repair && !quick);
    }

    #[test]
    fn what_runs_without_a_server() {
        for args in [
            &["image", "pull", "x"][..],
            &["image", "list"],
            &["image", "remove", "x"],
            &["volume", "create", "v"],
            &["volume", "list"],
            &["network", "ls"],
            &["container", "inspect", "c"],
            &["container", "logs", "c"],
            &["container", "exec", "c", "true"],
            &["container", "wait", "c"],
            &["events", "--stream=false"],
            &["events"],
        ] {
            assert_eq!(of(args), Daemonless::InProcess, "{args:?}");
        }
        assert_eq!(of(&["auto-update"]), Daemonless::InProcess);
        assert_eq!(of(&["pod", "list"]), Daemonless::InProcess);
        assert_eq!(of(&["network", "create", "n"]), Daemonless::InProcess);
        assert_eq!(of(&["pod", "stats"]), Daemonless::InProcess);
        // `login --secret` reads the secret in the engine
        assert_eq!(of(&["login", "--secret", "s", "r"]), Daemonless::InProcess);
        assert!(matches!(of(&["login", "r"]), Daemonless::Standalone(_)));
    }

    #[test]
    fn what_runs_in_process() {
        for args in [
            &["build", "-t", "x", "."][..],
            &["image", "build", "-t", "x", "."],
            &["push", "x"],
            &["image", "push", "x"],
            &["commit", "c", "x"],
            &["image", "commit", "c", "x"],
            &["container", "commit", "c", "x"],
            &["container", "create", "x"],
            &["container", "run", "x"],
            &["container", "cp", "a", "b"],
            &["system", "check"],
            &["system", "fsck"],
            &["system", "prune"],
            &["system", "gc"],
            &["system", "df"],
            &["manifest", "create", "m"],
            &["secret", "ls"],
            &["healthcheck", "run", "c"],
            &["stats", "--no-stream"],
            &["auto-update", "--dry-run"],
            &["events"],
        ] {
            assert_eq!(of(args), Daemonless::InProcess, "{args:?}");
        }
        for args in [&["system", "restart"][..], &["health"]] {
            assert!(matches!(of(args), Daemonless::NeedsServer(_)), "{args:?}");
        }
        for args in [
            &["varlink"][..],
            &["registry", "logout", "--all"],
            &["version"],
            &["completion", "bash"],
        ] {
            assert!(matches!(of(args), Daemonless::Standalone(_)), "{args:?}");
        }
    }

    #[test]
    fn kube_is_another_program() {
        assert!(matches!(of(&["kube", "play"]), Daemonless::Standalone(_)));
    }

    /// Every command the command line has, as the words that name it.
    const COMMANDS: &[&str] = &[
        "artifact add",
        "artifact extract",
        "artifact inspect",
        "artifact ls",
        "artifact pull",
        "artifact push",
        "artifact rm",
        "auto-update",
        "completion",
        "container attach",
        "container checkpoint",
        "container clone",
        "container cp",
        "container create",
        "container diff",
        "container exec",
        "container exists",
        "container export",
        "container init",
        "container inspect",
        "container kill",
        "container list",
        "container logs",
        "container mount",
        "container pause",
        "container port",
        "container prune",
        "container rename",
        "container reopen-log",
        "container restart",
        "container restore",
        "container rm",
        "container run",
        "container start",
        "container stats",
        "container stop",
        "container top",
        "container unmount",
        "container unpause",
        "container update",
        "container wait",
        "events",
        "health",
        "healthcheck inspect",
        "healthcheck ls",
        "healthcheck run",
        "image build",
        "image commit",
        "image complete",
        "image pulls",
        "image diff",
        "image exists",
        "image generate-sigstore-key",
        "image history",
        "image import",
        "image inspect",
        "image list",
        "image load",
        "image prune",
        "image pull",
        "image push",
        "image remove",
        "image save",
        "image sign",
        "image search",
        "image tag",
        "image tree",
        "image trust set",
        "image trust show",
        "image untag",
        "info",
        "kube",
        "manifest add",
        "manifest annotate",
        "manifest create",
        "manifest exists",
        "manifest inspect",
        "manifest push",
        "manifest remove",
        "manifest rm",
        "network connect",
        "network create",
        "network disconnect",
        "network reload",
        "network exists",
        "network inspect",
        "network list",
        "network prune",
        "network remove",
        "network update",
        "pod clone",
        "pod create",
        "pod exists",
        "pod inspect",
        "pod kill",
        "pod list",
        "pod logs",
        "pod pause",
        "pod prune",
        "pod restart",
        "pod rm",
        "pod start",
        "pod stats",
        "pod stop",
        "pod top",
        "pod unpause",
        "pod update",
        "quadlet disable",
        "quadlet enable",
        "quadlet status",
        "registry login",
        "registry logout",
        "secret create",
        "secret exists",
        "secret inspect",
        "secret ls",
        "secret rm",
        "stats",
        "system check",
        "system df",
        "system gc",
        "system info",
        "system inspect",
        "system prune",
        "system restart",
        "system stores",
        "unshare",
        "varlink",
        "version",
        "volume create",
        "volume exists",
        "volume export",
        "volume import",
        "volume inspect",
        "volume list",
        "volume mount",
        "volume prune",
        "volume reload",
        "volume remove",
        "volume unmount",
    ];

    /// The words of the commands that take no subcommand.
    fn leaves(cmd: &clap::Command, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        let subs: Vec<_> = cmd
            .get_subcommands()
            .filter(|c| c.get_name() != "help")
            .collect();
        if subs.is_empty() {
            out.push(path.clone());
        }
        for sub in subs {
            path.push(sub.get_name().to_string());
            leaves(sub, path, out);
            path.pop();
        }
    }

    /// The command line of a leaf: its words and what it requires.
    fn line_of(cmd: &clap::Command, words: &[String], value: &str) -> Vec<String> {
        let mut sub = cmd;
        for w in words {
            sub = sub.find_subcommand(w).expect("a command of the path");
        }
        let mut line = vec!["velarx".to_string()];
        line.extend(words.iter().cloned());
        for arg in sub.get_arguments().filter(|a| a.is_required_set()) {
            let takes = arg.get_action().takes_values();
            let v = arg
                .get_possible_values()
                .first()
                .map_or(value.to_string(), |p| p.get_name().to_string());
            match arg.get_long() {
                Some(long) => {
                    line.push(format!("--{long}"));
                    if takes {
                        line.push(v);
                    }
                }
                None => line.push(v),
            }
        }
        line
    }

    #[test]
    fn every_command_is_classified() {
        use clap::CommandFactory;
        let found = std::thread::Builder::new()
            .stack_size(8 << 20)
            .spawn(|| {
                let root = Cli::command();
                let mut out = Vec::new();
                leaves(&root, &mut Vec::new(), &mut out);
                out.into_iter()
                    .map(|words| {
                        let line = ["x", "1"].iter().find_map(|v| {
                            let line = line_of(&root, &words, v);
                            crate::cli::try_parse_with(
                                crate::cli::command_line(),
                                end_options_after_operand(
                                    &root,
                                    line.iter().map(Into::into).collect(),
                                ),
                            )
                            .ok()
                            .map(|cli| (line, cli.command))
                        });
                        (words.join(" "), line)
                    })
                    .map(|(name, parsed)| {
                        let (line, command) =
                            parsed.unwrap_or_else(|| panic!("`{name}` does not parse"));
                        (name, line, daemonless(&command), joins_namespaces(&command))
                    })
                    .collect::<Vec<_>>()
            })
            .expect("a thread for the commands")
            .join()
            .expect("the commands");
        let names: Vec<&str> = found.iter().map(|(n, _, _, _)| n.as_str()).collect();
        for name in &names {
            assert!(
                COMMANDS.contains(name),
                "`{name}` is a new command: add it to COMMANDS, and give it its class in \
                 `daemonless` (it runs in process, or why a server must)"
            );
        }
        for known in COMMANDS {
            assert!(
                names.contains(known),
                "`{known}` is gone: take it out of COMMANDS"
            );
        }
        // the ones that need a server say what for
        let mut not_engine: Vec<String> = found
            .iter()
            .filter(|(_, _, class, _)| *class != Daemonless::InProcess)
            .map(|(name, _, class, _)| format!("{name}: {class:?}"))
            .collect();
        not_engine.sort();
        let expected = [
            "completion: Standalone(\"it prints a script\")",
            "health: NeedsServer(\"`health` (it reports the health of the engine service)\")",
            "image generate-sigstore-key: Standalone(\"it writes the files of a key pair\")",
            "image trust set: Standalone(\"it edits the policy and registries.d files\")",
            "image trust show: Standalone(\"it edits the policy and registries.d files\")",
            "kube: Standalone(\"it is another program\")",
            "quadlet disable: Standalone(\"it links the systemd generators\")",
            "quadlet enable: Standalone(\"it links the systemd generators\")",
            "quadlet status: Standalone(\"it links the systemd generators\")",
            "registry login: Standalone(\"it edits the file of credentials\")",
            "registry logout: Standalone(\"it edits the file of credentials\")",
            "system restart: NeedsServer(\"`system restart` (it restarts the engine service)\")",
            "unshare: Standalone(\"it joins the namespaces of the rootless user\")",
            "varlink: Standalone(\"it is the engine service\")",
            "version: Standalone(\"it asks the server only if one is named\")",
        ];
        assert_eq!(not_engine, expected);
        // the commands whose process joins the rootless namespaces: those
        // that run in an engine, the engine service, the
        // monitor and `unshare`; none of those that ask a server or touch
        // no container
        let mut apart: Vec<&str> = found
            .iter()
            .filter(|(_, _, _, joins)| !*joins)
            .map(|(name, _, _, _)| name.as_str())
            .collect();
        apart.sort();
        assert_eq!(
            apart,
            [
                "completion",
                "health",
                "image generate-sigstore-key",
                "image trust set",
                "image trust show",
                "kube",
                "quadlet disable",
                "quadlet enable",
                "quadlet status",
                "registry login",
                "registry logout",
                "system restart",
                "version",
            ]
        );
        for (name, _, class, joins) in &found {
            assert!(
                !(*class == Daemonless::InProcess && !*joins),
                "`{name}` runs in an engine of its process: it joins the namespaces"
            );
        }
    }
}
