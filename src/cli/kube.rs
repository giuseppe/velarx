// SPDX-License-Identifier: Apache-2.0
//! `velarx kube ARGS` runs the program `velarx-kube` with ARGS: Kubernetes
//! YAML (`play`, `down`, `generate`, `apply`) is not part of the engine.
//! It is looked for next to this executable, then in `PATH`; the global
//! options `--config`, `--log-level` and `--log-format` come before ARGS.

use crate::cli::GlobalArgs;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

const PROGRAM: &str = "velarx-kube";

/// The program `velarx-kube`, if it is installed.
fn find(beside: Option<&Path>, path: Option<&OsStr>) -> Option<PathBuf> {
    let executable = |p: &PathBuf| {
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    beside
        .map(|dir| dir.join(PROGRAM))
        .into_iter()
        .chain(
            path.into_iter()
                .flat_map(std::env::split_paths)
                .map(|dir| dir.join(PROGRAM)),
        )
        .find(executable)
}

/// The command line of the program: the global options, then `args`.
fn command_line(global: &GlobalArgs, args: &[OsString]) -> Vec<OsString> {
    let mut line: Vec<OsString> = vec!["--config".into(), global.config.clone().into()];
    if let Some(level) = &global.log_level {
        line.extend(["--log-level".into(), level.into()]);
    }
    line.extend(["--log-format".into(), (&global.log_format).into()]);
    line.extend(args.iter().cloned());
    line
}

/// Run `velarx-kube` with `args`: it replaces this process.
pub fn run(global: &GlobalArgs, args: &[OsString]) -> anyhow::Result<()> {
    let exe = std::env::current_exe().ok();
    let beside = exe.as_deref().and_then(Path::parent);
    let path = std::env::var_os("PATH");
    let Some(program) = find(beside, path.as_deref()) else {
        anyhow::bail!("{PROGRAM} is not next to velarx nor in PATH");
    };
    let error = std::process::Command::new(&program)
        .args(command_line(global, args))
        .exec();
    anyhow::bail!("cannot run {}: {error}", program.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(dir: &Path, name: &str, mode: u32) {
        let path = dir.join(name);
        // not executed
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_program_is_beside_the_executable_first_then_in_the_path() {
        let beside = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        program(other.path(), PROGRAM, 0o755);
        let path = std::env::join_paths([other.path()]).unwrap();
        assert_eq!(
            find(Some(beside.path()), Some(&path)),
            Some(other.path().join(PROGRAM))
        );
        program(beside.path(), PROGRAM, 0o755);
        assert_eq!(
            find(Some(beside.path()), Some(&path)),
            Some(beside.path().join(PROGRAM))
        );
        assert_eq!(find(None, None), None);
    }

    #[test]
    fn a_file_that_cannot_run_is_not_a_program() {
        let dir = tempfile::tempdir().unwrap();
        program(dir.path(), PROGRAM, 0o644);
        let path = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find(None, Some(&path)), None);
    }

    #[test]
    fn the_global_options_come_before_the_arguments() {
        let cli = crate::cli::parse_for_test([
            "velarx",
            "--config",
            "/etc/c.toml",
            "--log-level",
            "debug",
            "kube",
            "--flag",
            "x",
        ])
        .unwrap();
        let crate::cli::Commands::Kube { args } = &cli.command else {
            panic!("not the kube command");
        };
        let line: Vec<_> = command_line(&cli.global, args)
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            line,
            [
                "--config",
                "/etc/c.toml",
                "--log-level",
                "debug",
                "--log-format",
                "text",
                "--flag",
                "x"
            ]
        );
    }
}
