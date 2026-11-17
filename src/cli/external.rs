// SPDX-License-Identifier: Apache-2.0
//! `velarx NAME ARGS`, for a NAME that is no command of velarx, runs the
//! program `velarx-NAME` (as git and cargo do), so that what is not part
//! of the engine can be installed beside it.  It is looked for next to this
//! executable, then in `PATH`; the global options `--config`,
//! `--log-level` and `--log-format` come before ARGS.

use crate::cli::GlobalArgs;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};

/// The program of the command `name`, if it is installed.
fn find(name: &OsStr, beside: Option<&Path>, path: Option<&OsStr>) -> Option<PathBuf> {
    let mut program = OsString::from("velarx-");
    program.push(name);
    let executable = |p: &PathBuf| {
        p.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    beside
        .map(|dir| dir.join(&program))
        .into_iter()
        .chain(
            path.into_iter()
                .flat_map(std::env::split_paths)
                .map(|dir| dir.join(&program)),
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

/// Run the program of `args[0]` with the rest: it replaces this process.
pub fn run(global: &GlobalArgs, args: &[OsString]) -> anyhow::Result<()> {
    let name = args
        .first()
        .ok_or_else(|| anyhow::anyhow!("no command given"))?;
    if name.as_encoded_bytes().contains(&b'/') {
        anyhow::bail!("{}: not a command", name.to_string_lossy());
    }
    let exe = std::env::current_exe().ok();
    let beside = exe.as_deref().and_then(Path::parent);
    let path = std::env::var_os("PATH");
    let Some(program) = find(name, beside, path.as_deref()) else {
        anyhow::bail!(
            "unknown command `{0}`: the program velarx-{0} is not next to velarx nor in PATH",
            name.to_string_lossy()
        );
    };
    let error = std::process::Command::new(&program)
        .args(command_line(global, &args[1..]))
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
        program(other.path(), "velarx-foo", 0o755);
        program(other.path(), "velarx-bar", 0o755);
        program(beside.path(), "velarx-bar", 0o755);
        let path = std::env::join_paths([other.path()]).unwrap();
        let find = |n: &str| find(OsStr::new(n), Some(beside.path()), Some(&path));
        assert_eq!(find("foo"), Some(other.path().join("velarx-foo")));
        assert_eq!(find("bar"), Some(beside.path().join("velarx-bar")));
        assert_eq!(find("missing"), None);
    }

    #[test]
    fn a_file_that_cannot_run_is_not_a_program() {
        let dir = tempfile::tempdir().unwrap();
        program(dir.path(), "velarx-foo", 0o644);
        let path = std::env::join_paths([dir.path()]).unwrap();
        assert_eq!(find(OsStr::new("foo"), None, Some(&path)), None);
    }

    #[test]
    fn the_global_options_come_before_the_arguments() {
        let cli = crate::cli::parse_for_test([
            "velarx",
            "--config",
            "/etc/c.toml",
            "--log-level",
            "debug",
            "foo",
            "--flag",
            "x",
        ])
        .unwrap();
        let crate::cli::Commands::External(args) = &cli.command else {
            panic!("not an external command");
        };
        assert_eq!(args[0], "foo");
        let line: Vec<_> = command_line(&cli.global, &args[1..])
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
