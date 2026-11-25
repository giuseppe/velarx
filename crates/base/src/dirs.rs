// SPDX-License-Identifier: Apache-2.0
//! Where the engine and its frontends keep their files when nothing says.

use std::path::PathBuf;

/// Why the directories of this process could not be settled.
#[derive(Debug, thiserror::Error)]
pub enum DirsError {
    #[error(transparent)]
    Ids(#[from] crate::ids::IdsError),
    /// the directory for the runtime files of a user with no
    /// `XDG_RUNTIME_DIR` is refused or cannot be made
    #[error("{0}")]
    Run(std::io::Error),
}

impl DirsError {
    /// For the places that have no way to hand the error on (see
    /// [`IdsError::exit`](crate::ids::IdsError::exit)).
    pub fn exit(&self) -> ! {
        eprintln!("velarx: {self}");
        std::process::exit(1)
    }
}

/// The directories the defaults are made of.  Root of the initial user
/// namespace (`ids::rootful`) uses the host's, whatever `HOME` and
/// `XDG_*` say (they stay set under `sudo`); the others follow them.
pub struct DefaultDirs {
    /// where the state of the storage lives
    pub data: PathBuf,
    /// sockets, locks, the state of the running containers
    pub run: PathBuf,
    /// the configuration file
    pub config_file: PathBuf,
}

impl DefaultDirs {
    /// `env`: the environment, a variable that is not set or is empty gives
    /// `None`.
    pub fn resolve(rootful: bool, env: impl Fn(&str) -> Option<PathBuf>) -> Self {
        Self::resolve_with(rootful, env, |_| {
            Ok::<_, std::convert::Infallible>("/run/velarx".into())
        })
        .unwrap_or_else(|e| match e {})
    }

    /// [`resolve`](Self::resolve) with `runtime`, the directory of a user
    /// whose environment has no `XDG_RUNTIME_DIR`.
    fn resolve_with<E>(
        rootful: bool,
        env: impl Fn(&str) -> Option<PathBuf>,
        runtime: impl Fn(&dyn Fn(&str) -> Option<PathBuf>) -> Result<PathBuf, E>,
    ) -> Result<Self, E> {
        if rootful {
            return Ok(Self {
                data: "/var/lib/velarx".into(),
                run: "/run/velarx".into(),
                config_file: "/etc/velarx/config.toml".into(),
            });
        }
        let data = match (env("XDG_DATA_HOME"), env("HOME")) {
            (Some(xdg), _) => xdg,
            (None, Some(home)) => home.join(".local/share"),
            (None, None) => PathBuf::from("/var/lib"),
        };
        let run = match env("XDG_RUNTIME_DIR") {
            Some(runtime) => runtime.join("velarx"),
            None => runtime(&env)?,
        };
        let config_file = match (env("XDG_CONFIG_HOME"), env("HOME")) {
            (Some(xdg), _) => xdg.join("velarx/config.toml"),
            (None, Some(home)) => home.join(".config/velarx/config.toml"),
            (None, None) => PathBuf::from("/etc/velarx/config.toml"),
        };
        Ok(Self {
            data: data.join("velarx"),
            run,
            config_file,
        })
    }

    /// Those of this process.
    pub fn current() -> Result<Self, DirsError> {
        Self::resolve_with(
            crate::ids::rootful()?,
            |name| {
                std::env::var_os(name)
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            },
            |env| private_run_dir(env).map_err(DirsError::Run),
        )
    }
}

/// The directory of a user without `XDG_RUNTIME_DIR` (a `su -`, cron, ssh
/// without logind), as podman finds it: `/run/user/UID` when it is theirs
/// and private, else `$TMPDIR/velarx-run-UID`, made `0700`.  An error that
/// names the directory when it cannot be made or is not theirs and private.
fn private_run_dir(env: &dyn Fn(&str) -> Option<PathBuf>) -> std::io::Result<PathBuf> {
    private_run_dir_in(
        rustix::process::getuid().as_raw(),
        std::path::Path::new("/run/user"),
        &env("TMPDIR").unwrap_or_else(|| "/tmp".into()),
    )
}

fn private_run_dir_in(
    uid: u32,
    run_user: &std::path::Path,
    tmpdir: &std::path::Path,
) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let user = run_user.join(uid.to_string());
    if check_private(&user, uid).is_ok() {
        return Ok(user.join("velarx"));
    }
    let tmp = tmpdir.join(format!("velarx-run-{uid}"));
    // (a directory that is there is only theirs if they made it)
    match std::fs::DirBuilder::new().mode(0o700).create(&tmp) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(std::io::Error::new(
            e.kind(),
            format!("cannot make `{}`: {e}", tmp.display()),
        )),
    }
    .and_then(|()| check_private(&tmp, uid))
    .map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("{e}; set XDG_RUNTIME_DIR to use another directory"),
        )
    })?;
    Ok(tmp.join("velarx"))
}

/// Whether `dir` is a directory (not a link) of the user `uid` that only
/// they can enter; if not, an error that names it and says why.
fn check_private(dir: &std::path::Path, uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let refused = |why: String| std::io::Error::other(format!("`{}` {why}", dir.display()));
    let m =
        std::fs::symlink_metadata(dir).map_err(|e| refused(format!("cannot be looked at: {e}")))?;
    if !m.is_dir() {
        return Err(refused("is not a directory".into()));
    }
    if m.uid() != uid {
        return Err(refused(format!("belongs to user {}, not {uid}", m.uid())));
    }
    if m.mode() & 0o077 != 0 {
        return Err(refused(format!(
            "can be entered by others (mode {:o})",
            m.mode() & 0o777
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_without_a_runtime_dir_gets_a_private_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let uid = rustix::process::getuid().as_raw();
        let none = dir.path().join("no-run-user");
        let tmp = dir.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        // no /run/user/UID: the directory of the temporary files, made private
        let run = private_run_dir_in(uid, &none, &tmp).unwrap();
        assert_eq!(run, tmp.join(format!("velarx-run-{uid}/velarx")));
        assert_eq!(private_run_dir_in(uid, &none, &tmp).unwrap(), run);
        // /run/user/UID that is theirs and private wins
        let run_user = dir.path().join("run-user");
        let own = run_user.join(uid.to_string());
        std::fs::create_dir_all(&own).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            private_run_dir_in(uid, &run_user, &tmp).unwrap(),
            own.join("velarx")
        );
        // one that others can enter is refused, and named
        let open = tmp.join(format!("velarx-run-{uid}"));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let e = private_run_dir_in(uid, &none, &tmp)
            .unwrap_err()
            .to_string();
        assert_eq!(
            e,
            format!(
                "`{}` can be entered by others (mode 755); set XDG_RUNTIME_DIR to use another directory",
                open.display()
            )
        );
        // a directory of the temporary files that cannot be made is named
        let e = private_run_dir_in(uid, &none, &tmp.join("none"))
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with(&format!("cannot make `{}", tmp.join("none").display()))
                && e.ends_with("; set XDG_RUNTIME_DIR to use another directory"),
            "{e}"
        );
    }

    /// A directory of another user is refused with its name and owner:
    /// the user it is checked for is not the one that made it.
    #[test]
    fn a_directory_of_another_user_is_refused_by_name() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let uid = rustix::process::getuid().as_raw();
        let own = dir.path().join("own");
        std::fs::create_dir(&own).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
        check_private(&own, uid).unwrap();
        let e = check_private(&own, uid + 1).unwrap_err().to_string();
        assert_eq!(
            e,
            format!("`{}` belongs to user {uid}, not {}", own.display(), uid + 1)
        );
        // in the one run directory a user may use, the refusal is the error
        let tmp = dir.path().join("tmp");
        std::fs::create_dir(&tmp).unwrap();
        let squatted = tmp.join(format!("velarx-run-{}", uid + 1));
        std::fs::create_dir(&squatted).unwrap();
        let e = private_run_dir_in(uid + 1, &dir.path().join("none"), &tmp)
            .unwrap_err()
            .to_string();
        assert_eq!(
            e,
            format!(
                "`{}` belongs to user {uid}, not {}; set XDG_RUNTIME_DIR to use another directory",
                squatted.display(),
                uid + 1
            )
        );
        // a link is not a directory of the user
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&own, &link).unwrap();
        assert!(check_private(&link, uid)
            .unwrap_err()
            .to_string()
            .contains("is not a directory"));
    }

    #[test]
    fn resolve_keeps_the_rootful_fallback_without_a_runtime() {
        let d = DefaultDirs::resolve(false, |n| (n == "HOME").then(|| PathBuf::from("/home/v")));
        assert_eq!(d.run, PathBuf::from("/run/velarx"));
    }
}
