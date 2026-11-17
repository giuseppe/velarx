// SPDX-License-Identifier: Apache-2.0
//! Where the engine and its frontends keep their files when nothing says.

use std::path::PathBuf;

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
        Self::resolve_with(rootful, env, |_| None)
    }

    /// [`resolve`](Self::resolve) with `runtime`, the directory of a user
    /// whose environment has no `XDG_RUNTIME_DIR`.
    fn resolve_with(
        rootful: bool,
        env: impl Fn(&str) -> Option<PathBuf>,
        runtime: impl Fn(&dyn Fn(&str) -> Option<PathBuf>) -> Option<PathBuf>,
    ) -> Self {
        if rootful {
            return Self {
                data: "/var/lib/velarx".into(),
                run: "/run/velarx".into(),
                config_file: "/etc/velarx/config.toml".into(),
            };
        }
        let data = match (env("XDG_DATA_HOME"), env("HOME")) {
            (Some(xdg), _) => xdg,
            (None, Some(home)) => home.join(".local/share"),
            (None, None) => PathBuf::from("/var/lib"),
        };
        let run = match env("XDG_RUNTIME_DIR") {
            Some(runtime) => runtime.join("velarx"),
            None => runtime(&env).unwrap_or_else(|| PathBuf::from("/run/velarx")),
        };
        let config_file = match (env("XDG_CONFIG_HOME"), env("HOME")) {
            (Some(xdg), _) => xdg.join("velarx/config.toml"),
            (None, Some(home)) => home.join(".config/velarx/config.toml"),
            (None, None) => PathBuf::from("/etc/velarx/config.toml"),
        };
        Self {
            data: data.join("velarx"),
            run,
            config_file,
        }
    }

    /// Those of this process.
    pub fn current() -> Result<Self, crate::ids::IdsError> {
        Ok(Self::resolve_with(
            crate::ids::rootful()?,
            |name| {
                std::env::var_os(name)
                    .filter(|v| !v.is_empty())
                    .map(PathBuf::from)
            },
            private_run_dir,
        ))
    }
}

/// The directory of a user without `XDG_RUNTIME_DIR` (a `su -`, cron, ssh
/// without logind), as podman finds it: `/run/user/UID` when it is theirs
/// and private, else `$TMPDIR/velarx-run-UID`, made `0700`; none when
/// neither is.
fn private_run_dir(env: &dyn Fn(&str) -> Option<PathBuf>) -> Option<PathBuf> {
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
) -> Option<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let private = |dir: &std::path::Path| {
        std::fs::symlink_metadata(dir)
            .is_ok_and(|m| m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0)
    };
    let user = run_user.join(uid.to_string());
    if private(&user) {
        return Some(user.join("velarx"));
    }
    let tmp = tmpdir.join(format!("velarx-run-{uid}"));
    // (a directory that is there is only theirs if they made it)
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&tmp);
    private(&tmp).then(|| tmp.join("velarx"))
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
        assert_eq!(private_run_dir_in(uid, &none, &tmp), Some(run));
        // /run/user/UID that is theirs and private wins
        let run_user = dir.path().join("run-user");
        let own = run_user.join(uid.to_string());
        std::fs::create_dir_all(&own).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            private_run_dir_in(uid, &run_user, &tmp),
            Some(own.join("velarx"))
        );
        // one that others can enter is no one's own: nothing
        let open = tmp.join(format!("velarx-run-{uid}"));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(private_run_dir_in(uid, &none, &tmp), None);
        // another user's is none of theirs
        assert_eq!(private_run_dir_in(uid + 1, &none, &tmp), None);
    }

    #[test]
    fn resolve_keeps_the_rootful_fallback_without_a_runtime() {
        let d = DefaultDirs::resolve(false, |n| (n == "HOME").then(|| PathBuf::from("/home/v")));
        assert_eq!(d.run, PathBuf::from("/run/velarx"));
    }
}
