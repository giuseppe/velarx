// SPDX-License-Identifier: Apache-2.0
//! The ids of this process as the host sees them: for the client as for
//! the engine.

/// The map of the initial user namespace: every id is itself.
const INITIAL_UID_MAP: &str = "0 0 4294967295\n";

/// `/proc/self/uid_map`.  A kernel built without user namespaces has no
/// such file (and `/proc` is there): every process is in the initial one,
/// whose map is the identity.
fn read_uid_map() -> std::io::Result<String> {
    uid_map_or_initial(std::fs::read_to_string("/proc/self/uid_map"), || {
        std::fs::metadata("/proc/self/stat").is_ok()
    })
}

/// The map READ gave, or the initial one when there is no file of it in a
/// `/proc` that is mounted (MOUNTED).
fn uid_map_or_initial(
    read: std::io::Result<String>,
    mounted: impl FnOnce() -> bool,
) -> std::io::Result<String> {
    match read {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && mounted() => {
            Ok(INITIAL_UID_MAP.to_string())
        }
        read => read,
    }
}

/// `/proc/self/uid_map` could not be read: the engine cannot choose its
/// directories or its way of mapping ids without it, and a wrong guess
/// would put a root engine in a user's directories or the other way round.
/// Nothing of velarx works without `/proc` (it reads its descriptors, its
/// mounts and its cgroup there).
#[derive(Debug, thiserror::Error)]
#[error("cannot read /proc/self/uid_map (is /proc mounted?): {0}")]
pub struct IdsError(#[source] pub std::io::Error);

impl IdsError {
    /// For the places that have no way to hand the error on (the default of
    /// a setting, which the deserializer asks for without a result): report
    /// it and end the process with a failure status, as a command line
    /// that cannot be parsed ends.
    pub fn exit(&self) -> ! {
        eprintln!("velarx: {self}");
        std::process::exit(1)
    }

    /// Whether the I/O error `e` is this error handed on as one
    /// (`io::Error::other`).
    pub fn is_cause_of(e: &std::io::Error) -> bool {
        e.get_ref().is_some_and(|inner| inner.is::<Self>())
    }
}

/// Where the content of `/proc/self/uid_map` comes from.  The `*_with`
/// functions take it so that the failure of the read can be shown without a
/// host that has no `/proc`.
pub type MapSource<'a> = &'a dyn Fn() -> Result<String, IdsError>;

/// The content of `/proc/self/uid_map` of this process, as settled when it
/// was.
fn uid_map() -> Result<String, IdsError> {
    if let Some((_, map)) = SETTLED.get() {
        return Ok(map.clone());
    }
    read_uid_map().map_err(IdsError)
}

/// What [`settle`] read: whether the effective user is root, and the map.
static SETTLED: std::sync::OnceLock<(bool, String)> = std::sync::OnceLock::new();

/// Read the ids of this process once and for all.  A process that confines
/// itself calls it right before (Landlock leaves it no `/proc`), once its
/// user namespace is the one it keeps: [`rootful`] and
/// [`in_user_namespace`] answer from what it read from then on, in every
/// thread.  Not for a process that joins another user namespace later.
/// An unreadable map is an error the caller reports: the process does not
/// go on without knowing who it is.
pub fn settle() -> Result<(), IdsError> {
    if SETTLED.get().is_none() {
        let map = read_uid_map().map_err(IdsError)?;
        let _ = SETTLED.set((rustix::process::geteuid().is_root(), map));
    }
    Ok(())
}

/// Whether this process runs in a user namespace other than the initial one.
pub fn in_user_namespace() -> Result<bool, IdsError> {
    in_user_namespace_with(&uid_map)
}

/// [`in_user_namespace`] with the map from SOURCE.
pub fn in_user_namespace_with(source: MapSource) -> Result<bool, IdsError> {
    Ok(!is_initial_uid_map(&source()?))
}

/// Whether `uid_map` (the content of `/proc/self/uid_map`) is the identity
/// mapping of the initial user namespace.
fn is_initial_uid_map(uid_map: &str) -> bool {
    uid_map.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"]
}

/// [`rootful`] with its two facts given: the effective user is root, and
/// the content of `/proc/self/uid_map`.
pub fn rootful_from(euid_is_root: bool, uid_map: &str) -> bool {
    euid_is_root && is_initial_uid_map(uid_map)
}

/// Whether this process is root of the initial user namespace: the host's
/// root (the directories of the host, `/var/lib/velarx`, `/run/velarx`,
/// `/etc/velarx`, whatever `HOME` says under `sudo`; the system's
/// systemd manager; the kernel mounts EROFS images).  Root of a user
/// namespace (a rootless velarx that joined its own) is not.
pub fn rootful() -> Result<bool, IdsError> {
    rootful_with(&uid_map)
}

/// [`rootful`] with the map from SOURCE.
pub fn rootful_with(source: MapSource) -> Result<bool, IdsError> {
    let root = match SETTLED.get() {
        Some((root, _)) => *root,
        None => rustix::process::geteuid().is_root(),
    };
    Ok(rootful_from(root, &source()?))
}

/// The programs root of the host starts do not get the user's runtime
/// directory: the `$XDG_RUNTIME_DIR` that `sudo -E` leaves is the user's, and
/// the OCI runtime (or a hook) would make files in it.  A rootless process
/// passes it on.
pub fn scrub_runtime_dir(
    cmd: &mut std::process::Command,
) -> Result<&mut std::process::Command, IdsError> {
    if rootful()? {
        cmd.env_remove("XDG_RUNTIME_DIR");
    }
    Ok(cmd)
}

/// The id of the user outside of the user namespace of the process (the
/// process's own when it is in none).
pub fn host_uid() -> Result<u32, IdsError> {
    host_uid_with(&uid_map)
}

/// [`host_uid`] with the map from SOURCE.
pub fn host_uid_with(source: MapSource) -> Result<u32, IdsError> {
    Ok(host_uid_from(
        rustix::process::geteuid().as_raw(),
        &source()?,
    ))
}

/// [`host_uid`] of the user `euid` with the content of `/proc/self/uid_map`
/// given.  A user the map does not hold is not mapped to the host (the id
/// stays what it is, as the kernel shows it).
fn host_uid_from(euid: u32, uid_map: &str) -> u32 {
    crate::idmap::parse_proc_map(uid_map)
        .into_iter()
        .find_map(|r| {
            let off = euid.checked_sub(r.container_id)?;
            (off < r.size).then(|| r.host_id.checked_add(off)).flatten()
        })
        .unwrap_or(euid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIAL: &str = "         0          0 4294967295\n";

    #[test]
    fn rootful_is_root_of_the_initial_user_namespace() {
        assert!(rootful_from(true, INITIAL));
        // root of a user namespace
        assert!(!rootful_from(true, "         0       1000          1\n"));
        assert!(!rootful_from(true, "0 0 65536\n"));
        // not root
        assert!(!rootful_from(false, INITIAL));
    }

    /// A kernel without user namespaces has no map: the process is in the
    /// initial namespace, root there is the host's.  A `/proc` that is not
    /// mounted or a map that cannot be read tells nothing.
    #[test]
    fn a_kernel_without_user_namespaces_has_the_initial_map() {
        use std::io::{Error, ErrorKind};
        let missing = || Err(Error::from(ErrorKind::NotFound));
        let map = uid_map_or_initial(missing(), || true).unwrap();
        assert!(rootful_from(true, &map));
        assert_eq!(host_uid_from(1000, &map), 1000);
        assert!(uid_map_or_initial(missing(), || false).is_err());
        let denied = Err(Error::from(ErrorKind::PermissionDenied));
        assert!(uid_map_or_initial(denied, || true).is_err());
        assert_eq!(
            uid_map_or_initial(Ok("0 1000 1\n".into()), || true).unwrap(),
            "0 1000 1\n"
        );
    }

    #[test]
    fn the_host_uid_is_mapped_by_the_map() {
        assert_eq!(host_uid_from(0, "0 1000 1\n1 100000 65536\n"), 1000);
        assert_eq!(host_uid_from(5, "0 1000 1\n1 100000 65536\n"), 100004);
        assert_eq!(host_uid_from(7, "0 1000 1\n"), 7);
    }

    #[test]
    fn rootful_of_this_process_agrees_with_the_map() {
        let map = read_uid_map().unwrap();
        assert_eq!(
            rootful().unwrap(),
            rustix::process::geteuid().is_root() && is_initial_uid_map(&map)
        );
    }

    /// A confined process reaches no `/proc`: what it read of its ids
    /// before it confined itself is the answer then.
    #[test]
    fn the_ids_settled_are_answered_where_proc_cannot_be_read() {
        let (root, nested) = (rootful().unwrap(), in_user_namespace().unwrap());
        settle().unwrap();
        std::thread::spawn(move || {
            // (Landlock on this thread only: it reaches no file)
            let Some(ruleset) = velarx_sys::confine::Ruleset::new().unwrap() else {
                return;
            };
            ruleset.restrict_thread().unwrap();
            assert!(read_uid_map().is_err());
            assert_eq!(rootful().unwrap(), root);
            assert_eq!(in_user_namespace().unwrap(), nested);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn root_of_the_host_does_not_pass_the_runtime_directory_of_a_user() {
        let mut cmd = std::process::Command::new("true");
        cmd.env("XDG_RUNTIME_DIR", "/run/user/1000");
        scrub_runtime_dir(&mut cmd).unwrap();
        let value = cmd
            .get_envs()
            .find(|(k, _)| *k == "XDG_RUNTIME_DIR")
            .and_then(|(_, v)| v);
        assert_eq!(value.is_none(), rootful().unwrap());
    }

    /// An unreadable map is an error that names the cause, from every
    /// question that needs it; none of them guesses.
    #[test]
    fn an_unreadable_map_is_an_error_with_its_cause() {
        use std::io::{Error, ErrorKind};
        let denied = || {
            Err(IdsError(Error::new(
                ErrorKind::PermissionDenied,
                "denied by the test",
            )))
        };
        let e = rootful_with(&denied).unwrap_err();
        assert_eq!(e.0.kind(), ErrorKind::PermissionDenied);
        let text = e.to_string();
        assert!(text.contains("/proc/self/uid_map"), "{text}");
        assert!(text.contains("denied by the test"), "{text}");
        assert!(std::error::Error::source(&e).is_some());
        assert!(in_user_namespace_with(&denied).is_err());
        assert!(host_uid_with(&denied).is_err());
    }

    /// A default that cannot be told without the ids (the directories of a
    /// setting, of `--config`) ends the process with status 1 and the
    /// cause, not with a panic.
    #[test]
    fn a_default_without_the_ids_ends_the_process_with_the_cause() {
        const CHILD: &str = "VELARX_TEST_IDS_EXIT";
        const NO_LANDLOCK: &str = "no Landlock: not shown";
        if std::env::var_os(CHILD).is_some() {
            // (Landlock on this thread: /proc/self/uid_map is out of reach)
            let Some(ruleset) = velarx_sys::confine::Ruleset::new().unwrap() else {
                eprintln!("{NO_LANDLOCK}");
                return;
            };
            ruleset.restrict_thread().unwrap();
            let dirs = crate::dirs::DefaultDirs::current().unwrap_or_else(|e| e.exit());
            panic!("the directories without the ids: {:?}", dirs.run);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "ids::tests::a_default_without_the_ids_ends_the_process_with_the_cause",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains(NO_LANDLOCK) {
            return;
        }
        assert_eq!(out.status.code(), Some(1), "{err}");
        assert!(
            err.contains("velarx: cannot read /proc/self/uid_map (is /proc mounted?): "),
            "{err}"
        );
        assert!(!err.contains("panicked"), "{err}");
    }

    #[test]
    fn an_io_error_tells_whether_it_is_of_the_ids() {
        use std::io::{Error, ErrorKind};
        let ids = IdsError(Error::new(ErrorKind::NotFound, "no /proc"));
        assert!(IdsError::is_cause_of(&Error::other(ids)));
        assert!(!IdsError::is_cause_of(&Error::other("something else")));
        assert!(!IdsError::is_cause_of(&Error::from(ErrorKind::NotFound)));
    }

    #[test]
    fn a_readable_map_answers_the_questions() {
        let nested = || Ok("0 1000 1\n".to_string());
        assert!(in_user_namespace_with(&nested).unwrap());
        assert!(!rootful_with(&nested).unwrap());
        let initial = || Ok(INITIAL.to_string());
        assert!(!in_user_namespace_with(&initial).unwrap());
    }
}
