// SPDX-License-Identifier: Apache-2.0
//! Limits a process puts on itself.

use std::io;

/// No privileges to gain, no core dumps: for the processes that handle what
/// comes from a registry or an image.
pub fn harden() -> io::Result<()> {
    rustix::thread::set_no_new_privs(true)?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    Ok(())
}

/// No file this process writes is larger than `bytes`: a write beyond it
/// fails with `EFBIG` (the signal that would end the process is ignored)
/// instead of filling the disk.  The fetchers set it too: the file of a
/// call they write to is the only one they have.
pub fn limit_file_size(bytes: u64) -> io::Result<()> {
    velarx_sys::signal::ignore(libc::SIGXFSZ);
    rustix::process::setrlimit(
        rustix::process::Resource::Fsize,
        rustix::process::Rlimit {
            current: Some(bytes),
            maximum: Some(bytes),
        },
    )?;
    Ok(())
}

/// The soft limit of open files the process had before anything raised it:
/// what the user's shell or unit gave, which what it starts for a container
/// gets back ([`restore_open_files`]).
static ORIGINAL_OPEN_FILES: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// The raises of the soft limit are one at a time: a call that read the limit
/// before another raised it further must not set the lower one.
static RAISING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The most [`raise_open_files`] raises the soft limit to (podman's default
/// for the containers of root): a bound on what a program it starts that does
/// not restore the limit pays (one that closes every descriptor up to its
/// limit in a loop; a unit with `LimitNOFILE=infinity` gives a hard limit of
/// `fs.nr_open`, about a billion).
pub const OPEN_FILES_CEILING: u64 = 1 << 20;

/// What the mount of an image holds for each of its layers, at most: the
/// image server of a lazy image holds its image, its index and the directory
/// of the files fetched for it (three); the kernel mount of a complete image
/// holds fewer (the image, and its detached mount while the overlay is made).
pub const OPEN_FILES_PER_LAYER: u64 = 3;

/// What the process holds besides the layers of an image while it mounts
/// one: the database, the sockets, the runtime and the monitor it starts, the
/// objects directories of the stores and the overlay itself.  Measured as the
/// smallest hard limit that runs an image (rootless, debug build): 781 for a
/// lazy image of 249 layers (3 * 249 + 34), 531 for a complete one of 499
/// (499 + 32): 34 at most, 64 with a margin.
pub const OPEN_FILES_BASE: u64 = 64;

/// The open files a mount of an image of `layers` layers needs:
/// [`OPEN_FILES_PER_LAYER`] for each, and [`OPEN_FILES_BASE`].
pub fn open_files_needed(layers: usize) -> u64 {
    (layers as u64).saturating_mul(OPEN_FILES_PER_LAYER) + OPEN_FILES_BASE
}

/// A process cannot have as many open files as it needs: only a higher hard
/// limit mends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoOpenFiles {
    pub needed: u64,
    /// The soft and the hard limit now (none: unlimited)
    pub soft: Option<u64>,
    pub hard: Option<u64>,
}

fn limit_text(l: Option<u64>) -> String {
    l.map_or_else(|| "unlimited".to_string(), |n| n.to_string())
}

impl std::fmt::Display for NoOpenFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "it needs {} open files ({OPEN_FILES_PER_LAYER} for each of its layers and {OPEN_FILES_BASE} for the engine): soft limit {}, hard limit {}",
            self.needed,
            limit_text(self.soft),
            limit_text(self.hard)
        )
    }
}

impl std::error::Error for NoOpenFiles {}

/// The hard limit of open files lets the process have `needed`, else the
/// error that says so.  Nothing is raised.
pub fn check_open_files(needed: u64) -> Result<(), NoOpenFiles> {
    let (soft, hard) = open_files();
    match hard {
        Some(h) if h < needed => Err(NoOpenFiles { needed, soft, hard }),
        _ => Ok(()),
    }
}

/// The soft limit of open files is at least `needed`, raised just before
/// the descriptors are opened (never lowered, never above the hard limit:
/// then the error, with nothing changed).  The limit the process had is
/// kept ([`original_open_files`]): what it starts for a container gets it
/// back ([`restore_open_files`]).
pub fn ensure_open_files(needed: u64) -> Result<(), NoOpenFiles> {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    let _one_at_a_time = RAISING.lock().unwrap_or_else(|e| e.into_inner());
    let limit = getrlimit(Resource::Nofile);
    if limit.maximum.is_some_and(|hard| hard < needed) {
        return Err(NoOpenFiles {
            needed,
            soft: limit.current,
            hard: limit.maximum,
        });
    }
    if let Some(soft) = limit.current.filter(|soft| *soft < needed) {
        let _ = ORIGINAL_OPEN_FILES.set(soft);
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(needed),
                maximum: limit.maximum,
            },
        )
        .map_err(|_| NoOpenFiles {
            needed,
            soft: limit.current,
            hard: limit.maximum,
        })?;
    }
    Ok(())
}

/// The soft limit of open files raised to the hard one, at most to
/// [`OPEN_FILES_CEILING`] (a soft limit above it stays), for a service that
/// holds a connection of each of its clients, at once hundreds: more than the
/// 1024 that a shell or a user unit of systemd gives.  The limit the process
/// had is kept ([`original_open_files`]).  An engine that runs a command
/// does not: it raises its limit for the layers of the image it mounts
/// ([`ensure_open_files`]).
pub fn raise_open_files() -> io::Result<()> {
    raise_open_files_to(OPEN_FILES_CEILING)
}

fn raise_open_files_to(ceiling: u64) -> io::Result<()> {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
    let _one_at_a_time = RAISING.lock().unwrap_or_else(|e| e.into_inner());
    let limit = getrlimit(Resource::Nofile);
    if let Some(soft) = limit.current {
        let _ = ORIGINAL_OPEN_FILES.set(soft);
    }
    let raised = limit.maximum.map_or(ceiling, |hard| hard.min(ceiling));
    if limit.current.is_some_and(|soft| soft < raised) {
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(raised),
                maximum: limit.maximum,
            },
        )?;
    }
    Ok(())
}

/// The soft limit of open files this process had before anything raised it:
/// what it has now if nothing did (the limit that what it starts gets).
pub fn original_open_files() -> Option<u64> {
    let _one_at_a_time = RAISING.lock().unwrap_or_else(|e| e.into_inner());
    rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .map(|now| *ORIGINAL_OPEN_FILES.get_or_init(|| now))
}

/// The soft and the hard limit of open files of this process now (none:
/// unlimited).
pub fn open_files() -> (Option<u64>, Option<u64>) {
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    (limit.current, limit.maximum)
}

/// The command starts with the soft limit of open files `soft` (never more
/// than its hard limit, which stays): what a process raised for its own work
/// does not pass on to what it starts for a container.  `None` leaves what
/// the process has.
pub fn restore_open_files(cmd: &mut std::process::Command, soft: Option<u64>) {
    let Some(soft) = soft else {
        return;
    };
    velarx_sys::spawn::pre_exec(cmd, move |_| {
        use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};
        let now = getrlimit(Resource::Nofile);
        let soft = match now.maximum {
            Some(hard) => soft.min(hard),
            None => soft,
        };
        if now.current != Some(soft) {
            setrlimit(
                Resource::Nofile,
                Rlimit {
                    current: Some(soft),
                    maximum: now.maximum,
                },
            )?;
        }
        Ok(())
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lower the limits of this process (a child of a test).
    fn limit_to(soft: u64, hard: u64) {
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(soft),
                maximum: Some(hard),
            },
        )
        .unwrap();
    }

    fn limit_of(cmd: &mut std::process::Command) -> String {
        let out = cmd.output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn the_soft_limit_is_raised_and_the_first_one_kept() {
        crate::testing::in_child(|| {
            limit_to(256, 4096);
            assert_eq!(original_open_files(), Some(256));
            raise_open_files().unwrap();
            assert_eq!(open_files(), (Some(4096), Some(4096)));
            assert_eq!(original_open_files(), Some(256));
            // (a second call does not take the raised limit for the one the
            // user gave)
            raise_open_files().unwrap();
            assert_eq!(original_open_files(), Some(256));
        });
    }

    /// The soft limit is raised as far as the ceiling, not to a hard limit
    /// above it, and one above the ceiling is not lowered.
    #[test]
    fn the_soft_limit_is_raised_at_most_to_the_ceiling() {
        crate::testing::in_child(|| {
            limit_to(256, 4096);
            raise_open_files_to(1000).unwrap();
            assert_eq!(open_files(), (Some(1000), Some(4096)));
            assert_eq!(original_open_files(), Some(256));
            limit_to(2048, 4096);
            raise_open_files_to(1000).unwrap();
            assert_eq!(open_files(), (Some(2048), Some(4096)));
        });
    }

    /// The limit is raised to what is needed and no further, once, and the
    /// first limit is the one a command gets back.
    #[test]
    fn the_soft_limit_is_raised_to_what_is_needed_and_never_lowered() {
        crate::testing::in_child(|| {
            limit_to(256, 4096);
            ensure_open_files(100).unwrap();
            assert_eq!(open_files(), (Some(256), Some(4096)));
            ensure_open_files(1000).unwrap();
            assert_eq!(open_files(), (Some(1000), Some(4096)));
            ensure_open_files(600).unwrap();
            assert_eq!(open_files(), (Some(1000), Some(4096)));
            assert_eq!(original_open_files(), Some(256));
        });
    }

    /// A hard limit below the need is the error, and nothing is raised.
    #[test]
    fn a_hard_limit_below_the_need_is_an_error_that_changes_nothing() {
        crate::testing::in_child(|| {
            limit_to(256, 1200);
            let e = ensure_open_files(open_files_needed(499)).unwrap_err();
            assert_eq!(e.needed, 3 * 499 + OPEN_FILES_BASE);
            assert_eq!((e.soft, e.hard), (Some(256), Some(1200)));
            assert_eq!(open_files(), (Some(256), Some(1200)));
            assert_eq!(check_open_files(1200), Ok(()));
            assert!(check_open_files(1201).is_err());
            assert!(
                e.to_string().contains("soft limit 256, hard limit 1200"),
                "{e}"
            );
        });
    }

    /// An engine that did not mount an image has the limit it was given.
    #[test]
    fn the_soft_limit_stays_when_nothing_needs_more() {
        crate::testing::in_child(|| {
            limit_to(256, 4096);
            assert_eq!(original_open_files(), Some(256));
            assert_eq!(open_files(), (Some(256), Some(4096)));
        });
    }

    #[test]
    fn a_command_gets_the_limit_it_is_given_and_keeps_the_hard_one() {
        crate::testing::in_child(|| {
            limit_to(256, 4096);
            raise_open_files().unwrap();
            let mut cmd = std::process::Command::new("sh");
            cmd.args(["-c", "echo $(ulimit -Sn) $(ulimit -Hn)"]);
            assert_eq!(limit_of(&mut cmd), "4096 4096");
            restore_open_files(&mut cmd, original_open_files());
            assert_eq!(limit_of(&mut cmd), "256 4096");
            // (a limit above the hard one is the hard one)
            let mut cmd = std::process::Command::new("sh");
            cmd.args(["-c", "echo $(ulimit -Sn) $(ulimit -Hn)"]);
            restore_open_files(&mut cmd, Some(1 << 20));
            assert_eq!(limit_of(&mut cmd), "4096 4096");
            // (none: what the process has)
            let mut cmd = std::process::Command::new("sh");
            cmd.args(["-c", "echo $(ulimit -Sn) $(ulimit -Hn)"]);
            restore_open_files(&mut cmd, None);
            assert_eq!(limit_of(&mut cmd), "4096 4096");
        });
    }
}
