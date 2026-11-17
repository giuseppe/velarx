// SPDX-License-Identifier: Apache-2.0
//! The user-namespace tree of a rootless user.
//!
//! An unprivileged process cannot mount file systems, so every rootless
//! process of a store runs in a user namespace where it is root and in a
//! mount namespace of that user namespace.  There is ONE such pair per user
//! and boot, and every process joins it: a container can only join the
//! namespaces of another one (`--network container:`, `--pid container:`, a
//! pod, `cp`) from the user namespace that owns them.
//!
//! Nothing keeps the pair alive but the processes that live in it (the
//! monitors of the containers, the daemon, the helpers that outlive their
//! command); there is no process whose only purpose is to hold it.  Two
//! tables of the store's database say which pair is the current one and who
//! lives in it (`velarx_db::namespaces`, keyed by the boot id of the
//! kernel):
//!
//! * a process finds a live member of the recorded pair (the pid with its
//!   start time, so a recycled pid is not taken for it), opens
//!   `/proc/PID/ns/user` and `/proc/PID/ns/mnt`, checks that they are the
//!   recorded namespaces (device, inode and file handle) and joins them with
//!   `setns`, in place: no fork, no waiter process;
//! * when none is alive it makes the pair.  When only the mount namespace is
//!   gone it makes a new one inside the live user namespace.
//!
//! Both happen under an exclusive transaction of the database held from the
//! check to the record of the process as a holder: of two processes that
//! start together one creates and the other joins what it made, and a
//! process in the pair is always recorded before another one looks.
//!
//! The file handles of the namespaces (`name_to_handle_at`) are recorded and
//! compared, but not reopened with `open_by_handle_at`: since Linux 7.0 (and
//! the stable kernels 6.18.40+ and 6.19.9+) the kernel opens the handle of a
//! namespace only for a process that is in it already or for root of the
//! initial user namespace, so it never works for the process that wants to
//! join.  A process of the pair is reached through `/proc` instead, as
//! podman does when its handles cannot be reopened.
//!
//! Joining must happen before the process has a thread
//! (`setns(CLONE_NEWUSER)` needs a single thread).

use rusqlite::{Transaction, TransactionBehavior};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use tracing::debug;
use velarx_nsid::store;
use velarx_nsid::{id_of, own, start_time, Holder, Kind, NamespaceId, Stored};

use super::rootless::write_maps;

fn context(what: &str, e: io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// The live members of the recorded pair.
#[derive(Default)]
struct Live {
    user: Option<OwnedFd>,
    mnt: Option<OwnedFd>,
    /// Holders that are gone (or whose pid another process has now).
    gone: Vec<Holder>,
}

/// Open the namespaces of `kinds` through the holders that are alive and in
/// the recorded namespaces.
fn find_live(stored: &Stored, kinds: &[Kind]) -> Live {
    let mut live = Live::default();
    for h in &stored.holders {
        if start_time(h.pid) != Some(h.start) {
            live.gone.push(h.clone());
            continue;
        }
        for &kind in kinds {
            let slot = match kind {
                Kind::User => &mut live.user,
                Kind::Mnt => &mut live.mnt,
                // (the tree is of the user and mount namespaces)
                _ => continue,
            };
            let Some(recorded) = stored.namespace(kind) else {
                continue;
            };
            if slot.is_some() {
                continue;
            }
            // A process is the holder if it is in the recorded namespace;
            // the descriptor is what is checked, so the process may exit
            // or change namespaces between the look and the join.
            let Ok(fd) = velarx_nsid::open_of(&h.pid.to_string(), kind) else {
                continue;
            };
            if id_of(fd.as_fd()).is_ok_and(|id| id.is_same(recorded)) {
                *slot = Some(fd);
            }
        }
    }
    live
}

/// What a process has to do to be in the pair.
enum Plan {
    /// It is in it.
    Inside,
    /// Join the namespaces opened (the user namespace first); with
    /// `new_mnt`, make the mount namespace then: the recorded one is gone.
    Join {
        user: Option<OwnedFd>,
        mnt: Option<OwnedFd>,
        new_mnt: bool,
    },
    /// No member of the pair is alive: make both.
    Fresh,
}

/// The plan for a process in `here`, given what is recorded and who lives.
fn plan(stored: &Stored, here: &Here) -> (Plan, Vec<Holder>) {
    let in_user = stored
        .namespace(Kind::User)
        .is_some_and(|s| s.is_same(&here.user));
    let in_mnt = stored
        .namespace(Kind::Mnt)
        .is_some_and(|s| s.is_same(&here.mnt));
    if in_user && in_mnt {
        return (Plan::Inside, Vec::new());
    }
    let mut kinds = Vec::new();
    if !in_user {
        kinds.push(Kind::User);
    }
    if !in_mnt {
        kinds.push(Kind::Mnt);
    }
    let live = find_live(stored, &kinds);
    let gone = live.gone;
    if !in_user && live.user.is_none() {
        return (Plan::Fresh, gone);
    }
    let new_mnt = !in_mnt && live.mnt.is_none();
    (
        Plan::Join {
            user: live.user,
            mnt: live.mnt,
            new_mnt,
        },
        gone,
    )
}

/// The namespaces of this process.
struct Here {
    user: NamespaceId,
    mnt: NamespaceId,
}

impl Here {
    fn read() -> io::Result<Self> {
        Ok(Self {
            user: own(Kind::User)?,
            mnt: own(Kind::Mnt)?,
        })
    }
}

fn setns(fd: &OwnedFd, kind: rustix::thread::LinkNameSpaceType, what: &str) -> io::Result<()> {
    rustix::thread::move_into_link_name_space(fd.as_fd(), Some(kind))
        .map_err(|e| context(&format!("cannot join the {what} namespace"), e.into()))
}

/// Make the mounts of this namespace slaves (`mount --make-rslave /`): the
/// mounts and unmounts of the host reach the namespace (a disk mounted
/// under /mnt after the namespace was made, an automounted home), what the
/// processes of the namespace mount never reaches the host or anyone else.
/// Private would keep the namespace a snapshot of the mounts of the moment
/// it was made, for as long as a process lives in it.
fn isolate_mounts() -> io::Result<()> {
    rustix::mount::mount_change(
        "/",
        rustix::mount::MountPropagationFlags::DOWNSTREAM
            | rustix::mount::MountPropagationFlags::REC,
    )
    .map_err(|e| context("make the mounts slaves of the host's", e.into()))
}

/// The process that writes the id maps of the user namespace this one is
/// about to make: it has to be outside of it (newuidmap and newgidmap
/// refuse the process of the namespace itself), so it is forked before.
struct MapWriter {
    pid: libc::pid_t,
    go: std::fs::File,
    /// What the writer says when it fails (what the helper said).
    why: std::fs::File,
}

impl MapWriter {
    fn start() -> io::Result<Self> {
        let (go_r, go_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        let (why_r, why_w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
        let parent = std::process::id();
        let pid = match velarx_sys::process::fork_single_threaded("the id map writer")? {
            velarx_sys::process::Fork::Parent(pid) => pid,
            velarx_sys::process::Fork::Child(_) => {
                // (the write end is the parent's alone: when it dies, or
                // gives up before its namespace is made, the read ends)
                drop(go_w);
                drop(why_r);
                let mut go = std::fs::File::from(go_r);
                let mut byte = [0u8; 1];
                let ok = go.read(&mut byte).is_ok_and(|n| n == 1)
                    && match write_maps(parent) {
                        Ok(()) => true,
                        Err(e) => {
                            let _ = std::fs::File::from(why_w).write_all(e.to_string().as_bytes());
                            false
                        }
                    };
                // leave the child without running the parent's destructors
                velarx_sys::process::exit_now(if ok { 0 } else { 1 });
            }
        };
        Ok(Self {
            pid,
            go: std::fs::File::from(go_w),
            why: std::fs::File::from(why_r),
        })
    }

    /// The parent is in its namespace: write the maps, wait for the result.
    fn write(mut self) -> io::Result<()> {
        let told = self.go.write_all(&[1]);
        drop(self.go);
        let status = wait_for(self.pid)?;
        told?;
        if status == 0 {
            return Ok(());
        }
        // (the writer has ended: its end of the pipe is closed)
        let mut why = String::new();
        let _ = self.why.read_to_string(&mut why);
        Err(io::Error::other(if why.is_empty() {
            "cannot set the id maps of the namespace".to_string()
        } else {
            format!("cannot set the id maps of the namespace: {}", why.trim())
        }))
    }
}

/// Wait for the child `pid`: its exit code.
fn wait_for(pid: libc::pid_t) -> io::Result<i32> {
    velarx_sys::process::wait_exit_code(pid)
}

/// Become root of new user and mount namespaces.
fn make_user_and_mount_namespaces() -> io::Result<()> {
    let maps = MapWriter::start()?;
    if let Err(e) = velarx_sys::ns::unshare(
        rustix::thread::UnshareFlags::NEWUSER | rustix::thread::UnshareFlags::NEWNS,
    ) {
        drop(maps.go);
        let _ = wait_for(maps.pid);
        return Err(context("cannot create a user namespace", e));
    }
    maps.write()?;
    isolate_mounts()
}

/// Make a new mount namespace in the user namespace this process is in.
fn make_mount_namespace() -> io::Result<()> {
    velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNS)
        .map_err(|e| context("cannot create a mount namespace", e))?;
    isolate_mounts()
}

fn myself(role: &str) -> io::Result<Holder> {
    let pid = std::process::id() as i32;
    Ok(Holder {
        pid,
        start: start_time(pid).ok_or_else(|| io::Error::other("cannot read my start time"))?,
        role: role.to_string(),
    })
}

/// Do what `plan` says, and record in `tx` (the transaction that holds the
/// lock) what is made and this process as a holder.  With no `tx` the plan
/// is a join of namespaces that are recorded already: nothing is written.
fn execute(
    plan: Plan,
    gone: &[Holder],
    tx: Option<&Transaction<'_>>,
    boot_id: &str,
    role: &str,
) -> io::Result<()> {
    let cwd = match plan {
        Plan::Inside => None,
        _ => Some(
            std::env::current_dir().map_err(|e| context("cannot read the working directory", e))?,
        ),
    };
    let (fresh, new_mnt) = match plan {
        Plan::Inside => return Ok(()),
        Plan::Fresh => {
            make_user_and_mount_namespaces()?;
            (true, false)
        }
        Plan::Join { user, mnt, new_mnt } => {
            if let Some(fd) = &user {
                setns(fd, rustix::thread::LinkNameSpaceType::User, "user")?;
            }
            if let Some(fd) = &mnt {
                setns(fd, rustix::thread::LinkNameSpaceType::Mount, "mount")?;
            }
            if new_mnt {
                make_mount_namespace()?;
            }
            (false, new_mnt)
        }
    };
    // (a new mount namespace is at the root of the old one, and joining one
    // at the root of that: back to where the command was run)
    if let Some(cwd) = cwd {
        std::env::set_current_dir(&cwd).map_err(|e| {
            context(
                &format!("cannot go back to {} in the new namespaces", cwd.display()),
                e,
            )
        })?;
    }
    // Joining a user namespace makes the process not dumpable: its /proc/self
    // would be the owner's no more.
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::Dumpable);
    let Some(tx) = tx else {
        return Ok(());
    };
    velarx_nsid::tree::record_pair(tx, boot_id, fresh, new_mnt, gone, &myself(role)?)
}

/// Put this process in the user and mount namespaces that the store `db`
/// records, making them if no process lives in them.  `role` is recorded
/// with it when it makes them, and with `register` when it joins them: a
/// process that starts what outlives it is a holder from its join on, a
/// process that only reads the store writes nothing.  Before any thread is
/// started.  The connection it used is the result: a command keeps it until
/// its engine opens the store (`velarx_db::volatile::keep`).
pub fn enter(db: &Path, role: &str, register: bool) -> io::Result<velarx_db::volatile::Connection> {
    let boot_id = velarx_nsid::store::boot_id()?;
    enter_boot(db, role, register, &boot_id)
}

fn enter_boot(
    db: &Path,
    role: &str,
    register: bool,
    boot_id: &str,
) -> io::Result<velarx_db::volatile::Connection> {
    let mut conn = store::open(db)?;
    let here = Here::read()?;
    // What is recorded is read without a lock first: a process that joins
    // namespaces that are recorded and has nothing to record writes nothing.
    let stored =
        store::load(&conn, boot_id, store::TREE).map_err(velarx_nsid::tree::db_error("read"))?;
    let (first, gone) = plan(&stored, &here);
    let needs_write = match &first {
        Plan::Inside => false,
        Plan::Join { .. } => register,
        // (a process that records nothing and makes the namespaces: nothing
        // outlives it to be found through; `register_holder` records the
        // pair when it starts what does)
        Plan::Fresh => register,
    };
    let recorded = if needs_write {
        // The check, the join or the making, and the record of this process
        // as a holder are one transaction: of processes that start
        // together, one makes the pair and the others join what it made;
        // and a process that joined is a holder before anyone else looks,
        // so that while it lives (its monitors not started yet, the holder
        // it joined through gone) no other process takes the pair for dead
        // and makes a second one.
        drop(first);
        let tx = Transaction::new(&mut conn, TransactionBehavior::Immediate)
            .map_err(velarx_nsid::tree::db_error("lock"))?;
        let stored =
            store::load(&tx, boot_id, store::TREE).map_err(velarx_nsid::tree::db_error("read"))?;
        let (plan, gone) = plan(&stored, &here);
        let recorded = !matches!(plan, Plan::Inside);
        execute(plan, &gone, Some(&tx), boot_id, role)?;
        tx.commit().map_err(velarx_nsid::tree::db_error("commit"))?;
        recorded
    } else {
        execute(first, &gone, None, boot_id, role)?;
        false
    };
    debug!("the user namespace tree: {role}");
    super::rootless::set_joined();
    velarx_nsid::tree::joined(db, boot_id, recorded);
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;
    use velarx_base::testing::in_child;
    use velarx_nsid::tree::{members, register_holder, remember};

    fn ns_mut(s: &mut Stored, kind: Kind) -> &mut NamespaceId {
        &mut s.namespaces.iter_mut().find(|(k, _)| *k == kind).unwrap().1
    }

    /// The writer of the id maps ends when its parent goes away without
    /// asking for them (killed, or its namespace could not be made): it
    /// holds no write end of its own pipe.
    #[test]
    fn the_map_writer_ends_with_a_parent_that_did_not_ask() {
        in_child(|| {
            let maps = MapWriter::start().unwrap();
            let pid = maps.pid;
            drop(maps.go);
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || tx.send(wait_for(pid)));
            let status = rx.recv_timeout(std::time::Duration::from_secs(10));
            if status.is_err() {
                let _ = velarx_sys::process::kill(pid, libc::SIGKILL);
            }
            assert_eq!(
                status.ok().and_then(Result::ok),
                Some(1),
                "the writer ended"
            );
        });
    }

    #[test]
    fn a_namespace_file_tells_its_namespace() {
        let a = own(Kind::User).unwrap();
        let b = own(Kind::User).unwrap();
        assert!(a.is_same(&b));
        assert!(!a.is_same(&own(Kind::Mnt).unwrap()));
    }

    /// A holder is a live process in the recorded namespace; a recycled pid
    /// (another start time) and a dead process are not.
    #[test]
    fn a_recycled_pid_is_not_a_holder() {
        let me = std::process::id() as i32;
        let start = start_time(me).unwrap();
        let holder = |pid, start| Holder {
            pid,
            start,
            role: "t".into(),
        };
        let stored = |holders| Stored {
            namespaces: vec![(Kind::User, own(Kind::User).unwrap())],
            holders,
        };

        let live = find_live(&stored(vec![holder(me, start)]), &[Kind::User]);
        assert!(live.user.is_some() && live.gone.is_empty());

        let live = find_live(&stored(vec![holder(me, start + 1)]), &[Kind::User]);
        assert!(live.user.is_none());
        assert_eq!(live.gone, vec![holder(me, start + 1)]);

        let live = find_live(&stored(vec![holder(i32::MAX, 1)]), &[Kind::User]);
        assert!(live.user.is_none() && live.gone.len() == 1);

        // alive, but in another namespace than the recorded one
        let mut other = stored(vec![holder(me, start)]);
        ns_mut(&mut other, Kind::User).ino += 1;
        assert!(find_live(&other, &[Kind::User]).user.is_none());
    }

    #[test]
    fn a_process_in_the_recorded_namespaces_does_nothing() {
        let here = Here::read().unwrap();
        let stored = Stored {
            namespaces: vec![
                (Kind::User, here.user.clone()),
                (Kind::Mnt, here.mnt.clone()),
            ],
            holders: Vec::new(),
        };
        assert!(matches!(plan(&stored, &here).0, Plan::Inside));
        let mut gone = stored.clone();
        ns_mut(&mut gone, Kind::Mnt).ino += 1;
        // the user namespace is the one, the mount namespace is not and
        // nobody lives in the recorded one
        assert!(matches!(
            plan(&gone, &here).0,
            Plan::Join {
                user: None,
                mnt: None,
                new_mnt: true
            }
        ));
        // nothing is recorded: make both
        assert!(matches!(plan(&Stored::default(), &here).0, Plan::Fresh));
    }

    /// Processes of the tests below: forked from a thread of the test
    /// binary, so single-threaded and free to unshare.
    struct Forked {
        pid: libc::pid_t,
        report: std::fs::File,
        done: std::fs::File,
    }

    fn pipe() -> (std::fs::File, std::fs::File) {
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        (std::fs::File::from(r), std::fs::File::from(w))
    }

    /// Fork a child that waits for `go` (when given), runs `body`, writes
    /// its result to the report and stays alive until a byte comes on the
    /// `done` pipe (a sibling forked later holds copies of its ends, so the
    /// end of the pipe says nothing).
    fn fork_holding(go: Option<&std::fs::File>, body: impl FnOnce() -> String) -> Forked {
        let (report_r, report_w) = pipe();
        let (done_r, done_w) = pipe();
        let go = go.map(|g| g.try_clone().unwrap());
        let pid = match velarx_sys::process::fork_single_threaded("the test").unwrap() {
            velarx_sys::process::Fork::Parent(pid) => pid,
            velarx_sys::process::Fork::Child(_) => {
                drop((report_r, done_w));
                let mut byte = [0u8; 1];
                if let Some(mut g) = go {
                    let _ = g.read(&mut byte);
                }
                let text = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body))
                    .unwrap_or_else(|_| "panicked".into());
                let mut report = report_w;
                let _ = writeln!(report, "{text}");
                let _ = (&done_r).read(&mut byte);
                // leave the child without the destructors of the test
                velarx_sys::process::exit_now(0);
            }
        };
        drop((report_w, done_r));
        Forked {
            pid,
            report: report_r,
            done: done_w,
        }
    }

    impl Forked {
        /// What the body returned.
        fn result(&mut self) -> String {
            use std::io::BufRead;
            let mut text = String::new();
            std::io::BufReader::new(&self.report)
                .read_line(&mut text)
                .unwrap();
            text.trim().to_string()
        }

        /// Let it leave, and wait for it.
        fn finish(mut self) {
            self.done.write_all(&[1]).unwrap();
            assert_eq!(wait_for(self.pid).unwrap(), 0);
        }
    }

    /// The user and mount namespaces of this process, as "user mnt": the
    /// inode number of a namespace that is gone is given to the next one,
    /// the handle tells them apart.
    fn here_now() -> String {
        let id = |kind| name_of(&own(kind).unwrap());
        format!("{} {}", id(Kind::User), id(Kind::Mnt))
    }

    fn name_of(id: &NamespaceId) -> String {
        let handle = id.handle.as_ref().map_or(String::new(), |h| {
            h.bytes.iter().map(|b| format!("{b:02x}")).collect()
        });
        format!("{}-{handle}", id.ino)
    }

    /// Whether this host lets a process make a user namespace.
    fn can_make_a_user_namespace() -> bool {
        let mut probe = fork_holding(None, || {
            let ok = velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWUSER).is_ok();
            ok.to_string()
        });
        let ok = probe.result() == "true";
        probe.finish();
        ok
    }

    fn scratch_db() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let db = dir.path().join("db.sqlite");
        (dir, db)
    }

    fn enter_and_report(db: &Path, boot: &str, role: &str) -> String {
        match enter_boot(db, role, true, boot) {
            Ok(_) => here_now(),
            Err(e) => format!("error: {e}"),
        }
    }

    /// Of processes that start together one makes the namespaces and the
    /// other joins them: the transaction of the database is the lock.
    #[test]
    fn processes_that_start_together_share_one_user_namespace() {
        in_child(|| {
            if !can_make_a_user_namespace() {
                eprintln!("skipped: no user namespaces here");
                return;
            }
            let (_dir, db) = scratch_db();
            let (mut go_r, mut go_w) = pipe();
            let _ = &mut go_r;
            let mut all: Vec<Forked> = (0..4)
                .map(|i| {
                    let db = db.clone();
                    fork_holding(Some(&go_r), move || {
                        enter_and_report(&db, "boot-race", &format!("racer {i}"))
                    })
                })
                .collect();
            go_w.write_all(&[1; 4]).unwrap();
            let results: Vec<String> = all.iter_mut().map(Forked::result).collect();
            assert!(
                results.iter().all(|r| !r.starts_with("error")),
                "{results:?}"
            );
            assert!(
                results.windows(2).all(|w| w[0] == w[1]),
                "one user and one mount namespace: {results:?}"
            );
            let conn = store::open(&db).unwrap();
            let stored = store::load(&conn, "boot-race", store::TREE).unwrap();
            assert_eq!(
                format!(
                    "{} {}",
                    name_of(stored.namespace(Kind::User).unwrap()),
                    name_of(stored.namespace(Kind::Mnt).unwrap())
                ),
                results[0]
            );
            // each is a holder: one made them, the others joined
            assert_eq!(stored.holders.len(), 4, "{:?}", stored.holders);
            for f in all {
                f.finish();
            }
        });
    }

    /// While a process lives in the namespaces, another joins them; when none
    /// does, a new pair is made; the namespaces of another boot are no help.
    #[test]
    fn the_namespaces_are_joined_while_one_lives_and_made_when_none_does() {
        in_child(|| {
            if !can_make_a_user_namespace() {
                eprintln!("skipped: no user namespaces here");
                return;
            }
            let (_dir, db) = scratch_db();
            let d = db.clone();
            let mut first = fork_holding(None, move || enter_and_report(&d, "boot-1", "first"));
            let made = first.result();
            assert!(!made.starts_with("error"), "{made}");
            assert_ne!(
                made.split(' ').next().unwrap(),
                name_of(&own(Kind::User).unwrap()),
                "not the namespace of the test"
            );

            let d = db.clone();
            let mut second = fork_holding(None, move || enter_and_report(&d, "boot-1", "second"));
            assert_eq!(second.result(), made, "joined what the first made");
            second.finish();

            // the key includes the boot: after a reboot the record is of no use
            let d = db.clone();
            let mut other_boot = fork_holding(None, move || {
                enter_and_report(&d, "boot-2", "after a reboot")
            });
            let other = other_boot.result();
            assert_ne!(other, made, "another boot makes its own");
            other_boot.finish();
            let conn = store::open(&db).unwrap();
            assert_eq!(
                store::load(&conn, "boot-1", store::TREE).unwrap(),
                Stored::default(),
                "the record of the old boot goes"
            );

            // nobody is left in the pair of boot-2: its process ended
            first.finish();
            let d = db.clone();
            let mut third = fork_holding(None, move || enter_and_report(&d, "boot-2", "third"));
            let third_result = third.result();
            assert_ne!(third_result, other, "none lived in it: a new pair");
            third.finish();
        });
    }

    /// A process that joined is a holder at once: when the one it joined
    /// through leaves before it has started anything, the next process
    /// joins through it instead of making a second pair.
    #[test]
    fn a_process_that_joined_holds_the_pair() {
        in_child(|| {
            if !can_make_a_user_namespace() {
                eprintln!("skipped: no user namespaces here");
                return;
            }
            let (_dir, db) = scratch_db();
            let d = db.clone();
            let mut creator = fork_holding(None, move || enter_and_report(&d, "boot-j", "creator"));
            let made = creator.result();
            assert!(!made.starts_with("error"), "{made}");
            let d = db.clone();
            let mut joined = fork_holding(None, move || enter_and_report(&d, "boot-j", "engine"));
            assert_eq!(joined.result(), made);
            creator.finish();

            let d = db.clone();
            let mut next = fork_holding(None, move || enter_and_report(&d, "boot-j", "next"));
            assert_eq!(
                next.result(),
                made,
                "joined through the process that joined"
            );
            next.finish();
            joined.finish();
        });
    }

    /// A process that joins the namespaces and registers nothing writes
    /// nothing: the holders are those of the process that made them; one
    /// that registers is a holder from its join on.
    #[test]
    fn a_join_that_registers_nothing_writes_nothing() {
        in_child(|| {
            if !can_make_a_user_namespace() {
                eprintln!("skipped: no user namespaces here");
                return;
            }
            let (_dir, db) = scratch_db();
            let d = db.clone();
            let mut creator = fork_holding(None, move || enter_and_report(&d, "boot-w", "creator"));
            let made = creator.result();
            assert!(!made.starts_with("error"), "{made}");
            let holders = |db: &Path| {
                let conn = store::open(db).unwrap();
                store::load(&conn, "boot-w", store::TREE).unwrap().holders
            };
            assert_eq!(holders(&db).len(), 1);
            let (d, wal) = (db.clone(), db.with_extension("sqlite-wal"));
            let size = |p: &Path| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            let before = size(&wal);
            let mut reader = fork_holding(None, move || {
                match enter_boot(&d, "reader", false, "boot-w") {
                    Ok(_) => here_now(),
                    Err(e) => format!("error: {e}"),
                }
            });
            assert_eq!(reader.result(), made, "the reader joined the namespaces");
            reader.finish();
            assert_eq!(holders(&db).len(), 1, "no holder for a reader");
            assert_eq!(size(&wal), before, "nothing written to the log");
            let d = db.clone();
            let mut starter = fork_holding(None, move || {
                match enter_boot(&d, "starter", true, "boot-w") {
                    Ok(_) => here_now(),
                    Err(e) => format!("error: {e}"),
                }
            });
            assert_eq!(starter.result(), made);
            assert_eq!(holders(&db).len(), 2, "a registering join is a holder");
            starter.finish();
            creator.finish();
        });
    }

    /// A command that records nothing and makes its own pair writes nothing;
    /// the pair is recorded when it starts what outlives it.
    #[test]
    fn a_pair_made_by_a_command_that_records_nothing_is_recorded_by_what_it_starts() {
        in_child(|| {
            if !can_make_a_user_namespace() {
                eprintln!("skipped: no user namespaces here");
                return;
            }
            let (_dir, db) = scratch_db();
            let d = db.clone();
            let mut maker = fork_holding(None, move || {
                if let Err(e) = enter_boot(&d, "reader", false, "boot-x") {
                    return format!("error: {e}");
                }
                let rows = |d: &Path| {
                    let c = store::open(d).unwrap();
                    let s = store::load(&c, "boot-x", store::TREE).unwrap();
                    (s.namespaces.len(), s.holders.len())
                };
                let before = rows(&d);
                register_holder(std::process::id(), "monitor");
                format!("{before:?} {:?}", rows(&d))
            });
            assert_eq!(maker.result(), "(0, 0) (2, 1)");
            maker.finish();
        });
    }

    /// A command that recorded nothing made its pair while another one made
    /// and recorded its own: what it starts is not recorded, and the pair
    /// that is recorded, with its holders, stays.
    #[test]
    fn a_recorded_pair_that_lives_is_not_replaced_by_one_that_recorded_nothing() {
        in_child(|| {
            if !can_make_a_user_namespace() {
                eprintln!("skipped: no user namespaces here");
                return;
            }
            let (_dir, db) = scratch_db();
            let (entered_r, entered_w) = pipe();
            let (then_r, mut then_w) = pipe();
            let d = db.clone();
            let mut reader = fork_holding(None, move || {
                if let Err(e) = enter_boot(&d, "reader", false, "boot-y") {
                    return format!("error: {e}");
                }
                drop(entered_w);
                let _ = (&then_r).read(&mut [0u8; 1]);
                register_holder(std::process::id(), "monitor");
                here_now()
            });
            let _ = (&entered_r).read(&mut [0u8; 1]);
            let d = db.clone();
            let mut creator = fork_holding(None, move || enter_and_report(&d, "boot-y", "creator"));
            let made = creator.result();
            assert!(!made.starts_with("error"), "{made}");
            then_w.write_all(&[1]).unwrap();
            assert_ne!(reader.result(), made, "two pairs");
            let conn = store::open(&db).unwrap();
            let stored = store::load(&conn, "boot-y", store::TREE).unwrap();
            let roles: Vec<_> = stored.holders.iter().map(|h| h.role.as_str()).collect();
            assert_eq!(roles, ["creator"], "the recorded pair and its holder stay");
            reader.finish();
            creator.finish();
        });
    }

    /// A command that recorded nothing and made a mount namespace in the
    /// live user namespace (the recorded mount namespace is gone) records
    /// that mount namespace when it starts what outlives it: the next
    /// command joins it.
    #[test]
    fn a_mount_namespace_made_by_a_command_that_recorded_nothing_is_recorded() {
        in_child(|| {
            if !can_make_a_user_namespace() {
                eprintln!("skipped: no user namespaces here");
                return;
            }
            let (_dir, db) = scratch_db();
            let d = db.clone();
            let mut creator = fork_holding(None, move || enter_and_report(&d, "boot-n", "creator"));
            let made = creator.result();
            assert!(!made.starts_with("error"), "{made}");
            // (a holder of the user namespace that left the mount namespace)
            let d = db.clone();
            let mut user_only = fork_holding(None, move || {
                if let Err(e) = enter_boot(&d, "netns", true, "boot-n") {
                    return format!("error: {e}");
                }
                match make_mount_namespace() {
                    Ok(()) => here_now(),
                    Err(e) => format!("error: {e}"),
                }
            });
            let moved = user_only.result();
            assert!(!moved.starts_with("error"), "{moved}");
            creator.finish();
            let d = db.clone();
            let mut reader = fork_holding(None, move || {
                if let Err(e) = enter_boot(&d, "reader", false, "boot-n") {
                    return format!("error: {e}");
                }
                register_holder(std::process::id(), "monitor");
                here_now()
            });
            let read = reader.result();
            assert!(!read.starts_with("error"), "{read}");
            assert_ne!(read, moved, "a mount namespace of its own");
            let d = db.clone();
            let mut next = fork_holding(None, move || enter_and_report(&d, "boot-n", "next"));
            assert_eq!(next.result(), read, "the next command joins it");
            next.finish();
            reader.finish();
            user_only.finish();
        });
    }

    /// A database that cannot be read is an error, not a tree with no
    /// members: whoever looks for a process there would conclude that none
    /// keeps the namespace.
    #[test]
    fn a_database_that_cannot_be_read_is_an_error_not_no_members() {
        in_child(|| {
            let (_dir, db) = scratch_db();
            assert!(members().unwrap().is_empty(), "no store set yet");
            remember(db.clone()).unwrap();
            assert!(members().unwrap().is_empty(), "an empty database");
            // (and its log, which has the pages the file lacks)
            for ext in ["-wal", "-shm"] {
                let mut log = db.clone().into_os_string();
                log.push(ext);
                let _ = std::fs::remove_file(log);
            }
            std::fs::write(&db, b"not a database, but long enough to be read as one").unwrap();
            let e = members().unwrap_err();
            assert!(
                e.to_string().contains("the namespaces in the database"),
                "{e}"
            );
        });
    }

    /// The user namespace lives (a member is in it) and the mount namespace
    /// is gone: only a new mount namespace is made, in the same user namespace.
    #[test]
    fn a_gone_mount_namespace_is_made_again_in_the_live_user_namespace() {
        in_child(|| {
            if !can_make_a_user_namespace() {
                eprintln!("skipped: no user namespaces here");
                return;
            }
            let (_dir, db) = scratch_db();
            let d = db.clone();
            let mut creator = fork_holding(None, move || enter_and_report(&d, "boot-m", "creator"));
            let made = creator.result();
            let (user, mnt) = made.split_once(' ').unwrap();

            // a member of the user namespace with a mount namespace of its own
            // (what a monitor is)
            let d = db.clone();
            let mut monitor = fork_holding(None, move || {
                if let Err(e) = enter_boot(&d, "monitor", true, "boot-m") {
                    return format!("error: {e}");
                }
                make_mount_namespace().unwrap();
                register_holder(std::process::id(), "monitor");
                here_now()
            });
            let monitor_result = monitor.result();
            assert!(!monitor_result.starts_with("error"), "{monitor_result}");
            assert_eq!(monitor_result.split(' ').next(), Some(user));
            assert_ne!(monitor_result.split(' ').nth(1), Some(mnt));
            // the creator, the last in the recorded mount namespace, leaves
            creator.finish();

            let d = db.clone();
            let mut next = fork_holding(None, move || enter_and_report(&d, "boot-m", "next"));
            let next_result = next.result();
            let (next_user, next_mnt) = next_result.split_once(' ').unwrap();
            assert_eq!(next_user, user, "the same user namespace");
            assert_ne!(next_mnt, mnt, "a new mount namespace");
            let conn = store::open(&db).unwrap();
            let stored = store::load(&conn, "boot-m", store::TREE).unwrap();
            assert_eq!(name_of(stored.namespace(Kind::User).unwrap()), user);
            assert_eq!(name_of(stored.namespace(Kind::Mnt).unwrap()), next_mnt);
            next.finish();
            monitor.finish();
        });
    }
}
