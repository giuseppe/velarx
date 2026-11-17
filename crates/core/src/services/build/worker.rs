// SPDX-License-Identifier: Apache-2.0
//! The worker that runs the copies of a build (`velarx
//! build-worker`): the files it reads come from a client (the context) or
//! an image, and the decompressors of ADD parse them, so it is confined
//! before it reads them.
//!
//! The daemon gives it the job on its standard input, the directory to
//! fill as descriptor 3 and the source (the context directory, or a pipe
//! that carries a tar stream) as descriptor 4; it answers on its standard
//! output, nothing when the job is done (the digest for a job that asks
//! for it, `changed` when a node it copied from a context changed since the
//! job's `unchanged_since`), why it failed otherwise.
//!
//! The confinement that is required: the worker has a mount namespace of
//! its own (and a user namespace of its own when it was started without
//! the right to make one) whose root is an empty tmpfs that holds the
//! destination and, read-only, the source; nothing else is reachable by a
//! path or by a descriptor, so the owners, modes, times and xattrs it may
//! set are those of the destination only.  It keeps the capabilities that
//! set them (CHOWN, DAC_OVERRIDE, FOWNER, FSETID, SETFCAP for the file
//! capabilities of the files copied) and no other, its files are at most
//! `max_bytes` long, and a seccomp allow-list lets it make the calls a copy
//! makes and nothing else: no socket, io_uring, exec, fork, mount,
//! namespace, mknod but of fifos (no device: it has no MKNOD capability,
//! and a device node in the store would open the device to whoever reaches
//! it), set*id, the `fcntl` commands that do not route signals only, and
//! signals to itself only.  A worker that cannot
//! set all of this up exits with an error.
//!
//! Landlock (read below the source, write below the destination) is a
//! second wall where the kernel has it, not a requirement: the pivoted
//! root already leaves nothing else to reach.
//!
//! In the user namespace of the fallback the worker maps its own ids only:
//! `--chown` and the owners of an archive other than the daemon's user
//! fail there.  A daemon that runs as root, or in the user namespace of a
//! rootless setup, never takes the fallback.

use super::copy::{self, CopyJob};
use super::helper;
use crate::services::Cancel;
use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr, Scope, ABI,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::Duration;
use velarx_sandbox as sandbox;

const DEST_FD: i32 = 3;
const SOURCE_FD: i32 = 4;
/// The largest job a worker reads.
const MAX_JOB: u64 = 64 * 1024 * 1024;

/// CHOWN, DAC_OVERRIDE, FOWNER, FSETID and SETFCAP.
const KEPT_CAPS: u32 = 0b1_1011 | 1 << 31;

/// Where the files of a job come from.
pub enum JobSource {
    /// A directory (the build context).
    Dir(PathBuf),
    /// A stream: a pipe or a file.
    Stream(OwnedFd),
    /// A directory held open (the build context, which is read through its
    /// descriptor and never copied).
    Fd(OwnedFd),
}

impl JobSource {
    /// Whether the source is a directory (a stream is not).
    pub fn is_tree(&self) -> bool {
        matches!(self, Self::Dir(_) | Self::Fd(_))
    }

    /// Another handle on a directory source (a stream is read once).
    pub fn duplicate(&self) -> io::Result<Self> {
        match self {
            Self::Dir(p) => Ok(Self::Dir(p.clone())),
            Self::Fd(fd) => Ok(Self::Fd(fd.try_clone()?)),
            Self::Stream(_) => Err(io::Error::other("a stream is read once")),
        }
    }
}

/// Runs the jobs: in a worker when `exe` is set, in this process (unit
/// tests) otherwise.
#[derive(Debug, Clone)]
pub struct Runner {
    pub exe: Option<PathBuf>,
    /// A worker that runs longer is killed.
    pub timeout: Duration,
}

impl Default for Runner {
    fn default() -> Self {
        Self {
            exe: None,
            timeout: Duration::from_secs(3600),
        }
    }
}

fn open_dir(path: &Path, flags: rustix::fs::OFlags) -> io::Result<OwnedFd> {
    use rustix::fs::{openat, Mode, OFlags};
    openat(
        rustix::fs::CWD,
        path,
        flags | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io::Error::new(e.kind(), format!("open {}: {e}", path.display())))
}

impl Runner {
    /// Run `job`, filling the directory `dest`: whether a node it copied
    /// from a context changed since `job.unchanged_since`.
    pub async fn run(
        &self,
        job: CopyJob,
        dest: &Path,
        source: JobSource,
        cancel: &Cancel,
    ) -> io::Result<bool> {
        let job = CopyJob {
            digest: false,
            ..job
        };
        match self.start(job, dest, source, cancel).await?.as_str() {
            "" => Ok(false),
            CHANGED => Ok(true),
            answer => Err(io::Error::other(answer.to_string())),
        }
    }

    /// The digest of what `job` would copy from the context directory
    /// `source` (see [`copy::digest`]); `dest` is an empty directory the
    /// worker is given.
    pub async fn digest(
        &self,
        job: CopyJob,
        dest: &Path,
        source: JobSource,
        cancel: &Cancel,
    ) -> io::Result<String> {
        let job = CopyJob {
            digest: true,
            ..job
        };
        let answer = self.start(job, dest, source, cancel).await?;
        if answer.parse::<velarx_types::digest::Digest>().is_err() {
            return Err(io::Error::other(format!(
                "the build worker answered `{}` for a digest",
                answer.chars().take(100).collect::<String>()
            )));
        }
        Ok(answer)
    }

    /// Run `job` in a worker (or here) and take its answer.
    async fn start(
        &self,
        job: CopyJob,
        dest: &Path,
        source: JobSource,
        cancel: &Cancel,
    ) -> io::Result<String> {
        let dest_fd = open_dir(dest, rustix::fs::OFlags::RDONLY)?;
        let source_fd = match source {
            JobSource::Dir(p) => open_dir(&p, rustix::fs::OFlags::PATH)?,
            JobSource::Stream(fd) => as_pipe(fd)?,
            JobSource::Fd(fd) => fd,
        };
        let (exe, timeout) = (self.exe.clone(), self.timeout);
        let here = cancel.clone();
        helper::stoppable(cancel, move |stop| match exe {
            None => run_here(&job, dest_fd.as_fd(), source_fd, &here),
            Some(exe) => spawn(
                &exe,
                &job,
                dest_fd.as_fd(),
                source_fd.as_fd(),
                timeout,
                stop,
            ),
        })
        .await
    }
}

/// The answer of a copy that saw a source change (see
/// `CopyJob::unchanged_since`); a copy that did not answers nothing.
const CHANGED: &str = "changed";

/// Run a job in this process: its answer, as a worker's.
fn run_here(
    job: &CopyJob,
    dest: BorrowedFd<'_>,
    source: OwnedFd,
    cancel: &Cancel,
) -> io::Result<String> {
    if job.digest {
        copy::digest(job, source)
    } else {
        copy::run(job, dest, source, cancel)
            .map(|changed| if changed { CHANGED } else { "" }.to_string())
    }
}

/// A stream as a pipe: a file given to the worker is a node it could change
/// the owner or mode of; what is written to the pipe is the file's content.
fn as_pipe(fd: OwnedFd) -> io::Result<OwnedFd> {
    let st = rustix::fs::fstat(&fd)?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Fifo {
        return Ok(fd);
    }
    let (reader, mut writer) = std::io::pipe()?;
    let mut file = std::fs::File::from(fd);
    std::thread::Builder::new()
        .name("build-feed".into())
        .spawn(move || {
            // The worker reads what it needs; it may stop before the end.
            let _ = io::copy(&mut file, &mut writer);
        })?;
    Ok(reader.into())
}

/// Start a worker for `job` and wait for it, at most `timeout`: its
/// answer when it succeeds.
fn spawn(
    exe: &Path,
    job: &CopyJob,
    dest: BorrowedFd<'_>,
    source: BorrowedFd<'_>,
    timeout: Duration,
    stop: BorrowedFd<'_>,
) -> io::Result<String> {
    use std::process::{Command, Stdio};
    let (dest_raw, source_raw) = (dest.as_raw_fd(), source.as_raw_fd());
    let mut cmd = Command::new(exe);
    cmd.arg("build-worker")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    velarx_sys::spawn::pre_exec(&mut cmd, move |child| {
        // In place as 3 and 4 (out of each other's way, close-on-exec cleared).
        child.place_fds(&[dest_raw, source_raw], DEST_FD)
    });
    let child = cmd.spawn().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("start the build worker {}: {e}", exe.display()),
        )
    })?;
    let body = serde_json::to_vec(job).map_err(io::Error::other)?;
    let (status, answer) = match helper::talk(child, body, timeout, stop)? {
        helper::Talked::Done(status, answer) => (status, answer),
        helper::Talked::Stopped => return Err(Cancel::error()),
        helper::Talked::TimedOut => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the build worker ran longer than {}s", timeout.as_secs()),
            ))
        }
    };
    if status.success() {
        return Ok(answer);
    }
    let msg = if answer.is_empty() {
        format!("the build worker failed: {status}")
    } else {
        answer
    };
    Err(io::Error::other(msg))
}

/// The error of a call, with what it was doing.
fn rc<T, E: Into<io::Error>>(r: Result<T, E>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {}", e.into()))
}

fn write_proc(path: &CStr, data: &str) -> Result<(), String> {
    use rustix::fs::{open, Mode, OFlags};
    let name = path.to_string_lossy();
    let fd = rc(
        open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty()),
        &format!("open {name}"),
    )?;
    match rustix::io::write(&fd, data.as_bytes()) {
        Ok(n) if n == data.len() => Ok(()),
        Ok(_) => Err(format!("write {name}: short write")),
        Err(e) => Err(format!("write {name}: {}", io::Error::from(e))),
    }
}

/// The directory of descriptor `fd` opened again by its path, in the mount
/// namespace this process is in now (a bind mount takes a source of its
/// own namespace), checked to be the same directory.
fn reopen_here(fd: BorrowedFd<'_>, path: &CStr) -> Result<OwnedFd, String> {
    use rustix::fs::{fstat, open, Mode, OFlags};
    let before = rc(fstat(fd), "fstat")?;
    let new = rc(
        open(
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ),
        &format!("open {}", path.to_string_lossy()),
    )?;
    match fstat(&new) {
        Ok(after) if (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino) => Ok(new),
        _ => Err(format!("{} changed", path.to_string_lossy())),
    }
}

fn fd_path(fd: BorrowedFd<'_>) -> Result<std::ffi::CString, String> {
    let p = std::fs::read_link(velarx_sys::fd::proc_path(&fd))
        .map_err(|e| format!("the path of descriptor {}: {e}", fd.as_raw_fd()))?;
    std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str()))
        .map_err(|e| e.to_string())
}

/// A new mount namespace whose root holds the destination as `/dest` and
/// the source directory as `/src` (read-only), and nothing else; the
/// destination and the source directory are opened again in it, and
/// returned (the source only when it is a directory).
fn isolate(
    dest: BorrowedFd<'_>,
    source: BorrowedFd<'_>,
    source_is_dir: bool,
) -> Result<(OwnedFd, Option<OwnedFd>), String> {
    use rustix::fs::{mkdir, open, Mode, OFlags};
    use rustix::mount::{mount, mount_bind, mount_change, MountFlags, MountPropagationFlags};
    use rustix::thread::UnshareFlags;
    use velarx_sys::mount::MountAttr;
    const RDONLY: u64 = 0x1;
    const NOSUID: u64 = 0x2;
    const NODEV: u64 = 0x4;
    const NOEXEC: u64 = 0x8;
    let setattr = |path: &CStr, set: u64| -> Result<(), String> {
        rc(
            velarx_sys::mount::setattr_path(
                path,
                &MountAttr {
                    attr_set: set,
                    ..Default::default()
                },
            ),
            "mount_setattr",
        )
    };
    let (uid, gid) = (
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    );
    let dest_path = fd_path(dest)?;
    let src_path = if source_is_dir {
        Some(fd_path(source)?)
    } else {
        None
    };
    if velarx_sys::ns::unshare(UnshareFlags::NEWNS).is_err() {
        // Without the right to mount: a user namespace of its own where
        // it has it, mapping its ids only.
        rc(
            velarx_sys::ns::unshare(UnshareFlags::NEWUSER | UnshareFlags::NEWNS),
            "unshare",
        )?;
        write_proc(c"/proc/self/setgroups", "deny")?;
        write_proc(c"/proc/self/uid_map", &format!("0 {uid} 1"))?;
        write_proc(c"/proc/self/gid_map", &format!("0 {gid} 1"))?;
    }
    rc(
        mount_change(
            "/",
            MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
        ),
        "make the mounts private",
    )?;
    // Opened again before /tmp is covered.
    let dest_here = reopen_here(dest, &dest_path)?;
    let src_here = match &src_path {
        Some(p) => Some(reopen_here(source, p)?),
        None => None,
    };
    rc(
        mount(
            "none",
            "/tmp",
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
            c"mode=0755,size=64k",
        ),
        "mount the new root",
    )?;
    rc(mkdir("/tmp/dest", Mode::from_raw_mode(0o755)), "mkdir dest")?;
    rc(
        mount_bind(velarx_sys::fd::proc_str(&dest_here), "/tmp/dest"),
        "bind the destination",
    )?;
    setattr(c"/tmp/dest", NOSUID | NODEV | NOEXEC)?;
    drop(dest_here);
    if let Some(src_here) = src_here {
        rc(mkdir("/tmp/src", Mode::from_raw_mode(0o755)), "mkdir src")?;
        rc(
            mount_bind(velarx_sys::fd::proc_str(&src_here), "/tmp/src"),
            "bind the source",
        )?;
        setattr(c"/tmp/src", RDONLY | NOSUID | NODEV | NOEXEC)?;
        drop(src_here);
    }
    rc(rustix::process::chdir("/tmp"), "chdir")?;
    rc(rustix::process::pivot_root(".", "."), "pivot_root")?;
    rc(
        rustix::mount::unmount(".", rustix::mount::UnmountFlags::DETACH),
        "detach the old root",
    )?;
    rc(rustix::process::chdir("/"), "chdir /")?;
    // The descriptors of the old root lead to it: replaced.
    let dest = rc(
        open(
            "/dest",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ),
        "open /dest",
    )?;
    let src = if source_is_dir {
        Some(rc(
            open(
                "/src",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ),
            "open /src",
        )?)
    } else {
        None
    };
    Ok((dest, src))
}

fn keep_capabilities() -> Result<(), String> {
    use rustix::thread::{CapabilitySet, CapabilitySets};
    let current = rc(rustix::thread::capabilities(None), "capget")?;
    rc(
        velarx_sys::caps::drop_bounding_except(|cap| cap < 32 && KEPT_CAPS & (1 << cap) != 0),
        "the bounding set",
    )?;
    rc(velarx_sys::caps::clear_ambient(), "the ambient set")?;
    let kept = CapabilitySet::from_bits_retain(
        (current.permitted.bits() & u64::from(u32::MAX)) & u64::from(KEPT_CAPS),
    );
    rc(
        rustix::thread::set_capabilities(
            None,
            CapabilitySets {
                effective: kept,
                permitted: kept,
                inheritable: CapabilitySet::empty(),
            },
        ),
        "capset",
    )
}

fn landlock(dest: BorrowedFd<'_>, source: Option<BorrowedFd<'_>>) -> Result<(), String> {
    let abi = ABI::V6;
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("landlock: {e}"))?
        .set_compatibility(CompatLevel::BestEffort)
        .scope(Scope::AbstractUnixSocket | Scope::Signal)
        .map_err(|e| format!("landlock: {e}"))?
        .create()
        .map_err(|e| format!("landlock: {e}"))?
        .add_rule(PathBeneath::new(dest, AccessFs::from_all(abi)))
        .map_err(|e| format!("landlock: {e}"))?;
    if let Some(source) = source {
        ruleset = ruleset
            .add_rule(PathBeneath::new(source, AccessFs::from_read(abi)))
            .map_err(|e| format!("landlock: {e}"))?;
    }
    // (the status is not looked at: Landlock is not required, see the
    // module; the pivoted root is)
    ruleset
        .restrict_self()
        .map_err(|e| format!("landlock: {e}"))?;
    Ok(())
}

/// The calls a copy makes; every other one fails with EPERM.
fn allowed_syscalls() -> Vec<i64> {
    // Extended below on x86_64 only.
    let list = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_preadv,
        libc::SYS_pwritev,
        libc::SYS_lseek,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_statx,
        libc::SYS_fstatfs,
        libc::SYS_getdents64,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_symlinkat,
        libc::SYS_readlinkat,
        libc::SYS_linkat,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        452, // fchmodat2
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_utimensat,
        libc::SYS_flistxattr,
        libc::SYS_fgetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_copy_file_range,
        libc::SYS_sendfile,
        libc::SYS_splice,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_ftruncate,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_capget,
        // the pipes and the socket of the decompressors (`external`): the
        // socket is the one inherited, none can be made
        libc::SYS_pipe2,
        libc::SYS_ppoll,
        libc::SYS_sendmsg,
    ];
    #[cfg(target_arch = "x86_64")]
    let list = [
        list,
        vec![
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_dup2,
            libc::SYS_readlink,
            libc::SYS_poll,
        ],
    ]
    .concat();
    list
}

fn cond(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, String> {
    sandbox::condition(arg, SeccompCmpArgLen::Qword, op, value)
}

fn seccomp_program(pid: u32) -> Result<BpfProgram, String> {
    let mut allowed: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in allowed_syscalls() {
        // No condition: the call is allowed.
        allowed.insert(nr, Vec::new());
    }
    // Signals to itself only (an abort): all the bits of the pid compared.
    for nr in [libc::SYS_kill, libc::SYS_tgkill, libc::SYS_tkill] {
        allowed.insert(
            nr,
            vec![sandbox::rule(vec![cond(0, SeccompCmpOp::Eq, pid.into())?])?],
        );
    }
    // The commands of `fcntl` that do not route signals (F_SETOWN,
    // F_SETSIG, O_ASYNC would let the daemon's writes signal any process).
    use SeccompCmpArgLen::{Dword, Qword};
    let fcntl_cmd = |cmd: libc::c_int| sandbox::condition(1, Dword, SeccompCmpOp::Eq, cmd as u64);
    allowed.insert(
        libc::SYS_fcntl,
        vec![
            sandbox::rule(vec![fcntl_cmd(libc::F_GETFD)?])?,
            sandbox::rule(vec![fcntl_cmd(libc::F_SETFD)?])?,
            sandbox::rule(vec![fcntl_cmd(libc::F_GETFL)?])?,
            sandbox::rule(vec![fcntl_cmd(libc::F_DUPFD_CLOEXEC)?])?,
            sandbox::rule(vec![
                fcntl_cmd(libc::F_SETFL)?,
                sandbox::condition(2, Qword, SeccompCmpOp::MaskedEq(libc::O_ASYNC as u64), 0)?,
            ])?,
        ],
    );
    // Fifos only: the type bits of the mode compared.
    allowed.insert(
        libc::SYS_mknodat,
        vec![sandbox::rule(vec![sandbox::condition(
            2,
            Dword,
            SeccompCmpOp::MaskedEq(libc::S_IFMT as u64),
            libc::S_IFIFO as u64,
        )?])?],
    );
    // What the self-test asks.
    allowed.insert(
        libc::SYS_prctl,
        vec![
            sandbox::rule(vec![cond(
                0,
                SeccompCmpOp::Eq,
                libc::PR_GET_NO_NEW_PRIVS as u64,
            )?])?,
            sandbox::rule(vec![cond(
                0,
                SeccompCmpOp::Eq,
                libc::PR_GET_SECCOMP as u64,
            )?])?,
        ],
    );
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e: seccompiler::BackendError| e.to_string())?;
    let filter = SeccompFilter::new(
        allowed,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| e.to_string())?;
    velarx_sys::confine::seccompiler_program(filter)
}

/// Confine this process.  Call it before any thread is started.  The
/// destination and the source it was given (put in place by the daemon, as
/// 3 and 4) are returned as the confined process has them.
fn confine(
    startup: &velarx_sys::fd::Startup,
    max_bytes: u64,
    decompressors: bool,
) -> Result<(OwnedFd, OwnedFd), String> {
    // Standard error to the answer: no descriptor of a host file.
    rc(
        rustix::stdio::dup2_stderr(rustix::stdio::stdout()),
        "redirect stderr",
    )?;
    startup.close_from((SOURCE_FD + 1) as u32);
    // The xz and bzip2 archives of ADD are extracted by the system
    // programs, which this process cannot execute once confined: its
    // spawner (a process of its own, confined) does, before the root changes.
    if decompressors {
        super::external::Decompressors::start_for_worker()?;
    }
    let (Some(given_dest), Some(given_source)) = (startup.adopt(DEST_FD), startup.adopt(SOURCE_FD))
    else {
        return Err("the descriptors of the job are not open".into());
    };
    let source_is_dir = rustix::fs::fstat(&given_source)
        .map(|st| {
            rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::Directory
        })
        .unwrap_or(false);
    // (the descriptors of the old root lead to it: those opened again in
    // the new one replace them, and they are closed before the limits)
    let (dest, new_source) = isolate(given_dest.as_fd(), given_source.as_fd(), source_is_dir)?;
    drop(given_dest);
    let source = new_source.unwrap_or(given_source);
    rc(
        rustix::process::setrlimit(
            rustix::process::Resource::Fsize,
            rustix::process::Rlimit {
                current: Some(max_bytes),
                maximum: Some(max_bytes),
            },
        ),
        "RLIMIT_FSIZE",
    )?;
    // A file over the limit fails to be written, it does not kill.
    velarx_sys::signal::ignore(libc::SIGXFSZ);
    sandbox::process_limits()?;
    keep_capabilities()?;
    landlock(dest.as_fd(), source_is_dir.then(|| source.as_fd()))?;
    let program = seccomp_program(std::process::id())?;
    seccompiler::apply_filter(&program).map_err(|e| format!("seccomp: {e}"))?;
    Ok((dest, source))
}

/// What the confined worker cannot do: `(what, as it should be)`.
fn probes(dest: BorrowedFd<'_>) -> Vec<(&'static str, bool)> {
    use rustix::fs::{chmodat, mknodat, openat, AtFlags, FileType, Mode, OFlags, CWD};
    use rustix::io::Errno;
    use velarx_sys::selftest;
    let denied = |e: Result<(), Errno>| e == Err(Errno::PERM);
    // (the file calls with a descriptor: the filter has no `open` or `chmod`)
    let open = |p: &str, flags: OFlags, mode: Mode| openat(CWD, p, flags, mode);
    let mut out = Vec::new();
    out.push((
        "no /etc/passwd",
        open("/etc/passwd", OFlags::RDONLY, Mode::empty()).is_err(),
    ));
    out.push((
        "no host path to chmod",
        chmodat(
            CWD,
            "/usr/bin",
            Mode::from_raw_mode(0o777),
            AtFlags::empty(),
        )
        .is_err(),
    ));
    out.push((
        "write in the destination",
        openat(
            dest,
            "probe",
            OFlags::WRONLY | OFlags::CREATE,
            Mode::from_raw_mode(0o600),
        )
        .is_ok(),
    ));
    let node = |name: &str, kind: FileType, mode: u32, dev: u64| {
        mknodat(dest, name, kind, Mode::from_raw_mode(mode), dev)
    };
    out.push((
        "a device node",
        denied(node(
            "probe-dev",
            FileType::CharacterDevice,
            0o666,
            rustix::fs::makedev(1, 3),
        )),
    ));
    out.push((
        "a block device node",
        denied(node(
            "probe-dev",
            FileType::BlockDevice,
            0o666,
            rustix::fs::makedev(8, 0),
        )),
    ));
    out.push((
        "a fifo",
        node("probe-fifo", FileType::Fifo, 0o600, 0).is_ok(),
    ));
    out.push(("only the destination and the source in /", {
        let exists = |p: &str| open(p, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).is_ok();
        exists("/dest") && !exists("/usr") && !exists("/proc") && !exists("/etc")
    }));
    let socket =
        |family| rustix::net::socket(family, rustix::net::SocketType::STREAM, None).map(drop);
    out.push(("a socket", denied(socket(rustix::net::AddressFamily::INET))));
    out.push((
        "a UNIX socket",
        denied(socket(rustix::net::AddressFamily::UNIX)),
    ));
    out.push(("io_uring", selftest::io_uring_setup_errno() == libc::EPERM));
    out.push(("execve", selftest::execve_true_errno() == libc::EPERM));
    // the xz archive of an ADD goes through the spawner, if xz is installed
    if super::external::Programs::system().any() {
        out.push((
            "an xz archive extracted by the spawner",
            super::external::decompress("xz", &super::external::XZ_OK[..]).is_ok_and(|mut r| {
                let mut got = Vec::new();
                r.read_to_end(&mut got).is_ok() && got == b"ok"
            }),
        ));
    }
    out.push(("fork", selftest::fork_is_refused()));
    out.push((
        "unshare",
        velarx_sys::ns::unshare(rustix::thread::UnshareFlags::NEWNS).is_err(),
    ));
    out.push(("setuid", selftest::setuid_errno(0) != 0));
    let signal_refused = |pid: i32| {
        velarx_sys::process::kill(pid, 0).is_err_and(|e| e.raw_os_error() == Some(libc::EPERM))
    };
    out.push(("signal every process", signal_refused(-1)));
    let fcntl = |cmd, arg| selftest::fcntl_errno(dest.as_raw_fd(), cmd, arg);
    out.push(("F_SETOWN", fcntl(libc::F_SETOWN, 1) == libc::EPERM));
    out.push((
        "F_SETSIG",
        fcntl(10 /* F_SETSIG */, libc::SIGKILL) == libc::EPERM,
    ));
    out.push((
        "O_ASYNC",
        fcntl(libc::F_SETFL, libc::O_ASYNC | libc::O_NONBLOCK) == libc::EPERM,
    ));
    out.push((
        "F_SETFL without O_ASYNC",
        fcntl(libc::F_SETFL, libc::O_NONBLOCK) == 0,
    ));
    // (the filter refuses getppid: the C library answers what the kernel did)
    let ppid = std::os::unix::process::parent_id() as i32;
    out.push(("signal the daemon", signal_refused(ppid)));
    out.push(("signal init", signal_refused(1)));
    out.push((
        "tgkill init",
        selftest::tgkill_errno(1, 1, 0) == libc::EPERM,
    ));
    out.push((
        "signal itself",
        velarx_sys::process::kill(std::process::id() as i32, 0).is_ok(),
    ));
    out.push((
        "no_new_privs",
        rustix::thread::no_new_privs().unwrap_or(false),
    ));
    out.push((
        "seccomp",
        rustix::thread::secure_computing_mode() == Ok(rustix::thread::SecureComputingMode::Filter),
    ));
    out.push((
        "only the file capabilities",
        rustix::thread::capabilities(None)
            .is_ok_and(|c| c.effective.bits() & !u64::from(KEPT_CAPS) == 0),
    ));
    out
}

/// Entry point of `velarx build-worker`.
pub fn main(startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    let self_test = std::env::args_os()
        .nth(2)
        .is_some_and(|a| a == "--self-test");
    let mut out = std::io::stdout();
    let result = (|| -> Result<String, String> {
        let mut body = Vec::new();
        std::io::stdin()
            .take(MAX_JOB)
            .read_to_end(&mut body)
            .map_err(|e| format!("read the job: {e}"))?;
        let job: Option<CopyJob> = if self_test {
            None
        } else {
            Some(serde_json::from_slice(&body).map_err(|e| format!("invalid job: {e}"))?)
        };
        let max_bytes = job
            .as_ref()
            .map_or(copy::Limits::default().max_bytes, |j| j.limits.max_bytes);
        let decompressors = job
            .as_ref()
            .is_none_or(|j| j.add || matches!(j.source, copy::Source::Unpack));
        let (dest, source) = confine(startup, max_bytes, decompressors)
            .map_err(|e| format!("the build worker cannot confine itself: {e}"))?;
        let Some(job) = job else {
            let report = serde_json::to_string(&probes(dest.as_fd())).map_err(|e| e.to_string())?;
            return Err(format!("self-test {report}"));
        };
        run_here(&job, dest.as_fd(), source, &Cancel::default()).map_err(|e| e.to_string())
    })();
    match result {
        Ok(answer) => {
            let _ = out.write_all(answer.as_bytes());
            let _ = out.flush();
            Ok(())
        }
        Err(msg) => {
            let _ = out.write_all(msg.as_bytes());
            let _ = out.flush();
            std::process::exit(1);
        }
    }
}
