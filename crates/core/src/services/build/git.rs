// SPDX-License-Identifier: Apache-2.0
//! `ADD` of a git repository, and a git repository as the build context:
//! `https://host/repo.git#ref:subdir` (buildah), `git://host/repo#ref:subdir`
//! or `git@host:repo.git#ref:subdir` (Docker).  The repository is cloned by
//! git in a confined helper (`velarx git-clone`): an unprivileged
//! user (nobody when the daemon is root) in a mount namespace (and a user
//! namespace when it is not root) of its own, whose root is a tmpfs with, read-only, `/usr` and the files of
//! `/etc` that name resolution, TLS and ssh need, a few device nodes, the
//! empty destination (read-write) and nothing else of the host; no new
//! privileges, files at most the size a copy may write, and git told not
//! to read a system or user configuration, run hooks or use transports
//! other than https, http and ssh.
//!
//! The daemon gives it the destination as descriptor 3 and the request on
//! its standard input; it answers on its standard output, nothing when the
//! clone is done.

use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;
use velarx_wire::redact;

const DEST_FD: i32 = 3;
/// The largest request read.
const MAX_REQUEST: u64 = 64 * 1024;
/// The id the helper runs as when the daemon is root.
const NOBODY: u32 = 65534;

/// A git source of ADD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSource {
    /// The repository, without the fragment.
    pub url: String,
    /// The branch, tag or commit; HEAD if none.
    pub reference: String,
    /// The directory of the repository to copy, relative; empty for all.
    pub subdir: String,
}

/// The source as a git repository, if it is one: an http(s) URL whose
/// path ends in `.git` (with a fragment or not), a `git://` URL, or
/// `git@host:path`.
pub fn parse(source: &str) -> Option<Result<GitSource, String>> {
    let http = source.starts_with("https://") || source.starts_with("http://");
    let (repo, fragment) = match source.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (source, None),
    };
    let is_git = if http {
        repo.ends_with(".git") && fragment.is_none_or(|f| !f.is_empty())
    } else {
        source.starts_with("git@") || source.starts_with("git://")
    };
    if !is_git {
        return None;
    }
    Some(check(repo, fragment))
}

fn check(repo: &str, fragment: Option<&str>) -> Result<GitSource, String> {
    if repo.len() > 2048 || repo.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!("invalid git repository `{}`", redact::urls(repo)));
    }
    if let Some(rest) = repo.strip_prefix("git@") {
        // git@host:path, the host a name.
        let (host, path) = rest.split_once(':').ok_or_else(|| {
            format!(
                "invalid git repository `{}`: git@HOST:PATH",
                redact::urls(repo)
            )
        })?;
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
            || path.is_empty()
            || path.starts_with('-')
        {
            return Err(format!("invalid git repository `{}`", redact::urls(repo)));
        }
    } else {
        // (git parses the rest of the URL itself)
        let rest = repo
            .strip_prefix("https://")
            .or_else(|| repo.strip_prefix("http://"))
            .or_else(|| repo.strip_prefix("git://"));
        if rest.is_none_or(|r| r.split('/').next().is_none_or(str::is_empty)) {
            return Err(format!("invalid git repository `{}`", redact::urls(repo)));
        }
    }
    let (reference, subdir) = match fragment {
        Some(f) => match f.split_once(':') {
            Some((r, s)) => (r, s),
            None => (f, ""),
        },
        None => ("", ""),
    };
    if reference.starts_with('-')
        || reference.len() > 256
        || reference.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
    {
        return Err(format!("invalid git reference `{reference}`"));
    }
    let mut parts = Vec::new();
    for c in subdir.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err(format!("the subdirectory `{subdir}` goes up")),
            c => parts.push(c),
        }
    }
    Ok(GitSource {
        url: repo.to_string(),
        reference: if reference.is_empty() {
            "HEAD".into()
        } else {
            reference.into()
        },
        subdir: parts.join("/"),
    })
}

/// What the daemon asks the helper.
#[derive(Debug, Serialize, Deserialize)]
struct Request {
    source: GitSource,
    /// The largest file git may write, and the most bytes of the files of
    /// the tree together.
    max_bytes: u64,
    /// The most files of the tree.
    max_entries: u64,
    /// The ssh agent of the daemon, for git@ repositories.
    ssh_auth_sock: Option<String>,
    /// The known hosts of the daemon's user, for git@ repositories.
    known_hosts: Option<String>,
    /// Report what the sandbox lets git do instead of cloning (tests).
    #[serde(default)]
    self_test: bool,
}

/// What git can and cannot do in the sandbox: `(what, as it should be)`.
fn probes() -> Vec<(&'static str, bool)> {
    let exists = |p: &str| std::fs::symlink_metadata(p).is_ok();
    let writable = |p: &str| {
        let f = format!("{p}/.probe");
        let ok = std::fs::write(&f, b"x").is_ok();
        let _ = std::fs::remove_file(&f);
        ok
    };
    let uid = rustix::process::geteuid().as_raw();
    let nnp = rustix::thread::no_new_privs().unwrap_or(false);
    vec![
        ("git is there", exists("/usr/bin/git")),
        ("no /proc", !exists("/proc/self")),
        ("no /etc/shadow", !exists("/etc/shadow")),
        ("no /root", !exists("/root")),
        ("no /var", !exists("/var")),
        ("/usr read-only", !writable("/usr")),
        ("/etc read-only", !writable("/etc")),
        ("the destination writable", writable("/dest")),
        ("not root", uid != 0),
        ("no_new_privs", nnp),
    ]
}

/// Clone `source` into the empty directory `dest` with the helper `exe`
/// (this executable), killed after `timeout`; a tree larger than `limits`
/// is refused before it is written.
pub fn clone(
    exe: &Path,
    source: &GitSource,
    dest: &Path,
    limits: &super::copy::Limits,
    timeout: Duration,
    stop: std::os::fd::BorrowedFd<'_>,
) -> io::Result<()> {
    use std::process::{Command, Stdio};
    let dir = std::fs::File::open(dest)?;
    let raw = dir.as_raw_fd();
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let request = Request {
        source: source.clone(),
        max_bytes: limits.max_bytes,
        max_entries: limits.max_entries,
        ssh_auth_sock: std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|s| s.starts_with('/')),
        known_hosts: home
            .map(|h| h.join(".ssh/known_hosts"))
            .filter(|p| p.is_file())
            .and_then(|p| p.to_str().map(str::to_string)),
        self_test: false,
    };
    let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
    let mut cmd = Command::new(exe);
    cmd.arg("git-clone")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    velarx_sys::spawn::pre_exec(&mut cmd, move |child| child.place_fds(&[raw], DEST_FD));
    let child = cmd
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("start the git helper: {e}")))?;
    drop(dir);
    let (status, answer) = match super::helper::talk(child, body, timeout, stop)? {
        super::helper::Talked::Done(status, answer) => (status, answer),
        super::helper::Talked::Stopped => return Err(crate::services::Cancel::error()),
        super::helper::Talked::TimedOut => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "cloning {} took longer than {}s",
                    redact::urls(&source.url),
                    timeout.as_secs()
                ),
            ))
        }
    };
    if status.success() && answer.is_empty() {
        return Ok(());
    }
    Err(io::Error::other(if answer.is_empty() {
        format!(
            "cloning {}: the git helper failed: {status}",
            redact::urls(&source.url)
        )
    } else {
        format!(
            "cloning {}: {}",
            redact::urls(&source.url),
            redact::urls(&answer)
        )
    }))
}

/// The error of a call, with what it was doing.
fn rc<T, E: Into<io::Error>>(r: Result<T, E>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {}", e.into()))
}

fn write_file(path: &CStr, data: &str) -> Result<(), String> {
    std::fs::write(path.to_string_lossy().as_ref(), data)
        .map_err(|e| format!("write {}: {e}", path.to_string_lossy()))
}

/// Bind `src` of the host at `dst` (made first, a directory or a file as
/// `src` is), read-only unless `writable`; nothing if `src` does not exist.
fn bind(src: &str, dst: &str, writable: bool) -> Result<(), String> {
    let meta = match std::fs::metadata(src) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    if meta.is_dir() {
        std::fs::create_dir_all(dst).map_err(|e| format!("mkdir {dst}: {e}"))?;
    } else {
        if let Some(parent) = Path::new(dst).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {dst}: {e}"))?;
        }
        std::fs::write(dst, b"").map_err(|e| format!("create {dst}: {e}"))?;
    }
    use rustix::mount::{mount_bind_recursive, mount_remount, MountFlags};
    rc(mount_bind_recursive(src, dst), &format!("bind {src}"))?;
    let mut flags = MountFlags::BIND | MountFlags::NOSUID;
    if !writable {
        flags |= MountFlags::RDONLY;
    }
    // In a user namespace the flags the host mount has (nodev, noexec)
    // are locked: they must be given again.
    let mut r = Ok(());
    for extra in [
        MountFlags::empty(),
        MountFlags::NODEV,
        MountFlags::NODEV | MountFlags::NOEXEC,
    ] {
        r = mount_remount(dst, flags | extra, "");
        if r.is_ok() {
            break;
        }
    }
    rc(r, &format!("remount {dst}"))
}

/// The new root: a tmpfs with what git needs of the host.  A root daemon
/// sets it up in a mount namespace, then becomes nobody; any other in user
/// and mount namespaces of its own.
fn isolate(req: &Request, dest_given: OwnedFd) -> Result<(), String> {
    use rustix::fs::{fstat, open, Mode, OFlags};
    use rustix::mount::{
        mount, mount_bind, mount_change, mount_remount, MountFlags, MountPropagationFlags,
        UnmountFlags,
    };
    use rustix::thread::UnshareFlags;
    let dest_path = std::fs::read_link(velarx_sys::fd::proc_path(&dest_given))
        .map_err(|e| format!("the destination: {e}"))?;
    let (uid, gid) = (
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    );
    rc(rustix::thread::set_no_new_privs(true), "no_new_privs")?;
    if uid == 0 {
        rc(velarx_sys::ns::unshare(UnshareFlags::NEWNS), "unshare")?;
    } else {
        rc(
            velarx_sys::ns::unshare(UnshareFlags::NEWUSER | UnshareFlags::NEWNS),
            "unshare",
        )?;
        write_file(c"/proc/self/setgroups", "deny")?;
        write_file(c"/proc/self/uid_map", &format!("{uid} {uid} 1"))?;
        write_file(c"/proc/self/gid_map", &format!("{gid} {gid} 1"))?;
    }
    rc(
        mount_change(
            "/",
            MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
        ),
        "make the mounts private",
    )?;
    // The destination opened again in this namespace before /tmp (where
    // it may be) is covered: a bind takes a source of its namespace.
    let dest = dest_path.to_str().ok_or("the destination is not UTF-8")?;
    let dest_here = rc(
        open(
            dest,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        ),
        "open the destination",
    )?;
    match (fstat(&dest_given), fstat(&dest_here)) {
        (Ok(a), Ok(b)) if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) => {}
        _ => return Err("the destination changed".into()),
    }
    let root = "/tmp";
    rc(
        mount(
            "none",
            "/tmp",
            "tmpfs",
            MountFlags::NOSUID | MountFlags::NODEV,
            c"mode=0755,size=16m",
        ),
        "mount the new root",
    )?;
    bind("/usr", &format!("{root}/usr"), false)?;
    for d in ["bin", "sbin", "lib", "lib64", "lib32"] {
        let host = format!("/{d}");
        match std::fs::read_link(&host) {
            Ok(target) => std::os::unix::fs::symlink(&target, format!("{root}/{d}"))
                .map_err(|e| format!("link {d}: {e}"))?,
            Err(_) => bind(&host, &format!("{root}/{d}"), false)?,
        }
    }
    for f in [
        "resolv.conf",
        "hosts",
        "nsswitch.conf",
        "host.conf",
        "gai.conf",
        "passwd",
        "group",
        "services",
        "protocols",
    ] {
        bind(&format!("/etc/{f}"), &format!("{root}/etc/{f}"), false)?;
    }
    for d in [
        "ssl",
        "pki",
        "ca-certificates",
        "crypto-policies",
        "alternatives",
    ] {
        bind(&format!("/etc/{d}"), &format!("{root}/etc/{d}"), false)?;
    }
    for n in ["null", "zero", "urandom", "random"] {
        bind(&format!("/dev/{n}"), &format!("{root}/dev/{n}"), true)?;
    }
    if let Some(sock) = &req.ssh_auth_sock {
        bind(sock, &format!("{root}/run/ssh-agent.sock"), true)?;
    }
    if let Some(k) = &req.known_hosts {
        bind(k, &format!("{root}/run/known_hosts"), false)?;
    }
    for d in ["home", "tmp"] {
        let p = format!("{root}/{d}");
        std::fs::create_dir_all(&p).map_err(|e| format!("mkdir {p}: {e}"))?;
        rc(
            mount(
                "none",
                p.as_str(),
                "tmpfs",
                MountFlags::NOSUID | MountFlags::NODEV,
                c"mode=1777,size=64m",
            ),
            "mount a scratch tmpfs",
        )?;
    }
    std::fs::create_dir_all(format!("{root}/dest")).map_err(|e| e.to_string())?;
    rc(
        mount_bind(velarx_sys::fd::proc_str(&dest_here), "/tmp/dest"),
        "bind the destination",
    )?;
    drop(dest_here);
    if uid == 0 {
        rc(
            rustix::fs::fchown(
                &dest_given,
                Some(rustix::fs::Uid::from_raw(NOBODY)),
                Some(rustix::fs::Gid::from_raw(NOBODY)),
            ),
            "chown the destination",
        )?;
    }
    rc(rustix::process::chdir("/tmp"), "chdir")?;
    rc(rustix::process::pivot_root(".", "."), "pivot_root")?;
    rc(
        rustix::mount::unmount(".", UnmountFlags::DETACH),
        "detach the old root",
    )?;
    rc(rustix::process::chdir("/"), "chdir /")?;
    // Only the destination and the scratch directories are writable.
    rc(
        mount_remount(
            "/",
            MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
            "",
        ),
        "make the root read-only",
    )?;
    drop(dest_given);
    if uid == 0 {
        // Root no more: nobody, without capabilities.
        rc(
            velarx_sys::process::become_user_and_group(NOBODY, NOBODY),
            "become nobody",
        )?;
    }
    rc(rustix::process::chdir("/dest"), "chdir /dest")?;
    rc(
        rustix::process::setrlimit(
            rustix::process::Resource::Fsize,
            rustix::process::Rlimit {
                current: Some(req.max_bytes),
                maximum: Some(req.max_bytes),
            },
        ),
        "RLIMIT_FSIZE",
    )?;
    velarx_sys::signal::ignore(libc::SIGXFSZ);
    Ok(())
}

/// git with `args` in /dest, confined as set up.
fn command(req: &Request, args: &[&str]) -> std::process::Command {
    let mut cmd = std::process::Command::new("/usr/bin/git");
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "protocol.https.allow=always",
        "-c",
        "protocol.http.allow=always",
        "-c",
        "protocol.ssh.allow=always",
        "-c",
        "protocol.git.allow=always",
        "-c",
        "advice.detachedHead=false",
        "-c",
        "init.defaultBranch=main",
    ])
    .args(args)
    .current_dir("/dest")
    .env_clear()
    .env("PATH", "/usr/bin:/bin")
    .env("HOME", "/home")
    .env("LANG", "C")
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .env("GIT_TERMINAL_PROMPT", "0")
    .env("GIT_ALLOW_PROTOCOL", "https:http:ssh:git");
    let known = if req.known_hosts.is_some() {
        "/run/known_hosts"
    } else {
        "/dev/null"
    };
    cmd.env(
        "GIT_SSH_COMMAND",
        format!(
            "ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known}"
        ),
    );
    if req.ssh_auth_sock.is_some() {
        cmd.env("SSH_AUTH_SOCK", "/run/ssh-agent.sock");
    }
    cmd.stdin(std::process::Stdio::null());
    cmd
}

/// Run git with `args`; its output on error.
fn git(req: &Request, args: &[&str]) -> Result<(), String> {
    let out = command(req, args)
        .output()
        .map_err(|e| format!("run git: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
    text.truncate(4096);
    Err(format!(
        "git {} failed: {}",
        args.first().copied().unwrap_or(""),
        text.trim()
    ))
}

/// Refuse the fetched tree when its files are more, or larger together,
/// than the limits, before they are written: a small pack may hold a blob
/// that many paths name.
fn check_tree(req: &Request) -> Result<(), String> {
    use std::io::BufRead;
    let mut child = command(req, &["ls-tree", "-r", "-l", "-z", "FETCH_HEAD"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("run git: {e}"))?;
    let mut out = io::BufReader::new(child.stdout.take().ok_or("no output of git ls-tree")?);
    let (mut bytes, mut entries) = (0u64, 0u64);
    let mut record = Vec::new();
    let over = loop {
        record.clear();
        if out
            .read_until(0, &mut record)
            .map_err(|e| format!("git ls-tree: {e}"))?
            == 0
        {
            break false;
        }
        // MODE TYPE OBJECT SIZE\tPATH, the size `-` for a submodule
        let meta = record.split(|b| *b == b'\t').next().unwrap_or_default();
        let size = meta
            .split(|b| *b == b' ')
            .filter(|f| !f.is_empty())
            .nth(3)
            .and_then(|f| std::str::from_utf8(f).ok()?.parse::<u64>().ok())
            .unwrap_or(0);
        bytes = bytes.saturating_add(size);
        entries += 1;
        if bytes > req.max_bytes || entries > req.max_entries {
            break true;
        }
    };
    if over {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "the tree is larger than a copy may write ({} bytes, {} files)",
            req.max_bytes, req.max_entries
        ));
    }
    match child.wait() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("git ls-tree failed: {s}")),
        Err(e) => Err(format!("git ls-tree: {e}")),
    }
}

/// `velarx git-clone`.
pub fn main(startup: &velarx_sys::fd::Startup) -> anyhow::Result<()> {
    let result = (|| -> Result<(), String> {
        rc(
            rustix::stdio::dup2_stderr(rustix::stdio::stdout()),
            "redirect stderr",
        )?;
        startup.close_from((DEST_FD + 1) as u32);
        let mut body = Vec::new();
        io::stdin()
            .take(MAX_REQUEST)
            .read_to_end(&mut body)
            .map_err(|e| format!("read the request: {e}"))?;
        let req: Request =
            serde_json::from_slice(&body).map_err(|e| format!("invalid request: {e}"))?;
        // Checked again: the request comes from the daemon, the URL from a
        // Containerfile.
        let fragment = if req.source.subdir.is_empty() {
            req.source.reference.clone()
        } else {
            format!("{}:{}", req.source.reference, req.source.subdir)
        };
        let checked = check(&req.source.url, Some(&fragment))?;
        if checked != req.source {
            return Err("inconsistent request".into());
        }
        // (put in place by the daemon, and the helper's alone)
        let dest = startup
            .adopt(DEST_FD)
            .ok_or("the destination descriptor is not open")?;
        isolate(&req, dest)?;
        if req.self_test {
            let report = serde_json::to_string(&probes()).map_err(|e| e.to_string())?;
            return Err(format!("self-test {report}"));
        }
        git(&req, &["init", "-q", "."])?;
        git(&req, &["remote", "add", "origin", &req.source.url])?;
        git(
            &req,
            &[
                "fetch",
                "-q",
                "-u",
                "--depth=1",
                "--no-tags",
                "origin",
                "--",
                &req.source.reference,
            ],
        )?;
        check_tree(&req)?;
        git(&req, &["checkout", "-q", "FETCH_HEAD"])?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(msg) => {
            let mut out = io::stdout();
            let _ = out.write_all(msg.as_bytes());
            let _ = out.flush();
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_sources() {
        let g = |s: &str| parse(s).map(|r| r.map(|g| (g.url, g.reference, g.subdir)));
        assert_eq!(g("https://example.com/f.txt"), None);
        assert_eq!(g("https://example.com/r.tar.gz"), None);
        assert_eq!(
            g("https://h/o/r.git"),
            Some(Ok(("https://h/o/r.git".into(), "HEAD".into(), "".into())))
        );
        assert_eq!(
            g("https://h/o/r.git#v1.0:docs/sub"),
            Some(Ok((
                "https://h/o/r.git".into(),
                "v1.0".into(),
                "docs/sub".into()
            )))
        );
        assert_eq!(
            g("git@github.com:o/r.git#main"),
            Some(Ok((
                "git@github.com:o/r.git".into(),
                "main".into(),
                "".into()
            )))
        );
        assert_eq!(
            g("git://h/o/r#v1:d"),
            Some(Ok(("git://h/o/r".into(), "v1".into(), "d".into())))
        );
        assert!(matches!(g("git://"), Some(Err(_))));
        assert!(matches!(g("https://h/r.git#-x"), Some(Err(_))));
        assert!(matches!(g("https://h/r.git#v:../x"), Some(Err(_))));
        assert!(matches!(g("git@-oProxy=x:r"), Some(Err(_))));
        assert!(matches!(g("git@h:-r"), Some(Err(_))));
        assert!(matches!(g("git@h"), Some(Err(_))));
    }
}
