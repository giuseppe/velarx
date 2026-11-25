// SPDX-License-Identifier: Apache-2.0
//! SELinux labels of containers, as podman sets them.
//!
//! A container runs with the process context of the policy for containers
//! (`lxc_contexts`: `container_t` by default) and a level of two random
//! categories (`s0:c1,c2`) that no other container has; its files (the
//! overlay of the root file system, the tmpfs mounts, the files of its
//! bundle) get the file context (`container_file_t`) with the same level.
//! `--privileged` has no label, `--security-opt label=disable` neither;
//! `label=user:|role:|type:|filetype:|level:` replace a part.
//!
//! `:z` relabels a volume with the shared level `s0`, `:Z` with the level of
//! the container.  The source is resolved once to a descriptor (no symlink
//! followed after that) and the paths podman refuses (`NEVER_RELABELED`: exact
//! paths such as `/usr` and `/etc`, `$HOME`) and the directories of the engine
//! are refused.

use serde::{Deserialize, Serialize};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

const XATTR: &str = "security.selinux";
const MAX_DEPTH: usize = 256;

/// SELinux is enabled on the host.
pub fn enabled() -> bool {
    Path::new("/sys/fs/selinux/enforce").exists()
}

/// The SELinux settings of a container (what `label=` gave and the level).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelinuxConfig {
    #[serde(default)]
    pub disable: bool,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default, rename = "type")]
    pub typ: Option<String>,
    #[serde(default)]
    pub filetype: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    /// `label=files`: the files of a privileged container are labelled as
    /// those of the others, with a level of their own (`file_level`); its
    /// process is `spc_t` of the sensitivity `s0` unless `type` and `level`
    /// say otherwise
    #[serde(default)]
    pub files: bool,
    /// The level of those files, drawn for the container
    #[serde(default)]
    pub file_level: Option<String>,
}

/// A user, role or type: no separator.
pub fn valid_name(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
}

/// `s0`, `s0:c1,c2`, `s0-s15:c0.c1023`: a sensitivity (or a range of them)
/// and, after a colon, categories.  `s0,c1,c2` is none.
pub fn valid_level(v: &str) -> bool {
    velarx_mcs_core::strict(v.as_bytes())
}

impl SelinuxConfig {
    /// Check the parts given with `label=`.
    pub fn validate(&self) -> Result<(), String> {
        for (what, v) in [
            ("user", &self.user),
            ("role", &self.role),
            ("type", &self.typ),
            ("file type", &self.filetype),
        ] {
            if let Some(v) = v.as_deref().filter(|v| !valid_name(v)) {
                return Err(format!("invalid SELinux {what} `{v}`"));
            }
        }
        match self.level.as_deref() {
            Some(l) if !valid_level(l) => Err(format!("invalid SELinux level `{l}`")),
            _ => Ok(()),
        }
    }
}

const SELINUXFS: &str = "/sys/fs/selinux";

/// The SELinux label of the file or socket open as `fd`.
pub fn fd_label(fd: BorrowedFd<'_>) -> Option<String> {
    let mut buf = [0u8; 256];
    let n = rustix::fs::fgetxattr(fd, XATTR, &mut buf).ok()?;
    let label = std::str::from_utf8(&buf[..n]).ok()?.trim_end_matches('\0');
    (!label.is_empty()).then(|| label.to_string())
}

/// The object class of the socket open as `fd`, in the policy's names.
pub fn socket_class(fd: BorrowedFd<'_>) -> Option<&'static str> {
    use rustix::net::{getsockname, sockopt::socket_type, AddressFamily, SocketType};
    let family = getsockname(fd).ok()?.address_family();
    let kind = socket_type(fd).ok()?;
    match (family, kind) {
        (AddressFamily::UNIX, SocketType::STREAM) => Some("unix_stream_socket"),
        (AddressFamily::UNIX, SocketType::DGRAM) => Some("unix_dgram_socket"),
        (AddressFamily::INET | AddressFamily::INET6, SocketType::STREAM) => Some("tcp_socket"),
        (AddressFamily::INET | AddressFamily::INET6, SocketType::DGRAM) => Some("udp_socket"),
        _ => None,
    }
}

/// The object class of the file, pipe, terminal or socket open as `fd`, in
/// the policy's names.
pub fn fd_class(fd: BorrowedFd<'_>) -> Option<&'static str> {
    use rustix::fs::{fstat, FileType};
    match FileType::from_raw_mode(fstat(fd).ok()?.st_mode) {
        FileType::RegularFile => Some("file"),
        FileType::Directory => Some("dir"),
        FileType::Fifo => Some("fifo_file"),
        FileType::CharacterDevice => Some("chr_file"),
        FileType::BlockDevice => Some("blk_file"),
        FileType::Socket => socket_class(fd),
        _ => None,
    }
}

/// The permissions SELinux checks on a descriptor that a process keeps
/// across the exec into a new context: those of the way it is open (read,
/// write, or append for a descriptor open to append).
pub fn inherited_perms(fd: BorrowedFd<'_>) -> Vec<&'static str> {
    use rustix::fs::OFlags;
    let Ok(flags) = rustix::fs::fcntl_getfl(fd) else {
        return Vec::new();
    };
    let mut perms = Vec::new();
    let mode = flags & OFlags::RWMODE;
    if mode != OFlags::WRONLY {
        perms.push("read");
    }
    if mode != OFlags::RDONLY {
        perms.push(if flags.contains(OFlags::APPEND) {
            "append"
        } else {
            "write"
        });
    }
    perms
}

/// Whether a process of context `process` keeps the descriptor `fd` when it
/// starts (the kernel replaces those it may not use with /dev/null, without
/// a word in the audit log); `None` when that cannot be told.
pub fn keeps(process: &str, fd: BorrowedFd<'_>) -> Option<bool> {
    let label = fd_label(fd)?;
    let class = fd_class(fd)?;
    let perms = inherited_perms(fd);
    if perms.is_empty() {
        return None;
    }
    allowed(process, &label, class, &perms)
}

/// The permissions in `bits` (the first field the kernel answers to a
/// query of `access`, in hexadecimal) that `perms` (their numbers, from 1)
/// all are; all of them in a permissive domain (the flag 1 of the last
/// field).
fn permitted(answer: &str, perms: &[u32]) -> Option<bool> {
    let mut fields = answer.split_whitespace();
    let bits = u32::from_str_radix(fields.next()?, 16).ok()?;
    let permissive = fields
        .nth(4)
        .and_then(|f| u32::from_str_radix(f, 16).ok())
        .is_some_and(|f| f & 1 != 0);
    Some(
        permissive
            || perms
                .iter()
                .all(|p| *p >= 1 && *p <= 32 && bits & (1 << (p - 1)) != 0),
    )
}

/// Whether the kernel lets a process of context `process` do `perms` on an
/// object of class `class` labelled `object` (everything, in permissive
/// mode or a permissive domain); `None` when the kernel cannot tell (no
/// SELinux, a context it does not know).
pub fn allowed(process: &str, object: &str, class: &str, perms: &[&str]) -> Option<bool> {
    use std::io::{Read, Write};
    if !valid_name(class) || process.contains([' ', '\n']) || object.contains([' ', '\n']) {
        return None;
    }
    if std::fs::read_to_string(format!("{SELINUXFS}/enforce"))
        .ok()?
        .trim()
        == "0"
    {
        return Some(true);
    }
    let number = |what: String| -> Option<u32> {
        std::fs::read_to_string(format!("{SELINUXFS}/{what}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    let class_number = number(format!("class/{class}/index"))?;
    let perms = perms
        .iter()
        .map(|p| {
            valid_name(p)
                .then(|| number(format!("class/{class}/perms/{p}")))
                .flatten()
        })
        .collect::<Option<Vec<u32>>>()?;
    let mut access = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("{SELINUXFS}/access"))
        .ok()?;
    access
        .write_all(format!("{process} {object} {class_number}").as_bytes())
        .ok()?;
    let mut answer = [0u8; 256];
    let n = access.read(&mut answer).ok()?;
    permitted(std::str::from_utf8(&answer[..n]).ok()?, &perms)
}

/// The contexts of the policy for containers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contexts {
    pub user: String,
    pub role: String,
    pub typ: String,
    pub level: String,
    pub file_user: String,
    pub file_role: String,
    pub file_type: String,
    pub ro_file_type: String,
}

/// The value of `key` in a file of `key=value` or `key = "value"` lines.
fn config_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let rest = l.trim_start().strip_prefix(key)?.trim_start();
        let v = rest.strip_prefix('=')?;
        Some(v.trim().trim_matches('"').to_string())
    })
}

/// `user:role:type:level`
fn split_context(c: &str) -> Option<(String, String, String, String)> {
    let at = velarx_mcs_core::context_colons(c.as_bytes())?;
    let (u, r, t, l) = (
        &c[..at[0]],
        &c[at[0] + 1..at[1]],
        &c[at[1] + 1..at[2]],
        &c[at[2] + 1..],
    );
    (valid_name(u)
        && valid_name(r)
        && valid_name(t)
        && velarx_mcs_core::parse(l.as_bytes()).is_some())
    .then(|| (u.into(), r.into(), t.into(), l.into()))
}

impl Contexts {
    /// Read the contexts below `root` (`/` for the host); the defaults of
    /// the container policy when the files say nothing.
    pub fn load(root: &Path) -> Self {
        let read = |p: PathBuf| std::fs::read_to_string(p).unwrap_or_default();
        let policy = config_value(&read(root.join("etc/selinux/config")), "SELINUXTYPE")
            .filter(|p| valid_name(p));
        let lxc = policy
            .map(|p| read(root.join(format!("etc/selinux/{p}/contexts/lxc_contexts"))))
            .unwrap_or_default();
        let get = |k: &str| config_value(&lxc, k).and_then(|c| split_context(&c));
        let (user, role, typ, level) = get("process").unwrap_or_else(|| {
            (
                "system_u".into(),
                "system_r".into(),
                "container_t".into(),
                "s0".into(),
            )
        });
        let (file_user, file_role, file_type, _) = get("file").unwrap_or_else(|| {
            (
                "system_u".into(),
                "object_r".into(),
                "container_file_t".into(),
                "s0".into(),
            )
        });
        let ro_file_type = get("ro_file")
            .map(|c| c.2)
            .unwrap_or_else(|| "container_ro_file_t".into());
        Contexts {
            user,
            role,
            typ,
            level,
            file_user,
            file_role,
            file_type,
            ro_file_type,
        }
    }

    /// The contexts of the host, read once.
    pub fn host() -> &'static Contexts {
        static HOST: std::sync::OnceLock<Contexts> = std::sync::OnceLock::new();
        HOST.get_or_init(|| Contexts::load(Path::new("/")))
    }
}

/// The process and mount labels of a container (none when it is not
/// confined).
pub fn labels(
    s: &SelinuxConfig,
    privileged: bool,
    c: &Contexts,
) -> (Option<String>, Option<String>) {
    if s.disable {
        return (None, None);
    }
    let user = s.user.as_deref().unwrap_or(&c.user);
    let role = s.role.as_deref().unwrap_or(&c.role);
    let mount = |level: &str| {
        format!(
            "{}:{}:{}:{level}",
            s.user.as_deref().unwrap_or(&c.file_user),
            c.file_role,
            s.filetype.as_deref().unwrap_or(&c.file_type),
        )
    };
    if privileged {
        // not confined: the label of the caller, unless a type is given or
        // the files are labelled; then the type is `spc_t` by default
        let process = (s.typ.is_some() || s.files).then(|| {
            let typ = s.typ.as_deref().unwrap_or("spc_t");
            format!("{user}:{role}:{typ}:{}", s.level.as_deref().unwrap_or("s0"))
        });
        let files = s
            .level
            .as_deref()
            .or(s.file_level.as_deref())
            .unwrap_or(&c.level);
        return (process, s.files.then(|| mount(files)));
    }
    let level = s.level.as_deref().unwrap_or(&c.level);
    let process = format!(
        "{user}:{role}:{}:{level}",
        s.typ.as_deref().unwrap_or(&c.typ)
    );
    (Some(process), Some(mount(level)))
}

/// The label with the level `s0`, shared by every container (`:z`).
pub fn shared_label(label: &str) -> Option<String> {
    let at = velarx_mcs_core::context_colons(label.as_bytes())?;
    Some(format!("{}:s0", &label[..at[2]]))
}

/// Whether a container at `a` and one at `b` may reach each other's
/// files: one's categories include the other's (an empty set, `s0`, is
/// left out: no container of the allocator has one).  A level that is none
/// counts as reaching.
pub fn levels_overlap(a: &str, b: &str) -> bool {
    velarx_mcs_core::overlap(a.as_bytes(), b.as_bytes())
}

/// Whether the fresh level `fresh`, chosen by `allocate_level`, is no longer
/// free because of `used`, the level of a container recorded since: `used`
/// has categories and is equal to `fresh` or inside it.  This is the rule
/// that holds for the result of both passes of the allocator: the first
/// avoids every level that reaches another, the second (when a wide level in
/// use, `s0:c0.c1023`, makes every pair reach it) only an equal or a
/// containing one.  A `fresh` pair inside a wide level in use is accepted,
/// as the allocator accepts it.  Two creations that chose at the same time
/// collide only when their pairs are equal, which this sees.  A level in
/// use that does not parse is ignored, as the second pass does.
pub fn level_taken(fresh: &str, used: &str) -> bool {
    velarx_mcs_core::contains(fresh.as_bytes(), used.as_bytes())
}

/// `level` is of the form the allocator gives, `s0:cA,cB` with A < B.
pub fn is_allocated_form(level: &str) -> bool {
    velarx_mcs_core::read_pair(level.as_bytes()).is_some()
}

/// How many pairs of categories are tried for a level before giving up.
const ATTEMPTS: usize = 1000;

/// A level of two random categories that reaches none of `used`; when every
/// pair does because a level in use is wide on purpose (`s0:c0.c1023`), one
/// that is not equal to or a superset of a level in use.
pub fn allocate_level(used: &[String]) -> Result<String, String> {
    let mut bytes = [0u8; 8 * ATTEMPTS];
    let mut filled = 0;
    while filled < bytes.len() {
        match rustix::rand::getrandom(&mut bytes[filled..], rustix::rand::GetRandomFlags::empty()) {
            Ok(n) => filled += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(format!("getrandom: {e}")),
        }
    }
    let mut rand = [0u32; 2 * ATTEMPTS];
    for (r, b) in rand.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *r = u32::from_ne_bytes(*b);
    }
    let used: Vec<Vec<u8>> = used.iter().map(|u| u.as_bytes().to_vec()).collect();
    match velarx_mcs_core::pick(&rand, &used) {
        Some(label) => Ok(String::from_utf8_lossy(label.as_bytes()).into_owned()),
        None => Err("no free SELinux level".into()),
    }
}

fn at_or_below(path: &str, dir: &str) -> bool {
    let dir = dir.trim_end_matches('/');
    if dir.is_empty() {
        return true;
    }
    path == dir || path.strip_prefix(dir).is_some_and(|r| r.starts_with('/'))
}

/// The paths podman never relabels (go-selinux `chcon`): these exact paths
/// only, a directory below one of them is relabeled.
const NEVER_RELABELED: [&str; 24] = [
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/etc/passwd",
    "/etc/pki",
    "/etc/shadow",
    "/home",
    "/lib",
    "/lib64",
    "/media",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/var",
    "/var/lib",
    "/var/log",
];

/// `path` with its `.`, `..` and repeated or final `/` taken out, as a
/// string, with no link resolved (the path podman checks: the one the user
/// gave, cleaned).
fn clean_path(path: &Path) -> String {
    use std::path::Component;
    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for c in path.components() {
        match c {
            Component::Normal(n) => parts.push(n),
            Component::ParentDir => {
                parts.pop();
            }
            _ => {}
        }
    }
    let mut out = String::new();
    for p in parts {
        out.push('/');
        out.push_str(&p.to_string_lossy());
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// A path that is never relabeled: podman's (`NEVER_RELABELED`, `$HOME` and
/// the home directory of `$SUDO_USER`, each as exactly that path) and the
/// directories of the engine with everything below them.
pub fn path_forbidden(path: &str, engine_dirs: &[PathBuf]) -> bool {
    let clean = clean_path(Path::new(path));
    if NEVER_RELABELED.contains(&clean.as_str()) || is_home_directory(&clean) {
        return true;
    }
    for d in engine_dirs {
        let real = std::fs::canonicalize(d).unwrap_or_else(|_| d.clone());
        for d in [d, &real] {
            if d.to_str().is_some_and(|d| at_or_below(&clean, d)) {
                return true;
            }
        }
    }
    false
}

/// `$HOME` and the home directory of `$SUDO_USER`.
fn is_home_directory(path: &str) -> bool {
    let sudo_home = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty())
        .and_then(|user| {
            std::fs::read_to_string("/etc/passwd")
                .ok()?
                .lines()
                .map(|l| l.split(':').collect::<Vec<_>>())
                .find(|f| f.len() > 5 && f[0] == user)
                .map(|f| f[5].to_string())
        });
    std::env::var("HOME")
        .ok()
        .into_iter()
        .chain(sudo_home)
        .any(|h| is_home(path, &h))
}

/// Whether `path` (clean, see `clean_path`) is the home directory `home`,
/// spelled with a final `/` or reached through a link too (as the path a
/// link leads to is checked, see `relabel_path`).  A relative or empty
/// `home` is none.
fn is_home(path: &str, home: &str) -> bool {
    home.starts_with('/')
        && (clean_path(Path::new(home)) == path
            || std::fs::canonicalize(home).is_ok_and(|r| r.to_str() == Some(path)))
}

/// podman's refusal of a path.
fn not_allowed(path: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("SELinux relabeling of {path} is not allowed"),
    )
}

fn io_err(what: &str, e: rustix::io::Errno) -> std::io::Error {
    std::io::Error::new(
        std::io::Error::from_raw_os_error(e.raw_os_error()).kind(),
        format!("{what}: {e}"),
    )
}

/// The file system has no SELinux labels (`context=` mounts, some FUSE).
fn unsupported(e: rustix::io::Errno) -> bool {
    use rustix::io::Errno;
    e == Errno::NOTSUP || e == Errno::OPNOTSUPP || e == Errno::NODATA
}

fn set_label_at(
    dir: BorrowedFd<'_>,
    name: &std::ffi::OsStr,
    label: &[u8],
) -> rustix::io::Result<()> {
    // The directory is held by its descriptor: the entry is one component
    // of it and its last component is not followed.
    let path = velarx_sys::fd::proc_path(&dir).join(name);
    rustix::fs::lsetxattr(&path, XATTR, label, rustix::fs::XattrFlags::empty())
}

/// The mount the file open as `fd` is on, and its device.
fn mount_of(fd: BorrowedFd<'_>) -> std::io::Result<(u64, u64)> {
    use rustix::fs::{statx, AtFlags, StatxFlags};
    let x =
        statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).map_err(|e| io_err("stat", e))?;
    if x.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
        return Err(std::io::Error::other(
            "the kernel does not say the mount of a file",
        ));
    }
    Ok((
        x.stx_mnt_id,
        rustix::fs::makedev(x.stx_dev_major, x.stx_dev_minor),
    ))
}

/// The walk of what is below a volume: a mount is the state of a directory
/// (`None`: a directory that is not left on the mount it was found on, never
/// relabeled).
struct Relabel<'a> {
    label: &'a [u8],
    engine_dirs: &'a [PathBuf],
}

impl velarx_base::walk::Visit for Relabel<'_> {
    type Dir = Option<(u64, u64)>;

    /// (what was opened is on the mount the name was on)
    fn enter(
        &mut self,
        dir: BorrowedFd<'_>,
        _: &[std::ffi::OsString],
        state: &mut Self::Dir,
    ) -> std::io::Result<()> {
        if let Some(mnt) = *state {
            if mount_of(dir)? != mnt {
                *state = None;
            }
        }
        Ok(())
    }

    fn entry(
        &mut self,
        dir: BorrowedFd<'_>,
        name: &std::ffi::OsStr,
        _: &rustix::fs::Stat,
        _: usize,
        parent: &mut Self::Dir,
    ) -> std::io::Result<Option<Self::Dir>> {
        use rustix::fs::{statx, AtFlags, FileType, StatxFlags};
        use rustix::io::Errno;
        let Some(mnt) = *parent else {
            return Ok(None);
        };
        let x = match statx(
            dir,
            name,
            AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT,
            StatxFlags::TYPE | StatxFlags::MNT_ID,
        ) {
            Ok(x) => x,
            Err(Errno::NOENT) => return Ok(None),
            Err(e) => return Err(io_err("stat", e)),
        };
        let is_dir = FileType::from_raw_mode(x.stx_mode.into()) == FileType::Directory;
        // what is mounted below the volume is part of what the container sees
        // (a recursive bind mount): a whole file system is relabeled too
        // (`mount_relabeled`), a bind mount of a directory or a file is not
        let here = (
            x.stx_mnt_id,
            rustix::fs::makedev(x.stx_dev_major, x.stx_dev_minor),
        );
        if x.stx_mask & StatxFlags::MNT_ID.bits() == 0 || here != mnt {
            if is_dir {
                return relabel_mount(dir, name, self.label, self.engine_dirs);
            }
            return Ok(None);
        }
        match set_label_at(dir, name, self.label) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(e) if unsupported(e) => return Ok(None),
            Err(e) => return Err(io_err(&format!("set the SELinux label of {name:?}"), e)),
        }
        Ok(is_dir.then_some(Some(mnt)))
    }
}

/// Relabel what is below the directory `dir`, on the mount `mnt` (see
/// `mount_of`).  A mount below it is found by its mount, not its device (a
/// bind mount of a directory of the same file system has the same): it is
/// relabeled only when `mount_relabeled` says so.
fn relabel_children(
    dir: OwnedFd,
    label: &[u8],
    mnt: (u64, u64),
    engine_dirs: &[PathBuf],
) -> std::io::Result<()> {
    velarx_base::walk::Walk {
        max_depth: MAX_DEPTH,
        sorted: false,
        skip_gone: true,
        lenient: false,
    }
    .run(dir, Some(mnt), &mut Relabel { label, engine_dirs })
    .map(|_| ())
}

/// The file systems of the kernel that show its state or its settings: a
/// mount of one of them below a volume is not relabeled.
const STATE_FS: [&str; 19] = [
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "selinuxfs",
    "devpts",
    "devtmpfs",
    "securityfs",
    "debugfs",
    "tracefs",
    "bpf",
    "pstore",
    "efivarfs",
    "configfs",
    "fusectl",
    "binfmt_misc",
    "nsfs",
    "mqueue",
    "autofs",
];

/// Whether the mount `id` of the mount table `table`, found below a volume,
/// is relabeled with it.  Only a whole file system is (a tmpfs, a disk, a
/// network share: its root is the root of the file system): a bind mount of
/// a directory may show any directory of the host (`/etc` bound below the
/// volume is still `/etc`), so it is left alone, as are the file systems of
/// the kernel's state and a file system that is also mounted on a directory
/// that is never relabeled (`/` or `/home` mounted again below the volume).
fn mount_relabeled(table: &str, id: u64, engine_dirs: &[PathBuf]) -> bool {
    let mounts = velarx_base::mountinfo::parse(table);
    let Some(m) = mounts.iter().find(|m| u64::from(m.id) == id) else {
        return false;
    };
    if m.root != Path::new("/") || STATE_FS.contains(&m.fs_type.as_str()) {
        return false;
    }
    !mounts.iter().any(|o| {
        o.device == m.device
            && o.point
                .to_str()
                .is_none_or(|p| path_forbidden(p, engine_dirs))
    })
}

/// The directory `name` of `dir`, the root of a mount below the volume: when
/// the mount is one that is relabeled (`mount_relabeled`), its root is
/// labeled and the mount is what its entries are walked on.  The mount is the
/// one the descriptor is on, not what the name was.
fn relabel_mount(
    dir: BorrowedFd<'_>,
    name: &std::ffi::OsStr,
    label: &[u8],
    engine_dirs: &[PathBuf],
) -> std::io::Result<Option<Option<(u64, u64)>>> {
    use rustix::fs::{openat, Mode, OFlags};
    use rustix::io::Errno;
    let sub = match openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        // (gone, or a FUSE mount of another user)
        Err(Errno::NOENT | Errno::ACCESS | Errno::PERM) => return Ok(None),
        Err(e) => return Err(io_err("open", e)),
    };
    let Ok(mnt) = mount_of(sub.as_fd()) else {
        return Ok(None);
    };
    let table = std::fs::read_to_string("/proc/self/mountinfo")?;
    if !mount_relabeled(&table, mnt.0, engine_dirs) {
        return Ok(None);
    }
    let target = std::fs::read_link(velarx_sys::fd::proc_path(&sub))?;
    if !target
        .to_str()
        .is_some_and(|t| t.starts_with('/') && !path_forbidden(t, engine_dirs))
    {
        return Ok(None);
    }
    match rustix::fs::fsetxattr(&sub, XATTR, label, rustix::fs::XattrFlags::empty()) {
        Ok(()) => {}
        // (a read-only mount, or one the policy does not let relabel: as
        // it was)
        Err(e) if unsupported(e) || e == Errno::ROFS || e == Errno::ACCESS || e == Errno::PERM => {
            return Ok(None)
        }
        Err(e) => return Err(io_err(&format!("set the SELinux label of {name:?}"), e)),
    }
    Ok(Some(Some(mnt)))
}

/// Set `label` on the file open as `fd` (`O_PATH`) and, for a directory,
/// on what is below it, mounts below it included.
fn relabel_fd(fd: &OwnedFd, label: &str, engine_dirs: &[PathBuf]) -> std::io::Result<()> {
    use rustix::fs::{fsetxattr, fstat, openat, FileType, Mode, OFlags, XattrFlags};
    if label.is_empty() || label.contains(['\n', '\0']) {
        return Err(std::io::Error::other("invalid SELinux label"));
    }
    let bytes = label.as_bytes();
    let st = fstat(fd).map_err(|e| io_err("stat", e))?;
    match FileType::from_raw_mode(st.st_mode) {
        FileType::Directory => {
            let dir = openat(
                fd,
                ".",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| io_err("open", e))?;
            match fsetxattr(&dir, XATTR, bytes, XattrFlags::empty()) {
                Ok(()) => {}
                Err(e) if unsupported(e) => return Ok(()),
                Err(e) => return Err(io_err("set the SELinux label", e)),
            }
            let mnt = mount_of(dir.as_fd())?;
            relabel_children(dir, bytes, mnt, engine_dirs)
        }
        FileType::Symlink => Err(std::io::Error::other("a symlink is not relabeled")),
        _ => {
            // the magic link of the descriptor reaches the file itself
            let proc = velarx_sys::fd::proc_str(&fd);
            match rustix::fs::setxattr(proc.as_str(), XATTR, bytes, XattrFlags::empty()) {
                Ok(()) => Ok(()),
                Err(e) if unsupported(e) => Ok(()),
                Err(e) => Err(io_err("set the SELinux label", e)),
            }
        }
    }
}

/// Relabel the root of a container's writable layer, the directory open as
/// `fd` (the descriptor the storage driver gives), and what is below it, mounts
/// below it included.  No path of the host is resolved: the label is set
/// through the descriptor, and a link below it is labeled itself.  The
/// directory is the driver's own (not a source the user names), so no
/// directory is forbidden.
pub fn relabel_root(fd: &OwnedFd, label: &str) -> std::io::Result<()> {
    relabel_fd(fd, label, &[])
}

/// Relabel `path` (a volume or a bind mount source) and what is below it.
/// The path is resolved once; a forbidden directory is refused (pass the
/// directories of the engine as `engine_dirs` for the sources the user
/// names).
pub fn relabel_path(path: &Path, label: &str, engine_dirs: &[PathBuf]) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    // the path as given, as podman checks it (a link is not resolved)
    let given = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let given = clean_path(&given);
    if path_forbidden(&given, engine_dirs) {
        return Err(not_allowed(&given));
    }
    // what is relabeled is what the mount reaches, so the same rule
    // applies to it: a link to `/usr` is refused
    let real = std::fs::canonicalize(path)?;
    let fd = rustix::fs::openat2(
        rustix::fs::CWD,
        &real,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| io_err(&format!("open {}", real.display()), e))?;
    // what the descriptor is, not what the path was
    let target = std::fs::read_link(velarx_sys::fd::proc_path(&fd))?;
    let t = target.to_string_lossy();
    if !t.starts_with('/') || path_forbidden(&t, engine_dirs) {
        return Err(not_allowed(&t));
    }
    relabel_fd(&fd, label, engine_dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Contexts {
        Contexts::load(Path::new("/nonexistent"))
    }

    #[test]
    fn kernel_answers_are_read() {
        // read (1) and write (3): 0b101
        assert_eq!(permitted("5 5 0 ffffffff 12 0", &[1, 3]), Some(true));
        assert_eq!(permitted("1 1 0 ffffffff 12 0", &[1, 3]), Some(false));
        assert_eq!(permitted("0", &[1]), Some(false));
        assert_eq!(permitted("zz", &[1]), None);
        assert_eq!(permitted("", &[1]), None);
        assert_eq!(permitted("ffffffff", &[0]), Some(false));
        assert_eq!(permitted("80000000", &[32]), Some(true));
        // a permissive domain
        assert_eq!(permitted("1 1 0 ffffffff 12 1", &[1, 3]), Some(true));
    }

    #[test]
    fn a_context_with_a_space_is_not_asked_about() {
        assert_eq!(allowed("a b", "c", "file", &["read"]), None);
        assert_eq!(allowed("a", "c\nd", "file", &["read"]), None);
        assert_eq!(allowed("a", "c", "../x", &["read"]), None);
    }

    #[test]
    fn a_socket_has_its_class() {
        use std::os::fd::AsFd;
        use std::os::unix::net::{UnixDatagram, UnixListener};
        let dir = tempfile::tempdir().unwrap();
        let l = UnixListener::bind(dir.path().join("s")).unwrap();
        assert_eq!(socket_class(l.as_fd()), Some("unix_stream_socket"));
        let d = UnixDatagram::bind(dir.path().join("d")).unwrap();
        assert_eq!(socket_class(d.as_fd()), Some("unix_dgram_socket"));
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(socket_class(t.as_fd()), Some("tcp_socket"));
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(socket_class(u.as_fd()), Some("udp_socket"));
        let f = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(socket_class(f.as_fd()), None);
    }

    #[test]
    fn a_descriptor_has_its_class() {
        use std::os::fd::AsFd;
        let f = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(fd_class(f.as_fd()), Some("chr_file"));
        let dir = tempfile::tempdir().unwrap();
        let r = std::fs::File::create(dir.path().join("f")).unwrap();
        assert_eq!(fd_class(r.as_fd()), Some("file"));
        let d = std::fs::File::open(dir.path()).unwrap();
        assert_eq!(fd_class(d.as_fd()), Some("dir"));
        let (rd, _wr) = rustix::pipe::pipe().unwrap();
        assert_eq!(fd_class(rd.as_fd()), Some("fifo_file"));
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(fd_class(a.as_fd()), Some("unix_stream_socket"));
    }

    #[test]
    fn a_descriptor_is_checked_for_how_it_is_open() {
        use std::os::fd::AsFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        let w = std::fs::File::create(&path).unwrap();
        assert_eq!(inherited_perms(w.as_fd()), ["write"]);
        let a = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        assert_eq!(inherited_perms(a.as_fd()), ["append"]);
        let r = std::fs::File::open(&path).unwrap();
        assert_eq!(inherited_perms(r.as_fd()), ["read"]);
        let rw = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(inherited_perms(rw.as_fd()), ["read", "write"]);
    }

    #[test]
    fn names_and_levels() {
        assert!(valid_name("container_t") && valid_name("a.b-c"));
        assert!(!valid_name("") && !valid_name("a:b") && !valid_name("a b"));
        for l in ["s0", "s0:c1,c2", "s0-s15:c0.c1023"] {
            assert!(valid_level(l), "{l}");
        }
        for l in [
            "", "s", "c1", "s0;x", "s0 c1", "s0,c4,c5", "s0:", "s0:c1,", "s0:c1024", "s0:x1",
            "s0:c1;c2", "s0-:c1",
        ] {
            assert!(!valid_level(l), "{l}");
        }
        let s = SelinuxConfig {
            typ: Some("x:y".into()),
            ..Default::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn contexts_from_the_policy() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("etc/selinux/targeted/contexts")).unwrap();
        std::fs::write(
            d.path().join("etc/selinux/config"),
            "SELINUX=enforcing\nSELINUXTYPE=targeted\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("etc/selinux/targeted/contexts/lxc_contexts"),
            "process = \"system_u:system_r:my_t:s0\"\nfile = \"system_u:object_r:my_file_t:s0\"\n\
             ro_file = \"system_u:object_r:my_ro_t:s0\"\n",
        )
        .unwrap();
        let c = Contexts::load(d.path());
        assert_eq!(
            (
                c.typ.as_str(),
                c.file_type.as_str(),
                c.ro_file_type.as_str()
            ),
            ("my_t", "my_file_t", "my_ro_t")
        );
        let c = host();
        assert_eq!(
            (c.typ.as_str(), c.file_type.as_str()),
            ("container_t", "container_file_t")
        );
    }

    #[test]
    fn label_pairs() {
        let c = host();
        let s = SelinuxConfig {
            level: Some("s0:c1,c2".into()),
            ..Default::default()
        };
        let (p, m) = labels(&s, false, &c);
        assert_eq!(p.as_deref(), Some("system_u:system_r:container_t:s0:c1,c2"));
        assert_eq!(
            m.as_deref(),
            Some("system_u:object_r:container_file_t:s0:c1,c2")
        );
        assert_eq!(
            shared_label(&m.unwrap()).as_deref(),
            Some("system_u:object_r:container_file_t:s0")
        );
        assert_eq!(labels(&s, true, &c), (None, None));
        let s = SelinuxConfig {
            typ: Some("spc_t".into()),
            ..Default::default()
        };
        assert_eq!(
            labels(&s, true, &c).0.as_deref(),
            Some("system_u:system_r:spc_t:s0")
        );
        // a privileged container: no label of its own, `label=files` labels
        // the files with a level of their own and the process `spc_t` of `s0`
        let plain = SelinuxConfig::default();
        assert_eq!(labels(&plain, true, &c), (None, None));
        let files = SelinuxConfig {
            files: true,
            file_level: Some("s0:c3,c4".into()),
            ..Default::default()
        };
        assert_eq!(
            labels(&files, true, &c),
            (
                Some("system_u:system_r:spc_t:s0".into()),
                Some("system_u:object_r:container_file_t:s0:c3,c4".into())
            )
        );
        let own = SelinuxConfig {
            typ: Some("my_t".into()),
            level: Some("s0:c1,c2".into()),
            ..files.clone()
        };
        assert_eq!(
            labels(&own, true, &c),
            (
                Some("system_u:system_r:my_t:s0:c1,c2".into()),
                Some("system_u:object_r:container_file_t:s0:c1,c2".into())
            )
        );
        let s = SelinuxConfig {
            disable: true,
            files: true,
            ..Default::default()
        };
        assert_eq!(labels(&s, true, &c), (None, None));
        let s = SelinuxConfig {
            disable: true,
            ..Default::default()
        };
        assert_eq!(labels(&s, false, &c), (None, None));
        let s = SelinuxConfig {
            filetype: Some("x_t".into()),
            level: Some("s0".into()),
            ..Default::default()
        };
        assert_eq!(
            labels(&s, false, &c).1.as_deref(),
            Some("system_u:object_r:x_t:s0")
        );
    }

    #[test]
    fn levels_are_unique() {
        let mut used = Vec::new();
        for _ in 0..200 {
            let l = allocate_level(&used).unwrap();
            assert!(valid_level(&l));
            assert!(!used.contains(&l));
            used.push(l);
        }
    }

    /// What podman 5.8 does with `-v PATH:/x:Z` (the observed result: its
    /// error is "SELinux relabeling of PATH is not allowed" for a refused
    /// path), each path alone: the exact paths of its list are refused, a
    /// directory below one is not, a link is not resolved, a path is cleaned.
    #[test]
    fn forbidden_paths_are_podmans() {
        let refused = [
            "/",
            "/bin",
            "/boot",
            "/dev",
            "/etc",
            "/etc/passwd",
            "/etc/pki",
            "/etc/shadow",
            "/home",
            "/lib",
            "/lib64",
            "/media",
            "/opt",
            "/proc",
            "/root",
            "/run",
            "/sbin",
            "/srv",
            "/sys",
            "/tmp",
            "/usr",
            "/var",
            "/var/lib",
            "/var/log",
            "/usr/",
            "/tmp/",
            "//usr//share/..",
            "/dev/shm/../../usr",
            // (podman cleans the source too: `filepath.Abs`)
            "//usr",
            "/usr/.",
            "/usr//",
        ];
        let allowed = [
            "/usr/share",
            "/usr/lib",
            "/usr/local/data",
            "/dev/shm",
            "/dev/shm/c1240/x",
            "/dev/shm/c1240/x/",
            "/dev/shm/c1240/../c1240/x",
            "/tmp/c1240x",
            "/etc/alternatives",
            "/etc/foo",
            "/var/lib/dnf",
            "/var/lib/foo",
            "/var/tmp",
            "/var/tmp/x",
            "/var/run",
            "/mnt",
            "/lib32",
            "/proc/1",
            "/sys/fs",
            "/srv/data",
            "/home/u/data",
        ];
        for p in refused {
            assert!(path_forbidden(p, &[]), "{p}");
        }
        for p in allowed {
            assert!(!path_forbidden(p, &[]), "{p}");
        }
        // $HOME exactly, not what is below it
        if let Ok(h) = std::env::var("HOME") {
            if h.starts_with('/') && h != "/" {
                assert!(path_forbidden(&h, &[]), "{h}");
                assert!(path_forbidden(&format!("{h}/"), &[]), "{h}/");
                assert!(!path_forbidden(&format!("{h}/sub"), &[]), "{h}/sub");
            }
        }
        // the directories of the engine, with everything below them
        assert!(path_forbidden(
            "/data/engine/vol",
            &[PathBuf::from("/data/engine")]
        ));
        assert!(!path_forbidden(
            "/data/engines",
            &[PathBuf::from("/data/engine")]
        ));
    }

    /// The wording is podman's, for the path as given and for what a link
    /// reaches.  (The label is not a valid one: if the check were gone, a
    /// test run as root would fail before it changed a label of the host.)
    #[test]
    fn relabel_refusal_wording() {
        let e = relabel_path(Path::new("/usr/"), "bad\nlabel", &[]).unwrap_err();
        assert_eq!(e.to_string(), "SELinux relabeling of /usr is not allowed");
        let e = relabel_path(Path::new("//usr/."), "bad\nlabel", &[]).unwrap_err();
        assert_eq!(e.to_string(), "SELinux relabeling of /usr is not allowed");
        let d = tempfile::tempdir().unwrap();
        let link = d.path().join("l");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        let e = relabel_path(&link, "bad\nlabel", &[]).unwrap_err();
        assert_eq!(e.to_string(), "SELinux relabeling of /etc is not allowed");
        // a link to a directory below one of them is relabeled: it gets
        // as far as the label
        std::fs::create_dir(d.path().join("sub")).unwrap();
        let ok = d.path().join("ok");
        std::os::unix::fs::symlink(d.path().join("sub"), &ok).unwrap();
        let e = relabel_path(&ok, "bad\nlabel", &[]).unwrap_err();
        assert_eq!(e.to_string(), "invalid SELinux label");
    }

    #[test]
    fn relabel_refuses_links_and_forbidden() {
        let d = tempfile::tempdir().unwrap();
        let link = d.path().join("l");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        // the link is resolved first: /etc is refused
        let e = relabel_path(&link, "bad\nlabel", &[]).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
        assert!(relabel_path(d.path(), "bad\nlabel", &[]).is_err());
        assert!(relabel_path(d.path(), "x", &[d.path().to_path_buf()]).is_err());
    }

    /// A home directory is refused as itself, spelled with a final `/` and
    /// where a link to it leads; what is below it is not.
    #[test]
    fn home_directories() {
        let d = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(d.path()).unwrap();
        let home = real.join("home");
        std::fs::create_dir(&home).unwrap();
        let link = real.join("link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        let h = home.to_str().unwrap();
        let l = link.to_str().unwrap();
        assert!(is_home(h, h));
        assert!(is_home(h, &format!("{h}/")));
        assert!(is_home(h, l), "{l} leads to {h}");
        assert!(!is_home(&format!("{h}/sub"), h));
        assert!(!is_home(h, "home"));
        assert!(!is_home("/", ""));
    }

    /// A mount table as the kernel writes it: `/` and `/home` of one disk,
    /// the tmpfs of `/tmp` and `/dev/shm`, and below the volume
    /// `/srv/vol`: a tmpfs of its own, `/etc` and `/home/u` bound, the whole
    /// disk mounted again, the tmpfs of `/tmp` bound, `/proc`, a network
    /// share, a disk the engine has, the `/dev/shm` tmpfs bound, a
    /// directory of the disk of `/srv/data` bound.
    const TABLE: &str = "\
22 1 253:0 / / rw,relatime shared:1 - xfs /dev/mapper/root rw
23 22 253:0 /home /home rw,relatime shared:2 - xfs /dev/mapper/root rw
24 22 0:30 / /tmp rw,nosuid shared:3 - tmpfs tmpfs rw
25 22 0:5 / /dev rw,nosuid shared:4 - devtmpfs devtmpfs rw
26 25 0:31 / /dev/shm rw,nosuid shared:5 - tmpfs tmpfs rw
27 22 8:16 / /var/lib/velarx rw shared:6 - ext4 /dev/sdb rw
28 22 8:32 / /srv/data rw shared:8 - ext4 /dev/sdc rw
40 22 0:50 / /srv/vol/tmpfs rw shared:7 - tmpfs none rw
41 22 253:0 /etc /srv/vol/etc rw shared:1 - xfs /dev/mapper/root rw
42 22 253:0 /home/u /srv/vol/home rw shared:2 - xfs /dev/mapper/root rw
43 22 253:0 / /srv/vol/root rw shared:1 - xfs /dev/mapper/root rw
44 22 0:30 / /srv/vol/tmp rw shared:3 - tmpfs tmpfs rw
45 22 0:22 / /srv/vol/proc rw - proc proc rw
46 22 0:60 / /srv/vol/nfs rw - nfs4 srv:/export rw
47 22 8:16 / /srv/vol/engine rw - ext4 /dev/sdb rw
48 22 0:31 / /srv/vol/shm rw - tmpfs tmpfs rw
49 22 0:61 / /srv/vol/with\\040space rw - tmpfs none rw
50 22 8:32 /alice /srv/vol/alice rw shared:8 - ext4 /dev/sdc rw
";

    #[test]
    fn mounts_below_a_volume_that_are_relabeled() {
        let engine = [PathBuf::from("/var/lib/velarx")];
        // whole file systems of their own
        // (`/dev/shm` is not a path podman refuses: its tmpfs is one too)
        for id in [40, 46, 48, 49] {
            assert!(mount_relabeled(TABLE, id, &engine), "{id}");
        }
        // bind mounts of directories, the disk of `/` again, the tmpfs of
        // `/tmp`, the kernel's state, the engine's disk, a mount that is not
        // in the table
        for id in [41, 42, 43, 44, 45, 47, 50, 99] {
            assert!(!mount_relabeled(TABLE, id, &engine), "{id}");
        }
        // the engine's disk is relabeled when its directory is not forbidden
        // (a named volume)
        assert!(mount_relabeled(TABLE, 47, &[]));
    }

    /// Relabel a directory with the label it has (a change of label needs
    /// the policy's permission): a walk that followed a link, or went into a
    /// mount that is not relabeled, would reach a file of root (`/etc`) and
    /// fail.
    #[test]
    fn relabel_does_not_follow_links() {
        if !enabled() {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let Some(label) = std::fs::File::open(d.path())
            .ok()
            .and_then(|f| fd_label(f.as_fd()))
        else {
            return;
        };
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/f"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc", d.path().join("etc")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("sub/passwd")).unwrap();
        std::os::unix::fs::symlink("/proc/self/root/etc", d.path().join("root")).unwrap();
        if rustix::process::geteuid().is_root() {
            return; // (root could relabel /etc: only the other user's walk proves it)
        }
        relabel_path(d.path(), &label, &[]).unwrap();
        let f = std::fs::File::open(d.path().join("sub/f")).unwrap();
        assert_eq!(fd_label(f.as_fd()).as_deref(), Some(label.as_str()));
    }

    /// What a level given by a user or by the CRI may be, edge by edge.
    #[test]
    fn levels_that_are_taken_and_refused() {
        for l in [
            "s0",
            "s15",
            "s0-s15",
            "s0:c0",
            "s0:c1023",
            "s0:c1,c1",
            "s0:c3.c3",
            "s0:c0.c1023",
            "s0:c1,c5.c9,c2",
            "s0-s0:c1,c2",
            "s99999999999999999999:c1",
            "s10:c10.c100",
        ] {
            assert!(valid_level(l), "{l}");
        }
        for l in [
            "",
            ":",
            ":c1",
            "s",
            "s0:",
            "s0::c1",
            "s0:c1:c2",
            "S0",
            "s0:C1",
            "s0:c",
            "s0:c1.",
            "s0:.c1",
            "s0:c1..c2",
            "s0:c1.c2.c3",
            "s0:c5.c3",
            "s0:c1023.c1024",
            "s0:c1024",
            "s0:c99999999999",
            "s0:c+1",
            "s0:c-1",
            "s0:c 1",
            "s0: c1",
            "s0:c1 ",
            "s0:c1\n",
            "s0:c1,,c2",
            "s0:,c1",
            "s0,c1",
            "s0:c1\"",
            "s0:c1,c2\",context=x",
            "s0-",
            "-s0",
            "s0--s1",
            "s0-s1:",
            "s0\0",
            "s0:c١",
            "s٠",
            "s0:c1;c2",
            "s0-s1-s2",
            "s00",
            "s0:c01",
            "s0:c1.c01",
            "s0:c0000000000000000000001",
        ] {
            assert!(!valid_level(l), "{l:?}");
        }
        // what reaches `context=` of a mount is validated first
        let s = SelinuxConfig {
            level: Some("s0:c1,c2\",context=x".into()),
            ..Default::default()
        };
        assert!(s.validate().is_err());
    }

    /// Two levels reach each other's files when the categories of one are
    /// all in the other; a level that is not one counts as reaching.
    #[test]
    fn levels_that_overlap() {
        assert!(levels_overlap("s0:c1,c2", "s0:c1,c2"));
        assert!(levels_overlap("s0:c1,c2", "s0:c2,c1"));
        assert!(levels_overlap("s0:c1,c2", "s0:c1.c2"));
        assert!(levels_overlap("s0:c1,c2", "s0:c1,c2,c3"));
        assert!(levels_overlap("s0:c1,c2,c3", "s0:c1,c2"));
        assert!(levels_overlap("s0:c7", "s0:c0.c1023"));
        assert!(levels_overlap("s0:c1,c1", "s0:c1,c9"));
        assert!(!levels_overlap("s0:c1,c2", "s0:c2,c3"));
        assert!(!levels_overlap("s0:c1,c2,c3", "s0:c3,c4,c5"));
        assert!(!levels_overlap("s0", "s0"));
        assert!(!levels_overlap("s0:c1", "s0-s5"));
        assert!(levels_overlap("s0:c1,c2", "junk"));
        assert!(levels_overlap("junk", "s0"));
        assert!(levels_overlap("", ""));
    }

    /// What the insert of a container judges (`level_taken`): the level in
    /// use that is equal to the fresh pair or inside it, and no other.
    #[test]
    fn a_fresh_level_taken_at_the_insert() {
        // every pair is inside a wide level in use, and is accepted
        let fresh = allocate_level(&["s0:c0.c1023".to_string()]).unwrap();
        assert!(!level_taken(&fresh, "s0:c0.c1023"));
        // the same pair recorded by a create at the same time
        assert!(level_taken("s0:c1,c5", "s0:c1,c5"));
        assert!(level_taken("s0:c1,c5", "s0:c5,c1"));
        // a level in use with one category of the pair
        assert!(level_taken("s0:c1,c5", "s0:c1"));
        // the first pass of the allocator avoids a pair that contains
        // another level in use when it can; this one is not inside the pair
        assert!(!level_taken("s0:c1,c2", "s0:c1,c2,c3"));
        assert!(!level_taken("s0:c1,c2", "s0:c3,c4"));
        // no categories, and what is not a level, are ignored
        assert!(!level_taken("s0:c1,c2", "s0"));
        assert!(!level_taken("s0:c1,c2", "junk"));
    }

    /// The level of a fresh container is `s0:cA,cB` with A < B, and reaches
    /// no level in use, however the level in use is spelled.
    #[test]
    fn pairs_of_categories() {
        let mut used = Vec::new();
        for _ in 0..50 {
            let l = allocate_level(&used).unwrap();
            assert!(is_allocated_form(&l), "{l}");
            assert!(used.iter().all(|u| !levels_overlap(&l, u)));
            used.push(l);
        }
        assert!(!is_allocated_form("s0:c2,c1") && !is_allocated_form("s0:c1,c2,c3"));
        // a level that is wide on purpose does not stop the allocation
        for wide in ["s0:c0.c1023", "s0-s0:c0.c1023", "s0:c0.c1000"] {
            let l = allocate_level(&[wide.to_string()]).unwrap();
            assert!(is_allocated_form(&l), "{wide} {l}");
        }
        // a pair never is the set of a level in use, or has one inside
        for _ in 0..200 {
            let l = allocate_level(&["s0:c1".to_string(), "s0:c7,c8".to_string()]).unwrap();
            let (a, b) = velarx_mcs_core::read_pair(l.as_bytes()).unwrap();
            assert!(![a, b].contains(&1) && !(a == 7 && b == 8), "{l}");
        }
        // many levels in use, none of them wide, and a wide one: still a pair
        let mut many: Vec<String> = (0..300)
            .map(|i| format!("s0:c{},c{}", 2 * i, 2 * i + 1))
            .collect();
        many.push("s0:c0.c1023".into());
        assert!(allocate_level(&many).is_ok());
    }

    /// The level field of a context has colons of its own.
    #[test]
    fn the_level_of_a_context_is_replaced() {
        let f = |c| shared_label(c).as_deref().map(str::to_owned);
        assert_eq!(f("u:r:t:s0:c1,c2").as_deref(), Some("u:r:t:s0"));
        assert_eq!(f("u:r:t:s0-s0:c0.c1023").as_deref(), Some("u:r:t:s0"));
        assert_eq!(f("u:r:t:s0").as_deref(), Some("u:r:t:s0"));
        assert_eq!(f("u:r:t:").as_deref(), Some("u:r:t:s0"));
        assert_eq!(f("u:r:t:x:y:z").as_deref(), Some("u:r:t:s0"));
        assert_eq!(f("u:r:t"), None);
        assert_eq!(f(""), None);
        assert_eq!(
            split_context("u:r:t:s0:c1,c2"),
            Some(("u".into(), "r".into(), "t".into(), "s0:c1,c2".into()))
        );
        assert_eq!(split_context("u:r:t:s0:c1024"), None);
        assert_eq!(split_context("u:r:t"), None);
        assert_eq!(split_context("u:r:t:"), None);
        assert_eq!(split_context("u:r:t x:s0"), None);
    }

    #[test]
    fn levels_are_compared_as_sets_of_categories() {
        assert!(levels_overlap("s0:c1,c2", "s0:c2,c1"));
        assert!(levels_overlap("s0:c1,c2", "s0:c0.c1023"));
        assert!(!levels_overlap("s0:c1,c2", "s0:c1,c3"));
        assert!(!levels_overlap("s0:c1,c2", "s0"));
    }
}
