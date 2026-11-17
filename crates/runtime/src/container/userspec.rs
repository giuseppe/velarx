// SPDX-License-Identifier: Apache-2.0
//! The user a container process runs as.
//!
//! `--user NAME|UID[:GROUP|GID]` (or the `User` of the image) is resolved
//! against the `/etc/passwd` and `/etc/group` of the container, read below
//! its root without following symlinks out of it.  The rules are podman's:
//!
//! - no user is `0`; a uid that the image does not know is accepted, with
//!   gid 0 and no home; a name that it does not know is an error;
//! - the additional groups are the primary gid, the `--group-add` groups and,
//!   when no group is given in the user, the groups of the image that list
//!   the user as a member;
//! - `--group-add keep-groups` keeps the groups of the caller (crun's
//!   `run.oci.keep_original_groups`) and cannot be combined with others;
//! - a uid or gid missing from the image gets a passwd or group entry
//!   (`--passwd-entry`, `--group-entry`, disabled by `--passwd=false`).

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

/// The `--group-add` value that keeps the groups of the caller.
pub const KEEP_GROUPS: &str = "keep-groups";

/// What the spec needs to know about the user.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedUser {
    pub uid: u32,
    pub gid: u32,
    /// The supplementary groups, the primary gid first.
    pub additional_gids: Vec<u32>,
    /// The home directory of the passwd entry; none when the image does
    /// not know the uid.
    pub home: Option<String>,
    /// `--group-add keep-groups`
    #[serde(default)]
    pub keep_groups: bool,
}

impl ResolvedUser {
    /// `HOME` of the process: the home of the user, else the working
    /// directory (the home of the passwd entry that is added for it).
    pub fn home_or<'a>(&'a self, workdir: &'a str) -> &'a str {
        match self.home.as_deref() {
            Some("") => "/",
            Some(h) => h,
            None if workdir.is_empty() => "/",
            None => workdir,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UserError {
    #[error("invalid user `{0}`")]
    Invalid(String),
    #[error("unable to find user {0}: no matching entries in passwd file")]
    NoUser(String),
    #[error("unable to find group {0}: no matching entries in group file")]
    NoGroup(String),
    #[error(
        "the `--group-add keep-groups` option is not allowed with any other `--group-add` option"
    )]
    KeepGroups,
    #[error("unable to find the host user {0}: no matching entry in the /etc/passwd of the host")]
    NoHostUser(String),
    #[error("invalid umask `{0}`: an octal value up to 0777 is expected")]
    Umask(String),
    #[error("invalid {0} entry `{1}`: it must be one line")]
    Entry(&'static str, String),
    #[error("cannot read `{0}` of the container: {1}")]
    Read(String, String),
}

/// A numeric id: digits only, below `u32::MAX` (which means "no id").
fn parse_id(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u32>().ok().filter(|&n| n != u32::MAX)
}

struct PasswdEntry<'a> {
    name: &'a str,
    uid: u32,
    gid: u32,
    home: &'a str,
}

fn passwd_entries(content: &str) -> impl Iterator<Item = PasswdEntry<'_>> {
    content.lines().filter_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            return None;
        }
        Some(PasswdEntry {
            name: f[0],
            uid: parse_id(f[2])?,
            gid: parse_id(f[3])?,
            home: f[5],
        })
    })
}

struct GroupEntry<'a> {
    name: &'a str,
    gid: u32,
    members: &'a str,
}

fn group_entries(content: &str) -> impl Iterator<Item = GroupEntry<'_>> {
    content.lines().filter_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 {
            return None;
        }
        Some(GroupEntry {
            name: f[0],
            gid: parse_id(f[2])?,
            members: f[3],
        })
    })
}

fn add_gid(v: &mut Vec<u32>, gid: u32) {
    if !v.contains(&gid) {
        v.push(gid);
    }
}

fn group_id(group: &str, g: &str) -> Result<u32, UserError> {
    match parse_id(g) {
        Some(gid) => Ok(gid),
        None => group_entries(group)
            .find(|e| e.name == g)
            .map(|e| e.gid)
            .ok_or_else(|| UserError::NoGroup(g.to_string())),
    }
}

/// Whether `group_add` asks for `keep-groups`, which must then be alone.
pub fn keep_groups(group_add: &[String]) -> Result<bool, UserError> {
    match group_add.iter().any(|g| g == KEEP_GROUPS) {
        true if group_add.len() > 1 => Err(UserError::KeepGroups),
        k => Ok(k),
    }
}

/// Resolve `user` (`""` means root) with the contents of the container's
/// passwd and group files.  `group_add` entries are names or ids.
pub fn resolve_user(
    passwd: &str,
    group: &str,
    user: &str,
    group_add: &[String],
) -> Result<ResolvedUser, UserError> {
    resolve_user_groups(passwd, group, user, group_add, false)
}

/// [`resolve_user`]; with `strict` the groups the image gives the user
/// are left out: the additional groups are its group and `group_add`.
pub fn resolve_user_groups(
    passwd: &str,
    group: &str,
    user: &str,
    group_add: &[String],
    strict: bool,
) -> Result<ResolvedUser, UserError> {
    let user = if user.is_empty() { "0" } else { user };
    let (user_part, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    if user_part.is_empty() || group_part == Some("") {
        return Err(UserError::Invalid(user.to_string()));
    }

    let by_id = parse_id(user_part);
    let entry = passwd_entries(passwd).find(|e| match by_id {
        Some(id) => e.uid == id,
        None => e.name == user_part,
    });
    let mut out = ResolvedUser::default();
    match (&entry, by_id) {
        (Some(e), _) => {
            out.uid = e.uid;
            out.gid = e.gid;
            out.home = Some(e.home.to_string());
        }
        (None, Some(id)) => out.uid = id,
        (None, None) => return Err(UserError::NoUser(user_part.to_string())),
    }
    if let Some(g) = group_part {
        out.gid = group_id(group, g)?;
    }

    out.keep_groups = keep_groups(group_add)?;
    out.additional_gids.push(out.gid);
    for g in group_add.iter().filter(|g| *g != KEEP_GROUPS) {
        add_gid(&mut out.additional_gids, group_id(group, g)?);
    }
    // As runc's GetExecUser: the groups of the image only when the user
    // does not name its group.
    if let (Some(e), None, false) = (&entry, group_part, strict) {
        for g in group_entries(group) {
            if g.members.split(',').any(|m| m == e.name) {
                add_gid(&mut out.additional_gids, g.gid);
            }
        }
    }
    Ok(out)
}

/// `--umask`: an octal mode up to 0777.
pub fn parse_umask(s: &str) -> Result<u32, UserError> {
    let bad = || UserError::Umask(s.to_string());
    if s.is_empty() || s.len() > 4 {
        return Err(bad());
    }
    u32::from_str_radix(s, 8)
        .ok()
        .filter(|m| *m <= 0o777)
        .ok_or_else(bad)
}

/// The entries added for a user that the image does not know.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EntryOptions<'a> {
    /// `--passwd-entry`: `$USERNAME`, `$UID`, `$GID`, `$NAME`, `$HOME`
    pub passwd_template: Option<&'a str>,
    /// `--group-entry`: `$GROUPNAME`, `$GID`, `$USERNAME`
    pub group_template: Option<&'a str>,
    /// The user and group names of the entries (`--userns=keep-id` uses
    /// those of the host); by default the uid and the gid.
    pub identity: Option<(&'a str, &'a str)>,
}

const PASSWD_TEMPLATE: &str = "$USERNAME:*:$UID:$GID:$NAME:$HOME:/bin/sh";
const GROUP_TEMPLATE: &str = "$GROUPNAME:x:$GID:$USERNAME";

fn has_id(content: &str, id: u32) -> bool {
    content
        .lines()
        .any(|l| l.split(':').nth(2).and_then(parse_id) == Some(id))
}

fn expand(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    'outer: while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos + 1..];
        // the longest name first: $GID is not $GIDX
        for (k, v) in vars {
            if let Some(tail) = rest.strip_prefix(k) {
                out.push_str(v);
                rest = tail;
                continue 'outer;
            }
        }
        out.push('$');
    }
    out.push_str(rest);
    out
}

fn with_line(content: &str, line: &str) -> String {
    let mut s = String::with_capacity(content.len() + line.len() + 2);
    s.push_str(content);
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s.push_str(line);
    s.push('\n');
    s
}

/// `passwd` with the entries of the users of the host that `--hostuser`
/// names (by name or by uid) and the image lacks; the home directory is the
/// host's when `home_is_mounted` says the container has it, else the
/// working directory.
pub fn with_host_users(
    passwd: &str,
    host_passwd: &str,
    users: &[String],
    workdir: &str,
    home_is_mounted: impl Fn(&str) -> bool,
) -> Result<String, UserError> {
    let mut out = passwd.to_string();
    for want in users {
        let id = parse_id(want);
        let fields: Vec<&str> = host_passwd
            .lines()
            .map(|l| l.split(':').collect::<Vec<_>>())
            .find(|f| f.len() >= 7 && (f[0] == want || id.is_some() && parse_id(f[2]) == id))
            .ok_or_else(|| UserError::NoHostUser(want.clone()))?;
        let (name, uid, gid, gecos, home) = (fields[0], fields[2], fields[3], fields[4], fields[5]);
        let known = |content: &str| {
            content.lines().any(|l| {
                let mut f = l.split(':');
                f.next() == Some(name) || f.nth(1) == Some(uid)
            })
        };
        if known(&out) {
            continue;
        }
        let home = if home_is_mounted(home) {
            home
        } else if workdir.is_empty() {
            "/"
        } else {
            workdir
        };
        out = with_line(
            &out,
            &format!("{name}:*:{uid}:{gid}:{gecos}:{home}:/bin/sh"),
        );
    }
    Ok(out)
}

/// The new contents of `/etc/passwd` and `/etc/group` when the uid or the
/// gid of `user` lacks an entry in `passwd` or `group`; `None` for a file
/// that needs no change.
pub fn added_entries(
    passwd: &str,
    group: &str,
    user: &ResolvedUser,
    workdir: &str,
    opts: &EntryOptions<'_>,
) -> Result<(Option<String>, Option<String>), UserError> {
    let uid = user.uid.to_string();
    let gid = user.gid.to_string();
    let workdir = if workdir.is_empty() { "/" } else { workdir };
    let (name, group_name) = opts.identity.unwrap_or((&uid, &gid));
    // podman leaves the comment of the entry of keep-id empty
    let gecos = match opts.identity {
        Some(_) => "",
        None => "container user",
    };
    let vars: [(&str, &str); 6] = [
        ("USERNAME", name),
        ("GROUPNAME", group_name),
        ("UID", &uid),
        ("GID", &gid),
        ("NAME", gecos),
        ("HOME", workdir),
    ];
    let line = |what: &'static str, template: &str| {
        let l = expand(template, &vars);
        if l.contains(['\n', '\r', '\0']) {
            return Err(UserError::Entry(what, template.to_string()));
        }
        Ok(l)
    };
    let new_passwd = match has_id(passwd, user.uid) {
        true => None,
        false => Some(with_line(
            passwd,
            &line("passwd", opts.passwd_template.unwrap_or(PASSWD_TEMPLATE))?,
        )),
    };
    let new_group = match has_id(group, user.gid) {
        true => None,
        false => Some(with_line(
            group,
            &line("group", opts.group_template.unwrap_or(GROUP_TEMPLATE))?,
        )),
    };
    Ok((new_passwd, new_group))
}

/// Largest file read from the container to resolve users.
const MAX_ETC_FILE: u64 = 16 << 20;

/// Read `rel` (like `etc/passwd`) below `root`, resolving symlinks inside
/// the root (they cannot leave it) and refusing anything but a regular file.
/// A missing file reads as empty.
pub fn read_in_root(root: &Path, rel: &str) -> Result<String, UserError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};
    use std::os::fd::AsFd;
    let read_err = |e: String| UserError::Read(format!("/{rel}"), e);
    let dir = rustix::fs::openat(
        rustix::fs::CWD,
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| read_err(e.to_string()))?;
    let fd = match velarx_sys::fs::open_in_root(dir.as_fd(), rel, ResolveFlags::NO_XDEV) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(String::new()),
        Err(e) => return Err(read_err(e.to_string())),
    };
    read_regular(fd).map_err(read_err)
}

fn read_regular(fd: OwnedFd) -> Result<String, String> {
    let st = rustix::fs::fstat(&fd).map_err(|e| e.to_string())?;
    if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::RegularFile {
        return Err("not a regular file".into());
    }
    let mut buf = Vec::new();
    std::fs::File::from(fd)
        .take(MAX_ETC_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_ETC_FILE {
        return Err("too large".into());
    }
    // Lines that are not UTF-8 cannot match a name given as a string.
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Resolve `user` with the files below `root`: what a caller needs from a
/// root file system and a `--user` string (`--userns=keep-id` passes the
/// `uid:gid` of the user on the host).
pub fn resolve_user_in_root(
    root: &Path,
    user: &str,
    group_add: &[String],
    strict: bool,
) -> Result<ResolvedUser, UserError> {
    let passwd = read_in_root(root, "etc/passwd")?;
    let group = read_in_root(root, "etc/group")?;
    resolve_user_groups(&passwd, &group, user, group_add, strict)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\nbin:x:1:1:bin:/bin:/sbin/nologin\n\
alice:x:1000:1001:Alice:/home/alice:/bin/sh\nnohome:x:7:7:x::/bin/sh\nbad:x:z:1:x:/:/bin/sh\n";
    const GROUP: &str =
        "root:x:0:root\nbin:x:1:root,bin\nalice:x:1001:\nwheel:x:10:root,alice,bob\n\
audio:x:63:\nnum:x:4294967295:alice\n";

    fn r(user: &str, add: &[&str]) -> Result<ResolvedUser, UserError> {
        let add: Vec<String> = add.iter().map(|s| s.to_string()).collect();
        resolve_user(PASSWD, GROUP, user, &add)
    }

    #[test]
    fn root_by_default() {
        let u = r("", &[]).unwrap();
        assert_eq!((u.uid, u.gid, u.home.as_deref()), (0, 0, Some("/root")));
        assert_eq!(u.additional_gids, vec![0, 1, 10]);
    }

    #[test]
    fn name_gets_image_groups() {
        let u = r("alice", &[]).unwrap();
        assert_eq!((u.uid, u.gid), (1000, 1001));
        assert_eq!(u.additional_gids, vec![1001, 10]);
        // by uid too
        assert_eq!(r("1000", &[]).unwrap(), u);
        assert_eq!(r("bin", &[]).unwrap().additional_gids, vec![1]);
    }

    #[test]
    fn a_group_in_the_user_drops_the_image_groups() {
        let u = r("alice:audio", &[]).unwrap();
        assert_eq!((u.uid, u.gid), (1000, 63));
        assert_eq!(u.additional_gids, vec![63]);
        let u = r("1000:1234", &["wheel"]).unwrap();
        assert_eq!(u.additional_gids, vec![1234, 10]);
    }

    #[test]
    fn strict_groups_leave_out_those_of_the_image() {
        let r = |u: &str, strict| {
            resolve_user_groups(PASSWD, GROUP, u, &["4242".to_string()], strict).unwrap()
        };
        let merged = r("alice", false).additional_gids;
        let strict = r("alice", true).additional_gids;
        assert_eq!(strict, [1001, 4242]);
        assert!(merged.len() > strict.len(), "{merged:?}");
    }

    #[test]
    fn group_add() {
        let u = r("alice", &["audio", "4242", "10"]).unwrap();
        assert_eq!(u.additional_gids, vec![1001, 63, 4242, 10]);
        assert!(!u.keep_groups);
        let u = r("0", &["keep-groups"]).unwrap();
        assert!(u.keep_groups);
        assert_eq!(u.additional_gids, vec![0, 1, 10]);
        assert_eq!(
            r("0", &["keep-groups", "audio"]),
            Err(UserError::KeepGroups)
        );
    }

    #[test]
    fn unknown_uid_is_accepted_unknown_name_is_not() {
        let u = r("5000", &[]).unwrap();
        assert_eq!((u.uid, u.gid, u.home.as_deref()), (5000, 0, None));
        assert_eq!(u.additional_gids, vec![0]);
        assert_eq!(u.home_or("/srv"), "/srv");
        assert_eq!(u.home_or(""), "/");
        assert_eq!(r("bob", &[]), Err(UserError::NoUser("bob".into())));
        assert_eq!(
            r("alice:nogroup", &[]),
            Err(UserError::NoGroup("nogroup".into()))
        );
        assert_eq!(
            r("0", &["nogroup"]),
            Err(UserError::NoGroup("nogroup".into()))
        );
        assert!(matches!(r(":1", &[]), Err(UserError::Invalid(_))));
        assert!(matches!(r("1:", &[]), Err(UserError::Invalid(_))));
    }

    #[test]
    fn empty_home_is_root() {
        let u = r("nohome", &[]).unwrap();
        assert_eq!(u.home_or("/srv"), "/");
    }

    #[test]
    fn malformed_ids_are_not_ids() {
        assert!(r("4294967295", &[]).is_err());
        assert!(r("-1", &[]).is_err());
        assert!(r("1000x", &[]).is_err());
        assert!(r("+1", &[]).is_err());
        // the line with a bad uid is skipped, not matched by name
        assert_eq!(r("bad", &[]), Err(UserError::NoUser("bad".into())));
        // a group line with an invalid gid is ignored
        assert_eq!(r("0", &["num"]), Err(UserError::NoGroup("num".into())));
    }

    #[test]
    fn umask() {
        assert_eq!(parse_umask("0022"), Ok(0o22));
        assert_eq!(parse_umask("077"), Ok(0o77));
        assert_eq!(parse_umask("0777"), Ok(0o777));
        for bad in ["", "999", "1000", "08", "0x1", "-1", "00022"] {
            assert!(parse_umask(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn entries_for_unknown_ids() {
        let u = r("4242:4243", &[]).unwrap();
        let (p, g) = added_entries(PASSWD, GROUP, &u, "/tmp", &EntryOptions::default()).unwrap();
        assert_eq!(
            p.unwrap(),
            format!("{PASSWD}4242:*:4242:4243:container user:/tmp:/bin/sh\n")
        );
        assert_eq!(g.unwrap(), format!("{GROUP}4243:x:4243:4242\n"));

        // known ids: no change
        let u = r("alice", &[]).unwrap();
        assert_eq!(
            added_entries(PASSWD, GROUP, &u, "/", &EntryOptions::default()).unwrap(),
            (None, None)
        );

        // a file without a final newline, and missing files
        let u = r("0:4242", &[]).unwrap();
        let (p, g) = added_entries("", "root:x:0:", &u, "", &EntryOptions::default()).unwrap();
        assert_eq!(p.unwrap(), "0:*:0:4242:container user:/:/bin/sh\n");
        assert_eq!(g.unwrap(), "root:x:0:\n4242:x:4242:0\n");
    }

    #[test]
    fn entry_templates_and_identity() {
        let u = r("4242", &[]).unwrap();
        let opts = EntryOptions {
            passwd_template: Some("$USERNAME:x:$UID:$GID:$NAME:$HOME:/bin/false:$UIDX$"),
            group_template: Some("g$GROUPNAME:x:$GID:"),
            identity: None,
        };
        let (p, g) = added_entries("", "root:x:0:", &u, "/h", &opts).unwrap();
        assert_eq!(
            p.unwrap(),
            "4242:x:4242:0:container user:/h:/bin/false:4242X$\n"
        );
        assert_eq!(g, None);
        let u = r("4242:9", &[]).unwrap();
        let (_, g) = added_entries("", "", &u, "/", &opts).unwrap();
        assert_eq!(g.unwrap(), "g9:x:9:\n");
        // keep-id: the names of the host
        let u = r("1002:1002", &[]).unwrap();
        let opts = EntryOptions {
            identity: Some(("me", "us")),
            ..Default::default()
        };
        let (p, g) = added_entries("", "", &u, "/", &opts).unwrap();
        assert_eq!(p.unwrap(), "me:*:1002:1002::/:/bin/sh\n");
        assert_eq!(g.unwrap(), "us:x:1002:me\n");
        let opts = EntryOptions {
            passwd_template: Some("a\nroot::0:0::/:/bin/sh"),
            ..Default::default()
        };
        assert!(matches!(
            added_entries("", "", &u, "/", &opts),
            Err(UserError::Entry("passwd", _))
        ));
    }

    #[test]
    fn root_files_are_read_in_the_root() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("etc")).unwrap();
        std::fs::write(d.path().join("etc/passwd"), PASSWD).unwrap();
        std::fs::write(d.path().join("etc/group"), GROUP).unwrap();
        let u = resolve_user_in_root(d.path(), "alice", &[], false).unwrap();
        assert_eq!(u.uid, 1000);
        // An absolute symlink stays in the root: the host's file is not read.
        std::fs::remove_file(d.path().join("etc/passwd")).unwrap();
        std::os::unix::fs::symlink("/etc/group", d.path().join("etc/passwd")).unwrap();
        assert_eq!(read_in_root(d.path(), "etc/passwd").unwrap(), GROUP);
        std::os::unix::fs::symlink("../../../../../etc/group", d.path().join("etc/g2")).unwrap();
        assert_eq!(read_in_root(d.path(), "etc/g2").unwrap(), GROUP);
        std::os::unix::fs::symlink("/etc/nosuch", d.path().join("etc/g3")).unwrap();
        assert_eq!(read_in_root(d.path(), "etc/g3").unwrap(), "");
        assert!(matches!(
            resolve_user_in_root(d.path(), "alice", &[], false),
            Err(UserError::NoUser(_))
        ));
        // a loop is an error
        std::os::unix::fs::symlink("/etc/loop", d.path().join("etc/loop")).unwrap();
        assert!(matches!(
            read_in_root(d.path(), "etc/loop"),
            Err(UserError::Read(..))
        ));
        // A missing file is empty: uid 0 still resolves.
        assert_eq!(
            resolve_user_in_root(d.path(), "0", &[], false).unwrap().uid,
            0
        );
        // A symlink inside the root is followed.
        std::fs::write(d.path().join("etc/real"), PASSWD).unwrap();
        std::fs::remove_file(d.path().join("etc/passwd")).unwrap();
        std::os::unix::fs::symlink("/etc/real", d.path().join("etc/passwd")).unwrap();
        assert_eq!(
            resolve_user_in_root(d.path(), "alice", &[], false)
                .unwrap()
                .uid,
            1000
        );
    }

    #[test]
    fn special_files_are_refused() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("etc")).unwrap();
        let p = d.path().join("etc/passwd");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &p,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .unwrap();
        assert!(matches!(
            read_in_root(d.path(), "etc/passwd"),
            Err(UserError::Read(..))
        ));
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        assert!(matches!(
            read_in_root(d.path(), "etc/passwd"),
            Err(UserError::Read(..))
        ));
    }

    #[test]
    fn host_users_get_the_entries_the_image_lacks() {
        let host = "root:x:0:0:root:/root:/bin/bash\nbob:x:1234:1235:Bob B:/home/bob:/bin/zsh\n\
alice:x:5000:5000::/home/other:/bin/sh\nshort:x:1\n";
        let users = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let got = with_host_users(PASSWD, host, &users(&["bob", "1234"]), "/w", |_| false).unwrap();
        assert_eq!(got, format!("{PASSWD}bob:*:1234:1235:Bob B:/w:/bin/sh\n"));
        let got = with_host_users("", host, &users(&["1234"]), "", |h| h == "/home/bob").unwrap();
        assert_eq!(got, "bob:*:1234:1235:Bob B:/home/bob:/bin/sh\n");
        // known by name, or by uid, in the image
        assert_eq!(
            with_host_users(PASSWD, host, &users(&["root", "alice"]), "/", |_| false).unwrap(),
            PASSWD
        );
        assert_eq!(
            with_host_users(PASSWD, host, &users(&["nobody"]), "/", |_| false),
            Err(UserError::NoHostUser("nobody".into()))
        );
    }
}
