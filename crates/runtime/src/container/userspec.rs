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
//!
//! What a user is is decided by `velarx-user-core` (its rules are numbered
//! there); this module reads the files, keeps the words of the errors and
//! `keep-groups`, and makes the entries added for an unknown user.

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
        use velarx_user_core::Home;
        let home = self.home.as_deref();
        match velarx_user_core::home(home.map(str::as_bytes), workdir.is_empty()) {
            Home::Entry => home.unwrap_or("/"),
            Home::Root => "/",
            Home::Workdir => workdir,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UserError {
    #[error("invalid user `{0}`")]
    Invalid(String),
    #[error("invalid group `{0}`")]
    InvalidGroup(String),
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
    #[error(
        "a user has at most {} supplementary groups",
        velarx_user_core::MAX_GROUPS
    )]
    TooManyGroups,
    #[error("invalid umask `{0}`: an octal value up to 0777 is expected")]
    Umask(String),
    #[error("invalid {0} entry `{1}`: it must be one line")]
    Entry(&'static str, String),
    #[error("cannot read `{0}` of the container: {1}")]
    Read(String, String),
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
    passwd: &[u8],
    group: &[u8],
    user: &str,
    group_add: &[String],
) -> Result<ResolvedUser, UserError> {
    resolve_user_groups(passwd, group, user, group_add, false)
}

/// [`resolve_user`]; with `strict` the groups the image gives the user
/// are left out: the additional groups are its group and `group_add`.
pub fn resolve_user_groups(
    passwd: &[u8],
    group: &[u8],
    user: &str,
    group_add: &[String],
    strict: bool,
) -> Result<ResolvedUser, UserError> {
    use velarx_user_core::{Group, Refusal};
    let keep = keep_groups(group_add)?;
    let added: Vec<&String> = group_add.iter().filter(|g| *g != KEEP_GROUPS).collect();
    let ids: Vec<Vec<u8>> = added.iter().map(|g| g.as_bytes().to_vec()).collect();
    let user = if user.is_empty() { "0" } else { user };
    let (name, group_part) = velarx_user_core::split_user(user.as_bytes());
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let group_text = |which: Group| match which {
        Group::OfUser => text(group_part.unwrap_or_default()),
        Group::Add(i) => added[i].clone(),
    };
    let r = velarx_user_core::resolve(passwd, group, user.as_bytes(), &ids, strict).map_err(
        |refusal| match refusal {
            Refusal::Malformed => UserError::Invalid(user.to_string()),
            Refusal::BadUserId => UserError::Invalid(text(name)),
            Refusal::NoUser => UserError::NoUser(text(name)),
            Refusal::BadGroupId(w) => UserError::InvalidGroup(group_text(w)),
            Refusal::NoGroup(w) => UserError::NoGroup(group_text(w)),
            Refusal::TooManyGroups => UserError::TooManyGroups,
        },
    )?;
    Ok(ResolvedUser {
        uid: r.uid,
        gid: r.gid,
        additional_gids: r.gids,
        home: r.home.map(|(from, to)| text(&passwd[from..to])),
        keep_groups: keep,
    })
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

/// `content` with `line` after its last line; the bytes of `content` are
/// kept as they are.
fn with_line(content: &[u8], line: &[u8]) -> Vec<u8> {
    let mut s = Vec::with_capacity(content.len() + line.len() + 2);
    s.extend_from_slice(content);
    if !s.is_empty() && !s.ends_with(b"\n") {
        s.push(b'\n');
    }
    s.extend_from_slice(line);
    s.push(b'\n');
    s
}

/// `passwd` with the entries of the users of the host that `--hostuser`
/// names (by name or by uid) and the image lacks; the home directory is the
/// host's when `home_is_mounted` says the container has it, else the
/// working directory.  A user is matched by name or by uid, whichever it
/// is, unlike the lookup of the image where a numeric user is a uid only.
pub fn with_host_users(
    passwd: &[u8],
    host_passwd: &[u8],
    users: &[String],
    workdir: &str,
    home_is_mounted: impl Fn(&str) -> bool,
) -> Result<Vec<u8>, UserError> {
    let mut out = passwd.to_vec();
    for want in users {
        let id = velarx_user_core::parse_id(want.as_bytes());
        let entry = velarx_user_core::passwd_find(host_passwd, Some(want.as_bytes()), id)
            .ok_or_else(|| UserError::NoHostUser(want.clone()))?;
        let bytes = |(from, to): (usize, usize)| &host_passwd[from..to];
        let (name, uid, gid) = (bytes(entry.name), entry.uid, entry.gid);
        let (gecos, home) = (bytes(entry.gecos), bytes(entry.home));
        if velarx_user_core::passwd_find(&out, Some(name), Some(uid)).is_some() {
            continue;
        }
        let home = if home_is_mounted(&String::from_utf8_lossy(home)) {
            home
        } else if workdir.is_empty() {
            b"/"
        } else {
            workdir.as_bytes()
        };
        let line = [
            name,
            format!(":*:{uid}:{gid}:").as_bytes(),
            gecos,
            b":",
            home,
            b":/bin/sh",
        ]
        .concat();
        out = with_line(&out, &line);
    }
    Ok(out)
}

/// The new passwd and group files: `None` for one that needs no change.
pub type AddedFiles = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The new contents of `/etc/passwd` and `/etc/group` when the uid or the
/// gid of `user` lacks an entry in `passwd` or `group`; `None` for a file
/// that needs no change.
pub fn added_entries(
    passwd: &[u8],
    group: &[u8],
    user: &ResolvedUser,
    workdir: &str,
    opts: &EntryOptions<'_>,
) -> Result<AddedFiles, UserError> {
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
    let new_passwd = match velarx_user_core::has_uid(passwd, user.uid) {
        true => None,
        false => Some(with_line(
            passwd,
            line("passwd", opts.passwd_template.unwrap_or(PASSWD_TEMPLATE))?.as_bytes(),
        )),
    };
    let new_group = match velarx_user_core::has_gid(group, user.gid) {
        true => None,
        false => Some(with_line(
            group,
            line("group", opts.group_template.unwrap_or(GROUP_TEMPLATE))?.as_bytes(),
        )),
    };
    Ok((new_passwd, new_group))
}

/// Largest file read from the container to resolve users.
const MAX_ETC_FILE: u64 = 16 << 20;

/// Read `rel` (like `etc/passwd`) below `root`, resolving symlinks inside
/// the root (they cannot leave it) and refusing anything but a regular file.
/// A missing file reads as empty.
pub fn read_in_root(root: &Path, rel: &str) -> Result<Vec<u8>, UserError> {
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
        Err(rustix::io::Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(read_err(e.to_string())),
    };
    read_regular(fd).map_err(read_err)
}

fn read_regular(fd: OwnedFd) -> Result<Vec<u8>, String> {
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
    Ok(buf)
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

    // The tests state files and results as text: these read them as such.
    // (`bytes_of_the_files_are_kept` runs the ones of `super` on bytes.)
    fn resolve_user(
        passwd: &str,
        group: &str,
        user: &str,
        add: &[String],
    ) -> Result<ResolvedUser, UserError> {
        super::resolve_user(passwd.as_bytes(), group.as_bytes(), user, add)
    }

    fn resolve_user_groups(
        passwd: &str,
        group: &str,
        user: &str,
        add: &[String],
        strict: bool,
    ) -> Result<ResolvedUser, UserError> {
        super::resolve_user_groups(passwd.as_bytes(), group.as_bytes(), user, add, strict)
    }

    fn added_entries(
        passwd: &str,
        group: &str,
        user: &ResolvedUser,
        workdir: &str,
        opts: &EntryOptions<'_>,
    ) -> Result<(Option<String>, Option<String>), UserError> {
        let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
        super::added_entries(passwd.as_bytes(), group.as_bytes(), user, workdir, opts)
            .map(|(p, g)| (p.map(text), g.map(text)))
    }

    fn with_host_users(
        passwd: &str,
        host: &str,
        users: &[String],
        workdir: &str,
        mounted: impl Fn(&str) -> bool,
    ) -> Result<String, UserError> {
        super::with_host_users(passwd.as_bytes(), host.as_bytes(), users, workdir, mounted)
            .map(|b| String::from_utf8(b).unwrap())
    }

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
    fn digits_above_the_id_range_are_never_names() {
        // a passwd line named like the number must not capture it
        let passwd = "4294967295:x:0:0:x:/root:/bin/sh\n99999999999:x:0:0:x:/:/bin/sh\n";
        let group = "4294967295:x:5:\n";
        for user in ["4294967295", "99999999999"] {
            let got = resolve_user(passwd, group, user, &[]);
            assert_eq!(got, Err(UserError::Invalid(user.into())));
        }
        assert_eq!(
            resolve_user(passwd, group, "0:4294967295", &[]),
            Err(UserError::InvalidGroup("4294967295".into()))
        );
        let add = ["4294967295".to_string()];
        assert_eq!(
            resolve_user(passwd, group, "0", &add),
            Err(UserError::InvalidGroup("4294967295".into()))
        );
    }

    #[test]
    fn what_a_passwd_line_is() {
        let p = |passwd: &str, user: &str| resolve_user(passwd, "", user, &[]);
        let uid_of = |passwd: &str, user: &str| p(passwd, user).map(|u| (u.uid, u.gid));
        // the first line wins, by name and by uid
        let dup = "a:x:1:1::/one:/bin/sh\na:x:2:2::/two:/bin/sh\nb:x:1:3::/three:/bin/sh\n";
        assert_eq!(uid_of(dup, "a"), Ok((1, 1)));
        assert_eq!(uid_of(dup, "1"), Ok((1, 1)));
        // a line with an empty or bad uid or gid, or short, is no entry
        for bad in [
            "a:x::1::/h:/bin/sh\n",
            "a:x:1::g:/h:/bin/sh\n",
            "a:x:1:1::/h\n",
            "a:x:1\n",
            "a:x:-1:1::/h:/bin/sh\n",
            "a:x:+1:1::/h:/bin/sh\n",
            "a:x:4294967296:1::/h:/bin/sh\n",
        ] {
            assert_eq!(
                uid_of(bad, "a"),
                Err(UserError::NoUser("a".into())),
                "{bad}"
            );
        }
        // more fields are fine; leading zeros are the number
        assert_eq!(uid_of("a:x:007:08::/h:/bin/sh:more\n", "a"), Ok((7, 8)));
        assert_eq!(uid_of("", "0000000000000000000000000042"), Ok((42, 0)));
        // a name of digits that is a valid id is the id
        let digits = "1000:x:5:5::/h:/bin/sh\n";
        assert_eq!(uid_of(digits, "1000"), Ok((1000, 0)));
        assert_eq!(uid_of(digits, "5"), Ok((5, 5)));
        // no space is trimmed
        for user in [" a", "a ", "\ta"] {
            assert!(p("a:x:1:1::/h:/bin/sh\n", user).is_err(), "{user:?}");
        }
        // a line ending is \r\n or \n; a lone \r ends nothing
        assert_eq!(
            uid_of("a:x:1:1::/h:/bin/sh\r\nb:x:2:2::/h:/s\r\n", "b"),
            Ok((2, 2))
        );
        assert_eq!(uid_of("a:x:1:1::/h:\r", "a"), Ok((1, 1)));
        assert_eq!(
            p("a:x:1:1::/h:/bin/sh\rb:x:2:2::/h:/s\n", "b"),
            Err(UserError::NoUser("b".into()))
        );
        // there are no comment lines in a passwd file
        assert_eq!(uid_of("#a:x:3:3::/h:/bin/sh\n", "#a"), Ok((3, 3)));
    }

    #[test]
    fn who_is_a_member_of_a_group() {
        let groups = |passwd: &str, group: &str, user: &str| {
            resolve_user(passwd, group, user, &[]).map(|u| u.additional_gids)
        };
        let passwd = "a:x:1:1::/h:/bin/sh\n";
        // whole names of the list only
        let group = "g:x:5:a\nh:x:6:b,a,c\nj:x:7:ab,a b\nk:x:8:\n";
        assert_eq!(groups(passwd, group, "a"), Ok(vec![1, 5, 6]));
        // a gid listed twice is one
        assert_eq!(
            groups(passwd, "g:x:1:a\nh:x:5:a\ni:x:5:a\n", "a"),
            Ok(vec![1, 5])
        );
        // a group line of three fields or with a bad gid lists nobody
        assert_eq!(groups(passwd, "g:x:5\nh:x:z:a\n", "a"), Ok(vec![1]));
        // an entry without a name is in no group
        let nameless = ":x:9:9::/h:/bin/sh\n";
        assert_eq!(groups(nameless, "g:x:5:\nh:x:6:a\n", "9"), Ok(vec![9]));
    }

    #[test]
    fn a_group_comment_is_no_group() {
        let passwd = "a:x:1:1::/h:/bin/sh\n";
        let group = "#c:x:5:a\nreal:x:6:a\n";
        let u = resolve_user(passwd, group, "a", &[]).unwrap();
        assert_eq!(u.additional_gids, vec![1, 6]);
        assert_eq!(
            resolve_user(passwd, group, "a:#c", &[]),
            Err(UserError::NoGroup("#c".into()))
        );
        // a group of that gid is added: the comment does not count
        let u = resolve_user(passwd, group, "a:5", &[]).unwrap();
        let (_, g) = added_entries(passwd, group, &u, "/", &EntryOptions::default()).unwrap();
        assert_eq!(g.unwrap(), "#c:x:5:a\nreal:x:6:a\n5:x:5:1\n");
    }

    /// An entry is added to files that are not UTF-8 and every byte of them
    /// is as it was.
    #[test]
    fn the_bytes_of_the_files_are_kept() {
        let passwd = b"a:x:1:1:caf\xe9 \xff:/:/bin/sh\n".as_slice();
        let group = b"g\xe9:x:1:a\n".as_slice();
        let u = super::resolve_user(passwd, group, "4242", &[]).unwrap();
        let (p, g) =
            super::added_entries(passwd, group, &u, "/", &EntryOptions::default()).unwrap();
        let (p, g) = (p.unwrap(), g.unwrap());
        assert_eq!(p[..passwd.len()], *passwd);
        assert_eq!(
            p[passwd.len()..],
            *b"4242:*:4242:0:container user:/:/bin/sh\n"
        );
        assert_eq!(g[..group.len()], *group);
        // the entries of a host user too
        let host = b"h:x:9:9:j\xf6rg:/home/h:/bin/sh\n".as_slice();
        let users = ["h".to_string()];
        let got = super::with_host_users(passwd, host, &users, "/w", |_| false).unwrap();
        assert_eq!(got[..passwd.len()], *passwd);
        assert_eq!(got[passwd.len()..], *b"h:*:9:9:j\xf6rg:/w:/bin/sh\n");
    }

    #[test]
    fn a_user_has_a_bounded_number_of_groups() {
        let group: String = (0..70_000).map(|i| format!("g{i}:x:{i}:alice\n")).collect();
        let got = resolve_user(PASSWD, &group, "alice", &[]);
        assert_eq!(got, Err(UserError::TooManyGroups));
        // not asked for the groups of the image, the user has its own
        assert!(resolve_user_groups(PASSWD, &group, "alice", &[], true).is_ok());
        // a gid that wraps is no gid, and names the group that it was
        let add = ["1".to_string(), "4294967296".to_string()];
        assert_eq!(
            resolve_user(PASSWD, GROUP, "0", &add),
            Err(UserError::InvalidGroup("4294967296".into()))
        );
    }

    #[test]
    fn an_entry_that_is_no_entry_does_not_know_the_id() {
        let u = r("4242", &[]).unwrap();
        // a short line is no entry of the id: the id is added
        let (p, g) =
            added_entries("a:x:4242\n", "g:x:0\n", &u, "/", &EntryOptions::default()).unwrap();
        assert_eq!(
            p.unwrap(),
            "a:x:4242\n4242:*:4242:0:container user:/:/bin/sh\n"
        );
        assert_eq!(g.unwrap(), "g:x:0\n0:x:0:4242\n");
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
        assert_eq!(
            read_in_root(d.path(), "etc/passwd").unwrap(),
            GROUP.as_bytes()
        );
        std::os::unix::fs::symlink("../../../../../etc/group", d.path().join("etc/g2")).unwrap();
        assert_eq!(read_in_root(d.path(), "etc/g2").unwrap(), GROUP.as_bytes());
        std::os::unix::fs::symlink("/etc/nosuch", d.path().join("etc/g3")).unwrap();
        assert!(read_in_root(d.path(), "etc/g3").unwrap().is_empty());
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
