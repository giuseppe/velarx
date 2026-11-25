// SPDX-License-Identifier: Apache-2.0
//! The user a container process runs as, as podman gives it: the value of
//! `--user`, of the `User` of the image or of the user of a pod (`NAME`,
//! `UID`, `NAME:GROUP`, `UID:GID`...) against the `/etc/passwd` and
//! `/etc/group` of the image.  Both files come from the image, so they are
//! bytes nobody vouched for: any bytes, of any length, are an answer or a
//! refusal here, never a panic and never an id that is not the one written.
//!
//! The rules:
//!
//! 1. `resolve` returns, whatever the bytes.
//! 2. An id is digits and nothing else, and below 4294967295 (which means
//!    "no id" to the kernel): `-1`, `+1`, ` 1`, `1x` and the empty string
//!    are not ids, `007` is 7, and a number that does not fit is not an id
//!    (it is never taken modulo 2^32).  The uid and the gid of an answer,
//!    and every group in it, are ids.
//! 3. The user string is `USER`, or `USER:GROUP` at its first colon; the
//!    empty string is `0`.  An empty `USER` or `GROUP` is `Malformed`.
//! 4. A `USER` of digits is an id, and never a name: when it is no id it is
//!    `BadUserId`.  It is the uid of the first entry of the passwd file that
//!    has it, and a uid the file does not have is accepted as it is, with
//!    gid 0 and no home.  Any other `USER` is a name: the first entry of
//!    that name, or `NoUser`.
//! 5. An entry is a line of at least seven fields separated by colons,
//!    whose third field (uid) and fourth (gid) are ids; the first is the
//!    name, the sixth the home.  A line that is not one is skipped, not an
//!    error, and not read as 0.  A line ends at `\n`, and a `\r` before it
//!    is no part of it; a passwd file has no comment lines.  A group line
//!    has at least four fields (name, password, gid as an id, members) and
//!    is skipped likewise; so is a group line that starts with `#` (a
//!    comment, as runc reads the file).
//! 6. The gid is that of `GROUP` when there is one, else that of the entry
//!    (0 for a uid the file does not have).  A `GROUP` of digits is an id
//!    (`BadGroupId` when it is not) and is used as it is, known or not; any
//!    other is the gid of the first group of that name, or `NoGroup`.  The
//!    groups of `group_add` are resolved so, in the same way.
//! 7. The supplementary groups are the gid, then those of `group_add` in
//!    its order, then, when the user is an entry of a non-empty name and
//!    has no `GROUP` and `strict` is not set, the groups of the file that
//!    list that name whole among their comma separated members, in the
//!    order of the file.  A gid is in the list once, at its first place,
//!    and the list has at most `MAX_GROUPS` of them (the kernel takes no
//!    more): another is `TooManyGroups`.  An entry with no name is in no
//!    group.
//! 8. The home is that of the entry, none for a uid the file does not have;
//!    `home` says what `HOME` is: an empty home is `/`, none is the working
//!    directory, or `/` when it is empty too.
//!
//! The code is plain loops over bytes, so that Aeneas can translate it
//! (tools/verify): `while` with a flag, no `loop`, no closure, no iterator,
//! no `String`.  What the shell keeps: reading the files below the root of
//! the container (and their bounds), the words of the errors, `keep-groups`,
//! and the entries added for a user the image does not have.

/// The most supplementary groups a process may have (`NGROUPS_MAX`).
pub const MAX_GROUPS: usize = 65536;

/// The kernel's "no id": never an id of ours.
const NO_ID: u64 = u32::MAX as u64;

/// Digits and nothing else, at least one.
pub fn is_digits(s: &[u8]) -> bool {
    let mut ok = !s.is_empty();
    let mut i = 0;
    while i < s.len() && ok {
        ok = s[i] >= b'0' && s[i] <= b'9';
        i += 1;
    }
    ok
}

/// The id written by `s` (rule 2).
pub fn parse_id(s: &[u8]) -> Option<u32> {
    if !is_digits(s) {
        return None;
    }
    let mut v: u64 = 0;
    let mut i = 0;
    while i < s.len() && v < NO_ID {
        v = v * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    if v >= NO_ID {
        None
    } else {
        Some(v as u32)
    }
}

/// `user` as its user and its group, if it has one (rule 3, before the
/// empty string and the empty parts).
pub fn split_user(user: &[u8]) -> (&[u8], Option<&[u8]>) {
    let mut i = 0;
    while i < user.len() && user[i] != b':' {
        i += 1;
    }
    if i < user.len() {
        (&user[..i], Some(&user[i + 1..]))
    } else {
        (user, None)
    }
}

/// An entry of the passwd file; the ranges are in the bytes of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Passwd {
    pub name: (usize, usize),
    pub uid: u32,
    pub gid: u32,
    pub gecos: (usize, usize),
    pub home: (usize, usize),
}

/// A line of the group file: the name, the gid, the members.
struct GroupLine {
    name: (usize, usize),
    gid: u32,
    members: (usize, usize),
}

/// Where the line at `pos` ends: `end` is the `\n` (or the end of the
/// data), `stop` the end of its text, without the `\r` before the `\n`.
fn line_at(data: &[u8], pos: usize) -> (usize, usize) {
    let mut end = pos;
    while end < data.len() && data[end] != b'\n' {
        end += 1;
    }
    let mut stop = end;
    if end < data.len() && stop > pos && data[stop - 1] == b'\r' {
        stop -= 1;
    }
    (end, stop)
}

/// The places of the first six colons of the line, and how many of them
/// it has (at most six).
fn colons(data: &[u8], start: usize, stop: usize) -> ([usize; 6], usize) {
    let mut cut = [0usize; 6];
    let mut n = 0;
    let mut i = start;
    while i < stop && n < 6 {
        if data[i] == b':' {
            cut[n] = i;
            n += 1;
        }
        i += 1;
    }
    (cut, n)
}

fn passwd_line(data: &[u8], start: usize, stop: usize) -> Option<Passwd> {
    let (cut, n) = colons(data, start, stop);
    if n < 6 {
        return None;
    }
    let uid = parse_id(&data[cut[1] + 1..cut[2]]);
    let gid = parse_id(&data[cut[2] + 1..cut[3]]);
    match (uid, gid) {
        (Some(uid), Some(gid)) => Some(Passwd {
            name: (start, cut[0]),
            uid,
            gid,
            gecos: (cut[3] + 1, cut[4]),
            home: (cut[4] + 1, cut[5]),
        }),
        _ => None,
    }
}

fn group_line(data: &[u8], start: usize, stop: usize) -> Option<GroupLine> {
    if start < stop && data[start] == b'#' {
        return None;
    }
    let (cut, n) = colons(data, start, stop);
    if n < 3 {
        return None;
    }
    let gid = parse_id(&data[cut[1] + 1..cut[2]])?;
    let members_end = if n > 3 { cut[3] } else { stop };
    Some(GroupLine {
        name: (start, cut[0]),
        gid,
        members: (cut[2] + 1, members_end),
    })
}

fn is_text(data: &[u8], range: (usize, usize), text: &[u8]) -> bool {
    &data[range.0..range.1] == text
}

/// The first entry of `passwd` whose name is `name`, or whose uid is `uid`.
pub fn passwd_find(passwd: &[u8], name: Option<&[u8]>, uid: Option<u32>) -> Option<Passwd> {
    let mut pos = 0;
    let mut found = None;
    while pos < passwd.len() && found.is_none() {
        let (end, stop) = line_at(passwd, pos);
        if let Some(e) = passwd_line(passwd, pos, stop) {
            let by_name = match name {
                Some(n) => is_text(passwd, e.name, n),
                None => false,
            };
            if by_name || uid == Some(e.uid) {
                found = Some(e);
            }
        }
        pos = end + 1;
    }
    found
}

/// The entry of the user part of a user string: that of the uid when it
/// is an id, else that of the name.
fn find_user(passwd: &[u8], name: &[u8], id: Option<u32>) -> Option<Passwd> {
    if id.is_some() {
        return passwd_find(passwd, None, id);
    }
    passwd_find(passwd, Some(name), None)
}

/// Whether `passwd` has an entry of the uid.
pub fn has_uid(passwd: &[u8], uid: u32) -> bool {
    passwd_find(passwd, None, Some(uid)).is_some()
}

/// Whether `group` has a group line of the gid.
pub fn has_gid(group: &[u8], gid: u32) -> bool {
    let mut pos = 0;
    let mut found = false;
    while pos < group.len() && !found {
        let (end, stop) = line_at(group, pos);
        if let Some(g) = group_line(group, pos, stop) {
            found = g.gid == gid;
        }
        pos = end + 1;
    }
    found
}

/// The gid of the first group of that name.
fn group_gid(group: &[u8], name: &[u8]) -> Option<u32> {
    let mut pos = 0;
    let mut found = None;
    while pos < group.len() && found.is_none() {
        let (end, stop) = line_at(group, pos);
        if let Some(g) = group_line(group, pos, stop) {
            if is_text(group, g.name, name) {
                found = Some(g.gid);
            }
        }
        pos = end + 1;
    }
    found
}

/// Whether `name` (not empty) is one of the comma separated `members`.
fn is_member(data: &[u8], members: (usize, usize), name: &[u8]) -> bool {
    let mut found = false;
    let mut from = members.0;
    while from <= members.1 && !found {
        let mut to = from;
        while to < members.1 && data[to] != b',' {
            to += 1;
        }
        found = is_text(data, (from, to), name);
        from = to + 1;
    }
    found
}

/// Which group of the request a refusal is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// The `GROUP` of the user string.
    OfUser,
    /// The group of `group_add` at that place.
    Add(usize),
}

/// Why a user is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// An empty user or group in `USER:GROUP`.
    Malformed,
    /// The user is digits that are no id.
    BadUserId,
    /// A name that the passwd file does not have.
    NoUser,
    /// A group of digits that is no id.
    BadGroupId(Group),
    /// A group name that the group file does not have.
    NoGroup(Group),
    /// More than `MAX_GROUPS` groups.
    TooManyGroups,
}

/// What a user is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub uid: u32,
    pub gid: u32,
    /// The home of the entry, in the bytes of the passwd file; none for a
    /// uid the file does not have.
    pub home: Option<(usize, usize)>,
    /// The supplementary groups: the gid first, no gid twice.
    pub gids: Vec<u32>,
}

/// The gid that `g` (a `GROUP` or a `group_add`) names.
fn group_id(group: &[u8], g: &[u8], which: Group) -> Result<u32, Refusal> {
    match parse_id(g) {
        Some(gid) => Ok(gid),
        None if is_digits(g) => Err(Refusal::BadGroupId(which)),
        None => match group_gid(group, g) {
            Some(gid) => Ok(gid),
            None => Err(Refusal::NoGroup(which)),
        },
    }
}

/// Adds `gid` to the list, which `seen` has in order of value (so that
/// whether a gid is in costs a binary search, not a walk): false when the
/// list is full and `gid` is not in it.
fn add_gid(gids: &mut Vec<u32>, seen: &mut Vec<u32>, gid: u32) -> bool {
    let mut lo = 0;
    let mut hi = seen.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if seen[mid] < gid {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo < seen.len() && seen[lo] == gid {
        return true;
    }
    if gids.len() >= MAX_GROUPS {
        return false;
    }
    gids.push(gid);
    if lo == seen.len() {
        seen.push(gid);
    } else {
        seen.insert(lo, gid);
    }
    true
}

/// Adds the gids of the groups of the file that list the name of the
/// entry (if there is one, with a name), in the order of the file: false
/// when the list is full.
fn add_member_groups(
    group: &[u8],
    passwd: &[u8],
    entry: Option<Passwd>,
    gids: &mut Vec<u32>,
    seen: &mut Vec<u32>,
) -> bool {
    let name = match entry {
        Some(e) => e.name,
        None => return true,
    };
    if name.0 >= name.1 {
        return true;
    }
    let who = &passwd[name.0..name.1];
    let mut pos = 0;
    let mut room = true;
    while pos < group.len() && room {
        let (end, stop) = line_at(group, pos);
        if let Some(g) = group_line(group, pos, stop) {
            room = !is_member(group, g.members, who) || add_gid(gids, seen, g.gid);
        }
        pos = end + 1;
    }
    room
}

/// Adds the gids of the groups of `group_add`, in order: why one cannot
/// be, if one cannot.
fn add_groups(
    group: &[u8],
    group_add: &[Vec<u8>],
    gids: &mut Vec<u32>,
    seen: &mut Vec<u32>,
) -> Option<Refusal> {
    let mut refusal = None;
    let mut i = 0;
    while i < group_add.len() && refusal.is_none() {
        refusal = add_group(group, group_add, i, gids, seen);
        i += 1;
    }
    refusal
}

/// Adds the gid that the group of `group_add` at the place `i` names to
/// the list: why it cannot be, if it cannot.
fn add_group(
    group: &[u8],
    group_add: &[Vec<u8>],
    i: usize,
    gids: &mut Vec<u32>,
    seen: &mut Vec<u32>,
) -> Option<Refusal> {
    match group_id(group, &group_add[i], Group::Add(i)) {
        Ok(gid) if add_gid(gids, seen, gid) => None,
        Ok(_) => Some(Refusal::TooManyGroups),
        Err(r) => Some(r),
    }
}

/// The user `user` (rules 3 to 7) with the passwd and group files of the
/// image.  `group_add` are names or ids of more groups (each its own
/// vector: the translator takes no loop over a list of references);
/// `strict` leaves out the groups of the file.
pub fn resolve(
    passwd: &[u8],
    group: &[u8],
    user: &[u8],
    group_add: &[Vec<u8>],
    strict: bool,
) -> Result<Resolved, Refusal> {
    if user.is_empty() {
        resolve_user(passwd, group, b"0", group_add, strict)
    } else {
        resolve_user(passwd, group, user, group_add, strict)
    }
}

/// `resolve` of a user string that is not empty.
fn resolve_user(
    passwd: &[u8],
    group: &[u8],
    user: &[u8],
    group_add: &[Vec<u8>],
    strict: bool,
) -> Result<Resolved, Refusal> {
    let (name, group_part) = split_user(user);
    let own_group = group_part.is_none();
    if name.is_empty() {
        return Err(Refusal::Malformed);
    }
    if let Some(g) = group_part {
        if g.is_empty() {
            return Err(Refusal::Malformed);
        }
    }
    let id = parse_id(name);
    if id.is_none() && is_digits(name) {
        return Err(Refusal::BadUserId);
    }
    let entry = find_user(passwd, name, id);
    let (uid, mut gid, home) = match (entry, id) {
        (Some(e), _) => (e.uid, e.gid, Some(e.home)),
        (None, Some(id)) => (id, 0, None),
        (None, None) => return Err(Refusal::NoUser),
    };
    if let Some(g) = group_part {
        gid = group_id(group, g, Group::OfUser)?;
    }

    let mut gids = vec![gid];
    let mut seen = vec![gid];
    if let Some(r) = add_groups(group, group_add, &mut gids, &mut seen) {
        return Err(r);
    }
    if own_group && !strict && !add_member_groups(group, passwd, entry, &mut gids, &mut seen) {
        return Err(Refusal::TooManyGroups);
    }
    Ok(Resolved {
        uid,
        gid,
        home,
        gids,
    })
}

/// What `HOME` is (rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Home {
    /// The home of the entry.
    Entry,
    /// `/`.
    Root,
    /// The working directory.
    Workdir,
}

/// `HOME` of a process: `home` is that of the entry (none for an unknown
/// uid), `workdir_empty` says the container has no working directory.
pub fn home(home: Option<&[u8]>, workdir_empty: bool) -> Home {
    match home {
        Some(h) => {
            if h.is_empty() {
                Home::Root
            } else {
                Home::Entry
            }
        }
        None if workdir_empty => Home::Root,
        None => Home::Workdir,
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
