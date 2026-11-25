// SPDX-License-Identifier: Apache-2.0
//! The rules of a user, stated on strings and the standard library, the
//! way a person reads the passwd and group files, and not on how `resolve`
//! walks bytes: `model` answers a request in the plainest way, `check`
//! compares and states what holds of every answer.

use super::*;

/// An id: digits, and a number below the kernel's "no id".
fn id(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = s.parse().ok()?;
    u32::try_from(n).ok().filter(|n| *n != u32::MAX)
}

struct Entry<'a> {
    name: &'a str,
    uid: u32,
    gid: u32,
    home: &'a str,
}

fn entries(passwd: &str) -> Vec<Entry<'_>> {
    let mut v = Vec::new();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 7 {
            if let (Some(uid), Some(gid)) = (id(f[2]), id(f[3])) {
                v.push(Entry {
                    name: f[0],
                    uid,
                    gid,
                    home: f[5],
                });
            }
        }
    }
    v
}

/// (name, gid, members) of the group lines.
fn groups(group: &str) -> Vec<(&str, u32, &str)> {
    let mut v = Vec::new();
    for line in group.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 4 {
            if let Some(gid) = id(f[2]) {
                v.push((f[0], gid, f[3]));
            }
        }
    }
    v
}

fn group_of(group: &str, g: &str, which: Group) -> Result<u32, Refusal> {
    if let Some(gid) = id(g) {
        return Ok(gid);
    }
    if g.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::BadGroupId(which));
    }
    groups(group)
        .iter()
        .find(|(name, _, _)| *name == g)
        .map(|(_, gid, _)| *gid)
        .ok_or(Refusal::NoGroup(which))
}

/// What `resolve` must answer, with the home as text.
pub(crate) type Answer = Result<(u32, u32, Option<String>, Vec<u32>), Refusal>;

pub(crate) fn model(passwd: &str, group: &str, user: &str, add: &[&str], strict: bool) -> Answer {
    let user = if user.is_empty() { "0" } else { user };
    let (name, group_part) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    if name.is_empty() || group_part == Some("") {
        return Err(Refusal::Malformed);
    }
    let by_id = id(name);
    if by_id.is_none() && name.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::BadUserId);
    }
    let all = entries(passwd);
    let entry = all.iter().find(|e| match by_id {
        Some(n) => e.uid == n,
        None => e.name == name,
    });
    let (uid, mut gid, home) = match (entry, by_id) {
        (Some(e), _) => (e.uid, e.gid, Some(e.home.to_string())),
        (None, Some(n)) => (n, 0, None),
        (None, None) => return Err(Refusal::NoUser),
    };
    if let Some(g) = group_part {
        gid = group_of(group, g, Group::OfUser)?;
    }
    let mut gids = vec![gid];
    for (i, g) in add.iter().enumerate() {
        let g = group_of(group, g, Group::Add(i))?;
        if !gids.contains(&g) {
            gids.push(g);
        }
    }
    if let (Some(e), None, false) = (entry, group_part, strict) {
        if !e.name.is_empty() {
            for (_, g, members) in groups(group) {
                if members.split(',').any(|m| m == e.name) && !gids.contains(&g) {
                    gids.push(g);
                }
            }
        }
    }
    if gids.len() > MAX_GROUPS {
        return Err(Refusal::TooManyGroups);
    }
    Ok((uid, gid, home, gids))
}

/// `resolve` as the text of `model`.
pub(crate) fn run(passwd: &str, group: &str, user: &str, add: &[&str], strict: bool) -> Answer {
    let add: Vec<Vec<u8>> = add.iter().map(|g| g.as_bytes().to_vec()).collect();
    resolve(
        passwd.as_bytes(),
        group.as_bytes(),
        user.as_bytes(),
        &add,
        strict,
    )
    .map(|r| {
        let home = r.home.map(|(a, b)| passwd[a..b].to_string());
        (r.uid, r.gid, home, r.gids)
    })
}

/// The statements of an answer, and that it is the model's.
pub(crate) fn check(passwd: &str, group: &str, user: &str, add: &[&str], strict: bool) {
    let what = || format!("{passwd:?} {group:?} {user:?} {add:?} {strict}");
    let got = run(passwd, group, user, add, strict);
    assert_eq!(got, model(passwd, group, user, add, strict), "{}", what());
    let Ok((uid, gid, _, gids)) = &got else {
        return;
    };
    // no id of an answer is the kernel's "no id"
    assert!(*uid != u32::MAX && *gid != u32::MAX, "{}", what());
    assert!(!gids.contains(&u32::MAX), "{}", what());
    // the gid is the first group, and no group is twice
    assert_eq!(gids.first(), Some(gid), "{}", what());
    let mut sorted = gids.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), gids.len(), "{}", what());
    // an id given as the user, or as its group, is that id whatever the
    // files say (a number is never a name, and never wraps)
    let (name, group_part) = user
        .split_once(':')
        .map_or((user, None), |(u, g)| (u, Some(g)));
    if let Some(n) = id(name) {
        if !passwd_has(passwd, n) {
            assert_eq!(*uid, n, "{}", what());
        }
    }
    if let Some(n) = group_part.and_then(id) {
        assert_eq!(*gid, n, "{}", what());
    }
}

/// Whether an entry has the uid, for the statement that an unknown one is
/// taken as it is.
fn passwd_has(passwd: &str, uid: u32) -> bool {
    entries(passwd).iter().any(|e| e.uid == uid)
}
