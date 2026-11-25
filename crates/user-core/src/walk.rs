// SPDX-License-Identifier: Apache-2.0
//! The requests of a small world, every one of them, and the rules checked
//! on each answer (see `rules`): every passwd file and every group file of
//! up to two lines of a pool that has the shapes of lines that matter
//! (good, short, a bad or empty id, a name of digits, an entry without a
//! name, a comment, a `\r`), every user string of up to three characters of
//! `a`, `1` and `:` and the ids and names at the edges, every `group_add` of
//! up to two of a small set, strict or not.  And the bytes that a string
//! cannot hold.

use super::rules::{check, run};
use super::*;

const PASSWD_LINES: [&str; 12] = [
    "a:x:1:1::/h:/bin/sh\n",
    "a:x:2:2:g:/two:/bin/sh\n",
    "b:x:1:3::/:/bin/sh\n",
    "1:x:7:7::/seven:/bin/sh\n",
    ":x:9:9::/:/bin/sh\n",
    "c:x::1::/h:/bin/sh\n",
    "c:x:4294967295:1::/h:/bin/sh\n",
    "d:x:4:4::/h\n",
    "e:x:5:z::/h:/bin/sh:more\r\n",
    "#f:x:6:6::/h:/bin/sh\n",
    "g:x:0:0:::/bin/sh",
    "99999999999:x:8:8::/h:/bin/sh\n",
];

const GROUP_LINES: [&str; 10] = [
    "g:x:1:a\n",
    "h:x:2:b,a,c\n",
    "i:x:3:\n",
    "j:x:3:a\n",
    "k:x:4\n",
    "l:x:z:a\n",
    "a:x:7:ab,a b,,\n",
    "m:x:4294967295:a\r\n",
    "n:x:5:x:y,a",
    "#o:x:6:a\n",
];

const USERS: [&str; 18] = [
    "",
    "0",
    "007",
    "1x",
    "-1",
    "+1",
    " 1",
    "4294967294",
    "4294967295",
    "4294967296",
    "99999999999",
    "a:g",
    "a:1:2",
    "1:5:",
    "1:4294967295",
    "1:0000000000000000000000000000000001",
    "9:i",
    "#f",
];

const ADDS: [&str; 5] = ["g", "1", "z", "4294967295", "00"];

/// Every sequence of at most `n` of the lines, as the text of a file.
fn files(lines: &[&str], n: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut from = 0;
    for _ in 0..n {
        let to = all.len();
        for i in from..to {
            for l in lines {
                all.push(format!("{}{}", all[i], l));
            }
        }
        from = to;
    }
    all
}

/// The user strings: short ones over `a`, `1` and `:`, and the edges.
fn users() -> Vec<String> {
    let mut all: Vec<String> = USERS.iter().map(|s| s.to_string()).collect();
    let mut level = vec![String::new()];
    for _ in 0..3 {
        let mut next = Vec::new();
        for s in &level {
            for c in ["a", "1", ":"] {
                next.push(format!("{s}{c}"));
            }
        }
        all.extend(next.iter().cloned());
        level = next;
    }
    all
}

/// The `group_add` lists: none, one, or two of them.
fn adds() -> Vec<Vec<&'static str>> {
    let mut all = vec![vec![]];
    for a in ADDS {
        all.push(vec![a]);
        for b in ADDS {
            all.push(vec![a, b]);
        }
    }
    all
}

/// The requests checked.
fn walk() -> usize {
    let passwds = files(&PASSWD_LINES, 2);
    let groups = files(&GROUP_LINES, 2);
    let users = users();
    let adds = adds();
    let mut checked = 0;
    for p in &passwds {
        for g in &groups {
            for u in &users {
                // the lists and the strictness vary on a part of the
                // worlds only, or the walk is a hundred times longer
                for (i, add) in adds.iter().enumerate() {
                    for strict in [false, true] {
                        if i < 3 || (p.len() + g.len() + u.len() + i) % 7 == 0 {
                            check(p, g, u, add, strict);
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    checked
}

#[test]
fn every_request_of_the_small_world() {
    assert!(walk() > 1_000_000);
}

/// Every line of the pool alone, with every user: no file of two lines
/// is needed to see what one line does.
#[test]
fn every_line_against_every_user() {
    for l in PASSWD_LINES {
        for g in GROUP_LINES {
            for u in users() {
                check(l, g, &u, &[], false);
            }
        }
    }
}

/// Bytes that no string holds, and every byte on its own: they are an
/// answer or a refusal, and one that does not read a byte as another.
#[test]
fn bytes_that_are_no_text() {
    let nul = b"a\0b:x:1:1::/h\0:/bin/sh\n";
    assert_eq!(passwd_find(nul, Some(b"a"), None), None);
    assert!(passwd_find(nul, Some(b"a\0b"), None).is_some());
    // a name of bytes that are no UTF-8 matches the same bytes only
    let raw = b"\xff\xfe:x:3:3::/\xc3:/bin/sh\n";
    assert!(resolve(raw, b"", b"\xff\xfe", &[], false).is_ok());
    assert_eq!(
        resolve(raw, b"", "\u{fffd}\u{fffd}".as_bytes(), &[], false),
        Err(Refusal::NoUser)
    );
    let r = resolve(raw, b"", b"3", &[], false).unwrap();
    assert_eq!(r.home.map(|(a, b)| &raw[a..b]), Some(&b"/\xc3"[..]));
    for byte in 0..=255u8 {
        let one = [byte];
        let line = [&b"x:x:1:1::"[..], &one, b":/s\n"].concat();
        let _ = resolve(&line, &line, &one, &[one.to_vec()], false);
        let _ = resolve(&line, &line, &[b"1:", &one[..]].concat(), &[], true);
    }
}

/// A group line that starts with `#` is a comment: no group, no gid, no
/// membership; a passwd line that starts with `#` is a line like another.
#[test]
fn a_group_comment_is_no_group() {
    let group = b"#c:x:5:a\nreal:x:6:a\n";
    assert!(!has_gid(group, 5) && has_gid(group, 6));
    assert_eq!(
        resolve(b"", group, b"1:c", &[], false),
        Err(Refusal::NoGroup(Group::OfUser))
    );
    let r = resolve(b"a:x:1:1::/:/s\n", group, b"a", &[], false).unwrap();
    assert_eq!(r.gids, [1, 6]);
    assert!(has_uid(b"#a:x:9:1::/:/s\n", 9));
}

/// An entry with no name is in no group, not even one with an empty
/// member.
#[test]
fn an_entry_with_no_name_is_in_no_group() {
    let passwd = b":x:9:9::/:/bin/sh\n";
    let group = b"empty:x:3:\nhole:x:4:a,,b\n";
    let got = resolve(passwd, group, b"9", &[], false).unwrap();
    assert_eq!(got.gids, [9]);
}

#[test]
fn ids_at_the_edges() {
    for (s, want) in [
        ("0", Some(0)),
        ("4294967294", Some(4294967294)),
        ("4294967295", None),
        ("4294967296", None),
        ("18446744073709551616", None),
        (
            "00000000000000000000000000000000000000000000000000",
            Some(0),
        ),
        (
            "000000000000000000000000000000000000000000000000005",
            Some(5),
        ),
        ("42949672950", None),
        ("", None),
        ("-0", None),
        ("+0", None),
        ("0x1", None),
        ("１", None),
    ] {
        assert_eq!(parse_id(s.as_bytes()), want, "{s}");
    }
    // a uid that wraps is no root
    let got = resolve(b"", b"", b"4294967296", &[], false);
    assert_eq!(got, Err(Refusal::BadUserId));
    let got = resolve(b"", b"", b"0:4294967296", &[], false);
    assert_eq!(got, Err(Refusal::BadGroupId(Group::OfUser)));
}

/// Large files are linear: a passwd of 16 MiB of lines, and a group file
/// that lists the user in every one of 400000 groups, answer at once; the
/// list of groups stops at `MAX_GROUPS`, and a gid listed again is not a
/// group more.
#[test]
fn huge_files() {
    let mut passwd = Vec::new();
    while passwd.len() < 16 << 20 {
        passwd.extend_from_slice(b"u:x:1:1:");
        passwd.extend_from_slice(&[b'g'; 100]);
        passwd.extend_from_slice(b":/h:/bin/sh\n");
    }
    passwd.extend_from_slice(b"last:x:5:5::/last:/bin/sh\n");
    let got = resolve(&passwd, b"", b"last", &[], false).unwrap();
    assert_eq!(got.uid, 5);

    let mut many = Vec::new();
    for i in 0..400_000u32 {
        many.extend_from_slice(format!("g{i}:x:{}:last\n", i % 100_000).as_bytes());
    }
    assert_eq!(
        resolve(&passwd, &many, b"last", &[], false),
        Err(Refusal::TooManyGroups)
    );
    assert!(resolve(&passwd, &many, b"last", &[], true).is_ok());
    // 65535 other groups and the gid make 65536: the limit
    let mut some = Vec::new();
    for i in 0..65_535u32 {
        some.extend_from_slice(format!("g{i}:x:{}:last,x\n", i + 100).as_bytes());
    }
    for _ in 0..5000 {
        some.extend_from_slice(b"d:x:100:last\n");
    }
    let got = resolve(&passwd, &some, b"last", &[], false).unwrap();
    assert_eq!(got.gids.len(), MAX_GROUPS);
    some.extend_from_slice(b"one-more:x:3:last\n");
    assert_eq!(
        resolve(&passwd, &some, b"last", &[], false),
        Err(Refusal::TooManyGroups)
    );
    // one line of 16 MiB without a colon, or of colons only
    let line = vec![b'a'; 16 << 20];
    assert_eq!(
        resolve(&line, &line, b"a", &[], false),
        Err(Refusal::NoUser)
    );
    let colons = vec![b':'; 16 << 20];
    assert_eq!(
        resolve(&colons, &colons, b"a", &[], false),
        Err(Refusal::NoUser)
    );
}

/// A long `group_add` is a loop, not a deep stack: a gid named again is
/// no group more, and the gid and 65535 others are the limit.
#[test]
fn a_long_list_of_added_groups() {
    let again = vec![b"7".to_vec(); 1_000_000];
    let got = resolve(b"", b"", b"0", &again, false).unwrap();
    assert_eq!(got.gids, [0, 7]);
    // the largest gid so far goes at the end of the sorted list
    let names: Vec<Vec<u8>> = (1..=65_536u32)
        .map(|i| i.to_string().into_bytes())
        .collect();
    let got = resolve(b"", b"", b"0", &names[..65_535], false).unwrap();
    assert_eq!(got.gids.len(), MAX_GROUPS);
    assert_eq!(got.gids.last(), Some(&65_535));
    assert_eq!(
        resolve(b"", b"", b"0", &names, false),
        Err(Refusal::TooManyGroups)
    );
    // the same ids from the largest down: each goes at the front
    let down: Vec<Vec<u8>> = names[..65_535].iter().rev().cloned().collect();
    let got = resolve(b"", b"", b"0", &down, false).unwrap();
    assert_eq!(got.gids.len(), MAX_GROUPS);
}

#[test]
fn a_line_without_a_final_newline_is_a_line() {
    assert_eq!(
        run("a:x:1:2::/h:/s", "", "a", &[], false),
        Ok((1, 2, Some("/h".into()), vec![2]))
    );
}

#[test]
fn what_home_is() {
    assert_eq!(home(Some(b""), false), Home::Root);
    assert_eq!(home(Some(b"/h"), true), Home::Entry);
    assert_eq!(home(None, true), Home::Root);
    assert_eq!(home(None, false), Home::Workdir);
}
