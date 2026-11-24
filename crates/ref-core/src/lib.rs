// SPDX-License-Identifier: Apache-2.0
//! The one grammar of an image reference, `[host/]path[:tag][@digest]`, for
//! every place that reads one: the request to a registry, the blocks of
//! registries.conf, and the identities of the signature policy.  A
//! reference comes from a user or from an image nobody vouched for, and its
//! parts are put in URLs and compared as text, so what a part may hold is
//! decided here, once, on bytes.
//!
//! The rules, for every byte string:
//!
//! 1. `parse` returns, whatever the bytes.
//! 2. What `parse` accepts has parts in the grammar: the host is lower case
//!    labels of letters, digits and dashes with an optional decimal port,
//!    or `[` and lower case hex digits and `:` and `]` with an optional
//!    port; the path is components of lower case letters and digits joined
//!    by `.`, `_`, `__` or dashes; the tag is at most 128 of letters,
//!    digits, `_`, `.`, `-`, not beginning with `.` or `-`; the digest is
//!    `sha256:`, `sha384:` or `sha512:` and as many lower case hex digits
//!    as the hash has.  So no `/`, `?`, `#`, `%`, `@`, `..`, no white space
//!    and no control byte, and no byte over 127, is in a host or in a
//!    component of a path.
//! 3. The first component, up to the first `/`, is the host when it has a
//!    `.` or a `:` or is `localhost`, else it is of the path.  The tag is
//!    after the first `:` of the last component, the digest after the one
//!    `@`.  There is no other way to split a string the grammar accepts.
//! 4. The name (host and path, after `normalize`) is at most 255 bytes, the
//!    string at most 1024, and a string of 64 hex digits is an image id,
//!    not a name.
//! 5. `parse` reads the string as it is written: no white space is
//!    trimmed, no letter is lowered.  `normalize` is the one step that
//!    changes a name: the host `docker.io` where there is none and in
//!    place of `index.docker.io`, and `library/` before a path of one
//!    component of docker.io.
//! 6. `print` of what `normalize` made is a reference that `parse`
//!    accepts, with a host, and that `normalize` leaves as it is.
//!
//! The code is plain loops over bytes and spans, so that Aeneas can
//! translate it (tools/verify): `while i < n && ok` over a flag, no
//! `loop`, no return or `?` in a loop, no closure, no iterator, no method
//! of `str` or `String`, no comparison of an `Option`.  What the host of
//! the IPv6 literal is as an address, and the words of an error, are for
//! the shell.

/// The longest string accepted.
const MAX_INPUT: usize = 1024;
/// The longest name, host and path as `normalize` makes them with the `/`.
const MAX_NAME: usize = 255;
/// The longest tag.
const MAX_TAG: usize = 128;
/// The host that a name without one, and `index.docker.io`, is of.
const HUB: &[u8] = b"docker.io";
const HUB_INDEX: &[u8] = b"index.docker.io";
/// What a path of one component of docker.io is under.
const LIBRARY: &[u8] = b"library/";

/// Where the parts of an accepted reference are.  The host is
/// `s[..host_end]`, none when `host_end` is 0, and the path follows its `/`
/// to `name_end`; the tag and the digest are the ranges, without their `:`
/// and `@`.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub struct Spans {
    pub host_end: usize,
    pub name_end: usize,
    pub tag: Option<(usize, usize)>,
    pub digest: Option<(usize, usize)>,
}

/// What is wrong with a string, with the offset of the first byte of the
/// part that is.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub enum Error {
    Empty,
    TooLong,
    Host(usize),
    Path(usize),
    Tag(usize),
    Digest(usize),
    /// 64 hex digits: an image id.
    Id,
}

/// A name after the defaults of docker.io.
#[cfg_attr(test, derive(Debug, Clone, PartialEq, Eq))]
pub struct Name {
    pub host: Vec<u8>,
    pub path: Vec<u8>,
}

fn is_digit(b: u8) -> bool {
    b.wrapping_sub(b'0') < 10
}

/// A letter or a digit, in lower case.
fn is_alnum(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9')
}

fn is_hex(b: u8) -> bool {
    matches!(b, b'a'..=b'f' | b'0'..=b'9')
}

/// A byte of a tag, which does not begin with `.` or `-`.
fn is_word(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
}

/// The first `b` of `s[from..to]`, or `to`.
fn find(s: &[u8], from: usize, to: usize, b: u8) -> usize {
    let mut i = from;
    while i < to && s[i] != b {
        i += 1;
    }
    i
}

/// The last `b` of `s[from..to]`, if any.
fn find_last(s: &[u8], from: usize, to: usize, b: u8) -> Option<usize> {
    let mut at = None;
    let mut i = from;
    while i < to {
        if s[i] == b {
            at = Some(i);
        }
        i += 1;
    }
    at
}

/// `s[from..to]` is `lit`.
fn is_lit(s: &[u8], from: usize, to: usize, lit: &[u8]) -> bool {
    let mut ok = to - from == lit.len();
    let mut i = 0;
    while ok && i < lit.len() {
        ok = s[from + i] == lit[i];
        i += 1;
    }
    ok
}

/// `s[from..to]` is a host and not a path: it has a `.` or a `:`, or is
/// `localhost`.  (The grammar of what a host is comes after.)
fn host_like(s: &[u8], from: usize, to: usize) -> bool {
    find(s, from, to, b'.') < to
        || find(s, from, to, b':') < to
        || is_lit(s, from, to, b"localhost")
}

/// Whether `first`, the part of a name before its first `/`, is a host.
pub fn looks_like_host(first: &[u8]) -> bool {
    host_like(first, 0, first.len())
}

/// The offset of the first byte that is not a decimal port `s[from..to]`
/// (at least one digit), if any.
fn port_bad(s: &[u8], from: usize, to: usize) -> Option<usize> {
    let mut bad = if from == to { Some(to) } else { None };
    let mut i = from;
    while i < to && bad.is_none() {
        if !is_digit(s[i]) {
            bad = Some(i);
        }
        i += 1;
    }
    bad
}

/// `[` hex digits and colons `]` and a port, in `s[from..to]`.
fn bracket_bad(s: &[u8], from: usize, to: usize) -> Option<usize> {
    let close = find(s, from, to, b']');
    let mut bad = if close == to { Some(to) } else { None };
    if close - from == 1 {
        bad = Some(close);
    }
    let mut i = from + 1;
    while i < close && bad.is_none() {
        if !is_hex(s[i]) && s[i] != b':' {
            bad = Some(i);
        }
        i += 1;
    }
    if bad.is_none() && close + 1 < to {
        if s[close + 1] == b':' {
            bad = port_bad(s, close + 2, to);
        } else {
            bad = Some(close + 1);
        }
    }
    bad
}

/// Labels of lower case letters, digits and dashes (not at either end)
/// joined by `.`, and a port, in `s[from..to]`.
fn domain_bad(s: &[u8], from: usize, to: usize) -> Option<usize> {
    let mut bad = None;
    // the labels end at the colon of the port, if any
    let end = find(s, from, to, b':');
    let mut i = from;
    while i < end && bad.is_none() {
        // a dash is after a letter, a digit or a dash, a dot after a letter or a digit
        if !is_alnum(s[i]) {
            let after_label = i > from && s[i - 1] != b'.';
            let after_alnum = after_label && s[i - 1] != b'-';
            let ok = if s[i] == b'-' {
                after_label
            } else {
                s[i] == b'.' && after_alnum
            };
            if !ok {
                bad = Some(i);
            }
        }
        i += 1;
    }
    if bad.is_some() {
        bad
    } else if end == from || !is_alnum(s[end - 1]) {
        Some(end)
    } else if end < to {
        port_bad(s, end + 1, to)
    } else {
        None
    }
}

/// The first byte of `s[from..to]` that is not a host.
fn host_bad(s: &[u8], from: usize, to: usize) -> Option<usize> {
    if from == to {
        Some(to)
    } else if s[from] == b'[' {
        bracket_bad(s, from, to)
    } else {
        domain_bad(s, from, to)
    }
}

/// The first byte of the component `s[from..to]` that is not a component
/// of a path: lower case letters and digits, joined by one `.`, one or
/// two `_`, or dashes.
fn component_bad(s: &[u8], from: usize, to: usize) -> Option<usize> {
    let mut bad = None;
    if from == to || !is_alnum(s[from]) {
        bad = Some(from);
    } else if !is_alnum(s[to - 1]) {
        bad = Some(to - 1);
    }
    let mut i = from;
    while i < to && bad.is_none() {
        if is_alnum(s[i]) {
            i += 1;
        } else {
            // a run of one separator byte, and a letter or digit after it
            let mut end = i;
            while end < to && s[end] == s[i] {
                end += 1;
            }
            let run = end - i;
            let sep = s[i];
            if sep != b'-' && !(sep == b'.' && run == 1) && !(sep == b'_' && run <= 2) {
                bad = Some(i);
            } else if !is_alnum(s[end]) {
                bad = Some(end);
            }
            i = end;
        }
    }
    bad
}

/// The first byte of `s[from..to]` that is not components joined by `/`.
fn path_bad(s: &[u8], from: usize, to: usize) -> Option<usize> {
    let mut bad = None;
    let mut start = from;
    let mut i = from;
    while i <= to && bad.is_none() {
        if i == to || s[i] == b'/' {
            bad = component_bad(s, start, i);
            start = i + 1;
        }
        i += 1;
    }
    bad
}

/// The first byte of the tag `s[from..to]` that is not in one.
fn tag_bad(s: &[u8], from: usize, to: usize) -> Option<usize> {
    let mut bad = if from == to || !is_word(s[from]) {
        Some(from)
    } else if to - from > MAX_TAG {
        Some(from + MAX_TAG)
    } else {
        None
    };
    let mut i = from;
    while i < to && bad.is_none() {
        if !is_word(s[i]) && s[i] != b'.' && s[i] != b'-' {
            bad = Some(i);
        }
        i += 1;
    }
    bad
}

/// The first byte of the digest `s[from..to]` that is not in one: the
/// algorithm and as many lower case hex digits as its hash has.
fn digest_bad(s: &[u8], from: usize, to: usize) -> Option<usize> {
    let hex = if to - from < 7 {
        0
    } else if is_lit(s, from, from + 7, b"sha256:") {
        64
    } else if is_lit(s, from, from + 7, b"sha384:") {
        96
    } else if is_lit(s, from, from + 7, b"sha512:") {
        128
    } else {
        0
    };
    let mut bad = if hex == 0 {
        Some(from)
    } else if to - from != 7 + hex {
        Some(to)
    } else {
        None
    };
    let mut i = from + 7;
    while i < to && bad.is_none() {
        if !is_hex(s[i]) {
            bad = Some(i);
        }
        i += 1;
    }
    bad
}

/// The host of `s[..host_end]` is docker.io, as written or after `normalize`
/// (none, or `index.docker.io`).
fn is_hub(s: &[u8], host_end: usize) -> bool {
    host_end == 0 || is_lit(s, 0, host_end, HUB) || is_lit(s, 0, host_end, HUB_INDEX)
}

/// Where the path of a reference begins.
fn path_start(spans: &Spans) -> usize {
    if spans.host_end > 0 {
        spans.host_end + 1
    } else {
        0
    }
}

/// `normalize` puts `library/` before the path: docker.io, one component.
fn needs_library(s: &[u8], spans: &Spans) -> bool {
    is_hub(s, spans.host_end) && find(s, path_start(spans), spans.name_end, b'/') == spans.name_end
}

/// The bytes of the name after `normalize`, with its `/`.
fn name_len(s: &[u8], spans: &Spans) -> usize {
    let hub = HUB.len();
    let library = LIBRARY.len();
    let host = if is_hub(s, spans.host_end) {
        hub
    } else {
        spans.host_end
    };
    let prefix = if needs_library(s, spans) { library } else { 0 };
    host + 1 + spans.name_end - path_start(spans) + prefix
}

/// `s` is 64 hex digits.
fn is_id(s: &[u8], spans: &Spans) -> bool {
    let mut ok = spans.name_end == 64
        && spans.host_end == 0
        && spans.tag.is_none()
        && spans.digest.is_none();
    let mut i = 0;
    while ok && i < spans.name_end {
        ok = is_hex(s[i]);
        i += 1;
    }
    ok
}

/// Where the parts of `s` are, or what is wrong with it.
pub fn parse(s: &[u8]) -> Result<Spans, Error> {
    let n = s.len();
    if n == 0 {
        return Err(Error::Empty);
    }
    if n > MAX_INPUT {
        return Err(Error::TooLong);
    }
    let at = find(s, 0, n, b'@');
    // each part is checked before the next is looked for, and each check is a value, so that
    // the translation does not repeat the rest of the function for each way it can go on
    let digest_error = if at < n {
        digest_bad(s, at + 1, n)
    } else {
        None
    };
    if let Some(bad) = digest_error {
        return Err(Error::Digest(bad));
    }
    let digest = if at < n { Some((at + 1, n)) } else { None };
    // the colon of a tag is in the last component: before it is a port
    let last = match find_last(s, 0, at, b'/') {
        Some(slash) => slash + 1,
        None => 0,
    };
    let name_end = find(s, last, at, b':');
    let tag_error = if name_end < at {
        tag_bad(s, name_end + 1, at)
    } else {
        None
    };
    if let Some(bad) = tag_error {
        return Err(Error::Tag(bad));
    }
    let tag = if name_end < at {
        Some((name_end + 1, at))
    } else {
        None
    };
    let first = find(s, 0, name_end, b'/');
    let host_end = if first < name_end && host_like(s, 0, first) {
        first
    } else {
        0
    };
    let host_error = if host_end > 0 {
        host_bad(s, 0, host_end)
    } else {
        None
    };
    if let Some(bad) = host_error {
        return Err(Error::Host(bad));
    }
    let spans = Spans {
        host_end,
        name_end,
        tag,
        digest,
    };
    if let Some(bad) = path_bad(s, path_start(&spans), name_end) {
        return Err(Error::Path(bad));
    }
    if name_len(s, &spans) > MAX_NAME {
        return Err(Error::TooLong);
    }
    if is_id(s, &spans) {
        return Err(Error::Id);
    }
    Ok(spans)
}

/// `s[from..to]` after `out`.
fn append(out: &mut Vec<u8>, s: &[u8], from: usize, to: usize) {
    let mut i = from;
    while i < to {
        out.push(s[i]);
        i += 1;
    }
}

/// The name of an accepted `s` after the defaults of docker.io: a name with
/// no host, or `index.docker.io`, is of `docker.io`, and a path of one
/// component of it is under `library/`.
pub fn normalize(s: &[u8], spans: &Spans) -> Name {
    // locals, so that the translator does not join borrows of a constant
    let hub = HUB;
    let library = LIBRARY;
    let mut host = Vec::new();
    if is_hub(s, spans.host_end) {
        append(&mut host, hub, 0, hub.len());
    } else {
        append(&mut host, s, 0, spans.host_end);
    }
    let mut path = Vec::new();
    if needs_library(s, spans) {
        append(&mut path, library, 0, library.len());
    }
    append(&mut path, s, path_start(spans), spans.name_end);
    Name { host, path }
}

/// The full form of a reference: `host/path`, and `:tag` and `@digest` when
/// there are.
pub fn print(name: &Name, tag: Option<&[u8]>, digest: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    append(&mut out, &name.host, 0, name.host.len());
    out.push(b'/');
    append(&mut out, &name.path, 0, name.path.len());
    if let Some(tag) = tag {
        out.push(b':');
        append(&mut out, tag, 0, tag.len());
    }
    if let Some(digest) = digest {
        out.push(b'@');
        append(&mut out, digest, 0, digest.len());
    }
    out
}

/// Why `s` is not a host, with its port if it has one: the error, at the
/// offset in `s`.
pub fn host_error(s: &[u8]) -> Result<(), Error> {
    match host_bad(s, 0, s.len()) {
        Some(at) => Err(Error::Host(at)),
        None => Ok(()),
    }
}

/// Why `s` is not what a block of registries.conf or a rule of a signature
/// policy can name: a host, or a host and a path (`host/a/b`), as written.
pub fn prefix_error(s: &[u8]) -> Result<(), Error> {
    let first = find(s, 0, s.len(), b'/');
    match host_bad(s, 0, first) {
        Some(at) => Err(Error::Host(at)),
        None if first == s.len() => Ok(()),
        None => match path_bad(s, first + 1, s.len()) {
            Some(at) => Err(Error::Path(at)),
            None => Ok(()),
        },
    }
}

/// `s` is a host, with its port if it has one.
pub fn host_ok(s: &[u8]) -> bool {
    host_bad(s, 0, s.len()).is_none()
}

/// `prefix_error` has no error.
pub fn prefix_ok(s: &[u8]) -> bool {
    match prefix_error(s) {
        Ok(()) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
