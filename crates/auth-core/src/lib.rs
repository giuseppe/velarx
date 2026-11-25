// SPDX-License-Identifier: Apache-2.0
//! Which credential of an auth file (`auths`, `credHelpers`) a request to
//! a registry carries.  The keys are text a user or a tool wrote, the host
//! and the repository come from a reference nobody vouched for, so what a
//! key may match is decided here, once, on bytes, for every place that
//! looks: pull, push, login and logout, the token request, the mirrors, the
//! credentials a client hands to the engine.
//!
//! The rules, for every key, host and repository:
//!
//! 1. Nothing here panics, whatever the bytes.
//! 2. A credential is never for a host other than the one its key names:
//!    a key matches only a host that is its first component (the text up to
//!    its first `/`) byte for byte.  No prefix (`r.io` is not `r.io.evil`,
//!    nor `xr.io`), no sub-domain, no folding of case, no port (`r.io` is
//!    not `r.io:5000` and the other way round), no scheme, no user
//!    information: a key that has one is the text of another host, which
//!    no reference has.
//! 3. The one name Docker Hub has three ways is one host: `docker.io`,
//!    `index.docker.io` and `registry-1.docker.io` are `docker.io`, in a
//!    key and in the host of a request; with a port they are not.
//! 4. A key with a path (`r.io/ns/repo`) is for the repositories whose
//!    path begins with that path, by whole components: `r.io/ns` is for
//!    `ns` and `ns/x`, not for `nsx`; a key with a path is for no request
//!    that has no repository.
//! 5. The most specific key wins: of the keys that match, the longest (the
//!    full repository, then each parent namespace, then the host, as
//!    containers/image looks them up); of equal ones, a key that was
//!    written as it is kept (`docker.io`, not `index.docker.io`), then the
//!    later in the list.
//! 6. The key of a helper (`credHelpers`) is the host alone, as
//!    [`exact`] says: a key with a path, or another host, is no helper of
//!    this one.
//! 7. A key is written [`normalize`]d: a scheme `https://` or `http://`
//!    (in any case) and what follows the host go (`https://index.docker.io/v1/` is
//!    `docker.io`), a trailing `/` goes, and the Hub is `docker.io`.  A key
//!    of another scheme (`s3://bucket`, the destination of a transport) has
//!    its scheme and its authority in lower case and its path as written,
//!    and keeps its `://` (`s3:///` is `s3://`), so it is never the key of
//!    a registry, which has none.  `normalize` of a normalized key is the
//!    same key.
//!
//! The code is plain loops over bytes, so that Aeneas can translate it
//! (tools/verify): `while` with a flag, no `loop`, no return or `?` in a
//! loop, no closure, no iterator, no `String`, no reference inside a
//! list.  What the shell keeps: the files, the decoding of `auth`, the
//! helpers and the words of the errors.

/// The host the names of Docker Hub are.
const HUB: &[u8] = b"docker.io";

/// `a` and `b` are the same bytes.
fn same(a: &[u8], b: &[u8]) -> bool {
    let mut equal = a.len() == b.len();
    let mut i = 0;
    while equal && i < a.len() {
        equal = a[i] == b[i];
        i += 1;
    }
    equal
}

/// `b` in lower case (ASCII only).
#[allow(clippy::manual_range_contains)] // (`contains` is a library call the proofs would model)
fn lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

/// `a` is `lit` (in lower case) but for the case of its letters.
fn same_lower(a: &[u8], lit: &[u8]) -> bool {
    let mut equal = a.len() == lit.len();
    let mut i = 0;
    while equal && i < a.len() {
        equal = lower(a[i]) == lit[i];
        i += 1;
    }
    equal
}

/// `s[at..]` begins with `lit`.
fn has(s: &[u8], at: usize, lit: &[u8]) -> bool {
    let mut ok = at <= s.len() && s.len() - at >= lit.len();
    let mut i = 0;
    while ok && i < lit.len() {
        ok = s[at + i] == lit[i];
        i += 1;
    }
    ok
}

/// `s[at]` is `b`.
fn at_is(s: &[u8], at: usize, b: u8) -> bool {
    at < s.len() && s[at] == b
}

/// The first `b` of `s[from..to]`, or `to`.
fn find(s: &[u8], from: usize, to: usize, b: u8) -> usize {
    let mut i = from;
    while i < to && s[i] != b {
        i += 1;
    }
    i
}

/// The start of the first `://` of `s`.
fn find_scheme(s: &[u8]) -> Option<usize> {
    let mut at = None;
    let mut i = 0;
    while at.is_none() && i < s.len() {
        if has(s, i, b"://") {
            at = Some(i);
        }
        i += 1;
    }
    at
}

/// `s` in lower case, appended to `out`.
fn push_lower(out: &mut Vec<u8>, s: &[u8]) {
    let mut i = 0;
    while i < s.len() {
        out.push(lower(s[i]));
        i += 1;
    }
}

/// `host` is a name of Docker Hub other than `docker.io` (rule 3).
pub fn hub_alias(host: &[u8]) -> bool {
    same(host, b"index.docker.io") || same(host, b"registry-1.docker.io")
}

/// The host of a request as a key names it: the names of the Hub are
/// `docker.io`.
fn registry(host: &[u8]) -> &[u8] {
    if hub_alias(host) {
        HUB
    } else {
        host
    }
}

/// A key of `auths` as it is kept (rule 7).
pub fn normalize(key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let sep = find_scheme(key);
    let web = match sep {
        Some(i) => same_lower(&key[..i], b"https") || same_lower(&key[..i], b"http"),
        None => false,
    };
    let after = match sep {
        Some(i) => i + 3,
        None => 0,
    };
    // the `/` at the end go, but not the `://` of a scheme
    let mut end = key.len();
    while end > after && key[end - 1] == b'/' {
        end -= 1;
    }
    if sep.is_some() && !web {
        let mut stop = after;
        while stop < end && !matches!(key[stop], b'/' | b'?' | b'#') {
            stop += 1;
        }
        push_lower(&mut out, &key[..after - 3]);
        out.extend_from_slice(b"://");
        push_lower(&mut out, &key[after..stop]);
        out.extend_from_slice(&key[stop..end]);
    } else {
        // a key with an http(s) scheme is Docker's URL form: its path is not kept
        let stop = if web {
            find(key, after, end, b'/')
        } else {
            end
        };
        let slash = find(key, after, stop, b'/');
        out.extend_from_slice(registry(&key[after..slash]));
        if slash < stop {
            out.extend_from_slice(&key[slash..stop]);
        }
    }
    out
}

/// How specific `key` (normalized) is for the repository `repo` of `host`,
/// none when it is not for it (rules 2 to 4): the length of the key, so
/// that of two keys the one with more of the path is the more specific.
pub fn matches(key: &[u8], host: &[u8], repo: &[u8]) -> Option<usize> {
    let host = registry(host);
    let mut ok = has(key, 0, host) && (key.len() == host.len() || at_is(key, host.len(), b'/'));
    if ok && key.len() > host.len() {
        // the path of the key is the beginning of the repository, by whole
        // components
        let path = &key[host.len() + 1..];
        ok = !repo.is_empty()
            && has(repo, 0, path)
            && (repo.len() == path.len() || at_is(repo, path.len(), b'/'));
    }
    if ok {
        Some(key.len())
    } else {
        None
    }
}

/// A key of the auth file: its normalized text and the text it was
/// written as.
pub struct Key {
    pub kept: Vec<u8>,
    pub written: Vec<u8>,
}

/// How specific the key number `i` is for the request, none if it is not for
/// it (`matches`).
fn rank_of(keys: &[Key], i: usize, host: &[u8], repo: &[u8]) -> Option<usize> {
    matches(&keys[i].kept, host, repo)
}

/// The key number `i` was written as it is kept.
fn is_kept(keys: &[Key], i: usize) -> bool {
    same(&keys[i].kept, &keys[i].written)
}

/// The key of `keys` for the repository `repo` of `host`: the most specific
/// that matches (rule 5), its place in the list.  Of equal keys the one
/// written as it is kept wins, then the later.
pub fn pick(keys: &[Key], host: &[u8], repo: &[u8]) -> Option<usize> {
    let mut best = None;
    let mut best_rank = 0;
    let mut best_kept = false;
    let mut i = 0;
    while i < keys.len() {
        if let Some(rank) = rank_of(keys, i, host, repo) {
            let kept = is_kept(keys, i);
            if best.is_none() || rank > best_rank || (rank == best_rank && (kept || !best_kept)) {
                best = Some(i);
                best_rank = rank;
                best_kept = kept;
            }
        }
        i += 1;
    }
    best
}

/// The first key of `keys` (normalized) that is `host` and nothing else
/// (rule 6).
pub fn exact(keys: &[Vec<u8>], host: &[u8]) -> Option<usize> {
    let host = registry(host);
    let mut found = None;
    let mut i = 0;
    while found.is_none() && i < keys.len() {
        if same(&keys[i], host) {
            found = Some(i);
        }
        i += 1;
    }
    found
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
