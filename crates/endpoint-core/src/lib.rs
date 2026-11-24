// SPDX-License-Identifier: Apache-2.0
//! Which registries a reference is fetched from.  The blocks of
//! registries.conf say, for a name `host/path`, where it really is (the
//! `location` of the block), which other registries have it (the mirrors)
//! and what each may do (`insecure`, `allow_private`, `blocked`); the
//! answer is the list of endpoints to try, in order, each with its own
//! flags.
//!
//! The shell reads the TOML into [`Block`]s, in file order, and the
//! reference into its host and path (both as bytes, the host with its port
//! if it has one); it makes the URLs, finds the credentials and sends the
//! requests.
//!
//! The rules, for every blocks and every reference (see `rules`):
//!
//! 1. Nothing panics, whatever the bytes.
//! 2. The block of a name is the longest prefix that governs it (the first
//!    of equals); a prefix governs a name that is it or goes on after a
//!    boundary (`/` or `@`), a prefix `*.domain` the names of the
//!    subdomains of `domain`.  A `:` is not a boundary: a name has no tag,
//!    so it is a port, and a prefix `example.com` does not govern
//!    `example.com:5000` (a prefix that names the port does).
//! 3. A name governed by a block that is `blocked` has no endpoints
//!    ([`Refused::Blocked`]), for a push too.
//! 4. The primary, the registry itself, is the last endpoint: the name with
//!    the prefix of the block replaced by its `location`.  A push has the
//!    primary only.
//! 5. The mirrors come first, in the order of the block, each at its
//!    location with the name rewritten; one that is the primary is
//!    dropped; a mirror for digests only is there only for a reference
//!    with a digest, one for tags only only for a reference without.
//! 6. An endpoint is insecure when `tls_verify` is off or its own entry
//!    (the block for the primary, the mirror for a mirror) says so: never
//!    because of another entry.  An endpoint may reach private addresses
//!    when its own block says so, or, for a mirror, the block that lists
//!    it (the administrator wrote the mirror there); a mirror with neither
//!    may not, and the block of the registry it mirrors does not make it
//!    insecure.
//! 7. A host `docker.io` is `registry-1.docker.io`.
//! 8. A mirror for digests only is asked by the digest ([`Endpoint::by_digest`]),
//!    whatever the algorithm of the digest: never by a tag, which is not
//!    what the digest names.  Nothing else is.
//! 9. A mirror whose own block is `blocked` is not an endpoint, and a
//!    rewrite that leaves no repository (the name that is a prefix, and a
//!    location without a path) is an error for the name, for the registry
//!    and for a mirror ([`Refused::NoRepository`]): nothing is ignored
//!    silently.
//! 10. The credentials of the command line ([`Creds::CommandLine`]) are for
//!     the endpoints on the host the user named, and for no other: a mirror
//!     on another host, or a registry that a `location` moved to another
//!     host, has the credentials stored for it, if any, and the realm of its
//!     token is its own business.
//!
//! Written to be translated (tools/verify): plain structs, index loops with
//! flags, no closure, no iterator adapter, and small functions that take the
//! blocks and an index rather than a borrow of a block.

/// When a mirror is used.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub enum Mode {
    All,
    DigestOnly,
    TagOnly,
}

/// A `[[registry.mirror]]` of a block, its `pull-from-mirror` settled (its
/// own, else the block's).
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone)]
pub struct Mirror {
    pub location: Vec<u8>,
    pub insecure: bool,
    pub mode: Mode,
}

/// A `[[registry]]` block, its prefix settled (the location when it has no
/// prefix).
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone)]
pub struct Block {
    pub prefix: Vec<u8>,
    pub location: Option<Vec<u8>>,
    pub insecure: bool,
    pub blocked: bool,
    pub allow_private: bool,
    pub mirrors: Vec<Mirror>,
}

/// What is asked of the endpoints.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub struct Ask {
    pub has_digest: bool,
    pub push: bool,
    pub tls_verify: bool,
}

/// Whose credentials an endpoint may be given.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub enum Creds {
    /// those stored for its host, and those the user gave on the command line
    CommandLine,
    /// those stored for its host
    Stored,
}

/// A registry to try: where, and what it may do.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone)]
pub struct Endpoint {
    pub host: Vec<u8>,
    pub path: Vec<u8>,
    pub insecure: bool,
    pub allow_private: bool,
    pub creds: Creds,
    /// The manifest is asked by its digest, not by its tag
    pub by_digest: bool,
}

/// Why a name has no endpoints.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub enum Refused {
    /// its block is `blocked`
    Blocked,
    /// the location of its block, or of a mirror, leaves no repository
    NoRepository,
}

fn same(a: &[u8], b: &[u8]) -> bool {
    let mut equal = a.len() == b.len();
    let mut i = 0;
    while i < a.len() && equal {
        equal = a[i] == b[i];
        i += 1;
    }
    equal
}

fn starts_with(name: &[u8], prefix: &[u8]) -> bool {
    let mut yes = prefix.len() <= name.len();
    let mut i = 0;
    while i < prefix.len() && yes {
        yes = name[i] == prefix[i];
        i += 1;
    }
    yes
}

fn ends_with(name: &[u8], suffix: &[u8]) -> bool {
    let mut yes = suffix.len() <= name.len();
    let mut i = 0;
    while i < suffix.len() && yes {
        yes = name[name.len() - suffix.len() + i] == suffix[i];
        i += 1;
    }
    yes
}

/// The bytes of `a` from `from`.
fn tail(a: &[u8], from: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = from;
    while i < a.len() {
        out.push(a[i]);
        i += 1;
    }
    out
}

/// `a` and `b` one after the other.
fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = tail(a, 0);
    let mut i = 0;
    while i < b.len() {
        out.push(b[i]);
        i += 1;
    }
    out
}

/// The place of the first `/` of `name`, or its length.
fn slash(name: &[u8]) -> usize {
    let mut i = 0;
    while i < name.len() && name[i] != b'/' {
        i += 1;
    }
    i
}

fn wildcard(prefix: &[u8]) -> bool {
    prefix.len() >= 2 && prefix[0] == b'*' && prefix[1] == b'.'
}

/// Whether the prefix of the block number `b` governs `name`.
fn governs(blocks: &[Block], b: usize, name: &[u8]) -> bool {
    let prefix = &blocks[b].prefix;
    if wildcard(prefix) {
        // the host of the name, without its port
        let mut end = 0;
        while end < name.len() && name[end] != b'/' && name[end] != b'@' {
            end += 1;
        }
        let mut port = end;
        let mut i = 0;
        while i < end {
            if name[i] == b':' {
                port = i;
            }
            i += 1;
        }
        let domain = tail(prefix, 2);
        let host = tail(&name[..port], 0);
        return host.len() > domain.len()
            && ends_with(&host, &domain)
            && host[host.len() - domain.len() - 1] == b'.';
    }
    let mut yes = starts_with(name, prefix);
    if yes && name.len() > prefix.len() {
        let next = name[prefix.len()];
        yes = next == b'/' || next == b'@';
    }
    yes
}

/// The length of the prefix of the block number `i`.
fn prefix_len(blocks: &[Block], i: usize) -> usize {
    blocks[i].prefix.len()
}

/// The block of `name`: the longest prefix that governs it, the first of
/// equals.
pub fn select(blocks: &[Block], name: &[u8]) -> Option<usize> {
    let mut best = None;
    let mut best_len = 0;
    let mut i = 0;
    while i < blocks.len() {
        let len = prefix_len(blocks, i);
        if len > best_len && governs(blocks, i, name) {
            best = Some(i);
            best_len = len;
        }
        i += 1;
    }
    best
}

/// `host` as the endpoint says it: the Hub under its API host.
fn folded(host: &[u8]) -> Vec<u8> {
    if same(host, b"docker.io") {
        tail(b"registry-1.docker.io", 0)
    } else {
        tail(host, 0)
    }
}

/// The endpoint for `host` and `path`; `typed` is the host of the reference.
fn endpoint(
    host: &[u8],
    path: &[u8],
    insecure: bool,
    allow_private: bool,
    typed: &[u8],
) -> Endpoint {
    let host = folded(host);
    let creds = if same(&host, &folded(typed)) {
        Creds::CommandLine
    } else {
        Creds::Stored
    };
    Endpoint {
        host,
        path: tail(path, 0),
        insecure,
        allow_private,
        creds,
        by_digest: false,
    }
}

/// The endpoint at `name` (`host/path`), if it has a repository.
fn at(name: &[u8], insecure: bool, allow_private: bool, typed: &[u8]) -> Option<Endpoint> {
    let i = slash(name);
    if i == name.len() {
        return None;
    }
    Some(endpoint(
        &name[..i],
        &name[i + 1..],
        insecure,
        allow_private,
        typed,
    ))
}

/// The name `name`, governed by `block`, at the location of its mirror
/// number `mirror`: the prefix, or for a wildcard prefix the host, is
/// replaced.
fn moved(blocks: &[Block], b: usize, mirror: usize, name: &[u8]) -> Vec<u8> {
    let block = &blocks[b];
    let location = &block.mirrors[mirror].location;
    if wildcard(&block.prefix) {
        let i = slash(name);
        if i == name.len() {
            return tail(location, 0);
        }
        return join(location, &name[i..]);
    }
    if starts_with(name, &block.prefix) {
        return join(location, &name[block.prefix.len()..]);
    }
    tail(name, 0)
}

// The small functions below take the blocks and an index, not a borrow of
// a block: the translator cannot join the branches of a function that
// hold a borrow into a vector.

/// Whether a mirror of `mode` serves a reference with or without a digest.
fn serves(mode: Mode, has_digest: bool) -> bool {
    match mode {
        Mode::All => true,
        Mode::DigestOnly => has_digest,
        Mode::TagOnly => !has_digest,
    }
}

/// The name `name`, governed by `block`, where the registry of the block
/// has it: at its `location` if it has one, else where it is.
fn registered(blocks: &[Block], b: usize, name: &[u8]) -> Vec<u8> {
    let block = &blocks[b];
    match &block.location {
        Some(location) if starts_with(name, &block.prefix) => {
            join(location, &name[block.prefix.len()..])
        }
        _ => tail(name, 0),
    }
}

/// Whether the block number `found`, if there is one, is `blocked`.
fn blocked(blocks: &[Block], found: Option<usize>) -> bool {
    match found {
        Some(b) => blocks[b].blocked,
        None => false,
    }
}

/// Whether the block number `found`, if there is one, has `allow_private`.
fn allows_private(blocks: &[Block], found: Option<usize>) -> bool {
    match found {
        Some(b) => blocks[b].allow_private,
        None => false,
    }
}

/// Whether the request turned the verification of TLS off.
fn unverified(ask: &Ask) -> bool {
    !ask.tls_verify
}

/// The mode of the mirror number `m` of the block number `b`.
fn mirror_mode(blocks: &[Block], b: usize, m: usize) -> Mode {
    blocks[b].mirrors[m].mode
}

/// Whether the mirror number `m` of the block number `b` is `insecure`.
fn mirror_insecure(blocks: &[Block], b: usize, m: usize) -> bool {
    blocks[b].mirrors[m].insecure
}

/// The endpoint of the mirror number `m` of the block `b` for `name`, if
/// the mirror is used.  Its flags are its own: `insecure` is its entry's
/// (or the request's); it may reach private addresses if the block of its
/// own location says so, or the block that lists it (the administrator
/// wrote it there).
fn mirrored(
    blocks: &[Block],
    b: usize,
    m: usize,
    name: &[u8],
    host: &[u8],
    ask: &Ask,
) -> Result<Option<Endpoint>, Refused> {
    let mode = mirror_mode(blocks, b, m);
    if !serves(mode, ask.has_digest) {
        return Ok(None);
    }
    let insecure = mirror_insecure(blocks, b, m) || unverified(ask);
    let there = moved(blocks, b, m, name);
    let own = select(blocks, &there);
    // (a mirror that is blocked is not used)
    if blocked(blocks, own) {
        return Ok(None);
    }
    let private = blocks[b].allow_private || allows_private(blocks, own);
    let Some(mut e) = at(&there, insecure, private, host) else {
        return Err(Refused::NoRepository);
    };
    e.by_digest = matches!(mode, Mode::DigestOnly);
    Ok(Some(e))
}

/// The endpoints for the name `host/path`, in the order to try them: the
/// mirrors, then the registry.
pub fn endpoints(
    blocks: &[Block],
    host: &[u8],
    path: &[u8],
    ask: &Ask,
) -> Result<Vec<Endpoint>, Refused> {
    let name = join(&join(host, b"/"), path);
    let found = select(blocks, &name);
    let mut insecure = unverified(ask);
    let mut allow_private = false;
    let mut at_block = tail(&name, 0);
    if let Some(b) = found {
        if blocks[b].blocked {
            return Err(Refused::Blocked);
        }
        insecure = insecure || blocks[b].insecure;
        allow_private = blocks[b].allow_private;
        at_block = registered(blocks, b, &name);
    }
    let Some(primary) = at(&at_block, insecure, allow_private, host) else {
        return Err(Refused::NoRepository);
    };
    let mut out = Vec::new();
    if let Some(b) = found {
        let count = blocks[b].mirrors.len();
        let mut i = 0;
        while i < count && !ask.push {
            let mirror = mirrored(blocks, b, i, &name, host, ask)?;
            if let Some(e) = mirror {
                let same_host = same(&e.host, &primary.host);
                let same_path = same(&e.path, &primary.path);
                if !same_host || !same_path {
                    out.push(e);
                }
            }
            i += 1;
        }
    }
    out.push(primary);
    Ok(out)
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
