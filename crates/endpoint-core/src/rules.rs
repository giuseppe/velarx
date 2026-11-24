// SPDX-License-Identifier: Apache-2.0
//! The rules of the endpoints (see the head of the crate), checked on the
//! answer of `endpoints` for given blocks and a given reference.  They are
//! stated by a reference written with the string methods of the standard
//! library, not by how `endpoints` computes: the block of a name, its
//! primary, its mirrors, and what each may do.

use super::*;

/// What a caller sees of an endpoint.
pub type Seen = (String, String, bool, bool, bool);

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn seen(e: &Endpoint) -> Seen {
    (
        text(&e.host),
        text(&e.path),
        e.insecure,
        e.allow_private,
        e.by_digest,
    )
}

/// Whether the prefix `prefix` governs `name`.  An empty prefix governs
/// nothing.
pub fn governs_ref(prefix: &str, name: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    if let Some(domain) = prefix.strip_prefix("*.") {
        let host = name.split(['/', '@']).next().unwrap();
        let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
        return host
            .strip_suffix(domain)
            .is_some_and(|front| front.ends_with('.'));
    }
    match name.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => rest.starts_with(['/', '@']),
        None => false,
    }
}

/// The block of `name`: of the blocks that govern it the longest prefix,
/// the first of the longest.
fn block_ref(blocks: &[Block], name: &str) -> Option<usize> {
    let governing: Vec<usize> = (0..blocks.len())
        .filter(|&i| governs_ref(&text(&blocks[i].prefix), name))
        .collect();
    let longest = governing.iter().map(|&i| blocks[i].prefix.len()).max()?;
    governing
        .into_iter()
        .find(|&i| blocks[i].prefix.len() == longest)
}

/// `host/path` as an endpoint: the Hub under its API host; no `/`, no
/// repository.
fn endpoint_ref(at: &str, flags: [bool; 3]) -> Result<Seen, Refused> {
    let (host, path) = at.split_once('/').ok_or(Refused::NoRepository)?;
    let host = if host == "docker.io" {
        "registry-1.docker.io"
    } else {
        host
    };
    let [insecure, private, by_digest] = flags;
    Ok((
        host.to_string(),
        path.to_string(),
        insecure,
        private,
        by_digest,
    ))
}

/// The endpoints of the reference, or whether it is refused.
fn expected(blocks: &[Block], host: &str, path: &str, ask: &Ask) -> Result<Vec<Seen>, Refused> {
    let name = format!("{host}/{path}");
    let Some(b) = block_ref(blocks, &name) else {
        let insecure = !ask.tls_verify;
        return Ok(vec![endpoint_ref(&name, [insecure, false, false])?]);
    };
    let block = &blocks[b];
    if block.blocked {
        return Err(Refused::Blocked);
    }
    let prefix = text(&block.prefix);
    let insecure = !ask.tls_verify || block.insecure;
    let private = block.allow_private;
    let at = match (&block.location, name.strip_prefix(&prefix)) {
        (Some(location), Some(rest)) => format!("{}{rest}", text(location)),
        _ => name.clone(),
    };
    let primary = endpoint_ref(&at, [insecure, private, false])?;
    let mut all = Vec::new();
    for m in block.mirrors.iter().filter(|_| !ask.push) {
        let serves = match m.mode {
            Mode::All => true,
            Mode::DigestOnly => ask.has_digest,
            Mode::TagOnly => !ask.has_digest,
        };
        let location = text(&m.location);
        let there = if prefix.starts_with("*.") {
            match name.split_once('/') {
                Some((_, rest)) => format!("{location}/{rest}"),
                None => location,
            }
        } else {
            format!("{location}{}", name.strip_prefix(&prefix).unwrap())
        };
        if !serves {
            continue;
        }
        let own = block_ref(blocks, &there);
        // (a mirror that is blocked is not used)
        if own.is_some_and(|o| blocks[o].blocked) {
            continue;
        }
        let private = private || own.is_some_and(|o| blocks[o].allow_private);
        let by_digest = matches!(m.mode, Mode::DigestOnly);
        let insecure = m.insecure || !ask.tls_verify;
        let e = endpoint_ref(&there, [insecure, private, by_digest])?;
        if e.0 != primary.0 || e.1 != primary.1 {
            all.push(e);
        }
    }
    all.push(primary);
    Ok(all)
}

/// The rules hold for `blocks` and the reference `host/path` asked as `ask`.
pub fn check(blocks: &[Block], host: &str, path: &str, ask: &Ask) {
    let note = format!("{blocks:?}, {host}/{path}, {ask:?}");
    let name = format!("{host}/{path}");
    assert_eq!(
        select(blocks, name.as_bytes()),
        block_ref(blocks, &name),
        "{note}"
    );
    let made = endpoints(blocks, host.as_bytes(), path.as_bytes(), ask);
    let want = expected(blocks, host, path, ask);
    let got: Result<Vec<Seen>, Refused> = made
        .as_ref()
        .map(|all| all.iter().map(seen).collect())
        .map_err(|e| *e);
    assert_eq!(got, want, "{note}");
    if let (Ok(all), Ok(made)) = (&got, &made) {
        // the credentials of the command line are for the host that was named
        let named = if host == "docker.io" {
            "registry-1.docker.io"
        } else {
            host
        };
        for (e, seen) in made.iter().zip(all) {
            assert_eq!(e.creds == Creds::CommandLine, seen.0 == named, "{note}");
        }
        // the registry itself is the last, and a push has it alone
        assert!(!all.is_empty(), "{note}");
        assert!(!ask.push || all.len() == 1, "{note}");
        // every endpoint is insecure when the user said not to verify
        assert!(ask.tls_verify || all.iter().all(|e| e.2), "{note}");
        // the registry itself has the flags of its block, if it has one
        let primary = all.last().unwrap();
        let block = block_ref(blocks, &name).map(|b| &blocks[b]);
        let own = block.is_some_and(|b| b.insecure);
        assert_eq!(primary.2, own || !ask.tls_verify, "{note}");
        assert_eq!(primary.3, block.is_some_and(|b| b.allow_private), "{note}");
        // and the mirrors are those of the block only
        let mirrors = block.map_or(0, |b| b.mirrors.len());
        assert!(all.len() <= mirrors + 1, "{note}");
    }
}

/// A port is not the end of a host: a prefix of the host does not govern
/// the host on a port, one that names the port does, and the longest of
/// the prefixes that govern wins.
#[test]
fn a_colon_is_not_a_boundary() {
    let block = |prefix: &str| Block {
        prefix: prefix.as_bytes().to_vec(),
        location: None,
        insecure: false,
        blocked: false,
        allow_private: false,
        mirrors: Vec::new(),
    };
    let blocks = [block("a.test"), block("a.test:5000"), block("*.test")];
    let of = |name: &str| select(&blocks, name.as_bytes());
    assert_eq!(of("a.test/x"), Some(0));
    assert_eq!(of("a.test:5000/x"), Some(1));
    assert_eq!(of("a.test:5/x"), Some(2));
    assert_eq!(of("a.test:5000"), Some(1));
    assert_eq!(of("b.test:5000/x"), Some(2));
    assert_eq!(of("a.test.evil/x"), None);
}

/// Two inputs the reader of the configuration never makes: an empty prefix
/// governs nothing, and a wildcard governs a host with an empty label.
#[test]
fn the_edges_of_a_prefix() {
    let block = |prefix: &str| Block {
        prefix: prefix.as_bytes().to_vec(),
        location: None,
        insecure: false,
        blocked: false,
        allow_private: false,
        mirrors: Vec::new(),
    };
    let blocks = [block(""), block("*.test")];
    let of = |name: &str| select(&blocks, name.as_bytes());
    assert!(!governs_ref("", "/x"));
    assert!(!governs_ref("", "@x"));
    assert!(!governs_ref("", ""));
    assert_eq!(of("/x"), None);
    assert_eq!(of("@x"), None);
    assert!(governs_ref("*.test", ".test/x"));
    assert_eq!(of(".test/x"), Some(1));
}

/// The credentials of the command line go to the endpoints on the host that
/// was named, a mirror on the same host included, and not to a registry that
/// a location moved to another host, nor to a mirror on another one.
#[test]
fn command_line_credentials_go_to_the_host_that_was_named() {
    let block = |prefix: &str, location: Option<&str>, mirrors: &[&str]| Block {
        prefix: prefix.as_bytes().to_vec(),
        location: location.map(|l| l.as_bytes().to_vec()),
        insecure: false,
        blocked: false,
        allow_private: false,
        mirrors: mirrors
            .iter()
            .map(|l| Mirror {
                location: l.as_bytes().to_vec(),
                insecure: false,
                mode: Mode::All,
            })
            .collect(),
    };
    let ask = Ask {
        has_digest: false,
        push: false,
        tls_verify: true,
    };
    let who = |blocks: &[Block], host: &str| -> Vec<(String, bool)> {
        let all = endpoints(blocks, host.as_bytes(), b"x", &ask).ok().unwrap();
        all.iter()
            .map(|e| (text(&e.host), e.creds == Creds::CommandLine))
            .collect()
    };
    let t = |s: &str, b: bool| (s.to_string(), b);
    // a mirror on the same host (another path) and on another host
    let blocks = [block("a.test", None, &["a.test/m", "m.test"])];
    assert_eq!(
        who(&blocks, "a.test"),
        [t("a.test", true), t("m.test", false), t("a.test", true)]
    );
    // the registry moved to another host has none; the Hub is one host
    let blocks = [
        block("a.test", Some("internal.test"), &[]),
        block("docker.io", None, &["docker.io/m"]),
    ];
    assert_eq!(who(&blocks, "a.test"), [t("internal.test", false)]);
    assert_eq!(
        who(&blocks, "docker.io"),
        [
            t("registry-1.docker.io", true),
            t("registry-1.docker.io", true)
        ]
    );
}

/// A mirror is insecure by its own entry only, never by a block; it may
/// reach private addresses by the block of its own location or the block
/// that lists it.
#[test]
fn a_mirror_has_its_own_flags() {
    let block = |prefix: &str, flags: u8, mirror: &[&str]| Block {
        prefix: prefix.as_bytes().to_vec(),
        location: None,
        insecure: flags & 1 != 0,
        blocked: false,
        allow_private: flags & 2 != 0,
        mirrors: mirror
            .iter()
            .map(|l| Mirror {
                location: l.as_bytes().to_vec(),
                insecure: *l == "n.test",
                mode: Mode::All,
            })
            .collect(),
    };
    // a.test is insecure and may reach private addresses; it lists m.test
    // (no block), n.test (insecure by its entry), b.test (a block of its
    // own that may reach them) and c.test (a block that is insecure)
    let blocks = [
        block("a.test", 3, &["m.test", "n.test", "b.test", "c.test"]),
        block("b.test", 2, &[]),
        block("c.test", 1, &[]),
        block("d.test", 0, &["e.test"]),
        block("e.test", 2, &[]),
    ];
    let ask = Ask {
        has_digest: false,
        push: false,
        tls_verify: true,
    };
    let flags = |host: &str| -> Vec<(String, bool, bool)> {
        let all = endpoints(&blocks, host.as_bytes(), b"x", &ask)
            .ok()
            .unwrap();
        all.iter()
            .map(|e| (text(&e.host), e.insecure, e.allow_private))
            .collect()
    };
    let f = |h: &str, i: bool, p: bool| (h.to_string(), i, p);
    assert_eq!(
        flags("a.test"),
        [
            f("m.test", false, true),
            f("n.test", true, true),
            f("b.test", false, true),
            f("c.test", false, true),
            f("a.test", true, true),
        ]
    );
    // the block that lists the mirror does not allow it; the mirror's own does
    assert_eq!(
        flags("d.test"),
        [f("e.test", false, true), f("d.test", false, false)]
    );
}

/// A mirror for digests only is asked by the digest, the others are not.
#[test]
fn a_digest_only_mirror_is_asked_by_the_digest() {
    let mirror = |mode| Mirror {
        location: b"m.test/z".to_vec(),
        insecure: false,
        mode,
    };
    let block = Block {
        prefix: b"a.test".to_vec(),
        location: None,
        insecure: false,
        blocked: false,
        allow_private: false,
        mirrors: vec![
            mirror(Mode::All),
            mirror(Mode::TagOnly),
            mirror(Mode::DigestOnly),
        ],
    };
    let ask = |has_digest| Ask {
        has_digest,
        push: false,
        tls_verify: true,
    };
    let by = |has_digest| -> Vec<bool> {
        let all = endpoints(
            std::slice::from_ref(&block),
            b"a.test",
            b"x",
            &ask(has_digest),
        );
        all.ok().unwrap().iter().map(|e| e.by_digest).collect()
    };
    // with a digest: the mirror for all, the one for digests (by it), the registry
    assert_eq!(by(true), [false, true, false]);
    // without: the mirror for all, the one for tags, the registry
    assert_eq!(by(false), [false, false, false]);
}

/// A location without a path where the name is the prefix leaves no
/// repository: an error, for the registry and for a mirror, and a mirror
/// that is blocked is skipped, whatever its location.
#[test]
fn a_name_without_a_repository_is_refused_and_a_blocked_mirror_skipped() {
    let block = |prefix: &str, location: Option<&str>, blocked: bool, mirrors: &[&str]| Block {
        prefix: prefix.as_bytes().to_vec(),
        location: location.map(|l| l.as_bytes().to_vec()),
        insecure: false,
        blocked,
        allow_private: false,
        mirrors: mirrors
            .iter()
            .map(|l| Mirror {
                location: l.as_bytes().to_vec(),
                insecure: false,
                mode: Mode::All,
            })
            .collect(),
    };
    let ask = Ask {
        has_digest: false,
        push: false,
        tls_verify: true,
    };
    let at = |blocks: &[Block], path: &str| -> Result<Vec<String>, Refused> {
        let all = endpoints(blocks, b"docker.io", path.as_bytes(), &ask)?;
        Ok(all
            .iter()
            .map(|e| format!("{}/{}", text(&e.host), text(&e.path)))
            .collect())
    };
    let moved = [block(
        "docker.io/library/alpine",
        Some("internal"),
        false,
        &[],
    )];
    assert_eq!(at(&moved, "library/alpine"), Err(Refused::NoRepository));
    assert_eq!(
        at(&moved, "library/alpine/x"),
        Ok(vec!["internal/x".to_string()])
    );
    let mirrored = [block(
        "docker.io/library/alpine",
        None,
        false,
        &["cache.test"],
    )];
    assert_eq!(at(&mirrored, "library/alpine"), Err(Refused::NoRepository));
    // a prefix without a path leaves a repository to every name
    let hub = [block("docker.io", Some("internal"), false, &["cache.test"])];
    assert_eq!(
        at(&hub, "library/alpine"),
        Ok(vec![
            "cache.test/library/alpine".to_string(),
            "internal/library/alpine".to_string()
        ])
    );
    // a blocked mirror is skipped, even when it has no path
    let blocked = [
        block("docker.io/library/alpine", None, false, &["b.test"]),
        block("b.test", None, true, &[]),
    ];
    assert_eq!(
        at(&blocked, "library/alpine"),
        Ok(vec!["registry-1.docker.io/library/alpine".to_string()])
    );
}
