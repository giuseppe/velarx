// SPDX-License-Identifier: Apache-2.0
//! The keys, hosts and repositories of small worlds, every one of them, and
//! the rules checked on each answer (see `rules`): every key of up to five
//! bytes of a small alphabet against hosts that have a port, the names of
//! the Hub, a common prefix, and every repository of up to three bytes;
//! every list of up to three keys of a pool of the shapes that matter;
//! and every string of a small alphabet, and every scheme before every
//! shape of key, through `normalize`.

use super::rules::{check_normalize, check_pick};
use super::*;

const HOSTS: [&str; 9] = [
    "a",
    "a:5",
    "a:",
    "b",
    "a.b",
    "docker.io",
    "index.docker.io",
    "registry-1.docker.io",
    "docker.io:5",
];

/// Every string of up to `most` bytes of `alphabet`.
fn every(alphabet: &[u8], most: usize) -> Vec<String> {
    let mut all = vec![String::new()];
    let mut from = 0;
    for _ in 0..most {
        let to = all.len();
        for i in from..to {
            for b in alphabet {
                let s = format!("{}{}", all[i], *b as char);
                all.push(s);
            }
        }
        from = to;
    }
    all
}

fn repos() -> Vec<String> {
    every(b"ab/", 3)
}

#[test]
fn every_small_key_against_every_host_and_repository() {
    let repos = repos();
    for key in every(b"ab:/.", 5) {
        for host in HOSTS {
            for repo in &repos {
                check_pick(&[(&key, &key)], host, repo);
            }
        }
    }
}

/// The keys of a file that matter: the host, the host with a port, a
/// namespace, a repository, a name that only starts like the host, the
/// forms of the Hub, and what is not a registry.
const POOL: [&str; 14] = [
    "a",
    "a:5",
    "a/a",
    "a/a/b",
    "a/ab",
    "ab",
    "a.b",
    "b",
    "docker.io",
    "docker.io/a",
    "docker.io:5",
    "s3://a",
    "a.b/a",
    "a/",
];

#[test]
fn every_list_of_keys_picks_the_most_specific() {
    let repos = repos();
    let mut lists: Vec<Vec<(&str, &str)>> = vec![Vec::new()];
    for a in POOL.map(|k| (k, k)) {
        lists.push(vec![a]);
        for b in POOL.map(|k| (k, k)) {
            lists.push(vec![a, b]);
            for c in POOL.map(|k| (k, k)) {
                lists.push(vec![a, b, c]);
            }
        }
    }
    for keys in &lists {
        for host in HOSTS {
            for repo in &repos {
                check_pick(keys, host, repo);
            }
        }
    }
}

/// The keys of a file that name the same host in different ways, each as
/// it is kept and as it was written.
const WRITTEN: [(&str, &str); 8] = [
    ("docker.io", "docker.io"),
    ("docker.io", "index.docker.io"),
    ("docker.io", "https://index.docker.io/v1/"),
    ("docker.io", "registry-1.docker.io"),
    ("docker.io/a", "docker.io/a"),
    ("docker.io/a", "docker.io/a/"),
    ("a", "a"),
    ("a", "a/"),
];

#[test]
fn of_equal_keys_the_one_written_as_it_is_kept_wins() {
    let repos = repos();
    let mut lists: Vec<Vec<(&str, &str)>> = vec![Vec::new()];
    for a in WRITTEN {
        lists.push(vec![a]);
        for b in WRITTEN {
            lists.push(vec![a, b]);
            for c in WRITTEN {
                lists.push(vec![a, b, c]);
            }
        }
    }
    for keys in &lists {
        for host in HOSTS {
            for repo in &repos {
                check_pick(keys, host, repo);
            }
        }
    }
}

#[test]
fn every_string_of_the_separators_normalizes() {
    for key in every(b"a:/?#A", 6) {
        check_normalize(&key);
    }
}

#[test]
fn every_scheme_before_every_shape_of_key_normalizes() {
    let schemes = [
        "",
        "https://",
        "http://",
        "HTTPS://",
        "Http://",
        "s3://",
        "S3://",
        "ftp:/",
        "://",
        "x://",
        "index.docker.io/a://",
        "docker.io/A://",
    ];
    let bodies = [
        "",
        "a",
        "A",
        "a/",
        "a//",
        "a/b",
        "a/b/",
        "a?b",
        "a#b",
        "a:5/",
        "a:5/b",
        "docker.io/v1/",
        "index.docker.io/v1/",
        "registry-1.docker.io/library",
        "u@a/",
        "a@b/c",
        "/a",
        "a://b",
    ];
    for s in schemes {
        for b in bodies {
            for t in ["", "/", "//"] {
                check_normalize(&format!("{s}{b}{t}"));
            }
        }
    }
}

/// What the rules do not say by themselves: the keys that look like the
/// host of a request and are not.
#[test]
fn a_key_that_looks_like_the_host_is_not_it() {
    let host = "registry.example.com";
    for key in [
        "registry.example.com.evil.org",
        "registry.example.comx",
        "xregistry.example.com",
        "evil.org/registry.example.com",
        "registry.example.com:5000",
        "Registry.Example.com",
        "registry.example.com@evil.org",
        "registry.example.com\\@evil.org",
        "https://registry.example.com",
        "registry.example.com/",
        "registry.example.com//",
    ] {
        assert!(
            matches(key.as_bytes(), host.as_bytes(), b"ns/repo").is_none(),
            "{key}"
        );
    }
    // the keys with nothing of a host are the empty key, for no host
    assert_eq!(normalize(b"/"), b"");
    assert_eq!(normalize(b"https://"), b"");
    // a key of another scheme keeps its `://`, even with nothing after it
    assert_eq!(normalize(b"S3:///"), b"s3://");
    assert_eq!(normalize(b"index.docker.io/a://"), b"index.docker.io/a://");
    // a key with userinfo, once normalized, is the userinfo and the host
    let got = normalize(b"https://good@evil.org/");
    assert_eq!(got, b"good@evil.org");
    assert!(matches(&got, b"evil.org", b"x").is_none());
    assert!(matches(&got, b"good", b"x").is_none());
    // the namespace of a key is a path component
    assert!(matches(b"example.com/ns", b"example.com", b"nsx/repo").is_none());
    assert_eq!(
        matches(b"example.com/ns", b"example.com", b"ns/repo"),
        Some(14)
    );
    assert_eq!(matches(b"example.com/ns", b"example.com", b"ns"), Some(14));
    assert!(matches(b"example.com/ns", b"example.com", b"").is_none());
    // the Hub in its three forms, and its key in Docker's URL form
    let key = normalize(b"https://index.docker.io/v1/");
    assert_eq!(key, b"docker.io");
    for host in ["docker.io", "index.docker.io", "registry-1.docker.io"] {
        assert!(matches(&key, host.as_bytes(), b"library/alpine").is_some());
    }
    assert!(matches(&key, b"docker.io.evil.org", b"x").is_none());
}
