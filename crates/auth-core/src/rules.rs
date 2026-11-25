// SPDX-License-Identifier: Apache-2.0
//! The rules of the keys (see the head of the crate), stated on strings
//! and the standard library, the way a person reads a key, and not on how
//! the bytes are walked: `model_*` answers in the plainest way, `check_*`
//! compares and states what holds of every answer.

use super::*;

/// The key as its first component (up to the first `/`) and the
/// components of its path, if it has one.
fn parts(key: &str) -> (&str, Option<Vec<&str>>) {
    match key.split_once('/') {
        Some((host, path)) => (host, Some(path.split('/').collect())),
        None => (key, None),
    }
}

fn hub_of(host: &str) -> &str {
    match host {
        "index.docker.io" | "registry-1.docker.io" => "docker.io",
        h => h,
    }
}

/// Whether `key` is for the repository `repo` of `host`: its first
/// component is the host, and its path, if any, is the beginning of the
/// path of the repository by whole components.
pub fn model_matches(key: &str, host: &str, repo: &str) -> bool {
    let (khost, kpath) = parts(key);
    if khost != hub_of(host) {
        return false;
    }
    match kpath {
        None => true,
        Some(path) => {
            let repo: Vec<&str> = if repo.is_empty() {
                Vec::new()
            } else {
                repo.split('/').collect()
            };
            path.len() <= repo.len() && repo[..path.len()] == path[..]
        }
    }
}

/// The place of the longest of the matching keys; of equals the one
/// written as it is kept, then the later.  A key is (kept, written).
pub fn model_pick(keys: &[(&str, &str)], host: &str, repo: &str) -> Option<usize> {
    let order = |(k, w): (&str, &str)| (k.len(), k == w);
    let mut best: Option<usize> = None;
    for (i, key) in keys.iter().enumerate() {
        if model_matches(key.0, host, repo) && best.is_none_or(|b| order(keys[b]) <= order(*key)) {
            best = Some(i);
        }
    }
    best
}

/// A key as it is kept, as the string methods say it: a key in Docker's
/// URL form (an http or https scheme) is the host, the other schemes are
/// in lower case up to the end of the authority and keep their `://`, the
/// Hub is `docker.io`.
pub fn model_normalize(key: &str) -> String {
    if let Some((scheme, rest)) = key.split_once("://") {
        if !matches!(scheme.to_ascii_lowercase().as_str(), "https" | "http") {
            let rest = rest.trim_end_matches('/');
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let (authority, tail) = rest.split_at(end);
            return format!(
                "{}://{}{tail}",
                scheme.to_ascii_lowercase(),
                authority.to_ascii_lowercase()
            );
        }
    }
    let (rest, scheme) = match key.split_once("://") {
        Some((scheme, r)) if matches!(scheme.to_ascii_lowercase().as_str(), "https" | "http") => {
            (r, true)
        }
        _ => (key, false),
    };
    let rest = rest.trim_end_matches('/');
    let rest = if scheme {
        rest.split('/').next().unwrap_or(rest)
    } else {
        rest
    };
    match rest.split_once('/') {
        Some((host, path)) => format!("{}/{path}", hub_of(host)),
        None => hub_of(rest).to_string(),
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

/// What holds of `matches` and `pick` for these keys (each the kept text
/// and the text it was written as), this host and this repository.  `host`
/// has no `/`.
pub fn check_pick(keys: &[(&str, &str)], host: &str, repo: &str) {
    let bytes: Vec<Key> = keys
        .iter()
        .map(|(k, w)| Key {
            kept: k.as_bytes().to_vec(),
            written: w.as_bytes().to_vec(),
        })
        .collect();
    for (k, _) in keys {
        let got = matches(k.as_bytes(), host.as_bytes(), repo.as_bytes());
        let want = model_matches(k, host, repo);
        assert_eq!(got.is_some(), want, "{k:?} {host:?} {repo:?}");
        if let Some(rank) = got {
            assert_eq!(rank, k.len());
            // 2: the host of the key is the host, byte for byte
            let first = k.split('/').next().unwrap();
            assert_eq!(first, hub_of(host), "{k:?} is for {host:?}");
        }
        // an empty key is for no host
        if k.is_empty() && !host.is_empty() {
            assert!(got.is_none(), "{host:?}");
        }
    }
    let got = pick(&bytes, host.as_bytes(), repo.as_bytes());
    assert_eq!(
        got,
        model_pick(keys, host, repo),
        "{keys:?} {host:?} {repo:?}"
    );
    if let Some(i) = got {
        // 5: nothing that matches is more specific, and of the equally
        // specific ones, if this was not written as it is kept, none was
        for (k, w) in keys {
            if model_matches(k, host, repo) {
                assert!(k.len() <= keys[i].0.len());
                if k.len() == keys[i].0.len() && k == w {
                    assert_eq!(keys[i].0, keys[i].1, "{keys:?} {host:?} {repo:?}");
                }
            }
        }
    }
    // 6: a helper is the host and nothing else
    let plain: Vec<Vec<u8>> = keys.iter().map(|(k, _)| k.as_bytes().to_vec()).collect();
    let want = keys.iter().position(|(k, _)| *k == hub_of(host));
    assert_eq!(exact(&plain, host.as_bytes()), want, "{keys:?} {host:?}");
}

/// What holds of `normalize` of this key.
pub fn check_normalize(key: &str) {
    let got = normalize(key.as_bytes());
    assert_eq!(text(&got), model_normalize(key), "{key:?}");
    // 7: a normalized key is kept as it is
    assert_eq!(normalize(&got), got, "{key:?}");
    // a key that is a registry (no scheme left) never ends with `/`
    if !text(&got).contains("://") {
        assert!(!got.ends_with(b"/"), "{key:?}");
    }
    // a key of a scheme other than http(s) keeps its `://`
    if let Some((scheme, _)) = key.split_once("://") {
        if !matches!(scheme.to_ascii_lowercase().as_str(), "https" | "http") {
            assert!(text(&got).contains("://"), "{key:?}");
        }
    }
}
