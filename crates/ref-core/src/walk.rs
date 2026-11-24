// SPDX-License-Identifier: Apache-2.0
//! The strings of small worlds, every one of them, and the rules checked
//! on each answer (see `rules`): every string up to a length over a
//! small alphabet that has a byte of each class and of each separator; the
//! same with a digest after it (right, short, upper case, a second `@`);
//! the bounds on each side; the table of references that the three readers
//! of an image name disagreed on; and the strings made of every host,
//! path, tag and digest of a list, which all must be accepted.

use super::rules::verify;
use super::*;

/// The bytes of each class: a letter, an upper case letter, a digit, the
/// separators of a name, a bracket, white space, a byte that no URL part
/// holds, a NUL and a byte over 127.
const ALPHABET: &[u8] = b"aA0._-:/@[] %\0\x80";
/// Without the rarer ones, for the longer strings.
const SMALL: &[u8] = b"a.-:/@A[]0";

const D256: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Every string of up to `most` bytes of `alphabet`: how many, how many
/// accepted.
fn every(alphabet: &[u8], most: usize, tail: &[u8]) -> (u64, u64) {
    let (mut cases, mut accepted) = (0, 0);
    let mut s = Vec::new();
    fn walk(alphabet: &[u8], most: usize, tail: &[u8], s: &mut Vec<u8>, n: &mut (u64, u64)) {
        let mut whole = s.clone();
        whole.extend_from_slice(tail);
        n.0 += 1;
        n.1 += u64::from(verify(&whole));
        if s.len() < most {
            for b in alphabet {
                s.push(*b);
                walk(alphabet, most, tail, s, n);
                s.pop();
            }
        }
    }
    let mut n = (0, 0);
    walk(alphabet, most, tail, &mut s, &mut n);
    cases += n.0;
    accepted += n.1;
    (cases, accepted)
}

#[test]
fn every_string_of_five_bytes() {
    let (cases, accepted) = every(ALPHABET, 5, b"");
    // 1 + 15 + 15^2 + ... + 15^5
    assert_eq!(cases, 813_616);
    assert_eq!(accepted, 1064);
}

#[test]
fn every_string_of_six_bytes_of_few() {
    let (cases, accepted) = every(SMALL, 6, b"");
    assert_eq!(cases, 1_111_111);
    assert_eq!(accepted, 3270);
}

/// A prefix, as registries.conf and a policy write it: every string of up
/// to five bytes, and where the error of one that is not is.
#[test]
fn every_prefix_of_five_bytes() {
    use super::rules::prefix_spec;
    fn walk(s: &mut Vec<u8>, accepted: &mut u32) {
        let ok = prefix_ok(s);
        assert_eq!(ok, prefix_spec(s), "{s:?}");
        match prefix_error(s) {
            Ok(()) => assert!(ok),
            Err(Error::Host(at)) | Err(Error::Path(at)) => assert!(!ok && at <= s.len()),
            Err(_) => panic!("{s:?}"),
        }
        *accepted += u32::from(ok);
        if s.len() < 5 {
            for b in ALPHABET {
                s.push(*b);
                walk(s, accepted);
                s.pop();
            }
        }
    }
    let mut accepted = 0;
    walk(&mut Vec::new(), &mut accepted);
    assert_eq!(accepted, 452);
    // where the error is, in the string
    assert!(matches!(prefix_error(b"Quay.io"), Err(Error::Host(0))));
    assert!(matches!(prefix_error(b"quay.io/a/B"), Err(Error::Path(10))));
    assert!(matches!(prefix_error(b"a.io/a//b"), Err(Error::Path(7))));
}

/// What follows the name: the digests of the three algorithms, and what is
/// not one.
fn tails() -> Vec<String> {
    let hex = |n: usize| "0123456789abcdef".repeat(n / 16);
    vec![
        format!("@{D256}"),
        format!("@sha384:{}", hex(96)),
        format!("@sha512:{}", hex(128)),
        format!("@sha256:{}", hex(62)),
        format!("@sha256:{}", hex(64).to_uppercase()),
        format!("@sha256:{}", hex(80)),
        format!("@md5:{}", hex(32)),
        format!("@{D256}@{D256}"),
        format!("@@{D256}"),
        "@".to_string(),
    ]
}

#[test]
fn every_string_of_four_bytes_with_a_digest_after_it() {
    let (mut cases, mut accepted) = (0, 0);
    for tail in tails() {
        let (c, a) = every(ALPHABET, 4, tail.as_bytes());
        cases += c;
        accepted += a;
    }
    assert_eq!(cases, 10 * 54_241);
    assert_eq!(accepted, 570);
}

/// The bounds, each side of each.
#[test]
fn the_bounds_each_side() {
    let a = |n: usize| "a".repeat(n);
    let accepts = |s: String| parse(s.as_bytes()).is_ok();
    // host and path as they are after the defaults of docker.io
    assert!(accepts(format!("quay.io/{}", a(247))));
    assert!(!accepts(format!("quay.io/{}", a(248))));
    assert!(accepts(a(237)) && !accepts(a(238)));
    assert!(accepts(format!("docker.io/{}", a(237))));
    assert!(!accepts(format!("docker.io/{}", a(238))));
    assert!(
        accepts(format!("docker.io/b/{}", a(243))) && !accepts(format!("docker.io/b/{}", a(244)))
    );
    assert!(accepts(format!("{}.io/x", a(250))) && !accepts(format!("{}.io/x", a(251))));
    // a tag
    assert!(accepts(format!("a:{}", a(128))) && !accepts(format!("a:{}", a(129))));
    // the whole string
    assert!(!accepts(format!("a/{}", ["b"; 600].join("/"))));
    assert!(!accepts(format!("a@{D256}{}", a(1024))));
    // an image id, with a digit less or more, or with a part more
    let id = "0123456789abcdef".repeat(4);
    assert!(parse(id.as_bytes()).is_err());
    assert!(accepts(id[1..].to_string()) && accepts(format!("{id}0")));
    assert!(accepts(format!("{id}:t")) && accepts(format!("x/{id}")));
}

fn show(s: &str) -> String {
    match parse(s.as_bytes()) {
        Err(_) => "error".to_string(),
        Ok(spans) => {
            let name = normalize(s.as_bytes(), &spans);
            let tag = spans.tag.map(|(a, b)| &s.as_bytes()[a..b]);
            let digest = spans.digest.map(|(a, b)| &s.as_bytes()[a..b]);
            String::from_utf8(print(&name, tag, digest)).unwrap()
        }
    }
}

/// The inputs on which the three readers of a name (the request to a
/// registry, registries.conf, the signature policy) disagreed, and what
/// the one reader makes of each: the full form after the defaults of
/// docker.io, or an error.
#[test]
fn the_table_of_the_three_readers() {
    let d1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    let hex = |n: usize| "ab".repeat(n);
    let table: Vec<(String, String)> = vec![
        ("x".into(), "docker.io/library/x".into()),
        ("x:tag".into(), "docker.io/library/x:tag".into()),
        ("x:5000".into(), "docker.io/library/x:5000".into()),
        ("x:5000/y".into(), "x:5000/y".into()),
        ("localhost/x".into(), "localhost/x".into()),
        ("docker.io/alpine".into(), "docker.io/library/alpine".into()),
        ("index.docker.io/a/b".into(), "docker.io/a/b".into()),
        ("docker.io/a.b/c".into(), "docker.io/a.b/c".into()),
        ("Quay.IO/a/b".into(), "error".into()),
        ("Foo/bar".into(), "error".into()),
        ("quay.io/a..b".into(), "error".into()),
        ("quay.io/a--_b".into(), "error".into()),
        ("quay.io/a___b".into(), "error".into()),
        (":5000/x".into(), "error".into()),
        ("a.b:abc/x".into(), "error".into()),
        ("a..b/x".into(), "error".into()),
        ("a.-b/x".into(), "error".into()),
        ("[::1]:5000/a".into(), "[::1]:5000/a".into()),
        ("quay.io//a".into(), "error".into()),
        ("a/".into(), "error".into()),
        ("/a".into(), "error".into()),
        ("a:".into(), "error".into()),
        ("a:.x".into(), "error".into()),
        ("../x".into(), "error".into()),
        ("%2f".into(), "error".into()),
        ("?".into(), "error".into()),
        ("#".into(), "error".into()),
        ("quay.io/a b".into(), "error".into()),
        ("quay.io/a\0b".into(), "error".into()),
        ("quay.io/caf\u{e9}".into(), "error".into()),
        (format!("quay.io/a:{}", "t".repeat(129)), "error".into()),
        (format!("quay.io/a:t@{D256}"), format!("quay.io/a:t@{D256}")),
        (format!("quay.io/a:b c@{D256}"), "error".into()),
        (format!("x@y@{D256}"), "error".into()),
        (format!("a@{d1}@{D256}"), "error".into()),
        (format!("h.io@evil.com/a@{D256}"), "error".into()),
        (" alpine\n".into(), "error".into()),
        ("a".repeat(258), "error".into()),
        ("a".repeat(255), "error".into()),
        (format!("quay.io/{}", "a".repeat(255)), "error".into()),
        (format!("{}.io/x", "a".repeat(252)), "error".into()),
        ("0123456789abcdef".repeat(4), "error".into()),
        (
            format!("a@sha384:{}", hex(48)),
            format!("docker.io/library/a@sha384:{}", hex(48)),
        ),
        (format!("a@foo:{}", "z".repeat(32)), "error".into()),
        (format!("a@sha256:{}", "A".repeat(64)), "error".into()),
        ("a@sha256:abc".into(), "error".into()),
        ("alpine@".into(), "error".into()),
        (
            format!("quay.io/a:v1@sha512:{}", hex(64)),
            format!("quay.io/a:v1@sha512:{}", hex(64)),
        ),
    ];
    assert_eq!(table.len(), 48);
    for (input, expected) in &table {
        assert_eq!(show(input), *expected, "{input:?}");
        verify(input.as_bytes());
    }
}

/// Every string made of a host (or none), a path, a tag (or none) and a
/// digest (or none) of the lists is accepted, and its parts are where it
/// was made.
#[test]
fn every_string_of_the_grammar_is_accepted() {
    let hosts = [
        "",
        "localhost",
        "localhost:5000",
        "quay.io",
        "a-b.c--d.e",
        "a.b:1",
        "a.b:65535",
        "0.0.0.0:80",
        "[::1]",
        "[::1]:5000",
        "[2001:db8::1]",
        "[0:a]:1",
        "docker.io",
        "index.docker.io",
    ];
    let paths = [
        "a",
        "a/b",
        "a.b/c",
        "a_b/c__d/e-f/g--h",
        "0/1/2/3",
        "library/alpine",
        "a.b",
    ];
    let tags = ["", "latest", "_x", "A", "1.2-rc_3", "X.Y", "-"];
    let digests = [String::new(), format!("@{D256}")];
    let (mut cases, mut accepted) = (0, 0);
    for host in hosts {
        for path in paths {
            for tag in tags {
                for digest in &digests {
                    let mut s = String::new();
                    if !host.is_empty() {
                        s = format!("{host}/");
                    }
                    s.push_str(path);
                    if !tag.is_empty() {
                        s = format!("{s}:{tag}");
                    }
                    s.push_str(digest);
                    cases += 1;
                    let ok = verify(s.as_bytes());
                    accepted += u64::from(ok);
                    // `-` begins no tag
                    assert_eq!(ok, tag != "-", "{s:?}");
                    // (a first component like a host is the host)
                    let hosty = host.is_empty() && path.starts_with("a.b/");
                    if let (Ok(spans), false) = (parse(s.as_bytes()), hosty) {
                        assert_eq!(spans.host_end, host.len(), "{s:?}");
                        assert_eq!(spans.tag.is_some(), !tag.is_empty(), "{s:?}");
                        assert_eq!(spans.digest.is_some(), !digest.is_empty(), "{s:?}");
                    }
                }
            }
        }
    }
    assert_eq!((cases, accepted), (1372, 1176));
}
