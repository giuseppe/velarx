// SPDX-License-Identifier: Apache-2.0
//! The rules of the choice (see the head of the crate), checked on the
//! answer of `choose` for given entries and a platform asked for.  They are
//! stated by a list of the acceptable platforms written with the string
//! methods of the standard library, not by how `wanted_variant` computes
//! it: the table of containers/image, and its walk down the list.

use super::*;

/// The acceptable variants for a request, best first, as containers/image
/// builds them: the table `arm` -> v8 v7 v6 v5, `arm64` -> v8.
pub fn wanted_ref(arch: &str, variant: &str) -> Vec<String> {
    let table: Vec<&str> = match arch {
        "arm" => vec!["v8", "v7", "v6", "v5"],
        "arm64" => vec!["v8"],
        _ => vec![],
    };
    let mut list: Vec<&str> = Vec::new();
    if variant.is_empty() {
        list.push("");
        list.extend(&table);
    } else {
        match table.iter().position(|v| *v == variant) {
            Some(at) => list.extend(&table[at..]),
            None => list.push(variant),
        }
        list.push("");
    }
    list.iter().map(|v| v.to_string()).collect()
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

/// What `choose` must answer, by the rules, and the check that it does.
pub fn check(entries: &[Entry], want: Platform) {
    let (os, arch, variant) = (text(want.os), text(want.arch), text(want.variant));
    let list = wanted_ref(arch, variant);
    // rule 2: the platforms, one by one, and no more
    let spelled = |k: usize| {
        wanted_variant(want.arch, want.variant, k).map(|w| match w {
            Wanted::Absent => &b""[..],
            Wanted::V8 => b"v8",
            Wanted::V7 => b"v7",
            Wanted::V6 => b"v6",
            Wanted::V5 => b"v5",
            Wanted::Asked => want.variant,
        })
    };
    for (k, v) in list.iter().enumerate() {
        assert_eq!(spelled(k), Some(v.as_bytes()));
    }
    assert_eq!(spelled(list.len()), None);
    // the place of an entry on the list, as the rules say
    let place = |e: &Entry| -> Option<usize> {
        let p = &e.platform;
        if !e.image || text(p.os) != os || text(p.arch) != arch {
            return None;
        }
        list.iter().position(|v| v == text(p.variant))
    };
    let chosen = choose(entries, want);
    let best = entries.iter().filter_map(place).min();
    match chosen {
        // rule 5: nothing exactly when no entry is acceptable
        None => assert_eq!(best, None, "{entries:?} for {want:?}"),
        Some(i) => {
            // rules 3 and 4: an acceptable entry, the best, the first of them
            let k = place(&entries[i]).expect("an acceptable entry");
            assert_eq!(Some(k), best, "{entries:?} for {want:?}");
            assert!(entries[..i].iter().all(|e| place(e) != Some(k)));
            // (and the same is told by the rank of the platform)
            assert_eq!(rank(entries[i].platform, want), Some(k));
        }
    }
}

/// An attestation is never chosen, even when it is what is asked for.
#[test]
fn an_attestation_is_never_chosen() {
    let unknown = Platform {
        os: b"unknown",
        arch: b"unknown",
        variant: b"",
    };
    let entries = [Entry {
        platform: unknown,
        image: false,
    }];
    assert_eq!(choose(&entries, unknown), None);
    check(&entries, unknown);
}

/// The cases of containers/image, by name.
#[test]
fn the_cases_of_the_problem() {
    let p = |arch: &'static str, variant: &'static str| Platform {
        os: b"linux",
        arch: arch.as_bytes(),
        variant: variant.as_bytes(),
    };
    let image = |platform| Entry {
        platform,
        image: true,
    };
    // arm64 with and without v8 are one platform
    assert_eq!(choose(&[image(p("arm64", ""))], p("arm64", "v8")), Some(0));
    assert_eq!(choose(&[image(p("arm64", "v8"))], p("arm64", "")), Some(0));
    // the best variant, not the first
    let arm = [
        image(p("arm", "v5")),
        image(p("arm", "v7")),
        image(p("arm", "v6")),
    ];
    assert_eq!(choose(&arm, p("arm", "")), Some(1));
    assert_eq!(choose(&arm, p("arm", "v6")), Some(2));
    assert_eq!(choose(&arm, p("arm", "v7")), Some(1));
    assert_eq!(choose(&arm[..1], p("arm", "v7")), Some(0));
    assert_eq!(choose(&arm[1..2], p("arm", "v5")), None);
    // an entry without a variant is the first choice of a request without
    assert_eq!(
        choose(&[image(p("arm", "v7")), image(p("arm", ""))], p("arm", "")),
        Some(1)
    );
    // amd64 knows no variants
    assert_eq!(choose(&[image(p("amd64", "v3"))], p("amd64", "")), None);
    assert_eq!(
        choose(&[image(p("amd64", "v3"))], p("amd64", "v3")),
        Some(0)
    );
}

/// An index longer than the ones of the walk: `choose` halves it, and the
/// first of the best entries is named even when an equal one is in the
/// other half.
#[test]
fn a_long_index() {
    let p = |arch: &'static str, variant: &'static str| Platform {
        os: b"linux",
        arch: arch.as_bytes(),
        variant: variant.as_bytes(),
    };
    let image = |platform| Entry {
        platform,
        image: true,
    };
    let index = [
        image(p("amd64", "")),
        image(p("arm", "v5")),
        image(p("arm", "v7")),
        Entry {
            platform: p("arm", "v8"),
            image: false,
        },
        image(p("arm", "v6")),
        image(p("arm", "v7")),
        image(p("arm", "")),
        image(p("arm", "v8")),
    ];
    assert_eq!(choose(&index, p("arm", "")), Some(6));
    assert_eq!(choose(&index, p("arm", "v8")), Some(7));
    assert_eq!(choose(&index, p("arm", "v7")), Some(2));
    assert_eq!(choose(&index, p("arm", "v6")), Some(4));
    assert_eq!(choose(&index, p("arm", "v5")), Some(1));
    assert_eq!(choose(&index, p("amd64", "v2")), Some(0));
    assert_eq!(choose(&index, p("arm64", "")), None);
    assert_eq!(choose(&index[1..6], p("arm", "")), Some(1));
    assert_eq!(choose(&index[3..], p("arm", "v7")), Some(2));
    // and the rules hold for every part of it
    for want in [p("arm", ""), p("arm", "v7"), p("arm", "v9"), p("amd64", "")] {
        for from in 0..index.len() {
            for to in from..=index.len() {
                check(&index[from..to], want);
            }
        }
    }
}
