// SPDX-License-Identifier: Apache-2.0
//! The fuzz targets of `fuzz/` in `cargo test`: every file of their
//! corpora (the seeds, and what cargo-fuzz found and was kept) is replayed,
//! then mutations of the seeds are run, so that a parser that panics on an
//! input fails here without a fuzzer.

#![cfg(feature = "fuzzing")]

use std::path::PathBuf;
use velarx::fuzzing::{run, TARGETS};

fn corpus(target: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target);
    let mut out: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .map(|p| {
            let data = std::fs::read(&p).unwrap();
            (p, data)
        })
        .collect();
    out.sort();
    out
}

#[test]
fn every_target_has_seeds() {
    for t in TARGETS {
        assert!(!corpus(t).is_empty(), "no seed for {t}");
        assert!(run(t, b""), "{t} is not a target");
    }
    assert!(!run("nope", b""));
}

#[test]
fn the_corpora_replay() {
    for t in TARGETS {
        for (path, data) in corpus(t) {
            let r = std::panic::catch_unwind(|| run(t, &data));
            assert!(r.is_ok(), "{t} panics on {}", path.display());
        }
    }
}

/// Mutations of the seeds: bytes changed, cut, inserted, a piece of the
/// input repeated or another seed's spliced in.  The generator is seeded:
/// a failure happens again; FUZZ_ITERATIONS changes how many per target.
#[test]
fn mutations_of_the_seeds() {
    use rand::{Rng, SeedableRng};
    let n: usize = std::env::var("FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500);
    for (k, t) in TARGETS.iter().enumerate() {
        let seeds: Vec<Vec<u8>> = corpus(t).into_iter().map(|(_, d)| d).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x73_0000 + k as u64);
        // the archive target writes a file a run: fewer of them
        let rounds = if *t == "archive" { n / 10 } else { n };
        for i in 0..rounds {
            let mut d = seeds[i % seeds.len()].clone();
            for _ in 0..rng.gen_range(1..6) {
                let len = d.len();
                match rng.gen_range(0..6) {
                    0 if len > 0 => {
                        let at = rng.gen_range(0..len);
                        d[at] = rng.gen();
                    }
                    1 if len > 0 => d.truncate(rng.gen_range(0..len)),
                    2 => {
                        let at = rng.gen_range(0..=len);
                        d.insert(at, rng.gen());
                    }
                    3 if len > 0 => {
                        // an interesting byte: a NUL, a quote, a newline...
                        let at = rng.gen_range(0..len);
                        d[at] = *[0u8, b'"', b'\n', b'/', b'.', 0xff, b'-', b'9', b':']
                            .get(rng.gen_range(0..9))
                            .unwrap_or(&0);
                    }
                    4 if len > 1 => {
                        let a = rng.gen_range(0..len);
                        let b = rng.gen_range(a..len.min(a + 64) + 1);
                        let piece = d[a..b.min(len)].to_vec();
                        let at = rng.gen_range(0..=d.len());
                        d.splice(at..at, piece);
                    }
                    _ => {
                        let other = &seeds[rng.gen_range(0..seeds.len())];
                        if !other.is_empty() {
                            let a = rng.gen_range(0..other.len());
                            let at = rng.gen_range(0..=d.len());
                            d.splice(at..at, other[a..].iter().take(128).copied());
                        }
                    }
                }
            }
            let r = std::panic::catch_unwind(|| run(t, &d));
            assert!(
                r.is_ok(),
                "{t} panics on mutation {i}: {:?}",
                String::from_utf8_lossy(&d)
            );
        }
    }
}
