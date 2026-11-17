// SPDX-License-Identifier: Apache-2.0
//! The fuzz targets of `fuzz/` here without a fuzzer: every file of their
//! corpora, whole and cut at each of a few lengths, goes through the
//! target, which must not panic.

use std::path::PathBuf;
use velarx_p2p::fuzzing::{run, TARGETS};

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
fn the_corpora_replay_whole_and_cut() {
    for t in TARGETS {
        for (path, data) in corpus(t) {
            for cut in (0..=data.len()).step_by(1.max(data.len() / 64)) {
                let piece = &data[..cut];
                let r = std::panic::catch_unwind(|| run(t, piece));
                assert!(r.is_ok(), "{t} panics on {} cut at {cut}", path.display());
            }
        }
    }
}
