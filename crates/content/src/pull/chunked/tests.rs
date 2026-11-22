// SPDX-License-Identifier: Apache-2.0
fn cap(blob: i64) -> u64 {
    crate::pull::inflate_limit(blob, 128, 64 << 20, 1 << 40)
}

use super::*;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;

fn layer(annotations: &[(&str, &str)], media: &str) -> OciDescriptor {
    OciDescriptor {
        media_type: media.to_string(),
        digest: crate::sha256(b""),
        size: 1000,
        annotations: annotations
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<HashMap<_, _>>(),
    }
}

const ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";

#[test]
fn test_parse_info() {
    let prefix = "io.github.containers.zstd-chunked.";
    let l = layer(
        &[
            (&format!("{prefix}manifest-position"), "100:50:200:1"),
            (
                &format!("{prefix}manifest-checksum"),
                &crate::sha256_text(b""),
            ),
            (&format!("{prefix}tarsplit-position"), "150:20:40"),
        ],
        ZSTD,
    );
    let i = parse_info(&l).unwrap().unwrap();
    assert_eq!(i.toc, (100, 50, 200));
    assert_eq!(i.tarsplit, Some((150, 20, 40)));
    assert_eq!(i.checksum, crate::sha256(b""));

    assert!(parse_info(&layer(&[], ZSTD)).unwrap().is_none());

    let mut bad = l.clone();
    bad.annotations
        .insert(format!("{prefix}manifest-position"), "1:2:x:1".into());
    assert!(parse_info(&bad).is_err());
    let mut bad = l.clone();
    bad.annotations
        .insert(format!("{prefix}manifest-checksum"), "sha256:zz".into());
    assert!(parse_info(&bad).is_err());
    // a table the layer names and this does not know, or half of its
    // labels, is not "no table": the layer is refused
    let mut other = l.clone();
    other
        .annotations
        .insert(format!("{prefix}manifest-position"), "1:2:3:2".into());
    assert!(parse_info(&other).is_err());
    for half in ["manifest-position", "manifest-checksum"] {
        let mut half_of = l.clone();
        half_of.annotations.remove(&format!("{prefix}{half}"));
        assert!(parse_info(&half_of).is_err(), "{half}");
    }
    // any of the annotations says that the layer has a table: on a layer
    // that is not zstd, or alone
    let mut gz = l.clone();
    gz.media_type = "application/vnd.oci.image.layer.v1.tar+gzip".into();
    assert!(parse_info(&gz).is_err());
    for name in ["tarsplit-position", "version"] {
        let alone = layer(&[(&format!("{prefix}{name}"), "2")], ZSTD);
        assert!(parse_info(&alone).is_err(), "{name}");
        let alone = layer(
            &[(&format!("io.containers.zstd-chunked.{name}"), "2")],
            ZSTD,
        );
        assert!(parse_info(&alone).is_err(), "{name}");
    }
}

fn reg(
    name: &str,
    d: &str,
    size: u64,
    offset: u64,
    end: u64,
    chunk: Option<(&str, u64)>,
) -> TocEntry {
    TocEntry {
        mode: 0o644,
        size,
        digest: Some(d.into()),
        offset,
        end_offset: end,
        chunk_digest: chunk.map(|c| c.0.to_string()),
        chunk_size: chunk.map_or(0, |c| c.1),
        ..TocEntry::new(name, TocEntryType::Reg)
    }
}

fn chunk(name: &str, d: &str, size: u64, off: u64, offset: u64) -> TocEntry {
    let mut e = reg(name, "", 0, offset, 0, Some((d, size)));
    e.entry_type = TocEntryType::Chunk;
    e.digest = None;
    e.chunk_offset = off;
    e
}

fn d(n: u8) -> String {
    crate::sha256_text(&[n])
}

fn toc(entries: Vec<TocEntry>) -> Toc {
    Toc {
        version: 1,
        entries,
        tar_split_digest: None,
    }
}

#[test]
fn test_plan_skips_known_and_duplicate_content() {
    let t = toc(vec![
        reg("a", &d(1), 10, 0, 100, None),
        reg("b", &d(1), 10, 100, 200, None),
        reg("c", &d(2), 10, 200, 300, None),
        reg("empty", &crate::sha256_text(b""), 0, 0, 0, None),
    ]);
    let have = |x: &str, _| x == d(2);
    let plan = make_plan(&t, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &have).unwrap();
    assert_eq!(plan.jobs.len(), 1);
    assert_eq!(plan.skipped_files, 2);
    assert_eq!(plan.skipped_compressed, 200);
    assert_eq!(plan.chunks.len(), 1);
    assert_eq!(plan.chunks[0].comp, 0..100);
    assert_eq!(plan.chunks[0].digest, Some(crate::sha256(&[1])));
}

#[test]
fn test_plan_multi_chunk_file() {
    let t = toc(vec![
        reg("f", &d(9), 30, 100, 160, Some((&d(1), 10))),
        chunk("f", &d(2), 10, 10, 120),
        chunk("f", &d(3), 10, 20, 140),
    ]);
    let plan = make_plan(&t, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &|_, _| {
        false
    })
    .unwrap();
    let c = &plan.chunks;
    assert_eq!(c.len(), 3);
    assert_eq!((c[0].comp.clone(), c[0].file_off), (100..120, 0));
    assert_eq!((c[1].comp.clone(), c[1].file_off), (120..140, 10));
    assert_eq!((c[2].comp.clone(), c[2].file_off), (140..160, 20));
    assert_eq!(plan.jobs[0].chunks, 0..3);
}

#[test]
fn test_plan_zeros_chunks_are_holes() {
    let mut z = chunk("f", &d(2), 20, 10, 120);
    z.chunk_type = Some("zeros".into());
    let t = toc(vec![reg("f", &d(9), 30, 100, 135, Some((&d(1), 10))), z]);
    let plan = make_plan(&t, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &|_, _| {
        false
    })
    .unwrap();
    assert_eq!(plan.chunks.len(), 1);
    assert_eq!(plan.jobs[0].holes, vec![(10, 20)]);
    assert_eq!(plan.zeros, 20);
}

/// The holes of a file are not what the blob inflates to: a file of
/// 1 GiB with 10 bytes of data plans from a blob of 1000 bytes.
#[test]
fn test_plan_holes_are_not_counted_against_the_inflate_cap() {
    let mut z = chunk("f", &d(2), (1 << 30) - 10, 10, 120);
    z.chunk_type = Some("zeros".into());
    let t = toc(vec![
        reg("f", &d(9), 1 << 30, 100, 135, Some((&d(1), 10))),
        z,
    ]);
    let plan = make_plan(&t, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &|_, _| {
        false
    })
    .unwrap();
    assert_eq!(plan.planned, 10);
    assert_eq!(plan.zeros, (1 << 30) - 10);
}

#[test]
fn test_plan_rejects_inconsistent_tocs() {
    let cases: Vec<Vec<TocEntry>> = vec![
        vec![reg("f", &d(1), 10, 0, 5000, None)],
        vec![reg("f", &d(1), 10, 50, 50, None)],
        vec![
            reg("f", &d(9), 30, 100, 140, Some((&d(1), 10))),
            chunk("f", &d(2), 10, 10, 120),
        ],
        vec![
            reg("f", &d(9), 30, 100, 140, Some((&d(1), 10))),
            chunk("f", &d(2), 20, 15, 120),
        ],
        vec![reg("f", &d(9), 5, 100, 140, Some((&d(1), 10)))],
        vec![reg("f", "../../etc/passwd", 10, 0, 10, None)],
    ];
    for entries in cases {
        assert!(make_plan(
            &toc(entries),
            Algorithm::Sha256,
            1000,
            1 << 20,
            cap(1000),
            &|_, _| false
        )
        .is_err());
    }
    // A compressed range far bigger than its content.
    let big: Vec<Vec<TocEntry>> = vec![
        vec![reg("f", &d(1), 10, 0, (2 << 20) + 10, None)],
        vec![
            reg("f", &d(9), 20, 100, (4 << 20) + 200, Some((&d(1), 10))),
            chunk("f", &d(2), 10, 10, (3 << 20) + 100),
        ],
    ];
    for entries in big {
        assert!(make_plan(
            &toc(entries),
            Algorithm::Sha256,
            1 << 30,
            1 << 20,
            cap(1 << 30),
            &|_, _| false
        )
        .is_err());
    }
}

#[test]
fn test_plan_limits() {
    let big = toc(vec![reg("f", &d(1), 1 << 30, 0, 10, None)]);
    assert!(matches!(
        make_plan(
            &big,
            Algorithm::Sha256,
            1000,
            1 << 20,
            cap(1000),
            &|_, _| { false }
        ),
        Err(ImageError::Layer(_))
    ));
    // 1 GiB of files from a blob of 1000 bytes is over the floor of the cap.
    let t = toc(vec![
        reg("a", &d(1), 1 << 30, 0, 10, None),
        reg("b", &d(2), 1 << 30, 10, 20, None),
    ]);
    assert!(
        make_plan(&t, Algorithm::Sha256, 1000, 2 << 30, cap(1000), &|_, _| {
            false
        })
        .is_err()
    );
    let small = toc(vec![reg("a", &d(1), 1 << 20, 0, 10, None)]);
    assert!(make_plan(
        &small,
        Algorithm::Sha256,
        1000,
        1 << 20,
        cap(1000),
        &|_, _| { false }
    )
    .is_ok());
}

fn comps(c: &[ChunkPlan]) -> Vec<Range<u64>> {
    c.iter().map(|c| c.comp.clone()).collect()
}

#[test]
fn test_batches_merge_adjacent_chunks_and_respect_limits() {
    let mk = |start: u64, len: u64| ChunkPlan {
        job: 0,
        file_off: 0,
        size: 1,
        digest: None,
        comp: start..start + len,
    };
    // 200 chunks of 1 KiB with gaps of 2 KiB: the gaps cost less than
    // the requests they save, the ranges are merged
    let chunks: Vec<ChunkPlan> = (0..200).map(|i| mk(i * 3000, 1000)).collect();
    let remote: Vec<usize> = (0..200).collect();
    let batches = make_batches(&comps(&chunks), &remote, 4, Learnt::default());
    let members: usize = batches.iter().flat_map(|b| &b.members).map(Vec::len).sum();
    assert_eq!(members, 200);
    let ranges: usize = batches.iter().map(|b| b.ranges.len()).sum();
    assert!(ranges < 200);
    for b in &batches {
        assert!(b.ranges.len() <= MAX_RANGES_PER_REQUEST);
        assert!(super::super::ranges::range_header(&b.ranges).len() <= MAX_RANGE_HEADER);
        for (r, m) in b.ranges.iter().zip(&b.members) {
            for &i in m {
                assert!(chunks[i].comp.start >= r.start && chunks[i].comp.end <= r.end);
            }
        }
    }
    // Adjacent chunks end up in one range.
    let chunks: Vec<ChunkPlan> = (0..10).map(|i| mk(i * 1000, 1000)).collect();
    let remote: Vec<usize> = (0..10).collect();
    let batches = make_batches(&comps(&chunks), &remote, 4, Learnt::default());
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].ranges, vec![0..10000]);
    assert_eq!(batches[0].members[0], remote);
    // Gaps of 1 MiB cost about a request: chunks of 64 KiB 1 MiB apart
    // stay apart
    let chunks: Vec<ChunkPlan> = (0..20).map(|i| mk(i * (2 << 20), 64 << 10)).collect();
    let remote: Vec<usize> = (0..20).collect();
    let batches = make_batches(&comps(&chunks), &remote, 4, Learnt::default());
    let ranges: usize = batches.iter().map(|b| b.ranges.len()).sum();
    assert_eq!(ranges, 20);
    // a registry that took at most 4 ranges per request
    let learnt = Learnt {
        per_request: Some(4),
        whole: false,
    };
    let batches = make_batches(&comps(&chunks), &remote, 4, learnt);
    assert!(batches.iter().all(|b| b.ranges.len() <= 4));
    // overlapping chunks are not merged
    let chunks = vec![mk(0, 100), mk(50, 100)];
    let batches = make_batches(&comps(&chunks), &[0, 1], 4, Learnt::default());
    let ranges: usize = batches.iter().map(|b| b.ranges.len()).sum();
    assert_eq!(ranges, 2);
}

/// The compressed tar-split of the tar of `entries` (files of zeros).
fn tarsplit_of(entries: &[TocEntry]) -> Vec<u8> {
    use crate::pull::tarsplit::Recorder;
    use std::io::Cursor;
    let mut tar = Vec::new();
    velarx_storage::canonical::write(entries, &mut tar, |e, out| {
        out.write_all(&vec![0; e.size as usize])
    })
    .unwrap();
    let mut r = TarReader::with_sink(Cursor::new(tar), Recorder::new().unwrap());
    while r.next_entry().unwrap().is_some() {}
    r.finish().unwrap().1.finish().unwrap().compressed
}

#[test]
fn test_metadata_checks() {
    let ts = tarsplit_of(&[]);
    let toc_json = serde_json::json!({
        "version": 1,
        "entries": [],
        "tarSplitDigest": crate::sha256(&ts),
    })
    .to_string();
    let toc_z = zstd::encode_all(toc_json.as_bytes(), 3).unwrap();
    let info = Info {
        toc: (0, toc_z.len() as u64, toc_json.len() as u64),
        checksum: crate::sha256(&toc_z),
        tarsplit: Some((0, ts.len() as u64, 0)),
        table: false,
    };
    let layer = crate::sha256(b"layer");
    assert!(verify_metadata(&info, &toc_z, ts.clone(), &layer, u64::MAX).is_ok());
    let mut bad = info.clone();
    bad.checksum = crate::sha256(b"other");
    assert!(verify_metadata(&bad, &toc_z, ts.clone(), &layer, u64::MAX).is_err());
    assert!(verify_metadata(&info, &toc_z, b"tx".to_vec(), &layer, u64::MAX).is_err());
    let mut bad = info.clone();
    bad.toc.2 += 1;
    assert!(verify_metadata(&bad, &toc_z, ts, &layer, u64::MAX).is_err());
}

#[test]
fn test_decompress_is_bounded() {
    let z = zstd::encode_all(&vec![0u8; 1 << 20][..], 3).unwrap();
    assert!(decompress_bounded(&z, 1 << 10, 0, "x").is_err());
    assert_eq!(
        decompress_bounded(&z, 1 << 20, 0, "x").unwrap().len(),
        1 << 20
    );
}

/// The tries of a range request, which the pull of the client and the
/// fetcher of the registry share: a server that takes fewer ranges is asked
/// half of them, and a request that brings nothing is given up after
/// `RETRIES` tries while one that brings something starts again.
#[tokio::test]
async fn test_the_tries_of_a_range_request() {
    use crate::pull::ranges::RangesError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let batch = || Batch {
        ranges: (0..4u64).map(|i| i * 10..i * 10 + 10).collect(),
        members: (0..4).map(|i| vec![i]).collect(),
    };
    let comp = |i: usize| i as u64 * 10..i as u64 * 10 + 10;
    let digest = crate::sha256(b"tries");
    // a server that takes two ranges at most: 4, then 2 and 2
    let asked = std::sync::Mutex::new(Vec::new());
    fetch_with_tries(
        batch(),
        "tries-limit.invalid",
        &digest,
        comp,
        |_| false,
        || false,
        |b| {
            asked.lock().unwrap().push(b.ranges.len());
            async move {
                match b.ranges.len() > 2 {
                    true => Err(RangesError::Rejected(416)),
                    false => Ok(()),
                }
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(*asked.lock().unwrap(), [4, 2, 2]);
    // a server that answers with the whole blob is for the caller: no retry
    let tries = AtomicUsize::new(0);
    let e = fetch_with_tries(
        batch(),
        "tries-whole.invalid",
        &digest,
        comp,
        |_| false,
        || false,
        |_| {
            tries.fetch_add(1, Ordering::SeqCst);
            async { Err(RangesError::WholeBlob) }
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(e, RangesError::WholeBlob), "{e:?}");
    assert_eq!(tries.load(Ordering::SeqCst), 1);
    // a request that brings nothing is tried RETRIES times
    let tries = AtomicUsize::new(0);
    let e = fetch_with_tries(
        batch(),
        "tries-none.invalid",
        &digest,
        comp,
        |_| false,
        || false,
        |_| {
            tries.fetch_add(1, Ordering::SeqCst);
            async { Err(RangesError::Other(fail("down"))) }
        },
    )
    .await
    .unwrap_err();
    assert!(format!("{e:?}").contains("down"), "{e:?}");
    assert_eq!(tries.load(Ordering::SeqCst), RETRIES);
    // a pull that is over is not tried again
    let tries = AtomicUsize::new(0);
    fetch_with_tries(
        batch(),
        "tries-stop.invalid",
        &digest,
        comp,
        |_| false,
        || true,
        |_| {
            tries.fetch_add(1, Ordering::SeqCst);
            async { Err(RangesError::Other(fail("stopped"))) }
        },
    )
    .await
    .unwrap_err();
    assert_eq!(tries.load(Ordering::SeqCst), 1);
    // what arrived before the error is not asked again, and the tries start over
    let claimed = std::sync::Mutex::new(vec![false; 4]);
    let seen = std::sync::Mutex::new(Vec::new());
    fetch_with_tries(
        batch(),
        "tries-part.invalid",
        &digest,
        comp,
        |i| claimed.lock().unwrap()[i],
        || false,
        |b| {
            seen.lock().unwrap().push(b.chunks());
            let n = seen.lock().unwrap().len();
            if n < 6 {
                claimed.lock().unwrap()[n - 1] = true;
            }
            async move {
                match b.chunks() {
                    1 => Ok(()),
                    _ => Err(RangesError::Other(fail("cut"))),
                }
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(*seen.lock().unwrap(), [4, 3, 2, 1]);
}

/// A file the replay opened and the archive never read is an error at the
/// end of the replay: the tar-split and the archive do not agree.
#[test]
fn a_file_opened_and_never_read_fails_the_replay() {
    use crate::pull::tarsplit::{decoder, Recorder, MAX_SIZE};
    use std::io::Cursor;

    struct Stale(Option<Opened>);
    impl Opens for Stale {
        fn opened(&mut self) -> &mut Option<Opened> {
            &mut self.0
        }
    }
    impl Contents for Stale {
        fn open(&mut self, name: &str, _size: u64) -> io::Result<Box<dyn Read + Send>> {
            Err(io::Error::other(format!("{name} was not asked for")))
        }
    }

    // (an archive of a directory: no file to open)
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_size(0);
    h.set_mode(0o755);
    b.append_data(&mut h, "d", &[][..]).unwrap();
    let stream = b.into_inner().unwrap();
    let mut r = TarReader::with_sink(Cursor::new(stream), Recorder::new().unwrap());
    while r.next_entry().unwrap().is_some() {}
    let (_, recorder) = r.finish().unwrap();
    let tarsplit = recorder.finish().unwrap().compressed;
    let replay = |opened: Option<Opened>| {
        let input = decoder(tarsplit.clone(), MAX_SIZE).unwrap();
        replay_of(input, Stale(opened), Algorithm::Sha256, Algorithm::Sha256)
    };
    assert!(replay(None).is_ok());
    let stale = Opened {
        name: "f".into(),
        size: 1,
        digest: String::new(),
        copy: None,
        verified: false,
    };
    match replay(Some(stale)) {
        Err(e) => assert!(
            e.to_string()
                .contains("tar-split has files the archive does not"),
            "{e}"
        ),
        Ok(_) => panic!("a file opened and never read was not seen"),
    }
}

/// A table a fetcher made of a layer it unpacked is a claim: the replay
/// hashes each file and refuses one that is not the digest the claim names
/// it by, even when the stream (the diff id) is right.
#[test]
fn a_file_that_is_not_what_a_claim_says_fails_the_replay() {
    use crate::pull::tarsplit::{decoder, Recorder, MAX_SIZE};
    use std::io::Cursor;

    struct Claimed(Option<Opened>, String);
    impl Opens for Claimed {
        fn opened(&mut self) -> &mut Option<Opened> {
            &mut self.0
        }
    }
    impl Contents for Claimed {
        fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
            self.0 = Some(Opened {
                name: name.into(),
                size,
                digest: self.1.clone(),
                copy: None,
                verified: false,
            });
            Ok(Box::new(Cursor::new(b"data".to_vec())))
        }
    }

    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(4);
    h.set_mode(0o644);
    b.append_data(&mut h, "f", &b"data"[..]).unwrap();
    let stream = b.into_inner().unwrap();
    let diff_id = Digest::of(Algorithm::Sha256, &stream);
    let mut r = TarReader::with_sink(Cursor::new(stream), Recorder::new().unwrap());
    while r.next_entry().unwrap().is_some() {}
    let (_, recorder) = r.finish().unwrap();
    let tarsplit = recorder.finish().unwrap().compressed;
    let replay = |claim: String| {
        let input = decoder(tarsplit.clone(), MAX_SIZE).unwrap();
        replay_of(
            input,
            Claimed(None, claim),
            Algorithm::Sha256,
            Algorithm::Sha256,
        )
    };
    let right = Digest::of(Algorithm::Sha256, b"data").to_string();
    let replayed = replay(right.clone()).unwrap();
    assert_eq!(replayed.diff_id, diff_id);
    assert_eq!(replayed.entries[0].digest.as_deref(), Some(right.as_str()));
    let wrong = Digest::of(Algorithm::Sha256, b"other").to_string();
    match replay(wrong) {
        Err(ImageError::Contradicted(e)) => assert!(e.contains("not the"), "{e}"),
        Err(e) => panic!("not a contradiction: {e}"),
        Ok(_) => panic!("a file that is not its claimed digest was taken"),
    }
}

/// A file is known by the digest of its content, never by an object: a key
/// that is an fs-verity digest fails the replay, of a copy the origin handed
/// over (which the replay does not hash) too.
#[test]
fn a_file_known_by_an_object_fails_the_replay() {
    use crate::pull::tarsplit::{decoder, Recorder, MAX_SIZE};
    use std::io::Cursor;

    struct Handed(Option<Opened>, String, bool);
    impl Opens for Handed {
        fn opened(&mut self) -> &mut Option<Opened> {
            &mut self.0
        }
    }
    impl Contents for Handed {
        fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
            self.0 = Some(Opened {
                name: name.into(),
                size,
                digest: self.1.clone(),
                copy: None,
                verified: self.2,
            });
            Ok(Box::new(Cursor::new(b"data".to_vec())))
        }
    }

    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(4);
    h.set_mode(0o644);
    b.append_data(&mut h, "f", &b"data"[..]).unwrap();
    let stream = b.into_inner().unwrap();
    let mut r = TarReader::with_sink(Cursor::new(stream), Recorder::new().unwrap());
    while r.next_entry().unwrap().is_some() {}
    let (_, recorder) = r.finish().unwrap();
    let tarsplit = recorder.finish().unwrap().compressed;
    let object = velarx_storage::fsverity_digest_of(Algorithm::Sha256, b"data");
    for verified in [true, false] {
        let input = decoder(tarsplit.clone(), MAX_SIZE).unwrap();
        match replay_of(
            input,
            Handed(None, object.clone(), verified),
            Algorithm::Sha256,
            Algorithm::Sha256,
        ) {
            Err(ImageError::Contradicted(e)) => {
                assert!(e.contains("no digest of a content"), "{e}")
            }
            Err(e) => panic!("not a contradiction: {e}"),
            Ok(_) => panic!("a file known by an object was taken"),
        }
    }
}

/// A file is not hashed by the replay only when the copy it reads was proved
/// to be its digest: a file opened before its content (whose bytes may come
/// from elsewhere) fails the replay.
#[test]
fn a_verified_file_opened_before_its_content_fails_the_replay() {
    use crate::pull::tarsplit::{decoder, Recorder, MAX_SIZE};
    use std::io::Cursor;

    struct Early(Option<Opened>);
    impl Opens for Early {
        fn opened(&mut self) -> &mut Option<Opened> {
            &mut self.0
        }
    }
    impl Contents for Early {
        fn open(&mut self, _: &str, _: u64) -> io::Result<Box<dyn Read + Send>> {
            Ok(Box::new(Cursor::new(b"data".to_vec())))
        }
    }

    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(4);
    h.set_mode(0o644);
    b.append_data(&mut h, "f", &b"data"[..]).unwrap();
    let stream = b.into_inner().unwrap();
    let mut r = TarReader::with_sink(Cursor::new(stream), Recorder::new().unwrap());
    while r.next_entry().unwrap().is_some() {}
    let (_, recorder) = r.finish().unwrap();
    let tarsplit = recorder.finish().unwrap().compressed;
    let early = Opened {
        name: "f".into(),
        size: 4,
        digest: Digest::of(Algorithm::Sha256, b"else").to_string(),
        copy: None,
        verified: true,
    };
    let input = decoder(tarsplit, MAX_SIZE).unwrap();
    match replay_of(
        input,
        Early(Some(early)),
        Algorithm::Sha256,
        Algorithm::Sha256,
    ) {
        Err(e) => assert!(e.to_string().contains("does not match the archive"), "{e}"),
        Ok(_) => panic!("a file was taken as a copy it was not read from"),
    }
}

/// A file of `OFFLOAD_FROM` bytes or more has its hash computed beside the
/// read of it (the stream's too): the replay says the same as for a small
/// one, the diff id of the stream and the digest of the file, and refuses
/// a file that is not what its claim says.
#[test]
fn a_big_file_is_hashed_beside_its_read_to_the_same_digests() {
    use crate::pull::tarsplit::{decoder, Recorder, MAX_SIZE};
    use std::io::Cursor;

    struct Claimed(Option<Opened>, String, Vec<u8>);
    impl Opens for Claimed {
        fn opened(&mut self) -> &mut Option<Opened> {
            &mut self.0
        }
    }
    impl Contents for Claimed {
        fn open(&mut self, name: &str, size: u64) -> io::Result<Box<dyn Read + Send>> {
            self.0 = Some(Opened {
                name: name.into(),
                size,
                digest: self.1.clone(),
                copy: None,
                verified: false,
            });
            Ok(Box::new(Cursor::new(self.2.clone())))
        }
    }

    let data: Vec<u8> = (0..(2 * OFFLOAD_FROM + 12_345) as u32)
        .map(|i| (i % 253) as u8)
        .collect();
    assert!(data.len() as u64 >= OFFLOAD_FROM);
    let mut b = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(0o644);
    b.append_data(&mut h, "big", &data[..]).unwrap();
    let stream = b.into_inner().unwrap();
    let diff_id = Digest::of(Algorithm::Sha256, &stream);
    let mut r = TarReader::with_sink(Cursor::new(stream), Recorder::new().unwrap());
    while r.next_entry().unwrap().is_some() {}
    let (_, recorder) = r.finish().unwrap();
    let tarsplit = recorder.finish().unwrap().compressed;
    let replay = |claim: String| {
        let input = decoder(tarsplit.clone(), MAX_SIZE).unwrap();
        replay_of(
            input,
            Claimed(None, claim, data.clone()),
            Algorithm::Sha256,
            Algorithm::Sha256,
        )
    };
    let right = Digest::of(Algorithm::Sha256, &data).to_string();
    let replayed = replay(right.clone()).unwrap();
    assert_eq!(replayed.diff_id, diff_id);
    assert_eq!(replayed.entries[0].digest.as_deref(), Some(right.as_str()));
    assert_eq!(replayed.files[0].size, data.len() as u64);
    let wrong = Digest::of(Algorithm::Sha256, b"other").to_string();
    assert!(matches!(replay(wrong), Err(ImageError::Contradicted(_))));
}

/// The `fsverity` value of a TOC entry in the algorithm of the layer keys the
/// file; one of the other algorithm is refused by name (a layer has the
/// digests of one algorithm); one that is no digest is another writer's and
/// is not looked at.
#[test]
fn test_plan_refuses_an_fsverity_value_of_the_other_algorithm_by_name() {
    let with = |v: &str| {
        let mut e = reg("f", &d(1), 10, 0, 100, None);
        e.fsverity = velarx_types::digest::parse_toc_fsverity(v);
        toc(vec![e])
    };
    let plan = |t: &Toc, alg| make_plan(t, alg, 1000, 1 << 20, cap(1000), &|_, _| false);
    let sha256 = format!("sha256-12:{}", "ab".repeat(32));
    assert!(plan(&with(&sha256), Algorithm::Sha256).is_ok());
    assert!(plan(&with("sha384-12:00"), Algorithm::Sha256).is_ok());
    let sha512 = format!("sha512-12:{}", "ab".repeat(64));
    let e = plan(&with(&sha512), Algorithm::Sha256)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("sha512 fs-verity digest") && e.contains("the digests of the layer are sha256"),
        "{e}"
    );
    // (and the reverse)
    let e = plan(&with(&sha256), Algorithm::Sha512)
        .unwrap_err()
        .to_string();
    assert!(e.contains("the digests of the layer are sha512"), "{e}");
}

/// A layer of SHA-512 digests is planned with SHA-512 digests of its files
/// and chunks, and refuses a digest of SHA-256 in either, by name; the same
/// layer is no layer of SHA-256.
#[test]
fn test_plan_of_a_sha512_layer_takes_sha512_digests_only() {
    let d512 = |n: u8| format!("sha512:{}", hex::encode([n; 64]));
    let plan = |t: &Toc, alg| make_plan(t, alg, 1000, 1 << 20, cap(1000), &|_, _| false);
    let file = reg("f", &d512(1), 10, 0, 100, None);
    let t = toc(vec![file.clone()]);
    let p = plan(&t, Algorithm::Sha512).unwrap();
    assert_eq!((p.alg, p.jobs.len()), (Algorithm::Sha512, 1));
    let e = plan(&t, Algorithm::Sha256).unwrap_err().to_string();
    assert!(
        e.contains("sha512 digest") && e.contains("digests of the layer are sha256"),
        "{e}"
    );
    // a sha256 file digest in a sha512 layer
    let t = toc(vec![reg("f", &d(1), 10, 0, 100, None)]);
    let e = plan(&t, Algorithm::Sha512).unwrap_err().to_string();
    assert!(e.contains("digests of the layer are sha512"), "{e}");
    // a sha512 file known by its sha512 fs-verity digest
    let mut v = reg("f", &d512(1), 10, 0, 100, None);
    v.fsverity = velarx_storage::to_toc(&format!("fsverity-sha512-12:{}", "cd".repeat(64)));
    let p = plan(&toc(vec![v]), Algorithm::Sha512).unwrap();
    assert_eq!(
        p.jobs[0].digest,
        format!("fsverity-sha512-12:{}", "cd".repeat(64))
    );
}

/// The chunks a verified table of contents gives are recorded where they are
/// in the objects of their layer: each with a digest, once, not the holes,
/// and not a file whose chunks do not cover it.
#[test]
fn test_located_chunks_follow_the_table() {
    let mut z = chunk("f", &d(2), 20, 10, 120);
    z.chunk_type = Some("zeros".into());
    let t = toc(vec![
        // a file known by its content hash, in three parts, one a hole
        reg("f", &d(9), 40, 100, 160, Some((&d(1), 10))),
        z,
        chunk("f", &d(3), 10, 30, 140),
        // a file of one chunk that its file digest covers: no chunk digest
        reg("one", &d(7), 10, 200, 210, None),
        // the same chunk again in another file: recorded once
        reg("g", &d(8), 10, 300, 310, Some((&d(1), 10))),
        // chunks that do not cover the file: nothing is recorded
        reg("bad", &d(6), 30, 400, 430, Some((&d(4), 10))),
    ]);
    let found = located_chunks(&t);
    let got: Vec<(String, String, u64, u64)> = found
        .iter()
        .map(|c| {
            (
                c.chunk_digest.to_string(),
                c.file_digest.clone(),
                c.offset,
                c.size,
            )
        })
        .collect();
    assert_eq!(
        got,
        vec![(d(1), d(9), 0, 10), (d(3), d(9), 30, 10),],
        "{got:?}"
    );
}

/// A session with a store, for the files an intake takes in.
fn intake_session(tmp: &std::path::Path) -> Arc<crate::pull::session::Session> {
    let store = Arc::new(velarx_storage::FileStore::new(tmp.join("files")).unwrap());
    crate::pull::session::Session::create(&tmp.join("staging"), store).unwrap()
}

/// A file with no name that holds `content`, as a fetcher hands it over: the
/// descriptor is at the end of the file, and another one that can write to
/// it is kept.
fn handed(content: &[u8]) -> (File, File) {
    use std::io::Write;
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(content).unwrap();
    let writer = file.try_clone().unwrap();
    (file, writer)
}

/// The files a fetcher hands over are copied by threads as they come, and
/// each is known by the digest of the bytes the engine copied, whatever
/// the fetcher says of it: a file of a content that is there already is one
/// copy, a copy is read from the start of the file, and what is hashed is
/// what is written.
#[tokio::test]
async fn files_handed_over_are_known_by_what_the_engine_copied() {
    let tmp = tempfile::tempdir().unwrap();
    let session = intake_session(tmp.path());
    let intake = Intake::new(session.clone(), Algorithm::Sha256, 4);
    let key_of = |content: &[u8]| Digest::of(Algorithm::Sha256, content).to_string();
    let (good, other) = (b"good".to_vec(), b"another one".to_vec());
    for content in [&good, &other, &good] {
        intake.give(handed(content).0).await.unwrap();
    }
    let taken = intake.finish().await.unwrap();
    assert_eq!(taken.len(), 2);
    for content in [&good, &other] {
        let copy = &taken[&key_of(content)];
        assert_eq!(std::fs::read(&copy.path).unwrap(), *content);
        assert_eq!(copy.size, content.len() as u64);
        assert_eq!(
            copy.verity,
            velarx_storage::fsverity_digest_of(Algorithm::Sha256, content)
        );
    }
    // (the copy of the second `good` is gone: two files are left)
    let left = session.temp_files().len();
    assert_eq!(left, 2);
}

/// The digest of the content of a handed file is computed only when what it
/// is known by is that digest: a file known by its fs-verity digest is
/// copied and measured, and its content is not hashed.
#[test]
fn the_content_of_a_handed_file_is_hashed_only_when_asked() {
    let tmp = tempfile::tempdir().unwrap();
    let to = CopiesTo::Sink(intake_session(tmp.path()));
    let content = b"some bytes";
    let verity = velarx_storage::fsverity_digest_of(Algorithm::Sha256, content);
    for (asked, hashed) in [
        (
            true,
            Some(Digest::of(Algorithm::Sha256, content).to_string()),
        ),
        (false, None),
    ] {
        let (read, copied) = take_in(handed(content).0, Algorithm::Sha256, &to, asked).unwrap();
        assert_eq!(read, hashed);
        assert_eq!(copied.verity, verity);
    }
}

/// A descriptor handed over that is not a regular file (a pipe) is the
/// fetcher's error, not a read that waits for it.
#[test]
fn a_handed_descriptor_that_is_not_a_regular_file_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let session = intake_session(tmp.path());
    let sink: Arc<dyn crate::pull::sink::Sink> = session;
    let (read, _write) = std::io::pipe().unwrap();
    let key = Digest::of(Algorithm::Sha256, b"x").to_string();
    let e = take_handed(
        File::from(std::os::fd::OwnedFd::from(read)),
        (&key, None),
        &sink,
    )
    .unwrap_err();
    assert!(matches!(e, ImageError::Layer(_)), "{e:?}");
}

/// The engine failing to store a file a fetcher handed over (the system
/// refuses it a file) is its own failure, not the fetcher's: an I/O error,
/// not a file that contradicts its name.
#[test]
fn a_store_that_fails_to_take_a_handed_file_is_an_io_error() {
    let tmp = tempfile::tempdir().unwrap();
    let session = intake_session(tmp.path());
    velarx_base::tree::remove_dir_all(tmp.path().join("staging")).unwrap();
    let sink: Arc<dyn crate::pull::sink::Sink> = session;
    let content = b"the right bytes";
    let key = Digest::of(Algorithm::Sha256, content).to_string();
    let e = take_handed(handed(content).0, (&key, None), &sink).unwrap_err();
    assert!(matches!(e, ImageError::Io(_)), "{e:?}");
}

/// A fetcher that keeps a descriptor it can write to changes nothing of what
/// the engine holds: the copy is the bytes that were read.
#[tokio::test]
async fn a_file_a_fetcher_changes_after_the_hand_over_is_not_what_was_copied() {
    let tmp = tempfile::tempdir().unwrap();
    let intake = Intake::new(intake_session(tmp.path()), Algorithm::Sha256, 1);
    let (file, writer) = handed(b"as it was");
    intake.give(file).await.unwrap();
    let taken = intake.finish().await.unwrap();
    std::os::unix::fs::FileExt::write_all_at(&writer, b"CHANGED!!", 0).unwrap();
    let key = Digest::of(Algorithm::Sha256, b"as it was").to_string();
    assert_eq!(std::fs::read(&taken[&key].path).unwrap(), b"as it was");
}

/// A file is read from its start at positions of its own, wherever the
/// fetcher moves the offset of the descriptor it kept: the bytes hashed are
/// those of the file, in their order.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_is_read_whatever_the_fetcher_does_to_its_offset() {
    let tmp = tempfile::tempdir().unwrap();
    let intake = Intake::new(intake_session(tmp.path()), Algorithm::Sha256, 1);
    let content: Vec<u8> = (0..8u32 << 20).map(|i| (i % 251) as u8).collect();
    let (file, writer) = handed(&content);
    let done = Arc::new(AtomicBool::new(false));
    let mover = {
        let done = done.clone();
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                io::Seek::seek(&mut &writer, io::SeekFrom::End(0)).unwrap();
            }
        })
    };
    intake.give(file).await.unwrap();
    let taken = intake.finish().await.unwrap();
    done.store(true, Ordering::Relaxed);
    mover.join().unwrap();
    let key = Digest::of(Algorithm::Sha256, &content).to_string();
    assert_eq!(taken[&key].size, content.len() as u64);
}

/// A file that a claim names by a digest and that no file handed over has
/// that digest for is missing for the replay: a fetcher that hands over other
/// content cannot have it taken for the claimed one.
#[test]
fn a_file_the_claim_names_that_was_not_handed_over_is_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let key = |content: &[u8]| Digest::of(Algorithm::Sha256, content).to_string();
    let toc: Toc = serde_json::from_str(&format!(
        r#"{{"version":1,"entries":[{{"type":"reg","name":"a","size":4,"digest":"{}"}}]}}"#,
        key(b"good")
    ))
    .unwrap();
    let evil = tmp.path().join("evil");
    std::fs::write(&evil, b"evil").unwrap();
    let mut source = StagedFiles {
        index: tarsplit::content_index(&toc),
        store: None,
        handed: HashMap::from([(
            key(b"evil"),
            Copied {
                path: evil,
                size: 4,
                verity: String::new(),
            },
        )]),
        used: HashSet::new(),
        stored: HashMap::new(),
        last: None,
    };
    match (&mut source).open("a", 4) {
        Err(e) => assert!(e.to_string().contains("was not handed over"), "{e}"),
        Ok(_) => panic!("other content was taken for the claimed one"),
    }
}

/// A file of two names is opened twice and copied once: the second open reads
/// the same copy and does not claim it again.
#[test]
fn a_file_of_two_names_is_one_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let key = Digest::of(Algorithm::Sha256, b"same").to_string();
    let toc: Toc = serde_json::from_str(&format!(
        r#"{{"version":1,"entries":[{{"type":"reg","name":"a","size":4,"digest":"{key}"}},{{"type":"reg","name":"b","size":4,"digest":"{key}"}}]}}"#
    ))
    .unwrap();
    let path = tmp.path().join("copy");
    std::fs::write(&path, b"same").unwrap();
    let mut source = StagedFiles {
        index: tarsplit::content_index(&toc),
        store: None,
        handed: HashMap::from([(
            key,
            Copied {
                path,
                size: 4,
                verity: "verity".into(),
            },
        )]),
        used: HashSet::new(),
        stored: HashMap::new(),
        last: None,
    };
    for (name, first) in [("a", true), ("b", false)] {
        let mut content = Vec::new();
        (&mut source)
            .open(name, 4)
            .unwrap()
            .read_to_end(&mut content)
            .unwrap();
        assert_eq!(content, b"same");
        let opened = source.last.take().unwrap();
        assert_eq!(opened.copy.is_some(), first);
        assert!(opened.verified);
    }
}

/// A file handed over with the digest the claim names it by but not the size
/// the claim says is refused: the copy is not what the layer has there.
#[test]
fn a_file_of_another_size_than_the_claim_says_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let key = Digest::of(Algorithm::Sha256, b"abcd").to_string();
    let toc: Toc = serde_json::from_str(&format!(
        r#"{{"version":1,"entries":[{{"type":"reg","name":"a","size":3,"digest":"{key}"}}]}}"#
    ))
    .unwrap();
    let path = tmp.path().join("copy");
    std::fs::write(&path, b"abcd").unwrap();
    let mut source = StagedFiles {
        index: tarsplit::content_index(&toc),
        store: None,
        handed: HashMap::from([(
            key,
            Copied {
                path,
                size: 4,
                verity: String::new(),
            },
        )]),
        used: HashSet::new(),
        stored: HashMap::new(),
        last: None,
    };
    match (&mut source).open("a", 3) {
        Err(e) => assert!(e.to_string().contains("invalid content"), "{e}"),
        Ok(_) => panic!("a copy of another size was taken"),
    }
}

/// The table of contents of a layer of the canonical tar of a root, a
/// directory and two files, as the writer makes it.
fn canonical_layer() -> Toc {
    use crate::layer::writer::{write_canonical_layer, Compression, ANNOTATION_PREFIX};
    let entries = [
        canonical_entry("./", TocEntryType::Dir, 0),
        canonical_entry("./d/", TocEntryType::Dir, 0),
        canonical_entry("./d/a", TocEntryType::Reg, 5),
        canonical_entry("./d/b", TocEntryType::Reg, 700),
    ];
    let mut tar = Vec::new();
    velarx_storage::canonical::write(&entries, &mut tar, |e, out| {
        out.write_all(&vec![b'a' + e.size as u8 % 20; e.size as usize])
    })
    .unwrap();
    let mut blob = Vec::new();
    let w = write_canonical_layer(
        &tar[..],
        Algorithm::Sha256,
        Compression::ZstdChunked,
        None,
        &mut blob,
    )
    .unwrap();
    let a = |k: &str| w.annotations[&format!("{ANNOTATION_PREFIX}{k}")].clone();
    let position: Vec<u64> = a("manifest-position")
        .split(':')
        .map(|n| n.parse().unwrap())
        .collect();
    let toc_z = &blob[position[0] as usize..(position[0] + position[1]) as usize];
    serde_json::from_slice(&zstd::decode_all(toc_z).unwrap()).unwrap()
}

fn canonical_entry(name: &str, kind: TocEntryType, size: u64) -> TocEntry {
    TocEntry {
        mode: 0o644,
        size,
        ..TocEntry::new(name.to_string(), kind)
    }
}

/// `toc` as the compressed table a descriptor vouches for.
fn vouched(toc: &Toc, tarsplit: Option<(u64, u64, u64)>) -> (Vec<u8>, Info) {
    let json = serde_json::to_vec(toc).unwrap();
    let z = zstd::encode_all(&json[..], 3).unwrap();
    let info = Info {
        toc: (0, z.len() as u64, json.len() as u64),
        checksum: crate::sha256(&z),
        tarsplit,
        table: false,
    };
    (z, info)
}

#[test]
fn test_a_canonical_layer_needs_no_tar_split() {
    let layer = crate::sha256(b"layer");
    let toc = canonical_layer();
    assert!(toc.is_canonical() && toc.tar_split_digest.is_none());
    let (z, info) = vouched(&toc, None);
    let meta = verify_metadata(&info, &z, Vec::new(), &layer, u64::MAX).unwrap();
    assert!(meta.tarsplit_z.is_empty());
    assert_eq!(meta.toc.entries.len(), toc.entries.len());
}

#[test]
fn test_a_table_of_version_2_that_is_not_canonical_is_an_error_that_names_the_layer() {
    let layer = crate::sha256(b"layer");
    let good = canonical_layer();
    let refused = |toc: &Toc, tarsplit| {
        let (z, info) = vouched(toc, tarsplit);
        let e = verify_metadata(&info, &z, b"ts".to_vec(), &layer, u64::MAX)
            .err()
            .unwrap();
        // (the descriptor vouches for it: the layer is not pulled whole)
        assert!(refuses(&e), "{e}");
        let text = e.to_string();
        assert!(text.contains(&layer.to_string()), "{text}");
        assert!(text.contains("version 2 table of contents"), "{text}");
        text
    };
    // names not in the order of the tar
    let mut toc = good.clone();
    toc.entries.swap(2, 3);
    assert!(refused(&toc, None).contains("sorts before"));
    // a name that is not a canonical path
    let mut toc = good.clone();
    toc.entries[2].name = "d/a".into();
    refused(&toc, None);
    // a file with content and no fs-verity digest
    let mut toc = good.clone();
    toc.entries[3].fsverity = None;
    assert!(refused(&toc, None).contains("fs-verity"));
    // a table that has a tar-split, or says it has
    let mut toc = good.clone();
    toc.tar_split_digest = Some(crate::sha256(b"ts").to_string());
    assert!(refused(&toc, None).contains("tar-split"));
    assert!(refused(&good, Some((0, 2, 0))).contains("tar-split"));
    // an entry the tar cannot say
    let mut toc = good.clone();
    toc.entries[1].size = 3;
    refused(&toc, None);
}

#[test]
fn test_a_table_of_version_1_without_a_tar_split_is_an_error_that_names_the_layer() {
    let layer = crate::sha256(b"layer");
    let toc = Toc {
        version: 1,
        entries: Vec::new(),
        tar_split_digest: None,
    };
    for toc in [toc.clone(), Toc { version: 3, ..toc }] {
        let (z, info) = vouched(&toc, None);
        let e = verify_metadata(&info, &z, Vec::new(), &layer, u64::MAX)
            .err()
            .unwrap();
        let text = e.to_string();
        assert!(text.contains(&layer.to_string()), "{text}");
        assert!(
            text.contains("no tar-split and is not of version 2"),
            "{text}"
        );
    }
}

#[test]
fn test_a_table_of_version_1_without_the_fs_verity_digest_of_a_file_is_an_error() {
    let layer = crate::sha256(b"layer");
    let mut file = canonical_layer().entries[3].clone();
    assert!(file.verity().is_some());
    let ts = tarsplit_of(std::slice::from_ref(&file));
    let tarsplit = crate::sha256(&ts).to_string();
    let toc = |file: &TocEntry| Toc {
        version: 1,
        entries: vec![file.clone()],
        tar_split_digest: Some(tarsplit.clone()),
    };
    let (z, info) = vouched(&toc(&file), Some((0, ts.len() as u64, 0)));
    assert!(verify_metadata(&info, &z, ts.clone(), &layer, u64::MAX).is_ok());
    file.fsverity = None;
    let (z, info) = vouched(&toc(&file), Some((0, ts.len() as u64, 0)));
    let e = verify_metadata(&info, &z, ts, &layer, u64::MAX)
        .err()
        .unwrap();
    let text = e.to_string();
    assert!(text.contains(&layer.to_string()), "{text}");
    assert!(
        text.contains(&format!("no fs-verity digest for `{}`", file.name)),
        "{text}"
    );
}

/// A tar-split that describes another file than the table is refused by
/// the pull that commits the layer, not by the check of a lazy pull (its
/// completion replays it before the commit).
#[test]
fn test_a_tar_split_the_table_contradicts_is_refused_by_the_pull() {
    let layer = crate::sha256(b"layer");
    let file = canonical_layer().entries[3].clone();
    let ts = tarsplit_of(std::slice::from_ref(&file));
    let mut other = file.clone();
    other.name = format!("{}.other", file.name);
    let toc = Toc {
        version: 1,
        entries: vec![other.clone()],
        tar_split_digest: Some(crate::sha256(&ts).to_string()),
    };
    let (z, info) = vouched(&toc, Some((0, ts.len() as u64, 0)));
    assert!(verified_table(&info, &z, ts.clone(), &layer, (u64::MAX, false)).is_ok());
    let e = verify_metadata(&info, &z, ts, &layer, u64::MAX)
        .err()
        .unwrap();
    assert!(matches!(e, ImageError::Contradicted(_)), "{e}");
    assert!(e.to_string().contains(".other`"), "{e}");
}

/// A lazy start does without the tar-split: the table is checked, the
/// tar-split is checked when it comes ([`check_tarsplit`] at the
/// completion), and a pull that commits the layer at once needs it.
#[test]
fn test_a_lazy_start_needs_no_tar_split() {
    let layer = crate::sha256(b"layer");
    let file = canonical_layer().entries[3].clone();
    let ts = tarsplit_of(std::slice::from_ref(&file));
    let toc = Toc {
        version: 1,
        entries: vec![file],
        tar_split_digest: Some(crate::sha256(&ts).to_string()),
    };
    let (z, info) = vouched(&toc, Some((0, ts.len() as u64, 0)));
    let lazy = verified_table(&info, &z, Vec::new(), &layer, (u64::MAX, false)).unwrap();
    assert!(lazy.tarsplit_z.is_empty());
    // (the table the layer is stored by keeps the digest of its tar-split)
    assert!(check_tarsplit(&lazy.stored, &ts).is_ok());
    let e = check_tarsplit(&lazy.stored, b"tx").unwrap_err();
    assert!(matches!(e, ImageError::DigestMismatch { .. }), "{e}");
    // (one that comes all the same is checked)
    let e = verified_table(&info, &z, b"tx".to_vec(), &layer, (u64::MAX, false))
        .err()
        .unwrap();
    assert!(matches!(e, ImageError::DigestMismatch { .. }), "{e}");
    assert!(verify_metadata(&info, &z, Vec::new(), &layer, u64::MAX).is_err());
    // (a table without the digest of its tar-split is refused at the start)
    let toc = Toc {
        tar_split_digest: None,
        ..toc
    };
    let (z, info) = vouched(&toc, Some((0, ts.len() as u64, 0)));
    assert!(verified_table(&info, &z, Vec::new(), &layer, (u64::MAX, false)).is_err());
}

/// `file` again under `name`, 4096 bytes larger (the last chunk too).
fn bigger_copy(file: &TocEntry, name: &str) -> TocEntry {
    let mut copy = file.clone();
    copy.name = name.to_string();
    copy.size += 4096;
    if copy.chunk_size != 0 {
        copy.chunk_size += 4096;
    }
    copy
}

#[test]
fn test_a_table_that_lists_one_digest_with_two_sizes_is_an_error_that_names_the_layer() {
    let layer = crate::sha256(b"layer");
    let digest = canonical_layer().entries[3].verity().unwrap();
    let refused = |toc: Toc, tarsplit: Option<(u64, u64, u64)>, ts: Vec<u8>| {
        let (z, info) = vouched(&toc, tarsplit);
        let e = verify_metadata(&info, &z, ts, &layer, u64::MAX)
            .err()
            .unwrap();
        assert!(refuses(&e), "{e}");
        let text = e.to_string();
        assert!(text.contains(&layer.to_string()), "{text}");
        assert!(text.contains(&digest), "{text}");
        assert!(text.contains("two sizes"), "{text}");
    };
    // version 2
    let mut toc = canonical_layer();
    let copy = bigger_copy(&toc.entries[3], "./d/c");
    toc.entries.push(copy);
    refused(toc, None, Vec::new());
    // version 1: the tar-split describes the same entries
    let file = canonical_layer().entries[3].clone();
    let entries = vec![file.clone(), bigger_copy(&file, "./c")];
    let ts = tarsplit_of(&entries);
    let toc = Toc {
        version: 1,
        entries,
        tar_split_digest: Some(crate::sha256(&ts).to_string()),
    };
    refused(toc, Some((0, ts.len() as u64, 0)), ts);
}

#[test]
fn test_a_table_of_version_1_whose_files_are_more_than_the_limit_is_refused() {
    let layer = crate::sha256(b"layer");
    let file = canonical_layer().entries[3].clone();
    let entries = vec![file.clone()];
    let ts = tarsplit_of(&entries);
    let toc = Toc {
        version: 1,
        entries,
        tar_split_digest: Some(crate::sha256(&ts).to_string()),
    };
    let (z, info) = vouched(&toc, Some((0, ts.len() as u64, 0)));
    let check = |max| verify_metadata(&info, &z, ts.clone(), &layer, max);
    check(file.size).unwrap();
    let e = check(file.size - 1).err().unwrap();
    assert!(refuses(&e), "{e}");
    let text = e.to_string();
    assert!(text.contains(&layer.to_string()), "{text}");
    assert!(text.contains("more than"), "{text}");
}

#[test]
fn test_a_table_whose_files_do_not_fit_a_layer_is_an_error_that_names_the_layer() {
    let layer = crate::sha256(b"layer");
    let good = canonical_layer();
    let refused = |toc: &Toc, tarsplit, ts: Vec<u8>, max| {
        let (z, info) = vouched(toc, tarsplit);
        let e = verify_metadata(&info, &z, ts, &layer, max).err().unwrap();
        assert!(refuses(&e), "{e}");
        assert!(e.to_string().contains(&layer.to_string()), "{e}");
    };
    // version 2: a file of 2^64-1 bytes, and a layer larger than the limit
    let mut toc = good.clone();
    toc.entries[3].size = u64::MAX;
    refused(&toc, None, Vec::new(), u64::MAX);
    refused(&good, None, Vec::new(), 1000);
    let (z, info) = vouched(&good, None);
    assert!(verify_metadata(&info, &z, Vec::new(), &layer, 1 << 20).is_ok());
    // version 1: sizes that add up to more than a u64
    let mut file = good.entries[3].clone();
    file.size = u64::MAX / 2 + 1;
    let mut other = file.clone();
    other.name = "./c".into();
    other.fsverity = good.entries[2].fsverity;
    let toc = Toc {
        version: 1,
        entries: vec![file, other],
        tar_split_digest: Some(crate::sha256(b"ts").to_string()),
    };
    refused(&toc, Some((0, 2, 0)), b"ts".to_vec(), u64::MAX);
}

#[test]
fn test_a_layer_with_a_table_is_never_read_as_a_stream() {
    let prefix = "io.github.containers.zstd-chunked.";
    let chunked = layer(
        &[
            (&format!("{prefix}manifest-position"), "100:50:200:1"),
            (
                &format!("{prefix}manifest-checksum"),
                &crate::sha256_text(b""),
            ),
        ],
        ZSTD,
    );
    let e = no_table(&chunked).unwrap_err().to_string();
    assert!(e.contains(&chunked.digest.to_string()), "{e}");
    assert!(e.contains("zstd:chunked"), "{e}");
    // (a layer with no labels, or a gzip layer, is one)
    no_table(&layer(&[], ZSTD)).unwrap();
}

/// The entries of a table are read apart, on several threads, and are the
/// ones the whole document has, in its order.
#[test]
fn test_a_table_is_parsed_to_the_same_entries_whichever_the_way() {
    let entries: Vec<TocEntry> = (0..2000u64)
        .map(|i| {
            let mut e = reg(
                &format!("d{}/f{i}", i % 7),
                &d(i as u8),
                10 + i,
                0,
                100,
                None,
            );
            e.mod_time = Some("2024-01-02T03:04:05+00:00".into());
            e.xattrs.insert("user.k".into(), "eA==".into());
            e
        })
        .collect();
    let toc = Toc {
        version: 1,
        entries,
        tar_split_digest: Some(d(9)),
    };
    let json = serde_json::to_vec(&toc).unwrap();
    let parsed = parse_toc(&json).unwrap();
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.tar_split_digest, toc.tar_split_digest);
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        serde_json::to_value(&toc).unwrap()
    );
    // a document that is not a table, in any of its parts
    let text = String::from_utf8(json).unwrap();
    for bad in [
        text.replacen("\"mode\"", "\"mode\":\"x\",\"mode\"", 1),
        text.replacen("\"size\":", "\"size\":-", 1),
        text.replacen("\"type\":\"reg\"", "\"type\":\"nope\"", 1),
        text[..text.len() - 2].to_string(),
        format!("{text} x"),
        text.replacen("\"version\":1,", "", 1),
    ] {
        assert!(parse_toc(bad.as_bytes()).is_err(), "{bad:.200}");
    }
}

/// A disk that is full is a failure of this end: the source of an index is
/// not passed over for it, as it is for an index that does not replay.
#[test]
fn a_full_disk_is_no_fault_of_the_index() {
    let full = ImageError::Io(io::Error::from_raw_os_error(libc::ENOSPC));
    assert!(of_this_end(&full));
    assert!(of_this_end(&ImageError::transfer(
        "store",
        FailureClass::NoSpace,
        "full"
    )));
    assert!(!of_this_end(&ImageError::Contradicted("wrong".into())));
    assert!(!of_this_end(&ImageError::DigestMismatch {
        expected: "a".into(),
        actual: "b".into(),
    }));
}

/// A layer of a root, a directory, two files and a hard link written with
/// `alg` (a canonical tar or one with a tar-split), and its descriptor.
fn written(alg: Algorithm, canonical: bool) -> (Vec<u8>, OciDescriptor) {
    use crate::layer::writer::{write_canonical_layer, write_layer, Compression};
    let mut entries = vec![
        canonical_entry("./", TocEntryType::Dir, 0),
        canonical_entry("./d/", TocEntryType::Dir, 0),
        canonical_entry("./d/a", TocEntryType::Reg, 5),
        canonical_entry("./d/b", TocEntryType::Reg, 200_000),
    ];
    let mut link = canonical_entry("./d/c", TocEntryType::Hardlink, 0);
    link.link_name = Some("./d/a".into());
    entries.push(link);
    let mut tar = Vec::new();
    velarx_storage::canonical::write(&entries, &mut tar, |e, out| {
        let bytes: Vec<u8> = (0..e.size).map(|i| (i * 7 % 251) as u8).collect();
        out.write_all(&bytes)
    })
    .unwrap();
    let mut blob = Vec::new();
    let c = Compression::ZstdChunked;
    let w = match canonical {
        true => write_canonical_layer(&tar[..], alg, c, None, &mut blob),
        false => write_layer(&tar[..], alg, c, &mut blob),
    }
    .unwrap();
    let desc = OciDescriptor {
        media_type: ZSTD.into(),
        digest: w.digest,
        size: blob.len() as i64,
        annotations: w.annotations.into_iter().collect(),
    };
    (blob, desc)
}

/// The metadata of `desc` as a pull verifies it, from the ranges of
/// `blob` its annotations name.
fn pulled(blob: &[u8], desc: &OciDescriptor, lazy: bool) -> ImageResult<Metadata> {
    let info = parse_info(desc)?.unwrap();
    let range = |(off, len, _): (u64, u64, u64)| blob[off as usize..(off + len) as usize].to_vec();
    let ts = info.tarsplit.map(range).unwrap_or_default();
    match lazy {
        true => verified_table(
            &info,
            &range(info.toc),
            Vec::new(),
            &desc.digest,
            (u64::MAX, false),
        ),
        false => verify_metadata(&info, &range(info.toc), ts, &desc.digest, u64::MAX),
    }
}

/// A descriptor without the annotations of the binary table: what a reader
/// that does not know it sees.
fn without_table(desc: &OciDescriptor) -> OciDescriptor {
    let mut old = desc.clone();
    old.annotations.retain(|k, _| !k.contains("table-"));
    old
}

/// A layer with a binary table is pulled by it, lazily or not, with the
/// digests of its algorithm, and is the same layer as by its JSON TOC (what
/// a reader that does not know the table takes, the content digests of the
/// files aside); a layer without one is pulled by its JSON TOC.
#[test]
fn test_a_layer_is_pulled_by_its_binary_table() {
    for alg in Algorithm::ALL {
        for canonical in [true, false] {
            let (blob, desc) = written(alg, canonical);
            let info = parse_info(&desc).unwrap().unwrap();
            assert!(info.table);
            assert_eq!(info.checksum.alg(), alg);
            assert_eq!(LayerKey::expected(&desc), LayerKey::Toc(info.checksum));
            let old = without_table(&desc);
            assert!(!parse_info(&old).unwrap().unwrap().table);
            for lazy in [false, true] {
                let by_table = pulled(&blob, &desc, lazy).unwrap();
                let by_json = pulled(&blob, &old, lazy).unwrap();
                let view = |t: &Toc| {
                    t.entries
                        .iter()
                        .map(|e| {
                            (
                                e.name.clone(),
                                e.entry_type,
                                e.size,
                                e.fsverity,
                                e.link_name.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                let names = |t: &Toc| {
                    t.entries
                        .iter()
                        .map(|e| e.name.trim_start_matches("./").to_string())
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    names(&by_table.stored),
                    names(&by_json.stored),
                    "{alg} {canonical} {lazy}"
                );
                if canonical {
                    assert_eq!(view(&by_table.stored), view(&by_json.stored));
                }
                assert!(by_table
                    .stored
                    .entries
                    .iter()
                    .all(|e| e.fsverity.is_none_or(|v| v.alg() == alg)));
                assert_eq!(by_table.toc_z.len() as u64, info.toc.1);
            }
        }
    }
}

/// A table that its checksum vouches for and that cannot be used is an
/// error that names the layer, never a reason to read the JSON TOC.
#[test]
fn test_a_table_that_cannot_be_used_is_an_error() {
    let (blob, desc) = written(Algorithm::Sha256, true);
    let info = parse_info(&desc).unwrap().unwrap();
    let (off, len, raw) = info.toc;
    let mut table = zstd::decode_all(&blob[off as usize..(off + len) as usize]).unwrap();
    // (the first name, after the root's, made a `/`)
    let names = u64::from_le_bytes(table[32 + 32 + 16..32 + 32 + 24].try_into().unwrap());
    table[names as usize] = b'/';
    let z = zstd::encode_all(&table[..], 3).unwrap();
    let bad = Info {
        toc: (off, z.len() as u64, raw),
        checksum: crate::sha256(&z),
        ..info.clone()
    };
    let e = verify_metadata(&bad, &z, Vec::new(), &desc.digest, u64::MAX)
        .err()
        .unwrap();
    assert!(matches!(e, ImageError::Contradicted(_)), "{e}");
    assert!(
        e.to_string().contains("invalid table") && e.to_string().contains(&desc.digest.to_string()),
        "{e}"
    );
    // a sha256 table vouched for by a sha512 checksum
    let z = &blob[off as usize..(off + len) as usize];
    let other = Info {
        checksum: Digest::of(Algorithm::Sha512, z),
        ..info
    };
    let e = verify_metadata(&other, z, Vec::new(), &desc.digest, u64::MAX)
        .err()
        .unwrap();
    assert!(
        e.to_string()
            .contains("the digests of its table are sha256"),
        "{e}"
    );
}

#[test]
fn test_parse_info_of_a_binary_table() {
    let prefix = "io.github.containers.zstd-chunked.";
    let checksum = crate::sha256_text(b"t");
    let both = layer(
        &[
            (&format!("{prefix}manifest-position"), "100:50:200:1"),
            (
                &format!("{prefix}manifest-checksum"),
                &crate::sha256_text(b""),
            ),
            (&format!("{prefix}table-position"), "10:20:30"),
            (&format!("{prefix}table-checksum"), &checksum),
            (&format!("{prefix}version"), "2"),
        ],
        ZSTD,
    );
    let i = parse_info(&both).unwrap().unwrap();
    assert_eq!(
        (i.toc, i.checksum.to_string(), i.table),
        ((10, 20, 30), checksum.clone(), true)
    );
    // a table alone (no JSON TOC) is a table too
    let mut alone = both.clone();
    alone.annotations.retain(|k, _| !k.contains("manifest-"));
    assert_eq!(parse_info(&alone).unwrap().unwrap(), i);
    // half of the table, or a position of another form: refused, not read by
    // the JSON TOC
    for (name, value) in [
        ("table-position", None),
        ("table-checksum", None),
        ("table-position", Some("10:20:30:1")),
        ("table-checksum", Some("sha256:zz")),
    ] {
        let mut bad = both.clone();
        let key = format!("{prefix}{name}");
        match value {
            Some(v) => bad.annotations.insert(key, v.into()),
            None => bad.annotations.remove(&key),
        };
        assert!(parse_info(&bad).is_err(), "{name} {value:?}");
    }
}
