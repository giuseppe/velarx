// SPDX-License-Identifier: Apache-2.0
fn cap(blob: i64) -> u64 {
    crate::pull::inflate_limit(blob, 128, 64 << 20, 1 << 40)
}

use super::*;
use bytes::Bytes;
use std::collections::HashMap;

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
        name: name.into(),
        entry_type: TocEntryType::Reg,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size,
        digest: Some(d.into()),
        fsverity: None,
        offset,
        end_offset: end,
        chunk_digest: chunk.map(|c| c.0.to_string()),
        chunk_size: chunk.map_or(0, |c| c.1),
        chunk_offset: 0,
        chunk_type: None,
        link_name: None,
        mod_time: None,
        access_time: None,
        change_time: None,
        dev_major: None,
        dev_minor: None,
        xattrs: HashMap::new(),
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
    let have = |x: &str| x == d(2);
    let plan = make_plan(&t, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &have).unwrap();
    assert_eq!(plan.jobs.len(), 1);
    assert_eq!(plan.jobs[0].name, "a");
    assert_eq!(plan.skipped_files, 2);
    assert_eq!(plan.skipped_compressed, 200);
    assert_eq!(plan.chunks.len(), 1);
    assert_eq!(plan.chunks[0].comp, 0..100);
    assert!(plan.chunks[0].digest.is_none());
}

#[test]
fn test_plan_multi_chunk_file() {
    let t = toc(vec![
        reg("f", &d(9), 30, 100, 160, Some((&d(1), 10))),
        chunk("f", &d(2), 10, 10, 120),
        chunk("f", &d(3), 10, 20, 140),
    ]);
    let plan = make_plan(&t, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &|_| false).unwrap();
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
    let plan = make_plan(&t, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &|_| false).unwrap();
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
    let plan = make_plan(&t, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &|_| false).unwrap();
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
            &|_| false
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
            &|_| false
        )
        .is_err());
    }
}

#[test]
fn test_plan_limits() {
    let big = toc(vec![reg("f", &d(1), 1 << 30, 0, 10, None)]);
    assert!(matches!(
        make_plan(&big, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &|_| {
            false
        }),
        Err(ImageError::Layer(_))
    ));
    // 1 GiB of files from a blob of 1000 bytes is over the floor of the cap.
    let t = toc(vec![
        reg("a", &d(1), 1 << 30, 0, 10, None),
        reg("b", &d(2), 1 << 30, 10, 20, None),
    ]);
    assert!(make_plan(&t, Algorithm::Sha256, 1000, 2 << 30, cap(1000), &|_| false).is_err());
    let small = toc(vec![reg("a", &d(1), 1 << 20, 0, 10, None)]);
    assert!(
        make_plan(&small, Algorithm::Sha256, 1000, 1 << 20, cap(1000), &|_| {
            false
        })
        .is_ok()
    );
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
        local: None,
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
    // a registry that ignores Range: one request of everything
    let learnt = Learnt {
        per_request: None,
        whole: true,
    };
    let batches = make_batches(&comps(&chunks), &remote, 4, learnt);
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].ranges, vec![0..19 * (2 << 20) + (64 << 10)]);
    assert_eq!(batches[0].members[0], remote);
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
    };
    let layer = crate::sha256(b"layer");
    assert!(verify_metadata(&info, &toc_z, ts.clone(), &layer).is_ok());
    let mut bad = info.clone();
    bad.checksum = crate::sha256(b"other");
    assert!(verify_metadata(&bad, &toc_z, ts.clone(), &layer).is_err());
    assert!(verify_metadata(&info, &toc_z, b"tx".to_vec(), &layer).is_err());
    let mut bad = info.clone();
    bad.toc.2 += 1;
    assert!(verify_metadata(&bad, &toc_z, ts, &layer).is_err());
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

fn shared_for(plan: Plan) -> (tempfile::TempDir, Arc<Shared>) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(velarx_storage::FileStore::new(tmp.path().join("files")).unwrap());
    let session =
        crate::pull::session::Session::create(&tmp.path().join("staging"), store).unwrap();
    (tmp, Shared::new(session, plan))
}

/// A file of three chunks and a hole in the middle, whose chunks arrive
/// in the worst order, is hashed and staged under its digest.
#[test]
fn test_out_of_order_chunks_with_a_hole() {
    let (a, b) = (vec![1u8; 100], vec![2u8; 50]);
    let mut content = a.clone();
    content.extend(vec![0u8; 30]);
    content.extend(&b);
    let file_digest = crate::sha256_text(&content);
    let plan = Plan {
        jobs: vec![FileJob {
            name: "f".into(),
            digest: file_digest.clone(),
            content: Some(file_digest.clone()),
            size: content.len() as u64,
            holes: vec![(100, 30)],
            chunks: 0..2,
        }],
        chunks: vec![
            ChunkPlan {
                job: 0,
                file_off: 0,
                size: 100,
                digest: Some(crate::sha256(&a)),
                comp: 0..1,
                local: None,
            },
            ChunkPlan {
                job: 0,
                file_off: 130,
                size: 50,
                digest: Some(crate::sha256(&b)),
                comp: 1..2,
                local: None,
            },
        ],
        ..Plan::default()
    };
    let (_tmp, sh) = shared_for(plan);
    let zb = zstd::encode_all(&b[..], 3).unwrap();
    let za = zstd::encode_all(&a[..], 3).unwrap();
    process_chunk(&sh, 1, Bytes::from(zb)).unwrap();
    assert!(!sh.files[0].lock().unwrap().done);
    process_chunk(&sh, 0, Bytes::from(za)).unwrap();
    assert!(sh.files[0].lock().unwrap().done);
    let path = sh.stage.content_path(&file_digest).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), content);
    assert_eq!(sh.files[0].lock().unwrap().verified.len(), 2);
}

/// The files of a driver (`FilesSink`) are not checked by anything after the
/// fetch: a file is told whole only when what is at its place is what its key
/// names.  The one chunk of a file known by the hash of its content has no
/// digest of its own, and an fs-verity key is tied to no chunk: bytes that are
/// not the key are a contradiction of the table of contents, and the driver is
/// not told the object is whole.
#[test]
fn test_a_driver_file_is_told_whole_only_when_it_is_its_key() {
    use crate::pull::sink::{FilesSink, Slot, Written};
    use std::os::unix::fs::FileExt;
    let content = b"the content of the file".to_vec();
    let verity = velarx_storage::fsverity_digest_of(Algorithm::Sha256, &content);
    for (key, chunk_digest, content_key) in [
        // known by the hash of its content: its one chunk has no digest
        (
            crate::sha256_text(&content),
            None,
            Some(crate::sha256_text(&content)),
        ),
        // known by its fs-verity digest: its chunk is checked by the hash
        (verity.clone(), Some(crate::sha256(&content)), None),
    ] {
        for bytes in [content.clone(), b"other bytes, the same size!".to_vec()] {
            let bytes = &bytes[..content.len()];
            let plan = Plan {
                jobs: vec![FileJob {
                    name: "f".into(),
                    digest: key.clone(),
                    content: content_key.clone(),
                    size: content.len() as u64,
                    holes: vec![],
                    chunks: 0..1,
                }],
                chunks: vec![ChunkPlan {
                    job: 0,
                    file_off: 0,
                    size: content.len() as u64,
                    // (the bytes of the fs-verity case are checked against
                    // the chunk's digest, which is the TOC's: here it is
                    // made of the bytes, as a table that lies has it)
                    digest: chunk_digest.as_ref().map(|_| crate::sha256(bytes)),
                    comp: 0..1,
                    local: None,
                }],
                ..Plan::default()
            };
            let tmp = tempfile::tempdir().unwrap();
            let pack = tempfile::tempfile().unwrap();
            let told: Arc<Mutex<Vec<String>>> = Arc::default();
            let sink = FilesSink::new(
                "test",
                tmp.path(),
                [(
                    key.clone(),
                    Slot {
                        file: Arc::new(pack.try_clone().unwrap()),
                        base: 4096,
                        size: content.len() as u64,
                    },
                )],
                {
                    let told = told.clone();
                    move |w| {
                        if let Written::Whole { key } = w {
                            told.lock().unwrap().push(key);
                        }
                    }
                },
            )
            .unwrap();
            let sh = Shared::new(sink, plan);
            let z = zstd::encode_all(bytes, 3).unwrap();
            let r = process_chunk(&sh, 0, Bytes::from(z));
            if bytes == &content[..] {
                r.unwrap();
                assert_eq!(*told.lock().unwrap(), vec![key.clone()]);
                let mut back = vec![0u8; content.len()];
                pack.read_exact_at(&mut back, 4096).unwrap();
                assert_eq!(back, content);
            } else {
                let e = r.expect_err("bytes that are not the key");
                assert!(matches!(e, ImageError::Contradicted(_)), "{key}: {e}");
                assert!(told.lock().unwrap().is_empty(), "{key}: told whole");
            }
        }
    }
}

/// A file whose chunks are all zeros has nothing to fetch: it is made
/// and staged at once, not waited for.
#[test]
fn test_a_file_of_zeros_chunks_only_is_completed() {
    let content = vec![0u8; 4096];
    let mut f = reg(
        "z",
        &crate::sha256_text(&content),
        4096,
        100,
        110,
        Some((&d(1), 4096)),
    );
    f.chunk_type = Some("zeros".into());
    let plan = make_plan(
        &toc(vec![f]),
        Algorithm::Sha256,
        1000,
        1 << 20,
        cap(1000),
        &|_| false,
    )
    .unwrap();
    assert!(plan.chunks.is_empty());
    assert_eq!(plan.jobs.len(), 1);
    let (_tmp, sh) = shared_for(plan);
    sh.complete_without_chunks().unwrap();
    assert!(sh.files[0].lock().unwrap().done);
    let path = sh
        .stage
        .content_path(&crate::sha256_text(&content))
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), content);

    // zeros that are not the content the TOC says
    let mut f = reg("z", &d(7), 4096, 100, 110, Some((&d(1), 4096)));
    f.chunk_type = Some("zeros".into());
    let plan = make_plan(
        &toc(vec![f]),
        Algorithm::Sha256,
        1000,
        1 << 20,
        cap(1000),
        &|_| false,
    )
    .unwrap();
    let (_tmp, sh) = shared_for(plan);
    assert!(sh.complete_without_chunks().is_err());
}

/// A plan of one file made of `parts`, each a chunk (no chunk digest
/// for a file of one chunk: its digest is the file's).
fn plan_of(parts: &[Vec<u8>]) -> (Plan, Vec<u8>) {
    let content: Vec<u8> = parts.concat();
    let mut chunks = Vec::new();
    let mut off = 0;
    for (i, p) in parts.iter().enumerate() {
        chunks.push(ChunkPlan {
            job: 0,
            file_off: off,
            size: p.len() as u64,
            digest: (parts.len() > 1).then(|| crate::sha256(p)),
            comp: i as u64..i as u64 + 1,
            local: None,
        });
        off += p.len() as u64;
    }
    let plan = Plan {
        jobs: vec![FileJob {
            name: "f".into(),
            digest: crate::sha256_text(&content),
            content: Some(crate::sha256_text(&content)),
            size: content.len() as u64,
            holes: vec![],
            chunks: 0..parts.len(),
        }],
        chunks,
        ..Plan::default()
    };
    (plan, content)
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
    assert!(e.to_string().contains("down"), "{e}");
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

/// A stage with no room: every file it is asked for fails with ENOSPC.
struct FullStage;

impl Stage for FullStage {
    fn create_temp(&self) -> io::Result<(File, Option<std::path::PathBuf>)> {
        Err(io::Error::from_raw_os_error(libc::ENOSPC))
    }
    fn takes_files(&self) -> bool {
        false
    }
    fn adopt(&self, _: Finished) -> io::Result<bool> {
        unreachable!("nothing was written")
    }
    fn open_object(&self, _: &str) -> io::Result<File> {
        Err(io::Error::from_raw_os_error(libc::ENOSPC))
    }
    fn content_path(&self, _: &str) -> Option<std::path::PathBuf> {
        None
    }
}

/// A write that fails on this machine (no space) is its own error, not the
/// layer's: it is not one of what the descriptor vouches for.
#[test]
fn test_a_chunk_that_cannot_be_written_is_the_error_of_the_pull() {
    let parts = vec![vec![1u8; 100]];
    let (plan, _) = plan_of(&parts);
    let sh = Shared::new(Arc::new(FullStage), plan);
    let e = process_chunk(
        &sh,
        0,
        Bytes::from(zstd::encode_all(&parts[0][..], 3).unwrap()),
    )
    .unwrap_err();
    assert!(
        matches!(&e, ImageError::Io(x) if x.raw_os_error() == Some(libc::ENOSPC)),
        "{e:?}"
    );
    assert!(!refuses(&e));
    // the bytes of a layer that are no stream are the layer's
    let bad = decompress_bounded(b"not zstd", 100, 0, "TOC").unwrap_err();
    assert!(matches!(bad, ImageError::Layer(_)), "{bad:?}");
}

#[test]
fn test_bad_chunk_content_is_rejected() {
    let a = vec![1u8; 100];
    let plan = Plan {
        jobs: vec![FileJob {
            name: "f".into(),
            digest: crate::sha256_text(&a),
            content: Some(crate::sha256_text(&a)),
            size: 100,
            holes: vec![],
            chunks: 0..1,
        }],
        chunks: vec![ChunkPlan {
            job: 0,
            file_off: 0,
            size: 100,
            digest: Some(crate::sha256(&a)),
            comp: 0..1,
            local: None,
        }],
        ..Plan::default()
    };
    let (_tmp, sh) = shared_for(plan);
    let z = zstd::encode_all(&vec![9u8; 100][..], 3).unwrap();
    assert!(process_chunk(&sh, 0, Bytes::from(z)).is_err());
    let z = zstd::encode_all(&vec![1u8; 200][..], 3).unwrap();
    assert!(process_chunk(&sh, 0, Bytes::from(z)).is_err());
    assert!(process_chunk(&sh, 0, Bytes::from_static(b"garbage")).is_err());
    assert!(sh.stage.content_path(&crate::sha256_text(&a)).is_none());
}

#[test]
fn test_file_digest_mismatch_is_rejected() {
    let a = vec![1u8; 100];
    let plan = Plan {
        jobs: vec![FileJob {
            name: "f".into(),
            digest: crate::sha256_text(b"something else"),
            content: Some(crate::sha256_text(b"something else")),
            size: 100,
            holes: vec![],
            chunks: 0..1,
        }],
        chunks: vec![ChunkPlan {
            job: 0,
            file_off: 0,
            size: 100,
            digest: Some(crate::sha256(&a)),
            comp: 0..1,
            local: None,
        }],
        ..Plan::default()
    };
    let (_tmp, sh) = shared_for(plan);
    let z = zstd::encode_all(&a[..], 3).unwrap();
    let err = process_chunk(&sh, 0, Bytes::from(z)).unwrap_err();
    assert!(err.to_string().contains("the TOC says"));
    assert!(!sh.files[0].lock().unwrap().done);
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
        e.fsverity = Some(v.into());
        toc(vec![e])
    };
    let plan = |t: &Toc, alg| make_plan(t, alg, 1000, 1 << 20, cap(1000), &|_| false);
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
    let plan = |t: &Toc, alg| make_plan(t, alg, 1000, 1 << 20, cap(1000), &|_| false);
    let file = reg("f", &d512(1), 10, 0, 100, None);
    let t = toc(vec![file.clone()]);
    let p = plan(&t, Algorithm::Sha512).unwrap();
    assert_eq!((p.alg, p.jobs.len()), (Algorithm::Sha512, 1));
    assert_eq!(p.jobs[0].content.as_deref(), Some(d512(1).as_str()));
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
    assert!(p.jobs[0].content.is_none());
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

/// A stage whose owner holds the object a chunk is in takes the copy: the
/// chunk is told to the owner, not written, and the file is told whole
/// without being measured (the owner has not applied the copy yet; the engine
/// reads the layer back).
#[test]
fn test_a_chunk_the_driver_holds_is_copied_not_written() {
    use crate::pull::sink::{FilesSink, Holds, Sink, Slot, Written};
    use std::os::unix::fs::FileExt;
    let head = vec![1u8; 100];
    let tail = vec![2u8; 60];
    let key = crate::sha256_text(&[head.clone(), tail.clone()].concat());
    let held: Holds = Arc::new(|keys: &[String]| Ok(keys.iter().map(|k| k == "held").collect()));
    let plan = Plan {
        jobs: vec![FileJob {
            name: "f".into(),
            digest: key.clone(),
            content: Some(key.clone()),
            size: 160,
            holes: vec![],
            chunks: 0..2,
        }],
        chunks: vec![
            ChunkPlan {
                job: 0,
                file_off: 0,
                size: 100,
                digest: Some(crate::sha256(&head)),
                comp: 0..1,
                local: Some(("held".into(), 7)),
            },
            ChunkPlan {
                job: 0,
                file_off: 100,
                size: 60,
                digest: Some(crate::sha256(&tail)),
                comp: 1..2,
                local: None,
            },
        ],
        ..Plan::default()
    };
    let tmp = tempfile::tempdir().unwrap();
    let pack = tempfile::tempfile().unwrap();
    let told: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = FilesSink::holding(
        "test",
        tmp.path(),
        [(
            key.clone(),
            Slot {
                file: Arc::new(pack.try_clone().unwrap()),
                base: 4096,
                size: 160,
            },
        )],
        {
            let told = told.clone();
            move |w| {
                told.lock().unwrap().push(match w {
                    Written::Whole { key } => format!("whole {key}"),
                    Written::Copy {
                        at,
                        from,
                        from_offset,
                        len,
                        ..
                    } => format!("copy {at} {from} {from_offset} {len}"),
                    Written::Hole { .. } => "hole".into(),
                    Written::Staged { key, .. } => format!("staged {key}"),
                })
            }
        },
        Some(held),
    )
    .unwrap();
    assert_eq!(
        sink.held(&["held".into(), "other".into()]).unwrap(),
        [true, false]
    );
    let sh = Shared::new(sink, plan);
    process_local(&sh, 0).unwrap();
    assert_eq!(*told.lock().unwrap(), vec!["copy 0 held 7 100"]);
    let z = zstd::encode_all(&tail[..], 3).unwrap();
    process_chunk(&sh, 1, Bytes::from(z)).unwrap();
    assert_eq!(
        *told.lock().unwrap(),
        vec!["copy 0 held 7 100".to_string(), format!("whole {key}")]
    );
    // only the chunk the engine wrote is at the place
    let mut back = vec![9u8; 160];
    pack.read_exact_at(&mut back, 4096).unwrap();
    assert!(
        back[..100].iter().all(|&b| b == 0),
        "the copy is not made here"
    );
    assert_eq!(&back[100..], &tail[..]);
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
        name: name.to_string(),
        entry_type: kind,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size,
        digest: None,
        fsverity: None,
        offset: 0,
        end_offset: 0,
        chunk_digest: None,
        chunk_size: 0,
        chunk_offset: 0,
        chunk_type: None,
        link_name: None,
        mod_time: None,
        access_time: None,
        change_time: None,
        dev_major: None,
        dev_minor: None,
        xattrs: Default::default(),
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
    };
    (z, info)
}

#[test]
fn test_a_canonical_layer_needs_no_tar_split() {
    let layer = crate::sha256(b"layer");
    let toc = canonical_layer();
    assert!(toc.is_canonical() && toc.tar_split_digest.is_none());
    let (z, info) = vouched(&toc, None);
    let meta = verify_metadata(&info, &z, Vec::new(), &layer).unwrap();
    assert!(meta.tarsplit_z.is_empty());
    assert_eq!(meta.toc.entries.len(), toc.entries.len());
}

#[test]
fn test_a_table_of_version_2_that_is_not_canonical_is_an_error_that_names_the_layer() {
    let layer = crate::sha256(b"layer");
    let good = canonical_layer();
    let refused = |toc: &Toc, tarsplit| {
        let (z, info) = vouched(toc, tarsplit);
        let e = verify_metadata(&info, &z, b"ts".to_vec(), &layer)
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
        let e = verify_metadata(&info, &z, Vec::new(), &layer)
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
    assert!(verify_metadata(&info, &z, ts.clone(), &layer).is_ok());
    file.fsverity = None;
    let (z, info) = vouched(&toc(&file), Some((0, ts.len() as u64, 0)));
    let e = verify_metadata(&info, &z, ts, &layer).err().unwrap();
    let text = e.to_string();
    assert!(text.contains(&layer.to_string()), "{text}");
    assert!(
        text.contains(&format!("no fs-verity digest for `{}`", file.name)),
        "{text}"
    );
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
