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

    let mut gz = l.clone();
    gz.media_type = "application/vnd.oci.image.layer.v1.tar+gzip".into();
    assert!(parse_info(&gz).unwrap().is_none());
    assert!(parse_info(&layer(&[], ZSTD)).unwrap().is_none());

    let mut bad = l.clone();
    bad.annotations
        .insert(format!("{prefix}manifest-position"), "1:2:x:1".into());
    assert!(parse_info(&bad).is_err());
    let mut bad = l.clone();
    bad.annotations
        .insert(format!("{prefix}manifest-checksum"), "sha256:zz".into());
    assert!(parse_info(&bad).is_err());
    let mut other = l;
    other
        .annotations
        .insert(format!("{prefix}manifest-position"), "1:2:3:2".into());
    assert!(parse_info(&other).unwrap().is_none());
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

#[test]
fn test_metadata_checks() {
    let toc_json = serde_json::json!({
        "version": 1,
        "entries": [],
        "tarSplitDigest": crate::sha256(b"ts"),
    })
    .to_string();
    let toc_z = zstd::encode_all(toc_json.as_bytes(), 3).unwrap();
    let info = Info {
        toc: (0, toc_z.len() as u64, toc_json.len() as u64),
        checksum: crate::sha256(&toc_z),
        tarsplit: Some((0, 2, 0)),
    };
    assert!(verify_metadata(&info, &toc_z, b"ts".to_vec(), 0).is_ok());
    let mut bad = info.clone();
    bad.checksum = crate::sha256(b"other");
    assert!(verify_metadata(&bad, &toc_z, b"ts".to_vec(), 0).is_err());
    assert!(verify_metadata(&info, &toc_z, b"tx".to_vec(), 0).is_err());
    let mut bad = info.clone();
    bad.toc.2 += 1;
    assert!(verify_metadata(&bad, &toc_z, b"ts".to_vec(), 0).is_err());
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

/// A write that fails on this machine (no space) is its own error, which no
/// other route of the pull makes right: it is not taken for a layer that
/// cannot be pulled by ranges, so that the layer is not pulled whole to fail
/// the same way behind a note.
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
    assert!(local_failure(&e) && no_other_route(&e) && !refuses(&e));
    // the bytes of a layer that are no stream are the layer's
    let bad = decompress_bounded(b"not zstd", 100, 0, "TOC").unwrap_err();
    assert!(!local_failure(&bad) && !no_other_route(&bad), "{bad:?}");
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
        measure: None,
        copy: None,
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
                measure: None,
                copy: None,
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
                measure: None,
                copy: None,
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
