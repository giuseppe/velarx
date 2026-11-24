// SPDX-License-Identifier: Apache-2.0
//! The inputs of a small world, every one of them, and the rules checked on
//! each answer (see `rules`): three fs-verity digests and three content
//! hashes; every claim they make (a verity claim, a content claim, a
//! replayed one with each pair, the engine's, a verified one), owned or not,
//! on the store's file system or not, required or not; every kernel measure,
//! read, hash, copy measure (or none of them; a content hash too, as a shell
//! that confused them would report it) and every state of the store.

use super::rules::{check, check_keep, check_plan};
use super::*;

/// The world's digests: `i` of the fs-verity ones, or of the content hashes.
fn dig(verity: bool, i: u8) -> Dig {
    let mut bytes = [0u8; 64];
    bytes[0] = i;
    Dig {
        verity,
        alg: 0,
        len: 32,
        bytes,
    }
}

/// None, then the three digests.
fn options(verity: bool) -> [Option<Dig>; 4] {
    [
        None,
        Some(dig(verity, 0)),
        Some(dig(verity, 1)),
        Some(dig(verity, 2)),
    ]
}

/// What the shell reports as fs-verity digests: none, the three digests, and
/// a content hash (a shell that confused the two).
fn reports() -> [Option<Dig>; 5] {
    let [none, a, b, c] = options(true);
    [none, a, b, c, Some(dig(false, 0))]
}

fn claims() -> Vec<Claim> {
    let mut all = vec![Claim::Engine];
    // (an fs-verity digest that is a content hash is a claim that cannot be
    // met, and is in the world too)
    for i in 0..3 {
        all.push(Claim::Content(dig(false, i)));
        for kind in [true, false] {
            all.push(Claim::Verity(dig(kind, i)));
            all.push(Claim::Verified(dig(kind, i)));
            for j in 0..3 {
                all.push(Claim::Replayed(dig(false, i), dig(kind, j)));
            }
        }
    }
    all
}

/// The counts of the walk: the facts, the plans and the verdicts, and how
/// many of the verdicts name, keep, refuse and fail.
fn walk() -> [usize; 6] {
    let mut counts = [0; 6];
    let held = [Held::Lacks, Held::Measures, Held::Unmeasured];
    for claim in claims() {
        for flags in 0..8u32 {
            let f = Facts {
                claim,
                own: flags & 1 != 0,
                same_fs: flags & 2 != 0,
                required: flags & 4 != 0,
            };
            counts[0] += 1;
            for kernel in reports() {
                for h in held {
                    check_plan(&f, kernel, h, plan(&f, kernel, h));
                    counts[1] += 1;
                    for merkle in reports() {
                        for copy_kernel in reports() {
                            for content in options(false) {
                                let seen = Seen {
                                    kernel,
                                    merkle,
                                    content,
                                    copy_kernel,
                                    held: h,
                                };
                                let v = verdict(&f, &seen);
                                check(&f, &seen, v);
                                if let Verdict::Name(n) = v {
                                    for after in held {
                                        check_keep(&f, n, after, keep(&f, n, after));
                                    }
                                }
                                counts[2 + match v {
                                    Verdict::Name(_) => 0,
                                    Verdict::Keep(_) => 1,
                                    Verdict::Wrong(_) => 2,
                                    Verdict::Fail(_) => 3,
                                }] += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    counts
}

/// What is after the `len` first bytes of a digest is not part of it.
#[test]
fn a_digest_is_its_first_bytes() {
    let (a, mut b) = (dig(true, 1), dig(true, 1));
    b.bytes[63] = 9;
    assert_eq!(a, b);
    b.bytes[31] = 9;
    assert_ne!(a, b);
    assert_ne!(a, dig(false, 1));
    assert_ne!(a, Dig { alg: 1, ..a });
    assert_ne!(a, Dig { len: 31, ..a });
}

#[test]
fn every_input_of_the_small_world() {
    let [facts, plans, names, keeps, wrongs, fails] = walk();
    assert_eq!(facts, 34 * 8);
    assert_eq!(plans, facts * 5 * 3);
    assert_eq!(names + keeps + wrongs + fails, plans * 5 * 5 * 4);
    // (each answer happens: the rules would pass an answer that is never
    // given)
    assert!(names > 0 && keeps > 0 && wrongs > 0 && fails > 0);
}

/// A copy whose measure is not the digest of the bytes written into it is
/// refused, whether or not fs-verity is required.
#[test]
fn a_copy_that_is_not_the_bytes_written_is_wrong() {
    for required in [false, true] {
        let f = Facts {
            claim: Claim::Engine,
            own: true,
            same_fs: false,
            required,
        };
        assert!(matches!(plan(&f, None, Held::Lacks), Plan::Copy { .. }));
        let seen = Seen {
            kernel: None,
            merkle: Some(dig(true, 0)),
            content: None,
            copy_kernel: Some(dig(true, 1)),
            held: Held::Lacks,
        };
        assert_eq!(verdict(&f, &seen), Verdict::Wrong(Why::NotKnown));
    }
}
