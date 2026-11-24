// SPDX-License-Identifier: Apache-2.0
//! The files of small worlds, every one of them, and the rules checked on
//! each answer (see `rules`).  A dense world: files of up to 3 bytes, up
//! to 3 chunks, every place in the file and in the layer, holes or data,
//! with and without offsets, three sets of caps.  A world of the extremes,
//! where the numbers are 0, 1, and the two before the largest `u64`, so
//! that every sum has its overflow.  And the bound of the compressed range,
//! each side of it, for sizes that make it big.

use super::rules::verify;
use super::*;

/// The chunks, every list of up to `most` of them made of `universe`, each
/// answered and checked with every file, caps and totals; how many cases,
/// and how many accepted.
struct World {
    universe: Vec<Chunk>,
    most: usize,
    files: Vec<File>,
    caps: Vec<Caps>,
    before: Vec<Totals>,
}

impl World {
    fn walk(&self) -> (u64, u64) {
        let (mut cases, mut accepted) = (0, 0);
        self.lists(&mut Vec::new(), &mut |chunks| {
            for file in &self.files {
                for caps in &self.caps {
                    for before in &self.before {
                        // (the files before this one were within the caps)
                        if before.zeros > caps.zeros || before.planned > caps.planned {
                            continue;
                        }
                        let answer = check(file, chunks, caps, before);
                        verify(file, chunks, caps, before, answer);
                        cases += 1;
                        accepted += u64::from(answer.is_ok());
                    }
                }
            }
        });
        (cases, accepted)
    }

    fn lists(&self, list: &mut Vec<Chunk>, each: &mut dyn FnMut(&[Chunk])) {
        each(list);
        if list.len() < self.most {
            for c in &self.universe {
                list.push(*c);
                self.lists(list, each);
                list.pop();
            }
        }
    }
}

/// Every chunk of the places `offs` in the file and sizes `sizes`, in the
/// places `comps` in the layer, of data or holes.
fn chunks_of(offs: &[u64], sizes: &[u64], comps: &[u64]) -> Vec<Chunk> {
    let mut out = Vec::new();
    for &file_off in offs {
        for &size in sizes {
            for &comp_off in comps {
                for zeros in [false, true] {
                    out.push(Chunk {
                        file_off,
                        size,
                        comp_off,
                        zeros,
                    });
                }
            }
        }
    }
    out
}

/// Every file of the sizes and ranges, placed or not.
fn files_of(sizes: &[u64], starts: &[u64], ends: &[u64]) -> Vec<File> {
    let mut out = Vec::new();
    for &size in sizes {
        for &comp_start in starts {
            for &comp_end in ends {
                for placed in [false, true] {
                    out.push(File {
                        size,
                        comp_start,
                        comp_end,
                        placed,
                    });
                }
            }
        }
    }
    out
}

fn caps_of(list: &[(u64, u64, u64)]) -> Vec<Caps> {
    list.iter()
        .map(|&(chunk, zeros, planned)| Caps {
            chunk,
            zeros,
            planned,
        })
        .collect()
}

#[test]
fn every_file_of_the_dense_world() {
    let places = [0, 1, 2];
    let world = World {
        universe: chunks_of(&places, &[0, 1, 2, 3], &places),
        most: 3,
        files: files_of(&[0, 1, 2, 3], &[0, 1], &[0, 1, 2, 3]),
        caps: caps_of(&[(1, 1, 1), (2, 3, 3), (u64::MAX, u64::MAX, u64::MAX)]),
        before: vec![Totals {
            zeros: 0,
            planned: 0,
        }],
    };
    let (cases, accepted) = world.walk();
    // 72 chunks make 1 + 72 + 72^2 + 72^3 lists, of 64 files, for 3 caps
    assert_eq!(cases, (1 + 72 + 72 * 72 + 72 * 72 * 72) * 64 * 3);
    assert_eq!(accepted, 6351);
}

#[test]
fn every_file_of_the_extremes() {
    let max = u64::MAX;
    let v = [0, 1, max - 1, max];
    let world = World {
        universe: chunks_of(&v, &v, &v),
        most: 2,
        files: files_of(&v, &v, &v),
        caps: caps_of(&[(1, 1, 1), (max, max, max), (max, 1, max), (max, max, 1)]),
        before: vec![
            Totals {
                zeros: 0,
                planned: 0,
            },
            Totals {
                zeros: max,
                planned: max,
            },
        ],
    };
    let (cases, accepted) = world.walk();
    // 16513 lists, 128 files, 4 caps, and the totals that are within them
    assert_eq!((cases, accepted), (10_568_320, 5732));
}

#[test]
fn every_compressed_range_each_side_of_the_bound() {
    let max = u64::MAX;
    let mut cases = 0;
    let mut accepted = 0;
    for size in [1, 63, 64, 65, 1 << 20, (1 << 20) + 1, max / 2, max - 1, max] {
        let bound = compressed_bound(size);
        for delta in [-1i128, 0, 1] {
            for start in [0, 7, max - bound] {
                let len = (bound as i128 + delta).clamp(0, max as i128) as u64;
                let Some(end) = start.checked_add(len) else {
                    continue;
                };
                let file = File {
                    size,
                    comp_start: start,
                    comp_end: end,
                    placed: true,
                };
                let one = [Chunk {
                    file_off: 0,
                    size,
                    comp_off: start,
                    zeros: false,
                }];
                let caps = Caps {
                    chunk: max,
                    zeros: max,
                    planned: max,
                };
                let before = Totals {
                    zeros: 0,
                    planned: 0,
                };
                let answer = check(&file, &one, &caps, &before);
                verify(&file, &one, &caps, &before, answer);
                cases += 1;
                accepted += u64::from(answer.is_ok());
            }
        }
    }
    assert_eq!((cases, accepted), (68, 54));
}

/// Two chunks of data of a byte each, the first with a compressed range
/// of the bound of its size, one less, one more, and the second the same.
#[test]
fn every_two_chunks_each_side_of_the_bound() {
    let bound = compressed_bound(1);
    let (mut cases, mut accepted) = (0, 0);
    for first in [bound - 1, bound, bound + 1] {
        for second in [bound - 1, bound, bound + 1] {
            let chunk = |file_off, comp_off| Chunk {
                file_off,
                size: 1,
                comp_off,
                zeros: false,
            };
            let file = File {
                size: 2,
                comp_start: 0,
                comp_end: first + second,
                placed: true,
            };
            let two = [chunk(0, 0), chunk(1, first)];
            let caps = Caps {
                chunk: 1,
                zeros: 0,
                planned: 2,
            };
            let answer = check(&file, &two, &caps, &Totals::ZERO);
            verify(&file, &two, &caps, &Totals::ZERO, answer);
            cases += 1;
            accepted += u64::from(answer.is_ok());
        }
    }
    assert_eq!((cases, accepted), (9, 4));
}
