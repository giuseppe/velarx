// SPDX-License-Identifier: Apache-2.0
//! The inputs of a small world, every one of them, and the rules checked on
//! each (see `rules`): the bounds 1, 2, 3 and 256; the counts 0 to 4, 256 and
//! 257; every series of algorithm bytes of the length of the count (of
//! 0, 1, 2, 0x80, 0x81, 0x82, 3 and 0xff for the short ones, a few series
//! for the long ones), complete with raw bytes or not, with what follows, and
//! every beginning of each.

use super::rules::{check, encode};

const BYTES: [u8; 8] = [0, 1, 2, 0x80, 0x81, 0x82, 3, 0xff];

/// Every series of `n` algorithm bytes.
fn series(n: usize) -> Vec<Vec<u8>> {
    let mut all = vec![Vec::new()];
    for _ in 0..n {
        all = all
            .iter()
            .flat_map(|s| {
                BYTES.iter().map(|b| {
                    let mut more = s.clone();
                    more.push(*b);
                    more
                })
            })
            .collect();
    }
    all
}

/// The heads of the world, with a count in the head that is not always the
/// number of the algorithm bytes.
fn walk() -> usize {
    let mut counts = 0;
    let mut long = vec![vec![1u8; 256], vec![2u8; 256], vec![0x81u8; 257]];
    long.push(
        (0..256)
            .map(|i| if i % 3 == 0 { 2 } else { 0x81 })
            .collect(),
    );
    long.push(vec![1; 255].into_iter().chain([0x83]).collect());
    for max in [1, 2, 3, 256] {
        for count in [0u16, 1, 2, 3, 4, 256, 257] {
            let all = if count <= 4 {
                series(count as usize)
            } else {
                long.iter()
                    .filter(|k| k.len() >= count as usize || count == 257)
                    .cloned()
                    .collect()
            };
            for kinds in all {
                for op in [5u8] {
                    let mut whole = vec![op, 3];
                    whole.extend(count.to_be_bytes());
                    whole.extend_from_slice(&kinds);
                    // (raw bytes for each valid byte, as the head says)
                    let full = encode(op, 3, &kinds, 0xAB);
                    whole.extend_from_slice(&full[4 + kinds.len()..]);
                    for rest in [&[][..], &[1, 2, 3][..]] {
                        check(&whole, rest, max);
                        counts += 1;
                    }
                }
            }
        }
    }
    counts
}

#[test]
fn every_head_of_the_world_satisfies_the_rules() {
    // 4 bounds, 2 rests, and the series of up to 4 bytes of the short
    // counts (4681) and the 10 of the long ones
    assert_eq!(walk(), 4 * 2 * (4681 + 10));
}
