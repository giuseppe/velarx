// SPDX-License-Identifier: Apache-2.0
//! The rules of the head of a request (see the head of the crate), checked
//! on the answer of `parse` for given bytes.  They are stated by an oracle
//! that does not read like `parse`: the length a head takes is found first,
//! from its count and algorithms, and every beginning of it is judged by
//! what it says.

use super::*;

/// What the bytes say to an observer who read the rules: the place where
/// they stop being a head (`bad`, the number of bytes that say so), or the
/// length of the head (`used`).
enum Oracle {
    Bad(usize),
    Head { count: usize, used: usize },
}

fn oracle(whole: &[u8], max: usize) -> Oracle {
    if whole.len() < HEADER {
        return Oracle::Head {
            count: 0,
            used: HEADER,
        };
    }
    let count = u16::from_be_bytes([whole[2], whole[3]]) as usize;
    if !(1..=max).contains(&count) {
        return Oracle::Bad(HEADER);
    }
    let mut used = HEADER + count;
    for i in 0..count {
        match whole.get(HEADER + i) {
            Some(b) if matches!(b & !FSVERITY, 1 | 2) => {
                used += if b & !FSVERITY == 1 { 32 } else { 64 };
            }
            Some(_) => return Oracle::Bad(HEADER + i + 1),
            None => {
                return Oracle::Head {
                    count,
                    used: HEADER + count,
                }
            }
        }
    }
    Oracle::Head { count, used }
}

/// `whole` is the bytes a peer may send, and every beginning of them (and
/// of what follows, `rest`) is judged.
pub fn check(whole: &[u8], rest: &[u8], max: usize) {
    let truth = oracle(whole, max);
    for len in 0..=whole.len() {
        let got = parse(&whole[..len], max);
        let note = || {
            let shown = &whole[..whole.len().min(12)];
            format!(
                "{len} bytes of {} that begin {shown:?}, max {max}, said {got:?}",
                whole.len()
            )
        };
        match (&truth, got) {
            (Oracle::Bad(at), got) => {
                if len >= *at {
                    assert_eq!(got, Parse::Bad, "{}", note());
                } else {
                    assert!(matches!(got, Parse::Need(n) if n > len), "{}", note());
                }
            }
            (Oracle::Head { count, used }, got) => match got {
                Parse::Need(n) => {
                    assert!(len < *used && n > len && n <= *used, "{}", note());
                    assert!(n <= most(max), "{}", note());
                }
                Parse::Done { count: c, used: u } => {
                    assert!(len >= *used && c == *count && u == *used, "{}", note());
                }
                Parse::Bad => panic!("{}", note()),
            },
        }
    }
    // after the head: nothing is looked at
    if let Oracle::Head { count, used } = truth {
        if used <= whole.len() && count > 0 {
            let mut longer = whole[..used].to_vec();
            longer.extend_from_slice(rest);
            assert_eq!(parse(&longer, max), Parse::Done { count, used });
            // read back as it was written
            assert_eq!(&longer[..used], &whole[..used]);
        }
    }
}

/// A head written from `kinds` and the raw bytes of each, `filler`.
pub fn encode(op: u8, urgency: u8, kinds: &[u8], filler: u8) -> Vec<u8> {
    let mut head = vec![op, urgency];
    head.extend((kinds.len() as u16).to_be_bytes());
    head.extend_from_slice(kinds);
    for k in kinds {
        head.extend(std::iter::repeat_n(filler, alg_len(*k)));
    }
    head
}

#[test]
fn a_head_written_is_read_back() {
    for kinds in [vec![1], vec![2], vec![0x81, 0x82, 1, 2], vec![2; 256]] {
        let head = encode(7, 3, &kinds, 0xAB);
        let raw: usize = kinds.iter().map(|k| alg_len(*k)).sum();
        assert_eq!(head.len(), HEADER + kinds.len() + raw);
        for rest in [&[][..], &[1, 2, 3][..], &[0xff; 70][..]] {
            let mut sent = head.clone();
            sent.extend_from_slice(rest);
            assert_eq!(
                parse(&sent, 256),
                Parse::Done {
                    count: kinds.len(),
                    used: head.len()
                }
            );
        }
        assert!(matches!(parse(&head[..head.len() - 1], 256), Parse::Need(n) if n == head.len()));
    }
}

#[test]
fn the_algorithm_bytes_that_are_refused() {
    for byte in 0..=255u8 {
        let valid = matches!(byte & !FSVERITY, 1 | 2);
        assert_eq!(alg_len(byte) != 0, valid, "{byte}");
        let got = parse(&[0, 0, 0, 1, byte], 256);
        assert_eq!(got == Parse::Bad, !valid, "{byte}");
    }
    assert_eq!(parse(&[0, 0, 0, 0], 256), Parse::Bad);
    assert_eq!(parse(&[0, 0, 1, 1], 256), Parse::Bad);
    assert_eq!(parse(&[0, 0, 0, 3], 2), Parse::Bad);
    assert_eq!(parse(&[], 256), Parse::Need(HEADER));
    assert_eq!(parse(&[0xff; 3], 0), Parse::Need(HEADER));
    // the longest a peer makes us wait for
    let longest = parse(&[0, 0, 1, 0, 2], 256);
    assert_eq!(longest, Parse::Need(HEADER + 256));
    assert_eq!(most(256), HEADER + 256 + 256 * 64);
}
