// SPDX-License-Identifier: Apache-2.0
//! CRC-64 with the ISO polynomial (`hash/crc64` of Go), the checksum that
//! tar-split records for the content of a file.

const POLY: u64 = 0xD800_0000_0000_0000;

const fn tables() -> [[u64; 256]; 8] {
    let mut t = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u64;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            j += 1;
        }
        t[0][i] = crc;
        i += 1;
    }
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[k - 1][i];
            t[k][i] = t[0][(prev & 0xff) as usize] ^ (prev >> 8);
            i += 1;
        }
        k += 1;
    }
    t
}

static TABLES: [[u64; 256]; 8] = tables();

/// The CRC of `data` appended to the data that has the CRC `crc` (0 to start).
pub fn update(crc: u64, data: &[u8]) -> u64 {
    let mut crc = !crc;
    let (words, rest) = data.as_chunks::<8>();
    for word in words {
        crc ^= u64::from_le_bytes(*word);
        crc = TABLES[7][(crc & 0xff) as usize]
            ^ TABLES[6][((crc >> 8) & 0xff) as usize]
            ^ TABLES[5][((crc >> 16) & 0xff) as usize]
            ^ TABLES[4][((crc >> 24) & 0xff) as usize]
            ^ TABLES[3][((crc >> 32) & 0xff) as usize]
            ^ TABLES[2][((crc >> 40) & 0xff) as usize]
            ^ TABLES[1][((crc >> 48) & 0xff) as usize]
            ^ TABLES[0][(crc >> 56) as usize];
    }
    for &b in rest {
        crc = TABLES[0][((crc ^ u64::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

/// The image of the vector `v` by the matrix `m` (its columns) over GF(2).
fn apply(m: &[u64; 64], mut v: u64) -> u64 {
    let mut out = 0;
    while v != 0 {
        out ^= m[v.trailing_zeros() as usize];
        v &= v - 1;
    }
    out
}

/// The same as `update(crc, &[0; n])`, in time that does not depend on `n`:
/// a byte of zeros is a linear map of the register, which is raised to the
/// power `n`.
pub fn update_zeros(crc: u64, mut n: u64) -> u64 {
    let mut step = [0u64; 64];
    for (i, column) in step.iter_mut().enumerate() {
        let c = 1u64 << i;
        *column = TABLES[0][(c & 0xff) as usize] ^ (c >> 8);
    }
    let mut register = !crc;
    while n > 0 {
        if n & 1 == 1 {
            register = apply(&step, register);
        }
        let mut squared = [0u64; 64];
        for (i, column) in squared.iter_mut().enumerate() {
            *column = apply(&step, step[i]);
        }
        step = squared;
        n >>= 1;
    }
    !register
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeros_equal_the_bytes() {
        for start in [0u64, 0x1234_5678_9abc_def0, u64::MAX] {
            for n in [0usize, 1, 2, 7, 8, 9, 63, 64, 65, 1000, 4096, 100_003] {
                assert_eq!(
                    update_zeros(start, n as u64),
                    update(start, &vec![0u8; n]),
                    "{start:x} {n}"
                );
            }
        }
        // a hole of 8 TiB is as one of the halves twice
        let half = update_zeros(update(0, b"x"), 4 << 40);
        assert_eq!(
            update_zeros(half, 4 << 40),
            update_zeros(update(0, b"x"), 8 << 40)
        );
    }

    #[test]
    fn test_check_value() {
        assert_eq!(update(0, b"123456789"), 0xb909_56c7_75a4_1001);
        assert_eq!(update(0, b""), 0);
    }

    #[test]
    fn test_incremental_matches_one_shot() {
        let data: Vec<u8> = (0..10_007u32).map(|i| (i * 31 % 251) as u8).collect();
        let whole = update(0, &data);
        for split in [1, 7, 8, 9, 4096, 10_000] {
            let (a, b) = data.split_at(split);
            assert_eq!(update(update(0, a), b), whole);
        }
    }
}
