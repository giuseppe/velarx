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

#[cfg(test)]
mod tests {
    use super::*;

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
