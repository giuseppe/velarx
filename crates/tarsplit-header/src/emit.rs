// SPDX-License-Identifier: Apache-2.0
//! The arithmetic of writing a canonical tar: the number fields of a header
//! and its checksum, the decimal numbers and the length of a PAX record, a
//! PAX time, and the order of two paths.  What `lib.rs` reads, written back
//! the way the reader takes it.  The same plain loops over bytes.  Of these,
//! `put_octal`, `put_decimal`, `record_len` and `path_order` are proved (in
//! `tools/verify/tarsplit-header`) never to panic or overflow, whatever they
//! are given (`put_decimal` needs room in the vector for 20 digits);
//! `seal` and `put_time` are only tested, and `put_time` needs `nanos` below
//! 10^9.

use crate::BLOCK;
use std::cmp::Ordering;

/// `value` as octal digits that fill `field` but its last byte, padded with
/// zeros, then a NUL (`0000755\0`).  It is `false` when the number has more
/// digits than that, or the field is empty; the field is then left with the
/// low digits of the number.  `number` reads back what is written.
pub fn put_octal(field: &mut [u8], value: u64) -> bool {
    if field.is_empty() {
        return false;
    }
    let digits = field.len() - 1;
    field[digits] = 0;
    let mut rest = value;
    let mut at = digits;
    while at > 0 {
        at -= 1;
        field[at] = b'0' + (rest & 7) as u8;
        rest >>= 3;
    }
    rest == 0
}

/// Write the checksum of a header in its field: the sum of the bytes with the
/// field taken as spaces, as six octal digits, a NUL and a space.  The sum is
/// at most 512 * 255, below 8^6, so the digits are enough.
pub fn seal(block: &mut [u8; BLOCK]) {
    let mut at = 148;
    while at < 156 {
        block[at] = b' ';
        at += 1;
    }
    let mut sum: u64 = 0;
    for &b in block.iter() {
        sum += u64::from(b);
    }
    // (it fits: the sum of 512 bytes is at most 130,560, below 8^6)
    put_octal(&mut block[148..155], sum);
}

/// `value` in decimal, without leading zeros, after the bytes of `out`.
pub fn put_decimal(out: &mut Vec<u8>, value: u64) {
    // the largest power of ten that is not above the value
    let mut scale: u64 = 1;
    while value / scale >= 10 {
        scale *= 10;
    }
    let mut rest = value;
    while scale > 0 {
        out.push(b'0' + (rest / scale) as u8);
        rest %= scale;
        scale /= 10;
    }
}

/// The number of decimal digits of `n`.
fn digits(n: usize) -> usize {
    let mut count = 1;
    let mut rest = n;
    while rest >= 10 {
        rest /= 10;
        count += 1;
    }
    count
}

/// The length of a PAX record, which counts its own digits: the record
/// `LEN KEY=VALUE\n` where `rest` is the bytes after the length (`" KEY=VALUE\n"`,
/// so `rest` is 3 more than the key and the value).  `None` when the length
/// does not fit in a `usize`.
///
/// The digits of `rest` are enough, or one more: `rest + digits(rest)` has
/// the digits of `rest` unless it reaches the next power of ten, and then
/// `rest + digits(rest) + 1` is below the one after.
pub fn record_len(rest: usize) -> Option<usize> {
    let len = rest.checked_add(digits(rest))?;
    if digits(len) == digits(rest) {
        Some(len)
    } else {
        len.checked_add(1)
    }
}

/// A PAX time as `pax_time` reads it: for a time from 1970, the seconds, and
/// when `nanos` is not 0 a `.` and the nanoseconds as nine digits without the
/// trailing zeros.  A time before 1970 is `-` and the same of the instant
/// that is as far after the epoch, so 1.5 seconds before it is `-1.5`.
/// `nanos` must be below 10^9: for a time before 1970 it computes
/// `10^9 - nanos`.  The time `i64::MIN` seconds exactly is written but
/// `pax_time` refuses it: 2^63 does not fit an `i64`.
pub fn put_time(out: &mut Vec<u8>, secs: i64, nanos: u32) {
    let mut magnitude = secs.unsigned_abs();
    let mut fraction = nanos;
    if secs < 0 {
        out.push(b'-');
        if nanos != 0 {
            magnitude -= 1;
            fraction = 1_000_000_000 - nanos;
        }
    }
    put_decimal(out, magnitude);
    if fraction != 0 {
        out.push(b'.');
        let mut text = [b'0'; 9];
        let mut at = 9;
        while at > 0 {
            at -= 1;
            text[at] = b'0' + (fraction % 10) as u8;
            fraction /= 10;
        }
        let mut len = 9;
        while text[len - 1] == b'0' {
            len -= 1;
        }
        out.extend_from_slice(&text[..len]);
    }
}

/// The order of two paths in a canonical tar: by their components, each
/// compared as bytes, and a component before the ones it is the start of
/// (`a/b` before `a-c`, because `a` is before `a-c`, though `-` is before `/`
/// as a byte).  The components are what `/` separates, so this is the order of
/// `a.split('/')` and `b.split('/')`, and it needs no splitting: the first
/// byte that differs decides, and a `/` is before any other byte.
pub fn path_order(a: &[u8], b: &[u8]) -> Ordering {
    let mut at = 0;
    while at < a.len() && at < b.len() && a[at] == b[at] {
        at += 1;
    }
    if at == a.len() {
        if at == b.len() {
            Ordering::Equal
        } else {
            Ordering::Less
        }
    } else if at == b.len() {
        Ordering::Greater
    } else if a[at] == b'/' {
        Ordering::Less
    } else if b[at] == b'/' {
        Ordering::Greater
    } else {
        a[at].cmp(&b[at])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{checksum_ok, number, pax_time, NumError};

    #[test]
    fn test_put_octal() {
        let mut field = [9u8; 8];
        assert!(put_octal(&mut field, 0o644));
        assert_eq!(&field, b"0000644\0");
        assert!(put_octal(&mut field, 0));
        assert_eq!(&field, b"0000000\0");
        assert!(put_octal(&mut field, 0o7_777_777));
        assert_eq!(&field, b"7777777\0");
        // one digit too many: refused, and the next field is not touched
        assert!(!put_octal(&mut field, 0o10_000_000));
        let mut twelve = [9u8; 12];
        assert!(put_octal(&mut twelve, 0o77_777_777_777));
        assert_eq!(&twelve, b"77777777777\0");
        assert!(!put_octal(&mut twelve, 0o100_000_000_000));
        assert!(!put_octal(&mut twelve, u64::MAX));
        let mut one = [9u8; 1];
        assert!(put_octal(&mut one, 0));
        assert_eq!(one, [0]);
        assert!(!put_octal(&mut one, 1));
        assert!(!put_octal(&mut [], 0));
    }

    #[test]
    fn test_put_octal_is_read_back_by_number() {
        for len in [2, 8, 12, 24] {
            for value in [
                0,
                1,
                7,
                8,
                0o644,
                0o7_777_777,
                0o10_000_000,
                0o77_777_777_777,
                0o100_000_000_000,
                u64::MAX >> 4,
                u64::MAX,
            ] {
                let mut field = vec![0xffu8; len];
                let fits = put_octal(&mut field, value);
                let max = 1u128 << (3 * (len - 1));
                assert_eq!(fits, u128::from(value) < max, "{value} in {len}");
                if fits {
                    assert_eq!(number(&field), Ok(value), "{value} in {len}");
                    let text = format!("{value:0width$o}\0", width = len - 1);
                    assert_eq!(field, text.as_bytes());
                }
            }
        }
    }

    #[test]
    fn test_seal() {
        for fill in [0u8, 1, b'a', 0xff] {
            let mut block = [fill; BLOCK];
            block[148..156].fill(7);
            seal(&mut block);
            let sum = u64::from(fill) * (BLOCK as u64 - 8) + 8 * u64::from(b' ');
            assert_eq!(&block[148..156], format!("{sum:06o}\0 ").as_bytes());
            assert_eq!(checksum_ok(&block), Ok(true));
        }
        let mut block = [0u8; BLOCK];
        block[0] = b'a';
        seal(&mut block);
        assert_eq!(checksum_ok(&block), Ok(true));
        block[1] = 1;
        assert_eq!(checksum_ok(&block), Ok(false));
    }

    #[test]
    fn test_put_decimal() {
        let mut values = vec![0, 1, 9, 10, 11, 99, 100, 101, u64::MAX, u64::MAX - 1];
        let mut p = 1u64;
        while let Some(next) = p.checked_mul(10) {
            values.extend([next - 1, next, next + 1]);
            p = next;
        }
        for value in values {
            let mut out = b"x".to_vec();
            put_decimal(&mut out, value);
            assert_eq!(out, format!("x{value}").as_bytes(), "{value}");
        }
    }

    /// The length of a record counts its digits: the first number whose
    /// digits and the rest make it.
    #[test]
    fn test_record_len() {
        let slow = |rest: usize| {
            let mut digits = rest.to_string().len();
            while (rest + digits).to_string().len() != digits {
                digits += 1;
            }
            rest + digits
        };
        for rest in (0..200_000).chain([9_999_995, 9_999_996, 99_999_994, 99_999_995]) {
            let len = record_len(rest).unwrap();
            assert_eq!(len, slow(rest), "{rest}");
            assert_eq!(len, rest + len.to_string().len(), "{rest}");
        }
        assert_eq!(record_len(3), Some(4));
        assert_eq!(record_len(8), Some(9));
        assert_eq!(record_len(9), Some(11));
        assert_eq!(record_len(97), Some(99));
        assert_eq!(record_len(98), Some(101));
        assert_eq!(record_len(usize::MAX - 19), None);
        assert_eq!(record_len(usize::MAX), None);
        // the top: the digits fit, the length is the last number there is
        assert_eq!(record_len(usize::MAX - 20), Some(usize::MAX));
    }

    fn time(secs: i64, nanos: u32) -> String {
        let mut out = Vec::new();
        put_time(&mut out, secs, nanos);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn test_put_time() {
        assert_eq!(time(0, 0), "0");
        assert_eq!(time(5, 0), "5");
        assert_eq!(time(1, 500_000_000), "1.5");
        assert_eq!(time(1, 5), "1.000000005");
        assert_eq!(time(1, 999_999_999), "1.999999999");
        assert_eq!(time(-1, 0), "-1");
        assert_eq!(time(-2, 500_000_000), "-1.5");
        assert_eq!(time(-1, 750_000_000), "-0.25");
        assert_eq!(time(-1, 1), "-0.999999999");
        assert_eq!(time(-1, 999_999_999), "-0.000000001");
        assert_eq!(time(i64::MAX, 999_999_999), "9223372036854775807.999999999");
        assert_eq!(time(i64::MIN, 1), "-9223372036854775807.999999999");
        assert_eq!(time(i64::MIN, 500_000_000), "-9223372036854775807.5");
        // `pax_time` has no `i64::MIN` seconds: 2^63 does not fit
        assert_eq!(time(i64::MIN, 0), "-9223372036854775808");
        assert_eq!(pax_time(b"-9223372036854775808"), Err(NumError::Overflow));
    }

    #[test]
    fn test_put_time_is_read_back_by_pax_time() {
        let secs = [
            0,
            1,
            -1,
            2,
            -2,
            9,
            10,
            -10,
            0o77_777_777_777,
            0o100_000_000_000,
            -62_135_596_800,
            253_402_300_799,
            i64::MAX,
            i64::MAX - 1,
            i64::MIN + 1,
            i64::MIN + 2,
        ];
        let nanos = [
            0,
            1,
            9,
            10,
            100_000_000,
            123_456_789,
            500_000_000,
            999_999_999,
        ];
        for s in secs {
            for n in nanos {
                assert_eq!(pax_time(time(s, n).as_bytes()), Ok((s, n)), "{s}.{n}");
            }
        }
        assert_eq!(pax_time(time(i64::MIN, 7).as_bytes()), Ok((i64::MIN, 7)));
    }

    /// The order of the components of the split strings, which `path_order`
    /// does not split.
    #[test]
    fn test_path_order_is_the_order_of_the_components() {
        let alphabet = [b'a', b'b', b'-', b'/', 0xff, 0];
        let mut paths: Vec<Vec<u8>> = vec![vec![]];
        let mut from = 0;
        for _ in 0..4 {
            let to = paths.len();
            for i in from..to {
                for &c in &alphabet {
                    let mut p = paths[i].clone();
                    p.push(c);
                    paths.push(p);
                }
            }
            from = to;
        }
        let split = |p: &[u8]| {
            p.split(|&b| b == b'/')
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>()
        };
        for a in &paths {
            for b in &paths {
                assert_eq!(path_order(a, b), split(a).cmp(&split(b)), "{a:?} {b:?}");
            }
        }
        assert_eq!(path_order(b"a/b", b"a-c"), Ordering::Less);
        assert_eq!(path_order(b"a", b"a/b"), Ordering::Less);
        assert_eq!(path_order(b"", b"a"), Ordering::Less);
    }
}
