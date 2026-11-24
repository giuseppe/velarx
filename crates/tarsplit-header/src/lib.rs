// SPDX-License-Identifier: Apache-2.0
//! The arithmetic of a tar header, on bytes of an archive that is not trusted
//! yet: the number fields, the checksum, the padding of an entry, the records
//! of a PAX extended header and the CRC-64 that tar-split records; `emit`
//! writes them back.  No dependency, and plain loops over bytes with no early
//! return inside them, the shape Aeneas translates: that none of it panics or
//! overflows is to be proved, not only fuzzed.

pub mod crc64;
pub mod emit;

use std::ops::Range;

/// The size of a tar block, and of a header.
pub const BLOCK: usize = 512;

/// Why a number field is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumError {
    /// A negative base-256 value.
    Negative,
    /// A value that does not fit in 64 bits.
    Overflow,
    /// An octal field with anything but octal digits between spaces.
    Invalid,
}

/// A NUL terminated string field.
pub fn cstr(field: &[u8]) -> &[u8] {
    let mut end = 0;
    while end < field.len() && field[end] != 0 {
        end += 1;
    }
    &field[..end]
}

/// An octal or base-256 number field.  An empty one has no digit and is 0,
/// as Go's archive/tar reads it.
pub fn number(field: &[u8]) -> Result<u64, NumError> {
    if !field.is_empty() && field[0] & 0x80 != 0 {
        base256(field)
    } else {
        octal(cstr(field))
    }
}

/// Big endian, the first byte without the marker bit.  A negative value
/// (0xff first byte) is not valid for any field here.
fn base256(field: &[u8]) -> Result<u64, NumError> {
    let mut value = u64::from(field[0] & 0x3f);
    let mut overflow = false;
    for &b in &field[1..] {
        overflow |= value >> 56 != 0;
        value = (value << 8) | u64::from(b);
    }
    if field[0] & 0x40 != 0 {
        Err(NumError::Negative)
    } else if overflow {
        Err(NumError::Overflow)
    } else {
        Ok(value)
    }
}

/// Octal digits, with spaces before and after; nothing at all is 0.
fn octal(field: &[u8]) -> Result<u64, NumError> {
    let mut start = 0;
    while start < field.len() && field[start] == b' ' {
        start += 1;
    }
    let mut end = field.len();
    while end > start && field[end - 1] == b' ' {
        end -= 1;
    }
    let mut value: u64 = 0;
    let mut invalid = false;
    let mut overflow = false;
    for &b in &field[start..end] {
        invalid |= !(b'0'..=b'7').contains(&b);
        overflow |= value >> 61 != 0;
        value = (value << 3) | u64::from(b & 7);
    }
    if invalid {
        Err(NumError::Invalid)
    } else if overflow {
        Err(NumError::Overflow)
    } else {
        Ok(value)
    }
}

/// Whether the checksum of a header is the sum of its bytes, with the
/// checksum field taken as spaces: unsigned, or signed as old tars wrote it.
pub fn checksum_ok(block: &[u8; BLOCK]) -> Result<bool, NumError> {
    let stored = number(&block[148..156])?;
    let mut unsigned: u64 = 0;
    let mut signed: i64 = 0;
    for (i, &b) in block.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    Ok(stored == unsigned || i64::try_from(stored).is_ok_and(|s| s == signed))
}

/// The bytes that follow `size` bytes of content to fill a block, or `None`
/// if the content, padded, does not fit in 64 bits.
pub fn padding(size: u64) -> Option<u64> {
    let padded = size.checked_next_multiple_of(BLOCK as u64)?;
    Some(padded - size)
}

/// An ASCII decimal digit.  The range test, not `is_ascii_digit`, is what the
/// proofs have a model of (as for the octal digits).
#[allow(clippy::manual_is_ascii_check)]
fn is_digit(b: u8) -> bool {
    (b'0'..=b'9').contains(&b)
}

/// A decimal number: digits only, at least one, no sign (the `+` that
/// `str::parse` takes is refused, as in the number fields).  Anything else is
/// `NumError::Invalid`, and a number that does not fit in 64 bits
/// `NumError::Overflow`.
pub fn decimal(digits: &[u8]) -> Result<u64, NumError> {
    let mut value: u64 = 0;
    let mut invalid = digits.is_empty();
    let mut overflow = false;
    for &b in digits {
        invalid |= !is_digit(b);
        // (the low bits of a byte that is no digit keep the arithmetic small;
        // the number is refused anyway)
        let digit = u64::from(b & 15);
        if value > (u64::MAX - digit) / 10 {
            overflow = true;
        } else {
            value = value * 10 + digit;
        }
    }
    if invalid {
        Err(NumError::Invalid)
    } else if overflow {
        Err(NumError::Overflow)
    } else {
        Ok(value)
    }
}

/// A PAX time, `[-]seconds[.fraction]`, as seconds (rounded down) and the
/// nanoseconds after them.  Digits of the fraction beyond the ninth are
/// dropped; an empty fraction is 0, as Go reads it.  Seconds that do not fit
/// in an `i64` are `NumError::Overflow`.
pub fn pax_time(value: &[u8]) -> Result<(i64, u32), NumError> {
    let mut negative = false;
    let mut text = value;
    if !value.is_empty() && value[0] == b'-' {
        negative = true;
        text = &value[1..];
    }
    let mut dot = 0;
    while dot < text.len() && text[dot] != b'.' {
        dot += 1;
    }
    let secs = decimal(&text[..dot])?;
    if secs > i64::MAX as u64 {
        return Err(NumError::Overflow);
    }
    let secs = secs as i64;
    let fraction = if dot < text.len() { dot + 1 } else { dot };
    // each digit counts for a tenth of the one before, from 0.1 s down to
    // 1 ns; past the ninth the scale is 0, so those digits only get checked
    let mut nanos: u32 = 0;
    let mut scale: u32 = 100_000_000;
    let mut invalid = false;
    for &b in &text[fraction..] {
        invalid |= !is_digit(b);
        nanos += u32::from(b & 15) * scale;
        scale /= 10;
    }
    if invalid {
        Err(NumError::Invalid)
    } else if !negative {
        Ok((secs, nanos))
    } else if nanos == 0 {
        Ok((-secs, 0))
    } else {
        Ok((-secs - 1, 1_000_000_000 - nanos))
    }
}

/// Why the record at the start of a PAX payload is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaxError {
    /// What precedes the first space is no decimal number.
    Length,
    /// No space, a length that is not inside the payload or that ends the
    /// record before its key, no newline at the end, or no `=`.
    Record,
}

/// The first record of a PAX payload, `len key=value\n`: all of it is the
/// first `len` bytes, and `key` and `value` are the ranges of the payload they
/// are at.
#[derive(Debug, PartialEq, Eq)]
pub struct PaxRecord {
    pub len: usize,
    pub key: Range<usize>,
    pub value: Range<usize>,
}

/// The first record of a PAX payload.  Its ranges are inside the first `len`
/// bytes, and `len` is not 0 and not beyond the payload, so the next record
/// starts at `len`, further on.
pub fn pax_record(data: &[u8]) -> Result<PaxRecord, PaxError> {
    let mut space = 0;
    while space < data.len() && data[space] != b' ' {
        space += 1;
    }
    if space == data.len() {
        return Err(PaxError::Record);
    }
    let len = match decimal(&data[..space]) {
        Ok(len) => len,
        Err(_) => return Err(PaxError::Length),
    };
    if len > data.len() as u64 {
        return Err(PaxError::Record);
    }
    let len = len as usize;
    let start = space + 1;
    if len <= start {
        return Err(PaxError::Record);
    }
    let end = len - 1;
    if data[end] != b'\n' {
        return Err(PaxError::Record);
    }
    let mut eq = start;
    while eq < end && data[eq] != b'=' {
        eq += 1;
    }
    if eq == end {
        return Err(PaxError::Record);
    }
    Ok(PaxRecord {
        len,
        key: start..eq,
        value: eq + 1..end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_octal() {
        assert_eq!(number(b"0000644\0"), Ok(0o644));
        assert_eq!(number(b"  644 \0\0"), Ok(0o644));
        assert_eq!(number(b"\0\0\0\0"), Ok(0));
        assert_eq!(number(b"        "), Ok(0));
        assert_eq!(number(b""), Ok(0));
        assert_eq!(number(b"1777777777777777777777"), Ok(u64::MAX));
        assert_eq!(number(b"2000000000000000000000"), Err(NumError::Overflow));
        assert_eq!(number(b"0001777777777777777777777"), Ok(u64::MAX));
        assert_eq!(number(b"0000008\0"), Err(NumError::Invalid));
        assert_eq!(number(b"06 44\0\0\0"), Err(NumError::Invalid));
        assert_eq!(number(b"-1\0\0"), Err(NumError::Invalid));
        assert_eq!(number(b"1\xc3\xa9\0"), Err(NumError::Invalid));
    }

    /// `u64::from_str_radix` took a leading `+`; a header with one is
    /// refused now, as Go's archive/tar refuses it (`strconv.ParseUint`).
    #[test]
    fn test_octal_plus_is_refused() {
        assert_eq!(number(b"+644\0\0\0\0"), Err(NumError::Invalid));
        assert_eq!(number(b" +644   "), Err(NumError::Invalid));
    }

    #[test]
    fn test_base256() {
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[10] = 0x01;
        field[11] = 0x10;
        assert_eq!(number(&field), Ok(0x110));
        field[0] = 0xff;
        assert_eq!(number(&field), Err(NumError::Negative));
        let mut field = [0xffu8; 12];
        field[0] = 0x80;
        assert_eq!(number(&field), Err(NumError::Overflow));
        field[0] = 0x80;
        field[1] = 0;
        field[2] = 0;
        field[3] = 0;
        assert_eq!(number(&field), Ok(u64::MAX));
    }

    #[test]
    fn test_cstr() {
        assert_eq!(cstr(b"ab\0cd"), b"ab");
        assert_eq!(cstr(b"abcd"), b"abcd");
        assert_eq!(cstr(b"\0ab"), b"");
    }

    #[test]
    fn test_checksum() {
        let mut block = [0u8; BLOCK];
        block[0] = b'a';
        let sum = u64::from(b'a') + 8 * u64::from(b' ');
        block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert_eq!(checksum_ok(&block), Ok(true));
        block[1] = 1;
        assert_eq!(checksum_ok(&block), Ok(false));
        block[148] = b'9';
        assert_eq!(checksum_ok(&block), Err(NumError::Invalid));
    }

    #[test]
    fn test_padding() {
        assert_eq!(padding(0), Some(0));
        assert_eq!(padding(1), Some(511));
        assert_eq!(padding(512), Some(0));
        assert_eq!(padding(513), Some(511));
        assert_eq!(padding(u64::MAX - 511), Some(0));
        assert_eq!(padding(u64::MAX - 510), None);
        assert_eq!(padding(u64::MAX), None);
    }

    #[test]
    fn test_decimal() {
        assert_eq!(decimal(b"0"), Ok(0));
        assert_eq!(decimal(b"0042"), Ok(42));
        assert_eq!(decimal(b"18446744073709551615"), Ok(u64::MAX));
        assert_eq!(decimal(b"18446744073709551616"), Err(NumError::Overflow));
        assert_eq!(decimal(b"99999999999999999999999"), Err(NumError::Overflow));
        for bad in [
            "", "-1", " 1", "1 ", "1_0", "0x1", "1e3", "\u{e9}", "/", ":",
        ] {
            assert_eq!(decimal(bad.as_bytes()), Err(NumError::Invalid), "{bad}");
        }
    }

    /// `str::parse` took a leading `+`; the PAX numbers refuse it now, as the
    /// header numbers do (and Go's `strconv.ParseUint`).
    #[test]
    fn test_decimal_plus_is_refused() {
        assert_eq!(decimal(b"+5"), Err(NumError::Invalid));
        assert_eq!(decimal(b"+"), Err(NumError::Invalid));
    }

    #[test]
    fn test_pax_time() {
        let t = |s: &str| pax_time(s.as_bytes());
        assert_eq!(t("5"), Ok((5, 0)));
        assert_eq!(t("1.5"), Ok((1, 500_000_000)));
        assert_eq!(t("1.000000005"), Ok((1, 5)));
        assert_eq!(t("1.1234567891"), Ok((1, 123_456_789)));
        assert_eq!(t("1.9999999999"), Ok((1, 999_999_999)));
        assert_eq!(t("-1"), Ok((-1, 0)));
        assert_eq!(t("-1.5"), Ok((-2, 500_000_000)));
        assert_eq!(t("-0.25"), Ok((-1, 750_000_000)));
        assert_eq!(t("-0"), Ok((0, 0)));
        assert_eq!(t("7."), Ok((7, 0)));
        assert_eq!(t("9223372036854775807"), Ok((i64::MAX, 0)));
        assert_eq!(t("-9223372036854775807.5"), Ok((i64::MIN, 500_000_000)));
        for bad in [
            "",
            "-",
            ".5",
            "1.5x",
            "1.5.5",
            "1.1234567891x",
            "1e3",
            "+1",
            "--1",
            "1.-5",
            "1.+5",
            "9223372036854775808",
            "99999999999999999999",
        ] {
            assert!(t(bad).is_err(), "{bad}");
        }
        assert!(pax_time(b"1.\xc3\xa9").is_err());
    }

    #[test]
    fn test_pax_record() {
        assert_eq!(
            pax_record(b"6 a=b\n"),
            Ok(PaxRecord {
                len: 6,
                key: 2..3,
                value: 4..5
            })
        );
        // only the first record, and an empty key and value
        assert_eq!(
            pax_record(b"0007 =\n7 c=d\n"),
            Ok(PaxRecord {
                len: 7,
                key: 5..5,
                value: 6..6
            })
        );
        let r = pax_record(b"8 a=b=c\n7 c=d\n").unwrap();
        assert_eq!((r.len, r.key, r.value), (8, 2..3, 4..7));
        assert_eq!(pax_record(b"nonsense"), Err(PaxError::Record));
        assert_eq!(pax_record(b""), Err(PaxError::Record));
        assert_eq!(pax_record(b" a=b\n"), Err(PaxError::Length));
        assert_eq!(pax_record(b"x a=b\n"), Err(PaxError::Length));
        assert_eq!(
            pax_record(b"99999999999999999999 a=b\n"),
            Err(PaxError::Length)
        );
        assert_eq!(pax_record(b"99 a=b\n"), Err(PaxError::Record));
        assert_eq!(pax_record(b"2 a=b\n"), Err(PaxError::Record));
        assert_eq!(pax_record(b"6 a=bx\n"), Err(PaxError::Record));
        assert_eq!(pax_record(b"5 a=b\n"), Err(PaxError::Record));
        assert_eq!(pax_record(b"6 a-b\n"), Err(PaxError::Record));
        assert_eq!(pax_record(b"0 \n"), Err(PaxError::Record));
        assert_eq!(pax_record(b"3 \n"), Err(PaxError::Record));
    }

    /// `str::parse` took a leading `+` in the length of a record.
    #[test]
    fn test_pax_record_plus_is_refused() {
        assert_eq!(pax_record(b"+6 a=b\n"), Err(PaxError::Length));
    }
}
