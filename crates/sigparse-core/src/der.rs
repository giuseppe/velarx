// SPDX-License-Identifier: Apache-2.0
//! DER elements and sequences, as far as the extensions of a certificate
//! need them: a one octet tag, a definite length, nothing else.

use crate::Span;

/// Why DER is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    /// A tag or length that is cut, or a length past the end.
    Truncated,
    /// The indefinite form of a length (0x80).
    Indefinite,
    /// A long form of more than 4 octets.
    TooLong,
    /// An element that is not a sequence (tag 0x30) where one is needed.
    NotSequence,
}

/// The element that begins at `at` and ends by `end` at the latest: its tag,
/// and the span of its content.  `at <= end <= data.len()`.
fn element_in(data: &[u8], at: usize, end: usize) -> Result<(u8, Span), DerError> {
    if end - at < 2 {
        return Err(DerError::Truncated);
    }
    let first = data[at + 1];
    let mut len = usize::from(first);
    let mut start = at + 2;
    if first >= 0x80 {
        let n = usize::from(first & 0x7f);
        if n == 0 {
            return Err(DerError::Indefinite);
        }
        if n > 4 {
            return Err(DerError::TooLong);
        }
        if end - start < n {
            return Err(DerError::Truncated);
        }
        len = 0;
        let mut i = 0;
        while i < n {
            len = (len << 8) | usize::from(data[start + i]);
            i += 1;
        }
        start += n;
    }
    if len > end - start {
        return Err(DerError::Truncated);
    }
    Ok((data[at], Span { off: start, len }))
}

/// The tag and the content of the element at the start of `data`; the rest
/// of `data` begins where the content ends.
pub fn element(data: &[u8]) -> Result<(u8, Span), DerError> {
    element_in(data, 0, data.len())
}

/// The contents of the elements of the sequence at the start of `data`
/// (their tags are not looked at).
pub fn sequence_items(data: &[u8]) -> Result<Vec<Span>, DerError> {
    let (tag, content) = element(data)?;
    if tag != 0x30 {
        return Err(DerError::NotSequence);
    }
    let mut items: Vec<Span> = Vec::new();
    let mut at = content.off;
    let mut fail: Option<DerError> = None;
    while fail.is_none() && at < content.end() {
        match element_in(data, at, content.end()) {
            Ok((_, item)) => {
                items.push(item);
                at = item.end();
            }
            Err(e) => fail = Some(e),
        }
    }
    match fail {
        Some(e) => Err(e),
        None => Ok(items),
    }
}
