// SPDX-License-Identifier: Apache-2.0
//! The head of a request over QUIC (the peer-to-peer provider, quic.rs):
//! the first bytes of a stream, which a member peer sends before anything
//! is known of it.
//! They are: an operation (u8), an urgency (u8), a count (u16, big endian),
//! `count` bytes that say what each digest is, and then the raw bytes of the
//! digests, as many as those bytes say.  A byte says the algorithm in its
//! low bits (1: SHA-256, 32 raw bytes; 2: SHA-512, 64) and in its high bit
//! whether the digest is an fs-verity one.  The shell reads the stream; this
//! crate says, of the bytes it has, whether they are a head, need more, or
//! are not one.
//!
//! The rules, for every byte string and every bound:
//!
//! 1. Nothing panics or reads out of bounds, whatever the bytes and the
//!    bound; the bytes after the head are never looked at.
//! 2. [`parse`] says [`Parse::Bad`] as soon as the bytes given say that the
//!    count is not valid (they are four) or that an algorithm byte is not
//!    (the byte is given), and never otherwise; [`Parse::Need`] when fewer
//!    than four bytes are held, or they can still become a valid head, with a total that is more than
//!    the bytes given and at most what the head takes; [`Parse::Done`]
//!    when they hold one.  What a peer makes the shell wait for is at most
//!    [`most`] of the bound.
//! 3. A count is valid when it is at least 1 and at most the bound; an
//!    algorithm byte is valid when its low bits are 1 or 2 (the byte 0x80 is
//!    not: an fs-verity digest has an algorithm).
//! 4. `Done { count, used }`: `count` digests, and `used` is the four
//!    bytes of the head, the `count` bytes of algorithms and the raw bytes
//!    the algorithms say, exactly: at most the bytes given, and no shorter
//!    beginning of them is a head.
//! 5. A head is read back as it was written: the bytes of the head of
//!    `Done` are what [`parse`] was given (checked for every head of a small
//!    world), and a head written from algorithms and raw bytes is `Done`
//!    of exactly its length, whatever follows it.
//!
//! The head of a request for signatures, whose count is the length of a
//! reference and not of digests, is not read here: the shell checks the
//! operation first.
//!
//! Written to be translated (tools/verify): plain enums and integers, index
//! loops with flags, no closure, no iterator adapter, no `return` in a loop.

/// The bytes before the algorithms: operation, urgency and count.
pub const HEADER: usize = 4;
/// The bit of an algorithm byte that says an fs-verity digest.
pub const FSVERITY: u8 = 0x80;

/// What the bytes of a head say.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, Copy)]
pub enum Parse {
    /// A beginning of a head: the whole needs at least this many bytes
    /// (more than there are), and may need more once they are known
    Need(usize),
    /// Not the beginning of any head
    Bad,
    /// A head of `count` digests that is `used` bytes long
    Done { count: usize, used: usize },
}

/// The length of a digest of the algorithm (the low bits of its byte), 0 for
/// one that is not known.
pub fn alg_len(byte: u8) -> usize {
    let alg = byte & !FSVERITY;
    if alg == 1 {
        32
    } else if alg == 2 {
        64
    } else {
        0
    }
}

/// The most bytes a valid head takes, for at most `max` digests of the
/// longest algorithm.
pub fn most(max: usize) -> usize {
    HEADER + max + max * 64
}

/// What `bytes`, from the first of a stream, say, for heads of at most
/// `max` digests.
pub fn parse(bytes: &[u8], max: usize) -> Parse {
    if bytes.len() < HEADER {
        return Parse::Need(HEADER);
    }
    let count = bytes[2] as usize * 256 + bytes[3] as usize;
    if count == 0 || count > max {
        return Parse::Bad;
    }
    let seen = if bytes.len() - HEADER < count {
        bytes.len() - HEADER
    } else {
        count
    };
    let mut raw = 0;
    let mut i = 0;
    let mut ok = true;
    while i < seen && ok {
        let n = alg_len(bytes[HEADER + i]);
        ok = n != 0;
        raw += n;
        i += 1;
    }
    let used = HEADER + count + raw;
    if !ok {
        Parse::Bad
    } else if seen < count {
        Parse::Need(HEADER + count)
    } else if bytes.len() < used {
        Parse::Need(used)
    } else {
        Parse::Done { count, used }
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
