// SPDX-License-Identifier: Apache-2.0
//! The packets of OpenPGP data (RFC 4880, 4.2), as spans of it.

use crate::{be, take, Error, Span};

/// Pieces of bodies of a message or keyring at most (a packet has one,
/// or more with partial lengths), so also packets.
pub const MAX_PACKETS: usize = 100_000;

const TAG_COMPRESSED: u8 = 8;
const TAG_LITERAL: u8 = 11;

/// A packet: its tag and where its body is.  The body is one piece, or
/// several when partial lengths cut it: `body`, then `more` in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub tag: u8,
    pub body: Span,
    pub more: Vec<Span>,
}

/// The length of the body of an old format packet (the byte `first` at
/// `at - 1`), and the offset where the body begins.
fn old_length(data: &[u8], at: usize, first: u8) -> Result<(usize, usize), Error> {
    match first & 3 {
        0 => Ok((be(data, at, 1)?, at + 1)),
        1 => Ok((be(data, at, 2)?, at + 2)),
        2 => Ok((be(data, at, 4)?, at + 4)),
        // no length: up to the end
        _ => Ok((data.len() - at, at)),
    }
}

/// The packet of an old format header (the byte `first` at `start`) and the
/// offset after it.
fn old(data: &[u8], start: usize, first: u8) -> Result<(Packet, usize), Error> {
    let (len, at) = old_length(data, start + 1, first)?;
    let body = take(data, at, len)?;
    let packet = Packet {
        tag: (first >> 2) & 0x0f,
        body,
        more: Vec::new(),
    };
    Ok((packet, body.end()))
}

/// The length of the piece whose length octets begin at `at` (a byte of
/// `data`) in the new format packet of the tag `tag`, the offset where the
/// piece begins, and whether the length is a partial one.
fn piece_length(data: &[u8], at: usize, tag: u8) -> Result<(usize, usize, bool), Error> {
    let o1 = data[at];
    if o1 < 192 {
        Ok((usize::from(o1), at + 1, false))
    } else if o1 < 224 {
        let o2 = be(data, at + 1, 1)?;
        Ok((((usize::from(o1) - 192) << 8) + o2 + 192, at + 2, false))
    } else if o1 == 255 {
        Ok((be(data, at + 1, 4)?, at + 5, false))
    } else if tag == TAG_COMPRESSED || tag == TAG_LITERAL {
        Ok((1usize << (o1 & 0x1f), at + 1, true))
    } else {
        Err(Error::PartialLength)
    }
}

/// The packet of a new format header (the byte `first` at `start`) and the
/// offset after it; `room` is how many pieces may still be read.
fn new(data: &[u8], start: usize, first: u8, room: usize) -> Result<(Packet, usize), Error> {
    let tag = first & 0x3f;
    let mut at = start + 1;
    let mut body = Span { off: 0, len: 0 };
    let mut more: Vec<Span> = Vec::new();
    let mut have = false;
    let mut fail: Option<Error> = None;
    let mut done = false;
    while fail.is_none() && !done {
        if at >= data.len() {
            fail = Some(Error::Truncated);
        } else {
            match piece_length(data, at, tag) {
                Err(e) => fail = Some(e),
                Ok((len, begin, partial)) => {
                    let too_many = have && more.len() + 2 > room;
                    if too_many {
                        fail = Some(Error::TooManyPackets);
                    } else {
                        match take(data, begin, len) {
                            Ok(piece) => {
                                if have {
                                    more.push(piece);
                                } else {
                                    body = piece;
                                    have = true;
                                }
                                at = piece.end();
                                done = !partial;
                            }
                            Err(e) => fail = Some(e),
                        }
                    }
                }
            }
        }
    }
    match fail {
        Some(e) => Err(e),
        None => Ok((Packet { tag, body, more }, at)),
    }
}

/// The packets of `data`, in order; the data is all of them or it is
/// refused.  The pieces of all the bodies are at most `MAX_PACKETS`.
pub fn packets(data: &[u8]) -> Result<Vec<Packet>, Error> {
    let mut out: Vec<Packet> = Vec::new();
    let mut at = 0;
    let mut pieces = 0;
    let mut fail: Option<Error> = None;
    while fail.is_none() && at < data.len() {
        if pieces >= MAX_PACKETS {
            fail = Some(Error::TooManyPackets);
        } else if data[at] & 0x80 == 0 {
            fail = Some(Error::NotAPacket);
        } else {
            let read = if data[at] & 0x40 == 0 {
                old(data, at, data[at])
            } else {
                new(data, at, data[at], MAX_PACKETS - pieces)
            };
            match read {
                Ok((packet, next)) => {
                    pieces += 1 + packet.more.len();
                    out.push(packet);
                    at = next;
                }
                Err(e) => fail = Some(e),
            }
        }
    }
    match fail {
        Some(e) => Err(e),
        None => Ok(out),
    }
}
