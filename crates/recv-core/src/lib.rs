// SPDX-License-Identifier: Apache-2.0
//! What a node takes from a peer of the peer-to-peer network, where the peer
//! is trusted for nothing: it may send any bytes, in any order, any size,
//! again, for what was not asked.  Two judgements are here, and what comes
//! after them (the check of the bytes against their digest, in `provider.rs`)
//! is not.
//!
//! * [`Reading`]: the answer to a request for chunks.  The peer answers each
//!   digest asked, in the order asked, with a status byte and for a chunk
//!   its length; the node never reads a digest from the peer, so an answer
//!   for something not asked cannot be formed.  The core says what each
//!   status is, whether a length is taken, and how many bytes one answer may
//!   hold.  [`item`] is the same for the answer to a request for one thing
//!   (an index, a profile, signatures), and [`status`] for the answer to a
//!   probe.
//! * [`Seen`]: what a peer told of the layers it holds with a Bloom filter,
//!   whole ([`Seen::full`]) or by what was added ([`Seen::delta`]).  The
//!   core keeps the run of the sender, the version of the filter held and
//!   the last version heard of, and says what to do with a message
//!   and, from a question to the filter, whether the peer holds a layer.
//!   [`full_ok`] and [`delta_ok`] say whether the bytes of a message have a
//!   size a filter may have.
//!
//! The rules, which `rules` states apart from the code and `walk` checks on
//! every small world:
//!
//! 1. Nothing panics, and no arithmetic overflows, whatever the numbers.
//! 2. A status byte is one of the four of [`status`], or [`Status::Bad`]; a
//!    bad one ends the answer.  An answer is for the digests asked, one
//!    turn each, in order: [`Reading::claim`] gives the turn of the next
//!    one before its status byte is read (so that a byte that never comes
//!    leaves that digest unanswered), and after the last it gives none and
//!    nothing is read.
//! 3. A chunk is taken when its length is at most the largest item, is the
//!    size asked when one was, and, unless the answer holds no bytes yet,
//!    does not bring the answer past the most it may hold ([`room`], which
//!    the server's own sending holds to as well).  The bytes of an
//!    answer are therefore at most the larger of the largest item and the
//!    most it may hold, and no length is allocated before this is decided.
//!    The callers give both as 16 MiB (`MAX_ITEM_BYTES` and
//!    `MAX_RESPONSE_PAYLOAD` of `limits.rs`, the first never above the
//!    second when it is compiled), so an answer holds at most 16 MiB.
//! 4. A correct peer is taken: a chunk of the size asked, that the server
//!    has room for by [`room`] and is at most the largest item, is taken
//!    whatever the order of the other answers.
//! 5. An item is taken when it is not empty and is at most the bound the
//!    asker gave.
//! 6. A whole filter is taken when its bytes are whole 64-bit words, no
//!    more than [`MAX_FILTER_BYTES`] and not none, and its hashes are 1 to
//!    [`MAX_HASHES`]; a delta when its bytes are whole words, not none and
//!    at most [`MAX_DELTA_KEYS`] keys.
//! 7. A whole filter of the run held and of a lower version than the one
//!    held is not taken (a stale message that came after a newer one); any
//!    other is, and it makes the run its own.
//! 8. A delta of another run is taken, whatever versions it names: it makes
//!    the run its own and says that the filter held lacks what that run
//!    holds ([`Seen::behind`]), until a whole filter of that run comes.  A
//!    delta of the run held that does not go past the version held is not
//!    taken.  A delta applies to the version held when it starts from it,
//!    and never to version 0, which is no filter of the run (the versions
//!    of a sender start at 1: a delta goes from a version to the next);
//!    any other leaves the filter behind.
//! 9. A filter says "no" only when it is believed, does not contain the
//!    key, and nothing is missing from it ([`Seen::behind`] is false).
//!    No key of the messages that arrived since the run last changed (those
//!    of the run of the last message) is ever answered "no", whatever was
//!    lost or came out of order.  The runs are random numbers and cannot
//!    be ordered: a whole filter of an old run that comes after a message of
//!    the new one is taken, and says "no" to what only the new run holds,
//!    until the next whole filter.
//!
//! What stays in the shell: the streams, base64, the Bloom filter's bits,
//! the time (how old a filter is), and how much a peer was wrong.
//!
//! Written to be translated (tools/verify): numbers and plain enums, no
//! closure, no iterator adapter, no `String`.

/// The status byte of an answer: the peer does not have the chunk.
pub const ABSENT: u8 = 0;
/// The peer has it, and its length and bytes follow.
pub const HERE: u8 = 1;
/// The peer has no room to send it in this answer: ask again.
pub const NO_ROOM: u8 = 2;
/// The peer could not read its store: not the same as having no chunk.
pub const FAILED: u8 = 3;

/// The hashes of a filter, at most.
pub const MAX_HASHES: u8 = 16;
/// The keys one delta carries, at most (more are sent as a whole filter).
pub const MAX_DELTA_KEYS: usize = 8192;
/// The bytes of a whole filter, at most: the largest a node may be set to
/// send (`filter_max_kib`, 4096).
pub const MAX_FILTER_BYTES: usize = 4 << 20;

/// What a status byte says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Absent,
    Here,
    NoRoom,
    Failed,
    /// None of the four.
    Bad,
}

/// What the byte `byte` says.
pub fn status(byte: u8) -> Status {
    if byte == ABSENT {
        Status::Absent
    } else if byte == HERE {
        Status::Here
    } else if byte == NO_ROOM {
        Status::NoRoom
    } else if byte == FAILED {
        Status::Failed
    } else {
        Status::Bad
    }
}

/// What the answer to one digest asked is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// The peer does not have it.
    Absent,
    /// The peer has no room for it in this answer.
    NoRoom,
    /// The peer failed to read it; the others still come.
    Failed,
    /// Its length follows: [`Reading::take`] says whether it is taken.
    Here,
    /// Not an answer: the peer is dropped.
    Bad,
}

/// What the status byte `byte` of the digest [`Reading::claim`] gave says.
pub fn turn(byte: u8) -> Turn {
    let s = status(byte);
    if s == Status::Absent {
        Turn::Absent
    } else if s == Status::NoRoom {
        Turn::NoRoom
    } else if s == Status::Failed {
        Turn::Failed
    } else if s == Status::Here {
        Turn::Here
    } else {
        Turn::Bad
    }
}

/// The answer to a request for chunks, as it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    asked: usize,
    next: usize,
    payload: u64,
    max_item: u64,
    max_payload: u64,
}

impl Reading {
    /// The answer to `asked` digests: a chunk is at most `max_item` bytes,
    /// and the chunks after the first with bytes bring the answer to at most
    /// `max_payload`.
    pub fn new(asked: usize, max_item: u64, max_payload: u64) -> Reading {
        Reading {
            asked,
            next: 0,
            payload: 0,
            max_item,
            max_payload,
        }
    }

    /// How many digests have had their turn: the last of them may still be
    /// unanswered, and what is left starts after it.
    pub fn next(&self) -> usize {
        self.next
    }

    /// The bytes taken so far.
    pub fn payload(&self) -> u64 {
        self.payload
    }

    /// The answer ends here (the peer failed to read its store while it sent
    /// a chunk: that chunk and the rest are for another peer).
    pub fn end(&mut self) {
        self.next = self.asked;
    }

    /// The turn of the next digest asked, before its status byte is read:
    /// its place in the list asked, or none when every digest was answered
    /// and nothing more is read.
    pub fn claim(&mut self) -> Option<usize> {
        if self.next >= self.asked {
            return None;
        }
        self.next += 1;
        Some(self.next - 1)
    }

    /// Whether the chunk of the last [`Turn::Here`], of `len` bytes and of
    /// the size `size` when it was asked, is taken; when it is, its bytes
    /// count toward the most the answer holds.  Called before the bytes are
    /// allocated or read.
    pub fn take(&mut self, len: u64, size: Option<u64>) -> bool {
        if len > self.max_item {
            return false;
        }
        if let Some(s) = size {
            if s != len {
                return false;
            }
        }
        if !room(self.payload, len, self.max_payload) {
            return false;
        }
        self.payload += len;
        true
    }
}

/// Whether an answer that holds `payload` bytes has room for a chunk of
/// `len` more, when it may hold `max_payload`: the first chunk with bytes
/// goes in whatever the rest weighs, the others while the answer stays
/// within the most.  The server sends by this rule and the asker takes by
/// it.  (`payload` is at most the larger of the two bounds, so the sum does
/// not overflow.)
pub fn room(payload: u64, len: u64, max_payload: u64) -> bool {
    payload == 0 || (payload <= max_payload && len <= max_payload - payload)
}

/// Whether an item of `len` bytes, the answer to a request for one thing
/// that may be at most `max` bytes, is taken.
pub fn item(len: u64, max: u64) -> bool {
    len != 0 && len <= max
}

/// Whether the text of a filter, `text` bytes of base64, may decode to a
/// whole filter of `max` bytes at most: checked before it is decoded.  (The
/// bound is worked out in 128 bits: it does not wrap for any `max`.)
pub fn full_text_ok(text: usize, max: usize) -> bool {
    text as u128 <= (max as u128 / 3) * 4 + 4
}

/// Whether the bytes of a whole filter, `bytes` of them and `hashes`
/// hashes, are one a filter may be.
pub fn full_ok(bytes: usize, hashes: u8) -> bool {
    bytes != 0
        && bytes.is_multiple_of(8)
        && bytes <= MAX_FILTER_BYTES
        && hashes != 0
        && hashes <= MAX_HASHES
}

/// Whether the bytes of a delta, `bytes` of them, are keys a delta may
/// carry.
pub fn delta_ok(bytes: usize) -> bool {
    bytes != 0 && bytes.is_multiple_of(8) && bytes / 8 <= MAX_DELTA_KEYS
}

/// What a filter says of a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    Maybe,
    No,
    /// No filter that is believed: the peer is asked as before filters
    Unknown,
}

/// What to do with a whole filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnFull {
    /// An older one than the one held: nothing.
    Stale,
    /// It replaces the one held.
    Take,
}

/// What to do with a delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnDelta {
    /// The filter held has what it adds: nothing.
    Stale,
    /// There is no filter to add to: only what was heard is noted.
    Skip,
    /// Add its keys to the filter held, then tell [`Seen::added`].
    Add,
}

/// The filter of a peer, as far as the order of its messages goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    /// The run of the sender the filter held is of, and its version.
    epoch: u64,
    version: u64,
    /// The last version of that run heard of: when it is past `version`, a
    /// message is missing and the filter does not say "no".
    heard: u64,
}

impl Seen {
    /// Nothing heard.
    pub fn new() -> Seen {
        Seen {
            epoch: 0,
            version: 0,
            heard: 0,
        }
    }

    /// The version of the filter held.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Whether a message of the peer is missing from the filter held (one
    /// was lost, comes later, or is of another run): its "no" is not
    /// believed then.
    pub fn behind(&self) -> bool {
        self.heard > self.version
    }

    /// A whole filter of the run `epoch` and the version `version`, whose
    /// bytes are taken ([`full_ok`]), when a filter is held (`held`) or not.
    pub fn full(&mut self, epoch: u64, version: u64, held: bool) -> OnFull {
        if epoch == self.epoch && version < self.version && held {
            return OnFull::Stale;
        }
        if epoch != self.epoch {
            self.epoch = epoch;
            self.heard = 0;
        }
        self.version = version;
        if version > self.heard {
            self.heard = version;
        }
        OnFull::Take
    }

    /// A delta of the run `epoch` that makes the version `to`, when a
    /// filter is held (`held`) or not.  A delta of another run leaves the
    /// filter behind, whatever `to` is: no whole filter of that run is held,
    /// so version 0 and a version heard of (at least 1) past it.
    pub fn delta(&mut self, epoch: u64, to: u64, held: bool) -> OnDelta {
        if epoch != self.epoch {
            self.epoch = epoch;
            self.version = 0;
            self.heard = if to > 0 { to } else { 1 };
        } else if to <= self.version {
            return OnDelta::Stale;
        }
        if to > self.heard {
            self.heard = to;
        }
        if held {
            OnDelta::Add
        } else {
            OnDelta::Skip
        }
    }

    /// The keys of the delta from `from` to `to` were added: the version
    /// follows when the delta applied to it, that is when it starts from
    /// the version held, which is not 0 (no whole filter of the run).
    pub fn added(&mut self, from: u64, to: u64) {
        if from == self.version && from != 0 {
            self.version = to;
        }
    }

    /// What the filter says of a key, from whether it is `believed` and
    /// whether it `contains` the key.
    pub fn says(&self, believed: bool, contains: bool) -> Said {
        if !believed {
            Said::Unknown
        } else if contains {
            Said::Maybe
        } else if self.behind() {
            Said::Unknown
        } else {
            Said::No
        }
    }
}

impl Default for Seen {
    fn default() -> Self {
        Seen::new()
    }
}

#[cfg(test)]
mod rules;
#[cfg(test)]
mod walk;
