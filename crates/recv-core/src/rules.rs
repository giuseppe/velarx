// SPDX-License-Identifier: Apache-2.0
//! The rules of the crate (see the docs of the library), stated with plain
//! arithmetic on 128-bit numbers and with sets of keys, not with the
//! counters of the functions, so that a mistake of the functions does not
//! repeat in the check.  Each check runs on one input; `walk` gives it
//! every input of a small world.

use super::*;

/// What a status byte says, from the four numbers.
pub(crate) fn check_status(byte: u8) {
    let want = match byte {
        0 => Status::Absent,
        1 => Status::Here,
        2 => Status::NoRoom,
        3 => Status::Failed,
        _ => Status::Bad,
    };
    assert_eq!(status(byte), want, "{byte}");
}

/// One answer read to its end: the statuses the peer sent for each digest
/// asked (and some more it sent after), and for a `Here` the length and the
/// size asked.  Rules 2 and 3: one turn per digest asked, then `End`; a
/// chunk is taken exactly by the arithmetic; what is taken is bounded; and
/// the first `Bad` ends the reading.
pub(crate) fn check_answer(
    asked: usize,
    max_item: u64,
    max_payload: u64,
    sent: &[(u8, u64, Option<u64>)],
) {
    let mut a = Reading::new(asked, max_item, max_payload);
    let mut held: u128 = 0;
    for (i, &(byte, len, size)) in sent.iter().enumerate() {
        let claimed = a.claim();
        if i >= asked {
            assert_eq!(claimed, None, "{sent:?}");
            continue;
        }
        // (the turn is the digest's before its byte is read: when the
        // read fails, `next` is past the digest, which is unanswered)
        assert_eq!(claimed, Some(i), "{sent:?}");
        assert_eq!(a.next(), i + 1);
        match byte {
            0 => assert_eq!(turn(byte), Turn::Absent),
            2 => assert_eq!(turn(byte), Turn::NoRoom),
            3 => assert_eq!(turn(byte), Turn::Failed),
            1 => {
                assert_eq!(turn(byte), Turn::Here);
                let want = len <= max_item
                    && size.is_none_or(|s| s == len)
                    && (held == 0 || held + len as u128 <= max_payload as u128);
                assert_eq!(a.take(len, size), want, "{sent:?} at {i}");
                if want {
                    held += len as u128;
                }
                assert_eq!(a.payload() as u128, held);
                assert!(held <= max_item.max(max_payload) as u128);
            }
            _ => {
                assert_eq!(turn(byte), Turn::Bad);
                break;
            }
        }
    }
}

/// Rule 3, the room of an answer, with plain arithmetic.
pub(crate) fn check_room(payload: u64, len: u64, max_payload: u64) {
    let want = payload == 0 || payload as u128 + len as u128 <= max_payload as u128;
    assert_eq!(
        room(payload, len, max_payload),
        want,
        "{payload} {len} {max_payload}"
    );
}

/// A correct peer: it holds each chunk of a list of sizes and sends it, or
/// says it has no room, by the rule it serves by (a chunk is at most
/// `max_item`, and [`room`] says whether the answer has room for it).  Every chunk it sends is taken, and the digests it
/// had no room for are exactly the ones it said so for (rule 4).
pub(crate) fn check_correct_peer(max_item: u64, max_payload: u64, sizes: &[u64]) {
    let mut a = Reading::new(sizes.len(), max_item, max_payload);
    let mut sent: u64 = 0;
    for &len in sizes {
        assert!(a.claim().is_some());
        if len <= max_item && room(sent, len, max_payload) {
            assert_eq!(turn(HERE), Turn::Here);
            assert!(a.take(len, Some(len)), "{sizes:?}: {len}");
            sent += len;
        } else {
            assert_eq!(turn(NO_ROOM), Turn::NoRoom);
        }
    }
    assert_eq!(a.claim(), None);
}

/// Rule 5.
pub(crate) fn check_item(len: u64, max: u64) {
    assert_eq!(item(len, max), len >= 1 && len <= max);
}

/// Rule 6, on a number of bytes and of hashes.
pub(crate) fn check_shape(bytes: usize, hashes: u8) {
    let words = bytes.is_multiple_of(8) && bytes >= 8;
    assert_eq!(
        full_ok(bytes, hashes),
        words && bytes <= 4 << 20 && (1..=16).contains(&hashes),
        "{bytes} {hashes}"
    );
    assert_eq!(delta_ok(bytes), words && bytes / 8 <= 8192, "{bytes}");
    // (the text is checked before it is decoded: a text that is the base64
    // of a size a filter may have is never refused)
    if bytes <= MAX_FILTER_BYTES {
        let text = bytes.div_ceil(3) * 4;
        assert!(full_text_ok(text, MAX_FILTER_BYTES), "{bytes}");
    }
    assert!(!full_text_ok(
        MAX_FILTER_BYTES.div_ceil(3) * 4 + 1,
        MAX_FILTER_BYTES
    ));
    // (the bound does not wrap: with no cap at all every text is below it)
    assert!(full_text_ok(usize::MAX, usize::MAX));
}

/// A message of the sender in one run, as a model of what it brings: the
/// keys a whole filter holds, or the key a delta adds.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Msg {
    Full { epoch: u64, version: u64 },
    Delta { epoch: u64, from: u64, to: u64 },
}

impl Msg {
    fn epoch(self) -> u64 {
        match self {
            Msg::Full { epoch, .. } | Msg::Delta { epoch, .. } => epoch,
        }
    }
}

/// The keys of a message of a sender that adds one key at each version: the
/// version `v` is the filter of the keys `0..v`, and the delta from `v`
/// adds the key `v` (it goes to `v + 1`).
fn keys_of(m: Msg) -> Vec<u64> {
    match m {
        Msg::Full { version, .. } => (0..version).collect(),
        Msg::Delta { from, .. } => vec![from],
    }
}

/// The shell of the receiver in a model: a set of keys, held or not, the
/// core beside it.  Returns what the filter says of `key`.
pub(crate) struct Model {
    pub seen: Seen,
    pub held: bool,
    pub keys: Vec<u64>,
    /// The run of the last message.
    pub run: Option<u64>,
    /// The run and the version the filter held is at: the last whole filter
    /// taken, and each delta of its run that applied since, from the version
    /// before it to a later one (never from 0, which no sender has).  None
    /// when a delta of another run came since the whole filter.  A delta
    /// that does not apply is added to the filter all the same, and leaves
    /// this alone: the filter is behind until a delta that applies makes
    /// the version heard of.
    pub chain: Option<(u64, u64)>,
}

impl Model {
    pub fn new() -> Model {
        Model {
            seen: Seen::new(),
            held: false,
            keys: Vec::new(),
            run: None,
            chain: None,
        }
    }

    pub fn receive(&mut self, m: Msg) {
        let before = self.run;
        self.run = Some(m.epoch());
        match m {
            Msg::Full { epoch, version } => {
                if self.seen.full(epoch, version, self.held) == OnFull::Take {
                    self.held = true;
                    self.keys = keys_of(m);
                    self.chain = Some((epoch, version));
                } else {
                    self.run = before;
                }
            }
            Msg::Delta { epoch, from, to } => match self.seen.delta(epoch, to, self.held) {
                OnDelta::Add => {
                    self.keys.extend(keys_of(m));
                    self.seen.added(from, to);
                    self.chain = match self.chain {
                        Some((e, _)) if e != epoch => None,
                        Some((_, v)) if v == from && from >= 1 && to > from => Some((epoch, to)),
                        other => other,
                    };
                }
                OnDelta::Stale => self.run = before,
                OnDelta::Skip => {}
            },
        }
    }

    pub fn says(&self, key: u64) -> Said {
        self.seen.says(self.held, self.keys.contains(&key))
    }
}

/// Rule 9: after each message, no key of the messages that arrived since
/// the run last changed is answered "no".
pub(crate) fn check_no_false_no(arrived: &[Msg]) {
    let mut model = Model::new();
    let mut told: Vec<u64> = Vec::new();
    let mut run = None;
    for &m in arrived {
        model.receive(m);
        if run != Some(m.epoch()) {
            run = Some(m.epoch());
            told.clear();
        }
        told.extend(keys_of(m));
        for &key in &told {
            assert_ne!(model.says(key), Said::No, "{arrived:?}: key {key}");
        }
    }
}

/// Rule 8, and what follows of rule 9 for any message: after each message of
/// a sequence of any (the numbers of a peer may be anything), a delta of
/// another run than the last message's leaves the filter behind, whatever
/// versions it names; and a filter that says "no" is a whole filter and
/// the deltas added since it, all of one run and each from the version the
/// one before made.
pub(crate) fn check_closed(arrived: &[Msg]) {
    let mut model = Model::new();
    for &m in arrived {
        let before = model.run;
        model.receive(m);
        if let Msg::Delta { epoch, .. } = m {
            if before != Some(epoch) {
                assert!(model.seen.behind(), "{arrived:?}");
            }
        }
        for key in 0..4 {
            if model.says(key) == Said::No {
                assert!(model.chain.is_some(), "{arrived:?}: key {key}");
            }
        }
    }
}
