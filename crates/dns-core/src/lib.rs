// SPDX-License-Identifier: Apache-2.0
//! The DNS messages of the container name server (RFC 1035): what is read
//! of a query that any container of a bridge can send, and the reply built
//! from the records that the shell looked up.  The shell decides what a
//! name means (the zone, the reverse names, the forwarding to the upstream
//! servers); this crate never looks anything up.
//!
//! The rules, for every byte string:
//!
//! 1. Nothing panics or reads out of bounds, whatever the bytes and the
//!    sizes.
//! 2. A query is a message of at least 12 bytes with the response bit
//!    clear.  Its question is read when the question count is 1 and the
//!    name is a series of labels of 1 to 63 bytes, without compression
//!    pointers, dots or NULs inside a label, up to 255 bytes on the wire
//!    (253 characters), followed by the type and the class.  The name is
//!    read as lower case dotted bytes, and the question ends at `end`.
//!    The other counts of the header, the bytes after the question and
//!    the additional records (EDNS) are not looked at by `question`.
//! 3. `parse` answers a query that has no readable question, or has an
//!    answer or authority count, with the reply FORMERR, and one whose
//!    opcode is not 0 with NOTIMP (FORMERR first); it does not answer a
//!    short message or a response.
//! 4. A reply echoes the ID of the query and its question bytes exactly (the
//!    case of the name too), and has no other section than the answers it
//!    holds: the answer count of the header is the number of records
//!    written, the others are 0.
//! 5. A reply is never longer than the size given (and never longer than
//!    65535 bytes).  When the question alone does not fit there is none.
//!    The records are written in the order given while they fit; the first
//!    that does not fit stops the series, the truncation bit is set, and no
//!    record is cut: the message ends where a record ends.
//! 6. A reply is authoritative (AA) only when the caller says so: this
//!    crate does not know the zone.  It always has the response bit, the
//!    recursion available bit, the recursion desired bit of the query, and
//!    the code given.
//! 7. A question of valid labels, written by a client, is read back as it
//!    was written (the round trip, checked in the tests).
//!
//! The code is plain loops over slices with indices, so that Aeneas can
//! translate it (tools/verify).  Rules 1 to 6, for every message, size and
//! records, and the lower case round trip of 7 are proved in Lean
//! (tools/verify/dns-core).

/// The header of a message.
pub const HEADER: usize = 12;
/// The longest name, in bytes on the wire (RFC 1035, 2.3.4): the labels with
/// their lengths and the zero that ends the name, 253 characters of text.
const MAX_NAME: usize = 255;
/// What a message can hold (the length of TCP messages is 16 bits).
const MAX_MESSAGE: usize = 65535;
/// The size of a record without its data: the pointer to the question
/// name, the type, the class, the TTL and the length of the data.
const RR_FIXED: usize = 12;

pub const TTL: u32 = 60;
pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;
pub const RCODE_FORMERR: u16 = 1;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NXDOMAIN: u16 = 3;
pub const RCODE_NOTIMP: u16 = 4;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const OPCODE: u16 = 0x7800;
const RCODE: u16 = 0x000f;

/// The question of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub flags: u16,
    /// Lower case, dotted, without a trailing dot ("" for the root).
    pub name: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    /// The offset after the question.
    pub end: usize,
}

/// What to do with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Too short, or a response: no reply.
    Drop,
    /// Not a query that can be answered: the code of the reply that tells
    /// it (`error_reply`).
    Refuse(u16),
    Query(Question),
}

/// A record of the answer section; its name is the question's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rr {
    pub ty: u16,
    pub data: Vec<u8>,
}

fn get16(m: &[u8], at: usize) -> Option<u16> {
    if m.len() < 2 || at > m.len() - 2 {
        return None;
    }
    Some((u16::from(m[at]) << 8) | u16::from(m[at + 1]))
}

fn put16(out: &mut [u8], at: usize, v: u16) {
    out[at] = (v >> 8) as u8;
    out[at + 1] = (v & 0xff) as u8;
}

fn push16(out: &mut Vec<u8>, v: u16) {
    out.push((v >> 8) as u8);
    out.push((v & 0xff) as u8);
}

/// The name at the offset HEADER as lower case dotted bytes, and the offset
/// after it.  A pointer, a label of 64 or more, a dot or a NUL inside a
/// label, a name of more than 255 bytes on the wire, or a name that is cut: None.
#[allow(clippy::manual_range_contains)] // (`contains` is a library call the proofs would model)
fn read_name(m: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut name: Vec<u8> = Vec::new();
    let mut off = HEADER;
    let mut ok = true;
    let mut done = false;
    while ok && !done {
        if off >= m.len() {
            ok = false;
        } else {
            let l = usize::from(m[off]);
            off += 1;
            if l == 0 {
                done = true;
            } else if l > 63 || off - HEADER + l + 1 > MAX_NAME || off + l > m.len() {
                ok = false;
            } else {
                if !name.is_empty() {
                    name.push(b'.');
                }
                let mut i = 0;
                while ok && i < l {
                    let c = m[off + i];
                    if c == b'.' || c == 0 {
                        ok = false;
                    } else {
                        if c >= b'A' && c <= b'Z' {
                            name.push(c + 32);
                        } else {
                            name.push(c);
                        }
                        i += 1;
                    }
                }
                off += l;
            }
        }
    }
    if ok {
        Some((name, off))
    } else {
        None
    }
}

/// The question of the query M: None for a message shorter than a header,
/// a response, a question count other than 1, an unreadable name, or a
/// question without its type and class.
#[allow(clippy::question_mark)] // (`?` is a library call the proofs would model)
pub fn question(m: &[u8]) -> Option<Question> {
    let Some(flags) = get16(m, 2) else {
        return None;
    };
    if m.len() < HEADER || flags & FLAG_QR != 0 || !matches!(get16(m, 4), Some(1)) {
        return None;
    }
    let Some((name, at)) = read_name(m) else {
        return None;
    };
    let (Some(id), Some(qtype), Some(qclass)) = (get16(m, 0), get16(m, at), get16(m, at + 2))
    else {
        return None;
    };
    Some(Question {
        id,
        flags,
        name,
        qtype,
        qclass,
        end: at + 4,
    })
}

/// What the server does with the message M.
pub fn parse(m: &[u8]) -> Parsed {
    let flags = match get16(m, 2) {
        Some(f) if m.len() >= HEADER && f & FLAG_QR == 0 => f,
        _ => return Parsed::Drop,
    };
    if !matches!(get16(m, 6), Some(0)) || !matches!(get16(m, 8), Some(0)) {
        return Parsed::Refuse(RCODE_FORMERR);
    }
    match question(m) {
        None => Parsed::Refuse(RCODE_FORMERR),
        Some(_) if flags & OPCODE != 0 => Parsed::Refuse(RCODE_NOTIMP),
        Some(q) => Parsed::Query(q),
    }
}

/// A reply of a header only: the ID of M (0 if it has none), the response
/// bit, the recursion bits of M and the code RCODE; no question, no
/// records.
pub fn error_reply(m: &[u8], rcode: u16) -> Vec<u8> {
    let rd = get16(m, 2).unwrap_or(0) & FLAG_RD;
    let mut out = vec![0u8; HEADER];
    put16(&mut out, 0, get16(m, 0).unwrap_or(0));
    put16(&mut out, 2, FLAG_QR | FLAG_RA | rd | (rcode & RCODE));
    out
}

/// The name NAME (dotted, may be empty) in wire format; None if a label is
/// empty or longer than 63, or the name is too long (the wire name is two
/// bytes longer than the dotted one: the length of the first label and the
/// zero that ends it).
pub fn encode_name(name: &[u8]) -> Option<Vec<u8>> {
    if name.len() > MAX_NAME - 2 {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut ok = true;
    if !name.is_empty() {
        let mut start = 0;
        let mut i = 0;
        while ok && i <= name.len() {
            if i == name.len() || name[i] == b'.' {
                let l = i - start;
                if l == 0 || l > 63 {
                    ok = false;
                } else {
                    out.push(l as u8);
                    let mut j = start;
                    while j < i {
                        out.push(name[j]);
                        j += 1;
                    }
                    start = i + 1;
                }
            }
            i += 1;
        }
    }
    out.push(0);
    if ok {
        Some(out)
    } else {
        None
    }
}

/// The reply to the query M: its ID and question, the code RCODE, AA when
/// AUTHORITATIVE, and the records RRS (type IN, the TTL, a pointer to the
/// question name) while they fit in OUT_SIZE bytes.  None when M has no
/// question, or the question alone does not fit.
#[allow(clippy::question_mark)] // (`?` is a library call the proofs would model)
pub fn reply(
    m: &[u8],
    rcode: u16,
    authoritative: bool,
    out_size: usize,
    rrs: &[Rr],
) -> Option<Vec<u8>> {
    let Some(q) = question(m) else {
        return None;
    };
    let limit = if out_size < MAX_MESSAGE {
        out_size
    } else {
        MAX_MESSAGE
    };
    if q.end > limit {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0;
    while i < q.end {
        out.push(m[i]);
        i += 1;
    }
    let mut count: u16 = 0;
    let mut cut = false;
    let mut k = 0;
    while k < rrs.len() && !cut {
        let n = rrs[k].data.len();
        // (a length near usize::MAX must not wrap the sum)
        if n > limit || out.len() + RR_FIXED + n > limit {
            cut = true;
        } else {
            push16(&mut out, 0xc000 | HEADER as u16);
            push16(&mut out, rrs[k].ty);
            push16(&mut out, CLASS_IN);
            out.push((TTL >> 24) as u8);
            out.push(((TTL >> 16) & 0xff) as u8);
            out.push(((TTL >> 8) & 0xff) as u8);
            out.push((TTL & 0xff) as u8);
            push16(&mut out, n as u16);
            let mut j = 0;
            while j < n {
                out.push(rrs[k].data[j]);
                j += 1;
            }
            count += 1;
            k += 1;
        }
    }
    let mut flags = FLAG_QR | FLAG_RA | (q.flags & FLAG_RD) | (rcode & RCODE);
    if authoritative {
        flags |= FLAG_AA;
    }
    if cut {
        flags |= FLAG_TC;
    }
    put16(&mut out, 2, flags);
    put16(&mut out, 6, count);
    put16(&mut out, 8, 0);
    put16(&mut out, 10, 0);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query for NAME (dotted bytes) as a client writes it.
    fn build_query(id: u16, flags: u16, name: &[u8], qtype: u16, qclass: u16) -> Option<Vec<u8>> {
        let mut m = Vec::new();
        push16(&mut m, id);
        push16(&mut m, flags);
        push16(&mut m, 1);
        m.extend_from_slice(&[0; 6]);
        m.extend_from_slice(&encode_name(name)?);
        push16(&mut m, qtype);
        push16(&mut m, qclass);
        Some(m)
    }

    fn rrs() -> Vec<Rr> {
        vec![
            Rr {
                ty: TYPE_A,
                data: vec![10, 0, 0, 1],
            },
            Rr {
                ty: TYPE_AAAA,
                data: vec![7; 16],
            },
            Rr {
                ty: TYPE_PTR,
                data: encode_name(b"web").unwrap(),
            },
            Rr {
                ty: TYPE_A,
                data: Vec::new(),
            },
        ]
    }

    /// The records of the answer section of R, as (type, data), by walking
    /// the bytes: None when they do not end exactly at the end of R.
    fn records(r: &[u8], end: usize) -> Option<Vec<Rr>> {
        let mut at = end;
        let mut found = Vec::new();
        while at < r.len() {
            let fixed = r.get(at..at + RR_FIXED)?;
            assert_eq!(fixed[..2], [0xc0, 0x0c]);
            assert_eq!(fixed[4..8], [0, 1, 0, 0]);
            assert_eq!(fixed[8..10], [0, TTL as u8]);
            let n = usize::from(fixed[10]) << 8 | usize::from(fixed[11]);
            let data = r.get(at + RR_FIXED..at + RR_FIXED + n)?.to_vec();
            found.push(Rr {
                ty: u16::from(fixed[2]) << 8 | u16::from(fixed[3]),
                data,
            });
            at += RR_FIXED + n;
        }
        Some(found)
    }

    /// Every rule on one message: what `question` and `parse` make of M, and
    /// the reply to it for some codes, sizes and records (`deep`: for all
    /// the combinations, else for a few).
    fn check(m: &[u8], deep: bool) {
        let q = question(m);
        let parsed = parse(m);
        let query = m.len() >= HEADER && m[2] & 0x80 == 0;
        // what a message is, from the header alone (the order of the rules:
        // not a query, then the counts and the name, then the opcode)
        let counts = get16(m, 4) == Some(1) && get16(m, 6) == Some(0) && get16(m, 8) == Some(0);
        let expected = match &q {
            _ if !query => Parsed::Drop,
            Some(_) if counts && m[2] & 0x78 != 0 => Parsed::Refuse(RCODE_NOTIMP),
            Some(q) if counts => Parsed::Query(q.clone()),
            _ => Parsed::Refuse(RCODE_FORMERR),
        };
        assert_eq!(parsed, expected);
        match (&parsed, &q) {
            (Parsed::Drop, _) => assert!(!query),
            (Parsed::Refuse(c), _) => {
                assert!(query && (*c == RCODE_FORMERR || *c == RCODE_NOTIMP));
                let r = error_reply(m, *c);
                assert_eq!((r.len(), r[..2] == m[..2]), (HEADER, true));
                assert_eq!(r[2] & 0x80, 0x80);
                assert_eq!(r[3] & 0x8f, 0x80 | *c as u8);
                assert!(r[4..].iter().all(|b| *b == 0));
            }
            (Parsed::Query(p), Some(q)) => assert_eq!(p, q),
            (Parsed::Query(_), None) => panic!("a query without a question"),
        }
        if let Some(q) = &q {
            assert!(query && HEADER < q.end && q.end <= m.len());
            assert_eq!(
                (q.id, q.flags),
                (get16(m, 0).unwrap(), get16(m, 2).unwrap())
            );
            assert!(q.name.len() <= MAX_NAME - 2);
            assert!(q.name.iter().all(|c| *c != 0 && !c.is_ascii_uppercase()));
            assert_eq!(get16(m, 4), Some(1));
            // the name read is the name written, in lower case
            let wire = encode_name(&q.name).expect("a name that was read can be written");
            assert!(wire.len() == q.end - 4 - HEADER);
            assert!(wire.eq_ignore_ascii_case(&m[HEADER..q.end - 4]));
        }
        let all = rrs();
        let sizes: &[usize] = if deep {
            &[0, 11, 12, 20, 21, 22, 40, 100, 512, 70000]
        } else {
            &[20, 30, 512]
        };
        let (codes, auth, counts): (&[u16], &[bool], &[usize]) = if deep {
            (&[0, RCODE_NXDOMAIN], &[false, true], &[0, 1, 3, 4])
        } else {
            (&[RCODE_NXDOMAIN], &[true], &[4])
        };
        for size in sizes.iter().copied() {
            for rcode in codes.iter().copied() {
                for authoritative in auth.iter().copied() {
                    for n in counts.iter().copied() {
                        let given = &all[..n];
                        let got = reply(m, rcode, authoritative, size, given);
                        let Some(q) = &q else {
                            assert_eq!(got, None);
                            continue;
                        };
                        let limit = size.min(MAX_MESSAGE);
                        let Some(r) = got else {
                            assert!(q.end > limit);
                            continue;
                        };
                        assert!(r.len() <= limit && q.end <= r.len());
                        // the ID and the question, exactly
                        assert_eq!(r[..2], m[..2]);
                        assert_eq!(r[HEADER..q.end], m[HEADER..q.end]);
                        assert_eq!(r[4..6], [0, 1]);
                        // the count is what is written, the rest of the
                        // sections is empty
                        let written = records(&r, q.end).expect("records end with the message");
                        assert_eq!(get16(&r, 6), Some(written.len() as u16));
                        assert_eq!(r[8..12], [0, 0, 0, 0]);
                        assert_eq!(written[..], given[..written.len()]);
                        // all of them, or the truncation bit
                        let tc = r[2] & 0x02 != 0;
                        assert_eq!(tc, written.len() < given.len());
                        // a record stops the series only when it does not fit
                        if tc {
                            let next = RR_FIXED + given[written.len()].data.len();
                            assert!(r.len() + next > limit);
                        }
                        let aa = r[2] & 0x04 != 0;
                        assert_eq!(aa, authoritative);
                        assert_eq!(r[2] & 0x81, 0x80 | (m[2] & 1));
                        assert_eq!(r[3], 0x80 | rcode as u8);
                    }
                }
            }
        }
    }

    /// Every message of up to 7 bytes after a header of one question, over
    /// the bytes that matter to the name: a length, the longest and a too
    /// long label, a pointer, a dot, a NUL, a letter, a capital.
    #[test]
    fn every_name_over_a_small_alphabet() {
        let letters = [0, 1, 2, 63, 64, 0xc0, b'.', b'A'];
        let head = build_query(0x1234, 0x0100, b"", 1, 1).unwrap();
        let head = &head[..HEADER];
        let mut tail: Vec<u8> = Vec::new();
        let mut seen = 0usize;
        // lengths 0..=7: counting in base 8
        for len in 0..=7u32 {
            for mut n in 0..letters.len().pow(len) {
                tail.clear();
                for _ in 0..len {
                    tail.push(letters[n % letters.len()]);
                    n /= letters.len();
                }
                let mut m = head.to_vec();
                m.extend_from_slice(&tail);
                check(&m, false);
                seen += 1;
            }
        }
        assert_eq!(seen, (0..=7u32).map(|l| 8usize.pow(l)).sum::<usize>());
    }

    /// Every header, short or not, over the bytes that matter to it: the
    /// QR bit, the opcode, the counts; followed by a question, or cut.
    #[test]
    fn every_header_over_a_small_alphabet() {
        let flags = [0x00, 0x01, 0x80, 0x08, 0x78, 0x04, 0x0f];
        let counts = [0, 1, 2];
        let question = b"\x03web\x00\x00\x01\x00\x01";
        let mut seen = 0;
        for f0 in flags {
            for f1 in flags {
                for qd in counts {
                    for an in counts {
                        for ns in counts {
                            for ar in counts {
                                let mut m = vec![0x12, 0x34, f0, f1, 0, qd, 0, an, 0, ns, 0, ar];
                                m.extend_from_slice(question);
                                for cut in 0..=m.len() {
                                    check(&m[..cut], true);
                                    seen += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(seen, 7 * 7 * 81 * 22);
    }

    /// A small deterministic generator of bytes (xorshift64).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    /// Random and mutated messages, long ones among them.
    #[test]
    fn random_messages() {
        let mut rng = Rng(0x5eed_d125);
        let seeds = [
            build_query(1, 0x0100, b"web", 1, 1).unwrap(),
            build_query(2, 0, b"a.b.dns.podman", 255, 1).unwrap(),
            build_query(3, 0x0100, b"5.7.88.10.in-addr.arpa", 12, 1).unwrap(),
        ];
        for i in 0..100_000 {
            let mut m = if i % 5 == 0 {
                let n = rng.below(600);
                (0..n).map(|_| rng.next() as u8).collect()
            } else {
                seeds[i % seeds.len()].clone()
            };
            for _ in 0..rng.below(5) {
                if m.is_empty() {
                    break;
                }
                let at = rng.below(m.len());
                match rng.below(4) {
                    0 => m[at] = rng.next() as u8,
                    1 => m.truncate(at),
                    2 => m.insert(at, rng.next() as u8),
                    _ => m[at] = [0, 63, 64, 0xc0, 0xff][rng.below(5)],
                }
            }
            check(&m, true);
        }
    }

    /// A question that is written is read back, for names of every shape
    /// that a client can write, in lower case.
    #[test]
    fn a_question_is_read_back_as_written() {
        let mut rng = Rng(77);
        for i in 0..20_000 {
            let mut name = Vec::new();
            for l in 0..rng.below(6) {
                if l > 0 {
                    name.push(b'.');
                }
                let longest = if i % 50 == 0 { 63 } else { 8 };
                for _ in 0..=rng.below(longest) {
                    // anything but a dot and a NUL, capitals among it
                    let mut c = 0;
                    while c == 0 || c == b'.' {
                        c = rng.next() as u8;
                    }
                    name.push(c);
                }
            }
            if name.len() > MAX_NAME - 2 {
                continue;
            }
            let (id, flags) = (rng.next() as u16, rng.next() as u16 & !FLAG_QR);
            let (qtype, qclass) = (rng.next() as u16, rng.next() as u16);
            let m = build_query(id, flags, &name, qtype, qclass).unwrap();
            let lower = name.to_ascii_lowercase();
            let q = Question {
                id,
                flags,
                name: lower,
                qtype,
                qclass,
                end: m.len(),
            };
            assert_eq!(question(&m), Some(q.clone()), "{m:?}");
            if flags & OPCODE == 0 {
                assert_eq!(parse(&m), Parsed::Query(q));
            }
        }
        // the longest name, and one character more, as a client writes
        // them (the name is not checked by `build_query`)
        let name = |last: usize| {
            let mut n = vec![[b'a'; 63].to_vec(); 3];
            n.push(vec![b'd'; last]);
            n.join(&b'.')
        };
        let wire = |n: &[u8]| {
            let mut m = build_query(1, 0, b"", 1, 1).unwrap();
            m.truncate(HEADER);
            for label in n.split(|c| *c == b'.') {
                m.push(label.len() as u8);
                m.extend_from_slice(label);
            }
            m.extend_from_slice(&[0, 0, 1, 0, 1]);
            m
        };
        assert_eq!(name(61).len(), 253);
        assert_eq!(question(&wire(&name(61))).unwrap().name, name(61));
        assert_eq!(build_query(1, 0, &name(61), 1, 1).unwrap().len(), 255 + 16);
        // a label of 64 and one of 192 (a pointer), with room for the bytes
        for l in [64, 0xc0, 0xff] {
            let mut m = wire(b"");
            m.truncate(HEADER);
            m.push(l as u8);
            m.extend_from_slice(&vec![b'a'; l]);
            m.extend_from_slice(&[0, 0, 1, 0, 1]);
            assert_eq!(question(&m), None);
        }
        assert_eq!(question(&wire(&name(62))), None);
        assert_eq!(question(&wire(&name(63))), None);
    }

    /// The records that fit, at every size: the count is the number of
    /// records that fit whole, and the message ends where the last ends.
    #[test]
    fn the_size_cuts_between_records() {
        let m = build_query(9, 0x0100, b"web", 255, 1).unwrap();
        let all = rrs();
        let mut last = 0;
        for size in 0..200 {
            let Some(r) = reply(&m, 0, true, size, &all) else {
                assert!(size < m.len());
                continue;
            };
            let n = usize::from(r[7]);
            let end: usize = m.len()
                + all[..n]
                    .iter()
                    .map(|r| RR_FIXED + r.data.len())
                    .sum::<usize>();
            assert_eq!(r.len(), end, "{size}");
            assert!(r.len() <= size && n >= last);
            last = n;
        }
        assert_eq!(last, 4);
        // nothing but the size limits a reply
        assert_eq!(reply(&m, 0, true, usize::MAX, &all).unwrap()[7], 4);
        let big = vec![
            Rr {
                ty: TYPE_PTR,
                data: vec![0; 40000]
            };
            3
        ];
        let r = reply(&m, 0, true, usize::MAX, &big).unwrap();
        assert_eq!((r.len() <= MAX_MESSAGE, r[7], r[2] & 2), (true, 1, 2));
    }

    #[test]
    fn names_on_the_wire() {
        assert_eq!(encode_name(b""), Some(vec![0]));
        assert_eq!(encode_name(b"a.bc"), Some(vec![1, b'a', 2, b'b', b'c', 0]));
        for bad in [&b"."[..], b"a.", b".a", b"a..b"] {
            assert_eq!(encode_name(bad), None);
        }
        assert!(encode_name(&[b'a'; 63]).is_some());
        assert_eq!(encode_name(&[b'a'; 64]), None);
        let name = |labels: usize, last: usize| {
            let mut n = vec![[b'a'; 63].to_vec(); labels];
            n.push(vec![b'a'; last]);
            n.join(&b'.')
        };
        // 255 bytes on the wire is the longest: 253 characters
        assert_eq!(encode_name(&name(3, 61)).map(|w| w.len()), Some(255));
        assert_eq!(encode_name(&name(3, 62)), None);
        assert_eq!(encode_name(&name(3, 63)), None);
    }
}
