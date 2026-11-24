// SPDX-License-Identifier: Apache-2.0
//! The rules of the header, checked: exhaustively over every byte string up
//! to a small length over alphabets that hit every length form, on seeded
//! random and mutated real blobs, and against plain slice readers (the
//! `oracle_` functions: what the shell read before this crate, in the
//! simplest form) that must give the same answer for all of them.

use crate::der::{self, DerError};
use crate::sig::subpackets;
use crate::{packets, signature, Error, Packet, Signature, Span, Subpackets, MAX_PACKETS};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../signature/tests/fixtures/signature"
);

fn file(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
}

/// Calls `f` with every byte string of at most `max` bytes over `alphabet`,
/// and says how many that was.
fn every(alphabet: &[u8], max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
    let mut count = 1;
    f(&[]);
    for len in 1..=max {
        let mut digits = vec![0usize; len];
        let mut more = true;
        while more {
            let bytes: Vec<u8> = digits.iter().map(|d| alphabet[*d]).collect();
            f(&bytes);
            count += 1;
            let mut i = len;
            while i > 0 && digits[i - 1] == alphabet.len() - 1 {
                digits[i - 1] = 0;
                i -= 1;
            }
            more = i > 0;
            if more {
                digits[i - 1] += 1;
            }
        }
    }
    count
}

/// How many byte strings of at most `max` bytes there are over `size`
/// symbols.
fn how_many(size: usize, max: u32) -> usize {
    (0..=max).map(|n| size.pow(n)).sum()
}

/// A fixed sequence of numbers (xorshift64).
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

    fn byte_of(&mut self, alphabet: &[u8]) -> u8 {
        alphabet[self.below(alphabet.len())]
    }
}

// What the shell read before, as simply as it can be said.

/// The packets as (tag, joined body).
fn oracle_packets(data: &[u8]) -> Result<Vec<(u8, Vec<u8>)>, Error> {
    let mut rest = data;
    let mut out = Vec::new();
    let mut pieces = 0;
    let take = |rest: &mut &[u8], n: usize| -> Result<Vec<u8>, Error> {
        if n > rest.len() {
            return Err(Error::Truncated);
        }
        let (head, tail) = rest.split_at(n);
        *rest = tail;
        Ok(head.to_vec())
    };
    let num = |rest: &mut &[u8], n: usize| -> Result<usize, Error> {
        Ok(take(rest, n)?
            .iter()
            .fold(0, |a, b| (a << 8) | usize::from(*b)))
    };
    while !rest.is_empty() {
        if pieces >= MAX_PACKETS {
            return Err(Error::TooManyPackets);
        }
        let first = take(&mut rest, 1)?[0];
        if first & 0x80 == 0 {
            return Err(Error::NotAPacket);
        }
        if first & 0x40 == 0 {
            let len = match first & 3 {
                0 => num(&mut rest, 1)?,
                1 => num(&mut rest, 2)?,
                2 => num(&mut rest, 4)?,
                _ => rest.len(),
            };
            out.push(((first >> 2) & 15, take(&mut rest, len)?));
            pieces += 1;
        } else {
            let tag = first & 0x3f;
            let mut body = Vec::new();
            let mut first_piece = true;
            loop {
                let o1 = num(&mut rest, 1)?;
                let (n, partial) = match o1 {
                    0..=191 => (o1, false),
                    192..=223 => {
                        let o2 = num(&mut rest, 1)?;
                        (((o1 - 192) << 8) + o2 + 192, false)
                    }
                    255 => (num(&mut rest, 4)?, false),
                    _ => {
                        if tag != 8 && tag != 11 {
                            return Err(Error::PartialLength);
                        }
                        (1 << (o1 & 0x1f), true)
                    }
                };
                if !first_piece && pieces >= MAX_PACKETS {
                    return Err(Error::TooManyPackets);
                }
                body.extend(take(&mut rest, n)?);
                pieces += 1;
                first_piece = false;
                if !partial {
                    break;
                }
            }
            out.push((tag, body));
        }
    }
    Ok(out)
}

/// What the subpackets say, with the bytes copied out.
#[derive(Debug, PartialEq)]
struct Said {
    created: Option<u32>,
    expires: Option<u32>,
    key_expires: Option<u32>,
    key_flags: Option<u8>,
    issuer: Option<[u8; 8]>,
    issuer_fpr: Option<Vec<u8>>,
    embedded: Vec<Vec<u8>>,
}

fn said(body: &[u8], s: &Subpackets) -> Said {
    Said {
        created: s.created,
        expires: s.expires,
        key_expires: s.key_expires,
        key_flags: s.key_flags,
        issuer: s.issuer,
        issuer_fpr: s.issuer_fpr.map(|f| f.of(body).to_vec()),
        embedded: s.embedded.iter().map(|e| e.of(body).to_vec()).collect(),
    }
}

fn oracle_subpackets(area: &[u8], hashed: bool, out: &mut Said) -> Result<(), Error> {
    let mut rest = area;
    while let Some((&o1, tail)) = rest.split_first() {
        rest = tail;
        let len = match o1 {
            0..=191 => usize::from(o1),
            192..=254 => {
                let (&o2, tail) = rest.split_first().ok_or(Error::Truncated)?;
                rest = tail;
                ((usize::from(o1) - 192) << 8) + usize::from(o2) + 192
            }
            255 => {
                let n = rest.get(..4).ok_or(Error::Truncated)?;
                rest = &rest[4..];
                n.iter().fold(0, |a, b| (a << 8) | usize::from(*b))
            }
        };
        if len == 0 {
            return Err(Error::EmptySubpacket);
        }
        if len > rest.len() {
            return Err(Error::Truncated);
        }
        let (sp, tail) = rest.split_at(len);
        rest = tail;
        let (kind, value) = (sp[0], &sp[1..]);
        let critical = kind & 0x80 != 0;
        let be32 = |v: &[u8]| match v {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(Error::BadTime),
        };
        match kind & 0x7f {
            2 if hashed => out.created = Some(be32(value)?),
            3 if hashed => out.expires = Some(be32(value)?),
            9 if hashed => out.key_expires = Some(be32(value)?),
            27 if hashed => out.key_flags = Some(value.first().copied().unwrap_or(0)),
            16 => {
                if let Ok(id) = <[u8; 8]>::try_from(value) {
                    out.issuer = Some(id);
                }
            }
            33 => {
                if let [4, fpr @ ..] = value {
                    out.issuer_fpr = Some(fpr.to_vec());
                }
            }
            32 => out.embedded.push(value.to_vec()),
            k if critical && hashed && !KNOWN.contains(&k) => {
                return Err(Error::UnknownCritical(k));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The subpacket kinds of RFC 4880 and RFC 9580 that a critical bit may
/// be on although nothing is read of them.
const KNOWN: [u8; 15] = [4, 5, 7, 11, 12, 21, 22, 23, 25, 26, 28, 29, 30, 31, 34];

fn empty() -> Said {
    Said {
        created: None,
        expires: None,
        key_expires: None,
        key_flags: None,
        issuer: None,
        issuer_fpr: None,
        embedded: Vec::new(),
    }
}

fn read_subpackets(area: &[u8], hashed: bool) -> Result<Said, Error> {
    let mut out = Subpackets::default();
    let span = Span {
        off: 0,
        len: area.len(),
    };
    subpackets(area, &span, hashed, &mut out)?;
    Ok(said(area, &out))
}

// What is true of everything that is returned.

fn pieces(p: &Packet) -> Vec<Span> {
    let mut all = vec![p.body];
    all.extend(p.more.iter().copied());
    all
}

fn joined(data: &[u8], p: &Packet) -> Vec<u8> {
    pieces(p).iter().flat_map(|s| s.of(data).to_vec()).collect()
}

fn check_packets(data: &[u8], got: &[Packet]) {
    assert!(got.iter().map(|p| 1 + p.more.len()).sum::<usize>() <= MAX_PACKETS);
    let mut after = 0;
    let mut sum = 0;
    for p in got {
        let all = pieces(p);
        for (i, s) in all.iter().enumerate() {
            // after a header of a byte at least, and after the piece before
            assert!(s.off > after, "{data:02x?}");
            assert!(s.end() <= data.len(), "{data:02x?}");
            sum += s.len;
            after = s.end();
            // a piece before the last is of a partial length: 2^n
            if i + 1 < all.len() {
                assert!(s.len.is_power_of_two() && s.len <= 1 << 30, "{data:02x?}");
            }
        }
        if all.len() > 1 {
            assert!(p.tag == 8 || p.tag == 11, "{data:02x?}");
        }
    }
    assert!(sum <= data.len());
    // all of the input, or nothing of it
    assert_eq!(after, if got.is_empty() { 0 } else { data.len() });
    assert!(!got.is_empty() || data.is_empty());
}

fn check_packet_bytes(data: &[u8]) {
    let got = packets(data);
    let want = oracle_packets(data);
    match (&got, &want) {
        (Ok(g), Ok(w)) => {
            check_packets(data, g);
            let g: Vec<(u8, Vec<u8>)> = g.iter().map(|p| (p.tag, joined(data, p))).collect();
            assert_eq!(&g, w, "{data:02x?}");
        }
        (Err(g), Err(w)) => assert_eq!(g, w, "{data:02x?}"),
        _ => panic!("{data:02x?}: {got:?} against {want:?}"),
    }
}

fn inside(s: &Span, area: &Span) -> bool {
    s.off >= area.off && s.end() <= area.end()
}

fn check_signature(body: &[u8], sig: &Signature) {
    let be16 = |at: usize| usize::from(body[at]) << 8 | usize::from(body[at + 1]);
    assert_eq!(body[0], 4);
    assert_eq!(
        (sig.sig_type, sig.algo, sig.hash),
        (body[1], body[2], body[3])
    );
    assert_eq!(sig.hashed.off, 6);
    assert_eq!(sig.hashed.len, be16(4));
    assert_eq!(sig.unhashed.off, sig.hashed.end() + 2);
    assert_eq!(sig.unhashed.len, be16(sig.hashed.end()));
    let left = sig.unhashed.end();
    assert_eq!(sig.left16, [body[left], body[left + 1]]);
    let mut after = left + 2;
    let want = match sig.algo {
        1 | 3 => 1,
        17 | 19 | 22 => 2,
        27 => 1,
        a => panic!("algorithm {a}"),
    };
    assert_eq!(sig.values.len(), want);
    for v in &sig.values {
        if sig.algo == 27 {
            assert_eq!((v.off, v.len), (after, 64));
        } else {
            assert_eq!(v.off, after + 2);
            assert_eq!(v.len, be16(after).div_ceil(8));
        }
        assert!(v.end() <= body.len());
        after = v.end();
    }
    for s in sig.sub.issuer_fpr.iter().chain(&sig.sub.embedded) {
        assert!(
            inside(s, &sig.hashed) || inside(s, &sig.unhashed),
            "{body:02x?}"
        );
    }
}

/// A signature body is read as the oracle reads it, and what is said of
/// it holds.
fn check_signature_bytes(body: &[u8]) -> Option<Signature> {
    let got = signature(body);
    match &got {
        Ok(sig) => {
            check_signature(body, sig);
            let mut want = empty();
            oracle_subpackets(sig.hashed.of(body), true, &mut want).unwrap();
            oracle_subpackets(sig.unhashed.of(body), false, &mut want).unwrap();
            assert_eq!(said(body, &sig.sub), want, "{body:02x?}");
        }
        Err(Error::Version(v)) => assert_eq!((body[0], body[0] != 4), (*v, true)),
        Err(_) => {}
    }
    got.ok()
}

/// The body of a v4 Ed25519 signature packet with these subpacket areas.
fn sig_body(hashed: &[u8], unhashed: &[u8]) -> Vec<u8> {
    let mut body = vec![4, 0, 27, 8];
    body.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
    body.extend_from_slice(hashed);
    body.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
    body.extend_from_slice(unhashed);
    body.extend_from_slice(&[0xab, 0xcd]);
    body.extend(std::iter::repeat_n(0x11u8, 64));
    body
}

fn sp(kind: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![(value.len() + 1) as u8, kind];
    out.extend_from_slice(value);
    out
}

/// The signature packets of the files of the shell's tests that have them
/// in the clear: keys, and messages that are not compressed.
fn real_signatures() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(FIXTURES).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".gpg") || name.ends_with(".sig") {
            let data = file(&name);
            for p in packets(&data).unwrap() {
                if p.tag == 2 {
                    out.push(p.body.of(&data).to_vec());
                }
            }
        }
    }
    out
}

// Packets.

#[test]
fn every_packet_header_form_gives_these_spans() {
    let span = |off, len| Span { off, len };
    let one = |tag, body, more| Packet { tag, body, more };
    let mut cases: Vec<(Vec<u8>, Vec<Packet>)> = vec![
        // old: one, two, four octets, and none
        (vec![0x88, 2, 7, 8], vec![one(2, span(2, 2), vec![])]),
        (vec![0x89, 0, 1, 7], vec![one(2, span(3, 1), vec![])]),
        (vec![0x8a, 0, 0, 0, 1, 7], vec![one(2, span(5, 1), vec![])]),
        (vec![0x8b, 7, 8, 9], vec![one(2, span(1, 3), vec![])]),
        (vec![0x8b], vec![one(2, span(1, 0), vec![])]),
        (vec![0xbc, 0], vec![one(15, span(2, 0), vec![])]),
        // new: one octet, up to 191; two octets from 192; five octets
        (vec![0xc2, 0], vec![one(2, span(2, 0), vec![])]),
        (vec![0xc2, 1, 7], vec![one(2, span(2, 1), vec![])]),
        (vec![0xff, 1, 7], vec![one(0x3f, span(2, 1), vec![])]),
        (
            vec![0xc2, 191].into_iter().chain([7; 191]).collect(),
            vec![one(2, span(2, 191), vec![])],
        ),
        (
            vec![0xc2, 192, 0].into_iter().chain([7; 192]).collect(),
            vec![one(2, span(3, 192), vec![])],
        ),
        (
            vec![0xc2, 193, 5].into_iter().chain([7; 453]).collect(),
            vec![one(2, span(3, 453), vec![])],
        ),
        (
            vec![0xc2, 223, 255].into_iter().chain([7; 8383]).collect(),
            vec![one(2, span(3, 8383), vec![])],
        ),
        (
            vec![0xc2, 255, 0, 0, 0, 2, 7, 8],
            vec![one(2, span(6, 2), vec![])],
        ),
        // partial: 2, 4, then the end by a length of one octet
        (
            vec![0xc8, 0xe1, 1, 2, 0xe2, 3, 4, 5, 6, 1, 7],
            vec![one(8, span(2, 2), vec![span(5, 4), span(10, 1)])],
        ),
        (
            vec![0xcb, 0xe0, 1, 255, 0, 0, 0, 1, 2],
            vec![one(11, span(2, 1), vec![span(8, 1)])],
        ),
        // two packets, and an empty one
        (
            vec![0x88, 1, 7, 0xc2, 0, 0x88, 0],
            vec![
                one(2, span(2, 1), vec![]),
                one(2, span(5, 0), vec![]),
                one(2, span(7, 0), vec![]),
            ],
        ),
    ];
    cases.push((vec![], vec![]));
    for (data, want) in cases {
        assert_eq!(packets(&data).unwrap(), want, "{data:02x?}");
    }
}

#[test]
fn packets_that_are_refused() {
    for (data, want) in [
        (vec![0x00], Error::NotAPacket),
        (vec![0x7f, 0], Error::NotAPacket),
        (vec![0xc2, 0, 0x00], Error::NotAPacket),
        (vec![0xc2, 0, 0xc2], Error::Truncated),
        (vec![0x88], Error::Truncated),
        (vec![0x88, 2, 1], Error::Truncated),
        (vec![0x89, 0], Error::Truncated),
        (vec![0x8a, 0, 0, 0], Error::Truncated),
        (vec![0x8a, 0xff, 0xff, 0xff, 0xff, 1], Error::Truncated),
        (vec![0xc2], Error::Truncated),
        (vec![0xc2, 1], Error::Truncated),
        (vec![0xc2, 192], Error::Truncated),
        (vec![0xc2, 192, 0], Error::Truncated),
        (vec![0xc2, 255, 0, 0, 0], Error::Truncated),
        (vec![0xc2, 255, 0xff, 0xff, 0xff, 0xff], Error::Truncated),
        // a partial length for what cannot have one, and one that never ends
        (vec![0xc2, 0xe1, 1, 2, 1, 3], Error::PartialLength),
        (vec![0xcb, 0xe0, 1], Error::Truncated),
        (vec![0xcb, 0xe1, 1], Error::Truncated),
        (vec![0xcb, 0xfe, 1], Error::Truncated),
    ] {
        assert_eq!(packets(&data), Err(want), "{data:02x?}");
    }
}

#[test]
fn at_most_max_packets() {
    let mut data: Vec<u8> = std::iter::repeat_n([0xc2, 0], MAX_PACKETS)
        .flatten()
        .collect();
    let got = packets(&data).unwrap();
    assert_eq!(got.len(), MAX_PACKETS);
    check_packets(&data, &got);
    // a byte after them, whatever it is
    for extra in [vec![0xc2, 0], vec![0x00], vec![0xc2]] {
        let mut more = data.clone();
        more.extend(extra);
        assert_eq!(packets(&more), Err(Error::TooManyPackets));
    }
    data.truncate(data.len() - 2);
    assert_eq!(packets(&data).unwrap().len(), MAX_PACKETS - 1);
}

#[test]
fn the_pieces_of_partial_lengths_count_as_packets() {
    // a compressed packet of pieces of one byte, and a last piece
    let pieces = |n: usize| {
        let mut data = vec![0xc8];
        for _ in 0..n - 1 {
            data.extend([0xe0, 7]);
        }
        data.extend([1, 7]);
        data
    };
    let ok = pieces(MAX_PACKETS);
    let got = packets(&ok).unwrap();
    assert_eq!(got[0].more.len(), MAX_PACKETS - 1);
    check_packets(&ok, &got);
    check_packet_bytes(&ok);
    let many = pieces(MAX_PACKETS + 1);
    assert_eq!(packets(&many), Err(Error::TooManyPackets));
    check_packet_bytes(&many);
    // together with the packets before it
    let mut after = vec![0xc2, 0];
    after.extend(pieces(MAX_PACKETS));
    assert_eq!(packets(&after), Err(Error::TooManyPackets));
    check_packet_bytes(&after);
    let mut before = pieces(MAX_PACKETS - 1);
    before.extend([0xc2, 0]);
    assert_eq!(packets(&before).unwrap().len(), 2);
    before.extend([0xc2, 0]);
    assert_eq!(packets(&before), Err(Error::TooManyPackets));
}

#[test]
fn every_short_message_over_the_length_forms() {
    let a = [
        0x40, 0x80, 0x81, 0x82, 0x83, 0xc2, 0xc8, 0xcb, 0x00, 0x01, 0xc0, 0xe1, 0xff, 0x03,
    ];
    assert_eq!(every(&a, 5, &mut check_packet_bytes), how_many(14, 5));
    // partial lengths of a byte, and the end of the data
    let b = [0x83, 0xc8, 0xe0, 0x00, 0x01, 0xff];
    assert_eq!(every(&b, 8, &mut check_packet_bytes), how_many(6, 8));
}

#[test]
fn real_files_cut_and_changed_at_every_byte() {
    for entry in std::fs::read_dir(FIXTURES).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if !(name.ends_with(".gpg") || name.ends_with(".sig")) {
            continue;
        }
        let data = file(&name);
        check_packet_bytes(&data);
        for n in 0..data.len() {
            check_packet_bytes(&data[..n]);
        }
        // every byte becomes each of the values that begin or end a form
        let mut m = data.clone();
        for i in 0..data.len() {
            for v in [
                0, 1, 2, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xdf, 0xe0, 0xfe, 0xff,
            ] {
                m[i] = v;
                check_packet_bytes(&m);
            }
            m[i] = data[i];
        }
    }
}

// The signature packet.

#[test]
fn the_fields_of_a_signature_by_position() {
    let mut hashed = sp(2, &[0, 0, 3, 232]);
    hashed.extend(sp(27, &[2]));
    let unhashed = sp(16, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let body = sig_body(&hashed, &unhashed);
    let sig = signature(&body).unwrap();
    assert_eq!(sig.hashed, Span { off: 6, len: 9 });
    assert_eq!(sig.unhashed, Span { off: 17, len: 10 });
    assert_eq!(sig.left16, [0xab, 0xcd]);
    assert_eq!(sig.values, [Span { off: 29, len: 64 }]);
    assert_eq!(
        (sig.sub.created, sig.sub.key_flags, sig.sub.issuer),
        (Some(1000), Some(2), Some([1, 2, 3, 4, 5, 6, 7, 8]))
    );
    check_signature(&body, &sig);
    // the other algorithms: the bit counts decide
    let mut b = vec![4, 0, 19, 8, 0, 0, 0, 0, 1, 2, 0, 9, 7, 7, 0, 8, 5];
    let sig = signature(&b).unwrap();
    assert_eq!(
        sig.values,
        [Span { off: 12, len: 2 }, Span { off: 16, len: 1 }]
    );
    b[2] = 1;
    assert_eq!(signature(&b).unwrap().values, [Span { off: 12, len: 2 }]);
    for algo in [0, 2, 16, 18, 20, 21, 23, 28, 255] {
        b[2] = algo;
        assert_eq!(signature(&b), Err(Error::Algorithm(algo)));
    }
}

#[test]
fn creation_time_expiry_and_flags_are_of_the_hashed_area_only() {
    let t = |v: u32| v.to_be_bytes();
    let mut area = sp(2, &t(1000));
    area.extend(sp(3, &t(50)));
    area.extend(sp(9, &t(60)));
    area.extend(sp(27, &[0x02]));
    let hashed = signature(&sig_body(&area, b"")).unwrap();
    assert_eq!(
        (
            hashed.sub.created,
            hashed.sub.expires,
            hashed.sub.key_expires,
            hashed.sub.key_flags
        ),
        (Some(1000), Some(50), Some(60), Some(2))
    );
    // the same words in the unhashed area are not said by the signer, and
    // are not even read (sizes of 0 to 9 octets)
    for kind in [2u8, 3, 9, 27] {
        for n in 0..10 {
            for crit in [0, 0x80] {
                let sub = signature(&sig_body(b"", &sp(kind | crit, &vec![9; n])))
                    .unwrap()
                    .sub;
                assert_eq!(sub, Subpackets::default(), "{kind} {n}");
            }
        }
    }
    // what is appended to the unhashed area of a signature changes none
    // of them
    let mut extra = area.clone();
    extra.extend(sp(0x80 | 100, &[1]));
    extra.extend(sp(16, &[7; 8]));
    let both = signature(&sig_body(&area, &extra)).unwrap();
    assert_eq!(
        (
            both.sub.created,
            both.sub.expires,
            both.sub.key_expires,
            both.sub.key_flags
        ),
        (Some(1000), Some(50), Some(60), Some(2))
    );
    // the creation time only in the unhashed area: none
    let only = signature(&sig_body(&sp(3, &t(5)), &sp(2, &t(1000)))).unwrap();
    assert_eq!((only.sub.created, only.sub.expires), (None, Some(5)));
    // the last of a kind counts, and key flags of no byte are flags of 0
    let mut twice = sp(2, &t(1));
    twice.extend(sp(2, &t(2)));
    twice.extend(sp(27, &[2]));
    twice.extend(sp(27, &[]));
    let sub = signature(&sig_body(&twice, b"")).unwrap().sub;
    assert_eq!((sub.created, sub.key_flags), (Some(2), Some(0)));
}

#[test]
fn every_kind_with_and_without_the_critical_bit_in_each_area() {
    let direct = [2u8, 3, 9, 16, 27, 32, 33];
    for kind in 0..=127u8 {
        for crit in [0u8, 0x80] {
            for n in 0..10 {
                let one = sp(kind | crit, &vec![0xaa; n]);
                // the hashed area
                let want = if matches!(kind, 2 | 3 | 9) && n != 4 {
                    Err(Error::BadTime)
                } else if crit != 0 && !direct.contains(&kind) && !KNOWN.contains(&kind) {
                    Err(Error::UnknownCritical(kind))
                } else {
                    Ok(())
                };
                let got = read_subpackets(&one, true);
                assert_eq!(
                    got.as_ref().map(|_| ()).map_err(|e| *e),
                    want,
                    "{kind} {crit} {n}"
                );
                assert_eq!(got, {
                    let mut s = empty();
                    oracle_subpackets(&one, true, &mut s).map(|_| s)
                });
                // the unhashed area refuses nothing and says nothing of
                // time and flags
                let got = read_subpackets(&one, false).unwrap();
                assert_eq!(
                    (got.created, got.expires, got.key_expires, got.key_flags),
                    (None, None, None, None)
                );
            }
        }
    }
}

#[test]
fn subpacket_lengths_of_every_form() {
    let mut long = vec![192, 0, 26];
    long.extend([0u8; 191]);
    assert!(read_subpackets(&long, false).is_ok());
    long[1] = 1;
    assert_eq!(read_subpackets(&long, false), Err(Error::Truncated));
    long.extend([0u8; 1]);
    assert!(read_subpackets(&long, false).is_ok());
    assert!(read_subpackets(&[255, 0, 0, 0, 2, 26, 0], false).is_ok());
    assert_eq!(
        read_subpackets(&[255, 0, 0, 0, 3, 26, 0], false),
        Err(Error::Truncated)
    );
    assert_eq!(
        read_subpackets(&[255, 0, 0, 0], false),
        Err(Error::Truncated)
    );
    assert_eq!(read_subpackets(&[192], false), Err(Error::Truncated));
    assert_eq!(read_subpackets(&[254], false), Err(Error::Truncated));
    assert_eq!(read_subpackets(&[0], false), Err(Error::EmptySubpacket));
    assert_eq!(
        read_subpackets(&[255, 0, 0, 0, 0], false),
        Err(Error::EmptySubpacket)
    );
    assert_eq!(read_subpackets(&[2, 26], false), Err(Error::Truncated));
    assert_eq!(
        read_subpackets(&[1, 26, 0], false),
        Err(Error::EmptySubpacket)
    );
    // a subpacket ends with its area, not with the packet
    let body = sig_body(&[1, 26], b"");
    assert!(signature(&body).is_ok());
    let mut lie = body.clone();
    lie[5] = 1;
    assert_eq!(signature(&lie), Err(Error::Truncated));
}

#[test]
fn every_short_area_of_subpackets() {
    let a = [0x00, 0x01, 0x02, 0x05, 0x82, 0x88, 0x1b, 0x21, 0xff];
    let b = [0x01, 0x02, 0x03, 0x09, 0x10, 0x20, 0x83, 0x89, 0x90, 0xc0];
    for alphabet in [&a[..], &b[..]] {
        let seen = every(alphabet, 6, &mut |area| {
            for hashed in [true, false] {
                let mut want = empty();
                let want = oracle_subpackets(area, hashed, &mut want).map(|_| want);
                assert_eq!(read_subpackets(area, hashed), want, "{area:02x?} {hashed}");
            }
        });
        assert_eq!(seen, how_many(alphabet.len(), 6));
    }
}

#[test]
fn every_short_signature_body() {
    // the header, then everything of the areas and values that the
    // alphabet can say, of an RSA signature (one value) and an ECDSA one
    // (two)
    let alphabet = [0, 1, 2, 9];
    let mut seen = 0;
    for algo in [1, 19] {
        let all = every(&alphabet, 10, &mut |tail| {
            let mut body = vec![4, 0, algo, 8];
            body.extend_from_slice(tail);
            seen += usize::from(check_signature_bytes(&body).is_some());
        });
        assert_eq!(all, how_many(4, 10));
    }
    assert!(seen > 100);
}

#[test]
fn real_signatures_cut_and_changed_at_every_byte() {
    let all = real_signatures();
    assert!(all.len() > 10);
    for body in all {
        let sig = check_signature_bytes(&body).expect("a real signature");
        // the signed part of the data: the hashed fields do not move when
        // anything of the unhashed area is changed or the area is replaced
        let hashed_says = (
            sig.sub.created,
            sig.sub.expires,
            sig.sub.key_expires,
            sig.sub.key_flags,
        );
        for n in 0..body.len() {
            assert!(signature(&body[..n]).is_err(), "cut at {n}");
        }
        let mut m = body.clone();
        for i in 0..body.len() {
            for v in 0..=255u8 {
                m[i] = v;
                let got = check_signature_bytes(&m);
                let in_unhashed = i >= sig.unhashed.off && i < sig.unhashed.end();
                if let (true, Some(got)) = (in_unhashed, got) {
                    let says = (
                        got.sub.created,
                        got.sub.expires,
                        got.sub.key_expires,
                        got.sub.key_flags,
                    );
                    assert_eq!(says, hashed_says, "byte {i} to {v}");
                }
            }
            m[i] = body[i];
        }
    }
}

#[test]
fn seeded_signatures_of_random_areas() {
    let kinds = [2u8, 3, 9, 16, 27, 32, 33, 4, 5, 20, 26, 100, 0, 1];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut refused = 0;
    for _ in 0..60_000 {
        let area = |rng: &mut Rng| {
            let mut out = Vec::new();
            for _ in 0..rng.below(5) {
                let kind = rng.byte_of(&kinds) | if rng.below(3) == 0 { 0x80 } else { 0 };
                let n = [0, 1, 4, 4, 4, 8, 9, 21][rng.below(8)];
                let value: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                out.extend(sp(kind, &value));
            }
            if rng.below(8) == 0 && !out.is_empty() {
                let at = rng.below(out.len());
                out[at] = rng.next() as u8;
            }
            out
        };
        let hashed = area(&mut rng);
        let unhashed = area(&mut rng);
        let body = sig_body(&hashed, &unhashed);
        let Some(sig) = check_signature_bytes(&body) else {
            refused += 1;
            continue;
        };
        // appending to the unhashed area, or replacing it with anything
        // that is read, moves none of the signer's words
        let bare = signature(&sig_body(&hashed, b"")).unwrap();
        assert_eq!(
            (
                sig.sub.created,
                sig.sub.expires,
                sig.sub.key_expires,
                sig.sub.key_flags
            ),
            (
                bare.sub.created,
                bare.sub.expires,
                bare.sub.key_expires,
                bare.sub.key_flags
            ),
            "{hashed:02x?} {unhashed:02x?}"
        );
    }
    assert!(refused > 1000 && refused < 59_000, "{refused}");
}

// DER.

/// What the shell read before: the tag, the content and the rest of the
/// element of `data`, as slices.
fn oracle_der(data: &[u8]) -> Result<(u8, &[u8], &[u8]), DerError> {
    let (&tag, rest) = data.split_first().ok_or(DerError::Truncated)?;
    let (&l, rest) = rest.split_first().ok_or(DerError::Truncated)?;
    let (len, rest) = if l < 0x80 {
        (usize::from(l), rest)
    } else {
        let n = usize::from(l & 0x7f);
        if n == 0 {
            return Err(DerError::Indefinite);
        }
        if n > 4 {
            return Err(DerError::TooLong);
        }
        if rest.len() < n {
            return Err(DerError::Truncated);
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |a, b| (a << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    if rest.len() < len {
        return Err(DerError::Truncated);
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn oracle_items(data: &[u8]) -> Result<Vec<&[u8]>, DerError> {
    let (tag, mut content, _) = oracle_der(data)?;
    if tag != 0x30 {
        return Err(DerError::NotSequence);
    }
    let mut out = Vec::new();
    while !content.is_empty() {
        let (_, item, rest) = oracle_der(content)?;
        out.push(item);
        content = rest;
    }
    Ok(out)
}

fn check_der(data: &[u8]) {
    let got = der::element(data);
    let want = oracle_der(data);
    match (&got, &want) {
        (Ok((tag, span)), Ok((wtag, content, rest))) => {
            assert_eq!(tag, wtag, "{data:02x?}");
            assert!(span.off >= 2 && span.end() <= data.len(), "{data:02x?}");
            assert_eq!(span.of(data), *content, "{data:02x?}");
            assert_eq!(&data[span.end()..], *rest, "{data:02x?}");
        }
        (Err(g), Err(w)) => assert_eq!(g, w, "{data:02x?}"),
        _ => panic!("{data:02x?}: {got:?} against {want:?}"),
    }
    let got = der::sequence_items(data);
    let want = oracle_items(data);
    match (&got, &want) {
        (Ok(items), Ok(want)) => {
            let (_, content) = der::element(data).unwrap();
            let mut after = content.off;
            let mut sum = 0;
            for item in items {
                // in order, after a header of 2 bytes at least, inside the sequence
                assert!(
                    item.off >= after + 2 && item.end() <= content.end(),
                    "{data:02x?}"
                );
                after = item.end();
                sum += item.len;
            }
            // the sequence is filled exactly
            assert!(items.is_empty() && content.len == 0 || after == content.end());
            assert!(sum <= content.len);
            let got: Vec<&[u8]> = items.iter().map(|s| s.of(data)).collect();
            assert_eq!(&got, want);
        }
        (Err(g), Err(w)) => assert_eq!(g, w, "{data:02x?}"),
        _ => panic!("{data:02x?}: {got:?} against {want:?}"),
    }
}

#[test]
fn der_lengths_of_every_form() {
    let span = |off, len| Span { off, len };
    let mut long = vec![4, 127];
    long.extend([1u8; 127]);
    for (data, want) in [
        (vec![4, 2, 7, 8, 9], (4, span(2, 2))),
        (vec![4, 0], (4, span(2, 0))),
        (long, (4, span(2, 127))),
        (vec![4, 0x81, 2, 7, 8], (4, span(3, 2))),
        (vec![4, 0x82, 0, 2, 7, 8], (4, span(4, 2))),
        (vec![4, 0x83, 0, 0, 2, 7, 8], (4, span(5, 2))),
        (vec![4, 0x84, 0, 0, 0, 2, 7, 8], (4, span(6, 2))),
        (vec![4, 0x81, 0], (4, span(3, 0))),
        (vec![0x1f, 1, 7], (0x1f, span(2, 1))),
    ] {
        assert_eq!(der::element(&data), Ok(want), "{data:02x?}");
    }
    let mut d = vec![4, 0x81, 200];
    d.extend([1u8; 200]);
    assert_eq!(der::element(&d), Ok((4, span(3, 200))));
    let mut d = vec![4, 0x82, 1, 0];
    d.extend([1u8; 256]);
    assert_eq!(der::element(&d), Ok((4, span(4, 256))));
    d.pop();
    assert_eq!(der::element(&d), Err(DerError::Truncated));
}

#[test]
fn der_that_is_refused() {
    for (data, want) in [
        (vec![], DerError::Truncated),
        (vec![4], DerError::Truncated),
        (vec![0x30, 0x80, 4, 1, 7, 0, 0], DerError::Indefinite),
        (vec![4, 0x85, 0, 0, 0, 0, 1, 7], DerError::TooLong),
        (vec![4, 0xff, 1], DerError::TooLong),
        (vec![4, 0x81], DerError::Truncated),
        (vec![4, 0x84, 0, 0, 1], DerError::Truncated),
        (vec![4, 1], DerError::Truncated),
        (vec![4, 2, 7], DerError::Truncated),
        (
            vec![4, 0x84, 0xff, 0xff, 0xff, 0xff, 1],
            DerError::Truncated,
        ),
    ] {
        assert_eq!(der::element(&data), Err(want), "{data:02x?}");
    }
}

#[test]
fn der_sequences_are_read_as_what_fills_them() {
    let span = |off, len| Span { off, len };
    let seq = [0x30, 9, 6, 2, 1, 2, 4, 1, 9, 5, 0];
    assert_eq!(
        der::sequence_items(&seq),
        Ok(vec![span(4, 2), span(8, 1), span(11, 0)])
    );
    assert_eq!(der::sequence_items(&[0x30, 0]), Ok(vec![]));
    // what follows the sequence is not looked at
    assert_eq!(
        der::sequence_items(&[0x30, 2, 4, 0, 0xff, 0xff]),
        Ok(vec![span(4, 0)])
    );
    // an item that runs past the sequence
    assert_eq!(
        der::sequence_items(&[0x30, 2, 4, 3, 1, 2, 3]),
        Err(DerError::Truncated)
    );
    assert_eq!(
        der::sequence_items(&[0x30, 3, 4, 0x80, 0]),
        Err(DerError::Indefinite)
    );
    assert_eq!(der::sequence_items(&[0x31, 0]), Err(DerError::NotSequence));
    assert_eq!(
        der::sequence_items(&[0x30, 4, 4, 0]),
        Err(DerError::Truncated)
    );
}

#[test]
fn every_short_der() {
    let a = [
        0x30, 0x04, 0x00, 0x01, 0x02, 0x7f, 0x80, 0x81, 0x82, 0x84, 0x85, 0xff,
    ];
    assert_eq!(every(&a, 5, &mut check_der), how_many(12, 5));
}

#[test]
fn der_of_a_real_certificate_cut_and_changed_at_every_byte() {
    // an extension of a certificate: a sequence of an OID and a value
    let mut data = vec![0x30, 0x82, 0x01, 0x04];
    data.extend([
        0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x04, 0x30, 0x02, 0x04, 0x00,
    ]);
    data.extend([0x04; 243]);
    check_der(&data);
    for n in 0..data.len() {
        check_der(&data[..n]);
    }
    let mut m = data.clone();
    for i in 0..data.len() {
        for v in 0..=255u8 {
            m[i] = v;
            check_der(&m);
        }
        m[i] = data[i];
    }
}
