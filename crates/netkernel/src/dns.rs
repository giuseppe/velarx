// SPDX-License-Identifier: Apache-2.0
//! DNS messages for the container names of a network (RFC 1035).  The queries come from the containers: every length is
//! checked, nothing is trusted.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The domain of the container names.
pub const DOMAIN: &str = "dns.podman";
pub const TTL: u32 = 60;
pub const UDP_SIZE: usize = 512;

const HEADER: usize = 12;
const MAX_NAME: usize = 255;
pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const RCODE_FORMERR: u16 = 1;
pub const RCODE_SERVFAIL: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;
const RCODE_NOTIMP: u16 = 4;

/// The names and addresses of a container on a network.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Record {
    /// Lower case, without trailing dot.
    pub names: Vec<String>,
    pub ips: Vec<Ipv4Addr>,
    /// On a dual-stack network.
    #[serde(default)]
    pub ips6: Vec<Ipv6Addr>,
}

pub type Zone = [Record];

/// What to do with a query.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// Malformed or not a query: no reply.
    Drop,
    /// The reply.
    Reply(Vec<u8>),
    /// Not a local name: forward the query.
    Forward,
}

fn get16(m: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(m.get(at..at + 2)?.try_into().ok()?))
}

/// The question name at OFF as lower case dotted text ("" for the root) and
/// the offset after it.  Compression pointers are refused: a question has
/// none.
fn parse_name(m: &[u8], mut off: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    loop {
        let l = usize::from(*m.get(off)?);
        off += 1;
        if l == 0 {
            break;
        }
        if l > 63 || name.len() + l + 1 > MAX_NAME {
            return None;
        }
        let label = m.get(off..off + l)?;
        // A dot or a NUL inside a label cannot be looked up.
        if label.iter().any(|c| *c == b'.' || *c == 0) {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|c| char::from(c.to_ascii_lowercase())));
        off += l;
    }
    Some((name, off))
}

/// Every record that has the name: containers that share an alias answer
/// all their addresses.
fn find_name<'a>(zone: &'a Zone, name: &str) -> Vec<&'a Record> {
    zone.iter()
        .filter(|r| r.names.iter().any(|n| n == name))
        .collect()
}

fn find_ip(zone: &Zone, ip: Ipv4Addr) -> Option<&Record> {
    zone.iter().find(|r| r.ips.contains(&ip))
}

/// `D.C.B.A.in-addr.arpa` to A.B.C.D.
pub fn parse_reverse(name: &str) -> Option<Ipv4Addr> {
    let rest = name.strip_suffix(".in-addr.arpa")?;
    let parts: Vec<&str> = rest.split('.').collect();
    let [d, c, b, a] = parts.as_slice() else {
        return None;
    };
    let octet = |s: &str| -> Option<u8> {
        if s.is_empty() || s.len() > 3 || !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    Some(Ipv4Addr::new(octet(a)?, octet(b)?, octet(c)?, octet(d)?))
}

/// NAME (dotted, may be "") in wire format; None if a label is invalid.
fn encode_name(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(name.len() + 2);
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    (out.len() <= MAX_NAME + 1).then_some(out)
}

fn header_only(m: &[u8], flags: u16) -> Vec<u8> {
    let mut out = vec![0u8; HEADER];
    out[..2].copy_from_slice(&m[..2]);
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out
}

/// The question of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// Lower case, without trailing dot.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// The offset after the question.
    pub end: usize,
}

/// The one question of the query MSG; None for a response, or a message
/// that does not carry exactly one question.
pub fn question(msg: &[u8]) -> Option<Question> {
    if msg.len() < HEADER || get16(msg, 2)? & FLAG_QR != 0 || get16(msg, 4) != Some(1) {
        return None;
    }
    let (name, at) = parse_name(msg, HEADER)?;
    Some(Question {
        name,
        qtype: get16(msg, at)?,
        qclass: get16(msg, at + 2)?,
        end: at + 4,
    })
}

/// The head of a reply to MSG, whose question is Q: its ID and question, no
/// records, the code RCODE.
pub fn head(msg: &[u8], q: &Question, rcode: u16) -> Vec<u8> {
    let mut out = msg[..q.end].to_vec();
    out[6..12].fill(0);
    let rd = get16(msg, 2).unwrap_or(0) & FLAG_RD;
    out[2..4].copy_from_slice(&(FLAG_QR | FLAG_RA | rd | rcode).to_be_bytes());
    out
}

/// Answer the query MSG from ZONE in at most OUT_SIZE bytes (truncated with
/// TC beyond).
pub fn answer(zone: &Zone, msg: &[u8], out_size: usize) -> Answer {
    if msg.len() < HEADER || out_size < HEADER {
        return Answer::Drop;
    }
    let Some(flags) = get16(msg, 2) else {
        return Answer::Drop;
    };
    if flags & FLAG_QR != 0 {
        return Answer::Drop;
    }
    let mut rflags = FLAG_QR | FLAG_RA | (flags & FLAG_RD);
    let one_question =
        get16(msg, 4) == Some(1) && get16(msg, 6) == Some(0) && get16(msg, 8) == Some(0);
    let question = parse_name(msg, HEADER).filter(|(_, end)| end + 4 <= msg.len());
    let (Some((mut name, qend)), true) = (question, one_question) else {
        return Answer::Reply(header_only(msg, rflags | RCODE_FORMERR));
    };
    if (flags >> 11) & 0xf != 0 {
        return Answer::Reply(header_only(msg, rflags | RCODE_NOTIMP));
    }
    let (Some(qtype), Some(qclass)) = (get16(msg, qend), get16(msg, qend + 2)) else {
        return Answer::Reply(header_only(msg, rflags | RCODE_FORMERR));
    };
    let qend = qend + 4;
    if qclass != CLASS_IN {
        return Answer::Forward;
    }

    let local = match name.strip_suffix(DOMAIN) {
        Some(n) if n.ends_with('.') && n.len() > 1 => Some(n.len() - 1),
        _ => None,
    };
    if let Some(len) = local {
        name.truncate(len);
    }
    let local_only = local.is_some();
    let mut ptr = false;
    let recs = match (qtype, local_only, parse_reverse(&name)) {
        (TYPE_PTR, false, Some(ip)) => {
            ptr = true;
            match find_ip(zone, ip) {
                Some(r) => vec![r],
                None => return Answer::Forward,
            }
        }
        _ => {
            let r = if name.is_empty() {
                Vec::new()
            } else {
                find_name(zone, &name)
            };
            if r.is_empty() && !local_only {
                return Answer::Forward;
            }
            r
        }
    };

    if qend > out_size {
        return Answer::Drop;
    }
    let mut out = msg[..qend].to_vec();
    out[6..12].fill(0);
    rflags |= FLAG_AA;
    let mut ancount: u16 = 0;
    match recs.as_slice() {
        [] => rflags |= RCODE_NXDOMAIN,
        recs if ptr => {
            for n in recs.iter().flat_map(|r| &r.names) {
                let Some(data) = encode_name(n) else {
                    continue;
                };
                if out.len() + 12 + data.len() > out_size {
                    rflags |= FLAG_TC;
                    break;
                }
                push_rr(&mut out, TYPE_PTR, &data);
                ancount += 1;
            }
        }
        recs if qtype == TYPE_A || qtype == TYPE_AAAA || qtype == TYPE_ANY => {
            let a = recs
                .iter()
                .flat_map(|r| &r.ips)
                .map(|ip| (TYPE_A, ip.octets().to_vec()));
            let aaaa = recs
                .iter()
                .flat_map(|r| &r.ips6)
                .map(|ip| (TYPE_AAAA, ip.octets().to_vec()));
            for (ty, data) in a.chain(aaaa) {
                if qtype != TYPE_ANY && qtype != ty {
                    continue;
                }
                if out.len() + 12 + data.len() > out_size {
                    rflags |= FLAG_TC;
                    break;
                }
                push_rr(&mut out, ty, &data);
                ancount += 1;
            }
        }
        // A known name without records of this type: an empty answer.
        _ => {}
    }
    out[2..4].copy_from_slice(&rflags.to_be_bytes());
    out[6..8].copy_from_slice(&ancount.to_be_bytes());
    Answer::Reply(out)
}

/// A resource record for the question name (a pointer to offset 12).
fn push_rr(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
    out.extend_from_slice(&(0xc000u16 | HEADER as u16).to_be_bytes());
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&TTL.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// A SERVFAIL reply to MSG (the forwarding failed); None if it is too short.
pub fn servfail(msg: &[u8]) -> Option<Vec<u8>> {
    let flags = get16(msg, 2)?;
    (msg.len() >= HEADER)
        .then(|| header_only(msg, FLAG_QR | FLAG_RA | (flags & FLAG_RD) | RCODE_SERVFAIL))
}

#[cfg(test)]
pub(crate) fn make_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    if !name.is_empty() {
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Vec<Record> {
        vec![Record {
            names: vec!["web".into(), "www".into()],
            ips: vec![Ipv4Addr::new(10, 88, 7, 5)],
            ips6: Vec::new(),
        }]
    }

    fn reply(a: Answer) -> Vec<u8> {
        match a {
            Answer::Reply(r) => r,
            other => panic!("not a reply: {other:?}"),
        }
    }

    #[test]
    fn the_question_is_read_and_a_reply_head_made() {
        let q = make_query("WEB.Example", 28);
        let question = question(&q).unwrap();
        assert_eq!(
            (
                question.name.as_str(),
                question.qtype,
                question.qclass,
                question.end
            ),
            ("web.example", 28, 1, q.len())
        );
        let h = head(&q, &question, RCODE_SERVFAIL);
        assert_eq!(&h[..2], &q[..2]);
        assert_eq!(
            (h[2] & 0x81, h[3] & 0x8f, &h[4..12]),
            (0x81, 0x82, &[0, 1, 0, 0, 0, 0, 0, 0][..])
        );
        assert_eq!(&h[12..], &q[12..]);
        // a response, two questions, a cut question: none
        let mut r = q.clone();
        r[2] |= 0x80;
        assert_eq!(super::question(&r), None);
        let mut two = q.clone();
        two[5] = 2;
        assert_eq!(super::question(&two), None);
        assert_eq!(super::question(&q[..q.len() - 1]), None);
    }

    #[test]
    fn answers() {
        let z = zone();
        let r = reply(answer(&z, &make_query("WEB", 1), 512));
        assert_eq!(&r[..2], &[0x12, 0x34]);
        assert!(r[2] & 0x80 != 0 && r[3] & 0x0f == 0);
        assert_eq!(r[7], 1);
        assert_eq!(&r[r.len() - 4..], &[10, 88, 7, 5]);

        let r = reply(answer(&z, &make_query("www.dns.podman", 1), 512));
        assert_eq!(r[7], 1);

        let r = reply(answer(&z, &make_query("web", 28), 512));
        assert_eq!((r[7], r[3] & 0x0f), (0, 0));

        let mut z6 = zone();
        z6[0].ips6.push("fd00:7::5".parse().unwrap());
        let r = reply(answer(&z6, &make_query("web", 28), 512));
        assert_eq!(r[7], 1);
        assert_eq!(
            &r[r.len() - 16..],
            &"fd00:7::5".parse::<Ipv6Addr>().unwrap().octets()
        );
        let r = reply(answer(&z6, &make_query("web", 1), 512));
        assert_eq!((r[7], &r[r.len() - 4..]), (1, &[10, 88, 7, 5][..]));
        let r = reply(answer(&z6, &make_query("web", 255), 512));
        assert_eq!(r[7], 2);

        assert_eq!(
            answer(&z, &make_query("example.com", 1), 512),
            Answer::Forward
        );
        assert_eq!(
            answer(&z, &make_query("dns.podman", 1), 512),
            Answer::Forward
        );
        let r = reply(answer(&z, &make_query("nosuch.dns.podman", 1), 512));
        assert_eq!(r[3] & 0x0f, 3);

        let r = reply(answer(&z, &make_query("5.7.88.10.in-addr.arpa", 12), 512));
        assert_eq!(r[7], 2);
        assert_eq!(
            answer(&z, &make_query("6.7.88.10.in-addr.arpa", 12), 512),
            Answer::Forward
        );
        let mut q = make_query("x", 1);
        let last = q.len() - 1;
        q[last] = 3;
        assert_eq!(answer(&z, &q, 512), Answer::Forward);
    }

    #[test]
    fn a_name_of_several_containers_answers_all_their_addresses() {
        let mut z = zone();
        z.push(Record {
            names: vec!["web".into()],
            ips: vec![Ipv4Addr::new(10, 88, 7, 6)],
            ips6: Vec::new(),
        });
        let r = reply(answer(&z, &make_query("web", 1), 512));
        assert_eq!(r[7], 2);
        let tail = &r[r.len() - 4..];
        assert_eq!(tail, &[10, 88, 7, 6]);
        // (a name of one of them only has one)
        let r = reply(answer(&z, &make_query("www", 1), 512));
        assert_eq!(r[7], 1);
    }

    #[test]
    fn truncated_and_malformed() {
        let z = zone();
        let q = make_query("web", 1);
        let r = reply(answer(&z, &q, q.len() + 4));
        assert!(r[2] & 0x02 != 0 && r[7] == 0);

        assert_eq!(answer(&z, &q[..5], 512), Answer::Drop);
        let mut bad = q.clone();
        bad[12] = 0xc0;
        assert_eq!(reply(answer(&z, &bad, 512))[3] & 0x0f, 1);
        let mut bad = q.clone();
        bad[2] |= 0x80;
        assert_eq!(answer(&z, &bad, 512), Answer::Drop);
        assert_eq!(reply(answer(&z, &q[..q.len() - 2], 512))[3] & 0x0f, 1);
        let mut bad = q.clone();
        bad[2] |= 0x10;
        assert_eq!(reply(answer(&z, &bad, 512))[3] & 0x0f, 4);
        let mut bad = q.clone();
        bad[13] = b'.';
        assert_eq!(reply(answer(&z, &bad, 512))[3] & 0x0f, 1);

        let s = servfail(&q).unwrap();
        assert_eq!((s.len(), s[3] & 0x0f), (12, 2));
        assert!(servfail(&q[..3]).is_none());
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            parse_reverse("4.3.2.1.in-addr.arpa"),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
        for bad in [
            "256.3.2.1.in-addr.arpa",
            "3.2.1.in-addr.arpa",
            "+4.3.2.1.in-addr.arpa",
            "4.3.2.1.in-addr.arpa.x",
        ] {
            assert!(parse_reverse(bad).is_none(), "{bad}");
        }
    }

    /// Random and mutated queries: no panic, replies within bounds.
    #[test]
    fn fuzz_queries() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5ea);
        let z = zone();
        let seeds = [
            make_query("web", 1),
            make_query("www.dns.podman", 255),
            make_query("5.7.88.10.in-addr.arpa", 12),
            make_query("", 1),
        ];
        for i in 0..200_000 {
            let mut q = if i % 4 == 0 {
                let n = rng.gen_range(0..80);
                (0..n).map(|_| rng.gen()).collect::<Vec<u8>>()
            } else {
                seeds[i % seeds.len()].clone()
            };
            for _ in 0..rng.gen_range(0..4) {
                if q.is_empty() {
                    break;
                }
                let at = rng.gen_range(0..q.len());
                match rng.gen_range(0..3) {
                    0 => q[at] = rng.gen(),
                    1 => q.truncate(at),
                    _ => q.insert(at, rng.gen()),
                }
            }
            let size = rng.gen_range(0..600);
            if let Answer::Reply(r) = answer(&z, &q, size) {
                assert!(r.len() <= size.max(HEADER), "{q:?}");
                assert!(r.len() >= HEADER);
            }
        }
    }
}
