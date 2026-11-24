// SPDX-License-Identifier: Apache-2.0
//! DNS messages for the container names of a network (RFC 1035).  The queries come from the containers: every length is
//! checked, nothing is trusted.

use std::net::{Ipv4Addr, Ipv6Addr};

use velarx_dns_core::{self as wire, Parsed, Rr, HEADER};
pub use wire::{CLASS_IN, RCODE_SERVFAIL, TTL, TYPE_A, TYPE_AAAA, TYPE_PTR};

/// The domain of the container names.
pub const DOMAIN: &str = "dns.podman";
pub const UDP_SIZE: usize = 512;

const TYPE_ANY: u16 = 255;

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

/// The question name as the text the zone is searched with.
fn text(name: &[u8]) -> String {
    name.iter().map(|c| char::from(*c)).collect()
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
    let q = wire::question(msg)?;
    Some(Question {
        name: text(&q.name),
        qtype: q.qtype,
        qclass: q.qclass,
        end: q.end,
    })
}

/// The head of a reply to the query MSG: its ID and question, no records,
/// the code RCODE.
pub fn head(msg: &[u8], rcode: u16) -> Option<Vec<u8>> {
    wire::reply(msg, rcode, false, usize::MAX, &[])
}

/// Answer the query MSG from ZONE in at most OUT_SIZE bytes (truncated with
/// TC beyond).
pub fn answer(zone: &Zone, msg: &[u8], out_size: usize) -> Answer {
    if out_size < HEADER {
        return Answer::Drop;
    }
    let q = match wire::parse(msg) {
        Parsed::Drop => return Answer::Drop,
        Parsed::Refuse(rcode) => return Answer::Reply(wire::error_reply(msg, rcode)),
        Parsed::Query(q) => q,
    };
    if q.qclass != CLASS_IN {
        return Answer::Forward;
    }
    let mut name = text(&q.name);
    let local = match name.strip_suffix(DOMAIN) {
        Some(n) if n.ends_with('.') && n.len() > 1 => Some(n.len() - 1),
        _ => None,
    };
    if let Some(len) = local {
        name.truncate(len);
    }
    let local_only = local.is_some();
    let mut ptr = false;
    let recs = match (q.qtype, local_only, parse_reverse(&name)) {
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

    let mut rrs = Vec::new();
    if ptr {
        for n in recs.iter().flat_map(|r| &r.names) {
            if let Some(data) = wire::encode_name(n.as_bytes()) {
                rrs.push(Rr { ty: TYPE_PTR, data });
            }
        }
    } else if q.qtype == TYPE_A || q.qtype == TYPE_ANY {
        for ip in recs.iter().flat_map(|r| &r.ips) {
            rrs.push(Rr {
                ty: TYPE_A,
                data: ip.octets().to_vec(),
            });
        }
    }
    if !ptr && (q.qtype == TYPE_AAAA || q.qtype == TYPE_ANY) {
        for ip in recs.iter().flat_map(|r| &r.ips6) {
            rrs.push(Rr {
                ty: TYPE_AAAA,
                data: ip.octets().to_vec(),
            });
        }
    }
    let rcode = if recs.is_empty() {
        wire::RCODE_NXDOMAIN
    } else {
        0
    };
    wire::reply(msg, rcode, true, out_size, &rrs).map_or(Answer::Drop, Answer::Reply)
}

/// A SERVFAIL reply to MSG (the forwarding failed); None if it is too short.
pub fn servfail(msg: &[u8]) -> Option<Vec<u8>> {
    (msg.len() >= HEADER).then(|| wire::error_reply(msg, RCODE_SERVFAIL))
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
        let h = head(&q, RCODE_SERVFAIL).unwrap();
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

    /// Bytes from a string of hex pairs.
    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    /// A reply is `Answer::Reply(hex)`.
    fn reply_of(s: &str) -> Answer {
        Answer::Reply(hex(s))
    }

    /// The packets of the containers, byte for byte: what the server does
    /// with each, malformed ones included.  The header is the ID 0x1234,
    /// the flags, and the four counts; the name "web" is `03 77 65 62 00`.
    #[test]
    fn packets_in_and_out() {
        let mut z = zone();
        z[0].ips6.push("fd00:7::5".parse().unwrap());
        let web = "03 77 65 62 00";
        let a_in = "00 01 00 01";
        let hdr = "12 34 01 00 00 01 00 00 00 00 00 00";
        let q = |h: &str, name: &str, tail: &str| hex(&format!("{h} {name} {tail}"));
        let ok = |name: &str, tail: &str| q(hdr, name, tail);

        // an A query: the question is echoed, one record that points at it
        assert_eq!(
            answer(&z, &ok(web, a_in), 512),
            reply_of(
                "12 34 85 80 00 01 00 01 00 00 00 00 03 77 65 62 00 00 01 00 01 \
                 c0 0c 00 01 00 01 00 00 00 3c 00 04 0a 58 07 05"
            )
        );
        // (the case of the name is the client's, the lookup is not)
        assert_eq!(
            answer(&z, &ok("03 57 45 62 00", a_in), 512),
            reply_of(
                "12 34 85 80 00 01 00 01 00 00 00 00 03 57 45 62 00 00 01 00 01 \
                 c0 0c 00 01 00 01 00 00 00 3c 00 04 0a 58 07 05"
            )
        );
        // AAAA
        assert_eq!(
            answer(&z, &ok(web, "00 1c 00 01"), 512),
            reply_of(
                "12 34 85 80 00 01 00 01 00 00 00 00 03 77 65 62 00 00 1c 00 01 \
                 c0 0c 00 1c 00 01 00 00 00 3c 00 10 fd 00 00 07 00 00 00 00 00 00 00 00 00 00 00 05"
            )
        );
        // ANY: the A record, then the AAAA
        assert_eq!(
            answer(&z, &ok(web, "00 ff 00 01"), 512),
            reply_of(
                "12 34 85 80 00 01 00 02 00 00 00 00 03 77 65 62 00 00 ff 00 01 \
                 c0 0c 00 01 00 01 00 00 00 3c 00 04 0a 58 07 05 \
                 c0 0c 00 1c 00 01 00 00 00 3c 00 10 fd 00 00 07 00 00 00 00 00 00 00 00 00 00 00 05"
            )
        );
        // a type the name has no record of: an answer without records
        assert_eq!(
            answer(&z, &ok(web, "00 10 00 01"), 512),
            reply_of("12 34 85 80 00 01 00 00 00 00 00 00 03 77 65 62 00 00 10 00 01")
        );
        // a name of the domain that no container has: NXDOMAIN, authoritative
        assert_eq!(
            answer(&z, &ok("02 6e 6f 03 64 6e 73 06 70 6f 64 6d 61 6e 00", a_in), 512),
            reply_of(
                "12 34 85 83 00 01 00 00 00 00 00 00 02 6e 6f 03 64 6e 73 06 70 6f 64 6d 61 6e 00 00 01 00 01"
            )
        );
        // a name that is not the domain's or a container's, the other class,
        // the root, and the domain itself: forwarded
        for forwarded in [
            ok("03 63 6f 6d 00", a_in),
            ok(web, "00 01 00 03"),
            ok("00", a_in),
            ok("03 64 6e 73 06 70 6f 64 6d 61 6e 00", a_in),
        ] {
            assert_eq!(
                answer(&z, &forwarded, 512),
                Answer::Forward,
                "{forwarded:?}"
            );
        }
        // a dot inside a label is not a name
        assert_eq!(
            answer(&z, &ok("0a 64 6e 73 2e 70 6f 64 6d 61 6e 00", a_in), 512),
            reply_of("12 34 81 81 00 00 00 00 00 00 00 00")
        );
        // RD is the client's; the other flags are not echoed
        let mut query = ok(web, a_in);
        query[2..4].copy_from_slice(&[0x00, 0x70]);
        let Answer::Reply(r) = answer(&z, &query, 512) else {
            panic!()
        };
        assert_eq!(&r[2..4], &[0x84, 0x80]);

        // a PTR query: the names of the container
        let ptr = "01 35 01 37 02 38 38 02 31 30 07 69 6e 2d 61 64 64 72 04 61 72 70 61 00";
        let r = answer(&z, &ok(ptr, "00 0c 00 01"), 512);
        let Answer::Reply(r) = r else { panic!() };
        assert_eq!(&r[2..12], &hex("85 80 00 01 00 02 00 00 00 00")[..]);
        assert_eq!(
            &r[r.len() - 34..],
            &hex("c0 0c 00 0c 00 01 00 00 00 3c 00 05 03 77 65 62 00 \
                 c0 0c 00 0c 00 01 00 00 00 3c 00 05 03 77 77 77 00")[..]
        );
        // a PTR query with the domain suffix is a name, not an address
        let local_ptr = "01 35 01 37 02 38 38 02 31 30 07 69 6e 2d 61 64 64 72 04 61 72 70 61 03 64 6e 73 06 70 6f 64 6d 61 6e 00";
        let Answer::Reply(r) = answer(&z, &ok(local_ptr, "00 0c 00 01"), 512) else {
            panic!()
        };
        assert_eq!((r[3], r[7]), (0x83, 0));
    }

    /// What is refused, dropped or answered with an error, and how the
    /// parser reads what is not a plain question.
    #[test]
    fn malformed_packets() {
        let z = zone();
        let web = "03 77 65 62 00";
        let a_in = "00 01 00 01";
        let hdr = |counts: &str| format!("12 34 01 00 {counts}");
        let one = "00 01 00 00 00 00 00 00";
        let formerr = reply_of("12 34 81 81 00 00 00 00 00 00 00 00");
        let ask = |h: String, rest: &str| hex(&format!("{h} {rest}"));

        // shorter than a header, or a response: no reply
        for short in 0..12 {
            assert_eq!(
                answer(&z, &hex(hdr(one).as_str())[..short], 512),
                Answer::Drop
            );
        }
        assert_eq!(answer(&z, &[], 512), Answer::Drop);
        let mut response = ask(hdr(one), &format!("{web} {a_in}"));
        response[2] |= 0x80;
        assert_eq!(answer(&z, &response, 512), Answer::Drop);
        // a size below a header, or below the question
        let plain = ask(hdr(one), &format!("{web} {a_in}"));
        assert_eq!(answer(&z, &plain, 11), Answer::Drop);
        assert_eq!(answer(&z, &plain, 20), Answer::Drop);
        assert!(matches!(answer(&z, &plain, 21), Answer::Reply(_)));

        // the counts: none or two questions, an answer, an authority, all
        // FORMERR with no question in the reply
        for counts in [
            "00 00 00 00 00 00 00 00",
            "00 02 00 00 00 00 00 00",
            "00 01 00 01 00 00 00 00",
            "00 01 00 00 00 01 00 00",
            "01 01 00 00 00 00 00 00",
        ] {
            assert_eq!(
                answer(&z, &ask(hdr(counts), &format!("{web} {a_in}")), 512),
                formerr,
                "{counts}"
            );
        }
        let edns = ask(
            hdr("00 01 00 00 00 00 00 01"),
            &format!("{web} {a_in} 00 00 29 10 00 00 00 00 00 00 00"),
        );
        // (the additional count is not looked at: an EDNS client is
        // answered, without an OPT record of the reply)
        assert_eq!(
            answer(&z, &edns, 512),
            answer(&z, &ask(hdr(one), &format!("{web} {a_in}")), 512)
        );

        // the names: a pointer (the question has none), a label of 64, a
        // label that runs past the end, a cut question, no end of the name
        for bad in [
            "c0 0c 00 01 00 01".to_string(),
            format!("40 {} 00 {a_in}", "61 ".repeat(64)),
            "05 77 65 62 00 01 00 01".to_string(),
            "03 77 65 62 00 00 01 00".to_string(),
            "03 77 65 62".to_string(),
            String::new(),
            "03 77 2e 62 00 00 01 00 01".to_string(),
            "03 77 00 62 00 00 01 00 01".to_string(),
        ] {
            assert_eq!(answer(&z, &ask(hdr(one), &bad), 512), formerr, "{bad}");
        }
        // a label of 63 is the longest; a name of 255 bytes on the wire (253
        // characters) is the longest, whatever the labels
        let label = |n: usize| format!("{:02x} {}", n, "61 ".repeat(n));
        let long63 = ask(hdr(one), &format!("{} 00 {a_in}", label(63)));
        assert_eq!(answer(&z, &long63, 512), Answer::Forward);
        // 3 labels of 63 and one more
        let name = |last: usize| {
            ask(
                hdr(one),
                &format!("{}{} 00 {a_in}", label(63).repeat(3), label(last)),
            )
        };
        assert_eq!(answer(&z, &name(61), 512), Answer::Forward);
        for over in [62, 63] {
            assert_eq!(answer(&z, &name(over), 512), formerr);
        }
        let five = ask(hdr(one), &format!("{} 00 {a_in}", label(63).repeat(5)));
        assert_eq!(answer(&z, &five, 512), formerr);

        // an opcode other than a query: NOTIMP (after FORMERR)
        let mut notify = ask(hdr(one), &format!("{web} {a_in}"));
        notify[2] = 0x21;
        assert_eq!(
            answer(&z, &notify, 512),
            reply_of("12 34 81 84 00 00 00 00 00 00 00 00")
        );
        let mut both = ask(hdr("00 02 00 00 00 00 00 00"), &format!("{web} {a_in}"));
        both[2] = 0x21;
        assert_eq!(answer(&z, &both, 512), formerr);

        // bytes after the question are ignored, and not echoed
        let trailing = ask(hdr(one), &format!("{web} {a_in} de ad be ef"));
        assert_eq!(
            answer(&z, &trailing, 512),
            answer(&z, &ask(hdr(one), &format!("{web} {a_in}")), 512)
        );
        // the question as `question` reads it: the other counts are not its
        // business, a response and a bad name are
        let q = question(&edns).unwrap();
        assert_eq!(
            (q.name.as_str(), q.qtype, q.qclass, q.end),
            ("web", 1, 1, 21)
        );
        assert_eq!(question(&trailing).unwrap().end, 21);
        assert_eq!(question(&notify).unwrap().end, 21);
        assert_eq!(question(&response), None);
        for bad in [
            "c0 0c 00 01 00 01",
            "05 77 65 62 00 01 00 01",
            "03 77 65 62 00 00 01",
        ] {
            assert_eq!(question(&ask(hdr(one), bad)), None, "{bad}");
        }
        assert_eq!(
            question(&ask(
                hdr("00 00 00 00 00 00 00 00"),
                &format!("{web} {a_in}")
            )),
            None
        );

        // SERVFAIL: the ID, RD, and nothing else, even for a response
        assert_eq!(
            servfail(&plain),
            Some(hex("12 34 81 82 00 00 00 00 00 00 00 00"))
        );
        let mut r = plain.clone();
        r[2] = 0x80;
        assert_eq!(
            servfail(&r),
            Some(hex("12 34 80 82 00 00 00 00 00 00 00 00"))
        );
        assert_eq!(servfail(&plain[..11]), None);
        assert_eq!(servfail(&[]), None);
    }

    /// What does not fit is cut at a record, with TC.
    #[test]
    fn truncation_at_a_record() {
        let mut z = zone();
        z[0].ips = (1..=4).map(|i| Ipv4Addr::new(10, 88, 7, i)).collect();
        let query = make_query("web", 1);
        // header, question (9 bytes), and records of 16 bytes
        let counts = [
            (21, 0),
            (36, 0),
            (37, 1),
            (52, 1),
            (53, 2),
            (84, 3),
            (85, 4),
            (512, 4),
        ];
        for (size, n) in counts {
            let Answer::Reply(r) = answer(&z, &query, size) else {
                panic!("{size}")
            };
            let full = n == 4;
            assert_eq!((r[7], r[2] & 2 != 0), (n, !full), "{size}");
            assert_eq!(r.len(), 21 + 16 * usize::from(n));
        }
        // the question alone does not fit: no reply
        assert_eq!(answer(&z, &query, 20), Answer::Drop);
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
