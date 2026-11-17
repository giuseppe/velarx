// SPDX-License-Identifier: Apache-2.0
//! nf_tables over nfnetlink: the transactions (tables, chains, sets, elements
//! and rules) and the dumps of the chains and set elements that the bridge
//! firewall needs, without running `nft`.
//!
//! Only the expressions of the firewall are encoded, in the form `nft` uses,
//! so that `nft list ruleset` shows our rules like its own.

use crate::netlink::{
    attributes, cstr, messages, read_u32, Msg, Netlink, NLMSG_ERROR, NLM_F_ACK, NLM_F_CREATE,
    NLM_F_DUMP,
};
use std::io;

pub const IP: u8 = 2;
pub const IP6: u8 = 10;

const SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NLM_F_APPEND: u16 = 0x800;

const NEWTABLE: u16 = 0;
const NEWCHAIN: u16 = 3;
const GETCHAIN: u16 = 4;
const DELCHAIN: u16 = 5;
const NEWRULE: u16 = 6;
const DELRULE: u16 = 8;
const NEWSET: u16 = 9;
const NEWSETELEM: u16 = 12;
const GETSETELEM: u16 = 13;
const DELSETELEM: u16 = 14;
// (the destroy messages delete what is there and are no error for what is
// not: Linux 6.3)
const DESTROYTABLE: u16 = 26;
const DESTROYCHAIN: u16 = 27;
const DESTROYSETELEM: u16 = 30;

const NFT_REG_VERDICT: u32 = 0;
/// The first register: the 32 bit registers `REG32_00 + n` overlap it.
pub const REG_1: u32 = 1;
const NFT_REG32_00: u32 = 8;

/// The register of the 32 bit word N, counted from the first register.
pub fn reg(word: u32) -> u32 {
    if word == 0 {
        REG_1
    } else {
        NFT_REG32_00 + word
    }
}

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NFT_JUMP: u32 = -3i32 as u32;
const NFT_DATA_VERDICT: u32 = 0xffff_ff00;

pub const META_IIFNAME: u32 = 6;
pub const META_OIFNAME: u32 = 7;
pub const META_L4PROTO: u32 = 16;
pub const CT_STATE: u32 = 0;
pub const CT_STATUS: u32 = 2;
pub const NETWORK_HEADER: u32 = 1;
pub const TRANSPORT_HEADER: u32 = 2;

/// The size of an interface name in a register.
pub const IFNAMSIZ: usize = 16;

/// A table: its family and name.
#[derive(Debug, Clone, Copy)]
pub struct Tab<'a> {
    pub family: u8,
    pub name: &'a str,
}

/// The type of a field of the key of a set (the numbers of nft's data types).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Ipv4,
    Ipv6,
    Service,
    Ifname,
}

impl Ty {
    fn id(self) -> u32 {
        match self {
            Ty::Ipv4 => 7,
            Ty::Ipv6 => 8,
            Ty::Service => 13,
            Ty::Ifname => 41,
        }
    }

    fn len(self) -> usize {
        match self {
            Ty::Ipv4 => 4,
            Ty::Ipv6 => 16,
            Ty::Service => 2,
            Ty::Ifname => IFNAMSIZ,
        }
    }
}

/// The type number and the length of a key or a value of the fields
/// FIELDS: concatenated ones take a whole number of 32 bit words each.
fn layout(fields: &[Ty]) -> (u32, u32) {
    if let [one] = fields {
        return (one.id(), one.len() as u32);
    }
    fields.iter().fold((0, 0), |(ty, len), f| {
        (ty << 6 | f.id(), len + (f.len() as u32).next_multiple_of(4))
    })
}

/// The fields PARTS as a concatenation: each padded to whole 32 bit words.
pub fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
        out.resize(out.len().next_multiple_of(4), 0);
    }
    out
}

/// An interface name as nft compares it: padded with zeros to the size of
/// the register.
pub fn ifname(name: &str) -> Vec<u8> {
    let mut v = name.as_bytes().to_vec();
    v.resize(IFNAMSIZ, 0);
    v
}

#[derive(Debug, Clone, Copy)]
pub enum SetData<'a> {
    /// A set of keys.
    None,
    /// A map to verdicts.
    Verdict,
    /// A map to values.
    Value(&'a [Ty]),
}

#[derive(Debug, Clone, Copy)]
pub struct SetDef<'a> {
    pub key: &'a [Ty],
    pub data: SetData<'a>,
    /// A set of intervals (the elements come in pairs, see `Elem`).
    pub interval: bool,
}

/// The place of a base chain.
#[derive(Debug, Clone, Copy)]
pub struct Hook {
    pub kind: &'static str,
    pub num: u32,
    pub priority: i32,
}

pub const PREROUTING: u32 = 0;
pub const INPUT: u32 = 1;
pub const FORWARD: u32 = 2;
pub const OUTPUT: u32 = 3;
pub const POSTROUTING: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElemData {
    None,
    Value(Vec<u8>),
    Jump(String),
}

/// An element of a set.  In a set of intervals an interval is the element
/// at its start (with the data) and one with `end` set at the first address
/// after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elem {
    pub key: Vec<u8>,
    pub data: ElemData,
    pub end: bool,
}

impl Elem {
    pub fn new(key: Vec<u8>, data: ElemData) -> Self {
        Elem {
            key,
            data,
            end: false,
        }
    }

    /// The elements of the interval of the addresses of the prefix of LEN
    /// bits of ADDR (big endian bytes, 4 or 16).
    pub fn prefix(addr: &[u8], len: u8, data: ElemData) -> Vec<Elem> {
        let bits = addr.len() * 8;
        let mut v = [0u8; 16];
        v[16 - addr.len()..].copy_from_slice(addr);
        let size = 1u128.checked_shl((bits - usize::from(len)) as u32);
        let mask = size.map_or(0, |s| !(s - 1));
        let start = u128::from_be_bytes(v) & mask;
        let end = size.and_then(|s| start.checked_add(s));
        let cut = |n: u128| n.to_be_bytes()[16 - addr.len()..].to_vec();
        let mut out = vec![Elem::new(cut(start), data)];
        // (the interval that reaches the end of the space has no end)
        if let Some(e) = end.filter(|e| bits == 128 || *e >> bits == 0) {
            out.push(Elem {
                key: cut(e),
                data: ElemData::None,
                end: true,
            });
        }
        out
    }
}

#[derive(Debug, Clone)]
pub enum Expr<'a> {
    Meta {
        key: u32,
        dreg: u32,
    },
    Payload {
        base: u32,
        offset: u32,
        len: u32,
        dreg: u32,
    },
    Ct {
        key: u32,
        dreg: u32,
    },
    /// `fib daddr type`
    FibDaddrType {
        dreg: u32,
    },
    /// REG = REG & MASK
    Bitwise {
        reg: u32,
        mask: Vec<u8>,
    },
    Cmp {
        reg: u32,
        ne: bool,
        data: Vec<u8>,
    },
    /// The key from SREG in the set; a map writes its value to DREG
    /// (the verdict register for a verdict map).
    Lookup {
        set: &'a str,
        sreg: u32,
        dreg: Option<u32>,
    },
    Accept,
    Drop,
    Jump(&'a str),
    /// `dnat to` the address from ADDR and the port from PROTO.
    Dnat {
        family: u8,
        addr: u32,
        proto: u32,
    },
    Masquerade,
}

fn be32(m: &mut Msg, ty: u16, v: u32) {
    m.attr(ty, &v.to_be_bytes());
}

/// A nested NFTA_DATA_VALUE attribute TY.
fn value(m: &mut Msg, ty: u16, data: &[u8]) {
    let at = m.begin(ty);
    m.attr(1, data);
    m.end(at);
}

fn verdict(m: &mut Msg, code: u32, chain: Option<&str>) {
    let d = m.begin(2);
    be32(m, 1, code);
    if let Some(c) = chain {
        m.attr_str(2, c);
    }
    m.end(d);
}

fn encode(m: &mut Msg, e: &Expr) {
    let name = match e {
        Expr::Meta { .. } => "meta",
        Expr::Payload { .. } => "payload",
        Expr::Ct { .. } => "ct",
        Expr::FibDaddrType { .. } => "fib",
        Expr::Bitwise { .. } => "bitwise",
        Expr::Cmp { .. } => "cmp",
        Expr::Lookup { .. } => "lookup",
        Expr::Accept | Expr::Drop | Expr::Jump(_) => "immediate",
        Expr::Dnat { .. } => "nat",
        Expr::Masquerade => "masq",
    };
    let elem = m.begin(1);
    m.attr_str(1, name);
    let data = m.begin(2);
    match e {
        Expr::Meta { key, dreg } | Expr::Ct { key, dreg } => {
            be32(m, 1, *dreg);
            be32(m, 2, *key);
        }
        Expr::Payload {
            base,
            offset,
            len,
            dreg,
        } => {
            be32(m, 1, *dreg);
            be32(m, 2, *base);
            be32(m, 3, *offset);
            be32(m, 4, *len);
        }
        Expr::FibDaddrType { dreg } => {
            be32(m, 1, *dreg);
            // NFT_FIB_RESULT_ADDRTYPE, NFTA_FIB_F_DADDR
            be32(m, 2, 3);
            be32(m, 3, 2);
        }
        Expr::Bitwise { reg, mask } => {
            be32(m, 1, *reg);
            be32(m, 2, *reg);
            be32(m, 3, mask.len() as u32);
            value(m, 4, mask);
            value(m, 5, &vec![0; mask.len()]);
        }
        Expr::Cmp { reg, ne, data } => {
            be32(m, 1, *reg);
            be32(m, 2, u32::from(*ne));
            value(m, 3, data);
        }
        Expr::Lookup { set, sreg, dreg } => {
            m.attr_str(1, set);
            be32(m, 2, *sreg);
            if let Some(d) = dreg {
                be32(m, 3, *d);
            }
        }
        Expr::Accept | Expr::Drop | Expr::Jump(_) => {
            be32(m, 1, NFT_REG_VERDICT);
            let data = m.begin(2);
            match e {
                Expr::Accept => verdict(m, NF_ACCEPT, None),
                Expr::Drop => verdict(m, NF_DROP, None),
                Expr::Jump(c) => verdict(m, NFT_JUMP, Some(c)),
                _ => {}
            }
            m.end(data);
        }
        Expr::Dnat {
            family,
            addr,
            proto,
        } => {
            // NFT_NAT_DNAT
            be32(m, 1, 1);
            be32(m, 2, u32::from(*family));
            be32(m, 3, *addr);
            be32(m, 4, *addr);
            be32(m, 5, *proto);
            be32(m, 6, *proto);
            // NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED
            be32(m, 7, 3);
        }
        Expr::Masquerade => {}
    }
    m.end(data);
    m.end(elem);
}

/// The elements in a message: a nested attribute holds at most 64 KiB.
const ELEMS_PER_MESSAGE: usize = 128;

/// The most bytes of one transaction sent to the kernel (a netlink message
/// is limited to the default socket buffer, 212992).
const MAX_BATCH: usize = 128 * 1024;

/// The messages of a transaction.
#[derive(Default)]
pub struct Batch {
    msgs: Vec<(Msg, String)>,
    /// The ID of the next set: the kernel wants one in the transaction.
    sets: u32,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, op: u16, flags: u16, family: u8, what: String) -> &mut Msg {
        let m = Msg::new(
            SUBSYS_NFTABLES << 8 | op,
            NLM_F_ACK | flags,
            &[family, 0, 0, 0],
        );
        self.msgs.push((m, what));
        &mut self.msgs.last_mut().expect("just pushed").0
    }

    /// Make the table exist.
    pub fn new_table(&mut self, t: &Tab) {
        self.push(
            NEWTABLE,
            NLM_F_CREATE,
            t.family,
            format!("table {}", t.name),
        )
        .attr_str(1, t.name);
    }

    /// Delete the table if it is there.
    pub fn destroy_table(&mut self, t: &Tab) {
        self.push(
            DESTROYTABLE,
            0,
            t.family,
            format!("destroy table {}", t.name),
        )
        .attr_str(1, t.name);
    }

    /// Make the chain exist (a base chain when HOOK is given).
    pub fn new_chain(&mut self, t: &Tab, name: &str, hook: Option<&Hook>) {
        let m = self.push(NEWCHAIN, NLM_F_CREATE, t.family, format!("chain {name}"));
        m.attr_str(1, t.name);
        m.attr_str(3, name);
        if let Some(h) = hook {
            let at = m.begin(4);
            be32(m, 1, h.num);
            be32(m, 2, h.priority as u32);
            m.end(at);
            m.attr_str(7, h.kind);
            // NF_ACCEPT
            be32(m, 5, NF_ACCEPT);
        }
    }

    /// Delete the rules of the chain.
    pub fn flush_chain(&mut self, t: &Tab, name: &str) {
        let m = self.push(DELRULE, 0, t.family, format!("flush chain {name}"));
        m.attr_str(1, t.name);
        m.attr_str(2, name);
    }

    /// Delete the chain, which has no rule and is not jumped to.
    pub fn del_chain(&mut self, t: &Tab, name: &str) {
        let m = self.push(DELCHAIN, 0, t.family, format!("delete chain {name}"));
        m.attr_str(1, t.name);
        m.attr_str(3, name);
    }

    /// Delete the chain and its rules if it is there; it must not be jumped
    /// to (by the end of the batch).
    pub fn destroy_chain(&mut self, t: &Tab, name: &str) {
        let m = self.push(DESTROYCHAIN, 0, t.family, format!("destroy chain {name}"));
        m.attr_str(1, t.name);
        m.attr_str(3, name);
    }

    /// Make the set exist.
    pub fn new_set(&mut self, t: &Tab, name: &str, def: &SetDef) {
        self.sets += 1;
        let id = self.sets;
        let m = self.push(NEWSET, NLM_F_CREATE, t.family, format!("set {name}"));
        m.attr_str(1, t.name);
        m.attr_str(2, name);
        be32(m, 10, id);
        let (key_type, key_len) = layout(def.key);
        let mut flags = 0;
        if def.interval {
            flags |= 4;
        }
        if !matches!(def.data, SetData::None) {
            flags |= 8;
        }
        if flags != 0 {
            be32(m, 3, flags);
        }
        be32(m, 4, key_type);
        be32(m, 5, key_len);
        match def.data {
            SetData::None => {}
            SetData::Verdict => {
                be32(m, 6, NFT_DATA_VERDICT);
                // sizeof(struct nft_verdict)
                be32(m, 7, 16);
            }
            SetData::Value(v) => {
                let (ty, len) = layout(v);
                be32(m, 6, ty);
                be32(m, 7, len);
            }
        }
    }

    fn elements(&mut self, op: u16, t: &Tab, set: &str, elems: &[Elem]) {
        let flags = if op == NEWSETELEM { NLM_F_CREATE } else { 0 };
        for chunk in elems.chunks(ELEMS_PER_MESSAGE) {
            let m = self.push(op, flags, t.family, format!("elements of {set}"));
            m.attr_str(1, t.name);
            m.attr_str(2, set);
            let list = m.begin(3);
            for e in chunk {
                let at = m.begin(1);
                value(m, 1, &e.key);
                match &e.data {
                    ElemData::None => {}
                    ElemData::Value(v) => value(m, 2, v),
                    ElemData::Jump(c) => {
                        let d = m.begin(2);
                        verdict(m, NFT_JUMP, Some(c));
                        m.end(d);
                    }
                }
                if e.end {
                    // NFT_SET_ELEM_INTERVAL_END
                    be32(m, 3, 1);
                }
                m.end(at);
            }
            m.end(list);
        }
    }

    /// Add the elements; one that is there with the same value is no error.
    pub fn add_elements(&mut self, t: &Tab, set: &str, elems: &[Elem]) {
        self.elements(NEWSETELEM, t, set, elems);
    }

    /// Delete the elements, which must exist.
    pub fn del_elements(&mut self, t: &Tab, set: &str, elems: &[Elem]) {
        self.elements(DELSETELEM, t, set, elems);
    }

    /// Delete the elements that are there (by key, whatever their value).
    pub fn destroy_elements(&mut self, t: &Tab, set: &str, elems: &[Elem]) {
        self.elements(DESTROYSETELEM, t, set, elems);
    }

    /// Append a rule to the chain.
    pub fn rule(&mut self, t: &Tab, chain: &str, exprs: &[Expr]) {
        let m = self.push(
            NEWRULE,
            NLM_F_CREATE | NLM_F_APPEND,
            t.family,
            format!("rule of {chain}"),
        );
        m.attr_str(1, t.name);
        m.attr_str(2, chain);
        let list = m.begin(4);
        for e in exprs {
            encode(m, e);
        }
        m.end(list);
    }
}

/// A socket to the nf_tables of the network namespace of the thread that
/// opens it.
pub struct Nft {
    nl: Netlink,
}

impl Nft {
    pub fn open() -> io::Result<Self> {
        Ok(Nft {
            nl: Netlink::open_protocol(Some(rustix::net::netlink::NETFILTER))?,
        })
    }

    /// Run the transaction: all of it or none.  A refusal of the kernel
    /// keeps the kind of its errno and names the step, but has no
    /// `raw_os_error()`: callers match on `kind()` (EBUSY: ResourceBusy).
    /// A transaction is one netlink message, which the kernel limits to the
    /// size of the socket buffer: a larger one (a long range of ports) goes
    /// as consecutive transactions of MAX_BATCH bytes each.
    pub fn apply(&mut self, batch: Batch) -> io::Result<()> {
        let mut chunk = Vec::new();
        let mut size = 0;
        for (m, w) in batch.msgs {
            if size + m.len() > MAX_BATCH && !chunk.is_empty() {
                self.transaction(std::mem::take(&mut chunk))?;
                size = 0;
            }
            size += m.len();
            chunk.push((m, w));
        }
        self.transaction(chunk)
    }

    fn transaction(&mut self, msgs: Vec<(Msg, String)>) -> io::Result<()> {
        let n = msgs.len() as u32;
        if n == 0 {
            return Ok(());
        }
        let first = self.nl.take_seq(n + 2);
        let mut buf =
            Msg::new(NFNL_MSG_BATCH_BEGIN, 0, &[0, 0, 0, SUBSYS_NFTABLES as u8]).finish(first);
        let mut what = Vec::new();
        for (i, (m, w)) in msgs.into_iter().enumerate() {
            buf.extend_from_slice(&m.finish(first + 1 + i as u32));
            what.push(w);
        }
        buf.extend_from_slice(
            &Msg::new(NFNL_MSG_BATCH_END, 0, &[0, 0, 0, SUBSYS_NFTABLES as u8])
                .finish(first + n + 1),
        );
        self.nl.send_raw(&buf)?;
        let mut left = n;
        let mut reply = vec![0u8; 32 * 1024];
        while left > 0 {
            let got = self.nl.recv_into(&mut reply)?;
            for (ty, seq, payload) in messages(&reply[..got]) {
                if ty != NLMSG_ERROR || seq < first || seq > first + n {
                    continue;
                }
                let errno = -(read_u32(payload, 0).unwrap_or(0) as i32);
                if seq == first {
                    // the kernel refused the batch itself (no nf_tables, no
                    // privilege): nothing else is answered
                    if errno != 0 {
                        let e = io::Error::from_raw_os_error(errno);
                        return Err(io::Error::new(e.kind(), format!("nftables batch: {e}")));
                    }
                    continue;
                }
                left -= 1;
                if errno != 0 {
                    let e = io::Error::from_raw_os_error(errno);
                    let w = &what[(seq - first - 1) as usize];
                    return Err(io::Error::new(e.kind(), format!("nftables {w}: {e}")));
                }
            }
        }
        Ok(())
    }

    /// The chains of the table: (name, whether it is a base chain); none for
    /// a table that is not there.
    pub fn chains(&mut self, t: &Tab) -> io::Result<Vec<(String, bool)>> {
        let req = Msg::new(
            SUBSYS_NFTABLES << 8 | GETCHAIN,
            NLM_F_DUMP,
            &[t.family, 0, 0, 0],
        );
        let mut out = Vec::new();
        self.nl.dump(req, SUBSYS_NFTABLES << 8 | NEWCHAIN, |p| {
            let (mut table, mut name, mut base) = (String::new(), String::new(), false);
            for (ty, d) in attributes(p.get(4..).unwrap_or(&[])) {
                match ty {
                    1 => table = cstr(d),
                    3 => name = cstr(d),
                    4 => base = true,
                    _ => {}
                }
            }
            if table == t.name {
                out.push((name, base));
            }
        })?;
        Ok(out)
    }

    /// The elements of the set; none when the set or the table is not there.
    pub fn elements(&mut self, t: &Tab, set: &str) -> io::Result<Vec<Elem>> {
        let mut req = Msg::new(
            SUBSYS_NFTABLES << 8 | GETSETELEM,
            NLM_F_DUMP,
            &[t.family, 0, 0, 0],
        );
        req.attr_str(1, t.name);
        req.attr_str(2, set);
        let mut out = Vec::new();
        let r = self.nl.dump(req, SUBSYS_NFTABLES << 8 | NEWSETELEM, |p| {
            for (ty, list) in attributes(p.get(4..).unwrap_or(&[])) {
                if ty != 3 {
                    continue;
                }
                for (_, e) in attributes(list) {
                    out.push(parse_element(e));
                }
            }
        });
        match r {
            Err(e) if e.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) => {
                Ok(Vec::new())
            }
            r => r.map(|()| out),
        }
    }
}

fn parse_element(e: &[u8]) -> Elem {
    let mut elem = Elem::new(Vec::new(), ElemData::None);
    for (ty, d) in attributes(e) {
        match ty {
            1 => {
                if let Some((_, v)) = attributes(d).find(|(t, _)| *t == 1) {
                    elem.key = v.to_vec();
                }
            }
            2 => {
                for (t, v) in attributes(d) {
                    match t {
                        1 => elem.data = ElemData::Value(v.to_vec()),
                        2 => {
                            let chain = attributes(v).find(|(t, _)| *t == 2).map(|(_, c)| cstr(c));
                            if let Some(c) = chain {
                                elem.data = ElemData::Jump(c);
                            }
                        }
                        _ => {}
                    }
                }
            }
            3 => elem.end = read_u32(d, 0).is_some_and(|f| u32::from_be(f) & 1 != 0),
            _ => {}
        }
    }
    elem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_intervals() {
        let j = ElemData::Jump("c".into());
        let v = Elem::prefix(&[10, 88, 7, 9], 24, j.clone());
        assert_eq!(v[0], Elem::new(vec![10, 88, 7, 0], j.clone()));
        assert_eq!(
            v[1],
            Elem {
                key: vec![10, 88, 8, 0],
                data: ElemData::None,
                end: true
            }
        );
        let v6 = Elem::prefix(
            &"fd00:7::".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            64,
            j.clone(),
        );
        assert_eq!(v6[1].key[..9], [0xfd, 0, 0, 7, 0, 0, 0, 1, 0]);
        // The last addresses have no end.
        assert_eq!(Elem::prefix(&[255, 255, 255, 0], 24, j.clone()).len(), 1);
        assert_eq!(Elem::prefix(&[0, 0, 0, 0], 0, j).len(), 1);
    }

    #[test]
    fn key_layouts() {
        assert_eq!(layout(&[Ty::Service]), (13, 2));
        assert_eq!(layout(&[Ty::Ipv4, Ty::Service]), (7 << 6 | 13, 8));
        assert_eq!(layout(&[Ty::Ipv4, Ty::Ifname]), (7 << 6 | 41, 20));
        assert_eq!(layout(&[Ty::Ipv6, Ty::Service]), (8 << 6 | 13, 20));
        assert_eq!(
            concat(&[&[1, 2, 3, 4], &[0, 53]]),
            vec![1, 2, 3, 4, 0, 53, 0, 0]
        );
    }
}
