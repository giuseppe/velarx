// SPDX-License-Identifier: Apache-2.0
//! The operator's tool of the certificate authority of a swarm:
//! `velarx-p2p ca ...`.  It works on files and nothing else (no network, no
//! service): the key of the authority is in a directory the operator keeps
//! where they choose, and no node ever holds it.
//!
//! * `ca init DIR`: the key (`ca.key`, 0600) and the certificate (`ca.crt`);
//!   the certificate goes to the nodes (`ca_path` of its settings).
//! * `ca request`, on a node: its public key and a proof that it holds the
//!   private key (the key itself does not leave the node).
//! * `ca sign`: the certificate of a node from its request.
//! * `ca revoke`: the revocation list (`revoked` in the directory of the
//!   authority), which holds every peer revoked so far.
//! * `ca show`: what a certificate or a list says.

use crate::authority::{
    peer_of, pem_certificate, pem_certificates, pkcs8_of, read_certificate, Admitted,
    RevocationList, Role,
};
use libp2p::identity::{self, Keypair, PeerId};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, SanType, SerialNumber, PKCS_ED25519,
};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const KEY: &str = "ca.key";
const CERT: &str = "ca.crt";
const LISTS: &str = "revoked";
/// A certificate is valid from a little before it is made: the clocks of the
/// nodes differ.
const BACKDATE: i64 = 300;
const REQUEST_HEADER: &str = "velarx-enrolment/1";

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn at(unix: i64) -> io::Result<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(unix).map_err(other)
}

/// An ed25519 public key as rcgen wants a subject key.
struct Subject([u8; 32]);

impl PublicKeyData for Subject {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ED25519
    }
}

fn signing_key(key: &Keypair) -> io::Result<KeyPair> {
    let pkcs8 = pkcs8_of(key)?;
    KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(pkcs8), &PKCS_ED25519)
        .map_err(other)
}

/// The key of the authority (written by `init`, mode 0600).
fn read_key(path: &Path) -> io::Result<Keypair> {
    Keypair::from_protobuf_encoding(&std::fs::read(path)?).map_err(other)
}

/// The authority of `dir`: its key, and the parameters its certificate has
/// (the same each time: the name of the issuer is made from its key).
fn authority(dir: &Path) -> io::Result<(Keypair, [u8; 32], CertificateParams)> {
    let key = read_key(&dir.join(KEY))?;
    let raw = key
        .clone()
        .try_into_ed25519()
        .map_err(|_| invalid("the key of the authority is not an ed25519 key"))?
        .public()
        .to_bytes();
    Ok((key, raw, ca_params(&raw, 0)?))
}

fn ca_params(raw: &[u8; 32], days: i64) -> io::Result<CertificateParams> {
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "velarx swarm authority");
    name.push(DnType::OrganizationalUnitName, hex::encode(&raw[..8]));
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = at(now() - BACKDATE)?;
    params.not_after = at(now() + days * 86400)?;
    Ok(params)
}

/// Make the authority in `dir`, valid for `days`.
pub fn init(dir: &Path, days: u32) -> io::Result<String> {
    let path = dir.join(KEY);
    let key = match read_key(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => crate::identity::load_or_create(&path)?,
        other => other?,
    };
    let raw = key
        .clone()
        .try_into_ed25519()
        .map_err(|_| invalid("not an ed25519 key"))?
        .public()
        .to_bytes();
    let params = ca_params(&raw, i64::from(days))?;
    let cert = params.self_signed(&signing_key(&key)?).map_err(other)?;
    let pem = pem_certificate(cert.der());
    std::fs::write(dir.join(CERT), &pem)?;
    Ok(pem)
}

/// The request of a node with the key `identity`: its public key and a
/// signature by it, so that the authority knows the node holds the key.
pub fn request(identity: &Keypair) -> String {
    let public = identity.public().encode_protobuf();
    let proof = identity
        .sign(&[REQUEST_HEADER.as_bytes(), b" ", &public].concat())
        .unwrap_or_default();
    format!(
        "{REQUEST_HEADER}\npeer {}\nkey {}\nproof {}\n",
        identity.public().to_peer_id(),
        hex::encode(&public),
        hex::encode(proof)
    )
}

/// The peer and the raw key of a request whose proof is good.
fn read_request(text: &str) -> io::Result<(PeerId, [u8; 32])> {
    let mut lines = text.lines();
    if lines.next() != Some(REQUEST_HEADER) {
        return Err(invalid("not a request of this version"));
    }
    let (mut key, mut proof) = (None, None);
    for line in lines {
        match line.split_once(' ') {
            Some(("key", v)) => key = Some(v.trim()),
            Some(("proof", v)) => proof = Some(v.trim()),
            _ => {}
        }
    }
    let key = hex::decode(key.ok_or_else(|| invalid("the request has no key"))?)
        .map_err(|_| invalid("the key of the request"))?;
    let proof = hex::decode(proof.ok_or_else(|| invalid("the request has no proof"))?)
        .map_err(|_| invalid("the proof of the request"))?;
    let public = identity::PublicKey::try_decode_protobuf(&key)
        .map_err(|e| invalid(format!("the key of the request: {e}")))?;
    if !public.verify(&[REQUEST_HEADER.as_bytes(), b" ", &key].concat(), &proof) {
        return Err(invalid("the proof of the request is wrong"));
    }
    let raw = public
        .try_into_ed25519()
        .map_err(|_| invalid("the key of the node is not an ed25519 key"))?
        .to_bytes();
    let peer = peer_of(&raw).map_err(other)?;
    Ok((peer, raw))
}

/// The certificate (PEM) of the node of `request`, signed by the authority
/// of `dir`, valid for `days`.
pub fn sign(
    dir: &Path,
    request: &str,
    name: &str,
    zone: Option<&str>,
    role: Role,
    days: u32,
) -> io::Result<(String, Admitted)> {
    let (peer, raw) = read_request(request)?;
    let (key, _, ca) = authority(dir)?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    params.distinguished_name = dn;
    let mut uris = vec![format!("velarx:name:{name}"), format!("velarx:role:{role}")];
    uris.extend(zone.map(|z| format!("velarx:zone:{z}")));
    params.subject_alt_names = uris
        .into_iter()
        .map(|u| rcgen::string::Ia5String::try_from(u).map(SanType::URI))
        .collect::<Result<_, _>>()
        .map_err(other)?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = at(now() - BACKDATE)?;
    params.not_after = at(now() + i64::from(days) * 86400)?;
    let mut serial = [0u8; 16];
    rustix::rand::getrandom(&mut serial, rustix::rand::GetRandomFlags::empty()).map_err(other)?;
    serial[0] &= 0x7f;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    let issuer = rcgen::Issuer::new(ca, signing_key(&key)?);
    let cert = params.signed_by(&Subject(raw), &issuer).map_err(other)?;
    let who = Admitted {
        peer_id: peer,
        name: name.to_string(),
        zone: zone.map(str::to_string),
        role,
    };
    Ok((pem_certificate(cert.der()), who))
}

/// Revoke `peers`: the list of `dir` is made again with them added.
pub fn revoke(dir: &Path, peers: &[PeerId]) -> io::Result<RevocationList> {
    let (key, raw, _) = authority(dir)?;
    let ed = key
        .try_into_ed25519()
        .map_err(|_| invalid("the key of the authority is not an ed25519 key"))?;
    let path = dir.join(LISTS);
    let (mut all, number) = match std::fs::read_to_string(&path) {
        Ok(text) => {
            let (lists, ignored) = RevocationList::parse_all(&text, &[raw]);
            if ignored > 0 {
                return Err(invalid(format!(
                    "{} holds a list that is not valid: it is not changed",
                    path.display()
                )));
            }
            let list = lists.into_iter().max_by_key(|l| l.number);
            (
                list.as_ref().map(|l| l.peers.clone()).unwrap_or_default(),
                list.map_or(0, |l| l.number),
            )
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (Vec::new(), 0),
        Err(e) => return Err(e),
    };
    for peer in peers {
        if !all.contains(peer) {
            all.push(*peer);
        }
    }
    let list = RevocationList::sign(&ed, number + 1, now() as u64, &all);
    let tmp = dir.join(format!(".{LISTS}.new"));
    std::fs::write(&tmp, list.text())?;
    std::fs::rename(&tmp, &path)?;
    Ok(list)
}

/// What a file says: a certificate, or revocation lists.
pub fn show(path: &Path) -> io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    if text.contains("BEGIN CERTIFICATE") {
        let mut out = String::new();
        for der in pem_certificates(&text).map_err(other)? {
            match read_certificate(&der).map_err(other)? {
                (_, Ok(who)) => out.push_str(&format!(
                    "node {}: peer {}, zone {}, role {}\n",
                    who.name,
                    who.peer_id,
                    who.zone.as_deref().unwrap_or("-"),
                    who.role
                )),
                (raw, Err(_)) => out.push_str(&format!("authority: key {}\n", hex::encode(raw))),
            }
        }
        return Ok(out);
    }
    let mut keys = Vec::new();
    for line in text.lines() {
        if let Some(k) = line.strip_prefix("issuer ") {
            if let Ok(k) = hex::decode(k).map(<[u8; 32]>::try_from) {
                keys.extend(k.ok());
            }
        }
    }
    let (lists, ignored) = RevocationList::parse_all(&text, &keys);
    let mut out = String::new();
    for l in &lists {
        out.push_str(&format!(
            "list {} of the authority {}: {} peer(s) revoked\n",
            l.number,
            hex::encode(&l.issuer[..8]),
            l.peers.len()
        ));
        for p in &l.peers {
            out.push_str(&format!("  {p}\n"));
        }
    }
    if ignored > 0 || lists.is_empty() {
        out.push_str(&format!(
            "{ignored} list(s) with a wrong signature or damaged\n"
        ));
    }
    Ok(out)
}
