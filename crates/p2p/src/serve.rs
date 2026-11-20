// SPDX-License-Identifier: Apache-2.0
//! What a node serves its peers with, whatever carries the requests (QUIC
//! and the simulator): the upload pacing, the slots and the
//! checks of the bytes read from the stores.
//!
//! A peer names chunks by digest and nothing else: the digest is checked to
//! be one before it reaches the stores, and the number of chunks, their size
//! and the size of the answer are bounded by the wire format.

use super::limits::{short, MAX_ITEM_BYTES};
use super::ChunkProvider;
use serde::{Deserialize, Serialize};
use std::io;
use tracing::{error, warn};
use velarx_storage::ChunkFile;

/// Chunks read from the stores at the same time, and whose files are asked
/// of the daemon in one round trip.
pub const WAVE: usize = 8;

/// The bytes of a file read at a time.
pub const PIECE: usize = 1 << 20;

/// The files of `digests` the provider hands over, one for each digest
/// (`None` for what it does not hold or hand over); `None` when it hands
/// over no files at all (the bytes come from `get_chunk` then); an error
/// when it cannot tell.  Blocking.
pub fn open_wave(
    provider: &dyn ChunkProvider,
    digests: &[String],
) -> io::Result<Option<Vec<Option<ChunkFile>>>> {
    let mut opened = provider.open_chunks(digests)?;
    if opened.is_empty() {
        return Ok(None);
    }
    opened.resize_with(digests.len(), || None);
    Ok(Some(
        opened
            .into_iter()
            .map(|f| {
                f.filter(|c| {
                    c.len <= MAX_ITEM_BYTES as u64
                        && c.file
                            .metadata()
                            .is_ok_and(|m| m.len() >= c.offset.saturating_add(c.len))
                })
            })
            .collect(),
    ))
}

/// The bytes of the chunk `digest` from the provider (one that hands over no
/// files), only if a peer may take them.  An error when the store could not
/// be read, or holds bytes that do not have the digest ([`corrupt`]): the
/// asker is told the store failed (it asks another peer), not that the chunk
/// is not here.  Blocking.
pub fn read_checked(provider: &dyn ChunkProvider, digest: &str) -> io::Result<Option<Vec<u8>>> {
    let Some(data) = read(provider, digest)? else {
        return Ok(None);
    };
    if !crate::limits::names(digest, &data) {
        return Err(corrupt(digest));
    }
    Ok(Some(data))
}

/// The error of a chunk whose bytes in the store do not have its digest: the
/// store of this node is damaged, which is logged as an error (never hidden,
/// never served as the chunk).
pub fn corrupt(digest: &str) -> io::Error {
    error!("The store holds bytes for {digest} that do not match it: it is damaged");
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the store holds bytes that do not match the digest",
    )
}

/// The chunk `digest` if it is a valid digest of something we have that a
/// peer may take.
fn read(provider: &dyn ChunkProvider, digest: &str) -> io::Result<Option<Vec<u8>>> {
    if !crate::limits::is_digest(digest) {
        return Ok(None);
    }
    let Some(data) = provider.get_chunk(digest)? else {
        return Ok(None);
    };
    if data.len() > MAX_ITEM_BYTES {
        warn!(
            "Not serving {}: {} bytes are more than a peer may take",
            short(digest),
            data.len()
        );
        return Ok(None);
    }
    Ok(Some(data))
}

/// Whether the chunk `digest` is here, as a request for it would find it: one
/// valid digest, handed over as a file or as bytes that a peer may take.
/// Blocking.
pub fn has(provider: &dyn ChunkProvider, digest: &str) -> io::Result<bool> {
    if !crate::limits::is_digest(digest) {
        return Ok(false);
    }
    let names = [digest.to_string()];
    match open_wave(provider, &names)? {
        Some(opened) => Ok(opened[0].is_some()),
        None => Ok(read(provider, digest)?.is_some()),
    }
}

/// What the node bounds in what it serves (`[serving]` of `p2p.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Serving {
    /// Requests answered at the same time over QUIC, for all peers
    pub quic_slots: usize,
    /// QUIC connections open
    pub quic_connections: usize,
    /// What the node uploads in all (Mbit/s); 0: no limit
    pub upload_limit_mbit: u64,
    /// The window of a QUIC connection (MiB): what the node sends a peer
    /// that it has not acknowledged yet, and what a peer may send it on one
    /// stream that it has not read yet (four times that on a connection).
    /// A connection moves at most a window a round trip: 8 MiB is 67 Gbit/s
    /// at 1 ms and 6.7 Gbit/s at 10 ms; it is also what each of the
    /// `quic_connections` may hold of the node's memory
    pub quic_window_mib: u64,
}

impl Default for Serving {
    fn default() -> Self {
        Self {
            quic_slots: 64,
            quic_connections: 256,
            upload_limit_mbit: 0,
            quic_window_mib: 8,
        }
    }
}

impl Serving {
    /// Refuse values that do not mean what they say.
    pub fn validate(&self) -> Result<(), String> {
        for (name, n) in [
            ("quic_slots", self.quic_slots as u64),
            ("quic_connections", self.quic_connections as u64),
            ("quic_window_mib", self.quic_window_mib),
        ] {
            if n == 0 {
                return Err(format!("[serving] {name} must not be 0"));
            }
        }
        if self.upload_limit_mbit > 1_000_000 {
            return Err("[serving] upload_limit_mbit is more than 1 Tbit/s".into());
        }
        if self.quic_window_mib > 1024 {
            return Err("[serving] quic_window_mib is more than 1 GiB".into());
        }
        Ok(())
    }
}

/// Who asks: the address it asks from (an IPv6 address is its /64).  A QUIC
/// server does not know who a peer is: the address is what the upload limit
/// turns between.
#[derive(Clone, Copy, Debug)]
pub struct Caller {
    pub address: std::net::IpAddr,
}

impl Caller {
    pub fn new(address: std::net::IpAddr) -> Self {
        Self {
            address: prefix(address),
        }
    }

    /// Whom the upload limit is shared between.
    pub fn share(&self) -> std::net::IpAddr {
        self.address
    }
}

/// What one address is counted as: an IPv6 address is its /64 (what one
/// host is commonly given), an IPv4 one mapped into IPv6 the IPv4 address.
pub fn prefix(address: std::net::IpAddr) -> std::net::IpAddr {
    use std::net::IpAddr;
    match address.to_canonical() {
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
        v4 => v4,
    }
}

/// What a node is serving now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingState {
    /// The requests being answered over QUIC, and the most at a time
    pub quic_slots: (usize, usize),
    pub admission: AdmissionState,
}

/// What an [`Admission`] holds now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmissionState {
    pub upload: crate::pacer::PacerState,
}

/// What a node serves, on every transport (so that one cannot be used to get
/// around the bounds of the other): the bytes a second, and the probes
/// answered at a time.
pub struct Admission {
    pacer: crate::pacer::Pacer,
    probes: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Probes answered at the same time.  A probe carries no data
/// and waits for no credit: it has places of its own, so that requests for
/// data that wait for the upload limit cannot make a node answer busy to the
/// question whether it has a chunk.
pub const PROBE_SLOTS: usize = 4;

impl Default for Admission {
    fn default() -> Self {
        Self::new(&Serving::default())
    }
}

impl Admission {
    pub fn new(serving: &Serving) -> Self {
        Self {
            pacer: crate::pacer::Pacer::new(serving.upload_limit_mbit.saturating_mul(125_000)),
            probes: std::sync::Arc::new(tokio::sync::Semaphore::new(PROBE_SLOTS)),
        }
    }

    /// The place to answer a probe in; `None` when there is none (busy).
    pub fn probe_slot(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        self.probes.clone().try_acquire_owned().ok()
    }

    /// What the upload limit holds now.
    pub fn state(&self) -> AdmissionState {
        AdmissionState {
            upload: self.pacer.state(),
        }
    }

    /// Wait until `bytes` may be sent without the node uploading more than
    /// its limit, in the turn of `who`; whether the credit came (its first
    /// piece by `first_by`, when given).  Before they are read: what is
    /// read is what may be sent.
    pub async fn pace(
        &self,
        who: &Caller,
        bytes: u64,
        first_by: Option<tokio::time::Instant>,
    ) -> bool {
        self.pacer.pace(who.share(), bytes, first_by).await
    }

    /// The most that is paced at a time.
    pub fn piece(&self) -> u64 {
        self.pacer.piece()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv6 address is counted by its /64, and a mapped IPv4 address as
    /// the IPv4 one.
    #[test]
    fn an_address_is_its_prefix() {
        let a: std::net::IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: std::net::IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        assert_eq!(Caller::new(a).address, Caller::new(b).address);
        let mapped: std::net::IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(
            Caller::new(mapped).address,
            "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn the_serving_settings_are_checked() {
        assert!(Serving::default().validate().is_ok());
        for bad in [
            Serving {
                quic_slots: 0,
                ..Serving::default()
            },
            Serving {
                upload_limit_mbit: u64::MAX,
                ..Serving::default()
            },
            Serving {
                quic_window_mib: u64::MAX,
                ..Serving::default()
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }
}
