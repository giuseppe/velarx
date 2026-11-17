// SPDX-License-Identifier: Apache-2.0
//! TUN Tunnel Protocol for P2P Overlay Network
//!
//! This module implements IP packet tunneling over libp2p streams.
//! It allows containers on different nodes to communicate with full
//! IP connectivity by forwarding packets through existing P2P connections.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response::Codec, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::io;

/// Protocol identifier for TUN tunneling
pub const TUN_PROTOCOL: StreamProtocol = StreamProtocol::new("/velarx/tun/1.0");

/// Maximum IP packet size (MTU + headers)
pub const MAX_PACKET_SIZE: usize = 65535;

/// IP packet wrapper for P2P transmission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunPacket {
    /// Raw IP packet bytes
    pub data: Vec<u8>,
}

impl TunPacket {
    /// Create a new TUN packet from raw bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

/// Empty response for fire-and-forget packet sending
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunResponse;

/// The packets sent to the peers that wait for their answer, by request, and
/// the most there are: a packet past them is dropped, as a network drops
/// what it cannot carry (the library queues all of them, each up to 64 KiB,
/// for a container that sends faster than the peer takes).
pub struct Sent<K> {
    to: std::collections::HashMap<K, libp2p::PeerId>,
}

/// The packets sent to one peer, and to all, that wait for an answer: a
/// peer that is slow or stopped answering (until its requests time out) holds
/// its own share, and the packets to the other peers still go.
pub const MAX_SENT_PER_PEER: usize = 128;
pub const MAX_SENT: usize = 1024;

impl<K: std::hash::Hash + Eq> Default for Sent<K> {
    fn default() -> Self {
        Self {
            to: Default::default(),
        }
    }
}

impl<K: std::hash::Hash + Eq> Sent<K> {
    /// Whether a packet for `peer` may be sent now.
    pub fn may_send(&self, peer: &libp2p::PeerId) -> bool {
        self.to.len() < MAX_SENT
            && self.to.values().filter(|p| *p == peer).count() < MAX_SENT_PER_PEER
    }

    /// The packet of the request `id` was sent to `peer`.
    pub fn sent(&mut self, id: K, peer: libp2p::PeerId) {
        self.to.insert(id, peer);
    }

    /// The request `id` was answered or failed.
    pub fn done(&mut self, id: &K) {
        self.to.remove(id);
    }
}

/// Codec for TUN packets over libp2p streams
///
/// Uses simple length-prefixed framing:
/// - 4 bytes: packet length (big-endian u32)
/// - N bytes: packet data
#[derive(Debug, Clone, Default)]
pub struct TunPacketCodec;

impl Codec for TunPacketCodec {
    type Protocol = StreamProtocol;
    type Request = TunPacket;
    type Response = TunResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read length prefix (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > MAX_PACKET_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("packet too large: {} bytes", len),
            ));
        }

        let mut data = vec![0u8; len];
        io.read_exact(&mut data).await?;

        Ok(TunPacket { data })
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Fire-and-forget: no response expected
        Ok(TunResponse)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let len = req.data.len() as u32;
        io.write_all(&len.to_be_bytes()).await?;

        io.write_all(&req.data).await?;

        io.flush().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        _io: &mut T,
        _res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Fire-and-forget: no response to write
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    #[test]
    fn what_waits_for_a_peer_is_bounded_and_made_room_for_by_answers() {
        let mut sent = Sent::<u32>::default();
        let (a, b) = (PeerId::random(), PeerId::random());
        for id in 0..MAX_SENT_PER_PEER as u32 {
            assert!(sent.may_send(&a));
            sent.sent(id, a);
        }
        assert!(
            !sent.may_send(&a),
            "past its room, a packet to one peer is dropped"
        );
        assert!(sent.may_send(&b), "another peer has its own room");
        sent.done(&0);
        assert!(sent.may_send(&a));
        // all of them: the peers together
        let mut sent = Sent::<u32>::default();
        for id in 0..MAX_SENT as u32 {
            sent.sent(id, PeerId::random());
        }
        assert!(!sent.may_send(&a));
    }
}
