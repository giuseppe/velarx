// SPDX-License-Identifier: Apache-2.0
//! The request-response protocol of the gossip between nodes (what a node
//! tells its peers, and the question for their images).  Data does not
//! travel here: chunks, indexes and profiles go over QUIC (`quic`).

use super::gossip::{GossipMessage, ImageInfo};
use super::limits::{MAX_LISTS_BYTES, MAX_REQUEST_BYTES};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response::Codec, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, SemaphorePermit};

/// How long a gossip message being read waits for room in the budget of
/// the bytes of the messages being read, for each piece.
const BUDGET_WAIT: Duration = Duration::from_secs(10);

/// The bytes of a gossip message taken from the budget, and read, at a time.
const PIECE: usize = 1 << 20;

/// The protocol of the gossip.  Version 1.
pub const GOSSIP_PROTOCOL: StreamProtocol = StreamProtocol::new("/velarx/gossip/1");

/// What a peer answers to a gossip message: the images it announces when
/// it was asked for them and does announce, the peers it knows when it was
/// asked for them, nothing otherwise (the message was taken).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipReply {
    /// The images of the answering node, for [`GossipMessage::ImageQuery`]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<ImageInfo>>,
    /// Peers the answering node is connected to, for
    /// [`GossipMessage::PeerQuery`] (`peer_exchange`): empty when it has none
    /// to tell or answered the asker lately
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<crate::peer_exchange::PeerAddress>>,
}

/// The bytes of the bodies being read, from all the streams of all the peers
/// of a node, are at most the size of the budget: a body is read in pieces
/// of [`PIECE`], and each piece is taken from the budget before the buffer
/// grows by it (the announced length takes nothing: a peer that sends
/// nothing holds one piece).  A piece waits for room up to [`BUDGET_WAIT`].
/// The bytes are given back when the permit that [`Budget::read`] returns
/// is dropped.  The clones of a budget are the same budget.
#[derive(Clone)]
pub(crate) struct Budget(Arc<Semaphore>);

impl Budget {
    pub(crate) fn new(bytes: usize) -> Self {
        Self(Arc::new(Semaphore::new(bytes)))
    }

    /// The bytes not taken.
    #[cfg(test)]
    pub(crate) fn free(&self) -> usize {
        self.0.available_permits()
    }

    /// The `len` bytes of a body, read in pieces of [`PIECE`], with the
    /// permit that holds what was taken.
    pub(crate) async fn read<T>(
        &self,
        io: &mut T,
        len: usize,
    ) -> io::Result<(Vec<u8>, SemaphorePermit<'_>)>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut held = self.0.acquire_many(0).await.map_err(io::Error::other)?;
        let mut buf = Vec::new();
        while buf.len() < len {
            let step = (len - buf.len()).min(PIECE);
            let piece = tokio::time::timeout(BUDGET_WAIT, self.0.acquire_many(step as u32))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no room to read a body"))?
                .map_err(io::Error::other)?;
            held.merge(piece);
            let at = buf.len();
            buf.reserve_exact(step);
            buf.resize(at + step, 0);
            io.read_exact(&mut buf[at..]).await?;
        }
        Ok((buf, held))
    }
}

/// Codec of the gossip protocol: a message (or its answer) is JSON in a
/// frame.  A message may announce and be written at most `most` bytes (the
/// revocation lists it carries, [`MAX_LISTS_BYTES`], for a node with an
/// authority); an answer is at most [`MAX_REQUEST_BYTES`].
///
/// The body of a message is read through the [`Budget`] of the node, which
/// the handshake shares: the bytes are given back when the message is
/// parsed or the reading fails or is dropped.
#[derive(Clone)]
pub struct GossipCodec {
    budget: Budget,
    most: usize,
}

/// A budget and a bound of its own: for a behaviour built with
/// `Behaviour::new`, which the tests of the liveness do.  A node takes its
/// codec from [`GossipCodec::new`].
impl Default for GossipCodec {
    fn default() -> Self {
        Self::new(Budget::new(MAX_LISTS_BYTES), MAX_LISTS_BYTES)
    }
}

impl GossipCodec {
    pub(crate) fn new(budget: Budget, most: usize) -> Self {
        Self { budget, most }
    }

    /// A budget of `most` bytes, and `most` the bound of a message.
    #[cfg(test)]
    fn with_budget(most: usize) -> Self {
        Self::new(Budget::new(most), most)
    }
}

impl Codec for GossipCodec {
    type Protocol = StreamProtocol;
    type Request = GossipMessage;
    type Response = GossipReply;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let len = read_len(io, self.most, "gossip message").await?;
        // (held until the message is parsed: the bytes and the strings made
        // of them are what the budget is for)
        let (buf, _held) = self.budget.read(io, len).await?;
        serde_json::from_slice(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid gossip: {e}")))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_frame(io, MAX_REQUEST_BYTES, "gossip answer").await?;
        serde_json::from_slice(&buf).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid gossip answer: {e}"),
            )
        })
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_json::to_vec(&req).map_err(io::Error::other)?;
        write_frame(io, &data, self.most).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_json::to_vec(&res).map_err(io::Error::other)?;
        write_frame(io, &data, MAX_REQUEST_BYTES).await
    }
}
/// A frame of the gossip protocol: its length (big endian u32), then that many
/// bytes.  The length is checked before anything else is read, and the bytes
/// are read as they come, so a peer that announces a lot and sends little costs
/// nothing.
async fn read_frame<T>(io: &mut T, max: usize, what: &str) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let len = read_len(io, max, what).await?;
    read_body(io, len).await
}

/// The length a frame announces, when it is at most `max`.
pub(crate) async fn read_len<T>(io: &mut T, max: usize, what: &str) -> io::Result<usize>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{what} too large"),
        ));
    }
    Ok(len)
}

async fn read_body<T>(io: &mut T, len: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut buf = Vec::new();
    io.take(len as u64).read_to_end(&mut buf).await?;
    if buf.len() != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(buf)
}

async fn write_frame<T>(io: &mut T, data: &[u8], max: usize) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    if data.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    io.write_all(&(data.len() as u32).to_be_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await
}

/// Streams for the tests of what is read from a peer.
#[cfg(test)]
pub(crate) mod streams {
    use futures::AsyncRead;
    use std::io;

    /// What a stream gives: `head` (then, when `stalls`, nothing for ever;
    /// else a read past it is a failure of the test).
    pub(crate) struct Gives {
        pub head: Vec<u8>,
        pub stalls: bool,
    }

    impl AsyncRead for Gives {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<io::Result<usize>> {
            if self.head.is_empty() {
                assert!(self.stalls, "more was read than was given");
                return std::task::Poll::Pending;
            }
            let n = buf.len().min(self.head.len());
            buf[..n].copy_from_slice(&self.head[..n]);
            self.head.drain(..n);
            std::task::Poll::Ready(Ok(n))
        }
    }

    pub(crate) fn announcing(len: u32) -> Gives {
        Gives {
            head: len.to_be_bytes().to_vec(),
            stalls: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::streams::{announcing, Gives};
    use super::*;

    /// A gossip message and its answer cross the codec, and what is not
    /// one does not decode.
    #[tokio::test]
    async fn test_gossip_crosses_the_codec() {
        use futures::io::Cursor;
        let mut codec = GossipCodec::default();
        let mut wire = Vec::new();
        let layer =
            velarx_types::digest::Digest::of(velarx_types::digest::Algorithm::Sha256, b"layer")
                .to_string();
        let mut told =
            crate::filter::Advertiser::new(Default::default(), crate::entropy::Entropy::seeded(1));
        told.add(std::slice::from_ref(&layer));
        let message = told.full().unwrap();
        codec
            .write_request(&GOSSIP_PROTOCOL, &mut wire, message.clone())
            .await
            .unwrap();
        match codec
            .read_request(&GOSSIP_PROTOCOL, &mut Cursor::new(wire))
            .await
            .unwrap()
        {
            GossipMessage::LayerFilter(got) => {
                assert!(matches!(message, GossipMessage::LayerFilter(sent) if sent == got))
            }
            other => panic!("{other:?}"),
        }
        let mut wire = Vec::new();
        codec
            .write_response(&GOSSIP_PROTOCOL, &mut wire, GossipReply::default())
            .await
            .unwrap();
        let reply = codec
            .read_response(&GOSSIP_PROTOCOL, &mut Cursor::new(wire))
            .await
            .unwrap();
        assert!(reply.images.is_none());
        let mut garbage = Cursor::new(framed_garbage());
        assert!(codec
            .read_request(&GOSSIP_PROTOCOL, &mut garbage)
            .await
            .is_err());
        // what version 1 does not know is refused, not taken in part
        for (text, request) in [
            (&br#"{"LayerFilter":{"version":1,"salt":1,"hashes":1,"keys":0,"bits":"","more":1}}"#[..], true),
            (br#""ImageQueryV2""#, true),
            (br#"{"images":[],"later":true}"#, false),
        ] {
            let mut wire = (text.len() as u32).to_be_bytes().to_vec();
            wire.extend_from_slice(text);
            let failed = if request {
                codec
                    .read_request(&GOSSIP_PROTOCOL, &mut Cursor::new(wire))
                    .await
                    .is_err()
            } else {
                codec
                    .read_response(&GOSSIP_PROTOCOL, &mut Cursor::new(wire))
                    .await
                    .is_err()
            };
            assert!(failed, "{}", String::from_utf8_lossy(text));
        }
        // a message larger than the largest lists is refused before it is read
        let mut wire = ((MAX_LISTS_BYTES + 1) as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(b"{}");
        assert!(codec
            .read_request(&GOSSIP_PROTOCOL, &mut Cursor::new(wire))
            .await
            .is_err());
    }

    fn framed_garbage() -> Vec<u8> {
        let mut v = 4u32.to_be_bytes().to_vec();
        v.extend_from_slice(b"\xff\xfe{{");
        v
    }

    /// A stream that gives at most `step` bytes at a time.
    struct Dribble {
        rest: Vec<u8>,
        step: usize,
    }

    impl AsyncRead for Dribble {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<io::Result<usize>> {
            let n = buf.len().min(self.rest.len()).min(self.step);
            buf[..n].copy_from_slice(&self.rest[..n]);
            self.rest.drain(..n);
            std::task::Poll::Ready(Ok(n))
        }
    }

    fn free(codec: &GossipCodec) -> usize {
        codec.budget.free()
    }

    /// The budget of the bytes of the messages read at once: a message
    /// larger than it is refused with only its length read, and the bytes
    /// it took are given back when the message is taken, when it is not a
    /// message, when its bytes do not come, when there is no room, and
    /// when the reading is dropped.
    #[tokio::test(start_paused = true)]
    async fn test_the_bytes_of_the_messages_read_at_once_are_bounded() {
        use futures::io::Cursor;
        let mut codec = GossipCodec::with_budget(20);
        // larger than the budget: refused, the body not read (the stream
        // panics when it is)
        let refused = codec
            .read_request(&GOSSIP_PROTOCOL, &mut announcing(21))
            .await;
        assert!(refused.is_err());
        assert_eq!(free(&codec), 20);
        // taken
        let body = br#""ImageQuery""#;
        let mut wire = (body.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(body);
        codec
            .read_request(&GOSSIP_PROTOCOL, &mut Cursor::new(wire))
            .await
            .unwrap();
        assert_eq!(free(&codec), 20);
        // not a message
        assert!(codec
            .read_request(&GOSSIP_PROTOCOL, &mut Cursor::new(framed_garbage()))
            .await
            .is_err());
        assert_eq!(free(&codec), 20);
        // a body that ends early
        let mut wire = 12u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"short");
        let err = codec
            .read_request(&GOSSIP_PROTOCOL, &mut Cursor::new(wire))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(free(&codec), 20);
        // while 12 are held, a message of 12 more waits and then gives up
        let held = codec.budget.0.clone().acquire_many_owned(12).await.unwrap();
        let mut stream = Gives {
            head: [&12u32.to_be_bytes()[..], &[b'x'; 12]].concat(),
            stalls: false,
        };
        let err = codec
            .read_request(&GOSSIP_PROTOCOL, &mut stream)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(free(&codec), 8);
        drop(held);
        assert_eq!(free(&codec), 20);
        // the answer to a message has a bound of its own
        assert!(read_frame(
            &mut announcing(MAX_REQUEST_BYTES as u32 + 1),
            MAX_REQUEST_BYTES,
            "x"
        )
        .await
        .is_err());
    }

    /// The bound of a node with no authority: a message that announces more
    /// is refused with only its length read, a larger one is not written,
    /// and the largest messages a node makes fit.
    #[tokio::test]
    async fn test_a_node_with_no_authority_bounds_a_message_by_what_it_makes() {
        use crate::filter::{FilterDelta, FilterFull, MAX_DELTA_KEYS};
        use crate::limits::MAX_GOSSIP_BYTES;
        use base64::Engine;
        let mut codec = GossipCodec::new(Budget::new(MAX_LISTS_BYTES), MAX_GOSSIP_BYTES);
        let refused = codec
            .read_request(
                &GOSSIP_PROTOCOL,
                &mut announcing(MAX_GOSSIP_BYTES as u32 + 1),
            )
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        let lists = GossipMessage::Revocations {
            lists: vec!["x".repeat(MAX_GOSSIP_BYTES)],
        };
        let mut wire = Vec::new();
        let refused = codec
            .write_request(&GOSSIP_PROTOCOL, &mut wire, lists)
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
        assert!(wire.is_empty());
        // the largest filter, every field at its largest, and the largest delta
        let b64 = base64::engine::general_purpose::STANDARD;
        let filter = GossipMessage::LayerFilter(FilterFull {
            epoch: u64::MAX,
            version: u64::MAX,
            salt: u64::MAX,
            hashes: velarx_recv_core::MAX_HASHES,
            keys: u32::MAX,
            bits: b64.encode(vec![0xffu8; velarx_recv_core::MAX_FILTER_BYTES]),
        });
        let delta = GossipMessage::LayerFilterDelta(FilterDelta {
            epoch: u64::MAX,
            from: u64::MAX - 1,
            to: u64::MAX,
            added: b64.encode(vec![0xffu8; MAX_DELTA_KEYS * 8]),
        });
        for message in [filter, delta] {
            let mut wire = Vec::new();
            codec
                .write_request(&GOSSIP_PROTOCOL, &mut wire, message)
                .await
                .unwrap();
            codec
                .read_request(&GOSSIP_PROTOCOL, &mut futures::io::Cursor::new(wire))
                .await
                .unwrap();
        }
    }

    /// A peer that announces the most and sends nothing holds one piece,
    /// not the budget: the message of another peer is read meanwhile, and
    /// the piece is given back when the reading is dropped.
    #[tokio::test(start_paused = true)]
    async fn test_a_peer_that_announces_and_sends_nothing_holds_one_piece() {
        use futures::io::Cursor;
        let most = 3 * PIECE;
        let codec = GossipCodec::with_budget(most);
        let mut silent = Gives {
            head: (most as u32).to_be_bytes().to_vec(),
            stalls: true,
        };
        let mut hostile = codec.clone();
        let protocol = GOSSIP_PROTOCOL;
        let mut reading = Box::pin(hostile.read_request(&protocol, &mut silent));
        assert!(futures::poll!(reading.as_mut()).is_pending());
        assert_eq!(free(&codec), most - PIECE);
        // another peer's message goes through, and gives its bytes back
        let body = br#""ImageQuery""#;
        let mut wire = (body.len() as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(body);
        codec
            .clone()
            .read_request(&GOSSIP_PROTOCOL, &mut Cursor::new(wire))
            .await
            .unwrap();
        assert_eq!(free(&codec), most - PIECE);
        drop(reading);
        assert_eq!(free(&codec), most);
    }

    /// A body is read whole when it comes in many small writes, across
    /// several pieces, and takes exactly its length from the budget.
    #[tokio::test]
    async fn test_a_body_in_many_small_writes_is_read_whole() {
        let body: Vec<u8> = (0..2 * PIECE + PIECE / 2 + 7)
            .map(|i| (i % 251) as u8)
            .collect();
        let budget = Budget::new(4 * PIECE);
        let mut stream = Dribble {
            rest: body.clone(),
            step: 1000,
        };
        let (got, held) = budget.read(&mut stream, body.len()).await.unwrap();
        assert_eq!(got, body);
        assert_eq!(budget.free(), 4 * PIECE - body.len());
        drop(held);
        assert_eq!(budget.free(), 4 * PIECE);
    }

    #[tokio::test]
    async fn test_a_frame_is_read_as_it_comes_and_bounded() {
        use futures::io::Cursor;
        let framed = |body: &[u8], claimed: u32| {
            let mut v = claimed.to_be_bytes().to_vec();
            v.extend_from_slice(body);
            v
        };
        let mut ok = Cursor::new(framed(b"hello", 5));
        assert_eq!(read_frame(&mut ok, 10, "x").await.unwrap(), b"hello");
        // Too large for the limit: refused before reading.
        let mut big = Cursor::new(framed(b"hello", 11));
        assert!(read_frame(&mut big, 10, "x").await.is_err());
        // A huge claim with little behind it costs nothing and fails.
        let mut truncated = Cursor::new(framed(b"short", u32::MAX));
        assert!(read_frame(&mut truncated, MAX_REQUEST_BYTES, "x")
            .await
            .is_err());
        let mut truncated = Cursor::new(framed(b"short", 100));
        assert_eq!(
            read_frame(&mut truncated, 1000, "x")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
