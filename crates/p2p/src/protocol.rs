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

/// Codec of the gossip protocol: a message (or its answer) is JSON in a
/// frame.  A message may be as large as the revocation lists it carries
/// ([`MAX_LISTS_BYTES`]); an answer is at most [`MAX_REQUEST_BYTES`].
#[derive(Clone, Default)]
pub struct GossipCodec;

impl Codec for GossipCodec {
    type Protocol = StreamProtocol;
    type Request = GossipMessage;
    type Response = GossipReply;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = read_frame(io, MAX_LISTS_BYTES, "gossip message").await?;
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
        write_frame(io, &data, MAX_LISTS_BYTES).await
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
/// bytes.  The length is checked before anything is read, and the bytes are
/// read as they come, so a peer that announces a lot and sends little costs
/// nothing.
async fn read_frame<T>(io: &mut T, max: usize, what: &str) -> io::Result<Vec<u8>>
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A gossip message and its answer cross the codec, and what is not
    /// one does not decode.
    #[tokio::test]
    async fn test_gossip_crosses_the_codec() {
        use futures::io::Cursor;
        let mut codec = GossipCodec;
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
