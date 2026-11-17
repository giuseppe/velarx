// SPDX-License-Identifier: Apache-2.0
//! Streaming responses and Docker's multiplexed stream framing.

use std::future::Future;
use std::io;
use std::pin::Pin;
use tokio::io::{AsyncWrite, AsyncWriteExt, DuplexStream};

/// Where a stream is written: a pipe to the client of the engine, or the
/// body of a response.
pub trait Sink: AsyncWrite + Unpin + Send + 'static {
    /// Resolves when the reader is gone, even if nothing is written (a
    /// stream may be idle for hours); never for a sink that cannot tell.
    fn gone(&self) -> impl Future<Output = ()> + Send;
}

impl Sink for DuplexStream {
    fn gone(&self) -> impl Future<Output = ()> + Send {
        std::future::pending()
    }
}

/// The write end of the pipe a stream of the engine goes through.  Nothing
/// times it out: a follow stream may be idle for hours, and a reader that
/// reads slowly is one that reads.  It ends when the reader closes its end.
pub struct PipeSink {
    tx: tokio::net::unix::pipe::Sender,
    _busy: Option<velarx_content::activation::Busy>,
}

impl PipeSink {
    pub fn new(
        write: std::os::fd::OwnedFd,
        busy: Option<velarx_content::activation::Busy>,
    ) -> io::Result<Self> {
        Ok(Self {
            tx: tokio::net::unix::pipe::Sender::from_owned_fd(write)?,
            _busy: busy,
        })
    }
}

impl AsyncWrite for PipeSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.tx).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.tx).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.tx).poll_shutdown(cx)
    }
}

impl Sink for PipeSink {
    async fn gone(&self) {
        // (the error condition of a pipe whose readers are all gone)
        if self.tx.ready(tokio::io::Interest::ERROR).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

pub struct JsonLines<W: Sink = DuplexStream> {
    w: W,
}

impl<W: Sink> JsonLines<W> {
    pub fn new(w: W) -> Self {
        Self { w }
    }

    /// False when the client is gone.
    pub async fn send(&mut self, v: &impl serde::Serialize) -> bool {
        let mut b = match serde_json::to_vec(v) {
            Ok(b) => b,
            Err(_) => return true,
        };
        b.push(b'\n');
        self.w.write_all(&b).await.is_ok()
    }

    /// The result of `f`, or none if the client went away first.
    pub async fn while_there<T>(&self, f: impl Future<Output = T>) -> Option<T> {
        tokio::select! {
            v = f => Some(v),
            () = self.w.gone() => None,
        }
    }
}

/// Docker's stream types.
pub const STDOUT: u8 = 1;
pub const STDERR: u8 = 2;

/// A frame of Docker's multiplexed stream: the stream type, three zero bytes
/// and the length (big endian) before the data.
pub fn mux_frame(stream: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len());
    out.extend_from_slice(&[stream, 0, 0, 0]);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Write `data` as frames of the stream, at most 32 KiB each.
pub async fn write_mux<W: AsyncWrite + Unpin>(
    w: &mut W,
    stream: u8,
    data: &[u8],
) -> io::Result<()> {
    for chunk in data.chunks(32 * 1024) {
        w.write_all(&mux_frame(stream, chunk)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout() {
        assert_eq!(
            mux_frame(STDERR, b"abc"),
            vec![2, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c']
        );
        assert_eq!(mux_frame(STDOUT, b""), vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn mux_splits_large_writes() {
        let mut out = Vec::new();
        write_mux(&mut out, STDOUT, &vec![7u8; 70_000])
            .await
            .unwrap();
        // 32768 + 32768 + 4464, each with a header
        assert_eq!(out.len(), 70_000 + 3 * 8);
        assert_eq!(&out[4..8], &32768u32.to_be_bytes());
    }
}
