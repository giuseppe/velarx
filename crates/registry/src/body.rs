// SPDX-License-Identifier: Apache-2.0
//! Bodies that must keep coming, at the [`Speed`] of the client.

use crate::speed::Speed;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;
use velarx_types::{ImageError, ImageResult};

/// The body of a response, as a stream of its chunks.
pub struct Body {
    inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    speed: Speed,
    /// Since when the consumer waits for the next chunk
    waiting: Option<Instant>,
    /// Time waited, and bytes received, in the current window
    waited: Duration,
    bytes: u64,
}

impl Body {
    pub fn new(resp: reqwest::Response, speed: Speed) -> Self {
        Self::of(resp.bytes_stream(), speed)
    }

    fn of(
        stream: impl Stream<Item = reqwest::Result<Bytes>> + Send + 'static,
        speed: Speed,
    ) -> Self {
        Self {
            inner: Box::pin(stream),
            speed,
            waiting: None,
            waited: Duration::ZERO,
            bytes: 0,
        }
    }

    /// The next chunk of the body.
    pub async fn chunk(&mut self) -> ImageResult<Option<Bytes>> {
        self.next().await.transpose()
    }

    fn slow(&self) -> ImageError {
        ImageError::Registry(format!(
            "the server is too slow: {} bytes in {} seconds, less than {} KiB per second ([pull] min_speed_kib, min_speed_secs)",
            self.bytes,
            self.waited.as_secs(),
            self.speed.bytes_per_sec / 1024
        ))
    }
}

impl Stream for Body {
    type Item = ImageResult<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = self.inner.poll_next_unpin(cx);
        let Poll::Ready(item) = polled else {
            self.waiting.get_or_insert_with(Instant::now);
            return Poll::Pending;
        };
        if let Some(since) = self.waiting.take() {
            self.waited += since.elapsed();
        }
        Poll::Ready(match item {
            Some(Ok(chunk)) => {
                self.bytes += chunk.len() as u64;
                if self.speed.bytes_per_sec != 0 && self.waited >= self.speed.window {
                    let enough = self.waited.as_secs_f64() * self.speed.bytes_per_sec as f64;
                    if (self.bytes as f64) < enough {
                        return Poll::Ready(Some(Err(self.slow())));
                    }
                    self.waited = Duration::ZERO;
                    self.bytes = 0;
                }
                Some(Ok(chunk))
            }
            Some(Err(e)) => Some(Err(e.into())),
            None => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chunks of one byte that arrive `every` apart.
    fn trickle(every: Duration, n: usize) -> impl Stream<Item = reqwest::Result<Bytes>> + Send {
        futures::stream::unfold(0, move |i| async move {
            if i == n {
                return None;
            }
            tokio::time::sleep(every).await;
            Some((Ok(Bytes::from_static(b"x")), i + 1))
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_trickle_is_refused_with_the_limit_it_broke() {
        let mut body = Body::of(trickle(Duration::from_secs(50), 100), Speed::default());
        let mut got = 0;
        let err = loop {
            match body.chunk().await {
                Ok(Some(c)) => got += c.len(),
                Ok(None) => panic!("the trickle was let through"),
                Err(e) => break e.to_string(),
            }
        };
        assert!(err.contains("min_speed_kib"), "{err}");
        assert!(got < 10, "{got} bytes before it was stopped");
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_body_and_a_disabled_check_pass() {
        let fast = futures::stream::iter((0..100).map(|_| Ok(Bytes::from(vec![0u8; 64 * 1024]))));
        let mut body = Body::of(fast, Speed::default());
        let mut total = 0;
        while let Some(c) = body.chunk().await.unwrap() {
            total += c.len();
        }
        assert_eq!(total, 100 * 64 * 1024);
        let mut body = Body::of(trickle(Duration::from_secs(50), 10), Speed::new(0, 0));
        let mut n = 0;
        while let Some(c) = body.chunk().await.unwrap() {
            n += c.len();
        }
        assert_eq!(n, 10);
    }

    /// `min_speed_secs = 0` is no check, not a check of every chunk: a
    /// small chunk after a short wait is not a slow server.
    #[tokio::test(start_paused = true)]
    async fn a_window_of_zero_is_no_check() {
        let mut body = Body::of(trickle(Duration::from_millis(100), 3), Speed::new(1024, 0));
        let mut n = 0;
        while let Some(c) = body.chunk().await.unwrap() {
            n += c.len();
        }
        assert_eq!(n, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_consumer_is_not_a_slow_server() {
        let fast = futures::stream::iter((0..10).map(|_| Ok(Bytes::from_static(b"x"))));
        let mut body = Body::of(fast, Speed::default());
        while body.chunk().await.unwrap().is_some() {
            // (the bytes are ready: time spent here is not waiting)
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}
