// SPDX-License-Identifier: Apache-2.0
//! What stops an operation that runs for long (a build, with its pulls,
//! copies and commits): asked for once, seen by every part of it.

use std::io::{self, Read, Write};
use tokio::sync::watch;

/// What tells an operation to stop: it kills what it started, does not go
/// on, and cleans up as for a step that failed.  It may have several
/// askers ([`Cancel::or`]): the first one that asks stops it.
#[derive(Clone, Debug, Default)]
pub struct Cancel(Vec<watch::Receiver<bool>>);

impl Cancel {
    /// A cancel that `tx.send(true)` asks for.
    pub fn new() -> (watch::Sender<bool>, Self) {
        let (tx, rx) = watch::channel(false);
        (tx, Self(vec![rx]))
    }

    /// A cancel that `rx` turning true asks for.
    pub fn on(rx: watch::Receiver<bool>) -> Self {
        Self(vec![rx])
    }

    /// A cancel that this one and `other` both ask for.
    pub fn or(&self, other: &Cancel) -> Self {
        Self(self.0.iter().chain(&other.0).cloned().collect())
    }

    /// Whether the operation was asked to stop.
    pub fn asked(&self) -> bool {
        self.0.iter().any(|rx| *rx.borrow())
    }

    /// The error of an operation that stopped because it was asked to.
    pub fn error() -> io::Error {
        io::Error::other("cancelled")
    }

    /// An error if the operation was asked to stop (for the loops of the
    /// code that does not wait).
    pub fn check(&self) -> io::Result<()> {
        if self.asked() {
            Err(Self::error())
        } else {
            Ok(())
        }
    }

    /// Return once the operation is asked to stop (never for one that
    /// nobody can stop).
    pub async fn wait(&mut self) {
        let waits: Vec<_> = self
            .0
            .iter_mut()
            .map(|rx| {
                Box::pin(async move {
                    // (an asker that is gone never asks)
                    if rx.wait_for(|asked| *asked).await.is_err() {
                        std::future::pending::<()>().await;
                    }
                })
            })
            .collect();
        if waits.is_empty() {
            std::future::pending::<()>().await;
        }
        futures::future::select_all(waits).await;
    }

    /// `fut`, unless the operation is asked to stop first: then `None` and
    /// `fut` is dropped.
    pub async fn unless<T>(&self, fut: impl std::future::Future<Output = T>) -> Option<T> {
        let mut cancel = self.clone();
        tokio::select! {
            r = fut => Some(r),
            () = cancel.wait() => None,
        }
    }

    /// A reader or writer that fails once the operation is asked to stop.
    pub fn io<T>(&self, inner: T) -> Stoppable<T> {
        Stoppable {
            inner,
            cancel: self.clone(),
        }
    }
}

/// An I/O stream that stops with an error when its operation is cancelled
/// (an `io::copy` of a big file ends at once).
pub struct Stoppable<T> {
    inner: T,
    cancel: Cancel,
}

impl<T: Read> Read for Stoppable<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.cancel.check()?;
        self.inner.read(buf)
    }
}

impl<T: velarx_content::layer::holes::HoleWrite> velarx_content::layer::holes::HoleWrite
    for Stoppable<T>
{
    fn hole(&mut self, len: u64) -> io::Result<()> {
        self.cancel.check()?;
        self.inner.hole(len)
    }
}

impl<T: Write> Write for Stoppable<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.cancel.check()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_stops_once_asked() {
        let (stop, cancel) = Cancel::new();
        let mut r = cancel.io(&b"abcdef"[..]);
        let mut buf = [0u8; 3];
        assert_eq!(r.read(&mut buf).unwrap(), 3);
        stop.send(true).unwrap();
        assert!(cancel.asked());
        let e = r.read(&mut buf).unwrap_err();
        assert_eq!(e.to_string(), "cancelled");
        assert_ne!(e.kind(), io::ErrorKind::Interrupted);
        let mut w = cancel.io(Vec::new());
        assert!(w.write_all(b"x").is_err());
    }

    #[tokio::test]
    async fn a_future_is_dropped_when_asked() {
        let (stop, cancel) = Cancel::new();
        assert_eq!(cancel.unless(async { 1 }).await, Some(1));
        stop.send(true).unwrap();
        assert_eq!(cancel.unless(std::future::pending::<()>()).await, None);
        assert_eq!(Cancel::default().unless(async { 2 }).await, Some(2));
    }

    #[tokio::test]
    async fn either_asker_stops_a_combined_cancel() {
        for first in [true, false] {
            let (a, ca) = Cancel::new();
            let (b, cb) = Cancel::new();
            let both = ca.or(&cb);
            assert!(!both.asked());
            // (an asker that is gone does not stop it)
            let (gone, cg) = Cancel::new();
            drop(gone);
            let both = both.or(&cg);
            let waiting = tokio::spawn({
                let mut both = both.clone();
                async move { both.wait().await }
            });
            if first { a.send(true) } else { b.send(true) }.unwrap();
            waiting.await.unwrap();
            assert!(both.asked());
            assert!(first == ca.asked() && first != cb.asked());
        }
    }
}
