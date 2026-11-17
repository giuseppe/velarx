// SPDX-License-Identifier: Apache-2.0
//! Progress of the operations that move bytes through a reader, a writer or
//! a loop (the layer of a commit, the regeneration and upload of a layer for
//! a push): the same events as a pull, sent at a bounded rate by the code
//! that moves the bytes, and never waited for.

use super::{ProgressSink, TransferProgress};
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use velarx_content::layer::holes::HoleRead;
use velarx_types::digest::Digest;

/// The least time between two reports of the bytes of a blob.
const PERIOD: Duration = Duration::from_millis(100);

/// What the status of a warning starts with.
pub const WARNING: &str = "warning: ";

/// What a report of progress is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// The image as a whole
    Image,
    /// A blob of the image
    Digest(Digest),
    /// A layer the operation makes, which has no digest yet
    Made(&'static str),
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Image => Ok(()),
            Self::Digest(d) => d.fmt(f),
            Self::Made(label) => f.write_str(label),
        }
    }
}

impl TransferProgress {
    /// The state of the blob `subject`; `total` is 0 when it is not known.
    pub fn blob(subject: Subject, status: &str, current: u64, total: u64, complete: bool) -> Self {
        Self {
            subject,
            status: status.to_string(),
            current_bytes: current,
            total_bytes: total,
            complete,
        }
    }

    /// Something the person who pulls should know, for the image as a whole:
    /// a line of its own, not a state (`warning: ` and the text).
    pub fn warning(text: &str) -> Self {
        Self::phase(&format!("{WARNING}{text}"))
    }

    /// What the operation does now, for the image as a whole.
    pub fn phase(status: &str) -> Self {
        Self::blob(Subject::Image, status, 0, 0, false)
    }
}

/// The reports of one blob: `add` and `set` send the bytes done at most once
/// per [`PERIOD`], `end` sends the last state.
pub struct Meter {
    tx: Option<mpsc::Sender<TransferProgress>>,
    subject: Subject,
    status: &'static str,
    total: u64,
    current: u64,
    last: Instant,
}

impl Meter {
    pub fn new(
        tx: Option<mpsc::Sender<TransferProgress>>,
        subject: Subject,
        status: &'static str,
        total: u64,
    ) -> Self {
        let meter = Self {
            tx,
            subject,
            status,
            total,
            current: 0,
            last: Instant::now(),
        };
        meter.send(false);
        meter
    }

    fn send(&self, complete: bool) {
        if let Some(tx) = &self.tx {
            tx.report(TransferProgress::blob(
                self.subject.clone(),
                if complete { "complete" } else { self.status },
                self.current,
                self.total,
                complete,
            ));
        }
    }

    fn tick(&mut self) {
        if self.tx.is_some() && self.last.elapsed() >= PERIOD {
            self.last = Instant::now();
            self.send(false);
        }
    }

    pub fn add(&mut self, n: u64) {
        self.current += n;
        self.tick();
    }

    pub fn set(&mut self, current: u64) {
        self.current = current;
        self.tick();
    }

    /// The last state: `total` is what it came to, when it was not known.
    /// `complete`: the blob is done, not only this step of it.
    pub fn end(mut self, complete: bool) {
        if self.total == 0 {
            self.total = self.current;
        } else if complete {
            self.current = self.total;
        }
        self.send(complete);
    }
}

/// A reader or a writer that counts what goes through it.
pub struct Counting<T> {
    inner: T,
    meter: Meter,
}

impl<T> Counting<T> {
    pub fn new(inner: T, meter: Meter) -> Self {
        Self { inner, meter }
    }

    pub fn finish(self, complete: bool) {
        self.meter.end(complete);
    }
}

impl<T: Read> Read for Counting<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.meter.add(n as u64);
        Ok(n)
    }
}

impl<T: HoleRead> HoleRead for Counting<T> {
    fn hole(&mut self, max: u64) -> std::io::Result<u64> {
        let n = self.inner.hole(max)?;
        self.meter.add(n);
        Ok(n)
    }
}

impl<T: Write> Write for Counting<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.meter.add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_meter_reports_the_start_and_the_end_and_little_between() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut meter = Meter::new(Some(tx), Subject::Made("layer"), "uploading", 1000);
        for _ in 0..100 {
            meter.add(10);
        }
        meter.end(true);
        let mut events = Vec::new();
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        let first = events.first().unwrap();
        assert_eq!(
            (
                first.status.as_str(),
                first.current_bytes,
                first.total_bytes
            ),
            ("uploading", 0, 1000)
        );
        let last = events.last().unwrap();
        assert_eq!(
            (last.status.as_str(), last.current_bytes, last.total_bytes),
            ("complete", 1000, 1000)
        );
        assert!(last.complete);
        assert!(events.len() <= 3, "{} events", events.len());
    }

    /// The `layer` of a report is the text it always was: empty for the
    /// image, the digest of a blob, the label of a layer being made.
    #[test]
    fn a_subject_reads_as_the_layer_of_the_report() {
        let d = Digest::of(velarx_types::digest::Algorithm::Sha256, b"x");
        assert_eq!(Subject::Image.to_string(), "");
        assert_eq!(Subject::Digest(d).to_string(), d.to_string());
        assert!(Subject::Digest(d).to_string().starts_with("sha256:"));
        assert_eq!(Subject::Made("new layer").to_string(), "new layer");
        assert_eq!(TransferProgress::phase("resolving").subject.to_string(), "");
    }

    #[test]
    fn an_unknown_total_is_what_went_through() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut reader = Counting::new(
            std::io::Cursor::new(vec![0u8; 5000]),
            Meter::new(Some(tx), Subject::Made("layer"), "compressing", 0),
        );
        std::io::copy(&mut reader, &mut std::io::sink()).unwrap();
        reader.finish(true);
        let mut last = None;
        while let Ok(e) = rx.try_recv() {
            last = Some(e);
        }
        let last = last.unwrap();
        assert_eq!((last.current_bytes, last.total_bytes), (5000, 5000));
    }

    #[test]
    fn a_meter_without_a_receiver_costs_nothing_and_a_full_channel_does_not_block() {
        let mut meter = Meter::new(None, Subject::Made("x"), "uploading", 10);
        meter.add(5);
        meter.end(true);
        let (tx, _rx) = mpsc::channel(1);
        let mut meter = Meter::new(Some(tx), Subject::Made("x"), "uploading", 10);
        // (the meter reports once per PERIOD of the clock: it passes)
        std::thread::sleep(PERIOD);
        meter.add(1);
        std::thread::sleep(PERIOD);
        meter.add(1);
        meter.end(true);
    }
}
