// SPDX-License-Identifier: Apache-2.0
//! For the tests: what the code under test logs, captured per thread.
//!
//! The tests of a package run as threads of one process, and a test that
//! reads what is logged captures what its own thread logs.  One subscriber
//! is installed for the process, the first time a test captures: it writes
//! the events of a thread that captures into the sink of that thread and
//! ignores the others.

use std::cell::RefCell;
use std::sync::{Arc, Mutex, Once};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

thread_local! {
    /// What the thread captures: the level and the sink.
    static CURRENT: RefCell<Option<(tracing::Level, Sink)>> = const { RefCell::new(None) };
}

/// The writer of the subscriber: the sink of the thread that logs.
struct Route;

impl std::io::Write for Route {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        CURRENT.with(|c| match &*c.borrow() {
            Some((_, sink)) => sink.clone().write(b),
            None => Ok(b.len()),
        })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Route {
    type Writer = Route;
    fn make_writer(&'a self) -> Route {
        Route
    }
}

/// The events of the thread that captures, up to its level.  Whether one is
/// wanted is asked each time (it depends on the thread), also by
/// `tracing::enabled!`.
struct OfTheThread;

impl<S: tracing::Subscriber> Layer<S> for OfTheThread {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(
        &self,
        meta: &tracing::Metadata<'_>,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        CURRENT.with(|c| {
            c.borrow()
                .as_ref()
                .is_some_and(|(level, _)| meta.level() <= level)
        })
    }
}

fn install() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(Route);
        tracing_subscriber::registry()
            .with(OfTheThread)
            .with(layer)
            .try_init()
            .expect("the process has a subscriber of its own besides the capture of the log");
    });
}

/// What the thread logs while this lives, at `level` and below; the lines
/// have no time and no target.
pub struct Captured {
    sink: Sink,
    before: Option<(tracing::Level, Sink)>,
}

/// Capture what the current thread logs, until the result is dropped.
pub fn capture(level: tracing::Level) -> Captured {
    install();
    let sink = Sink::default();
    let before = CURRENT.with(|c| c.borrow_mut().replace((level, sink.clone())));
    Captured { sink, before }
}

impl Drop for Captured {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = self.before.take());
    }
}

impl Captured {
    /// Everything logged so far.
    pub fn text(&self) -> String {
        String::from_utf8(
            self.sink
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        )
        .unwrap()
    }

    /// The lines logged so far.
    pub fn lines(&self) -> Vec<String> {
        self.text().lines().map(str::to_string).collect()
    }
}

/// What `f` logs at `level` and below, as text.
pub fn logged_by(level: tracing::Level, f: impl FnOnce()) -> String {
    let c = capture(level);
    f();
    c.text()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() {
        tracing::debug!("passed");
    }

    /// What another thread logs is not captured, whatever call site it
    /// reaches first.
    #[test]
    fn only_the_thread_that_captures_is_captured() {
        let c = capture(tracing::Level::DEBUG);
        std::thread::spawn(event).join().unwrap();
        assert_eq!(c.text(), "");
        event();
        assert!(c.text().contains("passed"), "{:?}", c.text());
        let quiet = capture(tracing::Level::INFO);
        event();
        assert_eq!(quiet.text(), "");
        drop(quiet);
        event();
        assert_eq!(c.text().matches("passed").count(), 2);
    }
}
