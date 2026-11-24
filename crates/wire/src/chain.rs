// SPDX-License-Identifier: Apache-2.0
//! The debug log of a chain of trust (`--log-level=debug`): one line per
//! link, written where the link is checked, with the digest that vouches and
//! the digest it vouches for (`FROM -> TO`, or `A == B` for a digest compared
//! with a measure), a closing `COMPLETE` line with the digests from the root
//! to the EROFS image of each layer when every link held, or `BROKEN <link>
//! expected X found Y` at the link that did not and no `COMPLETE`.  The
//! engine checks the first links and the monitor, which the engine hands the
//! count to (`Chain::resume`), the last ones.
//!
//! Nothing is formatted when the log is not at debug level.

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;

const RUNNING: u8 = 0;
const BROKEN: u8 = 1;
const COMPLETE: u8 = 2;

/// A link that did not hold: its name, what it expected, what it found.
pub type Broken = (String, String, String);

/// A layer measured: the layer (from 1), the digest of its blob and the
/// fs-verity digest of its EROFS image.
pub type Measured = (usize, String, String);

/// The chain of one image of a start: `total` links in all, the root file
/// system or an image mounted in the container (`scope`: empty for the
/// first, `image mount /dest: ` for the other).
pub struct Chain {
    scope: String,
    total: usize,
    on: bool,
    done: AtomicUsize,
    state: AtomicU8,
    /// The digests from the root to the configuration, in order, for the
    /// last line.
    trail: Mutex<Vec<String>>,
    /// The layers measured: the layer (from 1), the digest of its blob and
    /// the fs-verity digest of its EROFS image, in the order measured (the
    /// monitor measures the top one first).
    layers: Mutex<Vec<Measured>>,
    /// The layers (up to this one, from 2) whose files the FUSE file system
    /// checks, not the overlay: 0 when the overlay checks every layer's.
    fuse_layers: AtomicUsize,
    /// The layers (from 1) held to the digest the engine recorded when it
    /// made their EROFS images, where the manifest states none of ours.
    record: Mutex<Vec<usize>>,
    /// The lines kept instead of said while the chain is held back
    /// (`held_back`): `None` once it speaks.
    held: Mutex<Option<Vec<String>>>,
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chain")
            .field("scope", &self.scope)
            .field("total", &self.total)
            .field("done", &self.done())
            .finish()
    }
}

impl Chain {
    pub fn new(scope: &str, total: usize) -> Self {
        Self::build(scope, total, tracing::enabled!(tracing::Level::DEBUG))
    }

    /// A chain that says nothing (a check that is not a start's).
    pub fn off() -> Self {
        Self::build("", 0, false)
    }

    fn build(scope: &str, total: usize, on: bool) -> Self {
        Chain {
            scope: scope.to_string(),
            total,
            on,
            done: AtomicUsize::new(0),
            state: AtomicU8::new(RUNNING),
            trail: Mutex::new(Vec::new()),
            layers: Mutex::new(Vec::new()),
            fuse_layers: AtomicUsize::new(0),
            record: Mutex::new(Vec::new()),
            held: Mutex::new(None),
        }
    }

    /// This chain with its lines kept, not said, until [`Chain::speak`]: a
    /// check that may fail without being the one the log is about.
    pub fn held_back(self) -> Self {
        if self.on {
            *self.held.lock().unwrap_or_else(|e| e.into_inner()) = Some(Vec::new());
        }
        self
    }

    /// Say the lines kept, and every later line as it comes.
    pub fn speak(&self) {
        let kept = self.held.lock().unwrap_or_else(|e| e.into_inner()).take();
        for line in kept.into_iter().flatten() {
            self.say(format_args!("{line}"));
        }
    }

    /// The chain from the link after `done` links held, whose digests were
    /// `trail` (the engine's, which gave them with the configuration of the
    /// monitor).
    pub fn resume(
        scope: &str,
        total: usize,
        done: usize,
        trail: &[String],
        layers: &[Measured],
    ) -> Self {
        let chain = Self::new(scope, total);
        chain.done.store(done, Ordering::Relaxed);
        *chain.trail.lock().unwrap_or_else(|e| e.into_inner()) = trail.to_vec();
        *chain.layers.lock().unwrap_or_else(|e| e.into_inner()) = layers.to_vec();
        chain
    }

    /// Layer `n` (from 1) is held to the digest the engine recorded, which
    /// the line of its measure says.
    pub fn from_record(&self, n: usize) {
        self.record
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(n);
    }

    /// The layers held to the record.
    pub fn records(&self) -> Vec<usize> {
        self.record
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// A line of the chain in the debug log: the one place that logs, for
    /// every kind of line.
    #[inline(never)]
    fn say(&self, line: std::fmt::Arguments<'_>) {
        if let Some(kept) = self.held.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            kept.push(line.to_string());
            return;
        }
        tracing::debug!("verity chain: {}{line}", self.scope);
    }

    pub fn is_on(&self) -> bool {
        self.on
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// How many links held.
    pub fn done(&self) -> usize {
        self.done.load(Ordering::Relaxed)
    }

    /// The digests from the root so far, in order.
    pub fn trail(&self) -> Vec<String> {
        self.trail.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Add `digest` to the digests from the root, for the line that closes
    /// the chain.
    pub fn add(&self, digest: impl FnOnce() -> String) {
        if self.on {
            self.trail
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(digest());
        }
    }

    /// Layer `n` (from 1), whose blob has the digest `blob`, measured as
    /// `erofs`.
    pub fn measured(&self, n: usize, blob: impl FnOnce() -> (String, String)) {
        if self.on {
            let (blob, erofs) = blob();
            self.layers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((n, blob, erofs));
        }
    }

    /// The layers measured so far, in the order they were.
    pub fn layers(&self) -> Vec<Measured> {
        self.layers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The EROFS image of layer `n` (from 1) is not one of the digests
    /// `accepted`: it could not be opened, or measured as `found` (none: it
    /// has no fs-verity digest, or is not there).
    pub fn layer_broken(
        &self,
        n: usize,
        accepted: &[String],
        found: impl FnOnce() -> Option<String>,
    ) {
        self.broken(|| {
            (
                format!("layer {n} erofs fd"),
                accepted.join(","),
                found().unwrap_or_else(|| "none".to_string()),
            )
        })
    }

    /// Layer `n` (from 1), whose blob is `blob` and whose EROFS image the
    /// annotation of its descriptor (the record, with `from_record`) and the measure on the open image agree
    /// on (`erofs`): the link of the layer.
    pub fn layer_measured(&self, n: usize, blob: &str, erofs: &str) {
        let from = match self.records().contains(&n) {
            true => "record",
            false => "annotation",
        };
        self.link(|| format!("layer {n} {from} {erofs} == erofs fd {erofs}"));
        self.measured(n, || (blob.to_string(), erofs.to_string()));
    }

    /// The last link of the chain of an enforced image, once its overlay is
    /// mounted: the EROFS images measured (the top one first, as the overlay
    /// lists them) to the overlay, which checks the files only with
    /// `verity=require`: any other value breaks the chain.
    pub fn overlay(&self, verity: &str) {
        if !self.on {
            return;
        }
        match verity {
            "require" => self.link(|| {
                let erofs = self.erofs().join(",");
                match self.fuse_layers() {
                    0 => format!("erofs fd {erofs} -> overlay verity=require"),
                    // (the overlay checks the stubs of the lowest layer, the
                    // FUSE file system the files it serves of the others)
                    2 => format!(
                        "erofs fd {erofs} -> overlay verity=require (files of layer 1), \
                         fuse verity=require (files of layer 2)"
                    ),
                    n => format!(
                        "erofs fd {erofs} -> overlay verity=require (files of layer 1), \
                         fuse verity=require (files of layers 2-{n})"
                    ),
                }
            }),
            _ => self.broken(|| {
                (
                    "overlay".into(),
                    "verity=require".into(),
                    format!("verity={verity}"),
                )
            }),
        }
    }

    /// The files of the layers 2 to `last` are checked by the FUSE file
    /// system (the overlay follows the stubs of the lowest layer only).
    pub fn files_by_fuse(&self, last: usize) {
        self.fuse_layers.store(last, Ordering::Relaxed);
    }

    /// The last layer whose files the FUSE file system checks (from 2), 0
    /// when it checks none.
    pub fn fuse_layers(&self) -> usize {
        self.fuse_layers.load(Ordering::Relaxed)
    }

    /// The fs-verity digests measured, the top layer first (as an overlay
    /// lists its layers).
    pub fn erofs(&self) -> Vec<String> {
        let mut layers = self
            .layers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        layers.sort_by_key(|l| std::cmp::Reverse(l.0));
        layers.into_iter().map(|l| l.2).collect()
    }

    /// A link that held: `FROM -> TO`, with the digests.
    pub fn link(&self, line: impl FnOnce() -> String) {
        self.done.fetch_add(1, Ordering::Relaxed);
        if self.on {
            self.say(format_args!("{}", line()));
        }
    }

    /// The link after the last that held did not: the first call says it,
    /// the rest (the error on its way up) do not.
    pub fn broken(&self, what: impl FnOnce() -> Broken) {
        if self.on
            && self
                .state
                .compare_exchange(RUNNING, BROKEN, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let (link, expected, found) = what();
            self.say(format_args!(
                "BROKEN {link} expected {expected} found {found}"
            ));
        }
    }

    /// Every link held: the digests from the root, then, for each layer
    /// from the lowest, its blob and the digest its EROFS image measured.
    /// Nothing if one did not; a chain that has not said all its links is
    /// broken, not complete.
    pub fn complete(&self) {
        if self.on && self.done() != self.total {
            return self.broken(|| {
                (
                    "links".to_string(),
                    self.total.to_string(),
                    self.done().to_string(),
                )
            });
        }
        if self.on
            && self
                .state
                .compare_exchange(RUNNING, COMPLETE, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let mut layers = self
                .layers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            layers.sort_by_key(|l| l.0);
            let trail = self.trail();
            let parts: Vec<String> = (!trail.is_empty())
                .then(|| trail.join(" -> "))
                .into_iter()
                .chain(
                    layers
                        .iter()
                        .map(|(_, blob, erofs)| format!("{blob} -> {erofs}")),
                )
                .collect();
            self.say(format_args!("COMPLETE {}", parts.join(" ; ")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `f` logs at `level`, a line each, without the time and level.
    fn logged(level: tracing::Level, f: impl FnOnce()) -> Vec<String> {
        let text = crate::logcapture::logged_by(level, f);
        text.lines()
            .map(|l| {
                l.split_once(' ')
                    .map_or(l, |(_, rest)| rest)
                    .trim()
                    .to_string()
            })
            .collect()
    }

    /// The line of a layer measured says what the digest came from.
    #[test]
    fn a_layer_says_whether_its_digest_is_the_annotation_or_the_record() {
        let lines = logged(tracing::Level::DEBUG, || {
            let c = Chain::new("", 2);
            c.from_record(2);
            c.layer_measured(1, "sha256:b1", "sha256:e1");
            c.layer_measured(2, "sha256:b2", "sha256:e2");
        });
        assert_eq!(
            lines,
            [
                "verity chain: layer 1 annotation sha256:e1 == erofs fd sha256:e1",
                "verity chain: layer 2 record sha256:e2 == erofs fd sha256:e2",
            ]
        );
    }

    #[test]
    fn a_chain_held_back_says_its_lines_when_it_speaks() {
        let lines = logged(tracing::Level::DEBUG, || {
            let c = Chain::new("", 2).held_back();
            c.link(|| "one".into());
            c.link(|| "two".into());
            c.speak();
            c.broken(|| ("x".into(), "a".into(), "b".into()));
        });
        assert_eq!(
            lines,
            [
                "verity chain: one",
                "verity chain: two",
                "verity chain: BROKEN x expected a found b"
            ]
        );
        let lines = logged(tracing::Level::DEBUG, || {
            let c = Chain::new("", 1).held_back();
            c.link(|| "never said".into());
        });
        assert!(lines.is_empty(), "{lines:?}");
    }

    #[test]
    fn each_link_is_a_line_and_the_end_lists_the_digests_by_layer() {
        let lines = logged(tracing::Level::DEBUG, || {
            let c = Chain::new("", 5);
            c.link(|| "root typed sha256:aa".into());
            c.add(|| "sha256:aa".into());
            c.link(|| "sha256:aa manifest -> sha256:cc config".into());
            c.add(|| "sha256:cc".into());
            c.link(|| {
                "sha256:aa manifest -> sha256:l1 layer 1 blob -> sha256:e1 annotation".into()
            });
            c.link(|| "layer 1 annotation sha256:e1 == erofs fd sha256:e1".into());
            c.measured(1, || ("sha256:l1".into(), "sha256:e1".into()));
            c.link(|| "erofs fd sha256:e1 -> overlay verity=require".into());
            c.complete();
        });
        assert_eq!(
            lines,
            [
                "verity chain: root typed sha256:aa",
                "verity chain: sha256:aa manifest -> sha256:cc config",
                "verity chain: sha256:aa manifest -> sha256:l1 layer 1 blob -> sha256:e1 annotation",
                "verity chain: layer 1 annotation sha256:e1 == erofs fd sha256:e1",
                "verity chain: erofs fd sha256:e1 -> overlay verity=require",
                "verity chain: COMPLETE sha256:aa -> sha256:cc ; sha256:l1 -> sha256:e1",
            ]
        );
    }

    #[test]
    fn a_broken_link_is_named_once_and_nothing_completes() {
        let lines = logged(tracing::Level::DEBUG, || {
            let c = Chain::new("image mount /img: ", 4);
            c.link(|| "root typed sha256:aa".into());
            c.broken(|| ("manifest".into(), "sha256:aa".into(), "sha256:bb".into()));
            c.broken(|| ("again".into(), "x".into(), "y".into()));
            c.complete();
        });
        assert_eq!(
            lines,
            [
                "verity chain: image mount /img: root typed sha256:aa",
                "verity chain: image mount /img: BROKEN manifest expected sha256:aa found sha256:bb",
            ]
        );
    }

    #[test]
    fn the_monitor_goes_on_where_the_engine_stopped() {
        let lines = logged(tracing::Level::DEBUG, || {
            let c = Chain::resume("", 5, 3, &["sha256:aa".into(), "sha256:cc".into()], &[]);
            // (in any order: the overlay lists the top one first)
            c.measured(1, || ("sha256:l1".into(), "sha256:e1".into()));
            c.link(|| "layer 1".into());
            c.measured(2, || ("sha256:l2".into(), "sha256:e2".into()));
            c.link(|| "layer 2".into());
            assert_eq!(c.erofs(), ["sha256:e2", "sha256:e1"]);
            c.complete();
        });
        assert_eq!(
            lines[2],
            "verity chain: COMPLETE sha256:aa -> sha256:cc ; sha256:l1 -> sha256:e1 ; sha256:l2 -> sha256:e2"
        );
    }

    #[test]
    fn the_layers_measured_by_the_engine_come_with_the_chain_to_the_monitor() {
        let lines = logged(tracing::Level::DEBUG, || {
            let engine = Chain::new("", 4);
            engine.link(|| "root typed sha256:aa".into());
            engine.add(|| "sha256:aa".into());
            // (the top layer first, as the driver mounts them)
            engine.layer_measured(2, "sha256:l2", "sha256:e2");
            engine.layer_measured(1, "sha256:l1", "sha256:e1");
            let monitor = Chain::resume(
                "",
                engine.total(),
                engine.done(),
                &engine.trail(),
                &engine.layers(),
            );
            monitor.overlay("require");
            monitor.complete();
        });
        assert_eq!(
            lines,
            [
                "verity chain: root typed sha256:aa",
                "verity chain: layer 2 annotation sha256:e2 == erofs fd sha256:e2",
                "verity chain: layer 1 annotation sha256:e1 == erofs fd sha256:e1",
                "verity chain: erofs fd sha256:e2,sha256:e1 -> overlay verity=require",
                "verity chain: COMPLETE sha256:aa ; sha256:l1 -> sha256:e1 ; sha256:l2 -> sha256:e2",
            ]
        );
    }

    #[test]
    fn an_overlay_that_is_not_require_breaks_the_chain() {
        let lines = logged(tracing::Level::DEBUG, || {
            let c = Chain::new("", 1);
            c.overlay("on");
            c.complete();
        });
        assert_eq!(
            lines,
            ["verity chain: BROKEN overlay expected verity=require found verity=on"]
        );
    }

    #[test]
    fn a_chain_with_a_link_missing_is_not_complete() {
        let lines = logged(tracing::Level::DEBUG, || {
            let c = Chain::new("", 3);
            c.link(|| "root typed sha256:aa".into());
            c.link(|| "sha256:aa manifest -> sha256:cc config".into());
            c.complete();
        });
        assert_eq!(
            lines,
            [
                "verity chain: root typed sha256:aa",
                "verity chain: sha256:aa manifest -> sha256:cc config",
                "verity chain: BROKEN links expected 3 found 2",
            ]
        );
    }

    #[test]
    fn nothing_is_formatted_below_debug() {
        let lines = logged(tracing::Level::INFO, || {
            let c = Chain::new("", 1);
            c.link(|| unreachable!("formatted"));
            c.add(|| unreachable!("formatted"));
            c.measured(1, || unreachable!("formatted"));
            c.broken(|| unreachable!("formatted"));
            c.complete();
            let off = Chain::off();
            off.link(|| unreachable!("formatted"));
        });
        assert!(lines.is_empty(), "{lines:?}");
    }
}
