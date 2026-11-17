// SPDX-License-Identifier: Apache-2.0
//! What a long operation shows while it runs: one bar per blob (a layer
//! pulled, pushed, compressed...) with the bytes done, the total and the
//! rate where the total is known, a spinner where it is not, and the steps
//! of a build as lines above them.  On a terminal the bars are redrawn; on
//! anything else (a pipe, a file, CI) there are plain lines on the standard
//! error, one when a blob starts a new stage, without escape codes or
//! carriage returns.  The events are those of a pull, whoever sends them.

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::io::Write;
use velarx_proto::workload::{TransferProgress, TransferStatus};

/// Format bytes as human-readable string for progress bars
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Whether the progress goes to a terminal.
pub fn on_terminal() -> bool {
    std::io::IsTerminal::is_terminal(&std::io::stderr())
}

/// The first 12 hex digits of a digest, or the name of a blob without one.
fn short(layer: &str) -> &str {
    let id = velarx_shape::without_algorithm(layer);
    id.get(..12).unwrap_or(id)
}

fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// What the renderer takes of a progress: the blob, the word of what it
/// does now, the bytes.
struct Step {
    layer: String,
    status: String,
    current: u64,
    total: u64,
}

impl Step {
    fn of(p: &TransferProgress) -> Self {
        let status = match p.status {
            TransferStatus::Downloading => "downloading".to_string(),
            TransferStatus::Exists => "exists".to_string(),
            TransferStatus::Complete => "complete".to_string(),
            TransferStatus::Phase => p.message.clone(),
            TransferStatus::Warning => format!("warning: {}", p.message),
        };
        Self {
            layer: p.layer.clone(),
            status,
            current: p.current_bytes,
            total: p.total_bytes,
        }
    }
}

pub struct Renderer {
    show: Show,
}

enum Show {
    Bars(Box<Bars>),
    Lines(Lines),
    /// `--quiet`
    Silent,
}

impl Renderer {
    /// Bars on a terminal, lines elsewhere.
    pub fn new() -> Self {
        Self::on(on_terminal())
    }

    pub fn on(terminal: bool) -> Self {
        Self {
            show: if terminal {
                Show::Bars(Box::new(Bars::new()))
            } else {
                Show::Lines(Lines::new(Box::new(std::io::stderr())))
            },
        }
    }

    /// Nothing shown (`--quiet`).
    pub fn silent() -> Self {
        Self { show: Show::Silent }
    }

    /// Lines to `out`, whatever it is.
    pub fn lines_to(out: Box<dyn Write>) -> Self {
        Self {
            show: Show::Lines(Lines::new(out)),
        }
    }

    pub fn event(&mut self, p: &TransferProgress) {
        let step = Step::of(p);
        match &mut self.show {
            Show::Bars(b) => b.event(&step),
            Show::Lines(l) => l.event(&step),
            // (a warning is shown with --quiet too, as podman's are)
            Show::Silent if step.layer.is_empty() && p.status == TransferStatus::Warning => {
                self.print_err(&format!("{}\n", capitalised(&step.status)));
            }
            Show::Silent => {}
        }
    }

    /// A new step starts: the blobs of the last one are no longer shown.
    pub fn next_step(&mut self) {
        if let Show::Bars(b) = &mut self.show {
            b.clear();
        }
    }

    /// Print `text` on the standard output, between the redraws of the bars.
    pub fn print(&self, text: &str) {
        let out = || {
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(text.as_bytes());
            let _ = stdout.flush();
        };
        match &self.show {
            Show::Bars(b) => b.multi.suspend(out),
            Show::Lines(_) | Show::Silent => out(),
        }
    }

    /// Print `text` on the standard error, between the redraws of the bars.
    pub fn print_err(&self, text: &str) {
        let out = || {
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(text.as_bytes());
            let _ = stderr.flush();
        };
        match &self.show {
            Show::Bars(b) => b.multi.suspend(out),
            Show::Lines(_) | Show::Silent => out(),
        }
    }

    /// The operation is over: what is still going on is not.
    pub fn finish(&mut self) {
        if let Show::Bars(b) = &mut self.show {
            for bar in b.bars.values() {
                if !bar.is_finished() {
                    bar.finish();
                }
            }
        }
    }
}

/// A reader or a writer whose bytes are shown as the progress of the blob
/// `name`: an archive the client saves, loads or imports, whose total is
/// known when it comes from a file.  The bytes are shown at most every
/// 100 ms.
pub struct Transfer<'a, T> {
    inner: T,
    renderer: &'a mut Renderer,
    name: &'static str,
    status: &'static str,
    total: u64,
    done: u64,
    last: std::time::Instant,
}

impl<'a, T> Transfer<'a, T> {
    pub fn new(
        inner: T,
        renderer: &'a mut Renderer,
        name: &'static str,
        status: &'static str,
        total: u64,
    ) -> Self {
        let mut t = Self {
            inner,
            renderer,
            name,
            status,
            total,
            done: 0,
            last: std::time::Instant::now(),
        };
        t.show(status);
        t
    }

    fn show(&mut self, status: &str) {
        self.renderer.event(&TransferProgress {
            layer: self.name.to_string(),
            status: TransferStatus::Phase,
            message: status.to_string(),
            current_bytes: self.done,
            total_bytes: self.total,
            ..Default::default()
        });
    }

    fn count(&mut self, n: usize) {
        self.done += n as u64;
        if self.last.elapsed() >= std::time::Duration::from_millis(100) {
            self.last = std::time::Instant::now();
            self.show(self.status);
        }
    }

    /// All the bytes went through.
    pub fn finish(mut self) {
        self.total = self.done;
        self.show("complete");
    }
}

impl<T: std::io::Read> std::io::Read for Transfer<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count(n);
        Ok(n)
    }
}

impl<T: Write> Write for Transfer<'_, T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count(n);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}

/// A byte count or a state of a blob on its own line.
struct Lines {
    out: Box<dyn Write>,
    stage: HashMap<String, String>,
}

impl Lines {
    fn new(out: Box<dyn Write>) -> Self {
        Self {
            out,
            stage: HashMap::new(),
        }
    }

    fn event(&mut self, p: &Step) {
        if self.stage.get(&p.layer).is_some_and(|s| *s == p.status) {
            return;
        }
        self.stage.insert(p.layer.clone(), p.status.clone());
        let line = if p.layer.is_empty() {
            // (a pull ends with the sum of what it did)
            match p.status.as_str() {
                "complete" => return,
                status => capitalised(status),
            }
        } else {
            let size = |total: u64| match total {
                0 => String::new(),
                n => format!(" {}", format_bytes(n)),
            };
            match p.status.as_str() {
                // (the start of a stage that has a bar next)
                "checking" | "waiting" => return,
                "exists" | "already_exists" => format!("{} already exists", short(&p.layer)),
                "mounted" => format!("{} mounted", short(&p.layer)),
                status => format!("{} {status}{}", short(&p.layer), size(p.total)),
            }
        };
        let _ = writeln!(self.out, "{line}");
        let _ = self.out.flush();
    }
}

struct Bars {
    multi: MultiProgress,
    bars: HashMap<String, ProgressBar>,
    styles: Styles,
}

struct Styles {
    progress: ProgressStyle,
    spinner: ProgressStyle,
    finished: ProgressStyle,
}

impl Styles {
    fn new() -> Self {
        let bar = |template: &str, chars: &str| {
            ProgressStyle::default_bar()
                .template(template)
                .expect("Invalid progress style template")
                .progress_chars(chars)
        };
        Self {
            progress: bar(
                "{prefix:12} [{bar:40.cyan/blue}] {percent:>3}% {bytes}/{total_bytes} {bytes_per_sec} {msg}",
                "=>-",
            ),
            spinner: ProgressStyle::default_spinner()
                .template("{prefix:12} {spinner:.green} {msg}")
                .expect("Invalid spinner style template"),
            finished: bar("{prefix:12} [{bar:40.green/green}] 100% {msg}", "##-"),
        }
    }
}

impl Bars {
    fn new() -> Self {
        Self {
            multi: MultiProgress::new(),
            bars: HashMap::new(),
            styles: Styles::new(),
        }
    }

    fn clear(&mut self) {
        for bar in self.bars.values() {
            bar.finish_and_clear();
        }
        self.bars.clear();
    }

    fn event(&mut self, progress: &Step) {
        let status = progress.status.to_lowercase();
        if progress.layer.is_empty() && status.starts_with("warning: ") {
            let _ = self.multi.println(capitalised(&progress.status));
            return;
        }
        // (a pull ends with the sum of what it did)
        if progress.layer.is_empty() && status == "complete" {
            return;
        }
        let (multi, styles) = (&self.multi, &self.styles);
        let bar = self.bars.entry(progress.layer.clone()).or_insert_with(|| {
            let pb = multi
                .add(ProgressBar::new(progress.total.max(100)).with_style(styles.spinner.clone()));
            pb.set_prefix(
                if progress.layer.is_empty() {
                    "image"
                } else {
                    short(&progress.layer)
                }
                .to_string(),
            );
            pb.set_message("Starting...");
            pb
        });

        if progress.layer.is_empty() {
            bar.set_style(styles.spinner.clone());
            bar.set_message(capitalised(&progress.status));
        } else if matches!(
            status.as_str(),
            "downloading" | "uploading" | "compressing" | "extracting"
        ) {
            let label = capitalised(&status);
            if progress.total > 0 {
                bar.set_style(styles.progress.clone());
                bar.set_length(progress.total);
                bar.set_position(progress.current);
                bar.set_message(label);
            } else {
                bar.set_style(styles.spinner.clone());
                bar.set_message(format!("{label} {}", format_bytes(progress.current)));
            }
        } else if status == "waiting" || status == "checking" {
            bar.set_style(styles.spinner.clone());
            bar.set_message(capitalised(&status));
        } else if status == "already_exists" || status == "exists" {
            bar.set_style(styles.finished.clone());
            bar.finish_with_message("Already exists");
        } else if status == "mounted" {
            bar.set_style(styles.finished.clone());
            bar.finish_with_message("Mounted");
        } else if status == "complete" || status == "done" {
            if progress.total > 0 {
                bar.set_style(styles.progress.clone());
                bar.set_length(progress.total);
                bar.set_position(progress.total);
            }
            let size_msg = if progress.total > 0 {
                format!("Complete ({})", format_bytes(progress.total))
            } else {
                "Complete".to_string()
            };
            bar.set_style(styles.finished.clone());
            bar.finish_with_message(size_msg);
        } else if status == "cached" {
            bar.set_style(styles.finished.clone());
            bar.finish_with_message("Cached");
        } else {
            bar.set_message(progress.status.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A writer whose text the test reads back.
    #[derive(Clone, Default)]
    struct Text(Arc<Mutex<Vec<u8>>>);

    impl Write for Text {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn event(layer: &str, status: &str, current: u64, total: u64) -> TransferProgress {
        let (status, message) = match status {
            "downloading" => (TransferStatus::Downloading, String::new()),
            "exists" => (TransferStatus::Exists, String::new()),
            "complete" => (TransferStatus::Complete, String::new()),
            s => match s.strip_prefix("warning: ") {
                Some(w) => (TransferStatus::Warning, w.to_string()),
                None => (TransferStatus::Phase, s.to_string()),
            },
        };
        TransferProgress {
            layer: layer.into(),
            status,
            message,
            current_bytes: current,
            total_bytes: total,
            ..Default::default()
        }
    }

    fn lines(events: &[TransferProgress]) -> String {
        let text = Text::default();
        let mut r = Renderer::lines_to(Box::new(text.clone()));
        for e in events {
            r.event(e);
        }
        r.finish();
        let out = text.0.lock().unwrap().clone();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn lines_tell_the_stages_of_a_blob_once() {
        let d = format!("sha256:{}", "ab".repeat(32));
        let out = lines(&[
            event(&d, "checking", 0, 5_000_000),
            event(&d, "uploading", 0, 5_000_000),
            event(&d, "uploading", 1_000_000, 5_000_000),
            event(&d, "uploading", 4_000_000, 5_000_000),
            event(&d, "complete", 5_000_000, 5_000_000),
            event("sha256:cc", "exists", 9, 9),
            event("sha256:dd", "mounted", 9, 9),
            event("new layer", "compressing", 100, 0),
            event("new layer", "complete", 5000, 5000),
            event("", "pushing the manifest", 0, 0),
            event("", "complete", 0, 0),
        ]);
        assert_eq!(
            out,
            "abababababab uploading 4.8 MB\n\
             abababababab complete 4.8 MB\n\
             cc already exists\n\
             dd mounted\n\
             new layer compressing\n\
             new layer complete 4.9 KB\n\
             Pushing the manifest\n"
        );
    }

    #[test]
    fn a_warning_is_a_line_of_its_own() {
        let out = lines(&[
            event("", "pulling", 0, 0),
            event(
                "",
                "warning: quay.io: the cached authentication hint did not work",
                0,
                0,
            ),
            event("sha256:aa", "complete", 100, 100),
        ]);
        assert_eq!(
            out,
            "Pulling\nWarning: quay.io: the cached authentication hint did not work\naa complete 100 B\n"
        );
    }

    #[test]
    fn lines_have_no_escape_codes_or_carriage_returns() {
        let out = lines(&[
            event("sha256:aa", "downloading", 10, 100),
            event("sha256:aa", "complete", 100, 100),
        ]);
        assert!(!out.contains('\x1b') && !out.contains('\r'), "{out:?}");
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn a_transfer_shows_its_start_and_its_end() {
        let text = Text::default();
        let mut r = Renderer::lines_to(Box::new(text.clone()));
        let mut t = Transfer::new(
            std::io::Cursor::new(vec![1u8; 3000]),
            &mut r,
            "archive",
            "loading",
            0,
        );
        std::io::copy(&mut t, &mut std::io::sink()).unwrap();
        t.finish();
        let out = String::from_utf8(text.0.lock().unwrap().clone()).unwrap();
        assert_eq!(out, "archive loading\narchive complete 2.9 KB\n");
    }

    #[test]
    fn short_names_of_blobs() {
        assert_eq!(short(&format!("sha256:{}", "f".repeat(64))), "ffffffffffff");
        assert_eq!(short("new layer"), "new layer");
        assert_eq!(short("sha256:ab"), "ab");
        assert_eq!(capitalised("merging the layers"), "Merging the layers");
        assert_eq!(capitalised(""), "");
    }
}
