// SPDX-License-Identifier: Apache-2.0
//! Trace points across the processes of a command: with
//! `VELARX_TRACE_FILE` set, each point appends a line
//! `<pid> <CLOCK_MONOTONIC ns> <label>` to that file, which every process
//! (client, server, monitor, workers) shares, so the phases of a command
//! can be timed (`tests/perf/phases.py`).  Without it a point costs a
//! check of a cached flag.  std only: the client uses it.

use std::fs::File;
use std::io::Write;
use std::sync::OnceLock;

/// The variable that names the file.
pub const ENV: &str = "VELARX_TRACE_FILE";

fn file() -> Option<&'static File> {
    static FILE: OnceLock<Option<File>> = OnceLock::new();
    FILE.get_or_init(|| {
        let path = std::env::var_os(ENV).filter(|p| !p.is_empty())?;
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .ok()
    })
    .as_ref()
}

/// Nanoseconds of `CLOCK_MONOTONIC`, the clock of every process.
pub fn now_ns() -> u64 {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// The line of a point.
fn line(pid: u32, ns: u64, label: &str) -> String {
    // one line per point: the label cannot break it
    let label: String = label
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    format!("{pid} {ns} {label}\n")
}

/// Record the point `label` when tracing is on.
pub fn point(label: &str) {
    if let Some(mut f) = file() {
        // one write of a short line to a file opened for appending: the
        // lines of concurrent processes do not mix
        let _ = f.write_all(line(std::process::id(), now_ns(), label).as_bytes());
    }
}

/// Record the point whose label `label` builds, when tracing is on.
pub fn point_with(label: impl FnOnce() -> String) {
    if enabled() {
        point(&label());
    }
}

/// Whether tracing is on (to skip building a label).
pub fn enabled() -> bool {
    file().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_point_is_one_line() {
        assert_eq!(line(7, 42, "pull start"), "7 42 pull start\n");
        assert_eq!(line(7, 42, "a\nb"), "7 42 a b\n");
        let (a, b) = (now_ns(), now_ns());
        assert!(b >= a && a > 0);
    }
}
