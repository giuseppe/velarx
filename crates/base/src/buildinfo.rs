// SPDX-License-Identifier: Apache-2.0
//! What `--version` and the server information say of the build: the
//! commit and the time.
//!
//! The libraries must not know them at compile time: a value that changes
//! with every commit would recompile every package that reads it, and
//! everything above.  The binary packages (`crates/bin`, and one per
//! frontend) have the build script that finds them, and each binary calls
//! `set` first thing in `main`; code that runs in a process that is no
//! velarx binary (a test) gets `unknown`.

use std::sync::OnceLock;

const UNKNOWN: &str = "unknown";

static BUILD: OnceLock<(&'static str, &'static str)> = OnceLock::new();

/// Records the commit (`git describe`, or what a packager gave) and the time
/// (RFC 3339, UTC, or `unknown`) of this build.  Once per process.
pub fn set(commit: &'static str, time: &'static str) {
    assert!(
        BUILD.set((commit, time)).is_ok(),
        "the build information is set once, by main"
    );
}

/// The commit this program was built from.
pub fn commit() -> &'static str {
    BUILD.get().map_or(UNKNOWN, |b| b.0)
}

/// When it was built: RFC 3339 in UTC, or `unknown`.
pub fn time() -> &'static str {
    BUILD.get().map_or(UNKNOWN, |b| b.1)
}

/// `NAME VERSION (COMMIT)` when the program was run with `--version` or
/// `-V` and nothing else: the line it prints before it leaves.
pub fn version_line(name: &str, version: &str) -> Option<String> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next()?;
    (args.next().is_none() && (first == "--version" || first == "-V"))
        .then(|| format!("{name} {version} ({})", commit()))
}
