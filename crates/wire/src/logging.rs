// SPDX-License-Identifier: Apache-2.0
//! Log output setup shared by the CLI and the daemon.

use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// What is always quieter than the level asked: FUSE's chatter.
const QUIET: &str = "fuser=off,velarx_fuse=warn";

/// Start logging at `level` (or `RUST_LOG`: a level or `target=level,...`);
/// `format` is `text` or `json`.
pub fn init(level: &str, format: &str) {
    init_quieter(level, format, "");
}

/// [`init`], with `quiet` (`target=level,...`) quieter than the level asked
/// too: what a program knows its dependencies say that is no fault.
pub fn init_quieter(level: &str, format: &str, quiet: &str) {
    let quiet = if quiet.is_empty() {
        QUIET.to_string()
    } else {
        format!("{QUIET},{quiet}")
    };
    let mut problems = Vec::new();
    let from_env = std::env::var("RUST_LOG").ok().filter(|v| !v.is_empty());
    let filter = from_env
        .as_deref()
        .and_then(|v| {
            let parsed = format!("{v},{quiet}").parse::<Targets>();
            parsed
                .map_err(|e| problems.push(format!("RUST_LOG `{v}` is not a filter: {e}")))
                .ok()
        })
        .or_else(|| {
            let parsed = format!("{level},{quiet}").parse::<Targets>();
            parsed
                .map_err(|e| problems.push(format!("the log level `{level}` is not a filter: {e}")))
                .ok()
        })
        .unwrap_or_else(|| {
            format!("info,{quiet}")
                .parse::<Targets>()
                .unwrap_or_default()
        });

    // (on standard error, as podman's: standard output is the command's
    // answer, and the container's with `--log-driver=passthrough`; colours
    // only for a terminal)
    if format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::stderr)
            .finish()
            .with(filter)
            .init();
    } else {
        use std::io::IsTerminal;
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::stderr)
            .with_ansi(std::io::stderr().is_terminal())
            .finish()
            .with(filter)
            .init();
    }
    for problem in problems {
        tracing::error!("{problem}");
    }
}

#[cfg(test)]
mod tests {
    /// Names of images, references and texts of registries end up in logs:
    /// an escape sequence in one must not act on the terminal that shows
    /// them.  tracing-subscriber escapes the control characters of
    /// the fields and of the message (since 0.3.20); this keeps it so.
    #[test]
    fn control_characters_of_fields_are_escaped() {
        let out = crate::logcapture::logged_by(tracing::Level::INFO, || {
            let name = "evil\x1b]0;owned\x07/img";
            tracing::info!(image = name, "Pulling {name}");
        });
        assert!(!out.contains('\x1b') && !out.contains('\x07'), "{out:?}");
        assert!(out.contains("Pulling evil"), "{out:?}");
        // the line still ends as a line
        assert!(out.ends_with('\n'));
    }
}
