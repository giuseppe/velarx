// SPDX-License-Identifier: Apache-2.0
//! How fast a body must keep coming (the bodies of the HTTP client check it).
//!
//! The timeout of a read restarts with every byte: a server that sends one
//! now and then keeps a download open for ever.  A body fails when,
//! over a stretch of time spent waiting for the server, it brought fewer
//! bytes per second than the minimum (`[pull] min_speed_kib` and
//! `min_speed_secs`).  Only the waiting counts: a consumer that is slow to
//! take the bytes does not make the server slow.

use std::time::Duration;

/// The least a download must bring: `bytes_per_sec` on average over
/// `window` of waiting (0 bytes or a window of 0: no check).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Speed {
    pub bytes_per_sec: u64,
    pub window: Duration,
}

impl Speed {
    /// A window of 0 seconds is no check: the average over no time is
    /// that of the last chunk, and a few bytes after a short wait would
    /// fail a download that is fast.
    pub fn new(bytes_per_sec: u64, window_secs: u64) -> Self {
        Self {
            bytes_per_sec: if window_secs == 0 { 0 } else { bytes_per_sec },
            window: Duration::from_secs(window_secs),
        }
    }
}

impl Default for Speed {
    fn default() -> Self {
        Self::new(1024, 120)
    }
}
