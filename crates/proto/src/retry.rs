// SPDX-License-Identifier: Apache-2.0
//! How a transfer that fails on the way is tried again (`--retry`,
//! `--retry-delay`): the policy a pull, a push, an artifact transfer or a
//! build carries to the engine, which is the one that tries again.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The tries after the first and the time between them.
#[cfg_attr(feature = "proxy", derive(zlink::introspect::CustomType))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Retry {
    /// The tries after the first.
    pub count: u32,
    /// The time between the tries in milliseconds; none: 1 s (podman's).
    pub delay_ms: Option<u64>,
}

impl Retry {
    /// The time to wait before a try.
    pub fn wait(&self) -> Duration {
        match self.delay_ms {
            Some(ms) => Duration::from_millis(ms),
            None => Duration::from_secs(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_is_the_delay_or_a_second() {
        let fixed = Retry {
            count: 3,
            delay_ms: Some(250),
        };
        assert_eq!(fixed.wait(), Duration::from_millis(250));
        assert_eq!(Retry::default().wait(), Duration::from_secs(1));
    }
}
