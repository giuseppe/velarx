// SPDX-License-Identifier: Apache-2.0
//! Time, size and name conversions shared by the handlers.

use chrono::DateTime;

/// RFC 3339, UTC, the fraction of a second in groups of three digits;
/// "0001-01-01T00:00:00Z" for 0.
pub fn time_string(ns: i64) -> String {
    velarx_shape::time::rfc3339(ns)
}

/// The time of a database record (RFC 3339) in nanoseconds since the epoch,
/// 0 when it does not parse.
pub fn record_time_ns(s: &str) -> i64 {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .and_then(|t| t.timestamp_nanos_opt())
        .unwrap_or(0)
}

/// The hex id from the 12 character or algorithm-prefixed forms.
pub fn strip_sha256(id: &str) -> &str {
    velarx_shape::without_algorithm(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(time_string(0), "0001-01-01T00:00:00Z");
        assert_eq!(
            time_string(1_700_000_000_000_000_000),
            "2023-11-14T22:13:20Z"
        );
        assert_eq!(
            time_string(1_700_000_000_123_000_000),
            "2023-11-14T22:13:20.123Z"
        );
    }
}
