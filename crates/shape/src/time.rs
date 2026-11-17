// SPDX-License-Identifier: Apache-2.0
//! The times of the documents: the records carry nanoseconds since the
//! epoch, podman's and Docker's documents RFC 3339 text.

use velarx_proto::time::{civil, format_rfc3339, Fraction};

/// RFC 3339 in UTC with the fraction of a second in groups of three digits,
/// as many as it needs (`2026-01-02T03:04:05.120Z`); Go's zero time,
/// `0001-01-01T00:00:00Z`, for 0 (a time that is not set).
pub fn rfc3339(ns: i64) -> String {
    if ns <= 0 {
        return "0001-01-01T00:00:00Z".to_string();
    }
    format_rfc3339(ns, Fraction::Groups)
}

/// A time as Go's ANSIC layout writes it, in UTC: `Mon Jan  2 15:04:05
/// 2006`.
pub fn ansic(ns: i64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = ns.div_euclid(1_000_000_000);
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil(days);
    // (1970-01-01 was a Thursday)
    format!(
        "{} {} {d:>2} {:02}:{:02}:{:02} {y}",
        DAYS[(days + 4).rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// Now, in nanoseconds since the epoch (what a status that says how long
/// ago is told at).
pub fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_rfc3339_in_utc() {
        assert_eq!(rfc3339(0), "0001-01-01T00:00:00Z");
        assert_eq!(rfc3339(-5), "0001-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_000_000_000), "1970-01-01T00:00:01Z");
        assert_eq!(rfc3339(1_767_323_045_000_000_000), "2026-01-02T03:04:05Z");
        assert_eq!(
            rfc3339(1_767_323_045_120_000_000),
            "2026-01-02T03:04:05.120Z"
        );
        assert_eq!(
            rfc3339(1_767_323_045_000_001_000),
            "2026-01-02T03:04:05.000001Z"
        );
        assert_eq!(
            rfc3339(1_767_323_045_000_000_007),
            "2026-01-02T03:04:05.000000007Z"
        );
        // a leap day, the end of a year
        assert_eq!(rfc3339(951_782_400_000_000_000), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_735_689_599_000_000_000), "2024-12-31T23:59:59Z");
    }

    #[test]
    fn ansic_is_go_s() {
        assert_eq!(ansic(1_767_323_045_000_000_000), "Fri Jan  2 03:04:05 2026");
        assert_eq!(ansic(0), "Thu Jan  1 00:00:00 1970");
        assert_eq!(ansic(951_782_400_000_000_000), "Tue Feb 29 00:00:00 2000");
    }

    #[test]
    fn rfc3339_text_reads_back() {
        let now = 1_767_323_045_000_000_000;
        for ns in [951_782_400_000_000_000, 1_735_689_599_000_000_000, now + 7] {
            assert_eq!(velarx_proto::time::parse_rfc3339(&rfc3339(ns)), Some(ns));
        }
    }
}
