// SPDX-License-Identifier: Apache-2.0
//! Durations as Go writes them.

/// A duration as Go's time.ParseDuration reads it: `1h30m`, `90s`,
/// `1.5h`, `300ms` (no sign).
pub fn parse_go_duration(s: &str) -> Option<std::time::Duration> {
    parse_duration(s, false)
}

/// [`parse_go_duration`] with the units `d` (a day) and `w` (a week) too,
/// which the times of the logs take (`--since 2d`).
pub fn parse_go_duration_days(s: &str) -> Option<std::time::Duration> {
    parse_duration(s, true)
}

fn parse_duration(s: &str, days: bool) -> Option<std::time::Duration> {
    if s == "0" {
        return Some(std::time::Duration::ZERO);
    }
    let mut rest = s;
    let mut total = 0f64;
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let num_len = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let n: f64 = rest[..num_len].parse().ok()?;
        rest = &rest[num_len..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let scale = match &rest[..unit_len] {
            "ns" => 1e-9,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" if days => 86_400.0,
            "w" if days => 604_800.0,
            _ => return None,
        };
        rest = &rest[unit_len..];
        total += n * scale;
    }
    std::time::Duration::try_from_secs_f64(total).ok()
}

/// [`parse_go_duration`] in nanoseconds (what the documents of the engine
/// carry).
pub fn parse_go_duration_ns(s: &str) -> Option<i64> {
    i64::try_from(parse_go_duration(s)?.as_nanos()).ok()
}

/// Go's `time.Duration.String()`: `6s`, `1m30s`, `1h0m0s`, `500ms`, `0s`.
pub fn go_duration_string(ns: i64) -> String {
    if ns == 0 {
        return "0s".into();
    }
    let (sign, u) = if ns < 0 {
        ("-", ns.unsigned_abs())
    } else {
        ("", ns as u64)
    };
    // (the digits of the fraction, no trailing zeros)
    let frac = |n: u64, digits: usize| -> String {
        let f = format!("{n:0digits$}");
        let f = f.trim_end_matches('0');
        if f.is_empty() {
            String::new()
        } else {
            format!(".{f}")
        }
    };
    if u < 1_000_000_000 {
        let (div, digits, unit) = if u < 1_000 {
            (1, 0, "ns")
        } else if u < 1_000_000 {
            (1_000, 3, "µs")
        } else {
            (1_000_000, 6, "ms")
        };
        return format!("{sign}{}{}{unit}", u / div, frac(u % div, digits));
    }
    let secs = u / 1_000_000_000;
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    let seconds = format!("{s}{}", frac(u % 1_000_000_000, 9));
    let out = if h > 0 {
        format!("{h}h{m}m{seconds}s")
    } else if m > 0 {
        format!("{m}m{seconds}s")
    } else {
        format!("{seconds}s")
    };
    format!("{sign}{out}")
}

#[cfg(test)]
mod tests {
    use super::{go_duration_string, parse_go_duration, parse_go_duration_ns};
    use std::time::Duration;

    #[test]
    fn go_durations() {
        assert_eq!(parse_go_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(
            parse_go_duration("24h0m0s"),
            Some(Duration::from_secs(86400))
        );
        assert_eq!(parse_go_duration("1.5s"), Some(Duration::from_millis(1500)));
        assert_eq!(parse_go_duration("300ms"), Some(Duration::from_millis(300)));
        assert_eq!(parse_go_duration("0"), Some(Duration::ZERO));
        assert_eq!(parse_go_duration_ns("1h30m"), Some(5_400_000_000_000));
        assert_eq!(parse_go_duration_ns("10ms"), Some(10_000_000));
        assert_eq!(parse_go_duration_ns("0"), Some(0));
        assert_eq!(parse_go_duration_ns("9999999999999h"), None);
        for bad in ["", "5", "1d", "-1h", "h", "1hx"] {
            assert_eq!(parse_go_duration(bad), None, "{bad}");
        }
        assert_eq!(
            super::parse_go_duration_days("1d"),
            Some(Duration::from_secs(86_400))
        );
        assert_eq!(
            super::parse_go_duration_days("1w1h"),
            Some(Duration::from_secs(608_400))
        );
    }

    #[test]
    fn durations_print_as_go_prints_them() {
        for (ns, want) in [
            (0, "0s"),
            (6_000_000_000, "6s"),
            (90_000_000_000, "1m30s"),
            (3_600_000_000_000, "1h0m0s"),
            (3_605_000_000_000, "1h0m5s"),
            (123_000_000_000, "2m3s"),
            (61_250_000_000, "1m1.25s"),
            (1_500_000_000, "1.5s"),
            (500_000_000, "500ms"),
            (749_000_000, "749ms"),
            (1_500_000, "1.5ms"),
            (1_234_567, "1.234567ms"),
            (1_500, "1.5µs"),
            (7, "7ns"),
            (-2_000_000_000, "-2s"),
        ] {
            assert_eq!(go_duration_string(ns), want, "{ns}");
        }
    }
}
