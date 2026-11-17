// SPDX-License-Identifier: Apache-2.0
//! RFC 3339 text and the civil calendar: the one reader and the one writer
//! of the times of the documents, with the style of the fraction of a second
//! as a parameter (the frontends write it in different ways).

/// How the fraction of a second of an RFC 3339 time is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fraction {
    /// Always nine digits (`.120000000`).
    Nine,
    /// None for a whole second, else three, six or nine digits, as many as
    /// it needs (`.120`).
    Groups,
    /// Go's RFC3339Nano: the digits without their trailing zeros (`.12`).
    Trimmed,
}

/// `ns` nanoseconds since the epoch as RFC 3339 in UTC, the fraction of a
/// second written as `fraction` says.
pub fn format_rfc3339(ns: i64, fraction: Fraction) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000);
    let (days, rest) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil(days);
    let fraction = match fraction {
        _ if nanos == 0 && fraction != Fraction::Nine => String::new(),
        Fraction::Nine => format!(".{nanos:09}"),
        Fraction::Groups if nanos % 1_000_000 == 0 => format!(".{:03}", nanos / 1_000_000),
        Fraction::Groups if nanos % 1_000 == 0 => format!(".{:06}", nanos / 1_000),
        Fraction::Groups => format!(".{nanos:09}"),
        Fraction::Trimmed => format!(".{nanos:09}").trim_end_matches('0').to_string(),
    };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}{fraction}Z",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    )
}

/// RFC 3339 (any fraction of a second, `Z` or an offset, a comma or a dot
/// before the fraction) as nanoseconds since the epoch.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |from: usize, to: usize| -> Option<i64> {
        let part = s.get(from..to)?;
        part.bytes().all(|c| c.is_ascii_digit()).then_some(())?;
        part.parse().ok()
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut pos = 19;
    let mut nanos = 0i64;
    if matches!(b.get(pos), Some(b'.' | b',')) {
        let start = pos + 1;
        let mut end = start;
        while b.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            return None;
        }
        let digits = &s[start..end.min(start + 9)];
        nanos = digits.parse::<i64>().ok()? * 10i64.pow(9 - digits.len() as u32);
        pos = end;
    }
    let offset = match b.get(pos)? {
        b'Z' | b'z' if pos + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if pos + 6 == b.len() && b[pos + 3] == b':' => {
            let secs = num(pos + 1, pos + 3)? * 3600 + num(pos + 4, pos + 6)? * 60;
            if *sign == b'+' {
                secs
            } else {
                -secs
            }
        }
        _ => return None,
    };
    days_from_civil(y, mo as u32, d as u32)
        .checked_mul(86_400)?
        .checked_add(h * 3600 + mi * 60 + sec - offset)?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}

/// Which way a duration in a time of a query goes from now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Toward {
    /// how long ago (`since`, and the filters `until`)
    Past,
    /// how long from now (the `until` of the logs and of the events)
    Future,
}

/// A time of a query (`since`, `until`) as podman's `ParseInputTime` reads
/// it, in nanoseconds since the epoch: RFC 3339 (a comma before the fraction
/// too, any offset), a date and time without a zone (UTC), a date with a
/// zone or without one (UTC), seconds since the epoch (a sign, a fraction),
/// or a Go duration (a sign too) from `now_ns` in the direction `toward`.
/// A time before the epoch, such as Go's zero time, is 0.
///
/// `lenient` is what the logs of the command line add to podman's forms:
/// the units `d` and `w`, and blanks around the text.
pub fn parse_input_time(s: &str, now_ns: i64, toward: Toward, lenient: bool) -> Option<i64> {
    let s = if lenient { s.trim() } else { s };
    if s.is_empty() {
        return None;
    }
    let at = |s: &str| {
        parse_rfc3339(s)
            .or_else(|| parse_rfc3339(&format!("{s}Z")))
            .or_else(|| {
                let (date, zone) = (s.get(..10)?, s.get(10..)?);
                let zone = if zone.is_empty() { "Z" } else { zone };
                parse_rfc3339(&format!("{date}T00:00:00{zone}"))
            })
    };
    if let Some(ns) = at(s).or_else(|| {
        // (a time long before the epoch, such as Go's zero time, does not
        // fit a count of nanoseconds)
        let year: i64 = s.get(..4)?.parse().ok()?;
        (year < 1970).then_some(())?;
        at(&format!("2000{}", s.get(4..)?)).map(|_| 0)
    }) {
        return Some(ns.max(0));
    }
    if s.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        // (exact: the seconds, and up to nine digits of fraction)
        let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
        if (secs.is_empty() && frac.is_empty()) || frac.contains('.') {
            return None;
        }
        let secs: i64 = if secs.is_empty() {
            0
        } else {
            secs.parse().ok()?
        };
        let frac = frac.get(..frac.len().min(9)).unwrap_or("");
        let nanos = if frac.is_empty() {
            0
        } else {
            frac.parse::<i64>().ok()? * 10i64.pow(9 - frac.len() as u32)
        };
        return secs.checked_mul(1_000_000_000)?.checked_add(nanos);
    }
    if let Some(secs) = s.parse::<f64>().ok().filter(|f| f.is_finite()) {
        // (a sign or an exponent)
        let whole = (secs.trunc() as i64).saturating_mul(1_000_000_000);
        return Some(whole.saturating_add((secs.fract() * 1e9) as i64).max(0));
    }
    let (negative, unsigned) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let d = if lenient {
        crate::duration::parse_go_duration_days(unsigned)
    } else {
        crate::duration::parse_go_duration(unsigned)
    }?;
    let d = i64::try_from(d.as_nanos()).ok()?;
    // (a duration goes back for `since`, a negative one the other way)
    let back = (toward == Toward::Past) != negative;
    Some(
        if back {
            now_ns.saturating_sub(d)
        } else {
            now_ns.saturating_add(d)
        }
        .max(0),
    )
}

/// The days from 1970-01-01 of a date of the proleptic Gregorian calendar
/// (the inverse of [`civil`]).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The year, month and day of a day counted from 1970-01-01 (the proleptic
/// Gregorian calendar).
pub fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_time_of_a_query() {
        const NOW: i64 = 1_800_000_000_000_000_000;
        let t = |s, toward| parse_input_time(s, NOW, toward, false);
        let past = |s| t(s, Toward::Past);
        assert_eq!(past("1700000000.5"), Some(1_700_000_000_500_000_000));
        // exact to the nanosecond, and not through a float
        assert_eq!(
            past("1700000000.123456789"),
            Some(1_700_000_000_123_456_789)
        );
        assert_eq!(past("1700000000"), t("1700000000", Toward::Future));
        assert_eq!(
            past("2023-11-14T22:13:20.5+01:00"),
            Some(1_699_996_400_500_000_000)
        );
        assert_eq!(
            past("2023-11-14T22:13:20,5Z"),
            Some(1_700_000_000_500_000_000)
        );
        // podman's layouts without a time or without a zone
        assert_eq!(past("2023-11-14T22:13:20"), Some(1_700_000_000_000_000_000));
        assert_eq!(past("2023-11-14"), Some(1_699_920_000_000_000_000));
        assert_eq!(past("2023-11-14Z"), Some(1_699_920_000_000_000_000));
        assert_eq!(past("2023-11-14+01:00"), Some(1_699_916_400_000_000_000));
        for bad in [
            "2023-11-14T",
            "2023-11-14X",
            "2023-13-45",
            "2023-11-14T22:13",
        ] {
            assert_eq!(past(bad), None, "{bad}");
        }
        // before the epoch is 0
        assert_eq!(past("0001-01-01T00:00:00Z"), Some(0));
        assert_eq!(past("1960-01-01T00:00:00Z"), Some(0));
        assert_eq!(past("2026-13-01T00:00:00Z"), None);
        assert_eq!(past("-5"), Some(0));
        assert_eq!(past("1e3"), Some(1_000_000_000_000));
        // a duration goes back from now, or ahead of it; a sign turns it
        assert_eq!(past("5m"), Some(NOW - 300_000_000_000));
        assert_eq!(past("1h30m"), Some(NOW - 5_400_000_000_000));
        assert_eq!(past("0.1s"), Some(NOW - 100_000_000));
        assert_eq!(t("5m", Toward::Future), Some(NOW + 300_000_000_000));
        assert_eq!(past("-1s"), Some(NOW + 1_000_000_000));
        assert_eq!(past("+5m"), past("5m"));
        assert_eq!(t("-1s", Toward::Future), Some(NOW - 1_000_000_000));
        // (more than a time can hold is none)
        assert_eq!(past("99999999999999999999"), None);
        assert_eq!(past("99999999999999999999h"), None);
        for bad in [
            "", "h", "10x", "abc", "1h x", "-", ".", "1.2.3", "inf", "nan", "2d", "1w",
        ] {
            assert_eq!(past(bad), None, "{bad:?}");
        }
        // the logs of the command line: days and weeks, and blanks
        let lenient = |s| parse_input_time(s, NOW, Toward::Past, true);
        assert_eq!(lenient("2d"), Some(NOW - 2 * 86_400_000_000_000));
        assert_eq!(lenient(" 1w "), Some(NOW - 7 * 86_400_000_000_000));
        assert_eq!(lenient("1700000000"), past("1700000000"));
        assert_eq!(past(" 5m"), None);
        assert_eq!(lenient("  "), None);
    }

    #[test]
    fn the_styles_of_the_fraction() {
        let t = |ns, f| format_rfc3339(ns, f);
        let whole = 1_700_000_000_000_000_000;
        assert_eq!(t(whole, Fraction::Groups), "2023-11-14T22:13:20Z");
        assert_eq!(t(whole, Fraction::Trimmed), "2023-11-14T22:13:20Z");
        assert_eq!(t(whole, Fraction::Nine), "2023-11-14T22:13:20.000000000Z");
        let ms = whole + 120_000_000;
        assert_eq!(t(ms, Fraction::Groups), "2023-11-14T22:13:20.120Z");
        assert_eq!(t(ms, Fraction::Trimmed), "2023-11-14T22:13:20.12Z");
        assert_eq!(t(ms, Fraction::Nine), "2023-11-14T22:13:20.120000000Z");
        let us = whole + 120_300_000;
        assert_eq!(t(us, Fraction::Groups), "2023-11-14T22:13:20.120300Z");
        let ns = whole + 1;
        assert_eq!(t(ns, Fraction::Groups), "2023-11-14T22:13:20.000000001Z");
        assert_eq!(t(ns, Fraction::Trimmed), "2023-11-14T22:13:20.000000001Z");
    }

    #[test]
    fn rfc3339_is_read_back_with_any_zone_and_fraction() {
        let whole = 1_700_000_000_000_000_000;
        for f in [Fraction::Nine, Fraction::Groups, Fraction::Trimmed] {
            for ns in [whole, whole + 5, whole + 120_000_000] {
                assert_eq!(parse_rfc3339(&format_rfc3339(ns, f)), Some(ns));
            }
        }
        assert_eq!(parse_rfc3339("2023-11-14T23:13:20+01:00"), Some(whole));
        assert_eq!(
            parse_rfc3339("2023-11-14T22:13:20,5Z"),
            Some(whole + 500_000_000)
        );
        assert_eq!(parse_rfc3339("2023-11-14"), None);
        assert_eq!(parse_rfc3339("2023-13-14T22:13:20Z"), None);
        assert_eq!(parse_rfc3339("2023-11-14T22:13:20"), None);
    }

    #[test]
    fn the_calendar_round_trips() {
        for days in [-1_000_000, -1, 0, 1, 19_000, 2_932_896] {
            let (y, m, d) = civil(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil(0), (1970, 1, 1));
    }
}
