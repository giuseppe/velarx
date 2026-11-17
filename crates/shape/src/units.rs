// SPDX-License-Identifier: Apache-2.0
//! Sizes as Go's go-units writes them (`HumanSize`, `BytesSize`): the one
//! port, so every document and table shows the same text for a size.

/// A size as Go's `units.HumanSize` prints it: decimal units, four
/// significant digits (`12.18MB`, `0B`).
pub fn go_size(bytes: f64) -> String {
    go_size_with(bytes, 4)
}

/// A size as Go's `units.HumanSizeWithPrecision` prints it with
/// `precision` significant digits.
pub fn go_size_with(bytes: f64, precision: usize) -> String {
    go_units(
        bytes,
        1000.0,
        &["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"],
        precision,
    )
}

/// A size as Go's `units.BytesSize` prints it: binary units, four
/// significant digits (`11.62MiB`).
pub fn go_bytes_size(bytes: f64) -> String {
    go_units(
        bytes,
        1024.0,
        &["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"],
        4,
    )
}

fn go_units(bytes: f64, base: f64, units: &[&str], precision: usize) -> String {
    let mut v = bytes.max(0.0);
    let mut i = 0;
    while v >= base && i + 1 < units.len() {
        v /= base;
        i += 1;
    }
    let whole = if v >= 1000.0 {
        4
    } else if v >= 100.0 {
        3
    } else if v >= 10.0 {
        2
    } else {
        1
    };
    let digits = precision.saturating_sub(whole);
    let s = format!("{v:.digits$}");
    let s = if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    };
    format!("{s}{}", units[i])
}

/// A time span in seconds as go-units' `HumanDuration` says it (`About a
/// minute`, `3 days`); a negative span is less than a second.
pub fn human_duration(seconds: i64) -> String {
    let m = seconds / 60;
    let h = seconds / 3600;
    match seconds {
        s if s < 1 => "Less than a second".into(),
        1 => "1 second".into(),
        s if s < 60 => format!("{s} seconds"),
        _ if m == 1 => "About a minute".into(),
        _ if m < 60 => format!("{m} minutes"),
        _ if h == 1 => "About an hour".into(),
        _ if h < 48 => format!("{h} hours"),
        _ if h < 24 * 7 * 2 => format!("{} days", h / 24),
        _ if h < 24 * 30 * 2 => format!("{} weeks", h / 24 / 7),
        _ if h < 24 * 365 * 2 => format!("{} months", h / 24 / 30),
        _ => format!("{} years", h / 24 / 365),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_and_binary_units_with_four_significant_digits() {
        assert_eq!(go_size(0.0), "0B");
        assert_eq!(go_size(999.0), "999B");
        assert_eq!(go_size(1500.0), "1.5kB");
        assert_eq!(go_size(100_000.0), "100kB");
        assert_eq!(go_size(98_304.0), "98.3kB");
        assert_eq!(go_size(3_077_000.0), "3.077MB");
        assert_eq!(go_size(12_345_678.0), "12.35MB");
        assert_eq!(go_size(12_180_391.0), "12.18MB");
        assert_eq!(go_bytes_size(12_180_391.0), "11.62MiB");
        assert_eq!(go_bytes_size(1024.0), "1KiB");
        assert_eq!(go_size_with(12_345_678.0, 2), "12MB");
    }
}
