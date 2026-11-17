// SPDX-License-Identifier: Apache-2.0
//! The lines of `pod logs`, as podman prints them: with several containers
//! each line starts with the ID of its container (its name with `--names`),
//! then comes the time (`--timestamps`), then the message; `--color` gives
//! each container a color for the whole line.

use crate::client::PodLogEntry;

/// How `pod logs` prints a line.
#[derive(Debug, Clone, Copy, Default)]
pub struct LineFormat {
    pub names: bool,
    pub timestamps: bool,
    pub color: bool,
}

/// The ANSI colors of the containers, in the order podman has them: light
/// gray, red, yellow, blue, magenta, cyan, green.
const COLORS: [&str; 7] = ["37", "31", "33", "34", "35", "36", "32"];

/// A time as podman prints it in a log: RFC 3339 with nine digits, in the
/// time zone of the caller (`Z` for UTC).
pub fn local_time(rfc3339: &str) -> String {
    let ns = velarx_wire::monitor::logfmt::parse_rfc3339_ns(rfc3339);
    let time = ns.and_then(|ns| {
        chrono::DateTime::from_timestamp(
            ns.div_euclid(1_000_000_000),
            ns.rem_euclid(1_000_000_000) as u32,
        )
    });
    match time {
        Some(t) => t
            .with_timezone(&chrono::Local)
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        None => rfc3339.to_string(),
    }
}

/// A writer of log lines that start with a time: it is written in the time
/// zone of the caller, whole lines at a time.
pub struct LocalTimes<'a> {
    out: &'a mut dyn std::io::Write,
    partial: Vec<u8>,
}

impl<'a> LocalTimes<'a> {
    pub fn new(out: &'a mut dyn std::io::Write) -> Self {
        Self {
            out,
            partial: Vec::new(),
        }
    }
}

impl std::io::Write for LocalTimes<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.partial.extend_from_slice(buf);
        while let Some(end) = self.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.partial.drain(..=end).collect();
            let text = String::from_utf8_lossy(&line);
            match text.split_once(' ') {
                Some((time, rest)) => {
                    self.out.write_all(local_time(time).as_bytes())?;
                    self.out.write_all(b" ")?;
                    self.out.write_all(rest.as_bytes())?;
                }
                None => self.out.write_all(&line)?,
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// The line of an entry, without the newline.
pub fn line(f: &LineFormat, e: &PodLogEntry) -> String {
    let mut out = String::new();
    if e.containers > 1 {
        if f.names {
            out.push_str(&e.container_name);
        } else {
            out.extend(e.container_id.chars().take(12));
        }
        out.push(' ');
    }
    if f.timestamps {
        out.push_str(&local_time(&e.timestamp));
        out.push(' ');
    }
    out.push_str(&e.message);
    if f.color {
        format!(
            "\x1b[{}m{out}\x1b[0m",
            COLORS[e.container_index % COLORS.len()]
        )
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(containers: usize, index: usize) -> PodLogEntry {
        PodLogEntry {
            container_name: "web".into(),
            container_id: "0123456789abcdef".into(),
            container_index: index,
            containers,
            timestamp: "2026-10-18T10:27:43.517021Z".into(),
            stream: "stdout".into(),
            message: "hello".into(),
        }
    }

    #[test]
    fn one_container_has_no_prefix() {
        assert_eq!(line(&LineFormat::default(), &entry(1, 0)), "hello");
    }

    #[test]
    fn several_containers_start_with_the_id_or_the_name() {
        let f = LineFormat::default();
        assert_eq!(line(&f, &entry(2, 0)), "0123456789ab hello");
        let f = LineFormat { names: true, ..f };
        assert_eq!(line(&f, &entry(2, 0)), "web hello");
    }

    #[test]
    fn the_time_comes_after_the_prefix_with_nine_digits() {
        let f = LineFormat {
            timestamps: true,
            ..Default::default()
        };
        let l = line(&f, &entry(2, 0));
        assert!(l.starts_with("0123456789ab 2026-10-18T"), "{l}");
        assert!(l.ends_with(" hello"), "{l}");
        let time = l.split(' ').nth(1).unwrap();
        // 2026-10-18T12:27:43.517021000+02:00 or ...Z
        assert!(time.contains(".517021000"), "{time}");
        assert!(time.ends_with('Z') || time.contains('+') || time[19..].contains('-'));
    }

    #[test]
    fn a_color_covers_the_whole_line_and_follows_the_index() {
        let f = LineFormat {
            color: true,
            ..Default::default()
        };
        assert_eq!(line(&f, &entry(2, 1)), "\x1b[31m0123456789ab hello\x1b[0m");
        assert_eq!(line(&f, &entry(2, 7)), "\x1b[37m0123456789ab hello\x1b[0m");
        assert_eq!(line(&f, &entry(2, 2)), "\x1b[33m0123456789ab hello\x1b[0m");
    }
}
