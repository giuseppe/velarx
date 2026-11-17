// SPDX-License-Identifier: Apache-2.0
//! The systemd journal as a log driver, through its native protocol: one
//! datagram of `FIELD=value` lines per message on `/run/systemd/journal/socket`.

use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::net::{self, AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType};

use super::config::LogConfig;
use velarx_wire::monitor::logfmt::Stream;

pub const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

pub struct JournalWriter {
    sock: OwnedFd,
    /// The fields every message of the container has.
    base: Vec<u8>,
    /// The last message of each stream was partial.
    partial: [bool; 2],
}

/// Add `name=value` to a journal entry: the plain form for a value on one
/// line, the length prefixed form otherwise.
fn field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(name.as_bytes());
    if value.contains(&b'\n') {
        out.push(b'\n');
        out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    } else {
        out.push(b'=');
    }
    out.extend_from_slice(value);
    out.push(b'\n');
}

/// A journal field name: capital letters, digits and `_`, not starting with
/// a digit or `_`.
fn valid_field_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with(|c: char| c.is_ascii_digit() || c == '_')
        && s.bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

impl JournalWriter {
    pub fn open(id: &str, log: &LogConfig) -> io::Result<Self> {
        Self::open_at(Path::new(JOURNAL_SOCKET), id, log)
    }

    pub fn open_at(path: &Path, id: &str, log: &LogConfig) -> io::Result<Self> {
        let sock = net::socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )?;
        net::connect(&sock, &SocketAddrUnix::new(path)?)?;
        let short = &id[..id.len().min(12)];
        let mut base = Vec::new();
        field(&mut base, "CONTAINER_ID", short.as_bytes());
        field(&mut base, "CONTAINER_ID_FULL", id.as_bytes());
        if !log.name.is_empty() {
            field(&mut base, "CONTAINER_NAME", log.name.as_bytes());
        }
        let tag = log.tag.as_deref().unwrap_or(short);
        field(&mut base, "CONTAINER_TAG", tag.as_bytes());
        field(&mut base, "SYSLOG_IDENTIFIER", tag.as_bytes());
        if !log.image.is_empty() {
            field(&mut base, "IMAGE_NAME", log.image.as_bytes());
        }
        // Labels become fields of their own, with a prefix that cannot
        // collide with the fields of the journal.
        let mut labels: Vec<_> = log.labels.iter().collect();
        labels.sort();
        for (k, v) in labels {
            let name = format!(
                "CONTAINER_LABEL_{}",
                k.to_ascii_uppercase()
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                    .collect::<String>()
            );
            if valid_field_name(&name) {
                field(&mut base, &name, v.as_bytes());
            }
        }
        Ok(Self {
            sock,
            base,
            partial: [false; 2],
        })
    }

    fn send(&self, stream: Stream, line: &[u8], partial: bool) -> io::Result<()> {
        let mut entry = Vec::with_capacity(self.base.len() + line.len() + 64);
        field(&mut entry, "MESSAGE", line);
        field(
            &mut entry,
            "PRIORITY",
            match stream {
                Stream::Stdout => b"6",
                Stream::Stderr => b"3",
            },
        );
        if partial {
            field(&mut entry, "CONTAINER_PARTIAL_MESSAGE", b"true");
        }
        entry.extend_from_slice(&self.base);
        loop {
            match net::send(&self.sock, &entry, SendFlags::NOSIGNAL) {
                Ok(_) => return Ok(()),
                Err(rustix::io::Errno::INTR) => continue,
                // The socket is blocking, as conmon's: a slow journald blocks
                // the container's output until it reads.  Only an error that
                // says the message cannot be queued at all drops it.
                Err(rustix::io::Errno::AGAIN) | Err(rustix::io::Errno::NOBUFS) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Log what a stream of the container produced: a message per line.
    pub fn write(&mut self, stream: Stream, mut data: &[u8]) -> io::Result<()> {
        let idx = stream as usize;
        while !data.is_empty() {
            match data.iter().position(|&c| c == b'\n') {
                Some(i) => {
                    self.send(stream, &data[..i], false)?;
                    self.partial[idx] = false;
                    data = &data[i + 1..];
                }
                None => {
                    self.send(stream, data, true)?;
                    self.partial[idx] = true;
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn finish(&mut self) -> io::Result<()> {
        for stream in [Stream::Stdout, Stream::Stderr] {
            if self.partial[stream as usize] {
                self.send(stream, b"", false)?;
                self.partial[stream as usize] = false;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    fn log() -> LogConfig {
        LogConfig {
            name: "web".into(),
            image: "img:1".into(),
            tag: Some("mytag".into()),
            labels: [
                ("app.name".to_string(), "x".to_string()),
                ("9".to_string(), "y".to_string()),
            ]
            .into(),
            ..Default::default()
        }
    }

    fn recv(sock: &UnixDatagram) -> String {
        let mut buf = vec![0u8; 8192];
        let n = sock.recv(&mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn messages_carry_the_container_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let server = UnixDatagram::bind(&path).unwrap();
        server
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut w = JournalWriter::open_at(&path, "0123456789abcdef", &log()).unwrap();
        w.write(Stream::Stdout, b"hello\npar").unwrap();
        w.write(Stream::Stderr, b"bad\n").unwrap();
        let first = recv(&server);
        assert!(first.starts_with("MESSAGE=hello\nPRIORITY=6\n"), "{first}");
        for f in [
            "CONTAINER_ID=0123456789ab\n",
            "CONTAINER_ID_FULL=0123456789abcdef\n",
            "CONTAINER_NAME=web\n",
            "CONTAINER_TAG=mytag\n",
            "SYSLOG_IDENTIFIER=mytag\n",
            "IMAGE_NAME=img:1\n",
            "CONTAINER_LABEL_APP_NAME=x\n",
        ] {
            assert!(first.contains(f), "{f} in {first}");
        }
        assert!(!first.contains("CONTAINER_PARTIAL_MESSAGE"));
        let second = recv(&server);
        assert!(
            second.starts_with("MESSAGE=par\nPRIORITY=6\nCONTAINER_PARTIAL_MESSAGE=true\n"),
            "{second}"
        );
        let third = recv(&server);
        assert!(third.starts_with("MESSAGE=bad\nPRIORITY=3\n"), "{third}");
        w.finish().unwrap();
        // The partial line is ended.
        let end = recv(&server);
        assert!(end.starts_with("MESSAGE=\nPRIORITY=6\n"), "{end}");
    }

    #[test]
    fn a_value_with_a_newline_uses_the_length_prefixed_form() {
        let mut out = Vec::new();
        field(&mut out, "MESSAGE", b"a\nb");
        assert_eq!(out, b"MESSAGE\n\x03\0\0\0\0\0\0\0a\nb\n");
    }

    #[test]
    fn field_names() {
        assert!(valid_field_name("CONTAINER_LABEL_A_B"));
        assert!(!valid_field_name("_PRIVATE"));
        assert!(!valid_field_name("9A"));
        assert!(!valid_field_name("A-B"));
        assert!(!valid_field_name(""));
    }

    #[test]
    fn no_journal_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        assert!(JournalWriter::open_at(&dir.path().join("none"), "id", &log()).is_err());
    }
}
