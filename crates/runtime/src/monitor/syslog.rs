// SPDX-License-Identifier: Apache-2.0
//! syslog as a log driver: a datagram per line of the container on
//! `/dev/log`, in the format of the C library's syslog(3) (RFC 3164):
//! `<PRI>Mmm dd hh:mm:ss TAG[PID]: MESSAGE`, facility user, info for
//! stdout and err for stderr (or the `<N>` a line starts with, as
//! conmon's).  A line longer than `MAX_LINE` goes out in pieces.

use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::net::{self, AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType};

use super::config::LogConfig;
use velarx_wire::monitor::logfmt::Stream;

pub const SYSLOG_SOCKET: &str = "/dev/log";

/// The longest message: what is left of a longer line goes in the next.
pub const MAX_LINE: usize = 8192;

const LOG_USER: u8 = 1 << 3;
const LOG_ERR: u8 = 3;
const LOG_INFO: u8 = 6;

pub struct SyslogWriter {
    sock: OwnedFd,
    tag: String,
    pid: u32,
    /// The start of a line of each stream, until its end comes.
    partial: [Vec<u8>; 2],
}

/// The tag of the messages of a container: `--log-opt tag`, else its name,
/// else its short ID; no control characters.
pub fn tag_of(id: &str, log: &LogConfig) -> io::Result<String> {
    let tag = match (&log.tag, log.name.is_empty()) {
        (Some(t), _) => t.clone(),
        (None, false) => log.name.clone(),
        (None, true) => id[..id.len().min(12)].to_string(),
    };
    if let Some(b) = tag.bytes().find(|&b| b < 0x20 || b == 0x7f) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the syslog tag {tag:?} has a control character ({b:#04x})"),
        ));
    }
    Ok(tag)
}

/// `Mmm dd hh:mm:ss` of now, in the local time, as syslog(3) writes it.
fn timestamp() -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let Some(tm) = velarx_sys::ffi::local_time() else {
        return "Jan  1 00:00:00".to_string();
    };
    format!(
        "{} {:2} {:02}:{:02}:{:02}",
        MONTHS[tm.month.clamp(0, 11) as usize],
        tm.day,
        tm.hour,
        tm.minute,
        tm.second
    )
}

impl SyslogWriter {
    pub fn open(id: &str, log: &LogConfig) -> io::Result<Self> {
        Self::open_at(Path::new(SYSLOG_SOCKET), id, log)
    }

    pub fn open_at(path: &Path, id: &str, log: &LogConfig) -> io::Result<Self> {
        let tag = tag_of(id, log)?;
        let sock = net::socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )?;
        net::connect(&sock, &SocketAddrUnix::new(path)?).map_err(|e| {
            io::Error::new(
                io::Error::from(e).kind(),
                format!("cannot connect to syslog at {}: {e}", path.display()),
            )
        })?;
        Ok(Self {
            sock,
            tag,
            pid: std::process::id(),
            partial: [Vec::new(), Vec::new()],
        })
    }

    /// The message of one line: its own priority if it starts with `<N>`.
    fn message(&self, stream: Stream, line: &[u8]) -> Vec<u8> {
        let (severity, text) = match line {
            [b'<', n @ b'0'..=b'7', b'>', rest @ ..] => (n - b'0', rest),
            _ => (
                match stream {
                    Stream::Stdout => LOG_INFO,
                    Stream::Stderr => LOG_ERR,
                },
                line,
            ),
        };
        let mut m = format!(
            "<{}>{} {}[{}]: ",
            LOG_USER | severity,
            timestamp(),
            self.tag,
            self.pid
        )
        .into_bytes();
        m.extend(text.iter().map(|&b| if b == 0 { b'?' } else { b }));
        m
    }

    fn send(&self, stream: Stream, line: &[u8]) -> io::Result<()> {
        let m = self.message(stream, line);
        loop {
            match net::send(&self.sock, &m, SendFlags::NOSIGNAL) {
                Ok(_) => return Ok(()),
                Err(rustix::io::Errno::INTR) => continue,
                // The socket is blocking, as conmon's: a slow syslog blocks
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
                    let mut line = std::mem::take(&mut self.partial[idx]);
                    line.extend_from_slice(&data[..i]);
                    for piece in line.chunks(MAX_LINE) {
                        self.send(stream, piece)?;
                    }
                    if line.is_empty() {
                        self.send(stream, b"")?;
                    }
                    data = &data[i + 1..];
                }
                None => {
                    self.partial[idx].extend_from_slice(data);
                    while self.partial[idx].len() >= MAX_LINE {
                        let piece: Vec<u8> = self.partial[idx].drain(..MAX_LINE).collect();
                        self.send(stream, &piece)?;
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    /// Send the unfinished lines.
    pub fn finish(&mut self) -> io::Result<()> {
        for stream in [Stream::Stdout, Stream::Stderr] {
            let line = std::mem::take(&mut self.partial[stream as usize]);
            if !line.is_empty() {
                self.send(stream, &line)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    fn recv(sock: &UnixDatagram) -> String {
        let mut buf = vec![0u8; 2 * MAX_LINE];
        let n = sock.recv(&mut buf).unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    fn server() -> (tempfile::TempDir, std::path::PathBuf, UnixDatagram) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let s = UnixDatagram::bind(&path).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        (dir, path, s)
    }

    /// The message without its time, which changes.
    fn strip_time(m: &str) -> String {
        let (pri, rest) = m.split_once('>').unwrap();
        format!("{pri}>{}", &rest[16..])
    }

    #[test]
    fn lines_go_as_messages_with_tag_pid_and_priority() {
        let (_d, path, s) = server();
        let log = LogConfig {
            name: "web".into(),
            ..Default::default()
        };
        let mut w = SyslogWriter::open_at(&path, "0123456789abcdef", &log).unwrap();
        w.write(Stream::Stdout, b"hello\nwor").unwrap();
        w.write(Stream::Stdout, b"ld\n").unwrap();
        w.write(Stream::Stderr, b"bad\n<4>warned\nend").unwrap();
        w.finish().unwrap();
        let pid = std::process::id();
        let first = recv(&s);
        // <PRI>Mmm dd hh:mm:ss TAG[PID]: MESSAGE
        let b = first.as_bytes();
        assert!(first.starts_with("<14>"), "{first}");
        assert!(
            b[4].is_ascii_uppercase() && b[7] == b' ' && b[10] == b' ',
            "{first}"
        );
        assert!(b[13] == b':' && b[16] == b':' && b[19] == b' ', "{first}");
        assert_eq!(strip_time(&first), format!("<14>web[{pid}]: hello"));
        assert_eq!(strip_time(&recv(&s)), format!("<14>web[{pid}]: world"));
        assert_eq!(strip_time(&recv(&s)), format!("<11>web[{pid}]: bad"));
        assert_eq!(strip_time(&recv(&s)), format!("<12>web[{pid}]: warned"));
        assert_eq!(strip_time(&recv(&s)), format!("<11>web[{pid}]: end"));
    }

    #[test]
    fn the_tag_and_long_lines() {
        let (_d, path, s) = server();
        let log = LogConfig {
            tag: Some("custom".into()),
            name: "web".into(),
            ..Default::default()
        };
        let mut w = SyslogWriter::open_at(&path, "0123456789abcdef", &log).unwrap();
        let long = vec![b'x'; MAX_LINE + 10];
        w.write(Stream::Stdout, &long).unwrap();
        w.write(Stream::Stdout, b"\n").unwrap();
        let a = recv(&s);
        assert!(a.contains(" custom["), "{a}");
        assert!(a.ends_with(&"x".repeat(MAX_LINE)));
        assert!(recv(&s).ends_with("]: xxxxxxxxxx"));
        // no name, no tag: the short ID
        let mut w =
            SyslogWriter::open_at(&path, "0123456789abcdef", &LogConfig::default()).unwrap();
        w.write(Stream::Stdout, b"x\n").unwrap();
        assert!(recv(&s).contains(" 0123456789ab["));
        let bad = LogConfig {
            tag: Some("a\nb".into()),
            ..Default::default()
        };
        assert!(SyslogWriter::open_at(&path, "0123456789abcdef", &bad).is_err());
    }
}
