// SPDX-License-Identifier: Apache-2.0
use super::*;

/// What `logs` shows of a container.
#[derive(Clone)]
pub(super) struct LogsOptions {
    pub(super) follow: bool,
    pub(super) tail: Option<usize>,
    pub(super) timestamps: bool,
    pub(super) since: Option<String>,
    pub(super) until: Option<String>,
    /// The events backend of the configuration: podman follows the journal
    /// of a container only with the journald backend.
    pub(super) events_logger: Option<String>,
}

/// The logs of `container` to `out` and `err`: asked of the engine.
pub(super) fn show_logs(
    client: &client::EngineClient,
    container: &str,
    o: &LogsOptions,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    // (of a list of drivers the first is the one `logs` reads)
    let driver = client.inspect_container(container)?.host.log_driver;
    let driver = driver.split(',').next().unwrap_or_default();
    if o.follow {
        if driver == "journald" {
            if let Some(logger) = o.events_logger.as_deref().filter(|l| *l != "journald") {
                anyhow::bail!(
                    "using --follow with the journald --log-driver but without the journald \
                     --events-backend ({logger}) is not supported"
                );
            }
            return follow_journal(client, container, o, out, err);
        }
        if driver != "k8s-file" {
            anyhow::bail!("--follow needs the k8s-file or the journald log driver");
        }
    }
    // (the times are in the time zone of the caller, as podman's)
    let (mut local_out, mut local_err);
    let (out, err): (&mut dyn std::io::Write, &mut dyn std::io::Write) = if o.timestamps {
        local_out = cli::podlogs::LocalTimes::new(out);
        local_err = cli::podlogs::LocalTimes::new(err);
        (&mut local_out, &mut local_err)
    } else {
        (out, err)
    };
    client.stream_logs(
        container,
        o.follow,
        o.tail,
        o.timestamps,
        o.since.as_deref(),
        o.until.as_deref(),
        out,
        err,
    )?;
    Ok(())
}

/// `logs --follow` of a container that logs to the journal: `journalctl
/// --follow` of its entries until the container is no longer running, then
/// what the journal got after the last entry shown.
pub(super) fn follow_journal(
    client: &client::EngineClient,
    container: &str,
    o: &LogsOptions,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> anyhow::Result<()> {
    use velarx_wire::monitor::journal::Query;
    use velarx_wire::monitor::logfmt::{now_ns, parse_log_time, Toward};
    let id = client.inspect_container(container)?.id;
    let time = |name: &str, spec: &Option<String>, toward| -> anyhow::Result<Option<i64>> {
        match spec {
            None => Ok(None),
            Some(s) => parse_log_time(s, now_ns(), toward)
                .map(Some)
                .ok_or_else(|| anyhow::anyhow!("invalid --{name} time: {s}")),
        }
    };
    let query = Query {
        program: "journalctl".into(),
        id: id.clone(),
        uid: velarx_base::ids::host_uid()?,
        since_ns: time("since", &o.since, Toward::Past)?,
        until_ns: time("until", &o.until, Toward::Future)?,
        tail: o.tail,
    };
    let follow = query
        .follow()
        .map_err(|e| anyhow::anyhow!("journalctl: {e}"))?;
    // (the engine says when the container ended, and the end of the pipe
    // tells the follow; this thread is not joined, a container that goes on
    // is not waited for)
    let (stop, ended) = rustix::pipe::pipe()?;
    {
        let client = client.clone();
        std::thread::spawn(move || {
            let _ = client.wait_condition(&id, &[], 0);
            drop(ended);
        });
    }
    let mut failed = None;
    let mut show = |l: velarx_wire::monitor::logfmt::JournalLine| {
        let w: &mut dyn std::io::Write = if l.stderr { &mut *err } else { &mut *out };
        let wrote = (|| {
            if o.timestamps {
                write!(w, "{} ", cli::podlogs::local_time(&l.timestamp))?;
            }
            writeln!(w, "{}", l.message)?;
            w.flush()
        })();
        match wrote {
            Ok(()) => true,
            Err(e) => {
                failed = Some(e);
                false
            }
        }
    };
    follow
        .run(std::os::fd::AsFd::as_fd(&stop), &mut show)
        .map_err(|e| anyhow::anyhow!("journalctl: {e}"))?;
    match failed {
        Some(e) => Err(e.into()),
        None => Ok(()),
    }
}

/// A writer that puts `prefix ` before each line, and writes whole lines
/// only (several containers write together); with a color, the line is in
/// the ANSI color of that number (podman's seven, in its order).
pub(super) struct PrefixLines {
    prefix: String,
    stderr: bool,
    color: Option<usize>,
    buf: Vec<u8>,
}

const COLORS: [&str; 7] = [
    "\x1b[37m", "\x1b[31m", "\x1b[33m", "\x1b[34m", "\x1b[35m", "\x1b[36m", "\x1b[32m",
];
const COLOR_RESET: &str = "\x1b[0m";

impl PrefixLines {
    pub(super) fn new(prefix: String, stderr: bool, color: Option<usize>) -> Self {
        Self {
            prefix,
            stderr,
            color,
            buf: Vec::new(),
        }
    }

    /// The bytes of one line as they are written.
    fn render(&self, line: &[u8]) -> Vec<u8> {
        let mut text = Vec::with_capacity(self.prefix.len() + 16 + line.len());
        let (body, newline) = match line.strip_suffix(b"\n") {
            Some(b) => (b, &b"\n"[..]),
            None => (line, &b""[..]),
        };
        if let Some(c) = self.color {
            text.extend_from_slice(COLORS[c % COLORS.len()].as_bytes());
        }
        if !self.prefix.is_empty() {
            text.extend_from_slice(self.prefix.as_bytes());
            text.push(b' ');
        }
        text.extend_from_slice(body);
        if self.color.is_some() {
            text.extend_from_slice(COLOR_RESET.as_bytes());
        }
        text.extend_from_slice(newline);
        text
    }

    fn emit(&mut self, line: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let text = self.render(line);
        if self.stderr {
            std::io::stderr().lock().write_all(&text)
        } else {
            std::io::stdout().lock().write_all(&text)
        }
    }
}

impl std::io::Write for PrefixLines {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        while let Some(n) = self.buf.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=n).collect();
            self.emit(&line)?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            let mut line = std::mem::take(&mut self.buf);
            line.push(b'\n');
            self.emit(&line)?;
        }
        Ok(())
    }
}

impl Drop for PrefixLines {
    fn drop(&mut self) {
        use std::io::Write;
        let _ = self.flush();
    }
}

/// `inspect --format`: podman's JSON of the objects, through the template;
/// exit 125 if one is not there.
pub(super) fn inspect_as_podman(
    client: &client::EngineClient,
    kind: client::Kind,
    names: &[String],
    format: Option<&str>,
) -> anyhow::Result<()> {
    if !cli::report::inspect(client, Some(kind), names, format, false)? {
        exit_with(125);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_have_a_prefix_and_a_color_that_ends_before_the_newline() {
        let line = |prefix: &str, color| PrefixLines::new(prefix.into(), false, color);
        assert_eq!(line("web", None).render(b"hi\n"), b"web hi\n");
        assert_eq!(line("", None).render(b"hi\n"), b"hi\n");
        assert_eq!(line("", Some(0)).render(b"hi\n"), b"\x1b[37mhi\x1b[0m\n");
        assert_eq!(
            line("web", Some(1)).render(b"2026 hi\n"),
            b"\x1b[31mweb 2026 hi\x1b[0m\n"
        );
        // seven colors, then again
        assert_eq!(
            line("", Some(7)).render(b"x\n"),
            line("", Some(0)).render(b"x\n")
        );
        assert_eq!(line("", Some(2)).render(b"x"), b"\x1b[33mx\x1b[0m");
    }
}
