// SPDX-License-Identifier: Apache-2.0
//! Reading the logs of containers.

use super::container::{ContainerError, ContainerResult, ContainerService, NOT_LOGGING};
use crate::container::ContainerConfig;
use crate::monitor::config::{LogConfig, LogDriver};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use velarx_config::{log_opt_size, parse_size};
use velarx_db::{ContainerRecord, RecordState};
use velarx_wire::monitor::journal;
use velarx_wire::monitor::logfmt::{self, LineAssembler, ReadOptions, Stream};
pub use velarx_wire::wire::LogLocation;

/// Log entry from container output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    pub stream: LogStream,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogStream {
    Stdout,
    Stderr,
}

/// What `logs` shows.
#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    pub tail: Option<usize>,
    pub timestamps: bool,
    pub since_ns: Option<i64>,
    pub until_ns: Option<i64>,
}

/// The options `--log-opt` accepts.
const LOG_OPTS: &[&str] = &[
    "max-size",
    "max-file",
    "path",
    "tag",
    "global-size-max",
    "compress",
];

/// A boolean of a log option, as Docker's: `true`/`false`, `1`/`0`.
fn log_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

/// Refuse a log configuration the monitor could not use.
pub fn validate_log_config(driver: &str, opts: &HashMap<String, String>) -> ContainerResult<()> {
    let invalid = ContainerError::InvalidArgument;
    if !driver.is_empty() {
        LogDriver::parse_list(driver).map_err(|e| {
            if e.starts_with("unknown log driver") {
                // podman's words (the drivers are k8s-file, journald,
                // syslog, none and passthrough)
                invalid(
                    "running container create option: invalid log driver: invalid argument"
                        .to_string(),
                )
            } else {
                invalid(e)
            }
        })?;
    }
    for (k, v) in opts {
        match k.as_str() {
            "max-size" | "global-size-max" => {
                let size = if k == "max-size" {
                    log_opt_size(v)
                } else {
                    parse_size(v)
                };
                if size.is_none() {
                    return Err(invalid(format!(
                        "invalid size `{v}` for the log option {k}"
                    )));
                }
            }
            "max-file" => {
                if v.parse::<u32>().ok().filter(|&n| n >= 1).is_none() {
                    return Err(invalid(format!(
                        "invalid number `{v}` for the log option max-file"
                    )));
                }
            }
            "path" => {
                let p = std::path::Path::new(v);
                if !p.is_absolute()
                    || p.file_name().is_none()
                    || p.components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(invalid(format!(
                        "the log path `{v}` must be an absolute path to a file"
                    )));
                }
            }
            "compress" => {
                if log_bool(v).is_none() {
                    return Err(invalid(format!(
                        "invalid boolean `{v}` for the log option compress"
                    )));
                }
            }
            "tag" => {
                if let Some(b) = v.bytes().find(|&b| b < 0x20 || b == 0x7f) {
                    return Err(invalid(format!(
                        "the log tag {v:?} has a control character ({b:#04x})"
                    )));
                }
            }
            _ => {
                return Err(invalid(format!(
                    "unknown log option `{k}` (supported: {})",
                    LOG_OPTS.join(", ")
                )))
            }
        }
    }
    Ok(())
}

/// The directory of `allowlist` the `path` option is in: none without a
/// path; an error when the allowlist is set and has no directory above it.
/// (The path has no `..`: `validate_log_config` refused it.)
pub fn allowed_log_path(
    allowlist: &[PathBuf],
    opts: &HashMap<String, String>,
) -> ContainerResult<Option<PathBuf>> {
    let Some(path) = opts.get("path") else {
        return Ok(None);
    };
    if allowlist.is_empty() {
        return Ok(None);
    }
    let parent = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("/"));
    allowlist
        .iter()
        .find(|d| parent.starts_with(d))
        .cloned()
        .map(Some)
        .ok_or_else(|| {
            ContainerError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "the log path {path} is not in a directory of log_path_allowlist ({})",
                    allowlist
                        .iter()
                        .map(|d| d.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ))
        })
}

/// A log tag with podman's and Docker's templates: `{{.ID}}` (short),
/// `{{.FullID}}`, `{{.Name}}`, `{{.ImageName}}`.
pub fn expand_tag(tag: &str, id: &str, name: &str, image: &str) -> String {
    let mut out = String::new();
    let mut rest = tag;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find("}}") else {
            out.push_str(&rest[i..]);
            return out;
        };
        match rest[i + 2..i + j].trim() {
            ".ID" => out.push_str(&id[..id.len().min(12)]),
            ".FullID" => out.push_str(id),
            ".Name" => out.push_str(name),
            ".ImageName" => out.push_str(image),
            _ => out.push_str(&rest[i..i + j + 2]),
        }
        rest = &rest[i + j + 2..];
    }
    out.push_str(rest);
    out
}

impl ContainerService {
    /// The log configuration of a container: its options, then the
    /// defaults of the daemon.
    pub(crate) fn log_config_of(
        &self,
        container: &ContainerRecord,
        config: &ContainerConfig,
    ) -> LogConfig {
        let defaults = &self.containers_config;
        let opts = &config.log_opts;
        let size = |key: &str, default: &str| {
            opts.get(key)
                .and_then(|v| match key {
                    "max-size" => log_opt_size(v),
                    _ => parse_size(v),
                })
                .or_else(|| parse_size(default))
                .unwrap_or(0)
        };
        // (validated at create: a list that does not parse is the default)
        let drivers = LogDriver::parse_list(&config.log_driver)
            .or_else(|_| LogDriver::parse_list(defaults.effective_log_driver()))
            .unwrap_or_else(|_| vec![LogDriver::default()]);
        let name = container.name.clone().unwrap_or_default();
        LogConfig {
            driver: drivers.first().copied().unwrap_or_default(),
            also: drivers.iter().skip(1).copied().collect(),
            allow_dir: allowed_log_path(&defaults.log_path_allowlist, opts)
                .ok()
                .flatten(),
            path: opts
                .get("path")
                .map(PathBuf::from)
                .unwrap_or_else(|| self.log_file(&container.id)),
            max_size: size("max-size", &defaults.log_max_size),
            max_files: opts
                .get("max-file")
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.log_max_files),
            global_max: size("global-size-max", &defaults.log_global_size_max),
            compress: opts
                .get("compress")
                .and_then(|v| log_bool(v))
                .unwrap_or(defaults.log_compress),
            tag: opts
                .get("tag")
                .map(|t| expand_tag(t, &container.id, &name, &config.image)),
            name,
            image: config.image.clone(),
            labels: config.labels.clone(),
        }
    }

    /// The longest a followed line is held back to be put in order with the
    /// lines of the other containers (a line that arrives later than that
    /// comes out of order).
    pub fn log_follow_window(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.containers_config.log_follow_window_ms)
    }

    pub async fn log_location(&self, id: &str) -> ContainerResult<LogLocation> {
        let container = self.db.get_container(id).await?;
        let config: ContainerConfig = serde_json::from_str(&container.config)?;
        let log = self.log_config_of(&container, &config);
        Ok(LogLocation {
            driver: log.driver,
            path: log.path,
            allow_dir: log.allow_dir,
        })
    }

    /// Open the log file of a running container again, after somebody
    /// rotated it (the kubelet does).
    pub async fn reopen_log(&self, id: &str) -> ContainerResult<()> {
        let container = self.db.get_container(id).await?;
        if container.state != RecordState::Running {
            return Err(ContainerError::NotRunning(id.to_string()));
        }
        let dir = self.mon_dir(&container.id);
        tokio::task::spawn_blocking(move || velarx_wire::monitor::client::reopen_log(&dir))
            .await
            .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?
            .map_err(ContainerError::Io)
    }

    /// The lines of the log of a container.
    pub async fn collect_logs(&self, id: &str, query: &LogQuery) -> ContainerResult<Vec<LogEntry>> {
        let loc = self.log_location(id).await?;
        match loc.driver {
            LogDriver::K8sFile => {}
            LogDriver::None => {
                return Err(ContainerError::NoLogs {
                    message: "this container is using the 'none' log driver, cannot read logs: this container is not logging output".into(),
                    cause: NOT_LOGGING.into(),
                })
            }
            LogDriver::Journald => return self.journal_logs(id, query).await,
            LogDriver::Passthrough => {
                return Err(ContainerError::NoLogs {
                    message: "this container is using the 'passthrough' log driver, cannot read logs: this container is not logging output".into(),
                    cause: NOT_LOGGING.into(),
                })
            }
            LogDriver::Syslog => {
                let message = "the logs of the container are in syslog: they cannot be read back \
                     (log driver syslog; k8s-file,syslog keeps them in a file too)";
                return Err(ContainerError::NoLogs {
                    message: message.into(),
                    cause: message.into(),
                })
            }
        }
        let opts = ReadOptions {
            since_ns: query.since_ns,
            until_ns: query.until_ns,
            tail: query.tail,
            follow: false,
            allow_dir: loc.allow_dir.clone(),
        };
        let timestamps = query.timestamps;
        let path = loc.path;
        tokio::task::spawn_blocking(move || -> std::io::Result<Vec<LogEntry>> {
            let mut asm = LineAssembler::default();
            let mut out = Vec::new();
            let entry = |(ts, stream, content): (i64, Stream, Vec<u8>)| LogEntry {
                timestamp: timestamps.then(|| logfmt::format_rfc3339_ns(ts)),
                stream: match stream {
                    Stream::Stdout => LogStream::Stdout,
                    Stream::Stderr => LogStream::Stderr,
                },
                message: String::from_utf8_lossy(&content).into_owned(),
            };
            match logfmt::read_logs(&path, &opts, None, &mut |r| {
                if let Some(line) = asm.push(r) {
                    out.push(entry(line));
                }
                Ok(())
            }) {
                Ok(()) => {}
                // Nothing was ever written.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            out.extend(asm.finish().into_iter().map(entry));
            Ok(out)
        })
        .await
        .map_err(|e| ContainerError::Io(std::io::Error::other(e)))?
        .map_err(ContainerError::Io)
    }

    /// All the lines of the log, with their time, for a pod.
    pub async fn get_logs(
        &self,
        id: &str,
        since_ns: Option<i64>,
        until_ns: Option<i64>,
        tail: Option<u64>,
    ) -> ContainerResult<Vec<LogEntry>> {
        let query = LogQuery {
            tail: tail.filter(|&n| n > 0).map(|n| n as usize),
            timestamps: true,
            since_ns,
            until_ns,
        };
        self.collect_logs(id, &query).await
    }

    /// The lines of the container in the journal and those it writes next, as
    /// they come, until the container ends: `journalctl --follow` of its
    /// entries, then what the journal got after the last one read (each line
    /// once, in the order of the journal).  The channel closes at the end, or
    /// when its receiver is dropped.
    pub async fn follow_journal_logs(
        self: &Arc<Self>,
        id: &str,
        query: LogQuery,
    ) -> ContainerResult<tokio::sync::mpsc::Receiver<LogEntry>> {
        use std::os::fd::AsFd;
        let container = self.db.get_container(id).await?;
        let follow = journal_query(&container.id, &query)?
            .follow()
            .map_err(journal_error)?;
        let (stop, ended) = rustix::pipe::pipe().map_err(std::io::Error::from)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let (done, read) = tokio::sync::oneshot::channel::<()>();
        let timestamps = query.timestamps;
        let lines = tx.clone();
        tokio::task::spawn_blocking(move || {
            let _done = done;
            let mut give = |l| lines.blocking_send(journal_entry(l, timestamps)).is_ok();
            if let Err(e) = follow.run(stop.as_fd(), &mut give) {
                tracing::debug!("following the journal: {e}");
            }
        });
        // (the end of the container, of the reader of the lines or of the
        // follow itself closes the pipe: the follow reads what is left and
        // ends, and nothing waits for a container that goes on)
        let service = self.clone();
        let id = container.id.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = service.wait(&id) => {}
                () = tx.closed() => {}
                _ = read => {}
            }
            drop(ended);
        });
        Ok(rx)
    }

    /// The lines of the container in the journal, read with `journalctl`.
    async fn journal_logs(&self, id: &str, query: &LogQuery) -> ContainerResult<Vec<LogEntry>> {
        let container = self.db.get_container(id).await?;
        let journal = journal_query(&container.id, query)?;
        let lines = tokio::task::spawn_blocking(move || journal.read())
            .await
            .map_err(std::io::Error::other)?
            .map_err(journal_error)?;
        Ok(lines
            .into_iter()
            .map(|l| journal_entry(l, query.timestamps))
            .collect())
    }
}

/// What the journal is asked of the container `id`: the entries of this
/// user's monitors (another user cannot put lines in the log of a container
/// with its fields, as podman's).
fn journal_query(id: &str, query: &LogQuery) -> ContainerResult<journal::Query> {
    Ok(journal::Query {
        program: "journalctl".into(),
        id: id.to_string(),
        uid: velarx_base::ids::host_uid().map_err(std::io::Error::other)?,
        since_ns: query.since_ns,
        until_ns: query.until_ns,
        tail: query.tail,
    })
}

/// A `journalctl` that is not there is a host that cannot read the journal.
fn journal_error(e: std::io::Error) -> ContainerError {
    if e.kind() == std::io::ErrorKind::NotFound {
        ContainerError::Unsupported(
            "the journald log driver needs journalctl, which is not installed".to_string(),
        )
    } else {
        ContainerError::Io(e)
    }
}

/// The output of `journalctl -o json` for the entries that have all of
/// `matches` (FIELD=value) between `since` and `until` (nanoseconds), and
/// with `after` those kept after the entry of that cursor.
pub async fn journalctl(
    matches: &[String],
    since: Option<i64>,
    until: Option<i64>,
    after: Option<&str>,
) -> std::io::Result<std::process::Output> {
    let mut cmd = tokio::process::Command::new("journalctl");
    cmd.args(["--no-pager", "-o", "json"]).args(matches);
    if let Some(cursor) = after {
        cmd.arg(format!("--after-cursor={cursor}"));
    }
    if let Some(ns) = since {
        cmd.arg(format!("--since={}", journal::epoch(ns)));
    }
    if let Some(ns) = until {
        cmd.arg(format!("--until={}", journal::epoch(ns)));
    }
    cmd.stdin(std::process::Stdio::null()).kill_on_drop(true);
    // (it reads what the journal holds and ends; a caller that goes away
    // drops the future, which kills it)
    cmd.output().await
}

fn journal_entry(l: logfmt::JournalLine, timestamps: bool) -> LogEntry {
    LogEntry {
        timestamp: timestamps.then_some(l.timestamp),
        stream: if l.stderr {
            LogStream::Stderr
        } else {
            LogStream::Stdout
        },
        message: l.message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entries of `journalctl -o json`: one object per line, partial
    /// messages joined.
    fn parse_journal_json(data: &[u8], timestamps: bool) -> Vec<LogEntry> {
        let mut lines = logfmt::JournalLines::default();
        data.split(|&c| c == b'\n')
            .filter(|l| !l.is_empty())
            .filter_map(|l| lines.push(l))
            .map(|l| journal_entry(l, timestamps))
            .collect()
    }

    #[test]
    fn journal_entries_are_joined_and_typed() {
        let data = br#"{"MESSAGE":"par","PRIORITY":"6","PARTIAL_MESSAGE":"true","__REALTIME_TIMESTAMP":"1700000000000001"}
{"MESSAGE":"tial","PRIORITY":"6","__REALTIME_TIMESTAMP":"1700000001000000"}
{"MESSAGE":[104,105],"PRIORITY":"3","__REALTIME_TIMESTAMP":"1700000002000000"}
garbage
{"PRIORITY":"6"}
"#;
        let e = parse_journal_json(data, true);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].message, "partial");
        assert_eq!(e[0].stream, LogStream::Stdout);
        assert_eq!(
            e[0].timestamp.as_deref(),
            Some("2023-11-14T22:13:20.000001000Z")
        );
        assert_eq!(
            (e[1].message.as_str(), &e[1].stream),
            ("hi", &LogStream::Stderr)
        );
        assert!(parse_journal_json(data, false)[0].timestamp.is_none());
    }

    #[test]
    fn log_options_are_validated() {
        let opts = |kv: &[(&str, &str)]| -> HashMap<String, String> {
            kv.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        assert!(validate_log_config("", &HashMap::new()).is_ok());
        assert!(validate_log_config("journald", &opts(&[("tag", "x")])).is_ok());
        assert!(validate_log_config(
            "k8s-file",
            &opts(&[
                ("max-size", "10m"),
                ("max-file", "3"),
                ("path", "/var/log/x.log")
            ])
        )
        .is_ok());
        assert!(validate_log_config("syslog", &HashMap::new()).is_ok());
        assert!(validate_log_config("k8s-file,syslog,journald", &HashMap::new()).is_ok());
        for bad in [
            "gelf",
            "k8s-file,k8s-file",
            "none,syslog",
            "k8s-file,passthrough",
            "k8s-file,",
        ] {
            assert!(validate_log_config(bad, &HashMap::new()).is_err(), "{bad}");
        }
        assert!(validate_log_config("", &opts(&[("tag", "a\nb")])).is_err());
        assert!(validate_log_config("", &opts(&[("max-size", "10x")])).is_err());
        assert!(validate_log_config("", &opts(&[("max-file", "0")])).is_err());
        assert!(validate_log_config("", &opts(&[("path", "relative.log")])).is_err());
        assert!(validate_log_config("", &opts(&[("path", "/a/../etc/x")])).is_err());
        assert!(validate_log_config("", &opts(&[("path", "/")])).is_err());
        assert!(validate_log_config("", &opts(&[("bogus", "1")])).is_err());
    }

    #[test]
    fn the_allowlist_of_log_paths() {
        let allow = vec![PathBuf::from("/var/log/ctr"), PathBuf::from("/srv/logs")];
        let o =
            |p: &str| -> HashMap<String, String> { [("path".to_string(), p.to_string())].into() };
        assert_eq!(allowed_log_path(&[], &o("/etc/x.log")).unwrap(), None);
        assert_eq!(allowed_log_path(&allow, &HashMap::new()).unwrap(), None);
        assert_eq!(
            allowed_log_path(&allow, &o("/srv/logs/a/b.log")).unwrap(),
            Some(PathBuf::from("/srv/logs"))
        );
        assert_eq!(
            allowed_log_path(&allow, &o("/var/log/ctr/b.log")).unwrap(),
            Some(PathBuf::from("/var/log/ctr"))
        );
        for bad in ["/var/log/ctrx/b.log", "/etc/x.log", "/var/log/b.log"] {
            assert!(allowed_log_path(&allow, &o(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn tag_templates() {
        let id = "0123456789abcdef0123";
        assert_eq!(expand_tag("plain", id, "web", "img"), "plain");
        assert_eq!(
            expand_tag(
                "{{.Name}}/{{ .ID }}/{{.FullID}}/{{.ImageName}}",
                id,
                "web",
                "img:1"
            ),
            "web/0123456789ab/0123456789abcdef0123/img:1"
        );
        assert_eq!(
            expand_tag("{{.Nope}}-{{.Name", id, "web", "i"),
            "{{.Nope}}-{{.Name"
        );
    }
}
