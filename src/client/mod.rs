// SPDX-License-Identifier: Apache-2.0
mod backend;
mod engine;
pub mod policy;

pub use backend::*;
pub use engine::{warn, EngineClient, Opened};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use thiserror::Error;
use velarx_proto::workload::{CheckpointReport, RestoreReport};
use velarx_registry::auth::RegistryAccess;
pub use velarx_wire::request::{BuildRun, CreateContainerRequest};
use velarx_wire::wire::{CheckpointOptions, ManifestRequest, RestoreOptions};
pub use velarx_wire::wire::{PodLogEntry, TopResult};

mod types;
pub use types::*;

/// The spec of an artifact, the annotations of the index and its subject.
pub type ArtifactSpecParts = (
    velarx_proto::engine::ManifestArtifactSpec,
    std::collections::BTreeMap<String, String>,
    Option<String>,
);

/// The members of the object `v` that are strings (none when it is not
/// an object): annotations.
pub fn string_map(v: &Value) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in v.as_object().into_iter().flatten() {
        if let Some(v) = v.as_str() {
            out.insert(k.clone(), v.to_string());
        }
    }
    out
}

/// What `velarx manifest add --artifact` asks, from the modification the
/// command line builds (`req`: the members of podman's) and the files: the
/// spec of the artifact, the annotations of the index and its subject.
pub fn artifact_spec(req: &Value, files: &[PathBuf]) -> Result<ArtifactSpecParts, String> {
    let text = |k: &str| req[k].as_str().unwrap_or_default().to_string();
    let texts = |k: &str| -> Vec<String> {
        req[k]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let map = |k: &str| string_map(&req[k]);
    let mut titles: Vec<String> = Vec::new();
    for f in files {
        let title = f
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.contains(['"', '\r', '\n']))
            .ok_or_else(|| format!("invalid file name {}", f.display()))?
            .to_string();
        if titles.contains(&title) {
            return Err(format!("the file {title} is given twice"));
        }
        titles.push(title);
    }
    let spec = velarx_proto::engine::ManifestArtifactSpec {
        titles,
        artifact_type: req["artifact_type"].as_str().map(str::to_string),
        layer_type: text("artifact_layer_type"),
        config_type: text("artifact_config_type"),
        config: text("artifact_config"),
        exclude_titles: req["artifact_exclude_titles"].as_bool().unwrap_or(false),
        annotations: map("artifact_annotations"),
        subject: text("artifact_subject"),
        instance: velarx_proto::engine::InstanceSpec {
            annotations: map("annotations"),
            architecture: text("arch"),
            os: text("os"),
            os_version: text("os_version"),
            variant: text("variant"),
            features: texts("features"),
            os_features: texts("os_features"),
        },
    };
    let subject = Some(text("subject")).filter(|s| !s.is_empty());
    Ok((spec, map("index_annotations"), subject))
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("daemon not running (socket not found: {0})")]
    DaemonNotRunning(PathBuf),
    #[error("connection error: {0}")]
    Connection(String),
    #[error("request error: {0}")]
    Request(String),
    #[error("{message}")]
    Api {
        status: u16,
        message: String,
        /// The engine's condition, when the error is one it named
        condition: Option<velarx_proto::engine::Condition>,
    },
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// A signal ended the command (in the engine of the command: once its
    /// operation stopped; SIGPIPE: the reader of its output went away).
    #[error("interrupted by signal {0}")]
    Interrupted(i32),
}

impl ClientError {
    /// An error with a status, that the engine did not name.
    pub fn api(status: u16, message: String) -> Self {
        Self::Api {
            status,
            message,
            condition: None,
        }
    }

    /// An error of `condition` of the engine's interface.
    pub fn refused(condition: velarx_proto::engine::Condition, message: String) -> Self {
        Self::Api {
            status: condition.status(),
            message,
            condition: Some(condition),
        }
    }

    /// The engine named this condition.
    pub fn is(&self, wanted: velarx_proto::engine::Condition) -> bool {
        matches!(self, Self::Api { condition: Some(c), .. } if *c == wanted)
    }

    /// The daemon says the resource does not exist.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Api { status: 404, .. })
    }

    /// The daemon failed (a 5xx): not a thing that is not there.
    pub fn is_server_error(&self) -> bool {
        matches!(self, Self::Api { status, .. } if *status >= 500)
    }

    /// A signal ended the command.
    pub fn is_interrupted(&self) -> bool {
        matches!(self, Self::Interrupted(_))
    }

    /// The daemon says the resource exists already.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Api { status: 409, .. })
    }

    /// The writer of the output of a command failed: a reader that went
    /// away (`| head`) ends the command with the status of SIGPIPE, as
    /// podman's.
    pub fn of_output(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            Self::Interrupted(libc::SIGPIPE)
        } else {
            Self::Connection(format!("the output of the command: {e}"))
        }
    }
}

pub type ClientResult<T> = Result<T, ClientError>;

/// The error of the first `--filter` without a `=` (podman's words): it
/// would select nothing or all, so a prune refuses it, with the engine or
/// without.
pub fn filter_without_value(filter: &[String]) -> Option<String> {
    filter
        .iter()
        .find(|f| !f.contains('='))
        .map(|f| format!("filter input must be in the form of filter=value: {f} is invalid"))
}

/// [`filter_without_value`] as the error of a prune through the engine.
pub fn check_prune_filters(filter: &[String]) -> ClientResult<()> {
    match filter_without_value(filter) {
        Some(message) => Err(ClientError::api(500, message)),
        None => Ok(()),
    }
}

/// podman's `--filter KEY=VALUE`s, by key.
pub fn filter_map(filter: &[String]) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut m: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for f in filter {
        let (k, v) = f.split_once('=').unwrap_or((f.as_str(), ""));
        m.entry(k.to_string()).or_default().push(v.to_string());
    }
    m
}

/// The repository and the tag of an image name (`latest` when it has
/// none; a port of the registry is no tag).
pub fn split_tag(name: &str) -> (&str, &str) {
    let slash = name.rfind('/').map_or(0, |i| i + 1);
    match name[slash..].rfind(':') {
        Some(c) => (&name[..slash + c], &name[slash + c + 1..]),
        None => (name, "latest"),
    }
}

#[cfg(test)]
mod secret_tests {
    use velarx_wire::request::SecretRef;

    #[test]
    fn secret_options() {
        let r = SecretRef::parse("db,type=env,target=DB_PASS").unwrap();
        assert!(r.env && r.target == "DB_PASS" && r.name == "db");
        let r = SecretRef::parse("key,target=/etc/key,mode=0600,uid=1,gid=2").unwrap();
        assert_eq!((r.mode, r.uid, r.gid, r.env), (0o600, 1, 2, false));
        assert_eq!(SecretRef::parse("plain").unwrap().name, "plain");
    }

    #[test]
    fn secret_errors() {
        for bad in [
            "",
            "a,type=file",
            "a,mode=9",
            "a,bogus",
            "a,x=1",
            "type=env",
        ] {
            assert!(SecretRef::parse(bad).is_err(), "{bad}");
        }
    }
}
