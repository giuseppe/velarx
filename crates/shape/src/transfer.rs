// SPDX-License-Identifier: Apache-2.0
//! The JSON lines of the answers of podman's and Docker's pulls and pushes,
//! made of the records the engine answers as they go (`ImagePull`,
//! `ImagePush`): libpod's text (`stream`) or its report of each layer
//! (`pullProgress`), Docker's statuses.

use serde_json::{json, Map, Value};
use std::collections::HashSet;
use velarx_proto::workload::{TransferProgress, TransferStatus};

/// What the answer of a pull is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullFormat {
    /// libpod's text
    Libpod,
    /// libpod's report of each layer (podman 6's `pullProgress`)
    LibpodReport,
    /// Docker's statuses (podman's CompatPull)
    Docker,
}

/// The first 12 hex digits of a digest or an id, as the progress shows
/// them.
fn short_digest(d: &str) -> String {
    crate::without_algorithm(d).chars().take(12).collect()
}

/// The error of a registry in a message, as Docker's errcode writes it
/// (`unauthorized: access to the requested resource is not authorized`):
/// what podman's compat pull answers.
pub fn registry_error_text(msg: &str) -> Option<String> {
    let start = msg.find("{\"errors\"")?;
    let v: Value = serde_json::Deserializer::from_str(&msg[start..])
        .into_iter::<Value>()
        .next()?
        .ok()?;
    let e = v["errors"].get(0)?;
    let code = e["code"].as_str()?.to_ascii_lowercase().replace('_', " ");
    let message = e["message"].as_str().unwrap_or("");
    Some(format!("{code}: {message}"))
}

/// The lines of the answer of a pull, as the progress comes.
pub struct PullLines {
    format: PullFormat,
    quiet: bool,
    seen: HashSet<String>,
}

impl PullLines {
    pub fn new(format: PullFormat, quiet: bool) -> Self {
        Self {
            format,
            quiet,
            seen: HashSet::new(),
        }
    }

    /// libpod's text of a pull that starts (none of an image of the store).
    pub fn start(&self, reference: &str) -> Vec<Value> {
        if self.format != PullFormat::Libpod || self.quiet {
            return Vec::new();
        }
        vec![json!({ "stream": format!("Trying to pull {reference}...\n") })]
    }

    /// What a progress of a layer shows (nothing of the image as a whole).
    pub fn progress(&mut self, p: &TransferProgress) -> Vec<Value> {
        if p.layer.is_empty() {
            return Vec::new();
        }
        let first = self.seen.insert(p.layer.clone());
        let exists = p.status == TransferStatus::Exists;
        match self.format {
            PullFormat::LibpodReport => {
                let (stream, status, current, total) = if exists {
                    ("Artifact already exists", "skipped", 0, 0)
                } else if p.complete {
                    (
                        "Artifact pulled successfully",
                        "success",
                        p.total_bytes,
                        p.total_bytes,
                    )
                } else if first {
                    (
                        "Starting to pull artifact",
                        "pulling",
                        p.current_bytes,
                        p.total_bytes,
                    )
                } else {
                    (
                        "Pulling artifact",
                        "pulling",
                        p.current_bytes,
                        p.total_bytes,
                    )
                };
                let mut progress = Map::new();
                progress.insert("status".into(), json!(status));
                if current != 0 {
                    progress.insert("current".into(), json!(current));
                }
                if total != 0 {
                    progress.insert("total".into(), json!(total));
                }
                progress.insert("progressComponentID".into(), json!(p.layer));
                vec![json!({"status": "pulling", "stream": stream, "pullProgress": progress})]
            }
            _ if self.quiet => Vec::new(),
            PullFormat::Libpod if first => {
                vec![json!({ "stream": format!("Copying blob {}\n", p.layer) })]
            }
            PullFormat::Libpod => Vec::new(),
            PullFormat::Docker => {
                let short = short_digest(&p.layer);
                let status = |s: &str, detail: Value| json!({"status": s, "progressDetail": detail, "id": short});
                if exists {
                    return vec![status("Already exists", json!({}))];
                }
                let mut lines = Vec::new();
                if first {
                    lines.push(status("Pulling fs layer", json!({})));
                }
                lines.push(if p.complete {
                    status("Download complete", json!({}))
                } else {
                    status(
                        "Downloading",
                        json!({"current": p.current_bytes, "total": p.total_bytes}),
                    )
                });
                lines
            }
        }
    }

    /// The end of a pull of the images `ids` (the last the one asked for);
    /// `pulled` false: the image of the store was the answer.
    pub fn end(&self, ids: &[String], pulled: bool) -> Vec<Value> {
        let id = ids.last().cloned().unwrap_or_default();
        match self.format {
            PullFormat::Docker => vec![json!({
                "status": "Download complete", "progressDetail": {}, "id": short_digest(&id),
            })],
            PullFormat::LibpodReport => {
                vec![json!({"status": "success", "images": ids, "id": id})]
            }
            PullFormat::Libpod => {
                let mut lines = Vec::new();
                if pulled && !self.quiet {
                    lines.push(json!({"stream": "Writing manifest to image destination\n"}));
                }
                // (quiet: podman 5's report alone)
                lines.push(json!({"images": ids, "id": id}));
                lines
            }
        }
    }

    /// The end of a pull that failed after the answer started.
    pub fn error(&self, message: &str) -> Value {
        match self.format {
            PullFormat::Docker => {
                let msg = registry_error_text(message).unwrap_or_else(|| message.to_string());
                json!({"error": msg, "errorDetail": {"message": msg}})
            }
            PullFormat::LibpodReport => json!({"status": "error", "error": message}),
            PullFormat::Libpod => json!({ "error": message }),
        }
    }
}

/// libpod's text of a push that starts.
pub fn push_start(destination: &str, quiet: bool) -> Vec<Value> {
    if quiet {
        return Vec::new();
    }
    vec![json!({ "stream": format!("Pushing {destination}\n") })]
}

/// libpod's end of a push of the manifest `digest`.
pub fn push_end(digest: &str, quiet: bool) -> Vec<Value> {
    let mut lines = Vec::new();
    if !quiet {
        lines.push(json!({"stream": "Writing manifest to image destination\n"}));
    }
    lines.push(json!({ "manifestdigest": digest }));
    lines
}

/// Docker's answer of a push of the tag `tag` to `destination`, done.
pub fn docker_pushed(destination: &str, tag: &str, digest: &str, size: u64) -> Vec<Value> {
    vec![
        json!({"status": format!("The push refers to repository [{destination}]")}),
        json!({
            "status": format!("{tag}: digest: {digest} size: {size}"),
            "progressDetail": {},
            "aux": {"Tag": tag, "Digest": digest, "Size": size},
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(status: TransferStatus, current: u64, complete: bool) -> TransferProgress {
        TransferProgress {
            layer: format!("sha256:{}", "ab".repeat(32)),
            status,
            current_bytes: current,
            total_bytes: 10,
            complete,
            ..Default::default()
        }
    }

    #[test]
    fn registry_errors_as_errcode_writes_them() {
        let m = "registry error: Failed to get manifest: 401 Unauthorized - {\"errors\":[{\"code\":\"UNAUTHORIZED\",\"detail\":{},\"message\":\"access to the requested resource is not authorized\"}]}\u{fffd}";
        assert_eq!(
            registry_error_text(m).as_deref(),
            Some("unauthorized: access to the requested resource is not authorized")
        );
        let m =
            "404 - {\"errors\":[{\"code\":\"MANIFEST_UNKNOWN\",\"message\":\"manifest unknown\"}]}";
        assert_eq!(
            registry_error_text(m).as_deref(),
            Some("manifest unknown: manifest unknown")
        );
        assert_eq!(registry_error_text("connection refused"), None);
    }

    #[test]
    fn libpod_s_text_tells_each_blob_once() {
        let mut l = PullLines::new(PullFormat::Libpod, false);
        assert_eq!(
            l.start("quay.io/a:1"),
            [json!({"stream": "Trying to pull quay.io/a:1...\n"})]
        );
        let first = l.progress(&layer(TransferStatus::Downloading, 1, false));
        assert_eq!(first.len(), 1);
        assert!(first[0]["stream"]
            .as_str()
            .unwrap()
            .starts_with("Copying blob sha256:abab"));
        assert!(l
            .progress(&layer(TransferStatus::Downloading, 5, false))
            .is_empty());
        // (the image as a whole shows nothing)
        assert!(l.progress(&TransferProgress::default()).is_empty());
        let ids = ["x".to_string(), "y".to_string()];
        assert_eq!(
            l.end(&ids, true),
            [
                json!({"stream": "Writing manifest to image destination\n"}),
                json!({"images": ["x", "y"], "id": "y"})
            ]
        );
        assert_eq!(
            l.end(&ids, false),
            [json!({"images": ["x", "y"], "id": "y"})]
        );
        let quiet = PullLines::new(PullFormat::Libpod, true);
        assert!(quiet.start("a").is_empty());
        assert_eq!(
            quiet.end(&ids, true),
            [json!({"images": ["x", "y"], "id": "y"})]
        );
        assert_eq!(l.error("boom"), json!({"error": "boom"}));
    }

    #[test]
    fn docker_s_statuses() {
        let mut l = PullLines::new(PullFormat::Docker, false);
        assert!(l.start("a").is_empty());
        let lines = l.progress(&layer(TransferStatus::Downloading, 3, false));
        assert_eq!(
            lines,
            [
                json!({"status": "Pulling fs layer", "progressDetail": {}, "id": "abababababab"}),
                json!({"status": "Downloading", "progressDetail": {"current": 3, "total": 10},
                       "id": "abababababab"}),
            ]
        );
        assert_eq!(
            l.progress(&layer(TransferStatus::Complete, 10, true))[0]["status"],
            "Download complete"
        );
        let mut other = PullLines::new(PullFormat::Docker, false);
        assert_eq!(
            other.progress(&layer(TransferStatus::Exists, 0, true)),
            [json!({"status": "Already exists", "progressDetail": {}, "id": "abababababab"})]
        );
        assert_eq!(
            l.end(&["sha256:0123456789abcdef".into()], true),
            [json!({"status": "Download complete", "progressDetail": {}, "id": "0123456789ab"})]
        );
        let e = l.error("x {\"errors\":[{\"code\":\"DENIED\",\"message\":\"no\"}]}");
        assert_eq!(
            e,
            json!({"error": "denied: no", "errorDetail": {"message": "denied: no"}})
        );
    }

    #[test]
    fn libpod_s_report_of_each_layer() {
        let mut l = PullLines::new(PullFormat::LibpodReport, false);
        assert!(l.start("a").is_empty());
        let start = &l.progress(&layer(TransferStatus::Downloading, 0, false))[0];
        assert_eq!(start["stream"], "Starting to pull artifact");
        assert_eq!(start["pullProgress"]["status"], "pulling");
        assert!(start["pullProgress"].get("current").is_none());
        assert_eq!(start["pullProgress"]["total"], 10);
        let done = &l.progress(&layer(TransferStatus::Complete, 10, true))[0];
        assert_eq!(
            (&done["stream"], &done["pullProgress"]["current"]),
            (&json!("Artifact pulled successfully"), &json!(10))
        );
        assert_eq!(
            l.end(&["i".into()], true),
            [json!({"status": "success", "images": ["i"], "id": "i"})]
        );
        assert_eq!(l.error("boom"), json!({"status": "error", "error": "boom"}));
    }

    #[test]
    fn the_lines_of_a_push() {
        assert_eq!(
            push_start("quay.io/a:1", false),
            [json!({"stream": "Pushing quay.io/a:1\n"})]
        );
        assert!(push_start("quay.io/a:1", true).is_empty());
        assert_eq!(
            push_end("sha256:d", true),
            [json!({"manifestdigest": "sha256:d"})]
        );
        assert_eq!(push_end("sha256:d", false).len(), 2);
        let d = docker_pushed("quay.io/a", "1", "sha256:d", 7);
        assert_eq!(d[0]["status"], "The push refers to repository [quay.io/a]");
        assert_eq!(
            d[1]["aux"],
            json!({"Tag": "1", "Digest": "sha256:d", "Size": 7})
        );
    }
}
