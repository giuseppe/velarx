// SPDX-License-Identifier: Apache-2.0
//! Secrets: podman's SecretInfoReport and Docker's Secret.

use crate::{string_map, time::rfc3339};
use serde_json::{json, Value};
use velarx_proto::workload::SecretRecord;

/// With `SecretData` when the record has the data (`showsecret`, of either
/// API as podman's).
fn common(s: &SecretRecord) -> Value {
    let mut o = json!({
        "ID": s.id,
        "CreatedAt": rfc3339(s.created_ns),
        "UpdatedAt": rfc3339(s.updated_ns),
        "Spec": {
            "Name": s.name,
            "Driver": {"Name": s.driver, "Options": string_map(&s.driver_options)},
            "Labels": string_map(&s.labels),
        },
    });
    if let (Some(d), Some(m)) = (&s.data, o.as_object_mut()) {
        m.insert("SecretData".into(), json!(String::from_utf8_lossy(d)));
    }
    o
}

/// podman's SecretInfoReport.
pub fn libpod(s: &SecretRecord) -> Value {
    common(s)
}

/// Docker's Secret (podman's, with its version).
pub fn docker(s: &SecretRecord) -> Value {
    let mut o = common(s);
    if let Some(m) = o.as_object_mut() {
        m.insert("Version".into(), json!({"Index": 1}));
    }
    o
}

/// Of either API.
pub fn document(s: &SecretRecord, libpod: bool) -> Value {
    if libpod {
        self::libpod(s)
    } else {
        docker(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> SecretRecord {
        SecretRecord {
            id: "0123abcd".into(),
            name: "s".into(),
            driver: "file".into(),
            labels: [("k".to_string(), "v".to_string())].into(),
            created_ns: 1_767_323_045_000_000_000,
            updated_ns: 1_767_323_045_120_000_000,
            ..Default::default()
        }
    }

    #[test]
    fn the_shapes_of_a_secret() {
        let p = libpod(&secret());
        assert_eq!(p["ID"], "0123abcd");
        assert_eq!(p["Spec"]["Name"], "s");
        assert_eq!(p["Spec"]["Driver"]["Name"], "file");
        assert_eq!(p["Spec"]["Driver"]["Options"], json!({}));
        assert_eq!(p["Spec"]["Labels"]["k"], "v");
        assert_eq!(p["CreatedAt"], "2026-01-02T03:04:05Z");
        assert_eq!(p["UpdatedAt"], "2026-01-02T03:04:05.120Z");
        assert!(p.get("SecretData").is_none() && p.get("Version").is_none());
        let d = docker(&secret());
        assert_eq!(d["Version"]["Index"], 1);
    }

    #[test]
    fn the_data_only_when_the_record_has_it() {
        let s = SecretRecord {
            data: Some(b"hunter2".to_vec()),
            ..secret()
        };
        assert_eq!(libpod(&s)["SecretData"], "hunter2");
        assert_eq!(docker(&s)["SecretData"], "hunter2");
        assert!(docker(&secret()).get("SecretData").is_none());
        let debug = format!("{s:?}");
        assert!(
            !debug.contains("hunter2") && debug.contains("redacted"),
            "{debug}"
        );
    }
}
