// SPDX-License-Identifier: Apache-2.0
//! Volumes: podman's VolumeConfigResponse and Docker's Volume.

use crate::{string_map, time::rfc3339};
use serde_json::{json, Value};
use velarx_proto::workload::VolumeRecord;

/// podman's VolumeConfigResponse (`podman volume inspect`, libpod's routes).
pub fn libpod(v: &VolumeRecord) -> Value {
    let mut o = docker(v);
    o["Options"] = string_map(&v.options);
    if let Some(m) = o.as_object_mut() {
        // (podman's omitempty: left out when 0, false)
        if v.uid != 0 {
            m.insert("UID".into(), json!(v.uid));
        }
        if v.gid != 0 {
            m.insert("GID".into(), json!(v.gid));
        }
        if v.anonymous {
            m.insert("Anonymous".into(), json!(true));
        }
        m.insert("MountCount".into(), json!(0));
        m.insert("NeedsCopyUp".into(), json!(v.needs_copy_up));
        m.insert("NeedsChown".into(), json!(v.needs_chown));
        m.insert("LockNumber".into(), json!(0));
    }
    o
}

/// Docker's Volume.
pub fn docker(v: &VolumeRecord) -> Value {
    json!({
        "Name": v.name,
        "Driver": v.driver,
        "Mountpoint": v.mountpoint,
        "CreatedAt": rfc3339(v.created_ns),
        "Labels": string_map(&v.labels),
        "Scope": v.scope,
        // a map that Go writes as null when it is empty
        "Options": if v.options.is_empty() {
            Value::Null
        } else {
            string_map(&v.options)
        },
    })
}

/// Of either API.
pub fn document(v: &VolumeRecord, libpod: bool) -> Value {
    if libpod {
        self::libpod(v)
    } else {
        docker(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shapes_of_a_volume() {
        let v = VolumeRecord {
            name: "v".into(),
            driver: "local".into(),
            mountpoint: "/x/v".into(),
            labels: [("k".to_string(), "x".to_string())].into(),
            created_ns: 1_767_323_045_000_000_000,
            scope: "local".into(),
            ..Default::default()
        };
        let p = libpod(&v);
        assert_eq!(p["Labels"]["k"], "x");
        assert_eq!(p["CreatedAt"], "2026-01-02T03:04:05Z");
        assert_eq!(p["MountCount"], 0);
        assert_eq!(p["Options"], json!({}));
        let d = docker(&v);
        assert!(d.get("MountCount").is_none());
        assert_eq!(d["Options"], Value::Null);
        assert_eq!(d["Driver"], "local");
    }
}
