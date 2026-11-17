// SPDX-License-Identifier: Apache-2.0
//! The text of a bundle's `config.json`, with the keys in the order of the
//! OCI runtime spec (what runc, crun and podman write): `process` and
//! `root` before `linux`.
//!
//! A `serde_json::Value` keeps its object keys sorted, which puts `hooks`
//! and `linux` before `process`.  The init of a krun VM reads the file with
//! a scan for the first string `args` (and `env`, `cwd`) whatever its place
//! in the document, so the `args` of the seccomp rules of `linux` ran as
//! the command.  Every write of a spec goes through here.

use std::io;
use std::path::Path;

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::Value;

/// The top-level keys in the order of the OCI `Spec` struct; the ones this
/// does not list follow, sorted.
const KEY_ORDER: &[&str] = &[
    "ociVersion",
    "process",
    "root",
    "hostname",
    "domainname",
    "mounts",
    "hooks",
    "annotations",
    "linux",
];

struct Ordered<'a>(&'a Value);

impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let Value::Object(map) = self.0 else {
            return self.0.serialize(s);
        };
        let mut out = s.serialize_map(Some(map.len()))?;
        for key in KEY_ORDER {
            if let Some(v) = map.get(*key) {
                out.serialize_entry(key, v)?;
            }
        }
        for (key, v) in map {
            if !KEY_ORDER.contains(&key.as_str()) {
                out.serialize_entry(key, v)?;
            }
        }
        out.end()
    }
}

/// The spec as pretty JSON text, its top-level keys in the OCI order.
fn to_vec_pretty(spec: &Value) -> io::Result<Vec<u8>> {
    serde_json::to_vec_pretty(&Ordered(spec)).map_err(io::Error::other)
}

/// Write the spec to PATH (whole or not at all), its top-level keys in the
/// OCI order.
pub fn write(path: &Path, spec: &Value) -> io::Result<()> {
    // (a temporary file of its own: writers of one spec do not share it)
    velarx_base::atomic_file::write(path, &to_vec_pretty(spec)?, 0o666)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec() -> Value {
        json!({
            "linux": {"seccomp": {"syscalls": [{"names": ["read"],
                "args": [{"index": 0, "op": "SCMP_CMP_EQ", "value": 0, "valueTwo": 0}]}]}},
            "hooks": {"prestart": [{"path": "/h", "args": ["h"], "env": ["A=b"]}]},
            "process": {"args": ["true"], "cwd": "/", "env": ["PATH=/bin"]},
            "annotations": {"a": "b"},
            "mounts": [],
            "hostname": "h",
            "root": {"path": "rootfs"},
            "ociVersion": "1.0.2",
            "zzz": 1,
        })
    }

    fn top_keys(text: &str) -> Vec<String> {
        let v: serde_json::Map<String, Value> = serde_json::from_str(text).unwrap();
        // (the map sorts: read the order from the text)
        let mut keys: Vec<(usize, String)> = v
            .keys()
            .map(|k| (text.find(&format!("\n  \"{k}\"")).unwrap(), k.clone()))
            .collect();
        keys.sort();
        keys.into_iter().map(|(_, k)| k).collect()
    }

    #[test]
    fn top_level_keys_follow_the_oci_order() {
        let text = String::from_utf8(to_vec_pretty(&spec()).unwrap()).unwrap();
        assert_eq!(
            top_keys(&text),
            [
                "ociVersion",
                "process",
                "root",
                "hostname",
                "mounts",
                "hooks",
                "annotations",
                "linux",
                "zzz"
            ]
        );
    }

    #[test]
    fn first_args_is_the_one_of_the_process() {
        let text = String::from_utf8(to_vec_pretty(&spec()).unwrap()).unwrap();
        let (args, linux) = (
            text.find("\"args\"").unwrap(),
            text.find("\"linux\"").unwrap(),
        );
        let process = text.find("\"process\"").unwrap();
        assert!(process < args && args < linux, "{text}");
        // the sorted text of the value is what krun misread
        let sorted = serde_json::to_string_pretty(&spec()).unwrap();
        assert!(sorted.find("\"linux\"") < sorted.find("\"process\""));
    }

    #[test]
    fn a_round_trip_keeps_the_order() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("config.json");
        write(&path, &spec()).unwrap();
        let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["process"]["cwd"] = json!("/tmp");
        write(&path, &v).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.find("\"process\"").unwrap() < text.find("\"linux\"").unwrap());
        assert!(text.contains("/tmp"));
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1,
            "a temporary file left"
        );
    }
}
