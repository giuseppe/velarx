// SPDX-License-Identifier: Apache-2.0
//! Records decoded through a [`Value`]: serde's derived `Deserialize` is a
//! visitor the compiler makes again for every deserializer and for every
//! list of the record (2 to 20 kB each in a release build), while a
//! frontend that only reads a record to lay it out as another document can
//! decode the `Value` it decodes anyway and take the members with one small
//! function of the record.  The rules are those of a derived
//! `#[serde(default)]` record: a missing member is the default, a member of
//! another type is an error, a member the record does not have is ignored.

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The members of a JSON object, taken one by one.
pub(crate) struct Members(Map<String, Value>);

/// A member that is not of the type of its field.
fn wrong(key: &str, what: &str) -> String {
    format!("the member `{key}` is not {what}")
}

impl Members {
    pub(crate) fn of(v: Value) -> Result<Self, String> {
        match v {
            Value::Object(m) => Ok(Self(m)),
            _ => Err("a record is not an object".into()),
        }
    }

    pub(crate) fn text(&mut self, key: &str) -> Result<String, String> {
        match self.0.remove(key) {
            None => Ok(String::new()),
            Some(Value::String(s)) => Ok(s),
            Some(_) => Err(wrong(key, "a string")),
        }
    }

    pub(crate) fn texts(&mut self, key: &str) -> Result<Vec<String>, String> {
        self.list(key, |v| match v {
            Value::String(s) => Ok(s),
            _ => Err(wrong(key, "a list of strings")),
        })
    }

    pub(crate) fn flag(&mut self, key: &str) -> Result<bool, String> {
        match self.0.remove(key) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(b),
            Some(_) => Err(wrong(key, "a boolean")),
        }
    }

    pub(crate) fn int(&mut self, key: &str) -> Result<i64, String> {
        match self.0.remove(key) {
            None => Ok(0),
            Some(v) => v.as_i64().ok_or_else(|| wrong(key, "an integer")),
        }
    }

    /// `null` or missing: none.
    pub(crate) fn opt_int(&mut self, key: &str) -> Result<Option<i64>, String> {
        match self.0.remove(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v.as_i64().map(Some).ok_or_else(|| wrong(key, "an integer")),
        }
    }

    pub(crate) fn size(&mut self, key: &str) -> Result<u64, String> {
        match self.0.remove(key) {
            None => Ok(0),
            Some(v) => v.as_u64().ok_or_else(|| wrong(key, "a size")),
        }
    }

    pub(crate) fn map(&mut self, key: &str) -> Result<BTreeMap<String, String>, String> {
        match self.0.remove(key) {
            None => Ok(BTreeMap::new()),
            Some(Value::Object(o)) => o
                .into_iter()
                .map(|(k, v)| match v {
                    Value::String(s) => Ok((k, s)),
                    _ => Err(wrong(key, "a map of strings")),
                })
                .collect(),
            Some(_) => Err(wrong(key, "a map")),
        }
    }

    /// The record of the member `key`; missing: none.
    pub(crate) fn record<T>(
        &mut self,
        key: &str,
        record: fn(Members) -> Result<T, String>,
    ) -> Result<Option<T>, String> {
        match self.0.remove(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => Members::of(v).and_then(record).map(Some),
        }
    }

    /// The record of the member `key`; missing: the default.
    pub(crate) fn nested<T: Default>(
        &mut self,
        key: &str,
        record: fn(Members) -> Result<T, String>,
    ) -> Result<T, String> {
        match self.0.remove(key) {
            None => Ok(T::default()),
            Some(v) => Members::of(v).and_then(record),
        }
    }

    /// The records of the list `key`, each decoded by `record`.
    pub(crate) fn records<T>(
        &mut self,
        key: &str,
        record: fn(Members) -> Result<T, String>,
    ) -> Result<Vec<T>, String> {
        self.list(key, |v| Members::of(v).and_then(record))
    }

    fn list<T>(
        &mut self,
        key: &str,
        item: impl FnMut(Value) -> Result<T, String>,
    ) -> Result<Vec<T>, String> {
        match self.0.remove(key) {
            None => Ok(Vec::new()),
            Some(Value::Array(a)) => a.into_iter().map(item).collect(),
            Some(_) => Err(wrong(key, "a list")),
        }
    }
}

/// A field of a record, taken from the member of its name.
// (the members of requests are read by the engine: the service feature)
#[cfg_attr(not(feature = "proxy"), allow(dead_code))]
pub(crate) trait Member: Sized {
    /// A request must have the member (not one of an optional field).
    const REQUIRED: bool = true;

    fn take(m: &mut Members, key: &str) -> Result<Self, String>;

    /// The member of a request: missing is an error unless the field is
    /// optional (the definition's rule: a field without `?` is given).
    fn take_given(m: &mut Members, key: &str) -> Result<Self, String> {
        if Self::REQUIRED && !m.0.contains_key(key) {
            return Err(format!("the member `{key}` is missing"));
        }
        Self::take(m, key)
    }
}

/// A record decoded from its members (by [`deserialize_members`]).
pub(crate) trait Record: Sized {
    fn from_members(m: Members) -> Result<Self, String>;
}

impl Member for String {
    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.text(key)
    }
}

impl Member for bool {
    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.flag(key)
    }
}

impl Member for i64 {
    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.int(key)
    }
}

impl Member for Option<i64> {
    const REQUIRED: bool = false;

    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.opt_int(key)
    }
}

impl Member for u64 {
    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.size(key)
    }
}

impl Member for Vec<String> {
    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.texts(key)
    }
}

impl Member for BTreeMap<String, String> {
    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.map(key)
    }
}

/// `null` or missing: none.
impl Member for Option<String> {
    const REQUIRED: bool = false;

    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        match m.0.remove(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(wrong(key, "a string")),
        }
    }
}

impl<T: Record> Member for Option<T> {
    const REQUIRED: bool = false;

    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.record(key, T::from_members)
    }
}

impl<T: Record> Member for Vec<T> {
    fn take(m: &mut Members, key: &str) -> Result<Self, String> {
        m.records(key, T::from_members)
    }
}

/// `Deserialize` for records through [`Members`]: each field from the
/// member of its name (the names of the fields are listed, their types
/// are those of the record).  A record that is the field of another is
/// its default when the member is missing.
macro_rules! deserialize_members {
    ($($t:ident { $($field:ident),* $(,)? })*) => {$(
        impl $crate::members::Record for $t {
            fn from_members(mut m: $crate::members::Members) -> Result<Self, String> {
                Ok(Self {
                    $($field: $crate::members::Member::take(&mut m, stringify!($field))?,)*
                })
            }
        }

        impl $crate::members::Member for $t {
            fn take(m: &mut $crate::members::Members, key: &str) -> Result<Self, String> {
                m.nested(key, <$t as $crate::members::Record>::from_members)
            }
        }

        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
                $crate::members::Members::of(v)
                    .and_then(<$t as $crate::members::Record>::from_members)
                    .map_err(serde::de::Error::custom)
            }
        }
    )*};
}
pub(crate) use deserialize_members;

/// [`deserialize_members`] for the records of a request, and for the replies
/// a client reads member by member: a member of a field that is not optional
/// must be there (a client that misspells one is told, a reply of another
/// version is no reply), as a derived `Deserialize` without defaults does.
macro_rules! deserialize_request_members {
    ($($t:ident { $($field:ident),* $(,)? })*) => {$(
        impl $crate::members::Record for $t {
            fn from_members(mut m: $crate::members::Members) -> Result<Self, String> {
                Ok(Self {
                    $($field: $crate::members::Member::take_given(&mut m, stringify!($field))?,)*
                })
            }
        }

        impl $crate::members::Member for $t {
            fn take(m: &mut $crate::members::Members, key: &str) -> Result<Self, String> {
                m.nested(key, <$t as $crate::members::Record>::from_members)
            }
        }

        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v = <serde_json::Value as serde::Deserialize>::deserialize(d)?;
                $crate::members::Members::of(v)
                    .and_then(<$t as $crate::members::Record>::from_members)
                    .map_err(serde::de::Error::custom)
            }
        }
    )*};
}
pub(crate) use deserialize_request_members;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_members_are_defaults_and_wrong_ones_errors() {
        let mut m = Members::of(json!({"a": "x", "n": null, "l": ["p", "q"], "i": 3})).unwrap();
        assert_eq!(m.text("a").unwrap(), "x");
        assert_eq!(m.text("gone").unwrap(), "");
        assert_eq!(m.opt_int("n").unwrap(), None);
        assert_eq!(m.texts("l").unwrap(), ["p", "q"]);
        assert_eq!(m.int("i").unwrap(), 3);
        let mut m = Members::of(json!({"a": 1, "l": [1], "b": "no", "s": -1})).unwrap();
        assert!(m.text("a").is_err());
        assert!(m.texts("l").is_err());
        assert!(m.flag("b").is_err());
        assert!(m.size("s").is_err());
        assert!(Members::of(json!([])).is_err());
    }

    /// The replies a client reads as they are, not as podman's documents,
    /// must have their members.
    #[test]
    fn a_reply_that_is_no_document_must_have_its_members() {
        use crate::workload::{ArtifactInspected, ManifestRemoved};
        assert!(serde_json::from_value::<ArtifactInspected>(json!({})).is_err());
        assert!(serde_json::from_value::<ArtifactInspected>(json!({"artifact": []})).is_err());
        assert!(serde_json::from_value::<ArtifactInspected>(json!({"artifact": {}})).is_ok());
        assert!(serde_json::from_value::<ManifestRemoved>(json!({"id": "a"})).is_err());
        let removed: ManifestRemoved =
            serde_json::from_value(json!({"id": "a", "names": ["b"]})).unwrap();
        assert_eq!(removed.names, ["b"]);
    }

    /// What the engine serializes decodes to the same record: a member
    /// named differently by `from_members` than by the derived
    /// `Serialize` fails here.
    #[test]
    fn the_records_decode_what_they_serialize() {
        use crate::workload::*;
        fn round_trip<T>(r: T)
        where
            T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
        {
            let text = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<T>(&text).unwrap(), r, "{text}");
        }
        let strings = |s: &[&str]| s.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        round_trip(ExecRecord {
            id: "e".into(),
            container_id: "c".into(),
            running: true,
            exit_code: Some(-3),
            pid: 42,
            command: strings(&["sh", "-c"]),
            user: "bin".into(),
            tty: true,
            stdin: true,
            stdout: true,
            stderr: true,
            privileged: true,
            detach_keys: "ctrl-a".into(),
            error: Some("cannot run".into()),
        });
        let descriptor = |t: &str| ManifestDescriptor {
            media_type: t.into(),
            digest: "sha256:d".into(),
            size: 7,
            artifact_type: "a/b".into(),
            annotations: [("k".to_string(), "v".to_string())].into(),
            data: "e30=".into(),
        };
        round_trip(ManifestListRecord {
            id: "i".into(),
            schema_version: 2,
            media_type: "idx".into(),
            artifact_type: "t".into(),
            subject: Some(descriptor("s")),
            annotations: [("a".to_string(), "b".to_string())].into(),
            manifests: vec![
                ManifestInstance {
                    media_type: "m".into(),
                    digest: "sha256:m".into(),
                    size: 3,
                    artifact_type: String::new(),
                    annotations: Default::default(),
                    platform: Some(ImagePlatform {
                        architecture: "arm64".into(),
                        os: "linux".into(),
                        os_version: "1".into(),
                        os_features: strings(&["f"]),
                        variant: "v8".into(),
                        features: strings(&["g"]),
                    }),
                },
                ManifestInstance::default(),
            ],
            config: Some(descriptor("c")),
            layers: vec![descriptor("l")],
        });
        round_trip(ArtifactInspected {
            artifact: ArtifactRecord {
                name: "n".into(),
                digest: "sha256:x".into(),
                schema_version: 2,
                media_type: "m".into(),
                artifact_type: "t".into(),
                config: Some(descriptor("c")),
                layers: vec![descriptor("l"), descriptor("l2")],
                subject: None,
                annotations: [("a".to_string(), "b".to_string())].into(),
            },
        });
        round_trip(ArtifactListed { artifact: None });
        round_trip(BuildPruned {
            ids: strings(&["a", "b"]),
            space: 9,
        });
        round_trip(ManifestRemoved {
            id: "i".into(),
            names: strings(&["a", "b"]),
        });
        round_trip(RemoteImage {
            media_type: "m".into(),
            digest: "d".into(),
            size: u64::MAX,
            platforms: vec![ImagePlatform {
                architecture: "arm64".into(),
                os: "linux".into(),
                os_version: "1".into(),
                os_features: strings(&["a"]),
                variant: "v8".into(),
                features: strings(&["f"]),
            }],
        });
        let map = |k: &str| [(k.to_string(), "v".to_string())].into_iter().collect();
        let config = ImageConfigRecord {
            user: "u".into(),
            exposed_ports: strings(&["80/tcp"]),
            env: strings(&["A=b"]),
            entrypoint: strings(&["e"]),
            cmd: strings(&["c"]),
            volumes: strings(&["/v"]),
            working_dir: "/w".into(),
            labels: map("l"),
            stop_signal: "SIGTERM".into(),
            args_escaped: true,
            on_build: strings(&["o"]),
            shell: strings(&["sh"]),
            healthcheck: Some(ImageHealthcheck {
                test: strings(&["CMD", "t"]),
                interval_ns: 1,
                timeout_ns: 2,
                start_period_ns: 3,
                start_interval_ns: 4,
                retries: 5,
            }),
        };
        round_trip(ImageRecord {
            id: "i".into(),
            names: strings(&["n"]),
            digest_names: strings(&["n@sha256:d"]),
            names_history: strings(&["h"]),
            digests: strings(&["sha256:d"]),
            digest: "sha256:d".into(),
            size: 9,
            created_ns: 1,
            stored_ns: 2,
            parent_id: "p".into(),
            has_children: true,
            containers: 3,
            read_only: true,
            manifest_list: true,
            os: "linux".into(),
            architecture: "amd64".into(),
            variant: "v".into(),
            author: "a".into(),
            comment: "c".into(),
            labels: map("l"),
            annotations: map("a"),
            manifest_type: "m".into(),
            config,
            history: vec![ImageHistoryEntry {
                created_ns: 1,
                created_by: "b".into(),
                author: "a".into(),
                comment: "c".into(),
                empty_layer: true,
                id: "i".into(),
                size: 4,
                tags: strings(&["t"]),
            }],
            layers: strings(&["l"]),
            composefs: vec![ComposefsLayer {
                layer: "sha256:l".into(),
                digests: strings(&["sha256:d"]),
            }],
            graph_driver: "overlay".into(),
        });
        round_trip(VolumeRecord {
            name: "v".into(),
            driver: "local".into(),
            mountpoint: "/m".into(),
            created_ns: 1,
            labels: map("l"),
            options: map("o"),
            scope: "local".into(),
            uid: 1,
            gid: 2,
            anonymous: true,
            needs_copy_up: true,
            needs_chown: true,
        });
        round_trip(ContainerPaths {
            bundle: "b".into(),
            oci_config: "o".into(),
            resolv_conf: "r".into(),
            hostname: "h".into(),
            hosts: "hs".into(),
            monitor_pid_file: "m".into(),
            pid_file: "p".into(),
            log: "l".into(),
            graph_driver: "g".into(),
            graph_data: [("UpperDir".to_string(), "u".to_string())].into(),
        });
        round_trip(NetworkMember {
            id: "i".into(),
            name: "n".into(),
            running: true,
            mac_address: "m".into(),
            ipv4: "4".into(),
            ipv6: "6".into(),
        });
        // (a reply without the members that are empty)
        assert_eq!(
            serde_json::from_str::<ExecRecord>(r#"{"id": "e", "exit_code": null}"#).unwrap(),
            ExecRecord {
                id: "e".into(),
                ..Default::default()
            }
        );
        // (a record in a record: missing, its default; null, an error)
        assert_eq!(
            serde_json::from_str::<ImageRecord>(r#"{"id": "i"}"#).unwrap(),
            ImageRecord {
                id: "i".into(),
                ..Default::default()
            }
        );
        assert!(serde_json::from_str::<ImageRecord>(r#"{"config": null}"#).is_err());
    }

    /// The records of a request decode what a client serializes, and a
    /// member that is not optional must be there.
    #[cfg(feature = "proxy")]
    #[test]
    fn a_request_record_has_its_members() {
        use crate::engine::{InstanceSpec, ManifestArtifactSpec};
        let spec = ManifestArtifactSpec {
            titles: vec!["a".into(), "b".into()],
            artifact_type: Some(String::new()),
            layer_type: "l".into(),
            config: "{}".into(),
            exclude_titles: true,
            annotations: [("k".to_string(), "v".to_string())].into(),
            instance: InstanceSpec {
                architecture: "arm64".into(),
                os_features: vec!["f".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let v = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            serde_json::from_value::<ManifestArtifactSpec>(v.clone()).unwrap(),
            spec
        );
        // (`?string`: missing or null is none)
        let mut none = v.clone();
        none.as_object_mut().unwrap().remove("artifact_type");
        let decoded: ManifestArtifactSpec = serde_json::from_value(none).unwrap();
        assert_eq!(decoded.artifact_type, None);
        for gone in ["titles", "instance", "exclude_titles"] {
            let mut short = v.clone();
            short.as_object_mut().unwrap().remove(gone);
            let e = serde_json::from_value::<ManifestArtifactSpec>(short).unwrap_err();
            assert!(
                e.to_string().contains(&format!("`{gone}` is missing")),
                "{e}"
            );
        }
        let mut short = v;
        short["instance"].as_object_mut().unwrap().remove("os");
        assert!(serde_json::from_value::<ManifestArtifactSpec>(short).is_err());
    }
}
