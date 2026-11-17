// SPDX-License-Identifier: Apache-2.0
//! The documents of manifest lists and artifacts: OCI's index and manifest
//! as podman answers them.

use serde_json::{json, Map, Value};
use velarx_proto::workload::{
    ArtifactRecord, ImagePlatform, ManifestDescriptor, ManifestInstance, ManifestListRecord,
};

fn put_texts(o: &mut Map<String, Value>, key: &str, v: &[String]) {
    if !v.is_empty() {
        o.insert(key.into(), json!(v));
    }
}

/// OCI's descriptor, without what is empty.
fn descriptor(d: &ManifestDescriptor) -> Value {
    let mut o = Map::new();
    o.insert("mediaType".into(), json!(d.media_type));
    o.insert("digest".into(), json!(d.digest));
    o.insert("size".into(), json!(d.size));
    if !d.artifact_type.is_empty() {
        o.insert("artifactType".into(), json!(d.artifact_type));
    }
    if !d.annotations.is_empty() {
        o.insert("annotations".into(), crate::string_map(&d.annotations));
    }
    if !d.data.is_empty() {
        o.insert("data".into(), json!(d.data));
    }
    Value::Object(o)
}

/// OCI's platform.
fn platform(p: &ImagePlatform) -> Value {
    let mut o = Map::new();
    o.insert("architecture".into(), json!(p.architecture));
    o.insert("os".into(), json!(p.os));
    if !p.os_version.is_empty() {
        o.insert("os.version".into(), json!(p.os_version));
    }
    put_texts(&mut o, "os.features", &p.os_features);
    if !p.variant.is_empty() {
        o.insert("variant".into(), json!(p.variant));
    }
    put_texts(&mut o, "features", &p.features);
    Value::Object(o)
}

fn instance(m: &ManifestInstance) -> Value {
    let mut o = Map::new();
    o.insert("mediaType".into(), json!(m.media_type));
    o.insert("digest".into(), json!(m.digest));
    o.insert("size".into(), json!(m.size));
    if !m.artifact_type.is_empty() {
        o.insert("artifactType".into(), json!(m.artifact_type));
    }
    if let Some(p) = &m.platform {
        o.insert("platform".into(), platform(p));
    }
    if !m.annotations.is_empty() {
        o.insert("annotations".into(), crate::string_map(&m.annotations));
    }
    Value::Object(o)
}

/// A manifest list (an index) or, of a registry, an image manifest.
pub fn index_document(l: &ManifestListRecord) -> Value {
    let mut o = Map::new();
    o.insert("schemaVersion".into(), json!(l.schema_version));
    if !l.media_type.is_empty() {
        o.insert("mediaType".into(), json!(l.media_type));
    }
    if !l.artifact_type.is_empty() {
        o.insert("artifactType".into(), json!(l.artifact_type));
    }
    if let Some(c) = &l.config {
        o.insert("config".into(), descriptor(c));
    }
    if !l.layers.is_empty() {
        o.insert(
            "layers".into(),
            Value::Array(l.layers.iter().map(descriptor).collect()),
        );
    }
    if l.config.is_none() {
        o.insert(
            "manifests".into(),
            Value::Array(l.manifests.iter().map(instance).collect()),
        );
    }
    if let Some(s) = &l.subject {
        o.insert("subject".into(), descriptor(s));
    }
    if !l.annotations.is_empty() {
        o.insert("annotations".into(), crate::string_map(&l.annotations));
    }
    Value::Object(o)
}

/// podman's inspect of an artifact: its name, digest and manifest.
pub fn artifact_document(a: &ArtifactRecord) -> Value {
    let mut m = Map::new();
    m.insert("schemaVersion".into(), json!(a.schema_version));
    m.insert("mediaType".into(), json!(a.media_type));
    if !a.artifact_type.is_empty() {
        m.insert("artifactType".into(), json!(a.artifact_type));
    }
    if let Some(c) = &a.config {
        m.insert("config".into(), descriptor(c));
    }
    m.insert(
        "layers".into(),
        Value::Array(a.layers.iter().map(descriptor).collect()),
    );
    if let Some(s) = &a.subject {
        m.insert("subject".into(), descriptor(s));
    }
    if !a.annotations.is_empty() {
        m.insert("annotations".into(), crate::string_map(&a.annotations));
    }
    json!({"Manifest": Value::Object(m), "Name": a.name, "Digest": a.digest})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_index_is_oci_s() {
        let l = ManifestListRecord {
            id: "i".into(),
            schema_version: 2,
            media_type: "application/vnd.oci.image.index.v1+json".into(),
            manifests: vec![ManifestInstance {
                media_type: "m".into(),
                digest: "sha256:a".into(),
                size: 5,
                platform: Some(ImagePlatform {
                    architecture: "arm64".into(),
                    os: "linux".into(),
                    variant: "v8".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            index_document(&l),
            json!({
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [{"mediaType": "m", "digest": "sha256:a", "size": 5,
                    "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}}]
            })
        );
    }

    #[test]
    fn an_artifact_is_podman_s() {
        let a = ArtifactRecord {
            name: "n".into(),
            digest: "sha256:d".into(),
            schema_version: 2,
            media_type: "m".into(),
            artifact_type: "t".into(),
            config: Some(ManifestDescriptor {
                media_type: "c".into(),
                digest: "sha256:c".into(),
                size: 2,
                data: "e30=".into(),
                ..Default::default()
            }),
            layers: vec![ManifestDescriptor {
                media_type: "l".into(),
                digest: "sha256:l".into(),
                size: 3,
                annotations: [(
                    "org.opencontainers.image.title".to_string(),
                    "f".to_string(),
                )]
                .into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let d = artifact_document(&a);
        assert_eq!(d["Name"], "n");
        assert_eq!(d["Manifest"]["config"]["data"], "e30=");
        assert_eq!(
            d["Manifest"]["layers"][0]["annotations"]["org.opencontainers.image.title"],
            "f"
        );
        assert!(d["Manifest"].get("subject").is_none());
    }
}
