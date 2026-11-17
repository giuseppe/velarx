// SPDX-License-Identifier: Apache-2.0
//! Artifacts in manifest lists (podman manifest add --artifact): an OCI
//! image manifest whose layers are files, made here and added to a list as
//! buildah's AddArtifact makes it.  The manifest and its blobs are kept in
//! a directory of the list (`manifest-artifacts/<list id>/<hex digest>`),
//! removed with it, and pushed with the list.

use super::manifest::edit_instance;
use super::*;
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use velarx_types::digest::DigestWriter;
use velarx_types::transport::ImageLocation;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const OCI_EMPTY: &str = "application/vnd.oci.empty.v1+json";
/// What ORAS calls an artifact of an unknown type.
const UNKNOWN_ARTIFACT: &str = "application/vnd.unknown.artifact.v1";
const TITLE: &str = "org.opencontainers.image.title";

/// How an artifact manifest is made (the `artifact_*` fields of podman's
/// manifest modify request).
#[derive(Debug, Clone, Default)]
pub struct ArtifactOptions {
    /// None: the unknown artifact type; an empty one: no type.
    pub artifact_type: Option<String>,
    pub config_type: String,
    /// The configuration's content (a JSON document), empty for none.
    pub config: String,
    /// The media type of every layer, else guessed from each file.
    pub layer_type: String,
    /// No title annotation on the layers.
    pub exclude_titles: bool,
    pub annotations: BTreeMap<String, String>,
    /// An image of a registry the artifact is about.
    pub subject: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: Digest,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_type: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactManifest {
    schema_version: u32,
    media_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<Descriptor>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

/// The media type of a file of an artifact: by the extension of its name,
/// else by its first bytes (Go's mime.TypeByExtension and
/// http.DetectContentType, as buildah does), without parameters.
pub(super) fn guess_media_type(name: &str, head: &[u8]) -> String {
    if let Some(ext) = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()) {
        if let Some(t) = type_by_extension(&ext) {
            return t;
        }
    }
    let sniffed = if head.starts_with(&[0x1f, 0x8b, 0x08]) {
        "application/x-gzip"
    } else if head.starts_with(b"PK\x03\x04") {
        "application/zip"
    } else if head.starts_with(b"%PDF-") {
        "application/pdf"
    } else if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        "image/png"
    } else if head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a") {
        "image/gif"
    } else if head.starts_with(&[0xff, 0xd8, 0xff]) {
        "image/jpeg"
    } else if head.starts_with(b"\x00asm") {
        "application/wasm"
    } else if head.iter().any(|&b| {
        b <= 0x08 || b == 0x0b || (0x0e..=0x1a).contains(&b) || (0x1c..=0x1f).contains(&b)
    }) {
        "application/octet-stream"
    } else {
        "text/plain"
    };
    sniffed.to_string()
}

/// Go's built-in table, then the system's mime.types.
fn type_by_extension(ext: &str) -> Option<String> {
    let builtin = match ext {
        "avif" => Some("image/avif"),
        "css" => Some("text/css"),
        "gif" => Some("image/gif"),
        "htm" | "html" => Some("text/html"),
        "jpeg" | "jpg" => Some("image/jpeg"),
        "js" | "mjs" => Some("text/javascript"),
        "json" => Some("application/json"),
        "pdf" => Some("application/pdf"),
        "png" => Some("image/png"),
        "svg" => Some("image/svg+xml"),
        "wasm" => Some("application/wasm"),
        "webp" => Some("image/webp"),
        "xml" => Some("text/xml"),
        _ => None,
    };
    if let Some(t) = builtin {
        return Some(t.to_string());
    }
    static SYSTEM: std::sync::OnceLock<BTreeMap<String, String>> = std::sync::OnceLock::new();
    SYSTEM
        .get_or_init(|| {
            let mut map = BTreeMap::new();
            for path in [
                "/etc/mime.types",
                "/etc/apache2/mime.types",
                "/etc/httpd/conf/mime.types",
            ] {
                let Ok(text) = std::fs::read_to_string(path) else {
                    continue;
                };
                for line in text.lines() {
                    let line = line.split('#').next().unwrap_or("");
                    let mut words = line.split_whitespace();
                    let Some(t) = words.next() else { continue };
                    for e in words {
                        map.entry(e.to_ascii_lowercase())
                            .or_insert_with(|| t.to_string());
                    }
                }
            }
            map
        })
        .get(ext)
        .cloned()
}

fn hex_of(digest: &Digest) -> String {
    digest.hex()
}

impl ImageService {
    /// Where the artifacts of the lists are kept.
    fn artifacts_dir(&self) -> PathBuf {
        self.staging_dir
            .parent()
            .unwrap_or(&self.staging_dir)
            .join("manifest-artifacts")
    }

    fn list_artifacts_dir(&self, list_id: &str) -> ImageResult<PathBuf> {
        if list_id.len() != 64 || !list_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ImageError::Manifest(format!(
                "invalid manifest list id `{}`",
                printable(list_id)
            )));
        }
        Ok(self.artifacts_dir().join(list_id))
    }

    /// The file of a blob or manifest an artifact of the list has.
    pub(super) fn artifact_blob(&self, list_id: &str, digest: &Digest) -> Option<PathBuf> {
        let path = self.list_artifacts_dir(list_id).ok()?.join(hex_of(digest));
        path.is_file().then_some(path)
    }

    /// Forget the artifacts of a list (it is removed).
    pub(super) fn remove_artifacts(&self, list_id: &str) {
        if let Ok(dir) = self.list_artifacts_dir(list_id) {
            match velarx_base::tree::remove_dir_all(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => warn!("Cannot remove {}: {e}", dir.display()),
            }
        }
    }

    /// Make an artifact of `files` (their names and the files that hold
    /// them, which are copied into the list) and add it to the list, with
    /// the platform and annotations of `instance`.  Returns its digest.
    pub async fn manifest_add_artifact(
        &self,
        reference: &str,
        files: &[(String, PathBuf)],
        opts: &ArtifactOptions,
        instance: &InstanceOptions,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<Digest> {
        if files.is_empty() {
            return Err(ImageError::Manifest(
                "an artifact needs at least one file".into(),
            ));
        }
        let list = self.manifest_get(reference).await?;
        let subject = if opts.subject.is_empty() {
            None
        } else {
            Some(
                self.subject_descriptor(&opts.subject, tls_verify, access)
                    .await?,
            )
        };
        // (the digests of what is added are those of the list)
        let alg = list.alg;
        let dir = self.list_artifacts_dir(&list.id)?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;

        // The layers: each file copied to a file of the list with no digest
        // for a name, digested as it is copied (the caller can still write
        // its own file: what is hashed is what was copied), and given the
        // name of its digest after.
        let mut layers = Vec::new();
        for (name, path) in files {
            let (path, d) = (path.clone(), dir.clone());
            let (digest, size, head) = tokio::task::spawn_blocking(move || {
                let mut f = std::fs::File::open(&path)?;
                let mut copy = tempfile::Builder::new().prefix(".tmp-").tempfile_in(&d)?;
                let mut hasher = DigestWriter::new(alg);
                let mut head = Vec::new();
                let mut size = 0u64;
                let mut buf = vec![0u8; 256 * 1024];
                loop {
                    let n = f.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    if head.len() < 512 {
                        let take = (512 - head.len()).min(n);
                        head.extend_from_slice(&buf[..take]);
                    }
                    hasher.update(&buf[..n]);
                    copy.write_all(&buf[..n])?;
                    size += n as u64;
                }
                let digest = hasher.finalize();
                copy.as_file().sync_all()?;
                match copy.persist_noclobber(d.join(hex_of(&digest))) {
                    Ok(_) => {}
                    // (the same content, given its name by an earlier add)
                    Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.error),
                }
                Ok::<_, std::io::Error>((digest, size, head))
            })
            .await
            .map_err(|e| ImageError::Storage(e.to_string()))??;
            let title = name.rsplit('/').next().unwrap_or(name).to_string();
            let media_type = if opts.layer_type.is_empty() {
                guess_media_type(&title, &head)
            } else {
                opts.layer_type.clone()
            };
            layers.push(Descriptor {
                media_type,
                digest,
                size,
                annotations: (!opts.exclude_titles)
                    .then(|| BTreeMap::from([(TITLE.to_string(), title)])),
                data: None,
                artifact_type: None,
            });
        }

        // The configuration, as libimage makes it.
        let (config_type, config_data) = if !opts.config.is_empty() {
            (
                if opts.config_type.is_empty() {
                    OCI_CONFIG.to_string()
                } else {
                    opts.config_type.clone()
                },
                opts.config.as_bytes().to_vec(),
            )
        } else if !opts.config_type.is_empty() {
            (opts.config_type.clone(), b"{}".to_vec())
        } else {
            (OCI_EMPTY.to_string(), b"{}".to_vec())
        };
        let config_digest = Digest::of(alg, &config_data);
        write_blob(&dir, &config_digest, &config_data)?;
        let config = Descriptor {
            media_type: config_type,
            digest: config_digest,
            size: config_data.len() as u64,
            annotations: None,
            data: Some(base64::engine::general_purpose::STANDARD.encode(&config_data)),
            artifact_type: None,
        };

        let artifact_type = match &opts.artifact_type {
            None => Some(UNKNOWN_ARTIFACT.to_string()),
            Some(t) if t.is_empty() => None,
            Some(t) => Some(t.clone()),
        };
        let manifest = ArtifactManifest {
            schema_version: 2,
            media_type: OCI_MANIFEST,
            artifact_type: artifact_type.clone(),
            config,
            layers,
            subject,
            annotations: opts.annotations.clone(),
        };
        let bytes = serde_json::to_vec(&manifest)?;
        let digest = Digest::of(alg, &bytes);
        write_blob(&dir, &digest, &bytes)?;

        let mut entry = json!({
            "mediaType": OCI_MANIFEST,
            "digest": digest,
            "size": bytes.len(),
        });
        if let Some(t) = &artifact_type {
            entry["artifactType"] = json!(t);
        }
        edit_instance(&mut entry, instance);
        // (added to the latest index of the list)
        self.edit_list(&list.id, |index, _| {
            let manifests = index["manifests"]
                .as_array_mut()
                .ok_or_else(|| ImageError::Manifest("the index has no manifests".into()))?;
            manifests.retain(|m| m["digest"] != entry["digest"]);
            manifests.push(entry.clone());
            Ok(())
        })
        .await?;
        Ok(digest)
    }

    /// The descriptor of the subject of an artifact: what a registry has.
    async fn subject_descriptor(
        &self,
        reference: &str,
        tls_verify: bool,
        access: &velarx_registry::auth::RegistryAccess,
    ) -> ImageResult<Descriptor> {
        let reference = ImageLocation::registry(reference, "an artifact subject")
            .map_err(|e| ImageError::Invalid(e.to_string()))?;
        let (body, digest) = self
            .remote_manifest_raw(&reference, tls_verify, access)
            .await?;
        let v: Value = serde_json::from_slice(&body)?;
        let media_type = v["mediaType"].as_str().unwrap_or(OCI_MANIFEST).to_string();
        let artifact_type = if v.get("manifests").is_none() {
            v["artifactType"].as_str().map(str::to_string)
        } else {
            None
        };
        Ok(Descriptor {
            media_type,
            digest,
            size: body.len() as u64,
            annotations: None,
            data: None,
            artifact_type,
        })
    }
}

/// Write a blob of an artifact under its digest (once).
fn write_blob(dir: &std::path::Path, digest: &Digest, data: &[u8]) -> ImageResult<()> {
    let path = dir.join(hex_of(digest));
    if path.is_file() {
        return Ok(());
    }
    let mut f = tempfile::NamedTempFile::new_in(dir)?;
    f.write_all(data)?;
    f.as_file().sync_all()?;
    f.persist(&path).map_err(|e| ImageError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_types_of_artifact_files() {
        assert_eq!(guess_media_type("listed.txt", b"oh yeah"), "text/plain");
        assert_eq!(
            guess_media_type("zeroes", &[0u8; 512]),
            "application/octet-stream"
        );
        assert_eq!(guess_media_type("x", b"hello\n"), "text/plain");
        assert_eq!(guess_media_type("a.json", b"{}"), "application/json");
        assert_eq!(
            guess_media_type("b", &[0x1f, 0x8b, 0x08, 0]),
            "application/x-gzip"
        );
        assert_eq!(guess_media_type("c.PNG", b""), "image/png");
    }
}
