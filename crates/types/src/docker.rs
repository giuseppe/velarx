// SPDX-License-Identifier: Apache-2.0
//! Velarx reads the Docker schema 2 formats and writes OCI images only: every
//! place that meets a Docker format it does not read (schema 1, foreign
//! layers), a Docker archive or a request to write the Docker format refuses
//! it with the error built here.

use crate::error::{ImageError, ImageResult};

pub use velarx_base::docker::{as_oci, is_docker_media_type, NOT_READ, NOT_SUPPORTED};
use velarx_base::docker::{essence, oci_media_type, refusal as message, unreadable};

/// The error for `what` (a media type, a format, an archive) that Velarx
/// does not write.
pub fn refusal(what: &str) -> ImageError {
    ImageError::DockerFormat(message(what))
}

/// Refuse `media_type` if it is one of Docker's that Velarx does not read
/// (it reads the schema 2 manifest and list, the configuration and the gzip
/// and uncompressed layers): the single place that classifies a media type.
pub fn refuse_media_type(media_type: &str) -> ImageResult<()> {
    docker_media_type(media_type).map_or(Ok(()), |m| Err(ImageError::DockerFormat(m)))
}

/// Refuse `media_type` of a manifest, an index or a layer that Velarx
/// writes if it is one of Docker's.
pub fn refuse_written_media_type(media_type: &str) -> ImageResult<()> {
    if is_docker_media_type(media_type) {
        return Err(refusal(&format!(
            "media type {}",
            crate::error::printable(essence(media_type))
        )));
    }
    Ok(())
}

/// The refusal of `media_type` if it is one of Docker's that is not read.
fn docker_media_type(media_type: &str) -> Option<String> {
    (is_docker_media_type(media_type) && oci_media_type(media_type).is_none()).then(|| {
        unreadable(&format!(
            "media type {}",
            crate::error::printable(essence(media_type))
        ))
    })
}

/// Refuse a manifest or an index (its bytes) that is in a Docker format
/// Velarx does not read: a schema 1 manifest, or one that names such a media
/// type (a foreign layer) for itself, its configuration or its layers.  The
/// manifests an index lists are not judged here: the one taken is, by
/// [`refuse_instance`] and when its bytes come (a list may have a schema 1
/// instance for another platform, as podman pulls it).  What is not JSON is
/// left to the parser that comes next.
pub fn refuse_manifest(bytes: &[u8]) -> ImageResult<()> {
    docker_manifest(bytes).map_or(Ok(()), |m| Err(ImageError::DockerFormat(m)))
}

/// Refuse the instance `digest` of the index `instances` (its manifests) if
/// its descriptor names a Docker media type Velarx does not read.
pub fn refuse_instance(instances: &[serde_json::Value], digest: &str) -> ImageResult<()> {
    instances
        .iter()
        .filter(|m| m.get("digest").and_then(|d| d.as_str()) == Some(digest))
        .filter_map(|m| m.get("mediaType")?.as_str())
        .try_for_each(refuse_media_type)
}

/// The refusal of [`refuse_manifest`] as a message, for the thin client
/// (which has no [`ImageError`]).
pub fn docker_manifest(bytes: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    if value.get("schemaVersion").and_then(|v| v.as_i64()) == Some(1) {
        return Some(unreadable(
            "media type application/vnd.docker.distribution.manifest.v1+json (schema 1)",
        ));
    }
    fn media_type(v: &serde_json::Value) -> Option<&str> {
        v.get("mediaType")?.as_str()
    }
    let layers = value
        .get("layers")
        .and_then(|l| l.as_array())
        .into_iter()
        .flatten();
    std::iter::once(&value)
        .chain(value.get("config"))
        .chain(layers)
        .filter_map(media_type)
        .find_map(docker_media_type)
}

/// Refuse the name of an image format that is Docker's (see
/// `velarx_base::docker::refuse_format_name`).
pub fn refuse_format_name(name: &str) -> ImageResult<()> {
    velarx_base::docker::refuse_format_name(name).map_err(ImageError::DockerFormat)
}

/// The message of an archive that is a `docker save`, where one is not read (an
/// `oci-archive:` transport).
pub fn archive_refusal() -> String {
    message("a docker-archive (manifest.json)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(r: ImageResult<()>) -> String {
        match r.unwrap_err() {
            ImageError::DockerFormat(m) => m,
            e => panic!("another error: {e}"),
        }
    }

    #[test]
    fn docker_media_types_velarx_does_not_read_are_refused_with_their_name() {
        for mt in [
            "application/vnd.docker.distribution.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v1+prettyjws",
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
            "application/vnd.docker.image.rootfs.foreign.diff.tar",
            "Application/Vnd.Docker.Image.Rootfs.Foreign.Diff.Tar.Gzip; charset=x",
            "application/vnd.docker.plugin.v1+json",
        ] {
            let m = refused(refuse_media_type(mt));
            assert!(m.contains(NOT_READ), "{m}");
            assert!(m.to_lowercase().contains("application/vnd.docker."), "{m}");
        }
    }

    #[test]
    fn docker_schema_2_and_oci_media_types_pass() {
        for mt in [
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.docker.container.image.v1+json",
            "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "application/vnd.docker.image.rootfs.diff.tar",
            "Application/Vnd.Docker.Image.Rootfs.Diff.Tar.Gzip; charset=x",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.oci.image.config.v1+json",
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.oci.empty.v1+json",
            "application/json",
            "",
        ] {
            assert!(refuse_media_type(mt).is_ok(), "{mt}");
        }
    }

    #[test]
    fn written_media_types_are_oci() {
        let m = refused(refuse_written_media_type(
            "application/vnd.docker.distribution.manifest.v2+json",
        ));
        assert!(m.starts_with(
            "media type application/vnd.docker.distribution.manifest.v2+json: Docker"
        ));
        assert!(m.contains(NOT_SUPPORTED), "{m}");
        assert!(refuse_written_media_type("application/vnd.oci.image.index.v1+json").is_ok());
    }

    #[test]
    fn manifests_are_checked_whole() {
        let oci = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
            "config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0","size":1},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:0","size":1}]}"#;
        assert!(refuse_manifest(oci).is_ok());
        assert!(refuse_manifest(b"not json").is_ok());
        let docker = String::from_utf8_lossy(oci)
            .replace("oci.image.manifest.v1", "docker.distribution.manifest.v2")
            .replace("oci.image.config.v1", "docker.container.image.v1")
            .replace(
                "oci.image.layer.v1.tar+gzip",
                "docker.image.rootfs.diff.tar.gzip",
            );
        assert!(refuse_manifest(docker.as_bytes()).is_ok());
        let foreign = docker.replace("rootfs.diff", "rootfs.foreign.diff");
        assert!(refused(refuse_manifest(foreign.as_bytes())).contains("rootfs.foreign.diff"));
        let list = br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json",
            "manifests":[{"mediaType":"application/vnd.docker.distribution.manifest.v2+json","digest":"sha256:0","size":1}]}"#;
        assert!(refuse_manifest(list).is_ok());
        // an index with a schema 1 instance: the instance taken is judged
        let list_v1 = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
            "manifests":[{"mediaType":"application/vnd.docker.distribution.manifest.v1+json","digest":"sha256:1","size":1},
                         {"mediaType":"application/vnd.docker.distribution.manifest.v2+json","digest":"sha256:2","size":1}]}"#;
        assert!(refuse_manifest(list_v1).is_ok());
        let v: serde_json::Value = serde_json::from_slice(list_v1).unwrap();
        let instances = v["manifests"].as_array().unwrap();
        assert!(refused(refuse_instance(instances, "sha256:1")).contains("manifest.v1+json"));
        assert!(refuse_instance(instances, "sha256:2").is_ok());
        let v1 = br#"{"schemaVersion":1,"name":"a","tag":"b","fsLayers":[]}"#;
        assert!(refused(refuse_manifest(v1)).contains("schema 1"));
    }

    #[test]
    fn format_names_and_archives() {
        for f in ["docker", "v2s1", "v2s2", "docker-archive"] {
            assert!(
                refused(refuse_format_name(f)).contains(NOT_SUPPORTED),
                "{f}"
            );
        }
        for f in ["oci", "oci-archive", "oci-dir", "zip"] {
            assert!(refuse_format_name(f).is_ok(), "{f}");
        }
    }
}
