// SPDX-License-Identifier: Apache-2.0
//! Velarx reads the Docker schema 2 image format and writes OCI images only:
//! what every place that meets a Docker format it does not take says, and what
//! tells a Docker media type or format name.  (The checks of manifests and the
//! errors of the engine are in `velarx-types`, which uses these.)

/// What the refusals of the Docker formats Velarx does not write (or load
/// from an archive) say after what was refused.
pub const NOT_SUPPORTED: &str =
    "Docker image formats are not supported: only OCI images (application/vnd.oci.image.*)";

/// What the refusals of the Docker formats Velarx does not read say after
/// what was refused.
pub const NOT_READ: &str =
    "Docker schema 1 images and foreign layers are not supported: only OCI and Docker schema 2 images are read";

/// The media types of the Docker formats start with this.
const DOCKER_PREFIX: &str = "application/vnd.docker.";

/// The Docker media types Velarx reads and the OCI ones it parses them as:
/// the schema 2 manifest and its list, the image configuration and the
/// gzip and uncompressed layers (as containers/image reads them).
const READ: [(&str, &str); 5] = [
    (
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ),
    (
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    ),
    (
        "application/vnd.docker.container.image.v1+json",
        "application/vnd.oci.image.config.v1+json",
    ),
    (
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "application/vnd.oci.image.layer.v1.tar+gzip",
    ),
    (
        "application/vnd.docker.image.rootfs.diff.tar",
        "application/vnd.oci.image.layer.v1.tar",
    ),
];

/// The media type without its parameters.
pub fn essence(media_type: &str) -> &str {
    media_type.split(';').next().unwrap_or("").trim()
}

/// The message for `what` (a media type, a format, an archive) that Velarx
/// does not write.
pub fn refusal(what: &str) -> String {
    format!("{what}: {NOT_SUPPORTED}")
}

/// The message for `what` (a media type) that is Docker's and that Velarx
/// does not read.
pub fn unreadable(what: &str) -> String {
    format!("{what}: {NOT_READ}")
}

/// Whether `media_type` is one of Docker's (the schema 2 manifest and its
/// list, the schema 1 manifests, the image configuration, the layers).
pub fn is_docker_media_type(media_type: &str) -> bool {
    essence(media_type)
        .to_ascii_lowercase()
        .starts_with(DOCKER_PREFIX)
}

/// The OCI media type a Docker one is parsed as, None when it is not one
/// Velarx reads (an OCI one, or a Docker one it refuses).
pub fn oci_media_type(media_type: &str) -> Option<&'static str> {
    let essence = essence(media_type).to_ascii_lowercase();
    READ.iter().find(|(d, _)| *d == essence).map(|(_, o)| *o)
}

/// `media_type` as an OCI one: a Docker media type Velarx reads is mapped,
/// anything else is kept.
pub fn as_oci(media_type: &str) -> &str {
    oci_media_type(media_type).unwrap_or(media_type)
}

/// Refuse the name of an image format that is Docker's: `docker`, `v2s1`
/// and `v2s2` (a manifest format), `docker-archive`.
pub fn refuse_format_name(name: &str) -> Result<(), String> {
    if matches!(name, "docker" | "v2s1" | "v2s2" | "docker-archive") {
        return Err(refusal(&format!("the format {name}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_media_types_and_format_names() {
        for mt in [
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.image.rootfs.diff.tar.gzip; x=y",
            "Application/Vnd.Docker.Container.Image.V1+Json",
        ] {
            assert!(is_docker_media_type(mt), "{mt}");
        }
        for mt in [
            "application/vnd.oci.image.manifest.v1+json",
            "",
            "text/plain",
        ] {
            assert!(!is_docker_media_type(mt), "{mt}");
        }
        for f in ["docker", "v2s1", "v2s2", "docker-archive"] {
            assert!(refuse_format_name(f).unwrap_err().contains(NOT_SUPPORTED));
        }
        assert_eq!(
            oci_media_type("application/vnd.docker.image.rootfs.diff.tar.gzip; x=y"),
            Some("application/vnd.oci.image.layer.v1.tar+gzip")
        );
        assert_eq!(
            oci_media_type("application/vnd.docker.image.rootfs.diff.tar"),
            Some("application/vnd.oci.image.layer.v1.tar")
        );
        assert_eq!(
            as_oci("application/vnd.docker.distribution.manifest.v2+json"),
            "application/vnd.oci.image.manifest.v1+json"
        );
        for mt in [
            "application/vnd.docker.distribution.manifest.v1+json",
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
            "application/vnd.docker.image.rootfs.foreign.diff.tar",
            "application/vnd.oci.image.manifest.v1+json",
        ] {
            assert_eq!(oci_media_type(mt), None, "{mt}");
            assert_eq!(as_oci(mt), mt);
        }
        for f in ["oci", "oci-archive", "zip"] {
            assert!(refuse_format_name(f).is_ok());
        }
    }
}
