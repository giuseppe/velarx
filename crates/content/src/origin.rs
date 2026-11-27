// SPDX-License-Identifier: Apache-2.0
//! The origin of a pull, by the scheme of what is pulled: the one rule
//! (`velarx_types::transport` parses the text) that the walk of a pull and
//! the walk of a push apply.
//!
//! * a docker reference (or `docker://REF`): the registry fetcher;
//! * `oci:DIR[:REF]`, `oci-archive:FILE[:REF]`, `docker-archive:FILE[:REF]`,
//!   `dir:DIR` and `archive:FILE` (a load: every image of an archive of
//!   either kind): `velarx-dir` as the origin of a path;
//! * `rootfs:PATH` (a root file system, a directory or a tar: the one layer of
//!   an image) and
//!   `docker-daemon:IMAGE` (the archive of `docker save`, read from the
//!   socket of the daemon the engine connects to): `velarx-dir` as well;
//! * `SCHEME://...` of a `[[transports]]`: the transport process on its
//!   socket.

use std::path::PathBuf;
use velarx_config::TransportConfig;
use velarx_types::transport::{ImageLocation, TransportError};
use velarx_types::{ImageError, ImageResult};

/// The kinds of path an origin can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathScheme {
    /// `oci:DIR[:REF]`: a directory in the OCI image layout
    Oci,
    /// `dir:DIR`: one manifest and its blobs
    Dir,
    /// `oci-archive:FILE[:REF]`
    OciArchive,
    /// `docker-archive:FILE[:REF|:@N]`
    DockerArchive,
    /// `archive:FILE`: a load, either kind, every image
    Archive,
    /// `rootfs:PATH`: a directory or a tar that is the one layer of an image
    Rootfs,
    /// `docker-daemon:IMAGE`: the archive a Docker daemon saves, read from
    /// the connection to its socket
    DockerDaemon,
}

impl PathScheme {
    /// The text before the first `:`.
    pub fn name(self) -> &'static str {
        match self {
            PathScheme::Oci => "oci",
            PathScheme::Dir => "dir",
            PathScheme::OciArchive => "oci-archive",
            PathScheme::DockerArchive => "docker-archive",
            PathScheme::Archive => "archive",
            PathScheme::Rootfs => "rootfs",
            PathScheme::DockerDaemon => "docker-daemon",
        }
    }

    pub fn of(name: &str) -> Option<Self> {
        Some(match name {
            "oci" => PathScheme::Oci,
            "dir" => PathScheme::Dir,
            "oci-archive" => PathScheme::OciArchive,
            "docker-archive" => PathScheme::DockerArchive,
            "archive" => PathScheme::Archive,
            "rootfs" => PathScheme::Rootfs,
            "docker-daemon" => PathScheme::DockerDaemon,
            _ => return None,
        })
    }

    /// A directory (a layout), not a file.
    pub fn is_directory(self) -> bool {
        matches!(self, PathScheme::Oci | PathScheme::Dir)
    }

    /// Either a directory or a file, as the command line or the engine
    /// opens it (the path of an `archive:` is a file).
    pub fn is_either(self) -> bool {
        self == PathScheme::Rootfs
    }

    /// A path of this host, which the client opens or the engine opens for
    /// it (the origin of a daemon is the connection to its socket).
    pub fn is_path(self) -> bool {
        self != PathScheme::DockerDaemon
    }
}

/// Where a pull gets its image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// A docker reference
    Registry(String),
    /// A path of this host: the client opens it and hands the descriptor
    /// (`source_fd`); the engine opens `path` for a call that has none
    /// (podman's local routes).  `selector`: the image of it (`:REF` or
    /// `:@N`; for a daemon the image it saves).  A daemon has no path: the
    /// engine connects to the socket of `[pull] docker_socket`
    Path {
        scheme: PathScheme,
        path: PathBuf,
        selector: Option<String>,
    },
    /// `SCHEME://...` of a `[[transports]]`
    Transport { scheme: String, location: String },
}

impl Origin {
    /// What `text` (`PullSpec.source`) names.  A name of the local store
    /// (`containers-storage:`) is no origin.
    pub fn parse(text: &str) -> Result<Self, TransportError> {
        if let Some(path) = text.strip_prefix("archive:") {
            // (no path: the client opened it, `source_fd`)
            if path.contains('\0') {
                return Err(TransportError::Invalid {
                    spec: text.to_string(),
                    why: "a NUL byte".into(),
                });
            }
            return Ok(Origin::Path {
                scheme: PathScheme::Archive,
                path: PathBuf::from(path),
                selector: None,
            });
        }
        if let Some((scheme, _)) = ImageLocation::external(text)? {
            return Ok(Origin::Transport {
                scheme: scheme.to_string(),
                location: text.to_string(),
            });
        }
        Ok(match ImageLocation::parse(text)? {
            ImageLocation::Registry(name) => Origin::Registry(name),
            ImageLocation::OciLayout { path, tag } => Origin::Path {
                scheme: PathScheme::Oci,
                path: path.into(),
                selector: tag,
            },
            ImageLocation::OciArchive { path, tag } => Origin::Path {
                scheme: PathScheme::OciArchive,
                path: path.into(),
                selector: tag,
            },
            ImageLocation::DockerArchive { path, selector } => Origin::Path {
                scheme: PathScheme::DockerArchive,
                path: path.into(),
                selector,
            },
            ImageLocation::Dir { path } => Origin::Path {
                scheme: PathScheme::Dir,
                path: path.into(),
                selector: None,
            },
            ImageLocation::Rootfs { path } => Origin::Path {
                scheme: PathScheme::Rootfs,
                path: path.into(),
                selector: None,
            },
            ImageLocation::DockerDaemon { reference } => Origin::Path {
                scheme: PathScheme::DockerDaemon,
                path: PathBuf::new(),
                selector: Some(reference),
            },
            ImageLocation::Storage(_) => {
                return Err(TransportError::NotHere {
                    name: "containers-storage".into(),
                    what: "a pull from an origin".into(),
                    only: "a registry, a path or a transport of [[transports]]",
                })
            }
        })
    }

    /// What `Open(source)` of the fetcher is told of the origin: for a
    /// path the scheme and the selector (`oci-archive:NAME`), never the text
    /// of the path, which the fetcher gets as the descriptor of the
    /// `target`.
    pub fn source_text(&self) -> String {
        match self {
            Origin::Registry(name) => name.clone(),
            Origin::Path {
                scheme, selector, ..
            } => format!("{}:{}", scheme.name(), selector.as_deref().unwrap_or("")),
            Origin::Transport { location, .. } => location.clone(),
        }
    }
}

/// The scheme and the selector `Open(source)` of a path origin carries
/// (the inverse of [`Origin::source_text`] for a path).
pub fn path_source(text: &str) -> Option<(PathScheme, Option<String>)> {
    let (scheme, selector) = text.split_once(':')?;
    Some((
        PathScheme::of(scheme)?,
        Some(selector).filter(|s| !s.is_empty()).map(str::to_string),
    ))
}

/// The transport of `scheme` among `transports` (`[[transports]]`).
pub fn transport_of<'a>(
    transports: &'a [TransportConfig],
    scheme: &str,
) -> ImageResult<&'a TransportConfig> {
    transports
        .iter()
        .find(|t| t.scheme == scheme)
        .ok_or_else(|| {
            let known: Vec<&str> = transports.iter().map(|t| t.scheme.as_str()).collect();
            ImageError::Invalid(format!(
                "no transport is configured for {scheme}:// (add a [[transports]]; configured: {})",
                if known.is_empty() {
                    "none".to_string()
                } else {
                    known.join(", ")
                }
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pull_is_by_the_scheme_of_what_is_named() {
        assert_eq!(
            Origin::parse("alpine:3").unwrap(),
            Origin::Registry("alpine:3".into())
        );
        assert_eq!(
            Origin::parse("docker://quay.io/x/y:1").unwrap(),
            Origin::Registry("quay.io/x/y:1".into())
        );
        let path = |scheme, p: &str, selector: Option<&str>| Origin::Path {
            scheme,
            path: p.into(),
            selector: selector.map(str::to_string),
        };
        assert_eq!(
            Origin::parse("oci:/l:v1").unwrap(),
            path(PathScheme::Oci, "/l", Some("v1"))
        );
        assert_eq!(
            Origin::parse("oci-archive:a.tar").unwrap(),
            path(PathScheme::OciArchive, "a.tar", None)
        );
        assert_eq!(
            Origin::parse("docker-archive:a.tar:@1").unwrap(),
            path(PathScheme::DockerArchive, "a.tar", Some("@1"))
        );
        assert_eq!(
            Origin::parse("dir:/d").unwrap(),
            path(PathScheme::Dir, "/d", None)
        );
        assert_eq!(
            Origin::parse("archive:/x.tar").unwrap(),
            path(PathScheme::Archive, "/x.tar", None)
        );
        assert_eq!(
            Origin::parse("rootfs:/srv/root").unwrap(),
            path(PathScheme::Rootfs, "/srv/root", None)
        );
        assert_eq!(
            Origin::parse("docker-daemon:alpine:3").unwrap(),
            path(PathScheme::DockerDaemon, "", Some("alpine:3"))
        );
        assert_eq!(
            Origin::parse("s3://bucket/x:1").unwrap(),
            Origin::Transport {
                scheme: "s3".into(),
                location: "s3://bucket/x:1".into()
            }
        );
        // (a load from a descriptor has no path)
        assert_eq!(
            Origin::parse("archive:").unwrap(),
            path(PathScheme::Archive, "", None)
        );
        assert!(Origin::parse("containers-storage:x").is_err());
        assert!(Origin::parse("s3://user:pw@bucket/x").is_err());
    }

    #[test]
    fn a_fetcher_is_told_the_scheme_and_the_selector_but_not_the_path() {
        let origin = Origin::parse("oci-archive:/secret/place.tar:v1").unwrap();
        let text = origin.source_text();
        assert_eq!(text, "oci-archive:v1");
        assert_eq!(
            path_source(&text),
            Some((PathScheme::OciArchive, Some("v1".to_string())))
        );
        assert_eq!(path_source("archive:"), Some((PathScheme::Archive, None)));
        assert_eq!(path_source("alpine:3"), None);
    }
}
