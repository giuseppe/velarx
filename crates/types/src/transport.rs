// SPDX-License-Identifier: Apache-2.0
//! The transports of an image name, as podman and skopeo write them
//! (`docker://REF`, `oci:PATH[:TAG]`, `oci-archive:FILE[:TAG]`,
//! `docker-archive:FILE[:REF|:@N]`, `dir:PATH`, `containers-storage:NAME`, and
//! the sources `docker-daemon:IMAGE` and `rootfs:DIR`): the one parser that
//! every command and every API route that takes an image name uses.
//!
//! A name without a transport is a name of the local store or of a registry.
//! Only the transports of containers/image are recognised, so that an image
//! called `registry:3` or `docker:dind` is not a transport.  `docker:` is one
//! only with the two slashes, as in containers/image.  A prefix that has the
//! two slashes (`name://`) and is not a transport is an error, not a registry
//! called `name`.

use thiserror::Error;

/// The transports that velarx implements, for the messages.
pub const SUPPORTED: &str =
    "docker://, oci:, oci-archive:, docker-archive:, docker-daemon:, rootfs:, dir: and containers-storage: (or a name without a transport)";

/// Where an image is, as its name says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageLocation {
    /// `docker://REF` or a name without a transport: a registry's image
    /// (or one of the local store, for the commands that look there first).
    Registry(String),
    /// `oci:PATH[:TAG]`: a directory in the OCI image layout; `tag` is the
    /// `org.opencontainers.image.ref.name` of the entry of its `index.json`.
    OciLayout { path: String, tag: Option<String> },
    /// `oci-archive:FILE[:TAG]`: a tar of an OCI image layout.
    OciArchive { path: String, tag: Option<String> },
    /// `dir:PATH`: one manifest and its blobs in a directory (not a layout).
    Dir { path: String },
    /// `containers-storage:NAME`: an image of the local store.
    Storage(String),
    /// `docker-archive:FILE[:REF|:@N]`: a `docker save` archive.  `selector`
    /// is the image to take: a reference one of its `RepoTags` has, or the
    /// N-th entry of its `manifest.json` (`@0` is the first).
    DockerArchive {
        path: String,
        selector: Option<String>,
    },
    /// `docker-daemon:IMAGE`: an image of a running Docker daemon, a source
    /// only.  `reference` is what the daemon takes in `docker save`: a name
    /// with a tag, or an ID.
    DockerDaemon { reference: String },
    /// `rootfs:DIR`: a root file system in a directory, which becomes the one
    /// layer of an image; a source only.
    Rootfs { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransportError {
    /// A transport of containers/image that velarx does not have.
    #[error("the transport {name} is not supported: velarx supports {SUPPORTED}")]
    Unsupported { name: String },
    /// `NAME://...` where NAME is no transport at all.
    #[error("unknown transport {name}://: velarx supports {SUPPORTED}")]
    Unknown { name: String },
    /// The destination of an external scheme has credentials in its
    /// authority, or none: the text is never part of the message (it may
    /// hold a secret).
    #[error("the destination of the transport {scheme}:// {why}")]
    Authority { scheme: String, why: &'static str },
    #[error("invalid image name `{spec}`: {why}")]
    Invalid { spec: String, why: String },
    /// A command or route that takes a registry name only.
    #[error("the transport {name} is not supported by {what}: only {only} can be used")]
    NotHere {
        name: String,
        what: String,
        only: &'static str,
    },
}

fn invalid(spec: &str, why: &str) -> TransportError {
    TransportError::Invalid {
        spec: spec.to_string(),
        why: why.to_string(),
    }
}

/// `path[:tag]` of the layout transports: the tag follows the first colon,
/// as containers/image splits it.
fn path_and_tag(spec: &str, rest: &str) -> Result<(String, Option<String>), TransportError> {
    let (path, tag) = match rest.split_once(':') {
        Some((p, t)) => (p, Some(t)),
        None => (rest, None),
    };
    if path.is_empty() {
        return Err(invalid(spec, "the path is empty"));
    }
    if path.contains('\0') || tag.is_some_and(|t| t.contains('\0')) {
        return Err(invalid(spec, "a NUL byte"));
    }
    // (an empty image part is no image part: "the only image", as skopeo)
    let tag = tag.filter(|t| !t.is_empty());
    Ok((path.to_string(), tag.map(str::to_string)))
}

/// The selector of `docker-archive:FILE:SELECTOR`, checked as podman checks
/// it: `@N` a number, else a reference with a tag (the tag `latest` when
/// it has none), not a digest.
fn check_archive_selector(spec: &str, selector: &str) -> Result<(), TransportError> {
    if let Some(n) = selector.strip_prefix('@') {
        return match n.parse::<i64>() {
            Ok(i) if i < 0 => Err(invalid(
                spec,
                &format!("invalid source index @{i}: must not be negative"),
            )),
            Ok(_) => Ok(()),
            Err(_) => Err(invalid(
                spec,
                &format!("invalid source index @{n}: a number, as in @0"),
            )),
        };
    }
    let bad = || invalid(spec, &format!("invalid reference `{selector}`"));
    if selector.is_empty() || selector != selector.trim() {
        return Err(bad());
    }
    let reference = crate::ImageReference::parse(selector).map_err(|_| bad())?;
    reference.validate().map_err(|_| bad())?;
    if reference.digest.is_some() {
        return Err(invalid(
            spec,
            &format!("the reference `{selector}` has no tag: name the image by its tag or @N"),
        ));
    }
    Ok(())
}

impl ImageLocation {
    pub fn parse(spec: &str) -> Result<Self, TransportError> {
        // `docker://` has the slashes; `name://` of another name is an error
        if let Some((name, rest)) = spec.split_once("://") {
            let is_name = !name.is_empty()
                && name.starts_with(|c: char| c.is_ascii_lowercase())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b));
            if name == "docker" {
                if rest.is_empty() || rest.contains('\0') {
                    return Err(invalid(spec, "no image name after docker://"));
                }
                return Ok(Self::Registry(rest.to_string()));
            }
            if is_name
                && !matches!(
                    name,
                    "oci"
                        | "oci-archive"
                        | "docker-archive"
                        | "docker-daemon"
                        | "rootfs"
                        | "dir"
                        | "containers-storage"
                )
            {
                return Err(match Self::by_name(name) {
                    Some(e) => e,
                    None => TransportError::Unknown {
                        name: name.to_string(),
                    },
                });
            }
        }
        let Some((name, rest)) = spec.split_once(':') else {
            return Ok(Self::Registry(spec.to_string()));
        };
        match name {
            "oci" => {
                let (path, tag) = path_and_tag(spec, rest)?;
                Ok(Self::OciLayout { path, tag })
            }
            "oci-archive" => {
                let (path, tag) = path_and_tag(spec, rest)?;
                Ok(Self::OciArchive { path, tag })
            }
            "docker-archive" => {
                // (the selector follows the first `:`, as containers/image
                // splits it: the reference keeps the colons of its own)
                let (path, selector) = match rest.split_once(':') {
                    Some((p, s)) => (p, Some(s)),
                    None => (rest, None),
                };
                if path.is_empty() {
                    return Err(invalid(spec, "the path is empty"));
                }
                if path.contains('\0') || selector.is_some_and(|s| s.contains('\0')) {
                    return Err(invalid(spec, "a NUL byte"));
                }
                if let Some(s) = selector {
                    check_archive_selector(spec, s)?;
                }
                Ok(Self::DockerArchive {
                    path: path.to_string(),
                    selector: selector.map(str::to_string),
                })
            }
            "docker-daemon" => {
                if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(invalid(
                        spec,
                        "no image name, or a name with a space or a control character",
                    ));
                }
                Ok(Self::DockerDaemon {
                    reference: rest.to_string(),
                })
            }
            "rootfs" => {
                if rest.is_empty() || rest.contains('\0') {
                    return Err(invalid(spec, "the path is empty"));
                }
                Ok(Self::Rootfs {
                    path: rest.to_string(),
                })
            }
            "dir" => {
                if rest.is_empty() || rest.contains('\0') {
                    return Err(invalid(spec, "the path is empty"));
                }
                Ok(Self::Dir {
                    path: rest.to_string(),
                })
            }
            "containers-storage" => {
                if rest.is_empty() || rest.contains('\0') {
                    return Err(invalid(spec, "no image name after containers-storage:"));
                }
                if rest.starts_with('[') {
                    return Err(invalid(
                        spec,
                        "a store specification [driver@root+runroot] is not supported: velarx has one store",
                    ));
                }
                Ok(Self::Storage(rest.to_string()))
            }
            // (the name of a tag, `docker:dind`, is not a transport)
            n => match Self::by_name(n) {
                Some(e) => Err(e),
                None => Ok(Self::Registry(spec.to_string())),
            },
        }
    }

    /// The error for a transport of containers/image that is not
    /// implemented.
    fn by_name(name: &str) -> Option<TransportError> {
        match name {
            "ostree" | "sif" | "tarball" => Some(TransportError::Unsupported {
                name: name.to_string(),
            }),
            _ => None,
        }
    }

    /// Whether `name` is a transport of containers/image, one velarx has or
    /// knows it has not: a scheme of `[[transports]]` cannot be it.
    pub fn is_transport_name(name: &str) -> bool {
        matches!(
            name,
            "docker"
                | "oci"
                | "oci-archive"
                | "docker-archive"
                | "docker-daemon"
                | "rootfs"
                | "dir"
                | "containers-storage"
        ) || Self::by_name(name).is_some()
    }

    /// `SCHEME://REST` of a scheme that is no transport of velarx: the
    /// scheme and the rest, `None` when the text is none.  A push to it is
    /// the business of a `[[transports]]` of that scheme, if the
    /// configuration has one.  The authority (what stands before the first
    /// `/`, `?` or `#` of the rest) must be there and carry no userinfo (`user:password@`):
    /// the destination is told to the helpers, logged and used as the key of
    /// the credentials, which go to `--creds`, `login` or the auth file; the
    /// error never contains the text.  Every entry point of a destination
    /// calls this, and the other functions here give `None` for a refused one.
    pub fn external(spec: &str) -> Result<Option<(&str, &str)>, TransportError> {
        let Some((scheme, rest)) = spec.split_once("://") else {
            return Ok(None);
        };
        let shaped = scheme.starts_with(|c: char| c.is_ascii_lowercase())
            && scheme
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b));
        if !shaped || rest.is_empty() || Self::is_transport_name(scheme) {
            return Ok(None);
        }
        let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
        let refuse = |why| {
            Err(TransportError::Authority {
                scheme: scheme.to_string(),
                why,
            })
        };
        if authority.is_empty() {
            return refuse("has no authority: write SCHEME://AUTHORITY/NAME");
        }
        if authority.contains('@') {
            return refuse(
                "must not carry credentials (user and password before the @): use --creds, `velarx login` or the auth file",
            );
        }
        Ok(Some((scheme, rest)))
    }

    /// The key of the credentials of a destination of an external scheme:
    /// `SCHEME://AUTHORITY` in lower case (what stands before the first
    /// `/`, `?` or `#` of the rest), and nothing a docker reference means:
    /// no short-name resolution, no search registry, no path.  The auth file,
    /// the client and the engine look the credentials of such a destination
    /// up under exactly this key (`normalize_auth_key` gives the same case to
    /// the keys they hold).  `None` when the text is no such destination, or
    /// is refused by `external`.
    pub fn credential_key(spec: &str) -> Option<String> {
        let (scheme, rest) = Self::external(spec).ok()??;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        Some(format!("{scheme}://{}", rest[..end].to_ascii_lowercase()))
    }

    /// What the log may say of a destination: `SCHEME://AUTHORITY` without
    /// any userinfo, never the path, the query or a secret.
    pub fn loggable(spec: &str) -> String {
        let Some((scheme, rest)) = spec.split_once("://") else {
            return String::new();
        };
        let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
        let host = authority.rsplit('@').next().unwrap_or(authority);
        format!("{scheme}://{host}")
    }

    /// The name a destination of an external scheme gives the image: the
    /// tag of its last path segment (`s3://bucket/x:1` is `1`), or the
    /// digest (`s3://bucket/x@sha256:...`); none when it names neither
    /// (the manifest is then put by its digest).  What the pusher of the
    /// scheme and its helpers are told as the names of the commit.
    pub fn external_name(spec: &str) -> Option<String> {
        let (_, rest) = Self::external(spec).ok()??;
        let rest = rest.split(['?', '#']).next().unwrap_or(rest);
        let (_, path) = rest.split_once('/')?;
        let last = path.rsplit('/').next().unwrap_or(path);
        if let Some((_, digest)) = last.split_once('@') {
            return Some(digest.to_string());
        }
        last.split_once(':')
            .map(|(_, tag)| tag.to_string())
            .filter(|t| !t.is_empty())
    }

    /// A destination of an external scheme without the name it gives the
    /// image (`s3://bucket/x:1` is `s3://bucket/x`): the repository the
    /// images of a list are pushed to by their digests.
    pub fn external_repository(spec: &str) -> Option<&str> {
        Self::external(spec).ok()??;
        let cut = spec.find(['?', '#']).unwrap_or(spec.len());
        let spec = &spec[..cut];
        let start = spec.find("://")? + 3;
        let Some(last) = spec[start..].rfind('/').map(|i| start + i) else {
            return Some(spec);
        };
        let end = spec[last..]
            .find(['@', ':'])
            .map_or(spec.len(), |i| last + i);
        Some(&spec[..end])
    }

    /// The transport as it is written.
    pub fn transport(&self) -> &'static str {
        match self {
            Self::Registry(_) => "docker://",
            Self::OciLayout { .. } => "oci:",
            Self::OciArchive { .. } => "oci-archive:",
            Self::Dir { .. } => "dir:",
            Self::Storage(_) => "containers-storage:",
            Self::DockerArchive { .. } => "docker-archive:",
            Self::DockerDaemon { .. } => "docker-daemon:",
            Self::Rootfs { .. } => "rootfs:",
        }
    }

    /// The name of a registry (or of the local store, without a transport),
    /// for what takes nothing else: `what` is the subject of the message
    /// (`the REST API`).
    pub fn registry(spec: &str, what: &str) -> Result<String, TransportError> {
        match Self::parse(spec)? {
            Self::Registry(name) => Ok(name),
            other => Err(TransportError::NotHere {
                name: other.transport().trim_end_matches(':').to_string(),
                what: what.to_string(),
                only: "docker:// (a registry name)",
            }),
        }
    }

    /// The name of an image of the store: a name, or `containers-storage:`
    /// and a name.
    pub fn local(spec: &str, what: &str) -> Result<String, TransportError> {
        match Self::parse(spec)? {
            Self::Registry(name) | Self::Storage(name) => Ok(name),
            other => Err(TransportError::NotHere {
                name: other.transport().trim_end_matches(':').to_string(),
                what: what.to_string(),
                only: "containers-storage: and docker:// (a name)",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_a_destination_of_an_external_scheme_has_a_key_and_a_name() {
        let key = |s| ImageLocation::credential_key(s);
        let name = |s| ImageLocation::external_name(s);
        assert_eq!(
            key("s3://bucket/private/x:1").as_deref(),
            Some("s3://bucket")
        );
        assert_eq!(key("s3://host:9000/x").as_deref(), Some("s3://host:9000"));
        assert_eq!(key("s3://bucket").as_deref(), Some("s3://bucket"));
        assert_eq!(key("gs://peer?x=1/y").as_deref(), Some("gs://peer"));
        // (a registry and a path are not external: they have no such key)
        assert_eq!(key("docker://quay.io/a/b"), None);
        assert_eq!(key("oci:/tmp/x"), None);
        assert_eq!(key("quay.io/a/b"), None);
        assert_eq!(name("s3://bucket/private/x:1").as_deref(), Some("1"));
        assert_eq!(name("s3://bucket/x").as_deref(), None);
        assert_eq!(name("s3://host:9000").as_deref(), None);
        assert_eq!(name("s3://host:9000/x").as_deref(), None);
        let repo = |s| ImageLocation::external_repository(s);
        assert_eq!(
            repo("s3://bucket/private/x:1"),
            Some("s3://bucket/private/x")
        );
        assert_eq!(repo("s3://host:9000/x"), Some("s3://host:9000/x"));
        assert_eq!(repo("s3://host:9000"), Some("s3://host:9000"));
        assert_eq!(repo("quay.io/x"), None);
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            name(&format!("s3://bucket/x@{digest}")).as_deref(),
            Some(digest.as_str())
        );
    }

    use super::*;

    #[test]
    fn a_destination_with_userinfo_or_without_authority_is_refused_without_its_text() {
        for bad in [
            "s3://AKID:SECRET@bucket/x:1",
            "s3://SECRET@bucket",
            "s3://u:SECRET@host:9000/x",
            "s3://AKID:SECRET@/x",
            "s3://AKID:SECRET@",
            "s3://AKID:SECRET@bucket?x#y",
            "s3:///x:1",
            "s3://?SECRET",
            "s3://#SECRET",
        ] {
            let e = ImageLocation::external(bad).unwrap_err();
            assert!(matches!(e, TransportError::Authority { .. }), "{bad}");
            let text = format!("{e} {e:?}");
            assert!(!text.contains("SECRET") && !text.contains("AKID"), "{text}");
            assert!(text.contains("s3://"), "{text}");
            assert_eq!(ImageLocation::credential_key(bad), None, "{bad}");
            assert_eq!(ImageLocation::external_name(bad), None, "{bad}");
            assert_eq!(ImageLocation::external_repository(bad), None, "{bad}");
            let logged = ImageLocation::loggable(bad);
            assert!(
                !logged.contains("SECRET") && !logged.contains("AKID"),
                "{logged}"
            );
        }
        // (an `@` after the authority is a path, not userinfo)
        assert!(ImageLocation::external("s3://bucket/x@sha256:00")
            .unwrap()
            .is_some());
        assert!(ImageLocation::external("s3://bucket?a=b@c")
            .unwrap()
            .is_some());
    }

    #[test]
    fn what_the_log_says_of_a_destination_is_its_scheme_and_authority() {
        assert_eq!(
            ImageLocation::loggable("s3://bucket/a/b:1?x=1"),
            "s3://bucket"
        );
        assert_eq!(ImageLocation::loggable("s3://h:9000/x"), "s3://h:9000");
        assert_eq!(
            ImageLocation::loggable("s3://AKID:SECRET@bucket/x"),
            "s3://bucket"
        );
        assert_eq!(ImageLocation::loggable("quay.io/a"), "");
    }

    #[test]
    fn the_key_of_a_destination_is_in_lower_case() {
        let key = |s| ImageLocation::credential_key(s);
        assert_eq!(key("s3://Bucket/X:1").as_deref(), Some("s3://bucket"));
        assert_eq!(key("s3://BUCKET:9000").as_deref(), Some("s3://bucket:9000"));
        assert_eq!(key("s3://[::1]:9000/x").as_deref(), Some("s3://[::1]:9000"));
        assert_eq!(key("s3://bucket/x"), key("s3://BUCKET/y"));
    }

    #[test]
    fn a_scheme_that_is_no_transport_is_external() {
        assert_eq!(
            ImageLocation::external("s3://bucket/img:1").unwrap(),
            Some(("s3", "bucket/img:1"))
        );
        for no in [
            "docker://alpine",
            "oci://x",
            "docker-daemon://x",
            "sif://x",
            "S3://x",
            "s3://",
            "s3:x",
            "alpine",
            "localhost:5000/a",
        ] {
            assert_eq!(ImageLocation::external(no).unwrap(), None, "{no}");
        }
    }

    fn reg(s: &str) -> ImageLocation {
        ImageLocation::Registry(s.to_string())
    }

    #[test]
    fn names_without_a_transport_are_registry_names() {
        for s in [
            "alpine",
            "alpine:3",
            "localhost:5000/a/b:1",
            "registry:3",
            "docker:dind",
            "quay.io/a/b@sha256:00",
            "dir",
            "sha256:abcdef",
        ] {
            assert_eq!(ImageLocation::parse(s).unwrap(), reg(s), "{s}");
        }
    }

    #[test]
    fn docker_transport() {
        assert_eq!(
            ImageLocation::parse("docker://localhost:5000/alpine:chunked").unwrap(),
            reg("localhost:5000/alpine:chunked")
        );
        assert_eq!(
            ImageLocation::parse("docker://alpine").unwrap(),
            reg("alpine")
        );
        assert!(ImageLocation::parse("docker://").is_err());
    }

    #[test]
    fn layout_transports() {
        let layout = |p: &str, t: Option<&str>| ImageLocation::OciLayout {
            path: p.into(),
            tag: t.map(Into::into),
        };
        assert_eq!(
            ImageLocation::parse("oci:/tmp/l").unwrap(),
            layout("/tmp/l", None)
        );
        assert_eq!(
            ImageLocation::parse("oci:rel/dir:v1").unwrap(),
            layout("rel/dir", Some("v1"))
        );
        assert_eq!(
            ImageLocation::parse("oci-archive:/tmp/a.tar:latest").unwrap(),
            ImageLocation::OciArchive {
                path: "/tmp/a.tar".into(),
                tag: Some("latest".into())
            }
        );
        assert_eq!(
            ImageLocation::parse("oci-archive:a.tar").unwrap(),
            ImageLocation::OciArchive {
                path: "a.tar".into(),
                tag: None
            }
        );
        // an empty image part is the only image, as skopeo has it
        assert_eq!(ImageLocation::parse("oci:/x:").unwrap(), layout("/x", None));
        for bad in ["oci:", "oci::tag", "oci-archive:", "oci-archive::x"] {
            assert!(
                matches!(
                    ImageLocation::parse(bad),
                    Err(TransportError::Invalid { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn dir_and_storage_transports() {
        assert_eq!(
            ImageLocation::parse("dir:/tmp/d:odd").unwrap(),
            ImageLocation::Dir {
                path: "/tmp/d:odd".into()
            }
        );
        assert!(ImageLocation::parse("dir:").is_err());
        assert_eq!(
            ImageLocation::parse("containers-storage:localhost/a:1").unwrap(),
            ImageLocation::Storage("localhost/a:1".into())
        );
        assert!(ImageLocation::parse("containers-storage:").is_err());
        let e = ImageLocation::parse("containers-storage:[overlay@/x+/y]a").unwrap_err();
        assert!(e.to_string().contains("one store"), "{e}");
    }

    #[test]
    fn docker_archive_transport() {
        let da = |p: &str, s: Option<&str>| ImageLocation::DockerArchive {
            path: p.into(),
            selector: s.map(Into::into),
        };
        assert_eq!(
            ImageLocation::parse("docker-archive:/tmp/x.tar").unwrap(),
            da("/tmp/x.tar", None)
        );
        // (the reference of the selector keeps its colons: the first splits)
        assert_eq!(
            ImageLocation::parse("docker-archive:/tmp/x.tar:localhost/a:v1").unwrap(),
            da("/tmp/x.tar", Some("localhost/a:v1"))
        );
        assert_eq!(
            ImageLocation::parse("docker-archive:rel/x.tar:docker.io/library/alpine:3").unwrap(),
            da("rel/x.tar", Some("docker.io/library/alpine:3"))
        );
        // (the N-th entry of manifest.json, `@0` the first, as skopeo)
        assert_eq!(
            ImageLocation::parse("docker-archive:/tmp/x.tar:@1").unwrap(),
            da("/tmp/x.tar", Some("@1"))
        );
        // (`FILE@N` is a file of that name: the index follows the colon)
        assert_eq!(
            ImageLocation::parse("docker-archive:/tmp/x.tar@1").unwrap(),
            da("/tmp/x.tar@1", None)
        );
        // the selector is checked as podman checks it: an empty one, a
        // negative or non-numeric index, an invalid reference and a digest
        // are errors
        for bad in [
            "docker-archive:",
            "docker-archive::x.tar",
            "docker-archive:/a\0b",
            "docker-archive:/tmp/x.tar:",
            "docker-archive:/tmp/x.tar:@-1",
            "docker-archive:/tmp/x.tar:@x",
            "docker-archive:/tmp/x.tar:@",
            "docker-archive:/tmp/x.tar:Upper",
            "docker-archive:/tmp/x.tar:a b",
            "docker-archive:/tmp/x.tar:a/../b",
            "docker-archive:/tmp/x.tar:a@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(
                matches!(
                    ImageLocation::parse(bad),
                    Err(TransportError::Invalid { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_daemon_and_a_root_file_system_are_sources() {
        assert_eq!(
            ImageLocation::parse("docker-daemon:alpine:3").unwrap(),
            ImageLocation::DockerDaemon {
                reference: "alpine:3".into()
            }
        );
        assert_eq!(
            ImageLocation::parse("rootfs:/srv/root").unwrap(),
            ImageLocation::Rootfs {
                path: "/srv/root".into()
            }
        );
        for bad in [
            "docker-daemon:",
            "docker-daemon:a b",
            "docker-daemon:a\r\nb",
            "rootfs:",
            "rootfs:/a\0b",
        ] {
            assert!(
                matches!(
                    ImageLocation::parse(bad),
                    Err(TransportError::Invalid { .. })
                ),
                "{bad:?}"
            );
        }
        let e = ImageLocation::registry("docker-daemon:alpine", "the REST API").unwrap_err();
        assert!(e.to_string().contains("docker-daemon"), "{e}");
    }

    #[test]
    fn unknown_transports_name_the_supported_ones() {
        let e = ImageLocation::parse("registry://quay.io/a").unwrap_err();
        assert!(matches!(e, TransportError::Unknown { .. }));
        assert!(e.to_string().contains("registry://"), "{e}");
        assert!(e.to_string().contains("oci-archive:"), "{e}");
        let e = ImageLocation::parse("ostree:x@/repo").unwrap_err();
        assert!(matches!(e, TransportError::Unsupported { .. }), "{e}");
        let e = ImageLocation::parse("tarball:/x.tar").unwrap_err();
        assert!(e.to_string().contains("not supported"), "{e}");
    }

    #[test]
    fn windows_like_paths_are_no_transport() {
        for s in [r"C:\images\a.tar", "c:/images/a.tar", r"d:\x"] {
            assert_eq!(ImageLocation::parse(s).unwrap(), reg(s), "{s}");
        }
        // (the registry parser refuses them later)
        assert!(crate::ImageReference::parse(r"C:\images\a.tar").is_err());
    }

    #[test]
    fn registry_only_callers() {
        assert_eq!(
            ImageLocation::registry("docker://a/b", "the REST API").unwrap(),
            "a/b"
        );
        assert_eq!(ImageLocation::registry("a/b", "x").unwrap(), "a/b");
        let e = ImageLocation::registry("oci:/x", "the REST API").unwrap_err();
        assert_eq!(
            e.to_string(),
            "the transport oci is not supported by the REST API: only docker:// (a registry name) can be used"
        );
        assert_eq!(
            ImageLocation::local("containers-storage:a", "x").unwrap(),
            "a"
        );
        assert!(ImageLocation::local("dir:/x", "x").is_err());
    }
}
