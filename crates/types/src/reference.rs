// SPDX-License-Identifier: Apache-2.0
use crate::digest::Digest;
use crate::error::{printable, ImageError, ImageResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<Digest>,
    /// The tag of `NAME:TAG@DIGEST` when the digest is not a sha256: it
    /// names the manifest on registries that cannot address one by that
    /// algorithm, and the digest is what the bytes are checked against.
    #[serde(default)]
    pub locator_tag: Option<String>,
}

impl ImageReference {
    pub fn parse(reference: &str) -> ImageResult<Self> {
        let mut registry = "docker.io".to_string();
        let repository;
        let mut tag = None;
        let mut digest = None;
        let mut locator_tag = None;

        let reference = reference.trim();

        let (name_part, _) = if let Some(idx) = reference.rfind('@') {
            let text = &reference[idx + 1..];
            digest = Some(text.parse().map_err(|e| {
                ImageError::Registry(format!(
                    "invalid digest in the image reference `{}`: {e}",
                    printable(reference)
                ))
            })?);
            // NAME:TAG@DIGEST: the digest names the image, the tag goes
            let name = &reference[..idx];
            let last = name.rfind('/').map_or(0, |i| i + 1);
            match name[last..].rfind(':') {
                Some(c) => {
                    if digest.is_some_and(|d: Digest| d.alg() != crate::digest::Algorithm::Sha256) {
                        locator_tag = Some(name[last + c + 1..].to_string());
                    }
                    (&name[..last + c], None)
                }
                None => (name, None),
            }
        } else if let Some(idx) = reference.rfind(':') {
            let potential_tag = &reference[idx + 1..];
            if !potential_tag.contains('/') {
                tag = Some(potential_tag.to_string());
                (&reference[..idx], tag.as_deref())
            } else {
                (reference, None)
            }
        } else {
            (reference, None)
        };

        let parts: Vec<&str> = name_part.splitn(2, '/').collect();
        if parts.len() == 1 {
            repository = format!("library/{}", parts[0]);
        } else if velarx_base::reference::is_registry_domain(parts[0]) {
            registry = parts[0].to_string();
            repository = parts[1].to_string();
        } else {
            repository = name_part.to_string();
        }

        if tag.is_none() && digest.is_none() {
            tag = Some("latest".to_string());
        }

        Ok(Self {
            registry,
            repository,
            tag,
            digest,
            locator_tag,
        })
    }

    /// Whether the parts of the reference can be put in a registry URL: a
    /// reference is typed by a user, or comes from an image, and must not
    /// change the path or the query of the request.
    pub fn validate(&self) -> ImageResult<()> {
        let bad = |what: &str| {
            ImageError::Registry(format!(
                "invalid {what} in the image reference `{}`",
                printable(&self.full_name())
            ))
        };
        let host_ok = !self.registry.is_empty()
            && self.registry.len() <= 255
            && self.registry.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')
            });
        if !host_ok {
            return Err(bad("registry"));
        }
        let component_ok = |c: &str| {
            !c.is_empty()
                && c.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
                && c.starts_with(|ch: char| ch.is_ascii_alphanumeric())
                && c.ends_with(|ch: char| ch.is_ascii_alphanumeric())
        };
        if self.repository.len() > 255 || !self.repository.split('/').all(component_ok) {
            return Err(bad("repository"));
        }
        // (the tag of `NAME:TAG@sha512:D` is what the manifest is asked by)
        for tag in self.tag.iter().chain(&self.locator_tag) {
            let ok = !tag.is_empty()
                && tag.len() <= 128
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
                && !tag.starts_with(['.', '-']);
            if !ok {
                return Err(bad("tag"));
            }
        }
        Ok(())
    }

    /// The name without tag or digest, with the registry unless it is
    /// docker.io: `localhost:5000/alpine`, `library/alpine`.
    pub fn name(&self) -> String {
        if self.registry == "docker.io" {
            self.repository.clone()
        } else {
            format!("{}/{}", self.registry, self.repository)
        }
    }

    pub fn full_name(&self) -> String {
        let name = if self.registry == "docker.io" {
            self.repository.clone()
        } else {
            format!("{}/{}", self.registry, self.repository)
        };

        if let (Some(tag), Some(digest)) = (&self.locator_tag, &self.digest) {
            format!("{name}:{tag}@{digest}")
        } else if let Some(digest) = &self.digest {
            format!("{}@{}", name, digest)
        } else if let Some(tag) = &self.tag {
            format!("{}:{}", name, tag)
        } else {
            name
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_with_a_tag_and_a_digest() {
        let d = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let r = ImageReference::parse(&format!("quay.io/libpod/testimage:20241011@{d}")).unwrap();
        assert_eq!(
            (r.registry.as_str(), r.repository.as_str()),
            ("quay.io", "libpod/testimage")
        );
        assert_eq!(
            (r.tag, r.digest.map(|d| d.to_string())),
            (None, Some(d.to_string()))
        );
        assert_eq!(r.locator_tag, None);
        assert!(ImageReference::parse(&format!("localhost:5000/a@{d}"))
            .unwrap()
            .validate()
            .is_ok());
    }

    #[test]
    fn a_sha512_digest_keeps_the_tag_as_the_locator() {
        let d = format!("sha512:{}", "ab".repeat(64));
        let r = ImageReference::parse(&format!("quay.io/a/b:v1@{d}")).unwrap();
        assert_eq!(
            (r.tag.as_deref(), r.locator_tag.as_deref()),
            (None, Some("v1"))
        );
        assert_eq!(r.digest.unwrap().to_string(), d);
        assert_eq!(r.full_name(), format!("quay.io/a/b:v1@{d}"));
        assert!(r.validate().is_ok());
        let r = ImageReference::parse(&format!("quay.io/a/b@{d}")).unwrap();
        assert_eq!(r.locator_tag, None);
        assert_eq!(r.full_name(), format!("quay.io/a/b@{d}"));
        let e = ImageReference::parse("quay.io/a/b@sha512:ab")
            .unwrap_err()
            .to_string();
        assert!(e.contains("128"), "{e}");
        assert!(ImageReference::parse("quay.io/a/b@blake3:ab").is_err());
    }

    #[test]
    fn test_reference_validation() {
        let ok = |r: &str| ImageReference::parse(r).unwrap().validate().is_ok();
        assert!(ok("alpine"));
        assert!(ok("localhost:5000/ns/img.name_x-y:1.2-rc"));
        assert!(ok(
            "quay.io/a/b@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ));
        assert!(!ok("localhost:5000/../x"));
        assert!(!ok("localhost:5000/a/./b"));
        assert!(!ok("localhost:5000/a?x=1"));
        assert!(!ok("localhost:5000/a%2f..%2fb"));
        assert!(!ok("localhost:5000/Upper"));
        assert!(!ok("localhost:5000/a:tag with space"));
        assert!(ImageReference::parse("localhost:5000/a@sha256:../../x").is_err());
        assert!(!ok("host#frag/a"));
        // the tag that locates a sha512 manifest goes into the URL as well
        let d = format!("sha512:{}", "ab".repeat(64));
        assert!(ok(&format!("localhost:5000/a:v1.2_x-y@{d}")));
        for tag in ["x?y=1", "", "../m", ".x", "-x", "a b", &"t".repeat(129)] {
            assert!(!ok(&format!("localhost:5000/a:{tag}@{d}")), "{tag:?}");
        }
    }
}
