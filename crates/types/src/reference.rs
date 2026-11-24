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

/// The error of a reference that is not one.
fn bad(reference: &str, why: &str) -> ImageError {
    ImageError::Registry(format!(
        "invalid image reference `{}`: {why}",
        printable(reference)
    ))
}

impl ImageReference {
    pub fn parse(reference: &str) -> ImageResult<Self> {
        let bytes = reference.as_bytes();
        let spans = velarx_base::reference::parse(bytes).map_err(|e| bad(reference, &e))?;
        let part = |r: Option<(usize, usize)>| r.map(|(from, to)| reference[from..to].to_string());
        let digest: Option<Digest> = match part(spans.digest) {
            Some(text) => Some(text.parse().map_err(|e| {
                ImageError::Registry(format!(
                    "invalid digest in the image reference `{}`: {e}",
                    printable(reference)
                ))
            })?),
            None => None,
        };
        let name = velarx_ref_core::normalize(bytes, &spans);
        // NAME:TAG@DIGEST: the digest names the image, the tag goes, but
        // for a digest that is not a sha256 it locates the manifest
        let mut tag = part(spans.tag);
        let mut locator_tag = None;
        if let Some(d) = &digest {
            if d.alg() != crate::digest::Algorithm::Sha256 {
                locator_tag = tag.take();
            }
            tag = None;
        } else if tag.is_none() {
            tag = Some("latest".to_string());
        }
        Ok(Self {
            registry: String::from_utf8_lossy(&name.host).into_owned(),
            repository: String::from_utf8_lossy(&name.path).into_owned(),
            tag,
            digest,
            locator_tag,
        })
    }

    /// Whether the parts of the reference can be put in a registry URL: a
    /// reference is typed by a user, or comes from an image, and must not
    /// change the path or the query of the request.  It is so when the
    /// reference, written in full, is read back with the same parts.
    pub fn validate(&self) -> ImageResult<()> {
        let name = format!("{}/{}", self.registry, self.repository);
        // (the tag of `NAME:TAG@sha512:D` is what the manifest is asked by)
        let tags = self.tag.iter().chain(&self.locator_tag);
        for form in std::iter::once(name)
            .chain(tags.map(|t| format!("{}/{}:{t}", self.registry, self.repository)))
        {
            match velarx_base::reference::parse(form.as_bytes()) {
                Ok(spans) if spans.host_end == self.registry.len() => {}
                Ok(_) => return Err(bad(&form, "the registry is not the first component")),
                Err(e) => return Err(bad(&form, &e)),
            }
        }
        Ok(())
    }

    /// The name without tag or digest, with the registry unless it is
    /// docker.io and the name reads back as it is: `localhost:5000/alpine`,
    /// `library/alpine`, but `docker.io/a.b/c`, as `a.b/c` is of the host
    /// `a.b`.
    pub fn name(&self) -> String {
        let first = self.repository.split('/').next().unwrap_or_default();
        if self.registry == "docker.io" && !velarx_ref_core::looks_like_host(first.as_bytes()) {
            self.repository.clone()
        } else {
            format!("{}/{}", self.registry, self.repository)
        }
    }

    pub fn full_name(&self) -> String {
        let name = self.name();

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
        assert!(e.contains("not a digest"), "{e}");
        assert!(ImageReference::parse("quay.io/a/b@blake3:ab").is_err());
    }

    #[test]
    fn an_ipv6_registry_has_one_spelling() {
        assert!(ImageReference::parse("[::1]:5000/a").is_ok());
        for other in ["[0::1]:5000/a", "[:]/a", "[0:0::1]/a"] {
            assert!(ImageReference::parse(other).is_err(), "{other}");
        }
    }

    #[test]
    fn test_reference_validation() {
        let ok = |r: &str| ImageReference::parse(r).and_then(|r| r.validate()).is_ok();
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

    const D: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn short(s: &str) -> String {
        if s.len() > 40 {
            format!("<{} bytes>", s.len())
        } else {
            format!("{s:?}")
        }
    }

    /// What `parse` makes of `input` and whether `validate` accepts it.
    fn shown(input: &str) -> String {
        match ImageReference::parse(input) {
            Err(_) => "parse error".to_string(),
            Ok(r) => format!(
                "host {} path {} tag {} digest {} locator {} name {} {}",
                short(&r.registry),
                short(&r.repository),
                r.tag.as_deref().map_or("none".into(), short),
                r.digest.is_some(),
                r.locator_tag.as_deref().map_or("none".into(), short),
                short(&r.name()),
                if r.validate().is_ok() {
                    "valid"
                } else {
                    "invalid"
                },
            ),
        }
    }

    /// What the real code answers for the inputs of the table of the design of
    /// image references: what `parse` makes of each (the host, the path, the
    /// tag, whether there is a digest, the locator tag, the name that `name()`
    /// prints) and whether `validate` accepts it.
    #[test]
    fn the_parse_and_validate_of_the_reference_table() {
        let table: Vec<(String, &str)> = vec![
            (
                "x".to_string(),
                "host \"docker.io\" path \"library/x\" tag \"latest\" digest false locator none name \"library/x\" valid",
            ),
            (
                "x:tag".to_string(),
                "host \"docker.io\" path \"library/x\" tag \"tag\" digest false locator none name \"library/x\" valid",
            ),
            (
                "x:5000".to_string(),
                "host \"docker.io\" path \"library/x\" tag \"5000\" digest false locator none name \"library/x\" valid",
            ),
            (
                "x:5000/y".to_string(),
                "host \"x:5000\" path \"y\" tag \"latest\" digest false locator none name \"x:5000/y\" valid",
            ),
            (
                "localhost/x".to_string(),
                "host \"localhost\" path \"x\" tag \"latest\" digest false locator none name \"localhost/x\" valid",
            ),
            (
                "docker.io/alpine".to_string(),
                "host \"docker.io\" path \"library/alpine\" tag \"latest\" digest false locator none name \"library/alpine\" valid",
            ),
            (
                "index.docker.io/a/b".to_string(),
                "host \"docker.io\" path \"a/b\" tag \"latest\" digest false locator none name \"a/b\" valid",
            ),
            (
                "docker.io/a.b/c".to_string(),
                "host \"docker.io\" path \"a.b/c\" tag \"latest\" digest false locator none name \"docker.io/a.b/c\" valid",
            ),
            (
                "Quay.IO/a/b".to_string(),
                "parse error",
            ),
            (
                "Foo/bar".to_string(),
                "parse error",
            ),
            (
                "quay.io/a..b".to_string(),
                "parse error",
            ),
            (
                "quay.io/a--_b".to_string(),
                "parse error",
            ),
            (
                "quay.io/a___b".to_string(),
                "parse error",
            ),
            (
                ":5000/x".to_string(),
                "parse error",
            ),
            (
                "a.b:abc/x".to_string(),
                "parse error",
            ),
            (
                "a..b/x".to_string(),
                "parse error",
            ),
            (
                "a.-b/x".to_string(),
                "parse error",
            ),
            (
                "[::1]:5000/a".to_string(),
                "host \"[::1]:5000\" path \"a\" tag \"latest\" digest false locator none name \"[::1]:5000/a\" valid",
            ),
            (
                "quay.io//a".to_string(),
                "parse error",
            ),
            (
                "a/".to_string(),
                "parse error",
            ),
            (
                "/a".to_string(),
                "parse error",
            ),
            (
                "a:".to_string(),
                "parse error",
            ),
            (
                "a:.x".to_string(),
                "parse error",
            ),
            (
                "../x".to_string(),
                "parse error",
            ),
            (
                "%2f".to_string(),
                "parse error",
            ),
            (
                "?".to_string(),
                "parse error",
            ),
            (
                "#".to_string(),
                "parse error",
            ),
            (
                "quay.io/a b".to_string(),
                "parse error",
            ),
            (
                "quay.io/a\0b".to_string(),
                "parse error",
            ),
            (
                "quay.io/caf\u{e9}".to_string(),
                "parse error",
            ),
            (
                format!("quay.io/a:{}", "t".repeat(129)),
                "parse error",
            ),
            (
                format!("quay.io/a:t@{D}"),
                "host \"quay.io\" path \"a\" tag none digest true locator none name \"quay.io/a\" valid",
            ),
            (
                format!("quay.io/a:b c@{D}"),
                "parse error",
            ),
            (
                format!("x@y@{D}"),
                "parse error",
            ),
            (
                format!("a@{D1}@{D}"),
                "parse error",
            ),
            (
                format!("h.io@evil.com/a@{D}"),
                "parse error",
            ),
            (
                " alpine\n".to_string(),
                "parse error",
            ),
            (
                "a".repeat(258),
                "parse error",
            ),
            (
                "a".repeat(255),
                "parse error",
            ),
            (
                format!("quay.io/{}", "a".repeat(255)),
                "parse error",
            ),
            (
                format!("{}.io/x", "a".repeat(252)),
                "parse error",
            ),
            (
                "0123456789abcdef".repeat(4),
                "parse error",
            ),
            (format!("a@sha384:{}", "ab".repeat(48)), "parse error"),
            (format!("a@foo:{}", "z".repeat(32)), "parse error"),
            (format!("a@sha256:{}", "A".repeat(64)), "parse error"),
            ("a@sha256:abc".to_string(), "parse error"),
            ("alpine@".to_string(), "parse error"),
            (
                format!("quay.io/a:v1@sha512:{}", "ab".repeat(64)),
                "host \"quay.io\" path \"a\" tag none digest true locator \"v1\" name \"quay.io/a\" valid",
            ),
        ];
        for (input, expected) in &table {
            assert_eq!(shown(input), *expected, "{input:?}");
        }
    }
}
