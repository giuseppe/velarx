// SPDX-License-Identifier: Apache-2.0
//! Docker references as the identity rules of signatures compare them:
//! normalized like `docker/reference.ParseNormalizedNamed` (the
//! default registry, `library/`), with or without a tag or a digest, and
//! the `signedIdentity` rules of policy.json.

use velarx_policy_core::{covers, identity_matches, Ref, Rule};

/// A normalized reference: `domain/path[:tag][@digest]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerRef {
    pub domain: String,
    pub path: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl DockerRef {
    /// Parse and normalize `s` as `ParseNormalizedNamed` does.
    pub fn parse_normalized(s: &str) -> Result<Self, String> {
        let bytes = s.as_bytes();
        let spans = velarx_base::reference::parse(bytes)
            .map_err(|e| format!("invalid reference format: {s:?}: {e}"))?;
        let name = velarx_ref_core::normalize(bytes, &spans);
        // (an accepted string is ASCII: its spans are on characters)
        let part = |r: Option<(usize, usize)>| r.map(|(from, to)| s[from..to].to_string());
        Ok(Self {
            domain: String::from_utf8_lossy(&name.host).into_owned(),
            path: String::from_utf8_lossy(&name.path).into_owned(),
            tag: part(spans.tag),
            digest: part(spans.digest),
        })
    }

    /// `domain/path`.
    pub fn name(&self) -> String {
        format!("{}/{}", self.domain, self.path)
    }

    /// The whole reference, as `reference.Named.String()` writes it.
    pub fn string(&self) -> String {
        let mut s = self.name();
        if let Some(t) = &self.tag {
            s.push(':');
            s.push_str(t);
        }
        if let Some(d) = &self.digest {
            s.push('@');
            s.push_str(d);
        }
        s
    }

    pub fn name_only(&self) -> bool {
        self.tag.is_none() && self.digest.is_none()
    }

    /// The reference as the decision of velarx-policy-core has it.
    pub fn to_core(&self) -> Ref {
        Ref {
            name: self.name().into_bytes(),
            tag: self.tag.clone().map(String::into_bytes),
            digest: self.digest.clone().map(String::into_bytes),
        }
    }
}

/// The `signedIdentity` rules.
/// The default is `matchRepoDigestOrExact`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum SignedIdentity {
    MatchExact,
    #[default]
    MatchRepoDigestOrExact,
    MatchRepository,
    ExactReference {
        #[serde(rename = "dockerReference")]
        docker_reference: String,
    },
    ExactRepository {
        #[serde(rename = "dockerRepository")]
        docker_repository: String,
    },
    RemapIdentity {
        prefix: String,
        #[serde(rename = "signedPrefix")]
        signed_prefix: String,
    },
}

impl SignedIdentity {
    /// The rule of velarx-policy-core for the image asked by `intended`.
    /// One that cannot be a reference (a reference that does not parse, a
    /// prefix replaced by what is not one as written) matches nothing.
    pub fn rule(&self, intended: &DockerRef) -> Rule {
        let reference = |r: &str| DockerRef::parse_normalized(r).map(|r| r.to_core());
        match self {
            SignedIdentity::MatchExact => Rule::Exact,
            SignedIdentity::MatchRepoDigestOrExact => Rule::RepoDigestOrExact,
            SignedIdentity::MatchRepository => Rule::Repository,
            SignedIdentity::ExactReference { docker_reference } => {
                reference(docker_reference).map_or(Rule::Nothing, Rule::ExactReference)
            }
            SignedIdentity::ExactRepository { docker_repository } => {
                DockerRef::parse_normalized(docker_repository).map_or(Rule::Nothing, |r| {
                    Rule::ExactRepository(r.name().into_bytes())
                })
            }
            SignedIdentity::RemapIdentity {
                prefix,
                signed_prefix,
            } if covers(prefix.as_bytes(), intended.name().as_bytes()) => {
                let s = intended
                    .string()
                    .replacen(prefix.as_str(), signed_prefix, 1);
                // the result must be a reference as it is, not one that
                // normalization changes
                match DockerRef::parse_normalized(&s) {
                    Ok(r) if r.string() == s => Rule::Remapped(r.to_core()),
                    _ => Rule::Nothing,
                }
            }
            SignedIdentity::RemapIdentity { .. } => Rule::RepoDigestOrExact,
        }
    }

    /// Whether a signature for `signed` is a signature for the image the
    /// user asked as `intended`.
    pub fn matches(&self, intended: &DockerRef, signed: &str) -> bool {
        DockerRef::parse_normalized(signed).is_ok_and(|signed| {
            identity_matches(&self.rule(intended), &intended.to_core(), &signed.to_core())
        })
    }

    /// Whether the rule is usable: references that parse, prefixes that
    /// are a host or a repository.
    pub fn validate(&self) -> Result<(), String> {
        let prefix_ok = |p: &str| {
            // a host, or a host and a path, written as they are normalized
            velarx_base::reference::host_ok(p.as_bytes())
                || DockerRef::parse_normalized(p).is_ok_and(|r| r.name() == p && r.name_only())
        };
        match self {
            SignedIdentity::ExactReference { docker_reference } => {
                let r = DockerRef::parse_normalized(docker_reference)?;
                if r.name_only() {
                    return Err(format!(
                        "dockerReference {docker_reference:?} has neither a tag nor a digest"
                    ));
                }
            }
            SignedIdentity::ExactRepository { docker_repository } => {
                DockerRef::parse_normalized(docker_repository)?;
            }
            SignedIdentity::RemapIdentity {
                prefix,
                signed_prefix,
            } => {
                for p in [prefix, signed_prefix] {
                    if !prefix_ok(p) {
                        return Err(format!("invalid prefix {p:?} of remapIdentity"));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> DockerRef {
        DockerRef::parse_normalized(s).unwrap()
    }

    #[test]
    fn references_are_normalized() {
        assert_eq!(r("busybox").string(), "docker.io/library/busybox");
        assert_eq!(r("busybox:1").string(), "docker.io/library/busybox:1");
        assert_eq!(r("docker.io/busybox").string(), "docker.io/library/busybox");
        assert_eq!(r("index.docker.io/a/b:c").string(), "docker.io/a/b:c");
        assert_eq!(r("localhost/a").string(), "localhost/a");
        assert_eq!(r("localhost:5000/a/b:v1").string(), "localhost:5000/a/b:v1");
        assert_eq!(r("[::1]:5000/a@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").name(), "[::1]:5000/a");
        let both = r(
            "quay.io/a/b:t@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        assert_eq!(both.tag.as_deref(), Some("t"));
        assert!(both.digest.is_some());
        assert!(r("a").name_only());
        for bad in [
            "",
            "A",
            "a/B",
            "a:",
            "a::b",
            "a@sha256:00",
            "-a",
            "a//b",
            "quay.io/a/b:-x",
            "a b",
            "a@md5",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(DockerRef::parse_normalized(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn identities_match_as_containers_image() {
        let tagged = r("quay.io/a/b:v1");
        let digested = r(
            "quay.io/a/b@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let default = SignedIdentity::default();
        assert!(default.matches(&tagged, "quay.io/a/b:v1"));
        assert!(!default.matches(&tagged, "quay.io/a/b:v2"));
        assert!(!default.matches(&tagged, "quay.io/a/b"));
        assert!(default.matches(&digested, "quay.io/a/b:anything"));
        assert!(!default.matches(&digested, "quay.io/a/c:v1"));

        assert!(SignedIdentity::MatchExact.matches(&tagged, "quay.io/a/b:v1"));
        assert!(!SignedIdentity::MatchExact.matches(&digested, "quay.io/a/b:v1"));
        assert!(SignedIdentity::MatchRepository.matches(&tagged, "quay.io/a/b:other"));
        assert!(SignedIdentity::MatchRepository.matches(&tagged, "quay.io/a/b"));
        assert!(!SignedIdentity::MatchRepository.matches(&tagged, "quay.io/a/bb:v1"));

        let exact = SignedIdentity::ExactReference {
            docker_reference: "docker.io/library/busybox:1".into(),
        };
        assert!(exact.matches(&tagged, "busybox:1"));
        assert!(!exact.matches(&tagged, "busybox:2"));
        let repo = SignedIdentity::ExactRepository {
            docker_repository: "busybox".into(),
        };
        assert!(repo.matches(&tagged, "docker.io/library/busybox:any"));

        let remap = SignedIdentity::RemapIdentity {
            prefix: "mirror.local/quay".into(),
            signed_prefix: "quay.io".into(),
        };
        let mirrored = r("mirror.local/quay/a/b:v1");
        assert!(remap.matches(&mirrored, "quay.io/a/b:v1"));
        assert!(!remap.matches(&mirrored, "mirror.local/quay/a/b:v1"));
        // a prefix of a component is no prefix
        assert!(!remap.matches(&r("mirror.local/quayx/a:v1"), "quay.iox/a:v1"));
        assert!(remap.validate().is_ok());
        assert!(SignedIdentity::RemapIdentity {
            prefix: "Not A Prefix".into(),
            signed_prefix: "quay.io".into()
        }
        .validate()
        .is_err());
        assert!(SignedIdentity::ExactReference {
            docker_reference: "busybox".into()
        }
        .validate()
        .is_err());
    }

    const D1: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const D2: &str = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// The references a signature can name, in the order the tables list
    /// them.
    fn signed_names() -> [String; 8] {
        [
            "quay.io/a/b:v1".into(),
            "quay.io/a/b:v2".into(),
            "quay.io/a/b".into(),
            format!("quay.io/a/b@{D1}"),
            format!("quay.io/a/b@{D2}"),
            format!("quay.io/a/b:v1@{D1}"),
            "quay.io/a/c:v1".into(),
            "quay.io/a/bb:v1".into(),
        ]
    }

    /// The signed references of `signed_names` that the rule accepts for
    /// the image asked by `intended`, by their index.
    fn accepted_by(rule: &SignedIdentity, intended: &str) -> Vec<usize> {
        let intended = r(intended);
        (0..8)
            .filter(|i| rule.matches(&intended, &signed_names()[*i]))
            .collect()
    }

    /// Each rule against each way of asking: by tag, by digest, by both,
    /// by the name alone.
    #[test]
    fn each_identity_rule_against_each_way_of_asking() {
        let (tag, digest, both, bare) = (
            "quay.io/a/b:v1",
            &format!("quay.io/a/b@{D1}"),
            &format!("quay.io/a/b:v1@{D1}"),
            "quay.io/a/b",
        );
        let exact = SignedIdentity::MatchExact;
        assert_eq!(accepted_by(&exact, tag), [0]);
        assert_eq!(accepted_by(&exact, digest), [3]);
        assert_eq!(accepted_by(&exact, both), [5]);
        assert!(accepted_by(&exact, bare).is_empty());
        // a tag is the same reference, a digest the same repository
        let default = SignedIdentity::MatchRepoDigestOrExact;
        assert_eq!(accepted_by(&default, tag), [0]);
        assert_eq!(accepted_by(&default, digest), [0, 1, 3, 4, 5]);
        assert_eq!(accepted_by(&default, both), [5]);
        assert!(accepted_by(&default, bare).is_empty());
        // the repository, with or without a tag or a digest
        let repository = SignedIdentity::MatchRepository;
        for intended in [tag, digest, both, bare] {
            assert_eq!(accepted_by(&repository, intended), [0, 1, 2, 3, 4, 5]);
        }
        // the rules that name the reference or the repository do not look
        // at the image
        let reference = SignedIdentity::ExactReference {
            docker_reference: "quay.io/a/b:v1".into(),
        };
        let name_only = SignedIdentity::ExactReference {
            docker_reference: "quay.io/a/b".into(),
        };
        let repo = SignedIdentity::ExactRepository {
            docker_repository: "quay.io/a/b".into(),
        };
        for intended in [tag, digest, both, bare, "quay.io/x/y:z"] {
            assert_eq!(accepted_by(&reference, intended), [0]);
            // (a name alone is not a reference: `validate` refuses it, and
            // it accepts nothing)
            assert!(accepted_by(&name_only, intended).is_empty());
            assert_eq!(accepted_by(&repo, intended), [0, 1, 2, 3, 4, 5]);
        }
    }

    /// A signature whose reference is not one is for no image, under every
    /// rule.
    #[test]
    fn a_signed_reference_that_does_not_parse_matches_no_rule() {
        let rules = [
            SignedIdentity::MatchExact,
            SignedIdentity::MatchRepoDigestOrExact,
            SignedIdentity::MatchRepository,
            SignedIdentity::ExactReference {
                docker_reference: "quay.io/a/b:v1".into(),
            },
            SignedIdentity::ExactRepository {
                docker_repository: "quay.io/a/b".into(),
            },
            SignedIdentity::RemapIdentity {
                prefix: "quay.io".into(),
                signed_prefix: "quay.io".into(),
            },
        ];
        for rule in rules {
            for bad in ["", "Quay.io/A/B:v1", "quay.io/a/b:", "quay.io//a"] {
                assert!(!rule.matches(&r("quay.io/a/b:v1"), bad), "{rule:?} {bad:?}");
            }
        }
        // and a rule that names a reference that does not parse, none
        let broken = SignedIdentity::ExactReference {
            docker_reference: "Not A Reference".into(),
        };
        assert!(accepted_by(&broken, "quay.io/a/b:v1").is_empty());
    }

    fn remap(prefix: &str, signed_prefix: &str) -> SignedIdentity {
        SignedIdentity::RemapIdentity {
            prefix: prefix.into(),
            signed_prefix: signed_prefix.into(),
        }
    }

    /// `remapIdentity`: the image's reference with its prefix replaced is
    /// judged as `matchRepoDigestOrExact` does; an image the prefix is not
    /// a prefix of is judged as it is.
    #[test]
    fn remap_identity_replaces_the_prefix_of_the_image() {
        let rule = remap("mirror.local/quay", "quay.io");
        let yes = |intended: &str, signed: &str| rule.matches(&r(intended), signed);
        // by tag: the same reference after the replacement
        assert!(yes("mirror.local/quay/a/b:v1", "quay.io/a/b:v1"));
        assert!(!yes("mirror.local/quay/a/b:v1", "quay.io/a/b:v2"));
        assert!(!yes("mirror.local/quay/a/b:v1", "quay.io/a/b"));
        assert!(!yes("mirror.local/quay/a/b:v1", "quay.io/a/c:v1"));
        // by digest: the same repository after the replacement
        let digested = format!("mirror.local/quay/a/b@{D1}");
        assert!(yes(&digested, "quay.io/a/b:anything"));
        assert!(yes(&digested, &format!("quay.io/a/b@{D2}")));
        assert!(!yes(&digested, "quay.io/a/c:v1"));
        // by name alone: nothing names it
        assert!(!yes("mirror.local/quay/a/b", "quay.io/a/b"));
        assert!(!yes("mirror.local/quay/a/b", "quay.io/a/b:v1"));
        // a signature for the mirror itself is not for the image
        assert!(!yes("mirror.local/quay/a/b:v1", "mirror.local/quay/a/b:v1"));
        // not a prefix of the image: the image is judged as it is
        assert!(yes("other.local/a:v1", "other.local/a:v1"));
        assert!(!yes("other.local/a:v1", "quay.io/a:v1"));
        // a host is a prefix, and so is a whole name
        assert!(
            remap("mirror.local", "quay.io").matches(&r("mirror.local/a/b:v1"), "quay.io/a/b:v1")
        );
        assert!(remap("mirror.local/quay/a/b", "quay.io/x/y")
            .matches(&r("mirror.local/quay/a/b:v1"), "quay.io/x/y:v1"));
    }

    /// The reference made by the replacement must be one as it is written:
    /// one that normalization changes accepts nothing.
    #[test]
    fn a_remap_whose_result_is_not_normalized_accepts_nothing() {
        let rule = remap("mirror.local", "index.docker.io");
        for signed in ["index.docker.io/a/b:v1", "docker.io/a/b:v1"] {
            assert!(!rule.matches(&r("mirror.local/a/b:v1"), signed), "{signed}");
        }
        // the replacement that is a whole reference as written is fine
        let rule = remap("mirror.local", "docker.io");
        assert!(rule.matches(&r("mirror.local/a/b:v1"), "docker.io/a/b:v1"));
    }

    const D: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn short(s: &str) -> String {
        if s.len() > 40 {
            format!("<{} bytes>", s.len())
        } else {
            format!("{s:?}")
        }
    }

    /// What `parse_normalized` makes of `input`.
    fn shown(input: &str) -> String {
        match DockerRef::parse_normalized(input) {
            Err(_) => "error".to_string(),
            Ok(r) => format!(
                "domain {} path {} tag {} digest {}",
                short(&r.domain),
                short(&r.path),
                r.tag.as_deref().map_or("none".into(), short),
                r.digest.as_deref().map_or("none".into(), |d| {
                    let (algo, hex) = d.split_once(':').unwrap();
                    format!("{algo}:{}", short(hex))
                }),
            ),
        }
    }

    /// What the real code answers for the inputs of the table of the design of
    /// image references: what `parse_normalized` makes of each, that is the
    /// grammar of the identity rules of signatures (the domain, the path, the
    /// tag and the digest of the normalized reference, or an error).
    #[test]
    fn parse_normalized_on_the_reference_table() {
        let table: Vec<(String, &str)> = vec![
            (
                "x".to_string(),
                "domain \"docker.io\" path \"library/x\" tag none digest none",
            ),
            (
                "x:tag".to_string(),
                "domain \"docker.io\" path \"library/x\" tag \"tag\" digest none",
            ),
            (
                "x:5000".to_string(),
                "domain \"docker.io\" path \"library/x\" tag \"5000\" digest none",
            ),
            (
                "x:5000/y".to_string(),
                "domain \"x:5000\" path \"y\" tag none digest none",
            ),
            (
                "localhost/x".to_string(),
                "domain \"localhost\" path \"x\" tag none digest none",
            ),
            (
                "docker.io/alpine".to_string(),
                "domain \"docker.io\" path \"library/alpine\" tag none digest none",
            ),
            (
                "index.docker.io/a/b".to_string(),
                "domain \"docker.io\" path \"a/b\" tag none digest none",
            ),
            (
                "docker.io/a.b/c".to_string(),
                "domain \"docker.io\" path \"a.b/c\" tag none digest none",
            ),
            ("Quay.IO/a/b".to_string(), "error"),
            ("Foo/bar".to_string(), "error"),
            ("quay.io/a..b".to_string(), "error"),
            ("quay.io/a--_b".to_string(), "error"),
            ("quay.io/a___b".to_string(), "error"),
            (":5000/x".to_string(), "error"),
            ("a.b:abc/x".to_string(), "error"),
            ("a..b/x".to_string(), "error"),
            ("a.-b/x".to_string(), "error"),
            (
                "[::1]:5000/a".to_string(),
                "domain \"[::1]:5000\" path \"a\" tag none digest none",
            ),
            ("quay.io//a".to_string(), "error"),
            ("a/".to_string(), "error"),
            ("/a".to_string(), "error"),
            ("a:".to_string(), "error"),
            ("a:.x".to_string(), "error"),
            ("../x".to_string(), "error"),
            ("%2f".to_string(), "error"),
            ("?".to_string(), "error"),
            ("#".to_string(), "error"),
            ("quay.io/a b".to_string(), "error"),
            ("quay.io/a\0b".to_string(), "error"),
            ("quay.io/caf\u{e9}".to_string(), "error"),
            (format!("quay.io/a:{}", "t".repeat(129)), "error"),
            (
                format!("quay.io/a:t@{D}"),
                "domain \"quay.io\" path \"a\" tag \"t\" digest sha256:<64 bytes>",
            ),
            (format!("quay.io/a:b c@{D}"), "error"),
            (format!("x@y@{D}"), "error"),
            (format!("a@{D1}@{D}"), "error"),
            (format!("h.io@evil.com/a@{D}"), "error"),
            (" alpine\n".to_string(), "error"),
            ("a".repeat(258), "error"),
            ("a".repeat(255), "error"),
            (format!("quay.io/{}", "a".repeat(255)), "error"),
            (format!("{}.io/x", "a".repeat(252)), "error"),
            ("0123456789abcdef".repeat(4), "error"),
            (
                format!("a@sha384:{}", "ab".repeat(48)),
                "domain \"docker.io\" path \"library/a\" tag none digest sha384:<96 bytes>",
            ),
            (format!("a@foo:{}", "z".repeat(32)), "error"),
            (format!("a@sha256:{}", "A".repeat(64)), "error"),
            ("a@sha256:abc".to_string(), "error"),
            ("alpine@".to_string(), "error"),
            (
                format!("quay.io/a:v1@sha512:{}", "ab".repeat(64)),
                "domain \"quay.io\" path \"a\" tag \"v1\" digest sha512:<128 bytes>",
            ),
        ];
        for (input, expected) in &table {
            assert_eq!(shown(input), *expected, "{input:?}");
        }
    }

    /// An IPv6 host has one spelling: a scope written for `[::1]:5000` is
    /// not escaped by `[0::1]:5000`.
    #[test]
    fn an_ipv6_host_has_one_spelling() {
        assert_eq!(r("[::1]:5000/a:v1").string(), "[::1]:5000/a:v1");
        for other in ["[0::1]:5000/a:v1", "[0:0::1]:5000/a:v1", "[:]/a:v1"] {
            assert!(DockerRef::parse_normalized(other).is_err(), "{other}");
        }
        assert!(remap("[::1]:5000", "quay.io").validate().is_ok());
        assert!(remap("[0::1]:5000", "quay.io").validate().is_err());
    }

    /// A prefix `*.host` of `remapIdentity` is refused when the policy is
    /// read: `covers` never matches it, and the image would be judged as
    /// itself.
    #[test]
    fn a_wildcard_prefix_of_remap_identity_is_refused() {
        let rule = SignedIdentity::RemapIdentity {
            prefix: "*.example.com".into(),
            signed_prefix: "example.org".into(),
        };
        assert!(rule.validate().is_err());
    }
}
