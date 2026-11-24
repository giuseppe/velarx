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

const MAX_NAME: usize = 255;

fn path_component_ok(c: &str) -> bool {
    // [a-z0-9]+ separated by `.`, `_`, `__` or dashes
    let b = c.as_bytes();
    if b.is_empty() || !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        let ch = b[i];
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && matches!(b[i], b'.' | b'_' | b'-') {
            i += 1;
        }
        let sep = &c[start..i];
        // anything else (an upper case letter...) is no separator
        let ok = !sep.is_empty()
            && (sep == "." || sep == "_" || sep == "__" || sep.bytes().all(|x| x == b'-'));
        if !ok {
            return false;
        }
    }
    true
}

fn domain_ok(d: &str) -> bool {
    let (host, port) = if let Some(rest) = d.strip_prefix('[') {
        // [ipv6]:port
        match rest.split_once(']') {
            Some((ip, after)) => {
                if ip.parse::<std::net::Ipv6Addr>().is_err() {
                    return false;
                }
                match after.strip_prefix(':') {
                    Some(p) => ("x", Some(p)),
                    None if after.is_empty() => ("x", None),
                    None => return false,
                }
            }
            None => return false,
        }
    } else {
        match d.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (d, None),
        }
    };
    if let Some(p) = port {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn tag_ok(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 128
        && (t.as_bytes()[0].is_ascii_alphanumeric() || t.as_bytes()[0] == b'_')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn digest_ok(d: &str) -> bool {
    let Some((algo, hex)) = d.split_once(':') else {
        return false;
    };
    let algo_ok = !algo.is_empty()
        && algo.split(['+', '.', '_', '-']).all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    let hex_ok = hex.len() >= 32
        && hex
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b'_' | b'-'));
    let known = match algo {
        "sha256" => hex.len() == 64,
        "sha384" => hex.len() == 96,
        "sha512" => hex.len() == 128,
        _ => true,
    };
    algo_ok
        && hex_ok
        && known
        && (!matches!(algo, "sha256" | "sha384" | "sha512")
            || hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}

impl DockerRef {
    /// Parse and normalize `s` as `ParseNormalizedNamed` does.
    pub fn parse_normalized(s: &str) -> Result<Self, String> {
        let bad = || format!("invalid reference format: {s:?}");
        let (rest, digest) = match s.split_once('@') {
            Some((r, d)) => {
                if !digest_ok(d) {
                    return Err(bad());
                }
                (r, Some(d.to_string()))
            }
            None => (s, None),
        };
        let (name, tag) = match rest.rfind(':') {
            Some(i) if !rest[i + 1..].contains('/') => {
                let t = &rest[i + 1..];
                if !tag_ok(t) {
                    return Err(bad());
                }
                (&rest[..i], Some(t.to_string()))
            }
            _ => (rest, None),
        };
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_uppercase()) && !name.contains('/') {
            return Err(bad());
        }
        let (mut domain, mut path) = match name.split_once('/') {
            Some((first, remainder))
                if velarx_base::reference::is_registry_domain(first)
                    || first.bytes().any(|b| b.is_ascii_uppercase()) =>
            {
                (first.to_string(), remainder.to_string())
            }
            _ => ("docker.io".to_string(), name.to_string()),
        };
        if domain == "index.docker.io" {
            domain = "docker.io".into();
        }
        if domain == "docker.io" && !path.contains('/') {
            path = format!("library/{path}");
        }
        if !domain_ok(&domain)
            || !path.split('/').all(path_component_ok)
            || domain.len() + 1 + path.len() > MAX_NAME
        {
            return Err(bad());
        }
        // a 64 hex name alone is an image id, not a name
        if domain == "docker.io"
            && path.len() == 72
            && path.starts_with("library/")
            && path[8..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(bad());
        }
        Ok(Self {
            domain,
            path,
            tag,
            digest,
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
            // `*.host`, a host, or a host and a path, all normalized
            let name = p.strip_prefix("*.").unwrap_or(p);
            !name.is_empty()
                && (domain_ok(name) && !name.contains('/')
                    || DockerRef::parse_normalized(name)
                        .is_ok_and(|r| r.name() == name && r.name_only()))
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
        // a wildcard is never a prefix (`validate` accepts it): the image
        // is judged as it is
        let wild = remap("*.local", "quay.io");
        assert!(wild.validate().is_ok());
        assert!(wild.matches(&r("mirror.local/a:v1"), "mirror.local/a:v1"));
        assert!(!wild.matches(&r("mirror.local/a:v1"), "quay.io/a:v1"));
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
}
