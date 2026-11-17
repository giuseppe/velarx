// SPDX-License-Identifier: Apache-2.0
//! Docker references as the identity rules of signatures compare them:
//! normalized like `docker/reference.ParseNormalizedNamed` (the
//! default registry, `library/`), with or without a tag or a digest, and
//! the `signedIdentity` rules of policy.json.

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
}

/// `matchRepoDigestOrExact`: the same reference when the image is asked
/// by tag, the same repository when it is asked by digest.
fn repo_digest_or_exact(intended: &DockerRef, signed: &DockerRef) -> bool {
    if signed.name_only() {
        return false;
    }
    if intended.tag.is_some() {
        signed.string() == intended.string()
    } else if intended.digest.is_some() {
        signed.name() == intended.name()
    } else {
        false
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

/// Whether `name` starts with `prefix` as a whole host or path component.
fn has_prefix(name: &str, prefix: &str) -> bool {
    name == prefix || (name.starts_with(prefix) && name.as_bytes().get(prefix.len()) == Some(&b'/'))
}

impl SignedIdentity {
    /// Whether a signature for `signed` is a signature for the image the
    /// user asked as `intended`.
    pub fn matches(&self, intended: &DockerRef, signed: &str) -> bool {
        let Ok(signed) = DockerRef::parse_normalized(signed) else {
            return false;
        };
        match self {
            SignedIdentity::MatchExact => {
                !intended.name_only() && !signed.name_only() && signed.string() == intended.string()
            }
            SignedIdentity::MatchRepoDigestOrExact => repo_digest_or_exact(intended, &signed),
            SignedIdentity::MatchRepository => signed.name() == intended.name(),
            SignedIdentity::ExactReference { docker_reference } => {
                match DockerRef::parse_normalized(docker_reference) {
                    Ok(r) => !r.name_only() && !signed.name_only() && signed.string() == r.string(),
                    Err(_) => false,
                }
            }
            SignedIdentity::ExactRepository { docker_repository } => {
                match DockerRef::parse_normalized(docker_repository) {
                    Ok(r) => signed.name() == r.name(),
                    Err(_) => false,
                }
            }
            SignedIdentity::RemapIdentity {
                prefix,
                signed_prefix,
            } => {
                let mut intended = intended.clone();
                if has_prefix(&intended.name(), prefix) {
                    let s = intended
                        .string()
                        .replacen(prefix.as_str(), signed_prefix, 1);
                    // the result must be a reference as it is, not one that
                    // normalization changes
                    match DockerRef::parse_normalized(&s) {
                        Ok(r) if r.string() == s => intended = r,
                        _ => return false,
                    }
                }
                repo_digest_or_exact(&intended, &signed)
            }
        }
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
}
