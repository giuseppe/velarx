// SPDX-License-Identifier: Apache-2.0
//! Signature Policy Parser
//!
//! Parses and evaluates container signature policies compatible with
//! The policy.json format of podman, buildah, etc. (velarx's file is
//! /etc/velarx/policy.json).
//!
//! Policy format:
//! {
//!   "default": [{"type": "insecureAcceptAnything"}],
//!   "transports": {
//!     "docker": {
//!       "docker.io": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/path/to/key.gpg"}],
//!       "registry.example.com": [{"type": "reject"}]
//!     }
//!   }
//! }

use super::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info};

/// Largest policy.json read.
const MAX_POLICY_SIZE: u64 = 4 << 20;

/// Container signature policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignaturePolicy {
    /// Default policy for images not matched by specific rules
    pub default: Vec<PolicyRequirement>,
    /// Transport-specific policies
    #[serde(default)]
    pub transports: HashMap<String, HashMap<String, Vec<PolicyRequirement>>>,
}

impl Default for SignaturePolicy {
    fn default() -> Self {
        // Default policy accepts everything (insecure, but matches podman default)
        Self {
            default: vec![PolicyRequirement::InsecureAcceptAnything],
            transports: HashMap::new(),
        }
    }
}

/// Policy requirement types, as containers/image has them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
pub enum PolicyRequirement {
    /// Accept any image without verification
    InsecureAcceptAnything,
    /// Reject all images
    Reject,
    /// A simple signing (OpenPGP) signature by one of the keys.
    SignedBy {
        #[serde(rename = "keyType")]
        key_type: KeyType,
        #[serde(rename = "keyPath", default)]
        key_path: Option<String>,
        #[serde(rename = "keyPaths", default)]
        key_paths: Option<Vec<String>>,
        /// base64 of the keyring
        #[serde(rename = "keyData", default)]
        key_data: Option<String>,
        #[serde(rename = "signedIdentity", default)]
        signed_identity: Option<SignedIdentity>,
    },
    /// A sigstore signature by a public key, a Fulcio certificate or the
    /// certificate of a PKI.
    SigstoreSigned {
        #[serde(rename = "keyPath", default)]
        key_path: Option<String>,
        #[serde(rename = "keyPaths", default)]
        key_paths: Option<Vec<String>>,
        /// base64 of a PEM public key
        #[serde(rename = "keyData", default)]
        key_data: Option<String>,
        #[serde(rename = "keyDatas", default)]
        key_datas: Option<Vec<String>>,
        #[serde(default)]
        fulcio: Option<Box<FulcioConfig>>,
        #[serde(rename = "rekorPublicKeyPath", default)]
        rekor_public_key_path: Option<String>,
        #[serde(rename = "rekorPublicKeyPaths", default)]
        rekor_public_key_paths: Option<Vec<String>>,
        #[serde(rename = "rekorPublicKeyData", default)]
        rekor_public_key_data: Option<String>,
        #[serde(rename = "rekorPublicKeyDatas", default)]
        rekor_public_key_datas: Option<Vec<String>>,
        #[serde(default)]
        pki: Option<Box<PkiConfig>>,
        #[serde(rename = "signedIdentity", default)]
        signed_identity: Option<SignedIdentity>,
    },
    /// Not implemented by containers/image either: refuses every image.
    SignedBaseLayer {
        #[serde(rename = "baseLayerIdentity", default)]
        base_layer_identity: Option<serde_json::Value>,
    },
}

/// Key types for signedBy requirements: only `GPGKeys` is implemented, as
/// in containers/image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    #[serde(rename = "GPGKeys")]
    GpgKeys,
    #[serde(rename = "signedByGPGKeys")]
    SignedByGpgKeys,
    #[serde(rename = "X509Certificates")]
    X509Certificates,
    #[serde(rename = "signedByX509CAs")]
    SignedByX509Cas,
}

/// Fulcio (OIDC-based certificate authority) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FulcioConfig {
    pub ca_path: Option<String>,
    /// base64 of the PEM certificates
    pub ca_data: Option<String>,
    pub oidc_issuer: Option<String>,
    pub subject_email: Option<String>,
}

/// A private PKI of sigstore signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PkiConfig {
    pub ca_roots_path: Option<String>,
    pub ca_roots_data: Option<String>,
    pub ca_intermediates_path: Option<String>,
    pub ca_intermediates_data: Option<String>,
    pub subject_email: Option<String>,
    pub subject_hostname: Option<String>,
}

pub use super::reference::SignedIdentity;

impl SignaturePolicy {
    /// Load policy from file
    pub fn load<P: AsRef<Path>>(path: P) -> SignatureResult<Self> {
        let path = path.as_ref();
        // a policy that is not there is an error, never "accept anything"
        let content = velarx_base::conf::read_config_file(path, MAX_POLICY_SIZE).map_err(|e| {
            SignatureError::InvalidFormat(format!("cannot read {}: {e}", path.display()))
        })?;
        let policy = Self::parse(&content)?;
        info!("Loaded signature policy from {}", path.display());
        Ok(policy)
    }

    /// Parse a policy.json: `default` is required, and every list of
    /// requirements must have one at least.
    pub fn parse(content: &str) -> SignatureResult<Self> {
        let raw: serde_json::Value = serde_json::from_str(content)?;
        // the requirements without fields: serde does not refuse unknown
        // fields there (it does for the others)
        let lists = raw
            .get("default")
            .into_iter()
            .chain(
                raw.get("transports")
                    .and_then(|t| t.as_object())
                    .into_iter()
                    .flat_map(|t| t.values())
                    .filter_map(|scopes| scopes.as_object())
                    .flat_map(|scopes| scopes.values()),
            )
            .filter_map(|l| l.as_array())
            .flatten();
        for r in lists {
            let kind = r.get("type").and_then(|t| t.as_str());
            let fields = r.as_object().map_or(0, |o| o.len());
            if matches!(kind, Some("insecureAcceptAnything" | "reject")) && fields != 1 {
                return Err(SignatureError::InvalidFormat(format!(
                    "unknown fields in a {} requirement",
                    kind.unwrap_or_default()
                )));
            }
            if let Some(identity) = r.get("signedIdentity") {
                let kind = identity.get("type").and_then(|t| t.as_str());
                let fields = identity.as_object().map_or(0, |o| o.len());
                let plain = matches!(
                    kind,
                    Some("matchExact" | "matchRepoDigestOrExact" | "matchRepository")
                );
                if plain && fields != 1 {
                    return Err(SignatureError::InvalidFormat(format!(
                        "unknown fields in a {} identity",
                        kind.unwrap_or_default()
                    )));
                }
            }
        }
        let policy: SignaturePolicy = serde_json::from_value(raw)?;
        if policy.default.is_empty() {
            return Err(SignatureError::InvalidFormat(
                "`default` must be a non empty list of requirements".into(),
            ));
        }
        for (transport, scopes) in &policy.transports {
            for (scope, reqs) in scopes {
                if reqs.is_empty() {
                    return Err(SignatureError::InvalidFormat(format!(
                        "`{transport}:{scope}` must be a non empty list of requirements"
                    )));
                }
            }
        }
        // the identity rules are checked once, here, as containers/image
        // does when it reads the policy
        let all = policy.default.iter().chain(
            policy
                .transports
                .values()
                .flat_map(|s| s.values().flatten()),
        );
        for r in all {
            let identity = match r {
                PolicyRequirement::SignedBy {
                    signed_identity, ..
                }
                | PolicyRequirement::SigstoreSigned {
                    signed_identity, ..
                } => signed_identity.as_ref(),
                _ => None,
            };
            if let Some(i) = identity {
                i.validate().map_err(SignatureError::InvalidFormat)?;
            }
        }
        Ok(policy)
    }

    /// Load from default locations: the user's policy.json only for a
    /// rootless process (a root daemon does not obey the policy of
    /// whatever $HOME it was started with), then the system's.  Without
    /// any of the files the built-in default applies, which accepts
    /// every image (what containers-common ships); a file that exists
    /// and is invalid is an error.
    pub fn load_default() -> SignatureResult<Self> {
        let paths = crate::trust::policy_paths().map_err(SignatureError::InvalidFormat)?;
        Self::load_first(&paths)
    }

    /// The first of `paths` that exists, else the built-in default.
    fn load_first(paths: &[std::path::PathBuf]) -> SignatureResult<Self> {
        match paths.iter().find(|p| p.exists()) {
            Some(p) => Self::load(p),
            None => Ok(Self::default()),
        }
    }

    /// The policy requirements for an image, like containers/image: the
    /// scope of the image with its tag or digest, of the repository, of
    /// each parent namespace up to the registry, of the `*.domain`
    /// wildcards of the registry host (without a port), the default of
    /// the transport, and last the default.  Scopes are names, compared
    /// whole: `localhost` is not a scope of `localhost:5000/img`.
    pub fn requirements_for(
        &self,
        transport: &str,
        registry: &str,
        repository: &str,
        tag: Option<&str>,
        digest: Option<&str>,
    ) -> &[PolicyRequirement] {
        self.scoped_requirements_for(transport, registry, repository, tag, digest)
            .1
    }

    /// Like [`Self::requirements_for`], with the scope that applies, as a
    /// message names it.
    pub fn scoped_requirements_for(
        &self,
        transport: &str,
        registry: &str,
        repository: &str,
        tag: Option<&str>,
        digest: Option<&str>,
    ) -> (String, &[PolicyRequirement]) {
        let Some(scopes) = self.transports.get(transport) else {
            return ("the default".to_string(), &self.default);
        };
        let name = format!("{registry}/{repository}");
        let full = match (digest, tag) {
            (Some(d), _) => Some(format!("{name}@{d}")),
            (None, Some(t)) => Some(format!("{name}:{t}")),
            _ => None,
        };
        let mut candidates: Vec<String> = full.into_iter().collect();
        let mut n = name.as_str();
        loop {
            candidates.push(n.to_string());
            match n.rsplit_once('/') {
                Some((parent, _)) => n = parent,
                None => break,
            }
        }
        if !registry.contains(':') {
            candidates.extend(
                registry
                    .match_indices('.')
                    .map(|(i, _)| format!("*{}", &registry[i..])),
            );
        }
        candidates.push(String::new());
        for scope in candidates {
            if let Some(reqs) = scopes.get(&scope) {
                debug!("Policy scope `{scope}` applies to {name}");
                let scope = match scope.is_empty() {
                    true => format!("the default of the {transport} transport"),
                    false => format!("scope {scope}"),
                };
                return (scope, reqs);
            }
        }
        ("the default".to_string(), &self.default)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unknown_fields_and_bad_identities_refuse_the_policy() {
        for json in [
            // a typo would drop the Rekor requirement
            r#"{"default": [{"type": "sigstoreSigned", "keyPath": "/k", "rekorPublicKeyPth": "/r"}]}"#,
            r#"{"default": [{"type": "reject", "extra": 1}]}"#,
            r#"{"default": [{"type": "sigstoreSigned", "fulcio": {"caPath": "/c", "oidcIssuer": "i", "subjectEmail": "e", "x": 1}}]}"#,
            r#"{"default": [{"type": "insecureAcceptAnything"}], "other": {}}"#,
            r#"{"default": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/k",
                "signedIdentity": {"type": "remapIdentity", "prefix": "Not A Prefix", "signedPrefix": "quay.io"}}]}"#,
            r#"{"default": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/k",
                "signedIdentity": {"type": "exactReference", "dockerReference": "busybox"}}]}"#,
            r#"{"default": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/k",
                "signedIdentity": {"type": "matchExact", "extra": 1}}]}"#,
        ] {
            assert!(SignaturePolicy::parse(json).is_err(), "{json}");
        }
        SignaturePolicy::parse(
            r#"{"default": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/k",
                "signedIdentity": {"type": "remapIdentity", "prefix": "mirror.local/quay", "signedPrefix": "quay.io"}}]}"#,
        )
        .unwrap();
    }

    #[test]
    fn no_policy_file_means_accept_everything() {
        let d = tempfile::tempdir().unwrap();
        let p = SignaturePolicy::load_first(&[d.path().join("a.json"), d.path().join("b.json")])
            .unwrap();
        assert!(matches!(
            p.requirements_for("docker", "quay.io", "a/b", Some("1"), None),
            [PolicyRequirement::InsecureAcceptAnything]
        ));
    }

    #[test]
    fn an_invalid_policy_file_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("policy.json");
        std::fs::write(&f, "{").unwrap();
        assert!(SignaturePolicy::load_first(&[d.path().join("none.json"), f]).is_err());
    }

    #[test]
    fn a_policy_that_is_not_there_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        assert!(SignaturePolicy::load(d.path().join("policy.json")).is_err());
    }

    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = SignaturePolicy::default();
        assert_eq!(policy.default.len(), 1);
        assert!(matches!(
            policy.default[0],
            PolicyRequirement::InsecureAcceptAnything
        ));
    }

    #[test]
    fn test_parse_simple_policy() {
        let json = r#"{
            "default": [{"type": "insecureAcceptAnything"}],
            "transports": {
                "docker": {
                    "docker.io": [{"type": "reject"}]
                }
            }
        }"#;

        let policy: SignaturePolicy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.default.len(), 1);
        assert!(policy.transports.contains_key("docker"));
    }

    #[test]
    fn test_parse_signed_by_policy() {
        let json = r#"{
            "default": [{"type": "reject"}],
            "transports": {
                "docker": {
                    "registry.example.com": [{
                        "type": "signedBy",
                        "keyType": "GPGKeys",
                        "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY"
                    }]
                }
            }
        }"#;

        let policy: SignaturePolicy = serde_json::from_str(json).unwrap();
        let reqs = policy.requirements_for("docker", "registry.example.com", "myimage", None, None);
        assert_eq!(reqs.len(), 1);
        assert!(matches!(reqs[0], PolicyRequirement::SignedBy { .. }));
    }

    #[test]
    fn test_parse_sigstore_policy() {
        let json = r#"{
            "default": [{"type": "insecureAcceptAnything"}],
            "transports": {
                "docker": {
                    "ghcr.io": [{
                        "type": "sigstoreSigned",
                        "fulcio": {
                            "oidcIssuer": "https://github.com/login/oauth",
                            "subjectEmail": "ci@example.com"
                        }
                    }]
                }
            }
        }"#;

        let policy: SignaturePolicy = serde_json::from_str(json).unwrap();
        let reqs = policy.requirements_for("docker", "ghcr.io", "myorg/myimage", None, None);
        assert_eq!(reqs.len(), 1);
        assert!(matches!(reqs[0], PolicyRequirement::SigstoreSigned { .. }));
    }

    #[test]
    fn test_find_requirements_fallback() {
        let policy = SignaturePolicy::default();

        let reqs = policy.requirements_for("docker", "unknown.registry.io", "myimage", None, None);
        assert_eq!(reqs.len(), 1);
        assert!(matches!(reqs[0], PolicyRequirement::InsecureAcceptAnything));
    }

    #[test]
    fn test_scope_lookup_uses_the_most_specific_scope() {
        let policy: SignaturePolicy = serde_json::from_str(
            r#"{"default":[{"type":"reject"}],
                "transports":{"docker":{
                  "docker.io":[{"type":"reject"}],
                  "docker.io/library":[{"type":"insecureAcceptAnything"}],
                  "*.example.com":[{"type":"insecureAcceptAnything"}],
                  "localhost:5000":[{"type":"insecureAcceptAnything"}]}}}"#,
        )
        .unwrap();
        let ok = |r: &str, repo: &str| {
            matches!(
                policy.requirements_for("docker", r, repo, None, None),
                [PolicyRequirement::InsecureAcceptAnything]
            )
        };
        assert!(ok("docker.io", "library/alpine"));
        assert!(!ok("docker.io", "someone/alpine"));
        assert!(ok("a.example.com", "x/y"));
        assert!(!ok("example.com", "x/y"));
        assert!(ok("localhost:5000", "x"));
        assert!(!ok("localhost:50001", "x"));
        assert!(!ok("quay.io", "x"));
    }

    #[test]
    fn test_scopes_of_tags_digests_and_names() {
        let policy = SignaturePolicy::parse(
            r#"{"default":[{"type":"insecureAcceptAnything"}],
                "transports":{"docker":{
                  "quay.io/org/img:bad":[{"type":"reject"}],
                  "quay.io/org/img@sha256:dead":[{"type":"reject"}],
                  "localhost":[{"type":"reject"}],
                  "*.evil.io":[{"type":"reject"}]}}}"#,
        )
        .unwrap();
        let rejected = |r: &str, repo: &str, tag: Option<&str>, digest: Option<&str>| {
            matches!(
                policy.requirements_for("docker", r, repo, tag, digest),
                [PolicyRequirement::Reject]
            )
        };
        assert!(rejected("quay.io", "org/img", Some("bad"), None));
        assert!(!rejected("quay.io", "org/img", Some("good"), None));
        assert!(rejected("quay.io", "org/img", None, Some("sha256:dead")));
        assert!(!rejected("quay.io", "org/img", None, Some("sha256:beef")));
        assert!(rejected("localhost", "img", None, None));
        assert!(!rejected("localhost:5000", "img", None, None));
        assert!(rejected("a.b.evil.io", "img", None, None));
        assert!(!rejected("evil.io", "img", None, None));
        assert!(!rejected("evil.io:443", "img", None, None));
    }

    #[test]
    fn test_invalid_policies() {
        for bad in [
            r#"{}"#,
            r#"{"default": []}"#,
            r#"{"default": [{"type": "maybe"}]}"#,
            r#"{"default": [{"type": "reject"}], "transports": {"docker": {"a.io": []}}}"#,
        ] {
            assert!(SignaturePolicy::parse(bad).is_err(), "{bad}");
        }
    }
}
