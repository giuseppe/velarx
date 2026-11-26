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

use super::reference::DockerRef;
use super::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info};
use velarx_policy_core::select;

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

    /// The first of `paths` that is there (see [`crate::trust::is_there`]),
    /// else the built-in default.
    fn load_first(paths: &[std::path::PathBuf]) -> SignatureResult<Self> {
        for path in paths {
            if crate::trust::is_there(path).map_err(SignatureError::InvalidFormat)? {
                return Self::load(path);
            }
        }
        Ok(Self::default())
    }

    /// The policy requirements for an image, like containers/image: the
    /// scope of the image with its tag or digest, of the repository, of
    /// each parent namespace up to the registry, of the `*.domain`
    /// wildcards of the registry host (the port is not part of what they
    /// match), the default of the transport, and last the default.  Scopes
    /// are names, compared whole: `localhost` is not a scope of
    /// `localhost:5000/img`.  `reference` is normalized, so the scope sees
    /// the name that the identity of a signature is compared with.
    pub fn requirements_for(&self, transport: &str, reference: &DockerRef) -> &[PolicyRequirement] {
        self.scoped_requirements_for(transport, reference).1
    }

    /// The requirements for what a transport serves whole, with no name
    /// the scopes could match: the default of the transport, else the
    /// default.
    pub fn transport_requirements(&self, transport: &str) -> &[PolicyRequirement] {
        self.transports
            .get(transport)
            .and_then(|scopes| scopes.get(""))
            .unwrap_or(&self.default)
    }

    /// Like [`Self::requirements_for`], with the scope that applies, as a
    /// message names it.
    pub fn scoped_requirements_for(
        &self,
        transport: &str,
        reference: &DockerRef,
    ) -> (String, &[PolicyRequirement]) {
        let Some(scopes) = self.transports.get(transport) else {
            return ("the default".to_string(), &self.default);
        };
        let keys: Vec<&String> = scopes.keys().collect();
        let bytes: Vec<Vec<u8>> = keys.iter().map(|k| k.as_bytes().to_vec()).collect();
        if let Some(i) = select(&bytes, &reference.to_core()) {
            let scope = keys[i];
            debug!("Policy scope `{scope}` applies to {}", reference.name());
            let scope_name = match scope.is_empty() {
                true => format!("the default of the {transport} transport"),
                false => format!("scope {scope}"),
            };
            return (scope_name, &scopes[scope]);
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
            p.requirements_for("docker", &dref("quay.io/a/b:1")),
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

    const DEAD: &str = "sha256:deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead";
    const BEEF: &str = "sha256:beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef";

    fn dref(name: &str) -> DockerRef {
        DockerRef::parse_normalized(name).unwrap()
    }

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
        let reqs = policy.requirements_for("docker", &dref("registry.example.com/myimage"));
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
        let reqs = policy.requirements_for("docker", &dref("ghcr.io/myorg/myimage"));
        assert_eq!(reqs.len(), 1);
        assert!(matches!(reqs[0], PolicyRequirement::SigstoreSigned { .. }));
    }

    #[test]
    fn test_find_requirements_fallback() {
        let policy = SignaturePolicy::default();

        let reqs = policy.requirements_for("docker", &dref("unknown.registry.io/myimage"));
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
                policy.requirements_for("docker", &dref(&format!("{r}/{repo}"))),
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
                  "quay.io/org/img@sha256:deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead":[{"type":"reject"}],
                  "localhost":[{"type":"reject"}],
                  "*.evil.io":[{"type":"reject"}]}}}"#,
        )
        .unwrap();
        let rejected = |name: &str| {
            matches!(
                policy.requirements_for("docker", &dref(name)),
                [PolicyRequirement::Reject]
            )
        };
        assert!(rejected("quay.io/org/img:bad"));
        assert!(!rejected("quay.io/org/img:good"));
        assert!(rejected(&format!("quay.io/org/img@{DEAD}")));
        assert!(!rejected(&format!("quay.io/org/img@{BEEF}")));
        assert!(rejected("localhost/img"));
        assert!(!rejected("localhost:5000/img"));
        assert!(rejected("a.b.evil.io/img"));
        assert!(!rejected("evil.io/img"));
        assert!(!rejected("evil.io:443/img"));
    }

    /// The scope that applies to `name`, or `the default`.
    fn scope_of(policy: &SignaturePolicy, name: &str) -> String {
        policy.scoped_requirements_for("docker", &dref(name)).0
    }

    /// A policy with these scopes, each with a requirement.
    fn with_scopes(scopes: &[&str]) -> SignaturePolicy {
        let body: Vec<String> = scopes
            .iter()
            .map(|s| format!(r#""{s}": [{{"type": "reject"}}]"#))
            .collect();
        SignaturePolicy::parse(&format!(
            r#"{{"default": [{{"type": "insecureAcceptAnything"}}],
                "transports": {{"docker": {{{}}}}}}}"#,
            body.join(",")
        ))
        .unwrap()
    }

    #[test]
    fn a_transport_has_its_default_else_the_default() {
        let policy = SignaturePolicy::parse(
            r#"{"default": [{"type": "insecureAcceptAnything"}],
                "transports": {"s3": {"": [{"type": "reject"}], "a": [{"type": "reject"}]},
                               "gs": {"a": [{"type": "reject"}]}}}"#,
        )
        .unwrap();
        let rejects = |t: &str| {
            matches!(
                policy.transport_requirements(t),
                [PolicyRequirement::Reject]
            )
        };
        assert!(rejects("s3"));
        assert!(!rejects("gs"));
        assert!(!rejects("other"));
    }

    #[test]
    fn the_scopes_are_tried_from_the_most_specific() {
        let by_digest = format!("a.b.io/x/y/z@{DEAD}");
        let order = [
            by_digest.as_str(),
            "a.b.io/x/y/z",
            "a.b.io/x/y",
            "a.b.io/x",
            "a.b.io",
            "*.b.io",
            "*.io",
            "",
        ];
        for first in 0..order.len() {
            let policy = with_scopes(&order[first..]);
            let got = scope_of(&policy, &by_digest);
            let want = match order[first] {
                "" => "the default of the docker transport".to_string(),
                s => format!("scope {s}"),
            };
            assert_eq!(got, want, "without {:?}", &order[..first]);
        }
        // the tag in the place of the digest
        let policy = with_scopes(&["a.b.io/x/y/z:1", "a.b.io/x/y/z"]);
        assert_eq!(scope_of(&policy, "a.b.io/x/y/z:1"), "scope a.b.io/x/y/z:1");
        assert_eq!(scope_of(&policy, "a.b.io/x/y/z:2"), "scope a.b.io/x/y/z");
        // another transport, and no scope at all: the global default
        let policy = with_scopes(&["a.b.io"]);
        assert_eq!(
            policy.scoped_requirements_for("dir", &dref("a.b.io/x")).0,
            "the default"
        );
        assert_eq!(scope_of(&policy, "c.io/x"), "the default");
    }

    #[test]
    fn a_wildcard_scope_of_a_host_with_a_port() {
        let policy = with_scopes(&["*.corp.example"]);
        assert_eq!(
            scope_of(&policy, "reg.corp.example/x"),
            "scope *.corp.example"
        );
        assert_eq!(
            scope_of(&policy, "reg.corp.example:5000/x"),
            "scope *.corp.example"
        );
        // (a wildcard covers the strict subdomains: not `corp.example`)
        assert_eq!(scope_of(&policy, "corp.example:5000/x"), "the default");
        // a scope written with a port matches that host and port only
        let policy = with_scopes(&["reg.x:5000/ns"]);
        assert_eq!(scope_of(&policy, "reg.x:5000/ns/a"), "scope reg.x:5000/ns");
        assert_eq!(scope_of(&policy, "reg.x:5001/ns/a"), "the default");
    }

    #[test]
    fn a_scope_covers_whole_components_only() {
        let policy = with_scopes(&["x.io/ab"]);
        assert_eq!(scope_of(&policy, "x.io/a"), "the default");
        assert_eq!(scope_of(&policy, "x.io/ab/c"), "scope x.io/ab");
        assert_eq!(scope_of(&policy, "x.io/abc"), "the default");
        let policy = with_scopes(&["x.io/a"]);
        assert_eq!(scope_of(&policy, "x.io/ab"), "the default");
        assert_eq!(scope_of(&policy, "x.io/a/b"), "scope x.io/a");
        let policy = with_scopes(&["x.io"]);
        assert_eq!(scope_of(&policy, "x.io:5000/a"), "the default");
        assert_eq!(scope_of(&policy, "xx.io/a"), "the default");
    }

    #[test]
    fn a_host_is_compared_as_written() {
        // containers/image lowercases nothing either: a host in capitals
        // is no reference, it does not get the default scope
        let policy = with_scopes(&["quay.io/x"]);
        assert_eq!(scope_of(&policy, "quay.io/x/y"), "scope quay.io/x");
        assert!(DockerRef::parse_normalized("Quay.io/x/y").is_err());
    }

    #[test]
    fn a_policy_path_that_is_a_dangling_symlink_or_cannot_be_read() {
        let d = tempfile::tempdir().unwrap();
        let link = d.path().join("policy.json");
        std::os::unix::fs::symlink(d.path().join("nowhere"), &link).unwrap();
        assert!(SignaturePolicy::load_first(&[link]).is_err());
        // a directory in the place of the file cannot be read
        let dir = d.path().join("dir.json");
        std::fs::create_dir(&dir).unwrap();
        assert!(SignaturePolicy::load_first(&[dir]).is_err());
        // a path under a file cannot even be looked at
        let file = d.path().join("file");
        std::fs::write(&file, "").unwrap();
        assert!(SignaturePolicy::load_first(&[file.join("policy.json")]).is_err());
    }

    #[test]
    fn a_duplicated_key_of_the_policy() {
        // the last one wins, as the JSON parser does; containers/image
        // refuses such a file
        let policy = SignaturePolicy::parse(
            r#"{"default": [{"type": "reject"}], "default": [{"type": "insecureAcceptAnything"}]}"#,
        )
        .unwrap();
        assert!(matches!(
            policy.default[..],
            [PolicyRequirement::InsecureAcceptAnything]
        ));
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
