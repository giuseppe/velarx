// SPDX-License-Identifier: Apache-2.0
//! `image trust`: the entries of policy.json that podman's `image trust
//! set` writes for a scope, and the table `image trust show` makes of
//! the policy and registries.d.

use crate::registries_d::RegistriesD;
use crate::{PolicyRequirement, SignaturePolicy};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The trust a scope gets (`image trust set --type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustType {
    /// `insecureAcceptAnything` (podman's `accept`)
    Accept,
    Reject,
    /// `signedBy` with GPG public keys
    SignedBy,
    /// `sigstoreSigned` with PEM public keys
    SigstoreSigned,
}

impl TrustType {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "accept" | "insecureAcceptAnything" => Ok(Self::Accept),
            "reject" => Ok(Self::Reject),
            "signedBy" => Ok(Self::SignedBy),
            "sigstoreSigned" => Ok(Self::SigstoreSigned),
            _ => Err(format!(
                "invalid trust type {s:?}: it is accept, reject, signedBy or sigstoreSigned"
            )),
        }
    }
}

/// The policy files in the order the engine reads them: the user's
/// (rootless only), then the system's.
pub fn policy_paths() -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    if velarx_base::conf::rootless().map_err(|e| e.to_string())? {
        if let Some(dir) = velarx_base::conf::user_config_dir().map_err(|e| e.to_string())? {
            paths.push(dir.join("velarx/policy.json"));
        }
    }
    paths.push("/etc/velarx/policy.json".into());
    Ok(paths)
}

/// Whether the policy file `path` is there.  Only a path that does not
/// exist is not: one that cannot be looked at, or a file that is a symlink to
/// nothing, is an error, never "no policy".
pub fn is_there(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// The text of the policy in force (the first file there is, else the
/// built-in default that accepts every image) and where `set` writes: the
/// first of `policy_paths`, or `path`, which must be there unless `create`
/// (`set` starts a policy at a path that does not exist yet).
pub fn current(path: Option<&Path>, create: bool) -> Result<(String, PathBuf), String> {
    let read = |p: &Path| {
        velarx_base::conf::read_config_file(p, 4 << 20)
            .map_err(|e| format!("cannot read {}: {e}", p.display()))
    };
    if let Some(p) = path {
        let text = if create && !is_there(p)? {
            default_policy_text()
        } else {
            read(p)?
        };
        return Ok((text, p.to_path_buf()));
    }
    let paths = policy_paths()?;
    let target = paths.first().cloned().ok_or("no policy file")?;
    for p in &paths {
        if is_there(p)? {
            return Ok((read(p)?, target));
        }
    }
    Ok((default_policy_text(), target))
}

fn default_policy_text() -> String {
    serde_json::to_string_pretty(&json!({"default": [{"type": "insecureAcceptAnything"}]}))
        .unwrap_or_default()
}

fn absolute(p: &Path) -> Result<String, String> {
    let abs = std::path::absolute(p).map_err(|e| format!("{}: {e}", p.display()))?;
    abs.into_os_string()
        .into_string()
        .map_err(|_| format!("{}: the path is not UTF-8", p.display()))
}

/// The policy `policy` with the requirements of `kind` for `scope`
/// (`default` for the default of all), as podman's `trust set` writes it:
/// a scope that has entries in some transport keeps them there, a new
/// one goes to `docker`.
pub fn set_scope(
    policy: &str,
    scope: &str,
    kind: TrustType,
    key_files: &[PathBuf],
) -> Result<String, String> {
    if scope.is_empty() || scope.contains(char::is_whitespace) {
        return Err(format!("invalid scope {scope:?}"));
    }
    if kind != TrustType::SignedBy && kind != TrustType::SigstoreSigned && !key_files.is_empty() {
        return Err(
            "invalid options: public keys can only be used with signedBy or sigstoreSigned".into(),
        );
    }
    let requirements: Vec<Value> = match kind {
        TrustType::Accept => vec![json!({"type": "insecureAcceptAnything"})],
        TrustType::Reject => vec![json!({"type": "reject"})],
        TrustType::SignedBy | TrustType::SigstoreSigned => {
            if key_files.is_empty() {
                return Err(format!(
                    "at least one public key must be defined for type '{}'",
                    if kind == TrustType::SignedBy {
                        "signedBy"
                    } else {
                        "sigstoreSigned"
                    }
                ));
            }
            let mut out = Vec::new();
            for f in key_files {
                let data = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
                let path = absolute(f)?;
                if kind == TrustType::SignedBy {
                    crate::openpgp::parse_keyring(&data)
                        .map_err(|e| format!("{}: not a GPG public key: {e}", f.display()))?;
                    out.push(json!({"type": "signedBy", "keyType": "GPGKeys", "keyPath": path}));
                } else {
                    crate::sigstore::public_key_from_pem(&data)
                        .map_err(|e| format!("{}: {e}", f.display()))?;
                    out.push(json!({"type": "sigstoreSigned", "keyPath": path}));
                }
            }
            out
        }
    };
    let mut doc: Value = serde_json::from_str(policy).map_err(|e| format!("policy.json: {e}"))?;
    let root = doc.as_object_mut().ok_or("policy.json is not an object")?;
    if scope == "default" {
        root.insert("default".into(), Value::Array(requirements));
    } else {
        if root
            .get("default")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            return Err("default trust policy must be set".into());
        }
        let transports = root
            .entry("transports")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or("`transports` is not an object")?;
        let existing = transports
            .iter_mut()
            .find_map(|(_, scopes)| scopes.as_object_mut().filter(|s| s.contains_key(scope)));
        match existing {
            Some(scopes) => {
                scopes.insert(scope.into(), Value::Array(requirements));
            }
            None => {
                check_docker_scope(scope)?;
                transports
                    .entry("docker")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
                    .ok_or("`transports.docker` is not an object")?
                    .insert(scope.into(), Value::Array(requirements));
            }
        }
    }
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    // (what is written is a policy the engine reads)
    SignaturePolicy::parse(&text).map_err(|e| e.to_string())?;
    Ok(text + "\n")
}

/// Refuse a new docker scope that can match no image: a scope is compared
/// with the full normalized name of an image (`docker.io/library/alpine`).
fn check_docker_scope(scope: &str) -> Result<(), String> {
    let host = scope.split('/').next().unwrap_or(scope);
    if host == "index.docker.io" {
        return Err(format!(
            "invalid scope {scope:?}: the name of Docker Hub is docker.io, not index.docker.io"
        ));
    }
    if scope != "default" && !host.contains(['.', ':']) && host != "localhost" {
        return Err(format!(
            "invalid scope {scope:?}: it has no registry host; write docker.io/NAME, or docker.io/library/NAME for an official image of Docker Hub"
        ));
    }
    Ok(())
}

/// A row of `image trust show`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrustRow {
    pub transport: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub keytype: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub gpg_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sigstore: String,
}

fn row(
    transport: &str,
    name: &str,
    reqs: &[PolicyRequirement],
    registries: &RegistriesD,
) -> TrustRow {
    let mut row = TrustRow {
        transport: transport.into(),
        name: name.into(),
        keytype: String::new(),
        kind: String::new(),
        gpg_id: String::new(),
        sigstore: String::new(),
    };
    let mut ids: Vec<String> = Vec::new();
    for r in reqs {
        match r {
            PolicyRequirement::InsecureAcceptAnything => row.kind = "accept".into(),
            PolicyRequirement::Reject => row.kind = "reject".into(),
            PolicyRequirement::SignedBy {
                key_path,
                key_paths,
                ..
            } => {
                row.kind = "signed".into();
                row.keytype = "GPGKeys".into();
                for p in key_path.iter().chain(key_paths.iter().flatten()) {
                    match std::fs::read(p)
                        .ok()
                        .and_then(|d| crate::openpgp::parse_keyring(&d).ok())
                    {
                        Some(keys) if !keys.is_empty() => {
                            ids.extend(keys.into_iter().map(|k| k.fingerprint))
                        }
                        _ => ids.push(p.clone()),
                    }
                }
            }
            PolicyRequirement::SigstoreSigned {
                key_path,
                key_paths,
                ..
            } => {
                row.kind = "sigstoreSigned".into();
                row.keytype = "sigstore".into();
                ids.extend(key_path.iter().chain(key_paths.iter().flatten()).cloned());
            }
            PolicyRequirement::SignedBaseLayer { .. } => row.kind = "signedBaseLayer".into(),
        }
    }
    ids.dedup();
    row.gpg_id = ids.join(", ");
    if let Some(ns) = registries.docker.get(name) {
        row.sigstore = ns
            .sigstore
            .clone()
            .or_else(|| ns.lookaside.clone())
            .unwrap_or_default();
        if row.sigstore.is_empty() && ns.use_sigstore_attachments == Some(true) {
            row.sigstore = "(attachments)".into();
        }
    }
    row
}

/// The rows of the policy: its default, then its scopes by transport
/// and name.
pub fn show_rows(policy: &str, registries: &RegistriesD) -> Result<Vec<TrustRow>, String> {
    let policy = SignaturePolicy::parse(policy).map_err(|e| e.to_string())?;
    let mut rows = vec![row("all", "default", &policy.default, registries)];
    let mut transports: Vec<_> = policy.transports.iter().collect();
    transports.sort_by_key(|(t, _)| t.as_str());
    for (transport, scopes) in transports {
        let shown = if transport == "docker" {
            "repository"
        } else {
            transport.as_str()
        };
        let mut scopes: Vec<_> = scopes.iter().collect();
        scopes.sort_by_key(|(s, _)| s.as_str());
        for (scope, reqs) in scopes {
            rows.push(row(shown, scope, reqs, registries));
        }
    }
    Ok(rows)
}

/// The text of a registries.d file that has sigstore attachments looked
/// for and written for `scope`.
pub fn attachments_yaml(scope: &str) -> String {
    format!("docker:\n  {scope}:\n    use-sigstore-attachments: true\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"{"default":[{"type":"insecureAcceptAnything"}]}"#;

    #[test]
    fn a_scope_that_can_match_no_image_is_refused() {
        for scope in [
            "alpine",
            "library/alpine",
            "index.docker.io/library/alpine",
            "index.docker.io",
        ] {
            let e = set_scope(BASE, scope, TrustType::Reject, &[]).unwrap_err();
            assert!(e.contains("docker.io"), "{scope}: {e}");
        }
        for scope in [
            "docker.io/library",
            "docker.io/library/alpine",
            "docker.io/someorg",
            "docker.io",
            "reg.example:5000/ns",
            "localhost/ns",
            "localhost:5000",
            "*.example.com",
            "quay.io/org/img:tag",
        ] {
            set_scope(BASE, scope, TrustType::Reject, &[])
                .unwrap_or_else(|e| panic!("{scope}: {e}"));
        }
        set_scope(BASE, "default", TrustType::Reject, &[]).unwrap();
    }

    #[test]
    fn only_a_path_that_does_not_exist_is_no_policy() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(is_there(&d.path().join("none.json")), Ok(false));
        // (a link in a parent directory that leads nowhere: not there)
        std::os::unix::fs::symlink(d.path().join("nowhere"), d.path().join("dir")).unwrap();
        assert_eq!(is_there(&d.path().join("dir/policy.json")), Ok(false));
        std::fs::write(d.path().join("f"), BASE).unwrap();
        assert_eq!(is_there(&d.path().join("f")), Ok(true));
        // the file itself a link to nothing, or a path under a file
        std::os::unix::fs::symlink(d.path().join("nowhere"), d.path().join("link")).unwrap();
        assert_eq!(is_there(&d.path().join("link")), Ok(true));
        assert!(is_there(&d.path().join("f/policy.json")).is_err());
        // the policy shown or changed is read as the engine reads it
        // (`show` of a path that is not there is an error, as the engine's)
        assert!(current(Some(&d.path().join("none.json")), false).is_err());
        assert!(current(Some(&d.path().join("link")), false).is_err());
        assert_eq!(current(Some(&d.path().join("f")), false).unwrap().0, BASE);
        // `set` starts the file, but never writes through a link to nothing
        let (text, target) = current(Some(&d.path().join("none.json")), true).unwrap();
        assert_eq!(target, d.path().join("none.json"));
        assert_eq!(text, default_policy_text());
        assert!(current(Some(&d.path().join("link")), true).is_err());
        assert_eq!(current(Some(&d.path().join("f")), true).unwrap().0, BASE);
    }

    #[test]
    fn set_writes_the_entries_podman_writes() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k.pub");
        let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjRMvLZLP+3IgpEbDgdtuZjXJ7pLb\nQSGFaQFE7Zydj1mCzfDh04I5w3jAN/qNAPyq+1IDO890Q8MinNL9NNNEuQ==\n-----END PUBLIC KEY-----\n";
        std::fs::write(&key, pem).unwrap();
        let p = set_scope(BASE, "default", TrustType::Reject, &[]).unwrap();
        let v: Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["default"], json!([{"type": "reject"}]));
        let p = set_scope(
            &p,
            "quay.io/app",
            TrustType::SigstoreSigned,
            std::slice::from_ref(&key),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&p).unwrap();
        assert_eq!(
            v["transports"]["docker"]["quay.io/app"],
            json!([{"type": "sigstoreSigned", "keyPath": key.to_str().unwrap()}])
        );
        // a scope that exists is replaced where it is
        let p = set_scope(&p, "quay.io/app", TrustType::Accept, &[]).unwrap();
        let v: Value = serde_json::from_str(&p).unwrap();
        assert_eq!(
            v["transports"]["docker"]["quay.io/app"],
            json!([{"type": "insecureAcceptAnything"}])
        );
        let rows = show_rows(&p, &RegistriesD::default()).unwrap();
        assert_eq!(rows[0].kind, "reject");
        assert_eq!(
            (rows[1].transport.as_str(), rows[1].name.as_str()),
            ("repository", "quay.io/app")
        );
        assert_eq!(rows[1].kind, "accept");
    }

    #[test]
    fn set_refuses_what_podman_refuses() {
        let e = set_scope(BASE, "quay.io", TrustType::SignedBy, &[]).unwrap_err();
        assert!(e.contains("at least one public key"), "{e}");
        let e = set_scope(BASE, "quay.io", TrustType::Accept, &[PathBuf::from("/k")]).unwrap_err();
        assert!(e.contains("public keys can only be used"), "{e}");
        let e = set_scope("{}", "quay.io", TrustType::Reject, &[]).unwrap_err();
        assert!(e.contains("default trust policy must be set"), "{e}");
        assert!(TrustType::parse("bogus").is_err());
        let e = set_scope(
            BASE,
            "quay.io",
            TrustType::SigstoreSigned,
            &[PathBuf::from("/no/such")],
        )
        .unwrap_err();
        assert!(e.contains("/no/such"), "{e}");
    }
}
