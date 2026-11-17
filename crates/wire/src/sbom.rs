// SPDX-License-Identifier: Apache-2.0
//! The SBOM options of a build (`--sbom` and the options that go with it),
//! read as buildah reads them: a scanner image, the commands it runs on the
//! root of the built image and on the build context, the strategy that
//! merges what the commands write, and the places the result goes to.

use serde_json::Value;

pub use velarx_proto::buildspec::SbomFlags;

/// How the output of several commands is made one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Merge {
    Cat,
    CycloneDx,
    Spdx,
}

/// The scan a build makes: the image, and the commands as words (with the
/// placeholders `{ROOTFS}`, `{CONTEXT}` and `{OUTPUT}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub image: String,
    pub commands: Vec<Vec<String>>,
    pub merge: Merge,
}

const SYFT: &str = "ghcr.io/anchore/syft";
const TRIVY: &str = "ghcr.io/aquasecurity/trivy";

fn preset(name: &str) -> Option<(&'static str, Vec<String>, Merge)> {
    let syft = |format: &str| {
        ["{ROOTFS}", "{CONTEXT}"]
            .iter()
            .map(|dir| format!("/syft scan -q dir:{dir} --output {format}-json={{OUTPUT}}"))
            .collect()
    };
    let trivy = |format: &str| {
        ["{ROOTFS}", "{CONTEXT}"]
            .iter()
            .map(|dir| format!("trivy filesystem -q {dir} --format {format} --output {{OUTPUT}}"))
            .collect()
    };
    Some(match name {
        "" | "syft" | "syft-cyclonedx" => (SYFT, syft("cyclonedx"), Merge::CycloneDx),
        "syft-spdx" => (SYFT, syft("spdx"), Merge::Spdx),
        "trivy" | "trivy-cyclonedx" => (TRIVY, trivy("cyclonedx"), Merge::CycloneDx),
        "trivy-spdx" => (TRIVY, trivy("spdx-json"), Merge::Spdx),
        _ => return None,
    })
}

/// The words of a scanner command: run by `/bin/sh -c` when it redirects
/// or pipes (or cannot be split), as buildah does.
fn command_words(command: &str) -> Vec<String> {
    if !command.contains(['<', '>', '|']) {
        if let Ok(words) = crate::parse::split_quoted(command) {
            return words;
        }
    }
    vec!["/bin/sh".into(), "-c".into(), command.into()]
}

/// The scan the SBOM options of a build ask for.
pub trait SbomResolve {
    /// The scan the options ask for, none when none is asked; as buildah:
    /// the preset (syft by default) unless a scanner image, command or
    /// merge strategy is given, which then make the whole scan.
    fn resolve(&self) -> Result<Option<Scan>, String>;
}

impl SbomResolve for SbomFlags {
    fn resolve(&self) -> Result<Option<Scan>, String> {
        if !self.given() {
            return Ok(None);
        }
        let name = self.preset.as_deref().unwrap_or_default();
        let preset = preset(name)
            .ok_or_else(|| format!("parsing --sbom flag: unrecognized preset name {name:?}"))?;
        let (image, commands, merge) = if self.scanner_image.is_some()
            || !self.scanner_commands.is_empty()
            || self.merge_strategy.is_some()
        {
            let merge = match self.merge_strategy.as_deref() {
                Some("cat") => Some(Merge::Cat),
                Some("merge-cyclonedx-by-component-name-and-version") => Some(Merge::CycloneDx),
                Some("merge-spdx-by-package-name-and-versioninfo") => Some(Merge::Spdx),
                _ => None,
            };
            (
                self.scanner_image.clone().unwrap_or_default(),
                self.scanner_commands.clone(),
                merge,
            )
        } else {
            (preset.0.to_string(), preset.1, Some(preset.2))
        };
        if image.is_empty() || commands.is_empty() {
            return Err("sbom configuration missing one or more of (\"--sbom-scanner-image\" or \"--sbom-scanner-command\")".into());
        }
        if self.output.is_none()
            && self.purl_output.is_none()
            && self.image_output.is_none()
            && self.image_purl_output.is_none()
        {
            return Err("sbom configuration missing one or more of (\"--sbom-output\", \"--sbom-image-output\", \"--sbom-purl-output\" or \"--sbom-image-purl-output\")".into());
        }
        if commands.len() > 1 && self.merge_strategy.is_none() && merge.is_none() {
            return Err("sbom configuration included multiple \"--sbom-scanner-command\" values but no \"--sbom-merge-strategy\" value".into());
        }
        let merge = merge.ok_or_else(|| {
            format!(
                "sbom arguments included unrecognized merge strategy {:?}",
                self.merge_strategy.as_deref().unwrap_or_default()
            )
        })?;
        Ok(Some(Scan {
            image,
            commands: commands.iter().map(|c| command_words(c)).collect(),
            merge,
        }))
    }
}

/// The key of a record of the list a strategy merges, and its package
/// URL, as buildah reads them: `name@version` (`versionInfo` for SPDX).
fn record_key(strategy: Merge, record: &Value) -> Result<(String, Option<String>), String> {
    let o = record
        .as_object()
        .ok_or_else(|| format!("the SBOM record {record} is not an object"))?;
    let string = |field: &str| -> Result<Option<String>, String> {
        match o.get(field) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(v) => Err(format!("the SBOM field {field} {v} is not a string")),
        }
    };
    let name = string("name")?.ok_or_else(|| format!("no name in the SBOM record {record}"))?;
    let version = string(match strategy {
        Merge::Spdx => "versionInfo",
        _ => "version",
    })?
    .unwrap_or_default();
    let key = if version.is_empty() {
        name
    } else {
        format!("{name}@{version}")
    };
    let purl = match strategy {
        Merge::Spdx => {
            let mut purl = None;
            for r in o
                .get("externalRefs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if r["referenceCategory"] == "PACKAGE-MANAGER" && r["referenceType"] == "purl" {
                    match r.get("referenceLocator") {
                        None => {}
                        Some(Value::String(s)) => purl = Some(s.clone()),
                        Some(v) => return Err(format!("the SBOM purl {v} is not a string")),
                    }
                }
            }
            purl
        }
        _ => string("purl")?,
    };
    Ok((key, purl))
}

/// Add the records of the list `field` of `other` that `base` lacks (by
/// `key`) to `base`.
fn merge_list(
    base: &mut Value,
    other: &Value,
    field: &str,
    key: &mut dyn FnMut(&Value) -> Result<String, String>,
) -> Result<(), String> {
    let mut list = base[field].as_array().cloned().unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    for r in &list {
        seen.insert(key(r)?);
    }
    for r in other[field].as_array().into_iter().flatten() {
        if seen.insert(key(r)?) {
            list.push(r.clone());
        }
    }
    if !list.is_empty() {
        base[field] = Value::Array(list);
    }
    Ok(())
}

/// Merge the documents the commands wrote, in order, as buildah does: the
/// document, and the document of its package URLs (sorted).
pub fn merge(strategy: Merge, docs: &[Vec<u8>]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut purls = std::collections::BTreeSet::new();
    let document = match strategy {
        Merge::Cat => docs.concat(),
        Merge::CycloneDx | Merge::Spdx => {
            let field = if strategy == Merge::Spdx {
                "packages"
            } else {
                "components"
            };
            let mut merged: Option<Value> = None;
            for doc in docs {
                let value: Value = serde_json::from_slice(doc)
                    .map_err(|e| format!("the SBOM is not a JSON document: {e}"))?;
                // (the first document is merged with itself)
                let base = merged.get_or_insert_with(|| value.clone());
                merge_list(base, &value, field, &mut |r| {
                    let (key, purl) = record_key(strategy, r)?;
                    purls.extend(purl.filter(|p| !p.is_empty()));
                    Ok(key)
                })?;
                if strategy == Merge::Spdx {
                    merge_list(base, &value, "hasExtractedLicensingInfos", &mut |r| match r
                        .get("licenseId")
                    {
                        _ if !r.is_object() => Ok(String::new()),
                        Some(Value::String(id)) => Ok(id.clone()),
                        _ => Err(format!("no licenseId in the SBOM license {r}")),
                    })?;
                }
            }
            let merged = merged.ok_or("no SBOM was made")?;
            let mut out = serde_json::to_vec(&merged).map_err(|e| e.to_string())?;
            out.push(b'\n');
            out
        }
    };
    let mut contents = serde_json::Map::new();
    if !purls.is_empty() {
        contents.insert("dependencies".into(), purls.into_iter().collect());
    }
    let mut purl_document = serde_json::to_vec(&serde_json::json!({ "image_contents": contents }))
        .map_err(|e| e.to_string())?;
    purl_document.push(b'\n');
    Ok((document, purl_document))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags() -> SbomFlags {
        SbomFlags {
            output: Some("/tmp/sbom".into()),
            ..Default::default()
        }
    }

    #[test]
    fn presets_and_explicit_options_as_buildah() {
        assert_eq!(SbomFlags::default().resolve(), Ok(None));
        // (an output alone: syft's preset)
        let scan = flags().resolve().unwrap().unwrap();
        assert_eq!(scan.image, "ghcr.io/anchore/syft");
        assert_eq!(scan.merge, Merge::CycloneDx);
        let scan = SbomFlags {
            preset: Some("syft-spdx".into()),
            ..flags()
        }
        .resolve()
        .unwrap()
        .unwrap();
        assert_eq!(scan.merge, Merge::Spdx);
        assert_eq!(scan.commands.len(), 2);
        assert_eq!(
            scan.commands[0],
            [
                "/syft",
                "scan",
                "-q",
                "dir:{ROOTFS}",
                "--output",
                "spdx-json={OUTPUT}"
            ]
        );
        // an image, command or strategy replaces the preset
        let scan = SbomFlags {
            preset: Some("trivy".into()),
            scanner_image: Some("mine".into()),
            scanner_commands: vec!["scan 'a b' {OUTPUT}".into(), "x {ROOTFS} | y".into()],
            merge_strategy: Some("cat".into()),
            ..flags()
        }
        .resolve()
        .unwrap()
        .unwrap();
        assert_eq!(scan.image, "mine");
        assert_eq!(scan.commands[0], ["scan", "a b", "{OUTPUT}"]);
        assert_eq!(scan.commands[1], ["/bin/sh", "-c", "x {ROOTFS} | y"]);
        assert_eq!(scan.merge, Merge::Cat);
        for bad in [
            SbomFlags {
                preset: Some("syft".into()),
                ..Default::default()
            },
            SbomFlags {
                preset: Some("nope".into()),
                ..flags()
            },
            SbomFlags {
                preset: Some("trivy".into()),
                scanner_image: Some("x".into()),
                ..flags()
            },
            SbomFlags {
                scanner_commands: vec!["x".into()],
                ..flags()
            },
            // (one command needs a strategy too)
            SbomFlags {
                scanner_image: Some("x".into()),
                scanner_commands: vec!["x".into()],
                ..flags()
            },
            SbomFlags {
                scanner_image: Some("x".into()),
                scanner_commands: vec!["x".into(), "y".into()],
                ..flags()
            },
            SbomFlags {
                preset: Some("syft".into()),
                merge_strategy: Some("nope".into()),
                ..flags()
            },
        ] {
            assert!(bad.resolve().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn documents_are_merged_by_name_and_version() {
        let a = br#"{"bomFormat":"CycloneDX","components":[{"name":"a","version":"1","purl":"pkg:z@1"}]}"#;
        let b = br#"{"components":[{"name":"a","version":"1"},{"name":"b","version":"2","purl":"pkg:b@2"}]}"#;
        let (m, p) = merge(Merge::CycloneDx, &[a.to_vec(), b.to_vec()]).unwrap();
        let v: Value = serde_json::from_slice(&m).unwrap();
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["components"].as_array().unwrap().len(), 2);
        assert_eq!(
            String::from_utf8(p).unwrap(),
            "{\"image_contents\":{\"dependencies\":[\"pkg:b@2\",\"pkg:z@1\"]}}\n"
        );
        let s1 = br#"{"packages":[{"name":"x","versionInfo":"1"}],"hasExtractedLicensingInfos":[{"licenseId":"L1"}]}"#;
        let s2 = br#"{"packages":[{"name":"x","versionInfo":"1"},{"name":"x","versionInfo":"2","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:x@2"},{"referenceCategory":"OTHER","referenceType":"purl","referenceLocator":"pkg:no"}]}],"hasExtractedLicensingInfos":[{"licenseId":"L1"},{"licenseId":"L2"}]}"#;
        let (m, p) = merge(Merge::Spdx, &[s1.to_vec(), s2.to_vec()]).unwrap();
        let v: Value = serde_json::from_slice(&m).unwrap();
        assert_eq!(v["packages"].as_array().unwrap().len(), 2);
        assert_eq!(v["hasExtractedLicensingInfos"].as_array().unwrap().len(), 2);
        assert_eq!(
            String::from_utf8(p).unwrap(),
            "{\"image_contents\":{\"dependencies\":[\"pkg:x@2\"]}}\n"
        );
        let (m, p) = merge(Merge::Cat, &[b"ab".to_vec(), b"c".to_vec()]).unwrap();
        assert_eq!(m, b"abc");
        assert_eq!(p, b"{\"image_contents\":{}}\n");
        assert!(merge(Merge::Spdx, &[b"nope".to_vec()]).is_err());
        assert!(merge(
            Merge::CycloneDx,
            &[br#"{"components":[{"version":"1"}]}"#.to_vec()]
        )
        .is_err());
        assert!(merge(Merge::CycloneDx, &[br#"{"components":[7]}"#.to_vec()]).is_err());
    }
}
