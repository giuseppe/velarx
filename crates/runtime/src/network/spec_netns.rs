// SPDX-License-Identifier: Apache-2.0
//! The network namespace an OCI spec joins, in its `config.json`.

use std::io;
use std::path::{Path, PathBuf};

/// Make the OCI spec at SPEC (a bundle's config.json) join the network
/// namespace NETNS.
pub fn set_spec_netns(spec: &Path, netns: &Path) -> io::Result<()> {
    swap_spec_netns(spec, Some(netns)).map(|_| ())
}

/// The path of the network namespace the OCI spec at SPEC joins, None when
/// it makes its own.
pub fn spec_netns(spec: &Path) -> io::Result<Option<PathBuf>> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(spec)?)?;
    Ok(v.pointer("/linux/namespaces")
        .and_then(serde_json::Value::as_array)
        .and_then(|nss| {
            nss.iter()
                .find(|n| n.get("type").and_then(|t| t.as_str()) == Some("network"))
        })
        .and_then(|n| n.get("path").and_then(|p| p.as_str()))
        .map(PathBuf::from))
}

/// Make the spec join NETNS (`None`: make its own namespace); the path it
/// joined before, to put back.  The file is left alone when it already says
/// that.
pub fn swap_spec_netns(spec: &Path, netns: Option<&Path>) -> io::Result<Option<PathBuf>> {
    let data = std::fs::read(spec)?;
    let mut v: serde_json::Value = serde_json::from_slice(&data).map_err(io::Error::other)?;
    let Some(nss) = v
        .pointer_mut("/linux/namespaces")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Err(io::Error::other("the spec has no namespaces"));
    };
    let entry = match netns {
        Some(p) => serde_json::json!({"type": "network", "path": p.to_string_lossy()}),
        None => serde_json::json!({"type": "network"}),
    };
    let previous = match nss
        .iter_mut()
        .find(|n| n.get("type").and_then(|t| t.as_str()) == Some("network"))
    {
        Some(n) => {
            let was = n.get("path").and_then(|p| p.as_str()).map(PathBuf::from);
            if *n == entry {
                return Ok(was);
            }
            *n = entry;
            was
        }
        None => {
            nss.push(entry);
            None
        }
    };
    crate::container::spec_file::write(spec, &v)?;
    Ok(previous)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_network_namespace_of_a_spec_is_swapped_and_put_back() {
        let d = tempfile::tempdir().unwrap();
        let spec = d.path().join("config.json");
        std::fs::write(
            &spec,
            r#"{"linux": {"namespaces": [{"type": "pid"}, {"type": "network"}]},
                "process": {"args": ["true"]}}"#,
        )
        .unwrap();
        assert_eq!(spec_netns(&spec).unwrap(), None);
        let ns = Path::new("/proc/self/fd/7");
        assert_eq!(swap_spec_netns(&spec, Some(ns)).unwrap(), None);
        assert_eq!(spec_netns(&spec).unwrap().as_deref(), Some(ns));
        // (the same again: the file is left alone)
        assert_eq!(
            swap_spec_netns(&spec, Some(ns)).unwrap().as_deref(),
            Some(ns)
        );
        assert_eq!(swap_spec_netns(&spec, None).unwrap().as_deref(), Some(ns));
        assert_eq!(spec_netns(&spec).unwrap(), None);
        // (the process, with the command krun runs, comes before the linux section)
        let text = std::fs::read_to_string(&spec).unwrap();
        assert!(text.find("\"process\"").unwrap() < text.find("\"linux\"").unwrap());
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&spec).unwrap()).unwrap();
        assert_eq!(
            v["linux"]["namespaces"][1],
            serde_json::json!({"type": "network"})
        );
        assert_eq!(
            v["linux"]["namespaces"][0],
            serde_json::json!({"type": "pid"})
        );
    }

    #[test]
    fn spec_joins_a_namespace() {
        let d = tempfile::tempdir().unwrap();
        let spec = d.path().join("config.json");
        std::fs::write(
            &spec,
            r#"{"linux": {"namespaces": [{"type": "pid"}, {"type": "network", "path": "/proc/1/ns/net"}]}}"#,
        )
        .unwrap();
        set_spec_netns(&spec, Path::new("/run/x/netns/abc")).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&spec).unwrap()).unwrap();
        let nss = v["linux"]["namespaces"].as_array().unwrap();
        assert_eq!(nss.len(), 2);
        assert_eq!(nss[1]["path"], "/run/x/netns/abc");
        std::fs::write(&spec, r#"{"linux": {"namespaces": [{"type": "pid"}]}}"#).unwrap();
        set_spec_netns(&spec, Path::new("/n")).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&spec).unwrap()).unwrap();
        assert_eq!(v["linux"]["namespaces"][1]["type"], "network");
        std::fs::write(&spec, "{}").unwrap();
        assert!(set_spec_netns(&spec, Path::new("/n")).is_err());
    }
}
