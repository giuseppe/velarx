// SPDX-License-Identifier: Apache-2.0
//! The fuzz targets of the parsers of this crate (`fuzz/`): what they take
//! is a file of the user's, and a panic of them is what they look for.

/// The names of the targets.
pub const TARGETS: &[&str] = &["yaml", "kube_play"];

/// Run the target `name` on `data`; false for a name that is no target.
pub fn run(name: &str, data: &[u8]) -> bool {
    match name {
        "yaml" => yaml(data),
        "kube_play" => kube_play(data),
        _ => return false,
    }
    true
}

/// Kubernetes YAML, emitted again.
pub fn yaml(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(docs) = crate::yaml::parse_documents(s) {
        let _ = crate::yaml::parse_documents(&crate::yaml::emit_documents(&docs));
        for d in &docs {
            let _ = crate::validate::unknown_fields(d);
        }
    }
}

/// Kubernetes YAML as `play` maps it.
pub fn kube_play(data: &[u8]) {
    struct NoSecrets;
    impl crate::play::Sources for NoSecrets {
        fn secret(&self, _: &str) -> Option<Vec<u8>> {
            None
        }
    }
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(docs) = crate::yaml::parse_documents(s) {
        let _ = crate::play::plan(&docs, &Default::default(), &NoSecrets);
        let _ = crate::play::pod_names(&docs);
    }
}
