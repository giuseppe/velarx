// SPDX-License-Identifier: Apache-2.0
//! What the names of images have in common in every crate: the rule that
//! tells a registry in a name.

/// Whether the first component of an image name (the part before the first
/// `/`) is a registry: it has a dot or a port, or is `localhost` (the rule
/// of containers/image).
pub fn is_registry_domain(first: &str) -> bool {
    first.contains(['.', ':']) || first == "localhost"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_first_component_is_a_registry_with_a_dot_a_port_or_localhost() {
        for yes in ["quay.io", "localhost", "localhost:5000", "host:5000", "a.b"] {
            assert!(is_registry_domain(yes), "{yes}");
        }
        for no in ["library", "alpine", "localhost2", "Localhost", "myorg", ""] {
            assert!(!is_registry_domain(no), "{no}");
        }
    }
}
