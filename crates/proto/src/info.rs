// SPDX-License-Identifier: Apache-2.0
//! What `GetInfo` answers in every interface that has the shared one: who
//! serves it and what it can do.  Written once here; the generator of each
//! interface emits its text from this type.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(feature = "proxy")]
use zlink::introspect;

/// Who serves an interface and what it can do.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "proxy", derive(introspect::Type))]
pub struct Info {
    pub name: String,
    /// The version of the package
    pub version: String,
    /// The version of the protocol (1): compared for equality, it changes
    /// only for a deliberate break
    pub proto: u32,
    /// Words; a client ignores those it does not know
    pub capabilities: Vec<String>,
    /// Named limits (`max_objects`, ...); a client ignores those it does not know
    pub limits: BTreeMap<String, u64>,
}

/// A server that speaks another protocol than the client's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{name} ({interface}) speaks version {theirs} of the protocol, this client speaks {ours}")]
pub struct InfoError {
    pub interface: String,
    pub name: String,
    pub theirs: u32,
    pub ours: u32,
}

/// Refuse a server whose `proto` is not `proto`, naming both.
pub fn check(interface: &str, info: &Info, proto: u32) -> Result<(), InfoError> {
    if info.proto == proto {
        Ok(())
    } else {
        Err(InfoError {
            interface: interface.to_string(),
            name: info.name.clone(),
            theirs: info.proto,
            ours: proto,
        })
    }
}

impl Info {
    /// A named limit, when the server states it.
    pub fn limit(&self, name: &str) -> Option<u64> {
        self.limits.get(name).copied()
    }

    /// Whether the server states this capability word.
    pub fn can(&self, word: &str) -> bool {
        self.capabilities.iter().any(|w| w == word)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(proto: u32) -> Info {
        Info {
            name: "fetcher".into(),
            version: "1".into(),
            proto,
            capabilities: vec!["objects".into()],
            limits: BTreeMap::from([("max_objects".to_string(), 64)]),
        }
    }

    #[test]
    fn another_proto_is_refused_naming_both() {
        assert!(check("org.velarx.X", &info(1), 1).is_ok());
        let e = check("org.velarx.X", &info(2), 1).unwrap_err().to_string();
        assert!(e.contains("fetcher") && e.contains("org.velarx.X"), "{e}");
        assert!(e.contains('2') && e.contains('1'), "{e}");
    }

    #[test]
    fn limits_and_words_are_looked_up() {
        let i = info(1);
        assert_eq!(i.limit("max_objects"), Some(64));
        assert_eq!(i.limit("max_wants"), None);
        assert!(i.can("objects") && !i.can("whole"));
    }
}
