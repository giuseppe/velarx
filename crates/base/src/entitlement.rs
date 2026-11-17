// SPDX-License-Identifier: Apache-2.0
//! The entitlements of a build: what a Containerfile or a build request may
//! ask for that gives a RUN step more than the sandbox (BuildKit's names).
//! A build gets one only when the engine's configuration enables it and the
//! request names it.

use serde::{Deserialize, Serialize};

/// Something a build step may ask for that is off unless it is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Entitlement {
    /// `RUN --network=host` and a build with `--network=host`: the steps
    /// share the network namespace of the host.
    #[serde(rename = "network.host")]
    NetworkHost,
    /// `RUN --security=insecure`: the step runs as `run --privileged` does.
    #[serde(rename = "security.insecure")]
    SecurityInsecure,
}

impl Entitlement {
    pub const ALL: [Entitlement; 2] = [Entitlement::NetworkHost, Entitlement::SecurityInsecure];

    pub fn name(self) -> &'static str {
        match self {
            Entitlement::NetworkHost => "network.host",
            Entitlement::SecurityInsecure => "security.insecure",
        }
    }

    pub fn parse(name: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|e| e.name() == name)
            .ok_or_else(|| {
                format!("unknown entitlement `{name}`: network.host or security.insecure")
            })
    }

    /// The entitlements of `--allow` values: each may be a comma separated
    /// list (`--allow=network.host,security.insecure`); the result has no
    /// duplicate.
    pub fn parse_list<S: AsRef<str>>(values: &[S]) -> Result<Vec<Self>, String> {
        let mut out = Vec::new();
        for v in values {
            for name in v.as_ref().split(',') {
                let e = Self::parse(name.trim())?;
                if !out.contains(&e) {
                    out.push(e);
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

impl std::fmt::Display for Entitlement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for e in Entitlement::ALL {
            assert_eq!(Entitlement::parse(e.name()), Ok(e));
            assert_eq!(e.to_string(), e.name());
        }
    }

    #[test]
    fn unknown_names_are_errors() {
        for bad in [
            "",
            "network",
            "network.none",
            "Network.Host",
            "security.sandbox",
        ] {
            let e = Entitlement::parse(bad).unwrap_err();
            assert!(e.contains("unknown entitlement"), "{bad}: {e}");
        }
    }

    #[test]
    fn lists_are_comma_separated_and_deduplicated() {
        assert_eq!(Entitlement::parse_list::<&str>(&[]), Ok(vec![]));
        assert_eq!(
            Entitlement::parse_list(&["security.insecure,network.host", "network.host"]),
            Ok(vec![
                Entitlement::NetworkHost,
                Entitlement::SecurityInsecure
            ])
        );
        assert!(Entitlement::parse_list(&["network.host,"]).is_err());
        assert!(Entitlement::parse_list(&["network.host,bogus"]).is_err());
    }
}
