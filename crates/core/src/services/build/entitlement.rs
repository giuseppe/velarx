// SPDX-License-Identifier: Apache-2.0
//! The entitlements of a build (`velarx_base::entitlement`): what the steps
//! of a build need, and whether the engine's configuration and the request
//! allow it.  The one place that decides; the build asks before its first
//! step and a RUN step asks again (an ONBUILD trigger of a base image is
//! not in the Containerfile).
//!
//! Only what the untrusted Containerfile can ask for (`RUN --network=host`,
//! `RUN --security=insecure`) and the network of the build is an
//! entitlement; the run options of the request (`-v`, `--device`,
//! `--cap-add`, `--pid`, `--uts`, ...) are the client's choice, as for `run`.

use std::collections::BTreeMap;
use velarx_base::entitlement::Entitlement;
use velarx_wire::parse::{Containerfile, Instr};
use velarx_wire::request::NetworkMode;

/// What a build request allows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Allow {
    /// The request cannot say (the REST routes, a quadlet unit): whatever the engine's configuration enables.
    #[default]
    ByConfig,
    /// `build --allow`: these, and only if the configuration enables them.
    Listed(Vec<Entitlement>),
}

/// What an instruction needs: the entitlement and what asks for it.
pub fn instruction_needs(i: &Instr) -> Vec<(Entitlement, String)> {
    let mut out = Vec::new();
    if i.keyword == "RUN" {
        if i.flag("network") == Some("host") {
            out.push((
                Entitlement::NetworkHost,
                format!("line {}: RUN --network=host", i.line),
            ));
        }
        if i.flag("security") == Some("insecure") {
            out.push((
                Entitlement::SecurityInsecure,
                format!("line {}: RUN --security=insecure", i.line),
            ));
        }
    }
    out
}

/// What the stages the build makes (`built`, one flag per stage) and the
/// network of the build need.  A namespace joined by its path may be the
/// host's (`ns:/proc/1/ns/net`) or another container's: it needs what the
/// host network needs.
pub fn needs(
    file: &Containerfile,
    built: &[bool],
    network: Option<&str>,
) -> Vec<(Entitlement, String)> {
    let mut out = Vec::new();
    if let Some(n) = network {
        if matches!(
            NetworkMode::parse(n),
            NetworkMode::Host | NetworkMode::Ns(_)
        ) {
            out.push((Entitlement::NetworkHost, format!("build --network={n}")));
        }
    }
    for (stage, _) in file.stages.iter().zip(built).filter(|(_, b)| **b) {
        for i in &stage.instrs {
            out.extend(instruction_needs(i));
        }
    }
    out
}

/// Whether the build may have what it `needs`: the error says every
/// entitlement that is missing and what to do about each.
pub fn check(
    enabled: &[Entitlement],
    allow: &Allow,
    needs: &[(Entitlement, String)],
) -> Result<(), String> {
    if let Allow::Listed(listed) = allow {
        if let Some(e) = listed.iter().find(|e| !enabled.contains(e)) {
            return Err(format!(
                "--allow {e}: {e} is not enabled in the engine configuration \
                 ([build] insecure_entitlements)"
            ));
        }
    }
    let mut missing: BTreeMap<Entitlement, Vec<&str>> = BTreeMap::new();
    for (e, why) in needs {
        let allowed = match allow {
            Allow::ByConfig => enabled.contains(e),
            Allow::Listed(listed) => listed.contains(e),
        };
        if !allowed {
            missing.entry(*e).or_default().push(why);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let mut parts = Vec::new();
    for (e, why) in missing {
        let how = match (allow, enabled.contains(&e)) {
            (Allow::ByConfig, _) => format!(
                "enable it in the engine configuration ([build] insecure_entitlements = [\"{e}\"])"
            ),
            (Allow::Listed(_), true) => format!("start the build with --allow {e}"),
            (Allow::Listed(_), false) => format!(
                "start the build with --allow {e} and enable it in the engine configuration \
                 ([build] insecure_entitlements = [\"{e}\"])"
            ),
        };
        parts.push(format!("{e} is not allowed ({}): {how}", why.join("; ")));
    }
    Err(parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Entitlement::{NetworkHost as Host, SecurityInsecure as Insecure};

    fn file(text: &str) -> Containerfile {
        Containerfile::parse(text).unwrap()
    }

    #[test]
    fn a_plain_containerfile_needs_nothing() {
        let f =
            file("FROM scratch\nRUN true\nRUN --network=none true\nRUN --security=sandbox true\n");
        assert!(needs(&f, &[true], None).is_empty());
        assert!(needs(&f, &[true], Some("none")).is_empty());
        assert!(needs(&f, &[true], Some("bridge")).is_empty());
        assert!(needs(&f, &[true], Some("mynet")).is_empty());
        assert!(needs(&f, &[true], Some("pasta:-T,80")).is_empty());
    }

    #[test]
    fn the_steps_and_the_network_of_the_build_are_found() {
        let f = file(
            "FROM scratch AS a\nRUN --network=host true\nFROM a AS b\nRUN --security=insecure true\n\
             RUN --network=host true\nFROM b\nRUN --network=host true\n",
        );
        let n = needs(&f, &[true, true, false], Some("host"));
        let kinds: Vec<_> = n.iter().map(|(e, _)| *e).collect();
        assert_eq!(kinds, [Host, Host, Insecure, Host]);
        assert_eq!(n[0].1, "build --network=host");
        assert_eq!(n[1].1, "line 2: RUN --network=host");
        assert_eq!(n[2].1, "line 4: RUN --security=insecure");
        // a stage the build does not make needs nothing
        assert_eq!(needs(&f, &[true, true, true], None).len(), 4);
        assert_eq!(needs(&f, &[true, false, false], None).len(), 1);
        assert_eq!(needs(&f, &[false, true, true], None).len(), 3);
        // a namespace by its path may be the host's
        let n = needs(&f, &[false, false, false], Some("ns:/proc/1/ns/net"));
        assert_eq!(n, [(Host, "build --network=ns:/proc/1/ns/net".to_string())]);
    }

    #[test]
    fn nothing_needed_nothing_refused_unless_the_request_overreaches() {
        assert_eq!(check(&[], &Allow::ByConfig, &[]), Ok(()));
        assert_eq!(check(&[], &Allow::Listed(vec![]), &[]), Ok(()));
        assert_eq!(check(&[Host], &Allow::Listed(vec![Host]), &[]), Ok(()));
        let e = check(&[Insecure], &Allow::Listed(vec![Host]), &[]).unwrap_err();
        assert_eq!(
            e,
            "--allow network.host: network.host is not enabled in the engine configuration \
             ([build] insecure_entitlements)"
        );
    }

    #[test]
    fn both_gates_must_be_open() {
        let need = vec![(Host, "line 2: RUN --network=host".to_string())];
        assert_eq!(check(&[Host], &Allow::Listed(vec![Host]), &need), Ok(()));
        assert_eq!(check(&[Host], &Allow::ByConfig, &need), Ok(()));
        // the config alone is not the request
        let e = check(&[Host], &Allow::Listed(vec![]), &need).unwrap_err();
        assert_eq!(
            e,
            "network.host is not allowed (line 2: RUN --network=host): \
             start the build with --allow network.host"
        );
        // the request alone is not the config
        let e = check(&[], &Allow::Listed(vec![Host]), &need).unwrap_err();
        assert!(
            e.starts_with("--allow network.host: network.host is not enabled"),
            "{e}"
        );
        // nothing at all
        let e = check(&[], &Allow::Listed(vec![]), &need).unwrap_err();
        assert_eq!(
            e,
            "network.host is not allowed (line 2: RUN --network=host): start the build with \
             --allow network.host and enable it in the engine configuration \
             ([build] insecure_entitlements = [\"network.host\"])"
        );
        // a REST request: the configuration is all there is
        let e = check(&[], &Allow::ByConfig, &need).unwrap_err();
        assert_eq!(
            e,
            "network.host is not allowed (line 2: RUN --network=host): enable it in the \
             engine configuration ([build] insecure_entitlements = [\"network.host\"])"
        );
    }

    #[test]
    fn every_missing_entitlement_is_listed_once() {
        let need = vec![
            (Host, "line 2: RUN --network=host".to_string()),
            (Insecure, "line 3: RUN --security=insecure".to_string()),
            (Host, "line 5: RUN --network=host".to_string()),
        ];
        let e = check(&[Host, Insecure], &Allow::Listed(vec![]), &need).unwrap_err();
        assert_eq!(e.matches("network.host is not allowed").count(), 1, "{e}");
        assert!(
            e.contains("line 2: RUN --network=host; line 5: RUN --network=host"),
            "{e}"
        );
        assert!(
            e.contains("security.insecure is not allowed (line 3"),
            "{e}"
        );
    }
}
