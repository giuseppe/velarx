// SPDX-License-Identifier: Apache-2.0
//! firewalld: its own table rejects what its zones do not allow, whatever
//! the other tables accept, so the containers of a bridge network could not
//! reach their DNS server on the gateway (`ip velarx` accepts it, firewalld's
//! `filter_INPUT` rejects it).  As netavark does, the subnet of a bridge
//! network in the host namespace is a source of the `trusted` zone while
//! the bridge exists: in the runtime configuration only, so that nothing
//! stays after a reboot.  A restart or a reload of firewalld forgets it
//! while the bridge stays: each container start asks firewalld for the zone
//! of the subnet (a query, about 1 ms) and adds it only when it has none (an
//! add is 13-15 ms: firewalld applies its rules again).
//!
//! The trusted zone accepts the traffic of the subnet to the host and its
//! forwarding, as with podman: the `ip velarx` table still filters it.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use velarx_wire::addr::Subnet;
use velarx_wire::sdbus;

const ZONE: &str = "trusted";

/// Whether this process is in the network namespace of PID 1: firewalld
/// filters that one only; the subnets of the bridges of another namespace
/// are none of its business.
fn in_host_netns() -> bool {
    match (
        std::fs::metadata("/proc/self/ns/net"),
        std::fs::metadata("/proc/1/ns/net"),
    ) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// The bus name, the object and the interface of firewalld's zones.
const SERVICE: &str = "org.fedoraproject.FirewallD1";
const OBJECT: &str = "/org/fedoraproject/FirewallD1";
const INTERFACE: &str = "org.fedoraproject.FirewallD1.zone";

/// How long firewalld has to answer.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The D-Bus name of every error firewalld raises on purpose; the kind of
/// it is the first word of its message (`ALREADY_ENABLED: ...`).
const FIREWALLD_ERROR: &str = "org.fedoraproject.FirewallD1.Exception";

/// Whether the error of a call is a state to leave alone: firewalld not
/// running (the bus has no owner of its name, or none to start), the source
/// already in the zone (`ALREADY_ENABLED`, or `ZONE_ALREADY_SET` when
/// another store of this host bound the same subnet), not there
/// (`UNKNOWN_SOURCE`), or in a zone the administrator chose
/// (`ZONE_CONFLICT`).  No bus daemon at all is no firewalld.
fn expected_failure(e: &io::Error) -> bool {
    let Some(err) = sdbus::manager_error(e) else {
        return matches!(
            e.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
        );
    };
    match err.name.as_str() {
        "org.freedesktop.DBus.Error.ServiceUnknown"
        | "org.freedesktop.DBus.Error.NameHasNoOwner" => true,
        FIREWALLD_ERROR => matches!(
            err.message.split(':').next(),
            Some("ALREADY_ENABLED" | "ZONE_ALREADY_SET" | "UNKNOWN_SOURCE" | "ZONE_CONFLICT")
        ),
        _ => false,
    }
}

/// Whether firewalld is to be told of the subnets of this process's
/// bridges: as root, in the namespace it filters.
fn ours() -> bool {
    rustix::process::geteuid().is_root() && in_host_netns()
}

/// `method` of the zones for the source `subnet` (`ZONE` first unless
/// `zone` is false); its answer, none when firewalld cannot be asked (not
/// running) or refused it as a state to leave alone.
fn call(method: &str, subnet: &Subnet, zone: bool) -> Option<String> {
    let source = subnet.to_string();
    let args: &[&str] = if zone { &[ZONE, &source] } else { &[&source] };
    match sdbus::call_system_bus(SERVICE, OBJECT, INTERFACE, method, args, TIMEOUT) {
        Ok(answer) => {
            tracing::debug!("firewalld: {method} {subnet}: `{answer}`");
            Some(answer)
        }
        Err(e) if expected_failure(&e) => None,
        Err(e) => {
            tracing::warn!("firewalld: {method} {subnet}: {e}");
            None
        }
    }
}

/// Let firewalld accept the traffic of SUBNET, a bridge network in this
/// namespace, unless the subnet is a source of a zone already (ours, or one
/// the administrator chose).  Best effort.
pub fn trust(subnet: &Subnet) {
    if !ours() {
        return;
    }
    if call("getZoneOfSource", subnet, false).is_some_and(|z| z.is_empty()) {
        call("addSource", subnet, true);
    }
}

/// Undo `trust` when the bridge of SUBNET is gone.  Best effort.
pub fn untrust(subnet: &Subnet) {
    if ours() {
        call("removeSource", subnet, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raised(name: &str, message: &str) -> io::Error {
        sdbus::ManagerError {
            name: name.into(),
            message: message.into(),
        }
        .into()
    }

    #[test]
    fn a_source_already_in_the_zone_is_not_worth_a_warning() {
        assert!(expected_failure(&raised(
            FIREWALLD_ERROR,
            "ZONE_ALREADY_SET: '10.90.0.0/24' already bound to 'trusted'"
        )));
        assert!(!expected_failure(&raised(
            FIREWALLD_ERROR,
            "INVALID_ADDR: nope"
        )));
        // the code in the message of another error does not count
        assert!(!expected_failure(&raised(
            "org.freedesktop.DBus.Error.Failed",
            "ALREADY_ENABLED: x"
        )));
    }

    #[test]
    fn no_firewalld_is_told_by_the_bus_error_or_the_missing_socket() {
        assert!(expected_failure(&raised(
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "The name is not activatable"
        )));
        assert!(expected_failure(&raised(
            "org.freedesktop.DBus.Error.NameHasNoOwner",
            ""
        )));
        assert!(expected_failure(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(!expected_failure(&io::Error::other("ALREADY_ENABLED")));
    }
}
