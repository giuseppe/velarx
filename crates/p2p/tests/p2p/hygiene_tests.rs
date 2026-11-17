// SPDX-License-Identifier: Apache-2.0
//! What the files of the service must keep: data travels in real files, and
//! its units keep their hardening.

use std::path::Path;

/// Data travels in real files only: no memory file in the code that fetches,
/// serves or hands over content (the owner decided it: a file has a size the
/// client can bound and an owner that is the asker's).
#[test]
fn no_memory_file_carries_data() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let needles = [
        concat!("memfd", "_create"),
        "MemfdFlags",
        "sealed_memfd",
        "MFD_",
    ];
    for name in ["store", "provider", "service"] {
        let name = format!("src/{name}.rs");
        let text = std::fs::read_to_string(root.join(&name)).unwrap();
        for needle in needles {
            assert!(!text.contains(needle), "{name} uses {needle}");
        }
    }
}

/// The service talks to the network: a unit that loses one of these
/// options is caught here, not in a review.
#[test]
fn the_units_are_hardened() {
    const WANTED: [&str; 14] = [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "PrivateDevices=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "RestrictRealtime=yes",
        "LockPersonality=yes",
        "SystemCallArchitectures=native",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "MemoryDenyWriteExecute=yes",
        "RestrictNamespaces=yes",
        "RestrictSUIDSGID=yes",
        "SystemCallFilter=@system-service",
    ];
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../systemd");
    let mut missing = Vec::new();
    for unit in ["system/velarx-p2p.service", "user/velarx-p2p.service"] {
        let text = std::fs::read_to_string(root.join(unit)).unwrap();
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        for option in WANTED {
            if !lines.contains(&option) {
                missing.push(format!("{unit}: {option}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "options missing from the units: {missing:#?}"
    );
}

/// The content service has no capability; the overlay node has the four its
/// helper keeps (veths, packet sockets, port 53 of the DNS, the containers'
/// namespaces: a capability the unit lacks fails the helper's `capset`), and
/// is otherwise as hardened.
#[test]
fn the_overlay_unit_has_the_capabilities_of_its_helper_and_the_service_none() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../systemd/system");
    let read = |name: &str| std::fs::read_to_string(root.join(name)).unwrap();
    let (content, overlay) = (
        read("velarx-p2p.service"),
        read("velarx-p2p-overlay.service"),
    );
    let has = |text: &str, line: &str| text.lines().any(|l| l.trim() == line);
    assert!(has(&content, "CapabilityBoundingSet="));
    assert!(has(&content, "AmbientCapabilities="));
    let caps = "CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_ADMIN";
    assert!(has(&overlay, &format!("CapabilityBoundingSet={caps}")));
    assert!(has(&overlay, &format!("AmbientCapabilities={caps}")));
    for option in [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "PrivateDevices=yes",
        "MemoryDenyWriteExecute=yes",
        "SystemCallFilter=@system-service",
        "ExecStart=/usr/bin/velarx-p2p overlay",
    ] {
        assert!(has(&overlay, option), "{option}");
    }
}

/// The service calls the engine's services through their typed proxies, and
/// what it needs from a library it takes from one: no raw varlink call
/// written by hand, no second HMAC, no copy of the parser of a startup
/// profile.
#[test]
fn no_call_or_algorithm_is_written_again() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = |name: &str| std::fs::read_to_string(root.join("src").join(name)).unwrap();
    let store = text("store.rs");
    assert!(
        !store.contains("org.velarx.Store.") && !store.contains("struct Subscribe"),
        "store.rs makes a call of the store service by hand"
    );
    assert!(
        !text("quic.rs").contains("0x36u8"),
        "quic.rs computes an HMAC by hand"
    );
    let provider = text("provider.rs");
    assert!(
        !provider.contains("struct Doc"),
        "provider.rs parses a startup profile by itself"
    );
}
