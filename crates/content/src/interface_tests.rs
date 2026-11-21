// SPDX-License-Identifier: Apache-2.0
//! The descriptions the registry fetcher sends are what the types say (the
//! file of `org.velarx.Fetcher` is checked by `serve_fetch`'s tests).

/// The text a service sends for `GetInterfaceDescription` (the file,
/// embedded) is what the descriptors of the types and methods say.
#[test]
fn the_description_served_is_what_the_types_say() {
    assert_eq!(
        velarx_proto::interfaces::fetcher(),
        crate::serve_fetch::description()
    );
}

/// The description of the repository calls served is what the types say.
#[test]
fn the_registry_description_served_is_what_the_types_say() {
    assert_eq!(
        velarx_proto::interfaces::registry(),
        crate::serve_fetch::registry_description()
    );
}

/// The repository calls are their own interface, `org.velarx.Registry`, and
/// the file is made from the types.  `VELARX_WRITE_INTERFACES=1` writes it.
#[test]
fn the_registry_interface_file_is_current() {
    let text = crate::serve_fetch::registry_definition();
    velarx_base::testing::assert_interface_file("interfaces/org.velarx.Registry.varlink", &text);
    assert!(text.contains("interface org.velarx.Registry"));
    for method in ["GetInfo", "Tags", "Search", "Login", "Download"] {
        assert!(text.contains(&format!("method {method}(")), "{method}");
    }
    // (the calls of a push are the pusher's)
    for method in ["BlobExists", "BlobMount", "BlobUpload", "ManifestPut"] {
        assert!(!text.contains(&format!("method {method}(")), "{method}");
    }
    assert!(!text.contains("[`"), "a rustdoc link in the definition");
}

/// The two interfaces share no method: the repository calls are not in the
/// interface every fetcher serves.
#[test]
fn the_fetcher_interface_has_no_repository_call() {
    let text = crate::serve_fetch::definition();
    for method in [
        "Tags",
        "Search",
        "Login",
        "BlobExists",
        "BlobMount",
        "BlobUpload",
        "ManifestPut",
    ] {
        assert!(!text.contains(&format!("method {method}(")), "{method}");
    }
    assert!(!text.contains("type Remote ("));
}

/// The description of the pusher served is what the types say.
#[test]
fn the_pusher_description_served_is_what_the_types_say() {
    assert_eq!(
        velarx_proto::interfaces::pusher(),
        crate::serve_fetch::pusher_description()
    );
}

/// The pusher is its own interface, `org.velarx.Pusher`, and the file is made
/// from the types.  `VELARX_WRITE_INTERFACES=1` writes it.
#[test]
fn the_pusher_interface_file_is_current() {
    let text = crate::serve_fetch::pusher_definition();
    velarx_base::testing::assert_interface_file("interfaces/org.velarx.Pusher.varlink", &text);
    assert!(text.contains("interface org.velarx.Pusher"));
    for method in [
        "GetInfo",
        "Open",
        "Connect",
        "Renew",
        "Probe",
        "Put",
        "Commit",
        "Committed",
        "Finish",
    ] {
        assert!(text.contains(&format!("method {method}(")), "{method}");
    }
    // (cancelling is closing the connection of a call)
    for method in ["Layer", "Cancel"] {
        assert!(!text.contains(&format!("method {method}(")), "{method}");
    }
    assert!(!text.contains("[`"), "a rustdoc link in the definition");
}

/// The fetcher interface has no call of the pusher.
#[test]
fn the_fetcher_interface_has_no_pusher_call() {
    let text = crate::serve_fetch::definition();
    for method in ["Put", "Commit", "Committed", "Finish"] {
        assert!(!text.contains(&format!("method {method}(")), "{method}");
    }
}
