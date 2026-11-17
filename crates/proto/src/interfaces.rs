// SPDX-License-Identifier: Apache-2.0
//! The text of the interfaces that the services of velarx serve.
//!
//! A service answers `org.varlink.service.GetInterfaceDescription` with the
//! checked-in definition (`interfaces/*.varlink`), not with
//! a description built from the descriptors of its types and methods: the
//! descriptors with their comments were most of what an interface weighed
//! in the binary.  The tests of each service build the descriptors and
//! compare them with the file, so the text cannot drift from the types.
//! One function for each interface, so that a binary keeps the text of the
//! interfaces it serves and no other; the big one, the engine's, is kept
//! compressed.

include!(concat!(env!("OUT_DIR"), "/interfaces.rs"));

/// The description of `org.velarx.Engine` as a service sends it: its
/// definition without the comment that opens the file.
pub fn engine() -> String {
    inflate(ENGINE)
}

/// The description of `org.velarx.Fetcher`, as [`engine`] gives
/// the one of the engine.
pub fn fetcher() -> String {
    FETCHER.to_string()
}

/// The description of `org.velarx.Pusher`, as [`engine`] gives the one
/// of the engine.
pub fn pusher() -> String {
    PUSHER.to_string()
}

/// The description of `org.velarx.Registry`, as [`engine`] gives the one
/// of the engine.
pub fn registry() -> String {
    REGISTRY.to_string()
}

/// The description of `org.velarx.Store`, as [`engine`] gives the one of
/// the engine.
pub fn store() -> String {
    STORE.to_string()
}

fn inflate(compressed: &[u8]) -> String {
    use std::io::Read;

    let mut text = String::new();
    flate2::read::DeflateDecoder::new(compressed)
        .read_to_string(&mut text)
        .expect("a description is valid");
    text
}
