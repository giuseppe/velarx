// SPDX-License-Identifier: Apache-2.0
//! What the engine and its frontends share: the varlink interface
//! `org.velarx.Engine` ([`engine`]: its types, its errors and the client
//! side of it), the connection a frontend makes to the engine
//! ([`connect`]), and the confinement a frontend enters ([`confine`]).
//!
//! The engine (`velarx varlink`) serves the interface; the
//! frontends (`velarx-api`, later `velarx-cri`) are wrappers that decode
//! a protocol of their own and call it.  They link this package and not the
//! engine.  Without the feature `service` it is the types, and with `proxy`
//! the interface and its proxy, but no runtime: the thin client of velarx
//! compiles those.

/// The version of the interface: a frontend refuses another one.
pub const PROTO: u32 = 1;

/// The digest of the interface: the FNV-1a (64 bits, in hexadecimal) of
/// the text of the definition the engine serves,
/// `interfaces/org.velarx.Engine.varlink`.
pub const DIGEST: &str = env!("VELARX_INTERFACE_DIGEST");

/// The most a reply carries inline as a document: above it the document is
/// a pipe.  A varlink message is serialized and read in memory, and the
/// library grows its buffers a few hundred bytes at a time, so a large one
/// costs much more than the same bytes in a pipe.
pub const INLINE_MAX: usize = 16 * 1024;

/// Whether a process with this uid may use the private sockets of this one:
/// the same user, or root.
pub fn trusted_uid(uid: u32) -> bool {
    uid == velarx_sys::process::effective_uid() || uid == 0
}

#[cfg(feature = "service")]
pub mod bearer;
pub mod build;
pub mod buildspec;
#[cfg(feature = "service")]
pub mod confine;
#[cfg(feature = "service")]
pub mod connect;
pub mod descriptors;
pub mod duration;
pub mod health;
pub mod info;
pub mod modes;

/// What a call that changes something is told while the engine restarts:
/// ask again, the next connection is served by the engine that follows.
pub const RESTARTING: &str = "the engine is restarting: ask again";

#[cfg(feature = "proxy")]
pub mod engine;
// The library the interface is made with, for a client that speaks it over a
// socket of its own (the thin client of velarx).  Without the service its
// runtime is not compiled: the library alone is the same.
#[cfg(all(feature = "proxy", not(feature = "service")))]
pub extern crate zlink_core as zlink;
#[cfg(feature = "service")]
pub use zlink;
pub mod godecode;
#[cfg(feature = "service")]
pub mod interfaces;
mod members;
pub mod pod;
pub mod podgen;
pub mod request;
#[cfg(feature = "service")]
pub mod request_line;
pub mod retry;
#[cfg(feature = "service")]
pub mod serving;
pub mod size;
pub mod stream;
pub mod system;
pub mod time;
pub mod transfer;
pub mod wait;
pub mod workload;
