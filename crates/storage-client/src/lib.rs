// SPDX-License-Identifier: Apache-2.0
//! The client of `org.velarx.Storage`: the [`velarx_graph::StorageDriver`]
//! trait over a unix socket, for a storage driver that is a program of its
//! own (`[storage] driver = "varlink"`).
//!
//! The interface is `interfaces/org.velarx.Storage.varlink` (the calls of the
//! driver) and `interfaces/org.velarx.StorageFeed.varlink` (what the engine
//! offers it during a pull), both made from the types of [`proto`] and
//! [`feed_proto`] by a test, and `docs/STORAGE.md` has the rules of version 1.
//! What this package does with them:
//!
//! * **One connection for each call**, and on each one `GetInfo` first: a
//!   `proto` other than ours is `ProtocolMismatch`, naming both.  A connection
//!   with no reply for the idle timeout is `TimedOut`, naming the call; a
//!   connection that is refused or gone is `Unavailable`; a connect that is
//!   not accepted and a request that is not read within the timeout are
//!   `TimedOut` too.  The socket must be served by the engine's user or root
//!   (`SO_PEERCRED`).
//! * **Roots**: a `directory` root is a path relative to the work directory
//!   of the store (`<graph root>/varlink/work`, the engine's), which the
//!   monitor takes as its base: a driver cannot name another directory.
//! * **Long calls** (`CreateRoot`, `CreateImageVolume`, `BeginPull`,
//!   `Collect`, `Repair`, `Check`) are made with `more` through
//!   `velarx_graph::longcall::wait_for_call`: the call lasts as long as the
//!   driver sends progress.  `ReadObjects` is read through
//!   `velarx_graph::longcall::read_pipe_ranges` (the reply of a range before
//!   its bytes, the pipe polled under the deadline).
//! * **The limits** the driver states are applied: a request over one is an
//!   error, never sent; the ranges of a read are split by
//!   `velarx_graph::read_objects_in_batches`.
//! * **Descriptors** are named by position in the reply (`Mounted.fd`,
//!   `velarx_graph::assign_fds`); the keep set of a collection is a sealed
//!   memory file; the feed is the end of a socket pair.
//! * **Errors** a driver sends are `DriverError::from_wire`'s (an error name
//!   not known is a `Storage` error that carries it), and a value of an enum
//!   in a reply that is not known is a `Storage` error that names it.
//! * **The pull** is driven by the driver through the feed
//!   ([`feed::Feed`]); the diff id of each layer is proved by reading it back
//!   (`velarx_graph::prove_with`) before the engine's check and before
//!   `Commit`.  A `Fetch` is written by the engine's fetching code into the
//!   files the driver passed (`velarx_content::pull::sink::FilesSink`), and the
//!   driver is told as the objects become whole; a layer with no table of
//!   contents is refused before `BeginPull`.
//!
//! This package depends on no service of the engine (`velarx-core`), and no
//! engine option selects it yet.

pub mod conn;
pub mod convert;
mod driver;
#[cfg(test)]
mod fake;
pub mod feed;
pub mod feed_proto;
#[cfg(test)]
#[allow(
    dead_code,
    reason = "the methods are signatures to describe, nothing calls them"
)]
mod interface;
pub mod proto;
pub mod request;
#[cfg(test)]
mod tests;

pub use conn::Link;
pub use driver::{Inner, Options, VarlinkDriver};

/// `RemoveRoot`: the service removes the writable layer of `container` in
/// the store `store`, without a driver (the monitor of an `--rm` container
/// does this from its own thread).  Nothing is an error when it is not there.
pub fn remove_root(link: &Link, store: &str, container: &str) -> velarx_graph::DriverResult<()> {
    const NAME: &str = "varlink";
    let (mut session, _) = conn::Session::connect(link, NAME, None)?;
    session.call(
        &request::RemoveRoot(request::OfContainer { store, container }),
        &[],
    )?;
    Ok(())
}
