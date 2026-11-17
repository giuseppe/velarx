// SPDX-License-Identifier: Apache-2.0
//! What the command line (the thin client included) and the engine
//! exchange and parse the same way: the requests and the wire types of the
//! services, the syntax of the container options and of the network
//! addresses, and the Containerfile.  Blocking code only: no async runtime,
//! no database, no TLS.

pub mod addr;
pub mod buildopts;
pub mod chain;
pub mod cp;
pub mod events;
#[cfg(any(test, feature = "test-support"))]
pub mod logcapture;
pub mod logging;
pub mod monitor;
pub mod options;
pub mod parse;
pub mod proctitle;
pub mod redact;
pub mod request;
pub mod sbom;
pub mod sdbus;
pub mod sdnotify;
pub mod sparse;
pub mod text;
pub mod varlink;
pub mod wire;
