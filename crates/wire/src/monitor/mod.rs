// SPDX-License-Identifier: Apache-2.0
//! The interface of the monitor of a container (`org.velarx.Monitor`) and the
//! client side of it: what the engine and the `logs`, `attach` and `exec` of
//! the command line speak to it.  The monitor itself (the server) is in
//! velarx-core.

pub mod client;
pub mod health;
pub mod iface;
pub mod journal;
pub mod logfmt;
pub mod logsel;
pub mod logwatch;
pub mod proto;
pub mod rootid;
pub mod sys;
