// SPDX-License-Identifier: Apache-2.0
//! `velarx-api`: the REST API as a frontend of the
//! engine.
//!
//! The program decodes HTTP, calls the engine through the varlink interface
//! `org.velarx.Engine` ([`velarx_proto`]), and encodes the answers.  It
//! has no engine in it: no storage, no database, no services, no credentials.
//! It listens on a unix socket (the one systemd passes, or its own), and on
//! TCP when asked to, and it confines itself ([`velarx_proto::confine`]) before
//! it serves.

pub mod config;
pub mod engine;
pub mod listen;
pub mod podman;
pub mod serve;
pub mod tls;
