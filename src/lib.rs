// SPDX-License-Identifier: Apache-2.0
//! Velarx - A container engine for Linux that runs OCI images
//!
//! This library provides the core functionality for the Velarx container runtime.

#[cfg(feature = "engine")]
pub mod api;
pub mod cli;
pub mod client;
#[cfg(feature = "engine")]
pub mod daemon;
#[cfg(feature = "engine")]
pub mod engine;
#[cfg(feature = "engine")]
pub mod engine_service;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
pub mod preserve_fds;

#[cfg(test)]
mod testing;
