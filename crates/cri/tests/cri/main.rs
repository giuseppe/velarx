// SPDX-License-Identifier: Apache-2.0
//! The mapping of the CRI to the engine, with a mock engine: no daemon, no
//! sleeps.

mod internals;
mod mock;
mod podcheckpoint;
mod runtime;
mod streaming;
