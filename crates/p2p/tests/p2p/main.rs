// SPDX-License-Identifier: Apache-2.0
//! The tests of the P2P service, in one test binary like those of the
//! engine (`tests/integration`), with the same registry and services
//! (`common`): one link, and libtest runs the areas in parallel.  Tests
//! must not change state of the process (environment, current directory,
//! signal dispositions).

#[path = "../../../../tests/integration/common.rs"]
mod common;

mod announce_tests;
mod authority_tests;
mod dial_tests;
mod exchange_tests;
mod fuzz_corpus_tests;
mod hygiene_tests;
mod liveness_tests;
mod lookup_tests;
mod overlay_helper_tests;
mod overlay_node_tests;
mod p2p_node_tests;
mod p2p_sandbox_tests;
mod p2p_sources_tests;
mod scale_tests;
mod support;
