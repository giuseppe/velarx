// SPDX-License-Identifier: Apache-2.0
//! The integration tests, in one test binary: one link of the crate
//! instead of one per file, and libtest runs the tests of all the areas in
//! parallel.  Each area is a module, named as the file was when it was a
//! target of its own, so that `cargo test pull_tests::` runs one area.
//! Tests must not change state of the process (environment, current
//! directory, signal dispositions): the other areas run next to them.

mod common;
mod monitor_common;

mod api_tests;
mod archive_tests;
mod auth_tests;
mod bridge_tests;
mod build_tests;
mod cdi_tests;
mod check_tests;
mod commit_tests;
mod completer_tests;
mod composefs_conformance_tests;
mod confine_tests;
mod container_tests;
mod cp_tests;
mod daemon_tests;
mod db_tests;
mod dircache_tests;
mod fetcher_tests;
mod fuse_bench;
mod fuzz_corpus;
mod gc_tests;
mod image_server_tests;
mod integration_tests;
mod lazy_tests;
mod manifest_tests;
mod merged_tree_tests;
mod monitor_mount_fd_tests;
mod monitor_tests;
mod pod_tests;
mod podlogs_tests;
mod pull_tests;
mod push_tests;
mod pusher_tests;
mod registries_tests;
mod remote_tests;
mod seccomp_tests;
mod signing_tests;
mod sources_tests;
mod spec_tests;
mod store_service_tests;
mod store_tests;
mod supervised_monitor_tests;
mod toc_identity_tests;
mod userns_tests;
