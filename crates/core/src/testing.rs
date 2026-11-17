// SPDX-License-Identifier: Apache-2.0
//! Helpers of the unit tests of this package.

/// Run `f` to its end on a runtime of this thread alone.  For the body of
/// `velarx_base::testing::in_child`, which has no runtime of its own (a
/// test that expects a descriptor to be closed or a lock to be free after
/// a drop cannot run beside the tests that fork: they hold a copy of every
/// descriptor until their exec).
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}
