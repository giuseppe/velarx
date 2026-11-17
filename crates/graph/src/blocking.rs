// SPDX-License-Identifier: Apache-2.0
//! Blocking work called from async code that cannot await it.

/// Run `work`, which blocks (a file lock, a walk of a directory, many small
/// reads), from code that is on an async thread and cannot await it: the
/// other tasks of the thread move to another one meanwhile.  Where a
/// function can await, the engine's `off_thread` is the way; this is for the
/// calls that are not async, such as the event hub's `emit`, made from about
/// fifty handlers, and the sync methods of a storage driver.  (A runtime of
/// one thread, as in the tests, has nowhere to move them to and runs `work`
/// in place.)
pub fn blocking<R>(work: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `blocking` runs its work wherever it is called: on a worker of the
    /// engine's runtime, in the blocking pool, on a runtime of one thread
    /// (where `block_in_place` would panic) and outside of any runtime.
    #[test]
    fn blocking_works_on_every_kind_of_thread() {
        assert_eq!(blocking(|| 1), 1);
        let one = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert_eq!(one.block_on(async { blocking(|| 2) }), 2);
        let many = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .build()
            .unwrap();
        let on_worker = many.block_on(async { tokio::spawn(async { blocking(|| 3) }).await });
        assert_eq!(on_worker.unwrap(), 3);
        let in_pool = many.block_on(async { tokio::task::spawn_blocking(|| blocking(|| 4)).await });
        assert_eq!(in_pool.unwrap(), 4);
        assert_eq!(many.block_on(async { blocking(|| 5) }), 5);
    }
}
