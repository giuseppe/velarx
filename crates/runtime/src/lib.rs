// SPDX-License-Identifier: Apache-2.0
//! The runtime of the engine, below its services: the container runtime
//! (the OCI runtime, the spec, the bundle), the monitor of a container, the
//! networks, the user namespaces and the CDI devices.  `velarx-core` (the
//! services) is above it and re-exports these modules under its own name.

pub mod cdi;
pub mod container;
pub mod fsdir;
#[cfg(feature = "fuse")]
pub mod imagemount;
#[cfg(feature = "fuse")]
pub mod imageserver;
pub mod manager;
pub mod monitor;
pub mod network;
pub mod pods;
pub mod settle;
pub mod userns;

/// Run the file work of an async function (the calls of `std::fs` it
/// makes: a recursive remove, a walk, a copy) in one turn of the blocking
/// pool, so that the async threads never wait for a disk.
pub async fn off_thread<R: Send + 'static>(
    work: impl FnOnce() -> std::io::Result<R> + Send + 'static,
) -> std::io::Result<R> {
    // (the answer comes back in a slot: the pool runs one type of task for
    // every caller, where each type of answer would be a task type of its
    // own, about a kilobyte of code each)
    let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
    let answer = slot.clone();
    turn(Box::new(move || {
        let done = work();
        if let Ok(mut a) = answer.lock() {
            *a = Some(done);
        }
    }))
    .await?;
    let done = slot.lock().ok().and_then(|mut a| a.take());
    done.unwrap_or_else(|| Err(std::io::Error::other("the blocking work gave no answer")))
}

/// One turn of the blocking pool.
async fn turn(work: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(std::io::Error::other)
}
