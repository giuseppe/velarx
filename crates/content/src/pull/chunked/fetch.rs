// SPDX-License-Identifier: Apache-2.0
use super::*;

/// Hand a chunk another file of the store holds to the workers: wait for
/// memory and a worker, then copy, check and write it on a blocking thread.
pub(super) async fn dispatch_local(
    pace: &Pace,
    shared: &Arc<Shared>,
    handles: &mpsc::UnboundedSender<tokio::task::JoinHandle<()>>,
    idx: usize,
) {
    if shared.failed() {
        return;
    }
    let size = shared.plan.chunks[idx].size;
    let Ok(memory) = pace.reserve(size).await else {
        shared.set_error(fail("the pull was cancelled"));
        return;
    };
    let Ok(worker) = pace.workers.clone().acquire_owned().await else {
        shared.set_error(fail("the pull was cancelled"));
        return;
    };
    let sh = shared.clone();
    let handle = tokio::task::spawn_blocking(move || {
        let _memory = memory;
        let _worker = worker;
        if let Err(e) = process_local(&sh, idx) {
            sh.set_error(e);
        }
    });
    let _ = handles.send(handle);
}
