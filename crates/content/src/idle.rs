// SPDX-License-Identifier: Apache-2.0
//! The silence bound of a call to a fetcher or a pusher: the one helper both
//! walkers use.  A party that says nothing for its idle time (`idle_ms` of
//! its `Open`) is the party that failed, as `transient`.

use crate::fetcher::fetch_client::CallError;
use std::time::Duration;

/// The error of a call that got no reply for `idle`.
pub fn silent(idle: Duration) -> CallError {
    CallError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("silent for {} ms", idle.as_millis()),
    ))
}

/// Whether `e` is the silence of [`within`].
pub fn is_silent(e: &CallError) -> bool {
    matches!(e, CallError::Io(io) if io.kind() == std::io::ErrorKind::TimedOut)
}

/// `call`, which ends with the error of [`silent`] when it says nothing for
/// `idle`.
pub async fn within<T>(
    idle: Duration,
    call: impl std::future::Future<Output = Result<T, CallError>>,
) -> Result<T, CallError> {
    tokio::time::timeout(idle, call)
        .await
        .unwrap_or_else(|_| Err(silent(idle)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call that outlives its idle time is the error of silence, and one
    /// that answers is not.
    #[tokio::test(start_paused = true)]
    async fn a_silent_call_ends_with_the_silence() {
        let idle = Duration::from_secs(5);
        let late = within::<()>(idle, std::future::pending()).await;
        assert!(is_silent(&late.unwrap_err()));
        assert_eq!(within(idle, async { Ok(7) }).await.unwrap(), 7);
    }
}
