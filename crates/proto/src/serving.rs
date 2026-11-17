// SPDX-License-Identifier: Apache-2.0
//! What a server of the REST API shares, in the engine and in `velarx-api`:
//! who may connect to its unix socket, and the connections being served.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// Who may use a unix socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peers {
    /// Whoever can connect (the permissions of the socket decide).
    Any,
    /// The user of the process and root only (`SO_PEERCRED`): a rootless
    /// daemon's socket, mode 0600.
    Owner,
}

/// Check the client of a unix socket: its uid and pid are logged, and an
/// [`Peers::Owner`] socket serves only its user and root.
pub fn check_peer(stream: &tokio::net::UnixStream, peers: Peers) -> std::io::Result<()> {
    let cred = stream.peer_cred()?;
    tracing::debug!(
        "API connection from uid {} pid {}",
        cred.uid(),
        cred.pid()
            .map_or_else(|| "?".to_string(), |p| p.to_string())
    );
    match peers {
        Peers::Any => Ok(()),
        Peers::Owner if crate::trusted_uid(cred.uid()) => Ok(()),
        Peers::Owner => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("connection from uid {} refused", cred.uid()),
        )),
    }
}

/// The connections being served and when the last one ended: what the idle
/// timeout looks at.
#[derive(Debug)]
pub struct Activity {
    active: watch::Sender<usize>,
    last: Mutex<Instant>,
    /// The server stops: the connections end after their requests in
    /// progress (keep-alive ones at once)
    stopping: watch::Sender<bool>,
}

impl Default for Activity {
    fn default() -> Self {
        Self {
            active: watch::channel(0).0,
            last: Mutex::new(Instant::now()),
            stopping: watch::channel(false).0,
        }
    }
}

impl Activity {
    /// The connections open.
    pub fn connections(&self) -> usize {
        *self.active.borrow()
    }

    /// Have every connection end once its request in progress is answered.
    pub fn stop(&self) {
        self.stopping.send_replace(true);
    }

    /// Return when no connection is open, or after `timeout`: whether all
    /// ended.
    pub async fn drained(&self, timeout: Duration) -> bool {
        let mut open = self.active.subscribe();
        tokio::time::timeout(timeout, open.wait_for(|n| *n == 0))
            .await
            .is_ok_and(|r| r.is_ok())
    }

    /// Return once a connection of the ones open now ended (its descriptor
    /// is free again); never when none is open: the caller bounds the wait.
    pub async fn one_ended(&self) {
        let mut open = self.active.subscribe();
        let now = *open.borrow_and_update();
        if now == 0 {
            return std::future::pending().await;
        }
        let _ = open.wait_for(|n| *n < now).await;
    }

    /// Return once no connection was open for `limit`.
    pub async fn idle(&self, limit: Duration) {
        let mut open = self.active.subscribe();
        loop {
            if open.wait_for(|n| *n == 0).await.is_err() {
                return std::future::pending().await;
            }
            let Some(since) = self.idle_since() else {
                continue;
            };
            tokio::select! {
                () = tokio::time::sleep_until(since + limit) => {
                    if self.idle_for().is_some_and(|d| d >= limit) {
                        return;
                    }
                }
                _ = open.changed() => {}
            }
        }
    }

    fn touch(&self) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }

    /// Count a connection until the guard goes.
    pub fn begin(self: &Arc<Self>) -> Active {
        self.active.send_modify(|n| *n += 1);
        self.touch();
        Active(self.clone())
    }

    fn idle_since(&self) -> Option<Instant> {
        if self.connections() > 0 {
            return None;
        }
        Some(*self.last.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// How long nothing was served: `None` while a connection is open.
    pub fn idle_for(&self) -> Option<Duration> {
        self.idle_since().map(|t| t.elapsed())
    }
}

/// An open connection, counted while it lives.
pub struct Active(Arc<Activity>);

impl Active {
    /// Told when the server stops.
    pub fn stopping(&self) -> watch::Receiver<bool> {
        self.0.stopping.subscribe()
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.0.touch();
        self.0.active.send_modify(|n| *n -= 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn activity_is_idle_without_connections() {
        let activity = Arc::new(Activity::default());
        assert!(activity.idle_for().is_some());
        let c = activity.begin();
        let d = activity.begin();
        assert_eq!(activity.idle_for(), None);
        drop(c);
        assert_eq!(activity.idle_for(), None);
        drop(d);
        assert!(activity.idle_for().unwrap() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn room_is_made_by_a_connection_that_ends() {
        let activity = Arc::new(Activity::default());
        // none open: nothing will end (the caller bounds the wait)
        let none = tokio::time::timeout(Duration::from_secs(60), activity.one_ended());
        assert!(none.await.is_err());
        let one = activity.begin();
        let _two = activity.begin();
        let a = activity.clone();
        let waiting = tokio::spawn(async move { a.one_ended().await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(one);
        waiting.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn drained_waits_for_the_last_connection() {
        let activity = Arc::new(Activity::default());
        assert!(activity.drained(Duration::from_secs(1)).await);
        let c = activity.begin();
        assert!(!activity.drained(Duration::from_secs(1)).await);
        let a = activity.clone();
        let waiting = tokio::spawn(async move { a.drained(Duration::from_secs(60)).await });
        tokio::task::yield_now().await;
        drop(c);
        assert!(waiting.await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_counts_from_the_last_connection() {
        let activity = Arc::new(Activity::default());
        let limit = Duration::from_secs(10);
        let start = Instant::now();
        let c = activity.begin();
        let a = activity.clone();
        let waiting = tokio::spawn(async move {
            a.idle(limit).await;
            Instant::now()
        });
        tokio::time::sleep(Duration::from_secs(100)).await;
        assert!(!waiting.is_finished(), "left with a connection open");
        drop(c);
        let left = waiting.await.unwrap();
        assert!(left - start >= Duration::from_secs(100) + limit, "{left:?}");
    }
}
