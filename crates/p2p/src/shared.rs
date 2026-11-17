// SPDX-License-Identifier: Apache-2.0
//! What a question to the peers answered, kept for a while and asked once at a
//! time.
//!
//! A lookup in the DHT takes a round of queries to other peers (up to
//! seconds), a round of probes a round trip to each of up to eight peers;
//! the groups of a pull (up to four at once for a layer) ask the same thing
//! for the same layer.  One caller asks, the ones that come meanwhile wait
//! for its answer, and an answer is kept for as long as it says
//! ([`Keep`]); at most [`MAX_KEYS`] keys are.

use libp2p::PeerId;
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::Instant;

pub const TTL: Duration = Duration::from_secs(30);
pub const EMPTY_TTL: Duration = Duration::from_secs(5);
pub const MAX_KEYS: usize = 4096;

/// What of an answer is kept, and for how long: nothing for an answer that
/// is not worth keeping.
pub trait Keep: Clone {
    fn keep(&self) -> Option<(Self, Duration)>;
}

/// The providers of a key: an empty answer is kept for less (a provider may
/// announce it soon).
impl Keep for Vec<PeerId> {
    fn keep(&self) -> Option<(Self, Duration)> {
        Some((self.clone(), if self.is_empty() { EMPTY_TTL } else { TTL }))
    }
}

type Cells<V> = Mutex<HashMap<String, Arc<OnceCell<V>>>>;

/// The answers to the questions of the peers, by key.
pub struct Shared<V: Keep> {
    /// Until when each answer is kept
    entries: Mutex<HashMap<String, (Instant, V)>>,
    /// The questions under way: whoever asks for a key meanwhile waits for them
    asking: Cells<V>,
}

/// The providers the DHT gave for a key.
pub type ProviderCache = Shared<Vec<PeerId>>;

impl<V: Keep> Default for Shared<V> {
    fn default() -> Self {
        Self {
            entries: Mutex::default(),
            asking: Mutex::default(),
        }
    }
}

/// Removes the entry of a question when the last of its callers is done.
struct Leave<'a, V> {
    asking: &'a Cells<V>,
    key: &'a str,
    cell: Option<Arc<OnceCell<V>>>,
}

impl<V> Drop for Leave<'_, V> {
    fn drop(&mut self) {
        let Some(cell) = self.cell.take() else {
            return;
        };
        // (the callers take and let go of the entry under the lock: two
        // counts, the map's and this one, and no other caller waits for it;
        // an answer that is in is kept by the cache, not here)
        let mut asking = self.asking.lock().unwrap_or_else(|e| e.into_inner());
        if asking.get(self.key).is_some_and(|c| {
            Arc::ptr_eq(c, &cell) && (cell.initialized() || Arc::strong_count(&cell) <= 2)
        }) {
            asking.remove(self.key);
        }
        drop(cell);
    }
}

impl<V: Keep> Shared<V> {
    /// The answer for `key`: the kept one, else the answer of `ask`.
    /// One `ask` runs at a time for a key; a caller that comes while it runs
    /// waits for its answer.  The answer is kept as it says.  When the one
    /// that asks goes away, the next caller asks.
    pub async fn lookup(&self, key: &str, ask: impl Future<Output = V>) -> V {
        if let Some(answer) = self.get(key) {
            return answer;
        }
        let cell = self
            .asking
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.to_string())
            .or_default()
            .clone();
        // (the entry goes with the last caller of it, also one that goes away
        // before an answer: none is left behind for a key nobody asks again)
        let leave = Leave {
            asking: &self.asking,
            key,
            cell: Some(cell),
        };
        let cell = leave.cell.as_ref().expect("the question's cell");
        cell.get_or_init(|| async {
            // (an asker that was done between the look above and the cell
            // left its answer and no cell: not asked twice)
            if let Some(answer) = self.get(key) {
                return answer;
            }
            let answer = ask.await;
            self.put(key, &answer);
            answer
        })
        .await
        .clone()
    }

    /// The answer for `key`, if it is known and recent.
    pub fn get(&self, key: &str) -> Option<V> {
        self.get_at(key, Instant::now())
    }

    fn get_at(&self, key: &str, now: Instant) -> Option<V> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let (until, answer) = entries.get(key)?;
        if now < *until {
            return Some(answer.clone());
        }
        entries.remove(key);
        None
    }

    pub fn put(&self, key: &str, answer: &V) {
        self.put_at(key, answer, Instant::now())
    }

    fn put_at(&self, key: &str, answer: &V, now: Instant) {
        let Some((answer, ttl)) = answer.keep() else {
            return;
        };
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_KEYS && !entries.contains_key(key) {
            entries.retain(|_, (until, _)| now < *until);
            if entries.len() >= MAX_KEYS {
                // the one that expires first goes
                if let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, (until, _))| *until)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(key.to_string(), (now + ttl, answer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_kept_for_a_while() {
        let c = ProviderCache::default();
        let t0 = Instant::now();
        let peer = PeerId::random();
        assert!(c.get_at("a", t0).is_none());
        c.put_at("a", &vec![peer], t0);
        assert_eq!(c.get_at("a", t0 + Duration::from_secs(1)), Some(vec![peer]));
        assert!(c.get_at("a", t0 + TTL).is_none());
        // an empty answer, for less
        c.put_at("b", &vec![], t0);
        assert_eq!(c.get_at("b", t0 + Duration::from_secs(1)), Some(vec![]));
        assert!(c.get_at("b", t0 + EMPTY_TTL).is_none());
    }

    #[tokio::test]
    async fn callers_that_come_while_a_lookup_runs_wait_for_its_answer() {
        let c = ProviderCache::default();
        let peer = PeerId::random();
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let ask = || async {
            asked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tokio::task::yield_now().await;
            vec![peer]
        };
        let (a, b, d) = tokio::join!(
            c.lookup("k", ask()),
            c.lookup("k", ask()),
            c.lookup("k", ask())
        );
        assert_eq!((a, b, d), (vec![peer], vec![peer], vec![peer]));
        assert_eq!(asked.load(std::sync::atomic::Ordering::Relaxed), 1);
        // (and it is kept)
        assert_eq!(c.lookup("k", ask()).await, vec![peer]);
        assert_eq!(asked.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert!(c.asking.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn when_the_caller_that_asks_goes_away_the_next_asks() {
        let c = ProviderCache::default();
        let peer = PeerId::random();
        let mut first = Box::pin(c.lookup("k", std::future::pending()));
        let second = c.lookup("k", async { vec![peer] });
        // (the first is started and left behind)
        assert!(futures::poll!(first.as_mut()).is_pending());
        drop(first);
        assert_eq!(second.await, vec![peer]);
        assert!(c.asking.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_lookup_nobody_waits_for_any_more_leaves_nothing() {
        let c = ProviderCache::default();
        let mut first = Box::pin(c.lookup("k", std::future::pending()));
        assert!(futures::poll!(first.as_mut()).is_pending());
        drop(first);
        assert!(c.asking.lock().unwrap().is_empty());
    }

    #[test]
    fn the_keys_are_bounded() {
        let c = ProviderCache::default();
        let t0 = Instant::now();
        for i in 0..MAX_KEYS + 10 {
            c.put_at(
                &format!("k{i}"),
                &vec![],
                t0 + Duration::from_millis(i as u64),
            );
        }
        assert!(c.entries.lock().unwrap().len() <= MAX_KEYS);
        // the newest is there, the oldest not
        assert!(c.get_at(&format!("k{}", MAX_KEYS + 9), t0).is_some());
        assert!(c.get_at("k0", t0).is_none());
    }
}
