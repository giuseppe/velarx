// SPDX-License-Identifier: Apache-2.0
//! The Bloom filter of the layers a node holds, told to its peers.
//!
//! A node that pulls a layer asks "who has it?"; without an answer it asks
//! its neighbours one by one.  Each node therefore tells its peers a filter
//! of the keys of the layers it may give ([`velarx_types::LayerKey`], only
//! those the store service lets be shared): a peer tests the key of the layer
//! it wants against the filter of each neighbour and asks the ones that say
//! "maybe", and skips the ones that say "no".  A false positive costs a
//! request that is answered "I do not have it"; the bytes are checked by the
//! engine as always, so nothing here is trusted for more than whom to ask.
//!
//! * The sender ([`Advertiser`]) keeps the keys and the filter.  A filter has a
//!   size in steps (a capacity of a power of two keys, at least
//!   [`MIN_CAPACITY`]) and a number of hashes that follow from the target
//!   false-positive rate, so it is not rebuilt for each layer; it is rebuilt
//!   (and sent whole under a new version) when a layer goes (a Bloom filter
//!   cannot delete) or the capacity is exceeded.  What was added since the
//!   last message is sent as a delta of 8 bytes per key when that is smaller
//!   than the filter.  The caller coalesces the messages on a timer
//!   ([`run`]); a new peer is sent the whole filter at once, and every peer
//!   one every [`REFRESH`], which repairs a message that was lost.
//! * The receiver ([`Received`]) validates what a peer sent: bits that
//!   decode into whole words and a number of hashes.  What is refused is
//!   dropped: the peer is then asked as one with no filter (probed, as
//!   before filters).
//!
//! A filter never says "no" for a layer the sender told it holds (no false
//! negative), whatever is lost or comes out of order:
//!
//! * the messages of one run of the sender carry its *epoch* (random when the
//!   service starts): a whole filter of another epoch replaces the one held
//!   whatever its version (a node that restarted with its identity, while
//!   the peer still holds a connection of the run before, starts again at
//!   version 1), and a delta of another epoch makes the filter held say
//!   "maybe" or "not known", never "no", until the whole filter of that
//!   epoch comes;
//! * a delta that does not follow the version held (one went missing or
//!   comes later: each message is its own stream, and a small delta can
//!   overtake the whole filter sent just before it) is added all the same,
//!   and the filter says "not known" instead of "no" until a whole filter
//!   of the last version heard of comes;
//! * a message the sender could not deliver (the request failed while the
//!   peer is still connected) is followed by the whole filter to that peer
//!   at once, and every peer is sent the whole filter every [`REFRESH`].
//!
//! The filter is not a list: a member can test whether a node holds a layer
//! it already knows the key of, which a probe allows too.

use crate::entropy::Entropy;
use crate::gossip::GossipMessage;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::Instant;

/// The keys a filter is sized for at least.
pub const MIN_CAPACITY: usize = 256;
/// The hashes of a filter, at most.
pub const MAX_HASHES: u8 = 16;
/// The keys one delta carries, at most (more are sent as a whole filter).
pub const MAX_DELTA_KEYS: usize = 8192;
/// How often a node sends each peer its whole filter, whatever changed (each
/// time a random part of a fifth more or less: nodes that started together
/// do not all send at once).
pub const REFRESH: Duration = Duration::from_secs(600);
/// How long a filter is believed without an update (a peer that stopped
/// sending them is asked as one with no filter).
pub const TTL: Duration = Duration::from_secs(3 * 600);
/// The questions asked after a filter said "maybe" before it is judged, and
/// the share of them that were wrong beyond which it is not believed.
const JUDGED_AFTER: u64 = 8;

/// What a node decides about its filter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Config {
    /// Tell the peers the layers this node has
    pub advertise: bool,
    /// The false-positive rate the filter is sized for
    pub fpr: f64,
    /// The largest filter sent, in bytes
    pub max_bytes: usize,
    /// The least time between two updates sent to the peers
    pub interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            advertise: true,
            fpr: 0.01,
            max_bytes: 256 << 10,
            interval: Duration::from_secs(2),
        }
    }
}

/// The key of a layer in a filter: the first bytes of the hash of its text.
pub fn key_of(layer: &str) -> u64 {
    let hash = sha2::Sha256::digest(layer.as_bytes());
    u64::from_le_bytes(hash[..8].try_into().expect("8 bytes"))
}

fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// A Bloom filter of 64-bit keys.  Two filters with another salt put the
/// same key at other places, so a key that is a false positive for one peer
/// is not for the next.
#[derive(Clone, PartialEq, Eq)]
pub struct Bloom {
    salt: u64,
    hashes: u8,
    words: Vec<u64>,
    ones: u64,
    keys: u32,
}

impl Bloom {
    /// The hashes the rate `fpr` needs.
    pub fn hashes_for(fpr: f64) -> u8 {
        ((-fpr.ln() / std::f64::consts::LN_2).round() as i64).clamp(1, MAX_HASHES as i64) as u8
    }

    /// The bits for one key at the rate `fpr`: -ln(p) / ln(2)^2.
    pub fn bits_per_key(fpr: f64) -> f64 {
        -fpr.ln() / (std::f64::consts::LN_2 * std::f64::consts::LN_2)
    }

    /// The keys a filter of `keys` keys is sized for: a power of two, so it
    /// is not rebuilt for each key.
    pub fn capacity_for(keys: usize) -> usize {
        keys.max(MIN_CAPACITY).next_power_of_two()
    }

    /// An empty filter for `capacity` keys at the rate `fpr`, at most
    /// `max_bytes` big.
    pub fn new(capacity: usize, fpr: f64, max_bytes: usize, salt: u64) -> Self {
        let bits = (capacity as f64 * Self::bits_per_key(fpr)).ceil() as usize;
        let words = bits.div_ceil(64).clamp(1, (max_bytes / 8).max(1));
        Self {
            salt,
            hashes: Self::hashes_for(fpr),
            words: vec![0; words],
            ones: 0,
            keys: 0,
        }
    }

    fn bits(&self) -> u64 {
        self.words.len() as u64 * 64
    }

    /// The places of `key`: double hashing of one mixed value.
    fn places(&self, key: u64) -> impl Iterator<Item = (usize, u64)> + '_ {
        let x = mix(key ^ self.salt);
        let (h1, h2) = (x as u32, (x >> 32) as u32 | 1);
        let bits = self.bits();
        (0..self.hashes as u32).map(move |i| {
            let g = h1.wrapping_add(i.wrapping_mul(h2)) as u64;
            let bit = (g * bits) >> 32;
            ((bit / 64) as usize, 1u64 << (bit % 64))
        })
    }

    pub fn insert(&mut self, key: u64) {
        let places: Vec<(usize, u64)> = self.places(key).collect();
        for (word, mask) in places {
            if self.words[word] & mask == 0 {
                self.words[word] |= mask;
                self.ones += 1;
            }
        }
        self.keys = self.keys.saturating_add(1);
    }

    /// Whether the filter says `key` may be in it.
    pub fn contains(&self, key: u64) -> bool {
        self.places(key)
            .all(|(word, mask)| self.words[word] & mask != 0)
    }

    /// The share of the bits that are set.
    pub fn fill(&self) -> f64 {
        self.ones as f64 / self.bits() as f64
    }

    /// The rate at which it says "maybe" to a key that is not in it, from
    /// its fill (not from what the sender claims).
    pub fn estimated_fpr(&self) -> f64 {
        self.fill().powi(self.hashes as i32)
    }

    pub fn bytes(&self) -> usize {
        self.words.len() * 8
    }

    pub fn hashes(&self) -> u8 {
        self.hashes
    }

    /// The keys it was told it has (a claim, when it is a peer's).
    pub fn keys(&self) -> u32 {
        self.keys
    }

    fn wire_bits(&self) -> String {
        let mut raw = Vec::with_capacity(self.bytes());
        for w in &self.words {
            raw.extend_from_slice(&w.to_le_bytes());
        }
        base64::engine::general_purpose::STANDARD.encode(raw)
    }
}

/// Why a filter, or a delta, was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Not a filter: bytes that do not decode, no bits, a number of hashes
    /// that is none or too many
    Malformed,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("malformed")
    }
}

/// The filter of a node, whole, as a message of the gossip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterFull {
    /// The run of the sender (random when its service starts): versions are
    /// compared within one epoch only
    pub epoch: u64,
    /// What the filter is a version of: it grows by one at each filter that
    /// replaces the one before and at each delta
    pub version: u64,
    pub salt: u64,
    pub hashes: u8,
    /// The keys the sender says it put in it
    pub keys: u32,
    /// The bits, as base64 of whole 64-bit words
    pub bits: String,
}

/// What was added to the filter of a version, as a message of the gossip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterDelta {
    /// The run of the sender, as in [`FilterFull::epoch`]
    pub epoch: u64,
    /// The version it applies to, and the one it makes
    pub from: u64,
    pub to: u64,
    /// The keys, as base64 of 64-bit numbers
    pub added: String,
}

/// What a node sends its peers of its layers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sent {
    pub fulls: u64,
    pub deltas: u64,
    pub bytes: u64,
}

/// What a node tells of its own filter: for `velarx p2p advertised`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Own {
    pub keys: usize,
    pub bytes: usize,
    pub hashes: u8,
    pub version: u64,
    pub estimated_fpr: f64,
    pub sent: Sent,
}

/// The layers this node holds and the filter that tells the peers of them.
pub struct Advertiser {
    config: Config,
    entropy: Entropy,
    /// This run of the node, told with every message
    epoch: u64,
    /// The layers (by their text) and their keys
    layers: HashMap<String, u64>,
    bloom: Bloom,
    version: u64,
    /// Added since the last message
    pending: Vec<u64>,
    /// The next update is a whole new filter: a layer went, or the capacity
    /// was exceeded
    rebuild: bool,
    /// A new peer was told the filter made again: the others are by the
    /// next update
    whole_due: bool,
    capacity: usize,
    sent: Sent,
}

impl Advertiser {
    pub fn new(config: Config, entropy: Entropy) -> Self {
        let capacity = Bloom::capacity_for(0);
        let bloom = Bloom::new(capacity, config.fpr, config.max_bytes, entropy.word());
        Self {
            config,
            epoch: entropy.word(),
            entropy,
            layers: HashMap::new(),
            bloom,
            version: 1,
            pending: Vec::new(),
            rebuild: false,
            whole_due: false,
            capacity,
            sent: Sent::default(),
        }
    }

    /// Whether this node tells its peers its layers.
    pub fn advertises(&self) -> bool {
        self.config.advertise
    }

    /// The layers held now.
    pub fn layers(&self) -> usize {
        self.layers.len()
    }

    /// The layers whose key is `layer` or that `keep` does not have, and
    /// that were held (what a snapshot of the store takes away).
    pub fn not_in(&self, keep: &[String]) -> Vec<String> {
        let keep: std::collections::HashSet<&String> = keep.iter().collect();
        self.layers
            .keys()
            .filter(|l| !keep.contains(l))
            .cloned()
            .collect()
    }

    /// `layers` are held: the ones that were not held before (the filter is
    /// to be sent if there are any).
    pub fn add(&mut self, layers: &[String]) -> Vec<String> {
        let mut new = Vec::new();
        for layer in layers {
            if velarx_types::LayerKey::parse(layer).is_none() || self.layers.contains_key(layer) {
                continue;
            }
            let key = key_of(layer);
            self.layers.insert(layer.clone(), key);
            self.bloom.insert(key);
            self.pending.push(key);
            new.push(layer.clone());
        }
        if self.layers.len() > self.capacity {
            self.rebuild = true;
        }
        new
    }

    /// `layers` are not held any more: the ones that were.  A filter cannot
    /// forget a key: the next update is a new filter.
    pub fn remove(&mut self, layers: &[String]) -> Vec<String> {
        let gone: Vec<String> = layers
            .iter()
            .filter(|l| self.layers.remove(*l).is_some())
            .cloned()
            .collect();
        self.rebuild |= !gone.is_empty();
        gone
    }

    fn build(&mut self) {
        self.capacity = Bloom::capacity_for(self.layers.len());
        let mut bloom = Bloom::new(
            self.capacity,
            self.config.fpr,
            self.config.max_bytes,
            self.entropy.word(),
        );
        for key in self.layers.values() {
            bloom.insert(*key);
        }
        self.bloom = bloom;
        self.pending.clear();
        self.rebuild = false;
        self.version += 1;
    }

    fn whole(&self) -> FilterFull {
        FilterFull {
            epoch: self.epoch,
            version: self.version,
            salt: self.bloom.salt,
            hashes: self.bloom.hashes,
            keys: self.bloom.keys,
            bits: self.bloom.wire_bits(),
        }
    }

    fn counted(&mut self, message: GossipMessage, full: bool) -> GossipMessage {
        self.sent.bytes += serde_json::to_vec(&message).map_or(0, |v| v.len() as u64);
        if full {
            self.sent.fulls += 1;
        } else {
            self.sent.deltas += 1;
        }
        message
    }

    /// The filter whole: what a new peer is told.  A filter that is to be
    /// made again (a layer went) is made now: the peer is not told what is
    /// gone.
    pub fn full(&mut self) -> Option<GossipMessage> {
        self.config.advertise.then(|| {
            if self.rebuild {
                self.build();
                self.whole_due = true;
            }
            let m = GossipMessage::LayerFilter(self.whole());
            self.counted(m, true)
        })
    }

    /// What the peers are told of what changed since the last update:
    /// nothing, a delta, or the filter whole.
    pub fn update(&mut self) -> Option<GossipMessage> {
        if !self.config.advertise {
            return None;
        }
        if self.rebuild || self.whole_due {
            if self.rebuild {
                self.build();
            }
            self.whole_due = false;
            let m = GossipMessage::LayerFilter(self.whole());
            return Some(self.counted(m, true));
        }
        if self.pending.is_empty() {
            return None;
        }
        if self.pending.len() > MAX_DELTA_KEYS || self.pending.len() * 8 >= self.bloom.bytes() {
            // (the filter is smaller than what was added: it goes whole)
            self.pending.clear();
            self.version += 1;
            let m = GossipMessage::LayerFilter(self.whole());
            return Some(self.counted(m, true));
        }
        let mut raw = Vec::with_capacity(self.pending.len() * 8);
        for key in self.pending.drain(..) {
            raw.extend_from_slice(&key.to_le_bytes());
        }
        let from = self.version;
        self.version += 1;
        let m = GossipMessage::LayerFilterDelta(FilterDelta {
            epoch: self.epoch,
            from,
            to: self.version,
            added: base64::engine::general_purpose::STANDARD.encode(raw),
        });
        Some(self.counted(m, false))
    }

    /// The time to the next whole filter sent to every peer: [`REFRESH`], a
    /// fifth more or less at random.
    pub fn next_refresh(&self) -> Duration {
        REFRESH.mul_f64(0.8 + 0.4 * self.entropy.unit())
    }

    pub fn own(&self) -> Own {
        Own {
            keys: self.layers.len(),
            bytes: self.bloom.bytes(),
            hashes: self.bloom.hashes,
            version: self.version,
            estimated_fpr: self.bloom.estimated_fpr(),
            sent: self.sent,
        }
    }
}

/// An advertiser and what wakes the task that sends its updates.
pub struct Advertisement {
    state: Mutex<Advertiser>,
    changed: Notify,
}

impl Advertisement {
    pub fn new(config: Config, entropy: Entropy) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Advertiser::new(config, entropy)),
            changed: Notify::new(),
        })
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut Advertiser) -> T) -> T {
        f(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// `layers` are held: the update is sent within the interval.  The ones
    /// that were not held before.
    pub fn add(&self, layers: &[String]) -> Vec<String> {
        let new = self.with(|a| a.add(layers));
        if !new.is_empty() {
            self.changed.notify_one();
        }
        new
    }

    /// `layers` are not held any more; the ones that were.
    pub fn remove(&self, layers: &[String]) -> Vec<String> {
        let gone = self.with(|a| a.remove(layers));
        if !gone.is_empty() {
            self.changed.notify_one();
        }
        gone
    }
}

/// Send the updates of `ad` with `send` (false: nobody to send to any more)
/// until `stop` is ready: a change is sent after `interval` (what changes meanwhile
/// goes with it, so a node that pulls 50 layers sends one update, not 50),
/// and the whole filter about every [`REFRESH`].
pub async fn run<F>(
    ad: Arc<Advertisement>,
    interval: Duration,
    stop: impl std::future::Future<Output = ()>,
    mut send: impl FnMut(GossipMessage) -> F,
) where
    F: std::future::Future<Output = bool>,
{
    let refresh = tokio::time::sleep(ad.with(|a| a.next_refresh()));
    tokio::pin!(stop, refresh);
    loop {
        let message = tokio::select! {
            _ = &mut stop => return,
            _ = ad.changed.notified() => {
                tokio::time::sleep(interval).await;
                ad.with(|a| a.update())
            }
            _ = &mut refresh => {
                refresh.as_mut().reset(Instant::now() + ad.with(|a| a.next_refresh()));
                ad.with(|a| a.full())
            }
        };
        if let Some(message) = message {
            if !send(message).await {
                return;
            }
        }
    }
}

/// The filter of one peer, and what this node saw of it.
pub struct Received {
    bloom: Option<Bloom>,
    /// The run of the sender the filter held is of, and its version
    epoch: u64,
    version: u64,
    /// The last version of that run heard of: when it is past `version`, a
    /// message is missing and the filter does not say "no"
    heard: u64,
    at: Instant,
    /// What it said "maybe" to that it then served, and that it did not have
    pub hits: u64,
    pub false_positives: u64,
    /// Updates refused, by what is told of the last
    pub refused: u64,
    pub last_refused: Option<Refused>,
}

/// What a filter says of a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    Maybe,
    No,
    /// No filter that is believed: the peer is asked as before filters
    Unknown,
}

impl Received {
    pub fn new(now: Instant) -> Self {
        Self {
            bloom: None,
            epoch: 0,
            version: 0,
            heard: 0,
            at: now,
            hits: 0,
            false_positives: 0,
            refused: 0,
            last_refused: None,
        }
    }

    pub fn bytes(&self) -> usize {
        self.bloom.as_ref().map_or(0, Bloom::bytes)
    }

    pub fn bloom(&self) -> Option<&Bloom> {
        self.bloom.as_ref()
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.at)
    }

    /// Whether what it said "maybe" to was wrong most of the time (after
    /// some answers): a peer that claims everything is not believed.
    fn distrusted(&self) -> bool {
        self.false_positives >= JUDGED_AFTER && self.false_positives > self.hits * 2
    }

    /// Whether its filter is believed: there is one, it is not too old and
    /// it was not wrong most of the time.
    pub fn believed(&self, now: Instant) -> bool {
        self.bloom.is_some() && self.age(now) <= TTL && !self.distrusted()
    }

    /// Whether a message of the peer is missing from the filter held (one
    /// was lost, comes later, or is of another run): its "no" is not
    /// believed then.
    pub fn behind(&self) -> bool {
        self.heard > self.version
    }

    /// What its filter says of `key`.
    pub fn says(&self, key: u64, now: Instant) -> Said {
        match &self.bloom {
            Some(b) if self.believed(now) => {
                if b.contains(key) {
                    Said::Maybe
                } else if self.behind() {
                    Said::Unknown
                } else {
                    Said::No
                }
            }
            _ => Said::Unknown,
        }
    }

    fn refuse(&mut self, why: Refused) -> Refused {
        self.bloom = None;
        self.refused += 1;
        self.last_refused = Some(why);
        why
    }

    /// A whole filter of the peer.
    pub fn full(&mut self, f: &FilterFull, now: Instant) -> Result<(), Refused> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&f.bits)
            .map_err(|_| Refused::Malformed)
            .and_then(|r| {
                if r.is_empty() || r.len() % 8 != 0 {
                    Err(Refused::Malformed)
                } else {
                    Ok(r)
                }
            });
        let raw = raw.map_err(|e| self.refuse(e))?;
        if f.hashes == 0 || f.hashes > MAX_HASHES {
            return Err(self.refuse(Refused::Malformed));
        }
        if f.epoch == self.epoch && f.version < self.version && self.bloom.is_some() {
            // (an older filter that came after a newer one)
            return Ok(());
        }
        let words: Vec<u64> = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_le_bytes(*c))
            .collect();
        let ones = words.iter().map(|w| w.count_ones() as u64).sum();
        let bloom = Bloom {
            salt: f.salt,
            hashes: f.hashes,
            words,
            ones,
            keys: f.keys,
        };
        if f.epoch != self.epoch {
            // (a new run of the sender: what was heard of the run before
            // does not count)
            self.epoch = f.epoch;
            self.heard = 0;
        }
        self.bloom = Some(bloom);
        self.version = f.version;
        self.heard = self.heard.max(f.version);
        self.at = now;
        Ok(())
    }

    /// What the peer added to its filter.
    pub fn delta(&mut self, d: &FilterDelta, now: Instant) -> Result<(), Refused> {
        if d.epoch != self.epoch {
            // (a new run of the sender whose whole filter has not come: the
            // one held may lack what that run holds, and says no "no" until
            // it comes; its keys are added all the same)
            self.epoch = d.epoch;
            self.version = 0;
            self.heard = d.to;
        } else if d.to <= self.version {
            // (what the filter held already has)
            return Ok(());
        }
        // (a delta that does not follow is a message missing: the filter
        // says no "no" until a whole one of the last version heard of)
        self.heard = self.heard.max(d.to);
        let Some(bloom) = self.bloom.as_mut() else {
            // (the whole filter is on its way, or was refused)
            return Ok(());
        };
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(&d.added) else {
            return Err(self.refuse(Refused::Malformed));
        };
        if raw.is_empty() || raw.len() % 8 != 0 {
            return Err(self.refuse(Refused::Malformed));
        }
        for key in raw.as_chunks::<8>().0 {
            bloom.insert(u64::from_le_bytes(*key));
        }
        if d.from == self.version {
            self.version = d.to;
        }
        self.at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layer(n: usize) -> String {
        format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(n.to_le_bytes()))
        )
    }

    fn layers(range: std::ops::Range<usize>) -> Vec<String> {
        range.map(layer).collect()
    }

    fn advertiser() -> Advertiser {
        Advertiser::new(Config::default(), Entropy::seeded(7))
    }

    fn full(m: GossipMessage) -> FilterFull {
        match m {
            GossipMessage::LayerFilter(f) => f,
            other => panic!("{other:?}"),
        }
    }

    /// The filter has no false negative, and says "maybe" to a layer it
    /// does not hold about as often as its rate says.
    #[test]
    fn a_filter_has_no_false_negative_and_the_rate_it_is_sized_for() {
        for (n, fpr) in [
            (300usize, 0.01f64),
            (5000, 0.01),
            (5000, 0.001),
            (20_000, 0.05),
        ] {
            let mut a = Advertiser::new(
                Config {
                    fpr,
                    ..Config::default()
                },
                Entropy::seeded(n as u64),
            );
            a.add(&layers(0..n));
            let mut r = Received::new(Instant::now());
            r.full(&full(a.full().unwrap()), Instant::now()).unwrap();
            let now = Instant::now();
            for l in layers(0..n) {
                assert_eq!(
                    r.says(key_of(&l), now),
                    Said::Maybe,
                    "{n} layers: a false negative"
                );
            }
            let tests = 200_000;
            let wrong = (n..n + tests)
                .filter(|i| r.says(key_of(&layer(*i)), now) == Said::Maybe)
                .count();
            let measured = wrong as f64 / tests as f64;
            eprintln!(
                "{n} layers at {fpr}: {} bytes ({:.1} bits a key), {} hashes, measured {measured:.4}, estimated {:.4}",
                a.own().bytes,
                a.own().bytes as f64 * 8.0 / n as f64,
                a.own().hashes,
                a.own().estimated_fpr
            );
            // (a filter is sized for a power of two of keys: it is at its
            // rate when full, below it before)
            assert!(measured <= fpr * 1.5, "{measured} for {fpr}");
        }
    }

    /// A filter is rebuilt when the capacity is exceeded or a layer goes, not
    /// for each layer, and a delta applies to the version it follows.
    #[test]
    fn what_was_added_is_a_delta_and_what_went_is_a_new_filter() {
        let mut a = advertiser();
        a.add(&layers(0..1000));
        let now = Instant::now();
        let mut r = Received::new(now);
        // (the first update of a node that holds 1000 layers: the filter is
        // smaller than the keys it would send)
        let whole = full(a.update().unwrap());
        r.full(&whole, now).unwrap();
        assert!(a.update().is_none());
        // some layers: a delta of 8 bytes a key
        a.add(&layers(1000..1010));
        let Some(GossipMessage::LayerFilterDelta(d)) = a.update() else {
            panic!("a delta");
        };
        assert_eq!((d.from, d.to), (whole.version, whole.version + 1));
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&d.added)
                .unwrap()
                .len(),
            80
        );
        r.delta(&d, now).unwrap();
        for l in layers(0..1010) {
            assert_eq!(r.says(key_of(&l), now), Said::Maybe);
        }
        // the delta again, or an older one: nothing happens
        r.delta(&d, now).unwrap();
        assert_eq!(r.version(), d.to);
        // nothing changed: nothing is sent
        assert!(a.update().is_none());
        // a layer goes: a new filter under a new version, without it
        assert_eq!(a.remove(&layers(0..1)), layers(0..1));
        let new = full(a.update().unwrap());
        assert!(new.version > d.to);
        assert_ne!(new.salt, whole.salt);
        r.full(&new, now).unwrap();
        assert_eq!(r.says(key_of(&layer(5)), now), Said::Maybe);
        // (it can be a false positive at the rate, 1 in 100: this one is not)
        assert_eq!(r.says(key_of(&layer(0)), now), Said::No);
        // more layers than the capacity: a bigger filter, sent whole
        let capacity = Bloom::capacity_for(1009);
        a.add(&layers(2000..2000 + capacity));
        let big = full(a.update().unwrap());
        assert!(big.bits.len() > new.bits.len());
        assert!(a.own().sent.fulls >= 3 && a.own().sent.deltas == 1);
    }

    /// A message that went missing: the delta after it is added all the
    /// same, and the filter says "not known" instead of "no" (never a false
    /// negative) until a whole filter of the last version heard of comes.
    #[test]
    fn a_delta_that_does_not_follow_makes_no_false_negative_until_the_next_whole_one() {
        let mut a = advertiser();
        a.add(&layers(0..1000));
        let now = Instant::now();
        let mut r = Received::new(now);
        r.full(&full(a.update().unwrap()), now).unwrap();
        let elsewhere = key_of(&layer(5000));
        assert_eq!(r.says(elsewhere, now), Said::No);
        a.add(&layers(1000..1001));
        let lost = a.update().unwrap();
        a.add(&layers(1001..1002));
        let Some(GossipMessage::LayerFilterDelta(next)) = a.update() else {
            panic!("a delta")
        };
        assert!(matches!(lost, GossipMessage::LayerFilterDelta(_)));
        assert_eq!(r.delta(&next, now), Ok(()));
        assert!(r.behind());
        // what the peer told is "maybe", what was lost is not "no"
        assert_eq!(r.says(key_of(&layer(1001)), now), Said::Maybe);
        assert_eq!(r.says(key_of(&layer(1)), now), Said::Maybe);
        assert_ne!(r.says(key_of(&layer(1000)), now), Said::No);
        assert_eq!(r.says(elsewhere, now), Said::Unknown);
        // the message that was late comes: still "not known" (versions are
        // not tracked one by one), till the whole filter
        if let GossipMessage::LayerFilterDelta(late) = lost {
            r.delta(&late, now).unwrap();
        }
        assert_eq!(r.says(key_of(&layer(1000)), now), Said::Maybe);
        r.full(&full(a.full().unwrap()), now).unwrap();
        assert!(!r.behind());
        assert_eq!(r.says(key_of(&layer(1001)), now), Said::Maybe);
        assert_eq!(r.says(elsewhere, now), Said::No);
    }

    /// A delta that overtakes the whole filter sent before it (each message
    /// is a stream of its own, the delta is the smaller): the whole filter
    /// that comes after it is not believed to say "no".
    #[test]
    fn a_delta_that_overtakes_the_whole_filter_makes_no_false_negative() {
        let mut a = advertiser();
        a.add(&layers(0..10));
        let whole = full(a.full().unwrap());
        a.add(&layers(10..11));
        let Some(GossipMessage::LayerFilterDelta(delta)) = a.update() else {
            panic!("a delta")
        };
        let now = Instant::now();
        let mut r = Received::new(now);
        r.delta(&delta, now).unwrap();
        r.full(&whole, now).unwrap();
        assert_eq!(r.says(key_of(&layer(3)), now), Said::Maybe);
        assert_eq!(r.says(key_of(&layer(10)), now), Said::Unknown);
        // the next whole filter puts it right
        r.full(&full(a.full().unwrap()), now).unwrap();
        assert_eq!(r.says(key_of(&layer(10)), now), Said::Maybe);
        assert_eq!(r.says(key_of(&layer(99)), now), Said::No);
    }

    /// A node that restarts (with its identity) starts again at version 1,
    /// in a new epoch: a peer that still holds the filter of the run before
    /// (its connection of that run is not closed yet) takes the new one, and
    /// a delta of the new run makes the old filter say no "no".
    #[test]
    fn a_node_that_restarts_is_believed_though_its_versions_start_again() {
        let now = Instant::now();
        let mut before = Advertiser::new(Config::default(), Entropy::seeded(1));
        before.add(&layers(0..10));
        for i in 10..40 {
            before.add(&layers(i..i + 1));
            before.update();
        }
        let mut r = Received::new(now);
        r.full(&full(before.full().unwrap()), now).unwrap();
        assert!(r.version() > 30);
        // the store changed while the node was down
        let mut after = Advertiser::new(Config::default(), Entropy::seeded(2));
        after.add(&layers(100..110));
        let first = full(after.full().unwrap());
        assert!(first.version < r.version());
        // (what was added before the whole filter went with it)
        assert!(matches!(
            after.update(),
            Some(GossipMessage::LayerFilterDelta(_))
        ));
        // a delta of the new run first: the old filter says no "no"
        let later = Instant::now() + Duration::from_secs(1);
        after.add(&layers(110..111));
        let Some(GossipMessage::LayerFilterDelta(d)) = after.update() else {
            panic!("a delta")
        };
        r.delta(&d, later).unwrap();
        assert_eq!(r.says(key_of(&layer(105)), later), Said::Unknown);
        assert_eq!(r.says(key_of(&layer(110)), later), Said::Maybe);
        // the whole filter of the new run
        r.full(&full(after.full().unwrap()), later).unwrap();
        assert_eq!(r.says(key_of(&layer(105)), later), Said::Maybe);
        assert_eq!(r.says(key_of(&layer(110)), later), Said::Maybe);
        // and the version before the delta, of the new run, is no older
        // filter of the run before
        let mut r = Received::new(now);
        r.full(&full(before.full().unwrap()), now).unwrap();
        r.full(&first, later).unwrap();
        assert_eq!(r.says(key_of(&layer(105)), later), Said::Maybe);
        assert_eq!(r.says(key_of(&layer(5)), later), Said::No);
    }

    /// Each filter has a salt of its own: a layer that is a false positive
    /// in one is not in the others (no layer is a false positive across the
    /// swarm), though they hold the same layers.
    #[test]
    fn a_false_positive_of_one_filter_is_not_one_of_the_others() {
        let now = Instant::now();
        let held = layers(0..2000);
        let filters: Vec<Received> = (0..20)
            .map(|n| {
                let mut a = Advertiser::new(Config::default(), Entropy::seeded(100 + n));
                a.add(&held);
                let mut r = Received::new(now);
                r.full(&full(a.full().unwrap()), now).unwrap();
                r
            })
            .collect();
        let most = (5000..25_000)
            .map(|i| {
                let key = key_of(&layer(i));
                filters
                    .iter()
                    .filter(|r| r.says(key, now) == Said::Maybe)
                    .count()
            })
            .max()
            .unwrap();
        // (at about 0.9 % each, a layer is "maybe" in 5 of 20 independent
        // filters about once in a million tries, these are 20 000; with one
        // salt for all, a false positive is one in all 20)
        assert!(
            most <= 5,
            "a layer is a false positive in {most} of 20 filters"
        );
    }

    /// Nodes that start together do not send their whole filters together.
    #[test]
    fn the_whole_filter_is_sent_again_at_times_spread_around_the_refresh() {
        let a = advertiser();
        let times: Vec<Duration> = (0..200).map(|_| a.next_refresh()).collect();
        assert!(times
            .iter()
            .all(|t| *t >= REFRESH.mul_f64(0.8) && *t <= REFRESH.mul_f64(1.2)));
        let spread =
            times.iter().max().unwrap().as_secs_f64() - times.iter().min().unwrap().as_secs_f64();
        assert!(spread > REFRESH.as_secs_f64() * 0.3, "{spread}");
    }

    /// What is not a filter is refused and says nothing.
    #[test]
    fn a_malformed_filter_is_refused_and_says_nothing() {
        let now = Instant::now();
        let ok = || {
            let mut a = advertiser();
            a.add(&layers(0..50));
            full(a.full().unwrap())
        };
        let bits = |bytes: usize, byte: u8| {
            base64::engine::general_purpose::STANDARD.encode(vec![byte; bytes])
        };
        // not whole words, not base64, no bits, no hashes, too many hashes
        for bad in [
            FilterFull {
                bits: bits(12, 1),
                ..ok()
            },
            FilterFull {
                bits: "!!".into(),
                ..ok()
            },
            FilterFull {
                bits: String::new(),
                ..ok()
            },
            FilterFull { hashes: 0, ..ok() },
            FilterFull {
                hashes: MAX_HASHES + 1,
                ..ok()
            },
        ] {
            let mut r = Received::new(now);
            assert_eq!(r.full(&bad, now), Err(Refused::Malformed), "{bad:?}");
            assert_eq!(r.says(key_of(&layer(1)), now), Said::Unknown);
        }
    }

    /// A filter that says "maybe" and is wrong most of the time is not
    /// believed any more; one that is right is.
    #[test]
    fn a_filter_that_is_wrong_most_of_the_time_is_not_believed() {
        let now = Instant::now();
        let mut a = advertiser();
        a.add(&layers(0..50));
        let mut r = Received::new(now);
        r.full(&full(a.full().unwrap()), now).unwrap();
        r.false_positives = JUDGED_AFTER - 1;
        assert_eq!(r.says(key_of(&layer(1)), now), Said::Maybe);
        r.false_positives += 1;
        assert_eq!(r.says(key_of(&layer(1)), now), Said::Unknown);
        r.hits = r.false_positives;
        assert_eq!(r.says(key_of(&layer(1)), now), Said::Maybe);
    }

    /// A filter that is not renewed is not believed for ever.
    #[test]
    fn a_filter_expires() {
        let now = Instant::now();
        let mut a = advertiser();
        a.add(&layers(0..5));
        let mut r = Received::new(now);
        r.full(&full(a.full().unwrap()), now).unwrap();
        assert_eq!(r.says(key_of(&layer(1)), now + TTL), Said::Maybe);
        assert_eq!(
            r.says(key_of(&layer(1)), now + TTL + Duration::from_secs(1)),
            Said::Unknown
        );
    }

    /// A peer that connects after a layer went is not told the layer.
    #[test]
    fn a_new_peer_is_not_told_what_went() {
        let mut a = advertiser();
        a.add(&layers(0..2));
        a.remove(&layers(0..1));
        let now = Instant::now();
        let mut r = Received::new(now);
        r.full(&full(a.full().unwrap()), now).unwrap();
        assert_eq!(r.says(key_of(&layer(0)), now), Said::No);
        assert_eq!(r.says(key_of(&layer(1)), now), Said::Maybe);
        // (the peers told before are told the new filter by the next update)
        assert!(matches!(a.update(), Some(GossipMessage::LayerFilter(_))));
        assert!(a.update().is_none());
    }

    /// A node that tells nothing sends nothing.
    #[test]
    fn a_node_that_does_not_advertise_sends_nothing() {
        let mut a = Advertiser::new(
            Config {
                advertise: false,
                ..Config::default()
            },
            Entropy::seeded(1),
        );
        a.add(&layers(0..5));
        assert!(a.full().is_none() && a.update().is_none());
    }

    /// The sizes the documents give.
    #[test]
    fn the_size_follows_the_number_of_layers_and_the_rate() {
        let size =
            |n: usize, fpr: f64| Bloom::new(Bloom::capacity_for(n), fpr, 256 << 10, 1).bytes();
        eprintln!(
            "bytes: 300 layers {}, 5000 {}, 20000 {}, 100000 {} (1%); 5000 at 0.1% {}",
            size(300, 0.01),
            size(5000, 0.01),
            size(20_000, 0.01),
            size(100_000, 0.01),
            size(5000, 0.001)
        );
        assert!(size(5000, 0.01) < 12 << 10);
        assert!(size(5000, 0.001) > size(5000, 0.01));
        // the size is not made for each layer
        assert_eq!(size(4097, 0.01), size(8192, 0.01));
        // and never above what is allowed
        assert_eq!(
            Bloom::new(Bloom::capacity_for(10_000_000), 0.01, 256 << 10, 1).bytes(),
            256 << 10
        );
    }
}
