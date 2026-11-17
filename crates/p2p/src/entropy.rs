// SPDX-License-Identifier: Apache-2.0
//! Where the node's choices come from: the jitter of a retry and the order
//! of peers that rank the same.
//!
//! A node takes them from the kernel's pool, so that nodes started together
//! do not choose together.  The simulator gives each node a seed instead, so
//! that a run repeats.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;

/// A source of numbers: the kernel's, or a seeded one (a clone is another
/// handle on the same stream).
#[derive(Debug, Clone, Default)]
pub struct Entropy {
    seeded: Option<Arc<AtomicU64>>,
}

impl Entropy {
    /// The kernel's pool.
    pub fn system() -> Self {
        Self::default()
    }

    /// The numbers of `seed`, always the same ones.
    pub fn seeded(seed: u64) -> Self {
        Self {
            seeded: Some(Arc::new(AtomicU64::new(seed))),
        }
    }

    fn bits(&self) -> u64 {
        match &self.seeded {
            None => {
                let mut bytes = [0u8; 8];
                velarx_base::random::fill(&mut bytes);
                u64::from_le_bytes(bytes)
            }
            Some(state) => mix(state
                .fetch_add(GOLDEN, Ordering::Relaxed)
                .wrapping_add(GOLDEN)),
        }
    }

    /// A number of 64 random bits.
    pub fn word(&self) -> u64 {
        self.bits()
    }

    /// A number in `0..1`.
    pub fn unit(&self) -> f64 {
        (self.bits() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// A number in `0..n` (`n` is not 0).
    pub fn below(&self, n: usize) -> usize {
        scale(self.bits(), n)
    }

    /// `items` in a random order.  The kernel's pool is asked once for the
    /// whole shuffle (a stream of its draw gives the rest), not once for
    /// each item.
    pub fn shuffle<T>(&self, items: &mut [T]) {
        if items.len() < 2 {
            return;
        }
        match &self.seeded {
            Some(_) => {
                for i in (1..items.len()).rev() {
                    items.swap(i, self.below(i + 1));
                }
            }
            None => {
                let mut state = self.bits();
                for i in (1..items.len()).rev() {
                    state = state.wrapping_add(GOLDEN);
                    items.swap(i, scale(mix(state), i + 1));
                }
            }
        }
    }
}

/// The number of `state` (splitmix64).
fn mix(state: u64) -> u64 {
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// `bits` as a number in `0..n`.
fn scale(bits: u64, n: usize) -> usize {
    ((u128::from(bits) * n as u128) >> 64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_gives_the_same_numbers_and_another_seed_others() {
        let (a, b, c) = (Entropy::seeded(7), Entropy::seeded(7), Entropy::seeded(8));
        let (x, y, z): (Vec<_>, Vec<_>, Vec<_>) = (
            (0..8).map(|_| a.below(1000)).collect(),
            (0..8).map(|_| b.below(1000)).collect(),
            (0..8).map(|_| c.below(1000)).collect(),
        );
        assert_eq!(x, y);
        assert_ne!(x, z);
    }

    #[test]
    fn numbers_are_in_range_and_a_shuffle_keeps_the_items() {
        let e = Entropy::seeded(1);
        assert!((0..1000).all(|_| (0.0..1.0).contains(&e.unit()) && e.below(5) < 5));
        let mut v: Vec<u32> = (0..50).collect();
        e.shuffle(&mut v);
        assert_ne!(v, (0..50).collect::<Vec<_>>());
        v.sort();
        assert_eq!(v, (0..50).collect::<Vec<_>>());
    }

    #[test]
    fn the_system_source_is_not_constant() {
        let e = Entropy::system();
        assert_ne!(e.unit().to_bits(), e.unit().to_bits());
        // a shuffle keeps the items, and two are not the same order
        let shuffled = || {
            let mut v: Vec<u32> = (0..50).collect();
            e.shuffle(&mut v);
            v
        };
        let (a, b) = (shuffled(), shuffled());
        assert_ne!(a, b);
        let mut sorted = a.clone();
        sorted.sort();
        assert_eq!(sorted, (0..50).collect::<Vec<_>>());
    }
}
