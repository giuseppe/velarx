// SPDX-License-Identifier: Apache-2.0
//! What a simulated node answers, with the real admission (slots, the upload
//! pacer) and the real answers of `serve`.

use super::node::{Behavior, Node};
use crate::serve::{self, Caller};
use crate::{ChunkProvider, Presence};
use std::io;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use tokio::time::Instant;

/// A question whether the node has a chunk, while it is answered.
struct Probing<'a>(&'a super::node::Counters);

impl<'a> Probing<'a> {
    fn new(counters: &'a super::node::Counters) -> Self {
        counters.probed.fetch_add(1, Relaxed);
        let now = counters.probing.fetch_add(1, Relaxed) + 1;
        counters.probing_most.fetch_max(now, Relaxed);
        Self(counters)
    }
}

impl Drop for Probing<'_> {
    fn drop(&mut self) {
        self.0.probing.fetch_sub(1, Relaxed);
    }
}

impl Node {
    /// The answer to the question whether the node has the chunk `digest`,
    /// as `Quic::probe` gives it: no room without a place of the probes, else
    /// whether the store has it.  A silent node never answers.
    pub(super) async fn answer_probe(&self, digest: &str) -> io::Result<Presence> {
        let live = self.live();
        let _probing = Probing::new(&live.counters);
        let behavior = *live.behavior.lock().unwrap_or_else(|e| e.into_inner());
        match behavior {
            Behavior::Silent => super::net::Net::lost().await,
            Behavior::Busy => return Ok(Presence::Busy),
            // (it says it has everything)
            Behavior::Corrupt => return Ok(Presence::Has),
            _ => {}
        }
        let no_room = || {
            live.counters.refused.fetch_add(1, Relaxed);
            Ok(Presence::Busy)
        };
        let Some(_slot) = live.admission.probe_slot() else {
            return no_room();
        };
        if let Behavior::Slow(more) = behavior {
            tokio::time::sleep(more).await;
        }
        if !self.cfg.store_latency.is_zero() {
            tokio::time::sleep(self.cfg.store_latency).await;
        }
        match serve::has(self.store.as_ref(), digest) {
            Ok(true) => Ok(Presence::Has),
            Ok(false) => Ok(Presence::Lacks),
            Err(_) => Err(io::Error::other(crate::quic::StoreFailed)),
        }
    }

    /// The answer to a request for the index of `layer` (or, `profile`, the
    /// startup profile of an image) over QUIC: a slot by the time the next
    /// byte is due, the credit of the upload
    /// limit, then the store.
    pub(super) async fn answer_index(
        &self,
        reader: &Arc<Node>,
        layer: &str,
        profile: bool,
    ) -> io::Result<Option<Vec<u8>>> {
        let live = self.live();
        let behavior = *live.behavior.lock().unwrap_or_else(|e| e.into_inner());
        match behavior {
            Behavior::Silent => super::net::Net::lost().await,
            Behavior::Busy => return Err(io::Error::other(crate::quic::NoRoom)),
            _ => {}
        }
        let no_room = || {
            live.counters.refused.fetch_add(1, Relaxed);
            io::Error::other(crate::quic::NoRoom)
        };
        let limits = crate::quic::Limits::default();
        let caller = Caller::new(reader.ip);
        let Ok(Ok(_slot)) = tokio::time::timeout_at(
            Instant::now() + limits.idle / 2,
            live.quic_slots.clone().acquire_owned(),
        )
        .await
        else {
            return Err(no_room());
        };
        if let Behavior::Slow(more) = behavior {
            tokio::time::sleep(more).await;
        }
        if !self.cfg.store_latency.is_zero() {
            tokio::time::sleep(self.cfg.store_latency).await;
        }
        let found = match profile {
            true => self.store.get_profile(layer),
            false => self.store.get_index(layer),
        }
        .map_err(|_| io::Error::other(crate::quic::StoreFailed))?;
        let Some(data) =
            found.filter(|d| !d.is_empty() && d.len() <= crate::limits::MAX_ITEM_BYTES)
        else {
            return Ok(None);
        };
        let first_by = Instant::now() + limits.idle / 2;
        if !live
            .admission
            .pace(&caller, data.len() as u64, Some(first_by))
            .await
        {
            return Err(no_room());
        }
        self.world()
            .net
            .send(self.index, reader.index, data.len() as u64)
            .await
            .map_err(|_| io::Error::other("the reader is gone"))?;
        live.counters
            .served_bytes
            .fetch_add(data.len() as u64, Relaxed);
        Ok(Some(data))
    }

    /// The answer to a request over QUIC: the chunks it has of `digests`,
    /// sent to `reader` at the speed the reader takes them, or `NoRoom`
    /// (no slot by the time the next byte is due), or an error
    /// when the reader does not take the answer in time.
    pub(super) async fn answer_quic(
        &self,
        reader: &Arc<Node>,
        digests: &[String],
    ) -> io::Result<Vec<(String, Vec<u8>)>> {
        let live = self.live();
        let behavior = *live.behavior.lock().unwrap_or_else(|e| e.into_inner());
        match behavior {
            Behavior::Silent => super::net::Net::lost().await,
            Behavior::Busy => return Err(io::Error::other(crate::quic::NoRoom)),
            _ => {}
        }
        let no_room = || {
            live.counters.refused.fetch_add(1, Relaxed);
            io::Error::other(crate::quic::NoRoom)
        };
        let limits = crate::quic::Limits::default();
        let caller = Caller::new(reader.ip);
        let Ok(Ok(_slot)) = tokio::time::timeout_at(
            Instant::now() + limits.idle / 2,
            live.quic_slots.clone().acquire_owned(),
        )
        .await
        else {
            return Err(no_room());
        };
        if let Behavior::Slow(more) = behavior {
            tokio::time::sleep(more).await;
        }
        if !self.cfg.store_latency.is_zero() {
            tokio::time::sleep(self.cfg.store_latency).await;
        }
        let world = self.world();
        let piece = live.admission.piece() as usize;
        let mut sent = Vec::new();
        for digest in digests {
            let mut data = match serve::read_checked(self.store.as_ref(), digest) {
                Ok(Some(data)) => data,
                Ok(None) => continue,
                Err(_) => return Err(io::Error::other(crate::quic::StoreFailed)),
            };
            // the credit of the upload limit, a piece at a time
            for (i, part) in data.chunks(piece).enumerate() {
                let first_by = (i == 0).then(|| Instant::now() + limits.idle / 2);
                if !live
                    .admission
                    .pace(&caller, part.len() as u64, first_by)
                    .await
                {
                    return if sent.is_empty() {
                        Err(no_room())
                    } else {
                        Ok(sent)
                    };
                }
                // the reader takes it in the time it has
                let taken = tokio::time::timeout(
                    limits.grace,
                    world.net.send(self.index, reader.index, part.len() as u64),
                )
                .await;
                if !matches!(taken, Ok(Ok(()))) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the reader does not take the answer",
                    ));
                }
            }
            if behavior == Behavior::Corrupt {
                data[0] ^= 0xff;
            }
            live.counters
                .served_bytes
                .fetch_add(data.len() as u64, Relaxed);
            sent.push((digest.clone(), data));
        }
        if !sent.is_empty() {
            live.counters.served.fetch_add(1, Relaxed);
        }
        Ok(sent)
    }
}
