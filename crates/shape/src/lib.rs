// SPDX-License-Identifier: Apache-2.0
//! podman's and Docker's documents of the records the engine answers
//! (`velarx_proto::workload`): what `velarx-api` answers on the libpod and
//! Docker routes, and what the command line prints where podman's does.
//! The engine decides what the objects are (its typed records); this crate
//! only lays them out in the other tools' shapes, so that a document has one
//! shape for both and the engine carries none.

pub mod build;
pub mod container;
pub mod event;
pub mod image;
pub mod manifest;
pub mod network;
pub mod pod;
pub mod secret;
pub mod stats;
pub mod system;
pub mod time;
pub mod transfer;
pub mod units;
pub mod volume;

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// An image id as Docker writes it: the algorithm, `:` and the hex digits
/// (the id of an image of sha512 digests has 128 of them, else 64).
pub fn id_with_algorithm(id: &str) -> String {
    let alg = if id.len() == 128 { "sha512" } else { "sha256" };
    format!("{alg}:{id}")
}

/// An id or a digest without its algorithm.
pub fn without_algorithm(d: &str) -> &str {
    d.strip_prefix("sha256:")
        .or_else(|| d.strip_prefix("sha512:"))
        .unwrap_or(d)
}

/// A map of strings as a JSON object.
pub fn string_map(map: &BTreeMap<String, String>) -> Value {
    Value::Object(
        map.iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect::<Map<_, _>>(),
    )
}
