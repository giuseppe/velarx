// SPDX-License-Identifier: Apache-2.0
//! Image signature verification, compatible with the signature policy of
//! containers/image (`policy.json`): the requirements `insecureAcceptAnything`,
//! `reject`, `signedBy` (simple signing, OpenPGP) and `sigstoreSigned`
//! (cosign keys, Fulcio certificates, Rekor).

pub mod evaluate;
pub mod name;
pub mod openpgp;
mod policy;
pub mod reference;
pub mod registries_d;
pub mod sign;
pub mod sigstore;
pub mod trust;
mod types;

pub use policy::*;
