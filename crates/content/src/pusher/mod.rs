// SPDX-License-Identifier: Apache-2.0
//! Pushers: the processes that place the objects of an image (blobs,
//! configurations, manifests) at a destination (`org.velarx.Pusher`).
//! [`push`] has the types of the interface, [`push_client`] the engine's
//! typed client; the serving end is `crate::serve_push`, and the walker
//! of the engine's ordered list of them `crate::push::staged_push`.

pub mod push;
pub mod push_client;
