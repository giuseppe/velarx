// SPDX-License-Identifier: Apache-2.0
//! `velarx-kube`: `play`, `down`, `generate` and `apply`, Kubernetes YAML to
//! pods and containers and back, as podman's `kube` commands.  The engine
//! knows nothing of it: everything it needs of the engine it asks through
//! the typed interface `org.velarx.Engine` ([`engine`]).

pub mod apply;
pub mod commands;
pub mod describe;
pub mod engine;
pub mod fetch;
pub mod fuzzing;
pub mod generate;
pub mod play;
pub mod validate;
pub mod yaml;
