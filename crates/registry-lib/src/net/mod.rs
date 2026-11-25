// SPDX-License-Identifier: Apache-2.0
//! The requests to the registries: the confined workers that make them
//! (`pool`, `worker`, their protocol `proto`, their names `resolve` and their
//! cgroup `cgroup`),
//! the bodies of URLs (`url`), a login (`login`) and
//! the requests of a push (`push`).

pub mod cgroup;
pub mod login;
pub mod pool;
pub mod proto;
pub mod ranges;
pub mod resolve;
pub mod url;
pub mod worker;
