// SPDX-License-Identifier: Apache-2.0
//! The conformance suite of the storage drivers against `VarlinkDriver`
//! talking to the reference server over a unix socket.

use velarx_graph::conformance::conformance_suite;
use velarx_storage_server::conformance::{factory as served, plain};

fn factory(chunked_only: bool) -> velarx_graph::conformance::Factory {
    served(chunked_only, plain)
}

/// The layers come as zstd:chunked blobs of a registry, fetched by ranges.
mod chunked {
    use super::*;
    conformance_suite!(factory(true));
}

/// The layers come as tars of a registry that its fetcher unpacks whole: the
/// engine makes their tables of contents and gives the service the files it
/// lacks from the staging of the fetcher.
mod whole {
    use super::*;
    conformance_suite!(factory(false));
}
