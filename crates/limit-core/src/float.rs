// SPDX-License-Identifier: Apache-2.0
//! The one float of the crate: the weight of CPU shares between the two
//! ends, as crun computes it (`convert_shares_to_weight` in
//! src/libcrun/cgroup-internal.h; runc's `ConvertCPUSharesToCgroupV2Value`
//! is the same formula).  The weight is the value crun writes for a
//! container, so a pod's cgroup, made by the engine, must give the same
//! one.  The operations are the ones of the C code, in the same order, on
//! the system's libm, so the two agree at every number of shares.
//!
//! The translator (tools/verify) takes this module as opaque: the proof
//! does not look in, `weight_of_shares` holds the answer in 1 to 10000.

/// `ceil(10^((l*l + 125*l) / 612 - 7/34))` of `l = log2(shares)`, the
/// quadratic through (2, 1), (1024, 100) and (262144, 10000).  For
/// `shares` of 3 to 262143.
pub(crate) fn weight(shares: u64) -> u64 {
    let l = (shares as f64).log2();
    let exponent = (l * l + 125.0 * l) / 612.0 - 7.0 / 34.0;
    10f64.powf(exponent).ceil() as u64
}
