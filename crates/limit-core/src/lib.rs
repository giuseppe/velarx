// SPDX-License-Identifier: Apache-2.0
//! The arithmetic of resource limits: the numbers a request carries (the
//! CRI's `LinuxContainerResources`, the `HostConfig` of the REST API, the
//! `resource_limits` of a pod, a size written as `1.5g`) and the values the
//! cgroup v2 files and the systemd slice take.  Every number comes from a
//! client, so each function answers for any `i64`, `u64` or bytes: a value
//! is converted, or is not a limit, or is refused; it is never wrapped into
//! another one, and never turned into "no limit" when the client asked for
//! one.
//!
//! The rules:
//!
//! 1. Every function returns, whatever its arguments: no overflow, no
//!    panic, no division by zero.
//! 2. CPU shares are 0 (not set) or 2 to 262144; `weight_of_shares` makes
//!    the `cpu.weight` of them as crun does (`convert_shares_to_weight`,
//!    the quadratic of the runtimes since runc 1.2, 1024 shares is 100):
//!    0 is 0 (nothing to write), 2 or less is 1, 262144 or more is 10000,
//!    between them the weight is the one of `float::weight`, held in 1 to
//!    10000, and a greater number of shares never gives a smaller weight.
//!    The block IO weight (10 to 1000, `io_weight_of_blkio`) is made into
//!    the 1 to 10000 of `io.weight` with a linear formula.
//! 3. A byte limit is `limit_of`: 0 is not set, -1 is no limit, a positive
//!    number is that many bytes, any other number is `Invalid`, never read
//!    as its absolute value or as a huge unsigned number.
//! 4. `memory_swap` counts memory and swap together (the OCI and CRI
//!    meaning) and `memory.swap.max` only the swap: `swap_max` is the
//!    difference, `Max(0)` when they are equal.  No swap limit (0 or -1)
//!    is `Unlimited`.  A swap limit below the memory limit, or one with no
//!    memory limit (it would bound nothing), or a value that is not a limit,
//!    is `Invalid`.
//! 5. `cpu_max` of a quota (microseconds of CPU time per period) and a
//!    period: a period is 0 (the default, 100000 microseconds) or 1000 to
//!    1000000; the quota is 0 or -1 (no limit) or 1000 to 2^44 - 1 (what the
//!    kernel takes); every other pair is `Invalid`, a period that is out of
//!    range even when there is no quota.  A positive quota is never turned
//!    into no limit.
//! 6. `nano_cpus_max` of the REST API's `NanoCpus` (billionths of a CPU) is
//!    the quota of a 100000 microseconds period, rounded down: a positive
//!    count whose quota is below 1000 microseconds (a count below
//!    10000000, 0.01 CPU, as Docker refuses it; a quota of 0 would be no
//!    limit) is `Invalid`, as is one over the kernel's quota; `nano_cpus_of` is the
//!    count of a quota and a period, for a client to read.
//! 7. `quota_per_sec` is the quota of a second, `quota * 1000000 / period`,
//!    for the slice's `CPUQuotaPerSecUSec`: it does not wrap, and for a
//!    pair `cpu_max` took it is below 2^64.
//! 8. `oom_score_adj` is a score of -1000 to 1000, and a number that does
//!    not fit an `i32` is no score, whatever its low bits are.
//! 9. A pod's sandbox is the sum of its containers plus the overhead of
//!    its runtime class: `with_overhead` adds to a limit that is set (a
//!    sandbox with no limit of a kind has none), and saturates; a negative
//!    overhead is none.  The shares of the sum are at most 262144.  The
//!    overhead's quota is of its own period and is converted to the
//!    sandbox's before it is added (`sandbox_quota`).
//! 10. `cpuset_mask` of a list of CPUs (`0-3,7`): the numbers are digits
//!     and nothing else, a range is not reversed, a CPU is below 8192;
//!     empty parts and a CPU twice are allowed; the mask is the bits of the
//!     CPUs, and the answer the number of bytes of it that matter.
//! 11. `parse_size` is go-units' `RAMInBytes`, the size of podman's flags:
//!     a decimal number (`12`, `1.5`, `.5`, `5.`, `1e3`, with an optional
//!     sign) then an optional space, then an optional unit of `b`, `k`,
//!     `m`, `g`, `t` or `p` (any case, with an optional `ib` or `b`, in
//!     powers of 1024).  The answer is the number times the unit, rounded
//!     down, and below `i64::MAX`: a size that does not fit, a negative
//!     size and anything after the unit are refused, never saturated and
//!     never wrapped.  (The number is read as the exact decimal it is,
//!     in integers; go-units reads a `float64`, which is one
//!     byte more for a number within 1e-16 of an integer below it, never
//!     less.  Hex floats, which go-units reads, are refused.)
//!
//! Written to be translated (tools/verify): bytes and numbers, loops with a
//! flag, no closure, no iterator adapter, no `String`.  The one float, the
//! power of the weight of shares, is in `float.rs`, which the translator
//! takes as opaque (its answer is any number, which the core holds in 1 to
//! 10000); the options of the proof of this crate mark it so.

#![allow(
    clippy::manual_range_contains,
    clippy::manual_clamp,
    clippy::if_same_then_else,
    reason = "Aeneas has no model of `RangeInclusive::contains` or `clamp`, and each branch of a chain says one thing the rules name"
)]

mod float;

/// The fewest CPU shares a cgroup has.
pub const MIN_SHARES: u64 = 2;
/// The most CPU shares a cgroup has.
pub const MAX_SHARES: u64 = 262_144;
/// The greatest `cpu.weight`.
pub const MAX_WEIGHT: u64 = 10_000;
/// The least block IO weight of the OCI runtimes.
pub const MIN_BLKIO_WEIGHT: u64 = 10;
/// The greatest block IO weight.
pub const MAX_BLKIO_WEIGHT: u64 = 1_000;
/// The least CPU quota the kernel takes, in microseconds.
pub const MIN_QUOTA: u64 = 1_000;
/// The greatest CPU quota the kernel takes (44 bits), in microseconds.
pub const MAX_QUOTA: u64 = (1 << 44) - 1;
/// The least period of a quota, in microseconds.
pub const MIN_PERIOD: u64 = 1_000;
/// The greatest period of a quota, in microseconds.
pub const MAX_PERIOD: u64 = 1_000_000;
/// The period of a quota that has none, in microseconds.
pub const DEFAULT_PERIOD: u64 = 100_000;
/// The CPUs a list names are below this.
pub const MAX_CPUS: usize = 8192;
/// The bytes of the mask of `MAX_CPUS` CPUs.
pub const MASK_BYTES: usize = MAX_CPUS / 8;

/// The CPU shares a `cpu.weight` stands for, for display: the least
/// shares whose weight is at least `weight` (0 for 0, not set), so that
/// `weight_of_shares` of the answer is `weight` for every weight that
/// some shares give.
pub fn shares_of_weight(weight: u64) -> u64 {
    if weight == 0 {
        return 0;
    }
    let (mut low, mut high) = (MIN_SHARES, MAX_SHARES);
    while low < high {
        let mid = low + (high - low) / 2;
        if weight_of_shares(mid) >= weight {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    low
}

/// The `cpu.weight` of CPU shares: 0 for 0 (not set), else 1 to 10000.
pub fn weight_of_shares(shares: u64) -> u64 {
    if shares == 0 {
        0
    } else if shares <= MIN_SHARES {
        1
    } else if shares >= MAX_SHARES {
        MAX_WEIGHT
    } else {
        let w = float::weight(shares);
        if w < 1 {
            1
        } else if w > MAX_WEIGHT {
            MAX_WEIGHT
        } else {
            w
        }
    }
}

/// Whether CPU shares are 0 (not set) or 2 to 262144.
pub fn shares_ok(shares: u64) -> bool {
    shares == 0 || (shares >= MIN_SHARES && shares <= MAX_SHARES)
}

/// The `io.weight` of a block IO weight: 0 for 0 (not set), else 1 to 10000.
pub fn io_weight_of_blkio(weight: u64) -> u64 {
    if weight == 0 {
        return 0;
    }
    let w = if weight > MAX_BLKIO_WEIGHT {
        MAX_BLKIO_WEIGHT
    } else if weight < MIN_BLKIO_WEIGHT {
        MIN_BLKIO_WEIGHT
    } else {
        weight
    };
    1 + (w - MIN_BLKIO_WEIGHT) * (MAX_WEIGHT - 1) / (MAX_BLKIO_WEIGHT - MIN_BLKIO_WEIGHT)
}

/// What a signed byte limit of a request is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// 0: the request says nothing.
    Unset,
    /// -1: no limit.
    Unlimited,
    /// A positive number of bytes.
    Bytes(u64),
    /// Any other number.
    Invalid,
}

/// The limit a signed number of a request is.
pub fn limit_of(v: i64) -> Limit {
    if v == 0 {
        Limit::Unset
    } else if v == -1 {
        Limit::Unlimited
    } else if v > 0 {
        Limit::Bytes(v as u64)
    } else {
        Limit::Invalid
    }
}

/// The value of `memory.swap.max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Swap {
    /// `max`.
    Unlimited,
    /// This many bytes of swap.
    Max(u64),
    /// The two limits do not make one.
    Invalid,
}

/// The swap of the cgroup for a memory limit and a memory and swap limit.
pub fn swap_max(memory: i64, memory_swap: i64) -> Swap {
    let m = limit_of(memory);
    match limit_of(memory_swap) {
        Limit::Invalid => Swap::Invalid,
        Limit::Unset | Limit::Unlimited => {
            if m == Limit::Invalid {
                Swap::Invalid
            } else {
                Swap::Unlimited
            }
        }
        Limit::Bytes(s) => match m {
            Limit::Bytes(m) => {
                if s < m {
                    Swap::Invalid
                } else {
                    Swap::Max(s - m)
                }
            }
            _ => Swap::Invalid,
        },
    }
}

/// The value of `cpu.max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuMax {
    /// `max`: no quota.
    Unlimited,
    /// `quota period`, in microseconds.
    Quota { quota: u64, period: u64 },
    /// The pair is not one a cgroup takes.
    Invalid,
}

/// The `cpu.max` of a quota and a period (0: the default); see rule 5.
pub fn cpu_max(quota: i64, period: u64) -> CpuMax {
    let period = if period == 0 { DEFAULT_PERIOD } else { period };
    if period < MIN_PERIOD || period > MAX_PERIOD {
        CpuMax::Invalid
    } else if quota == 0 || quota == -1 {
        CpuMax::Unlimited
    } else if quota < 0 {
        CpuMax::Invalid
    } else if (quota as u64) < MIN_QUOTA || (quota as u64) > MAX_QUOTA {
        CpuMax::Invalid
    } else {
        CpuMax::Quota {
            quota: quota as u64,
            period,
        }
    }
}

/// The `cpu.max` of a count of billionths of a CPU (0 or less: none).
pub fn nano_cpus_max(nano: i64) -> CpuMax {
    if nano <= 0 {
        CpuMax::Unlimited
    } else if nano / 10_000 == 0 {
        CpuMax::Invalid
    } else {
        cpu_max(nano / 10_000, DEFAULT_PERIOD)
    }
}

/// The billionths of a CPU of a quota and a period (0: the default); 0 for
/// no quota, and at most `i64::MAX`.
pub fn nano_cpus_of(quota: i64, period: u64) -> i64 {
    let period = if period == 0 { DEFAULT_PERIOD } else { period };
    if quota <= 0 {
        return 0;
    }
    let n = (quota as u128) * 1_000_000_000 / (period as u128);
    if n > i64::MAX as u128 {
        i64::MAX
    } else {
        n as i64
    }
}

/// The microseconds of CPU time of a second, for a quota and its period (a
/// period of 0 is the default).
pub fn quota_per_sec(quota: u64, period: u64) -> u64 {
    let period = if period == 0 { DEFAULT_PERIOD } else { period };
    let n = (quota as u128) * 1_000_000 / (period as u128);
    if n > u64::MAX as u128 {
        u64::MAX
    } else {
        n as u64
    }
}

/// The score of an `oom_score_adj` of a request, if it is one.
pub fn oom_score_adj(v: i64) -> Option<i32> {
    if v >= -1000 && v <= 1000 {
        Some(v as i32)
    } else {
        None
    }
}

/// A limit of a sandbox: the sum of its containers' `r`, plus the overhead
/// `o` of its runtime class when `r` is set.
pub fn with_overhead(r: i64, o: i64) -> i64 {
    if r > 0 {
        r.saturating_add(if o > 0 { o } else { 0 })
    } else {
        r
    }
}

/// The shares of a sandbox: the sum with the overhead, at most `MAX_SHARES`.
pub fn sandbox_shares(r: i64, o: i64) -> i64 {
    let s = with_overhead(r, o);
    if s > MAX_SHARES as i64 {
        MAX_SHARES as i64
    } else {
        s
    }
}

/// The memory and swap limit of a sandbox: the overhead counts its memory
/// as well as its swap (`memory_swap` counts both).
pub fn sandbox_swap(r_swap: i64, o_swap: i64, o_memory: i64) -> i64 {
    with_overhead(r_swap, if o_swap > o_memory { o_swap } else { o_memory })
}

/// The quota of a sandbox of the period `r_period`: the overhead's quota
/// `o` is of the period `o_period`, and is converted to the sandbox's.  A
/// pair of periods with one that is not set adds the numbers as they are.
pub fn sandbox_quota(r: i64, r_period: i64, o: i64, o_period: i64) -> i64 {
    if r > 0 && o > 0 && o_period > 0 && r_period > 0 {
        let converted = (o as i128) * (r_period as i128) / (o_period as i128);
        if converted > (i64::MAX - r) as i128 {
            i64::MAX
        } else {
            r + converted as i64
        }
    } else {
        with_overhead(r, o)
    }
}

/// The period of a sandbox: the containers' when set, else the overhead's.
pub fn sandbox_period(r_period: i64, o_period: i64) -> i64 {
    if r_period > 0 {
        r_period
    } else {
        o_period
    }
}

fn digit(b: u8) -> bool {
    b >= b'0' && b <= b'9'
}

/// The mask of a list of CPUs `0-3,7` in `mask` (bit `n` of byte `n / 8`),
/// which the caller gives all zero: the bytes of it that matter, or `None`
/// for a list that is not one (rule 10).
pub fn cpuset_mask(list: &[u8], mask: &mut [u8; MASK_BYTES]) -> Option<usize> {
    let mut used = 0;
    let mut at = 0;
    let mut ok = true;
    while ok && at < list.len() {
        // one part: `N` or `N-M`, up to the comma
        let mut end = at;
        while end < list.len() && list[end] != b',' {
            end += 1;
        }
        if end > at {
            let mut i = at;
            let mut a: usize = 0;
            let mut digits: usize = 0;
            while i < end && digit(list[i]) && a < MAX_CPUS {
                a = a * 10 + (list[i] - b'0') as usize;
                digits += 1;
                i += 1;
            }
            let mut b = a;
            let mut digits_b = digits;
            if i < end && list[i] == b'-' {
                i += 1;
                b = 0;
                digits_b = 0;
                while i < end && digit(list[i]) && b < MAX_CPUS {
                    b = b * 10 + (list[i] - b'0') as usize;
                    digits_b += 1;
                    i += 1;
                }
            }
            if i != end || digits == 0 || digits_b == 0 || a > b || b >= MAX_CPUS {
                ok = false;
            } else {
                let mut n = a;
                while n <= b {
                    mask[n / 8] |= 1 << (n % 8);
                    n += 1;
                }
                if used < b / 8 + 1 {
                    used = b / 8 + 1;
                }
            }
        }
        at = end + 1;
    }
    if ok {
        Some(used)
    } else {
        None
    }
}

/// Why a size is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeError {
    /// Negative, or too large.
    Invalid,
    /// The number is not one: it is the bytes before this index.
    Number(usize),
    /// The unit is not one: it starts at this index.
    Suffix(usize),
}

/// The exponent that `s` writes from the place `i` to its end: an optional
/// sign and one or more digits, and nothing after them.
fn exponent(s: &[u8], mut i: usize) -> Option<i64> {
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut e: i64 = 0;
    let mut digits: usize = 0;
    while i < s.len() && digit(s[i]) {
        if e < 1_000_000 {
            e = e * 10 + (s[i] - b'0') as i64;
        }
        digits += 1;
        i += 1;
    }
    if digits == 0 || i != s.len() {
        return None;
    }
    Some(if neg { -e } else { e })
}

/// A decimal number as `sign`, `mantissa`, `exponent`: the digits it has,
/// the first 19 of them, and the power of ten they are multiplied by.
fn decimal(s: &[u8]) -> Option<(bool, u64, i64)> {
    let mut i = 0;
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut m: u64 = 0;
    let mut exp: i64 = 0;
    let mut digits: usize = 0;
    let mut frac = false;
    while i < s.len() && (digit(s[i]) || (s[i] == b'.' && !frac)) {
        if s[i] == b'.' {
            frac = true;
        } else {
            digits += 1;
            if m < 1_000_000_000_000_000_000 {
                m = m * 10 + (s[i] - b'0') as u64;
                if frac {
                    exp -= 1;
                }
            } else if !frac {
                exp += 1;
            }
        }
        i += 1;
    }
    if digits == 0 {
        return None;
    }
    if i < s.len() && (s[i] == b'e' || s[i] == b'E') {
        return Some((neg, m, exp + exponent(s, i + 1)?));
    }
    if i != s.len() {
        return None;
    }
    Some((neg, m, exp))
}

fn lower(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

/// The power of two of a unit (`k` is 10), `None` for text that is not one.
fn unit_shift(u: &[u8]) -> Option<u32> {
    if u.is_empty() {
        return Some(0);
    }
    if u.len() > 3 {
        return None;
    }
    let c = lower(u[0]);
    if c == b'b' {
        return if u.len() == 1 { Some(0) } else { None };
    }
    let shift = if c == b'k' {
        10
    } else if c == b'm' {
        20
    } else if c == b'g' {
        30
    } else if c == b't' {
        40
    } else if c == b'p' {
        50
    } else {
        return None;
    };
    if u.len() == 2 && lower(u[1]) != b'b' {
        None
    } else if u.len() == 3 && (lower(u[1]) != b'i' || lower(u[2]) != b'b') {
        None
    } else {
        Some(shift)
    }
}

/// The bytes of a size `s`, as go-units reads it (rule 11).
pub fn parse_size(s: &[u8]) -> Result<i64, SizeError> {
    // the number ends at the last digit, dot or space
    let mut sep = s.len();
    let mut i = s.len();
    while i > 0 && sep == s.len() {
        i -= 1;
        if digit(s[i]) || s[i] == b'.' || s[i] == b' ' {
            sep = i;
        }
    }
    if sep == s.len() {
        return Err(SizeError::Invalid);
    }
    let (num_end, unit) = if s[sep] == b' ' {
        (sep, sep + 1)
    } else {
        (sep + 1, sep + 1)
    };
    let (neg, m, exp) = match decimal(&s[..num_end]) {
        Some(d) => d,
        None => return Err(SizeError::Number(num_end)),
    };
    let below_zero = neg && m != 0;
    if below_zero {
        return Err(SizeError::Invalid);
    }
    let shift = match unit_shift(&s[unit..]) {
        Some(n) => n,
        None => return Err(SizeError::Suffix(unit)),
    };
    let mut v: u128 = (m as u128) << shift;
    let mut k = if exp < 0 { -exp } else { exp };
    while k > 0 && v > 0 && (exp < 0 || v < i64::MAX as u128) {
        if exp < 0 {
            v /= 10;
        } else {
            v *= 10;
        }
        k -= 1;
    }
    if v >= i64::MAX as u128 {
        Err(SizeError::Invalid)
    } else {
        Ok(v as i64)
    }
}

#[cfg(test)]
mod rules;

#[cfg(test)]
mod walk;
