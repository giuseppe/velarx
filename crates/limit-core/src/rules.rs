// SPDX-License-Identifier: Apache-2.0
//! The rules of the limits, stated on `i128`, strings and the standard
//! library, the way a person reads a table of what a cgroup file takes:
//! `size_model` and `cpuset_model` are the code that this crate replaced
//! (float and `split`), and the other `check`s state what holds of the
//! answer of each function without calling the arithmetic that makes it.

use super::*;

/// The size as go-units reads it with a `float64`: the code this replaced.
pub(crate) fn size_model(size: &str) -> Result<i64, SizeError> {
    let sep = size
        .rfind(|c: char| "0123456789. ".contains(c))
        .ok_or(SizeError::Invalid)?;
    let (num, sfx, num_end) = if size.as_bytes()[sep] != b' ' {
        (&size[..=sep], &size[sep + 1..], sep + 1)
    } else {
        (&size[..sep], &size[sep + 1..], sep)
    };
    let value: f64 = num.parse().map_err(|_| SizeError::Number(num_end))?;
    if value < 0.0 {
        return Err(SizeError::Invalid);
    }
    let unit = sep + 1;
    let n = if sfx.is_empty() {
        value as i64
    } else {
        let lower = sfx.to_ascii_lowercase();
        let bad = SizeError::Suffix(unit);
        let bytes = lower.as_bytes();
        if bytes.len() > 3 {
            return Err(bad);
        }
        if bytes[0] == b'b' {
            if bytes.len() > 1 {
                return Err(bad);
            }
            value as i64
        } else {
            let shift = match bytes[0] {
                b'k' => 10,
                b'm' => 20,
                b'g' => 30,
                b't' => 40,
                b'p' => 50,
                _ => return Err(bad),
            };
            match bytes.len() {
                2 if bytes[1] != b'b' => return Err(bad),
                3 if &lower[1..] != "ib" => return Err(bad),
                _ => {}
            }
            (value * (1u64 << shift) as f64) as i64
        }
    };
    if n == i64::MAX {
        Err(SizeError::Invalid)
    } else {
        Ok(n)
    }
}

/// The mask of a list of CPUs as `split` and `parse` read it: the code this
/// replaced, with the digits it left to `parse` (which takes a `+`).
pub(crate) fn cpuset_model(list: &str) -> Option<Vec<u8>> {
    let mut mask: Vec<u8> = Vec::new();
    for part in list.split(',').filter(|p| !p.is_empty()) {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a, b),
            None => (part, part),
        };
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
        if !digits(a) || !digits(b) {
            return None;
        }
        let a: usize = a.parse().ok()?;
        let b: usize = b.parse().ok()?;
        if a > b || b >= MAX_CPUS {
            return None;
        }
        if mask.len() <= b / 8 {
            mask.resize(b / 8 + 1, 0);
        }
        for n in a..=b {
            mask[n / 8] |= 1 << (n % 8);
        }
    }
    Some(mask)
}

pub(crate) fn mask_of(list: &str) -> Option<Vec<u8>> {
    let mut mask = [0u8; MASK_BYTES];
    cpuset_mask(list.as_bytes(), &mut mask).map(|n| mask[..n].to_vec())
}

/// What holds of the weight of `shares`.
pub(crate) fn check_weight(shares: u64) {
    let w = weight_of_shares(shares);
    if shares == 0 {
        assert_eq!(w, 0);
        return;
    }
    assert!((1..=MAX_WEIGHT).contains(&w), "{shares}: {w}");
    if shares >= 262_144 {
        assert_eq!(w, MAX_WEIGHT);
    }
    if shares <= 2 {
        assert_eq!(w, 1);
    }
    if shares < u64::MAX {
        assert!(weight_of_shares(shares + 1) >= w, "{shares}");
    }
}

/// What holds of the block IO weight.
pub(crate) fn check_io_weight(weight: u64) {
    let w = io_weight_of_blkio(weight);
    if weight == 0 {
        assert_eq!(w, 0);
        return;
    }
    assert!((1..=MAX_WEIGHT).contains(&w), "{weight}: {w}");
    if weight >= 1000 {
        assert_eq!(w, 10_000);
    }
    if weight <= 10 {
        assert_eq!(w, 1);
    }
    if weight < u64::MAX {
        assert!(io_weight_of_blkio(weight + 1) >= w);
    }
}

/// What holds of the swap of a pair of limits.
pub(crate) fn check_swap(memory: i64, swap: i64) {
    let got = swap_max(memory, swap);
    let what = format!("memory {memory} swap {swap}: {got:?}");
    let valid = |v: i64| v >= -1;
    let want = if !valid(memory) || !valid(swap) {
        Swap::Invalid
    } else if swap <= 0 {
        Swap::Unlimited
    } else if memory <= 0 || swap < memory {
        Swap::Invalid
    } else {
        Swap::Max((swap as i128 - memory as i128) as u64)
    };
    assert_eq!(got, want, "{what}");
    // the swap limit counts memory and swap together: the cgroup's swap
    // and the memory are what the request said
    if let Swap::Max(s) = got {
        assert_eq!(s as i128 + memory as i128, swap as i128, "{what}");
    }
}

/// What holds of the limit of a number.
pub(crate) fn check_limit(v: i64) {
    match limit_of(v) {
        Limit::Unset => assert_eq!(v, 0),
        Limit::Unlimited => assert_eq!(v, -1),
        Limit::Bytes(n) => assert!(v > 0 && n as i128 == v as i128),
        Limit::Invalid => assert!(v < -1),
    }
}

/// What holds of the `cpu.max` of a quota and a period.
pub(crate) fn check_cpu_max(quota: i64, period: u64) {
    let got = cpu_max(quota, period);
    let what = format!("quota {quota} period {period}: {got:?}");
    let p = if period == 0 { 100_000 } else { period };
    let want = if !(1_000..=1_000_000).contains(&p) {
        CpuMax::Invalid
    } else if quota == 0 || quota == -1 {
        CpuMax::Unlimited
    } else if (1_000..=(1i128 << 44) - 1).contains(&(quota as i128)) {
        CpuMax::Quota {
            quota: quota as u64,
            period: p,
        }
    } else {
        CpuMax::Invalid
    };
    assert_eq!(got, want, "{what}");
    // a quota that was asked for is never no quota
    if quota > 0 {
        assert_ne!(got, CpuMax::Unlimited, "{what}");
    }
    if let CpuMax::Quota {
        quota: q,
        period: p,
    } = got
    {
        // the slice's quota of a second does not wrap
        let per_sec = quota_per_sec(q, p);
        assert_eq!(per_sec as u128, q as u128 * 1_000_000 / p as u128, "{what}");
    }
}

/// What holds of the CPU count of a number of billionths.
pub(crate) fn check_nano(nano: i64) {
    let got = nano_cpus_max(nano);
    let want = if nano <= 0 {
        CpuMax::Unlimited
    } else if nano / 10_000 < 1_000 || nano / 10_000 > (1 << 44) - 1 {
        CpuMax::Invalid
    } else {
        CpuMax::Quota {
            quota: (nano / 10_000) as u64,
            period: 100_000,
        }
    };
    assert_eq!(got, want, "{nano}");
    if nano > 0 {
        assert_ne!(got, CpuMax::Unlimited, "{nano}");
    }
}

/// What holds of the count of CPUs of a quota.
pub(crate) fn check_nano_of(quota: i64, period: u64) {
    let n = nano_cpus_of(quota, period);
    let p = if period == 0 { 100_000 } else { period } as i128;
    let want = if quota <= 0 {
        0
    } else {
        (quota as i128 * 1_000_000_000 / p).min(i64::MAX as i128)
    };
    assert_eq!(n as i128, want, "{quota} {period}");
}

/// What holds of the sums of a sandbox.
pub(crate) fn check_sandbox(r: i64, o: i64) {
    let sum = with_overhead(r, o);
    let want = if r > 0 {
        (r as i128 + o.max(0) as i128).min(i64::MAX as i128) as i64
    } else {
        r
    };
    assert_eq!(sum, want, "{r} {o}");
    // a sandbox never has less than its containers have
    assert!(sum >= r, "{r} {o}");
    assert_eq!(sandbox_shares(r, o), sum.min(262_144), "{r} {o}");
}

/// What holds of the quota of a sandbox.
pub(crate) fn check_sandbox_quota(r: i64, rp: i64, o: i64, op: i64) {
    let got = sandbox_quota(r, rp, o, op);
    let want = if r > 0 && o > 0 && rp > 0 && op > 0 {
        (r as i128 + o as i128 * rp as i128 / op as i128).min(i64::MAX as i128) as i64
    } else {
        with_overhead(r, o)
    };
    assert_eq!(got, want, "{r} {rp} {o} {op}");
    assert!(got >= r, "{r} {rp} {o} {op}");
}

/// What holds of the score of a number.
pub(crate) fn check_oom(v: i64) {
    let got = oom_score_adj(v);
    assert_eq!(
        got.map(i64::from),
        (-1000..=1000).contains(&v).then_some(v),
        "{v}"
    );
}

/// The size is the model's, and what holds of it.
pub(crate) fn check_size(size: &str) {
    let got = parse_size(size.as_bytes());
    // (the float has 53 bits: above 2^53 it is the model that is off, by
    // its last bits)
    match (got, size_model(size)) {
        (Ok(n), Ok(f)) if f >= 1 << 53 => assert!(n.abs_diff(f) <= (f >> 50) as u64, "{size:?}"),
        (got, model) => assert_eq!(got, model, "{size:?}"),
    }
    if let Ok(n) = got {
        assert!((0..i64::MAX).contains(&n), "{size:?}");
    }
}

/// The mask is the model's, and what holds of it.
pub(crate) fn check_cpuset(list: &str) {
    let got = mask_of(list);
    assert_eq!(got, cpuset_model(list), "{list:?}");
    if let Some(mask) = got {
        // the last byte of the answer has a CPU: the answer is as short
        // as it can be
        assert!(mask.last().is_none_or(|b| *b != 0), "{list:?}");
    }
}
