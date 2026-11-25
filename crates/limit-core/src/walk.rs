// SPDX-License-Identifier: Apache-2.0
//! The requests of a small world, every one of them, and the rules checked
//! on each answer (see `rules`): every share count up to 300000 and the
//! edges of `u64`, every pair of the numbers at the edges of `i64` (zero,
//! one, minus one, the limits of the kernel and one beyond each, the
//! extremes) for the limits of memory, swap, CPU and the sandbox, every
//! string of up to six characters of an alphabet of the digits, the units
//! and the signs for a size and a list of CPUs.

use super::rules::*;
use super::*;

/// The numbers at the edges of what a limit may be.
const EDGES: [i64; 31] = [
    i64::MIN,
    i64::MIN + 1,
    -4_294_967_297,
    -4_294_967_296,
    -1_001,
    -1_000,
    -999,
    -3,
    -2,
    -1,
    0,
    1,
    2,
    3,
    999,
    1_000,
    1_001,
    100_000,
    262_144,
    262_145,
    1_000_000,
    1_000_001,
    4_294_967_295,
    4_294_967_296,
    (1 << 44) - 1,
    1 << 44,
    (1 << 44) + 1,
    1 << 62,
    i64::MAX - 1,
    i64::MAX,
    i64::MAX / 2,
];

fn edges_u64() -> Vec<u64> {
    let mut v = vec![u64::MAX, u64::MAX - 1, 1 << 63, (1 << 63) - 1];
    v.extend(EDGES.iter().filter(|e| **e >= 0).map(|e| *e as u64));
    v
}

/// Every string of at most `n` characters of `alphabet`.
fn strings(alphabet: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut all = vec![String::new()];
    let mut from = 0;
    for _ in 0..n {
        let to = all.len();
        for i in from..to {
            for c in &chars {
                let mut s = all[i].clone();
                s.push(*c);
                all.push(s);
            }
        }
        from = to;
    }
    all
}

#[test]
fn every_share_count() {
    for shares in 0..=300_000u64 {
        check_weight(shares);
        check_io_weight(shares);
    }
    for shares in edges_u64() {
        check_weight(shares);
        check_io_weight(shares);
    }
    // the values every reader knows
    assert_eq!(weight_of_shares(2), 1);
    assert_eq!(weight_of_shares(1024), 100);
    assert_eq!(weight_of_shares(262_144), 10_000);
    assert_eq!(weight_of_shares(u64::MAX), 10_000);
    assert_eq!(io_weight_of_blkio(10), 1);
    assert_eq!(io_weight_of_blkio(50), 405);
    assert_eq!(io_weight_of_blkio(1000), 10_000);
    assert!(shares_ok(0) && shares_ok(2) && shares_ok(262_144));
    assert!(!shares_ok(1) && !shares_ok(262_145) && !shares_ok(u64::MAX));
}

/// crun's `convert_shares_to_weight` (src/libcrun/cgroup-internal.h):
///
/// ```c
/// l = log2 ((double) shares);
/// exponent = (l * l + 125 * l) / 612.0 - 7.0 / 34.0;
/// return (uint64_t) ceil (pow (10, exponent));
/// ```
///
/// with 0 for 0, 1 for 2 or less and 10000 for 262144 or more, evaluated
/// by that C function compiled with gcc and glibc: these are its answers.
#[test]
fn the_weight_is_the_one_crun_writes() {
    let crun = [
        (0, 0),
        (1, 1),
        (2, 1),
        (3, 2),
        (4, 2),
        (10, 4),
        (100, 17),
        (128, 21),
        (256, 35),
        (512, 59),
        (1000, 99),
        (1024, 100),
        (2000, 170),
        (2048, 174),
        (4096, 303),
        (10000, 627),
        (16384, 942),
        (32768, 1681),
        (65536, 3023),
        (100000, 4340),
        (131072, 5478),
        (262143, 10000),
        (262144, 10000),
    ];
    for (shares, weight) in crun {
        assert_eq!(weight_of_shares(shares), weight, "{shares}");
    }
    // the weight never goes down, and stays where a cgroup takes it
    let mut last = 1;
    for shares in 2..=262_144 {
        let w = weight_of_shares(shares);
        assert!(w >= last && w <= 10_000, "{shares}: {w}");
        last = w;
    }
}

/// The shares shown for a weight are the least ones that give it.
#[test]
fn the_shares_shown_for_a_weight() {
    for shares in 2..=262_144 {
        let w = weight_of_shares(shares);
        let shown = shares_of_weight(w);
        assert!(shown <= shares, "{shares}");
        assert_eq!(weight_of_shares(shown), w, "{shares}");
        assert!(shown == 2 || weight_of_shares(shown - 1) < w, "{shares}");
    }
    assert_eq!(shares_of_weight(0), 0);
    assert_eq!(shares_of_weight(1), 2);
    assert_eq!(shares_of_weight(10_000), 262_115);
    assert_eq!(shares_of_weight(u64::MAX), 262_144);
    assert!(shares_of_weight(100) <= 1024);
    assert_eq!(weight_of_shares(shares_of_weight(100)), 100);
}

#[test]
fn every_pair_of_memory_and_swap() {
    for m in EDGES {
        check_limit(m);
        for s in EDGES {
            check_swap(m, s);
        }
    }
    // the kubelet's "no swap": the swap limit is the memory limit
    assert_eq!(swap_max(100, 100), Swap::Max(0));
    assert_eq!(swap_max(100, 250), Swap::Max(150));
    // the swap that is more than the memory in the other unit
    assert_eq!(swap_max(i64::MAX - 1, i64::MAX), Swap::Max(1));
    assert_eq!(swap_max(100, 99), Swap::Invalid);
    assert_eq!(swap_max(0, 100), Swap::Invalid);
    assert_eq!(swap_max(100, -1), Swap::Unlimited);
    assert_eq!(swap_max(100, 0), Swap::Unlimited);
}

#[test]
fn every_quota_and_period() {
    let periods = edges_u64();
    for q in EDGES {
        check_nano(q);
        for p in &periods {
            check_cpu_max(q, *p);
        }
    }
    for q in 990..=1010 {
        check_cpu_max(q, 0);
    }
    for p in 990..=1010 {
        check_cpu_max(1000, p);
    }
    for q in [i64::MIN, -2, -1, 0, 1, 1000, 1 << 44, i64::MAX] {
        for p in [0, 1_000, 1_000_000, u64::MAX] {
            check_nano_of(q, p);
        }
    }
    // the values every reader knows
    assert_eq!(
        cpu_max(50_000, 0),
        CpuMax::Quota {
            quota: 50_000,
            period: 100_000
        }
    );
    assert_eq!(quota_per_sec(50_000, 200_000), 250_000);
    assert_eq!(quota_per_sec(MAX_QUOTA, MIN_PERIOD), MAX_QUOTA * 1_000);
    assert_eq!(quota_per_sec(u64::MAX, 1), u64::MAX);
    assert_eq!(nano_cpus_max(1_500_000_000), cpu_max(150_000, 0));
    // 0.0000099 CPUs is a quota of 0 in a division, which is no limit
    assert_eq!(nano_cpus_max(9_999), CpuMax::Invalid);
    assert_eq!(nano_cpus_max(10_000_000), cpu_max(1_000, 0));
    assert_eq!(nano_cpus_max(9_999_999), CpuMax::Invalid);
    assert_eq!(nano_cpus_of(150_000, 0), 1_500_000_000);
    assert_eq!(nano_cpus_of(-1, 0), 0);
}

#[test]
fn every_sandbox_sum() {
    for r in EDGES {
        for o in EDGES {
            check_sandbox(r, o);
            for rp in EDGES {
                for op in EDGES {
                    check_sandbox_quota(r, rp, o, op);
                }
            }
        }
    }
    assert_eq!(sandbox_swap(100, 0, 10), 110);
    assert_eq!(sandbox_swap(0, 5, 10), 0);
    assert_eq!(sandbox_period(0, 5), 5);
    assert_eq!(sandbox_period(7, 5), 7);
    // an overhead of its own period: 10000 of 50000 is 20000 of 100000
    assert_eq!(sandbox_quota(100_000, 100_000, 10_000, 50_000), 120_000);
    assert_eq!(sandbox_quota(100_000, 0, 10_000, 50_000), 110_000);
}

#[test]
fn every_oom_score() {
    for v in EDGES {
        check_oom(v);
    }
    for v in -1100..=1100 {
        check_oom(v);
    }
    // the low 32 bits of 2^32 are a score, the number is not
    assert_eq!(oom_score_adj(1 << 32), None);
    assert_eq!(oom_score_adj((1 << 32) - 998), None);
    assert_eq!(oom_score_adj(-998), Some(-998));
}

#[test]
fn every_short_size() {
    for s in strings("019.e-+ kbiG", 5) {
        check_size(&s);
    }
    for s in strings("19.mgtpPKi B", 5) {
        check_size(&s);
    }
}

/// Sizes as podman writes them, and the numbers go-units' float cannot
/// hold, and the exponent that is a million.
#[test]
fn sizes_at_the_edges() {
    for (s, want) in [
        ("512", Ok(512)),
        ("512b", Ok(512)),
        ("64k", Ok(64 << 10)),
        ("1.5g", Ok(3 << 29)),
        ("512 MiB", Ok(512 << 20)),
        ("2gb", Ok(2 << 30)),
        ("1T", Ok(1 << 40)),
        ("1p", Ok(1 << 50)),
        ("1.085m", Ok(1_137_704)),
        ("0.9", Ok(0)),
        ("-0", Ok(0)),
        ("+5k", Ok(5 << 10)),
        ("1e3", Ok(1000)),
        ("1e3k", Ok(1_024_000)),
        (".5k", Ok(512)),
        ("5.k", Ok(5 << 10)),
        ("9223372036854775806", Ok(i64::MAX - 1)),
        ("9223372036854775807", Err(SizeError::Invalid)),
        ("9223372036854775808", Err(SizeError::Invalid)),
        ("8191p", Ok(8191 << 50)),
        ("8192p", Err(SizeError::Invalid)),
        ("99999999999999999999t", Err(SizeError::Invalid)),
        ("1e999999999", Err(SizeError::Invalid)),
        ("1e-999999999", Ok(0)),
        ("0e999999999", Ok(0)),
        ("0.0000000000000000000000000000000001e40", Ok(1_000_000)),
        ("-1", Err(SizeError::Invalid)),
        ("-1k", Err(SizeError::Invalid)),
        ("", Err(SizeError::Invalid)),
        ("k", Err(SizeError::Invalid)),
        ("1x", Err(SizeError::Suffix(1))),
        ("1kx", Err(SizeError::Suffix(1))),
        ("1 2", Err(SizeError::Number(3))),
        ("1.2.3", Err(SizeError::Number(5))),
    ] {
        assert_eq!(parse_size(s.as_bytes()), want, "{s:?}");
    }
    // the first 19 digits are the number, the rest are its magnitude
    let long = "1".to_string() + &"0".repeat(30);
    assert_eq!(parse_size(long.as_bytes()), Err(SizeError::Invalid));
    let tiny = "0.".to_string() + &"0".repeat(60) + "1";
    assert_eq!(parse_size(tiny.as_bytes()), Ok(0));
    assert_eq!(
        parse_size("9223372036854775806.9".as_bytes()),
        Ok(i64::MAX - 1)
    );
    // bytes that are no text are no size
    assert_eq!(parse_size(b"1\xffk"), Err(SizeError::Suffix(1)));
    assert!(parse_size(b"\xff1").is_err());
}

#[test]
fn every_short_cpu_list() {
    for s in strings("0189-,+ a", 6) {
        check_cpuset(&s);
    }
}

#[test]
fn cpu_lists_at_the_edges() {
    for (s, want) in [
        ("0-3,7", Some(vec![0b1000_1111])),
        ("9", Some(vec![0, 0b10])),
        ("", Some(vec![])),
        (",", Some(vec![])),
        ("0,,0,0", Some(vec![1])),
        ("5,0-0,3-5", Some(vec![0b0011_1001])),
        (
            "8191",
            Some(vec![0; 1023].into_iter().chain([0x80]).collect()),
        ),
        ("8192", None),
        ("3-1", None),
        ("1-", None),
        ("-1", None),
        ("1-2-3", None),
        ("+1", None),
        (" 1", None),
        ("1 ", None),
        ("99999999999999999999", None),
        ("0-99999999999999999999", None),
        ("0;1", None),
        ("a", None),
        ("０", None),
    ] {
        assert_eq!(mask_of(s), want, "{s:?}");
    }
    // the whole range: every bit of the mask
    assert_eq!(mask_of("0-8191"), Some(vec![0xff; MASK_BYTES]));
    // (the code this replaced took `+1`, as `parse` does; the kernel does not)
    assert_eq!("+1".parse::<usize>(), Ok(1));
}
