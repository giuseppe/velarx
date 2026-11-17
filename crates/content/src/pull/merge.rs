// SPDX-License-Identifier: Apache-2.0
//! Merging the byte ranges of a range request by cost.
//!
//! A range of a `multipart/byteranges` answer costs its framing (a
//! boundary and part headers) and its entry in the `Range` header; a
//! request costs a round trip.  Two ranges separated by a gap smaller than
//! what the second costs are fetched as one; then the smallest of the gaps
//! left are merged as long as the bytes they add cost less than the
//! requests they save.  A merged range never holds much more than its
//! share of what the requests in flight fetch, so that they still run in
//! parallel.  The ranges are sorted and disjoint, so a merge only ever joins
//! neighbours.

use std::ops::Range;

/// The bytes of the framing of one part of a multipart answer: boundary,
/// `Content-Type` and `Content-Range` (96 to 146 bytes measured).
pub const RANGE_PART_FRAMING: u64 = 96;

/// What a request costs, in bytes that would take as long to download: a
/// round trip before the first byte (20 to 170 ms from the CDN of a public
/// registry, 1 to 8 ms from a local one) at the 10 to 60 MB/s a
/// connection gets.
pub const REQUEST_COST: u64 = 1024 * 1024;

/// How the ranges are fetched.
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// What a request costs, in bytes.
    pub request_cost: u64,
    /// Ranges per request.
    pub per_request: usize,
    /// Requests in flight.
    pub parallel: usize,
    /// The smallest request worth one of its own, in bytes.
    pub min_batch: u64,
}

fn digits(mut v: u64) -> u64 {
    let mut n = 1;
    while v >= 10 {
        v /= 10;
        n += 1;
    }
    n
}

/// The bytes that fetching the range `offset..offset+length` on its own
/// costs: its part in the answer and `first-last,` in the `Range` header.
pub fn range_price(offset: u64, length: u64) -> u64 {
    let last = if length > 0 {
        offset.saturating_add(length - 1)
    } else {
        offset
    };
    RANGE_PART_FRAMING + digits(offset) + digits(last) + 2
}

/// The requests the `bytes` of the ranges are split in: at most
/// `parallel`, of at least `min_batch` bytes.
fn batches(policy: &Policy, bytes: u64) -> u64 {
    let b = bytes.checked_div(policy.min_batch).unwrap_or(1);
    b.min(policy.parallel as u64).max(1)
}

/// The requests that `n_ranges` ranges of `bytes` need.  The requests are
/// balanced by bytes, not by ranges: a quarter of the ranges a request may
/// have is left free so that none goes over the limit.
pub fn requests(policy: &Policy, n_ranges: usize, bytes: u64) -> u64 {
    if n_ranges == 0 {
        return 0;
    }
    let per_request = (policy.per_request - policy.per_request / 4).max(1) as u64;
    let by_ranges = (n_ranges as u64).div_ceil(per_request);
    by_ranges.max(batches(policy, bytes))
}

/// Why ranges cannot be merged.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeError {
    Overflow,
    NotSorted,
    Overlapping,
}

/// Merge `ranges` (sorted by start, disjoint): the merged ranges, sorted
/// and disjoint, and for each range the index of the merged one that holds
/// it.
pub fn merge(
    ranges: &[Range<u64>],
    policy: &Policy,
) -> Result<(Vec<Range<u64>>, Vec<usize>), MergeError> {
    let n = ranges.len();
    if n == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut needed = 0u64;
    for (i, r) in ranges.iter().enumerate() {
        if r.end < r.start {
            return Err(MergeError::Overflow);
        }
        if i > 0 {
            let prev = &ranges[i - 1];
            if r.start < prev.start {
                return Err(MergeError::NotSorted);
            }
            if r.start < prev.end {
                return Err(MergeError::Overlapping);
            }
        }
        needed = needed
            .checked_add(r.end - r.start)
            .ok_or(MergeError::Overflow)?;
    }

    let b = batches(policy, needed);
    let max_len = if b > 1 {
        needed / b + needed / b / 4 + 1
    } else {
        u64::MAX
    };

    // First: the gaps that cost less than the next range would.  `data[m]`
    // is the bytes needed in segment m.
    // (a range takes its share of the requests that carry it: a request
    // holds `per_request` of them at most)
    let share = policy.request_cost / policy.per_request.max(1) as u64;
    let mut segs: Vec<Range<u64>> = Vec::with_capacity(n);
    let mut data: Vec<u64> = Vec::with_capacity(n + 1);
    let mut map: Vec<usize> = Vec::with_capacity(n);
    for r in ranges {
        let len = r.end - r.start;
        match segs.last_mut() {
            Some(last)
                if r.start - last.end <= range_price(r.start, len) + share
                    && *data.last().expect("a segment") + len <= max_len =>
            {
                last.end = r.end;
                *data.last_mut().expect("a segment") += len;
            }
            _ => {
                segs.push(r.clone());
                data.push(len);
            }
        }
        map.push(segs.len() - 1);
    }
    let m = segs.len();

    // From here `data` holds the prefix sums.
    let mut sum = 0u64;
    for d in data.iter_mut() {
        let v = *d;
        *d = sum;
        sum += v;
    }
    data.push(sum);

    // Then: the smallest gaps, as many as minimize
    //   bytes of the gaps - framing they save + request cost * requests
    let mut joined = vec![false; m];
    if m > 1 {
        let gap = |j: usize| segs[j + 1].start - segs[j].end;
        let mut order: Vec<usize> = (0..m - 1).collect();
        order.sort_by_key(|&j| (gap(j), j));
        let cost = |k: usize| {
            i128::from(policy.request_cost) * i128::from(requests(policy, m - k, needed))
        };
        let mut best = cost(0);
        let mut best_k = 0;
        let (mut sum_gap, mut sum_price) = (0i128, 0i128);
        for (k, &j) in order.iter().enumerate() {
            let k = k + 1;
            sum_gap += i128::from(gap(j));
            sum_price += i128::from(range_price(
                segs[j + 1].start,
                segs[j + 1].end - segs[j + 1].start,
            ));
            let c = sum_gap + cost(k) - sum_price;
            if c < best {
                best = c;
                best_k = k;
            }
        }
        // `first[j]` is the first segment of the group that ends at j,
        // `last[j]` the last of the group that starts at j.
        let mut first: Vec<usize> = (0..m).collect();
        let mut last: Vec<usize> = (0..m).collect();
        let mut merges = 0;
        for &j in &order {
            if merges >= best_k {
                break;
            }
            let (f, l) = (first[j], last[j + 1]);
            if data[l + 1] - data[f] > max_len {
                continue;
            }
            merges += 1;
            first[l] = f;
            last[f] = l;
            joined[j + 1] = true;
        }
    }

    let mut out: Vec<Range<u64>> = Vec::with_capacity(m);
    let mut seg_out: Vec<usize> = Vec::with_capacity(m);
    for (i, s) in segs.iter().enumerate() {
        if joined[i] {
            out.last_mut().expect("a group before").end = s.end;
        } else {
            out.push(s.clone());
        }
        seg_out.push(out.len() - 1);
    }
    let map = map.into_iter().map(|s| seg_out[s]).collect();
    Ok((out, map))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No cost for a request: only the gaps that cost less than the
    /// framing they save are merged.
    const PRICE_ONLY: Policy = Policy {
        request_cost: 0,
        per_request: 1_000_000,
        parallel: 1,
        min_batch: 0,
    };

    fn framing(r: &[Range<u64>]) -> u64 {
        r.iter()
            .map(|r| range_price(r.start, r.end - r.start))
            .sum()
    }

    /// The invariants of any merge ; returns the
    /// merged ranges and the bytes added.
    fn check(input: &[Range<u64>], policy: &Policy) -> (Vec<Range<u64>>, u64) {
        let (out, map) = merge(input, policy).unwrap();
        let n = input.len();
        assert!(n == 0 || (!out.is_empty() && out.len() <= n));
        let (mut needed, mut longest) = (0u64, 0u64);
        for (i, r) in input.iter().enumerate() {
            assert!(map[i] < out.len());
            assert!(i == 0 || map[i] >= map[i - 1]);
            assert!(r.start >= out[map[i]].start && r.end <= out[map[i]].end);
            needed += r.end - r.start;
            longest = longest.max(r.end - r.start);
        }
        let b = batches(policy, needed);
        let cap = if b > 1 {
            needed / b + needed / b / 4 + 1
        } else {
            u64::MAX
        }
        .max(longest);
        let mut data = vec![0u64; out.len().max(1)];
        for (i, r) in input.iter().enumerate() {
            data[map[i]] += r.end - r.start;
        }
        let mut fetched = 0;
        for (i, o) in out.iter().enumerate() {
            assert!(i == 0 || o.start >= out[i - 1].end);
            assert!(data[i] <= cap);
            fetched += o.end - o.start;
        }
        assert!(fetched >= needed);
        if policy.parallel == 1 {
            assert!(
                fetched
                    + framing(&out)
                    + policy.request_cost * requests(policy, out.len(), fetched)
                    <= needed + framing(input) + policy.request_cost * requests(policy, n, needed)
            );
        }
        (out, fetched - needed)
    }

    fn gapped(n: u64, gap: u64, length: u64) -> Vec<Range<u64>> {
        (0..n)
            .map(|i| {
                let s = i * (length + gap);
                s..s + length
            })
            .collect()
    }

    #[test]
    fn plan_ranges() {
        let price = range_price(1000, 10);
        assert!((96 + 4 + 4 + 2..=96 + 20 + 20 + 2).contains(&price));
        assert!(range_price(0, 1) < range_price(u64::MAX / 2, 1));
        let input = [
            0..10,
            10..15,
            20..25,
            100..110,
            110..112,
            200..200,
            100_000..100_001,
        ];
        let (out, map) = merge(&input, &PRICE_ONLY).unwrap();
        assert_eq!(out, [0..200, 100_000..100_001]);
        assert_eq!(map, [0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(merge(&[], &PRICE_ONLY).unwrap(), (vec![], vec![]));
        assert_eq!(
            merge(&[10..11, 5..6], &PRICE_ONLY),
            Err(MergeError::NotSorted)
        );
        assert_eq!(
            merge(&[0..10, 5..20], &PRICE_ONLY),
            Err(MergeError::Overlapping)
        );
        assert_eq!(
            merge(
                &[
                    u64::MAX - 1..u64::MAX,
                    u64::MAX..u64::MAX,
                    u64::MAX..u64::MAX
                ],
                &PRICE_ONLY
            )
            .map(|(o, _)| o.len()),
            Ok(1)
        );
    }

    #[test]
    fn merge_price() {
        // A gap below the price of the next range is merged, one above is
        // not, when requests cost nothing.
        let price = range_price(5000, 100);
        let (out, waste) = check(&[0..5000 - price + 1, 5000..5100], &PRICE_ONLY);
        assert!(out.len() == 1 && waste == price - 1);
        let (out, waste) = check(&[0..5000 - price - 1, 5000..5100], &PRICE_ONLY);
        assert!(out.len() == 2 && waste == 0);
        // exactly the price: the same bytes, one range less
        let (out, _) = check(&[0..5000 - price, 5000..5100], &PRICE_ONLY);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn merge_requests() {
        let mut policy = Policy {
            request_cost: 1 << 20,
            per_request: 64,
            parallel: 4,
            min_batch: 1 << 20,
        };
        // 1000 ranges are 16 requests of 64.  The gaps of 10 KB cost less
        // than the 12 requests that merging them to 256 ranges saves.
        let input = gapped(1000, 10_000, 100_000);
        let (out, _) = check(&input, &policy);
        assert!(out.len() <= 48 * 4);
        assert_eq!(requests(&policy, out.len(), 1000 * 110_000), 4);
        // a registry that refuses more than 8 ranges
        policy.per_request = 8;
        let (out, _) = check(&input, &policy);
        assert!(out.len() <= 6 * 4);
        // one range per request: every gap of 10 KB is worth a request
        policy.per_request = 1;
        let (out, _) = check(&input, &policy);
        assert!(out.len() <= 4);
        // gaps of 100 KB cost more than the requests they save
        policy.per_request = 64;
        let input = gapped(1000, 100_000, 100_000);
        let (out, waste) = check(&input, &policy);
        assert!(out.len() >= 900 && waste <= 100 * 1000 * 100);
        // requests that cost nothing: only the framing counts
        policy.request_cost = 0;
        let (out, waste) = check(&input, &policy);
        assert!(out.len() == 1000 && waste == 0);
    }

    #[test]
    fn merge_cost() {
        let mut policy = Policy {
            request_cost: 1 << 20,
            per_request: 10,
            parallel: 1,
            min_batch: 1 << 20,
        };
        // 100 ranges, the gap before range i grows with i: the smallest
        // gaps are merged to save requests
        let mut input = Vec::new();
        let mut offset = 0u64;
        for i in 0..100u64 {
            offset += 1000 + i * 5000;
            input.push(offset..offset + 100 * 1024);
            offset += 100 * 1024;
        }
        let (out, _) = check(&input, &policy);
        assert!(out.len() > 1 && out.len() < 100);
        let (mut max_merged, mut min_kept) = (0u64, u64::MAX);
        for i in 1..100 {
            let gap = input[i].start - input[i - 1].end;
            if out.iter().any(|o| o.start == input[i].start) {
                min_kept = min_kept.min(gap);
            } else {
                max_merged = max_merged.max(gap);
            }
        }
        assert!(max_merged <= min_kept);
        policy.request_cost = 0;
        let (out, waste) = check(&input, &policy);
        assert!(out.len() == 100 && waste == 0);
        // the requests in flight get ranges of about the same size
        policy.request_cost = 1 << 20;
        policy.parallel = 4;
        let (out, _) = check(&input, &policy);
        assert!(out.len() >= 4);
    }

    #[test]
    fn merge_adversarial() {
        let mut policy = Policy {
            request_cost: 1 << 20,
            per_request: 64,
            parallel: 4,
            min_batch: 2 << 20,
        };
        // many tiny ranges: bounded by the requests in flight
        let n = 200_000u64;
        let input: Vec<Range<u64>> = (0..n).map(|i| i * 1000..i * 1000 + 10).collect();
        let (out, _) = check(&input, &policy);
        assert!(out.len() <= 48 * 4);
        policy.request_cost = 0;
        let (out, waste) = check(&input, &policy);
        assert!(out.len() == n as usize && waste == 0);
        // gaps that all cost less than the framing
        policy.request_cost = 1 << 20;
        let input: Vec<Range<u64>> = (0..n).map(|i| i * 120..i * 120 + 100).collect();
        let (out, _) = check(&input, &policy);
        assert!(out.len() <= 4);
        // offsets far apart
        let input = [0..1, u64::MAX / 2..u64::MAX / 2 + 1, u64::MAX - 1..u64::MAX];
        let (out, _) = check(&input, &policy);
        assert_eq!(out.len(), 3);
    }
}
