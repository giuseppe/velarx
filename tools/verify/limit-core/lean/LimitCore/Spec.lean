-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/limit-core, the arithmetic of resource limits: what a
-- number of a request (the CRI, the REST API, the pod specs) becomes in a cgroup v2 file, or is
-- refused.  This file is what a reviewer reads, in words and in statements, with no proof; Lean
-- checks the rest (the other files of LimitCore/; Theorems.lean ties each claim below to its proof).
--
-- Why it is needed: every number comes from a client, and a number that wrapped would write another
-- limit than the one asked (or no limit at all).  The tests of the crate (src/rules.rs, src/walk.rs)
-- check the rules on a small world of inputs; each claim below is the same rule for EVERY input.
-- A proof is worth what its statement says, so each claim has a comment of what it claims and of
-- what it does NOT.
--
-- Words.  The answers are stated in unbounded integers (`Int`, `Nat`): an answer that is
-- `min (a * b / c) (2^64 - 1)` is exactly that, so no step of the arithmetic wrapped.  A PERIOD of
-- 0 is the default one (`PeriodOf`).  `Short` says a list of bytes is shorter than 2^62, a bound
-- no memory of a machine reaches, which keeps the counters of the parsers from overflowing, and than
-- `Usize.max`.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no division
-- by zero, no endless loop) and what its answer is.
--
-- Read before this file: the header of crates/limit-core/src/lib.rs (the rules), and Models.lean.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every argument; the two parsers for every list of bytes that is `Short`):
--     EveryFunctionReturns        all the functions return
--     TheWeightOfShares           `weight_of_shares`: 0, 1, 10000 at the ends, never outside 1 to 10000
--     TheSharesOfWeight           `shares_of_weight`: 2 to 262144, and the weight of the answer reaches the weight asked
--     TheSharesAreChecked         `shares_ok`: 0 or 2 to 262144
--     TheBlockIoWeight            `io_weight_of_blkio`: exact formula, 1 to 10000, never smaller for more
--     TheLimitOfARequest          `limit_of`: not set, no limit, that many bytes, or invalid
--     TheSwapOfTheCgroup          `swap_max`: the swap alone, or invalid; never a wrapped difference
--     TheCpuMax                   `cpu_max`: exact table; a positive quota is never "no limit"
--     TheNanoCpus                 `nano_cpus_max`, `nano_cpus_of`: exact, rounded down, no wrap
--     TheQuotaOfASecond           `quota_per_sec`: exact, saturated at the top, never for what `cpu_max` takes
--     TheOomScore                 `oom_score_adj`: -1000 to 1000 kept as written, any other number refused
--     TheSandboxLimits            `with_overhead` and the `sandbox_*`: exact sums, saturated, never smaller
--     TheCpusetMask               `cpuset_mask`: the mask only gains bits below the length it answers
--     TheSizeIsBelowTheTop        `parse_size`: an answer is not negative and below `i64::MAX`
--
--   Trusted (not checked here):
--     Charon and Aeneas (the versions in ../../pins) and the models Aeneas has of the library;
--     Models.lean, the three functions Aeneas has no model of: `float::weight`, which returns some
--     number (see it), and the two halves of `?` on an option, `Option::branch` and
--     `Option::from_residual`; Lean itself.
--
--   Not claimed:
--     the weight `float::weight` gives for a count of shares between the ends, that it never gives a
--     smaller weight for more shares, and that `shares_of_weight` is its inverse (the answer reaches
--     the weight asked, but is not shown to be the FIRST that does): they depend on `f64` math of
--     which nothing is modelled, and the tests of the crate check them at every count of shares;
--     that `cpuset_mask` answers `Some` exactly for the list of CPUs the grammar of rule 10 names, and
--     which bits it sets (only that it stays in the bytes it answers); that `parse_size` reads the
--     size as go-units does, its refusals and their places (only the bounds of an answer), these
--     are checked by the tests against a model of the code the crate replaced; and the time and
--     the memory used.
--
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
-- and its answer `r` satisfies `P`"; `↑x` (or `x.val`) is the number a machine integer is;
-- `∀`, `∃`, `∧`, `∨`, `→`, `↔` are "for all", "there is", "and", "or", "if ... then", "exactly when".
import Extracted.Funs
open Aeneas Aeneas.Std Result velarx_limit_core
namespace LimitCore

/-- The period a request says: 0 is the default, 100000 microseconds. -/
def PeriodOf (p : Nat) : Nat := if p = 0 then 100000 else p

/-- The greatest quota the kernel takes: 2^44 - 1 microseconds. -/
def MaxQuota : Nat := 2 ^ 44 - 1

/-- The greatest `i64`. -/
def MaxI64 : Int := 2 ^ 63 - 1

/-- A list of bytes is shorter than 2^62 and than the largest `usize`: no memory is that large, and
a Rust slice is never as long as `usize::MAX`. -/
def Short (s : List Std.U8) : Prop := s.length < 2 ^ 62 ∧ s.length < Std.Usize.max

/-- `weight` is the block IO weight `w` as `io.weight`: 0 for 0, else the weight held in 10 to 1000
and moved linearly onto 1 to 10000. -/
def IoWeightOf (w : Nat) : Nat :=
  if w = 0 then 0 else 1 + (min 1000 (max 10 w) - 10) * 9999 / 990

/-- The answer `r` is the limit that the signed number `v` of a request is: 0 is not set, -1 is no
limit, a positive number is that many bytes, any other number is invalid. -/
def LimitIs (v : Int) (r : Limit) : Prop :=
  if v = 0 then r = Limit.Unset
  else if v = -1 then r = Limit.Unlimited
  else if 0 < v then ∃ b : Std.U64, r = Limit.Bytes b ∧ ↑b = v
  else r = Limit.Invalid

/-- The answer `r` is the swap of the cgroup for a memory limit `m` and a memory and swap limit
`s` of a request: no swap limit (0 or -1) is `Unlimited` unless the memory limit is no limit
either, a swap limit below the memory limit or with no memory limit to bound is `Invalid`, else the
swap is the difference. -/
def SwapIs (m s : Int) (r : Swap) : Prop :=
  if s < -1 ∨ (s ≤ 0 ∧ m < -1) then r = Swap.Invalid
  else if s ≤ 0 then r = Swap.Unlimited
  else if 0 < m ∧ m ≤ s then ∃ x : Std.U64, r = Swap.Max x ∧ ↑x = s - m
  else r = Swap.Invalid

/-- The answer `r` is the `cpu.max` of a quota and a period: a period that is out of range is
invalid, even with no quota; no quota (0 or -1) is `Unlimited`; a quota that is not 1000 to 2^44 - 1
is invalid; else it is the quota and the period as they are. -/
def CpuMaxIs (quota : Int) (period : Nat) (r : CpuMax) : Prop :=
  if PeriodOf period < 1000 ∨ 1000000 < PeriodOf period then r = CpuMax.Invalid
  else if quota = 0 ∨ quota = -1 then r = CpuMax.Unlimited
  else if quota < 1000 ∨ ↑MaxQuota < quota then r = CpuMax.Invalid
  else ∃ q p : Std.U64, r = CpuMax.Quota q p ∧ ↑q = quota ∧ ↑p = PeriodOf period

/-- The limit of a sandbox: the sum of the containers' `r` and the overhead `o` (none if it is
negative) when `r` is set, saturated at `i64::MAX`; `r` as it is when it is not. -/
def WithOverhead (r o : Int) : Int := if 0 < r then min (r + max o 0) MaxI64 else r

/-- The quota of a sandbox: when all four numbers are positive, the sum of `r` and the overhead's
quota `o` of its own period `op` converted to the sandbox's period `rp` (rounded down), saturated;
else `WithOverhead`. -/
def SandboxQuotaOf (r rp o op : Int) : Int :=
  if 0 < r ∧ 0 < o ∧ 0 < op ∧ 0 < rp then min (r + o * rp / op) MaxI64 else WithOverhead r o

/-- Every function returns on every argument (no panic, no overflow, no division by zero, no endless
loop): the conversions of the limits, the sandbox sums, `cpuset_mask` of any list of bytes and any
mask, and `parse_size` of any bytes.  NOT said: what they answer (the claims below). -/
def EveryFunctionReturns : Prop :=
  (∀ shares, weight_of_shares shares ⦃ _ => True ⦄) ∧
  (∀ weight, shares_of_weight weight ⦃ _ => True ⦄) ∧
  (∀ shares, shares_ok shares ⦃ _ => True ⦄) ∧
  (∀ weight, io_weight_of_blkio weight ⦃ _ => True ⦄) ∧
  (∀ v, limit_of v ⦃ _ => True ⦄) ∧
  (∀ m s, swap_max m s ⦃ _ => True ⦄) ∧
  (∀ quota period, cpu_max quota period ⦃ _ => True ⦄) ∧
  (∀ nano, nano_cpus_max nano ⦃ _ => True ⦄) ∧
  (∀ quota period, nano_cpus_of quota period ⦃ _ => True ⦄) ∧
  (∀ quota period, quota_per_sec quota period ⦃ _ => True ⦄) ∧
  (∀ v, oom_score_adj v ⦃ _ => True ⦄) ∧
  (∀ r o, with_overhead r o ⦃ _ => True ⦄) ∧
  (∀ r o, sandbox_shares r o ⦃ _ => True ⦄) ∧
  (∀ rs os om, sandbox_swap rs os om ⦃ _ => True ⦄) ∧
  (∀ r rp o op, sandbox_quota r rp o op ⦃ _ => True ⦄) ∧
  (∀ rp op, sandbox_period rp op ⦃ _ => True ⦄) ∧
  (∀ list mask, Short list.val → cpuset_mask list mask ⦃ _ => True ⦄) ∧
  (∀ s, Short s.val → parse_size s ⦃ _ => True ⦄)

/-- `weight_of_shares` of 0 is 0 (nothing to write), of 1 or 2 is 1, of 262144 or more is 10000,
and of any other number of shares is a weight of 1 to 10000, WHATEVER `float::weight` answers.  NOT
said: which weight it is between the ends, nor that more shares never give a smaller one. -/
def TheWeightOfShares : Prop :=
  ∀ shares : Std.U64, weight_of_shares shares ⦃ w =>
    (shares.val = 0 → w.val = 0) ∧ (0 < shares.val → 1 ≤ w.val ∧ w.val ≤ 10000) ∧
    (shares.val ≤ 2 → 0 < shares.val → w.val = 1) ∧ (262144 ≤ shares.val → w.val = 10000) ⦄

/-- `shares_of_weight` of 0 is 0, and of any other weight is a count of 2 to 262144 shares that is
either 262144 or has a weight (`weight_of_shares`) of at least the weight asked.  NOT said: that it
is the FIRST such count (that needs `weight_of_shares` to grow with the shares, which needs the
float). -/
def TheSharesOfWeight : Prop :=
  ∀ weight : Std.U64, shares_of_weight weight ⦃ r =>
    (weight.val = 0 → r.val = 0) ∧
    (0 < weight.val → 2 ≤ r.val ∧ r.val ≤ 262144 ∧
      (r.val = 262144 ∨ weight_of_shares r ⦃ w => weight.val ≤ w.val ⦄)) ⦄

/-- `shares_ok` is true exactly for 0 and the counts of 2 to 262144. -/
def TheSharesAreChecked : Prop :=
  ∀ shares : Std.U64, shares_ok shares ⦃ b =>
    (b = true ↔ shares.val = 0 ∨ (2 ≤ shares.val ∧ shares.val ≤ 262144)) ⦄

/-- `io_weight_of_blkio` is `IoWeightOf` (0 for 0, else 1 + (weight held in 10 to 1000 - 10) *
9999 / 990), so it is 1 to 10000 for a weight that is set; and a greater weight never gives a
smaller `io.weight`. -/
def TheBlockIoWeight : Prop :=
  (∀ w : Std.U64, io_weight_of_blkio w ⦃ r =>
    r.val = IoWeightOf w.val ∧ (0 < w.val → 1 ≤ r.val ∧ r.val ≤ 10000) ⦄) ∧
  (∀ a b : Std.U64, a.val ≤ b.val → io_weight_of_blkio a ⦃ x =>
    io_weight_of_blkio b ⦃ y => x.val ≤ y.val ⦄ ⦄)

/-- `limit_of` is `LimitIs`: 0 is not set, -1 no limit, a positive number that many bytes (the same
number, not its absolute value, not a wrapped one), any other number invalid. -/
def TheLimitOfARequest : Prop :=
  ∀ v : Std.I64, limit_of v ⦃ r => LimitIs v.val r ⦄

/-- `swap_max` is `SwapIs`.  NOT said: anything of what the kernel does with the swap. -/
def TheSwapOfTheCgroup : Prop :=
  ∀ m s : Std.I64, swap_max m s ⦃ r => SwapIs m.val s.val r ⦄

/-- `cpu_max` is `CpuMaxIs`; so a positive quota is never turned into "no limit", and the quota
and the period of an answer are the ones asked (a period of 0 the default). -/
def TheCpuMax : Prop :=
  ∀ (quota : Std.I64) (period : Std.U64), cpu_max quota period ⦃ r =>
    CpuMaxIs quota.val period.val r ∧ (0 < quota.val → r ≠ CpuMax.Unlimited) ⦄

/-- `nano_cpus_max` of no more than 0 is `Unlimited`; of a positive count it is invalid below
10000 (a quota of 0 would be no limit), else it is `cpu_max` of the quota `nano / 10000` of the
default period, and never `Unlimited`.  `nano_cpus_of` is the count of a quota and a period,
`quota * 1000000000 / period` rounded down and saturated at `i64::MAX`, 0 for no quota; and for a
count that `nano_cpus_max` made a quota of, it is at most the count and less than 10000 below it. -/
def TheNanoCpus : Prop :=
  (∀ nano : Std.I64, nano_cpus_max nano ⦃ r =>
    (nano.val ≤ 0 → r = CpuMax.Unlimited) ∧
    (0 < nano.val → nano.val < 10000 → r = CpuMax.Invalid) ∧
    (10000 ≤ nano.val → CpuMaxIs (nano.val / 10000) 100000 r) ∧
    (0 < nano.val → r ≠ CpuMax.Unlimited) ⦄) ∧
  (∀ (quota : Std.I64) (period : Std.U64), nano_cpus_of quota period ⦃ n =>
    n.val = if quota.val ≤ 0 then 0
      else min (quota.val * 1000000000 / (PeriodOf period.val : Int)) MaxI64 ⦄) ∧
  (∀ nano : Std.I64, nano_cpus_max nano ⦃ r => ∀ (q p : Std.U64) (i : Std.I64),
    r = CpuMax.Quota q p → i.val = q.val →
      nano_cpus_of i 100000#u64 ⦃ n => n.val ≤ nano.val ∧ nano.val - n.val < 10000 ⦄ ⦄)

/-- `quota_per_sec` is `quota * 1000000 / period` rounded down and saturated at 2^64 - 1; for a
quota of 1000 to 2^44 - 1 and a period that `cpu_max` takes (0 or 1000 to 1000000) it is the
quotient itself, never saturated. -/
def TheQuotaOfASecond : Prop :=
  ∀ quota period : Std.U64, quota_per_sec quota period ⦃ r =>
    r.val = min (quota.val * 1000000 / PeriodOf period.val) (2 ^ 64 - 1) ∧
    (1000 ≤ quota.val → quota.val ≤ MaxQuota →
      (period.val = 0 ∨ (1000 ≤ period.val ∧ period.val ≤ 1000000)) →
      r.val = quota.val * 1000000 / PeriodOf period.val) ⦄

/-- `oom_score_adj` of -1000 to 1000 is that number (not its low bits), of any other number none. -/
def TheOomScore : Prop :=
  ∀ v : Std.I64, oom_score_adj v ⦃ r =>
    (-1000 ≤ v.val → v.val ≤ 1000 → ∃ s : Std.I32, r = some s ∧ s.val = v.val) ∧
    ((v.val < -1000 ∨ 1000 < v.val) → r = none) ⦄

/-- `with_overhead` is `WithOverhead`; `sandbox_shares` is that, at most 262144; `sandbox_swap` is
`WithOverhead` with the greater of the overhead's swap and memory; `sandbox_quota` is
`SandboxQuotaOf`; `sandbox_period` is the containers' period when it is set, else the overhead's.
So a limit that is set stays set and never shrinks (no wrap), and one that is not set stays so. -/
def TheSandboxLimits : Prop :=
  (∀ r o : Std.I64, with_overhead r o ⦃ x => x.val = WithOverhead r.val o.val ∧
    (0 < r.val → r.val ≤ x.val) ∧ (r.val ≤ 0 → x.val = r.val) ⦄) ∧
  (∀ r o : Std.I64, sandbox_shares r o ⦃ x => x.val = min (WithOverhead r.val o.val) 262144 ⦄) ∧
  (∀ rs os om : Std.I64, sandbox_swap rs os om ⦃ x =>
    x.val = WithOverhead rs.val (max os.val om.val) ⦄) ∧
  (∀ r rp o op : Std.I64, sandbox_quota r rp o op ⦃ x =>
    x.val = SandboxQuotaOf r.val rp.val o.val op.val ∧ (0 < r.val → r.val ≤ x.val) ⦄) ∧
  (∀ rp op : Std.I64, sandbox_period rp op ⦃ x => x.val = if 0 < rp.val then rp.val else op.val ⦄)

/-- When `cpuset_mask` answers `Some used`, `used` is at most 1024 (the bytes of the mask) and the
bytes of the mask from `used` on are as they were: only the first `used` bytes gain bits.  NOT
said: which bits (the CPUs of the list), nor which lists are refused. -/
def TheCpusetMask : Prop :=
  ∀ (list : Slice Std.U8) (mask : Std.Array Std.U8 1024#usize), Short list.val →
    cpuset_mask list mask ⦃ r =>
      ∀ used, r.1 = some used → used.val ≤ 1024 ∧
        ∀ i, used.val ≤ i → i < 1024 → r.2.val[i]? = mask.val[i]? ⦄

/-- When `parse_size` answers a size, it is not negative and below `i64::MAX`: a size that does not
fit is refused, never saturated and never wrapped.  NOT said: which text makes which size, nor the
refusals. -/
def TheSizeIsBelowTheTop : Prop :=
  ∀ s : Slice Std.U8, Short s.val → parse_size s ⦃ r =>
    ∀ n, r = core.result.Result.Ok n → 0 ≤ n.val ∧ n.val < MaxI64 ⦄

end LimitCore
