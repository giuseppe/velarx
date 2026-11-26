-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/limit-core.  The statements are in
-- LimitCore/Spec.lean; the proofs are in the other files of LimitCore/, from Claims.lean.
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the three of Models.lean).
--
-- Read before this file: LimitCore/Spec.lean.
import Proved
import LimitCore.Claims

example : LimitCore.EveryFunctionReturns := LimitCore.every_function_returns
example : LimitCore.TheWeightOfShares := LimitCore.weight_of_shares_spec
example : LimitCore.TheSharesOfWeight := LimitCore.shares_of_weight_spec
example : LimitCore.TheSharesAreChecked := LimitCore.shares_ok_spec
example : LimitCore.TheBlockIoWeight := LimitCore.io_weight_spec
example : LimitCore.TheLimitOfARequest := LimitCore.limit_of_spec
example : LimitCore.TheSwapOfTheCgroup := LimitCore.swap_max_spec
example : LimitCore.TheCpuMax := LimitCore.cpu_max_spec
example : LimitCore.TheNanoCpus := LimitCore.nano_cpus_spec
example : LimitCore.TheQuotaOfASecond := LimitCore.quota_per_sec_spec
example : LimitCore.TheOomScore := LimitCore.oom_score_spec
example : LimitCore.TheSandboxLimits := LimitCore.sandbox_limits_spec
example : LimitCore.TheCpusetMask := LimitCore.cpuset_mask_spec
example : LimitCore.TheSizeIsBelowTheTop := LimitCore.size_is_below_the_top

#proved LimitCore.every_function_returns
#proved LimitCore.weight_of_shares_spec
#proved LimitCore.shares_of_weight_spec
#proved LimitCore.shares_ok_spec
#proved LimitCore.io_weight_spec
#proved LimitCore.limit_of_spec
#proved LimitCore.swap_max_spec
#proved LimitCore.cpu_max_spec
#proved LimitCore.nano_cpus_spec
#proved LimitCore.quota_per_sec_spec
#proved LimitCore.oom_score_spec
#proved LimitCore.sandbox_limits_spec
#proved LimitCore.cpuset_mask_spec
#proved LimitCore.size_is_below_the_top
