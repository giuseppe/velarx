-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean that say what a name rests on, and
-- that `Dig::eq` and `plan`, `verdict`, `keep` return: NothingEverPanics,
-- DigestEqualityIsSameDigest, SameDigestIsAnEquality, NamedImpliesEvidence,
-- ReplayedByAnotherProducerIsNeverTrusted, NoNameAgainstTheMeasure and ANameIsAnFsVerityDigest.
--
-- Why it is needed: Theorems.lean names one theorem for each claim; these are those theorems.  Each
-- is short: the work is in NamesHaveEvidence.lean (the evidence of each way of answering) and
-- the files before it.
--
-- Read before this file: Spec.lean, NamesHaveEvidence.lean.
--
-- Notation: `obtain ⟨p, is_plan, planned, answered⟩ := verdict_is f seen` takes the plan `verdict`
-- follows and the cases of its answer; `refine WP.spec_mono answered ?_` is "the answer satisfies
-- something that implies what is claimed"; `intro` takes the hypotheses of a claim.
import CommitCore.EvidenceMeansFsVerity
import CommitCore.TheKeep
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- `Dig::eq`, `plan`, `verdict` and `keep` return: each has a statement that it returns (the
loop of `Dig::eq` ends, the rest are straight line). -/
theorem nothing_ever_panics : NothingEverPanics := by
  refine ⟨fun a b => ?_, fun f kernel held => ?_, fun f seen => ?_, fun f named held => ?_⟩
  · exact WP.spec_mono (dig_eq_spec a b) (fun _ _ => trivial)
  · exact WP.spec_mono (plan_is f kernel held) (fun _ _ => trivial)
  · obtain ⟨_, _, _, answered⟩ := verdict_is f seen
    exact WP.spec_mono answered (fun _ _ => trivial)
  · exact WP.spec_mono (keep_is f named held) (fun _ _ => trivial)

/-- `Dig::eq` is `Same`: the statement of `dig_eq_spec`. -/
theorem digest_equality_is_same_digest : DigestEqualityIsSameDigest :=
  dig_eq_spec

/-- `Same` is reflexive, symmetric and transitive: the three facts of SameDigest.lean. -/
theorem same_digest_is_an_equality : SameDigestIsAnEquality :=
  ⟨same_refl, fun _ _ => same_symm, fun _ _ _ => same_trans⟩

/-- A name has evidence: `answer_has_evidence` for the answer of `verdict`. -/
theorem named_implies_evidence : NamedImpliesEvidence := by
  intro f seen
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  exact WP.spec_mono answered (fun _ answer => answer_has_evidence answer)

/-- A replay of another producer is not trusted: the engine does not vouch for a replay that is
not its own, so the evidence of a name or a kept object is the kernel's or the bytes'. -/
theorem replayed_by_another_producer_is_never_trusted :
    ReplayedByAnotherProducerIsNeverTrusted := by
  intro f seen k r replayed not_own
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer n named
  obtain ⟨names, keeps⟩ := answer_has_evidence answer
  -- the engine does not vouch for the file: it is a replay, and not its own
  have not_vouched : ¬ TheEngineVouches f := by
    rintro (⟨v, verified⟩ | ⟨own, _⟩)
    · simp [replayed] at verified
    · simp [not_own] at own
  rcases named with is_name | is_keep
  · rcases names n is_name with kernel | read | ⟨vouched, _⟩
    · exact Or.inl kernel
    · exact Or.inr read
    · exact absurd vouched not_vouched
  · rcases keeps n is_keep with (kernel | read | ⟨vouched, _⟩) | ⟨_, is_verity, _⟩
    · exact Or.inl kernel
    · exact Or.inr read
    · exact absurd vouched not_vouched
    · simp [replayed] at is_verity

/-- No name against the measure: a named or kept file agrees with itself (`Mismatch` has neither
`KernelDisagrees` nor `CopyDisagrees`). -/
theorem no_name_against_the_measure : NoNameAgainstTheMeasure := by
  intro f seen
  obtain ⟨_, _, _, answered⟩ := verdict_is f seen
  refine WP.spec_mono answered ?_
  intro v answer n named
  have agrees := answer_agrees answer named
  constructor
  · -- the kernel's measure of the file and the digest of the bytes read
    intro k m kernel merkle
    by_contra apart
    exact agrees (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl ⟨k, m, kernel, merkle, apart⟩)))))
  · -- the kernel's measure of the copy and the digest of the bytes written
    intro c m copy merkle
    by_contra apart
    exact agrees (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr ⟨c, m, copy, merkle, apart⟩)))))

/-- A name is an fs-verity digest: the evidence of the name, and the shell's fs-verity reports. -/
theorem a_name_is_an_fs_verity_digest : ANameIsAnFsVerityDigest := by
  intro f seen
  obtain ⟨_, _, _, answered⟩ := verdict_is_and_reports f seen
  refine WP.spec_mono answered ?_
  rintro v ⟨answer, reports_or_not_named⟩ n named
  -- a name or a kept object is only given when the reports are fs-verity digests
  have reports : ReportsAreFsVerity seen := by
    rcases reports_or_not_named with reports | not_named
    · exact reports
    · rcases named with is_name | is_keep
      · exact absurd is_name (not_named n).1
      · exact absurd is_keep (not_named n).2
  obtain ⟨names, keeps⟩ := answer_has_evidence answer
  have fine := not_malformed_of_agrees (answer_agrees answer named)
  rcases named with is_name | is_keep
  · exact evidence_is_fs_verity reports fine (Or.inl (names n is_name))
  · exact evidence_is_fs_verity reports fine (keeps n is_keep)

end CommitCore
