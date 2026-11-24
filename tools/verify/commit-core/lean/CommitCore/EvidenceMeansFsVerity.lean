-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `evidence_is_fs_verity`: a digest that has `Evidence` (or is the store's
-- word) is an fs-verity digest, and the one the claim names if it names one, as long as the
-- shell reports fs-verity digests (`ReportsAreFsVerity`: `verdict` checks it) and the claim is
-- not malformed.
--
-- Why it is needed: it is the proof of ANameIsAnFsVerityDigest: the name is the same as a digest
-- the shell reported or the claim names, and `Same` keeps the kind, the algorithm and the length.
--
-- Read before this file: Spec.lean, NamesHaveEvidence.lean.
--
-- Notation: `rcases h with (⟨...⟩ | ⟨...⟩ | ⟨...⟩) | ⟨...⟩` takes apart a statement that is one of
-- four, naming what each says.
import CommitCore.NamesHaveEvidence
open Aeneas Aeneas.Std Result velarx_commit_core
namespace CommitCore

/-- A digest the kernel measured or the shell computed, as the shell reports them, is an
fs-verity digest; so is one that is the same as it. -/
theorem same_as_a_report_is_fs_verity {seen : Seen} (reports : ReportsAreFsVerity seen)
    {d m : Dig} (same : Same m d) (is_report : seen.kernel = some m ∨ seen.merkle = some m) :
    d.verity = true := by
  have flag : m.verity = true := by
    rcases is_report with kernel | merkle
    · exact reports.1 m kernel
    · exact reports.2.1 m merkle
  rw [← same.1]
  exact flag

/-- The digest of a file named or kept is an fs-verity digest, and is the one the claim names,
if it names one. -/
theorem evidence_is_fs_verity {f : Facts} {seen : Seen} {d : Dig}
    (reports : ReportsAreFsVerity seen) (fine : ¬ Malformed f.claim)
    (evidence : Evidence f seen d ∨ TheStoreHoldsIt f seen d) :
    d.verity = true ∧ Allows f.claim d := by
  rcases evidence with (⟨⟨m, kernel, same⟩, allows, _⟩ | ⟨⟨m, merkle, same⟩, allows, _⟩ |
      ⟨_, e, expected, same⟩) | ⟨_, claim_is, _⟩
  · exact ⟨same_as_a_report_is_fs_verity reports same (Or.inl kernel), allows⟩
  · exact ⟨same_as_a_report_is_fs_verity reports same (Or.inr merkle), allows⟩
  · refine ⟨?_, fun e' expected' => ?_⟩
    · rw [← same.1]
      exact expected_is_fs_verity fine expected
    · rw [expected] at expected'
      cases expected'
      exact same
  · have expected : claimedVerity f.claim = some d := by rw [claim_is]; rfl
    refine ⟨expected_is_fs_verity fine expected, fun e expected' => ?_⟩
    rw [expected] at expected'
    cases expected'
    exact same_refl _

end CommitCore
