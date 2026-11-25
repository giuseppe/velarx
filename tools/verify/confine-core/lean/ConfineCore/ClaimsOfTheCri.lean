-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about `cri.from_cri`, and the claim
-- that `decide` and `from_cri` always return.
-- Why it is needed: Theorems.lean ties each claim to its proof.
-- Read before this file: Spec.lean, ClaimsOfTheDecision.lean.
-- Notation: `rcases c with ⟨...⟩` takes a context apart into its three fields; `cases x` splits on
-- the values of a field; `simp [f]` computes with the definition of `f`.
import ConfineCore.ClaimsOfTheDecision

open Aeneas Aeneas.Std Result
open velarx_confine_core hiding decide

namespace ConfineCore

/-- `from_cri` returns: it has no loop, no division and no index, only choices on the fields. -/
theorem from_cri_always_returns : ∀ c : cri.Context, cri.from_cri c ⦃ _ => True ⦄ := by
  intro c
  rcases c with ⟨present, privileged, profile⟩
  cases present <;> cases privileged <;> cases profile <;> simp [cri.from_cri]

theorem decide_and_from_cri_always_return : DecideAndFromCriAlwaysReturn :=
  ⟨decide_always_returns, from_cri_always_returns⟩

/-- No context: the code answers the default profile and no lists, whatever the other fields say. -/
theorem no_context_gives_the_engine_defaults : NoContextGivesTheEngineDefaults := by
  intro c no_context
  rcases c with ⟨present, privileged, profile⟩
  simp only at no_context
  subst no_context
  cases privileged <;> cases profile <;> simp [cri.from_cri]

/-- A privileged context: unconfined when there is a context, and no lists. -/
theorem a_privileged_context_gives_unconfined_and_no_paths :
    APrivilegedContextGivesUnconfinedAndNoPaths := by
  intro c privileged
  rcases c with ⟨present, privileged', profile⟩
  simp only at privileged
  subst privileged
  cases present <;> cases profile <;> simp [cri.from_cri]

/-- A context that is there and not privileged: one case for each profile. -/
theorem a_profile_means_what_it_names : AProfileMeansWhatItNames := by
  intro c present not_privileged
  rcases c with ⟨present', privileged, profile⟩
  simp only at present not_privileged
  subst present not_privileged
  cases profile <;> simp [cri.from_cri]

/-- The two profiles that are never unconfined, from the table of the profiles. -/
theorem a_named_profile_never_gives_unconfined : ANamedProfileNeverGivesUnconfined := by
  intro c present not_privileged named
  rcases c with ⟨present', privileged, profile⟩
  simp only at present not_privileged named
  subst present not_privileged
  rcases named with is_default | is_localhost <;> subst_vars <;> simp [cri.from_cri]

/-- The lists are the context's exactly when it is there and not privileged. -/
theorem own_paths_only_with_a_context : OwnPathsOnlyWithAContext := by
  intro c
  rcases c with ⟨present, privileged, profile⟩
  cases present <;> cases privileged <;> cases profile <;> simp [cri.from_cri]

end ConfineCore
