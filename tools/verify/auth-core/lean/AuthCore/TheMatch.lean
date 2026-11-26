-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `matches key host repo` answers the length of the key exactly when
-- `Matches key host repo` (Spec.lean), and none otherwise.  It returns for any bytes.
-- Why it is needed: `pick` asks `matches` for every key, and every claim about which key is for
-- which host rests on it.
-- Read before this file: Spec.lean, Bytes.lean, TheHub.lean.
-- Notation: `l <+: l'` is "l is the beginning of l'"; `l.drop n` is `l` without its first `n`;
-- `step as ⟨ x, hx ⟩` runs one line of a Rust function and names its result `x` and what is known
-- of it `hx`.
import AuthCore.Spec
import AuthCore.Bytes
import AuthCore.TheHub

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- A list is `pre`, or `pre`, a `/` and more, exactly when `pre` is its beginning and it ends
there or goes on with a `/` (a boundary of whole components). -/
theorem boundary_says (l pre : Bytes) :
    (pre <+: l ∧ (l.length = pre.length ∨ l[pre.length]? = some Slash)) ↔
      (l = pre ∨ ∃ t, l = pre ++ Slash :: t) := by
  constructor
  · rintro ⟨⟨u, rfl⟩, h⟩
    cases u with
    | nil => left; simp
    | cons c u' =>
      right
      rcases h with h | h
      · simp at h
      · simp only [List.getElem?_append_right (le_refl _), Nat.sub_self] at h
        simp at h
        exact ⟨u', by rw [h]⟩
  · rintro (rfl | ⟨t, rfl⟩)
    · exact ⟨List.prefix_refl _, Or.inl rfl⟩
    · refine ⟨⟨Slash :: t, rfl⟩, Or.inr ?_⟩
      simp []

/-- What comes after the `/` that follows `pre` in `pre ++ Slash :: path`. -/
theorem after_the_slash (pre path : Bytes) : (pre ++ Slash :: path).drop (pre.length + 1) = path := by
  rw [List.drop_append]
  simp

/-- `Matches` says, in the terms the code computes: the host is the beginning of the key and the
key ends there or goes on with a `/`; and if it goes on, the repository is not empty and the part
of the key after the `/` is the beginning of the repository and the repository ends there or goes
on with a `/`. -/
theorem matches_by_the_code (key host repo : Bytes) :
    Matches key host repo ↔
      ((HubOf host <+: key ∧ (key.length = (HubOf host).length ∨
          key[(HubOf host).length]? = some Slash)) ∧
        ((HubOf host).length < key.length →
          (repo ≠ [] ∧ key.drop ((HubOf host).length + 1) <+: repo ∧
            (repo.length = (key.drop ((HubOf host).length + 1)).length ∨
              repo[(key.drop ((HubOf host).length + 1)).length]? = some Slash)))) := by
  rw [boundary_says]
  constructor
  · rintro (rfl | ⟨path, rfl, nonempty, tail⟩)
    · exact ⟨Or.inl rfl, fun h => absurd h (by simp)⟩
    · refine ⟨Or.inr ⟨path, rfl⟩, fun _ => ⟨nonempty, ?_⟩⟩
      have drop := after_the_slash (HubOf host) path
      rw [drop]
      have := (boundary_says repo path).mpr tail
      exact this
  · rintro ⟨(rfl | ⟨path, rfl⟩), h⟩
    · exact Or.inl rfl
    · right
      have drop := after_the_slash (HubOf host) path
      have long : (HubOf host).length < (HubOf host ++ Slash :: path).length := by simp
      obtain ⟨nonempty, tail⟩ := h long
      rw [drop] at tail
      exact ⟨path, rfl, nonempty, (boundary_says repo path).mp tail⟩

/-- **`matches`** answers the length of the key exactly when the key is for the request. -/
@[step] theorem matches_says (key host repo : Slice Std.U8) :
    «matches» key host repo ⦃ r =>
      (Matches key.val host.val repo.val ∧ r = some key.len) ∨
      (¬ Matches key.val host.val repo.val ∧ r = none) ⦄ := by
  unfold «matches»
  step as ⟨ h1, is_h1 ⟩
  step as ⟨ b, is_b ⟩
  have by_code := matches_by_the_code key.val host.val repo.val
  rw [← is_h1] at by_code
  have key_len : key.len.val = key.length := Slice.len_val key
  have h1_len : h1.len.val = h1.length := Slice.len_val h1
  have repo_len : repo.len.val = repo.length := Slice.len_val repo
  have prefix_of_b : b = true ↔ h1.val <+: key.val := by
    rw [is_b]; simp
  by_cases hb : b = true
  · have begins := prefix_of_b.mp hb
    simp only [hb, ite_true]
    by_cases same_len : key.len = h1.len
    · simp only [same_len, ite_true, Std.bind_ok]
      simp only [gt_iff_lt, lt_self_iff_false, ite_false, ite_true, Std.bind_ok]
      refine (WP.spec_ok _).mpr ?_
      left
      have leneq : key.val.length = h1.val.length := by
        have := congrArg UScalar.val same_len
        rw [key_len, h1_len] at this
        exact this
      refine ⟨by_code.mpr ⟨⟨begins, Or.inl leneq⟩, fun h => ?_⟩, rfl⟩
      rw [leneq] at h
      exact absurd h (lt_irrefl _)
    · simp only [same_len, ite_false]
      step as ⟨ c, is_c ⟩
      have differ : (key.val).length ≠ h1.val.length := by
        intro h
        exact same_len (UScalar.eq_of_val_eq (by rw [key_len, h1_len]; exact h))
      have longer : h1.length < key.length := by
        have := begins.length_le
        have : h1.val.length = h1.length := rfl
        have : key.val.length = key.length := rfl
        omega
      by_cases hc : c = true
      · simp only [hc, ite_true]
        have longer' : key.len > h1.len := by scalar_tac
        simp only [longer', ite_true]
        step as ⟨ i3, is_i3 ⟩
        step as ⟨ path, is_path ⟩
        step as ⟨ b1, is_b1 ⟩
        have path_is : path.val = key.val.drop (h1.val.length + 1) := by
          rw [is_path, is_i3, h1_len]
        have longer_val : h1.val.length < key.val.length := longer
        have slash_at : key.val[h1.val.length]? = some Slash := by
          have := is_c.mp hc
          rw [h1_len] at this
          exact this
        have m_iff : Matches key.val host.val repo.val ↔ (repo.val ≠ [] ∧ path.val <+: repo.val ∧
            (repo.val.length = path.val.length ∨ repo.val[path.val.length]? = some Slash)) := by
          rw [by_code, path_is]
          constructor
          · intro m; exact m.2 longer_val
          · intro r; exact ⟨⟨begins, Or.inr slash_at⟩, fun _ => r⟩
        have empty_says : b1 = true ↔ repo.val = [] := by
          have : (b1 = true) = (repo.length = 0) := is_b1
          rw [this]
          simp [Slice.length]
        by_cases empty : b1 = true
        · simp only [empty, ite_true, Std.bind_ok]
          refine (WP.spec_ok _).mpr ?_
          right
          exact ⟨fun m => (m_iff.mp m).1 (empty_says.mp empty), rfl⟩
        · simp only [empty, Bool.false_eq_true, ite_false]
          step as ⟨ b2, is_b2 ⟩
          have repo_not_empty : repo.val ≠ [] := fun h => empty (empty_says.mpr h)
          by_cases begins2 : b2 = true
          · simp only [begins2, ite_true]
            have path_prefix : path.val <+: repo.val := by
              have := (is_b2.mp begins2).2
              simpa using this
            by_cases same_len2 : repo.len = path.len
            · simp only [same_len2, ite_true, Std.bind_ok]
              refine (WP.spec_ok _).mpr ?_
              left
              refine ⟨m_iff.mpr ⟨repo_not_empty, path_prefix, Or.inl ?_⟩, rfl⟩
              have := congrArg UScalar.val same_len2
              rw [repo_len, Slice.len_val path] at this
              exact this
            · simp only [same_len2, ite_false]
              step as ⟨ d, is_d ⟩
              have lens_differ : repo.val.length ≠ path.val.length := by
                intro h
                exact same_len2 (UScalar.eq_of_val_eq (by rw [repo_len, Slice.len_val path]; exact h))
              by_cases hd : d = true
              · simp only [hd, ite_true]
                refine (WP.spec_ok _).mpr ?_
                left
                refine ⟨m_iff.mpr ⟨repo_not_empty, path_prefix, Or.inr ?_⟩, rfl⟩
                have := is_d.mp hd
                rwa [Slice.len_val path] at this
              · simp only [hd, Bool.false_eq_true, ite_false]
                refine (WP.spec_ok _).mpr ?_
                right
                refine ⟨fun m => ?_, rfl⟩
                rcases (m_iff.mp m).2.2 with h | h
                · exact lens_differ h
                · apply hd
                  apply is_d.mpr
                  rw [Slice.len_val path]
                  exact h
          · simp only [begins2, Bool.false_eq_true, ite_false, Std.bind_ok]
            refine (WP.spec_ok _).mpr ?_
            right
            refine ⟨fun m => begins2 (is_b2.mpr ⟨by simp, ?_⟩), rfl⟩
            simpa using (m_iff.mp m).2.1
      · simp only [hc]
        simp only [Bool.false_eq_true, ite_false, Std.bind_ok]
        refine (WP.spec_ok _).mpr ?_
        right
        refine ⟨fun m => ?_, rfl⟩
        have := ((by_code.mp m).1).2
        rcases this with h | h
        · exact differ h
        · exact hc (is_c.mpr h)
  · simp only [hb, Bool.false_eq_true, ite_false, Std.bind_ok]
    refine (WP.spec_ok _).mpr ?_
    right
    exact ⟨fun m => hb (prefix_of_b.mpr ((by_code.mp m).1).1), rfl⟩

end AuthCore
