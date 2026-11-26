-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `pick keys host repo` answers the key picked (`Picks` of Spec.lean): of the
-- keys that match, one that no other matching key beats, and none exactly when no key matches.  It
-- returns for any list.
-- Why it is needed: the credential of a request is the one of the key `pick` answers.
-- Read before this file: Spec.lean, Bytes.lean, TheMatch.lean.
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each turn
-- while a fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩` runs one line of a Rust
-- function and names its result `x` and what is known of it `hx`; `l[i]?` is `some` of the element
-- at the place `i` of `l`, or `none`.
import AuthCore.Spec
import AuthCore.Bytes
import AuthCore.TheMatch

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- `NotBeaten` is an order: a key is not beaten by itself, and what is not beaten by a key that
no other beats is not beaten either. -/
theorem not_beaten_refl (k : Key) (i : Nat) : NotBeaten k i k i := by
  right
  exact ⟨rfl, Or.inr ⟨Iff.rfl, le_refl _⟩⟩

theorem not_beaten_trans (k : Key) (i : Nat) (k' : Key) (j : Nat) (k'' : Key) (m : Nat)
    (a : NotBeaten k i k' j) (b : NotBeaten k' j k'' m) : NotBeaten k i k'' m := by
  unfold NotBeaten at *
  by_cases w : AsWritten k <;> by_cases w' : AsWritten k' <;> by_cases w'' : AsWritten k'' <;>
    simp only [w, w', w'', true_and, false_and, iff_true, iff_false, not_true,
      not_false_eq_true, and_true, false_or, or_false, and_false, or_self,
      iff_self] at a b ⊢ <;> omega

/-- The key at the place `i` is replaced by the key at the place `j`, later, when it is more
specific, or as specific and written as it is kept, or as specific and the other is not. -/
theorem later_wins (k : Key) (i : Nat) (k' : Key) (j : Nat) (_later : i < j) :
    NotBeaten k' j k i ↔ (k.kept.length < k'.kept.length ∨
      (k.kept.length = k'.kept.length ∧ (AsWritten k' ∨ ¬ AsWritten k))) := by
  unfold NotBeaten
  by_cases w : AsWritten k <;> by_cases w' : AsWritten k' <;>
    simp only [w, w', true_and, false_and, iff_true, iff_false, not_true,
      not_false_eq_true, and_true, false_or, or_false, and_false, or_self,
      iff_self] <;> omega

/-- When the later key does not replace the earlier one, the earlier is not beaten by it. -/
theorem later_loses (k : Key) (i : Nat) (k' : Key) (j : Nat) (_later : i < j)
    (stays : ¬ (k.kept.length < k'.kept.length ∨
      (k.kept.length = k'.kept.length ∧ (AsWritten k' ∨ ¬ AsWritten k)))) :
    NotBeaten k i k' j := by
  unfold NotBeaten
  by_cases w : AsWritten k <;> by_cases w' : AsWritten k' <;>
    simp only [w, w', true_and, false_and, iff_true, iff_false, not_true,
      not_false_eq_true, and_true, false_or, or_false, and_false, or_self,
      iff_self, not_or] at stays ⊢ <;> omega

/-- The key at the place `i` is matched as `matches` says, on the bytes of its kept text: its rank
is its length. -/
theorem rank_of_says (keys : Slice Key) (i : Std.Usize) (host repo : Slice Std.U8)
    (inside : i.val < keys.length) :
    rank_of keys i host repo ⦃ r => ∃ k, keys.val[i.val]? = some k ∧
      ((Matches k.kept.val host.val repo.val ∧ ∃ n : Std.Usize, r = some n ∧ n.val = k.kept.length) ∨
        (¬ Matches k.kept.val host.val repo.val ∧ r = none)) ⦄ := by
  unfold rank_of
  step as ⟨ k, is_k ⟩
  have k_at : keys.val[i.val]? = some k := by
    simp [is_k, List.getElem?_eq_getElem (show i.val < keys.val.length from inside)]
  have := matches_says (alloc.vec.Vec.deref k.kept) host repo
  refine WP.spec_mono this ?_
  intro r h
  refine ⟨k, k_at, ?_⟩
  rcases h with ⟨m, rfl⟩ | ⟨m, rfl⟩
  · left
    refine ⟨by simpa using m, _, rfl, ?_⟩
    simp [ alloc.vec.Vec.deref]
  · right
    exact ⟨by simpa using m, rfl⟩

/-- **`is_kept`** says whether the key at the place `i` was written as it is kept. -/
theorem is_kept_says (keys : Slice Key) (i : Std.Usize) (inside : i.val < keys.length) :
    is_kept keys i ⦃ r => ∃ k, keys.val[i.val]? = some k ∧ (r = true ↔ AsWritten k) ⦄ := by
  unfold is_kept
  step as ⟨ k, is_k ⟩
  have k_at : keys.val[i.val]? = some k := by
    simp [is_k, List.getElem?_eq_getElem (show i.val < keys.val.length from inside)]
  step as ⟨ b, is_b ⟩
  exact ⟨k, k_at, by simpa [AsWritten] using is_b⟩

/-- What the loop of `pick` has seen after `n` keys: the best so far is a key of the first `n` that
matches, no matching key of those beats it, and its rank and whether it was written as it is kept
are known; with no best so far, none of the first `n` matches. -/
def PickSeen (keys : Slice Key) (host repo : Slice Std.U8) (best : Option Std.Usize)
    (rank : Std.Usize) (kept : Bool) (n : Nat) : Prop :=
  (∀ j, best = some j → j.val < n ∧ ∃ k, keys.val[j.val]? = some k ∧
      Matches k.kept.val host.val repo.val ∧ rank.val = k.kept.length ∧ (kept = true ↔ AsWritten k) ∧
      ∀ m k', m < n → keys.val[m]? = some k' → Matches k'.kept.val host.val repo.val →
        NotBeaten k j.val k' m) ∧
  (best = none → ∀ m k', m < n → keys.val[m]? = some k' → ¬ Matches k'.kept.val host.val repo.val)

/-- The key `i` does not match: what was seen stays true one key further. -/
theorem seen_unmatched (keys : Slice Key) (host repo : Slice Std.U8) (best : Option Std.Usize)
    (rank : Std.Usize) (kept : Bool) (i : Nat) (ki : Key) (ki_at : keys.val[i]? = some ki)
    (unmatched : ¬ Matches ki.kept.val host.val repo.val)
    (seen : PickSeen keys host repo best rank kept i) :
    PickSeen keys host repo best rank kept (i + 1) := by
  obtain ⟨found_is, none_is⟩ := seen
  refine ⟨fun j hj => ?_, fun hn m k' lt k'_at m' => ?_⟩
  · obtain ⟨lt, k, k_at, hm, hr, hk, best⟩ := found_is j hj
    refine ⟨by omega, k, k_at, hm, hr, hk, fun m k' lt' k'_at m' => ?_⟩
    by_cases old : m < i
    · exact best m k' old k'_at m'
    · have : m = i := by omega
      subst this
      rw [ki_at] at k'_at
      exact absurd m' (by rw [← Option.some.inj k'_at]; exact unmatched)
  · by_cases old : m < i
    · exact none_is hn m k' old k'_at m'
    · have : m = i := by omega
      subst this
      rw [ki_at] at k'_at
      have := Option.some.inj k'_at
      subst this
      exact unmatched m'

/-- The key `i` matches and replaces the best so far (there is none, or it is beaten): the key `i`
is the best of the first `i + 1`. -/
theorem seen_replaced (keys : Slice Key) (host repo : Slice Std.U8) (best : Option Std.Usize)
    (rank0 : Std.Usize) (kept0 kept : Bool) (i : Std.Usize) (ki : Key) (ki_at : keys.val[i.val]? = some ki)
    (matched : Matches ki.kept.val host.val repo.val) (n : Std.Usize) (hn : n.val = ki.kept.length)
    (is_kept : kept = true ↔ AsWritten ki)
    (seen : PickSeen keys host repo best rank0 kept0 i.val)
    (beats : ∀ j, best = some j → ∃ k0, keys.val[j.val]? = some k0 ∧ NotBeaten ki i.val k0 j.val) :
    PickSeen keys host repo (some i) n kept (i.val + 1) := by
  obtain ⟨found_is, none_is⟩ := seen
  refine ⟨fun j hj => ?_, fun hn => by simp at hn⟩
  have : j = i := by simpa using hj.symm
  subst this
  refine ⟨by omega, ki, ki_at, matched, hn, is_kept, fun m k' lt k'_at m' => ?_⟩
  by_cases old : m < j.val
  · cases best with
    | none => exact absurd m' (none_is rfl m k' old k'_at)
    | some j0 =>
      obtain ⟨_, k0, k0_at, hm0, _, _, best0⟩ := found_is j0 rfl
      obtain ⟨k0', k0'_at, nb⟩ := beats j0 rfl
      rw [k0_at] at k0'_at
      have := Option.some.inj k0'_at
      subst this
      exact not_beaten_trans _ _ _ _ _ _ nb (best0 m k' (by omega) k'_at m')
  · have : m = j.val := by omega
    subst this
    rw [ki_at] at k'_at
    rw [← Option.some.inj k'_at]
    exact not_beaten_refl _ _

/-- The key `i` matches and does not replace the best so far: the best so far is the best of the
first `i + 1`. -/
theorem seen_kept (keys : Slice Key) (host repo : Slice Std.U8) (best : Std.Usize)
    (rank : Std.Usize) (kept : Bool) (i : Nat) (ki : Key) (ki_at : keys.val[i]? = some ki)
    (_matched : Matches ki.kept.val host.val repo.val)
    (seen : PickSeen keys host repo (some best) rank kept i)
    (stays : ∀ k0, keys.val[best.val]? = some k0 → NotBeaten k0 best.val ki i) :
    PickSeen keys host repo (some best) rank kept (i + 1) := by
  obtain ⟨found_is, none_is⟩ := seen
  refine ⟨fun j hj => ?_, fun hn => by simp at hn⟩
  have : j = best := by simpa using hj.symm
  subst this
  obtain ⟨lt, k, k_at, hm, hr, hk, best⟩ := found_is j rfl
  refine ⟨by omega, k, k_at, hm, hr, hk, fun m k' lt' k'_at m' => ?_⟩
  by_cases old : m < i
  · exact best m k' old k'_at m'
  · have : m = i := by omega
    subst this
    rw [ki_at] at k'_at
    rw [← Option.some.inj k'_at]
    exact stays k k_at

/-- The loop of **`pick`**: from the key `i`, with the best so far, it ends with the key picked among
all the keys. -/
theorem pick_loop_picks (keys : Slice Key) (host repo : Slice Std.U8) (best : Option Std.Usize)
    (best_rank : Std.Usize) (best_kept : Bool) (i : Std.Usize) (inside : i.val ≤ keys.length)
    (seen : PickSeen keys host repo best best_rank best_kept i.val) :
    pick_loop keys host repo best best_rank best_kept i ⦃ found =>
      Picks keys.val host.val repo.val (found.map (·.val)) ⦄ := by
  unfold pick_loop
  apply loop.spec_decr_nat
    (fun (q : Option Std.Usize × Std.Usize × Bool × Std.Usize) => keys.length - q.2.2.2.val)
    (fun (q : Option Std.Usize × Std.Usize × Bool × Std.Usize) => q.2.2.2.val ≤ keys.length ∧
      PickSeen keys host repo q.1 q.2.1 q.2.2.1 q.2.2.2.val)
  · rintro ⟨best, best_rank, best_kept, i⟩ ⟨inside, seen⟩
    simp only at inside seen ⊢
    unfold pick_loop.body
    have keys_len : keys.val.length = keys.length := rfl
    by_cases below : i.val < keys.length
    · have below' : i < Slice.len keys := by scalar_tac
      simp only [below', ite_true]
      step with rank_of_says keys i host repo below as ⟨ o, ki, ki_at, hmatch ⟩
      rcases hmatch with ⟨matched, n, rfl, hn⟩ | ⟨unmatched, rfl⟩
      · simp only
        step with is_kept_says keys i below as ⟨ kept, ki', ki'_at, is_kept ⟩
        have same_key : ki' = ki := by rw [ki_at] at ki'_at; exact (Option.some.inj ki'_at).symm
        subst same_key
        have ki_at' : keys.val[i.val]? = some ki' := ki_at
        by_cases none_yet : best = none
        · subst none_yet
          simp only [ Option.isNone_none, ite_true, Std.bind_ok]
          step as ⟨ next, is_next ⟩
          refine ⟨by scalar_tac, ?_, by scalar_tac⟩
          rw [is_next]
          exact seen_replaced keys host repo _ _ _ _ i ki' ki_at' matched n hn is_kept seen
            (by intro j hj; simp at hj)
        · obtain ⟨j0, hj0⟩ := Option.ne_none_iff_exists'.mp none_yet
          subst hj0
          obtain ⟨j0_lt, k0, k0_at, hm0, hr0, hk0, _⟩ := seen.1 j0 rfl
          simp only [ Option.isNone_some, Bool.false_eq_true, ite_false]
          have replace_ok : (k0.kept.length < ki'.kept.length ∨
              (k0.kept.length = ki'.kept.length ∧ (AsWritten ki' ∨ ¬ AsWritten k0))) →
              ∀ j, some j0 = some j → ∃ k1, keys.val[j.val]? = some k1 ∧
                NotBeaten ki' i.val k1 j.val := by
            intro cond j hj
            obtain rfl := Option.some.inj hj
            exact ⟨k0, k0_at, (later_wins k0 j0.val ki' i.val j0_lt).mpr cond⟩
          have stay_ok : ¬ (k0.kept.length < ki'.kept.length ∨
              (k0.kept.length = ki'.kept.length ∧ (AsWritten ki' ∨ ¬ AsWritten k0))) →
              ∀ k1, keys.val[j0.val]? = some k1 → NotBeaten k1 j0.val ki' i.val := by
            intro cond k1 k1_at
            rw [k0_at] at k1_at
            obtain rfl := Option.some.inj k1_at
            exact later_loses k0 j0.val ki' i.val j0_lt cond
          have is_kept' := is_kept
          by_cases gt : n > best_rank
          · simp only [gt, ite_true, Std.bind_ok]
            step as ⟨ next, is_next ⟩
            refine ⟨by scalar_tac, ?_, by scalar_tac⟩
            rw [is_next]
            exact seen_replaced keys host repo _ _ _ _ i ki' ki_at' matched n hn is_kept seen
              (replace_ok (Or.inl (by scalar_tac)))
          · simp only [gt, ite_false]
            by_cases eq : n = best_rank
            · subst eq
              simp only [↓reduceIte]
              by_cases hk : kept = true
              · subst hk
                simp only [↓reduceIte, Std.bind_ok]
                step as ⟨ next, is_next ⟩
                refine ⟨by scalar_tac, ?_, by scalar_tac⟩
                rw [is_next]
                exact seen_replaced keys host repo _ _ _ _ i ki' ki_at' matched n hn is_kept seen
                  (replace_ok (Or.inr ⟨by scalar_tac, Or.inl (is_kept.mp rfl)⟩))
              · have hk' : kept = false := by simpa using hk
                subst hk'
                simp only [Bool.false_eq_true, ite_false]
                by_cases bk : best_kept = true
                · subst bk
                  simp only [ite_true, Std.bind_ok]
                  step as ⟨ next, is_next ⟩
                  refine ⟨by scalar_tac, ?_, by scalar_tac⟩
                  rw [is_next]
                  exact seen_kept keys host repo j0 _ _ i.val ki' ki_at' matched seen
                    (stay_ok (by
                      rintro (h | ⟨_, h | h⟩)
                      · scalar_tac
                      · exact hk (is_kept.mpr h)
                      · exact h (hk0.mp rfl)))
                · simp only [bk, Bool.false_eq_true, ite_false, Std.bind_ok]
                  step as ⟨ next, is_next ⟩
                  refine ⟨by scalar_tac, ?_, by scalar_tac⟩
                  rw [is_next]
                  exact seen_replaced keys host repo _ _ _ _ i ki' ki_at' matched n hn is_kept seen
                    (replace_ok (Or.inr ⟨by scalar_tac, Or.inr (fun h => bk (hk0.mpr h))⟩))
            · simp only [eq, ite_false, Std.bind_ok]
              step as ⟨ next, is_next ⟩
              refine ⟨by scalar_tac, ?_, by scalar_tac⟩
              rw [is_next]
              exact seen_kept keys host repo j0 _ _ i.val ki' ki_at' matched seen
                (stay_ok (by
                  rintro (h | ⟨h, _⟩) <;> scalar_tac))
      · simp only
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [is_next]
        exact seen_unmatched keys host repo _ _ _ i.val ki ki_at unmatched seen
    · have below' : ¬ i < Slice.len keys := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i.val = keys.length := by scalar_tac
      obtain ⟨found_is, none_is⟩ := seen
      refine ⟨fun j hj => ?_, ?_⟩
      · obtain ⟨j', rfl, rfl⟩ : ∃ j', best = some j' ∧ j'.val = j := by
          cases best with
          | none => simp at hj
          | some j' => exact ⟨j', rfl, by simpa using hj⟩
        obtain ⟨_, k, k_at, hm, _, _, best⟩ := found_is j' rfl
        exact ⟨k, k_at, hm, fun m k' k'_at m' => best m k' (by
          have := (List.getElem?_eq_some_iff.mp k'_at).1
          omega) k'_at m'⟩
      · constructor
        · intro isnone k hk
          rw [Option.map_eq_none_iff] at isnone
          obtain ⟨m, hm⟩ := List.mem_iff_getElem?.mp hk
          exact none_is isnone m k (by
            have := (List.getElem?_eq_some_iff.mp hm).1
            omega) hm
        · intro all
          by_contra notnone
          cases best with
          | none => exact notnone (by simp)
          | some j' =>
            obtain ⟨_, k, k_at, hm, _⟩ := found_is j' rfl
            exact all k (List.mem_iff_getElem?.mpr ⟨_, k_at⟩) hm
  · exact ⟨inside, seen⟩

/-- **`pick`** answers the most specific key that matches, none when no key matches. -/
@[step] theorem pick_picks (keys : Slice Key) (host repo : Slice Std.U8) :
    pick keys host repo ⦃ found => Picks keys.val host.val repo.val (found.map (·.val)) ⦄ := by
  unfold pick
  exact pick_loop_picks keys host repo none 0#usize false 0#usize (by simp)
    ⟨fun j hj => by simp at hj, fun _ m k' lt => by simp at lt⟩

end AuthCore
