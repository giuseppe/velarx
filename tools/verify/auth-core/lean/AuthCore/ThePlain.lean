-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the end of `normalize` makes of a key with no scheme, or an `http` or
-- `https` one, once the `/` at its end are cut: the host (what is before the first `/`), under the
-- name of the Hub if it is one, and, for a key with no scheme, the rest as it is.
-- Why it is needed: the branches of `normalize` for such a key are the same lines, and this is
-- what they answer.
-- Read before this file: Spec.lean, Bytes.lean, TheHub.lean, Scans.lean, Pieces.lean.
-- Notation: `step as ⟨ x, hx ⟩` runs one line of a Rust function and names its result `x` and what
-- is known of it `hx`; `l.takeWhile p` and `l.dropWhile p` are what is before and what is from the
-- first element that does not satisfy `p`.
import AuthCore.Spec
import AuthCore.Bytes
import AuthCore.TheHub
import AuthCore.Scans
import AuthCore.Pieces

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- The lines of `normalize` that follow the cut of the `/` at the end, for a key with no scheme
or a web key (the web keys cut their path: `web`). -/
def plain_finish (key : Slice Std.U8) (after end1 : Std.Usize) (web : Bool) :
    Result (alloc.vec.Vec Std.U8) := do
  let stop ← if web then find key after end1 47#u8 else ok end1
  let slash ← find key after stop 47#u8
  let s ← core.slice.index.Slice.index
    (core.slice.index.SliceIndexRangeUsizeSlice Std.U8) key { start := after, «end» := slash }
  let s1 ← registry s
  let out ← alloc.vec.Vec.extend_from_slice core.clone.CloneU8 (alloc.vec.Vec.new Std.U8) s1
  if slash < stop then
    let s2 ← core.slice.index.Slice.index
      (core.slice.index.SliceIndexRangeUsizeSlice Std.U8) key { start := slash, «end» := stop }
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 out s2
  else ok out

/-- The first `n` bytes of the key from `after`, cut as the scans cut them. -/
theorem cut_is (key : Bytes) (after n : Nat) :
    (key.take (after + n)).drop after = (key.drop after).take n := by
  rw [List.drop_take, Nat.add_sub_cancel_left]

/-- `takeWhile` of what `takeWhile` took is the same. -/
theorem take_while_twice {α : Type} (p : α → Bool) (l : List α) :
    (l.takeWhile p).takeWhile p = l.takeWhile p := by
  induction l with
  | nil => rfl
  | cons a l ih =>
    by_cases h : p a = true
    · simp [List.takeWhile_cons_of_pos h, ih]
    · simp [List.takeWhile_cons_of_neg h]

/-- What `plain_finish` answers: the first component of what is left of the key from `after`, the
Hub under its one name, and, for a key with no scheme, the rest. -/
theorem plain_finish_says (key : Slice Std.U8) (after end1 : Std.Usize) (web : Bool)
    (after_le : after.val ≤ key.length)
    (is_end : end1.val = after.val + (TrimSlashes (key.val.drop after.val)).length) :
    plain_finish key after end1 web ⦃ out =>
      out.val = HubOf ((TrimSlashes (key.val.drop after.val)).takeWhile
          (fun b => decide (b ≠ Slash))) ++
        (if web then [] else (TrimSlashes (key.val.drop after.val)).dropWhile
          (fun b => decide (b ≠ Slash))) ⦄ := by
  have key_len : key.val.length = key.length := rfl
  generalize hm : key.val.drop after.val = m at is_end ⊢
  have m_len : m.length = key.length - after.val := by rw [← hm]; simp
  generalize hT : TrimSlashes m = T at is_end ⊢
  have T_pref : T <+: m := hT ▸ trim_is_a_beginning m
  have T_le : T.length ≤ m.length := T_pref.length_le
  have T_is : T = m.take T.length := List.prefix_iff_eq_take.mp T_pref
  generalize hH : T.takeWhile (fun b => decide (b ≠ Slash)) = H
  have H_pref : H <+: T := hH ▸ List.takeWhile_prefix _
  have H_le : H.length ≤ T.length := H_pref.length_le
  have H_is : H = m.take H.length := List.prefix_iff_eq_take.mp (H_pref.trans T_pref)
  have H_is_T : H = T.take H.length := List.prefix_iff_eq_take.mp H_pref
  have H_rest : T.dropWhile (fun b => decide (b ≠ Slash)) = T.drop H.length := by
    have := List.takeWhile_append_dropWhile (p := fun b => decide (b ≠ Slash)) (l := T)
    rw [hH] at this
    conv_rhs => rw [← this]
    simp
  have p_eq : (fun x : Std.U8 => decide (x ≠ 47#u8)) = (fun b => decide (b ≠ Slash)) := rfl
  have end_le : end1.val ≤ key.length := by omega
  have cutT : (key.val.take end1.val).drop after.val = T := by
    rw [is_end, cut_is, hm]; exact T_is.symm
  have cutH : (key.val.take (after.val + H.length)).drop after.val = H := by
    rw [cut_is, hm]; exact H_is.symm
  have H_all : H.takeWhile (fun b => decide (b ≠ Slash)) = H := by
    rw [← hH]; exact take_while_twice _ _
  have slash_is : ∀ stop : Std.Usize, (stop.val = after.val + H.length ∨ stop.val = end1.val) →
      (find key after stop 47#u8 ⦃ slash => slash.val = after.val + H.length ⦄) := by
    intro stop hstop
    have stop_le : stop.val ≤ key.length := by omega
    step with find_finds key after stop 47#u8 stop_le as ⟨ slash, is_slash ⟩
    rw [is_slash]
    rcases hstop with h | h
    · rw [h, cutH, p_eq, H_all]
    · rw [h, cutT, p_eq, hH]
  unfold plain_finish
  by_cases hweb : web = true
  · subst hweb
    simp only [ite_true]
    step with find_finds key after end1 47#u8 end_le as ⟨ stop, is_stop ⟩
    have stop_is : stop.val = after.val + H.length := by rw [is_stop, cutT, p_eq, hH]
    step with (slash_is stop (Or.inl stop_is)) as ⟨ slash, is_slash ⟩
    step as ⟨ s, is_s, s_len ⟩
    have s_is : s.val = H := by
      rw [is_s, List.slice, is_slash, Nat.add_sub_cancel_left, hm, ← H_is]
    have key_max : key.length ≤ Std.Usize.max := key.property
    step as ⟨ s1, is_s1 ⟩
    rw [s_is] at is_s1
    have s1_le : s1.val.length ≤ H.length := by rw [is_s1]; exact hub_of_is_not_longer H
    step with extend_appends (alloc.vec.Vec.new Std.U8) s1 (by
      have h0 : (alloc.vec.Vec.new Std.U8).length = 0 := rfl
      have h1 : s1.length ≤ Std.Usize.max := s1.property
      omega) as ⟨ out, is_out ⟩
    have not_less : ¬ slash < stop := fun h =>
      absurd ((UScalar.lt_equiv _ _).mp h) (by omega)
    simp only [not_less, ↓reduceIte]
    refine (WP.spec_ok _).mpr ?_
    simp [is_out, is_s1, alloc.vec.Vec.new]
  · have hweb' : web = false := by simpa using hweb
    subst hweb'
    simp only [Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
    step with (slash_is end1 (Or.inr rfl)) as ⟨ slash, is_slash ⟩
    step as ⟨ s, is_s, s_len ⟩
    have s_is : s.val = H := by
      rw [is_s, List.slice, is_slash, Nat.add_sub_cancel_left, hm, ← H_is]
    have key_max : key.length ≤ Std.Usize.max := key.property
    step as ⟨ s1, is_s1 ⟩
    rw [s_is] at is_s1
    have s1_le : s1.val.length ≤ H.length := by rw [is_s1]; exact hub_of_is_not_longer H
    step with extend_appends (alloc.vec.Vec.new Std.U8) s1 (by
      have h0 : (alloc.vec.Vec.new Std.U8).length = 0 := rfl
      have h1 : s1.length ≤ Std.Usize.max := s1.property
      omega) as ⟨ out, is_out ⟩
    by_cases less : slash < end1
    · simp only [less, ↓reduceIte]
      step as ⟨ s2, is_s2, s2_len ⟩
      have s2_is : s2.val = T.drop H.length := by
        have e1 : List.drop (after.val + H.length) key.val = List.drop H.length m := by
          rw [← hm, List.drop_drop, Nat.add_comm]
        have e2 : H.length + (T.length - H.length) = T.length := by omega
        rw [is_s2, List.slice, is_slash, show end1.val - (after.val + H.length) = T.length - H.length by omega,
          e1, List.take_drop, e2, ← T_is]
      have out_len : out.val.length ≤ H.length := by
        rw [is_out, is_s1]; simp [alloc.vec.Vec.new]; exact hub_of_is_not_longer H
      step with extend_appends out s2 (by
        have h1 : s2.length ≤ T.length - H.length := by
          have : s2.length = s2.val.length := rfl
          rw [this, s2_is]; simp
        have h2 : out.length = out.val.length := rfl
        omega) as ⟨ out2, is_out2 ⟩
      rw [is_out2, s2_is, is_out, is_s1, H_rest]
      simp [alloc.vec.Vec.new]
    · simp only [less, ↓reduceIte]
      refine (WP.spec_ok _).mpr ?_
      have : T.length ≤ H.length := by
        by_contra h
        exact less ((UScalar.lt_equiv _ _).mpr (by omega))
      rw [is_out, is_s1, H_rest, List.drop_of_length_le this]
      simp [alloc.vec.Vec.new]

end AuthCore
