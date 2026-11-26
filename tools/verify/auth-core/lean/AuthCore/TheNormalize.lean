-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `normalize key` answers `Normalized` of the key (Spec.lean), for any key: it
-- cuts the key at its first `://`, tells a web scheme from another, and makes the key of the
-- three branches the other files show.  It returns for any bytes.
-- Why it is needed: the keys of the file are written with `normalize`, and the claims on the web key
-- and on `normalize` twice rest on it.
-- Read before this file: Spec.lean, Scans.lean, Pieces.lean, ThePlain.lean, TheOtherScheme.lean.
-- Notation: `step as ⟨ x, hx ⟩` runs one line of a Rust function and names its result `x` and what
-- is known of it `hx`; `l.takeWhile p` is what is before the first element that does not satisfy
-- `p`.
import AuthCore.Spec
import AuthCore.Bytes
import AuthCore.TheHub
import AuthCore.Scans
import AuthCore.Pieces
import AuthCore.ThePlain
import AuthCore.TheOtherScheme

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- The first component of a list and of what `TrimSlashes` leaves of it are the same. -/
theorem trim_keeps_the_host (m : Bytes) :
    (TrimSlashes m).takeWhile (fun b => decide (b ≠ Slash)) = m.takeWhile (fun b => decide (b ≠ Slash)) := by
  obtain ⟨S, h, slashes⟩ := trim_parts m
  generalize TrimSlashes m = T at h ⊢
  have S_none : S.takeWhile (fun b => decide (b ≠ Slash)) = [] := by
    cases S with
    | nil => rfl
    | cons c S => rw [List.takeWhile_cons_of_neg]; simp [slashes c (by simp)]
  rw [h, List.takeWhile_append, S_none]
  split
  · rename_i same
    have : T.takeWhile (fun b => decide (b ≠ Slash)) = T :=
      (List.takeWhile_prefix _).eq_of_length same
    rw [this]; simp
  · rfl

/-- The lines of `normalize` once the scheme is known to be at `i` (`web` says whether it is `http`
or `https`): the place after the `://`, the cut of the `/` at the end, and the branch of the key. -/
def rest_of_normalize (key : Slice Std.U8) (i : Std.Usize) (web : Bool) :
    Result (alloc.vec.Vec Std.U8) := do
  let after ← i + 3#usize
  let end1 ← normalize_loop0 key after key.len
  if (some i).isSome = true then
    if web = true then plain_finish key after end1 web
    else other_finish key after end1
  else plain_finish key after end1 web

/-- What `rest_of_normalize` answers, for a key that is a scheme, `://` and the rest, when `web` says
whether the scheme is `http` or `https` in any case. -/
theorem rest_of_normalize_says (key : Slice Std.U8) (i : Std.Usize) (web : Bool)
    (scheme rest : Bytes) (hs : SchemeSplit key.val = some (scheme, rest))
    (i_is : i.val = scheme.length) (web_says : web = true ↔ IsWeb scheme) :
    rest_of_normalize key i web ⦃ out => out.val = Normalized key.val ⦄ := by
  have is_key := scheme_split_puts_together _ _ _ hs
  have key_len : key.length = scheme.length + 3 + rest.length := by
    have : key.length = key.val.length := rfl
    rw [this, is_key]; simp [SchemeEnd]; omega
  have key_max : key.length ≤ Std.Usize.max := key.property
  unfold rest_of_normalize
  -- the place after the `://`
  step as ⟨ after, is_after ⟩
  have is_rest : key.val.drop after.val = rest := by
    have h : scheme.length + 3 = (scheme ++ SchemeEnd).length := by simp [SchemeEnd]
    rw [is_key, is_after, i_is, h]
    exact List.drop_left
  have after_le : after.val ≤ key.length := by omega
  have key_len' : key.len.val = key.length := Slice.len_val key
  -- the `/` at the end are cut, down to the `://`
  step with trim_loop_cuts key after key.len
    (after.val + (TrimSlashes (key.val.drop after.val)).length)
    (le_of_eq key_len') (by omega) (by
      rw [List.take_of_length_le (by simp)]) as ⟨ end1, is_end1 ⟩
  simp only [Option.isSome_some, ↓reduceIte]
  by_cases web_yes : web = true
  · -- a web key: its host
    simp only [web_yes, ↓reduceIte]
    have h := plain_finish_says key after end1 true after_le is_end1
    refine WP.spec_mono h ?_
    intro out is_out
    rw [is_out, Normalized, hs, is_rest, trim_keeps_the_host]
    simp only [web_says.mp web_yes, ↓reduceIte, List.append_nil]
  · -- a key of another scheme
    simp only [web_yes, Bool.false_eq_true, ↓reduceIte]
    have h := other_finish_says key after end1 scheme rest is_key (by omega)
      (by rw [is_end1, is_rest])
    refine WP.spec_mono h ?_
    intro out is_out
    rw [is_out, Normalized, hs]
    have not_web : ¬ IsWeb scheme := fun w => web_yes (web_says.mpr w)
    simp only [not_web, ↓reduceIte]

/-- **`normalize`** answers the key as it is kept. -/
@[step] theorem normalize_is_the_rule (key : Slice Std.U8) :
    normalize key ⦃ out => out.val = Normalized key.val ⦄ := by
  unfold velarx_auth_core.normalize
  step as ⟨ sep, is_sep ⟩
  have key_max : key.length ≤ Std.Usize.max := key.property
  cases sep with
  | none =>
    have hs : SchemeSplit key.val = none := by
      have := is_sep
      simpa using this.symm
    simp only [Std.bind_ok]
    have key_len : key.len.val = key.length := Slice.len_val key
    -- no scheme: the `/` at the end are cut from the start on
    step with trim_loop_cuts key 0#usize key.len (0 + (TrimSlashes (key.val.drop 0)).length)
      (le_of_eq key_len) (by simp) (by simp [key_len]) as ⟨ end1, is_end1 ⟩
    simp only [Option.isSome_none, Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
    have h := plain_finish_says key 0#usize end1 false (by simp) (by simpa using is_end1)
    simp only [plain_finish, Bool.false_eq_true, ↓reduceIte, Std.bind_ok,
      core.slice.index.Slice.index] at h
    refine WP.spec_mono h ?_
    intro out is_out
    rw [is_out, Normalized, hs]
    simp
  | some i =>
    obtain ⟨⟨scheme, rest⟩, hs⟩ : ∃ p, SchemeSplit key.val = some p := by
      cases h : SchemeSplit key.val with
      | none => simp [h] at is_sep
      | some p => exact ⟨p, rfl⟩
    have i_is : i.val = scheme.length := by
      rw [hs] at is_sep
      simpa using is_sep
    have key_is := scheme_split_puts_together _ _ _ hs
    have is_scheme : key.val.take i.val = scheme := by
      rw [i_is, key_is, List.append_assoc]
      simp
    have key_len : key.length = scheme.length + 3 + rest.length := by
      have : key.length = key.val.length := rfl
      rw [this, key_is]; simp [SchemeEnd]; omega
    step as ⟨ s, is_s, s_len ⟩
    have s_is : s.val = scheme := by
      rw [is_s, List.slice, Nat.sub_zero, List.drop_zero, is_scheme]
    simp only [lift, Std.bind_ok]
    have lit5 : (Array.to_slice (Array.make 5#usize [104#u8, 116#u8, 116#u8, 112#u8, 115#u8])).val = Https :=
      literal_bytes _ _ _
    have lit4 : (Array.to_slice (Array.make 4#usize [104#u8, 116#u8, 116#u8, 112#u8])).val = Http :=
      literal_bytes _ _ _
    step as ⟨ x, is_x ⟩
    by_cases hx : x = true
    · simp only [hx, ↓reduceIte, Std.bind_ok]
      have := rest_of_normalize_says key i true scheme rest hs i_is (by
        simp only [true_iff, IsWeb]
        right
        rw [← s_is]
        have := is_x.mp hx
        rw [lit5] at this
        exact this)
      exact this
    · simp only [hx, Bool.false_eq_true, ↓reduceIte]
      step as ⟨ y, is_y ⟩
      have := rest_of_normalize_says key i y scheme rest hs i_is (by
        rw [IsWeb, is_y, lit4, s_is]
        constructor
        · intro h; exact Or.inl h
        · rintro (h | h)
          · exact h
          · exact absurd (is_x.mpr (by rw [lit5, s_is]; exact h)) hx)
      unfold rest_of_normalize plain_finish other_finish at this
      exact this

end AuthCore
