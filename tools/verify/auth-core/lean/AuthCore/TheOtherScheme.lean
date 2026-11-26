-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the lines of `normalize` for a key with a scheme that is not `http`
-- or `https` make of it: the scheme and the authority in lower case, the `://`, and the rest as
-- written with no `/` at its end (`Normalized` of Spec.lean).
-- Why it is needed: this is one of the three branches of `normalize`.
-- Read before this file: Spec.lean, Bytes.lean, Scans.lean, Pieces.lean.
-- Notation: `step as ⟨ x, hx ⟩` runs one line of a Rust function and names its result `x` and what
-- is known of it `hx`; `l.take n` and `l.drop n` are the first `n` elements of `l` and `l` without
-- them.
import AuthCore.Spec
import AuthCore.Bytes
import AuthCore.TheHub
import AuthCore.Scans
import AuthCore.Pieces

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- The lines of `normalize` for a key of another scheme, once the `/` at its end are cut (`end1`):
the scheme in lower case, `://`, the authority in lower case and the rest as written. -/
def other_finish (key : Slice Std.U8) (after end1 : Std.Usize) :
    Result (alloc.vec.Vec Std.U8) := do
  let stop ← normalize_loop1 key end1 after
  let i ← after - 3#usize
  let s ← core.slice.index.Slice.index
    (core.slice.index.SliceIndexRangeToUsizeSlice Std.U8) key { «end» := i }
  let out ← push_lower (alloc.vec.Vec.new Std.U8) s
  let out1 ← alloc.vec.Vec.extend_from_slice core.clone.CloneU8 out
    (Array.to_slice (Array.make 3#usize [ 58#u8, 47#u8, 47#u8 ]))
  let s2 ← core.slice.index.Slice.index
    (core.slice.index.SliceIndexRangeUsizeSlice Std.U8) key { start := after, «end» := stop }
  let out2 ← push_lower out1 s2
  let s3 ← core.slice.index.Slice.index
    (core.slice.index.SliceIndexRangeUsizeSlice Std.U8) key { start := stop, «end» := end1 }
  alloc.vec.Vec.extend_from_slice core.clone.CloneU8 out2 s3

/-- What `other_finish` answers for a key that is a scheme, `://` and the rest, when `end1` is where
the `/` at the end of the rest are cut: the key as it is kept. -/
theorem other_finish_says (key : Slice Std.U8) (after end1 : Std.Usize) (scheme rest : Bytes)
    (is_key : key.val = scheme ++ SchemeEnd ++ rest) (is_after : after.val = scheme.length + 3)
    (is_end : end1.val = after.val + (TrimSlashes rest).length) :
    other_finish key after end1 ⦃ out =>
      out.val = scheme.map LowerByte ++ SchemeEnd ++
        (Authority (TrimSlashes rest)).map LowerByte ++
        (TrimSlashes rest).drop (Authority (TrimSlashes rest)).length ⦄ := by
  have key_len : key.length = scheme.length + 3 + rest.length := by
    have : key.length = key.val.length := rfl
    rw [this, is_key]; simp [SchemeEnd]; omega
  have key_max : key.length ≤ Std.Usize.max := key.property
  have is_rest : key.val.drop after.val = rest := by
    have h : scheme.length + 3 = (scheme ++ SchemeEnd).length := by simp [SchemeEnd]
    rw [is_key, is_after, h]
    exact List.drop_left
  have is_scheme : key.val.take (after.val - 3) = scheme := by
    rw [is_key, is_after, Nat.add_sub_cancel, List.append_assoc]
    simp
  -- what is left of the rest once its `/` at the end are cut (`R`), and its authority (`A`)
  generalize hR : TrimSlashes rest = R at is_end ⊢
  have R_pref : R <+: rest := hR ▸ trim_is_a_beginning rest
  have R_le : R.length ≤ rest.length := R_pref.length_le
  have R_is : rest.take R.length = R := (List.prefix_iff_eq_take.mp R_pref).symm
  have A_pref : Authority R <+: R := List.takeWhile_prefix _
  have A_le : (Authority R).length ≤ R.length := A_pref.length_le
  have A_is : rest.take (Authority R).length = Authority R :=
    (List.prefix_iff_eq_take.mp (A_pref.trans R_pref)).symm
  have is_kept : (key.val.take end1.val).drop after.val = R := by
    rw [List.drop_take, is_end, Nat.add_sub_cancel_left, is_rest, R_is]
  unfold other_finish
  -- the authority ends at the first `/`, `?` or `#` of what is kept
  step with authority_loop_ends key end1 after (after.val + (Authority R).length) (by omega)
    (by omega) (by rw [is_kept]) as ⟨ stop, is_stop ⟩
  -- the scheme, in lower case
  step as ⟨ i, is_i ⟩
  step as ⟨ s, is_s, s_len ⟩
  have s_is : s.val = scheme := by
    rw [is_s, List.slice, Nat.sub_zero, List.drop_zero, ← is_scheme, is_i]
  step with push_lower_appends (alloc.vec.Vec.new Std.U8) s (by
    have h0 : (alloc.vec.Vec.new Std.U8).length = 0 := rfl
    omega) as ⟨ out, is_out ⟩
  have out_len : out.val.length = scheme.length := by
    rw [is_out, s_is]; simp [alloc.vec.Vec.new]
  -- the `://`
  have lit := scheme_end_literal
  step with extend_appends out
    (Array.to_slice (Array.make 3#usize [58#u8, 47#u8, 47#u8])) (by
      have h1 : out.length = out.val.length := rfl
      have h2 : (Array.to_slice (Array.make 3#usize [58#u8, 47#u8, 47#u8])).length = 3 := rfl
      omega) as ⟨ out1, is_out1 ⟩
  have out1_is : out1.val = scheme.map LowerByte ++ SchemeEnd := by
    rw [is_out1, is_out, s_is, lit]; simp [alloc.vec.Vec.new]
  -- the authority, in lower case
  step as ⟨ s2, is_s2, s2_len ⟩
  have s2_is : s2.val = Authority R := by
    rw [is_s2, List.slice, is_stop, Nat.add_sub_cancel_left, is_rest, A_is]
  step with push_lower_appends out1 s2 (by
    have h1 : out1.length = out1.val.length := rfl
    have h3 : out1.val.length = scheme.length + 3 := by rw [out1_is]; simp [SchemeEnd]
    have h2 : s2.length = (Authority R).length := by
      have : s2.length = s2.val.length := rfl
      rw [this, s2_is]
    omega) as ⟨ out2, is_out2 ⟩
  have out2_is : out2.val = scheme.map LowerByte ++ SchemeEnd ++ (Authority R).map LowerByte := by
    rw [is_out2, out1_is, s2_is]
  -- the rest as written, up to the `/` at the end
  step as ⟨ s3, is_s3, s3_len ⟩
  have s3_is : s3.val = R.drop (Authority R).length := by
    have from_stop : key.val.drop stop.val = rest.drop (Authority R).length := by
      rw [← is_rest, List.drop_drop, is_stop, Nat.add_comm]
    have count : end1.val - stop.val = R.length - (Authority R).length := by omega
    rw [is_s3, List.slice, from_stop, count, ← List.drop_take, R_is]
  step with extend_appends out2 s3 (by
    have h1 : out2.length = out2.val.length := rfl
    have h3 : out2.val.length = scheme.length + 3 + (Authority R).length := by
      rw [out2_is]; simp [SchemeEnd]; omega
    have h2 : s3.length = R.length - (Authority R).length := by
      have : s3.length = s3.val.length := rfl
      rw [this, s3_is, List.length_drop]
    omega) as ⟨ out3, is_out3 ⟩
  rw [is_out3, out2_is, s3_is]

end AuthCore
