-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `print` writes: the host, a `/`, the path, then a `:` and the tag
-- when there is one, then an `@` and the digest when there is one, one after the other.
-- Why it is needed: `print` is how the full form of a reference is written for the engine; the
-- claims about it (Spec.lean) say that this form is read again as the same name.
-- Read before this file: Normal.lean.
-- Notation: as in Hosts.lean.
import RefCore.Normal
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- `append` of a whole slice writes all its bytes after those of the vector. -/
theorem append_a_slice (out : alloc.vec.Vec Std.U8) (t : Slice Std.U8)
    (room : out.length + t.length < Usize.max) :
    append out t 0#usize t.len ⦃ r => Bytes r.val = Bytes out.val ++ Bytes t.val ⦄ := by
  have len_val : t.len.val = t.length := by simp
  have whole : Piece (Bytes t.val) (0#usize).val t.len.val = Bytes t.val := by
    have := piece_whole (Bytes t.val)
    simpa [len_val] using this
  refine WP.spec_mono (append_copies out t 0#usize t.len (by simp) (by simp [len_val]) (by
    simp [len_val]; omega)) ?_
  intro r written
  rw [written, whole]

/-- `append` of a whole vector writes all its bytes after those of the vector. -/
theorem append_a_vector (out : alloc.vec.Vec Std.U8) (v : alloc.vec.Vec Std.U8)
    (room : out.length + v.length < Usize.max) :
    append out v.deref 0#usize v.len ⦃ r => Bytes r.val = Bytes out.val ++ Bytes v.val ⦄ := by
  have deref_val : v.deref.val = v.val := by simp [alloc.vec.Vec.deref]
  have same_len : v.len = v.deref.len := by
    apply UScalar.eq_of_val_eq
    simp [alloc.vec.Vec.len, alloc.vec.Vec.deref]
  have := append_a_slice out v.deref (by simpa [alloc.vec.Vec.deref] using room)
  rw [same_len]
  simpa only [deref_val] using this

/-- The length of a vector is the length of the list inside it. -/
theorem vec_length_is_the_list_length (v : alloc.vec.Vec Std.U8) :
    v.length = (↑v : List Std.U8).length := rfl

/-- `print` writes the host, a `/`, the path, and the tag after a `:` and the digest after an `@`
when there are. -/
theorem print_writes (n : Name) (tag digest : Option (Slice Std.U8))
    (small : n.host.length + n.path.length + (tag.map (·.length)).getD 0 +
      (digest.map (·.length)).getD 0 ≤ 4096) :
    print n tag digest ⦃ out =>
      Bytes out.val = Bytes n.host.val ++ 47 :: Bytes n.path.val ++
        (tag.map fun t => 58 :: Bytes t.val).getD [] ++
        (digest.map fun d => 64 :: Bytes d.val).getD [] ⦄ := by
  unfold print
  dsimp only
  have vec_new : (alloc.vec.Vec.new Std.U8).length = 0 := by simp [alloc.vec.Vec.new]
  have vec_new_bytes : Bytes (alloc.vec.Vec.new Std.U8).val = [] := by
    simp [alloc.vec.Vec.new, Bytes]
  step with append_a_vector (alloc.vec.Vec.new Std.U8) n.host (by scalar_tac) as ⟨ out, out_post ⟩
  have out_len : out.length = n.host.length := by
    have := congrArg List.length out_post
    simpa [vec_new_bytes] using this
  step as ⟨ out1, out1_post ⟩
  have out1_len : out1.length = n.host.length + 1 := by
    have := congrArg List.length out1_post
    simp only [List.length_append, List.length_singleton] at this
    simp only [vec_length_is_the_list_length] at out_len ⊢
    omega
  step with append_a_vector out1 n.path (by scalar_tac) as ⟨ out2, out2_post ⟩
  have out2_len : out2.length = n.host.length + 1 + n.path.length := by
    have := congrArg List.length out2_post
    simp only [List.length_append, bytes_length] at this
    simp only [vec_length_is_the_list_length] at out1_len ⊢
    omega
  have out1_bytes : Bytes out1.val = Bytes out.val ++ [47] := by
    rw [out1_post]
    simp [Bytes]
  refine WP.spec_bind (Pₘ := fun out3 => Bytes out3.val = Bytes out2.val ++
      (tag.map fun t => 58 :: Bytes t.val).getD [] ∧
      out3.length = out2.length + (tag.map (·.length + 1)).getD 0) ?_ ?_
  · cases tag with
    | none => simp [WP.spec_ok]
    | some t =>
      simp only [Option.map_some, Option.getD_some] at small ⊢
      have : out2.length ≤ 4097 := by omega
      step as ⟨ out4, out4_post ⟩
      have out4_len : out4.length = out2.length + 1 := by
        have := congrArg List.length out4_post
        simp only [List.length_append, List.length_singleton] at this
        simp only [vec_length_is_the_list_length]
        omega
      step with append_a_slice out4 t (by scalar_tac) as ⟨ out5, out5_post ⟩
      refine ⟨?_, ?_⟩
      · rw [out5_post]
        have := congrArg (List.map (·.val)) out4_post
        simp only [Bytes] at this ⊢
        simp [this]
      · have := congrArg List.length out5_post
        simp only [List.length_append, bytes_length] at this
        have slice_length : t.length = (↑t : List Std.U8).length := rfl
        simp only [vec_length_is_the_list_length] at out4_len ⊢
        omega
  · intro out3 ⟨out3_post, out3_len⟩
    cases digest with
    | none =>
      simp only [Option.map_none, Option.getD_none, List.append_nil, WP.spec_ok]
      rw [out3_post, out2_post, out1_bytes, out_post, vec_new_bytes]
      simp
    | some d =>
      simp only [Option.map_some, Option.getD_some] at small ⊢
      have out3_small : out3.length ≤ 4098 := by
        have tag_len : (tag.map (·.length + 1)).getD 0 ≤ (tag.map (·.length)).getD 0 + 1 := by
          cases tag <;> simp
        omega
      step as ⟨ out4, out4_post ⟩
      have out4_len : out4.length = out3.length + 1 := by
        have := congrArg List.length out4_post
        simp only [List.length_append, List.length_singleton] at this
        simp only [vec_length_is_the_list_length]
        omega
      step with append_a_slice out4 d (by scalar_tac) as ⟨ out5, out5_post ⟩
      have out4_bytes : Bytes out4.val = Bytes out3.val ++ [64] := by
        rw [out4_post]
        simp [Bytes]
      rw [out5_post, out4_bytes, out3_post, out2_post, out1_bytes, out_post, vec_new_bytes]
      simp

end RefCore
