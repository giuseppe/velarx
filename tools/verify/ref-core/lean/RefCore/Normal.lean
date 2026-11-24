-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `append` and `normalize` do: the name after the defaults of docker.io
-- is the host (`docker.io` for none or `index.docker.io`) and the path (`library/` before one
-- component of docker.io), as `Reference.Normal` of Spec.lean says.
-- Why it is needed: two references that have the same name after the defaults are the same image
-- name for the consumers.
-- Read before this file: Public.lean.
-- Notation: as in Hosts.lean.
import RefCore.Public
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The loop of `append` writes the bytes of the piece after those of the vector. -/
theorem append_loop_copies (s : Slice Std.U8) (start stop : Std.Usize) (out : alloc.vec.Vec Std.U8)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (room : out.length + (stop.val - start.val) < Usize.max) :
    append_loop out s stop start ⦃ r =>
      Bytes r.val = Bytes out.val ++ Piece (Bytes s.val) start stop ⦄ := by
  unfold append_loop
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.U8 × Std.Usize) => stop.val - q.2.val)
    (fun (q : alloc.vec.Vec Std.U8 × Std.Usize) => start.val ≤ q.2.val ∧ q.2.val ≤ stop.val ∧
      Bytes q.1.val = Bytes out.val ++ Piece (Bytes s.val) start q.2 ∧
      q.1.length = out.length + (q.2.val - start.val))
  · rintro ⟨written, i⟩ ⟨after_start, before_stop, copied, long⟩
    simp only at after_start before_stop copied long
    unfold append_loop.body
    dsimp only
    split
    · rename_i below
      step as ⟨ x, x_post ⟩
      have x_at := bytes_at s i x (by scalar_tac) x_post
      step as ⟨ more, more_post ⟩
      step as ⟨ next, next_post ⟩
      refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac, by scalar_tac⟩
      rw [next_post, piece_snoc _ _ _ _ after_start x_at, ← List.append_assoc, ← copied]
      simp [Bytes, more_post]
    · rename_i not_below
      simp only [WP.spec_ok]
      have at_end : i.val = stop.val := by scalar_tac
      rw [at_end] at copied
      exact copied
  · exact ⟨le_refl _, ordered, by simp [piece_empty], by simp⟩

/-- `append` gives the vector and then the piece of the string. -/
@[step] theorem append_copies (out : alloc.vec.Vec Std.U8) (s : Slice Std.U8)
    (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (room : out.length + (stop.val - start.val) < Usize.max) :
    append out s start stop ⦃ r => Bytes r.val = Bytes out.val ++ Piece
        (Bytes s.val) start stop ⦄ := by
  unfold append
  exact append_loop_copies s start stop out ordered inside room

/-- The places of what `parse` found are in the string and in order. -/
theorem found_places (s : Slice Std.U8) (spans : Spans) (at_ : Std.Usize)
    (found : Found s spans at_) :
    spans.host_end.val ≤ s.length ∧ PathStart spans.host_end.val ≤ spans.name_end.val ∧
      spans.name_end.val ≤ s.length ∧ spans.name_end.val ≤ 1024 ∧ spans.host_end.val ≤ 1024 := by
  obtain ⟨small, ⟨ne_le, at_le⟩, host, _⟩ := found
  have name_inside : spans.name_end.val ≤ s.length := by omega
  refine ⟨?_, ?_, name_inside, by omega, ?_⟩
  · rcases host with zero | ⟨_, below, _⟩ <;> omega
  · unfold PathStart
    rcases host with zero | ⟨positive, below, _⟩
    · simp [zero]
    · have : spans.host_end.val ≠ 0 := by omega
      simp [this]; omega
  · rcases host with zero | ⟨_, below, _⟩ <;> omega

open Classical in
/-- What `normalize` makes of what `parse` found: the host and the path of `Reference.Normal`. -/
theorem normalize_says (s : Slice Std.U8) (spans : Spans) (at_ : Std.Usize)
    (found : Found s spans at_) :
    normalize s spans ⦃ n => Bytes n.host.val = ((spans.Reading s).Normal.host).getD [] ∧
      Bytes n.path.val = (spans.Reading s).Normal.path ⦄ := by
  obtain ⟨host_inside, path_after, name_inside, small, host_small⟩ := found_places s spans at_ found
  unfold velarx_ref_core.normalize
  dsimp only
  have on_hub : (spans.Reading s).OnTheHub ↔ HubSpan s spans.host_end := by
    unfold Reference.OnTheHub HubSpan Spans.Reading
    by_cases no_host : spans.host_end.val = 0 <;> simp [no_host]
  have one : (spans.Reading s).OneComponent ↔
      47 ∉ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end := by
    simp [Reference.OneComponent, Spans.Reading]
  have hub_length' : (Slice.len HUB).val = 9 := by simp [hub_length]
  have library_length' : (Slice.len LIBRARY).val = 8 := by simp [library_length]
  have hub_piece : Piece (Bytes HUB.val) 0 (Slice.len HUB).val = Hub := by
    rw [piece_of_the_whole, hub_is_docker_io]
  have library_piece : Piece (Bytes LIBRARY.val) 0 (Slice.len LIBRARY).val = Ascii "library/" := by
    rw [piece_of_the_whole, library_is_library]
  have vec_new : (alloc.vec.Vec.new Std.U8).length = 0 := by simp [alloc.vec.Vec.new]
  have vec_new_bytes : Bytes (alloc.vec.Vec.new Std.U8).val = [] := by
    simp [alloc.vec.Vec.new, Bytes]
  have host_room : spans.host_end.val + 1 ≤ Usize.max := by scalar_tac
  step as ⟨ hub, hub_post ⟩
  split
  · rename_i is_hub
    have hub_span : HubSpan s spans.host_end := hub_post.mp is_hub
    step as ⟨ host, host_post ⟩
    step as ⟨ lib, lib_post ⟩
    split
    · rename_i needs
      have needs' := lib_post.mp needs
      step as ⟨ path, path_post ⟩
      have path_len : path.length = 8 := by
        rw [vec_new_bytes, List.nil_append, library_piece] at path_post
        have := congrArg List.length path_post
        simpa [Ascii] using this
      step as ⟨ ps, ps_post ⟩
      step as ⟨ path1, path1_post ⟩
      constructor
      · rw [host_post, vec_new_bytes, List.nil_append, hub_piece]
        simp [Reference.Normal, on_hub, hub_span]
      · rw [path1_post, path_post, vec_new_bytes, List.nil_append, library_piece, ps_post]
        have cond : (spans.Reading s).OnTheHub ∧ (spans.Reading s).OneComponent := by
          rw [on_hub, one]; exact needs'
        simp only [Reference.Normal, cond, ite_true]
        rfl
    · rename_i not_needs
      have not_needs' : ¬ (HubSpan s spans.host_end ∧
          47 ∉ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end) :=
        fun both => not_needs (lib_post.mpr both)
      step as ⟨ ps, ps_post ⟩
      step as ⟨ path, path_post ⟩
      constructor
      · rw [host_post, vec_new_bytes, List.nil_append, hub_piece]
        simp [Reference.Normal, on_hub, hub_span]
      · rw [path_post, vec_new_bytes, List.nil_append, ps_post]
        have : ¬ ((spans.Reading s).OnTheHub ∧ (spans.Reading s).OneComponent) := by
          rw [on_hub, one]; exact not_needs'
        simp only [Reference.Normal, this, ite_false]
        rfl
  · rename_i not_hub
    have not_hub_span : ¬ HubSpan s spans.host_end := fun span => not_hub (hub_post.mpr span)
    have not_on : ¬ (spans.Reading s).OnTheHub := by rw [on_hub]; exact not_hub_span
    step as ⟨ host, host_post ⟩
    step as ⟨ lib, lib_post ⟩
    have not_lib : ¬ lib = true := fun is_lib => not_hub_span (lib_post.mp is_lib).1
    split
    · rename_i needs
      exact absurd needs not_lib
    · step as ⟨ ps, ps_post ⟩
      step as ⟨ path, path_post ⟩
      have positive : spans.host_end.val ≠ 0 := fun zero => not_hub_span (Or.inl zero)
      constructor
      · rw [host_post, vec_new_bytes, List.nil_append]
        simp only [Reference.Normal, not_on, ite_false]
        simp [Spans.Reading, positive]
      · rw [path_post, vec_new_bytes, List.nil_append, ps_post]
        have : ¬ ((spans.Reading s).OnTheHub ∧ (spans.Reading s).OneComponent) :=
            fun both => not_on both.1
        simp only [Reference.Normal, this, ite_false]
        rfl

end RefCore
