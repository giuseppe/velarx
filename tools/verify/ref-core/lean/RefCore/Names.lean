-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the functions that decide the name after the defaults of docker.io
-- do: `is_hub` (no host, `docker.io` or `index.docker.io`), `path_start`, `needs_library`
-- (docker.io and a path of one component), `name_len` (the length of the name after the defaults)
-- and `is_id` (64 hex digits).
-- Why it is needed: `parse` refuses a name of more than 255 bytes after the defaults and the id of
-- an image; `normalize` makes the name.
-- Read before this file: Paths.lean.
-- Notation: `HubSpan s host_end` is "the host of the spans is none, `docker.io` or
-- `index.docker.io`"; `PathStart` is where the path begins.
import RefCore.Paths
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The bytes of the constant `HUB` are `docker.io`. -/
theorem hub_is_docker_io : Bytes HUB.val = Hub := by
  unfold HUB Hub Ascii Bytes
  rfl

/-- The bytes of the constant `HUB_INDEX` are `index.docker.io`. -/
theorem hub_index_is_index_docker_io : Bytes HUB_INDEX.val = Ascii "index.docker.io" := by
  unfold HUB_INDEX Ascii Bytes
  rfl

/-- The bytes of the constant `LIBRARY` are `library/`. -/
theorem library_is_library : Bytes LIBRARY.val = Ascii "library/" := by
  unfold LIBRARY Ascii Bytes
  rfl

/-- `is_hub` says `true` exactly when there is no host, or the host is `docker.io` or
`index.docker.io`. -/
@[step] theorem is_hub_says (s : Slice Std.U8) (host_end : Std.Usize)
    (inside : host_end.val ≤ s.length) :
    is_hub s host_end ⦃ r => (r = true ↔ host_end.val = 0 ∨
      Piece (Bytes s.val) 0 host_end = Hub ∨
      Piece (Bytes s.val) 0 host_end = Ascii "index.docker.io") ⦄ := by
  unfold is_hub
  split
  · rename_i none_
    simp only [WP.spec_ok, true_iff]
    exact Or.inl (by scalar_tac)
  · rename_i some_
    have not_zero : host_end.val ≠ 0 := fun same => some_ (UScalar.eq_of_val_eq
        (by simpa using same))
    step as ⟨ is_docker, is_docker_post ⟩
    split
    · rename_i found
      simp only [WP.spec_ok, true_iff]
      exact Or.inr (Or.inl (by rw [is_docker_post.mp found, hub_is_docker_io]))
    · rename_i missed
      step as ⟨ is_index, is_index_post ⟩
      have not_docker : Piece (Bytes s.val) 0 host_end ≠ Hub := fun same =>
        missed (is_docker_post.mpr (by rw [same, hub_is_docker_io]))
      rw [is_index_post, hub_index_is_index_docker_io]
      constructor
      · exact fun same => Or.inr (Or.inr same)
      · rintro (zero | docker | index)
        · exact absurd zero not_zero
        · exact absurd docker not_docker
        · exact index

/-- The host of the spans is none, `docker.io` or `index.docker.io`. -/
def HubSpan (s : Slice Std.U8) (host_end : Std.Usize) : Prop :=
  host_end.val = 0 ∨ Piece (Bytes s.val) 0 host_end = Hub ∨
    Piece (Bytes s.val) 0 host_end = Ascii "index.docker.io"

/-- `path_start` is the place after the host and its `/`, or the first place when there is no
host. -/
@[step] theorem path_start_says (spans : Spans) (room : spans.host_end.val + 1 ≤ Usize.max) :
    path_start spans ⦃ r => r.val = PathStart spans.host_end.val ⦄ := by
  unfold path_start PathStart
  split
  · rename_i has_host
    step as ⟨ r, r_post ⟩
    have : spans.host_end.val ≠ 0 := by scalar_tac
    simp [this, r_post]
  · rename_i no_host
    have : spans.host_end.val = 0 := by scalar_tac
    simp [this]

/-- `needs_library` says `true` exactly when the host is docker.io (or none) and the path is one
component. -/
@[step] theorem needs_library_says (s : Slice Std.U8) (spans : Spans)
    (host_inside : spans.host_end.val ≤ s.length)
    (path_after : PathStart spans.host_end.val ≤ spans.name_end.val)
    (path_inside : spans.name_end.val ≤ s.length) (room : spans.host_end.val + 1 ≤ Usize.max) :
    needs_library s spans ⦃ r => (r = true ↔ HubSpan s spans.host_end ∧
      47 ∉ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end) ⦄ := by
  unfold needs_library
  step as ⟨ hub, hub_post ⟩
  split
  · rename_i is_hub
    step as ⟨ start, start_post ⟩
    step as ⟨ slash, slash_after, slash_before, slash_none, slash_found ⟩
    constructor
    · intro at_end
      refine ⟨hub_post.mp is_hub, fun slash_in => ?_⟩
      have same : slash = spans.name_end := by simpa using at_end
      rw [start_post, same] at slash_none
      exact slash_none 47 slash_in rfl
    · rintro ⟨_, none_⟩
      by_contra not_end
      have below : slash.val < spans.name_end.val := by
        have : slash ≠ spans.name_end := by simpa using not_end
        scalar_tac
      have := piece_contains (Bytes s.val) (PathStart spans.host_end.val) spans.name_end.val
        slash.val 47 (by rw [← start_post]; exact slash_after) below (slash_found below)
      exact none_ this
  · rename_i not_hub
    simp only [WP.spec_ok, Bool.false_eq_true, false_iff, not_and]
    exact fun hub_span => absurd (hub_post.mpr hub_span) not_hub

/-- `HUB` has 9 bytes, `docker.io`. -/
theorem hub_length : HUB.length = 9 := by
  unfold HUB; rfl

/-- `LIBRARY` has 8 bytes, `library/`. -/
theorem library_length : LIBRARY.length = 8 := by
  unfold LIBRARY; rfl

open Classical in
/-- `name_len` is the length of the name after the defaults of docker.io: the host (`docker.io` for
a docker.io host), a `/`, the path, and `library/` when `needs_library`. -/
@[step] theorem name_len_says (s : Slice Std.U8) (spans : Spans)
    (host_inside : spans.host_end.val ≤ s.length)
    (path_after : PathStart spans.host_end.val ≤ spans.name_end.val)
    (path_inside : spans.name_end.val ≤ s.length) (small : spans.name_end.val ≤ 1024) :
    name_len s spans ⦃ r => r.val =
      (if HubSpan s spans.host_end then 9 else spans.host_end.val) + 1 +
      (spans.name_end.val - PathStart spans.host_end.val) +
      (if HubSpan s spans.host_end ∧
        47 ∉ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end then 8 else 0) ⦄
            := by
  have room : spans.host_end.val + 1 ≤ Usize.max := by
    unfold PathStart at path_after
    split at path_after <;> scalar_tac
  have host_small : spans.host_end.val ≤ 1024 := by
    unfold PathStart at path_after
    split at path_after <;> scalar_tac
  have hub_len : (Slice.len HUB).val = 9 := by simp [hub_length]
  have library_len : (Slice.len LIBRARY).val = 8 := by simp [library_length]
  unfold name_len
  step as ⟨ hub, hub_post ⟩
  split
  · rename_i is_hub
    have hub_span := hub_post.mp is_hub
    step as ⟨ library, library_post ⟩
    split
    · rename_i lib
      have lib_says := library_post.mp lib
      step as ⟨ a, a_post ⟩
      step as ⟨ b, b_post ⟩
      step as ⟨ c, c_post ⟩
      step as ⟨ d, d_post ⟩
      step as ⟨ e, e_post ⟩
      have hs : HubSpan s spans.host_end := hub_span
      simp only [hs, lib_says, ite_true]
      scalar_tac
    · rename_i not_lib
      have not_lib' : ¬ (HubSpan s spans.host_end ∧
          47 ∉ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end) :=
        fun both => not_lib (library_post.mpr both)
      step as ⟨ a, a_post ⟩
      step as ⟨ b, b_post ⟩
      step as ⟨ c, c_post ⟩
      step as ⟨ d, d_post ⟩
      step as ⟨ e, e_post ⟩
      have hs : HubSpan s spans.host_end := hub_span
      simp only [hs, ite_true]
      scalar_tac
  · rename_i not_hub
    have not_hub_span : ¬ HubSpan s spans.host_end := fun span => not_hub (hub_post.mpr span)
    step as ⟨ library, library_post ⟩
    have not_lib' : ¬ (HubSpan s spans.host_end ∧
        47 ∉ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end) :=
      fun both => not_hub_span both.1
    split
    · rename_i lib
      exact absurd (library_post.mp lib) not_lib'
    · step as ⟨ a, a_post ⟩
      step as ⟨ b, b_post ⟩
      step as ⟨ c, c_post ⟩
      step as ⟨ d, d_post ⟩
      step as ⟨ e, e_post ⟩
      scalar_tac

/-- The loop of `is_id` says `true` exactly when the flag was true and every byte from the start is
a hex digit. -/
theorem is_id_loop_checks_the_digits (s : Slice Std.U8) (stop : Std.Usize) (flag : Bool)
    (inside : stop.val ≤ s.length) :
    is_id_loop s stop flag 0#usize ⦃ r =>
      (r = true ↔ flag = true ∧ ∀ x ∈ Piece (Bytes s.val) 0 stop, IsHex x) ⦄ := by
  unfold is_id_loop
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => if q.1 = true
      then stop.val + 1 - q.2.val else 0)
    (fun (q : Bool × Std.Usize) => q.2.val ≤ stop.val ∧
      (q.1 = true ↔ flag = true ∧ ∀ x ∈ Piece (Bytes s.val) 0 q.2, IsHex x))
  · rintro ⟨ok1, i⟩ ⟨before_stop, so_far⟩
    simp only at before_stop so_far
    unfold is_id_loop.body
    dsimp only
    split
    · rename_i going
      split
      · rename_i below
        step as ⟨ x, x_post ⟩
        step as ⟨ hex, hex_post ⟩
        step as ⟨ next, next_post ⟩
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have snoc := piece_snoc (Bytes s.val) 0 i x.val (Nat.zero_le _) x_at
        refine ⟨by scalar_tac, ?_, ?_⟩
        · rw [next_post, snoc, forall_snoc]
          rw [hex_post]
          constructor
          · intro good
            exact ⟨(so_far.mp going).1, (so_far.mp going).2, good⟩
          · rintro ⟨_, _, good⟩
            exact good
        · by_cases good : hex = true
          · simp only [good, ite_true]; scalar_tac
          · simp only [good]; scalar_tac
      · rename_i not_below
        simp only [WP.spec_ok]
        have at_end : i.val = stop.val := by scalar_tac
        rw [at_end] at so_far
        exact so_far
    · rename_i stopped
      simp only [WP.spec_ok]
      have stopped' : ok1 = false := by simpa using stopped
      rw [stopped'] at so_far ⊢
      constructor
      · intro h; exact absurd h (by simp)
      · rintro ⟨flag_true, all⟩
        have := so_far.mpr ⟨flag_true, fun x inside' =>
          all x (piece_mem_of_shorter _ _ _ _ _ (Nat.zero_le _) before_stop inside')⟩
        simp at this
  · refine ⟨by scalar_tac, ?_⟩
    simp [piece_empty]

/-- `is_id` says `true` exactly when the string is 64 hex digits and nothing else: no host, no tag,
no digest. -/
@[step] theorem is_id_says (s : Slice Std.U8) (spans : Spans)
    (inside : spans.name_end.val ≤ s.length) :
    is_id s spans ⦃ r => (r = true ↔ spans.name_end.val = 64 ∧ spans.host_end.val = 0 ∧
      spans.tag = none ∧ spans.digest = none ∧
      ∀ x ∈ Piece (Bytes s.val) 0 spans.name_end, IsHex x) ⦄ := by
  unfold is_id
  refine WP.spec_bind (Pₘ := fun flag => flag = true ↔ spans.name_end.val = 64 ∧
    spans.host_end.val = 0 ∧ spans.tag = none ∧ spans.digest = none) ?_ ?_
  · split
    · rename_i len64
      split
      · rename_i no_host
        have len64' : spans.name_end.val = 64 := by rw [len64]; rfl
        have no_host' : spans.host_end.val = 0 := by rw [no_host]; rfl
        simp only [len64', no_host', true_and]
        cases h : spans.tag <;> cases h2 : spans.digest <;>
          simp [core.option.Option.is_none, WP.spec_ok]
      · rename_i has_host
        have : spans.host_end.val ≠ 0 := fun same => has_host (UScalar.eq_of_val_eq
            (by simpa using same))
        simp [WP.spec_ok, this]
    · rename_i not_64
      have : spans.name_end.val ≠ 64 := fun same => not_64 (UScalar.eq_of_val_eq
          (by simpa using same))
      simp [WP.spec_ok, this]
  · intro flag flag_says
    refine WP.spec_mono (is_id_loop_checks_the_digits s spans.name_end flag inside) ?_
    intro r loop_says
    rw [loop_says, flag_says]
    tauto

end RefCore
