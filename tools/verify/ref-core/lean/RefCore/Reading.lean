-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `parse` knows when it comes to the path (`Found`: the places of the
-- spans, the host, the tag and the digest that the readers gave), and that from it follow the two
-- facts that the claims need: the parts written one after the other are the string, and the
-- reference they make is in the grammar.
-- Why it is needed: it is the joint between the readers of each part and the claim about the
-- whole.
-- Read before this file: Names.lean.
-- Notation: `spans.Reading s` is the reference the spans cut out of `s`; `Reference.Text` is the
-- reference written as a string.
import RefCore.Names
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- What `parse` has found when it comes to the path: the places of the spans and the facts about
each part that the readers of the host, the tag and the digest gave. -/
structure Found (s : Slice Std.U8) (spans : Spans) (at_ : Std.Usize) : Prop where
  /-- The string is at most 1024 bytes. -/
  small : s.length ≤ 1024
  /-- The name ends before the digest, which ends the string. -/
  order : spans.name_end.val ≤ at_.val ∧ at_.val ≤ s.length
  /-- The host: none, or a host that looks like one, followed by a `/` and a path. -/
  host : spans.host_end.val = 0 ∨
    (0 < spans.host_end.val ∧ spans.host_end.val < spans.name_end.val ∧
      (Bytes s.val)[spans.host_end.val]? = some 47 ∧
      IsHost (Piece (Bytes s.val) 0 spans.host_end) ∧
      LooksLikeHost (Piece (Bytes s.val) 0 spans.host_end))
  /-- With no host, the first component of a path of several does not look like a host. -/
  first_component : spans.host_end.val = 0 → 47 ∈ Piece (Bytes s.val) 0 spans.name_end →
    ¬ LooksLikeHost ((Piece (Bytes s.val) 0 spans.name_end).takeWhile (· ≠ 47))
  /-- The tag: none, or after a `:` that follows the name. -/
  tag : (spans.tag = none ∧ spans.name_end.val = at_.val) ∨
    (spans.name_end.val < at_.val ∧ (Bytes s.val)[spans.name_end.val]? = some 58 ∧
      ∃ i : Std.Usize, i.val = spans.name_end.val + 1 ∧ spans.tag = some (i, at_) ∧
        IsTag (Piece (Bytes s.val) i at_))
  /-- The digest: none, or after an `@` that ends the rest. -/
  digest : (spans.digest = none ∧ at_.val = s.length) ∨
    (at_.val < s.length ∧ (Bytes s.val)[at_.val]? = some 64 ∧
      ∃ i : Std.Usize, i.val = at_.val + 1 ∧ spans.digest = some (i, s.len) ∧
        IsDigest (Piece (Bytes s.val) i s.len))

/-- The string is the host and its `/`, the path, the tag with its `:` and the digest with its `@`,
one after the other, as the spans cut them. -/
theorem found_cuts_the_string (s : Slice Std.U8) (spans : Spans) (at_ : Std.Usize)
    (found : Found s spans at_) : (spans.Reading s).Text = Bytes s.val := by
  obtain ⟨_, ⟨ne_le, at_le⟩, host, _, tag, digest⟩ := found
  have whole : Bytes s.val = Piece (Bytes s.val) 0 s.length := by
    have := piece_whole (Bytes s.val)
    simpa using this.symm
  have first_cut : Piece (Bytes s.val) 0 s.length = Piece (Bytes s.val) 0 spans.name_end ++
      Piece (Bytes s.val) spans.name_end at_ ++ Piece (Bytes s.val) at_ s.length := by
    rw [← piece_append _ _ _ _ (Nat.zero_le _) ne_le, ← piece_append _ _ _ _ (Nat.zero_le _) at_le]
  have tag_cut : Piece (Bytes s.val) spans.name_end at_ =
      (spans.tag.map fun t => 58 :: Piece (Bytes s.val) t.1 t.2).getD [] := by
    rcases tag with ⟨none_, same⟩ | ⟨below, colon, i, i_is, some_, _⟩
    · rw [none_, show spans.name_end.val = at_.val from same, piece_empty]; rfl
    · rw [some_, piece_cons _ _ _ 58 below colon, ← i_is]; rfl
  have digest_cut : Piece (Bytes s.val) at_ s.length =
      (spans.digest.map fun d => 64 :: Piece (Bytes s.val) d.1 d.2).getD [] := by
    rcases digest with ⟨none_, same⟩ | ⟨below, at_byte, i, i_is, some_, _⟩
    · rw [none_, same, piece_empty]; rfl
    · rw [some_, piece_cons _ _ _ 64 below at_byte, ← i_is]; rfl
  have host_cut : Piece (Bytes s.val) 0 spans.name_end =
      (if spans.host_end.val = 0 then [] else Piece (Bytes s.val) 0 spans.host_end ++ [47]) ++
        Piece (Bytes s.val) (PathStart spans.host_end) spans.name_end := by
    rcases host with none_ | ⟨positive, below, slash, _, _⟩
    · simp [none_, PathStart]
    · have not_zero : spans.host_end.val ≠ 0 := by omega
      simp only [not_zero, PathStart, ite_false]
      rw [piece_append _ 0 spans.host_end spans.name_end (Nat.zero_le _) below.le,
        piece_cons _ _ _ 47 below slash]
      simp
  refine Eq.trans ?_ whole.symm
  rw [first_cut, host_cut, tag_cut, digest_cut]
  simp only [Reference.Text, Spans.Reading]
  by_cases no_host : spans.host_end.val = 0 <;> simp [no_host, List.append_assoc] <;> rfl

open Classical in
/-- The length of the name of the reading is the number `name_len` computes. -/
theorem name_length_of_the_reading (s : Slice Std.U8) (spans : Spans)
    (host_inside : spans.host_end.val ≤ s.length)
    (path_after : PathStart spans.host_end.val ≤ spans.name_end.val)
    (name_inside : spans.name_end.val ≤ s.length) :
    (spans.Reading s).NameLength =
      (if HubSpan s spans.host_end then 9 else spans.host_end.val) + 1 +
      (spans.name_end.val - PathStart spans.host_end.val) +
      (if HubSpan s spans.host_end ∧
        47 ∉ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end then 8 else 0) := by
  have on_hub : (spans.Reading s).OnTheHub ↔ HubSpan s spans.host_end := by
    unfold Reference.OnTheHub HubSpan Spans.Reading
    by_cases no_host : spans.host_end.val = 0 <;> simp [no_host]
  have one : (spans.Reading s).OneComponent ↔ 47 ∉ Piece (Bytes s.val)
      (PathStart spans.host_end.val) spans.name_end := by
    simp [Reference.OneComponent, Spans.Reading]
  have path_len : (spans.Reading s).path.length =
      spans.name_end.val - PathStart spans.host_end.val := by
    simp only [Spans.Reading]
    rw [piece_length _ _ _ path_after (by simpa using name_inside)]
  unfold Reference.NameLength Reference.Normal
  simp only [on_hub, one]
  by_cases hub : HubSpan s spans.host_end
  · by_cases lib : 47 ∈ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end
    · simp [hub, lib, path_len, Hub, Ascii]
    · simp [hub, lib, path_len, Hub, Ascii]
      omega
  · have positive : spans.host_end.val ≠ 0 := fun zero => hub (Or.inl zero)
    have host_len : (Piece (Bytes s.val) 0 spans.host_end).length = spans.host_end.val := by
      rw [piece_length _ _ _ (Nat.zero_le _) (by simpa using host_inside)]
      omega
    have path_len' : (Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end).length =
        spans.name_end.val - PathStart spans.host_end.val := path_len
    simp [hub, path_len', Spans.Reading, positive, host_len]

open Classical in
/-- What `parse` has found, with a path, a name of at most 255 bytes and not an image id, is a
reference of the grammar. -/
theorem found_is_in_the_grammar (s : Slice Std.U8) (spans : Spans) (at_ : Std.Usize)
    (found : Found s spans at_)
    (path : Path (Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end))
    (name_short : (if HubSpan s spans.host_end then 9 else spans.host_end.val) + 1 +
      (spans.name_end.val - PathStart spans.host_end.val) +
      (if HubSpan s spans.host_end ∧
        47 ∉ Piece (Bytes s.val) (PathStart spans.host_end.val) spans.name_end then 8 else 0) ≤ 255)
    (not_id : ¬ (spans.name_end.val = 64 ∧ spans.host_end.val = 0 ∧ spans.tag = none ∧
      spans.digest = none ∧ ∀ x ∈ Piece (Bytes s.val) 0 spans.name_end, IsHex x)) :
    (spans.Reading s).InGrammar := by
  have text := found_cuts_the_string s spans at_ found
  obtain ⟨small, ⟨ne_le, at_le⟩, host, first_component, tag, digest⟩ := found
  have name_inside : spans.name_end.val ≤ s.length := by omega
  have host_inside : spans.host_end.val ≤ s.length := by
    rcases host with zero | ⟨_, below, _⟩ <;> omega
  have path_after : PathStart spans.host_end.val ≤ spans.name_end.val := by
    unfold PathStart
    rcases host with zero | ⟨positive, below, _⟩
    · simp [zero]
    · have : spans.host_end.val ≠ 0 := by omega
      simp [this]; omega
  refine ⟨?_, path, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro h is_host
    simp only [Spans.Reading] at is_host
    by_cases zero : spans.host_end.val = 0
    · simp [zero] at is_host
    · rcases host with zero' | ⟨_, _, _, good, looks⟩
      · exact absurd zero' zero
      · simp [zero] at is_host
        subst is_host
        exact ⟨good, looks⟩
  · intro no_host
    have zero : spans.host_end.val = 0 := by
      by_contra not_zero
      simp [Spans.Reading, not_zero] at no_host
    simp only [Spans.Reading, PathStart, zero, ite_true]
    exact first_component zero
  · intro t is_tag
    simp only [Spans.Reading] at is_tag
    rcases tag with ⟨none_, _⟩ | ⟨_, _, i, _, some_, good⟩
    · simp [none_] at is_tag
    · simp [some_] at is_tag
      subst is_tag
      exact good
  · intro d is_digest
    simp only [Spans.Reading] at is_digest
    rcases digest with ⟨none_, _⟩ | ⟨_, _, i, _, some_, good⟩
    · simp [none_] at is_digest
    · simp [some_] at is_digest
      subst is_digest
      exact good
  · rw [text]; simpa using small
  · rw [name_length_of_the_reading s spans host_inside path_after name_inside]
    exact name_short
  · rintro ⟨no_host, no_tag, no_digest, long, hex⟩
    apply not_id
    have zero : spans.host_end.val = 0 := by
      by_contra not_zero
      simp [Spans.Reading, not_zero] at no_host
    have path_is : (spans.Reading s).path = Piece (Bytes s.val) 0 spans.name_end := by
      simp [Spans.Reading, PathStart, zero]
    rw [path_is] at long hex
    refine ⟨?_, zero, ?_, ?_, hex⟩
    · rw [piece_length _ _ _ (Nat.zero_le _) (by simpa using name_inside)] at long
      omega
    · simpa [Spans.Reading] using no_tag
    · simpa [Spans.Reading] using no_digest

end RefCore
