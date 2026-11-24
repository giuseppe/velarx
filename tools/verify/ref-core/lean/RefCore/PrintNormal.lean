-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that `print` of the name `normalize` made, with the tag and the digest of
-- the reference, writes the name in full (`Reference.Normal`, written as a string), that this
-- string is accepted by `parse`, and that `normalize` leaves what it reads as it is.
-- Why it is needed: the engine stores and compares this full form; it must be read again, and as
-- the same name.
-- Read before this file: PrintSays.lean, NormalGrammar.lean, ParseComplete.lean.
-- Notation: `Reference.Text` is a reference written as a string; `r.Normal` is the reference after
-- the defaults of docker.io.
import RefCore.PrintSays
import RefCore.NormalGrammar
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The name after the defaults, written as a string, is its host, a `/`, its path, and the tag
and the digest of the reference. -/
theorem normal_text_is_the_name_and_the_rest (r : Reference) :
    r.Normal.Text = r.Normal.host.getD [] ++ 47 :: r.Normal.path ++
      (r.tag.map (58 :: ·)).getD [] ++ (r.digest.map (64 :: ·)).getD [] := by
  obtain ⟨h, is_h⟩ := Option.ne_none_iff_exists'.mp (normal_has_a_host r)
  unfold Reference.Text
  rw [is_h]
  simp only [Option.map_some, Option.getD_some, List.append_assoc]
  rfl

/-- The slices that hold the tag of a reference of the grammar have at most 128 bytes, and those
that hold its digest at most 135. -/
theorem held_slices_are_short {r : Reference} (grammar : r.InGrammar)
    {tag digest : Option (Slice Std.U8)} (held : HoldTagAndDigest tag digest r) :
    (tag.map (·.length)).getD 0 ≤ 128 ∧ (digest.map (·.length)).getD 0 ≤ 135 := by
  obtain ⟨tag_is, digest_is⟩ := held
  constructor
  · cases tag with
    | none => simp
    | some t =>
      rw [Option.map_some] at tag_is
      have := (grammar.tag _ tag_is.symm).2.1
      simpa using this
  · cases digest with
    | none => simp
    | some d =>
      rw [Option.map_some] at digest_is
      obtain ⟨algorithm, count, hex, split, _, hex_count, kinds⟩ := grammar.digest _ digest_is.symm
      have seven : (Ascii algorithm).length = 7 := by
        rcases kinds with ⟨rfl, _⟩ | ⟨rfl, _⟩ | ⟨rfl, _⟩ <;> rfl
      have : count ≤ 128 := by rcases kinds with ⟨_, c⟩ | ⟨_, c⟩ | ⟨_, c⟩ <;> omega
      have := congrArg List.length split
      simp only [Option.map_some, Option.getD_some, List.length_append, seven, hex_count,
        bytes_length] at this ⊢
      have slice_length : d.length = (↑d : List Std.U8).length := rfl
      omega

/-- `print` of a name that has the host and the path of `r.Normal`, with slices that hold the tag
and the digest of `r`, writes `r.Normal` as a string. -/
theorem print_of_the_normal_name {r : Reference} (grammar : r.InGrammar) (n : Name)
    (host_is : Bytes n.host.val = r.Normal.host.getD [])
    (path_is : Bytes n.path.val = r.Normal.path) (tag digest : Option (Slice Std.U8))
    (held : HoldTagAndDigest tag digest r) :
    print n tag digest ⦃ out => Bytes out.val = r.Normal.Text ⦄ := by
  have short := held_slices_are_short grammar held
  have name_short := grammar.name_short
  unfold Reference.NameLength at name_short
  have host_len : n.host.length = (r.Normal.host.getD []).length := by
    have := congrArg List.length host_is
    simpa using this
  have path_len : n.path.length = r.Normal.path.length := by
    have := congrArg List.length path_is
    simpa using this
  refine WP.spec_mono (print_writes n tag digest (by omega)) ?_
  intro out written
  rw [written, normal_text_is_the_name_and_the_rest, host_is, path_is]
  have tag_part : (tag.map fun t => 58 :: Bytes t.val).getD [] =
      (r.tag.map (58 :: ·)).getD [] := by
    rw [← held.1]; cases tag <;> simp
  have digest_part : (digest.map fun d => 64 :: Bytes d.val).getD [] =
      (r.digest.map (64 :: ·)).getD [] := by
    rw [← held.2]; cases digest <;> simp
  rw [tag_part, digest_part]

/-- `print` of the name `normalize` made writes the name after the defaults in full. -/
theorem print_writes_the_normal_name : PrintWritesTheNormalName := fun s =>
  WP.spec_mono (parse_accepts_only_the_grammar s) (fun _ good spans is_ok => by
    obtain ⟨⟨grammar, _⟩, at_, found⟩ := good spans is_ok
    refine WP.spec_mono (normalize_says s spans at_ found) ?_
    rintro n ⟨host_is, path_is⟩ tag digest held
    exact print_of_the_normal_name grammar n host_is path_is tag digest held)

/-- What `print` writes of the name `normalize` made is accepted, as the name after the defaults,
and `normalize` leaves it as it is. -/
theorem printed_normal_name_is_accepted : PrintedNormalNameIsAccepted := fun s =>
  WP.spec_mono (parse_accepts_only_the_grammar s) (fun _ good spans is_ok => by
    obtain ⟨⟨grammar, _⟩, at_, found⟩ := good spans is_ok
    refine WP.spec_mono (normalize_says s spans at_ found) ?_
    rintro n ⟨host_is, path_is⟩ tag digest held
    refine WP.spec_mono (print_of_the_normal_name grammar n host_is path_is tag digest held) ?_
    intro out written
    have text : (spans.Reading s).Normal.Text = Bytes out.deref.val := by
      rw [← written]
      simp [alloc.vec.Vec.deref]
    have normal_grammar := normal_is_in_the_grammar grammar
    refine WP.spec_mono (WP.spec_and
      (parse_finds_the_reading out.deref _ normal_grammar text)
      (parse_accepts_only_the_grammar out.deref)) ?_
    rintro res ⟨⟨spans', is_ok', reading⟩, good'⟩
    obtain ⟨_, at', found'⟩ := good' spans' is_ok'
    refine ⟨spans', is_ok', reading, ?_⟩
    refine WP.spec_mono (normalize_says out.deref spans' at' found') ?_
    rintro n' ⟨host', path'⟩
    rw [reading, normal_is_fixed] at host' path'
    exact ⟨by rw [host', host_is], by rw [path', path_is]⟩)

end RefCore
