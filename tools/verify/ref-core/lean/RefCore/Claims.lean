-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of each claim of Spec.lean, from the files before it.
-- Why it is needed: Theorems.lean names each of them and Lean checks it has the type of the claim.
-- Read before this file: Spec.lean.
-- Notation: `WP.spec_mono` weakens what a function is known to answer.
import RefCore.Normal
import RefCore.ParseComplete
import RefCore.PublicComplete
import RefCore.PrintNormal
import RefCore.PositiveParts
import RefCore.Safety
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- `parse` accepts every reference of the grammar. -/
theorem parse_accepts_the_grammar : ParseAcceptsTheGrammar := fun s r grammar text =>
  WP.spec_mono (parse_finds_the_reading s r grammar text) (fun _ found =>
    let ⟨spans, is_ok, _⟩ := found
    ⟨spans, is_ok⟩)

/-- Whatever spans `parse` accepts a reference of the grammar with, they cut it as the reference
is. -/
theorem accepted_strings_have_one_reading : AcceptedStringsHaveOneReading := fun s r grammar text =>
  WP.spec_mono (parse_finds_the_reading s r grammar text) (fun _ found spans is_ok => by
    obtain ⟨spans', is_ok', reading⟩ := found
    rw [is_ok] at is_ok'
    cases is_ok'
    exact reading)

/-- A path of the grammar is components that are not empty, `.` or `..`, with none of the bytes
that would be read as something else. -/
theorem path_is_safe {p : List Nat} (is_path : Path p) : PathIsSafe p := by
  obtain ⟨comps, not_empty, all, eq⟩ := path_is_its_components is_path
  refine ⟨comps, not_empty, eq, fun c inside => ?_⟩
  obtain ⟨⟨x, rest, c_is, x_alnum⟩, bytes⟩ := component_shape (all c inside)
  have x_digit_or_letter := x_alnum
  unfold IsAlnum IsLower IsDigit at x_digit_or_letter
  refine ⟨by rw [c_is]; simp, ?_, ?_, fun b in_c danger => ?_⟩
  · rw [c_is]; intro same
    have := (List.cons.inj same).1
    omega
  · rw [c_is]; intro same
    have := (List.cons.inj same).1
    omega
  · have byte := bytes b in_c
    unfold IsAlnum IsLower IsDigit at byte
    omega

/-- `parse` returns on every byte string (a consequence of the claim that says what it answers). -/
theorem parse_always_returns : ParseAlwaysReturns := fun s =>
  WP.spec_mono (parse_accepts_only_the_grammar s) (fun _ _ => trivial)

/-- The readers other than `parse` return. -/
theorem the_other_readers_always_return : TheOtherReadersAlwaysReturn := by
  refine ⟨fun first => ?_, fun s => ?_, fun s => ?_, fun s room => ?_, fun s room => ?_,
      fun s => ?_⟩
  · exact WP.spec_mono (looks_like_host_says first) (fun _ _ => trivial)
  · unfold velarx_ref_core.host_error
    dsimp only
    step as ⟨ o, o_post ⟩
    cases o <;> simp [WP.spec_ok]
  · unfold velarx_ref_core.host_ok
    dsimp only
    step as ⟨ o, o_post ⟩
  · exact WP.spec_mono (prefix_error_accepts_only_prefixes s room) (fun _ _ => trivial)
  · exact WP.spec_mono (prefix_ok_accepts_only_prefixes s room) (fun _ _ => trivial)
  · refine WP.spec_mono (parse_accepts_only_the_grammar s) ?_
    rintro r good spans is_ok
    obtain ⟨_, at_, found⟩ := good spans is_ok
    exact WP.spec_mono (normalize_says s spans at_ found) (fun _ _ => trivial)

/-- What `parse` accepts is in the grammar, and the spans cut the string into its parts. -/
theorem accepted_references_are_in_the_grammar : AcceptedReferencesAreInTheGrammar := fun s =>
  WP.spec_mono (parse_accepts_only_the_grammar s) (fun _ good spans is_ok =>
    ⟨(good spans is_ok).1.1, (good spans is_ok).1.2⟩)

/-- The host and the path of what `parse` accepts have none of the dangerous bytes. -/
theorem accepted_parts_are_safe : AcceptedPartsAreSafe := fun s =>
  WP.spec_mono (parse_accepts_only_the_grammar s) (fun _ good spans is_ok => by
    have grammar := (good spans is_ok).1.1
    refine ⟨fun h is_host => host_is_safe (grammar.host h is_host).1, path_is_safe grammar.path⟩)

/-- `looks_like_host` says `true` exactly for what `LooksLikeHost` describes. -/
theorem looks_like_host_is_exact : LooksLikeHostIsExact := looks_like_host_says

/-- `host_error` and `host_ok` find no fault exactly in a host. -/
theorem host_error_finds_exactly_hosts : HostErrorFindsExactlyHosts :=
  ⟨host_error_says_exactly, host_ok_says_exactly⟩

/-- `prefix_error` and `prefix_ok` find no fault exactly in a prefix. -/
theorem prefix_error_finds_exactly_prefixes : PrefixErrorFindsExactlyPrefixes :=
  ⟨prefix_error_says_exactly, prefix_ok_says_exactly⟩

/-- Adding the defaults of docker.io to a name that has them changes nothing. -/
theorem normal_name_is_fixed : NormalNameIsFixed := normal_is_fixed

/-- The name after the defaults of a reference of the grammar is a reference of the grammar. -/
theorem normal_name_is_in_the_grammar : NormalNameIsInTheGrammar := fun _ grammar =>
  normal_is_in_the_grammar grammar

/-- `normalize` makes the name that `Reference.Normal` says. -/
theorem normalize_adds_the_defaults : NormalizeAddsTheDefaults := fun s =>
  WP.spec_mono (parse_accepts_only_the_grammar s) (fun _ good spans is_ok => by
    obtain ⟨_, at_, found⟩ := good spans is_ok
    exact normalize_says s spans at_ found)

end RefCore
