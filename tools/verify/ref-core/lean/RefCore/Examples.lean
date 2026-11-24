-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: three references that `parse` accepts, shown from the claims of Spec.lean:
-- `alpine`, `quay.io/a/b:1` (with the parts the spans cut out of it) and
-- `localhost:5000/x@sha256:` and 64 zeros.  Each is proved by showing that the reference is in the
-- grammar, and then by using `ParseAcceptsTheGrammar` and `AcceptedStringsHaveOneReading`; the
-- code of `parse` is not run.
-- Why it is needed: it shows that the claims are not empty, on references anyone knows.
-- Read before this file: Spec.lean and Claims.lean.
-- Notation: `Ascii "alpine"` is the list of the numbers of the bytes of the text.
import RefCore.Claims
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- A word of lower-case letters and digits is a component of a path. -/
theorem word_is_a_component (text : String) (letters : ∀ b ∈ Ascii text, IsAlnum b)
    (not_empty : Ascii text ≠ []) : Component (Ascii text) :=
  Component.word ⟨not_empty, letters⟩

/-- A word of lower-case letters and digits, hyphens inside, is a label of a host name. -/
theorem word_is_a_label (text : String) (first last : Nat) (bytes : ∀ b ∈ Ascii text,
      IsAlnum b ∨ b = 45) (begins : (Ascii text).head? = some first) (first_alnum : IsAlnum first)
    (ends : (Ascii text).getLast? = some last) (last_alnum : IsAlnum last) :
    IsLabel (Ascii text) :=
  ⟨bytes, ⟨first, begins, first_alnum⟩, ⟨last, ends, last_alnum⟩⟩

/-! ### `alpine` -/

/-- The reference `alpine`: a path of one component, nothing else. -/
def alpine : Reference := ⟨none, Ascii "alpine", none, none⟩

/-- `alpine` is in the grammar. -/
theorem alpine_is_in_the_grammar : alpine.InGrammar := by
  refine ⟨by simp [alpine], ?_, fun _ has_slash => by simp [alpine, Ascii] at has_slash,
    by simp [alpine], by simp [alpine], ?_, ?_, ?_⟩
  · refine Path.one (word_is_a_component "alpine" ?_ (by simp [Ascii]))
    intro b inside
    simp [Ascii] at inside
    unfold IsAlnum IsLower IsDigit
    omega
  · simp [Reference.Text, alpine, Ascii]
  · simp [Reference.NameLength, Reference.Normal, Reference.OnTheHub, Reference.OneComponent,
      alpine, Hub, Ascii]
  · simp [Reference.IsImageId, alpine, Ascii]

/-- `alpine` is accepted: any string of those bytes is. -/
theorem alpine_is_accepted (s : Slice Std.U8) (is_alpine : Bytes s.val = Ascii "alpine") :
    parse s ⦃ res => ∃ spans, res = core.result.Result.Ok spans ⦄ :=
  parse_accepts_the_grammar s alpine alpine_is_in_the_grammar
    (by simp [Reference.Text, alpine, is_alpine])

open Classical in
/-- After the defaults of docker.io, `alpine` is `docker.io/library/alpine`: this is what
`normalize` makes of it and `print` writes. -/
theorem alpine_after_the_defaults :
    alpine.Normal = ⟨some Hub, Ascii "library/alpine", none, none⟩ := by
  have hub : alpine.OnTheHub := Or.inl rfl
  have one : alpine.OneComponent := by simp [Reference.OneComponent, alpine, Ascii]
  apply reference_ext
  · simp [Reference.Normal, hub]
  · show (if alpine.OnTheHub ∧ alpine.OneComponent then Ascii "library/" else []) ++ alpine.path
      = _
    simp only [hub, one, and_self, ↓reduceIte]
    simp [alpine, Ascii]
  · rfl
  · rfl

/-! ### `quay.io/a/b:1` -/

/-- The reference `quay.io/a/b:1`: the host `quay.io`, the path `a/b` and the tag `1`. -/
def quay : Reference := ⟨some (Ascii "quay.io"), Ascii "a/b", some (Ascii "1"), none⟩

/-- `quay.io/a/b:1` is in the grammar. -/
theorem quay_is_in_the_grammar : quay.InGrammar := by
  refine ⟨?_, ?_, fun no_host => by simp [quay] at no_host, ?_, by simp [quay], ?_, ?_, ?_⟩
  · intro h is_h
    simp only [quay, Option.some.injEq] at is_h
    subst is_h
    refine ⟨Or.inr (Or.inl ?_), Or.inl (by simp [Ascii])⟩
    have cut : Ascii "quay.io" = Ascii "quay" ++ [46] ++ Ascii "io" := by decide
    rw [cut]
    refine Domain.join (Domain.label ?_) ?_
    · refine word_is_a_label "quay" 113 121 ?_ rfl (Or.inl (by unfold IsLower; omega)) rfl
        (Or.inl (by unfold IsLower; omega))
      intro b inside
      simp [Ascii] at inside
      unfold IsAlnum IsLower IsDigit
      omega
    · refine word_is_a_label "io" 105 111 ?_ rfl (Or.inl (by unfold IsLower; omega)) rfl
        (Or.inl (by unfold IsLower; omega))
      intro b inside
      simp [Ascii] at inside
      unfold IsAlnum IsLower IsDigit
      omega
  · have cut : Ascii "a/b" = Ascii "a" ++ [47] ++ Ascii "b" := by decide
    show Path (Ascii "a/b")
    rw [cut]
    refine Path.more (Path.one (word_is_a_component "a" ?_ (by simp [Ascii])))
      (word_is_a_component "b" ?_ (by simp [Ascii])) <;>
    · intro b inside
      simp [Ascii] at inside
      unfold IsAlnum IsLower IsDigit
      omega
  · intro tag is_tag
    simp only [quay, Option.some.injEq] at is_tag
    subst is_tag
    refine ⟨⟨49, rfl, Or.inl (Or.inr (by unfold IsDigit; omega))⟩, by simp [Ascii], ?_⟩
    intro b inside
    simp [Ascii] at inside
    subst inside
    exact Or.inl (Or.inl (Or.inr (by unfold IsDigit; omega)))
  · simp [Reference.Text, quay, Ascii]
  · simp [Reference.NameLength, Reference.Normal, Reference.OnTheHub, Reference.OneComponent,
      quay, Hub, Ascii]
  · simp [Reference.IsImageId, quay]

/-- A string with those bytes is accepted, and its spans cut it into the host `quay.io`, the path
`a/b` and the tag `1`. -/
theorem quay_is_read (s : Slice Std.U8) (is_quay : Bytes s.val = Ascii "quay.io/a/b:1") :
    parse s ⦃ res => ∃ spans, res = core.result.Result.Ok spans ∧ spans.Reading s = quay ⦄ := by
  have text : quay.Text = Bytes s.val := by
    rw [is_quay]
    simp [Reference.Text, quay, Ascii]
  have accepted := parse_accepts_the_grammar s quay quay_is_in_the_grammar text
  have one := accepted_strings_have_one_reading s quay quay_is_in_the_grammar text
  refine WP.spec_mono (WP.spec_and accepted one) ?_
  rintro res ⟨⟨spans, is_ok⟩, reads⟩
  exact ⟨spans, is_ok, reads spans is_ok⟩

/-! ### `localhost:5000/x@sha256:` and 64 zeros -/

/-- The reference `localhost:5000/x@sha256:` and 64 zeros: a host with a port, a path of one
component and a digest. -/
def local_digest : Reference := ⟨some (Ascii "localhost:5000"), Ascii "x", none,
  some (Ascii "sha256:" ++ List.replicate 64 48)⟩

/-- `localhost:5000/x@sha256:` and 64 zeros is in the grammar. -/
theorem local_digest_is_in_the_grammar : local_digest.InGrammar := by
  refine ⟨?_, ?_, fun no_host => by simp [local_digest] at no_host, by simp [local_digest], ?_,
    ?_, ?_, ?_⟩
  · intro h is_h
    simp only [local_digest, Option.some.injEq] at is_h
    subst is_h
    refine ⟨Or.inr (Or.inr ⟨Ascii "localhost", Ascii "5000", ?_, ?_, by decide⟩),
      Or.inr (Or.inl (by simp [Ascii]))⟩
    · refine Domain.label (word_is_a_label "localhost" 108 116 ?_ rfl
        (Or.inl (by unfold IsLower; omega)) rfl (Or.inl (by unfold IsLower; omega)))
      intro b inside
      simp [Ascii] at inside
      unfold IsAlnum IsLower IsDigit
      omega
    · refine ⟨by simp [Ascii], ?_⟩
      intro b inside
      simp [Ascii] at inside
      unfold IsDigit
      omega
  · refine Path.one (word_is_a_component "x" ?_ (by simp [Ascii]))
    intro b inside
    simp [Ascii] at inside
    unfold IsAlnum IsLower IsDigit
    omega
  · intro d is_d
    simp only [local_digest, Option.some.injEq] at is_d
    subst is_d
    refine ⟨"sha256:", 64, List.replicate 64 48, rfl, ?_, by simp, Or.inl ⟨rfl, rfl⟩⟩
    intro b inside
    simp at inside
    unfold IsHex IsDigit
    omega
  · simp [Reference.Text, local_digest, Ascii]
  · simp [Reference.NameLength, Reference.Normal, Reference.OnTheHub, Reference.OneComponent,
      local_digest, Hub, Ascii]
  · simp [Reference.IsImageId, local_digest]

/-- A string with those bytes is accepted, and its spans cut it into the host `localhost:5000`, the
path `x` and the digest. -/
theorem local_digest_is_read (s : Slice Std.U8)
    (is_it : Bytes s.val = Ascii "localhost:5000/x@" ++ Ascii "sha256:" ++ List.replicate 64 48) :
    parse s ⦃ res => ∃ spans, res = core.result.Result.Ok spans ∧
      spans.Reading s = local_digest ⦄ := by
  have text : local_digest.Text = Bytes s.val := by
    rw [is_it]
    simp [Reference.Text, local_digest, Ascii]
  have accepted := parse_accepts_the_grammar s local_digest local_digest_is_in_the_grammar text
  have one := accepted_strings_have_one_reading s local_digest local_digest_is_in_the_grammar text
  refine WP.spec_mono (WP.spec_and accepted one) ?_
  rintro res ⟨⟨spans, is_ok⟩, reads⟩
  exact ⟨spans, is_ok, reads spans is_ok⟩

/-! ### What `parse` refuses -/

/-- A reference written with none of `/`, `:` and `@` has no host, no tag and no digest: it is its
path. -/
theorem plain_string_is_a_path {r : Reference} {l : List Nat} (text : r.Text = l)
    (no_slash : 47 ∉ l) (no_colon : 58 ∉ l) (no_at : 64 ∉ l) :
    r.host = none ∧ r.tag = none ∧ r.digest = none ∧ r.path = l := by
  have host : r.host = none := by
    cases is_h : r.host with
    | none => rfl
    | some h =>
      exfalso; apply no_slash; rw [← text]; unfold Reference.Text; rw [is_h]; simp
  have tag : r.tag = none := by
    cases is_t : r.tag with
    | none => rfl
    | some t =>
      exfalso; apply no_colon; rw [← text]; unfold Reference.Text; rw [is_t]; simp
  have digest : r.digest = none := by
    cases is_d : r.digest with
    | none => rfl
    | some d =>
      exfalso; apply no_at; rw [← text]; unfold Reference.Text; rw [is_d]; simp
  refine ⟨host, tag, digest, ?_⟩
  rw [← text]
  unfold Reference.Text
  rw [host, tag, digest]
  simp

/-- A string with a capital is refused: the bytes of a path are lower case. -/
theorem capital_is_refused (s : Slice Std.U8) (is_it : Bytes s.val = Ascii "Alpine") :
    parse s ⦃ res => ∀ spans, res ≠ core.result.Result.Ok spans ⦄ := by
  refine WP.spec_mono (WP.spec_and (parse_accepts_only_the_grammar s)
    (accepted_bytes_are_only_these s)) ?_
  rintro res ⟨good, bytes⟩ spans is_ok
  obtain ⟨⟨_, text⟩, _⟩ := good spans is_ok
  obtain ⟨_, path_bytes, _⟩ := bytes spans is_ok
  rw [is_it] at text
  obtain ⟨_, _, _, path⟩ := plain_string_is_a_path text (by simp [Ascii]) (by simp [Ascii])
    (by simp [Ascii])
  have := path_bytes 65 (by rw [path]; simp [Ascii])
  unfold IsAlnum IsLower IsDigit at this
  omega

/-- A string of 64 zeros is refused: it is the id of an image. -/
theorem id_is_refused (s : Slice Std.U8) (is_it : Bytes s.val = List.replicate 64 48) :
    parse s ⦃ res => ∀ spans, res ≠ core.result.Result.Ok spans ⦄ := by
  refine WP.spec_mono (parse_accepts_only_the_grammar s) ?_
  rintro res good spans is_ok
  obtain ⟨⟨grammar, text⟩, _⟩ := good spans is_ok
  rw [is_it] at text
  obtain ⟨host, tag, digest, path⟩ := plain_string_is_a_path text (by simp) (by simp) (by simp)
  refine grammar.not_an_id ⟨host, tag, digest, ?_, ?_⟩
  · rw [path]; simp
  · intro b inside
    rw [path] at inside
    simp at inside
    unfold IsHex IsDigit
    omega

/-- The examples of `ExamplesAreRead`. -/
theorem examples_are_read : ExamplesAreRead :=
  ⟨alpine_is_accepted, quay_is_read, local_digest_is_read, alpine_after_the_defaults,
    capital_is_refused, id_is_refused⟩

end RefCore
