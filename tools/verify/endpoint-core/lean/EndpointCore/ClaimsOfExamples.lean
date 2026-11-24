-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `WorkedExamples` of Spec.lean: cases that are worked out
-- from the theorems about `select` and `endpoints` (not by running the extracted code): the Hub
-- with a mirror, a push, a prefix with a port, and the credentials of the command line: a block
-- moved to another host does not get them, a mirror on the host named does.
-- Why it is needed: a statement that is true of every input says nothing a reader can check by
-- eye; the examples show what it says on inputs one can read.
-- Read before this file: Spec.lean, ClaimsOfSelect.lean, ClaimsOfTheEndpoints.lean,
-- GovernsMeansGoverns.lean, ChoicesAreUnique.lean.
-- Notation: `WP.spec_mono h ?_` is "use the result `h` about the function, and show that what it
-- says is enough"; `WP.spec_and h h'` is "both results hold of the same run".
import EndpointCore.Spec
import EndpointCore.ClaimsOfSelect
import EndpointCore.ClaimsOfTheEndpoints
import EndpointCore.GovernsMeansGoverns
import EndpointCore.ChoicesAreUnique
import EndpointCore.VectorsAreSlices
import EndpointCore.ListedMirrorsOneByOne
import EndpointCore.FactsOfPairedLists

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

open Classical

/-- A prefix that begins with something else than `*` is not a wildcard prefix. -/
theorem a_prefix_not_beginning_with_a_star_is_plain (first : Std.U8) (rest : Bytes)
    (not_star : first ≠ Star) : ¬ IsWildcard (first :: rest) := by
  rintro ⟨domain, is_wildcard⟩
  simp only [List.cons.injEq] at is_wildcard
  exact not_star is_wildcard.1

/-- `example.com` does not govern `example.com:5000/x`: the `:` is not a boundary. -/
theorem example_com_does_not_govern_a_port :
    ¬ Governs (Ascii "example.com") (Ascii "example.com:5000/x") := by
  have plain : ¬ IsWildcard (Ascii "example.com") :=
    a_prefix_not_beginning_with_a_star_is_plain _ _ (by decide)
  rw [a_plain_prefix_governs_by_the_next_byte _ _ plain (by decide) (by decide) 58#u8 (by decide)]
  decide

/-- `example.com:5000` is governed by the prefix that names the port. -/
theorem example_com_port_governs_itself :
    Governs (Ascii "example.com:5000") (Ascii "example.com:5000/x") := by
  have plain : ¬ IsWildcard (Ascii "example.com:5000") :=
    a_prefix_not_beginning_with_a_star_is_plain _ _ (by decide)
  rw [a_plain_prefix_governs_by_the_next_byte _ _ plain (by decide) (by decide) 47#u8 (by decide)]
  decide

/-- With the blocks `example.com` and `example.com:5000`, the second is chosen for
`example.com:5000/x`. -/
theorem the_block_with_the_port_is_chosen :
    Chooses [PlainBlock "example.com", PlainBlock "example.com:5000"]
      (Ascii "example.com:5000/x") (some 1) := by
  refine ⟨?_, ?_⟩
  · intro b is_b
    cases is_b
    refine ⟨PlainBlock "example.com:5000", by simp, by decide, ?_, ?_, ?_⟩
    · simpa [PlainBlock, TextVec] using example_com_port_governs_itself
    · intro other other_in _ governs
      simp only [List.mem_cons, List.not_mem_nil, or_false] at other_in
      rcases other_in with rfl | rfl
      · exact absurd (by simpa [PlainBlock, TextVec] using governs)
          example_com_does_not_govern_a_port
      · exact Nat.le_refl _
    · intro j earlier before at_j _ governs
      have : j = 0 := by omega
      subst this
      simp only [List.getElem?_cons_zero, Option.some.injEq] at at_j
      subst at_j
      exact absurd (by simpa [PlainBlock, TextVec] using governs)
        example_com_does_not_govern_a_port
  · constructor
    · intro absurd
      cases absurd
    · intro none_governs
      exact absurd (by simpa [PlainBlock, TextVec] using example_com_port_governs_itself)
        (none_governs (PlainBlock "example.com:5000") (by simp) (by decide))

/-- The bytes of a short text are the bytes of its text. -/
@[simp] theorem the_bytes_of_a_text (text : String) (short : text.toList.length ≤ 255) :
    (TextSlice text short).val = Ascii text := by
  simp [TextSlice, TextVec]

/-- The blocks of a short list are the blocks of the list. -/
@[simp] theorem the_blocks_of_a_list (blocks : List Block) (few : blocks.length ≤ 255) :
    (BlocksOf blocks few).val = blocks := by
  simp [BlocksOf]

/-- A block whose prefix is not a wildcard is not chosen for a name that goes on after the prefix
with a byte that is neither `/` nor `@`: with that block alone, no block is chosen. -/
theorem a_lone_prefix_does_not_govern_a_name_that_goes_on (text : String)
    (short : text.toList.length ≤ 255) (ref : Slice Std.U8) (c : Std.U8) (rest : Bytes)
    (plain : ¬ IsWildcard (Ascii text)) (split : ref.val = Ascii text ++ c :: rest)
    (not_slash : c ≠ Slash) (not_at : c ≠ AtSign) :
    select (BlocksOf [PlainBlock text [] short] (by simp)) ref ⦃ found => found = none ⦄ := by
  refine WP.spec_mono (select_chooses_the_block _ _) ?_
  intro found chosen
  have none_chosen : Chooses [PlainBlock text [] short] ref.val none := by
    refine ⟨by simp, ?_⟩
    simp only [true_iff, List.mem_singleton, forall_eq]
    intro _ governs
    have begins : Ascii text <+: ref.val := ⟨c :: rest, by rw [split]⟩
    have longer : (Ascii text).length < ref.val.length := by simp [split]
    have next : ref.val[(Ascii text).length]? = some c := by
      rw [split, List.getElem?_append_right (by omega)]
      simp
    rw [a_plain_prefix_governs_by_the_next_byte _ _ (by simpa [PlainBlock, TextVec] using plain)
      (by simpa [PlainBlock, TextVec] using begins) (by simpa [PlainBlock, TextVec] using longer)
      c (by simpa [PlainBlock, TextVec] using next)] at governs
    rcases governs with is_slash | is_at
    · exact not_slash is_slash
    · exact not_at is_at
  have := a_choice_is_unique _ _ _ _ chosen (by simpa using none_chosen)
  simpa using this

/-- The example of the prefix with no port: no block is chosen. -/
theorem a_prefix_does_not_govern_a_port :
    select (BlocksOf [PlainBlock "example.com"]) (TextSlice "example.com:5000/x") ⦃ found =>
      found = none ⦄ :=
  a_lone_prefix_does_not_govern_a_name_that_goes_on "example.com" (by decide) _ 58#u8
    (Ascii "5000/x") (a_prefix_not_beginning_with_a_star_is_plain _ _ (by decide)) (by decide)
    (by decide) (by decide)

/-- The example of a prefix that only starts the name: no block is chosen. -/
theorem a_prefix_does_not_govern_a_longer_host :
    select (BlocksOf [PlainBlock "example.com"]) (TextSlice "example.community/x") ⦃ found =>
      found = none ⦄ :=
  a_lone_prefix_does_not_govern_a_name_that_goes_on "example.com" (by decide) _ 109#u8
    (Ascii "unity/x") (a_prefix_not_beginning_with_a_star_is_plain _ _ (by decide)) (by decide)
    (by decide) (by decide)

/-- The example of the prefix with the port: the second block is chosen. -/
theorem a_prefix_that_names_the_port_governs_it :
    select (BlocksOf [PlainBlock "example.com", PlainBlock "example.com:5000"])
      (TextSlice "example.com:5000/x") ⦃ found => found = some 1#usize ⦄ := by
  refine WP.spec_mono (select_chooses_the_block _ _) ?_
  intro found chosen
  have := a_choice_is_unique _ _ _ _ chosen (by simpa using the_block_with_the_port_is_chosen)
  cases found with
  | none => simp at this
  | some b =>
    simp only [Option.map_some, Option.some.injEq] at this
    have : b = 1#usize := UScalar.eq_of_val_eq this
    rw [this]

/-- A lone block whose prefix governs the name is the block chosen for it. -/
theorem a_lone_block_that_governs_is_chosen (block : Block) (ref : Bytes)
    (nonempty : block.prefix.val ≠ []) (governs : Governs block.prefix.val ref) :
    Chooses [block] ref (some 0) := by
  refine ⟨?_, ?_⟩
  · intro b is_b
    cases is_b
    refine ⟨block, by simp, nonempty, governs, ?_, ?_⟩
    · intro other other_in _ _
      simp only [List.mem_singleton] at other_in
      rw [other_in]
    · intro j earlier before
      omega
  · constructor
    · intro absurd
      cases absurd
    · intro none_governs
      exact absurd governs (none_governs block (by simp) nonempty)

/-- A lone block, and a host and a path, whose texts (and those of its location and mirrors) are
at most 255 bytes long, satisfy `Fits`. -/
theorem a_lone_block_of_short_texts_fits (block : Block) (host path : Slice Std.U8)
    (host_short : host.length ≤ 255) (path_short : path.length ≤ 255)
    (location_short : ∀ location, block.location = some location → location.length ≤ 255)
    (mirrors_short : ∀ m ∈ block.mirrors.val, m.location.length ≤ 255)
    (few : block.mirrors.length ≤ 255) : Fits (BlocksOf [block] (by simp)) host path := by
  refine ⟨by scalar_tac, ?_⟩
  intro other other_in
  simp only [the_blocks_of_a_list, List.mem_singleton] at other_in
  subst other_in
  refine ⟨fun location is_location => ?_, fun m m_in => ?_, by scalar_tac⟩
  · have := location_short location is_location
    scalar_tac
  · have := mirrors_short m m_in
    scalar_tac

/-- The mirrors of a lone block, when it has only one: for a request that is not a push and that
the mirror serves, at an address that no block blocks and that is not the registry's, that mirror
is the only one listed. -/
theorem a_lone_block_lists_its_only_mirror (block : Block) (mir : Mirror) (ask : Ask)
    (ref address : Bytes) (single : block.mirrors.val = [mir]) (not_push : ask.push = false)
    (serves : Serves mir.mode ask.has_digest) (is_address : MirrorAddress block mir ref = address)
    (free : ¬ BlockedAt [block] address)
    (apart : Located address ≠ Located (RegistryOf [block] (some 0) ref)) :
    ListedMirrors [block] (some 0) ask ref = [(mir, address)] := by
  have listed : Listed [block] block ask ref (RegistryOf [block] (some 0) ref) mir := by
    refine ⟨⟨not_push, serves, ?_⟩, ?_⟩
    · rw [is_address]
      exact free
    · rw [is_address]
      exact apart
  simp only [ListedMirrors, ChosenBlock, Option.bind_some, List.getElem?_cons_zero]
  rw [single]
  unfold ListedAmong
  simp only [List.filter_cons, listed, decide_true, ite_true, List.filter_nil, List.map_cons,
    List.map_nil, is_address]

/-- A lone block that is chosen for the name, is not blocked, whose registry and mirrors all have
a repository, answers with a list: the registry is last, the mirrors that are listed come before
it, each at its address, and the credentials of the command line are for the endpoints on the
host that was named (the Hub folded) only. -/
theorem a_lone_block_answers_with_a_list (block : Block) (host path : Slice Std.U8) (ask : Ask)
    (fits : Fits (BlocksOf [block] (by simp)) host path)
    (chosen : Chooses [block] (NameOf host.val path.val) (some 0))
    (not_blocked : block.blocked = false)
    (has_slash : Slash ∈ RegistryName block (NameOf host.val path.val))
    (repositories : ∀ m ∈ block.mirrors.val,
      Slash ∈ MirrorAddress block m (NameOf host.val path.val)) :
    endpoints (BlocksOf [block] (by simp)) host path ask ⦃ r =>
      ∃ es mirrors primary, r = .Ok es ∧ es.val = mirrors ++ [primary] ∧
        Located (RegistryName block (NameOf host.val path.val)) = some primary.Where ∧
        List.Forall₂ (fun p e => Located p.2 = some e.Where)
          (ListedMirrors [block] (some 0) ask (NameOf host.val path.val)) mirrors ∧
        ∀ e ∈ es.val, (e.creds = Creds.CommandLine ↔ e.host.val = Folded host.val) ⦄ := by
  have chosen' : Chooses (BlocksOf [block] (by simp)).val (NameOf host.val path.val) (some 0) := by
    simpa using chosen
  have list := the_list_is_the_listed_mirrors_then_the_registry _ _ _ ask fits (some 0) chosen'
  have other := otherwise_a_list_is_answered _ _ _ ask fits (some 0) chosen'
  have creds := command_line_credentials_are_for_the_host_named _ _ _ ask fits
  refine WP.spec_mono (WP.spec_and list (WP.spec_and other creds)) ?_
  rintro r ⟨list, other, creds⟩
  simp only [the_blocks_of_a_list] at list other creds
  have blocked : ¬ ChosenIsBlocked [block] (some 0) := by
    rintro ⟨chosen_block, is_block, is_blocked⟩
    simp only [ChosenBlock, Option.bind_some, List.getElem?_cons_zero, Option.some.injEq]
      at is_block
    subst is_block
    simp [not_blocked] at is_blocked
  have registry : RegistryOf [block] (some 0) (NameOf host.val path.val) =
      RegistryName block (NameOf host.val path.val) := by
    simp [RegistryOf, ChosenBlock]
  have no_mirror : ¬ AMirrorHasNoRepository [block] (some 0) ask (NameOf host.val path.val) := by
    rintro ⟨chosen_block, is_block, m, m_in, _, no_slash⟩
    simp only [ChosenBlock, Option.bind_some, List.getElem?_cons_zero, Option.some.injEq]
      at is_block
    subst is_block
    exact no_slash (repositories m m_in)
  obtain ⟨es, is_ok⟩ := other.mpr ⟨blocked, by rw [registry]; exact has_slash, no_mirror⟩
  obtain ⟨mirrors, primary, es_is, located, paired⟩ := list es is_ok
  rw [registry] at located
  exact ⟨es, mirrors, primary, is_ok, es_is, located, paired, creds es is_ok⟩

/-- The block of the Hub, with a mirror. -/
abbrev HubBlock : Block := PlainBlock "docker.io" [PlainMirror "mirror.example.com/hub"]

/-- The name `docker.io/library/alpine`. -/
abbrev HubName' : Bytes := NameOf (Ascii "docker.io") (Ascii "library/alpine")

theorem the_hub_is_not_a_wildcard : ¬ IsWildcard (Ascii "docker.io") :=
  a_prefix_not_beginning_with_a_star_is_plain _ _ (by decide)

/-- The block of the Hub is chosen for `docker.io/library/alpine`. -/
theorem the_hub_block_is_chosen : Chooses [HubBlock] HubName' (some 0) := by
  have governs : Governs (Ascii "docker.io") HubName' := by
    rw [a_plain_prefix_governs_by_the_next_byte _ _ the_hub_is_not_a_wildcard (by decide)
      (by decide) 47#u8 (by decide)]
    decide
  exact a_lone_block_that_governs_is_chosen HubBlock HubName'
    (by simp [HubBlock, PlainBlock, TextVec, Ascii])
    (by simpa [HubBlock, PlainBlock, TextVec] using governs)

/-- The mirror of the Hub block. -/
abbrev HubMirror : Mirror := PlainMirror "mirror.example.com/hub"

/-- The address of the mirror for `docker.io/library/alpine`. -/
theorem the_mirror_address :
    MirrorAddress HubBlock HubMirror HubName' = Ascii "mirror.example.com/hub/library/alpine" := by
  unfold MirrorAddress Rewritten
  have plain : ¬ IsWildcard HubBlock.prefix.val := by
    simpa [HubBlock, PlainBlock, TextVec] using the_hub_is_not_a_wildcard
  simp only [plain, ↓reduceIte]
  simp only [HubBlock, PlainBlock, TextVec, HubMirror, PlainMirror, alloc.vec.Vec.from_val]
  decide

/-- The block of the Hub is chosen for `docker.io/library/alpine`, and none for the address of its
mirror. -/
theorem no_block_is_chosen_for_the_mirror : Chooses [HubBlock]
    (Ascii "mirror.example.com/hub/library/alpine") none := by
  refine ⟨by simp, ?_⟩
  simp only [true_iff, List.mem_singleton, forall_eq]
  intro _ governs
  have plain : ¬ IsWildcard HubBlock.prefix.val := by
    simpa [HubBlock, PlainBlock, TextVec] using the_hub_is_not_a_wildcard
  have := a_plain_prefix_governs_only_what_it_begins _ _ plain governs
  simp [HubBlock, PlainBlock, TextVec] at this
  revert this
  decide

/-- The registry of the Hub block, for `docker.io/library/alpine`, is at the name itself. -/
theorem the_hub_registry_is_at_the_name :
    RegistryOf [HubBlock] (some 0) HubName' = HubName' := by
  simp [RegistryOf, ChosenBlock, RegistryName, HubBlock, PlainBlock]

/-- With a request that is not a push, the mirror of the Hub block is listed, at its address. -/
theorem the_mirror_of_the_hub_is_listed (ask : Ask) (not_push : ask.push = false) :
    ListedMirrors [HubBlock] (some 0) ask HubName' =
      [(HubMirror, Ascii "mirror.example.com/hub/library/alpine")] := by
  refine a_lone_block_lists_its_only_mirror HubBlock HubMirror ask HubName' _
    (by simp [HubBlock, PlainBlock, HubMirror]) not_push (by simp [Serves, HubMirror, PlainMirror])
    the_mirror_address ?_ ?_
  · rintro ⟨b, block, chosen, _, _⟩
    have := a_choice_is_unique _ _ _ _ chosen no_block_is_chosen_for_the_mirror
    simp at this
  · rw [the_hub_registry_is_at_the_name]
    decide

/-- For every request, the Hub block answers with a list: the registry is last, and the mirrors that
are listed come before it, each at its address; and the credentials of the command line are for
the endpoints on the Hub's host only. -/
theorem the_hub_answers_with_a_list (ask : Ask) :
    endpoints (BlocksOf [HubBlock]) (TextSlice "docker.io") (TextSlice "library/alpine") ask ⦃ r =>
      ∃ es mirrors primary, r = .Ok es ∧ es.val = mirrors ++ [primary] ∧
        Located HubName' = some primary.Where ∧
        List.Forall₂ (fun p e => Located p.2 = some e.Where)
          (ListedMirrors [HubBlock] (some 0) ask HubName') mirrors ∧
        ∀ e ∈ es.val, (e.creds = Creds.CommandLine ↔ e.host.val = HubApi) ⦄ := by
  have fits : Fits (BlocksOf [HubBlock]) (TextSlice "docker.io") (TextSlice "library/alpine") := by
    refine a_lone_block_of_short_texts_fits HubBlock _ _ ?_ ?_ ?_ ?_ ?_
    · simp [TextSlice, TextVec, Ascii]
    · simp [TextSlice, TextVec, Ascii]
    · intro location is_location
      simp [HubBlock, PlainBlock] at is_location
    · intro m m_in
      simp only [HubBlock, PlainBlock, alloc.vec.Vec.from_val, List.mem_singleton] at m_in
      subst m_in
      simp [PlainMirror, TextVec, Ascii]
    · simp [HubBlock, PlainBlock]
  have chosen : Chooses [HubBlock]
      (NameOf (TextSlice "docker.io").val (TextSlice "library/alpine").val) (some 0) := by
    simpa using the_hub_block_is_chosen
  have registry : RegistryName HubBlock HubName' = HubName' := by
    simp [RegistryName, HubBlock, PlainBlock]
  refine WP.spec_mono (a_lone_block_answers_with_a_list HubBlock _ _ ask fits chosen rfl ?_ ?_) ?_
  · simp only [the_bytes_of_a_text]
    rw [registry]
    decide
  · intro m m_in
    simp only [HubBlock, PlainBlock, alloc.vec.Vec.from_val, List.mem_singleton] at m_in
    subst m_in
    simp only [the_bytes_of_a_text]
    rw [the_mirror_address]
    decide
  · rintro r ⟨es, mirrors, primary, is_ok, es_is, located, paired, creds⟩
    simp only [the_bytes_of_a_text, registry] at located paired creds
    have fold : Folded (Ascii "docker.io") = HubApi := by decide
    rw [fold] at creds
    exact ⟨es, mirrors, primary, is_ok, es_is, located, paired, creds⟩

/-- The Hub with a mirror: asked at the mirror, then at the Hub. -/
theorem the_hub_with_a_mirror :
    endpoints (BlocksOf [PlainBlock "docker.io" [PlainMirror "mirror.example.com/hub"]])
      (TextSlice "docker.io") (TextSlice "library/alpine")
      { has_digest := false, push := false, tls_verify := true } ⦃ r =>
    ∃ es, r = .Ok es ∧
      es.val.map Endpoint.Where = [(Ascii "mirror.example.com", Ascii "hub/library/alpine"),
        (Ascii "registry-1.docker.io", Ascii "library/alpine")] ∧
      es.val.map (·.creds) = [Creds.Stored, Creds.CommandLine] ⦄ := by
  refine WP.spec_mono (the_hub_answers_with_a_list _) ?_
  rintro r ⟨es, mirrors, primary, is_ok, es_is, located, paired, creds⟩
  rw [the_mirror_of_the_hub_is_listed _ rfl] at paired
  obtain ⟨first, rest, first_located, rest_paired, is_mirrors⟩ :=
    List.forall₂_cons_left_iff.mp paired
  have rest_nil : rest = [] := List.forall₂_nil_left_iff.mp rest_paired
  subst is_mirrors
  subst rest_nil
  have mirror_is : Located (Ascii "mirror.example.com/hub/library/alpine") =
      some (Ascii "mirror.example.com", Ascii "hub/library/alpine") := by decide
  have hub_is : Located HubName' = some (Ascii "registry-1.docker.io", Ascii "library/alpine") := by
    decide
  simp only [mirror_is, Option.some.injEq] at first_located
  simp only [hub_is, Option.some.injEq] at located
  have first_host : first.host.val = Ascii "mirror.example.com" :=
    (congrArg Prod.fst first_located).symm
  have first_path : first.path.val = Ascii "hub/library/alpine" :=
    (congrArg Prod.snd first_located).symm
  have primary_host : primary.host.val = HubApi := (congrArg Prod.fst located).symm
  have primary_path : primary.path.val = Ascii "library/alpine" :=
    (congrArg Prod.snd located).symm
  refine ⟨es, is_ok, ?_, ?_⟩
  · rw [es_is]
    simp [Endpoint.Where, first_host, first_path, primary_host, primary_path]
    decide
  · rw [es_is]
    have first_creds := creds first (by simp [es_is])
    have primary_creds := creds primary (by simp [es_is])
    have first_stored : first.creds = Creds.Stored := by
      cases h : first.creds
      · have is_hub := first_creds.mp h
        rw [first_host] at is_hub
        exact absurd is_hub (by decide)
      · rfl
    have primary_command_line : primary.creds = Creds.CommandLine :=
      primary_creds.mpr primary_host
    simp [first_stored, primary_command_line]

/-- A push of the same name is asked at the Hub only. -/
theorem a_push_is_asked_at_the_hub_only :
    endpoints (BlocksOf [PlainBlock "docker.io" [PlainMirror "mirror.example.com/hub"]])
      (TextSlice "docker.io") (TextSlice "library/alpine")
      { has_digest := false, push := true, tls_verify := true } ⦃ r =>
    ∃ es, r = .Ok es ∧
      es.val.map Endpoint.Where = [(Ascii "registry-1.docker.io", Ascii "library/alpine")] ⦄ := by
  refine WP.spec_mono (the_hub_answers_with_a_list _) ?_
  rintro r ⟨es, mirrors, primary, is_ok, es_is, located, paired, _⟩
  have no_mirror : ListedMirrors [HubBlock] (some 0)
      { has_digest := false, push := true, tls_verify := true } HubName' = [] := by
    simp only [ListedMirrors, ChosenBlock, Option.bind_some, List.getElem?_cons_zero,
      the_hub_registry_is_at_the_name]
    exact a_push_lists_no_mirror _ _ _ _ _ _ rfl
  rw [no_mirror] at paired
  have mirrors_nil : mirrors = [] := List.forall₂_nil_left_iff.mp paired
  subst mirrors_nil
  have hub_is : Located HubName' = some (Ascii "registry-1.docker.io", Ascii "library/alpine") := by
    decide
  rw [hub_is] at located
  refine ⟨es, is_ok, ?_⟩
  rw [es_is]
  simp [← Option.some.inj located]

theorem a_test_is_not_a_wildcard : ¬ IsWildcard (Ascii "a.test") :=
  a_prefix_not_beginning_with_a_star_is_plain _ _ (by decide)

/-- `a.test` governs `a.test/x`. -/
theorem a_test_governs_its_own_name :
    Governs (Ascii "a.test") (NameOf (Ascii "a.test") (Ascii "x")) := by
  rw [a_plain_prefix_governs_by_the_next_byte _ _ a_test_is_not_a_wildcard (by decide) (by decide)
    47#u8 (by decide)]
  decide

/-- The security case.  A block whose `location` is on another host than the name typed: the
registry is asked there, with the credentials stored for it and not those of the command line,
which the user typed for the host of the name. -/
theorem a_block_moved_to_another_host_has_stored_credentials :
    endpoints (BlocksOf [MovedBlock "a.test" "b.test"]) (TextSlice "a.test") (TextSlice "x")
      { has_digest := false, push := false, tls_verify := true } ⦃ r =>
    ∃ es, r = .Ok es ∧
      es.val.map Endpoint.Where = [(Ascii "b.test", Ascii "x")] ∧
      es.val.map (·.creds) = [Creds.Stored] ⦄ := by
  have fits : Fits (BlocksOf [MovedBlock "a.test" "b.test"]) (TextSlice "a.test")
      (TextSlice "x") := by
    refine a_lone_block_of_short_texts_fits _ _ _ ?_ ?_ ?_ ?_ ?_
    · simp [TextSlice, TextVec, Ascii]
    · simp [TextSlice, TextVec, Ascii]
    · intro location is_location
      simp only [MovedBlock, Option.some.injEq] at is_location
      subst is_location
      simp [TextVec, Ascii]
    · simp [MovedBlock]
    · simp [MovedBlock]
  have chosen : Chooses [MovedBlock "a.test" "b.test"]
      (NameOf (TextSlice "a.test").val (TextSlice "x").val) (some 0) := by
    simp only [the_bytes_of_a_text]
    exact a_lone_block_that_governs_is_chosen _ _ (by simp [MovedBlock, TextVec, Ascii])
      (by simpa [MovedBlock, TextVec] using a_test_governs_its_own_name)
  have registry : RegistryName (MovedBlock "a.test" "b.test")
      (NameOf (Ascii "a.test") (Ascii "x")) = Ascii "b.test/x" := by
    simp only [RegistryName, MovedBlock, TextVec, alloc.vec.Vec.from_val]
    decide
  refine WP.spec_mono (a_lone_block_answers_with_a_list _ _ _ _ fits chosen rfl ?_
    (by simp [MovedBlock])) ?_
  · simp only [the_bytes_of_a_text, registry]
    decide
  · rintro r ⟨es, mirrors, primary, is_ok, es_is, located, paired, creds⟩
    simp only [the_bytes_of_a_text, registry] at located paired creds
    have no_mirror : ListedMirrors [MovedBlock "a.test" "b.test"] (some 0)
        { has_digest := false, push := false, tls_verify := true }
        (NameOf (Ascii "a.test") (Ascii "x")) = [] := by
      simp [ListedMirrors, ChosenBlock, MovedBlock, ListedAmong]
    rw [no_mirror] at paired
    have mirrors_nil : mirrors = [] := List.forall₂_nil_left_iff.mp paired
    subst mirrors_nil
    have located_is : Located (Ascii "b.test/x") = some (Ascii "b.test", Ascii "x") := by decide
    rw [located_is] at located
    have host : primary.host.val = Ascii "b.test" :=
      (congrArg Prod.fst (Option.some.inj located)).symm
    have path : primary.path.val = Ascii "x" :=
      (congrArg Prod.snd (Option.some.inj located)).symm
    have primary_creds := creds primary (by simp [es_is])
    have stored : primary.creds = Creds.Stored := by
      cases h : primary.creds
      · have is_typed := primary_creds.mp h
        rw [host] at is_typed
        exact absurd is_typed (by decide)
      · rfl
    refine ⟨es, is_ok, ?_, ?_⟩ <;> rw [es_is] <;>
      simp [Endpoint.Where, host, path, stored]

/-- The same host, another path.  A mirror on the host of the name typed, with another path, is
asked with the credentials of the command line, as the registry is. -/
theorem a_mirror_on_the_host_named_has_the_credentials_of_the_command_line :
    endpoints (BlocksOf [PlainBlock "a.test" [PlainMirror "a.test/m"]])
      (TextSlice "a.test") (TextSlice "x")
      { has_digest := false, push := false, tls_verify := true } ⦃ r =>
    ∃ es, r = .Ok es ∧
      es.val.map Endpoint.Where = [(Ascii "a.test", Ascii "m/x"), (Ascii "a.test", Ascii "x")] ∧
      es.val.map (·.creds) = [Creds.CommandLine, Creds.CommandLine] ⦄ := by
  have fits : Fits (BlocksOf [PlainBlock "a.test" [PlainMirror "a.test/m"]])
      (TextSlice "a.test") (TextSlice "x") := by
    refine a_lone_block_of_short_texts_fits _ _ _ ?_ ?_ ?_ ?_ ?_
    · simp [TextSlice, TextVec, Ascii]
    · simp [TextSlice, TextVec, Ascii]
    · intro location is_location
      simp [PlainBlock] at is_location
    · intro m m_in
      simp only [PlainBlock, alloc.vec.Vec.from_val, List.mem_singleton] at m_in
      subst m_in
      simp [PlainMirror, TextVec, Ascii]
    · simp [PlainBlock]
  have chosen : Chooses [PlainBlock "a.test" [PlainMirror "a.test/m"]]
      (NameOf (TextSlice "a.test").val (TextSlice "x").val) (some 0) := by
    simp only [the_bytes_of_a_text]
    exact a_lone_block_that_governs_is_chosen _ _ (by simp [PlainBlock, TextVec, Ascii])
      (by simpa [PlainBlock, TextVec] using a_test_governs_its_own_name)
  have registry : RegistryName (PlainBlock "a.test" [PlainMirror "a.test/m"])
      (NameOf (Ascii "a.test") (Ascii "x")) = NameOf (Ascii "a.test") (Ascii "x") := by
    simp [RegistryName, PlainBlock]
  have address : MirrorAddress (PlainBlock "a.test" [PlainMirror "a.test/m"])
      (PlainMirror "a.test/m") (NameOf (Ascii "a.test") (Ascii "x")) =
      Ascii "a.test/m/x" := by
    unfold MirrorAddress Rewritten
    have plain : ¬ IsWildcard (PlainBlock "a.test" [PlainMirror "a.test/m"]).prefix.val := by
      simpa [PlainBlock, TextVec] using a_test_is_not_a_wildcard
    simp only [plain, ↓reduceIte]
    simp only [PlainBlock, TextVec, PlainMirror, alloc.vec.Vec.from_val]
    decide
  refine WP.spec_mono (a_lone_block_answers_with_a_list _ _ _ _ fits chosen rfl ?_ ?_) ?_
  · simp only [the_bytes_of_a_text, registry]
    decide
  · intro m m_in
    simp only [PlainBlock, alloc.vec.Vec.from_val, List.mem_singleton] at m_in
    subst m_in
    simp only [the_bytes_of_a_text, address]
    decide
  · rintro r ⟨es, mirrors, primary, is_ok, es_is, located, paired, creds⟩
    simp only [the_bytes_of_a_text, registry] at located paired creds
    have free : ¬ BlockedAt [PlainBlock "a.test" [PlainMirror "a.test/m"]]
        (Ascii "a.test/m/x") := by
      rintro ⟨b, block, _, is_block, blocked⟩
      rcases b with _ | b
      · simp only [List.getElem?_cons_zero, Option.some.injEq] at is_block
        subst is_block
        simp [PlainBlock] at blocked
      · simp at is_block
    have listed := a_lone_block_lists_its_only_mirror
      (PlainBlock "a.test" [PlainMirror "a.test/m"]) (PlainMirror "a.test/m")
      { has_digest := false, push := false, tls_verify := true }
      (NameOf (Ascii "a.test") (Ascii "x")) (Ascii "a.test/m/x") (by simp [PlainBlock]) rfl
      (by simp [Serves, PlainMirror]) address free (by
        have : RegistryOf [PlainBlock "a.test" [PlainMirror "a.test/m"]] (some 0)
            (NameOf (Ascii "a.test") (Ascii "x")) = NameOf (Ascii "a.test") (Ascii "x") := by
          simp [RegistryOf, ChosenBlock, RegistryName, PlainBlock]
        rw [this]
        decide)
    rw [listed] at paired
    obtain ⟨first, rest, first_located, rest_paired, is_mirrors⟩ :=
      List.forall₂_cons_left_iff.mp paired
    have rest_nil : rest = [] := List.forall₂_nil_left_iff.mp rest_paired
    subst is_mirrors
    subst rest_nil
    have mirror_is : Located (Ascii "a.test/m/x") = some (Ascii "a.test", Ascii "m/x") := by
      decide
    have registry_is : Located (NameOf (Ascii "a.test") (Ascii "x")) =
        some (Ascii "a.test", Ascii "x") := by decide
    simp only [mirror_is, Option.some.injEq] at first_located
    simp only [registry_is, Option.some.injEq] at located
    have first_host : first.host.val = Ascii "a.test" := (congrArg Prod.fst first_located).symm
    have first_path : first.path.val = Ascii "m/x" := (congrArg Prod.snd first_located).symm
    have primary_host : primary.host.val = Ascii "a.test" := (congrArg Prod.fst located).symm
    have primary_path : primary.path.val = Ascii "x" := (congrArg Prod.snd located).symm
    have folded : Folded (Ascii "a.test") = Ascii "a.test" := by decide
    rw [folded] at creds
    have first_creds : first.creds = Creds.CommandLine :=
      (creds first (by simp [es_is])).mpr first_host
    have primary_creds : primary.creds = Creds.CommandLine :=
      (creds primary (by simp [es_is])).mpr primary_host
    refine ⟨es, is_ok, ?_, ?_⟩ <;> rw [es_is] <;>
      simp [Endpoint.Where, first_host, first_path, primary_host, primary_path, first_creds,
        primary_creds]

/-- **`WorkedExamples`**: each of the cases of Spec.lean, from the theorems above. -/
theorem worked_examples : WorkedExamples :=
  ⟨the_hub_with_a_mirror, a_push_is_asked_at_the_hub_only, a_prefix_does_not_govern_a_longer_host,
    a_prefix_does_not_govern_a_port, a_prefix_that_names_the_port_governs_it,
    a_block_moved_to_another_host_has_stored_credentials,
    a_mirror_on_the_host_named_has_the_credentials_of_the_command_line⟩

end EndpointCore
