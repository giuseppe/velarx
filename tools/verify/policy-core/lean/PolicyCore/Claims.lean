-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean, each from the answers of the
-- functions proved in the files before it (Select.lean, Identity.lean, Decide.lean,
-- Precheck.lean).  The proofs of the modes and of `precheck` are about what the answers say
-- of the requirements, never about loops.
--
-- Why it is needed: Theorems.lean asks Lean to check that each theorem here has the type of
-- the claim of the same name in Spec.lean.
--
-- Read before this file: Spec.lean.
--
-- Notation: as in Spec.lean; `WP.spec_mono h f` is "use the answer `h` about a function, and
-- show that what it says is enough for what we want to say".
import PolicyCore.Precheck
import PolicyCore.Pick
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- `select` returns on every input: it follows from what it answers. -/
theorem select_never_fails : SelectNeverFails :=
  fun scopes image => WP.spec_mono (select_is scopes image) (fun _ _ => trivial)

/-- `select` answers the most specific scope: the answer proved of its loop (Select.lean). -/
theorem select_chooses_the_most_specific_scope : SelectChoosesTheMostSpecificScope :=
  fun scopes image => select_is scopes image

/-- `same` is equality of bytes (Scope.lean). -/
theorem same_is_equality_of_bytes : SameIsEqualityOfBytes :=
  fun a b => same_is_equal a b

/-- The same reference is reflexive, symmetric and transitive, as each field is equal to itself,
and equality is. -/
theorem same_ref_is_an_equivalence : SameRefIsAnEquivalence :=
  ⟨fun _ => ⟨rfl, rfl, rfl⟩,
   fun same => ⟨same.1.symm, same.2.1.symm, same.2.2.symm⟩,
   fun first second => ⟨first.1.trans second.1, first.2.1.trans second.2.1,
     first.2.2.trans second.2.2⟩⟩

/-- `identity_matches` says what each rule says (Identity.lean). -/
theorem identity_matches_is_the_rule : IdentityMatchesIsTheRule :=
  fun rule intended signed => identity_matches_is rule intended signed

/-- The rule `Exact`, with the vocabulary opened, is the same claim. -/
theorem exact_accepts_exactly_the_same_reference : ExactAcceptsExactlyTheSameReference :=
  fun intended signed => identity_matches_is Rule.Exact intended signed

/-- `precheck` returns on every input: it follows from what it answers. -/
theorem precheck_never_fails : PrecheckNeverFails :=
  fun mode items => WP.spec_mono (precheck_is mode items) (fun _ _ => trivial)

/-- `precheck` accepts exactly when nothing needs a signature (Precheck.lean). -/
theorem precheck_accepts_when_nothing_needs_a_signature :
    PrecheckAcceptsWhenNothingNeedsASignature :=
  fun mode items => WP.spec_mono (precheck_is mode items) (fun _ answer => answer.1)

/-- `precheck` leaves the decision to the signatures exactly when they can decide
(Precheck.lean). -/
theorem precheck_leaves_the_decision_to_the_signatures :
    PrecheckLeavesTheDecisionToTheSignatures :=
  fun mode items => WP.spec_mono (precheck_is mode items) (fun _ answer => answer.2)

/-- `decide` returns on every input: it follows from what it answers. -/
theorem decide_never_fails : DecideNeverFails :=
  fun mode intended items =>
    WP.spec_mono (decide_is mode intended items) (fun _ _ => trivial)

/-- `decide` accepts exactly when the requirements are acceptable (Decide.lean). -/
theorem decide_accepts_exactly_the_acceptable : DecideAcceptsExactlyTheAcceptable :=
  fun mode intended items => decide_is mode intended items

/-- What an acceptance gives, for every mode: the list is not empty, no requirement refuses by its
kind, and every signature requirement has a fact that satisfies it. -/
theorem accepted_is_acceptable (mode : Mode) (intended : Ref) (items : Slice Item) :
    velarx_policy_core.decide mode intended items ⦃ answer =>
      ∀ used signed, answer = Outcome.Accept used signed →
        Acceptable mode intended items.val ⦄ :=
  WP.spec_mono (decide_is mode intended items) fun _ iff used signed accepted =>
    iff.mp ⟨used, signed, accepted⟩

/-- A requirement that does not refuse by its kind, and that is a signature requirement, has a fact
that satisfies it, when the requirements are acceptable. -/
theorem signature_requirements_hold {mode : Mode} {intended : Ref} {items : List Item}
    (acceptable : Acceptable mode intended items) :
    ∀ item ∈ items, ∀ rule facts, item = Item.Signed rule facts →
      ∃ fact ∈ facts.val, FactSatisfies rule intended fact := by
  intro item listed rule facts is_signed
  subst is_signed
  exact (acceptable.2.1 _ listed).2

/-- In a mode of a pull (not `SignaturesOnly`), a requirement that does not refuse by its kind is
not a `reject`, a `signedBaseLayer` or an unusable requirement. -/
theorem not_a_refusing_kind {mode : Mode} (pull : mode ≠ Mode.SignaturesOnly) {item : Item}
    (not_refused : ¬ RefusesByKind mode item) :
    item ≠ Item.Reject ∧ item ≠ Item.Unimplemented ∧ item ≠ Item.Unusable :=
  ⟨fun is_reject => not_refused (by subst is_reject; exact pull),
   fun is_unimplemented => not_refused (by subst is_unimplemented; exact pull),
   fun is_unusable => not_refused (by subst is_unusable; trivial)⟩

/-- The security rule: an acceptance in `Mode.Whole` gives `Acceptable`, which is read out: no
requirement that refuses by its kind (for this mode, a `reject`, a `signedBaseLayer` or an
unusable one), and a satisfying fact for each signature requirement. -/
theorem whole_mode_accept_means_every_requirement_holds :
    WholeModeAcceptMeansEveryRequirementHolds := by
  intro intended items
  refine WP.spec_mono (accepted_is_acceptable Mode.Whole intended items) ?_
  intro answer accepted used signed is_accept
  have acceptable := accepted used signed is_accept
  refine ⟨acceptable.1, fun item listed => ?_, signature_requirements_hold acceptable⟩
  exact not_a_refusing_kind (mode := Mode.Whole) (fun same => nomatch same)
    (acceptable.2.1 item listed).1

/-- The same for `Mode.SignaturesOnly`, where `reject` and `signedBaseLayer` do not refuse: only
the unusable one is excluded. -/
theorem signatures_only_mode_accept_means_every_signature_requirement_holds :
    SignaturesOnlyModeAcceptMeansEverySignatureRequirementHolds := by
  intro intended items
  refine WP.spec_mono (accepted_is_acceptable Mode.SignaturesOnly intended items) ?_
  intro answer accepted used signed is_accept
  have acceptable := accepted used signed is_accept
  refine ⟨acceptable.1, fun item listed is_unusable => ?_, signature_requirements_hold acceptable⟩
  subst is_unusable
  exact (acceptable.2.1 _ listed).1 trivial

/-- The same as `Mode.Whole`, and the third part of `Acceptable` (a signature requirement is there)
read out. -/
theorem must_be_signed_mode_accept_means_a_signature_satisfied_a_requirement :
    MustBeSignedModeAcceptMeansASignatureSatisfiedARequirement := by
  intro intended items
  refine WP.spec_mono (accepted_is_acceptable Mode.MustBeSigned intended items) ?_
  intro answer accepted used signed is_accept
  have acceptable := accepted used signed is_accept
  refine ⟨acceptable.1, fun item listed => ?_, signature_requirements_hold acceptable, ?_⟩
  · exact not_a_refusing_kind (mode := Mode.MustBeSigned) (fun same => nomatch same)
      (acceptable.2.1 item listed).1
  · obtain ⟨item, listed, is_signature⟩ := acceptable.2.2 rfl
    cases item with
    | Signed rule facts => exact ⟨_, listed, rule, facts, rfl⟩
    | AcceptAnything => exact is_signature.elim
    | Reject => exact is_signature.elim
    | Unimplemented => exact is_signature.elim
    | Unusable => exact is_signature.elim

/-- What `precheck` accepts is acceptable: no requirement asks for a signature, so each is
satisfied whatever its facts are (there are none to ask). -/
theorem precheck_accept_is_kept_by_decide : PrecheckAcceptIsKeptByDecide := by
  intro mode items
  refine WP.spec_mono (precheck_is mode items) ?_
  intro answer described is_accept intended
  obtain ⟨nonempty, no_kind, no_signature, not_must⟩ := described.1.mp is_accept
  refine WP.spec_mono (decide_is mode intended items) fun outcome iff => iff.mpr ?_
  refine ⟨nonempty, fun item listed => ⟨no_kind item listed, ?_⟩,
    fun is_must => (not_must is_must).elim⟩
  -- no requirement asks for a signature, so each is satisfied as far as signatures go
  have not_signed := no_signature item listed
  cases item with
  | Signed rule facts => exact (not_signed trivial).elim
  | AcceptAnything => trivial
  | Reject => trivial
  | Unimplemented => trivial
  | Unusable => trivial

/-- If `decide` accepted, the requirements would be acceptable, and then `precheck` would not have
refused: one of its two other answers would hold. -/
theorem precheck_refusal_is_kept_by_decide : PrecheckRefusalIsKeptByDecide := by
  intro mode items
  refine WP.spec_mono (precheck_is mode items) ?_
  intro answer described refused intended
  refine WP.spec_mono (decide_is mode intended items) fun outcome iff => ?_
  cases outcome with
  | Refuse at_ why => exact ⟨at_, why, rfl⟩
  | Accept used signed =>
    -- an acceptance would make the requirements acceptable, so `precheck` would not refuse
    obtain ⟨nonempty, each, must_have⟩ := iff.mp ⟨used, signed, rfl⟩
    have no_kind : ∀ item ∈ items.val, ¬ RefusesByKind mode item := fun item listed =>
      (each item listed).1
    obtain ⟨at_, why, is_refuse⟩ := refused
    by_cases some_signature : ∃ item ∈ items.val, IsSignatureRequirement item
    · have := described.2.mpr ⟨nonempty, no_kind, some_signature⟩
      rw [this] at is_refuse
      cases is_refuse
    · have := described.1.mpr ⟨nonempty, no_kind,
        fun item listed is_signature => some_signature ⟨item, listed, is_signature⟩,
        fun is_must => some_signature (must_have is_must)⟩
      rw [this] at is_refuse
      cases is_refuse

/-- `pick` returns on every input: it follows from what it answers. -/
theorem pick_never_fails : PickNeverFails :=
  fun records => WP.spec_mono (pick_is records) (fun _ _ => trivial)

/-- `pick` names what the latest records say: the answer proved of its loop (Pick.lean). -/
theorem pick_names_what_the_latest_records_say : PickNamesWhatTheLatestRecordsSay :=
  fun records => pick_is records

/-- A record strictly later than the others is the one named (Pick.lean). -/
theorem pick_later_record_wins : PickLaterRecordWins :=
  fun records i r r_at later => WP.spec_mono (pick_is records)
    (fun answer named => later_record_is_named records.val answer named i r r_at later)

/-- Reordering the records does not change what is named (Pick.lean). -/
theorem pick_does_not_depend_on_the_order : PickDoesNotDependOnTheOrder :=
  fun records reordered order => WP.spec_mono (pick_is records) (fun answer named =>
    WP.spec_mono (pick_is reordered) (fun again named_again =>
      order_does_not_matter records.val reordered.val order answer again named named_again))

end PolicyCore
