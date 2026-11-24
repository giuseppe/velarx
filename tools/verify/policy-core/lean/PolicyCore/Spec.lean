-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/policy-core, the decision of the signature
-- policy of an image, in words and in statements, with no proof.  This file is what a reviewer
-- reads; Lean checks the rest (the proofs are in Bytes.lean, Scope.lean, Joined.lean,
-- Wildcard.lean, Select.lean, Identity.lean, Decide.lean, Precheck.lean, Pick.lean and
-- Claims.lean).
--
-- Why it is needed: a proof is worth what its statement says.  Each statement here is a
-- `def ... : Prop`: a claim, which `Theorems.lean` asks Lean to prove.  Each has a comment of what
-- it claims and of what it does NOT.  The small definitions before the claims are their
-- vocabulary: what "covers", "the most specific scope", "the same reference", "a signature that
-- satisfies a requirement" and "the requirements accept" mean, written as plain statements about
-- lists of bytes, not as the code.  The claims are the rules src/rules.rs checks on small worlds
-- (S1-S2 for `select`, D1 and the security claim for `decide`, P6 for `precheck`, K1-K2 and the
-- order check for `pick`), here for EVERY
-- input.
--
-- Total correctness: each claim says that the function RETURNS (no panic, no index outside a
-- slice, no overflow, every loop ends) on EVERY input, with no condition on the input, and that
-- its answer is as stated.  This is stronger than "if it returns": a claim of the form
-- `f x ⦃ r => P r ⦄` fails if `f x` can panic.
--
-- Not claimed (and not proved):
--   - what `velarx-signature` does around the decision: reading policy.json, loading the keys,
--     checking a signature (that a `Fact::Verified` was really verified by a key of the
--     requirement is the business of the shell), turning the answer into text;
--   - which signature `decide` keeps for a requirement (`used`: the newest, the first of those
--     of one time) and the time it answers (`signed`: the oldest of them); the claims here say
--     when `decide` accepts, not what it reports with the acceptance (the walk in
--     src/rules.rs checks `signed` as the oldest of the newest fact of each requirement; no
--     claim here); and, for `pick`, that the time of a record is true, only what is done with it;
--   - which requirement or which reason a refusal names (`at`, `why`), only that it refuses;
--   - that the shell gives `precheck` and `decide` the items of the scope `select` chose (or of
--     the default of the policy);
--   - that the shell turns the policy file into `Item`s and `Rule`s faithfully (a missing
--     `signedIdentity` is `RepoDigestOrExact`, a bad rule is `Nothing`, a bad key makes the
--     requirement `Unusable`), that it does the `remapIdentity` prefix replacement and builds
--     the reference of `Remapped`, and that it computes `digest_matches` correctly;
--   - the input side of the byte conversions: that names, tags and digests reach the functions
--     here as `velarx-signature` normalizes them;
--   - that two runs answer the same: `decide` is a function in the translation (it reads no
--     clock and iterates no hash table), which rests on the translation, not on a claim here.
--
-- Trusted: Charon and Aeneas (../../pins) and the models of the standard library Aeneas itself
-- has (`Vec` and slice indexing, `push`, the integer operations, `Slice::is_empty`,
-- `Option::is_some`); no model is written by hand.
--
-- Read before this file: lib.rs of crates/policy-core, and rules.rs next to it.
--
-- Index.  The claims, in the order below:
--
--   The scope that applies (`select`)
--     SelectNeverFails                    it returns, on every input
--     SelectChoosesTheMostSpecificScope   the scope it answers applies and none is more specific
--   References and the rules of identity (`same`, `identity_matches`)
--     SameIsEqualityOfBytes               `same` is equality of bytes (so an equivalence)
--     SameRefIsAnEquivalence              "the same reference" is an equivalence
--     IdentityMatchesIsTheRule            `identity_matches` says what each `signedIdentity` says
--     ExactAcceptsExactlyTheSameReference the rule `Exact`: the same reference, and no other
--   Before any signature is read (`precheck`)
--     PrecheckNeverFails                  it returns, on every input
--     PrecheckAcceptsWhenNothingNeedsASignature
--                                         exactly when no requirement needs one
--     PrecheckLeavesTheDecisionToTheSignatures
--                                         exactly when the signatures can still decide
--   What a tag names (`pick`)
--     PickNeverFails                      it returns, on every input
--     PickNamesWhatTheLatestRecordsSay    nothing, one record, or a tie: by the latest time only
--     PickLaterRecordWins                 a record strictly later than the others is named
--     PickDoesNotDependOnTheOrder         any reordering names the same digest, or a tie again
--   Whether the signatures satisfy the requirements (`decide`)
--     DecideNeverFails                    it returns, on every input
--     DecideAcceptsExactlyTheAcceptable   it accepts exactly when the requirements are acceptable
--     WholeModeAcceptMeansEveryRequirementHolds
--                                         THE SECURITY RULE
--     SignaturesOnlyModeAcceptMeansEverySignatureRequirementHolds
--                                         what an acceptance means for the create and the start
--     MustBeSignedModeAcceptMeansASignatureSatisfiedARequirement
--                                         what it means when a signature is required
--     PrecheckAcceptIsKeptByDecide        what `precheck` accepts, `decide` accepts
--     PrecheckRefusalIsKeptByDecide       what `precheck` refuses, `decide` refuses
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic,
--     it does not loop for ever) and the result `r` satisfies `P r`.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and",
--     `∨` is "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `≠` is "is not",
--     `∈` is "is an element of"; `[]` is the empty list, `a :: l` the list `l` with `a` in front,
--     `l ++ m` the list `l` followed by `m`.
--   - `v.val` is the list inside a vector or a slice; `l[k]? = some x` is "the element `k` of
--     the list is `x`"; `l <+: m` is "`l` is the beginning of `m`", `l <:+ m` is "`l` is the end
--     of `m`"; `o.map f` applies `f` inside an `Option`.
--   - `Outcome.Accept used signed` and `Outcome.Refuse at why` are the two answers of `decide`;
--     `Pre.Accept`, `Pre.NeedsSignatures` and `Pre.Refuse at why` the three of `precheck`.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_policy_core

namespace PolicyCore

/-! ## Names, scopes and the scope that applies -/

/-- The byte `/`. -/
def slash : Std.U8 := 47#u8
/-- The byte `:`. -/
def colon : Std.U8 := 58#u8
/-- The byte `@`. -/
def at_sign : Std.U8 := 64#u8
/-- The byte `*`. -/
def star : Std.U8 := 42#u8
/-- The byte `.`. -/
def dot : Std.U8 := 46#u8

/-- `scope` is a repository, a namespace or a host (with its port) of `full`: the beginning of
it, up to its end or up to a `/`.  `x/a` is not one of `x/ab`. -/
def CoversName (scope full : List Std.U8) : Prop :=
  scope <+: full ∧ (scope = full ∨ full[scope.length]? = some slash)

/-- The host of a name, without its port: the bytes before the first `/` or `:`. -/
def host (full : List Std.U8) : List Std.U8 :=
  full.takeWhile (fun c => c != slash && c != colon)

/-- `scope` is `*.suffix` and the host of the name ends with `.suffix`. -/
def IsWildcardOf (scope full : List Std.U8) : Prop :=
  ∃ dotted, scope = star :: dotted ∧ dotted.head? = some dot ∧ dotted <:+ host full

/-- `scope` is the exact reference of `image`: its name, `@` and its digest, or, when it has
no digest, its name, `:` and its tag.  An image with neither has no exact reference. -/
def IsReferenceOf (scope : List Std.U8) (image : Ref) : Prop :=
  match image.digest, image.tag with
  | some digest, _ => scope = image.name.val ++ at_sign :: digest.val
  | none, some tag => scope = image.name.val ++ colon :: tag.val
  | none, none => False

/-- How specifically `scope` applies to `image` (its class): 4 for its exact reference, 3 for
its name or a namespace or a host of it, 2 for a wildcard of its host, 1 for the scope of the
transport (the empty one), 0 for none.  It is the first of these that holds.  A scope
"applies" when its class is not 0. -/
noncomputable def classOf (scope : List Std.U8) (image : Ref) : Nat := by
  classical exact
    if IsReferenceOf scope image then 4
    else if scope ≠ [] ∧ CoversName scope image.name.val then 3
    else if IsWildcardOf scope image.name.val then 2
    else if scope = [] then 1
    else 0

/-- The scope `a` is more specific than the scope `b` for `image`: its class is higher, or the
classes are the same and it is longer. -/
def MoreSpecific (image : Ref) (a b : alloc.vec.Vec Std.U8) : Prop :=
  classOf b.val image < classOf a.val image ∨
    (classOf b.val image = classOf a.val image ∧ b.val.length < a.val.length)

/-- What `select` answers for the list of scopes and the image.  When it is `none`, no scope
applies.  When it is the position `j`: the scope there applies, no scope of the list is more
specific than it, and every scope before position `j` is less specific than it, so `j` is the
first of the most specific. -/
def Chosen (scopes : List (alloc.vec.Vec Std.U8)) (image : Ref) : Option Std.Usize → Prop
  | none => ∀ t ∈ scopes, classOf t.val image = 0
  | some j => ∃ s, scopes[j.val]? = some s ∧ 0 < classOf s.val image ∧
      (∀ t ∈ scopes, ¬ MoreSpecific image t s) ∧
      (∀ k < j.val, ∀ t, scopes[k]? = some t → MoreSpecific image s t)

/-- **`select` returns on every input.**  No panic, no index outside a slice, no overflow, the
loop ends, whatever the scopes and the image are (even a name that has no `/`, a scope longer than
the name, empty bytes).

Not said: which scope it answers (the next claim). -/
def SelectNeverFails : Prop :=
  ∀ (scopes : Slice (alloc.vec.Vec Std.U8)) (image : Ref),
    select scopes image ⦃ _ => True ⦄

/-- **`select` answers the most specific scope that applies.**  It returns, and its answer is
`none` when no scope of the list applies to the image, and otherwise the position of a scope
that applies and than which no scope of the list is more specific.  The order is the one of
containers/image: the exact reference of the image (its digest, else its tag), then its name
and each namespace or host of it, longest first (a scope covers whole components of a name
only, `x/a` is not one of `x/ab`), then a wildcard `*.suffix` of its host, longest first, then
the scope of the transport
(the empty one).  Of equally specific scopes the first of the list is answered.

Observation, not proved: scopes that are equally specific (the same class and the same
length) are the same bytes, so only a list that repeats a scope has a tie.

Not said: that the scope is the one of containers/image for a name that `velarx-signature` has not
normalized (the claim is about the bytes `select` is given); what the policy says for the scope
(the default of the policy when none applies is the business of the shell). -/
def SelectChoosesTheMostSpecificScope : Prop :=
  ∀ (scopes : Slice (alloc.vec.Vec Std.U8)) (image : Ref),
    select scopes image ⦃ answer => Chosen scopes.val image answer ⦄

/-! ## References and the rules of identity -/

/-- The reference has a tag or a digest. -/
def HasTagOrDigest (r : Ref) : Prop :=
  r.tag.isSome = true ∨ r.digest.isSome = true

/-- The two references are the same: the same name, the same tag (or none) and the same digest
(or none), byte for byte. -/
def SameRef (a b : Ref) : Prop :=
  a.name.val = b.name.val ∧ a.tag.map (·.val) = b.tag.map (·.val) ∧
    a.digest.map (·.val) = b.digest.map (·.val)

/-- What `repo_digest_or_exact` accepts.  Asked by tag: the same reference.  Asked by digest
only: the same name, and the signed reference has a tag or a digest.  Asked by neither:
nothing. -/
def RepoDigestOrExactAccepts (intended signed : Ref) : Prop :=
  HasTagOrDigest signed ∧
    (if intended.tag.isSome = true then SameRef intended signed
     else intended.digest.isSome = true ∧ intended.name.val = signed.name.val)

/-- Which signed references a signature requirement with this rule accepts, for the image asked
by `intended`: the `signedIdentity` of the requirement, in words.
- `Exact`: the same reference as the one asked, and one of them has a tag or a digest;
- `RepoDigestOrExact`: `RepoDigestOrExactAccepts`;
- `Repository`: the same name as the one asked, whatever the tag and the digest;
- `ExactReference r`: the same reference as `r` (which has a tag or a digest), whatever the one
  asked;
- `ExactRepository name`: this name, whatever the tag, the digest and the one asked;
- `Remapped r`: as `RepoDigestOrExact`, for `r` in place of the one asked;
- `Nothing`: none. -/
def RuleAccepts : Rule → (intended signed : Ref) → Prop
  | Rule.Exact, intended, signed =>
      HasTagOrDigest intended ∧ HasTagOrDigest signed ∧ SameRef intended signed
  | Rule.RepoDigestOrExact, intended, signed => RepoDigestOrExactAccepts intended signed
  | Rule.Repository, intended, signed => intended.name.val = signed.name.val
  | Rule.ExactReference r, _, signed =>
      HasTagOrDigest r ∧ HasTagOrDigest signed ∧ SameRef r signed
  | Rule.ExactRepository repository, _, signed => repository.val = signed.name.val
  | Rule.Remapped r, _, signed => RepoDigestOrExactAccepts r signed
  | Rule.Nothing, _, _ => False

/-- **`same` is equality of bytes.**  It returns on every input, and answers `true` exactly when
the two slices hold the same bytes (so it is reflexive, symmetric and transitive: an
equivalence).

Not said: anything of the time it takes. -/
def SameIsEqualityOfBytes : Prop :=
  ∀ a b : Slice Std.U8, same a b ⦃ r => r = true ↔ a.val = b.val ⦄

/-- **"The same reference" is an equivalence:** reflexive, symmetric and transitive.  This is a
fact about the definition `SameRef` above, not about the Rust: that the rules of identity use
it is `IdentityMatchesIsTheRule`. -/
def SameRefIsAnEquivalence : Prop :=
  Equivalence SameRef

/-- **`identity_matches` says what each rule says.**  It returns on every input, and answers
`true` exactly when `RuleAccepts` holds: this is what makes the vocabulary above, and not the
code, the meaning of the rules in the claims that follow.

Not said: that these rules are the ones containers/image has for `signedIdentity` (they are the
ones of the tests in src/rules.rs, the same words). -/
def IdentityMatchesIsTheRule : Prop :=
  ∀ (rule : Rule) (intended signed : Ref),
    identity_matches rule intended signed ⦃ r => r = true ↔ RuleAccepts rule intended signed ⦄

/-- **The rule `Exact` accepts the same reference as the one asked, and no other.**  A signature
for another name, another tag or another digest, or for a reference with the tag where the image
was asked by digest, does not satisfy a requirement with this rule; nor does anything when
neither the image nor the signature has a tag or a digest.

This is `IdentityMatchesIsTheRule` for the rule `Exact`, with the vocabulary opened. -/
def ExactAcceptsExactlyTheSameReference : Prop :=
  ∀ intended signed : Ref,
    identity_matches Rule.Exact intended signed ⦃ r =>
      r = true ↔ HasTagOrDigest intended ∧ HasTagOrDigest signed ∧ SameRef intended signed ⦄

/-! ## What the requirements ask -/

/-- The fact satisfies a signature requirement of `rule` for the image asked by `intended`: it
is a signature that was verified, it names the manifest, and the reference it signed is one that
the rule accepts. -/
def FactSatisfies (rule : Rule) (intended : Ref) : Fact → Prop
  | Fact.Unverified => False
  | Fact.Verified digest_matches signed _ =>
      digest_matches = true ∧ RuleAccepts rule intended signed

/-- The requirement asks for a signature (it is not `accept anything`, `reject`,
`signedBaseLayer` or an unusable requirement). -/
def IsSignatureRequirement : Item → Prop
  | Item.Signed _ _ => True
  | _ => False

/-- The requirement refuses by its kind alone, whatever the signatures are: an unusable one
always; `reject` and `signedBaseLayer` (the `Unimplemented` item) in every mode but
`SignaturesOnly`, which is for the create and the start of an image of the store. -/
def RefusesByKind (mode : Mode) : Item → Prop
  | Item.Unusable => True
  | Item.Reject => mode ≠ Mode.SignaturesOnly
  | Item.Unimplemented => mode ≠ Mode.SignaturesOnly
  | _ => False

/-- The requirement is satisfied as far as signatures go: a signature requirement has, among its
facts, one that satisfies it; a requirement of another kind asks for no signature. -/
def SignaturesSatisfy (intended : Ref) : Item → Prop
  | Item.Signed rule facts => ∃ fact ∈ facts.val, FactSatisfies rule intended fact
  | _ => True

/-- The requirements are acceptable for the image asked by `intended` in this mode: there is
at least one; none refuses by its kind; every signature requirement is satisfied by one of its
facts; and, in `MustBeSigned` mode, at least one requirement asks for a signature. -/
def Acceptable (mode : Mode) (intended : Ref) (items : List Item) : Prop :=
  items ≠ [] ∧
  (∀ item ∈ items, ¬ RefusesByKind mode item ∧ SignaturesSatisfy intended item) ∧
  (mode = Mode.MustBeSigned → ∃ item ∈ items, IsSignatureRequirement item)

/-! ## Before any signature is read -/

/-- **`precheck` returns on every input.**  Whatever the mode and the requirements, with or
without facts, even an empty list. -/
def PrecheckNeverFails : Prop :=
  ∀ (mode : Mode) (items : Slice Item), precheck mode items ⦃ _ => True ⦄

/-- **`precheck` accepts, whatever the signatures are, exactly when nothing needs one.**  It
returns, and answers `Pre.Accept` exactly when the list is not empty, no requirement refuses by
its kind, no requirement asks for a signature, and the mode is not `MustBeSigned` (that mode
asks for one).

Not said: what it answers otherwise (`NeedsSignatures` or `Refuse`: the next claim and
`PrecheckRefusalIsKeptByDecide`); which requirement or reason it names when it refuses. -/
def PrecheckAcceptsWhenNothingNeedsASignature : Prop :=
  ∀ (mode : Mode) (items : Slice Item),
    precheck mode items ⦃ answer =>
      answer = Pre.Accept ↔ items.val ≠ [] ∧ (∀ item ∈ items.val, ¬ RefusesByKind mode item) ∧
        (∀ item ∈ items.val, ¬ IsSignatureRequirement item) ∧ mode ≠ Mode.MustBeSigned ⦄

/-- **`precheck` leaves the decision to the signatures exactly when they can still decide.**  It
returns, and answers `Pre.NeedsSignatures` exactly when the list is not empty, no requirement
refuses by its kind and some requirement asks for a signature (in any mode).

Not said: whether the signatures that are found satisfy the requirements (`decide`). -/
def PrecheckLeavesTheDecisionToTheSignatures : Prop :=
  ∀ (mode : Mode) (items : Slice Item),
    precheck mode items ⦃ answer =>
      answer = Pre.NeedsSignatures ↔ items.val ≠ [] ∧
        (∀ item ∈ items.val, ¬ RefusesByKind mode item) ∧
        ∃ item ∈ items.val, IsSignatureRequirement item ⦄

/-! ## Whether the signatures satisfy the requirements -/

/-- **`decide` returns on every input.**  Whatever the mode, the image and the requirements
(with any number of facts, any times, any references), including an empty list. -/
def DecideNeverFails : Prop :=
  ∀ (mode : Mode) (intended : Ref) (items : Slice Item),
    velarx_policy_core.decide mode intended items ⦃ _ => True ⦄

/-- **`decide` accepts exactly when the requirements are `Acceptable`.**  It returns, and its
answer is `Outcome.Accept ...` exactly when the list is not empty, no requirement refuses by its
kind, every signature requirement has a fact that is verified, names the manifest and whose
reference its rule accepts, and, in `MustBeSigned` mode, one requirement asks for a signature.
Otherwise it answers `Outcome.Refuse ...`.

This is the whole of when `decide` accepts, in both directions: a refusal is never made when
the requirements are acceptable, and an acceptance is never made when they are not.

Not said: which signature is `used` for each requirement and the time `signed` (see the top of
this file); that a fact marked `Verified` was verified (the shell makes the facts). -/
def DecideAcceptsExactlyTheAcceptable : Prop :=
  ∀ (mode : Mode) (intended : Ref) (items : Slice Item),
    velarx_policy_core.decide mode intended items ⦃ answer =>
      (∃ used signed, answer = Outcome.Accept used signed) ↔
        Acceptable mode intended items.val ⦄

/-- **THE SECURITY RULE: when `decide` accepts in the whole-decision mode, every signature
requirement has a signature that satisfies it.**  The mode is `Mode.Whole`: a pull, and
`signature=check`.  When `decide` accepts:
- the requirement list is not empty;
- it holds no `reject`, no `signedBaseLayer` and no unusable requirement (`accept anything` and
  signature requirements are the only kinds left);
- for every signature requirement there is a fact, among the facts found for it, that was
  verified, names the manifest, and whose signed reference the rule of that requirement accepts
  for the image that was asked (`FactSatisfies`, which is what `identity_matches` answers:
  `IdentityMatchesIsTheRule`).

Not said: that a signature was really made by the key (the shell verifies it, and says so in the
`Fact`); that the facts are complete (a signature the shell did not find is not a fact); which of
the facts that satisfy a requirement is `used`. -/
def WholeModeAcceptMeansEveryRequirementHolds : Prop :=
  ∀ (intended : Ref) (items : Slice Item),
    velarx_policy_core.decide Mode.Whole intended items ⦃ answer =>
      ∀ used signed, answer = Outcome.Accept used signed →
        items.val ≠ [] ∧
        (∀ item ∈ items.val,
          item ≠ Item.Reject ∧ item ≠ Item.Unimplemented ∧ item ≠ Item.Unusable) ∧
        ∀ item ∈ items.val, ∀ rule facts, item = Item.Signed rule facts →
          ∃ fact ∈ facts.val, FactSatisfies rule intended fact ⦄

/-- **What an acceptance means in the mode for the create and the start of an image of the
store (`Mode.SignaturesOnly`).**  `reject` and `signedBaseLayer` are for pulls, so they are not
looked at: they do not refuse.  When `decide` accepts, the list is not empty, holds no unusable
requirement, and every signature requirement has a fact that satisfies it, as in the security
rule.

Not said: that there is no `reject` or `signedBaseLayer` in the list.  There may be: a list
holding only a `reject` or a `signedBaseLayer` IS accepted in this mode, because those are judged
at the pull, not here; that any requirement asks for a signature (a list of `accept anything`
alone is
accepted, as in `Mode.Whole`). -/
def SignaturesOnlyModeAcceptMeansEverySignatureRequirementHolds : Prop :=
  ∀ (intended : Ref) (items : Slice Item),
    velarx_policy_core.decide Mode.SignaturesOnly intended items ⦃ answer =>
      ∀ used signed, answer = Outcome.Accept used signed →
        items.val ≠ [] ∧ (∀ item ∈ items.val, item ≠ Item.Unusable) ∧
        ∀ item ∈ items.val, ∀ rule facts, item = Item.Signed rule facts →
          ∃ fact ∈ facts.val, FactSatisfies rule intended fact ⦄

/-- **What an acceptance means when a signature is required (`Mode.MustBeSigned`).**  When
`decide` accepts, everything the security rule says holds, and in addition some requirement of
the list asks for a signature (so, by the rest, some fact satisfies it): a list of `accept
anything` alone is refused.

Not said: that every requirement asks for one (`accept anything` is accepted next to a signature
requirement). -/
def MustBeSignedModeAcceptMeansASignatureSatisfiedARequirement : Prop :=
  ∀ (intended : Ref) (items : Slice Item),
    velarx_policy_core.decide Mode.MustBeSigned intended items ⦃ answer =>
      ∀ used signed, answer = Outcome.Accept used signed →
        items.val ≠ [] ∧
        (∀ item ∈ items.val,
          item ≠ Item.Reject ∧ item ≠ Item.Unimplemented ∧ item ≠ Item.Unusable) ∧
        (∀ item ∈ items.val, ∀ rule facts, item = Item.Signed rule facts →
          ∃ fact ∈ facts.val, FactSatisfies rule intended fact) ∧
        ∃ item ∈ items.val, ∃ rule facts, item = Item.Signed rule facts ⦄

/-- **What `precheck` accepts, `decide` accepts, whatever the facts are.**  When `precheck`
answers `Pre.Accept` for a list of requirements, `decide`, in the same mode and for any image,
answers `Outcome.Accept ...`: it does not refuse for a missing signature (no requirement of
that list asks for one) nor for anything else.

Not said: the converse (a list that `precheck` leaves to the signatures may be accepted or
refused by `decide`). -/
def PrecheckAcceptIsKeptByDecide : Prop :=
  ∀ (mode : Mode) (items : Slice Item),
    precheck mode items ⦃ answer =>
      answer = Pre.Accept → ∀ intended : Ref,
        velarx_policy_core.decide mode intended items ⦃ outcome =>
          ∃ used signed, outcome = Outcome.Accept used signed ⦄ ⦄

/-- **What `precheck` refuses, `decide` refuses, whatever the facts are.**  When `precheck`
answers `Pre.Refuse ...`, `decide`, in the same mode and for any image, answers
`Outcome.Refuse ...`: no signature turns the refusal into an acceptance.

Not said: that `decide` names the same requirement or reason (it may name an earlier requirement
that has no signature). -/
def PrecheckRefusalIsKeptByDecide : Prop :=
  ∀ (mode : Mode) (items : Slice Item),
    precheck mode items ⦃ answer =>
      (∃ at_ why, answer = Pre.Refuse at_ why) → ∀ intended : Ref,
        velarx_policy_core.decide mode intended items ⦃ outcome =>
          ∃ at_ why, outcome = Outcome.Refuse at_ why ⦄ ⦄

/-! ## What a tag names (`pick`) -/

/-- `r` is the record at position `i` of `records` and it is the first of the latest time: no
record has a later time, and every record before position `i` has an earlier one. -/
def FirstOfLatest (records : List Signed) (i : Nat) (r : Signed) : Prop :=
  records[i]? = some r ∧ (∀ s ∈ records, s.time.val ≤ r.time.val) ∧
    ∀ k < i, ∀ s, records[k]? = some s → s.time.val < r.time.val

/-- What `pick` answers for the list of accepted records.  `Nothing`: the list is empty.
`One i`: record `i` is the first of the latest time, and every record of that time names its
digest.  `Tie i j`: record `i` is the first of the latest time, and record `j` is of that time
and names another digest. -/
def Named (records : List Signed) : Picked → Prop
  | Picked.Nothing => records = []
  | Picked.One i => ∃ r, FirstOfLatest records i r ∧
      ∀ s ∈ records, s.time.val = r.time.val → s.digest.val = r.digest.val
  | Picked.Tie i j => ∃ r s, FirstOfLatest records i r ∧ records[j.val]? = some s ∧
      s.time.val = r.time.val ∧ s.digest.val ≠ r.digest.val

/-- **`pick` returns on every input.**  No panic, no index outside the list, no overflow, the loop
ends, whatever the list is (empty, one record, any times, any digests).

Not said: which record it names (the next claims). -/
def PickNeverFails : Prop :=
  ∀ records : Slice Signed, pick records ⦃ _ => True ⦄

/-- **`pick` names what the latest records say.**  It returns, and its answer is `Named`: nothing
exactly for the empty list; record `i` exactly when it is the first of the latest time and every
record of that time has its digest; two records `i` and `j` exactly when `i` is the first of the
latest time and `j` is another record of that time with another digest.  The three cases exclude
each other, so this is "exactly": a list answers the one that holds.  Only the time decides:
a record of an earlier time is never looked at, however many there are.  A record signed at the
latest possible time (`i64::MAX`) is always of the latest time: nothing here limits what time a
signer writes.

Not said: that the time is true (it is what the signer wrote, within the trust of its key); which
record `j` of a tie is named (some record of the latest time with another digest); that the
records are accepted by the policy (the shell lists only those it accepted). -/
def PickNamesWhatTheLatestRecordsSay : Prop :=
  ∀ records : Slice Signed, pick records ⦃ answer => Named records.val answer ⦄

/-- **A record strictly later than every other wins.**  When record `i` is of a later time than
each other record of the list, `pick` answers `One i`: whatever tie or disagreement there is
below it does not matter.

Not said: anything when two records share the latest time. -/
def PickLaterRecordWins : Prop :=
  ∀ (records : Slice Signed) (i : Nat) (r : Signed), records.val[i]? = some r →
    (∀ k s, records.val[k]? = some s → k ≠ i → s.time.val < r.time.val) →
    pick records ⦃ answer => ∃ i', answer = Picked.One i' ∧ i'.val = i ⦄

/-- What two answers of `pick` for the same records in two orders name: nothing both times, or a
tie both times, or one digest signed at one time both times (the positions may differ). -/
def SameNaming (records : List Signed) (answer : Picked) (reordered : List Signed)
    (again : Picked) : Prop :=
  (answer = Picked.Nothing ∧ again = Picked.Nothing) ∨
  (∃ i j i' j', answer = Picked.Tie i j ∧ again = Picked.Tie i' j') ∨
  ∃ i j r s, answer = Picked.One i ∧ again = Picked.One j ∧ records[i.val]? = some r ∧
    reordered[j.val]? = some s ∧ r.time.val = s.time.val ∧ r.digest.val = s.digest.val

/-- **The order of arrival does not change what is named.**  For a list and any reordering of it
(the same records, in any order), `pick` answers for both: nothing for both, a tie for both, or
the same digest signed at the same time for both.  Only the positions named may differ, and
only to name another of equal records (or another pair of a tie).

Not said: that the positions are the same (the first of equal records is named, so reordering
moves it). -/
def PickDoesNotDependOnTheOrder : Prop :=
  ∀ records reordered : Slice Signed, records.val.Perm reordered.val →
    pick records ⦃ answer => pick reordered ⦃ again =>
      SameNaming records.val answer reordered.val again ⦄ ⦄

end PolicyCore
