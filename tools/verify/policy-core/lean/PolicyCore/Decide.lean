-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `decide` answers, from the inside out: `counts` (a fact satisfies the
-- rule), `newest` (the loop that looks for the newest fact that does), `weigh` (what one
-- requirement says), `decide_loop` (the loop over the requirements), and `decide` itself:
-- it accepts exactly when the requirements are `Acceptable`.
--
-- Why it is needed: this is the proof of the security rule.  The invariant of each loop says,
-- for the positions before the one the loop is at, what has been found: `NewestFound` for the
-- facts of a requirement, `Weighed` for the requirements.
--
-- Read before this file: Spec.lean, Identity.lean.
--
-- Notation: `m ⦃ r => P r ⦄` is "the Rust function `m` returns, and its result `r` satisfies
-- `P r`" (as in Spec.lean); `loop.spec_decr_nat` proves that a loop returns because a number
-- goes down at each turn and an invariant is kept by the body; `step as ⟨ x, hx ⟩` runs one line
-- of the Rust function and names its result `x` and what is known of it `hx`; `v.val` is the
-- list inside a vector or a slice; `l[k]?` is the element `k` of a list, if there is one.
import PolicyCore.Identity
open Aeneas Aeneas.Std Result velarx_policy_core
namespace PolicyCore

/-- `counts` says whether the fact satisfies the rule. -/
@[step]
theorem counts_is (rule : Rule) (intended : Ref) (fact : Fact) :
    counts rule intended fact ⦃ r => r = true ↔ FactSatisfies rule intended fact ⦄ := by
  unfold counts
  cases fact with
  | Unverified => simp [FactSatisfies]
  | Verified matches_manifest signed time =>
    simp only
    cases matches_manifest
    · simp [FactSatisfies]
    · simp only [↓reduceIte, FactSatisfies]
      step as ⟨ r, hr ⟩
      simpa using hr

/-- `time_of` returns. -/
@[step]
theorem time_of_returns (fact : Fact) : time_of fact ⦃ _ => True ⦄ := by
  unfold time_of
  cases fact <;> simp

/-- What the loop of `newest` has found among the facts before the position `i`: when it has
found nothing, no fact before `i` satisfies the rule; when it has found the fact `j`, that is a
fact before `i` that satisfies it. -/
def NewestFound (rule : Rule) (intended : Ref) (facts : Slice Fact) (i : Nat)
    (best : Option (Std.Usize × Std.I64)) : Prop :=
  (best = none → ∀ k < i, ∀ f, facts.val[k]? = some f → ¬ FactSatisfies rule intended f) ∧
  ∀ j time, best = some (j, time) → j.val < i ∧
    ∃ f, facts.val[j.val]? = some f ∧ FactSatisfies rule intended f

/-- A fact that satisfies the rule, found at the position `i`, is what has been found. -/
theorem newest_found_new (rule : Rule) (intended : Ref) (facts : Slice Fact) (i : Std.Usize)
    (fact : Fact) (fact_at : facts.val[i.val]? = some fact)
    (satisfies : FactSatisfies rule intended fact) (time : Std.I64) :
    NewestFound rule intended facts (i.val + 1) (some (i, time)) := by
  refine ⟨fun impossible => by simp at impossible, fun j found_time is_some => ?_⟩
  simp only [Option.some.injEq, Prod.mk.injEq] at is_some
  obtain ⟨rfl, _⟩ := is_some
  exact ⟨by omega, fact, fact_at, satisfies⟩

/-- A fact that does not change what has been found (it is not better, or satisfies nothing)
leaves it as it was, one position on. -/
theorem newest_found_next (rule : Rule) (intended : Ref) (facts : Slice Fact) (i : Nat)
    (best : Option (Std.Usize × Std.I64)) (found : NewestFound rule intended facts i best)
    (fact : Fact) (fact_at : facts.val[i]? = some fact)
    (unchanged : best ≠ none ∨ ¬ FactSatisfies rule intended fact) :
    NewestFound rule intended facts (i + 1) best := by
  obtain ⟨nothing, something⟩ := found
  refine ⟨fun is_none k below f f_at => ?_, fun j time is_some => ?_⟩
  · rcases Nat.lt_succ_iff_lt_or_eq.mp below with earlier | at_i
    · exact nothing is_none k earlier f f_at
    · rw [at_i, fact_at] at f_at
      cases Option.some.inj f_at
      exact unchanged.resolve_left (by simpa using is_none)
  · obtain ⟨before, rest⟩ := something j time is_some
    exact ⟨by omega, rest⟩

/-- The loop of `newest`: starting from what is found before the position `i`, it finds, among
all the facts, nothing or a fact that satisfies the rule. -/
theorem newest_loop_is (rule : Rule) (intended : Ref) (facts : Slice Fact)
    (best : Option (Std.Usize × Std.I64)) (i : Std.Usize)
    (read : i.val ≤ facts.length) (found : NewestFound rule intended facts i.val best) :
    newest_loop rule intended facts best i ⦃ r =>
      NewestFound rule intended facts facts.length r ⦄ := by
  unfold newest_loop
  apply loop.spec_decr_nat (fun q => facts.length - q.2.val)
    (fun q => q.2.val ≤ facts.length ∧ NewestFound rule intended facts q.2.val q.1)
  · rintro ⟨best, i⟩ ⟨read, found⟩
    simp only at read found ⊢
    unfold newest_loop.body
    dsimp only [Slice.len]
    split
    · rename_i below
      have inside : i.val < facts.length := by scalar_tac
      step as ⟨ fact, h_fact ⟩
      have fact_at : facts.val[i.val]? = some fact := by simp [h_fact]
      step as ⟨ satisfies, h_satisfies ⟩
      refine WP.spec_bind (Pₘ := fun r => NewestFound rule intended facts (i.val + 1) r) ?_
        (fun best1 found1 => ?_)
      · by_cases counted : satisfies = true
        · simp only [counted, ↓reduceIte]
          step as ⟨ time ⟩
          cases best with
          | none =>
            simp only [Std.bind_ok]
            exact (WP.spec_ok _).mpr (newest_found_new rule intended facts i fact fact_at
              (h_satisfies.mp counted) time)
          | some previous =>
            obtain ⟨j, before⟩ := previous
            -- the time of the best so far is compared with the time of the new fact
            change (do
              let (best2, newer) ← (ok (some (j, before), decide (time > before)) :
                Result (Option (Std.Usize × Std.I64) × Bool))
              if newer = true then ok (some (i, time)) else ok best2) ⦃ _ => _ ⦄
            by_cases newer : time > before
            · simp only [Std.bind_ok, decide_eq_true newer]
              exact (WP.spec_ok _).mpr (newest_found_new rule intended facts i fact fact_at
                (h_satisfies.mp counted) time)
            · simp only [Std.bind_ok, decide_eq_false newer]
              exact (WP.spec_ok _).mpr (newest_found_next rule intended facts i.val _ found fact
                fact_at (Or.inl (by simp)))
        · simp only [counted, Bool.false_eq_true, ↓reduceIte]
          exact (WP.spec_ok _).mpr (newest_found_next rule intended facts i.val _ found fact
            fact_at (Or.inr (fun sat => counted (h_satisfies.mpr sat))))
      · step as ⟨ next, hnext ⟩
        exact ⟨by omega, by simpa [hnext] using found1, by omega⟩
    · rename_i past_end
      -- every fact was looked at
      have at_end : i.val = facts.length := by scalar_tac
      rw [at_end] at found
      exact (WP.spec_ok _).mpr found
  · exact ⟨read, found⟩

/-- `newest` finds nothing exactly when no fact satisfies the rule, and what it finds does. -/
@[step]
theorem newest_is (rule : Rule) (intended : Ref) (facts : Slice Fact) :
    newest rule intended facts ⦃ r => NewestFound rule intended facts facts.length r ⦄ := by
  unfold newest
  apply newest_loop_is
  · simp
  · exact ⟨fun _ k below => by simp at below, fun j time is_some => by simp at is_some⟩
/-- `refusal_of` refuses exactly what the kind of the requirement refuses. -/
@[step]
theorem refusal_of_is (mode : Mode) (item : Item) :
    refusal_of mode item ⦃ o => o.isSome = true ↔ RefusesByKind mode item ⦄ := by
  unfold refusal_of
  cases mode <;> cases item <;> simp [RefusesByKind]

/-- When `newest` has looked at every fact, it found nothing exactly when no fact satisfies the
rule. -/
theorem newest_none_iff (rule : Rule) (intended : Ref) (facts : Slice Fact)
    (best : Option (Std.Usize × Std.I64))
    (found : NewestFound rule intended facts facts.length best) :
    best = none ↔ ¬ ∃ fact ∈ facts.val, FactSatisfies rule intended fact := by
  obtain ⟨nothing, something⟩ := found
  constructor
  · rintro is_none ⟨fact, listed, satisfies⟩
    obtain ⟨k, k_at⟩ := List.mem_iff_getElem?.mp listed
    exact nothing is_none k (by simpa [Slice.length] using (List.getElem?_eq_some_iff.mp k_at).1)
      fact k_at satisfies
  · intro none_satisfies
    cases best with
    | none => rfl
    | some found_one =>
      obtain ⟨j, time⟩ := found_one
      obtain ⟨_, fact, fact_at, satisfies⟩ := something j time rfl
      exact (none_satisfies ⟨fact, List.mem_of_getElem? fact_at, satisfies⟩).elim

/-- The verdict refuses the image. -/
def Refusing : Verdict → Prop
  | Verdict.Refuses _ => True
  | _ => False

/-- The verdict carries the signature that satisfies the requirement. -/
def Carrying : Verdict → Prop
  | Verdict.Signed _ _ => True
  | _ => False

/-- `weigh` refuses when the kind of the requirement refuses or when no fact satisfies a
signature requirement; when it does not refuse it carries a signature for a signature requirement
and for no other. -/
@[step]
theorem weigh_is (mode : Mode) (intended : Ref) (item : Item) :
    weigh mode intended item ⦃ v =>
      (Refusing v ↔ RefusesByKind mode item ∨ ¬ SignaturesSatisfy intended item) ∧
      (¬ Refusing v → (Carrying v ↔ IsSignatureRequirement item)) ⦄ := by
  unfold weigh
  step as ⟨ refusal, h_refusal ⟩
  cases refusal with
  | some why =>
    -- the kind of the requirement refuses
    have by_kind : RefusesByKind mode item := h_refusal.mp rfl
    exact (WP.spec_ok _).mpr ⟨⟨fun _ => Or.inl by_kind, fun _ => trivial⟩,
      fun not_refusing => (not_refusing trivial).elim⟩
  | none =>
    have no_kind : ¬ RefusesByKind mode item := fun by_kind => by simpa using h_refusal.mpr by_kind
    cases item with
    | Signed rule facts =>
      simp only
      step as ⟨ best, found ⟩
      have none_iff := newest_none_iff rule intended facts.deref best found
      simp only [deref_val] at none_iff
      cases best with
      | none =>
        -- no fact satisfies it
        have none_satisfies := none_iff.mp rfl
        simp only [WP.spec_ok]
        simp [Refusing, SignaturesSatisfy, none_satisfies]
      | some found_one =>
        -- a fact does
        obtain ⟨index, time⟩ := found_one
        have satisfied : ∃ fact ∈ facts.val, FactSatisfies rule intended fact := by
          by_contra none_satisfies
          exact absurd (none_iff.mpr none_satisfies) (by simp)
        simp [Refusing, Carrying, SignaturesSatisfy, IsSignatureRequirement, no_kind, satisfied]
    | AcceptAnything =>
      simp [Refusing, Carrying, SignaturesSatisfy, IsSignatureRequirement, no_kind]
    | Reject =>
      simp [Refusing, Carrying, SignaturesSatisfy, IsSignatureRequirement, no_kind]
    | Unimplemented =>
      simp [Refusing, Carrying, SignaturesSatisfy, IsSignatureRequirement, no_kind]
    | Unusable =>
      simp [Refusing, Carrying, SignaturesSatisfy, IsSignatureRequirement, no_kind]
/-- What the loop of `decide` knows after the requirements before the position `i`: no
refusal so far exactly when each of them holds, and the signatures kept are as many as the
signature requirements seen (at least one, or none). -/
def Weighed (mode : Mode) (intended : Ref) (items : Slice Item) (i : Nat)
    (used : alloc.vec.Vec Std.Usize) (refused : Option (Std.Usize × Why)) : Prop :=
  used.length ≤ i ∧
  (refused = none ↔ ∀ k < i, ∀ item, items.val[k]? = some item →
    ¬ RefusesByKind mode item ∧ SignaturesSatisfy intended item) ∧
  (refused = none → (0 < used.length ↔ ∃ k < i, ∃ item, items.val[k]? = some item ∧
    IsSignatureRequirement item))

/-- A requirement that holds, and that adds the signatures kept as needed, extends what has been
weighed by one. -/
theorem weighed_next_fine (mode : Mode) (intended : Ref) (items : Slice Item) (i : Nat)
    (used used' : alloc.vec.Vec Std.Usize) (weighed : Weighed mode intended items i used none)
    (item : Item) (item_at : items.val[i]? = some item)
    (fine : ¬ RefusesByKind mode item ∧ SignaturesSatisfy intended item)
    (short : used'.length ≤ i + 1)
    (counted : 0 < used'.length ↔ (0 < used.length ∨ IsSignatureRequirement item)) :
    Weighed mode intended items (i + 1) used' none := by
  obtain ⟨_, nothing_refused, signatures⟩ := weighed
  refine ⟨short, ⟨fun _ k below u u_at => ?_, fun _ => rfl⟩, fun _ => ?_⟩
  · rcases Nat.lt_succ_iff_lt_or_eq.mp below with earlier | at_i
    · exact nothing_refused.mp rfl k earlier u u_at
    · rw [at_i, item_at] at u_at
      cases Option.some.inj u_at
      exact fine
  · rw [counted, signatures rfl]
    constructor
    · rintro (⟨k, earlier, found⟩ | is_signature)
      · exact ⟨k, by omega, found⟩
      · exact ⟨i, by omega, item, item_at, is_signature⟩
    · rintro ⟨k, below, u, u_at, is_signature⟩
      rcases Nat.lt_succ_iff_lt_or_eq.mp below with earlier | at_i
      · exact Or.inl ⟨k, earlier, u, u_at, is_signature⟩
      · rw [at_i, item_at] at u_at
        cases Option.some.inj u_at
        exact Or.inr is_signature

/-- A requirement that refuses stops the weighing: the refusal is kept. -/
theorem weighed_next_refused (mode : Mode) (intended : Ref) (items : Slice Item) (i : Nat)
    (used' : alloc.vec.Vec Std.Usize)
    (item : Item) (item_at : items.val[i]? = some item)
    (refuses : ¬ (¬ RefusesByKind mode item ∧ SignaturesSatisfy intended item))
    (short : used'.length ≤ i + 1) (refusal : Std.Usize × Why) :
    Weighed mode intended items (i + 1) used' (some refusal) := by
  refine ⟨short, ⟨fun impossible => by simp at impossible, fun all => ?_⟩, fun impossible => ?_⟩
  · exact (refuses (all i (by omega) item item_at)).elim
  · simp at impossible

/-- The loop of `decide`, when it stops, has weighed every requirement (or has refused). -/
theorem decide_loop_is (mode : Mode) (intended : Ref) (items : Slice Item)
    (used : alloc.vec.Vec Std.Usize) (signed : Std.I64) (refused : Option (Std.Usize × Why))
    (i : Std.Usize) (read : i.val ≤ items.length)
    (weighed : Weighed mode intended items i.val used refused) :
    decide_loop mode intended items used signed refused i ⦃ r =>
      Weighed mode intended items items.length r.1 r.2.2 ⦄ := by
  unfold decide_loop
  apply loop.spec_decr_nat (fun q => items.length - q.2.2.2.val)
    (fun q => q.2.2.2.val ≤ items.length ∧ Weighed mode intended items q.2.2.2.val q.1 q.2.2.1)
  · rintro ⟨used, signed, refused, i⟩ ⟨read, weighed⟩
    simp only at read weighed ⊢
    unfold decide_loop.body
    dsimp only [Slice.len]
    split
    · split
      · rename_i below still_going
        have inside : i.val < items.length := by scalar_tac
        obtain rfl : refused = none := by simpa using still_going
        obtain ⟨short, nothing_refused, signatures⟩ := weighed
        step as ⟨ item, h_item ⟩
        have item_at : items.val[i.val]? = some item := by simp [h_item]
        step as ⟨ verdict, h_refusing, h_carrying ⟩
        -- what the verdict says of the requirement `i`
        have fine_unless_refusing : ¬ Refusing verdict →
            ¬ RefusesByKind mode item ∧ SignaturesSatisfy intended item := fun accepted =>
          ⟨fun kind => accepted (h_refusing.mpr (Or.inl kind)),
           by_contra fun not_satisfied => accepted (h_refusing.mpr (Or.inr not_satisfied))⟩
        cases verdict with
        | Holds =>
          have fine := fine_unless_refusing (by simp [Refusing])
          have not_signature : ¬ IsSignatureRequirement item := fun sig =>
            by simpa [Carrying] using (h_carrying (by simp [Refusing])).mpr sig
          refine WP.spec_bind (Pₘ := fun r : alloc.vec.Vec Std.Usize × Std.I64 ×
            Option (Std.Usize × Why) => Weighed mode intended items (i.val + 1) r.1 r.2.2)
            ?_ (fun r kept => ?_)
          · refine (WP.spec_ok _).mpr (weighed_next_fine mode intended items i.val used used
              ⟨short, nothing_refused, signatures⟩ item item_at fine (by omega) ?_)
            simp [not_signature]
          · obtain ⟨used1, signed1, refused1⟩ := r
            step as ⟨ next, hnext ⟩
            exact ⟨by omega, by simpa [hnext] using kept, by omega⟩
        | Signed index time =>
          have fine := fine_unless_refusing (by simp [Refusing])
          have is_signature : IsSignatureRequirement item :=
            (h_carrying (by simp [Refusing])).mp (by simp [Carrying])
          -- its signature is kept, and the oldest time is remembered
          refine WP.spec_bind (Pₘ := fun r : alloc.vec.Vec Std.Usize × Std.I64 ×
            Option (Std.Usize × Why) => Weighed mode intended items (i.val + 1) r.1 r.2.2)
            ?_ (fun r kept => ?_)
          · step as ⟨ used2, h_used2 ⟩
            have kept_one : used2.length = used.length + 1 := by
              simp [h_used2, alloc.vec.Vec.length]
            have weighed_used2 := weighed_next_fine mode intended items i.val used used2
              ⟨short, nothing_refused, signatures⟩ item item_at fine (by omega)
              (by simp [kept_one, is_signature])
            -- the time kept does not matter here
            have keeps : ∀ time_kept : Std.I64, (ok (used2, time_kept, none) :
                Result (alloc.vec.Vec Std.Usize × Std.I64 × Option (Std.Usize × Why))) ⦃ r =>
                Weighed mode intended items (i.val + 1) r.1 r.2.2 ⦄ :=
              fun _ => (WP.spec_ok _).mpr weighed_used2
            split
            · simp only [Std.bind_ok]
              exact keeps _
            · split <;> (simp only [Std.bind_ok]; exact keeps _)
          · obtain ⟨used1, signed1, refused1⟩ := r
            step as ⟨ next, hnext ⟩
            exact ⟨by omega, by simpa [hnext] using kept, by omega⟩
        | Refuses why =>
          have not_fine : ¬ (¬ RefusesByKind mode item ∧ SignaturesSatisfy intended item) :=
            fun fine => by
              rcases h_refusing.mp (by simp [Refusing]) with kind | not_satisfied
              · exact fine.1 kind
              · exact not_satisfied fine.2
          refine WP.spec_bind (Pₘ := fun r : alloc.vec.Vec Std.Usize × Std.I64 ×
            Option (Std.Usize × Why) => Weighed mode intended items (i.val + 1) r.1 r.2.2)
            ?_ (fun r kept => ?_)
          · exact (WP.spec_ok _).mpr (weighed_next_refused mode intended items i.val used item
              item_at not_fine (by omega) (i, why))
          · obtain ⟨used1, signed1, refused1⟩ := r
            step as ⟨ next, hnext ⟩
            exact ⟨by omega, by simpa [hnext] using kept, by omega⟩
      · rename_i below stopped
        -- a requirement refused: the weighing stopped
        have refusal : ¬ refused = none := by simpa using stopped
        obtain ⟨short, nothing_refused, _⟩ := weighed
        have stopped_weighing : Weighed mode intended items items.length used refused :=
          ⟨by omega, ⟨fun is_none => (refusal is_none).elim, fun all => (refusal
            (nothing_refused.mpr fun k before u u_at => all k (by omega) u u_at)).elim⟩,
            fun is_none => (refusal is_none).elim⟩
        exact (WP.spec_ok _).mpr stopped_weighing
    · rename_i past_end
      -- every requirement was weighed
      have at_end : i.val = items.length := by scalar_tac
      rw [at_end] at weighed
      exact (WP.spec_ok _).mpr weighed
  · exact ⟨read, weighed⟩
/-- Saying a thing of each position of a list is saying it of each element. -/
theorem all_listed {α : Type} (l : List α) (P : α → Prop) :
    (∀ k < l.length, ∀ x, l[k]? = some x → P x) ↔ ∀ x ∈ l, P x := by
  constructor
  · intro all x listed
    obtain ⟨k, k_at⟩ := List.mem_iff_getElem?.mp listed
    exact all k (List.getElem?_eq_some_iff.mp k_at).1 x k_at
  · intro all k _ x x_at
    exact all x (List.mem_of_getElem? x_at)

/-- Saying a thing of some position of a list is saying it of some element. -/
theorem some_listed {α : Type} (l : List α) (Q : α → Prop) :
    (∃ k < l.length, ∃ x, l[k]? = some x ∧ Q x) ↔ ∃ x ∈ l, Q x := by
  constructor
  · rintro ⟨k, _, x, x_at, found⟩
    exact ⟨x, List.mem_of_getElem? x_at, found⟩
  · rintro ⟨x, listed, found⟩
    obtain ⟨k, k_at⟩ := List.mem_iff_getElem?.mp listed
    exact ⟨k, (List.getElem?_eq_some_iff.mp k_at).1, x, k_at, found⟩

/-- `must_be_signed` says whether the mode is `MustBeSigned`. -/
@[step]
theorem must_be_signed_is (mode : Mode) :
    must_be_signed mode ⦃ b => b = true ↔ mode = Mode.MustBeSigned ⦄ := by
  unfold must_be_signed
  cases mode <;> simp

/-- `decide` accepts exactly when the requirements are `Acceptable`. -/
theorem decide_is (mode : Mode) (intended : Ref) (items : Slice Item) :
    velarx_policy_core.decide mode intended items ⦃ o =>
      (∃ used signed, o = Outcome.Accept used signed) ↔ Acceptable mode intended items.val ⦄ := by
  unfold velarx_policy_core.decide
  refine WP.spec_bind (decide_loop_is mode intended items (alloc.vec.Vec.new Std.Usize) 0#i64
    none 0#usize (by simp) ⟨by simp [alloc.vec.Vec.new],
      ⟨fun _ k below => by simp at below, fun _ => rfl⟩, fun _ => by simp [alloc.vec.Vec.new]⟩)
    (fun r weighed => ?_)
  obtain ⟨used, signed, refused⟩ := r
  obtain ⟨_, nothing_refused, signatures⟩ := weighed
  simp only [all_listed] at nothing_refused
  simp only [some_listed] at signatures
  step as ⟨ empty, h_empty ⟩
  have empty_iff : empty = true ↔ items.val = [] := by
    rw [h_empty]
    simp [Slice.length]
  by_cases no_requirement : empty = true
  · -- no requirement at all: refused
    simp only [no_requirement, ↓reduceIte, WP.spec_ok]
    simp [Acceptable, empty_iff.mp no_requirement]
  · have not_nil : items.val ≠ [] := fun nil => no_requirement (empty_iff.mpr nil)
    simp only [no_requirement, Bool.false_eq_true, ↓reduceIte]
    cases refused with
    | some refusal =>
      -- a requirement refused
      obtain ⟨at_, why⟩ := refusal
      refine (WP.spec_ok _).mpr ?_
      constructor
      · rintro ⟨_, _, impossible⟩
        cases impossible
      · rintro ⟨_, fine, _⟩
        have := nothing_refused.mpr fine
        simp at this
    | none =>
      have fine_iff := nothing_refused.mp rfl
      have signature_iff := signatures rfl
      refine WP.spec_bind (Pₘ := fun b => b = true ↔ mode = Mode.MustBeSigned) ?_
        (fun must must_iff => ?_)
      · exact must_be_signed_is mode
      by_cases is_must : must = true
      · -- the mode asks for a signature
        simp only [is_must, ↓reduceIte]
        step as ⟨ none_kept, h_none_kept ⟩
        have mode_is := must_iff.mp is_must
        by_cases no_signature : none_kept = true
        · -- no signature was kept
          simp only [no_signature, ↓reduceIte]
          refine (WP.spec_ok _).mpr ⟨fun ⟨_, _, impossible⟩ => (by cases impossible), ?_⟩
          rintro ⟨_, _, needed⟩
          have kept := (signature_iff.mpr (by simpa using needed mode_is))
          have : used.length = 0 := by simpa using h_none_kept.mp no_signature
          omega
        · simp only [no_signature, Bool.false_eq_true, ↓reduceIte]
          refine (WP.spec_ok _).mpr
            ⟨fun _ => ⟨not_nil, fine_iff, fun _ => ?_⟩, fun _ => ⟨_, _, rfl⟩⟩
          refine signature_iff.mp ?_
          have : ¬ used.length = 0 := by simpa using fun h => no_signature (h_none_kept.mpr h)
          omega
      · simp only [is_must, Bool.false_eq_true, ↓reduceIte]
        exact (WP.spec_ok _).mpr ⟨fun _ => ⟨not_nil, fine_iff, fun is_mode =>
          (is_must (must_iff.mpr is_mode)).elim⟩, fun _ => ⟨_, _, rfl⟩⟩
end PolicyCore
