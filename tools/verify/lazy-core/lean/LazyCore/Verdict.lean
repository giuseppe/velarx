-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `TheVerdictOfAFailure` (Spec.lean).
-- When what ran for a pull fails with a class, the pull is over or waits,
-- as the class says: `NeedsCredentials`, `Failed`, `NoSpace` or `Backoff`.
--
-- The argument follows the Rust, from the inside out:
--   1. `try_failed` decides by the class: it records the state, and
--      either `leave`s the pull (it is over) or lets go of its layers and
--      asks to be woken (it waits).  `backoff` gives the wait of a
--      transient failure, and the wait is between the bounds of the
--      statement.  (`Verdict`, `try_failed_verdict`.)
--   2. `failed` of a pull (`Work::Pull p`) calls `try_failed` for that pull
--      only: the pull is looked up by name (the names are distinct, so
--      the one that is found is the one the statement is about).
--      (`failed_pull_verdict`.)
--   3. `step` then calls `advance`, which pushes more actions but leaves
--      a pull that is over (it is gone) or waiting as it is: it changes
--      only pulls that are working, and the names of the layers and of the groups stay.
--      (`Kept`, `advance_keeps_pulls`.)
--   4. Put together, the result of `step` is what Spec.lean says.
--
-- Read before this file: Ok.lean, Grows.lean, Pulls.lean, and the
-- statement in Spec.lean.
--
-- Notation: besides the notations of the files above,
--   - `List.Forall₂ R l l'` is "the lists have the same length and `R`
--     holds between the elements at each place";
--   - `a ++ b` joins lists, `l.take n` is the first `n` elements of `l`,
--     `l.drop n` the others;
--   - ``Nodup l`` is "no element of `l` is twice in it";
--   - a Rust loop `for p in pulls.iter_mut()` is extracted by Aeneas as
--     an iterator `it` (a slice and a place `it.i`) and a *back function*
--     `back`: the slice is changed in place, so Aeneas gives, with the
--     iterator, a function that takes the iterator at the end of the loop
--     (holding the changed pulls) and returns the whole vector.  Each
--     round of the loop makes a new back function from the last one: it
--     writes the pull of the round at its place, then calls the last one.
--     `Walked` below says what such a back function gives.
import LazyCore.Pulls

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

-- (`Ok` too: a lemma that does not fit is refused at once, the unifier does not open `Ok`)
attribute [local irreducible] Ok let_go leave_loop cancel_loop advance_loop2 advance_loop4_loop0
  advance_loop4 advance Core.lacking

/-- `Pull::working` says yes exactly for a pull whose phase is `Running Working`. -/
theorem working_iff (p : Pull) :
    Ok (Pull.working p) (fun b => b = true ↔ p.phase = Phase.Running Step.Working) := by
  unfold Pull.working Phase.Insts.CoreCmpPartialEqPhase.eq
  cases hp : p.phase with
  | Running s =>
    cases s <;> simp [Phase.read_discriminant, Step.Insts.CoreCmpPartialEqStep.eq,
      Step.read_discriminant] <;> exact Ok.ok.mpr (by simp)
  | _ => simp [Phase.read_discriminant]; exact Ok.ok.mpr (by simp)

/-- `backoff(failures, max)` is at most `max` seconds (in milliseconds), and at least a
second when `max` is not zero.  It is the only thing known of the wait of a transient failure. -/
theorem backoff_bounds (f : Std.U32) (max : Std.U64) :
    Ok (backoff f max) (fun w => w.val ≤ max.val * 1000 ∧ (1 ≤ max.val → 1000 ≤ w.val)) := by
  unfold backoff
  simp only [lift, bind_ok, core.num.U64.checked_shl, core.num.U64.saturating_mul]
  apply Ok.ok.mpr
  -- `failures.min(20)` is at most 20, so the shift `1 << n` does not overflow
  have at_most_20 : (core.cmp.impls.OrdU32.min f 20#u32).val ≤ 20 := by
    unfold core.cmp.impls.OrdU32.min; split <;> scalar_tac
  generalize core.cmp.impls.OrdU32.min f 20#u32 = i at at_most_20
  have below_64 : i.val < 64 := by omega
  simp only [below_64, ↓reduceIte, core.option.Option.unwrap_or]
  -- the shift is at least 1 (checked for each of the 21 values)
  have at_least_1 : 1 ≤ (⟨(1#u64).bv <<< i.val⟩ : Std.U64).val := by
    have : i.val ∈ Finset.range 21 := by simp; omega
    revert this; generalize i.val = n; intro hn
    fin_cases hn <;> decide
  generalize (⟨(1#u64).bv <<< i.val⟩ : Std.U64) = secs at at_least_1
  -- `.min(max)` is at most `max`, and at least 1 when `max` is
  have min_bounds : (core.cmp.impls.OrdU64.min secs max).val ≤ max.val ∧
      (1 ≤ max.val → 1 ≤ (core.cmp.impls.OrdU64.min secs max).val) := by
    unfold core.cmp.impls.OrdU64.min; split <;> scalar_tac
  generalize core.cmp.impls.OrdU64.min secs max = m at min_bounds
  -- `saturating_mul(1000)`: a number that fits is not changed
  have of_nat_val : ∀ k : Nat, k ≤ Std.U64.max →
      (⟨BitVec.ofNat UScalarTy.U64.numBits k⟩ : Std.U64).val = k := by
    intro k hk
    simp only [UScalar.val, BitVec.toNat_ofNat]
    apply Nat.mod_eq_of_lt
    scalar_tac
  rw [of_nat_val _ (Nat.min_le_left _ _)]
  have thousand : (1000#u64).val = 1000 := by rfl
  have fits : (1000 : Nat) ≤ Std.U64.max := by scalar_tac
  rw [thousand]
  refine ⟨le_trans (Nat.min_le_right _ _) (Nat.mul_le_mul_right 1000 min_bounds.1),
    fun nonzero => Nat.le_min.mpr ⟨fits, ?_⟩⟩
  have := min_bounds.2 nonzero
  omega

/-- If every element of `l'` is related to the element of `l` at the same place, each element of
one is related to one of the other. -/
theorem forall₂_mem_right {α β : Type} {R : α → β → Prop} {l : List α} {l' : List β}
    (related : List.Forall₂ R l l') {y : β} (in_l' : y ∈ l') : ∃ x ∈ l, R x y := by
  induction related with
  | nil => simp at in_l'
  | cons head _ ih =>
    rcases List.mem_cons.mp in_l' with rfl | in_rest
    · exact ⟨_, List.mem_cons_self, head⟩
    · obtain ⟨x, in_l, r⟩ := ih in_rest
      exact ⟨x, List.mem_cons_of_mem _ in_l, r⟩

/-- The other way round. -/
theorem forall₂_mem_left {α β : Type} {R : α → β → Prop} {l : List α} {l' : List β}
    (related : List.Forall₂ R l l') {x : α} (in_l : x ∈ l) : ∃ y ∈ l', R x y := by
  induction related with
  | nil => simp at in_l
  | cons head _ ih =>
    rcases List.mem_cons.mp in_l with rfl | in_rest
    · exact ⟨_, List.mem_cons_self, head⟩
    · obtain ⟨y, in_l', r⟩ := ih in_rest
      exact ⟨y, List.mem_cons_of_mem _ in_l', r⟩

/-- A list is related to itself when each element is. -/
theorem forall₂_self {α : Type} {R : α → α → Prop} (refl : ∀ a, R a a) (l : List α) :
    List.Forall₂ R l l := by
  induction l with
  | nil => exact List.Forall₂.nil
  | cons a rest ih => exact List.Forall₂.cons (refl a) ih

/-- Related lists have the same images. -/
theorem map_eq_of_forall₂ {α β : Type} (f : α → β) {l l' : List α}
    (same : List.Forall₂ (fun a b => f b = f a) l l') : l'.map f = l.map f := by
  induction same with
  | nil => rfl
  | cons head _ ih => simp [head, ih]

/-- `Kept a b`: what `advance` leaves of a pull `a` is `b`: the same name, the same layers, and
the same phase unless `a` was working (a working pull may go on to commit its image or to the
driver's pull, and then it is still past its preparation). -/
def Kept (a b : Pull) : Prop :=
  b.id = a.id ∧ (a.phase ≠ Phase.Running Step.Working → b.phase = a.phase) ∧
  b.layers = a.layers ∧ (a.phase = Phase.Running Step.Working → PastPreparing b.phase)

/-- A pull is kept as it is by itself. -/
theorem Kept.refl (a : Pull) : Kept a a :=
  ⟨rfl, fun _ => rfl, rfl, fun working => Or.inl working⟩

/-- `Walked R l it back`: the loop over the elements `l` of a vector (`for x in v.iter_mut()`,
extracted as the iterator `it` and its back function `back`, see the top of this file) has gone
through the elements before `it.i`: whatever the iterator holds at the end, `back` of it gives
those first elements as the loop left them (each is related by `R` to what it was: `Kept` for
the pulls), followed by the elements from `it.i` on as the iterator holds them. -/
def Walked {α : Type} (R : α → α → Prop) (l : List α) (it : core.slice.iter.IterMut α)
    (back : core.slice.iter.IterMut α → core.slice.iter.IterMut α) : Prop :=
  it.slice.val = l ∧ ∀ it' : core.slice.iter.IterMut α, it'.slice.val.length = l.length →
    ∃ pre, (back it').slice.val = pre ++ it'.slice.val.drop it.i ∧
      List.Forall₂ R (l.take it.i) pre

/-- One round of the loop: the element at `it.i` is replaced by an element `y` related to it
(`next` gives the element and a new back function that writes `y` there), and the
iterator moves on by one.  Then `Walked` holds for the next round. -/
theorem Walked.next {α : Type} {R : α → α → Prop} {l : List α} {it : core.slice.iter.IterMut α}
    {back : core.slice.iter.IterMut α → core.slice.iter.IterMut α}
    (walked : Walked R l it back) (more : it.i < it.slice.val.length) (y : α)
    (kept : R (it.slice.val[it.i]) y) :
    Walked R l { it with i := it.i + 1 }
      (fun im => back { im with slice := im.slice.setAtNat it.i y }) := by
  obtain ⟨same_list, gives⟩ := walked
  refine ⟨same_list, fun it' same_length => ?_⟩
  obtain ⟨pre, back_is, pre_kept⟩ :=
    gives { it' with slice := it'.slice.setAtNat it.i y } (by simpa using same_length)
  have in_l : it.i < l.length := by rw [← same_list]; exact more
  refine ⟨pre ++ [y], ?_, ?_⟩
  · rw [back_is]
    have : it.i < it'.slice.val.length := by omega
    simp [Slice.setAtNat, List.drop_set_of_lt, List.drop_eq_getElem_cons, this]
  · rw [List.take_succ_eq_append_getElem in_l]
    refine List.rel_append pre_kept ?_
    subst same_list
    exact List.Forall₂.cons kept List.Forall₂.nil

/-- When the iterator is at its end, every element of the loop was related: the vector
that `back` gives is the elements, each related by `R` to what it was. -/
theorem Walked.done {α : Type} {R : α → α → Prop} {l : List α} {it : core.slice.iter.IterMut α}
    {back : core.slice.iter.IterMut α → core.slice.iter.IterMut α}
    (walked : Walked R l it back) (at_end : ¬ it.i < it.slice.val.length) :
    List.Forall₂ R l (back it).slice.val := by
  obtain ⟨same_list, gives⟩ := walked
  obtain ⟨pre, back_is, pre_kept⟩ := gives it (by rw [same_list])
  rw [back_is, List.drop_eq_nil_of_le (by omega), List.append_nil]
  rwa [List.take_of_length_le (by rw [← same_list]; omega)] at pre_kept

set_option hygiene false in
/-- `walk_loop body`: the proof that a loop over the elements of a vector (`for x in v.iter_mut()`,
the loop function `body`) puts back in each round an element related to the old one by what `Walked`
is for.  It follows the body line by line (a push, a call or test whose result does not matter, a
branch) until the round ends, and closes it with `Walked.next`, the new element being `Kept` or
having the name of the old one; when the iterator is at its end, `Walked.done`.  A use follows
`Ok.loop (I := fun x => Walked ...)`, and `rintro` of the state and of `walked`. -/
macro "walk_loop " body:ident : tactic => `(tactic| (
  unfold $body core.slice.iter.IteratorIterMut.next
  dsimp only
  by_cases more : it.i < it.slice.len
  · have more' : it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    generalize hg : it.slice[it.i] = x
    have current : it.slice.val[it.i] = x := hg
    repeat (first
      | exact Ok.ok.mpr (walked.next more' _ (current ▸ Kept.refl _))
      | exact Ok.ok.mpr (walked.next more' _
          (current ▸ ⟨rfl, fun _ => rfl, rfl, fun working => Or.inl working⟩))
      | exact Ok.ok.mpr (walked.next more' _ (by simp [current]))
      | exact Ok.ok.mpr (walked.next more' _ (by rw [current]))
      | (refine Ok.bind (working_iff _) ?_; intro _ _)
      | (refine Ok.bind (push_appends _ _) ?_; intro _ _)
      | (refine Ok.bind (Ok.any _) ?_; intro _ _)
      | simp only [uncurry_eq]
      | split)
  · have at_end : ¬ it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    exact Ok.ok.mpr (walked.done at_end)))

/-- `Asks l a`: `a` is what `advance` asks for a working pull of `l`: the commit of its image
or the driver's pull of its layers. -/
def Asks (l : List Pull) (a : Action) : Prop :=
  ∃ y ∈ l, y.phase = Phase.Running Step.Working ∧
    (a = Action.CommitImage y.id ∨ a = Action.DriverPull y.id)

/-- `AllStored layers p`: every layer of the table `layers` that the pull `p` lacks is `Stored`
(the Rust `p.has_all(layers, |s| s == Stored)`, see `has_all_iff`). -/
def AllStored (layers : List Layer) (p : Pull) : Prop :=
  ∀ x ∈ layers, x.id ∈ p.layers.val → x.state = LayerState.Stored

/-- `AllReady layers p`: every layer of the table `layers` that the pull `p` lacks is `Ready` or
`Stored` (the Rust `p.has_all(layers, |s| matches!(s, Ready | Stored))`, see `has_all_iff`). -/
def AllReady (layers : List Layer) (p : Pull) : Prop :=
  ∀ x ∈ layers, x.id ∈ p.layers.val → x.state = LayerState.Ready ∨ x.state = LayerState.Stored

/-- `KeptImage layers a b`: what `advance` leaves of a pull `a` is `b` (`Kept`); a working pull
whose layers are all stored in `layers` is left at `Image` (it is the one whose image is asked), and
a working pull whose layers are all ready or stored, but not all stored, is left at `DriverPull` (the
one whose driver's pull is asked). -/
def KeptImage (layers : List Layer) (a b : Pull) : Prop :=
  Kept a b ∧ (a.phase = Phase.Running Step.Working → AllStored layers a →
    b.phase = Phase.Running Step.Image) ∧
  (a.phase = Phase.Running Step.Working → AllReady layers a → ¬ AllStored layers a →
    b.phase = Phase.Running Step.DriverPull)

/-- What the loop of `advance` over the pulls `l` has asked, as a list `t` of actions: only `Asks`;
the commit of an image only of a working pull whose layers are all stored in `layers`; the driver's
pull only of a working pull whose layers are all ready or stored, but not all stored. -/
def AskedFor (layers : List Layer) (l : List Pull) (t : List Action) : Prop :=
  (∀ a ∈ t, Asks l a) ∧
  (∀ p, Action.CommitImage p ∈ t →
    ∃ y ∈ l, y.id = p ∧ y.phase = Phase.Running Step.Working ∧ AllStored layers y) ∧
  (∀ p, Action.DriverPull p ∈ t →
    ∃ y ∈ l, y.id = p ∧ y.phase = Phase.Running Step.Working ∧ AllReady layers y ∧
      ¬ AllStored layers y)

/-- The loop of `advance` over the pulls (`for p in pulls.iter_mut()`) pushes to `out` only what
`AskedFor` says (of the pulls of `l`); it leaves every pull `KeptImage`: a pull that is not working is
not touched, and a working one only changes its phase, to `Image` if its layers are all stored, to
`DriverPull` if they are all ready or stored. -/
theorem advance_loop3_keeps_pulls (l : List Pull) (iter : core.slice.iter.IterMut Pull)
    (back : core.slice.iter.IterMut Pull → core.slice.iter.IterMut Pull)
    (out : alloc.vec.Vec Action) (layers : alloc.vec.Vec Layer)
    (walked : Walked (KeptImage layers.val) l iter back) :
    Ok (advance_loop3 iter back out layers) (fun r =>
      (∃ t, r.1.val = out.val ++ t ∧ AskedFor layers.val l t) ∧
      List.Forall₂ (KeptImage layers.val) l (r.2.2 r.2.1).slice.val) := by
  unfold advance_loop3
  refine Ok.loop (I := fun x => (∃ t, x.2.2.val = out.val ++ t ∧ AskedFor layers.val l t) ∧
    Walked (KeptImage layers.val) l x.1 x.2.1) ?_
    ⟨⟨[], by simp, by simp, by simp, by simp⟩, walked⟩
  rintro ⟨it, back, out1⟩ ⟨⟨t, grown, asked, commits, drivers⟩, walked⟩
  dsimp only at grown asked commits drivers walked
  unfold advance_loop3.body core.slice.iter.IteratorIterMut.next
  dsimp only
  by_cases more : it.i < it.slice.len
  · -- there is a pull `p`: `if !p.working() { continue }`
    have more' : it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    generalize hg : it.slice[it.i] = p
    have current : it.slice.val[it.i] = p := hg
    have p_in_l : p ∈ l := by
      rw [← current, ← walked.1]; exact List.getElem_mem more'
    refine Ok.bind (working_iff p) ?_; intro b is_working
    split
    · -- it is working: its name stays, and its phase is free to change
      have running_working := is_working.mp (by assumption)
      -- the pull after the round: the same name and layers, past its preparation, and `Image`
      -- if all its layers are stored
      have kept_if_same_id : ∀ y : Pull, y.id = p.id → y.layers = p.layers →
          PastPreparing y.phase → (AllStored layers.val p → y.phase = Phase.Running Step.Image) →
          (AllReady layers.val p → ¬ AllStored layers.val p →
            y.phase = Phase.Running Step.DriverPull) →
          KeptImage layers.val (it.slice.val[it.i]) y :=
        fun y same_id same_layers past image driver => by
          rw [current]
          exact ⟨⟨same_id, fun not_working => absurd running_working not_working, same_layers,
            fun _ => past⟩, fun _ stored => image stored, fun _ ready not_stored =>
            driver ready not_stored⟩
      -- what `advance` asks for the pull is `Asks`, added to what was asked
      have asks_more : ∀ a, (a = Action.CommitImage p.id ∨ a = Action.DriverPull p.id) →
          ∀ b ∈ t ++ [a], Asks l b := fun a is_a b in_b => by
        rcases List.mem_append.mp in_b with old | new
        · exact asked b old
        · exact ⟨p, p_in_l, running_working, by rw [List.mem_singleton.mp new]; exact is_a⟩
      -- `p.has_all(layers, |s| s == Stored)` says whether every layer it lacks is stored
      refine Ok.bind (has_all_iff _ p _ () (fun s => s.read_discriminant =
        LayerState.Stored.read_discriminant) stored_test) ?_
      intro all_stored all_stored_iff
      have stored_iff_all : (∀ x ∈ (alloc.vec.Vec.deref layers).val, x.id ∈ p.layers.val →
          x.state.read_discriminant = LayerState.Stored.read_discriminant) ↔
          AllStored layers.val p := by
        simp [AllStored, stored_iff, alloc.vec.Vec.deref]
      rw [stored_iff_all] at all_stored_iff
      split
      · -- every layer it lacks is stored: `phase = Image`, `CommitImage` is pushed
        have stored := all_stored_iff.mp (by assumption)
        refine Ok.bind (push_appends _ _) ?_; intro out2 pushed
        refine Ok.ok.mpr ⟨⟨t ++ [Action.CommitImage p.id], by simp [pushed, grown],
          asks_more _ (Or.inl rfl), fun q in_t => ?_, fun q in_t => ?_⟩,
          walked.next more' _ (kept_if_same_id _ rfl rfl (by simp [PastPreparing])
            (fun _ => rfl) (fun _ not_stored => absurd stored not_stored))⟩
        · rcases List.mem_append.mp in_t with old | new
          · exact commits q old
          · obtain rfl : q = p.id := by simpa using new
            exact ⟨p, p_in_l, rfl, running_working, stored⟩
        · rcases List.mem_append.mp in_t with old | new
          · exact drivers q old
          · simp at new
      · -- the layers are not all stored (so `kept_if_same_id` has nothing to say of `Image`)
        have not_stored : ¬ AllStored layers.val p := fun stored =>
          absurd (all_stored_iff.mpr stored) (by assumption)
        -- `p.has_all(layers, |s| matches!(s, Ready | Stored))` says whether every layer it lacks
        -- is ready or stored
        refine Ok.bind (has_all_iff _ p _ ()
          (fun s => s = LayerState.Ready ∨ s = LayerState.Stored) ready_test) ?_
        intro all_ready ready_iff
        have ready_iff_all : (∀ x ∈ (alloc.vec.Vec.deref layers).val, x.id ∈ p.layers.val →
            x.state = LayerState.Ready ∨ x.state = LayerState.Stored) ↔ AllReady layers.val p := by
          simp [AllReady, alloc.vec.Vec.deref]
        rw [ready_iff_all] at ready_iff
        split
        · -- they are ready or stored: `phase = DriverPull`, `DriverPull` is pushed
          have ready := ready_iff.mp (by assumption)
          refine Ok.bind (push_appends _ _) ?_; intro out2 pushed
          refine Ok.ok.mpr ⟨⟨t ++ [Action.DriverPull p.id], by simp [pushed, grown],
            asks_more _ (Or.inr rfl), fun q in_t => ?_, fun q in_t => ?_⟩,
            walked.next more' _ (kept_if_same_id _ rfl rfl (by simp [PastPreparing])
              (fun stored => absurd stored not_stored) (fun _ _ => rfl))⟩
          · rcases List.mem_append.mp in_t with old | new
            · exact commits q old
            · simp at new
          · rcases List.mem_append.mp in_t with old | new
            · exact drivers q old
            · obtain rfl : q = p.id := by simpa using new
              exact ⟨p, p_in_l, rfl, running_working, ready, not_stored⟩
        · -- neither: the pull is as it was
          have not_ready : ¬ AllReady layers.val p := fun ready =>
            absurd (ready_iff.mpr ready) (by assumption)
          exact Ok.ok.mpr ⟨⟨t, grown, asked, commits, drivers⟩, walked.next more' _
            (kept_if_same_id _ rfl rfl (Or.inl running_working)
              (fun stored => absurd stored not_stored)
              (fun ready _ => absurd ready not_ready))⟩
    · -- not working: nothing is done, the pull is `KeptImage` as it is
      rename_i not_working
      exact Ok.ok.mpr ⟨⟨t, grown, asked, commits, drivers⟩, walked.next more' _
        (by rw [current]; exact ⟨Kept.refl _, fun working =>
          absurd (is_working.mpr working) not_working, fun working =>
          absurd (is_working.mpr working) not_working⟩)⟩
  · -- no more pulls: the loop ends, and the back function gives the pulls
    have at_end : ¬ it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    exact Ok.ok.mpr ⟨⟨t, grown, asked, commits, drivers⟩, walked.done at_end⟩

/-- The loop of `advance` over the layers (`for l in layers.iter_mut()`) changes the state of a
layer at most: each layer keeps its name. -/
theorem advance_loop2_keeps_names (l : List Layer) (iter : core.slice.iter.IterMut Layer)
    (back : core.slice.iter.IterMut Layer → core.slice.iter.IterMut Layer) (cfg : Cfg)
    (out : alloc.vec.Vec Action) (working committing : Std.Usize)
    (groups : alloc.vec.Vec Group)
    (walked : Walked (fun a b : Layer => b.id = a.id) l iter back) :
    Ok (advance_loop2 iter back cfg out working committing groups) (fun r =>
      List.Forall₂ (fun a b : Layer => b.id = a.id) l (r.2.2.2 r.2.2.1).slice.val) := by
  unfold advance_loop2
  refine Ok.loop (I := fun x => Walked (fun a b : Layer => b.id = a.id) l x.1 x.2.1) ?_ walked
  rintro ⟨it, back, out1, committing1⟩ walked
  dsimp only at walked
  walk_loop advance_loop2.body

/-- What `advance` never changes of a group: its name and the layers that wait for it.  It changes
only its state. -/
def groupKey (g : Group) : Std.U32 × alloc.vec.Vec Std.U32 := (g.id, g.needed_by)

/-- Groups with the same keys have the same names. -/
theorem names_of_keys {l l' : List Group} (same : l'.map groupKey = l.map groupKey) :
    l'.map (·.id) = l.map (·.id) := by
  simpa [List.map_map, Function.comp_def, groupKey] using congrArg (List.map Prod.fst) same

/-- The loop of `advance` over the groups of a pull (`for g in 0..groups.len()`) changes the state
of a group at most: the groups keep their names and the layers that wait for them. -/
theorem advance_loop4_loop0_keeps_keys (iter : core.ops.range.Range Std.Usize)
    (pulls : alloc.vec.Vec Pull) (v : alloc.vec.Vec Group) (out : alloc.vec.Vec Action)
    (p : Std.Usize) (limit id sent : Std.U32) :
    Ok (advance_loop4_loop0 iter pulls v out p limit id sent)
      (fun r => r.1.val.map groupKey = v.val.map groupKey) := by
  unfold advance_loop4_loop0
  refine Ok.loop (I := fun x => x.2.1.val.map groupKey = v.val.map groupKey) ?_ rfl
  rintro ⟨iter, v1, out1, sent1⟩ same_keys
  dsimp only at same_keys
  unfold advance_loop4_loop0.body
  repeat (first
    | exact Ok.ok.mpr same_keys
    | -- the pull wants the group: it is sent, the group is put back with the same key
      (refine Ok.bind (index_mut_result _ _) ?_
       rintro _ ⟨in_range, rfl⟩
       simp only [uncurry_eq]
       repeat (refine Ok.bind (Ok.any _) ?_; intro _ _)
       refine Ok.ok.mpr ?_
       dsimp only
       rw [set_val]
       refine (map_set_of_same groupKey _ _ _ in_range ?_).trans same_keys
       rfl)
    | (refine Ok.bind (Ok.any _) ?_; intro _ _)
    | simp only [uncurry_eq]
    | split)

/-- The loop of `advance` over the pulls that fetch (`for p in 0..pulls.len()`) leaves the groups
with the names and the layers that wait for them they had. -/
theorem advance_loop4_keeps_keys (iter : core.ops.range.Range Std.Usize) (cfg : Cfg)
    (pulls : alloc.vec.Vec Pull) (layers : alloc.vec.Vec Layer) (groups : alloc.vec.Vec Group)
    (starts : alloc.vec.Vec ContainerStart) (now : Std.U64) (out : alloc.vec.Vec Action) :
    Ok (advance_loop4 iter cfg pulls layers groups starts now out)
      (fun r => r.2.1.val.map groupKey = groups.val.map groupKey) := by
  unfold advance_loop4
  refine Ok.loop (I := fun x => x.2.1.val.map groupKey = groups.val.map groupKey) ?_ rfl
  rintro ⟨iter, v1, out1⟩ same_keys
  dsimp only at same_keys
  unfold advance_loop4.body
  repeat (first
    | exact Ok.ok.mpr same_keys
    | -- the inner loop sends the groups the pull wants
      (refine Ok.bind (advance_loop4_loop0_keeps_keys _ _ _ _ _ _ _ _) ?_
       rintro ⟨v2, out2⟩ keys2
       exact Ok.ok.mpr (keys2.trans same_keys))
    | (refine Ok.bind (Ok.any _) ?_; intro _ _)
    | simp only [uncurry_eq]
    | split)

/-- `advance` pushes to `out` the layers it commits and the groups it fetches (they say nothing
of a pull) and what `Asks` says of the working pulls of the core, keeps the pulls where
they are, each `Kept`, and changes the state of the layers and of the groups, not their names (nor
the layers that wait for a group: `groupKey`).
It asks for the commit of the image of a pull only when the core it leaves holds that pull at
`Image`, with every layer of the table that the pull lacks `Stored`, and for the driver's pull of a
pull only when the core it leaves holds that pull at `DriverPull`, with every layer of the table that
the pull lacks `Ready` or `Stored`. -/
theorem advance_keeps_pulls (c : Core) (now : Std.U64) (out : alloc.vec.Vec Action) :
    Ok (advance c now out) (fun r => (∃ t, r.2.val = out.val ++ t ∧
      ∀ a ∈ t, AboutNoPull a ∨ Asks c.pulls.val a) ∧
      List.Forall₂ Kept c.pulls.val r.1.pulls.val ∧
      r.1.layers.val.map (·.id) = c.layers.val.map (·.id) ∧
      r.1.groups.val.map groupKey = c.groups.val.map groupKey ∧
      (∀ p, Action.CommitImage p ∈ r.2.val.drop out.val.length →
        ∃ q ∈ r.1.pulls.val, q.id = p ∧ q.phase = Phase.Running Step.Image ∧
          AllStored r.1.layers.val q) ∧
      ∀ p, Action.DriverPull p ∈ r.2.val.drop out.val.length →
        ∃ q ∈ r.1.pulls.val, q.id = p ∧ q.phase = Phase.Running Step.DriverPull ∧
          AllReady r.1.layers.val q) := by
  unfold advance
  simp only [lift, bind_ok, alloc.vec.Vec.deref_mut, core.slice.Slice.iter_mut,
    core.slice.Slice.iter, uncurry_eq]
  -- the counts of working pulls and of commits in progress
  refine Ok.bind (Ok.any _) ?_; intro working _
  refine Ok.bind (Ok.any _) ?_; intro committing _
  -- the loop over the layers only pushes actions that say nothing of a pull, and keeps the names
  refine Ok.bind
    (((advance_loop2_kinds _ _ _ _ _ _ _).appends.mono fun _ h => h.noPull).and
      (advance_loop2_keeps_names c.layers.val _ _ _ _ _ _ _
        ⟨rfl, fun it' _ => ⟨[], by simp, by simp⟩⟩)) ?_
  intro r0 ⟨no_pull0, names0⟩
  simp only [uncurry_eq]
  obtain ⟨t0, pushed0, none_about0⟩ := AppendsOnly.appended no_pull0
  -- the loop over the pulls: the step that matters, at the start the iterator is at 0
  refine Ok.bind (advance_loop3_keeps_pulls c.pulls.val _ _ _ _ ?_) ?_
  · exact ⟨rfl, fun it' _ => ⟨[], by simp, by simp⟩⟩
  intro r1 ⟨⟨t1, pushed1, asks1, commits1, drivers1⟩, kept⟩
  simp only [uncurry_eq]
  -- the loop over the groups only pushes actions that say nothing of a pull, and keeps the names
  refine Ok.bind
    (((advance_loop4_kinds _ _ _ _ _ _ _ _).appends.mono fun _ h => h.noPull).and
      (advance_loop4_keeps_keys _ _ _ _ _ _ _ _)) ?_
  rintro ⟨c2, v, out3⟩ ⟨no_pull2, keys2⟩
  obtain ⟨t2, pushed2, none_about2⟩ := AppendsOnly.appended no_pull2
  refine Ok.ok.mpr ⟨⟨t0 ++ t1 ++ t2, by simp [pushed2, pushed1, pushed0], ?_⟩,
    kept.imp fun _ _ k => k.1, map_eq_of_forall₂ (fun l : Layer => l.id) names0, keys2, ?_, ?_⟩
  · intro a ha
    simp only [List.mem_append] at ha
    rcases ha with (ha | ha) | ha
    exacts [Or.inl (none_about0 a ha), Or.inr (asks1 a ha), Or.inl (none_about2 a ha)]
  · -- the commit of an image was asked in the loop over the pulls, for a pull that is left at `Image`
    intro p asked_p
    have drop_is : out3.val.drop out.val.length = t0 ++ t1 ++ t2 := by
      rw [pushed2, pushed1, pushed0]; simp
    rw [drop_is] at asked_p
    simp only [List.mem_append] at asked_p
    rcases asked_p with (in_t0 | in_t1) | in_t2
    · exact absurd (none_about0 _ in_t0 p) (by simp [about])
    · obtain ⟨y, in_c, named, working, stored⟩ := commits1 p in_t1
      obtain ⟨y', in_c', ⟨⟨same_id, _, same_layers, _⟩, image, _⟩⟩ := forall₂_mem_left kept in_c
      exact ⟨y', in_c', same_id.trans named, image working stored,
        fun x in_x lacked => stored x in_x (same_layers ▸ lacked)⟩
    · exact absurd (none_about2 _ in_t2 p) (by simp [about])
  · -- the driver's pull was asked in the loop over the pulls, for a pull that is left at `DriverPull`
    intro p asked_p
    have drop_is : out3.val.drop out.val.length = t0 ++ t1 ++ t2 := by
      rw [pushed2, pushed1, pushed0]; simp
    rw [drop_is] at asked_p
    simp only [List.mem_append] at asked_p
    rcases asked_p with (in_t0 | in_t1) | in_t2
    · exact absurd (none_about0 _ in_t0 p) (by simp [about])
    · obtain ⟨y, in_c, named, working, ready, not_stored⟩ := drivers1 p in_t1
      obtain ⟨y', in_c', ⟨⟨same_id, _, same_layers, _⟩, _, driver⟩⟩ := forall₂_mem_left kept in_c
      exact ⟨y', in_c', same_id.trans named, driver working ready not_stored,
        fun x in_x lacked => ready x in_x (same_layers ▸ lacked)⟩
    · exact absurd (none_about2 _ in_t2 p) (by simp [about])

/-- `Core.lacking` returns the names of pulls of the core that are working. -/
theorem lacking_working (c : Core) (layers : Slice Std.U32) :
    Ok (Core.lacking c layers) (fun v => ∀ x ∈ v.val,
      ∃ q ∈ c.pulls.val, q.id = x ∧ q.phase = Phase.Running Step.Working) := by
  unfold Core.lacking
  simp only [core.slice.Slice.iter, bind_ok]
  unfold Core.lacking_loop
  refine Ok.loop (I := fun x : core.slice.iter.Iter Pull × alloc.vec.Vec Std.U32 =>
      x.1.slice.val = c.pulls.val ∧ ∀ y ∈ x.2.val,
    ∃ q ∈ c.pulls.val, q.id = y ∧ q.phase = Phase.Running Step.Working) ?_
    ⟨by simp [alloc.vec.Vec.deref], by simp [alloc.vec.Vec.new]⟩
  rintro ⟨it, found⟩ ⟨slice_is, inv⟩
  dsimp only at slice_is inv
  unfold Core.lacking_loop.body core.slice.iter.IteratorSliceIter.next
  dsimp only
  by_cases more : it.i < it.slice.len
  · have more' : it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    generalize hg : it.slice[it.i] = p
    have current : it.slice.val[it.i] = p := hg
    refine Ok.bind (working_iff p) ?_; intro b is_working
    split
    · have running_working := is_working.mp (by assumption)
      refine Ok.bind (Ok.any _) ?_; intro i _
      refine Ok.bind (Ok.any _) ?_; rintro ⟨b1, _⟩ _
      by_cases b1_true : b1 = true
      · simp only [b1_true]
        refine Ok.bind (push_appends _ _) ?_; intro found1 pushed
        refine Ok.ok.mpr ⟨slice_is, fun y hy => ?_⟩
        rw [pushed] at hy
        rcases List.mem_append.mp hy with hy | hy
        · exact inv y hy
        · rw [List.mem_singleton.mp hy]
          have p_in : p ∈ c.pulls.val := by
            rw [← current, ← slice_is]; exact List.getElem_mem more'
          exact ⟨p, p_in, rfl, running_working⟩
      · simp only [b1_true]
        exact Ok.ok.mpr ⟨slice_is, inv⟩
    · exact Ok.ok.mpr ⟨slice_is, inv⟩
  · simp only [more, ↓reduceDIte, bind_ok]
    exact Ok.ok.mpr inv

/-- `Core.lacking` returns the name of every working pull of the core that lacks one of the
layers (one of the layers is among the layers of the pull). -/
theorem lacking_complete (c : Core) (layers : Slice Std.U32) :
    Ok (Core.lacking c layers) (fun v => ∀ q ∈ c.pulls.val,
      q.phase = Phase.Running Step.Working → (∃ l ∈ layers.val, l ∈ q.layers.val) →
      q.id ∈ v.val) := by
  unfold Core.lacking
  simp only [core.slice.Slice.iter, bind_ok]
  unfold Core.lacking_loop
  -- the loop has gone through the pulls before `it.i`: those that qualify are in `found`
  refine Ok.loop (I := fun x : core.slice.iter.Iter Pull × alloc.vec.Vec Std.U32 =>
      x.1.slice.val = c.pulls.val ∧ ∀ j (hj : j < c.pulls.val.length), j < x.1.i →
        (c.pulls.val[j]).phase = Phase.Running Step.Working →
        (∃ l ∈ layers.val, l ∈ (c.pulls.val[j]).layers.val) →
        (c.pulls.val[j]).id ∈ x.2.val) ?_
    ⟨by simp [alloc.vec.Vec.deref], fun _ _ hj => absurd hj (by simp)⟩
  rintro ⟨it, found⟩ ⟨slice_is, walked⟩
  dsimp only at slice_is walked
  unfold Core.lacking_loop.body core.slice.iter.IteratorSliceIter.next
  dsimp only
  by_cases more : it.i < it.slice.len
  · -- there is a pull `p`
    have more' : it.i < it.slice.val.length := by simpa using more
    have more'' : it.i < c.pulls.val.length := by rw [← slice_is]; exact more'
    simp only [more, ↓reduceDIte, bind_ok]
    generalize hg : it.slice[it.i] = p
    have current : c.pulls.val[it.i] = p := by
      have : it.slice.val[it.i] = p := hg
      simpa [slice_is] using this
    refine Ok.bind (working_iff p) ?_; intro b is_working
    -- whatever the round pushes, the pulls up to and including `p` are in `found1` if
    -- `p` is when it qualifies
    have walked_on : ∀ found1 : alloc.vec.Vec Std.U32, (∀ y ∈ found.val, y ∈ found1.val) →
        (p.phase = Phase.Running Step.Working → (∃ l ∈ layers.val, l ∈ p.layers.val) →
          p.id ∈ found1.val) →
        ∀ j (hj : j < c.pulls.val.length), j < it.i + 1 →
          (c.pulls.val[j]).phase = Phase.Running Step.Working →
          (∃ l ∈ layers.val, l ∈ (c.pulls.val[j]).layers.val) →
          (c.pulls.val[j]).id ∈ found1.val := by
      intro found1 kept this_one j hj before_next working lacks
      rcases Nat.lt_or_eq_of_le (Nat.lt_succ_iff.mp before_next) with earlier | same
      · exact kept _ (walked j hj earlier working lacks)
      · subst same
        rw [current] at working lacks ⊢
        exact this_one working lacks
    split
    · -- `p.working()`: `layers.iter().any(|l| p.lacks(*l))`
      -- the test of the closure of `lacking`: "does the pull lack the layer?"
      have answers : ∀ x : Std.U32,
          Core.lacking.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool.call_mut p x =
            ok (decide (x ∈ p.layers.val), p) := fun x => by
        simp [Core.lacking.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool.call_mut,
          lacks_iff]
      obtain ⟨_, found_any⟩ := any_iff
        Core.lacking.closure.Insts.CoreOpsFunctionFnMutTupleShared0U32Bool
        (fun x => x ∈ p.layers.val) layers p answers
      simp only [core.slice.Slice.iter, found_any, bind_ok]
      by_cases lacks_one : ∃ x ∈ layers.val, x ∈ p.layers.val
      · -- it lacks one: its name is pushed
        simp only [lacks_one, decide_true]
        refine Ok.bind (push_appends _ _) ?_; intro found1 pushed
        refine Ok.ok.mpr ⟨slice_is, walked_on found1 ?_ ?_⟩
        · intro y hy; rw [pushed]; exact List.mem_append_left _ hy
        · intro _ _; rw [pushed]; simp
      · -- it lacks none
        simp only [lacks_one, decide_false]
        exact Ok.ok.mpr
          ⟨slice_is, walked_on found (fun _ h => h) fun _ lacks => absurd lacks lacks_one⟩
    · -- not working: it does not qualify
      rename_i not_working
      refine Ok.ok.mpr ⟨slice_is, walked_on found (fun _ h => h) ?_⟩
      intro working
      exact absurd (is_working.mpr working) not_working
  · -- no more pulls: all of them were gone through
    simp only [more, ↓reduceDIte, bind_ok]
    refine Ok.ok.mpr fun q in_pulls working lacks => ?_
    obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem in_pulls
    exact walked j hj (by simp [slice_is] at more; omega) working lacks

/-- The loop of `progress` over the pulls (`for p in pulls.iter_mut()`) leaves every pull `Kept`:
it only sets `progressed` of the working ones. -/
theorem progress_loop_keeps_pulls (l : List Pull) (iter : core.slice.iter.IterMut Pull)
    (back : core.slice.iter.IterMut Pull → core.slice.iter.IterMut Pull)
    (layers : Slice Std.U32) (walked : Walked Kept l iter back) :
    Ok (progress_loop iter back layers) (fun r => List.Forall₂ Kept l r.slice.val) := by
  unfold progress_loop
  refine Ok.loop (I := fun x => Walked Kept l x.1 x.2) ?_ walked
  rintro ⟨it, back⟩ walked
  dsimp only at walked
  walk_loop progress_loop.body

/-- `progress` keeps every pull as it is, but for `progressed`: each is `Kept`; the layers and
the groups are as they were. -/
theorem progress_keeps_pulls (c : Core) (layers : Slice Std.U32) :
    Ok (progress c layers) (fun r => List.Forall₂ Kept c.pulls.val r.pulls.val ∧
      r.layers = c.layers ∧ r.groups = c.groups) := by
  unfold progress
  simp only [lift, bind_ok, alloc.vec.Vec.deref_mut, core.slice.Slice.iter_mut,
    uncurry_eq]
  refine Ok.bind (progress_loop_keeps_pulls c.pulls.val _ _ _
    ⟨rfl, fun it' _ => ⟨[], by simp, by simp⟩⟩) ?_
  intro back kept
  exact Ok.ok.mpr ⟨kept, rfl, rfl⟩

/-- `start_at` hands out a record of the starts and a way to put it back, which leaves the pulls,
the layers and the groups as they were. -/
theorem start_at_keeps_pulls (c : Core) (layer : Std.U32) (now : Std.U64) :
    Ok (start_at c layer now) (fun r => ∀ cs, (r.2 cs).pulls = c.pulls ∧
      (r.2 cs).layers = c.layers ∧ (r.2 cs).groups = c.groups) := by
  unfold start_at
  refine Ok.bind (Ok.any _) ?_; intro v _
  refine Ok.bind (Ok.any _) ?_; intro i _
  refine Ok.bind (Ok.any _) ?_; rintro ⟨o, it⟩ _
  cases o with
  | none =>
    simp only []
    refine Ok.bind (Ok.any _) ?_; intro v1 _
    refine Ok.bind (Ok.any _) ?_; intro at_ _
    refine Ok.bind (Ok.any _) ?_; rintro ⟨cs, back⟩ _
    exact Ok.ok.mpr fun _ => ⟨rfl, rfl, rfl⟩
  | some at_ =>
    simp only []
    refine Ok.bind (Ok.any _) ?_; rintro ⟨cs, back⟩ _
    exact Ok.ok.mpr fun _ => ⟨rfl, rfl, rfl⟩

/-- `saturating_add` of two times is their sum, or the last time there is. -/
theorem saturating_add_val (x y : Std.U64) :
    (core.num.U64.saturating_add x y).val = min (x.val + y.val) Std.U64.max := by
  unfold core.num.U64.saturating_add UScalar.saturating_add
  simp only [UScalar.val, BitVec.toNat_ofNat]
  rw [Nat.mod_eq_of_lt (by scalar_tac), Nat.min_comm]
  congr 1
  scalar_tac

/-- `TryEnded c at_ id out s r`: `try_failed` ended the try of the pull `id` (which was at
`at_` among the pulls of `c`): after the actions already in `out` it pushed `Record id s`,
then some more, then `End id`, and the names of the pulls that are left are those of
`c` without the pull at `at_`. -/
def TryEnded (c : Core) (at_ : Nat) (id : Std.U32) (out : alloc.vec.Vec Action) (s : State)
    (r : Core × alloc.vec.Vec Action) : Prop :=
  (∃ t, (out.val ++ [Action.Record id s] ++ t ++ [Action.End id]) <+: r.2.val) ∧
  r.1.pulls.val.map (·.id) = (c.pulls.val.eraseIdx at_).map (·.id)

/-- `TryWaits c at_ id out s u r`: `try_failed` made the try of the pull `id` wait until
`u`: it pushed `Record id s`, then some more, then `Wake u`, and the pull is still at `at_`,
waiting until `u`. -/
def TryWaits (at_ : Nat) (id : Std.U32) (out : alloc.vec.Vec Action) (s : State) (u : Std.U64)
    (r : Core × alloc.vec.Vec Action) : Prop :=
  (∃ t, (out.val ++ [Action.Record id s] ++ t ++ [Action.Wake u]) <+: r.2.val) ∧
  ∃ h : at_ < r.1.pulls.val.length,
    (r.1.pulls.val[at_]).id = id ∧ (r.1.pulls.val[at_]).phase = Phase.Waiting u

/-- What a failure of class `cl` makes of the try of the pull named `id`, at `at_` among
the pulls of `c`: the cases of the statement in Spec.lean, in terms of `try_failed`'s
own result `r`. -/
def Verdict (c : Core) (now : Std.U64) (at_ : Nat) (id : Std.U32) (cl : Class)
    (out : alloc.vec.Vec Action) (r : Core × alloc.vec.Vec Action) : Prop :=
  match cl, c.cfg.retries with
  | Class.Credentials, _ => TryEnded c at_ id out State.NeedsCredentials r
  | Class.Fatal, _ => TryEnded c at_ id out State.Failed r
  | _, false => TryEnded c at_ id out State.Failed r
  | Class.NoSpace, true => ∃ u : Std.U64, u.val = min (now.val + 60000) Std.U64.max ∧
      TryWaits at_ id out (State.NoSpace u) u r
  | Class.Transient, true => ∃ (u : Std.U64) (wait : Nat),
      u.val = min (now.val + wait) Std.U64.max ∧
      wait ≤ c.cfg.retry_max.val * 1000 ∧ (1 ≤ c.cfg.retry_max.val → 1000 ≤ wait) ∧
      TryWaits at_ id out (State.Backoff u) u r

/-- `try_failed` of the pull at `at_` does what `Verdict` says of its class: it decides by
the class and the setting `retries`, records the state, and then either `leave`s the pull
or `let_go`s and asks to be woken at the end of the wait. -/
theorem try_failed_verdict (c : Core) (now : Std.U64) (at_ : Std.Usize) (cl : Class)
    (out : alloc.vec.Vec Action) (in_range : at_.val < c.pulls.val.length) :
    Ok (try_failed c now at_ cl out)
      (Verdict c now at_.val (c.pulls.val[at_.val]).id cl out) := by
  -- the pull is over: after `Record`, `leave` ends it (the end of `try_failed` for the
  -- classes that do not wait)
  have ends : ∀ (q : Pull) (out1 : alloc.vec.Vec Action) (s : State),
      q.id = (c.pulls.val[at_.val]).id →
      out1.val = out.val ++ [Action.Record (c.pulls.val[at_.val]).id s] →
      Ok (leave { c with pulls := c.pulls.set at_ q } at_ out1)
        (TryEnded c at_.val (c.pulls.val[at_.val]).id out s) := by
    intro q out1 s same_name pushed_record
    refine (leave_removes_the_pull _ _ _).mono ?_
    rintro r ⟨h, t, pushed, names⟩
    refine ⟨⟨t, ?_⟩, ?_⟩
    · simpa [pushed_record, alloc.vec.Vec.set, in_range, same_name] using pushed
    · simpa [alloc.vec.Vec.set, eraseIdx_set] using names
  -- the pull waits: after `Record`, `let_go` and `Wake u` (the end of `try_failed` for
  -- `NoSpace` and `Transient`)
  have waits : ∀ (q : Pull) (out1 : alloc.vec.Vec Action) (s : State) (u : Std.U64),
      q.id = (c.pulls.val[at_.val]).id → q.phase = Phase.Waiting u →
      out1.val = out.val ++ [Action.Record (c.pulls.val[at_.val]).id s] →
      Ok (do
          let (c2, out2) ← let_go { c with pulls := c.pulls.set at_ q } at_ out1
          let out3 ← alloc.vec.Vec.push out2 (Action.Wake u)
          ok (c2, out3))
        (TryWaits at_.val (c.pulls.val[at_.val]).id out s u) := by
    intro q out1 s u same_name waiting pushed_record
    refine Ok.bind (let_go_changes_layers _ _ _) ?_
    rintro ⟨c2, out2⟩ ⟨⟨⟨t, pushed_by_let_go⟩, _⟩, _, h, ls, pulls2⟩
    dsimp only at pulls2 pushed_by_let_go
    simp only [uncurry_eq]
    refine Ok.bind (push_appends _ _) ?_; intro out3 pushed_wake
    apply Ok.ok.mpr
    refine ⟨⟨t, ?_⟩, ?_⟩
    · simp [pushed_wake, ← pushed_by_let_go, pushed_record]
    · simp [pulls2, alloc.vec.Vec.set, in_range, same_name, waiting]
  -- the body of `try_failed`: the pull is taken (`&mut c.pulls[at]`), and `match class`
  unfold try_failed Verdict
  rw [index_mut_in_range _ _ in_range]
  simp only [bind_ok, uncurry_eq]
  split <;> cases cl <;> simp only [bind_ok]
  -- `Credentials` and `Fatal`: `Record`, then `leave`
  all_goals try (refine Ok.bind (push_appends _ _) ?_; intro out1 pushed_record
                 exact ends _ _ _ rfl pushed_record)
  -- the other classes depend on `retries`: without it the state is `Failed` and the pull is over
  all_goals cases hr : c.cfg.retries <;>
    simp only [Bool.false_eq_true, ↓reduceIte, bind_ok, lift, Std.bind_assoc, uncurry_eq]
  all_goals try (refine Ok.bind (push_appends _ _) ?_; intro out1 pushed_record
                 exact ends _ _ _ rfl pushed_record)
  -- `NoSpace` with retries: waits `SPACE_WAIT` (a minute) from now
  all_goals try (
    refine Ok.bind (push_appends _ _) ?_; intro out1 pushed_record
    refine Ok.mono (waits _ _ _ _ ?_ ?_ pushed_record) ?_
    · rfl
    · rfl
    · exact fun r hr => ⟨_, by rw [saturating_add_val]; simp [SPACE_WAIT], hr⟩)
  -- `Transient` with retries: waits `backoff`, which has the bounds of the statement
  all_goals (
    refine Ok.bind (backoff_bounds _ _) ?_; rintro wait ⟨at_most, at_least⟩
    refine Ok.bind (push_appends _ _) ?_; intro out1 pushed_record
    refine Ok.mono (waits _ _ _ _ ?_ ?_ pushed_record) ?_
    · rfl
    · rfl
    · exact fun r hr => ⟨_, wait.val, saturating_add_val _ _, at_most, at_least, hr⟩)

/-- The loop of `failed` (`for pull in failing`) over the list `[p]` of one pull: it looks
the pull up and calls `try_failed` for it, and ends with what that call gives (`P`). -/
theorem failed_loop0_one (c : Core) (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action)
    (p : Std.U32) (iter : alloc.vec.into_iter.IntoIter Std.U32) (one : iter.val = [p])
    (P : Core × alloc.vec.Vec Action → Prop)
    (looked_up : Ok (Core.pull_at c p)
      (fun o => ∃ n, o = some n ∧ Ok (try_failed c now n cl out) P)) :
    Ok (failed_loop0 iter c now cl out) P := by
  unfold failed_loop0
  -- the invariant: before the round `[p]` is left and nothing is changed;
  -- after it nothing is left and `P` holds
  refine Ok.loop (I := fun x => (x.1.val = [p] ∧ x.2.1 = c ∧ x.2.2 = out) ∨
    (x.1.val = [] ∧ P (x.2.1, x.2.2))) ?_ (Or.inl ⟨one, rfl, rfl⟩)
  rintro ⟨it, c1, out1⟩ state
  dsimp only at state
  unfold failed_loop0.body alloc.vec.into_iter.IteratorIntoIter.next
  dsimp only
  rcases state with ⟨left, rfl, rfl⟩ | ⟨left, done⟩
  · split
    · rename_i empty; rw [left] at empty; cases empty
    · -- the round: `pull_at`, then `try_failed`
      rename_i hd tl next
      rw [left] at next; cases next
      simp only [bind_ok, uncurry_eq]
      refine Ok.bind looked_up ?_
      rintro o ⟨n, rfl, tried⟩
      simp only []
      refine Ok.bind tried ?_
      rintro ⟨c2, out2⟩ result
      exact Ok.ok.mpr (Or.inr ⟨rfl, result⟩)
  · -- the next round finds the list empty: the loop ends
    split
    · simp only [bind_ok]; exact Ok.ok.mpr done
    · rename_i hd tl next; rw [left] at next; cases next

/-- The three loops of `failed` (`for pull in failing`, for the one pull that runs, for the
pulls that lack a layer, for those that wait for a group) are the same function: Aeneas
extracts each as one of its own, with the same body. -/
theorem failed_loops_are_the_same : failed_loop1 = failed_loop0 ∧ failed_loop2 = failed_loop0 :=
  ⟨rfl, rfl⟩

/-- `failed` of `Work::Pull p`, for a pull that runs at place `j` among distinct names,
calls `try_failed` for that pull and no other, and so does what `Verdict` says. -/
theorem failed_pull_verdict (c : Core) (now : Std.U64) (p : Std.U32) (cl : Class)
    (out : alloc.vec.Vec Action) (distinct : (c.pulls.val.map (·.id)).Nodup)
    (j : Nat) (in_range : j < c.pulls.val.length) (named_p : (c.pulls.val[j]).id = p)
    (s : Step) (running : (c.pulls.val[j]).phase = Phase.Running s) :
    Ok (failed c now (Work.Pull p) cl out) (Verdict c now j p cl out) := by
  -- the pull is found, at `j`, and `try_failed` of it does what is wanted
  have found : Ok (Core.pull_at c p)
      (fun o => ∃ n, o = some n ∧ n.val = j ∧
        Ok (try_failed c now n cl out) (Verdict c now j p cl out)) := by
    refine (pull_at_unique c p distinct j in_range named_p).mono ?_
    rintro o ⟨n, rfl, rfl⟩
    exact ⟨n, rfl, rfl, named_p ▸ try_failed_verdict c now n cl out in_range⟩
  -- `failed`: `Work::Pull`: the pull is found, its phase is `Running _`: `failing = vec![pull]`
  unfold failed
  simp only []
  refine Ok.bind found ?_
  rintro o ⟨n, rfl, rfl, _⟩
  simp only []
  rw [index_in_range _ _ in_range]
  simp only [bind_ok, running, lift]
  have one : Ok (alloc.vec.IntoIteratorVec.into_iter
      (alloc.slice.Slice.into_vec (Std.Array.to_slice (Array.make 1#usize [p]))))
      (fun it => it.val = [p]) := Ok.ok.mpr rfl
  refine Ok.bind one ?_
  intro it is_p
  -- then the loop `for pull in failing` over that one pull
  refine failed_loop0_one c now cl out p it is_p _ (found.mono ?_)
  rintro o ⟨m, rfl, _, tried⟩
  exact ⟨m, rfl, tried⟩

/-- When each pull is `Kept`, the names of the pulls are the same. -/
theorem kept_names {l l' : List Pull} (kept : List.Forall₂ Kept l l') :
    l'.map (·.id) = l.map (·.id) :=
  map_eq_of_forall₂ (·.id) (kept.imp fun _ _ k => k.1)

/-- When each pull is `Kept`, the pull at place `j` is still there, with the same name, and
if it was not working it has the same phase. -/
theorem kept_at {l l' : List Pull} (kept : List.Forall₂ Kept l l') (j : Nat)
    (in_range : j < l.length) :
    ∃ in_range' : j < l'.length, Kept l[j] l'[j] := by
  induction kept generalizing j with
  | nil => simp at in_range
  | cons head _ ih =>
    cases j with
    | zero => exact ⟨by simp, head⟩
    | succ j =>
      obtain ⟨in_range', kept_j⟩ := ih j (by simpa using in_range)
      exact ⟨by simpa using in_range', by simpa using kept_j⟩

/-- With distinct names, the name of the pull at `j` is not among the names of the other pulls. -/
theorem name_not_in_others (l : List Pull) (distinct : (l.map (·.id)).Nodup) (j : Nat)
    (in_range : j < l.length) : l[j].id ∉ (l.eraseIdx j).map (·.id) := by
  induction l generalizing j with
  | nil => simp at in_range
  | cons a l ih =>
    simp only [List.map_cons, List.nodup_cons] at distinct
    cases j with
    | zero => simpa using distinct.1
    | succ j =>
      simp only [List.eraseIdx_cons_succ, List.map_cons, List.mem_cons, List.getElem_cons_succ,
        not_or]
      have in_tail : j < l.length := by simpa using in_range
      refine ⟨fun same => distinct.1
        (same ▸ List.mem_map.mpr ⟨l[j], List.getElem_mem in_tail, rfl⟩), ih distinct.2 j in_tail⟩

/-- **The verdict of a failure** (the statement of Spec.lean).  `step` on `Done (Pull p) (Err cl)`
is `failed` for the pull, then `advance`.  `failed` gives the verdict (`Verdict`); `advance`
only adds actions and keeps the pulls `Kept`, so a pull that is gone stays gone and one that
waits still waits; the verdict read in the final core and `out` is the statement. -/
theorem the_verdict_of_a_failure : TheVerdictOfAFailure := by
  rintro c now p s cl out c' out' distinct ⟨q, hq, hqp, hqs⟩ returns
  obtain ⟨j, in_range, rfl⟩ := List.getElem_of_mem hq
  have verdict_then_advance :
      Ok (step c now (Event.Done (Work.Pull p) (core.result.Result.Err cl)) out)
      (fun r => ∃ r1, Verdict c now j p cl out r1 ∧ r1.2.val <+: r.2.val ∧
        List.Forall₂ Kept r1.1.pulls.val r.1.pulls.val) := by
    unfold step
    simp only []
    -- `failed`
    refine Ok.bind (failed_pull_verdict c now p cl out distinct j in_range hqp s hqs) ?_
    rintro ⟨c1, out1⟩ verdict
    simp only [uncurry_eq]
    -- `advance`
    exact (advance_keeps_pulls c1 now out1).mono
      fun r hr => ⟨_, verdict, ⟨hr.1.choose, hr.1.choose_spec.1.symm⟩, hr.2.1⟩
  obtain ⟨⟨c1, out1⟩, verdict, grown, kept⟩ := verdict_then_advance.eq returns
  dsimp only at grown kept
  -- a `TryEnded` verdict gives the statement's `over`: `Record` and `End` were asked for
  -- (`out` only grew), and the pull is not in the final core (the names are those of
  -- `c1`, which are those of `c` without the pull)
  have over_gives_spec : ∀ st, TryEnded c j p out st (c1, out1) → over c' out out' p st := by
    rintro st ⟨⟨t, pushed⟩, names⟩
    have pushed' : (out.val ++ ([Action.Record p st] ++ t ++ [Action.End p])) <+: out'.val := by
      simpa using pushed.trans grown
    refine ⟨asked_if_appended pushed' (by simp), asked_if_appended pushed' (by simp), ?_⟩
    rintro ⟨q', hq', named_p⟩
    have in_names : p ∈ c'.pulls.val.map (·.id) := List.mem_map.mpr ⟨q', hq', named_p⟩
    rw [kept_names kept, names] at in_names
    exact name_not_in_others _ distinct j in_range (hqp ▸ in_names)
  -- a `TryWaits` verdict gives `waits`: `Record` and `Wake u` were asked for, and the pull
  -- is still there, waiting until `u`, as `advance` does not change a pull that is not working
  have waits_gives_spec : ∀ st u, TryWaits j p out st u (c1, out1) → waits c' out out' p st u := by
    rintro st u ⟨⟨t, pushed⟩, h, named_p, waiting⟩
    have pushed' : (out.val ++ ([Action.Record p st] ++ t ++ [Action.Wake u])) <+: out'.val := by
      simpa using pushed.trans grown
    refine ⟨asked_if_appended pushed' (by simp), asked_if_appended pushed' (by simp), ?_⟩
    obtain ⟨in_range', kept_j⟩ := kept_at kept j h
    exact ⟨_, List.getElem_mem in_range', kept_j.1.trans named_p,
      (kept_j.2.1 (by rw [waiting]; simp)).trans waiting⟩
  -- the cases of the class, as in the statement
  unfold Verdict at verdict
  cases cl <;> cases hr : c.cfg.retries <;> simp only [hr] at verdict ⊢
  all_goals first
    | exact over_gives_spec _ verdict
    | (obtain ⟨u, is_after, tried⟩ := verdict; exact ⟨u, is_after, waits_gives_spec _ _ tried⟩)
    | (obtain ⟨u, w, is_after, at_most, at_least, tried⟩ := verdict;
       exact ⟨u, w, is_after, at_most, at_least, waits_gives_spec _ _ tried⟩)

end LazyCore
