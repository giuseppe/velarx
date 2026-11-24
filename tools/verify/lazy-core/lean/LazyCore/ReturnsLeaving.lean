-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the functions of lib.rs that begin the try of a pull and make a pull
-- leave return: `begin_try`, `let_go` (with its two loops), `leave` (with its loop),
-- `try_failed` and `add`.  Each lemma says that the function returns, that the tables it leaves
-- are short, and how many actions it pushed at most (`begin_try` two; `let_go` two for each layer
-- and each group; `leave` the `End`, and the ones `begin_try` pushes for the pulls that move up).
--
-- Why it is needed: `cancel`, `failed`, `succeeded`, `prepared` and `step` itself call these, so
-- the claim that `step` returns rests on them.  They are also the functions that index the pulls
-- by a place (`c.pulls[at]`): every lemma asks that the place be inside the table, and `leave`
-- says that the table has one pull less, so that the loops that go on after it stay inside.
--
-- Read before this file: Spec.lean, ReturnsBasics.lean, ReturnsQueries.lean, and in lib.rs
-- `begin_try`, `let_go`, `leave`, `try_failed` and `add`.
--
-- The tactics a reader meets in the proofs.  `step*` follows the Rust function line by line: for
-- each call it uses the lemma of this development that says when the call returns and what it
-- gives (the lemmas marked `@[step]`), and leaves what is to be shown (that a `Vec` has room, that
-- an index is inside) as goals.  `step as ⟨x, hx⟩` does one line and names the result `x` and what
-- is known of it `hx`.  `loop.spec_decr_nat` proves that a loop returns because a number goes down
-- at each turn (here, the elements left to read) while a fact (the invariant) is kept.
-- `bookkeeping` (ReturnsBasics.lean) closes the goals that are only sums of lengths.
--
-- Notation: `m ⦃ c1 out1 => P ⦄` is "the call returns the core `c1` and the actions `out1`, and
-- `P` holds"; `Short c` is "no table of `c` holds more than 2^25 entries" (Spec.lean);
-- `out.val.length` is the number of actions in `out`.
import LazyCore.ReturnsQueries

open Aeneas Aeneas.Std Result velarx_lazy_core
open Aeneas.Data.Coinductive

namespace LazyCore


/-- `begin_try` pushes two actions and keeps the tables as many as they were. -/
@[step] theorem begin_try_returns (on64 : OnA64BitMachine) (c : Core) (at_ : Std.Usize)
    (out : alloc.vec.Vec Action) (inside : at_.val < c.pulls.val.length)
    (room : out.val.length + 2 ≤ 2 ^ 63) :
    begin_try c at_ out ⦃ r => r.1.pulls.val.length = c.pulls.val.length ∧
      r.1.layers = c.layers ∧ r.1.groups = c.groups ∧ r.1.starts = c.starts ∧
      r.2.val.length ≤ out.val.length + 2 ⦄ := by
  have max_is := usize_max_is on64
  unfold begin_try
  -- the pull is found (its place is inside), two actions are pushed, the pull is put back
  step*
  bookkeeping

/-- The loop of `let_go` over the layers pushes at most two actions for each. -/
@[step] theorem let_go_loop0_returns (on64 : OnA64BitMachine) (iter : core.slice.iter.Iter Layer)
    (out : alloc.vec.Vec Action) (mine : alloc.vec.Vec Std.U32) (pulls : alloc.vec.Vec Pull)
    (i_le : iter.i ≤ iter.slice.val.length)
    (room : out.val.length + 2 * (iter.slice.val.length - iter.i) ≤ 2 ^ 63) :
    let_go_loop0 iter out mine pulls ⦃ r =>
      r.val.length ≤ out.val.length + 2 * (iter.slice.val.length - iter.i) ⦄ := by
  have max_is := usize_max_is on64
  unfold let_go_loop0
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length ∧
      p.2.val.length + 2 * (iter.slice.val.length - p.1.i) ≤
        out.val.length + 2 * (iter.slice.val.length - iter.i))
  · rintro ⟨it, acc⟩ ⟨same, i_le, room⟩
    dsimp only at same i_le room
    unfold let_go_loop0.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho⟩
    rcases ho with ⟨more, x, rfl, same1, i1⟩ | ⟨done, rfl, rfl⟩
    · simp only
      step as ⟨b⟩
      split
      · step as ⟨b1⟩
        split <;> step* <;> simp_all <;> omega
      · step*
        simp_all
        omega
    · simp only
      step*
  · exact ⟨rfl, i_le, by dsimp only; omega⟩

/-- The loop of `let_go` over the groups pushes at most two actions for each and puts the groups
back in as many. -/
@[step] theorem let_go_loop1_returns (on64 : OnA64BitMachine) (iter : core.slice.iter.IterMut Group)
    (back : core.slice.iter.IterMut Group → core.slice.iter.IterMut Group)
    (out : alloc.vec.Vec Action) (me : Std.U32) (pulls : alloc.vec.Vec Pull)
    (i_le : iter.i ≤ iter.slice.val.length)
    (room : out.val.length + 2 * (iter.slice.val.length - iter.i) ≤ 2 ^ 63)
    (back_ok : ∀ it', (back it').slice.val.length = it'.slice.val.length) :
    let_go_loop1 iter back out me pulls ⦃ out2 im back2 =>
      out2.val.length ≤ out.val.length + 2 * (iter.slice.val.length - iter.i) ∧
      im.slice = iter.slice ∧ ∀ it', (back2 it').slice.val.length = it'.slice.val.length ⦄ := by
  have max_is := usize_max_is on64
  unfold let_go_loop1
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.slice.val.length - p.1.i)
    (fun p => p.1.slice = iter.slice ∧ p.1.i ≤ iter.slice.val.length ∧
      (∀ it', (p.2.1 it').slice.val.length = it'.slice.val.length) ∧
      p.2.2.val.length + 2 * (iter.slice.val.length - p.1.i) ≤
        out.val.length + 2 * (iter.slice.val.length - iter.i))
  · rintro ⟨it, back1, acc⟩ ⟨same, i_le, back_ok, room⟩
    dsimp only at same i_le back_ok room
    unfold let_go_loop1.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, next_back, same1, next_ok, ho⟩
    rcases ho with ⟨more, x, rfl, i1⟩ | ⟨done, rfl, i1⟩
    · simp only
      step as ⟨o1⟩
      rcases o1 with _ | other
      · simp only
        split <;> step* <;> bookkeeping
      · simp only
        step*
        all_goals bookkeeping
    · simp only
      step*
      simp_all
  · exact ⟨rfl, i_le, back_ok, by dsimp only; omega⟩

/-- The test of the closure of `let_go` on a layer (that no pull lacks it) returns. -/
theorem let_go_layer_closure_returns (p : let_go.closure) (y : Layer) :
    let_go.closure.Insts.CoreOpsFunctionFnMutTupleShared2LayerBool.call_mut p y
      ⦃ _ _ => True ⦄ := by
  unfold let_go.closure.Insts.CoreOpsFunctionFnMutTupleShared2LayerBool.call_mut
  rcases p with ⟨v, v1⟩
  step*

/-- The test of the closure of `let_go` on a group (that a pull wants it) returns. -/
theorem let_go_group_closure_returns (p : let_go.closure_1) (y : Group) :
    let_go.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1GroupBool.call_mut p y
      ⦃ _ _ => True ⦄ := by
  unfold let_go.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1GroupBool.call_mut
  step*

/-- The `retain` of `let_go` over the layers returns, and keeps no more than it had. -/
@[step] theorem retain_let_go_layers (v : alloc.vec.Vec Layer) (f : let_go.closure) :
    alloc.vec.Vec.retain alloc.alloc.Global
      let_go.closure.Insts.CoreOpsFunctionFnMutTupleShared2LayerBool v f
      ⦃ r => r.val.length ≤ v.val.length ⦄ :=
  retain_total _ _ v f (answers_of_spec (inst :=
    let_go.closure.Insts.CoreOpsFunctionFnMutTupleShared2LayerBool) let_go_layer_closure_returns)

/-- The `retain` of `let_go` over the groups returns, and keeps no more than it had. -/
@[step] theorem retain_let_go_groups (v : alloc.vec.Vec Group) (f : let_go.closure_1) :
    alloc.vec.Vec.retain alloc.alloc.Global
      let_go.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1GroupBool v f
      ⦃ r => r.val.length ≤ v.val.length ⦄ :=
  retain_total _ _ v f (answers_of_spec (inst :=
    let_go.closure_1.Insts.CoreOpsFunctionFnMutTupleShared1GroupBool) let_go_group_closure_returns)

/-- `let_go` takes the layers and the groups no pull wants out of the tables, and asks for the
stop and the end of at most two things for each of them. -/
@[step] theorem let_go_returns (on64 : OnA64BitMachine) (c : Core) (at_ : Std.Usize)
    (out : alloc.vec.Vec Action) (fit : Short c) (inside : at_.val < c.pulls.val.length)
    (room : out.val.length + 4 * 2 ^ 25 ≤ 2 ^ 63) :
    let_go c at_ out ⦃ r => Short r.1 ∧ r.1.pulls.val.length = c.pulls.val.length ∧
      r.2.val.length ≤ out.val.length + 4 * 2 ^ 25 ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold let_go
  -- the layers of the pull are taken, the loop over the layers asks to stop and forget those no
  -- pull lacks, and the layers that go are taken out of the table
  step*
  all_goals try bookkeeping
  refine WP.spec_bind (retain_let_go_layers _ _) ?_
  intro layers layers_post
  -- the loop over the groups asks to stop and forget those no working pull wants, and the groups
  -- that go are taken out of the table
  step*
  all_goals bookkeeping

/-- The loop of `leave` over the pulls gives the place of a pull that left to the first that
waits, and each of them asks for two actions at most. -/
@[step] theorem leave_loop_returns (on64 : OnA64BitMachine) (iter : core.ops.range.Range Std.Usize)
    (c : Core) (out : alloc.vec.Vec Action) (fit : Short c)
    (start_le : iter.start.val ≤ iter.end.val) (end_le : iter.end.val ≤ c.pulls.val.length)
    (room : out.val.length + 2 * (iter.end.val - iter.start.val) ≤ 2 ^ 63) :
    leave_loop iter c out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length = c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + 2 * (iter.end.val - iter.start.val) ⦄ := by
  have max_is := usize_max_is on64
  unfold leave_loop
  -- a loop returns because a number goes down at each turn, while the invariant (what the loop
  -- keeps true: the tables are short, there is room for what is left to push) is kept
  apply loop.spec_decr_nat (fun p => p.1.end.val - p.1.start.val)
    (fun p => p.1.end.val = iter.end.val ∧ p.1.start.val ≤ p.1.end.val ∧ Short p.2.1 ∧
      p.2.1.pulls.val.length = c.pulls.val.length ∧
      p.2.2.val.length + 2 * (iter.end.val - p.1.start.val) ≤
        out.val.length + 2 * (iter.end.val - iter.start.val))
  · rintro ⟨it, c1, acc⟩ ⟨same_end, start_le, fit1, same_len, room⟩
    dsimp only at same_end start_le fit1 same_len room
    unfold leave_loop.body
    simp only
    -- a turn: the next element is read, and when there is none the loop is over
    step as ⟨o, it1, ho, same_end1⟩
    have same_end1 : it1.end.val = it.end.val := by rw [same_end1]
    by_cases lt : it.start.val < it.end.val
    · simp only [lt, ↓reduceIte] at ho
      obtain ⟨rfl, i1⟩ := ho
      simp only
      step*
      all_goals bookkeeping
    · simp only [lt, ↓reduceIte] at ho
      obtain ⟨rfl, _⟩ := ho
      simp only
      step*
  · exact ⟨rfl, start_le, fit, rfl, by dsimp only; omega⟩

/-- `leave` takes the pull out of the table and gives its place to the first that waits. -/
@[step] theorem leave_returns (on64 : OnA64BitMachine) (c : Core) (at_ : Std.Usize)
    (out : alloc.vec.Vec Action) (fit : Short c) (inside : at_.val < c.pulls.val.length)
    (room : out.val.length + 6 * 2 ^ 25 ≤ 2 ^ 63) :
    leave c at_ out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length + 1 = c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + 6 * 2 ^ 25 ⦄ := by
  have max_is := usize_max_is on64
  unfold leave
  step*
  all_goals bookkeeping

/-- A try of the pull at `at_` failed: its pull is recorded, then it waits (`let_go`) or leaves. -/
@[step] theorem try_failed_returns (on64 : OnA64BitMachine) (c : Core) (now : Std.U64)
    (at_ : Std.Usize) (cl : Class) (out : alloc.vec.Vec Action) (fit : Short c)
    (inside : at_.val < c.pulls.val.length) (room : out.val.length + 6 * 2 ^ 25 + 3 ≤ 2 ^ 63) :
    try_failed c now at_ cl out ⦃ c1 out1 => Short c1 ∧ c1.pulls.val.length ≤ c.pulls.val.length ∧
      out1.val.length ≤ out.val.length + 6 * 2 ^ 25 + 3 ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold try_failed
  -- the pull is found; whether the try progressed and the class of the failure (and whether the
  -- completion retries) give the state recorded, one case each; every case pushes the record,
  -- then `let_go` (the pull waits) or `leave` (it is over)
  step as ⟨pull, back, pull_post, back_post⟩
  by_cases hp : pull.progressed = true <;> simp only [hp, Bool.false_eq_true, ↓reduceIte, bind_ok]
  all_goals
    cases cl
    · by_cases hr : c.cfg.retries = true <;>
        simp only [hr, Bool.false_eq_true, ↓reduceIte, bind_ok] <;> step* <;> bookkeeping
    · by_cases hr : c.cfg.retries = true <;>
        simp only [hr, Bool.false_eq_true, ↓reduceIte, bind_ok] <;> step* <;> bookkeeping
    · simp only
      step* <;> bookkeeping
    · simp only
      step* <;> bookkeeping

/-- `add` puts one more pull in the table, and begins its try or records that it waits. -/
@[step] theorem add_returns (on64 : OnA64BitMachine) (c : Core) (pull : Std.U32) (containers : Bool)
    (out : alloc.vec.Vec Action) (fit : Short c) (pulls_room : c.pulls.val.length + 1 ≤ 2 ^ 25)
    (room : out.val.length + 2 ≤ 2 ^ 63) :
    add c pull containers out ⦃ c1 out1 => Short c1 ∧
      c1.pulls.val.length ≤ c.pulls.val.length + 1 ∧ out1.val.length ≤ out.val.length + 2 ⦄ := by
  have max_is := usize_max_is on64
  obtain ⟨pulls_fit, layers_fit, groups_fit, starts_fit⟩ := fit
  unfold add
  step*
  all_goals bookkeeping

end LazyCore
