-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `TheTablesStayWellFormed` and of
-- `ANewCoreIsWellFormed` (Spec.lean).  The three tables of the core (`pulls`,
-- `layers`, `groups`) agree, and `step` keeps it so: in particular a layer a pull lacks is
-- in the table of the layers, and a layer of the table is lacked by some pull.
--
-- Why it is needed: the next proof (an image is committed only after its layers) says
-- "every layer a pull lacks is stored" and must know that such a layer IS in the table,
-- or that is true of a layer that is missing.  This file is what discharges that
-- hypothesis by induction on the steps, from `Core::new`.  It says nothing of the states
-- of the layers and of the groups.
--
-- The argument follows the Rust, from the inside out, one fact per function of lib.rs
-- that touches the tables, of the shape
--
--     WellFormed c   gives   Ok (f c ...) (fun r => WellFormed r.1)
--
-- read "if the tables of `c` agree and `f` returns, the tables it leaves agree".  The
-- invariant moves in three places only:
--   - `let_go` (the layers of a pull go: the layers no other pull lacks leave the table, and so
--     do the groups no working pull wants), which leaves the pull lacking nothing;
--     `leave`, `try_failed` and `cancel` call it after they put the pull in a phase that is
--     not past its preparation, so their fact starts from `WellFormedExcept`;
--   - `prepared` (a pull that was preparing, so lacked nothing, gets the layers of the
--     event, and the table gets the layers it lacked);
--   - `add` (a pull that lacks nothing is pushed) and `leave` (it is taken out).
-- Every other function changes the state or the phase of the pulls, the layers and the
-- groups, not their names nor which layers a pull lacks (`SameNameAndLayers`,
-- `StaysPastPreparing`, `Kept`).
-- The functions are in the order of lib.rs, the loops before the function they are in; the walk
-- of the events of `step` is Step.lean.
--
-- Read before this file: Ok.lean, Pulls.lean, Verdict.lean (`Kept`, `Walked`), Names.lean, Step.lean,
-- Held.lean (the loop of `prepared` over the groups), and the statements `WellFormed`, `WellTold`
-- and `TheTablesStayWellFormed` in Spec.lean.
-- Models.lean has the three models this file needs: `Vec::retain`, `mem::take` and
-- `Vec::default`.
--
-- Notation: besides the notations of the files above, `l.filter keep` is the list of the
-- elements of `l` that `keep` says yes to, `l.eraseIdx i` the list without its `i`th element,
-- `l.set i x` the list with `x` at `i`, `List.Forall₂ R l l'` that the elements of the two lists
-- are related by `R`, place by place, and `l.Sublist l'` that `l` is `l'` with some
-- elements left out.
import LazyCore.Names
import LazyCore.Held

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

attribute [local irreducible] begin_try let_go_loop0 let_go_loop1 let_go leave_loop leave
  cancel_loop cancel advance_loop2 advance_loop3 advance_loop4_loop0 advance_loop4 advance
  Core.pull_at Core.layer_at Core.lacking slots_held goes wanting in_flight Core.starting
  Pull.has_all Pull.working Pull.wants Pull.lacks

/-! ### The invariant in pieces -/

/-- The first six clauses of `WellFormed` (Spec.lean): what the tables say, without what the
phase of a pull says of its layers. -/
def Agree (c : Core) : Prop :=
  distinct c ∧ (c.layers.val.map (·.id)).Nodup ∧ (c.groups.val.map (·.id)).Nodup ∧
  (∀ p ∈ c.pulls.val, p.layers.val.Nodup) ∧
  (∀ p ∈ c.pulls.val, ∀ l ∈ p.layers.val, ∃ x ∈ c.layers.val, x.id = l) ∧
  (∀ x ∈ c.layers.val, ∃ p ∈ c.pulls.val, x.id ∈ p.layers.val)

/-- `WellFormed` is the first six clauses and the last. -/
theorem wellFormed_iff (c : Core) : WellFormed c ↔
    Agree c ∧ ∀ p ∈ c.pulls.val, p.layers.val ≠ [] → PastPreparing p.phase :=
  ⟨fun ⟨a, b, c, d, e, f, g⟩ => ⟨⟨a, b, c, d, e, f⟩, g⟩,
    fun ⟨⟨a, b, c, d, e, f⟩, g⟩ => ⟨a, b, c, d, e, f, g⟩⟩

/-- `WellFormedExcept c i`: the tables agree, and every pull but the one at `i` lacks nothing
unless it is past its preparation.  It is what `let_go` is given: the pull at `i` is about to
let go of its layers, whatever phase it was just put in. -/
def WellFormedExcept (c : Core) (i : Nat) : Prop :=
  Agree c ∧ ∀ p ∈ c.pulls.val.eraseIdx i, p.layers.val ≠ [] → PastPreparing p.phase

/-- A core whose tables agree is well formed but for any one pull. -/
theorem wellFormedExcept_of_wellFormed {c : Core} (wf : WellFormed c) (i : Nat) :
    WellFormedExcept c i :=
  let ⟨agree, past⟩ := (wellFormed_iff c).mp wf
  ⟨agree, fun p in_erased => past p (List.mem_of_mem_eraseIdx in_erased)⟩

/-- The pull `b` has the name and the layers of the pull `a`. -/
def SameNameAndLayers (a b : Pull) : Prop := b.id = a.id ∧ b.layers = a.layers

/-- A pull stays as it is. -/
theorem SameNameAndLayers.refl (a : Pull) : SameNameAndLayers a a := ⟨rfl, rfl⟩

/-- The pull `b` has the name and the layers of the pull `a`, and if `a` lacked something and was
past its preparation, so is `b`. -/
def StaysPastPreparing (a b : Pull) : Prop :=
  SameNameAndLayers a b ∧ (a.layers.val ≠ [] → PastPreparing a.phase → PastPreparing b.phase)

/-- A pull stays as it is. -/
theorem StaysPastPreparing.refl (a : Pull) : StaysPastPreparing a a :=
  ⟨SameNameAndLayers.refl a, fun _ past => past⟩

/-- A pull `advance` leaves (`Kept`) stays past its preparation if it was. -/
theorem Kept.staysPastPreparing {a b : Pull} (kept : Kept a b) : StaysPastPreparing a b := by
  obtain ⟨same_id, same_phase, same_layers, working⟩ := kept
  refine ⟨⟨same_id, same_layers⟩, fun _ past => ?_⟩
  by_cases is_working : a.phase = Phase.Running Step.Working
  · exact working is_working
  · rw [same_phase is_working]; exact past

/-- A list in which the element at `i` was replaced by a related one is related to the
original. -/
theorem forall₂_set {α : Type} {R : α → α → Prop} (refl : ∀ a, R a a) (l : List α) (i : Nat)
    (y : α) (in_range : i < l.length) (related : R l[i] y) : List.Forall₂ R l (l.set i y) := by
  induction l generalizing i with
  | nil => simp at in_range
  | cons a rest ih =>
    cases i with
    | zero => exact List.Forall₂.cons related (forall₂_self refl rest)
    | succ i =>
      exact List.Forall₂.cons (refl a) (ih i (by simpa using in_range) (by simpa using related))

/-- Pulls replaced by pulls with the same names and layers, and tables whose names are the same,
still agree. -/
theorem agree_of_same_name_and_layers {c c' : Core} (agree : Agree c)
    (same : List.Forall₂ SameNameAndLayers c.pulls.val c'.pulls.val)
    (layers : c'.layers.val.map (·.id) = c.layers.val.map (·.id))
    (groups : c'.groups.val.map (·.id) = c.groups.val.map (·.id)) : Agree c' := by
  obtain ⟨distinct_c, layers_nodup, groups_nodup, pull_nodup, lacked_in, table_lacked⟩ := agree
  -- a layer is in the table of `c'` when it is in that of `c`: the same names
  have named : ∀ l, (∃ x ∈ c'.layers.val, x.id = l) ↔ (∃ x ∈ c.layers.val, x.id = l) := by
    intro l
    have := congrArg (l ∈ ·) layers
    simpa only [List.mem_map, eq_iff_iff] using this
  refine ⟨?_, by rw [layers]; exact layers_nodup, by rw [groups]; exact groups_nodup, ?_, ?_, ?_⟩
  · exact distinct_of_same_names distinct_c (map_eq_of_forall₂ (·.id) (same.imp fun _ _ s => s.1))
  · intro p' in_pulls
    obtain ⟨p, in_c, same_id, same_layers⟩ := forall₂_mem_right same in_pulls
    rw [same_layers]; exact pull_nodup p in_c
  · intro p' in_pulls l lacked
    obtain ⟨p, in_c, same_id, same_layers⟩ := forall₂_mem_right same in_pulls
    rw [same_layers] at lacked
    exact (named l).mpr (lacked_in p in_c l lacked)
  · intro x in_table
    obtain ⟨x0, in_c, same_name⟩ := (named x.id).mp ⟨x, in_table, rfl⟩
    obtain ⟨p, in_pulls, lacked⟩ := table_lacked x0 in_c
    obtain ⟨p', in_pulls', same_id, same_layers⟩ := forall₂_mem_left same in_pulls
    exact ⟨p', in_pulls', by rw [same_layers, ← same_name]; exact lacked⟩

/-- Pulls replaced by pulls that stay past their preparation if they were, and tables whose names
are the same, are well formed if they were. -/
theorem wellFormed_of_staying {c c' : Core} (wf : WellFormed c)
    (staying : List.Forall₂ StaysPastPreparing c.pulls.val c'.pulls.val)
    (layers : c'.layers.val.map (·.id) = c.layers.val.map (·.id))
    (groups : c'.groups.val.map (·.id) = c.groups.val.map (·.id)) : WellFormed c' := by
  obtain ⟨agree, past⟩ := (wellFormed_iff c).mp wf
  refine (wellFormed_iff c').mpr ⟨agree_of_same_name_and_layers agree
    (staying.imp fun _ _ s => s.1) layers groups, fun p' in_pulls lacks => ?_⟩
  obtain ⟨p, in_c, same, stays⟩ := forall₂_mem_right staying in_pulls
  have lacks_p : p.layers.val ≠ [] := by rw [← same.2]; exact lacks
  exact stays lacks_p (past p in_c lacks_p)

/-- The core after a pull of the same name and layers was put at `i` has tables that agree, and
every pull but that one is as it was. -/
theorem wellFormedExcept_of_set {c c' : Core} (wf : WellFormed c) {i : Nat}
    (in_range : i < c.pulls.val.length) (q : Pull) (same : SameNameAndLayers (c.pulls.val[i]) q)
    (pulls : c'.pulls.val = c.pulls.val.set i q) (layers : c'.layers = c.layers)
    (groups : c'.groups = c.groups) : WellFormedExcept c' i := by
  obtain ⟨agree, past⟩ := (wellFormed_iff c).mp wf
  refine ⟨agree_of_same_name_and_layers agree ?_ (by rw [layers]) (by rw [groups]), ?_⟩
  · rw [pulls]; exact forall₂_set SameNameAndLayers.refl _ i q in_range same
  · rw [pulls, eraseIdx_set]
    exact fun p in_erased => past p (List.mem_of_mem_eraseIdx in_erased)

/-- The core after a pull that stays past its preparation if it was is put at `i` is well formed. -/
theorem wellFormed_of_set {c c' : Core} (wf : WellFormed c) {i : Nat}
    (in_range : i < c.pulls.val.length) (q : Pull)
    (staying : StaysPastPreparing (c.pulls.val[i]) q)
    (pulls : c'.pulls.val = c.pulls.val.set i q) (layers : c'.layers = c.layers)
    (groups : c'.groups = c.groups) : WellFormed c' :=
  wellFormed_of_staying wf
    (by rw [pulls]; exact forall₂_set StaysPastPreparing.refl _ i q in_range staying)
    (by rw [layers]) (by rw [groups])

/-! ### What the functions of the library do -/

/-- `goes layer mine pulls`: the layer is one of `mine` and no pull lacks it. -/
theorem goes_iff (layer : Std.U32) (mine : Slice Std.U32) (pulls : Slice Pull) :
    goes layer mine pulls =
      ok (decide (layer ∈ mine.val ∧ ∀ p ∈ pulls.val, layer ∉ p.layers.val)) := by
  have contains := anyM_pure (core.cmp.PartialEqU32.eq layer) (fun y => layer = y)
    (fun x => rfl) mine.val
  unfold goes core.slice.Slice.contains
  rw [contains]
  simp only [bind_ok]
  by_cases mine_has : ∃ x ∈ mine.val, layer = x
  · obtain ⟨x, in_mine, same⟩ := mine_has
    subst same
    simp only [in_mine, core.slice.Slice.iter, bind_ok]
    have lacks : ∀ p : Pull,
        goes.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool.call_mut layer p =
          ok (decide (layer ∈ p.layers.val), layer) := by
      intro p
      simp [goes.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool.call_mut, lacks_iff]
    obtain ⟨it, found⟩ := any_iff goes.closure.Insts.CoreOpsFunctionFnMutTupleShared0PullBool
      (fun p : Pull => layer ∈ p.layers.val) pulls layer lacks
    simp only [found, bind_ok]
    simp [in_mine]
  · have : ¬ (layer ∈ mine.val) := fun in_mine => mine_has ⟨layer, in_mine, rfl⟩
    simp [this]

/-! ### `let_go` -/

/-- The loop of `let_go` over the groups (`for g in groups.iter_mut()`) changes the state of a group
at most: each group keeps its name. -/
theorem let_go_loop1_keeps_names (l : List Group) (iter : core.slice.iter.IterMut Group)
    (back : core.slice.iter.IterMut Group → core.slice.iter.IterMut Group)
    (out : alloc.vec.Vec Action) (me : Std.U32) (pulls : alloc.vec.Vec Pull)
    (walked : Walked (fun a b : Group => b.id = a.id) l iter back) :
    Ok (let_go_loop1 iter back out me pulls) (fun r =>
      List.Forall₂ (fun a b : Group => b.id = a.id) l (r.2.2 r.2.1).slice.val) := by
  unfold let_go_loop1
  refine Ok.loop (I := fun x => Walked (fun a b : Group => b.id = a.id) l x.1 x.2.1) ?_ walked
  rintro ⟨it, back, out1⟩ walked
  dsimp only at walked
  unfold let_go_loop1.body core.slice.iter.IteratorIterMut.next
  dsimp only
  by_cases more : it.i < it.slice.len
  · have more' : it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    generalize hg : it.slice[it.i] = g
    have current : it.slice.val[it.i] = g := hg
    refine Ok.bind (Ok.any _) ?_; intro wanted _
    cases wanted with
    | none =>
      -- no pull wants the group: it is told to be forgotten, and stays in the table for now
      cases g.state <;> simp only [bind_ok, Std.bind_assoc, uncurry_eq]
      all_goals first
        | (refine Ok.bind (push_appends _ _) ?_; intro out2 _
           exact Ok.ok.mpr (walked.next more' _ (by rw [current])))
        | (refine Ok.bind (push_appends _ _) ?_; intro out2 _
           refine Ok.bind (push_appends _ _) ?_; intro out3 _
           exact Ok.ok.mpr (walked.next more' _ (by rw [current])))
    | some other =>
      -- a pull wants it: what it had in flight is counted against another
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro in_flight_for_me _
      split
      · exact Ok.ok.mpr (walked.next more' _ (by rw [current]))
      · exact Ok.ok.mpr (walked.next more' _ (by simp [current]))
  · have at_end : ¬ it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    exact Ok.ok.mpr (walked.done at_end)

/-- What `let_go` leaves of the tables, said of the lists: the pull at `i` has no layers, the
layers that stay are those that are not among the layers of that pull or that another pull lacks,
and the groups that stay are some of those that were.  If the tables agreed but for that pull,
they agree now, and the pull lacks nothing. -/
theorem wellFormed_after_let_go {c c' : Core} {i : Nat} (except : WellFormedExcept c i)
    (in_range : i < c.pulls.val.length) (ls : alloc.vec.Vec Std.U32) (no_layers : ls.val = [])
    (pulls : c'.pulls.val = c.pulls.val.set i { c.pulls.val[i] with layers := ls })
    (layers : c'.layers.val = c.layers.val.filter fun x => !decide
      (x.id ∈ (c.pulls.val[i]).layers.val ∧ ∀ p ∈ c'.pulls.val, x.id ∉ p.layers.val))
    (groups : (c'.groups.val.map (·.id)).Sublist (c.groups.val.map (·.id))) :
    WellFormed c' ∧ ∃ h : i < c'.pulls.val.length, (c'.pulls.val[i]).layers.val = [] := by
  obtain ⟨⟨distinct_c, layers_nodup, groups_nodup, pull_nodup, lacked_in, table_lacked⟩, past⟩ :=
    except
  have in_range' : i < c'.pulls.val.length := by simp [pulls, in_range]
  -- the pulls of the new core: the pull at `i`, without layers, and the others
  have in_pulls : ∀ x, x ∈ c'.pulls.val ↔
      x = { c.pulls.val[i] with layers := ls } ∨ x ∈ c.pulls.val.eraseIdx i := by
    intro x; rw [pulls]; exact mem_set_iff _ _ in_range _ _
  have in_pulls_old : ∀ x, x ∈ c.pulls.val ↔ x = c.pulls.val[i] ∨ x ∈ c.pulls.val.eraseIdx i :=
    mem_iff_here_or_erased _ _ in_range
  refine ⟨⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩, in_range', by simp [pulls, no_layers]⟩
  -- the names of the pulls are distinct
  · exact distinct_of_set distinct_c i { c.pulls.val[i] with layers := ls } in_range rfl pulls
  -- the names of the layers are distinct
  · rw [layers]
    exact layers_nodup.sublist (List.filter_sublist.map _)
  -- the names of the groups are distinct
  · exact groups_nodup.sublist groups
  -- the layers a pull lacks are distinct
  · intro p' in_p'
    rcases (in_pulls p').mp in_p' with rfl | erased
    · simp [no_layers]
    · exact pull_nodup p' (List.mem_of_mem_eraseIdx erased)
  -- a layer a pull lacks is in the table
  · intro p' in_p' l lacked
    rcases (in_pulls p').mp in_p' with rfl | erased
    · simp [no_layers] at lacked
    · obtain ⟨x, in_table, named⟩ := lacked_in p' (List.mem_of_mem_eraseIdx erased) l lacked
      refine ⟨x, ?_, named⟩
      rw [layers, List.mem_filter]
      refine ⟨in_table, ?_⟩
      simp only [Bool.not_eq_true', decide_eq_false_iff_not, not_and, not_forall, not_not]
      exact fun _ => ⟨p', in_p', by rw [named]; exact lacked⟩
  -- a layer of the table is lacked by some pull
  · intro x in_table
    rw [layers, List.mem_filter] at in_table
    obtain ⟨in_old, keeps⟩ := in_table
    simp only [Bool.not_eq_true', decide_eq_false_iff_not, not_and, not_forall, not_not] at keeps
    by_cases mine : x.id ∈ (c.pulls.val[i]).layers.val
    · obtain ⟨p', in_p', lacked⟩ := keeps mine
      exact ⟨p', in_p', lacked⟩
    · obtain ⟨p0, in_p0, lacked⟩ := table_lacked x in_old
      rcases (in_pulls_old p0).mp in_p0 with rfl | erased
      · exact absurd lacked mine
      · exact ⟨p0, (in_pulls p0).mpr (Or.inr erased), lacked⟩
  -- a pull lacks nothing unless its try is past its preparation
  · intro p' in_p' lacks
    rcases (in_pulls p').mp in_p' with rfl | erased
    · exact absurd no_layers lacks
    · exact past p' erased lacks

/-- The test of `let_go` on the layers answers whether the layer stays, whatever it has seen. -/
theorem let_go_keeps (mine : alloc.vec.Vec Std.U32) (pulls : alloc.vec.Vec Pull) (l : Layer) :
    let_go.closure.Insts.CoreOpsFunctionFnMutTupleShared2LayerBool.call_mut (mine, pulls) l =
      ok (!decide (l.id ∈ mine.val ∧ ∀ p ∈ pulls.val, l.id ∉ p.layers.val), (mine, pulls)) := by
  unfold let_go.closure.Insts.CoreOpsFunctionFnMutTupleShared2LayerBool.call_mut
  simp [goes_iff, alloc.vec.Vec.deref]
  rfl

/-- `let_go` of the pull at `at_` makes the pull lack nothing, and the tables agree: the layers of
the pull that no other pull lacks leave the table, and so do the groups no working pull wants, and
they were all that did not agree.  (The pull at `at_` may be in any phase when it is given: the
callers have just put it at one that is not past its preparation.) -/
theorem let_go_well_formed (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action)
    (except : WellFormedExcept c at_.val) :
    Ok (let_go c at_ out) (fun r => WellFormed r.1 ∧
      ∃ h : at_.val < r.1.pulls.val.length, (r.1.pulls.val[at_.val]).layers.val = []) := by
  unfold let_go
  by_cases in_range : at_.val < c.pulls.val.length
  swap
  · refine Ok.bind (index_mut_result _ _) ?_
    rintro _ ⟨h, _⟩
    exact absurd h in_range
  rw [index_mut_in_range _ _ in_range]
  simp only [bind_ok, uncurry_eq, core.mem.take,
    alloc.vec.Vec.Insts.CoreDefaultDefault.default]
  refine Ok.bind (Ok.any _) ?_; intro p1 _
  refine Ok.bind (Ok.any _) ?_; intro iter _
  refine Ok.bind (Ok.any _) ?_; intro out1 _
  refine Ok.bind (retain_filter _ _ _ _ (fun l => let_go_keeps _ _ l) _) ?_
  intro layers is_filter
  simp only [lift, bind_ok, alloc.vec.Vec.deref_mut, core.slice.Slice.iter_mut, uncurry_eq]
  refine Ok.bind (let_go_loop1_keeps_names c.groups.val _ _ _ _ _
    ⟨rfl, fun it' _ => ⟨[], by simp, by simp⟩⟩) ?_
  intro r same_names
  refine Ok.bind (retain_sublist _ _ _ _) ?_
  intro groups1 sub
  apply Ok.ok.mpr
  have names := map_eq_of_forall₂ (fun g : Group => g.id) same_names
  exact wellFormed_after_let_go except in_range (alloc.vec.Vec.new Std.U32) rfl
    (set_val _ _ _) is_filter (by rw [← names]; exact sub.map (fun g : Group => g.id))

/-- `begin_try` of a pull that lacks nothing keeps the tables well formed: the pull is
preparing, and a preparing pull lacks nothing. -/
theorem begin_try_well_formed (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action)
    (wf : WellFormed c) (in_range : at_.val < c.pulls.val.length)
    (idle : (c.pulls.val[at_.val]).layers.val = []) :
    Ok (begin_try c at_ out) (fun r => WellFormed r.1) := by
  refine (begin_try_prepares c at_ out).mono ?_
  rintro r ⟨_, same_layers, same_groups, _, _, pulls⟩
  exact wellFormed_of_set wf in_range
    { c.pulls.val[at_.val] with phase := Phase.Running Step.Preparing, progressed := false }
    ⟨⟨rfl, rfl⟩, fun lacks => absurd idle lacks⟩ pulls same_layers same_groups

/-- Taking out of the pulls one that lacks nothing leaves tables that agree. -/
theorem wellFormed_of_erase {c c' : Core} (wf : WellFormed c) {i : Nat}
    (in_range : i < c.pulls.val.length) (idle : (c.pulls.val[i]).layers.val = [])
    (pulls : c'.pulls.val = c.pulls.val.eraseIdx i) (layers : c'.layers = c.layers)
    (groups : c'.groups = c.groups) : WellFormed c' := by
  obtain ⟨distinct_c, layers_nodup, groups_nodup, pull_nodup, lacked_in, table_lacked, past⟩ := wf
  have erased : ∀ p, p ∈ c'.pulls.val → p ∈ c.pulls.val := fun p in_p' =>
    List.mem_of_mem_eraseIdx (pulls ▸ in_p')
  refine ⟨?_, by rw [layers]; exact layers_nodup, by rw [groups]; exact groups_nodup,
    fun p in_p' => pull_nodup p (erased p in_p'), ?_, ?_, fun p in_p' => past p (erased p in_p')⟩
  · unfold distinct
    rw [pulls]
    exact List.Nodup.sublist ((List.eraseIdx_sublist _ _).map _) distinct_c
  · intro p in_p' l lacked
    rw [layers]; exact lacked_in p (erased p in_p') l lacked
  · intro x in_table
    rw [layers] at in_table
    obtain ⟨p, in_p, lacked⟩ := table_lacked x in_table
    rcases (mem_iff_here_or_erased _ i in_range p).mp in_p with rfl | in_erased
    · simp [idle] at lacked
    · exact ⟨p, pulls ▸ in_erased, lacked⟩

/-- A pull that is not past its preparation lacks nothing, in a core whose tables agree. -/
theorem idle_of_not_past {c : Core} (wf : WellFormed c) {p : Pull} (in_pulls : p ∈ c.pulls.val)
    (not_past : ¬ PastPreparing p.phase) : p.layers.val = [] :=
  by_contra fun lacks => not_past (wf.2.2.2.2.2.2 p in_pulls lacks)

/-- The loop of `leave` that gives the freed place to the first pull that waits keeps the tables
well formed: the pull that gets the place was queued, so it lacks nothing, and begins its try. -/
theorem leave_loop_well_formed (iter : core.ops.range.Range Std.Usize) (c : Core)
    (out : alloc.vec.Vec Action) (wf : WellFormed c) :
    Ok (leave_loop iter c out) (fun r => WellFormed r.1) := by
  unfold leave_loop
  refine Ok.loop (I := fun x => WellFormed x.2.1) ?_ wf
  rintro ⟨iter, c1, out1⟩ wf1
  dsimp only at wf1
  unfold leave_loop.body
  refine Ok.bind (Ok.any _) ?_; rintro ⟨o, iter1⟩ _
  simp only [uncurry_eq]
  cases o with
  | none => exact Ok.ok.mpr wf1
  | some at_ =>
    simp only []
    refine Ok.bind (Ok.any _) ?_; intro i _
    split
    · exact Ok.ok.mpr wf1
    · refine Ok.bind (index_result _ _) ?_
      rintro p ⟨in_range, rfl⟩
      refine Ok.bind (phase_eq_true _ _) ?_
      intro queued is_queued
      split
      · -- the pull is queued: it gets the place, and its try begins
        refine Ok.bind (index_mut_result _ _) ?_
        rintro _ ⟨in_range', rfl⟩
        simp only [uncurry_eq]
        have idle := idle_of_not_past wf1 (List.getElem_mem in_range)
          (by rw [is_queued (by assumption)]; simp [PastPreparing])
        have placed : WellFormed { c1 with
            pulls := alloc.vec.Vec.set c1.pulls at_ { c1.pulls.val[at_.val] with slot := true } } :=
          wellFormed_of_set wf1 in_range { c1.pulls.val[at_.val] with slot := true }
            ⟨⟨rfl, rfl⟩, fun _ past => past⟩ (set_val _ _ _) rfl rfl
        refine Ok.bind
          (begin_try_well_formed _ _ _ placed (by simpa [set_val] using in_range) ?_) ?_
        · simpa [set_val] using idle
        · rintro ⟨c2, out2⟩ wf2; exact Ok.ok.mpr wf2
      · exact Ok.ok.mpr wf1

/-- `leave` keeps the tables well formed: the pull lets go of its layers (`let_go`), then goes,
and it lacked nothing by then. -/
theorem leave_well_formed (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action)
    (except : WellFormedExcept c at_.val) : Ok (leave c at_ out) (fun r => WellFormed r.1) := by
  unfold leave
  refine Ok.bind ((let_go_well_formed c at_ out except).and (let_go_changes_layers c at_ out)) ?_
  rintro ⟨c1, out1⟩ ⟨⟨wf1, in_range1, idle⟩, _, _, in_range, ls, pulls1⟩
  simp only [uncurry_eq]
  obtain ⟨rest, removed, rest_is⟩ := remove_returns_and_erases c1.pulls at_ in_range1
  rw [removed]
  simp only [bind_ok, uncurry_eq]
  refine Ok.bind (push_appends _ _) ?_; intro out2 _
  exact leave_loop_well_formed _ _ _ (wellFormed_of_erase wf1 in_range1 idle rest_is rfl rfl)

/-- `try_failed` keeps the tables well formed: the pull is put in the phase it waits in and lets go
of its layers, or it is over and `leave`s. -/
theorem try_failed_well_formed (c : Core) (now : Std.U64) (at_ : Std.Usize) (cl : Class)
    (out : alloc.vec.Vec Action) (wf : WellFormed c) :
    Ok (try_failed c now at_ cl out) (fun r => WellFormed r.1) := by
  unfold try_failed
  refine Ok.bind (index_mut_result _ _) ?_
  rintro _ ⟨in_range, rfl⟩
  simp only [uncurry_eq]
  refine Ok.bind (Ok.any _) ?_; intro failures _
  refine Ok.bind (Ok.any _) ?_; rintro ⟨cfg, failures1, state⟩ _
  refine Ok.bind (push_appends _ _) ?_; intro out1 _
  -- the pull is put back, with another phase or failures, and the same layers
  have put_back : ∀ q : Pull, SameNameAndLayers (c.pulls.val[at_.val]) q →
      WellFormedExcept { c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q } at_.val :=
    fun q alike => wellFormedExcept_of_set wf in_range q alike (set_val _ _ _) rfl rfl
  -- the try is over (`_ => leave`)
  have over : ∀ q : Pull, q = { c.pulls.val[at_.val] with failures := failures1 } →
      Ok (leave { c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q } at_ out1)
        (fun r => WellFormed r.1) := fun q is_q =>
    leave_well_formed _ _ _ (put_back q (by rw [is_q]; exact ⟨rfl, rfl⟩))
  -- the try waits (`Backoff | NoSpace`): `let_go`, then `Wake`
  have waits : ∀ (wake : Std.U64) (q : Pull),
      q = { c.pulls.val[at_.val] with phase := Phase.Waiting wake, failures := failures1 } →
      Ok (do
        let (c2, out2) ← let_go
          { c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q } at_ out1
        let out3 ← alloc.vec.Vec.push out2 (Action.Wake wake)
        ok (c2, out3)) (fun r => WellFormed r.1) := by
    intro wake q is_q
    refine Ok.bind (let_go_well_formed _ _ _ (put_back q (by rw [is_q]; exact ⟨rfl, rfl⟩))) ?_
    rintro ⟨c2, out2⟩ ⟨wf2, _⟩
    refine Ok.bind (push_appends _ _) ?_; intro out3 _
    exact Ok.ok.mpr wf2
  -- the states that end the try, and the two that wait
  rcases state with _ | _ | wait | wait | _ | _
  all_goals first
    | exact over _ rfl
    | exact waits wait _ rfl

/-- `advance` keeps the tables well formed: it keeps every pull (`Kept`: its name, its layers, and
a pull past its preparation stays so) and the names of the layers and of the groups. -/
theorem advance_well_formed (c : Core) (now : Std.U64) (out : alloc.vec.Vec Action)
    (wf : WellFormed c) : Ok (advance c now out) (fun r => WellFormed r.1) :=
  (advance_keeps_pulls c now out).mono
    fun _ ⟨_, kept, layers, groups, _⟩ =>
      wellFormed_of_staying wf (kept.imp fun _ _ k => k.staysPastPreparing) layers
        (names_of_keys groups)

/-- A pull that lacks nothing, added at the end, keeps the tables well formed. -/
theorem wellFormed_of_push {c : Core} (wf : WellFormed c) (v : alloc.vec.Vec Pull) (q : Pull)
    (v_is : v.val = c.pulls.val ++ [q]) (new : q.id ∉ c.pulls.val.map (·.id))
    (idle : q.layers.val = []) : WellFormed { c with pulls := v } := by
  obtain ⟨distinct_c, layers_nodup, groups_nodup, pull_nodup, lacked_in, table_lacked, past⟩ := wf
  have in_v : ∀ p, p ∈ v.val ↔ p ∈ c.pulls.val ∨ p = q := by
    intro p; rw [v_is]; simp
  refine ⟨distinct_of_push distinct_c v q v_is new, layers_nodup, groups_nodup, ?_, ?_, ?_, ?_⟩
  · intro p in_p
    rcases (in_v p).mp in_p with old | rfl
    · exact pull_nodup p old
    · simp [idle]
  · intro p in_p l lacked
    rcases (in_v p).mp in_p with old | rfl
    · exact lacked_in p old l lacked
    · simp [idle] at lacked
  · intro x in_table
    obtain ⟨p, in_p, lacked⟩ := table_lacked x in_table
    exact ⟨p, (in_v p).mpr (Or.inl in_p), lacked⟩
  · intro p in_p lacks
    rcases (in_v p).mp in_p with old | rfl
    · exact past p old lacks
    · exact absurd idle lacks

/-- `add` keeps the tables well formed: the new pull lacks nothing, and it is queued or begins
its try. -/
theorem add_well_formed (c : Core) (pull : Std.U32) (containers : Bool)
    (out : alloc.vec.Vec Action) (wf : WellFormed c) :
    Ok (add c pull containers out) (fun r => WellFormed r.1) := by
  unfold add
  refine Ok.bind (pull_at_none c pull) ?_; intro o none_not_held
  cases o with
  | some n => exact Ok.ok.mpr wf
  | none =>
  have not_in_names : pull ∉ c.pulls.val.map (·.id) :=
    fun in_names => none_not_held rfl (held_iff_name.mpr in_names)
  -- the new pull is last, and nobody had its name
  have added : ∀ (v : alloc.vec.Vec Pull) (q : Pull), q.id = pull → q.layers.val = [] →
      v.val = c.pulls.val ++ [q] → WellFormed { c with pulls := v } :=
    fun v q named idle v_is => wellFormed_of_push wf v q v_is (named ▸ not_in_names) idle
  -- the try begins (`begin_try` of the last pull), or the pull is recorded as queued
  have began : ∀ (v : alloc.vec.Vec Pull) (q : Pull), q.id = pull → q.layers.val = [] →
      v.val = c.pulls.val ++ [q] →
      Ok (do let i2 ← (alloc.vec.Vec.len v - 1#usize)
             begin_try { c with pulls := v } i2 out) (fun r => WellFormed r.1) := by
    intro v q named idle v_is
    refine Ok.bind (pred_len _) ?_; intro i2 last
    have len : i2.val = c.pulls.val.length := by
      simp [alloc.vec.Vec.len, v_is] at last ⊢; omega
    have in_range : i2.val < v.val.length := by simp [v_is, len]
    refine begin_try_well_formed _ _ _ (added v q named idle v_is) in_range ?_
    simp [v_is, len, idle]
  simp only [core.option.Option.is_some, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  refine Ok.bind (Ok.any _) ?_; intro i _
  by_cases free : i < c.cfg.completers
  · simp only [free, ↓reduceIte]
    refine Ok.bind (push_appends _ _) ?_; intro v pushed
    exact began v _ rfl rfl pushed
  · simp only [free, ↓reduceIte]
    refine Ok.bind (push_appends _ _) ?_; intro v pushed
    cases containers
    · -- the pull is recorded as queued
      simp only [Bool.false_eq_true, ↓reduceIte]
      refine Ok.bind (push_appends _ _) ?_; intro out1 _
      exact Ok.ok.mpr (added v _ rfl rfl pushed)
    · simp only [↓reduceIte]
      exact began v _ rfl rfl pushed

/-- The loop of `cancel` over the other pulls that lacked a layer of the cancelled one keeps the
tables well formed: each lets go of its layers, then begins its try again. -/
theorem cancel_loop_well_formed (iter : alloc.vec.into_iter.IntoIter Std.U32) (c : Core)
    (out : alloc.vec.Vec Action) (wf : WellFormed c) :
    Ok (cancel_loop iter c out) (fun r => WellFormed r.1) := by
  unfold cancel_loop
  refine Ok.loop (I := fun x => WellFormed x.2.1) ?_ wf
  rintro ⟨it, c1, out1⟩ so_far
  dsimp only at so_far
  unfold cancel_loop.body
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, _⟩ | ⟨other, rest, rfl, cons, is_rest⟩)
  · exact Ok.ok.mpr so_far
  · refine Ok.bind (pull_at_sound c1 other) ?_
    intro o1 found
    cases o1 with
    | none => exact Ok.ok.mpr so_far
    | some at_ =>
      simp only []
      -- it lets go of its layers, then begins its try again
      refine Ok.bind (let_go_well_formed c1 at_ out1 (wellFormedExcept_of_wellFormed so_far _)) ?_
      rintro ⟨c2, out2⟩ ⟨wf2, in_range2, idle2⟩
      refine Ok.bind (begin_try_well_formed c2 at_ out2 wf2 in_range2 idle2) ?_
      rintro ⟨c3, out3⟩ wf3
      exact Ok.ok.mpr wf3

/-- `cancel` keeps the tables well formed: a pull that runs is marked `Cancelling` and lets go of
its layers, and the others that lacked one begin again. -/
theorem cancel_well_formed (c : Core) (pull : Std.U32) (out : alloc.vec.Vec Action)
    (wf : WellFormed c) : Ok (cancel c pull out) (fun r => WellFormed r.1) := by
  unfold cancel
  refine Ok.bind (pull_at_sound c pull) ?_
  intro o found
  cases o with
  | none => exact Ok.ok.mpr wf
  | some at_ =>
  obtain ⟨in_range, named⟩ := found at_ rfl
  simp only []
  rw [index_in_range _ _ in_range]
  simp only [bind_ok]
  split
  · exact leave_well_formed c at_ out (wellFormedExcept_of_wellFormed wf _)
  · -- it runs: its phase becomes `Cancelling`, it lets go of its layers
    refine Ok.bind (Ok.any _) ?_; intro mine _
    rw [index_mut_in_range _ _ in_range]
    simp only [bind_ok, uncurry_eq]
    have marked : ∀ q : Pull, q = { c.pulls.val[at_.val] with phase := Phase.Cancelling } →
        WellFormedExcept { c with pulls := alloc.vec.Vec.set c.pulls at_ q } at_.val :=
      fun q is_q => wellFormedExcept_of_set wf in_range q (by rw [is_q]; exact ⟨rfl, rfl⟩)
        (set_val _ _ _) rfl rfl
    refine Ok.bind (let_go_well_formed _ _ _ (marked _ rfl)) ?_
    rintro ⟨c1, out1⟩ ⟨wf1, _⟩
    simp only [uncurry_eq]
    refine Ok.bind (push_appends _ _) ?_; intro out2 _
    -- the other pulls that lacked a layer of it let go and begin their try again
    refine Ok.bind (Ok.any _) ?_; intro v1 _
    refine Ok.bind (Ok.any _) ?_; intro it _
    exact cancel_loop_well_formed it c1 out2 wf1
  · exact leave_well_formed c at_ out (wellFormedExcept_of_wellFormed wf _)
  · exact Ok.ok.mpr wf

/-- `progress` keeps the tables well formed: it only sets `progressed` of working pulls. -/
theorem progress_well_formed (c : Core) (layers : Slice Std.U32) (wf : WellFormed c) :
    Ok (progress c layers) (fun r => WellFormed r) :=
  (progress_keeps_pulls c layers).mono
    fun _ ⟨kept, same_layers, same_groups⟩ => wellFormed_of_staying wf
      (kept.imp fun _ _ k => k.staysPastPreparing) (by rw [same_layers]) (by rw [same_groups])

/-- The loop of `succeeded` over the layers (`for l in layers.iter_mut()`) changes the state of a
layer at most: each layer keeps its name. -/
theorem succeeded_loop_keeps_names (l : List Layer) (iter : core.slice.iter.IterMut Layer)
    (back : core.slice.iter.IterMut Layer → core.slice.iter.IterMut Layer) (p : Pull)
    (walked : Walked (fun a b : Layer => b.id = a.id) l iter back) :
    Ok (succeeded_loop iter back p) (fun r =>
      List.Forall₂ (fun a b : Layer => b.id = a.id) l r.slice.val) := by
  unfold succeeded_loop
  refine Ok.loop (I := fun x => Walked (fun a b : Layer => b.id = a.id) l x.1 x.2) ?_ walked
  rintro ⟨it, back⟩ walked
  dsimp only at walked
  walk_loop succeeded_loop.body

/-- `succeeded` keeps the tables well formed: a pull whose driver pull ended works again (same
layers), one that ended is `leave`d, a layer or a group that ended changes its state and the
pulls that lack it `progress`. -/
theorem succeeded_well_formed (c : Core) (work : Work) (out : alloc.vec.Vec Action)
    (wf : WellFormed c) : Ok (succeeded c work out) (fun r => WellFormed r.1) := by
  unfold succeeded
  cases work with
  | Pull pull =>
    refine Ok.bind (pull_at_sound c pull) ?_
    intro o found
    cases o with
    | none => exact Ok.ok.mpr wf
    | some at_ =>
      obtain ⟨in_range, named⟩ := found at_ rfl
      simp only []
      rw [index_in_range _ _ in_range]
      simp only [bind_ok]
      split
      · exact Ok.ok.mpr wf
      · split
        · exact Ok.ok.mpr wf
        · exact Ok.ok.mpr wf
        · -- the driver's pull ended: the pull works again
          refine Ok.bind (index_mut_result _ _) ?_
          rintro _ ⟨in_range', rfl⟩
          simp only [uncurry_eq, lift, bind_ok, alloc.vec.Vec.deref_mut, core.slice.Slice.iter_mut]
          refine Ok.bind (succeeded_loop_keeps_names c.layers.val _ _ _
            ⟨rfl, fun it' _ => ⟨[], by simp, by simp⟩⟩) ?_
          intro back names
          apply Ok.ok.mpr
          refine wellFormed_of_staying wf (c' := { c with
            pulls := alloc.vec.Vec.set c.pulls at_ { c.pulls.val[at_.val] with
              phase := Phase.Running Step.Working, progressed := true },
            layers := { slice := back.slice } }) ?_ ?_ rfl
          · rw [set_val]
            exact forall₂_set StaysPastPreparing.refl _ _ _ in_range
              ⟨⟨rfl, rfl⟩, fun _ _ => Or.inl rfl⟩
          · exact map_eq_of_forall₂ (fun l : Layer => l.id) names
        · exact leave_well_formed c at_ out (wellFormedExcept_of_wellFormed wf _)
      · exact Ok.ok.mpr wf
      · exact leave_well_formed c at_ out (wellFormedExcept_of_wellFormed wf _)
  | Layer layer =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr wf
    | some l =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro l1 _
      refine Ok.bind (Ok.any _) ?_; intro committing _
      split
      · -- the commit of the layer ended: the layer is stored, the pulls that lack it progress
        refine Ok.bind (index_mut_result _ _) ?_
        rintro _ ⟨in_range, rfl⟩
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro one _
        refine Ok.bind (progress_well_formed _ _ ?_) ?_
        · refine wellFormed_of_staying wf (forall₂_self StaysPastPreparing.refl _) ?_ rfl
          dsimp only
          rw [set_val]
          exact map_set_of_same (fun x : Layer => x.id) _ _ _ in_range rfl
        · intro c1 wf1; exact Ok.ok.mpr wf1
      · exact Ok.ok.mpr wf
  | Group group =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr wf
    | some g =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro g1 _
      split
      · exact Ok.ok.mpr wf
      · -- the fetch of the group ended: it is done, the pulls that lack its layers progress
        refine Ok.bind (index_mut_result _ _) ?_
        rintro _ ⟨in_range, rfl⟩
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro g3 _
        refine Ok.bind (Ok.any _) ?_; intro needed_by _
        refine Ok.bind (progress_well_formed _ _ ?_) ?_
        · refine wellFormed_of_staying wf (forall₂_self StaysPastPreparing.refl _) rfl ?_
          dsimp only
          rw [set_val]
          exact map_set_of_same (fun x : Group => x.id) _ _ _ in_range rfl
        · intro c1 wf1; exact Ok.ok.mpr wf1
      · exact Ok.ok.mpr wf

/-- The loop of `failed` over the pulls whose try fails (`try_failed` for each) keeps the tables
well formed. -/
theorem failed_loop0_well_formed (iter : alloc.vec.into_iter.IntoIter Std.U32) (c : Core)
    (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action) (wf : WellFormed c) :
    Ok (failed_loop0 iter c now cl out) (fun r => WellFormed r.1) := by
  unfold failed_loop0
  refine Ok.loop (I := fun x => WellFormed x.2.1) ?_ wf
  rintro ⟨it, c1, out1⟩ so_far
  dsimp only at so_far
  unfold failed_loop0.body
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, _⟩ | ⟨other, rest, rfl, cons, is_rest⟩)
  · exact Ok.ok.mpr so_far
  · refine Ok.bind (pull_at_sound c1 other) ?_
    intro o1 found
    cases o1 with
    | none => exact Ok.ok.mpr so_far
    | some at_ =>
      simp only []
      refine Ok.bind (try_failed_well_formed c1 now at_ cl out1 so_far) ?_
      rintro ⟨c2, out2⟩ wf2
      exact Ok.ok.mpr wf2

/-- `failed` keeps the tables well formed: the pulls whose try fails (`try_failed`), or the
pull that was stopped (`leave`), or a layer or a group that goes back to the state it was
fetched in, which changes no name. -/
theorem failed_well_formed (c : Core) (now : Std.U64) (work : Work) (cl : Class)
    (out : alloc.vec.Vec Action) (wf : WellFormed c) :
    Ok (failed c now work cl out) (fun r => WellFormed r.1) := by
  unfold failed
  cases work with
  | Pull pull =>
    refine Ok.bind (pull_at_sound c pull) ?_
    intro o found
    cases o with
    | none => exact Ok.ok.mpr wf
    | some at_ =>
      obtain ⟨in_range, named⟩ := found at_ rfl
      simp only []
      rw [index_in_range _ _ in_range]
      simp only [bind_ok]
      split
      · exact Ok.ok.mpr wf
      · -- the try of the pull fails
        simp only [lift, bind_ok]
        refine Ok.bind (Ok.any _) ?_; intro it _
        exact failed_loop0_well_formed it _ now cl out wf
      · exact Ok.ok.mpr wf
      · exact leave_well_formed c at_ out (wellFormedExcept_of_wellFormed wf _)
  | Layer layer =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr wf
    | some l =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro l1 _
      refine Ok.bind (Ok.any _) ?_; intro b _
      split
      · exact Ok.ok.mpr wf
      · -- the commit of the layer failed: it is fetched again, the pulls that lack it fail
        refine Ok.bind (index_mut_result _ _) ?_
        rintro _ ⟨in_range, rfl⟩
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro s _
        refine Ok.bind (Ok.any _) ?_; intro failing _
        refine Ok.bind (Ok.any _) ?_; intro it _
        rw [failed_loops_are_the_same.1]
        refine failed_loop0_well_formed it _ now cl out (wellFormed_of_staying wf
          (forall₂_self StaysPastPreparing.refl _) ?_ rfl)
        dsimp only
        rw [set_val]
        exact map_set_of_same (fun x : Layer => x.id) _ _ _ in_range rfl
  | Group group =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr wf
    | some g =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro g1 _
      refine Ok.bind (Ok.any _) ?_; intro b _
      split
      · -- the fetch of the group failed: it is to be fetched again, the pulls that wait for it fail
        refine Ok.bind (index_mut_result _ _) ?_
        rintro _ ⟨in_range, rfl⟩
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro g3 _
        refine Ok.bind (Ok.any _) ?_; intro failing _
        refine Ok.bind (Ok.any _) ?_; intro it _
        rw [failed_loops_are_the_same.2]
        refine failed_loop0_well_formed it _ now cl out (wellFormed_of_staying wf
          (forall₂_self StaysPastPreparing.refl _) rfl ?_)
        dsimp only
        rw [set_val]
        exact map_set_of_same (fun x : Group => x.id) _ _ _ in_range rfl
      · exact Ok.ok.mpr wf

/-- The loop of `prepared` that pushes a layer for each new layer appends to the table layers
that have those names, in order. -/
theorem prepared_loop3_names (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (v : alloc.vec.Vec Layer) :
    Ok (prepared_loop3 iter v) (fun r => r.val.map (·.id) = v.val.map (·.id) ++ iter.val) := by
  unfold prepared_loop3
  refine Ok.loop (I := fun x => x.2.val.map (·.id) ++ x.1.val = v.val.map (·.id) ++ iter.val)
    ?_ rfl
  rintro ⟨it, v1⟩ pushed
  dsimp only at pushed
  unfold prepared_loop3.body
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, ended⟩ | ⟨id, rest, rfl, cons, is_rest⟩)
  · exact Ok.ok.mpr (by simpa [ended] using pushed)
  · refine Ok.bind (push_appends _ _) ?_; intro v2 pushed2
    apply Ok.ok.mpr
    simp only [pushed2, is_rest, List.map_append, List.map_cons, List.map_nil, List.append_assoc,
      List.singleton_append]
    rw [← pushed, cons]

/-- What `prepared` leaves of the tables, said of the lists: the pull at `i`, which was preparing
and so lacked nothing, now works and lacks the layers of the event; the layers of the event that the
table lacked are added to it (and nothing else); the names of the groups are distinct.  Then the
tables agree. -/
theorem wellFormed_after_prepared {c c' : Core} (wf : WellFormed c) {i : Nat}
    (in_range : i < c.pulls.val.length)
    (preparing : (c.pulls.val[i]).phase = Phase.Running Step.Preparing)
    (layers : alloc.vec.Vec Std.U32) (nodup : layers.val.Nodup)
    (pulls : c'.pulls.val = c.pulls.val.set i
      { c.pulls.val[i] with layers := layers, phase := Phase.Running Step.Working })
    (table : c'.layers.val.map (·.id) = c.layers.val.map (·.id) ++
      layers.val.filter fun l => decide (l ∉ c.layers.val.map (·.id)))
    (groups : (c'.groups.val.map (·.id)).Nodup) : WellFormed c' := by
  -- the preparing pull lacked nothing
  have idle := idle_of_not_past wf (List.getElem_mem in_range)
    (by rw [preparing]; simp [PastPreparing])
  obtain ⟨distinct_c, layers_nodup, groups_nodup, pull_nodup, lacked_in, table_lacked, past⟩ := wf
  have in_pulls : ∀ x, x ∈ c'.pulls.val ↔
      x = { c.pulls.val[i] with layers := layers, phase := Phase.Running Step.Working } ∨
        x ∈ c.pulls.val.eraseIdx i := by
    intro x; rw [pulls]; exact mem_set_iff _ _ in_range _ _
  have in_pulls_old : ∀ x, x ∈ c.pulls.val ↔ x = c.pulls.val[i] ∨ x ∈ c.pulls.val.eraseIdx i :=
    mem_iff_here_or_erased _ _ in_range
  -- a layer of the table afterwards is one before or a new one, and a layer of the event is
  -- one or the other
  have in_table : ∀ l, (∃ x ∈ c'.layers.val, x.id = l) ↔
      l ∈ c.layers.val.map (·.id) ∨ (l ∈ layers.val ∧ l ∉ c.layers.val.map (·.id)) := by
    intro l
    have : (∃ x ∈ c'.layers.val, x.id = l) ↔ l ∈ c'.layers.val.map (·.id) := by simp
    rw [this, table]
    simp only [List.mem_append, List.mem_filter, decide_eq_true_eq]
  -- (the names of the groups are distinct: `groups`)
  refine ⟨?_, ?_, groups, ?_, ?_, ?_, ?_⟩
  -- the names of the pulls are distinct
  · exact distinct_of_set distinct_c i
      { c.pulls.val[i] with layers := layers, phase := Phase.Running Step.Working } in_range rfl
      pulls
  -- the names of the layers are distinct
  · rw [table, List.nodup_append]
    refine ⟨layers_nodup, nodup.filter _, ?_⟩
    intro a in_old b in_new same
    simp only [List.mem_filter, decide_eq_true_eq] at in_new
    exact in_new.2 (same ▸ in_old)
  -- the layers a pull lacks are distinct
  · intro p' in_p'
    rcases (in_pulls p').mp in_p' with rfl | erased
    · exact nodup
    · exact pull_nodup p' (List.mem_of_mem_eraseIdx erased)
  -- a layer a pull lacks is in the table
  · intro p' in_p' l lacked
    rcases (in_pulls p').mp in_p' with rfl | erased
    · by_cases old : l ∈ c.layers.val.map (·.id)
      · exact (in_table l).mpr (Or.inl old)
      · exact (in_table l).mpr (Or.inr ⟨lacked, old⟩)
    · obtain ⟨x, in_x, named⟩ := lacked_in p' (List.mem_of_mem_eraseIdx erased) l lacked
      exact (in_table l).mpr (Or.inl (List.mem_map.mpr ⟨x, in_x, named⟩))
  -- a layer of the table is lacked by some pull
  · intro x in_x
    have named := (in_table x.id).mp ⟨x, in_x, rfl⟩
    rcases named with old | ⟨in_event, _⟩
    · obtain ⟨x0, in_x0, same⟩ := List.mem_map.mp old
      obtain ⟨p0, in_p0, lacked⟩ := table_lacked x0 in_x0
      rcases (in_pulls_old p0).mp in_p0 with rfl | erased
      · simp [idle] at lacked
      · exact ⟨p0, (in_pulls p0).mpr (Or.inr erased), by rw [← same]; exact lacked⟩
    · exact ⟨_, (in_pulls _).mpr (Or.inl rfl), in_event⟩
  -- a pull lacks nothing unless its try is past its preparation
  · intro p' in_p' lacks
    rcases (in_pulls p').mp in_p' with rfl | erased
    · exact Or.inl rfl
    · exact past p' (List.mem_of_mem_eraseIdx erased) lacks

/-- `prepared` keeps the tables well formed, when the event is told as the caller promises
(`WellTold`): a late answer changes nothing; one in time gives a pull that was preparing, and
so lacked nothing, the layers of the event, adds to the table those it lacks, and the groups
that wait for them. -/
theorem prepared_well_formed (c : Core) (pull : Std.U32) (layers : alloc.vec.Vec Std.U32)
    (groups : alloc.vec.Vec GroupFact) (out : alloc.vec.Vec Action) (wf : WellFormed c)
    (nodup : layers.val.Nodup) (groups_nodup : (groups.val.map (·.id)).Nodup)
    (groups_new : ∀ g ∈ groups.val, ∀ x ∈ c.groups.val, x.id ≠ g.id) :
    Ok (prepared c pull layers groups out) (fun r => WellFormed r.1) := by
  unfold prepared
  refine Ok.bind (Ok.any _) ?_; intro o _
  refine Ok.bind (filter_preparing c o) ?_; intro at1 preparing
  refine Ok.bind (clone_layers layers) ?_; intro fresh is_fresh
  refine Ok.bind (fresh_layers c fresh) ?_; intro fresh1 is_fresh1
  cases at1 with
  | none =>
    -- a late answer: the layers and the groups it named are told back
    refine Ok.bind (Ok.any _) ?_; intro iter _
    refine Ok.bind (Ok.any _) ?_; intro out1 _
    refine Ok.bind (Ok.any _) ?_; intro iter1 _
    refine Ok.bind (Ok.any _) ?_; intro out2 _
    exact Ok.ok.mpr wf
  | some at2 =>
    obtain ⟨in_range, is_preparing⟩ := preparing at2 rfl
    simp only [alloc.vec.IntoIteratorVec.into_iter]
    refine Ok.bind (Ok.ok.mpr rfl : Ok (ok groups) fun it => it = groups) ?_
    rintro iter rfl
    refine Ok.bind (prepared_loop2_holds (· ∈ fresh1.val) iter _ _ _ fun _ => Iff.rfl) ?_
    rintro ⟨v, out1⟩ ⟨new, _, v_is, _, sub, _⟩
    simp only [uncurry_eq]
    refine Ok.bind (Ok.ok.mpr rfl : Ok (ok fresh1) fun it => it = fresh1) ?_
    rintro iter1 rfl
    refine Ok.bind (prepared_loop3_names iter1 c.layers) ?_; intro v1 names1
    refine Ok.bind (index_mut_result _ _) ?_
    rintro _ ⟨in_range1, rfl⟩
    simp only [uncurry_eq]
    refine Ok.bind (index_mut_result _ _) ?_
    rintro _ ⟨in_range2, rfl⟩
    simp only [uncurry_eq]
    apply Ok.ok.mpr
    refine wellFormed_after_prepared wf in_range is_preparing layers nodup ?_ ?_ ?_
    · simp [List.set_set]
    · rw [names1, is_fresh1, is_fresh]
    · rw [v_is, List.map_append, List.nodup_append]
      refine ⟨(wellFormed_iff c).mp wf |>.1.2.2.1, groups_nodup.sublist sub, ?_⟩
      intro a in_old b in_new same
      obtain ⟨g, in_g, rfl⟩ := List.mem_map.mp (sub.subset in_new)
      obtain ⟨x, in_x, rfl⟩ := List.mem_map.mp in_old
      exact groups_new g in_g x in_x same

/-- The loop of a `Tick` over the pulls begins the try of those whose wait is over: a waiting pull
lacks nothing, so the tables stay well formed. -/
theorem step_loop_well_formed (iter : core.ops.range.Range Std.Usize) (c : Core) (now : Std.U64)
    (out : alloc.vec.Vec Action) (wf : WellFormed c) :
    Ok (step_loop iter c now out) (fun r => WellFormed r.1) := by
  unfold step_loop
  refine Ok.loop (I := fun x => WellFormed x.2.1) ?_ wf
  rintro ⟨iter, c1, out1⟩ so_far
  dsimp only at so_far
  unfold step_loop.body
  refine Ok.bind (Ok.any _) ?_; rintro ⟨o, iter1⟩ _
  simp only [uncurry_eq]
  cases o with
  | none => exact Ok.ok.mpr so_far
  | some at_ =>
    simp only []
    refine Ok.bind (index_result _ _) ?_; rintro p ⟨in_range, rfl⟩
    split
    -- (a pull that is queued, running or stopped is left as it is)
    all_goals try exact Ok.ok.mpr so_far
    rename_i t waiting
    split
    · -- the wait is over: the try begins
      refine Ok.bind (begin_try_well_formed c1 at_ out1 so_far in_range
        (idle_of_not_past so_far (List.getElem_mem in_range)
          (by rw [waiting]; simp [PastPreparing]))) ?_
      rintro ⟨c2, out2⟩ wf2
      exact Ok.ok.mpr wf2
    · exact Ok.ok.mpr so_far

/-- `start_at` hands out a record of the starts and a way to put it back: whatever record is put
back, the tables stay well formed (the pulls, the layers and the groups are the same). -/
theorem start_at_well_formed (c : Core) (layer : Std.U32) (now : Std.U64) (wf : WellFormed c) :
    Ok (start_at c layer now) (fun r => ∀ cs, WellFormed (r.2 cs)) :=
  (start_at_keeps_pulls c layer now).mono fun _ same cs =>
    wellFormed_of_staying wf (by rw [(same cs).1]; exact forall₂_self StaysPastPreparing.refl _)
      (by rw [(same cs).2.1]) (by rw [(same cs).2.2])

/-- `Hurry` boosts a pull (not its layers, nor its phase): the tables stay well formed. -/
theorem hurried_well_formed (c : Core) (wf : WellFormed c) (at_ : Std.Usize)
    (in_range : at_.val < c.pulls.val.length) : WellFormed (hurried c at_ in_range) :=
  wellFormed_of_set wf in_range { c.pulls.val[at_.val] with boosted := true }
    ⟨⟨rfl, rfl⟩, fun _ past => past⟩ (set_val _ _ _) rfl rfl

/-- `Hurry` of a pull that is queued or waits begins its try: it lacks nothing, so the tables stay
well formed. -/
theorem hurried_begins_well_formed (c : Core) (out : alloc.vec.Vec Action) (wf : WellFormed c)
    (at_ : Std.Usize) (in_range : at_.val < c.pulls.val.length) (idle : Idle c.pulls.val[at_.val]) :
    Ok (begin_try (hurried c at_ in_range) at_ out) (fun r => WellFormed r.1) := by
  have lacks_nothing := idle_of_not_past wf (List.getElem_mem in_range) (by
    rcases idle with idle | ⟨t, idle⟩ <;> simp [PastPreparing, idle])
  exact begin_try_well_formed _ _ _ (hurried_well_formed c wf at_ in_range)
    (by simpa [hurried, set_val] using in_range) (by simpa [hurried, set_val] using lacks_nothing)

/-- **The tables stay well formed** (the statement of Spec.lean): each event is a call of one
function of lib.rs (then `advance`), or code of `step` itself (`Step.lean`), and each piece keeps
the tables well formed. -/
theorem the_tables_stay_well_formed : TheTablesStayWellFormed := by
  intro c now ev out c' out' wf told returns
  have kept : Ok (step c now ev out) (fun r => WellFormed r.1) :=
    StepFacts.holds (told := WellTold c) (A := fun r => WellFormed r.1)
      (Q := fun r => WellFormed r.1)
      { advance_ok := fun r w => advance_well_formed r.1 now r.2 w
        add_ok := fun pull containers => add_well_formed c pull containers out wf
        cancel_ok := fun pull => cancel_well_formed c pull out wf
        prepared_ok := fun pull layers groups ⟨nodup, groups_nodup, groups_new⟩ =>
          prepared_well_formed c pull layers groups out wf nodup groups_nodup groups_new
        succeeded_ok := fun work => succeeded_well_formed c work out wf
        failed_ok := fun work cl => failed_well_formed c now work cl out wf
        hurry_of_none := wf
        hurry_boosts := hurried_well_formed c wf
        hurry_begins := hurried_begins_well_formed c out wf
        start_of_a_layer := fun layer => start_at_well_formed c layer now wf
        wake := fun _ w _ _ _ => w
        tick_loop := fun iter => step_loop_well_formed iter c now out wf } ev told
  exact kept.eq returns

/-- **A new core is well formed** (the statement of Spec.lean): it has no pull, no layer and no
group. -/
theorem a_new_core_is_well_formed : ANewCoreIsWellFormed := by
  intro cfg c made
  have empty : Ok (Core.new cfg)
      (fun c => c.pulls.val = [] ∧ c.layers.val = [] ∧ c.groups.val = []) := by
    unfold Core.new
    exact Ok.ok.mpr ⟨rfl, rfl, rfl⟩
  obtain ⟨no_pulls, no_layers, no_groups⟩ := empty.eq made
  simp [WellFormed, distinct, no_pulls, no_layers, no_groups]

end LazyCore
