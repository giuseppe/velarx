-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loops over lists of peers in crates/group-core/src/lib.rs
-- answer, as plain facts about lists: `without` drops a peer from a list, `take_first` splits a
-- list into its first and the rest, and the loops of `requeue` and `found` append to a list.
--
-- Why it is needed: the decisions of the group (`go`, `ended`, `found`, `hedge_due`) are made of
-- these helpers; once each is known as a fact about lists, the proofs of the next files
-- never look into a loop again.
--
-- Read before this file: the helpers at the top of crates/group-core/src/lib.rs.
--
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless
-- loop, and its answer `r` satisfies `P`"; `v.val` is the list a `Vec` holds; `l.drop i` is
-- `l` without its first `i` items; `l ++ m` is `l` followed by `m`; `step*` goes through the
-- lines of a Rust function; `↑x` is the number of a machine integer.
import Extracted.Funs
open Aeneas Aeneas.Std Result velarx_group_core
namespace GroupCore

/-- The loop of `without` appends to what it has the peers it has not read, but the one dropped. -/
@[step]
theorem without_loop_spec (v : Slice Std.Usize) (peer : Std.Usize)
    (rest : alloc.vec.Vec Std.Usize) (i : Std.Usize) (read : i.val ≤ v.length)
    (room : rest.length + (v.length - i.val) ≤ Std.Usize.max) :
    without_loop v peer rest i ⦃ r =>
      r.val = rest.val ++ (v.val.drop i.val).filter (fun x => decide (x ≠ peer)) ⦄ := by
  unfold without_loop
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => v.length - q.2.val)
    (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => q.2.val ≤ v.length ∧
      q.1.length + (v.length - q.2.val) ≤ Std.Usize.max ∧
      q.1.val ++ (v.val.drop q.2.val).filter (fun x => decide (x ≠ peer)) =
        rest.val ++ (v.val.drop i.val).filter (fun x => decide (x ≠ peer)))
  · rintro ⟨out, e⟩ ⟨h1, h2, h3⟩
    simp only at h1 h2 h3 ⊢
    unfold without_loop.body
    step*
    · rename_i below
      have inside : e.val < v.length := by scalar_tac
      have cons : v.val.drop e.val = i2 :: v.val.drop (e.val + 1) := by
        rw [i2_post]; exact List.drop_eq_getElem_cons inside
      by_cases same : i2 = peer
      · simp only [same, bne_self_eq_false, Bool.false_eq_true, ite_false, Std.bind_ok]
        step as ⟨ e1, e1_post ⟩
        refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        have same' : i2.val = peer.val := by rw [same]
        rw [e1_post, ← h3, cons]; simp [same']
      · have differs : (i2 != peer) = true := by simpa using same
        simp only [differs, ite_true]
        have room' : out.val.length < Std.Usize.max := by simp [alloc.vec.Vec.length] at h2; scalar_tac
        step as ⟨ pushed, pushed_post ⟩
        step as ⟨ e1, e1_post ⟩
        refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, pushed_post]; scalar_tac, ?_, by scalar_tac⟩
        have same' : ¬ i2.val = peer.val := fun h => same (UScalar.eq_of_val_eq h)
        rw [e1_post, pushed_post, ← h3, cons]; simp [same']
    · rename_i past
      have : e.val = v.length := by scalar_tac
      rw [← h3, this]; simp
  · exact ⟨read, room, rfl⟩


/-- `without` returns the list without the peer, the others in their order. -/
@[step]
theorem without_spec (v : Slice Std.Usize) (peer : Std.Usize) :
    without v peer ⦃ r => r.val = v.val.filter (fun x => decide (x ≠ peer)) ⦄ := by
  unfold without
  step as ⟨ r, hr ⟩
  simpa [alloc.vec.Vec.new, Function.comp_def] using hr

/-- The loop of `take_first` appends to what it has the items it has not read. -/
@[step]
theorem take_first_loop_spec (v rest : alloc.vec.Vec Std.Usize) (i : Std.Usize)
    (read : i.val ≤ v.length) (room : rest.length + (v.length - i.val) ≤ Std.Usize.max) :
    take_first_loop v rest i ⦃ r => r.val = rest.val ++ v.val.drop i.val ⦄ := by
  unfold take_first_loop
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => v.length - q.2.val)
    (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => q.2.val ≤ v.length ∧
      q.1.length + (v.length - q.2.val) ≤ Std.Usize.max ∧
      q.1.val ++ v.val.drop q.2.val = rest.val ++ v.val.drop i.val)
  · rintro ⟨out, e⟩ ⟨h1, h2, h3⟩
    simp only at h1 h2 h3 ⊢
    unfold take_first_loop.body
    step*
    · rename_i below
      have inside : e.val < v.length := by scalar_tac
      have cons : v.val.drop e.val = i2 :: v.val.drop (e.val + 1) := by
        rw [i2_post]; exact List.drop_eq_getElem_cons inside
      refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, rest1_post]; scalar_tac, ?_, by scalar_tac⟩
      rw [i3_post, rest1_post, ← h3, cons]; simp
    · rename_i past
      have : e.val = v.length := by scalar_tac
      rw [← h3, this]; simp
  · exact ⟨read, room, rfl⟩

/-- `take_first` of a list that has a first item returns it and the rest. -/
@[step]
theorem take_first_spec (v : alloc.vec.Vec Std.Usize) (nonempty : v.val ≠ []) :
    take_first v ⦃ r => v.val = r.1 :: r.2.val ⦄ := by
  unfold take_first
  obtain ⟨q, rest, hv⟩ := List.exists_cons_of_ne_nil nonempty
  have inside : 0 < v.val.length := by simp [hv]
  step as ⟨ first, first_post ⟩
  step as ⟨ r, hr ⟩
  have head : first = q := by rw [first_post]; simp [hv]
  simp_all [alloc.vec.Vec.new]


/-- The loop of `requeue` appends to the queue what is left of the peers that had no room. -/
@[step]
theorem requeue_loop_spec (next busy : alloc.vec.Vec Std.Usize) (i : Std.Usize)
    (read : i.val ≤ busy.length) (room : next.length + (busy.length - i.val) ≤ Std.Usize.max) :
    Group.requeue_loop next busy i ⦃ r => r.val = next.val ++ busy.val.drop i.val ⦄ := by
  unfold Group.requeue_loop
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => busy.length - q.2.val)
    (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => q.2.val ≤ busy.length ∧
      q.1.length + (busy.length - q.2.val) ≤ Std.Usize.max ∧
      q.1.val ++ busy.val.drop q.2.val = next.val ++ busy.val.drop i.val)
  · rintro ⟨out, e⟩ ⟨h1, h2, h3⟩
    simp only at h1 h2 h3 ⊢
    unfold Group.requeue_loop.body
    step*
    · rename_i below
      have inside : e.val < busy.length := by scalar_tac
      have cons : busy.val.drop e.val = i2 :: busy.val.drop (e.val + 1) := by
        rw [i2_post]; exact List.drop_eq_getElem_cons inside
      refine ⟨by scalar_tac, by simp [alloc.vec.Vec.length, v2_post]; scalar_tac, ?_, by scalar_tac⟩
      rw [i3_post, v2_post, ← h3, cons]; simp
    · rename_i past
      have : e.val = busy.length := by scalar_tac
      rw [← h3, this]; simp
  · exact ⟨read, room, rfl⟩

/-- The loop of `found` appends the numbers `found + i` up to `found + n` to the queue. -/
@[step]
theorem found_loop_spec (found : Std.Usize) (next : alloc.vec.Vec Std.Usize) (n i : Std.Usize)
    (read : i.val ≤ n.val) (room : next.length + (n.val - i.val) ≤ Std.Usize.max)
    (fits : found.val + n.val ≤ Std.Usize.max) :
    Group.impl.found_loop found next n i ⦃ r =>
      ∃ added : List Std.Usize, r.val = next.val ++ added ∧
        added.map (·.val) = List.range' (found.val + i.val) (n.val - i.val) ⦄ := by
  unfold Group.impl.found_loop
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => n.val - q.2.val)
    (fun (q : alloc.vec.Vec Std.Usize × Std.Usize) => i.val ≤ q.2.val ∧ q.2.val ≤ n.val ∧
      q.1.length + (n.val - q.2.val) ≤ Std.Usize.max ∧
      ∃ added : List Std.Usize, q.1.val = next.val ++ added ∧
        added.map (·.val) = List.range' (found.val + i.val) (q.2.val - i.val))
  · rintro ⟨out, e⟩ ⟨h0, h1, h2, added, h3, h4⟩
    simp only at h0 h1 h2 h3 h4 ⊢
    unfold Group.impl.found_loop.body
    step*
    · have step_range : e.val - i.val + 1 = i3.val - i.val := by scalar_tac
      refine ⟨by scalar_tac, by scalar_tac, by simp [alloc.vec.Vec.length, v1_post]; scalar_tac,
        ⟨added ++ [i2], by simp [v1_post, h3], ?_⟩, by scalar_tac⟩
      rw [← step_range, List.range'_concat]
      simp [h4, i2_post]; omega
  · exact ⟨le_refl _, read, room, [], by simp, by simp⟩

end GroupCore
