-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs about `cpuset_mask`: its loops end, no byte of the mask outside the first `used` is touched, and no number or index overflows.
-- Why it is needed: the list of CPUs is a text of a client, and a mask is written at a place it computes.
-- Read before this file: Search.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Search
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_limit_core
namespace LimitCore

/-- `digit` is true exactly for the bytes `0` to `9`. -/
@[step] theorem digit_spec (b : Std.U8) : digit b ⦃ r => (r = true ↔ 48 ≤ b.val ∧ b.val ≤ 57) ⦄ := by
  unfold digit
  split <;> simp only [WP.spec_ok] <;> scalar_tac

/-- The comma that ends the part starting at `end`: not before it, not after the end. -/
theorem find_comma_spec (list : Slice Std.U8) (e : Std.Usize) (h : e.val ≤ list.length) :
    cpuset_mask_loop0_loop0 list e ⦃ r => e.val ≤ r.val ∧ r.val ≤ list.length ⦄ := by
  unfold cpuset_mask_loop0_loop0
  apply loop.spec_decr_nat (fun (q : Std.Usize) => list.length - q.val)
    (fun (q : Std.Usize) => e.val ≤ q.val ∧ q.val ≤ list.length)
    (fun (r : Std.Usize) => e.val ≤ r.val ∧ r.val ≤ list.length)
  · intro q ⟨h1, h2⟩
    unfold cpuset_mask_loop0_loop0.body
    step*
  · exact ⟨le_refl _, h⟩

/-- The loop of the digits of a CPU number: it stays between the start and the end of the part, keeps
the number below 81920 (it stops reading digits once it is 8192 or more) and counts digits. -/
theorem digits_loop_spec (list : Slice Std.U8) (e i a d : Std.Usize)
    (h : i.val ≤ e.val ∧ e.val ≤ list.length ∧ a.val ≤ 81919 ∧ d.val ≤ i.val) :
    cpuset_mask_loop0_loop1 list e i a d ⦃ r =>
      i.val ≤ r.1.val ∧ r.1.val ≤ e.val ∧ r.2.1.val ≤ 81919 ∧ r.2.2.val ≤ r.1.val ⦄ := by
  unfold cpuset_mask_loop0_loop1
  apply loop.spec_decr_nat (fun (q : Std.Usize × Std.Usize × Std.Usize) => e.val - q.1.val)
    (fun (q : Std.Usize × Std.Usize × Std.Usize) => i.val ≤ q.1.val ∧ q.1.val ≤ e.val ∧
      q.2.1.val ≤ 81919 ∧ q.2.2.val ≤ q.1.val)
    (fun (r : Std.Usize × Std.Usize × Std.Usize) =>
      i.val ≤ r.1.val ∧ r.1.val ≤ e.val ∧ r.2.1.val ≤ 81919 ∧ r.2.2.val ≤ r.1.val)
  · rintro ⟨i1, a1, d1⟩ ⟨h1, h2, h3, h4⟩
    simp only at h1 h2 h3 h4 ⊢
    have hm : MAX_CPUS.val = 8192 := by simp [MAX_CPUS]
    unfold cpuset_mask_loop0_loop1.body
    step*
    have hd := b_post.mp ‹_›
    scalar_tac
  · exact ⟨le_refl _, h.1, h.2.2.1, h.2.2.2⟩


/-- The loop of the digits of the end of a range: it stays between the start and the end of the part, keeps
the number below 81920 (it stops reading digits once it is 8192 or more) and counts digits. -/
theorem digits_b_loop_spec (list : Slice Std.U8) (e i a d : Std.Usize)
    (h : i.val ≤ e.val ∧ e.val ≤ list.length ∧ a.val ≤ 81919 ∧ d.val ≤ i.val) :
    cpuset_mask_loop0_loop2 list e i a d ⦃ r =>
      i.val ≤ r.1.val ∧ r.1.val ≤ e.val ∧ r.2.1.val ≤ 81919 ∧ r.2.2.val ≤ r.1.val ⦄ := by
  unfold cpuset_mask_loop0_loop2
  apply loop.spec_decr_nat (fun (q : Std.Usize × Std.Usize × Std.Usize) => e.val - q.1.val)
    (fun (q : Std.Usize × Std.Usize × Std.Usize) => i.val ≤ q.1.val ∧ q.1.val ≤ e.val ∧
      q.2.1.val ≤ 81919 ∧ q.2.2.val ≤ q.1.val)
    (fun (r : Std.Usize × Std.Usize × Std.Usize) =>
      i.val ≤ r.1.val ∧ r.1.val ≤ e.val ∧ r.2.1.val ≤ 81919 ∧ r.2.2.val ≤ r.1.val)
  · rintro ⟨i1, a1, d1⟩ ⟨h1, h2, h3, h4⟩
    simp only at h1 h2 h3 h4 ⊢
    have hm : MAX_CPUS.val = 8192 := by simp [MAX_CPUS]
    unfold cpuset_mask_loop0_loop2.body
    step*
    have hd := b1_post.mp ‹_›
    scalar_tac
  · exact ⟨le_refl _, h.1, h.2.2.1, h.2.2.2⟩

/-- The loop that sets the bits of the CPUs `n` to `b`: it changes only the bytes up to the one of
`b` (the places of the mask are all below 1024 as `b` is below 8192). -/
theorem set_bits_spec (b : Std.Usize) (mask : Std.Array Std.U8 1024#usize) (n : Std.Usize)
    (hb : b.val < 8192) (hn : n.val ≤ b.val + 1) :
    cpuset_mask_loop0_loop3 mask b n ⦃ r => ∀ k, b.val / 8 < k → r.val[k]? = mask.val[k]? ⦄ := by
  unfold cpuset_mask_loop0_loop3
  apply loop.spec_decr_nat (fun (q : Std.Array Std.U8 1024#usize × Std.Usize) => b.val + 1 - q.2.val)
    (fun (q : Std.Array Std.U8 1024#usize × Std.Usize) => q.2.val ≤ b.val + 1 ∧
      ∀ k, b.val / 8 < k → q.1.val[k]? = mask.val[k]?)
    (fun (r : Std.Array Std.U8 1024#usize) => ∀ k, b.val / 8 < k → r.val[k]? = mask.val[k]?)
  · rintro ⟨m1, n1⟩ ⟨h1, h2⟩
    simp only at h1 h2 ⊢
    unfold cpuset_mask_loop0_loop3.body
    step*
    refine ⟨by scalar_tac, fun k hk => ?_, by scalar_tac⟩
    rw [a_post, Std.Array.set_val_eq, List.getElem?_set_ne (by scalar_tac)]
    exact h2 k hk
  · exact ⟨hn, fun _ _ => rfl⟩

/-- The loop that sets the bits of the CPUs `n` to `b`: it changes only the bytes up to the one of
`b` (the places of the mask are all below 1024 as `b` is below 8192). -/
theorem set_bits4_spec (b : Std.Usize) (mask : Std.Array Std.U8 1024#usize) (n : Std.Usize)
    (hb : b.val < 8192) (hn : n.val ≤ b.val + 1) :
    cpuset_mask_loop0_loop4 mask b n ⦃ r => ∀ k, b.val / 8 < k → r.val[k]? = mask.val[k]? ⦄ := by
  unfold cpuset_mask_loop0_loop4
  apply loop.spec_decr_nat (fun (q : Std.Array Std.U8 1024#usize × Std.Usize) => b.val + 1 - q.2.val)
    (fun (q : Std.Array Std.U8 1024#usize × Std.Usize) => q.2.val ≤ b.val + 1 ∧
      ∀ k, b.val / 8 < k → q.1.val[k]? = mask.val[k]?)
    (fun (r : Std.Array Std.U8 1024#usize) => ∀ k, b.val / 8 < k → r.val[k]? = mask.val[k]?)
  · rintro ⟨m1, n1⟩ ⟨h1, h2⟩
    simp only at h1 h2 ⊢
    unfold cpuset_mask_loop0_loop4.body
    step*
    refine ⟨by scalar_tac, fun k hk => ?_, by scalar_tac⟩
    rw [a_post, Std.Array.set_val_eq, List.getElem?_set_ne (by scalar_tac)]
    exact h2 k hk
  · exact ⟨hn, fun _ _ => rfl⟩

/-- The loop that sets the bits of the CPUs `n` to `b`: it changes only the bytes up to the one of
`b` (the places of the mask are all below 1024 as `b` is below 8192). -/
theorem set_bits5_spec (b : Std.Usize) (mask : Std.Array Std.U8 1024#usize) (n : Std.Usize)
    (hb : b.val < 8192) (hn : n.val ≤ b.val + 1) :
    cpuset_mask_loop0_loop5 mask b n ⦃ r => ∀ k, b.val / 8 < k → r.val[k]? = mask.val[k]? ⦄ := by
  unfold cpuset_mask_loop0_loop5
  apply loop.spec_decr_nat (fun (q : Std.Array Std.U8 1024#usize × Std.Usize) => b.val + 1 - q.2.val)
    (fun (q : Std.Array Std.U8 1024#usize × Std.Usize) => q.2.val ≤ b.val + 1 ∧
      ∀ k, b.val / 8 < k → q.1.val[k]? = mask.val[k]?)
    (fun (r : Std.Array Std.U8 1024#usize) => ∀ k, b.val / 8 < k → r.val[k]? = mask.val[k]?)
  · rintro ⟨m1, n1⟩ ⟨h1, h2⟩
    simp only at h1 h2 ⊢
    unfold cpuset_mask_loop0_loop5.body
    step*
    refine ⟨by scalar_tac, fun k hk => ?_, by scalar_tac⟩
    rw [a_post, Std.Array.set_val_eq, List.getElem?_set_ne (by scalar_tac)]
    exact h2 k hk
  · exact ⟨hn, fun _ _ => rfl⟩

attribute [local step] find_comma_spec digits_loop_spec digits_b_loop_spec set_bits_spec
  set_bits4_spec set_bits5_spec

/-- The loop over the parts of the list: it ends, whatever the bytes are, and only the first `used`
bytes of the mask change. -/
theorem parts_loop_spec (list : Slice Std.U8) (mask0 : Std.Array Std.U8 1024#usize)
    (mask : Std.Array Std.U8 1024#usize) (used at_ : Std.Usize) (ok1 : Bool)
    (hlen : list.length < Std.Usize.max)
    (h : used.val ≤ 1024 ∧ at_.val ≤ list.length + 1 ∧
      ∀ k, used.val ≤ k → mask.val[k]? = mask0.val[k]?) :
    cpuset_mask_loop0 list mask used at_ ok1 ⦃ r =>
      r.2.1.val ≤ 1024 ∧ ∀ k, r.2.1.val ≤ k → r.1.val[k]? = mask0.val[k]? ⦄ := by
  unfold cpuset_mask_loop0
  apply loop.spec_decr_nat
    (fun (q : Std.Array Std.U8 1024#usize × Std.Usize × Std.Usize × Bool) => list.length + 1 - q.2.2.1.val)
    (fun (q : Std.Array Std.U8 1024#usize × Std.Usize × Std.Usize × Bool) => q.2.1.val ≤ 1024 ∧
      q.2.2.1.val ≤ list.length + 1 ∧ ∀ k, q.2.1.val ≤ k → q.1.val[k]? = mask0.val[k]?)
    (fun (r : Std.Array Std.U8 1024#usize × Std.Usize × Bool) =>
      r.2.1.val ≤ 1024 ∧ ∀ k, r.2.1.val ≤ k → r.1.val[k]? = mask0.val[k]?)
  · rintro ⟨m1, u1, a1, o1⟩ ⟨h1, h2, h3⟩
    simp only at h1 h2 h3 ⊢
    have hm : MAX_CPUS.val = 8192 := by simp [MAX_CPUS]
    -- one pass is one part of the list: its end, its numbers, then the bits; a refused part only
    -- moves on to the next one
    unfold cpuset_mask_loop0.body
    step*
    all_goals (try (refine ⟨by scalar_tac, by scalar_tac, h3, by scalar_tac⟩))
    all_goals
      split <;> step* <;>
      (refine ⟨by scalar_tac, by scalar_tac, fun k hk => ?_, by scalar_tac⟩
       rw [mask1_post k (by scalar_tac)]
       exact h3 k (by scalar_tac))
  · exact h

/-- Proof of `TheCpusetMask`: the loop over the parts keeps `used` at most 1024 and the bytes from `used` on as they were. -/
theorem cpuset_mask_post (list : Slice Std.U8) (mask : Std.Array Std.U8 1024#usize)
    (short : Short list.val) : cpuset_mask list mask ⦃ r =>
      ∀ used, r.1 = some used → used.val ≤ 1024 ∧
        ∀ i, used.val ≤ i → i < 1024 → r.2.val[i]? = mask.val[i]? ⦄ := by
  unfold cpuset_mask
  have hlen : list.length < Std.Usize.max := short.2
  step with parts_loop_spec list mask mask 0#usize 0#usize true hlen
    ⟨by scalar_tac, by scalar_tac, fun _ _ => rfl⟩ as ⟨m1, used, o1, hr1, hr2⟩
  split
  · simp only [WP.spec_ok]
    intro u hu
    cases hu
    exact ⟨hr1, fun i hi _ => hr2 i hi⟩
  · simp only [WP.spec_ok]; intro u hu; cases hu

end LimitCore
