-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `passwd_find` and `find_user` answer: an entry of a line of the file with the name or uid asked.
-- Why it is needed: `resolve` finds the entry of the user with them.
-- Read before this file: Entries.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Entries
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- The comparison of an optional uid with a uid says whether they are equal. -/
theorem option_eq_u32 (u : Option Std.U32) (x : Std.U32) :
    core.option.Option.Insts.CoreCmpPartialEqOption.eq core.cmp.PartialEqU32 u (some x) ⦃ b =>
      b = true ↔ u = some x ⦄ := by
  cases u with
  | none => simp [core.option.Option.Insts.CoreCmpPartialEqOption.eq]
  | some y =>
    simp only [core.option.Option.Insts.CoreCmpPartialEqOption.eq]
    simp [liftFun2, core.cmp.impls.PartialEqU32.eq]

/-- The name of an entry is a range of its line, before its stop. -/
theorem passwd_entry_bounds (d : List Std.U8) (start stop : Nat) (e : Passwd)
    (h : IsPasswdEntry d start stop e) :
    e.name.1.val ≤ e.name.2.val ∧ e.name.2.val < stop := by
  obtain ⟨c0, c1, c2, c3, c4, c5, rest, hL, n1, n2, _⟩ := h
  have sorted := colons_sorted d start stop
  have inside : ∀ x ∈ Colons d start stop, start ≤ x ∧ x < stop := fun x hx => by
    have := (mem_colons _ _ _ _).mp hx; exact ⟨this.1, this.2.1⟩
  have := inside c0 (by rw [hL]; simp)
  omega

/-- The test by name returns the entry, and says true only when the bytes of its name are the name asked for. -/
theorem by_name_spec (passwd : Slice Std.U8) (e : Passwd) (who : Option (Slice Std.U8))
    (hab : e.name.1.val ≤ e.name.2.val) (hb : e.name.2.val ≤ passwd.length) :
    (do
      match who with
      | none => ok (e, false)
      | some n =>
        do
        let by_name ← is_text passwd e.name n
        ok (e, by_name)) ⦃ r => r.1 = e ∧
          (r.2 = true → ∃ n, who = some n ∧ List.slice e.name.1.val e.name.2.val passwd.val = n.val) ⦄ := by
  cases who with
  | none => exact (WP.spec_ok _).mpr ⟨rfl, by simp⟩
  | some n =>
    step with is_text_spec passwd e.name.1 e.name.2 n hab hb as ⟨ r, r_post ⟩
    exact fun h => ⟨n, rfl, r_post.mp h⟩

/-- The loop of `passwd_find` returns, and an entry it answers is an entry of a line of the file with the name or the uid asked for. -/
theorem passwd_find_loop_spec (passwd : Slice Std.U8) (who : Option (Slice Std.U8))
    (uid : Option Std.U32) (pos : Std.Usize) (found : Option Passwd)
    (short : passwd.length < Std.Usize.max) (hpos : pos.val ≤ passwd.length + 1)
    (starts : pos.val < passwd.length → pos.val = 0 ∨ ByteAt passwd.val (pos.val - 1) 10)
    (sound : ∀ e, found = some e → FoundEntry passwd.val who uid e) :
    passwd_find_loop passwd who uid pos found ⦃ r =>
      ∀ e, r = some e → FoundEntry passwd.val who uid e ⦄ := by
  unfold passwd_find_loop
  apply loop.spec_decr_nat (fun (q : Option (Slice Std.U8) × Std.Usize × Option Passwd) =>
      passwd.length + 1 - q.2.1.val)
    (fun (q : Option (Slice Std.U8) × Std.Usize × Option Passwd) =>
      q.1 = who ∧ q.2.1.val ≤ passwd.length + 1 ∧
      (q.2.1.val < passwd.length → q.2.1.val = 0 ∨ ByteAt passwd.val (q.2.1.val - 1) 10) ∧
      ∀ e, q.2.2 = some e → FoundEntry passwd.val who uid e)
  · rintro ⟨who1, pos1, found1⟩ ⟨hw, h1, h2, h3⟩
    simp only at hw h1 h2 h3 ⊢
    subst hw
    unfold passwd_find_loop.body
    step*
    rename_i below isnone
    have lt : pos1.val < passwd.length := by scalar_tac
    step with line_at_spec passwd pos1 (by omega) (h2 lt) as ⟨ fin, stop, hline, hsf, hfin_le, hfin_nl ⟩
    step with passwd_line_spec passwd pos1 stop hline.1 hline.2.1 as ⟨ o, o_post ⟩
    have hps : pos1.val ≤ stop.val := hline.1
    have noovf : fin.val + 1 ≤ Std.Usize.max := by scalar_tac
    have finish : ∀ (found2 : Option Passwd) (pos2 : Std.Usize), pos2.val = fin.val + 1 →
        (∀ e, found2 = some e → FoundEntry passwd.val who1 uid e) →
        pos2.val ≤ passwd.length + 1 ∧
        (pos2.val < passwd.length → pos2.val = 0 ∨ ByteAt passwd.val (pos2.val - 1) 10) ∧
        (∀ e, found2 = some e → FoundEntry passwd.val who1 uid e) ∧
        passwd.length + 1 - pos2.val < passwd.length + 1 - pos1.val := by
      intro found2 pos2 pos2_post sound2
      refine ⟨by omega, ?_, sound2, by omega⟩
      intro lt2
      right
      have := hfin_nl (by omega)
      rw [pos2_post]; simpa using this
    rcases o with _ | e
    · simp only [bind_ok]
      step as ⟨ pos2, pos2_post ⟩
      exact finish found1 pos2 pos2_post h3
    · have entry := o_post e rfl
      have ⟨name_le, name_lt⟩ := passwd_entry_bounds _ _ _ e entry
      have name_in : e.name.2.val ≤ passwd.length := by omega
      simp only
      step with by_name_spec passwd e who1 name_le name_in as ⟨ r, he1, hname ⟩
      obtain ⟨e1, bn⟩ := r
      simp only at he1 hname
      subst he1
      -- the entry is kept when the name or the uid is the one asked for
      cases bn
      · simp
        step with option_eq_u32 uid e1.uid as ⟨ b1, hb1 ⟩
        by_cases hb : b1 = true
        · simp [hb]
          step as ⟨ pos2, pos2_post ⟩
          refine finish (some e1) pos2 pos2_post ?_
          intro e' he'; cases he'
          exact ⟨pos1.val, stop.val, hline, entry, Or.inr (hb1.mp hb)⟩
        · simp [hb]
          step as ⟨ pos2, pos2_post ⟩
          exact finish found1 pos2 pos2_post h3
      · simp
        step as ⟨ pos2, pos2_post ⟩
        refine finish (some e1) pos2 pos2_post ?_
        intro e' he'; cases he'
        obtain ⟨n, hn1, hn2⟩ := hname rfl
        exact ⟨pos1.val, stop.val, hline, entry, Or.inl ⟨n, hn1, hn2⟩⟩
  · exact ⟨rfl, hpos, starts, sound⟩

/-- `passwd_find` returns, and an entry it answers is an entry of a line of the file with the name or the uid asked for. -/
theorem passwd_find_spec (passwd : Slice Std.U8) (who : Option (Slice Std.U8))
    (uid : Option Std.U32) (short : passwd.length < Std.Usize.max) :
    passwd_find passwd who uid ⦃ r => ∀ e, r = some e → FoundEntry passwd.val who uid e ⦄ := by
  unfold passwd_find
  exact passwd_find_loop_spec passwd who uid 0#usize none short (by simp) (fun _ => Or.inl rfl)
    (by simp)

/-- `find_user` looks by uid when it has an id, by name otherwise. -/
theorem find_user_spec (passwd nm : Slice Std.U8) (id : Option Std.U32)
    (short : passwd.length < Std.Usize.max) :
    find_user passwd nm id ⦃ r =>
      (∀ n, id = some n → ∀ e, r = some e → FoundEntry passwd.val none id e) ∧
      (id = none → ∀ e, r = some e → FoundEntry passwd.val (some nm) none e) ⦄ := by
  unfold find_user
  cases id with
  | some n =>
    rw [if_yes (by simp)]
    step with passwd_find_spec passwd none (some n) short as ⟨ r, r_post ⟩
    refine ⟨fun m hm e he => ?_, by simp⟩
    cases hm; exact r_post e he
  | none =>
    rw [if_no (by simp)]
    step with passwd_find_spec passwd (some nm) none short as ⟨ r, r_post ⟩
    exact ⟨by simp, fun _ => r_post _⟩

end UserCore
