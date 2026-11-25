-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the whole loop of `parse` over the groups of categories: it says `ok`
--    exactly when the rest is groups of categories separated by commas, and then it has added
--    their categories.
-- Why it is needed: this is the heart of `ParseIsExactlyTheLevels`.
-- Read before this file: TheBody.lean.
-- Notation: `Items t S`: `t` is groups of categories separated by commas.
import McsCore.TheBody
open Aeneas Aeneas.Std Result velarx_mcs_core
namespace McsCore

/-- The body of the loop of `parse`, from a state that is `ok` and has `more` to read, does what both
`parse_loop1_body_sound` and `parse_loop1_body_complete` say. -/
theorem parse_loop1_body_both (level : Slice Std.U8) (cats : Cats) (start : Std.Usize) :
    parse_loop1.body level (Slice.len level) true cats start true ⦃ r =>
      (∃ ok2 cats2 at2 more2, r = ControlFlow.cont (ok2, cats2, at2, more2) ∧
        (ok2 = true → ∃ l S tail, level.val.drop start.val = l ++ tail ∧ Item l S ∧
          (∀ d, Mem cats2 d ↔ Mem cats d ∨ S d) ∧
          ((tail = [] ∧ more2 = false) ∨
            ∃ rest, tail = 44#u8 :: rest ∧ level.val.drop at2.val = rest ∧ more2 = true))) ∧
      (∀ l S tail, Item l S → level.val.drop start.val = l ++ tail →
        (tail = [] ∨ ∃ rest, tail = 44#u8 :: rest) →
        ∃ cats2 at2 more2, r = ControlFlow.cont (true, cats2, at2, more2) ∧
          (∀ d, Mem cats2 d ↔ Mem cats d ∨ S d) ∧
          ((tail = [] ∧ more2 = false) ∨
            ∃ rest, tail = 44#u8 :: rest ∧ level.val.drop at2.val = rest ∧ more2 = true)) ⦄ := by
  by_cases some : ∃ l S tail, Item l S ∧ level.val.drop start.val = l ++ tail ∧
      (tail = [] ∨ ∃ rest, tail = 44#u8 :: rest)
  · refine WP.spec_and (parse_loop1_body_sound level cats start) ?_
    have := spec_all (m := parse_loop1.body level (Slice.len level) true cats start true)
      (fun D : List Std.U8 × (Nat → Prop) × List Std.U8 =>
        Item D.1 D.2.1 ∧ level.val.drop start.val = D.1 ++ D.2.2 ∧
          (D.2.2 = [] ∨ ∃ rest, D.2.2 = 44#u8 :: rest))
      (fun D r => ∃ cats2 at2 more2, r = ControlFlow.cont (true, cats2, at2, more2) ∧
          (∀ d, Mem cats2 d ↔ Mem cats d ∨ D.2.1 d) ∧
          ((D.2.2 = [] ∧ more2 = false) ∨
            ∃ rest, D.2.2 = 44#u8 :: rest ∧ level.val.drop at2.val = rest ∧ more2 = true))
      (by obtain ⟨l, S, tail, h⟩ := some; exact ⟨(l, S, tail), h⟩)
      (fun D ⟨item, hdrop, follows⟩ =>
        parse_loop1_body_complete level cats start D.1 D.2.1 D.2.2 item hdrop follows)
    refine WP.spec_mono this ?_
    intro r h l S tail item hdrop follows
    exact h (l, S, tail) ⟨item, hdrop, follows⟩
  · refine WP.spec_mono (parse_loop1_body_sound level cats start) ?_
    intro r h
    refine ⟨h, ?_⟩
    intro l S tail item hdrop follows
    exact absurd ⟨l, S, tail, item, hdrop, follows⟩ some

/-- Groups of categories are one group, or a group, a comma and groups. -/
theorem items_cases {T : List Std.U8} {S : Nat → Prop} (h : Items T S) :
    (∃ S1, Item T S1 ∧ S = S1) ∨
    (∃ l r S1 S2, Item l S1 ∧ Items r S2 ∧ T = l ++ 44#u8 :: r ∧ S = (fun c => S1 c ∨ S2 c)) := by
  cases h with
  | last item => exact Or.inl ⟨_, item, rfl⟩
  | more item rest => exact Or.inr ⟨_, _, _, _, item, rest, by simp [text_comma], rfl⟩

/-- What the loop of `parse` that reads the categories does: from the place after the colon it says
`ok` exactly when the rest is groups of categories, and then it has added their categories. -/
theorem parse_loop1_spec (level : Slice Std.U8) (cats : Cats) (start : Std.Usize) :
    parse_loop1 level (Slice.len level) true cats start true ⦃ r =>
      (r.1 = true ↔ ∃ S, Items (level.val.drop start.val) S) ∧
      ∀ S, Items (level.val.drop start.val) S → ∀ d, Mem r.2 d ↔ Mem cats d ∨ S d ⦄ := by
  unfold parse_loop1
  have main : loop (fun x : Bool × Cats × Std.Usize × Bool =>
      parse_loop1.body level (Slice.len level) x.1 x.2.1 x.2.2.1 x.2.2.2) (true, cats, start, true) ⦃ y =>
      (y.1 = true → true = true ∧
        (true = true → ∃ S, Items (level.val.drop start.val) S ∧
          ∀ d, Mem y.2 d ↔ Mem cats d ∨ S d) ∧
        (true = false → ∀ d, Mem y.2 d ↔ Mem cats d)) ∧
      (true = true → true = false → y = (true, cats)) ∧
      (true = true → true = true → ∀ S, Items (level.val.drop start.val) S →
        y.1 = true ∧ ∀ d, Mem y.2 d ↔ Mem cats d ∨ S d) ⦄ := by
    apply loop_answers
      (fun x : Bool × Cats × Std.Usize × Bool =>
        parse_loop1.body level (Slice.len level) x.1 x.2.1 x.2.2.1 x.2.2.2)
      (fun x y =>
        (y.1 = true → x.1 = true ∧
          (x.2.2.2 = true → ∃ S, Items (level.val.drop x.2.2.1.val) S ∧
            ∀ d, Mem y.2 d ↔ Mem x.2.1 d ∨ S d) ∧
          (x.2.2.2 = false → ∀ d, Mem y.2 d ↔ Mem x.2.1 d)) ∧
        (x.1 = true → x.2.2.2 = false → y = (true, x.2.1)) ∧
        (x.1 = true → x.2.2.2 = true → ∀ S, Items (level.val.drop x.2.2.1.val) S →
          y.1 = true ∧ ∀ d, Mem y.2 d ↔ Mem x.2.1 d ∨ S d))
      (fun x => if x.1 = true ∧ x.2.2.2 = true then (level.val.drop x.2.2.1.val).length + 1 else 0)
      (fun _ => True)
    · rintro ⟨ok1, cats', at', more'⟩ -
      simp only
      by_cases hboth : ok1 = true ∧ more' = true
      · obtain ⟨rfl, rfl⟩ := hboth
        refine WP.spec_mono (parse_loop1_body_both level cats' at') ?_
        rintro r ⟨⟨ok2, cats2, at2, more2, rfl, sound⟩, complete⟩
        simp only
        cases ok2 with
        | false =>
          refine ⟨by simp, by simp, ?_⟩
          intro y ⟨first, _, _⟩
          have y_false : y.1 = false := by
            cases hy : y.1 with
            | false => rfl
            | true => exact absurd (first hy).1 (by simp)
          refine ⟨fun h => absurd h (by simp [y_false]), fun _ h => absurd h (by simp), ?_⟩
          intro _ _ S items
          rcases items_cases items with ⟨S1, item, rfl⟩ | ⟨l, r, S1, S2, item, rest, eq, rfl⟩
          · obtain ⟨c3, a3, m3, hr, _⟩ := complete _ _ [] item (by simp) (Or.inl rfl)
            simp at hr
          · obtain ⟨c3, a3, m3, hr, _⟩ := complete _ _ _ item eq (Or.inr ⟨_, rfl⟩)
            simp at hr
        | true =>
          obtain ⟨l, S, tail, hdrop, item, members, shape⟩ := sound rfl
          rcases shape with ⟨tail_nil, rfl⟩ | ⟨rest, tail_eq, drop_eq, rfl⟩
          · refine ⟨by simp, by simp, ?_⟩
            intro y ⟨f1, f2, f3⟩
            have items : Items (level.val.drop at'.val) S := by
              rw [hdrop, tail_nil, List.append_nil]; exact Items.last item
            refine ⟨fun hy => ⟨trivial, fun _ => ⟨S, items, ?_⟩, fun h => absurd h (by simp)⟩,
              fun _ h => absurd h (by simp), ?_⟩
            · intro d; rw [(f1 hy).2.2 rfl d, members d]
            · intro _ _ S'' items''
              rcases items_cases items'' with ⟨S1, item'', rfl⟩ | ⟨l'', r'', S1, S2, item'', rest'', eq'', rfl⟩
              · obtain ⟨c3, a3, m3, hr, mem3, _⟩ := complete _ _ [] item'' (by simp) (Or.inl rfl)
                simp only [ControlFlow.cont.injEq, Prod.mk.injEq] at hr
                obtain ⟨-, rfl, -, -⟩ := hr
                have y_is := f2 rfl rfl
                rw [y_is]
                exact ⟨rfl, fun d => mem3 d⟩
              · obtain ⟨c3, a3, m3, hr, mem3, shape3⟩ :=
                  complete l'' S1 (44#u8 :: r'') item'' eq'' (Or.inr ⟨_, rfl⟩)
                simp only [ControlFlow.cont.injEq, Prod.mk.injEq] at hr
                obtain ⟨-, -, -, rfl⟩ := hr
                rcases shape3 with ⟨h, _⟩ | ⟨_, _, _, h⟩ <;> simp at h
          · refine ⟨by simp, ?_, ?_⟩
            · simp [hdrop, tail_eq, drop_eq]
            · intro y ⟨f1, f2, f3⟩
              refine ⟨fun hy => ⟨trivial, fun _ => ?_, fun h => absurd h (by simp)⟩,
                fun _ h => absurd h (by simp), ?_⟩
              · obtain ⟨-, some, -⟩ := f1 hy
                obtain ⟨S', items', mem'⟩ := some rfl
                refine ⟨fun c => S c ∨ S' c, ?_, ?_⟩
                · have : level.val.drop at'.val = l ++ Text "," ++ rest := by
                    rw [hdrop, tail_eq, text_comma]; simp
                  rw [this]
                  have items_rest : Items rest S' := by rw [← drop_eq]; exact items'
                  exact Items.more item items_rest
                · intro d; rw [mem' d, members d, or_assoc]
              · intro _ _ S'' items''
                rcases items_cases items'' with ⟨S1, item'', rfl⟩ | ⟨l'', r'', S1, S2, item'', rest'', eq'', rfl⟩
                · obtain ⟨c3, a3, m3, hr, mem3, shape3⟩ := complete _ _ [] item'' (by simp) (Or.inl rfl)
                  simp only [ControlFlow.cont.injEq, Prod.mk.injEq] at hr
                  obtain ⟨-, -, -, rfl⟩ := hr
                  rcases shape3 with ⟨-, h⟩ | ⟨_, h, _⟩ <;> simp at h
                · obtain ⟨c3, a3, m3, hr, mem3, shape3⟩ :=
                    complete l'' S1 (44#u8 :: r'') item'' eq'' (Or.inr ⟨_, rfl⟩)
                  simp only [ControlFlow.cont.injEq, Prod.mk.injEq] at hr
                  obtain ⟨-, rfl, rfl, -⟩ := hr
                  rcases shape3 with ⟨h, _⟩ | ⟨rest3, h3, dr3, -⟩
                  · simp at h
                  · have r_eq : r'' = rest3 := (List.cons.inj h3).2
                    subst r_eq
                    obtain ⟨hy, mem_y⟩ := f3 rfl rfl S2 (by rw [dr3]; exact rest'')
                    refine ⟨hy, fun d => ?_⟩
                    rw [mem_y d, mem3 d, or_assoc]
      · unfold parse_loop1.body
        by_cases hok : ok1 = true
        · have hmore : more' = false := by
            cases hm : more' with
            | false => rfl
            | true => exact absurd ⟨hok, hm⟩ hboth
          subst hok hmore
          simp only [ite_true, Bool.false_eq_true, ite_false]
          refine (WP.spec_ok _).mpr ?_
          refine ⟨fun hy => ⟨trivial, fun h => absurd h (by simp), fun _ d => Iff.rfl⟩, ?_, ?_⟩
          · intro _ _; rfl
          · intro _ h; exact absurd h (by simp)
        · have hok' : ok1 = false := by simpa using hok
          subst hok'
          simp only [Bool.false_eq_true, ite_false]
          refine (WP.spec_ok _).mpr ?_
          refine ⟨fun hy => absurd hy (by simp), ?_, ?_⟩ <;>
          · intro h; exact absurd h (by simp)
    · trivial
  refine WP.spec_mono main ?_
  rintro y ⟨sound, -, complete⟩
  refine ⟨⟨fun h => ?_, fun ⟨S, items⟩ => ?_⟩, fun S items => ?_⟩
  · obtain ⟨-, some, -⟩ := sound h
    obtain ⟨S, items, -⟩ := some rfl
    exact ⟨S, items⟩
  · exact (complete rfl rfl S items).1
  · exact (complete rfl rfl S items).2

end McsCore
