-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `component_bad` does: when it finds nothing wrong, the bytes are a
-- component of the grammar (`Component`): lower-case letters and digits joined by one `.`, one or
-- two `_`, or a run of `-`. It also shows the other direction: `component_bad` finds nothing wrong
-- in every component of the grammar.
-- Why it is needed: a path is made of components, and a component is where `.`, `..` and the empty
-- name are refused.
-- Read before this file: Digests.lean, ComponentShapes.lean.
-- Notation: as in Hosts.lean.
import RefCore.Digests
import RefCore.ComponentShapes
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The inner loop of `component_bad` goes to the end of a run of one byte: it stops at the first
byte that differs, or at the end. -/
@[step] theorem run_loop_finds_the_end_of_the_run (s : Slice Std.U8) (stop i : Std.Usize)
    (b : Nat) (below : i.val < stop.val) (inside : stop.val ≤ s.length)
    (byte : (Bytes s.val)[i.val]? = some b) :
    component_bad_loop0_loop0 s stop i i ⦃ e =>
      i.val ≤ e.val ∧ e.val ≤ stop.val ∧ (∀ x ∈ Piece (Bytes s.val) i e, x = b) ∧
      (e.val < stop.val → ∃ y, (Bytes s.val)[e.val]? = some y ∧ y ≠ b) ⦄ := by
  unfold component_bad_loop0_loop0
  apply loop.spec_decr_nat (fun (e : Std.Usize) => stop.val - e.val)
    (fun (e : Std.Usize) => i.val ≤ e.val ∧ e.val ≤ stop.val ∧
      ∀ x ∈ Piece (Bytes s.val) i e, x = b)
  · intro e ⟨after_start, before_stop, same_so_far⟩
    unfold component_bad_loop0_loop0.body
    split
    · rename_i inside_run
      step as ⟨ x, x_post ⟩
      step as ⟨ first, first_post ⟩
      have x_at := bytes_at s e x (by scalar_tac) x_post
      have first_at := bytes_at s i first (by scalar_tac) first_post
      rw [byte] at first_at
      have first_is : first.val = b := (Option.some.inj first_at).symm
      split
      · rename_i same
        have same_val : x.val = b := by rw [← first_is]; exact (eq_says x first).mp same
        step as ⟨ next, next_post ⟩
        refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        rw [next_post, piece_snoc _ _ _ _ after_start x_at]
        intro y y_in
        rcases List.mem_append.mp y_in with old | new
        · exact same_so_far y old
        · rw [List.mem_singleton.mp new]; exact same_val
      · rename_i different
        simp only [WP.spec_ok]
        refine ⟨after_start, before_stop, same_so_far, fun _ => ⟨x.val, x_at, fun is_b => ?_⟩⟩
        exact different (by rw [eq_says]; rw [is_b, first_is])
    · rename_i not_inside
      simp only [WP.spec_ok]
      exact ⟨after_start, before_stop, same_so_far, fun below_stop => by scalar_tac⟩
  · exact ⟨by scalar_tac, by scalar_tac, by simp [piece_empty]⟩

/-- When a run of `m` bytes `x` is followed by another byte, the inner loop of `component_bad` goes
to the end of the run. -/
theorem run_loop_goes_to_the_end_of_the_run (s : Slice Std.U8) (stop i : Std.Usize) (m x b : Nat)
    (rest : List Nat) (below : i.val < stop.val) (inside : stop.val ≤ s.length)
    (cut : Piece (Bytes s.val) i stop = List.replicate m x ++ b :: rest) (not_empty : 1 ≤ m)
    (different : b ≠ x) :
    component_bad_loop0_loop0 s stop i i ⦃ e => e.val = i.val + m ⦄ := by
  have run_at : ∀ k, k < m → (Bytes s.val)[i.val + k]? = some x := by
    intro k small
    apply piece_byte (Bytes s.val) i stop k x
    rw [cut, List.getElem?_append_left (by simpa using small)]
    simp [small]
  have b_at : (Bytes s.val)[i.val + m]? = some b := by
    apply piece_byte (Bytes s.val) i stop m b
    rw [cut, List.getElem?_append_right (by simp)]
    simp
  have width := piece_length (Bytes s.val) i stop below.le (by simpa using inside)
  rw [cut] at width
  simp only [List.length_append, List.length_replicate, List.length_cons] at width
  have first_at := run_at 0 (by omega)
  rw [Nat.add_zero] at first_at
  step with run_loop_finds_the_end_of_the_run s stop i x below inside first_at
    as ⟨ e, e_after, e_before, e_same, e_stop ⟩
  by_cases same : e.val = i.val + m
  · exact same
  · exfalso
    rcases Nat.lt_or_gt_of_ne same with earlier | later
    · obtain ⟨y, y_at, y_ne⟩ := e_stop (by omega)
      have := run_at (e.val - i.val) (by omega)
      rw [show i.val + (e.val - i.val) = e.val by omega, y_at] at this
      exact y_ne (Option.some.inj this)
    · have in_run : b ∈ Piece (Bytes s.val) i e :=
        piece_contains _ _ _ (i.val + m) b (by omega) later b_at
      exact different (e_same b in_run)

/-- What the loop of `component_bad` keeps true at the place `q.2`, with `q.1` the byte it found
wrong, if any: it did not begin wrong, and while nothing is wrong, what was read is the beginning
of a component. -/
def ComponentInvariant (s : Slice Std.U8) (start stop : Std.Usize) (bad : Option Std.Usize)
    (q : Option Std.Usize × Std.Usize) : Prop :=
  start.val ≤ q.2.val ∧ q.2.val ≤ stop.val ∧
    (q.1 = none → bad = none ∧ ComponentSoFar (Bytes s.val) start q.2 stop)

/-- What a turn of that loop gives: it ends with no byte found wrong only on a component, or it
goes on, further, with the invariant. -/
def ComponentTurn (s : Slice Std.U8) (start stop : Std.Usize) (bad : Option Std.Usize)
    (i : Std.Usize) : ControlFlow (Option Std.Usize × Std.Usize) (Option Std.Usize) → Prop
  | .done y => y = none → bad = none ∧ Component (Piece (Bytes s.val) start stop)
  | .cont q => ComponentInvariant s start stop bad q ∧ stop.val - q.2.val < stop.val - i.val

/-- After a separator, `component_bad` looks at the byte that follows: when it is a letter or a
digit it goes on from there, else it marks the place. -/
theorem component_goes_on_after_the_separator (s : Slice Std.U8) (start stop : Std.Usize)
    (bad found : Option Std.Usize) (i e : Std.Usize) (bad_none : bad = none)
    (_unfound : found = none) (after_start : start.val ≤ i.val) (e_after : i.val + 1 ≤ e.val)
    (e_lt : e.val < stop.val) (inside : stop.val ≤ s.length)
    (component_c : Component (Piece (Bytes s.val) start i))
    (separator : IsSeparator (Piece (Bytes s.val) i e)) :
    (do
      let i2 ← s.index_usize e
      let b2 ← is_alnum i2
      if b2 = true then ok (ControlFlow.cont (found, e))
      else ok (ControlFlow.cont (some e, e))) ⦃ r => ComponentTurn s start stop bad i r ⦄ := by
  step as ⟨ y, y_post ⟩
  step as ⟨ alnum, alnum_post ⟩
  have y_at := bytes_at s e y (by scalar_tac) y_post
  split
  · rename_i is_alnum
    simp only [WP.spec_ok, ComponentTurn, ComponentInvariant]
    refine ⟨⟨by scalar_tac, by scalar_tac, fun _ => ⟨bad_none, ?_⟩⟩, by scalar_tac⟩
    exact Or.inr (Or.inr ⟨Piece (Bytes s.val) start i, Piece (Bytes s.val) i e, component_c,
      separator, piece_append _ start i e after_start (by scalar_tac), e_lt, y.val, y_at,
      alnum_post.mp is_alnum⟩)
  · simp only [WP.spec_ok, ComponentTurn, ComponentInvariant]
    exact ⟨⟨by scalar_tac, by scalar_tac, fun h => by simp at h⟩, by scalar_tac⟩

/-- The loop of `component_bad` reads a component from left to right: when it finds nothing wrong,
what it has read is a component of the grammar. -/
@[step] theorem component_loop_checks_the_separators (s : Slice Std.U8) (start stop : Std.Usize)
    (bad : Option Std.Usize) (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (initially : bad = none → start.val < stop.val ∧
      (∃ x, (Bytes s.val)[start.val]? = some x ∧ IsAlnum x) ∧
      ∃ z, (Bytes s.val)[stop.val - 1]? = some z ∧ IsAlnum z) :
    component_bad_loop0 s stop bad start ⦃ r =>
      (r = none → bad = none ∧ Component (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold component_bad_loop0
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => stop.val - q.2.val)
    (ComponentInvariant s start stop bad)
  · rintro ⟨found, i⟩ ⟨after_start, before_stop, so_far⟩
    simp only at after_start before_stop so_far
    unfold component_bad_loop0.body
    dsimp only
    split
    · rename_i below
      split
      · rename_i unfound
        have unfound' := (is_none_says found).mp unfound
        obtain ⟨bad_none, state⟩ := so_far unfound'
        obtain ⟨_, first_alnum, last_alnum⟩ := initially bad_none
        step as ⟨ x, x_post ⟩
        step as ⟨ alnum, alnum_post ⟩
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have snoc := piece_snoc (Bytes s.val) start i x.val after_start x_at
        split
        · rename_i is_alnum
          step as ⟨ next, next_post ⟩
          refine ⟨⟨by scalar_tac, by scalar_tac, fun _ => ⟨bad_none, ?_⟩⟩, by scalar_tac⟩
          refine Or.inr (Or.inl ?_)
          rw [next_post, snoc]
          exact so_far_then_a_letter (alnum_post.mp is_alnum) _ _ _ _ state rfl
        · rename_i not_alnum
          have x_not : ¬ IsAlnum x.val := fun a => not_alnum (alnum_post.mpr a)
          have component_c : Component (Piece (Bytes s.val) start i) := by
            rcases state with empty | whole | ⟨c, sep, _, _, _, _, y, y_at, y_alnum⟩
            · exfalso
              have same : i.val = start.val := by
                have := piece_length (Bytes s.val) start i after_start
                  (by simpa using (by scalar_tac : i.val ≤ s.length))
                rw [empty] at this
                simp at this
                omega
              obtain ⟨x', x'_at, x'_alnum⟩ := first_alnum
              rw [← same, x_at] at x'_at
              exact x_not (by rw [Option.some.inj x'_at]; exact x'_alnum)
            · exact whole
            · exfalso
              rw [x_at] at y_at
              exact x_not (by rw [Option.some.inj y_at]; exact y_alnum)
          have below' : i.val < stop.val := by scalar_tac
          step with run_loop_finds_the_end_of_the_run s stop i x.val below' inside x_at
            as ⟨ e, e_after, e_before, e_same, e_stop ⟩
          step as ⟨ run, run_post ⟩
          step as ⟨ sep, sep_post ⟩
          have sep_at := bytes_at s i sep (by scalar_tac) sep_post
          rw [x_at] at sep_at
          have sep_val : sep.val = x.val := (Option.some.inj sep_at).symm
          have e_gt : i.val + 1 ≤ e.val := by
            by_contra not_gt
            obtain ⟨y, y_at, y_ne⟩ := e_stop (by scalar_tac)
            have : e.val = i.val := by scalar_tac
            rw [this, x_at] at y_at
            exact y_ne (Option.some.inj y_at).symm
          have e_lt : e.val < stop.val := by
            by_contra not_lt
            have at_end : e.val = stop.val := by scalar_tac
            obtain ⟨z, z_at, z_alnum⟩ := last_alnum
            have z_last := piece_last (Bytes s.val) i stop z below' z_at
            obtain ⟨_, z_in⟩ := List.getLast?_eq_some_iff.mp z_last
            have z_mem : z ∈ Piece (Bytes s.val) i stop := by rw [z_in]; simp
            rw [← at_end] at z_mem
            exact x_not (by rw [← e_same z z_mem]; exact z_alnum)
          have run_val : run.val = e.val - i.val := run_post
          have run_piece : Piece (Bytes s.val) i e = List.replicate run.val x.val := by
            apply List.eq_replicate_iff.mpr ⟨?_, e_same⟩
            rw [piece_length _ _ _ e_after (by simpa using (by scalar_tac : e.val ≤ s.length))]
            scalar_tac
          have c1 : ((sep != 45#u8) = true) ↔ x.val ≠ 45 := by rw [bne_says, sep_val]; rfl
          have c2 : (sep = 46#u8) ↔ x.val = 46 := by rw [eq_says, sep_val]; rfl
          have c3 : (run = 1#usize) ↔ run.val = 1 := by rw [UScalar.eq_equiv]; rfl
          have c4 : (sep = 95#u8) ↔ x.val = 95 := by rw [eq_says, sep_val]; rfl
          have c5 : (run <= 2#usize) ↔ run.val ≤ 2 := by rw [UScalar.le_equiv]; rfl
          simp only [c1, c2, c3, c4, c5]
          iterate 5 (all_goals (try split))
          all_goals first
            | (simp only [WP.spec_ok]
               exact ⟨⟨by scalar_tac, by scalar_tac, fun h => by simp at h⟩, by scalar_tac⟩)
            | (have valid : x.val = 45 ∨ (x.val = 46 ∧ run.val = 1) ∨ (x.val = 95 ∧ run.val ≤ 2)
                := by
                 omega
               refine WP.spec_mono (component_goes_on_after_the_separator s start stop bad found i e
                 bad_none unfound' after_start e_gt e_lt inside component_c
                 (by rw [run_piece]; exact run_is_a_separator _ _ (by scalar_tac) valid)) ?_
               intro r turn
               cases r <;> exact turn)
      · rename_i found_one
        simp only [WP.spec_ok]
        intro is_none
        exact absurd ((is_none_says found).mpr is_none) found_one
    · rename_i not_below
      simp only [WP.spec_ok]
      intro is_none
      obtain ⟨bad_none, state⟩ := so_far is_none
      obtain ⟨below_stop, _⟩ := initially bad_none
      have at_end : i.val = stop.val := by scalar_tac
      refine ⟨bad_none, ?_⟩
      rcases state with empty | whole | ⟨_, _, _, _, _, limit, _⟩
      · exact absurd (by rw [at_end] at empty; exact empty)
          (piece_not_empty _ _ _ below_stop (by simpa using inside))
      · rw [at_end] at whole; exact whole
      · exact absurd limit (by scalar_tac)
  · exact ⟨le_refl _, ordered, fun is_none => ⟨is_none, Or.inl (piece_empty _ _)⟩⟩

/-- What a turn of the loop of `component_bad` gives when nothing is wrong so far: it ends with
nothing found wrong, or it goes on, further, with what can follow. -/
def CompleteTurn (s : Slice Std.U8) (stop i : Std.Usize) :
    ControlFlow (Option Std.Usize × Std.Usize) (Option Std.Usize) → Prop
  | .done y => y = none
  | .cont q => (q.2.val ≤ stop.val ∧ q.1 = none ∧ ComponentTail (Piece (Bytes s.val) q.2 stop)) ∧
      stop.val - q.2.val < stop.val - i.val

/-- After a separator, `component_bad` looks at the byte that follows: a letter or a digit, so it
goes on from there. -/
theorem component_goes_on_after_the_run (s : Slice Std.U8) (stop i e : Std.Usize) (b : Nat)
    (rest : List Nat) (after : i.val < e.val) (below : e.val < stop.val)
    (inside : stop.val ≤ s.length) (cut : Piece (Bytes s.val) e stop = b :: rest)
    (alnum : IsAlnum b) (more : ComponentTail rest) :
    (do
      let i2 ← s.index_usize e
      let b2 ← is_alnum i2
      if b2 = true then ok (ControlFlow.cont (none, e))
      else ok (ControlFlow.cont (some e, e))) ⦃ r => CompleteTurn s stop i r ⦄ := by
  step as ⟨ y, y_post ⟩
  step as ⟨ is_alnum_y, is_alnum_post ⟩
  have y_at := bytes_at s e y (by scalar_tac) y_post
  have b_at : (Bytes s.val)[e.val]? = some b := piece_head _ _ _ _ below (by rw [cut]; rfl)
  rw [y_at] at b_at
  have y_is : y.val = b := Option.some.inj b_at
  split
  · simp only [WP.spec_ok, CompleteTurn]
    exact ⟨⟨by scalar_tac, trivial, by rw [cut]; exact ComponentTail.letter alnum more⟩,
      by scalar_tac⟩
  · rename_i not_alnum
    exact absurd (is_alnum_post.mpr (by rw [y_is]; exact alnum)) not_alnum

/-- The loop of `component_bad` finds nothing wrong in what can follow the first byte of a
component. -/
theorem component_loop_accepts_every_tail (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (tail : ComponentTail (Piece (Bytes s.val) start stop)) :
    component_bad_loop0 s stop none start ⦃ r => r = none ⦄ := by
  unfold component_bad_loop0
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => stop.val - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => q.2.val ≤ stop.val ∧ q.1 = none ∧
      ComponentTail (Piece (Bytes s.val) q.2 stop))
  · rintro ⟨found, i⟩ ⟨before_stop, unfound, tail⟩
    simp only at before_stop unfound tail
    subst unfound
    unfold component_bad_loop0.body
    dsimp only
    split
    · rename_i below
      have below_val : i.val < stop.val := by scalar_tac
      simp only [core.option.Option.is_none, Option.isNone_none, ↓reduceIte]
      step as ⟨ x, x_post ⟩
      step as ⟨ alnum, alnum_post ⟩
      have x_at := bytes_at s i x (by scalar_tac) x_post
      have cons := piece_cons (Bytes s.val) i stop x.val (by scalar_tac) x_at
      rcases tail_cases tail with empty | ⟨b, rest, is_cons, b_alnum, more⟩ |
          ⟨sep, b, rest, is_cut, is_sep, b_alnum, more⟩
      · rw [cons] at empty; simp at empty
      · rw [cons] at is_cons
        obtain ⟨x_is, rest_is⟩ := List.cons.inj is_cons
        split
        · step as ⟨ next, next_post ⟩
          exact ⟨by scalar_tac, by rw [next_post, rest_is]; exact more, by scalar_tac⟩
        · rename_i not_alnum
          exact absurd (alnum_post.mpr (by rw [x_is]; exact b_alnum)) not_alnum
      · obtain ⟨y, m, sep_is, m_pos, valid⟩ := separator_is_a_run is_sep
        rw [sep_is] at is_cut
        obtain ⟨m', m_is⟩ : ∃ m', m = m' + 1 := ⟨m - 1, by omega⟩
        have x_is : x.val = y := by
          rw [cons, m_is, List.replicate_succ, List.cons_append] at is_cut
          exact (List.cons.inj is_cut).1
        have y_not_alnum : ¬ IsAlnum y := by
          unfold IsAlnum IsLower IsDigit; omega
        have b_ne : b ≠ y := by
          unfold IsAlnum IsLower IsDigit at b_alnum; omega
        split
        · rename_i is_alnum
          exact absurd (by rw [← x_is]; exact alnum_post.mp is_alnum) y_not_alnum
        · rename_i not_alnum
          have cut : Piece (Bytes s.val) i stop = List.replicate m y ++ b :: rest := is_cut
          have b_after : i.val + m < stop.val := by
            have := piece_length (Bytes s.val) i stop below.le (by simpa using inside)
            rw [cut] at this
            simp at this
            omega
          step with run_loop_goes_to_the_end_of_the_run s stop i m y b rest (by scalar_tac)
            inside cut m_pos b_ne as ⟨ e, e_post ⟩
          step as ⟨ run, run_post ⟩
          step as ⟨ sep, sep_post ⟩
          have sep_at := bytes_at s i sep (by scalar_tac) sep_post
          rw [x_at] at sep_at
          have sep_val : sep.val = x.val := (Option.some.inj sep_at).symm
          have run_val : run.val = m := by scalar_tac
          have c1 : ((sep != 45#u8) = true) ↔ x.val ≠ 45 := by rw [bne_says, sep_val]; rfl
          have c2 : (sep = 46#u8) ↔ x.val = 46 := by rw [eq_says, sep_val]; rfl
          have c3 : (run = 1#usize) ↔ run.val = 1 := by rw [UScalar.eq_equiv]; rfl
          have c4 : (sep = 95#u8) ↔ x.val = 95 := by rw [eq_says, sep_val]; rfl
          have c5 : (run <= 2#usize) ↔ run.val ≤ 2 := by rw [UScalar.le_equiv]; rfl
          have after_run : Piece (Bytes s.val) e stop = b :: rest := by
            have := piece_middle (Bytes s.val) i stop (List.replicate m y) (b :: rest) []
              below_val.le (by simpa using inside) (by rw [cut]; simp)
            have width := piece_length (Bytes s.val) i stop below_val.le (by simpa using inside)
            rw [cut] at width
            simp only [List.length_append, List.length_replicate, List.length_cons] at width
            simp only [List.length_replicate, List.length_cons] at this
            rw [show i.val + m + (rest.length + 1) = stop.val by omega] at this
            rw [show e.val = i.val + m by omega]
            exact this
          simp only [c1, c2, c3, c4, c5]
          iterate 5 (all_goals (try split))
          all_goals first
            | (exfalso; omega)
            | exact WP.spec_mono (component_goes_on_after_the_run s stop i e b rest
                (by omega) (by omega) inside after_run b_alnum more) (fun r h => by
                  cases r with
                  | done y => exact h
                  | cont q => obtain ⟨⟨a, b', c⟩, d⟩ := h; exact ⟨a, b', c, d⟩)
    · simp only [WP.spec_ok]
  · exact ⟨ordered, rfl, tail⟩

/-- `component_bad` finds nothing wrong in every component of the grammar. -/
theorem component_bad_accepts_every_component (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (is_component : Component (Piece (Bytes s.val) start stop)) :
    component_bad s start stop ⦃ r => r = none ⦄ := by
  obtain ⟨⟨first, rest, first_is, first_alnum⟩, _⟩ := component_shape is_component
  have below : start.val < stop.val := by
    by_contra not_below
    have same : stop.val = start.val := by scalar_tac
    rw [same, piece_empty] at first_is
    simp at first_is
  have first_at := piece_head _ _ _ first below (by rw [first_is]; rfl)
  obtain ⟨last, last_is, last_alnum⟩ := component_ends_in_alnum is_component
  have last_at := piece_last_byte _ _ _ last below (by simpa using inside) last_is
  unfold component_bad
  refine WP.spec_bind (Pₘ := fun bad => bad = none) ?_ ?_
  · split
    · rename_i empty
      have : start.val = stop.val := by rw [empty]
      omega
    · step as ⟨ x, x_post ⟩
      step as ⟨ alnum, alnum_post ⟩
      have x_at := bytes_at s start x (by scalar_tac) x_post
      rw [first_at] at x_at
      split
      · step as ⟨ before, before_post ⟩
        step as ⟨ z, z_post ⟩
        step as ⟨ alnum2, alnum2_post ⟩
        have z_at := bytes_at s before z (by scalar_tac) z_post
        rw [show before.val = stop.val - 1 by scalar_tac, last_at] at z_at
        split
        · simp [WP.spec_ok]
        · rename_i not_alnum
          exact absurd (alnum2_post.mpr (by rw [← Option.some.inj z_at]; exact last_alnum))
            not_alnum
      · rename_i not_alnum
        exact absurd (alnum_post.mpr (by rw [← Option.some.inj x_at]; exact first_alnum)) not_alnum
  · intro bad is_none
    rw [is_none]
    exact component_loop_accepts_every_tail s start stop ordered inside
      (component_is_a_tail is_component)

/-- `component_bad` finds nothing wrong only in a component of the grammar. -/
@[step] theorem component_bad_accepts_only_components (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    component_bad s start stop ⦃ r =>
      (r = none → Component (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold component_bad
  refine WP.spec_bind (Pₘ := fun bad => bad = none → start.val < stop.val ∧
      (∃ x, (Bytes s.val)[start.val]? = some x ∧ IsAlnum x) ∧
      ∃ z, (Bytes s.val)[stop.val - 1]? = some z ∧ IsAlnum z) ?_ ?_
  · split
    · simp [WP.spec_ok]
    · rename_i not_empty
      have below : start.val < stop.val := by
        have : start ≠ stop := not_empty
        scalar_tac
      step as ⟨ first, first_post ⟩
      step as ⟨ alnum, alnum_post ⟩
      have first_at := bytes_at s start first (by scalar_tac) first_post
      split
      · rename_i first_ok
        step as ⟨ before, before_post ⟩
        step as ⟨ last, last_post ⟩
        step as ⟨ alnum2, alnum2_post ⟩
        have last_at := bytes_at s before last (by scalar_tac) last_post
        split
        · rename_i last_ok
          simp only [WP.spec_ok]
          intro _
          refine ⟨below, ⟨first.val, first_at, alnum_post.mp first_ok⟩, last.val, ?_,
            alnum2_post.mp last_ok⟩
          rw [← show before.val = stop.val - 1 from by scalar_tac]
          exact last_at
        · simp [WP.spec_ok]
      · simp [WP.spec_ok]
  · intro bad initially
    step as ⟨ r, r_post ⟩
    rename_i is_none
    exact (r_post is_none).2

end RefCore
