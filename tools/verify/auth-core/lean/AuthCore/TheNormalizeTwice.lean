-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `normalize` of a key that `normalize` answered is that key again
-- (`NormalizeTwiceIsNormalize` of Spec.lean).  The work is on `Normalized`, with no Rust in it:
-- `normalize` answers `Normalized` (TheNormalize.lean), so it is enough that `Normalized` of what
-- `Normalized` answers is the same.  Each of the three kinds of key is followed: what is kept has
-- the same kind (a web key becomes a key with no scheme, a key with no scheme stays one, a key of
-- another scheme keeps its scheme, now in lower case) and the second time nothing changes.
-- Why it is needed: a client and the engine both normalize the keys of an auth file; if a second
-- `normalize` changed a key, they would not agree on it.  (It found a defect: the cut of the `/`
-- at the end took the `://` of `index.docker.io/a://` too, and the second time the key was read
-- with no scheme and became `docker.io/a:`.)
-- Read before this file: Spec.lean, Pieces.lean, TheNormalize.lean.
-- Notation: `l.takeWhile p` and `l.dropWhile p` are what is before and what is from the first
-- element that does not satisfy `p`; `l <+: l'` is "l is the beginning of l'"; `l.map f` is `f` of
-- each element.
import AuthCore.Spec
import AuthCore.Pieces
import AuthCore.TheNormalize

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-! ### The lower case of a byte -/

/-- A byte that is not a capital letter is its own lower case. -/
theorem lower_of_not_upper (b : Std.U8) (not_upper : ¬ (65 ≤ b.val ∧ b.val ≤ 90)) :
    LowerByte b = b := by
  unfold LowerByte
  simp only [not_upper, ↓reduceIte]

/-- The lower case of a capital letter is 32 above it. -/
theorem lower_of_upper (b : Std.U8) (upper : 65 ≤ b.val ∧ b.val ≤ 90) :
    (LowerByte b).val = b.val + 32 := by
  unfold LowerByte
  simp only [upper, and_self, ↓reduceIte]
  show (BitVec.ofNat 8 (b.val + 32)).toNat = b.val + 32
  rw [BitVec.toNat_ofNat]
  omega

/-- The lower case of a lower case is the same. -/
theorem lower_twice (b : Std.U8) : LowerByte (LowerByte b) = LowerByte b := by
  by_cases upper : 65 ≤ b.val ∧ b.val ≤ 90
  · exact lower_of_not_upper _ (by rw [lower_of_upper b upper]; omega)
  · rw [lower_of_not_upper b upper, lower_of_not_upper b upper]

/-- A byte that is no letter (`/`, `:`, `?`, `#`) is the lower case of itself only. -/
theorem lower_is_no_letter (b c : Std.U8) (no_letter : c.val < 65) : LowerByte b = c ↔ b = c := by
  constructor
  · intro same
    by_cases upper : 65 ≤ b.val ∧ b.val ≤ 90
    · have := lower_of_upper b upper
      rw [same] at this
      omega
    · rwa [lower_of_not_upper b upper] at same
  · intro same
    rw [same]
    exact lower_of_not_upper c (by omega)

/-- A list in lower case twice is in lower case once. -/
theorem map_lower_twice (l : Bytes) : (l.map LowerByte).map LowerByte = l.map LowerByte := by
  rw [List.map_map]
  congr 1
  funext b
  exact lower_twice b

/-! ### Where the scheme is cut -/

/-- With no `://` in `b :: l`, there is none in `l`. -/
theorem no_scheme_of_cons (b : Std.U8) (l : Bytes) (none_here : SchemeSplit (b :: l) = none) :
    SchemeSplit l = none := by
  rw [SchemeSplit] at none_here
  split at none_here
  · simp at none_here
  · simpa using none_here

/-- With no `://` in a list, there is none in its end. -/
theorem no_scheme_of_end (a l : Bytes) (none_here : SchemeSplit (a ++ l) = none) :
    SchemeSplit l = none := by
  induction a with
  | nil => simpa using none_here
  | cons b a ih => exact ih (no_scheme_of_cons b _ none_here)

/-- With no `://` in a list, there is none in its beginning. -/
theorem no_scheme_of_beginning (l T : Bytes) (none_here : SchemeSplit l = none) (pref : T <+: l) :
    SchemeSplit T = none := by
  induction l generalizing T with
  | nil =>
    rw [List.prefix_nil.mp pref]
    rfl
  | cons b l ih =>
    cases T with
    | nil => rfl
    | cons c T =>
      obtain ⟨same, pref'⟩ := List.cons_prefix_cons.mp pref
      subst same
      rw [SchemeSplit] at none_here ⊢
      split at none_here
      · simp at none_here
      · rename_i not_here
        have not_here' : ¬ SchemeEnd <+: c :: T := fun p => not_here (p.trans pref)
        simp only [not_here', ↓reduceIte, Option.map_eq_none_iff]
        exact ih T (by simpa using none_here) pref'

/-- A list with no `/` has no `://`. -/
theorem no_scheme_without_slash (l : Bytes) (no_slash : ∀ x ∈ l, x ≠ Slash) :
    SchemeSplit l = none := by
  induction l with
  | nil => rfl
  | cons b l ih =>
    rw [SchemeSplit]
    have not_here : ¬ SchemeEnd <+: b :: l := fun p =>
      no_slash Slash (p.subset (by simp [SchemeEnd])) rfl
    simp only [not_here, ↓reduceIte, Option.map_eq_none_iff]
    exact ih (fun x hx => no_slash x (by simp [hx]))

/-- Bytes with no `:` before a list with no `://` make a list with no `://`. -/
theorem no_scheme_after_no_colon (a l : Bytes) (no_colon : ∀ x ∈ a, x ≠ Colon)
    (none_here : SchemeSplit l = none) : SchemeSplit (a ++ l) = none := by
  induction a with
  | nil => simpa using none_here
  | cons c a ih =>
    rw [List.cons_append, SchemeSplit]
    have not_here : ¬ SchemeEnd <+: c :: (a ++ l) := by
      rintro ⟨t, ht⟩
      simp only [SchemeEnd, List.cons_append, List.cons.injEq] at ht
      exact no_colon c (by simp) ht.1.symm
    simp only [not_here, ↓reduceIte, Option.map_eq_none_iff]
    exact ih (fun x hx => no_colon x (by simp [hx]))

/-- When a list is cut at its first `://` into a scheme and the rest, no `://` begins before the
end of the scheme: the scheme and the `:/` that follow it have none. -/
theorem nothing_before_the_scheme_end (l s r : Bytes) (cut : SchemeSplit l = some (s, r)) :
    SchemeSplit (s ++ [Colon, Slash]) = none := by
  induction l generalizing s r with
  | nil => simp [SchemeSplit] at cut
  | cons b l ih =>
    rw [SchemeSplit] at cut
    split at cut
    · simp only [Option.some.injEq, Prod.mk.injEq] at cut
      rw [← cut.1]
      decide
    · rename_i not_here
      obtain ⟨⟨s0, r0⟩, cut0, same⟩ := Option.map_eq_some_iff.mp cut
      simp only [Prod.mk.injEq] at same
      rw [← same.1, List.cons_append, SchemeSplit]
      have l_is := scheme_split_puts_together _ _ _ cut0
      have not_here : ¬ SchemeEnd <+: b :: (s0 ++ [Colon, Slash]) := fun p =>
        not_here (p.trans (by
          rw [l_is]
          exact ⟨Slash :: r0, by simp [SchemeEnd]⟩))
      simp only [not_here, ↓reduceIte, Option.map_eq_none_iff]
      exact ih s0 r0 cut0

/-- A scheme with no `://` before its end, `://` and any rest are cut there. -/
theorem cut_at_the_scheme_end (s r : Bytes)
    (nothing_before : SchemeSplit (s ++ [Colon, Slash]) = none) :
    SchemeSplit (s ++ SchemeEnd ++ r) = some (s, r) := by
  induction s with
  | nil => simp [SchemeSplit, SchemeEnd]
  | cons b s ih =>
    rw [List.cons_append, SchemeSplit] at nothing_before
    split at nothing_before
    · simp at nothing_before
    · rename_i not_here
      rw [List.cons_append, List.cons_append, SchemeSplit]
      have not_here' : ¬ SchemeEnd <+: b :: (s ++ SchemeEnd ++ r) := fun p =>
        not_here (List.prefix_of_prefix_length_le p
          (by
            rw [List.append_assoc]
            exact List.cons_prefix_cons.mpr ⟨rfl, ⟨Slash :: r, by simp [SchemeEnd]⟩⟩)
          (by simp [SchemeEnd]))
      simp only [not_here', ↓reduceIte]
      rw [ih (by simpa using nothing_before)]
      rfl

/-- In lower case, a list that begins with `://` began with it. -/
theorem scheme_end_of_lower (m : Bytes) (p : SchemeEnd <+: m.map LowerByte) : SchemeEnd <+: m := by
  obtain ⟨t, ht⟩ := p
  match m, ht with
  | x :: y :: z :: rest, ht =>
    simp only [SchemeEnd, List.cons_append, List.nil_append, List.map_cons, List.cons.injEq] at ht
    obtain ⟨hx, hy, hz, -⟩ := ht
    rw [(lower_is_no_letter x Colon (by decide)).mp hx.symm,
      (lower_is_no_letter y Slash (by decide)).mp hy.symm,
      (lower_is_no_letter z Slash (by decide)).mp hz.symm]
    exact ⟨rest, by simp [SchemeEnd]⟩
  | [], ht => simp [SchemeEnd] at ht
  | [_], ht => simp [SchemeEnd] at ht
  | [_, _], ht => simp [SchemeEnd] at ht

/-- A list with no `://` has none in lower case. -/
theorem no_scheme_in_lower (l : Bytes) (none_here : SchemeSplit l = none) :
    SchemeSplit (l.map LowerByte) = none := by
  induction l with
  | nil => rfl
  | cons b l ih =>
    rw [SchemeSplit] at none_here
    split at none_here
    · simp at none_here
    · rename_i not_here
      rw [List.map_cons, SchemeSplit]
      have not_here' : ¬ SchemeEnd <+: LowerByte b :: l.map LowerByte := fun p =>
        not_here (scheme_end_of_lower (b :: l) (by simpa using p))
      simp only [not_here', ↓reduceIte, Option.map_eq_none_iff]
      exact ih (by simpa using none_here)

/-! ### The `/` at the end -/

/-- A list whose last byte is not `/` is left as it is by `TrimSlashes`, and so is the empty
list. -/
theorem trimmed_of_last (l : Bytes) (last : ∀ a x, l = a ++ [x] → x ≠ Slash) :
    TrimSlashes l = l := by
  rcases List.eq_nil_or_concat l with empty | ⟨a, x, is_l⟩
  · rw [empty]; rfl
  · rw [List.concat_eq_append] at is_l
    rw [is_l]
    exact trim_after_another_byte a x (last a x is_l)

/-- What `TrimSlashes` leaves does not end with `/`. -/
theorem last_of_trimmed (l a : Bytes) (x : Std.U8) (is_l : TrimSlashes l = a ++ [x]) :
    x ≠ Slash := by
  intro slash
  have twice : TrimSlashes (TrimSlashes l) = TrimSlashes l := by
    unfold TrimSlashes
    rw [List.reverse_reverse]
    congr 1
    generalize l.reverse = m
    induction m with
    | nil => rfl
    | cons c m ih =>
      by_cases s : c = Slash
      · rw [List.dropWhile_cons_of_pos (by simpa using s)]; exact ih
      · rw [List.dropWhile_cons_of_neg (by simpa using s),
          List.dropWhile_cons_of_neg (by simpa using s)]
  rw [is_l, slash, trim_after_a_slash] at twice
  have := congrArg List.length twice
  have := trim_is_not_longer a
  simp at *
  omega

/-! ### A key with no scheme -/

/-- `Normalized` of a host with no `/` (the Hub under its one name) followed by nothing or by a `/`
and more, with no `://` and no `/` at its end, is that key. -/
theorem normalized_of_a_plain_key (H D : Bytes) (no_slash : ∀ x ∈ H, x ≠ Slash)
    (after : D = [] ∨ ∃ t, D = Slash :: t) (no_scheme : SchemeSplit (H ++ D) = none)
    (trimmed : TrimSlashes (H ++ D) = H ++ D) (hub : HubOf H = H) :
    Normalized (H ++ D) = H ++ D := by
  have head : D.takeWhile (fun b => decide (b ≠ Slash)) = [] ∧
      D.dropWhile (fun b => decide (b ≠ Slash)) = D := by
    rcases after with empty | ⟨t, is_D⟩
    · simp [empty]
    · subst is_D
      constructor
      · exact List.takeWhile_cons_of_neg (by simp)
      · exact List.dropWhile_cons_of_neg (by simp)
  rw [Normalized, no_scheme]
  simp only
  rw [trimmed, List.takeWhile_append_of_pos (by simpa using no_slash), head.1,
    List.dropWhile_append_of_pos (by simpa using no_slash), head.2, List.append_nil, hub]

/-- The Hub under its one name is itself. -/
theorem hub_of_twice (h : Bytes) : HubOf (HubOf h) = HubOf h := by
  unfold HubOf
  by_cases is_alias : h = HubIndex ∨ h = HubRegistry
  · have not_again : ¬ (HubName = HubIndex ∨ HubName = HubRegistry) := by decide
    simp only [is_alias, not_again, ↓reduceIte]
  · simp only [is_alias, ↓reduceIte]

/-- What a key with no `://` is kept as is kept as itself. -/
theorem plain_twice (key : Bytes) (no_scheme : SchemeSplit key = none) :
    Normalized (Normalized key) = Normalized key := by
  have kept : Normalized key =
      HubOf ((TrimSlashes key).takeWhile fun b => decide (b ≠ Slash)) ++
        (TrimSlashes key).dropWhile fun b => decide (b ≠ Slash) := by
    rw [Normalized, no_scheme]
  rw [kept]
  -- the host (`t`) and what follows it (`D`) of what is left without the `/` at the end (`T`)
  generalize hT : TrimSlashes key = T
  have T_pref : T <+: key := hT ▸ trim_is_a_beginning key
  have T_last : ∀ a x, T = a ++ [x] → x ≠ Slash := fun a x is_T =>
    last_of_trimmed key a x (hT ▸ is_T)
  generalize ht : T.takeWhile (fun b => decide (b ≠ Slash)) = t
  generalize hD : T.dropWhile (fun b => decide (b ≠ Slash)) = D
  have T_is : T = t ++ D := by
    rw [← ht, ← hD, List.takeWhile_append_dropWhile]
  have t_no_slash : ∀ x ∈ t, x ≠ Slash := fun x hx => by
    rw [← ht] at hx
    simpa using List.all_eq_true.mp List.all_takeWhile x hx
  have D_after : D = [] ∨ ∃ r, D = Slash :: r := by
    cases D_is : D with
    | nil => exact Or.inl rfl
    | cons c r =>
      right
      refine ⟨r, ?_⟩
      have : (T.dropWhile (fun b => decide (b ≠ Slash))).head (by rw [hD, D_is]; simp) ≠ Slash →
          False := by
        have := List.head_dropWhile_not (fun b => decide (b ≠ Slash)) (l := T)
          (by rw [hD, D_is]; simp)
        simpa using this
      simp only [hD, D_is, List.head_cons] at this
      rw [show c = Slash from Classical.byContradiction this]
  have no_scheme_T : SchemeSplit T = none := no_scheme_of_beginning key T no_scheme T_pref
  have no_scheme_D : SchemeSplit D = none := no_scheme_of_end t D (T_is ▸ no_scheme_T)
  -- what is kept ends as `T` ends
  have last : ∀ H, (∀ x ∈ H, x ≠ Slash) → (D = [] → ∀ a x, H = a ++ [x] → x ≠ Slash) →
      TrimSlashes (H ++ D) = H ++ D := by
    intro H _ H_last
    apply trimmed_of_last
    intro a x is_l
    rcases List.eq_nil_or_concat D with empty | ⟨D0, y, is_D⟩
    · rw [empty, List.append_nil] at is_l
      exact H_last empty a x is_l
    · rw [List.concat_eq_append] at is_D
      rw [is_D, ← List.append_assoc] at is_l
      have := List.append_inj' is_l rfl
      rw [show x = y by simpa using this.2.symm]
      exact T_last (t ++ D0) y (by rw [T_is, is_D, List.append_assoc])
  unfold HubOf
  by_cases is_alias : t = HubIndex ∨ t = HubRegistry
  · -- the host is a name of the Hub: `docker.io` and what follows
    simp only [is_alias, ↓reduceIte]
    have hub_no_slash : ∀ x ∈ HubName, x ≠ Slash := by decide
    exact normalized_of_a_plain_key HubName D hub_no_slash D_after
      (no_scheme_after_no_colon HubName D (by decide) no_scheme_D)
      (last HubName hub_no_slash (fun _ a x is_l => by
        have := congrArg List.getLast? is_l
        simp [HubName] at this
        rw [← this]
        decide))
      (by
        have not_again : ¬ (HubName = HubIndex ∨ HubName = HubRegistry) := by decide
        simp only [HubOf, not_again, ↓reduceIte])
  · -- another host: the key is `T`
    simp only [is_alias, ↓reduceIte]
    exact normalized_of_a_plain_key t D t_no_slash D_after (T_is ▸ no_scheme_T)
      (last t t_no_slash (fun empty a x is_l => T_last a x (by rw [T_is, empty, is_l]; simp)))
      (by simp only [HubOf, is_alias, ↓reduceIte])

/-! ### A key with a scheme -/

/-- What a web key is kept as (its host, with no `/`) is kept as itself. -/
theorem web_twice (rest : Bytes) :
    Normalized (HubOf (rest.takeWhile fun b => decide (b ≠ Slash))) =
      HubOf (rest.takeWhile fun b => decide (b ≠ Slash)) := by
  generalize hk : HubOf (rest.takeWhile fun b => decide (b ≠ Slash)) = kept
  have t_no_slash : ∀ x ∈ rest.takeWhile (fun b => decide (b ≠ Slash)), x ≠ Slash :=
    fun x hx => by simpa using List.all_eq_true.mp List.all_takeWhile x hx
  have no_slash : ∀ x ∈ kept, x ≠ Slash := by
    rw [← hk]
    unfold HubOf
    split
    · decide
    · exact t_no_slash
  have := normalized_of_a_plain_key kept [] no_slash (Or.inl rfl)
    (by simpa using no_scheme_without_slash kept no_slash)
    (by
      rw [List.append_nil]
      exact trimmed_of_last kept (fun a x is_l => no_slash x (by rw [is_l]; simp)))
    (by rw [← hk]; exact hub_of_twice _)
  simpa using this

/-- What a key of another scheme is kept as (the scheme in lower case, `://`, the authority in lower
case and the rest, with no `/` at the end) is kept as itself. -/
theorem other_twice (key s r : Bytes) (cut : SchemeSplit key = some (s, r)) (not_web : ¬ IsWeb s) :
    Normalized (s.map LowerByte ++ SchemeEnd ++ (Authority (TrimSlashes r)).map LowerByte ++
      (TrimSlashes r).drop (Authority (TrimSlashes r)).length) =
    s.map LowerByte ++ SchemeEnd ++ (Authority (TrimSlashes r)).map LowerByte ++
      (TrimSlashes r).drop (Authority (TrimSlashes r)).length := by
  generalize hR : TrimSlashes r = R
  -- the authority (`A`) and what follows it (`X`)
  generalize hA : Authority R = A
  have R_is : R = A ++ R.drop A.length := by
    rw [← hA]
    exact (List.prefix_iff_eq_append.mp (List.takeWhile_prefix _)).symm
  generalize hX : R.drop A.length = X at R_is ⊢
  have X_is : X = R.dropWhile (fun b => decide (b ≠ Slash ∧ b ≠ Question ∧ b ≠ Hash)) := by
    have := List.takeWhile_append_dropWhile
      (p := fun b => decide (b ≠ Slash ∧ b ≠ Question ∧ b ≠ Hash)) (l := R)
    rw [← hX]
    conv_lhs => rw [← this]
    rw [show R.takeWhile _ = A from hA]
    exact List.drop_left
  have A_plain : ∀ x ∈ A, x ≠ Slash ∧ x ≠ Question ∧ x ≠ Hash := fun x hx => by
    rw [← hA] at hx
    have := List.all_eq_true.mp List.all_takeWhile x hx
    simpa using this
  -- in lower case the authority has no `/`, `?` or `#` either
  have A'_plain : ∀ x ∈ A.map LowerByte, x ≠ Slash ∧ x ≠ Question ∧ x ≠ Hash := by
    intro x hx
    obtain ⟨a, ha, is_x⟩ := List.mem_map.mp hx
    rw [← is_x]
    obtain ⟨p1, p2, p3⟩ := A_plain a ha
    exact ⟨fun e => p1 ((lower_is_no_letter a Slash (by decide)).mp e),
      fun e => p2 ((lower_is_no_letter a Question (by decide)).mp e),
      fun e => p3 ((lower_is_no_letter a Hash (by decide)).mp e)⟩
  -- the rest that is kept ends as `R` ends, which has no `/` at its end
  have R_last : ∀ a x, R = a ++ [x] → x ≠ Slash := fun a x is_R => last_of_trimmed r a x (hR ▸ is_R)
  have rest_trimmed : TrimSlashes (A.map LowerByte ++ X) = A.map LowerByte ++ X := by
    apply trimmed_of_last
    intro a x is_l
    rcases List.eq_nil_or_concat X with empty | ⟨X0, y, is_X⟩
    · rw [empty, List.append_nil] at is_l
      have : x ∈ A.map LowerByte := by rw [is_l]; simp
      exact (A'_plain x this).1
    · rw [List.concat_eq_append] at is_X
      rw [is_X, ← List.append_assoc] at is_l
      have := List.append_inj' is_l rfl
      rw [show x = y by simpa using this.2.symm]
      exact R_last (A ++ X0) y (by rw [R_is, is_X, List.append_assoc])
  -- the authority of the rest that is kept is the authority in lower case
  have X_head : X.takeWhile (fun b => decide (b ≠ Slash ∧ b ≠ Question ∧ b ≠ Hash)) = [] := by
    cases X_is' : X with
    | nil => rfl
    | cons c t =>
      have := List.head_dropWhile_not (fun b => decide (b ≠ Slash ∧ b ≠ Question ∧ b ≠ Hash))
        (l := R) (by rw [← X_is, X_is']; simp)
      simp only [← X_is, X_is', List.head_cons] at this
      exact List.takeWhile_cons_of_neg (by simpa using this)
  have authority_kept : Authority (A.map LowerByte ++ X) = A.map LowerByte := by
    unfold Authority
    rw [List.takeWhile_append_of_pos (by simpa using A'_plain), X_head, List.append_nil]
  -- the kept key is cut at the same `://`, and its scheme is no web scheme
  have l_is := scheme_split_puts_together _ _ _ cut
  have before := nothing_before_the_scheme_end _ _ _ cut
  have before' : SchemeSplit (s.map LowerByte ++ [Colon, Slash]) = none := by
    have := no_scheme_in_lower _ before
    rwa [List.map_append, show [Colon, Slash].map LowerByte = [Colon, Slash] by decide] at this
  have cut' : SchemeSplit (s.map LowerByte ++ SchemeEnd ++ A.map LowerByte ++ X) =
      some (s.map LowerByte, A.map LowerByte ++ X) := by
    rw [List.append_assoc (s.map LowerByte ++ SchemeEnd)]
    exact cut_at_the_scheme_end _ _ before'
  have not_web' : ¬ IsWeb (s.map LowerByte) := by
    unfold IsWeb at not_web ⊢
    rwa [map_lower_twice]
  rw [Normalized, cut']
  simp only [not_web', ↓reduceIte]
  rw [List.append_assoc (s.map LowerByte ++ SchemeEnd), rest_trimmed, authority_kept,
    map_lower_twice, map_lower_twice, List.drop_left' (by simp), List.append_assoc]

/-- What any key is kept as is kept as itself. -/
theorem normalized_twice (key : Bytes) : Normalized (Normalized key) = Normalized key := by
  cases cut : SchemeSplit key with
  | none => exact plain_twice key cut
  | some p =>
    obtain ⟨s, r⟩ := p
    by_cases web : IsWeb s
    · -- a web key
      have kept : Normalized key = HubOf (r.takeWhile fun b => decide (b ≠ Slash)) := by
        rw [Normalized, cut]
        simp only [web, ↓reduceIte]
      rw [kept]
      exact web_twice r
    · -- a key of another scheme
      have kept : Normalized key = s.map LowerByte ++ SchemeEnd ++
          (Authority (TrimSlashes r)).map LowerByte ++
          (TrimSlashes r).drop (Authority (TrimSlashes r)).length := by
        rw [Normalized, cut]
        simp only [web, ↓reduceIte]
      rw [kept]
      exact other_twice key s r cut web

/-- **`NormalizeTwiceIsNormalize`**: `normalize` answers `Normalized`, of the key and then of what
it answered. -/
theorem normalize_twice_is_normalize : NormalizeTwiceIsNormalize := by
  intro key kept
  refine WP.spec_mono (normalize_is_the_rule key) ?_
  intro out is_out same
  refine WP.spec_mono (normalize_is_the_rule kept) ?_
  intro again is_again
  rw [is_again, same, is_out, normalized_twice]

end AuthCore
