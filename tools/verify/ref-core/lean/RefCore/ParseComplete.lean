-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that `parse` accepts every reference of the grammar, with the spans that
-- cut the string into its parts: it follows `parse` line by line, as Parse.lean does, and at each
-- line finds the place that the grammar says (the `@`, the last `/`, the `:`, the first `/`).
-- Why it is needed: without it a parser that refuses everything would satisfy every other claim.
-- Read before this file: Parse.lean and the files before it (each reader of a part has, besides
-- "finds nothing wrong only in", "finds nothing wrong in every").
-- Notation: `find s a b x` is the first place of the byte `x` between `a` and `b`; `l ++ l'` is
-- `l` and then `l'`.
import RefCore.Public
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- A path is what comes before its last component (nothing, or a path and a `/`), and its last
component. -/
theorem path_has_a_last_component {p : List Nat} (is_path : Path p) :
    ∃ before c, p = before ++ c ∧ Component c ∧ (before = [] ∨ ∃ path, Path path ∧
      before = path ++ [47]) := by
  cases is_path with
  | one is_component => exact ⟨[], _, by simp, is_component, Or.inl rfl⟩
  | more old is_component => exact ⟨_ ++ [47], _, by simp, is_component, Or.inr ⟨_, old, rfl⟩⟩

/-- A path is its first component, and then nothing or a `/` and a path that can be read. -/
theorem path_has_a_first_component {p : List Nat} (is_path : Path p) :
    ∃ first after, p = first ++ after ∧ Component first ∧
      (after = [] ∨ ∃ rest, after = 47 :: rest) := by
  rcases path_rest_cases (path_is_what_can_be_read is_path) with is_component |
    ⟨c, r, is_component, _, is_cut⟩
  · exact ⟨p, [], by simp, is_component, Or.inl rfl⟩
  · exact ⟨c, 47 :: r, is_cut, is_component, Or.inr ⟨r, rfl⟩⟩

/-- The bytes of a path are lower-case letters, digits, `.`, `_`, `-` and `/`. -/
theorem path_bytes {p : List Nat} (is_path : Path p) :
    ∀ b ∈ p, IsAlnum b ∨ b = 46 ∨ b = 95 ∨ b = 45 ∨ b = 47 := by
  induction is_path with
  | one is_component =>
    intro b inside
    rcases (component_shape is_component).2 b inside with a | d | u | h
    · exact Or.inl a
    · exact Or.inr (Or.inl d)
    · exact Or.inr (Or.inr (Or.inl u))
    · exact Or.inr (Or.inr (Or.inr (Or.inl h)))
  | more old is_component ih =>
    intro b inside
    simp only [List.mem_append, List.mem_singleton] at inside
    rcases inside with (before | slash) | in_c
    · exact ih b before
    · exact Or.inr (Or.inr (Or.inr (Or.inr slash)))
    · rcases (component_shape is_component).2 b in_c with a | d | u | h
      · exact Or.inl a
      · exact Or.inr (Or.inl d)
      · exact Or.inr (Or.inr (Or.inl u))
      · exact Or.inr (Or.inr (Or.inr (Or.inl h)))

/-- A path is not empty. -/
theorem path_is_not_empty {p : List Nat} (is_path : Path p) : p ≠ [] := by
  obtain ⟨first, after, split, is_component, _⟩ := path_has_a_first_component is_path
  obtain ⟨⟨x, rest, is_cons, _⟩, _⟩ := component_shape is_component
  rw [split, is_cons]
  simp

/-- The parts of a reference of the grammar, written one after the other: the host with its `/`,
the path, the tag with its `:`, and the digest with its `@`, each possibly nothing. -/
theorem reference_is_laid_out (r : Reference) :
    ∃ host tag digest, r.Text = host ++ r.path ++ tag ++ digest ∧
      (host = [] ∧ r.host = none ∨ ∃ h, r.host = some h ∧ host = h ++ [47]) ∧
      (tag = [] ∧ r.tag = none ∨ ∃ t, r.tag = some t ∧ tag = 58 :: t) ∧
      (digest = [] ∧ r.digest = none ∨ ∃ d, r.digest = some d ∧ digest = 64 :: d) := by
  refine ⟨(r.host.map (· ++ [47])).getD [], (r.tag.map (58 :: ·)).getD [],
    (r.digest.map (64 :: ·)).getD [], rfl, ?_, ?_, ?_⟩
  · cases h : r.host <;> simp
  · cases h : r.tag <;> simp
  · cases h : r.digest <;> simp

/-- The digest that `parse` checks is found good, when there is one and it is a digest of the
grammar. -/
theorem digest_error_is_none (s : Slice Std.U8) (at_ : Std.Usize)
    (digest : at_.val < s.length → IsDigest (Piece (Bytes s.val) (at_.val + 1) s.length)) :
    (if at_ < s.len then do
        let i ← at_ + 1#usize
        digest_bad s i s.len
      else ok none) ⦃ e => e = none ⦄ := by
  split
  · rename_i has_digest
    step as ⟨ i, i_post ⟩
    have len_val : s.len.val = s.length := by simp
    have below : at_.val < s.length := by scalar_tac
    refine digest_bad_accepts_every_digest s i s.len (by scalar_tac) (by scalar_tac) ?_
    rw [i_post, len_val]
    exact digest below
  · simp [WP.spec_ok]

/-- The tag that `parse` checks is found good, when there is one and it is a tag of the grammar. -/
theorem tag_error_is_none (s : Slice Std.U8) (name_end at_ : Std.Usize)
    (inside : at_.val ≤ s.length)
    (tag : name_end.val < at_.val → IsTag (Piece (Bytes s.val) (name_end.val + 1) at_)) :
    (if name_end < at_ then do
        let i ← name_end + 1#usize
        tag_bad s i at_
      else ok none) ⦃ e => e = none ⦄ := by
  split
  · rename_i has_tag
    step as ⟨ i, i_post ⟩
    have below : name_end.val < at_.val := by scalar_tac
    refine tag_bad_accepts_every_tag s i at_ (by scalar_tac) inside ?_
    rw [i_post]
    exact tag below
  · simp [WP.spec_ok]

/-- The host that `parse` checks is found good, when there is one and it is a host of the
grammar. -/
theorem host_error_is_none (s : Slice Std.U8) (host_end : Std.Usize)
    (inside : host_end.val ≤ s.length)
    (host : 0 < host_end.val → IsHost (Piece (Bytes s.val) 0 host_end)) :
    (if host_end > 0#usize then host_bad s 0#usize host_end else ok none) ⦃ e => e = none ⦄ := by
  split
  · rename_i has_host
    exact host_bad_accepts_every_host s 0#usize host_end (by scalar_tac) inside
      (host (by scalar_tac))
  · simp [WP.spec_ok]

/-- The end of the host that `parse` computes is the first `/` when it follows what looks like a
host, and 0 otherwise. -/
theorem host_end_is (s : Slice Std.U8) (first name_end : Std.Usize)
    (inside : name_end.val ≤ s.length) (first_before : first.val ≤ name_end.val) :
    (if first < name_end then do
        let b ← host_like s 0#usize first
        if b = true then ok first else ok 0#usize
      else ok 0#usize) ⦃ h =>
      (first.val < name_end.val ∧ LooksLikeHost (Piece (Bytes s.val) 0 first) ∧ h = first) ∨
      ((first.val = name_end.val ∨ ¬ LooksLikeHost (Piece (Bytes s.val) 0 first)) ∧
        h = 0#usize) ⦄ := by
  split
  · rename_i has_slash
    step as ⟨ like, like_post ⟩
    split
    · rename_i looks
      simp only [WP.spec_ok]
      exact Or.inl ⟨by scalar_tac, like_post.mp looks, trivial⟩
    · rename_i not_like
      simp only [WP.spec_ok]
      exact Or.inr ⟨Or.inr (fun looks => not_like (like_post.mpr looks)), trivial⟩
  · rename_i no_slash
    simp only [WP.spec_ok]
    exact Or.inr ⟨Or.inl (by scalar_tac), trivial⟩

/-- Two references with the same parts are the same. -/
theorem reference_ext {a b : Reference} (host : a.host = b.host) (path : a.path = b.path)
    (tag : a.tag = b.tag) (digest : a.digest = b.digest) : a = b := by
  cases a; cases b
  simp_all

/-- A host of the grammar is not empty (it looks like a host). -/
theorem host_is_not_empty {h : List Nat} (looks : LooksLikeHost h) : h ≠ [] := by
  rintro rfl
  rcases looks with dot | colon | localhost
  · simp at dot
  · simp at colon
  · simp [Ascii] at localhost

/-- `parse` accepts every reference of the grammar, and the spans it gives cut the string into
exactly the parts of the reference. -/
theorem parse_finds_the_reading (s : Slice Std.U8) (r : Reference) (grammar : r.InGrammar)
    (text : r.Text = Bytes s.val) :
    parse s ⦃ res => ∃ spans, res = core.result.Result.Ok spans ∧ spans.Reading s = r ⦄ := by
  obtain ⟨H, T, D, laid, host_case, tag_case, digest_case⟩ := reference_is_laid_out r
  rw [laid] at text
  have path_is := grammar.path
  obtain ⟨p0, c, p_is, c_comp, p0_kind⟩ := path_has_a_last_component path_is
  obtain ⟨c1, p1, p_first, c1_comp, p1_kind⟩ := path_has_a_first_component path_is
  have path_len : r.path.length = p0.length + c.length := by rw [p_is]; simp
  have path_len' : r.path.length = c1.length + p1.length := by rw [p_first]; simp
  have c_ne : c ≠ [] := by
    obtain ⟨⟨x, rest, is_cons, _⟩, _⟩ := component_shape c_comp
    rw [is_cons]; simp
  have c1_ne : c1 ≠ [] := by
    obtain ⟨⟨x, rest, is_cons, _⟩, _⟩ := component_shape c1_comp
    rw [is_cons]; simp
  have len : s.length = H.length + r.path.length + T.length + D.length := by
    have := congrArg List.length text
    simp only [List.length_append, bytes_length] at this
    exact this.symm
  have len' : (↑s : List Std.U8).length = H.length + r.path.length + T.length + D.length := len
  have path_long : 0 < r.path.length := List.length_pos_iff.mpr (path_is_not_empty path_is)
  have small : s.length ≤ 1024 := by
    have := grammar.short
    rw [laid, text] at this
    simpa using this
  have len_val : s.len.val = s.length := by simp
  unfold parse
  dsimp only
  split
  · rename_i empty
    have : s.len.val = 0 := by rw [empty]; rfl
    omega
  · split
    · rename_i long
      have : s.len.val > MAX_INPUT.val := by scalar_tac
      have max : MAX_INPUT.val = 1024 := by simp [global_simps]
      omega
    · have whole : Piece (Bytes s.val) 0#usize s.len = H ++ r.path ++ T ++ D :=
        piece_of_the_parts s [] (H ++ r.path ++ T ++ D) [] 0#usize s.len (by simpa using text)
          rfl (by simp only [List.length_nil, List.length_append, Nat.zero_add]; omega)
      -- the first `@` is where the digest begins, or the end
      have host_bytes_ok : ∀ h, r.host = some h → ∀ x ∈ h, x ≠ 64 ∧ x ≠ 47 := by
        intro h is_h x inside
        have safe := host_is_safe (grammar.host h is_h).1 x inside
        unfold Dangerous at safe
        omega
      have tag_bytes_ok : ∀ t, r.tag = some t → ∀ x ∈ t, x ≠ 64 ∧ x ≠ 47 ∧ x ≠ 58 := by
        intro t is_t x inside
        have := (grammar.tag t is_t).2.2 x inside
        unfold IsWordByte IsAlnum IsLower IsDigit IsUpper at this
        omega
      have no_at : ∀ x ∈ H ++ r.path ++ T, x ≠ 64 := by
        intro x inside
        simp only [List.mem_append] at inside
        rcases inside with (in_host | in_path) | in_tag
        · rcases host_case with ⟨empty, _⟩ | ⟨h, is_h, h_is⟩
          · rw [empty] at in_host; simp at in_host
          · rw [h_is] at in_host
            simp only [List.mem_append, List.mem_singleton] at in_host
            rcases in_host with in_h | slash
            · exact (host_bytes_ok h is_h x in_h).1
            · omega
        · have := path_bytes path_is x in_path
          unfold IsAlnum IsLower IsDigit at this
          omega
        · rcases tag_case with ⟨empty, _⟩ | ⟨t, is_t, t_is⟩
          · rw [empty] at in_tag; simp at in_tag
          · rw [t_is] at in_tag
            simp only [List.mem_cons] at in_tag
            rcases in_tag with colon | in_t
            · omega
            · exact (tag_bytes_ok t is_t x in_t).1
      step with find_goes_to_the_end_of_the_cut s 0#usize s.len 64#u8 (H ++ r.path ++ T) D
        (by scalar_tac) (by scalar_tac) whole no_at
        (by
          rcases digest_case with ⟨empty, _⟩ | ⟨d, _, is_d⟩
          · exact Or.inl empty
          · exact Or.inr ⟨d, by rw [is_d]; rfl⟩) as ⟨ at_, at_post ⟩
      have at_is : at_.val = H.length + r.path.length + T.length := by
        simp only [List.length_append] at at_post; omega
      clear at_post
      -- the digest of the grammar, if there is one
      refine WP.spec_bind (digest_error_is_none s at_ ?_) ?_
      · intro below
        rcases digest_case with ⟨empty, _⟩ | ⟨d, digest_is, d_is⟩
        · rw [empty] at len; simp only [List.length_nil, Nat.add_zero] at len; omega
        · rw [d_is] at len
          have good := grammar.digest d digest_is
          have len_d : s.length = H.length + r.path.length + T.length + (d.length + 1) := by
            rw [len]; simp
          have len_d' : (↑s : List Std.U8).length = H.length + r.path.length + T.length +
              (d.length + 1) := len_d
          have := piece_of_the_parts s (H ++ r.path ++ T ++ [64]) d [] (at_.val + 1) s.length
            (by rw [← text, d_is]; simp)
            (by simp only [List.length_append, List.length_singleton]; omega)
            (by simp only [List.length_append, List.length_singleton]; omega)
          rw [this]
          exact good
      intro digest_error digest_ok
      subst digest_ok
      simp only
      refine WP.spec_bind (digest_value_says s at_ (by scalar_tac) small) ?_
      intro digest digest_says
      have no_slash_after : ∀ x ∈ c ++ T, x ≠ 47 := by
        intro x inside
        simp only [List.mem_append] at inside
        rcases inside with in_c | in_tag
        · exact component_has_no_slash c_comp x in_c
        · rcases tag_case with ⟨empty, _⟩ | ⟨t, is_t, t_is⟩
          · rw [empty] at in_tag; simp at in_tag
          · rw [t_is] at in_tag
            simp only [List.mem_cons] at in_tag
            rcases in_tag with colon | in_t
            · omega
            · exact (tag_bytes_ok t is_t x in_t).2.1
      have before_digest : Piece (Bytes s.val) 0#usize at_ = H ++ r.path ++ T :=
        piece_of_the_parts s [] (H ++ r.path ++ T) D 0 at_.val (by simpa using text) rfl
          (by simp only [List.length_nil, Nat.zero_add, List.length_append]; omega)
      -- the last `/` is the one before the last component of the path
      have p0_kind' : H ++ p0 = [] ∨ ∃ Y, H ++ p0 = Y ++ [47] := by
        rcases p0_kind with empty | ⟨path, _, p0_is⟩
        · rcases host_case with ⟨h_empty, _⟩ | ⟨h, _, h_is⟩
          · exact Or.inl (by rw [empty, h_empty]; rfl)
          · exact Or.inr ⟨h, by rw [h_is, empty]; simp⟩
        · exact Or.inr ⟨H ++ path, by rw [p0_is]; simp⟩
      refine WP.spec_bind (Pₘ := fun o => (H ++ p0 = [] ∧ o = none) ∨
          ∃ Y k, H ++ p0 = Y ++ [47] ∧ o = some k ∧ k.val = Y.length) ?_ ?_
      · rcases p0_kind' with empty | ⟨Y, is_cut⟩
        · refine WP.spec_mono (find_last_finds_nothing s 0#usize at_ 47#u8 (by scalar_tac)
            (by scalar_tac) ?_) (fun o is_none => Or.inl ⟨empty, is_none⟩)
          rw [before_digest, p_is]
          intro x inside
          have : x ∈ c ++ T := by
            simp only [List.mem_append] at inside ⊢
            rcases inside with (in_host | in_p) | in_t
            · rw [List.append_eq_nil_iff] at empty
              rw [empty.1] at in_host; simp at in_host
            · rcases in_p with in_p0 | in_c
              · rw [List.append_eq_nil_iff] at empty
                rw [empty.2] at in_p0; simp at in_p0
              · exact Or.inl in_c
            · exact Or.inr in_t
          exact no_slash_after x this
        · refine WP.spec_mono (find_last_finds_the_last_byte s 0#usize at_ 47#u8 Y (c ++ T)
            (by scalar_tac) (by scalar_tac) ?_ no_slash_after) (fun o ⟨k, is_k, k_val⟩ =>
            Or.inr ⟨Y, k, is_cut, is_k, by simpa using k_val⟩)
          rw [before_digest, p_is]
          have : H ++ (p0 ++ c) ++ T = (H ++ p0) ++ c ++ T := by simp
          rw [this, is_cut]
          simp
      intro o o_says
      refine WP.spec_bind (Pₘ := fun last => last.val = H.length + p0.length) ?_ ?_
      · cases o with
        | none =>
          simp only [WP.spec_ok]
          rcases o_says with ⟨empty, _⟩ | ⟨Y, k, _, is_some, _⟩
          · rw [List.append_eq_nil_iff] at empty
            rw [empty.1, empty.2]; rfl
          · simp at is_some
        | some k =>
          rcases o_says with ⟨_, is_none⟩ | ⟨Y, k', is_cut, is_k, k_val⟩
          · simp at is_none
          · have same : k' = k := by simpa using is_k.symm
            subst same
            have := congrArg List.length is_cut
            simp only [List.length_append, List.length_singleton] at this
            have k_bound : k'.val ≤ 1024 := by omega
            step as ⟨ last, last_post ⟩
            omega
      intro last last_is
      -- the `:` of the tag is the first one in the last component
      have at_le : at_.val ≤ s.length := by omega
      have last_le : last.val ≤ at_.val := by omega
      have no_colon : ∀ x ∈ c, x ≠ 58 := by
        intro x inside is_colon
        have := (component_shape c_comp).2 x inside
        unfold IsAlnum IsLower IsDigit at this
        omega
      have last_cut : Piece (Bytes s.val) last at_ = c ++ T :=
        piece_of_the_parts s (H ++ p0) (c ++ T) D last.val at_.val
          (by rw [← text, p_is]; simp) (by simp only [List.length_append]; omega)
          (by simp only [List.length_append]; omega)
      step with find_goes_to_the_end_of_the_cut s last at_ 58#u8 c T last_le at_le last_cut
        no_colon (by
          rcases tag_case with ⟨empty, _⟩ | ⟨t, _, t_is⟩
          · exact Or.inl empty
          · exact Or.inr ⟨t, by rw [t_is]; rfl⟩) as ⟨ name_end, name_end_post ⟩
      have name_end_is : name_end.val = H.length + r.path.length := by omega
      refine WP.spec_bind (tag_error_is_none s name_end at_ at_le ?_) ?_
      · intro below
        rcases tag_case with ⟨empty, _⟩ | ⟨t, tag_is, t_is⟩
        · have : T.length = 0 := by rw [empty]; rfl
          omega
        · have good := grammar.tag t tag_is
          have t_len : T.length = t.length + 1 := by rw [t_is]; rfl
          have := piece_of_the_parts s (H ++ r.path ++ [58]) t D (name_end.val + 1) at_.val
            (by rw [← text, t_is]; simp) (by simp only [List.length_append]; simp; omega)
            (by simp only [List.length_append]; simp; omega)
          rw [this]
          exact good
      intro tag_error tag_ok
      subst tag_ok
      simp only
      refine WP.spec_bind (tag_value_says s name_end at_ (by omega) at_le small) ?_
      intro tag tag_says
      -- the first `/` ends the host, when what is before it looks like one
      have name_cut : Piece (Bytes s.val) 0#usize name_end = H ++ r.path :=
        piece_of_the_parts s [] (H ++ r.path) (T ++ D) 0 name_end.val
          (by rw [← text]; simp) rfl (by simp only [List.length_nil, List.length_append]; omega)
      obtain ⟨X, rest, hp_cut, none47, rest_kind, view⟩ : ∃ X rest, H ++ r.path = X ++ rest ∧
          (∀ x ∈ X, x ≠ 47) ∧ (rest = [] ∨ ∃ y, rest = 47 :: y) ∧
          ((∃ h, r.host = some h ∧ H = h ++ [47] ∧ X = h ∧ IsHost h ∧ LooksLikeHost h) ∨
            (r.host = none ∧ H = [] ∧ X = c1 ∧ rest = p1)) := by
        rcases host_case with ⟨empty, no_host⟩ | ⟨h, is_h, h_is⟩
        · exact ⟨c1, p1, by rw [empty, p_first]; rfl, component_has_no_slash c1_comp, p1_kind,
            Or.inr ⟨no_host, empty, rfl, rfl⟩⟩
        · exact ⟨h, [47] ++ r.path, by rw [h_is]; simp,
            fun x inside => (host_bytes_ok h is_h x inside).2, Or.inr ⟨r.path, rfl⟩,
            Or.inl ⟨h, is_h, h_is, rfl, (grammar.host h is_h).1, (grammar.host h is_h).2⟩⟩
      have hp_len : H.length + r.path.length = X.length + rest.length := by
        have := congrArg List.length hp_cut
        simpa using this
      step with find_goes_to_the_end_of_the_cut s 0#usize name_end 47#u8 X rest (by scalar_tac)
        (by omega) (by rw [name_cut, hp_cut]) none47 (by
          rcases rest_kind with empty | ⟨y, rest_is⟩
          · exact Or.inl empty
          · exact Or.inr ⟨y, by rw [rest_is]; rfl⟩) as ⟨ first, first_post ⟩
      have first_is : first.val = X.length := by omega
      refine WP.spec_bind (host_end_is s first name_end (by omega) (by omega)) ?_
      intro host_end host_says
      have first_piece : Piece (Bytes s.val) 0 first = X :=
        piece_of_the_parts s [] X (rest ++ T ++ D) 0 first.val
          (by rw [← text, hp_cut]; simp) rfl (by simp only [List.length_nil]; omega)
      have host_end_is : (∃ h, r.host = some h ∧ H = h ++ [47] ∧ IsHost h ∧ h ≠ [] ∧
            host_end.val = h.length) ∨ (r.host = none ∧ H = [] ∧ host_end.val = 0) := by
        rcases view with ⟨h, is_h, h_is, x_is, ish, looks⟩ | ⟨no_host, empty, x_is, rest_is⟩
        · subst x_is
          rcases host_says with ⟨_, _, he⟩ | ⟨not_it, _⟩
          · exact Or.inl ⟨X, is_h, h_is, ish, host_is_not_empty looks, by rw [he]; exact first_is⟩
          · exfalso
            rcases not_it with same | not_looks
            · have : H.length = X.length + 1 := by rw [h_is]; simp
              omega
            · exact not_looks (by rw [first_piece]; exact looks)
        · have hl0 : H.length = 0 := by rw [empty]; rfl
          rcases host_says with ⟨below, looks, _⟩ | ⟨_, he⟩
          · exfalso
            rcases p1_kind with empty_p1 | ⟨y, p1_is⟩
            · rw [empty_p1] at rest_is
              have : rest.length = 0 := by rw [rest_is]; rfl
              have : p1.length = 0 := by rw [empty_p1]; rfl
              omega
            · have bad := grammar.first_component no_host
              rw [p_first, p1_is] at bad
              have mem : 47 ∈ c1 ++ 47 :: y := by simp
              have := bad mem
              rw [take_before_the_byte c1 y 47 (component_has_no_slash c1_comp)] at this
              exact this (by rw [first_piece, x_is] at looks; exact looks)
          · exact Or.inr ⟨no_host, empty, by rw [he]; rfl⟩
      -- what is known of the host
      have host_facts : (host_end.val = 0 ∧ H.length = 0 ∧ r.host = none) ∨
          (0 < host_end.val ∧ host_end.val + 1 = H.length ∧
            ∃ h, r.host = some h ∧ IsHost h ∧ Piece (Bytes s.val) 0 host_end = h) := by
        rcases host_end_is with ⟨h, is_h, h_is, ish, h_ne, he⟩ | ⟨no_host, empty, he⟩
        · refine Or.inr ⟨by have := List.length_pos_iff.mpr h_ne; omega, by rw [h_is]; simp [he],
            h, is_h, ish, ?_⟩
          exact piece_of_the_parts s [] h ([47] ++ r.path ++ T ++ D) 0 host_end.val
            (by rw [← text, h_is]; simp) rfl (by simp [he])
        · exact Or.inl ⟨he, by rw [empty]; rfl, no_host⟩
      have host_inside : host_end.val ≤ s.length := by
        rcases host_facts with ⟨zero, _⟩ | ⟨_, _, _⟩ <;> omega
      refine WP.spec_bind (host_error_is_none s host_end host_inside ?_) ?_
      · intro positive
        rcases host_facts with ⟨zero, _⟩ | ⟨_, _, h, _, ish, piece⟩
        · omega
        · rw [piece]; exact ish
      intro host_error host_ok
      subst host_ok
      simp only
      step as ⟨ ps, ps_post ⟩
      have ps_is : ps.val = H.length := by
        rw [ps_post]
        unfold PathStart
        rcases host_facts with ⟨zero, hl, _⟩ | ⟨positive, hl, _⟩
        · simp [zero, hl]
        · have : host_end.val ≠ 0 := by omega
          simp [this]; omega
      have path_piece : Piece (Bytes s.val) ps name_end = r.path :=
        piece_of_the_parts s H r.path (T ++ D) ps.val name_end.val (by rw [← text]; simp)
          ps_is (by omega)
      step with path_bad_accepts_every_path s ps name_end (by omega) (by omega) (by scalar_tac)
        (by rw [path_piece]; exact path_is) as ⟨ o1, o1_post ⟩
      subst o1_post
      simp only
      -- the spans cut the string into the parts of the reference
      have reading : (Spans.mk host_end name_end tag digest).Reading s = r := by
        apply reference_ext
        · simp only [Spans.Reading]
          rcases host_facts with ⟨zero, _, no_host⟩ | ⟨positive, _, h, is_h, ish, piece⟩
          · simp [zero, no_host]
          · have : host_end.val ≠ 0 := by omega
            simp [this, piece, is_h]
        · simp only [Spans.Reading]
          rw [← ps_post]
          exact path_piece
        · simp only [Spans.Reading]
          rcases tag_case with ⟨empty, no_tag⟩ | ⟨t, is_t, t_is⟩
          · have : T.length = 0 := by rw [empty]; rfl
            rcases tag_says with ⟨none_, _⟩ | ⟨below, _⟩
            · simp [none_, no_tag]
            · omega
          · have t_len : T.length = t.length + 1 := by rw [t_is]; rfl
            rcases tag_says with ⟨_, same⟩ | ⟨below, i, i_val, some_⟩
            · omega
            · have piece := piece_of_the_parts s (H ++ r.path ++ [58]) t D i.val at_.val
                (by rw [← text, t_is]; simp) (by simp only [List.length_append]; simp; omega)
                (by simp only [List.length_append]; simp; omega)
              simp [some_, is_t]
              exact piece
        · simp only [Spans.Reading]
          rcases digest_case with ⟨empty, no_digest⟩ | ⟨d, is_d, d_is⟩
          · have : D.length = 0 := by rw [empty]; rfl
            rcases digest_says with ⟨none_, _⟩ | ⟨below, _⟩
            · simp [none_, no_digest]
            · omega
          · have d_len : D.length = d.length + 1 := by rw [d_is]; rfl
            rcases digest_says with ⟨_, same⟩ | ⟨below, i, i_val, some_⟩
            · omega
            · have piece := piece_of_the_parts s (H ++ r.path ++ T ++ [64]) d [] i.val s.len.val
                (by rw [← text, d_is]; simp) (by simp only [List.length_append]; simp; omega)
                (by simp only [List.length_append]; simp; omega)
              simp [some_, is_d]
              exact piece
      -- the name is short enough, and is not the id of an image
      have path_after : PathStart host_end.val ≤ name_end.val := by omega
      have name_inside : name_end.val ≤ s.length := by omega
      step with name_len_says s (Spans.mk host_end name_end tag digest) host_inside path_after
        name_inside (by show name_end.val ≤ 1024; omega) as ⟨ length, length_post ⟩
      have name_short := grammar.name_short
      rw [← reading, name_length_of_the_reading s (Spans.mk host_end name_end tag digest)
        host_inside path_after name_inside, ← length_post] at name_short
      split
      · rename_i too_long
        have : ¬ length > MAX_NAME := by
          have : MAX_NAME.val = 255 := by simp [global_simps]
          scalar_tac
        exact absurd too_long this
      · step with is_id_says s (Spans.mk host_end name_end tag digest) name_inside
          as ⟨ is_it, is_it_post ⟩
        split
        · rename_i is_an_id
          obtain ⟨n64, zero, tag_none, digest_none, hex⟩ := is_it_post.mp is_an_id
          exfalso
          apply grammar.not_an_id
          rw [← reading]
          have path_is_whole : ((Spans.mk host_end name_end tag digest).Reading s).path =
              Piece (Bytes s.val) 0 name_end := by
            simp [Spans.Reading, PathStart, zero]
          refine ⟨by simp [Spans.Reading, zero], by simp [Spans.Reading, tag_none],
            by simp [Spans.Reading, digest_none], ?_, ?_⟩
          · rw [path_is_whole, piece_length _ _ _ (Nat.zero_le _) (by simpa using name_inside)]
            omega
          · rw [path_is_whole]; exact hex
        · simp only [WP.spec_ok]
          exact ⟨_, rfl, reading⟩
