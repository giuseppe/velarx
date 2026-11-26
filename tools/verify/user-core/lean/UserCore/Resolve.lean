-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `resolve_user`: what it answers for every user string (`ResolvePost`).
-- Why it is needed: every claim on `resolve` is read from this one.
-- Read before this file: Tail.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Tail
import UserCore.SpecEq
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- What `resolve_user` answers, for the user part `n` and the group part `gp` of the user string. -/
def ResolvePost (passwd group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict : Bool)
    (n : List Std.U8) (gp : Option (List Std.U8))
    (r : core.result.Result Resolved Refusal) : Prop :=
  (r = core.result.Result.Err Refusal.Malformed ↔ (n = [] ∨ gp = some [])) ∧
  (r = core.result.Result.Err Refusal.BadUserId ↔
    (¬ (n = [] ∨ gp = some []) ∧ IsDigits n ∧ NoId ≤ Value n)) ∧
  (∀ ref, r = core.result.Result.Err ref → ref = Refusal.Malformed ∨ ref = Refusal.BadUserId ∨
    ref = Refusal.NoUser ∨ GroupRefusal ref) ∧
  ∀ res, r = core.result.Result.Ok res →
    ¬ (n = [] ∨ gp = some []) ∧
    res.gids.val.head? = some res.gid ∧ res.gids.val.Nodup ∧ res.gids.val.length ≤ 65536 ∧
    res.uid.val < NoId ∧ res.gid.val < NoId ∧ (∀ x ∈ res.gids.val, x.val < NoId) ∧
    (IsDigits n → ParsedId n res.uid ∧
      (∀ e, passwd_find passwd none (some res.uid) = ok (some e) →
        res.home = some e.home ∧ (gp = none → res.gid = e.gid)) ∧
      (passwd_find passwd none (some res.uid) = ok none → res.home = none ∧ (gp = none → res.gid = 0#u32))) ∧
    (¬ IsDigits n → ∃ (nm : Slice Std.U8) (e : Passwd), nm.val = n ∧ FoundEntry passwd.val (some nm) none e ∧
      res.uid = e.uid ∧ res.home = some e.home ∧ (gp = none → res.gid = e.gid)) ∧
    (∀ g, gp = some g → NamesGroup group.val g res.gid) ∧
    (∀ x ∈ res.gids.val, x = res.gid ∨
      (∃ (k : Nat) (s : alloc.vec.Vec Std.U8), ga.val[k]? = some s ∧ NamesGroup group.val s.val x) ∨
      (gp = none ∧ strict = false ∧ ∃ e, ∃ start stop, IsLine passwd.val start stop ∧
        IsPasswdEntry passwd.val start stop e ∧ e.uid = res.uid ∧ res.home = some e.home ∧
        e.name.1.val < e.name.2.val ∧
        ListedIn group.val (List.slice e.name.1.val e.name.2.val passwd.val) x))

/-- Once the uid, gid and home are known and the groups added, the answer satisfies `ResolvePost`. -/
theorem post_of_tail (passwd group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict own : Bool)
    (n : List Std.U8) (gpl : Option (List Std.U8))
    (r : core.result.Result Resolved Refusal) (entry : Option Passwd) (uid gid : Std.U32)
    (home : Option (Std.Usize × Std.Usize))
    (hown : own = true ↔ gpl = none)
    (P0 : TailPost passwd group ga strict own entry uid gid home r)
    (notmal : ¬ (n = [] ∨ gpl = some []))
    (link : (∀ e, entry = some e → uid = e.uid ∧ home = some e.home ∧ (gpl = none → gid = e.gid)) ∧
      (entry = none → home = none ∧ (gpl = none → gid = 0#u32)))
    (hdig : IsDigits n → ParsedId n uid ∧ passwd_find passwd none (some uid) = ok entry)
    (hnamed : ¬ IsDigits n → ∃ (nm : Slice Std.U8) (e : Passwd), nm.val = n ∧ entry = some e ∧
      FoundEntry passwd.val (some nm) none e)
    (hgp : ∀ g, gpl = some g → NamesGroup group.val g gid)
    (hsmall : uid.val < NoId ∧ gid.val < NoId)
    (hline : ∀ e, entry = some e → ∃ start stop, IsLine passwd.val start stop ∧
      IsPasswdEntry passwd.val start stop e) :
    ResolvePost passwd group ga strict n gpl r := by
  obtain ⟨okp, errp⟩ := P0
  have ne_mal : r ≠ core.result.Result.Err Refusal.Malformed := by
    intro h; have := errp _ h; simp [GroupRefusal] at this
  have ne_bad : r ≠ core.result.Result.Err Refusal.BadUserId := by
    intro h; have := errp _ h; simp [GroupRefusal] at this
  refine ⟨⟨fun h => absurd h ne_mal, fun h => absurd h notmal⟩,
    ⟨fun h => absurd h ne_bad, ?_⟩, ?_, ?_⟩
  · rintro ⟨_, dig, big⟩
    have := (hdig dig).1.2.2
    have := (hdig dig).1.2.1
    omega
  · intro ref href
    exact Or.inr (Or.inr (Or.inr (errp ref href)))
  · intro res hres
    obtain ⟨hu, hg, hh, hhead, hnd, hlen, hall, hsrc⟩ := okp res hres
    refine ⟨notmal, by rw [hg]; exact hhead, hnd, hlen, by rw [hu]; exact hsmall.1,
      by rw [hg]; exact hsmall.2, hall, ?_, ?_, ?_, ?_⟩
    · intro dig
      obtain ⟨parsed, hfind⟩ := hdig dig
      refine ⟨by rw [hu]; exact parsed, ?_, ?_⟩
      · intro e he
        rw [hu, hfind] at he
        have he' : entry = some e := by simpa using he
        obtain ⟨_, h2, h3⟩ := link.1 e he'
        exact ⟨by rw [hh]; exact h2, fun hgn => by rw [hg]; exact h3 hgn⟩
      · intro he
        rw [hu, hfind] at he
        have he' : entry = none := by simpa using he
        obtain ⟨h2, h3⟩ := link.2 he'
        exact ⟨by rw [hh]; exact h2, fun hgn => by rw [hg]; exact h3 hgn⟩
    · intro nodig
      obtain ⟨nm, e, hnm, he, found⟩ := hnamed nodig
      obtain ⟨h1, h2, h3⟩ := link.1 e he
      exact ⟨nm, e, hnm, found, by rw [hu]; exact h1, by rw [hh]; exact h2,
        fun hgn => by rw [hg]; exact h3 hgn⟩
    · intro g hgg
      rw [hg]; exact hgp g hgg
    · intro x hx
      rcases hsrc x hx with h | h | ⟨hown', hstrict, e, he, hlt, hl⟩
      · exact Or.inl (by rw [hg]; exact h)
      · exact Or.inr (Or.inl h)
      · obtain ⟨start, stop, hl1, hl2⟩ := hline e he
        obtain ⟨h1, h2, _⟩ := link.1 e he
        exact Or.inr (Or.inr ⟨hown.mp hown', hstrict, e, start, stop, hl1, hl2, by rw [hu]; exact h1.symm,
          by rw [hh]; exact h2, hlt, hl⟩)

/-- Digits whose number is below `NoId` are the written form of an id. -/
theorem parsed_of_small (s : List Std.U8) (dig : IsDigits s) (small : Value s < NoId) :
    ∃ k : Std.U32, ParsedId s k := by
  unfold NoId at small
  refine ⟨⟨BitVec.ofNat 32 (Value s)⟩, dig, ?_, ?_⟩ <;>
    simp [Std.UScalar.val, BitVec.toNat_ofNat, NoId] <;> omega

/-- A refusal that is neither of the two of the user string, and the user string is no bad id, satisfies `ResolvePost`. -/
theorem post_err (passwd group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict : Bool)
    (n : List Std.U8) (gpl : Option (List Std.U8)) (ref : Refusal)
    (notmal : ¬ (n = [] ∨ gpl = some [])) (nobad : ¬ (IsDigits n ∧ NoId ≤ Value n))
    (hr : ref ≠ Refusal.Malformed ∧ ref ≠ Refusal.BadUserId ∧
      (ref = Refusal.NoUser ∨ GroupRefusal ref)) :
    ResolvePost passwd group ga strict n gpl (core.result.Result.Err ref) := by
  refine ⟨⟨fun h => (hr.1 (by injection h)).elim, fun h => absurd h notmal⟩,
    ⟨fun h => (hr.2.1 (by injection h)).elim, fun h => absurd ⟨h.2.1, h.2.2⟩ nobad⟩, ?_, by simp⟩
  intro r h; cases h
  rcases hr.2.2 with h | h
  · exact Or.inr (Or.inr (Or.inl h))
  · exact Or.inr (Or.inr (Or.inr h))

/-- `Malformed` for an empty user or group part satisfies `ResolvePost`. -/
theorem post_malformed (passwd group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict : Bool)
    (n : List Std.U8) (gpl : Option (List Std.U8)) (mal : n = [] ∨ gpl = some []) :
    ResolvePost passwd group ga strict n gpl (core.result.Result.Err Refusal.Malformed) := by
  refine ⟨⟨fun _ => mal, fun _ => rfl⟩, ⟨by simp, fun h => absurd mal h.1⟩, ?_, by simp⟩
  intro r h; cases h; exact Or.inl rfl

/-- `BadUserId` for digits that are no id satisfies `ResolvePost`. -/
theorem post_bad_user (passwd group : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict : Bool)
    (n : List Std.U8) (gpl : Option (List Std.U8)) (notmal : ¬ (n = [] ∨ gpl = some []))
    (dig : IsDigits n) (big : NoId ≤ Value n) :
    ResolvePost passwd group ga strict n gpl (core.result.Result.Err Refusal.BadUserId) := by
  refine ⟨⟨by simp, fun h => absurd h notmal⟩, ⟨fun _ => ⟨notmal, dig, big⟩, fun _ => rfl⟩, ?_, by simp⟩
  intro r h; cases h; exact Or.inr (Or.inl rfl)

/-- An entry of a line has ids below `NoId` and a name inside the data. -/
theorem entry_facts (d : List Std.U8) (start stop : Nat) (e : Passwd) (hl : IsLine d start stop)
    (h : IsPasswdEntry d start stop e) :
    e.uid.val < NoId ∧ e.gid.val < NoId ∧ e.name.1.val ≤ e.name.2.val ∧ e.name.2.val ≤ d.length := by
  obtain ⟨c0, c1, c2, c3, c4, c5, rest, hL, n1, n2, pu, pg, _⟩ := h
  have := passwd_entry_bounds d start stop e ⟨c0, c1, c2, c3, c4, c5, rest, hL, n1, n2, pu, pg, ‹_›⟩
  exact ⟨pu.2.2, pg.2.2, this.1, by have := hl.2.1; omega⟩

/-- With an id, `find_user` is the search by uid. -/
theorem find_user_numeric (passwd nm : Slice Std.U8) (k : Std.U32) :
    find_user passwd nm (some k) = passwd_find passwd none (some k) := by
  unfold find_user; simp

/-- The uid of the entry found by uid is that uid. -/
theorem found_by_uid (d : List Std.U8) (k : Std.U32) (e : Passwd)
    (h : FoundEntry d none (some k) e) : e.uid = k := by
  obtain ⟨_, _, _, _, h⟩ := h
  rcases h with ⟨n, hn, _⟩ | h
  · cases hn
  · exact (Option.some.inj h).symm

set_option hygiene false in
/-- What `resolve_user` does once it has the user part, with no group part, and an id for it or
a name: find the entry, then the groups. -/
macro "cont_none" : tactic => `(tactic| (
  obtain ⟨entry, heq, hfind⟩ := spec_ok_eq (find_user_spec passwd nm id shortp)
  rw [heq]
  simp only [Std.bind_tc_ok, Std.bind_ok]
  rcases entry with _ | e
  · rcases id with _ | id1
    · exact (WP.spec_ok _).mpr (post_err _ _ _ _ _ _ Refusal.NoUser notmal
        (fun h => hnodig rfl h.1) ⟨by simp, by simp, Or.inl rfl⟩)
    · have parsed := (hid id1).mp rfl
      rw [find_user_numeric] at heq
      refine WP.spec_mono (tail_spec passwd group ga strict _ none id1 0#u32 none shortg
        (by simp [NoId]) (by simp)) ?_
      intro r P0
      exact post_of_tail passwd group ga strict _ _ _ r none id1 0#u32 none (by simp [hgp]) P0 notmal
        ⟨fun e he => (by cases he), fun _ => ⟨rfl, fun _ => rfl⟩⟩
        (fun _ => ⟨parsed, heq⟩) (fun h => absurd parsed.1 h)
        (fun g h => (by rw [hgp] at h; cases h)) ⟨parsed.2.2, by simp [NoId]⟩ (fun e he => (by cases he))
  · obtain ⟨start, stop, hl, hp, _⟩ : ∃ start stop, IsLine passwd.val start stop ∧
        IsPasswdEntry passwd.val start stop e ∧ True := by
      rcases id with _ | k
      · obtain ⟨start, stop, hl, hp, _⟩ := hfind.2 rfl e rfl
        exact ⟨start, stop, hl, hp, trivial⟩
      · obtain ⟨start, stop, hl, hp, _⟩ := hfind.1 k rfl e rfl
        exact ⟨start, stop, hl, hp, trivial⟩
    obtain ⟨hu, hgd, hnl, hnu⟩ := entry_facts _ _ _ e hl hp
    refine WP.spec_mono (tail_spec passwd group ga strict _ (some e) e.uid e.gid (some e.home) shortg
      hgd (fun e' he' => (by cases he'; exact ⟨hnl, hnu⟩))) ?_
    intro r P0
    rcases id with _ | k
    · exact post_of_tail passwd group ga strict _ _ _ r (some e) e.uid e.gid (some e.home)
        (by simp [hgp]) P0 notmal
        ⟨fun e' he' => (by cases he'; exact ⟨rfl, rfl, fun _ => rfl⟩), fun h => (by cases h)⟩
        (fun d => absurd d (hnodig rfl)) (fun _ => ⟨nm, e, hn, rfl, hfind.2 rfl e rfl⟩)
        (fun g h => (by rw [hgp] at h; cases h)) ⟨hu, hgd⟩
        (fun e' he' => (by cases he'; exact ⟨start, stop, hl, hp⟩))
    · have parsed := (hid k).mp rfl
      have uid_k : e.uid = k := found_by_uid _ _ _ (hfind.1 k rfl e rfl)
      rw [find_user_numeric] at heq
      exact post_of_tail passwd group ga strict _ _ _ r (some e) e.uid e.gid (some e.home)
        (by simp [hgp]) P0 notmal
        ⟨fun e' he' => (by cases he'; exact ⟨rfl, rfl, fun _ => rfl⟩), fun h => (by cases h)⟩
        (fun _ => ⟨by rw [uid_k]; exact parsed, by rw [uid_k]; exact heq⟩)
        (fun h => absurd parsed.1 h) (fun g h => (by rw [hgp] at h; cases h)) ⟨hu, hgd⟩
        (fun e' he' => (by cases he'; exact ⟨start, stop, hl, hp⟩))))

set_option hygiene false in
/-- The same with a group part `g`: the gid is that of `g`. -/
macro "cont_some" : tactic => `(tactic| (
  obtain ⟨entry, heq, hfind⟩ := spec_ok_eq (find_user_spec passwd nm id shortp)
  rw [heq]
  simp only [Std.bind_tc_ok, Std.bind_ok]
  have nobad : ¬ (IsDigits (UserPart user.val) ∧ NoId ≤ Value (UserPart user.val)) := by
    rcases id with _ | k
    · exact fun h => hnodig rfl h.1
    · have parsed := (hid k).mp rfl
      intro h; have := parsed.2.1; have := parsed.2.2; omega
  rcases entry with _ | e
  · rcases id with _ | id1
    · exact (WP.spec_ok _).mpr (post_err _ _ _ _ _ _ Refusal.NoUser notmal
        (fun h => hnodig rfl h.1) ⟨by simp, by simp, Or.inl rfl⟩)
    · have parsed := (hid id1).mp rfl
      rw [find_user_numeric] at heq
      step with group_id_spec group g Group.OfUser shortg as ⟨ r0, hok, herr ⟩
      rcases r0 with val | ref
      · simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_tc_ok, Std.bind_ok]
        obtain ⟨small, names⟩ := hok val rfl
        refine WP.spec_mono (tail_spec passwd group ga strict _ none id1 val none shortg
          small (by simp)) ?_
        intro r P0
        exact post_of_tail passwd group ga strict _ _ _ r none id1 val none (by simp [hgp]) P0 notmal
          ⟨fun e he => (by cases he), fun _ => ⟨rfl, fun h => (by rw [hgp] at h; cases h)⟩⟩
          (fun _ => ⟨parsed, heq⟩) (fun h => absurd parsed.1 h)
          (fun g' h => (by rw [hgp] at h; cases h; exact names)) ⟨parsed.2.2, small⟩
          (fun e he => (by cases he))
      · simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_tc_ok, Std.bind_ok,
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
          core.convert.FromSame]
        refine (WP.spec_ok _).mpr (post_err _ _ _ _ _ _ ref notmal nobad ?_)
        rcases herr ref rfl with h | h <;> rw [h] <;> simp [GroupRefusal]
  · obtain ⟨start, stop, hl, hp, _⟩ : ∃ start stop, IsLine passwd.val start stop ∧
        IsPasswdEntry passwd.val start stop e ∧ True := by
      rcases id with _ | k
      · obtain ⟨start, stop, hl, hp, _⟩ := hfind.2 rfl e rfl
        exact ⟨start, stop, hl, hp, trivial⟩
      · obtain ⟨start, stop, hl, hp, _⟩ := hfind.1 k rfl e rfl
        exact ⟨start, stop, hl, hp, trivial⟩
    obtain ⟨hu, hgd, hnl, hnu⟩ := entry_facts _ _ _ e hl hp
    step with group_id_spec group g Group.OfUser shortg as ⟨ r0, hok, herr ⟩
    rcases r0 with val | ref
    · simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_tc_ok, Std.bind_ok]
      obtain ⟨small, names⟩ := hok val rfl
      refine WP.spec_mono (tail_spec passwd group ga strict _ (some e) e.uid val (some e.home) shortg
        small (fun e' he' => (by cases he'; exact ⟨hnl, hnu⟩))) ?_
      intro r P0
      rcases id with _ | k
      · exact post_of_tail passwd group ga strict _ _ _ r (some e) e.uid val (some e.home)
          (by simp [hgp]) P0 notmal
          ⟨fun e' he' => (by cases he'; exact ⟨rfl, rfl, fun h => (by rw [hgp] at h; cases h)⟩),
            fun h => (by cases h)⟩
          (fun d => absurd d (hnodig rfl)) (fun _ => ⟨nm, e, hn, rfl, hfind.2 rfl e rfl⟩)
          (fun g' h => (by rw [hgp] at h; cases h; exact names)) ⟨hu, small⟩
          (fun e' he' => (by cases he'; exact ⟨start, stop, hl, hp⟩))
      · have parsed := (hid k).mp rfl
        have uid_k : e.uid = k := found_by_uid _ _ _ (hfind.1 k rfl e rfl)
        rw [find_user_numeric] at heq
        exact post_of_tail passwd group ga strict _ _ _ r (some e) e.uid val (some e.home)
          (by simp [hgp]) P0 notmal
          ⟨fun e' he' => (by cases he'; exact ⟨rfl, rfl, fun h => (by rw [hgp] at h; cases h)⟩),
            fun h => (by cases h)⟩
          (fun _ => ⟨by rw [uid_k]; exact parsed, by rw [uid_k]; exact heq⟩)
          (fun h => absurd parsed.1 h) (fun g' h => (by rw [hgp] at h; cases h; exact names))
          ⟨hu, small⟩ (fun e' he' => (by cases he'; exact ⟨start, stop, hl, hp⟩))
    · simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_tc_ok, Std.bind_ok,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
        core.convert.FromSame]
      refine (WP.spec_ok _).mpr (post_err _ _ _ _ _ _ ref notmal nobad ?_)
      rcases herr ref rfl with h | h <;> rw [h] <;> simp [GroupRefusal]))

/-- `resolve_user` returns and its answer satisfies `ResolvePost`. -/
theorem resolve_user_spec (passwd group user : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict : Bool)
    (shortp : passwd.length < Std.Usize.max) (shortg : group.length < Std.Usize.max) :
    resolve_user passwd group user ga strict ⦃ r =>
      ResolvePost passwd group ga strict (UserPart user.val) (GroupPart user.val) r ⦄ := by
  unfold resolve_user
  step with split_user_spec user as ⟨ nm, gp, hn, hg ⟩
  step as ⟨ b, hb ⟩
  have nm_empty : b = true ↔ nm.val = [] := by
    rw [hb]; simp [Slice.length]
  by_cases mal : b = true
  · rw [if_yes mal]
    exact (WP.spec_ok _).mpr (post_malformed _ _ _ _ _ _ (Or.inl (by rw [← hn]; exact nm_empty.mp mal)))
  · rw [if_no mal]
    have nonempty : UserPart user.val ≠ [] := by rw [← hn]; exact fun h => mal (nm_empty.mpr h)
    rcases gp with _ | g
    · have hgp : GroupPart user.val = none := by rw [← hg]; rfl
      have notmal : ¬ (UserPart user.val = [] ∨ GroupPart user.val = some []) := by
        rw [hgp]; simp [nonempty]
      step with parse_id_spec nm as ⟨ id, hid ⟩
      rw [hn] at hid
      by_cases idn : id.isNone = true
      · have idnone : id = none := by simpa using idn
        simp only [idn, ite_true]
        step with is_digits_spec nm as ⟨ b2, hb2 ⟩
        by_cases dig : b2 = true
        · rw [if_yes dig]
          have digits : IsDigits (UserPart user.val) := by rw [← hn]; exact hb2.mp dig
          refine (WP.spec_ok _).mpr (post_bad_user _ _ _ _ _ _ notmal digits ?_)
          by_contra small
          obtain ⟨k, hk⟩ := parsed_of_small _ digits (by omega)
          have := (hid k).mpr hk
          rw [idnone] at this; cases this
        · rw [if_no dig]
          have hnodig : id = none → ¬ IsDigits (UserPart user.val) := fun _ d =>
            dig (hb2.mpr (by rw [hn]; exact d))
          cont_none
      · simp only [idn, Bool.false_eq_true, ite_false]
        have hnodig : id = none → ¬ IsDigits (UserPart user.val) := fun h => absurd (by simp [h]) idn
        cont_none
    · have hgp : GroupPart user.val = some g.val := by rw [← hg]; rfl
      step as ⟨ b1, hb1 ⟩
      have g_empty : b1 = true ↔ g.val = [] := by rw [hb1]; simp [Slice.length]
      by_cases gmal : b1 = true
      · rw [if_yes gmal]
        exact (WP.spec_ok _).mpr (post_malformed _ _ _ _ _ _ (Or.inr (by rw [hgp, g_empty.mp gmal])))
      · rw [if_no gmal]
        have notmal : ¬ (UserPart user.val = [] ∨ GroupPart user.val = some []) := by
          rw [hgp]
          rintro (h | h)
          · exact nonempty h
          · exact gmal (g_empty.mpr (Option.some.inj h))
        step with parse_id_spec nm as ⟨ id, hid ⟩
        rw [hn] at hid
        by_cases idn : id.isNone = true
        · have idnone : id = none := by simpa using idn
          simp only [idn, ite_true]
          step with is_digits_spec nm as ⟨ b2, hb2 ⟩
          by_cases dig : b2 = true
          · rw [if_yes dig]
            have digits : IsDigits (UserPart user.val) := by rw [← hn]; exact hb2.mp dig
            refine (WP.spec_ok _).mpr (post_bad_user _ _ _ _ _ _ notmal digits ?_)
            by_contra small
            obtain ⟨k, hk⟩ := parsed_of_small _ digits (by omega)
            have := (hid k).mpr hk
            rw [idnone] at this; cases this
          · rw [if_no dig]
            have hnodig : id = none → ¬ IsDigits (UserPart user.val) := fun _ d =>
              dig (hb2.mpr (by rw [hn]; exact d))
            cont_some
        · simp only [idn, Bool.false_eq_true, ite_false]
          have hnodig : id = none → ¬ IsDigits (UserPart user.val) := fun h => absurd (by simp [h]) idn
          cont_some

end UserCore
