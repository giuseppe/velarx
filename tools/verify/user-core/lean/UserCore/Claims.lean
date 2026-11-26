-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean, from the results of the other files.
-- Why it is needed: Theorems.lean ties each claim to its proof here.
-- Read before this file: Resolve.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Resolve
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- `resolve` answers as `resolve_user` does for the user string it reads: `0` for the empty one. -/
theorem resolve_spec (passwd group user : Slice Std.U8) (ga : Slice (alloc.vec.Vec Std.U8)) (strict : Bool)
    (shortp : passwd.length < Std.Usize.max) (shortg : group.length < Std.Usize.max) :
    resolve passwd group user ga strict ⦃ r =>
      ResolvePost passwd group ga strict (UserPart (UserString user.val))
        (GroupPart (UserString user.val)) r ⦄ := by
  unfold resolve
  step as ⟨ b, hb ⟩
  by_cases empty : b = true
  · rw [if_yes empty]
    have uempty : user.val = [] := by
      have : user.length = 0 := by simpa using (hb ▸ empty : user.length = 0)
      simpa [Slice.length] using this
    step as ⟨ s, hs ⟩
    have sval : s.val = [48#u8] := by simp [hs, Std.Array.to_slice]
    have := resolve_user_spec passwd group s ga strict shortp shortg
    rw [sval] at this
    have us : UserString user.val = [48#u8] := by simp [UserString, uempty]
    rw [us]
    exact this
  · rw [if_no empty]
    have nonempty : user.val ≠ [] := by
      intro h; apply empty
      have : user.length = 0 := by simp [Slice.length, h]
      simpa using (hb ▸ this : (b = true))
    have us : UserString user.val = user.val := by simp [UserString, nonempty]
    rw [us]
    exact resolve_user_spec passwd group user ga strict shortp shortg

/-- Proof of `ResolveAlwaysReturns`: each function is shown to return by the claim about its answer. -/
theorem resolve_always_returns : ResolveAlwaysReturns := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro passwd group user ga strict ⟨a, b⟩
    exact WP.spec_mono (resolve_spec passwd group user ga strict a b) (fun _ _ => trivial)
  · intro s
    exact WP.spec_mono (parse_id_spec s) (fun _ _ => trivial)
  · intro user
    exact WP.spec_mono (split_user_spec user) (fun _ _ => trivial)
  · intro passwd who uid short
    exact WP.spec_mono (passwd_find_spec passwd who uid short) (fun _ _ => trivial)
  · intro passwd uid short
    unfold has_uid
    step with passwd_find_spec passwd none (some uid) short as ⟨ o, _ ⟩
  · intro group gid short
    exact has_gid_spec group gid short
  · intro h w
    unfold home
    rcases h with _ | h
    · by_cases w' : w = true <;> simp [w']
    · step as ⟨ b, _ ⟩
      split <;> simp

/-- When `has_uid` says no, the search by uid found nothing. -/
theorem has_uid_false (passwd : Slice Std.U8) (uid : Std.U32) (short : passwd.length < Std.Usize.max)
    (h : has_uid passwd uid = ok false) : passwd_find passwd none (some uid) = ok none := by
  obtain ⟨o, ho, _⟩ := spec_ok_eq (passwd_find_spec passwd none (some uid) short)
  unfold has_uid at h
  rw [ho] at h
  have : o.isSome = false := by simpa [core.option.Option.is_some] using h
  rw [ho]
  cases o with
  | none => rfl
  | some _ => simp at this

/-- Two ids that are the written form of the same digits are the same id. -/
theorem parsed_unique (s : List Std.U8) (a b : Std.U32) (ha : ParsedId s a) (hb : ParsedId s b) :
    a = b := by
  have : a.val = b.val := by rw [← ha.2.1, ← hb.2.1]
  exact Std.UScalar.eq_of_val_eq this

/-- Proof of `ANumericUserKeepsItsId`. -/
theorem a_numeric_user_keeps_its_id : ANumericUserKeepsItsId := by
  intro passwd group user ga strict ⟨a, b⟩ dig
  refine WP.spec_mono (resolve_spec passwd group user ga strict a b) ?_
  intro r post res hres
  obtain ⟨notmal, _, _, _, _, _, _, hdig, _⟩ := post.2.2.2 res hres
  obtain ⟨parsed, _, hnone⟩ := hdig dig
  refine ⟨parsed, ?_⟩
  intro id pid hu hgp
  have same : id = res.uid := parsed_unique _ _ _ pid parsed
  rw [same] at hu
  obtain ⟨h1, h2⟩ := hnone (has_uid_false passwd res.uid a hu)
  exact ⟨h2 hgp, h1⟩

/-- Proof of `ANamedUserIsAnEntryOfTheFile`. -/
theorem a_named_user_is_an_entry_of_the_file : ANamedUserIsAnEntryOfTheFile := by
  intro passwd group user ga strict ⟨a, b⟩ nodig
  refine WP.spec_mono (resolve_spec passwd group user ga strict a b) ?_
  intro r post res hres
  obtain ⟨_, _, _, _, _, _, _, _, hnamed, _⟩ := post.2.2.2 res hres
  obtain ⟨nm, e, hnm, ⟨start, stop, hl, hp, hwho⟩, hu, hh, hg⟩ := hnamed nodig
  refine ⟨e, start, stop, hl, hp, ?_, hu, hh, hg⟩
  rcases hwho with ⟨n, hn, hs⟩ | hid
  · cases hn; rw [hs, hnm]
  · cases hid

/-- Proof of `TheGroupsAreIdsOnceAndBounded`. -/
theorem the_groups_are_ids_once_and_bounded : TheGroupsAreIdsOnceAndBounded := by
  intro passwd group user ga strict ⟨a, b⟩
  refine WP.spec_mono (resolve_spec passwd group user ga strict a b) ?_
  intro r post res hres
  obtain ⟨_, hhead, hnd, hlen, hu, hg, hall, _⟩ := post.2.2.2 res hres
  exact ⟨hhead, hnd, hlen, hu, hg, hall⟩

/-- Proof of `WhereAGroupComesFrom`. -/
theorem where_a_group_comes_from : WhereAGroupComesFrom := by
  intro passwd group user ga strict ⟨a, b⟩
  refine WP.spec_mono (resolve_spec passwd group user ga strict a b) ?_
  intro r post res hres
  obtain ⟨_, _, _, _, _, _, _, _, _, hgp, hsrc⟩ := post.2.2.2 res hres
  exact ⟨hgp, hsrc⟩

/-- Proof of `TheRefusalsOfTheUserString`. -/
theorem the_refusals_of_the_user_string : TheRefusalsOfTheUserString := by
  intro passwd group user ga strict ⟨a, b⟩
  refine WP.spec_mono (resolve_spec passwd group user ga strict a b) ?_
  intro r post
  exact ⟨post.1, post.2.1⟩

/-- Proof of `TheEmptyUserIsZero`: `resolve` of the empty string is `resolve_user` of `0`, as it is of `0`. -/
theorem the_empty_user_is_zero : TheEmptyUserIsZero := by
  intro passwd group user ga strict empty zero hzero
  unfold resolve
  have u : user.length = 0 := by simp [Slice.length, empty]
  have e : core.slice.Slice.is_empty user = ok true := by
    simp [core.slice.Slice.is_empty, u]
  have ez : core.slice.Slice.is_empty zero = ok false := by
    simp [core.slice.Slice.is_empty, Slice.length, hzero]
  have to_zero : Std.Array.to_slice (Std.Array.make 1#usize [48#u8] (by decide)) = zero :=
    Slice.ext _ _ (by simp [hzero, Std.Array.to_slice])
  rw [e, ez]
  simp [to_zero, lift]

end UserCore
