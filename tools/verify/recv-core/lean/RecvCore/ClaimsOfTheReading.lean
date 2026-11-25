-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about the answer to a request for chunks.
-- Why it is needed: Theorems.lean names what is proved; the proofs are here.  Each function of the crate has
--   no loop and no call to the library but `is_multiple_of`, so each proof opens the function (`unfold`), cuts
--   it at each `if` (`split_ifs`), and lets `step*` do the arithmetic of the line.
-- Read before this file: Spec.lean.
-- Notation: `step*` runs the function line by line and proves that no line overflows; `omega` and `scalar_tac`
--   decide a statement about whole numbers and the numbers of the types; `simp_all` rewrites with every given.
import RecvCore.Spec
open Aeneas Aeneas.Std Result velarx_recv_core
namespace RecvCore

/-- Proof of the first half of `WhatTheStatusBytesSay`: each `if` of `status` is a byte of the table. -/
theorem status_is (b : Std.U8) : status b ⦃ s =>
    (s = Status.Absent ↔ b.val = 0) ∧ (s = Status.Here ↔ b.val = 1) ∧
    (s = Status.NoRoom ↔ b.val = 2) ∧ (s = Status.Failed ↔ b.val = 3) ∧
    (s = Status.Bad ↔ 4 ≤ b.val) ⦄ := by
  unfold status
  simp only [ABSENT, HERE, NO_ROOM, FAILED]
  split_ifs <;> simp_all [UScalar.eq_equiv, WP.spec_ok]
  omega

/-- Proof of the second half: `turn` asks `status` and gives the turn of the same name. -/
theorem turn_is (b : Std.U8) : turn b ⦃ t =>
    (t = Turn.Absent ↔ b.val = 0) ∧ (t = Turn.Here ↔ b.val = 1) ∧
    (t = Turn.NoRoom ↔ b.val = 2) ∧ (t = Turn.Failed ↔ b.val = 3) ∧
    (t = Turn.Bad ↔ 4 ≤ b.val) ⦄ := by
  unfold turn
  refine WP.spec_bind (status_is b) ?_
  intro s same
  obtain ⟨absent, here, no_room, failed, bad⟩ := same
  cases s <;> simp_all [Status.Insts.CoreCmpPartialEqStatus.eq, Status.read_discriminant]

/-- Proof of `WhatRoomSaysExactly`: the two `if`s of `room` are `payload = 0` and `payload <= max`, and the
subtraction of the last is of a number not above. -/
theorem room_is (payload len mp : Std.U64) :
    room payload len mp ⦃ b => (b = true ↔ HasRoom payload len mp) ⦄ := by
  unfold room HasRoom
  split_ifs with zero below
  · simp [zero]
  · step*
  · simp_all [UScalar.eq_equiv]
    omega

/-- What `WhatTakeAcceptsExactly` says of the answer `a` of `take r len size`, as a name. -/
def TakeSays (r : Reading) (len : Std.U64) (size : Option Std.U64) (a : Bool × Reading) : Prop :=
  (a.1 = true ↔ len.val ≤ r.max_item.val ∧ SizeMatches len size ∧
    HasRoom r.payload len r.max_payload) ∧
  (a.1 = true → a.2.payload.val = r.payload.val + len.val) ∧
  (a.1 = false → a.2 = r) ∧
  a.2.asked = r.asked ∧ a.2.next = r.next ∧ a.2.max_item = r.max_item ∧
  a.2.max_payload = r.max_payload

/-- The part of `take` that both arms (a size asked, or not) end with: the length is of the size asked and
not above `max_item`; `room` is asked, and the length is added when there is room. -/
theorem take_asks_room (r : Reading) (len : Std.U64) (size : Option Std.U64)
    (not_too_long : len.val ≤ r.max_item.val) (sized : SizeMatches len size) :
    (do
      let b ← room r.payload len r.max_payload
      if b = true then do
        let i ← r.payload + len
        ok (true, { r with payload := i })
      else ok (false, r)) ⦃ a => TakeSays r len size a ⦄ := by
  refine WP.spec_bind (room_is r.payload len r.max_payload) ?_
  intro b room_says
  by_cases has_room : b = true
  · simp only [has_room, ite_true]
    have room : HasRoom r.payload len r.max_payload := room_says.mp has_room
    step*
    · rcases room with empty | fits <;> scalar_tac
    · exact ⟨⟨fun _ => ⟨not_too_long, sized, room⟩, fun _ => rfl⟩, by simpa using i_post, by simp⟩
  · have no_room : ¬ HasRoom r.payload len r.max_payload := fun h => has_room (room_says.mpr h)
    simp only [has_room]
    refine (WP.spec_ok _).mpr ?_
    exact ⟨⟨fun yes => absurd yes (by simp), fun h => absurd h.2.2 no_room⟩, by simp, by simp,
      rfl, rfl, rfl, rfl⟩

/-- Proof of `WhatTakeAcceptsExactly`: `take` refuses a length above `max_item`, refuses a size asked that
is not the length, and then ends as `take_asks_room` says. -/
theorem take_is (r : Reading) (len : Std.U64) (size : Option Std.U64) :
    Reading.take r len size ⦃ a => TakeSays r len size a ⦄ := by
  unfold Reading.take
  split_ifs with too_long
  · refine (WP.spec_ok _).mpr ?_
    refine ⟨⟨fun yes => by simp at yes, fun h => absurd h.1 (by scalar_tac)⟩, by simp, by simp,
      rfl, rfl, rfl, rfl⟩
  · have not_too_long : len.val ≤ r.max_item.val := by scalar_tac
    cases size with
    | none => exact take_asks_room r len none not_too_long (by intro s h; cases h)
    | some s =>
      dsimp only
      split_ifs with differ
      · refine (WP.spec_ok _).mpr ?_
        have : s.val ≠ len.val := by simpa [bne_iff_ne, UScalar.eq_equiv] using differ
        exact ⟨⟨fun yes => by simp at yes, fun h => absurd (h.2.1 s rfl) this⟩, by simp, by simp,
          rfl, rfl, rfl, rfl⟩
      · exact take_asks_room r len (some s) not_too_long
          (by intro t h; cases h; simpa [bne_iff_ne, UScalar.eq_equiv] using differ)

/-- Proof of the first claim of `TheTurnsAreThoseAsked`: `claim` compares `next` with `asked`, and gives
`next` and moves it by one, or gives none. -/
theorem claim_is (r : Reading) : Reading.claim r ⦃ a =>
    (r.next.val < r.asked.val → a.1 = some r.next ∧ a.2.next.val = r.next.val + 1 ∧
      a.2.asked = r.asked ∧ a.2.payload = r.payload ∧ a.2.max_item = r.max_item ∧
      a.2.max_payload = r.max_payload) ∧
    (r.asked.val ≤ r.next.val → a.1 = none ∧ a.2 = r) ⦄ := by
  unfold Reading.claim
  split_ifs with finished
  · refine (WP.spec_ok _).mpr ?_
    exact ⟨fun below => absurd finished (by scalar_tac), fun _ => ⟨rfl, rfl⟩⟩
  · step*
    exact ⟨fun _ => ⟨by simp [UScalar.eq_equiv]; omega, i_post⟩,
      fun above => absurd above (by omega)⟩

/-- Proof of the first claim of `TheTurnsAreThoseAsked`, for the reading that `claim` gives: `next` stays at
most `asked`. -/
theorem claim_keeps_next (r : Reading) (le : r.next.val ≤ r.asked.val) :
    Reading.claim r ⦃ a => a.2.next.val ≤ a.2.asked.val ⦄ := by
  refine WP.spec_mono (claim_is r) ?_
  rintro a ⟨ahead, done⟩
  by_cases below : r.next.val < r.asked.val
  · obtain ⟨_, step, same, _⟩ := ahead below
    rw [same]; omega
  · obtain ⟨_, same⟩ := done (by omega)
    rw [same]; exact le

/-- Proof of `end` of `TheTurnsAreThoseAsked`: `end` sets `next` to `asked`. -/
theorem end_is (r : Reading) : Reading.end r ⦃ r' =>
    r'.next = r.asked ∧ r'.asked = r.asked ∧ r'.payload = r.payload ∧
    r'.max_item = r.max_item ∧ r'.max_payload = r.max_payload ⦄ := by
  unfold Reading.end
  refine (WP.spec_ok _).mpr ?_
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

/-- The new reading is the one of the answer to `asked` digests and the maxima, with no bytes and no turn. -/
theorem new_is (asked : Std.Usize) (mi mp : Std.U64) : Reading.new asked mi mp ⦃ r =>
    r = ⟨asked, 0#usize, 0#u64, mi, mp⟩ ⦄ := by
  unfold Reading.new
  exact (WP.spec_ok _).mpr rfl

/-- The turns given by `n` calls of `claim` from a reading that is not past its end: the turns that are
left, from `next`, as many as there are calls, then none for the calls beyond. -/
theorem turns_are : ∀ (n : Nat) (r : Reading), r.next.val ≤ r.asked.val →
    Turns n r ⦃ l => l.map (Option.map (·.val)) =
      ((List.range' r.next.val (Nat.min n (r.asked.val - r.next.val))).map some) ++
        List.replicate (n - (r.asked.val - r.next.val)) none ⦄
  | 0, r, _ => by
    unfold Turns
    refine (WP.spec_ok _).mpr ?_
    simp
  | n + 1, r, le => by
    unfold Turns
    refine WP.spec_bind (claim_is r) ?_
    rintro ⟨a, r'⟩ ⟨ahead, done⟩
    dsimp only at ahead done ⊢
    by_cases below : r.next.val < r.asked.val
    · obtain ⟨first, step, same, _⟩ := ahead below
      have same_asked : r'.asked.val = r.asked.val := by rw [same]
      refine WP.spec_bind (turns_are n r' (by omega)) ?_
      intro l same_list
      refine (WP.spec_ok _).mpr ?_
      subst first
      simp only [List.map_cons, Option.map_some, same_list, step, same]
      have left : r.asked.val - r.next.val = (r.asked.val - (r.next.val + 1)) + 1 := by omega
      rw [left, show Nat.min (n + 1) (r.asked.val - (r.next.val + 1) + 1) =
        Nat.min n (r.asked.val - (r.next.val + 1)) + 1 from Nat.succ_min_succ _ _, show n + 1 - (r.asked.val - (r.next.val + 1) + 1) =
        n - (r.asked.val - (r.next.val + 1)) by omega, List.range'_succ]
      simp
    · obtain ⟨none_given, same⟩ := done (by omega)
      subst none_given same
      refine WP.spec_bind (turns_are n r' le) ?_
      intro l same_list
      refine (WP.spec_ok _).mpr ?_
      have empty : r'.asked.val - r'.next.val = 0 := by omega
      simp only [List.map_cons, Option.map_none, same_list, empty]
      simp [List.replicate_succ]

/-- Proof of `WhatTheStatusBytesSay`: `status_is` and `turn_is`. -/
theorem what_the_status_bytes_say : WhatTheStatusBytesSay :=
  ⟨status_is, turn_is⟩

/-- Proof of `WhatRoomSaysExactly`: `room_is`. -/
theorem what_room_says_exactly : WhatRoomSaysExactly :=
  room_is

/-- Proof of `WhatTakeAcceptsExactly`: `take_is`, read field by field. -/
theorem what_take_accepts_exactly : WhatTakeAcceptsExactly :=
  take_is

/-- Whatever the reading, a chunk that is taken leaves it within the maxima: the first chunk is at most
`max_item`, a later one brings the bytes to at most `max_payload`. -/
theorem take_keeps_within (r : Reading) (len : Std.U64) (size : Option Std.U64) :
    Reading.take r len size ⦃ a =>
      (a.1 = true → r.payload.val ≠ 0 → a.2.payload.val ≤ r.max_payload.val) ∧
      (Within r → Within a.2) ⦄ := by
  refine WP.spec_mono (take_is r len size) ?_
  rintro a ⟨taken, added, refused, _, _, same_item, same_max⟩
  have later : a.1 = true → r.payload.val ≠ 0 → a.2.payload.val ≤ r.max_payload.val := by
    intro yes busy
    obtain ⟨_, _, room⟩ := taken.mp yes
    rcases room with empty | fits
    · exact absurd empty busy
    · rw [added yes]; exact fits
  refine ⟨later, fun within => ?_⟩
  cases yes : a.1
  · rw [refused yes]; exact within
  · obtain ⟨short, _, room⟩ := taken.mp yes
    unfold Within
    rw [same_item, same_max]
    by_cases busy : r.payload.val = 0
    · right; rw [added yes]; omega
    · left; rw [added yes]; rcases room with empty | fits
      · exact absurd empty busy
      · exact fits

/-- The calls of `claim` and `end` do not change the bytes held or the maxima. -/
theorem claim_keeps_within (r : Reading) (within : Within r) :
    Reading.claim r ⦃ a => Within a.2 ⦄ := by
  refine WP.spec_mono (claim_is r) ?_
  rintro a ⟨ahead, done⟩
  by_cases below : r.next.val < r.asked.val
  · obtain ⟨_, _, _, same_payload, same_item, same_max⟩ := ahead below
    unfold Within at within ⊢
    rwa [same_payload, same_item, same_max]
  · obtain ⟨_, same⟩ := done (by omega)
    rw [same]; exact within

/-- Proof of `TheBoundsOfAnAnswerHold`: a new reading holds nothing (`new_is`), and `claim`, `end` and
`take` keep `Within`. -/
theorem the_bounds_of_an_answer_hold : TheBoundsOfAnAnswerHold := by
  refine ⟨fun asked mi mp => ?_, fun r within => claim_keeps_within r within, fun r within => ?_,
    fun r len size within => ?_, fun r len size => ?_⟩
  · refine WP.spec_mono (new_is asked mi mp) ?_
    intro r same
    subst same
    exact ⟨Or.inl (by simp), by simp, by simp, rfl⟩
  · refine WP.spec_mono (end_is r) ?_
    rintro r' ⟨_, _, same_payload, same_item, same_max⟩
    unfold Within at within ⊢
    rwa [same_payload, same_item, same_max]
  · exact WP.spec_mono (take_keeps_within r len size) (fun a h => h.2 within)
  · exact WP.spec_mono (take_keeps_within r len size) (fun a h => h.1)

/-- Proof of `TheTurnsAreThoseAsked`: `claim_is`, `claim_keeps_next`, `end_is`, and `take_is` (it does
not change `next`). -/
theorem the_turns_are_those_asked : TheTurnsAreThoseAsked := by
  refine ⟨claim_is, claim_keeps_next, fun r => ?_, fun r len size le => ?_⟩
  · exact WP.spec_mono (end_is r) (fun r' h => ⟨h.1, h.2.1, h.2.2.1⟩)
  · refine WP.spec_mono (take_is r len size) ?_
    rintro a ⟨_, _, _, same_asked, same_next, _⟩
    rw [same_asked, same_next]; exact le

/-- Proof of `EveryDigestAskedHasOneTurn`: `turns_are` from `next` 0, with `asked + 2` calls. -/
theorem every_digest_asked_has_one_turn : EveryDigestAskedHasOneTurn := by
  intro asked mi mp
  refine WP.spec_mono (new_is asked mi mp) ?_
  intro r same
  subst same
  refine WP.spec_mono (turns_are (asked.val + 2) _ (by simp)) ?_
  intro l same_list
  rw [same_list]
  simp [List.range_eq_range']

/-- Proof of `AnAnswerThatEndedGivesNoTurn`: after `end`, `next` is `asked`, and `claim_is` gives none. -/
theorem an_answer_that_ended_gives_no_turn : AnAnswerThatEndedGivesNoTurn := by
  intro r
  refine WP.spec_mono (end_is r) ?_
  rintro r' ⟨ended, same_asked, _⟩
  refine WP.spec_mono (claim_is r') ?_
  rintro a ⟨_, done⟩
  exact (done (by rw [ended, same_asked])).1

/-- Proof of `ACorrectPeerIsAlwaysTaken`: the three conditions of `take_is` hold. -/
theorem a_correct_peer_is_always_taken : ACorrectPeerIsAlwaysTaken := by
  intro r len size small sized room
  refine WP.spec_mono (take_is r len size) ?_
  rintro a ⟨taken, added, _⟩
  have yes := taken.mpr ⟨small, sized, room⟩
  exact ⟨yes, added yes⟩

end RecvCore
