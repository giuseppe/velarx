-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `AFilterThatSaysNoIsAWholeFilterAndTheDeltasThatFollowedIt`, the claim
--   of Spec.lean that after ANY messages of a peer a "no" of the filter means that a whole filter and the
--   deltas that moved the version since it (all of one run, each from the version before) were taken.
-- Why it is needed: `WhatSaysAnswersExactly` says a "no" needs a filter that is not behind, and the
--   claims about `delta` and `added` say when a filter is behind; this file puts them together over a
--   whole list of messages, which is the property the node relies on.
-- Read before this file: Spec.lean (`Message`, `Node`, `Extend`, `Receive`), ClaimsOfTheSeen.lean.
-- Notation: `Sound n` (below) is what holds of a node after every message; a proof by `induction` over
--   the list of messages shows each message keeps it.  `cases d` splits on what `delta` or `full` answered;
--   `omega` settles inequalities of whole numbers.
import RecvCore.ClaimsOfTheSeen
open Aeneas Aeneas.Std Result velarx_recv_core
namespace RecvCore

/-- What holds of a node after every message of any peer: (1) when the chain is at a run and a version,
the `Seen` is at that run and that version; (2) a node that holds no whole filter has no chain; (3) a node
that holds a whole filter and has no chain (a delta of another run came since) is at version 0 with
something heard of, so it is behind. -/
def Sound (n : Node) : Prop :=
  (∀ e v, n.chain = some (e, v) → n.seen.epoch = e ∧ n.seen.version = v) ∧
  (n.held = false → n.chain = none) ∧
  (n.held = true → n.chain = none → n.seen.version.val = 0 ∧ 0 < n.seen.heard.val)

/-- Nothing is heard and nothing is held: the start is sound. -/
theorem start_is_sound (s0 : Seen) : Sound ⟨s0, false, none⟩ :=
  ⟨fun _ _ chain => by simp at chain, fun _ => rfl, fun held => by simp at held⟩

/-- The chain of a node that has none stays none. -/
theorem extend_none (e base upto : Std.U64) : Extend none e base upto = none := rfl

/-- A delta of another run than the chain's ends the chain. -/
theorem extend_other_run (run version e base upto : Std.U64) (other : run ≠ e) :
    Extend (some (run, version)) e base upto = none := by
  simp [Extend, other]

/-- A delta of the chain's run, from the version it is at (not 0) to a later one, moves the chain. -/
theorem extend_follows (e version base upto : Std.U64) (on_version : version = base)
    (nonzero : version.val ≠ 0) (later : version.val < upto.val) :
    Extend (some (e, version)) e base upto = some (e, upto) := by
  subst on_version
  simp [Extend, nonzero, later]

/-- Any other delta of the chain's run leaves the chain where it is. -/
theorem extend_stays (e version base upto : Std.U64)
    (off : ¬ (version = base ∧ version.val ≠ 0 ∧ version.val < upto.val)) :
    Extend (some (e, version)) e base upto = some (e, version) := by
  simp only [Extend, ne_eq, not_true_eq_false, ite_false, ite_eq_right_iff]
  exact fun h => absurd h off

/-- One whole filter keeps the node sound: when it is taken the chain is that filter; when it is stale
nothing changes. -/
theorem a_whole_filter_keeps_sound (n : Node) (e v : Std.U64) (sound : Sound n) :
    Receive (Message.whole e v) n ⦃ n' => Sound n' ⦄ := by
  unfold Receive
  refine WP.spec_bind (full_is n.seen e v n.held) ?_
  rintro ⟨d, s⟩ ⟨_, stale_same, taken⟩
  cases d
  · -- it is stale: the `Seen` is as it was
    have same : s = n.seen := stale_same rfl
    subst same
    exact (WP.spec_ok _).mpr sound
  · -- it is taken: the chain is the whole filter, at its run and version
    obtain ⟨epoch_is, version_is, _⟩ := taken rfl
    refine (WP.spec_ok _).mpr ⟨?_, fun held => by simp at held, fun _ chain => by simp at chain⟩
    intro e' v' chain
    obtain ⟨rfl, rfl⟩ := Option.some.inj chain |> Prod.mk.inj
    exact ⟨epoch_is, version_is⟩

/-- One delta keeps the node sound: a stale one changes nothing, one with no filter to add to changes only
the `Seen` of a node that holds nothing, and one that is added moves the chain only when it goes from the
version held (not 0), as `added` does. -/
theorem a_delta_keeps_sound (n : Node) (e base upto : Std.U64) (sound : Sound n) :
    Receive (Message.delta e base upto) n ⦃ n' => Sound n' ⦄ := by
  obtain ⟨at_chain, no_filter, no_chain⟩ := sound
  unfold Receive
  refine WP.spec_bind (delta_is n.seen e upto n.held) ?_
  rintro ⟨d, s1⟩ ⟨stale_is, stale_same, add_is, skip_is, moved⟩
  cases d
  · -- stale: nothing changes
    have same : s1 = n.seen := stale_same rfl
    subst same
    exact (WP.spec_ok _).mpr ⟨at_chain, no_filter, no_chain⟩
  · -- skip: no filter was held, so there is no chain
    have unheld : n.held = false := (skip_is.mp rfl).2
    have no_chain' : n.chain = none := no_filter unheld
    refine (WP.spec_ok _).mpr ⟨fun _ _ chain => by simp [no_chain'] at chain,
      fun _ => no_chain', fun held => by simp [unheld] at held⟩

  · -- add: `added` is told, and the chain is extended
    obtain ⟨fresh, held⟩ := add_is.mp rfl
    obtain ⟨epoch_is, version_is, heard_is⟩ := moved (by simp)
    refine WP.spec_bind (added_is s1 base upto) ?_
    intro s2 ⟨same_epoch, same_heard, applies, stays⟩
    refine (WP.spec_ok _).mpr ?_
    dsimp only at *
    -- a delta that starts at version 0, or from where the `Seen` is not, leaves its version
    have not_applied : s1.version.val = 0 → ¬ (base = s1.version ∧ base.val ≠ 0) := by
      rintro zero ⟨on_version, nonzero⟩
      exact nonzero (by rw [on_version]; exact zero)
    rcases chain_is : n.chain with _ | ⟨run, version⟩
    · -- no chain (a delta of another run came since the whole filter): still at version 0, behind
      obtain ⟨version_zero, heard_some⟩ := no_chain held chain_is
      have s1_zero : s1.version.val = 0 := by split_ifs at version_is <;> omega
      have s1_heard : 0 < s1.heard.val := by split_ifs at heard_is <;> omega
      rw [extend_none]
      refine ⟨fun _ _ chain => by simp at chain, fun unheld => by simp [held] at unheld,
        fun _ _ => ⟨?_, ?_⟩⟩
      · rw [stays (not_applied s1_zero)]; exact s1_zero
      · rw [same_heard]; exact s1_heard
    · obtain ⟨run_is, version_held⟩ := at_chain run version chain_is
      by_cases same_run : run = e
      · -- the chain's run: the delta is past the version held, since it is not stale
        subst same_run
        have later : version.val < upto.val := by
          by_contra not_later
          exact fresh ⟨run_is.symm, by rw [version_held]; omega⟩
        have s1_version : s1.version = version := UScalar.eq_equiv _ _ |>.mpr (by
          rw [version_is, run_is]; simp [version_held])
        by_cases applied : base = s1.version ∧ base.val ≠ 0
        · have on_version : version = base := by rw [← s1_version]; exact applied.1.symm
          rw [extend_follows run version base upto on_version
            (by rw [on_version]; exact applied.2) later]
          refine ⟨fun e' v' chain => ?_, fun unheld => by simp [held] at unheld,
            fun _ chain => by simp at chain⟩
          obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj chain)
          exact ⟨by rw [same_epoch, epoch_is], applies applied⟩
        · rw [extend_stays run version base upto (by
            rintro ⟨on_version, nonzero, _⟩
            exact applied ⟨by rw [s1_version]; exact on_version.symm, by
              rw [← on_version]; exact nonzero⟩)]
          refine ⟨fun e' v' chain => ?_, fun unheld => by simp [held] at unheld,
            fun _ chain => by simp at chain⟩
          obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj chain)
          exact ⟨by rw [same_epoch, epoch_is], by rw [stays applied, s1_version]⟩
      · -- another run: the chain ends, and the filter is at version 0, behind
        rw [extend_other_run run version e base upto same_run]
        have other : e ≠ n.seen.epoch := fun h => same_run (by rw [← run_is, h])
        simp only [other, ite_false] at version_is heard_is
        have s1_heard : 0 < s1.heard.val := by omega
        refine ⟨fun _ _ chain => by simp at chain, fun unheld => by simp [held] at unheld,
          fun _ _ => ⟨?_, ?_⟩⟩
        · rw [stays (not_applied version_is)]; exact version_is
        · rw [same_heard]; exact s1_heard

/-- Any message keeps the node sound: `a_whole_filter_keeps_sound` and `a_delta_keeps_sound`. -/
theorem a_message_keeps_sound (n : Node) (m : Message) (sound : Sound n) :
    Receive m n ⦃ n' => Sound n' ⦄ := by
  cases m with
  | whole e v => exact a_whole_filter_keeps_sound n e v sound
  | delta e base upto => exact a_delta_keeps_sound n e base upto sound

/-- Any list of messages keeps the node sound, one after the other. -/
theorem any_messages_keep_sound : ∀ (msgs : List Message) (n : Node), Sound n →
    Receives msgs n ⦃ n' => Sound n' ⦄
  | [], n, sound => by
    unfold Receives
    exact (WP.spec_ok _).mpr sound
  | m :: ms, n, sound => by
    unfold Receives
    refine WP.spec_bind (a_message_keeps_sound n m sound) ?_
    intro n1 sound1
    exact any_messages_keep_sound ms n1 sound1

/-- Proof of `AFilterThatSaysNoIsAWholeFilterAndTheDeltasThatFollowedIt`: the node is sound after the
messages; `says` answers "no" only when the filter is believed (so a whole filter was taken) and not
behind; a sound node with no chain is behind, so the chain is there, and it is the `Seen`'s run and
version. -/
theorem a_filter_that_says_no_is_a_whole_filter_and_the_deltas_that_followed_it :
    AFilterThatSaysNoIsAWholeFilterAndTheDeltasThatFollowedIt := by
  intro msgs believed contains
  unfold Seen.new
  refine (WP.spec_ok _).mpr ?_
  refine WP.spec_mono (any_messages_keep_sound msgs _ (start_is_sound _)) ?_
  rintro n ⟨at_chain, _, no_chain⟩ believed_held
  refine WP.spec_mono (says_is n.seen believed contains) ?_
  rintro a ⟨no_iff, _, _⟩ says_no
  obtain ⟨believed_is, _, not_behind⟩ := no_iff.mp says_no
  rcases chain_is : n.chain with _ | ⟨run, version⟩
  · obtain ⟨zero, heard_some⟩ := no_chain (believed_held believed_is) chain_is
    exact absurd (by unfold Behind; omega) not_behind
  · obtain ⟨run_is, version_is⟩ := at_chain run version chain_is
    rw [run_is, version_is]

end RecvCore
