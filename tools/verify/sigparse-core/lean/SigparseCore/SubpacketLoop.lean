-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loop of `subpackets` knows after each subpacket (`Said`: what the
-- answer says of the subpackets read so far), and what `subpackets` answers.
-- Why it is needed: the claims about the times, the flags, the critical subpackets and the embedded
-- signatures are proved here once for the loop, for both areas.
-- Read before this file: Subpacket.lean.
-- Notation: `LastOfKind bytes subs k` is the last subpacket of kind `k` of the list `subs`;
-- `SubsRun` says that subpackets run from one position to another.
import SigparseCore.Subpacket
import SigparseCore.PiecesFrom
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- The last subpacket of a kind after one more subpacket: the new one if it is of that kind, else
the one before. -/
theorem last_of_kind_one_more (bytes : List Std.U8) (subs : List Sub) (sub : Sub) (kind : Nat) :
    LastOfKind bytes (subs ++ [sub]) kind =
      if sub.kind bytes = kind then some sub else LastOfKind bytes subs kind := by
  unfold LastOfKind
  by_cases same : sub.kind bytes = kind
  · simp [same]
  · simp [same]

/-- The time field `field` of the answer, of the kind `kind`, after reading the subpackets `subs`
from a state where it was `start`: in the hashed area it is the time of the last subpacket of its
kind, if there is one (and none if there is none); in the other it has not changed. -/
def TimeSaid (bytes : List Std.U8) (hashed : Bool) (kind : Nat) (subs : List Sub)
    (start field : Option Std.U32) : Prop :=
  if hashed = true then field.map (fun time => time.val) = (LastOfKind bytes subs kind).map
    (·.Time bytes)
  else field = start

/-- The same for the key flags. -/
def FlagsSaid (bytes : List Std.U8) (hashed : Bool) (subs : List Sub)
    (start field : Option Std.U8) : Prop :=
  if hashed = true then field.map (fun flags => flags.val) = (LastOfKind bytes subs 27).map
    (·.Flags bytes)
  else field = start

/-- What the answer says after the subpackets `subs` of an area were read from a state `start`: the
times and the flags (`TimeSaid`, `FlagsSaid`; the subpackets of the kinds of the times have a value
of 4 bytes, when the area is the hashed one), the embedded signatures (the values of the subpackets
of kind 32, in order, after the ones there were), the issuer fingerprint (a new one is inside the
area, which ends at `stop`), and the critical subpackets of the hashed area, which are of a known
kind. -/
def Said (bytes : List Std.U8) (hashed : Bool) (stop : Nat) (subs : List Sub)
    (start out : sig.Subpackets) : Prop :=
  TimeSaid bytes hashed 2 subs start.created out.created ∧
  TimeSaid bytes hashed 3 subs start.expires out.expires ∧
  TimeSaid bytes hashed 9 subs start.key_expires out.key_expires ∧
  FlagsSaid bytes hashed subs start.key_flags out.key_flags ∧
  (hashed = true → ∀ sub ∈ subs, (sub.kind bytes = 2 ∨ sub.kind bytes = 3 ∨ sub.kind bytes = 9) →
    sub.len = 5) ∧
  SpanPairs out.embedded = SpanPairs start.embedded ++
    ((subs.filter (fun sub => sub.kind bytes == 32)).map (fun sub => (sub.body + 1, sub.len - 1))) ∧
  (∀ span, out.issuer_fpr = some span → start.issuer_fpr = some span ∨
    span.off.val + span.len.val ≤ stop) ∧
  (hashed = true → ∀ sub ∈ subs, sub.Critical bytes → sub.kind bytes ∈ KnownKinds)

/-- One time field after one more subpacket. -/
theorem time_said_one_more (bytes : List Std.U8) (hashed : Bool) (kind : Nat) (subs : List Sub)
    (sub : Sub) (start before after : Option Std.U32)
    (said : TimeSaid bytes hashed kind subs start before)
    (applied : TimeAfter bytes hashed kind sub before after) :
    TimeSaid bytes hashed kind (subs ++ [sub]) start after := by
  unfold TimeSaid TimeAfter at *
  rw [last_of_kind_one_more]
  by_cases is_hashed : hashed = true
  · by_cases same : sub.kind bytes = kind
    · simp only [is_hashed, same, true_and, ite_true] at applied ⊢
      obtain ⟨_, time, is_time, value⟩ := applied
      simp [is_time, value]
    · simp only [is_hashed, same, ite_false, ite_true] at applied said ⊢
      rw [applied]
      exact said
  · simp only [is_hashed] at applied said ⊢
    rw [applied]
    exact said

/-- The key flags after one more subpacket. -/
theorem flags_said_one_more (bytes : List Std.U8) (hashed : Bool) (subs : List Sub) (sub : Sub)
    (start before after : Option Std.U8)
    (said : FlagsSaid bytes hashed subs start before)
    (applied : FlagsAfter bytes hashed sub before after) :
    FlagsSaid bytes hashed (subs ++ [sub]) start after := by
  unfold FlagsSaid FlagsAfter at *
  rw [last_of_kind_one_more]
  by_cases is_hashed : hashed = true
  · by_cases same : sub.kind bytes = 27
    · simp only [is_hashed, same, true_and, ite_true] at applied ⊢
      obtain ⟨flags, is_flags, value⟩ := applied
      simp [is_flags, value]
    · simp only [is_hashed, same, ite_false, ite_true] at applied said ⊢
      rw [applied]
      exact said
  · simp only [is_hashed] at applied said ⊢
    rw [applied]
    exact said

/-- What the answer says, after one more subpacket was read and applied. -/
theorem said_one_more (bytes : List Std.U8) (hashed : Bool) (stop : Nat) (subs : List Sub)
    (sub : Sub) (start out out' : sig.Subpackets) (inside : sub.body + sub.len ≤ stop)
    (said : Said bytes hashed stop subs start out) (applied : Applied bytes hashed sub out out')
    (known : hashed = true → sub.Critical bytes → sub.kind bytes ∈ KnownKinds) :
    Said bytes hashed stop (subs ++ [sub]) start out' := by
  obtain ⟨created, expires, key_expires, flags, four_bytes, embedded, fingerprint, criticals⟩
    := said
  obtain ⟨a_created, a_expires, a_key_expires, a_flags, a_embedded, a_fingerprint⟩ := applied
  refine ⟨time_said_one_more _ _ _ _ _ _ _ _ created a_created,
    time_said_one_more _ _ _ _ _ _ _ _ expires a_expires,
    time_said_one_more _ _ _ _ _ _ _ _ key_expires a_key_expires,
    flags_said_one_more _ _ _ _ _ _ _ flags a_flags, ?_, ?_, ?_, ?_⟩
  · -- the times have 4 bytes
    intro is_hashed s member time_kind
    rcases List.mem_append.mp member with earlier | last
    · exact four_bytes is_hashed s earlier time_kind
    · rw [List.mem_singleton] at last
      subst last
      unfold TimeAfter at a_created a_expires a_key_expires
      rcases time_kind with is_2 | is_3 | is_9
      · simp [is_hashed, is_2] at a_created
        exact a_created.1
      · simp [is_hashed, is_3] at a_expires
        exact a_expires.1
      · simp [is_hashed, is_9] at a_key_expires
        exact a_key_expires.1
  · -- the embedded signatures
    unfold EmbeddedAfter at a_embedded
    by_cases is_embedded : sub.kind bytes = 32
    · simp only [is_embedded, ite_true] at a_embedded
      rw [a_embedded, embedded, List.filter_append]
      simp [is_embedded, List.append_assoc]
    · simp only [is_embedded, ite_false] at a_embedded
      rw [a_embedded, embedded, List.filter_append]
      simp [is_embedded]
  · -- the issuer fingerprint
    intro span found
    rcases a_fingerprint span found with before | new
    · rcases fingerprint span before with start_one | old
      · exact Or.inl start_one
      · exact Or.inr old
    · exact Or.inr (by omega)
  · -- the critical subpackets
    intro is_hashed s member critical
    rcases List.mem_append.mp member with earlier | last
    · exact criticals is_hashed s earlier critical
    · rw [List.mem_singleton] at last
      subst last
      exact known is_hashed critical

/-- A length is written with at least one octet. -/
theorem length_at_has_octets (bytes : List Std.U8) (p stop len octets : Nat)
    (length_at : LengthAt bytes p stop = some (len, octets)) : 1 ≤ octets := by
  unfold LengthAt at length_at
  split at length_at
  · simp at length_at
  · split_ifs at length_at <;> simp_all
    omega

/-- A subpacket adds at most one embedded signature. -/
theorem applied_adds_at_most_one (bytes : List Std.U8) (hashed : Bool) (sub : Sub)
    (out out' : sig.Subpackets) (applied : Applied bytes hashed sub out out') :
    out'.embedded.val.length ≤ out.embedded.val.length + 1 := by
  have a_embedded := applied.2.2.2.2.1
  unfold EmbeddedAfter at a_embedded
  split at a_embedded
  · have := congrArg List.length a_embedded
    simpa [SpanPairs] using this.le
  · rw [a_embedded]
    omega

/-- The subpackets that run from `start` to `finish` take a byte each at least: `finish` is at least
`start` plus their number. -/
theorem subs_run_count (bytes : List Std.U8) (stop start finish : Nat) (subs : List Sub)
    (run : SubsRun bytes stop start finish subs) : start + subs.length ≤ finish := by
  induction subs generalizing start with
  | nil =>
    simp only [SubsRun] at run
    simp [run]
  | cons sub rest ih =>
    obtain ⟨_, same_start, ⟨octets, _, body_is⟩, nonempty, fits, rest_run⟩ := run
    have := ih _ rest_run
    simp only [List.length_cons]
    omega

/-- One more subpacket at the end of a run of subpackets. -/
theorem subs_run_one_more (bytes : List Std.U8) (stop start middle : Nat) (subs : List Sub)
    (sub : Sub) (run : SubsRun bytes stop start middle subs)
    (next : middle < stop ∧ sub.start = middle ∧
      (∃ octets, LengthAt bytes middle stop = some (sub.len, octets) ∧ sub.body = middle + octets) ∧
      1 ≤ sub.len ∧ sub.body + sub.len ≤ stop) :
    SubsRun bytes stop start (sub.body + sub.len) (subs ++ [sub]) := by
  induction subs generalizing start with
  | nil =>
    simp only [SubsRun] at run
    subst run
    exact ⟨next.1, next.2.1, next.2.2.1, next.2.2.2.1, next.2.2.2.2, rfl⟩
  | cons first rest ih =>
    exact ⟨run.1, run.2.1, run.2.2.1, run.2.2.2.1, run.2.2.2.2.1, ih _ run.2.2.2.2.2⟩

/-- What the loop of `subpackets` knows at each turn: the subpackets it has read run from the start
of the area to `at_` (which is inside the area), the answer says what they say (`Said`), and the
answer has no more embedded signatures than the bytes it has read allow (each subpacket takes at
least two). -/
def SubsRead (bytes : List Std.U8) (hashed : Bool) (area_start stop : Nat)
  (start out : sig.Subpackets)
    (at_ : Std.Usize) : Prop :=
  area_start ≤ at_.val ∧ at_.val ≤ stop ∧
  ∃ subs, SubsRun bytes stop area_start at_.val subs ∧ Said bytes hashed stop subs start out ∧
    out.embedded.val.length ≤ start.embedded.val.length + (at_.val - area_start)

/-- The loop of `subpackets` returns, and when it ends with no refusal, the subpackets it has read
make up the area from `area_start` to `end_` and the answer says what they say (`Said`).  One turn
reads the subpacket at `at_` (`one`) and the next starts after it, or holds a refusal and the next
turn ends the loop. -/
theorem subpackets_loop_reads (body : Slice Std.U8) (hashed : Bool) (end_ : Std.Usize)
    (start_out out : sig.Subpackets) (at_ : Std.Usize) (fail1 : Option velarx_sigparse_core.Error)
    (area_start : Nat) (inside : end_.val ≤ body.val.length)
    (room : start_out.embedded.val.length + (end_.val - area_start) < Usize.max)
    (read : SubsRead body.val hashed area_start end_.val start_out out at_) :
    sig.subpackets_loop body hashed out end_ at_ fail1 ⦃ r =>
      r.2 = none → ∃ subs, AreaMadeOf body.val area_start end_.val subs ∧
        Said body.val hashed end_.val subs start_out r.1 ⦄ := by
  unfold sig.subpackets_loop
  apply loop.spec_decr_nat
    (fun q => 2 * (end_.val - q.2.1.val) + (if q.2.2.isNone then 1 else 0))
    (fun q => q.2.1.val ≤ end_.val ∧
      (q.2.2 = none → SubsRead body.val hashed area_start end_.val start_out q.1 q.2.1))
  · rintro ⟨out, at_, fail1⟩ ⟨before_end, read⟩
    simp only at before_end read ⊢
    unfold sig.subpackets_loop.body
    dsimp only
    split
    · rename_i unrefused
      have unrefused : fail1 = none := by cases fail1 <;> simp_all [core.option.Option.is_none]
      subst unrefused
      obtain ⟨from_start, in_area, subs, run, said, few_embedded⟩ := read rfl
      split
      · rename_i below
        have below : at_.val < end_.val := by scalar_tac
        have := subs_run_count _ _ _ _ _ run
        step with one_reads as ⟨ r, out1, found ⟩
        cases r with
        | Ok next =>
          obtain ⟨sub, starts, ⟨octets, length_at, body_is⟩, nonempty, fits, next_is, applied,
            known⟩ := found.1 next rfl
          have run_next : SubsRun body.val end_.val area_start next.val (subs ++ [sub]) := by
            rw [next_is]
            exact subs_run_one_more _ _ _ _ _ _ run ⟨below, starts, ⟨octets, length_at, body_is⟩,
              nonempty, fits⟩
          have said_next := said_one_more _ _ _ _ _ _ _ _ fits said applied known
          have octets_positive := length_at_has_octets _ _ _ _ _ length_at
          have one_more : out1.embedded.val.length ≤ out.embedded.val.length + 1 :=
            applied_adds_at_most_one _ _ _ _ _ applied
          simp only [WP.spec_ok]
          refine ⟨by omega, fun _ => ⟨by omega, by omega, subs ++ [sub], run_next, said_next, ?_⟩,
            by omega⟩
          omega
        | Err e =>
          simp only [WP.spec_ok]
          exact ⟨before_end, fun same => by simp at same, by simp⟩
      · rename_i not_below
        have at_end : at_.val = end_.val := by scalar_tac
        simp only [WP.spec_ok]
        intro _
        refine ⟨subs, ?_, said⟩
        unfold AreaMadeOf
        rw [at_end] at run
        exact run
    · rename_i refused
      simp only [WP.spec_ok]
      intro none_refused
      simp_all [core.option.Option.is_none]
  · exact ⟨read.2.1, fun _ => read⟩

/-- The loop of `subpackets` does not refuse an area that is made of subpackets it accepts: given
the subpackets (`SubsRun`) that run from `at_` to `end_`, each acceptable in the hashed area
(`Sub.Acceptable`), and room for the embedded signatures they may add, the loop ends with no
refusal.  (The converse of `subpackets_loop_reads`: that says what a refusal-free end means, this
says that the end is refusal-free.) -/
theorem subpackets_loop_accepts (body : Slice Std.U8) (hashed : Bool) (end_ : Std.Usize)
    (start_out : sig.Subpackets) (start_at : Std.Usize) (inside : end_.val ≤ body.val.length)
    (before_end : start_at.val ≤ end_.val)
    (room : start_out.embedded.val.length + (end_.val - start_at.val) < Usize.max)
    (all_subs : List Sub) (all_run : SubsRun body.val end_.val start_at.val end_.val all_subs)
    (all_fine : hashed = true → ∀ sub ∈ all_subs, sub.Acceptable body.val) :
    sig.subpackets_loop body hashed start_out end_ start_at none ⦃ r => r.2 = none ⦄ := by
  unfold sig.subpackets_loop
  apply loop.spec_decr_nat
    (fun q => 2 * (end_.val - q.2.1.val) + (if q.2.2.isNone then 1 else 0))
    (fun q => q.2.2 = none ∧ q.2.1.val ≤ end_.val ∧
      q.1.embedded.val.length + (end_.val - q.2.1.val) < Usize.max ∧
      ∃ subs, SubsRun body.val end_.val q.2.1.val end_.val subs ∧
        (hashed = true → ∀ sub ∈ subs, sub.Acceptable body.val))
  · rintro ⟨out, at_, fail1⟩ ⟨unrefused, before_end, room, subs, run, fine⟩
    simp only at unrefused before_end room ⊢
    subst unrefused
    unfold sig.subpackets_loop.body
    dsimp only
    have := body.property
    split
    · split
      · rename_i below
        have below : at_.val < end_.val := by scalar_tac
        cases subs with
        | nil =>
          simp only [SubsRun] at run
          omega
        | cons sub rest =>
          obtain ⟨_, starts, found_sub, nonempty, fits, rest_run⟩ := run
          step with one_reads as ⟨ r, out1, found ⟩
          cases r with
          | Ok next =>
            obtain ⟨sub', starts', found_sub', nonempty', fits', next_is, applied_out, _⟩ :=
              found.1 next rfl
            have same : sub = sub' := sub_is_determined body.val at_.val end_.val sub sub' starts
              starts' found_sub found_sub'
            subst same
            have one_more : out1.embedded.val.length ≤ out.embedded.val.length + 1 := by
              exact applied_adds_at_most_one _ _ _ _ _ applied_out
            have octets_positive := length_at_has_octets _ _ _ _ _ found_sub'.choose_spec.1
            simp only [WP.spec_ok]
            refine ⟨trivial, by omega, by omega, ⟨rest, by rw [next_is]; exact rest_run,
              fun is_hashed s member => fine is_hashed s (List.mem_cons_of_mem _ member)⟩,
              by simp; omega⟩
          | Err e =>
            exact absurd ⟨sub, starts, found_sub, nonempty, fits, fun is_hashed =>
              fine is_hashed sub (List.mem_cons_self ..)⟩ (found.2 e rfl)
      · rename_i not_below
        simp only [WP.spec_ok]
    · simp only [WP.spec_ok]
  · exact ⟨rfl, before_end, room, all_subs, all_run, all_fine⟩

/-- Before any subpacket is read, the answer says nothing more than what it said at the start: in
the hashed area that means it says no time and no flags (it starts empty). -/
theorem said_nothing_yet (bytes : List Std.U8) (hashed : Bool) (stop : Nat) (out : sig.Subpackets)
    (empty : hashed = true → out.created = none ∧ out.expires = none ∧ out.key_expires = none ∧
      out.key_flags = none) :
    Said bytes hashed stop [] out out := by
  unfold Said TimeSaid FlagsSaid LastOfKind
  by_cases is_hashed : hashed = true
  · obtain ⟨created, expires, key_expires, key_flags⟩ := empty is_hashed
    simp [is_hashed, created, expires, key_expires, key_flags, SpanPairs]
    exact fun span found => Or.inl found
  · simp [is_hashed, SpanPairs]
    exact fun span found => Or.inl found

/-- `subpackets` reads the area as the subpackets that make it up: it returns, and when it accepts,
the area is made up of subpackets and the answer says what they say (`Said`). -/
theorem subpackets_reads (body : Slice Std.U8) (area : Span) (hashed : Bool) (out : sig.Subpackets)
    (inside : area.off.val + area.len.val ≤ body.val.length)
    (room : out.embedded.val.length + area.len.val < Usize.max)
    (empty : hashed = true → out.created = none ∧ out.expires = none ∧ out.key_expires = none ∧
      out.key_flags = none) :
    sig.subpackets body area hashed out ⦃ r =>
      ∀ u, r.1 = core.result.Result.Ok u →
        ∃ subs, AreaMadeOf body.val area.off.val (area.off.val + area.len.val) subs ∧
          Said body.val hashed (area.off.val + area.len.val) subs out r.2 ⦄ := by
  unfold sig.subpackets
  have := body.property
  step with span_end_is_the_sum as ⟨ stop, hstop ⟩
  have loop_reads := subpackets_loop_reads body hashed stop out out area.off none area.off.val
    (by omega) (by omega)
    ⟨le_refl _, by omega, [], by simp [SubsRun], said_nothing_yet _ _ _ _ empty, by simp⟩
  step with loop_reads as ⟨ out1, fail1, finished ⟩
  cases fail1 with
  | none =>
    simp only [WP.spec_ok]
    rintro u _
    obtain ⟨subs, made, said⟩ := finished rfl
    exact ⟨subs, by rwa [hstop] at made, by rwa [hstop] at said⟩
  | some e =>
    simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true]

/-- `subpackets` does not refuse an area made of subpackets it accepts: given the subpackets of the
area (`AreaMadeOf`), each acceptable in the hashed area (`Sub.Acceptable`), and room for the
embedded signatures they may add, it returns with no refusal. -/
theorem subpackets_accepts (body : Slice Std.U8) (area : Span) (hashed : Bool)
    (out : sig.Subpackets) (inside : area.off.val + area.len.val ≤ body.val.length)
    (room : out.embedded.val.length + area.len.val < Usize.max) (subs : List Sub)
    (made : AreaMadeOf body.val area.off.val (area.off.val + area.len.val) subs)
    (fine : hashed = true → ∀ sub ∈ subs, sub.Acceptable body.val) :
    sig.subpackets body area hashed out ⦃ r => ∃ u, r.1 = core.result.Result.Ok u ⦄ := by
  unfold sig.subpackets
  have := body.property
  step with span_end_is_the_sum as ⟨ stop, hstop ⟩
  have loop_accepts := subpackets_loop_accepts body hashed stop out area.off (by omega)
    (by omega) (by omega) subs (by rw [hstop]; exact made) (fun is_hashed => fine is_hashed)
  step with loop_accepts as ⟨ out1, fail1, finished ⟩
  subst finished
  simp [WP.spec_ok]

end SigparseCore
