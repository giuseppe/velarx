-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that the subpackets that make up an area are determined by the bytes.
-- Why it is needed: the claims about the hashed area are stated for the subpackets of the area (`∀
-- subs`); the code builds one list, and this makes it the only one.
-- Read before this file: SubpacketLoop.lean (`subs_run_count`).
-- Notation: as in the files before it.
import SigparseCore.SubpacketLoop
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- The subpackets that make up an area are determined by the bytes: two lists of subpackets that
both run from `start` to `finish` are the same list.  (The length written at a position says where
the subpacket ends, so the next one begins in only one place; and a subpacket takes at least a byte,
so a run that has begun cannot end where it began.) -/
theorem subs_run_unique (bytes : List Std.U8) (stop start finish : Nat) (first second : List Sub)
    (run_first : SubsRun bytes stop start finish first)
    (run_second : SubsRun bytes stop start finish second) : first = second := by
  induction first generalizing start second with
  | nil =>
    cases second with
    | nil => rfl
    | cons sub rest =>
      have count := subs_run_count _ _ _ _ _ run_second
      simp only [SubsRun] at run_first
      simp only [List.length_cons] at count
      omega
  | cons sub rest ih =>
    cases second with
    | nil =>
      have count := subs_run_count _ _ _ _ _ run_first
      simp only [SubsRun] at run_second
      simp only [List.length_cons] at count
      omega
    | cons sub' rest' =>
      obtain ⟨_, start_1, ⟨octets_1, length_1, body_1⟩, _, _, rest_run_1⟩ := run_first
      obtain ⟨_, start_2, ⟨octets_2, length_2, body_2⟩, _, _, rest_run_2⟩ := run_second
      rw [length_1] at length_2
      simp only [Option.some.injEq, Prod.mk.injEq] at length_2
      obtain ⟨len_same, octets_same⟩ := length_2
      have same : sub = sub' := by
        cases sub; cases sub'
        simp only [Sub.mk.injEq] at *
        omega
      subst same
      rw [ih _ rest' rest_run_1 rest_run_2]

/-- The subpackets that make up an area are determined by the bytes. -/
theorem area_made_of_unique (bytes : List Std.U8) (start stop : Nat) (first second : List Sub)
    (made_first : AreaMadeOf bytes start stop first)
    (made_second : AreaMadeOf bytes start stop second) : first = second :=
  subs_run_unique bytes stop start stop first second made_first made_second

end SigparseCore
