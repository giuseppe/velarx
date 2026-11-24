-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: facts about the pieces of the bodies of the packets (`PiecesFrom`): laying
-- out more pieces, where they lie, how many there are, and the pieces of a list of packets.
-- Why it is needed: the proofs of `packets` build the list of the pieces one packet at a time, and
-- these facts say that what they build keeps its shape.
-- Read before this file: Spec.lean (`Pieces`, `PiecesFrom`).
-- Notation: `l ++ [x]` is the list `l` with `x` at its end; `x ∈ l` is "`x` is an element of `l`".
import SigparseCore.Spec
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- Pieces laid out after `start` up to `middle`, and more pieces after `middle` up to `stop`, are
all of them laid out after `start` up to `stop`. -/
theorem pieces_from_append (first second : List Span) (start middle stop : Nat)
    (before : PiecesFrom start first middle) (after : PiecesFrom middle second stop) :
    PiecesFrom start (first ++ second) stop := by
  induction first generalizing start with
  | nil =>
    simp only [PiecesFrom] at before
    subst before
    exact after
  | cons piece rest ih =>
    exact ⟨before.1, ih _ before.2⟩

/-- Pieces laid out after `start` end at or after `start`, and every piece lies between `start` and
`stop`. -/
theorem pieces_from_inside (pieces : List Span) (start stop : Nat)
    (laid : PiecesFrom start pieces stop) :
    start ≤ stop ∧ ∀ piece ∈ pieces, start < piece.off.val
      ∧ piece.off.val + piece.len.val ≤ stop := by
  induction pieces generalizing start with
  | nil =>
    simp only [PiecesFrom] at laid
    simp [laid]
  | cons piece rest ih =>
    obtain ⟨begins, laid_rest⟩ := laid
    obtain ⟨le, inside⟩ := ih _ laid_rest
    refine ⟨by omega, ?_⟩
    intro member hmember
    rcases List.mem_cons.mp hmember with rfl | later
    · exact ⟨begins, le⟩
    · obtain ⟨after, within⟩ := inside member later
      exact ⟨by omega, within⟩

/-- Pieces laid out after `start` up to `stop` take a byte each: `stop` is at least `start` plus
their number. -/
theorem pieces_from_count (pieces : List Span) (start stop : Nat)
    (laid : PiecesFrom start pieces stop) : start + pieces.length ≤ stop := by
  induction pieces generalizing start with
  | nil =>
    simp only [PiecesFrom] at laid
    simp [laid]
  | cons piece rest ih =>
    obtain ⟨begins, laid_rest⟩ := laid
    have := ih _ laid_rest
    simp only [List.length_cons]
    omega

/-- A list of packets has at least as many pieces as packets. -/
theorem packets_have_pieces (packets : List packet.Packet) :
    packets.length ≤ (Pieces packets).length := by
  induction packets with
  | nil => simp [Pieces]
  | cons packet rest ih =>
    simp only [Pieces, List.length_cons, List.length_append]
    omega

/-- The pieces of the packets of a list with one more packet at its end. -/
theorem pieces_of_one_more (packets : List packet.Packet) (packet : packet.Packet) :
    Pieces (packets ++ [packet]) = Pieces packets ++ (packet.body :: packet.more.val) := by
  induction packets with
  | nil => simp [Pieces]
  | cons first rest ih =>
    simp [Pieces, ih]

end SigparseCore
