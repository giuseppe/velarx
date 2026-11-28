-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `addRow` (Model.lean) makes of a list of extents: one row for
-- each digest, the first extent of the digest, and nothing that is not an extent.
--
-- Why it is needed: the table `inlined_files` has the key (digest, layer), so a layer
-- with two equal files has one row for them; the claims (Claims.lean) say which one.
--
-- Read before this file: Model.lean (`addRow`, `rows`).
-- Notation: `xs.find? p` is the first element of `xs` that satisfies `p`, if any;
-- `xs.foldl addRow acc` adds the elements of `xs` one by one to `acc`; `a.or b` is `a`
-- if it is an answer and `b` otherwise.
import InlineModel.Model

namespace InlineModel

/-- The first extent of a digest in the rows after adding `xs` to `acc` is the one of `acc`
if there is one, otherwise the first of `xs`. -/
theorem find_addRows (xs acc : List Extent) (d : Digest) :
    (xs.foldl addRow acc).find? (·.digest == d) = (acc.find? (·.digest == d)).or
      (xs.find? (·.digest == d)) := by
  induction xs generalizing acc with
  | nil => simp
  | cons x xs ih =>
    simp only [List.foldl_cons, ih]
    unfold addRow
    split
    · -- the digest of `x` is already a row: `x` is not added
      rename_i held
      obtain ⟨y, mem, same⟩ := List.any_eq_true.mp held
      cases found : acc.find? (·.digest == d) with
      | some r => simp
      | none =>
        have none := List.find?_eq_none.mp found
        by_cases dx : x.digest = d
        · exfalso
          have := none y mem
          simp only [beq_iff_eq] at same this
          exact this (same.trans dx)
        · simp [dx]
    · -- a new digest: `x` goes last
      by_cases dx : x.digest = d <;> simp [List.find?_append, dx]

/-- A row is an extent that was added or was already there. -/
theorem mem_addRows (xs acc : List Extent) (r : Extent) (mem : r ∈ xs.foldl addRow acc) :
    r ∈ acc ∨ r ∈ xs := by
  induction xs generalizing acc with
  | nil => exact .inl mem
  | cons x xs ih =>
    rcases ih _ mem with h | h
    · unfold addRow at h
      split at h
      · exact .inl h
      · rcases List.mem_append.mp h with h | h
        · exact .inl h
        · exact .inr (List.mem_cons.mpr (.inl (List.mem_singleton.mp h)))
    · exact .inr (List.mem_cons_of_mem _ h)

/-- No two rows have the same digest, if none had before. -/
theorem nodup_addRows (xs acc : List Extent) (nodup : (acc.map (·.digest)).Nodup) :
    ((xs.foldl addRow acc).map (·.digest)).Nodup := by
  induction xs generalizing acc with
  | nil => exact nodup
  | cons x xs ih =>
    refine ih _ ?_
    unfold addRow
    split
    · exact nodup
    · rename_i fresh
      simp only [List.map_append, List.map_cons, List.map_nil]
      refine List.nodup_append.mpr ⟨nodup, List.nodup_cons.mpr ⟨by simp, List.nodup_nil⟩, ?_⟩
      intro a ha b hb same
      obtain ⟨y, mem, rfl⟩ := List.mem_map.mp ha
      have : b = x.digest := List.mem_singleton.mp hb
      exact fresh (List.any_eq_true.mpr ⟨y, mem, by simp [same, this]⟩)

end InlineModel
