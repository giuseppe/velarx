-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the placement of Model.lean (`placeRecords`, `placeData`,
-- `layout`) guarantees: the records of the inodes go up the image without a cut block,
-- the data after them, and everything the writer streams is ascending.
--
-- Why it is needed: Claims.lean reads the claims of Spec.lean (in the image, no overlap,
-- block rules, bytes kept) off these facts.
--
-- Read before this file: Model.lean, Ascending.lean.
-- Notation: `(placeRecords c xs).1` is the first part of the pair the function returns (the
-- records), `.2` the second (where they end); `omega` is the Lean tactic that proves a
-- statement about whole numbers with +, *, / and % by literals.
import InlineModel.Ascending

namespace InlineModel

/-- A record goes at or after the cursor. -/
theorem le_recordOffset (cursor : Nat) (x : Node) : cursor ≤ recordOffset cursor x := by
  unfold recordOffset avoidCut roundUp slot block
  split <;> omega

/-- A record that fits in a block is not cut by the end of a block. -/
theorem recordOffset_not_cut (cursor : Nat) (x : Node) (fits : x.record ≤ block) :
    recordOffset cursor x % block + x.record ≤ block := by
  unfold recordOffset avoidCut roundUp slot
  split
  · unfold block at *
    omega
  · rename_i uncut
    unfold block at *
    omega

/-- The records are laid out for the nodes given, in their order. -/
theorem placeRecords_nodes (cursor : Nat) (xs : List Node) :
    (placeRecords cursor xs).1.map Prod.fst = xs := by
  induction xs generalizing cursor with
  | nil => rfl
  | cons x xs ih => simp [placeRecords, ih]

/-- The data is laid out for the records given, in their order. -/
theorem placeData_records (b : Nat) (rs : List (Node × Nat)) :
    (placeData b rs).1.map (fun p => (p.node, p.offset)) = rs := by
  induction rs generalizing b with
  | nil => rfl
  | cons r rs ih => simp [placeData, ih]

/-- The records end at or after the cursor they start from. -/
theorem le_placeRecords (cursor : Nat) (xs : List Node) :
    cursor ≤ (placeRecords cursor xs).2 := by
  induction xs generalizing cursor with
  | nil => exact Nat.le_refl _
  | cons x xs ih =>
    have := ih (recordOffset cursor x + x.record)
    have := le_recordOffset cursor x
    simp only [placeRecords]
    omega

/-- The writes of the records (headers and inline data) go up from the cursor to where the
records end: each record is after the one before. -/
theorem records_ascend (cursor : Nat) (xs : List Node) (ps : List Placed)
    (placed : ps.map (fun p => (p.node, p.offset)) = (placeRecords cursor xs).1) :
    Ascending cursor (recordWrites ps) (placeRecords cursor xs).2 := by
  induction xs generalizing cursor ps with
  | nil => simp [placeRecords] at placed ⊢; subst placed; exact Nat.le_refl _
  | cons x xs ih =>
    cases ps with
    | nil => simp [placeRecords] at placed
    | cons p ps =>
      simp only [placeRecords, List.map_cons, List.cons.injEq, Prod.mk.injEq] at placed ⊢
      obtain ⟨⟨node, offset⟩, rest⟩ := placed
      have next := ih (recordOffset cursor x + x.record) ps rest
      have start := le_recordOffset cursor x
      simp only [recordWrites, Ascending, Placed.header, Placed.inlineData, node, offset]
      refine ⟨start, Nat.le_of_eq (by omega), ?_⟩
      have same : recordOffset cursor x + inodeSize + x.attrs + x.tail
          = recordOffset cursor x + x.record := by
        unfold Node.record; omega
      rw [same]
      exact next

/-- The data of a record goes at or after the block `b` and ends by the block `last`;
the blocks are used in order. -/
theorem data_ascends (b : Nat) (rs : List (Node × Nat)) :
    Ascending (b * block) (dataWrites (placeData b rs).1) ((placeData b rs).2 * block) := by
  induction rs generalizing b with
  | nil => simp [placeData, dataWrites, Ascending]
  | cons r rs ih =>
    obtain ⟨x, at_⟩ := r
    have next := ih (b + x.blocks)
    simp only [placeData, dataWrites, List.map_cons, Ascending, Placed.blockData, Node.blocks]
    simp only [dataWrites, Node.blocks] at next
    refine ⟨Nat.le_refl _, ?_⟩
    refine next.widen ?_ (Nat.le_refl _)
    unfold block at *
    omega

/-- The data of a layer starts at or after where the records end. -/
theorem data_after_records (cursor : Nat) : cursor ≤ (cursor + block - 1) / block * block := by
  unfold block; omega

/-- A record that fits in a block is not cut, in every record laid out. -/
theorem placeRecords_not_cut (cursor : Nat) (xs : List Node) :
    ∀ r ∈ (placeRecords cursor xs).1, r.1.record ≤ block → r.2 % block + r.1.record ≤ block := by
  induction xs generalizing cursor with
  | nil => intro r h; simp [placeRecords] at h
  | cons x xs ih =>
    intro r h
    simp only [placeRecords, List.mem_cons] at h
    rcases h with rfl | h
    · exact recordOffset_not_cut cursor x
    · exact ih _ r h

/-- The placed nodes are the nodes given, in their order. -/
theorem placed_nodes (nodes : List Node) : (layoutOf nodes).placed.map (·.node) = nodes := by
  have records := placeData_records
    (((placeRecords firstFree nodes).2 + block - 1) / block) (placeRecords firstFree nodes).1
  have step : ∀ ps : List Placed,
      ps.map (·.node) = (ps.map fun p => (p.node, p.offset)).map Prod.fst := by
    intro ps; simp [List.map_map]
  unfold layoutOf
  simp only
  rw [step, records]
  exact placeRecords_nodes _ _

/-- A record that fits in a block is not cut, in a layout. -/
theorem placed_not_cut (nodes : List Node) :
    ∀ p ∈ (layoutOf nodes).placed, p.node.record ≤ block →
      p.offset % block + p.node.record ≤ block := by
  intro p mem
  have records := placeData_records
    (((placeRecords firstFree nodes).2 + block - 1) / block) (placeRecords firstFree nodes).1
  have := placeRecords_not_cut firstFree nodes (p.node, p.offset)
    (records ▸ List.mem_map_of_mem (f := fun p => (p.node, p.offset)) mem)
  exact this

/-- The writer streams, in two parts: the writes of the inode area go up from the end of the
superblock to a point `middle`, and the writes of the blocks of data from there to the end
of the image. -/
theorem layoutOf_ascends (nodes : List Node) :
    ∃ middle, Ascending firstFree (recordWrites (layoutOf nodes).placed) middle ∧
      Ascending middle (dataWrites (layoutOf nodes).placed) ((layoutOf nodes).blocks * block) := by
  refine ⟨((placeRecords firstFree nodes).2 + block - 1) / block * block, ?_, ?_⟩
  · exact (records_ascend firstFree nodes _ (placeData_records _ _)).widen (Nat.le_refl _)
      (data_after_records _)
  · exact (data_ascends _ _).widen (Nat.le_refl _) (Nat.mul_le_mul_right _ (Nat.le_max_left _ _))

/-- The writer streams: all the writes of a layer, headers and inline data of the inodes,
then the blocks of data, go up the image from the end of the superblock to the end of the
image. -/
theorem emission_ascends (nodes : List Node) :
    Ascending firstFree (emission (layoutOf nodes)) ((layoutOf nodes).blocks * block) := by
  obtain ⟨_, records, data⟩ := layoutOf_ascends nodes
  exact records.append data

end InlineModel
