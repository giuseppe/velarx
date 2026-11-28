-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: where the extent of a held file is, by its node: in the record of
-- the inode (a small file that fits) or in blocks of its own, and how it sits among the
-- other records and blocks of the layout.
--
-- Why it is needed: Claims.lean proves the claims about extents (in the image, apart,
-- reading back, block rules) from these facts, with `omega`.
--
-- Read before this file: Model.lean, Ascending.lean, Layout.lean.
-- Notation: `∃ x, P` is "there is an x such that P"; `rcases h with a | b` splits "a or b"
-- into two cases; `obtain ⟨x, hx⟩ := h` takes apart "there is an x such that hx".
import InlineModel.Layout

namespace InlineModel

/-- What a node that holds a file of `d` looks like: its bytes are the content of `d`, and
either it is a small file inside its record (a record that fits in a block, and no blocks
of its own) or a file in blocks of its own (and no tail). -/
def HeldNode (content : Content) (d : Digest) (x : Node) : Prop :=
  x.bytes = content d ∧
    ((0 < x.tail ∧ x.dataLen = 0 ∧ x.record ≤ block ∧ x.tail < block) ∨
     (x.tail = 0 ∧ 0 < x.dataLen))

/-- The writer makes a held node of a file with content, the way the rule says. -/
theorem shape_held (content : Content) (n : Int) (e : Entry) (d : Digest)
    (held : (shape content n e).held = some d) :
    ∃ size, e.kind = .file d size ∧ HoldsInline n size ∧ HeldNode content d (shape content n e) := by
  obtain ⟨attrs, kind⟩ := e
  cases kind with
  | other tail dataLen => simp [shape] at held
  | file digest size =>
    by_cases holds : HoldsInline n size
    · by_cases fits : fitsInRecord attrs size
      · simp only [shape, holds, fits, ite_true, Option.some.injEq] at held ⊢
        subst held
        refine ⟨size, rfl, holds, rfl, Or.inl ⟨holds.1, rfl, ?_, ?_⟩⟩
        · obtain ⟨room, _⟩ := fits
          simp only [Node.record]
          omega
        · exact fits.2
      · simp only [shape, holds, fits, ite_true, ite_false, Option.some.injEq] at held ⊢
        subst held
        exact ⟨size, rfl, holds, rfl, Or.inr ⟨rfl, holds.1⟩⟩
    · simp [shape, holds] at held

/-- Every held node of a layout is a held node of the file it names. -/
theorem placed_held (content : Content) (n : Int) (es : List Entry)
    (p : Placed) (mem : p ∈ (layout content n es).placed) (d : Digest)
    (held : p.node.held = some d) : HeldNode content d p.node := by
  have nodes := placed_nodes (es.map (shape content n))
  have : p.node ∈ es.map (shape content n) := nodes ▸ List.mem_map_of_mem (f := (·.node)) mem
  obtain ⟨e, _, node⟩ := List.mem_map.mp this
  rw [← node] at held ⊢
  exact (shape_held content n e d held).choose_spec.2.2

/-- The records of an ascending inode area: each record ends before the next starts, and
all are between the floor and the end of the area. -/
theorem records_apart {ps : List Placed} {floor middle : Nat}
    (up : Ascending floor (recordWrites ps) middle) :
    ps.Pairwise (fun p q => p.offset + p.node.record ≤ q.offset) ∧
      ∀ p ∈ ps, floor ≤ p.offset ∧ p.offset + p.node.record ≤ middle := by
  induction ps generalizing floor with
  | nil => exact ⟨.nil, by simp⟩
  | cons p ps ih =>
    simp only [recordWrites, Ascending, Placed.header, Placed.inlineData] at up
    obtain ⟨start, header, rest⟩ := up
    have same : p.offset + inodeSize + p.node.attrs + p.node.tail = p.offset + p.node.record := by
      unfold Node.record; omega
    rw [same] at rest
    obtain ⟨apart, bounds⟩ := ih rest
    have after := rest.floor_le
    refine ⟨.cons (fun q mem => (bounds q mem).1) apart, ?_⟩
    intro q mem
    rcases List.mem_cons.mp mem with rfl | mem
    · exact ⟨start, after⟩
    · have := bounds q mem
      omega

/-- The blocks of data of an ascending data area: each run ends before the next starts,
and all are between the start of the area and its end. -/
theorem data_apart {ps : List Placed} {middle ceiling : Nat}
    (up : Ascending middle (dataWrites ps) ceiling) :
    ps.Pairwise (fun p q => p.firstBlock * block + p.node.dataLen ≤ q.firstBlock * block) ∧
      ∀ p ∈ ps, middle ≤ p.firstBlock * block ∧
        p.firstBlock * block + p.node.dataLen ≤ ceiling := by
  refine ⟨?_, ?_⟩
  · have apart : (ps.map Placed.blockData).Pairwise _ := up.apart
    exact (List.pairwise_map.mp apart).imp fun h => by simpa [Placed.blockData] using h
  · intro p mem
    exact up.bounds p.blockData (List.mem_map_of_mem mem)

/-- The inline data of a node is among the writes of the inode area. -/
theorem inlineData_mem {ps : List Placed} {p : Placed} (mem : p ∈ ps) :
    p.inlineData ∈ recordWrites ps := by
  induction ps with
  | nil => cases mem
  | cons q ps ih =>
    rcases List.mem_cons.mp mem with rfl | mem
    · simp [recordWrites]
    · simp [recordWrites, ih mem]

/-- The extent of a held file of a layout is a write the writer makes, of the bytes of the
file: its inline data, or its blocks. -/
theorem extent_is_a_write {content : Content} {d : Digest} {ps : List Placed} {p : Placed}
    (mem : p ∈ ps) (held : HeldNode content d p.node) :
    ∃ w ∈ recordWrites ps ++ dataWrites ps, w.start = (p.extent d).offset ∧
      w.len = (p.extent d).size ∧ w.bytes = content d := by
  obtain ⟨bytes, shape⟩ := held
  rcases shape with ⟨tail, data, _, _⟩ | ⟨tail, data⟩
  · refine ⟨p.inlineData, List.mem_append.mpr (.inl (inlineData_mem mem)), ?_, ?_, bytes⟩ <;>
      simp [Placed.extent, Placed.inlineData, tail, data]
  · refine ⟨p.blockData, List.mem_append.mpr (.inr (List.mem_map_of_mem mem)), ?_, ?_, bytes⟩ <;>
      simp [Placed.extent, Placed.blockData, tail]

/-- The extents of a layout are those of its held nodes. -/
theorem mem_extents (l : Layout) (e : Extent) :
    e ∈ extents l ↔ ∃ p ∈ l.placed, ∃ d, p.node.held = some d ∧ p.extent d = e := by
  unfold extents
  simp [List.mem_filterMap]

end InlineModel
