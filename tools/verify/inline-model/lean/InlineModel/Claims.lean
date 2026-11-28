-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean, one theorem for each, named
-- as the claim in snake case.  Theorems.lean lists them.
--
-- Why it is needed: Spec.lean has the statements only.  Here each is read off the facts
-- of Ascending.lean (the writer streams), Layout.lean (how the records and the blocks are
-- placed), Extents.lean (where the extent of a held file is), Rows.lean (the table) and
-- Lookup.lean (the stores).
--
-- Read before this file: Spec.lean, then the comments of Extents.lean.
-- Notation: `intro x` takes the "for every x" of the goal as a given; `obtain ⟨a, b⟩ := h`
-- takes apart "a and b" or "there is an a such that b"; `omega` proves a statement about
-- whole numbers with +, <, ≤, / and % by literals; `unfold f` replaces `f` by its definition.
import InlineModel.Extents
import InlineModel.Rows
import InlineModel.Lookup

namespace InlineModel

/-! ## The rule -/

/-- HoldsInline 0 contradicts itself: at 0 no file is held. -/
theorem nothing_at_zero : NothingAtZero := by
  intro size holds
  unfold HoldsInline at holds
  omega

/-- At -1 the rule is `0 < size` and nothing else. -/
theorem every_file_at_minus_one : EveryFileAtMinusOne := by
  intro size content
  unfold HoldsInline
  omega

/-- For `n > 0` the rule unfolds to `0 < size ≤ n`. -/
theorem up_to_and_including_n : UpToAndIncludingN := by
  intro n positive size
  unfold HoldsInline
  omega

/-! ## The files that get an extent -/

/-- What a node says it holds: its file and its size. -/
def Node.heldFile (x : Node) : Option (Digest × Nat) :=
  x.held.map fun d => (d, x.tail + x.dataLen)

/-- The node of an entry holds the file the rule says: the file of the entry, with its
whole size, when `HoldsInline`. -/
theorem heldFile_of_shape (content : Content) (n : Int) (e : Entry) :
    (shape content n e).heldFile = match e.kind with
      | .file d size => if HoldsInline n size then some (d, size) else none
      | .other .. => none := by
  obtain ⟨attrs, kind⟩ := e
  cases kind with
  | other tail dataLen => simp [shape, Node.heldFile]
  | file d size =>
    by_cases holds : HoldsInline n size
    · by_cases fits : fitsInRecord attrs size <;> simp [shape, Node.heldFile, holds, fits]
    · simp [shape, Node.heldFile, holds]

/-- The extents of the layout are what the nodes hold, which is what the rule says of the entries, in order (the nodes of the layout are the shapes of the entries). -/
theorem extents_are_the_held_files : ExtentsAreTheHeldFiles := by
  intro content n es
  have nodes := placed_nodes (es.map (shape content n))
  unfold extents layout
  -- the pair (digest, size) of an extent is what its node says
  rw [List.map_filterMap]
  have same : ∀ p : Placed, (p.node.held.map p.extent).map (fun e => (e.digest, e.size))
      = p.node.heldFile := by
    intro p
    cases held : p.node.held <;> simp [Node.heldFile, Placed.extent, held]
  simp only [same]
  -- the nodes are those of the entries, in order
  have nodes_held := congrArg (List.filterMap Node.heldFile) nodes
  rw [List.filterMap_map, List.filterMap_map] at nodes_held
  have rule : (Node.heldFile ∘ shape content n) = fun e => match e.kind with
      | .file d size => if HoldsInline n size then some (d, size) else none
      | .other .. => none := funext (heldFile_of_shape content n)
  exact nodes_held.trans (by rw [rule]; rfl)

/-- At 0 every file is a hole, as when each is made a hole beforehand; so no node holds a file and there is no extent. -/
theorem zero_is_the_image_of_today : ZeroIsTheImageOfToday := by
  intro content content' n es
  refine ⟨?_, ?_⟩
  · unfold layout
    congr 1
    rw [List.map_map]
    refine List.map_congr_left fun e _ => ?_
    obtain ⟨attrs, kind⟩ := e
    cases kind with
    | other tail dataLen => rfl
    | file d size =>
      have : ¬ HoldsInline 0 size := nothing_at_zero size
      simp [shape, Entry.asHole, this]
  · have := extents_are_the_held_files content 0 es
    have none : heldFiles 0 es = [] := by
      unfold heldFiles
      refine List.filterMap_eq_nil_iff.mpr fun e _ => ?_
      obtain ⟨attrs, kind⟩ := e
      cases kind with
      | other tail dataLen => rfl
      | file d size => simp [nothing_at_zero size]
    rw [none] at this
    exact List.map_eq_nil_iff.mp this

/-- One entry of `n` bytes is held and one of `n + 1` is not: the claim about the files, for a layer of one. -/
theorem the_threshold_is_inclusive : TheThresholdIsInclusive := by
  intro content n attrs d size positive exact
  have held : HoldsInline n size := by unfold HoldsInline; omega
  have beyond : ¬ HoldsInline n (size + 1) := by unfold HoldsInline; omega
  have lengths := fun es => congrArg List.length (extents_are_the_held_files content n es)
  refine ⟨?_, ?_⟩
  · simpa [heldFiles, held] using lengths [⟨attrs, .file d size⟩]
  · simpa [heldFiles, beyond] using lengths [⟨attrs, .file d (size + 1)⟩]

/-! ## Where the extents are -/

/-- Where the extent of a held node is, from the node: in its record (after the header, up
to the end of the record, which fits in a block), or at its first block, for all its
blocks.  Either way it is not empty. -/
theorem extent_place {content : Content} {d : Digest} {p : Placed} (held : HeldNode content d p.node) :
    ((p.extent d).offset = p.offset + inodeSize + p.node.attrs ∧
      (p.extent d).offset + (p.extent d).size = p.offset + p.node.record ∧
      0 < (p.extent d).size ∧ (p.extent d).size < block ∧ p.node.record ≤ block) ∨
    ((p.extent d).offset = p.firstBlock * block ∧
      (p.extent d).offset + (p.extent d).size = p.firstBlock * block + p.node.dataLen ∧
      0 < (p.extent d).size) := by
  obtain ⟨_, shape⟩ := held
  have size : (p.extent d).size = p.node.tail + p.node.dataLen := rfl
  have record : p.node.record = inodeSize + p.node.attrs + p.node.tail := rfl
  rcases shape with ⟨tail, data, fits, small⟩ | ⟨tail, data⟩
  · left
    have offset : (p.extent d).offset = p.offset + inodeSize + p.node.attrs := by
      simp [Placed.extent, Placed.inlineData, tail]
    omega
  · right
    have offset : (p.extent d).offset = p.firstBlock * block := by
      simp [Placed.extent, Placed.blockData, tail]
    omega

/-- The facts of the layout of the entries that the claims about extents are read off:
the inode area and the data area of the layout are ascending, and a record that fits is
not cut. -/
theorem layout_facts (content : Content) (n : Int) (es : List Entry) :
    ∃ middle,
      ((layout content n es).placed.Pairwise
          (fun p q => p.offset + p.node.record ≤ q.offset) ∧
        ∀ p ∈ (layout content n es).placed,
          firstFree ≤ p.offset ∧ p.offset + p.node.record ≤ middle) ∧
      ((layout content n es).placed.Pairwise
          (fun p q => p.firstBlock * block + p.node.dataLen ≤ q.firstBlock * block) ∧
        ∀ p ∈ (layout content n es).placed, middle ≤ p.firstBlock * block ∧
          p.firstBlock * block + p.node.dataLen ≤ (layout content n es).blocks * block) ∧
      middle ≤ (layout content n es).blocks * block ∧ firstFree ≤ middle := by
  obtain ⟨middle, records, data⟩ := layoutOf_ascends (es.map (shape content n))
  exact ⟨middle, records_apart records, data_apart data, data.floor_le, records.floor_le⟩

/-- The inode area ends where the data area starts and the data area at the end of the image; an extent is in one of the two. -/
theorem extents_are_in_the_image : ExtentsAreInTheImage := by
  intro content n es e mem
  obtain ⟨p, placed, d, held, rfl⟩ := (mem_extents _ e).mp mem
  obtain ⟨middle, ⟨_, records⟩, ⟨_, data⟩, end_, start⟩ := layout_facts content n es
  -- the extent is in the record of its node or in its blocks, which are in the image
  have place := extent_place (placed_held content n es p placed d held)
  have := records p placed
  have := data p placed
  unfold block at *
  omega

/-- Two held nodes are apart in the inode area and in the data area, and every record ends before every block of data; an extent is in the record or in the blocks of its node. -/
theorem extents_do_not_overlap : ExtentsDoNotOverlap := by
  intro content n es
  obtain ⟨middle, ⟨apart_records, records⟩, ⟨apart_data, data⟩, _⟩ := layout_facts content n es
  unfold extents
  rw [List.pairwise_filterMap]
  -- two nodes, one before the other in the layout: their records are apart and their
  -- blocks are apart
  refine (apart_records.and apart_data).imp_of_mem fun {p q} mp mq both => ?_
  -- each extent is in the record or in the blocks of its node
  intro a ha b hb
  obtain ⟨d, heldp, rfl⟩ := Option.map_eq_some_iff.mp (Option.mem_def.mp ha)
  obtain ⟨d', heldq, rfl⟩ := Option.map_eq_some_iff.mp (Option.mem_def.mp hb)
  have place_p := extent_place (placed_held content n es p mp d heldp)
  have place_q := extent_place (placed_held content n es q mq d' heldq)
  -- every record is before every block of data (`middle`)
  have := records p mp
  have := records q mq
  have := data p mp
  have := data q mq
  unfold block at *
  omega

/-- The extent is a write of the stream; the stream goes up, so no other write is over it, and what is read there is what was written. -/
theorem extents_keep_their_bytes : ExtentsKeepTheirBytes := by
  intro content n es e mem i small
  obtain ⟨p, placed, d, held, rfl⟩ := (mem_extents _ e).mp mem
  obtain ⟨w, wmem, start, len, bytes⟩ :=
    extent_is_a_write placed (placed_held content n es p placed d held)
  have reads : image (emission (layout content n es)) (w.start + i) = w.bytes i :=
    (emission_ascends (es.map (shape content n))).reads (fun _ => 0) w wmem i (by omega)
  rw [start, bytes] at reads
  exact reads

/-- A record that fits in a block is not cut (`placed_not_cut`), so a small file is in one block; a file in blocks starts at a block. -/
theorem the_block_rules : TheBlockRules := by
  intro content n es e mem
  obtain ⟨p, placed, d, held, rfl⟩ := (mem_extents _ e).mp mem
  have heldnode := placed_held content n es p placed d held
  have place := extent_place heldnode
  -- a small file is inside a record, which is not cut by the end of a block
  have cut := placed_not_cut (es.map (shape content n)) p placed
  unfold block at *
  omega

/-- The writes of the layout ascend (`emission_ascends`). -/
theorem the_writer_never_goes_back : TheWriterNeverGoesBack :=
  fun content n es => emission_ascends (es.map (shape content n))

/-! ## The table -/

/-- `addRow` never adds a digest that is there (`nodup_addRows`), and the first extent of a digest is found among the rows (`find_addRows`). -/
theorem the_table_has_each_digest_once : TheTableHasEachDigestOnce := by
  intro content n es
  refine ⟨nodup_addRows _ [] List.nodup_nil, fun e mem => ?_⟩
  have := find_addRows (extents (layout content n es)) [] e.digest
  have found : (extents (layout content n es)).find? (·.digest == e.digest) ≠ none := by
    intro none
    exact absurd (by simp) (List.find?_eq_none.mp none e mem)
  have same : (rows (layout content n es)).find? (·.digest == e.digest) =
      (extents (layout content n es)).find? (·.digest == e.digest) := by
    simpa [rows] using this
  cases row : (rows (layout content n es)).find? (·.digest == e.digest) with
  | none => exact absurd (same.symm.trans row) found
  | some r => exact ⟨r, List.mem_of_find?_eq_some row, by simpa using List.find?_some row⟩

/-- `find_addRows` with no row before; a row is an extent that was added (`mem_addRows`). -/
theorem the_row_is_the_first_extent : TheRowIsTheFirstExtent := by
  intro content n es d
  exact ⟨by simpa [rows] using find_addRows (extents (layout content n es)) [] d,
    fun r mem => (mem_addRows _ [] r mem).resolve_left (by simp)⟩

/-! ## The content of a digest in the stores -/

/-- `Store.find` looks at the objects before the rows. -/
theorem an_object_beats_an_extent : AnObjectBeatsAnExtent :=
  fun s d has => find_of_object s d has

/-- `lookup` is `Option.or` of the first store and the rest. -/
theorem first_store_wins : FirstStoreWins :=
  fun s ss d => lookup_first_store s ss d

/-- With no object, `Store.find` is the first row of the digest, which exists when a row has it. -/
theorem first_row_wins : FirstRowWins :=
  fun s d absent r mem digest => find_of_row s d absent r mem digest

/-- By induction on the stores: the answer is that of the first store that has one. -/
theorem an_answer_is_held : AnAnswerIsHeld :=
  fun stores d src answer => lookup_is_held stores d src answer

/-- By induction on the stores: no answer is no answer of each. -/
theorem no_answer_means_nothing_is_held : NoAnswerMeansNothingIsHeld :=
  fun stores d answer => lookup_none_is_nothing stores d answer

end InlineModel
