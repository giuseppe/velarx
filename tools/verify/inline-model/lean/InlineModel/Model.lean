-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the design of the inline threshold as a
-- small program in Lean: which files a layer holds in its EROFS image, where
-- the streaming writer of crates/fuse/src/layer_erofs.rs puts them, what is
-- recorded in the table `inlined_files`, and how the store answers "the
-- content of the file with digest d".  It is the model the code of the design
-- has to agree with; Spec.lean states what is proved of it.
--
-- Why it is needed: there is no code to translate yet (and the layout rules
-- are the ones of `layer_image`, which Charon cannot see through its
-- allocation of a whole image).  So the proofs are about this model, and the
-- model is kept small and close to the names of the design.
--
-- Read before this file: the design of the inline threshold and
-- `layer_image` in crates/fuse/src/layer_erofs.rs.
--
-- Notation: `def f (x : Nat) : Nat := ...` defines the function `f`; a
-- `structure` is a record; `x :: xs` is the list whose first element is `x`;
-- `xs ++ ys` joins two lists; `Int` is a number that may be negative.
namespace InlineModel

/-- The size of a block of the image (`BLOCK`): 4096 bytes. -/
def block : Nat := 4096

/-- The size of the inode header (`INODE_SIZE`): 64 bytes. -/
def inodeSize : Nat := 64

/-- Inodes start at a multiple of this (`SLOT`): 32 bytes. -/
def slot : Nat := 32

/-- Where the first inode may go: after the superblock (`SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE`). -/
def firstFree : Nat := 1024 + 128

/-- A digest of the content of a file, as an abstract name (the model never hashes). -/
abbrev Digest := Nat

/-- The smallest multiple of `m` that is at least `v` (`next_multiple_of`). -/
def roundUp (v m : Nat) : Nat := (v + m - 1) / m * m

/-! ## Which files a layer holds -/

/-- The threshold rule, in one place (`velarx_types::holds_inline`): a file of
`size` bytes is held by the layer image when it has content and, for a threshold
`n`, either `n = -1` (every file) or `size ≤ n` (`n = 0` holds nothing). -/
def HoldsInline (n : Int) (size : Nat) : Prop :=
  0 < size ∧ (n = -1 ∨ (0 < n ∧ (size : Int) ≤ n))

instance (n : Int) (size : Nat) : Decidable (HoldsInline n size) := by
  unfold HoldsInline; infer_instance

/-! ## What the writer lays out -/

/-- One thing of the layer, as `layer_image` sees it: a regular file with content
(its digest and size), or anything else (a directory, a symlink, an empty file...), for
which the code already knows what its record carries after the inode header (`tail`
bytes) and how many bytes it has in blocks of its own (`dataLen`). -/
inductive Kind where
  | file (digest : Digest) (size : Nat)
  | other (tail dataLen : Nat)

/-- An entry of the layer: what it is, and the bytes of its extended attributes
(`xattrs.len()`), which sit between its inode header and its inline data. -/
structure Entry where
  attrs : Nat
  kind : Kind

/-- The bytes a file has, by digest (the model of the data the layer carries). -/
abbrev Content := Digest → Nat → Nat

/-- A file of the entry that carries its content as a hole of today (what the layer is made
of when nothing is held). -/
def Entry.asHole (e : Entry) : Entry :=
  match e.kind with
  | .file _ _ => ⟨e.attrs, .other 4 0⟩
  | .other .. => e

/-- What the writer decides for an entry: bytes of its record after the header
(`tail`), bytes in blocks of its own (`dataLen`), which bytes they are, and the
file of the entry if the image holds its content (`held`). -/
structure Node where
  attrs : Nat
  tail : Nat
  dataLen : Nat
  bytes : Nat → Nat
  held : Option Digest

/-- A held file goes into its record (FLAT_INLINE, like a symlink) when it is less than
a block and fits in the block with its inode header and attributes; otherwise it takes
blocks of its own (FLAT_PLAIN). -/
def fitsInRecord (attrs size : Nat) : Prop :=
  inodeSize + attrs + size ≤ block ∧ size < block

instance (attrs size : Nat) : Decidable (fitsInRecord attrs size) := by
  unfold fitsInRecord; infer_instance

/-- What the writer makes of an entry for the threshold `n`.  A file that is not held is
what it is today: a hole with a 4 byte record tail (CHUNK_BASED). -/
def shape (content : Content) (n : Int) (e : Entry) : Node :=
  match e.kind with
  | .other tail dataLen => ⟨e.attrs, tail, dataLen, fun _ => 0, none⟩
  | .file d size =>
    if HoldsInline n size then
      if fitsInRecord e.attrs size then ⟨e.attrs, size, 0, content d, some d⟩
      else ⟨e.attrs, 0, size, content d, some d⟩
    else ⟨e.attrs, 4, 0, fun _ => 0, none⟩

/-- The bytes of the record of a node: header, attributes, inline data. -/
def Node.record (x : Node) : Nat := inodeSize + x.attrs + x.tail

/-- The blocks of its own a node takes. -/
def Node.blocks (x : Node) : Nat := (x.dataLen + block - 1) / block

/-- A node with the place the writer gave it. -/
structure Placed where
  node : Node
  offset : Nat
  firstBlock : Nat

/-- A record that fits in a block is not cut by the end of a block (`layer_image`): if it
would be, it starts at the next block.  `at_` is where it would start. -/
def avoidCut (at_ : Nat) (x : Node) : Nat :=
  if x.record ≤ block ∧ at_ % block + x.record > block then roundUp at_ block else at_

/-- Where the record of a node goes when the previous record ended at `cursor`: at the next
slot, not cut. -/
def recordOffset (cursor : Nat) (x : Node) : Nat :=
  avoidCut (roundUp cursor slot) x

/-- The records of the nodes, one after the other from `cursor`: each node with its
offset, and where the last record ends. -/
def placeRecords : Nat → List Node → List (Node × Nat) × Nat
  | cursor, [] => ([], cursor)
  | cursor, x :: xs =>
    let at_ := recordOffset cursor x
    let rest := placeRecords (at_ + x.record) xs
    ((x, at_) :: rest.1, rest.2)

/-- The blocks of data, one node after the other from block `b`: each node with its first
block, and the block after the last. -/
def placeData : Nat → List (Node × Nat) → List Placed × Nat
  | b, [] => ([], b)
  | b, (x, at_) :: xs =>
    let rest := placeData (b + x.blocks) xs
    (⟨x, at_, b⟩ :: rest.1, rest.2)

/-- The image of a layer: its nodes with their places, and its size in blocks
(`total`). -/
structure Layout where
  placed : List Placed
  blocks : Nat

/-- What `layer_image` lays out for the nodes of a layer: the records from the end of the
superblock, then the blocks of data after the last record, in the order of the nodes; at
least one block. -/
def layoutOf (nodes : List Node) : Layout :=
  let records := placeRecords firstFree nodes
  let data := placeData ((records.2 + block - 1) / block) records.1
  ⟨data.1, max data.2 1⟩

/-- The layout of the entries of a layer for the threshold `n`. -/
def layout (content : Content) (n : Int) (es : List Entry) : Layout :=
  layoutOf (es.map (shape content n))

/-! ## What the writer writes, in the order it writes it -/

/-- One write of the stream: `len` bytes from `start`, the byte `i` of which is `bytes i`
(what is between two writes is zero). -/
structure Write where
  start : Nat
  len : Nat
  bytes : Nat → Nat

/-- The header of the record of a node, with its attributes: no bytes of a file. -/
def Placed.header (p : Placed) : Write :=
  ⟨p.offset, inodeSize + p.node.attrs, fun _ => 0⟩

/-- The inline data of a node, right after its header and attributes. -/
def Placed.inlineData (p : Placed) : Write :=
  ⟨p.offset + inodeSize + p.node.attrs, p.node.tail, p.node.bytes⟩

/-- The data of a node in blocks of its own, from its first block. -/
def Placed.blockData (p : Placed) : Write :=
  ⟨p.firstBlock * block, p.node.dataLen, p.node.bytes⟩

/-- The writes of the inode area: each node's header, then its inline data. -/
def recordWrites : List Placed → List Write
  | [] => []
  | p :: ps => p.header :: p.inlineData :: recordWrites ps

/-- The writes of the blocks of data: each node's. -/
def dataWrites (ps : List Placed) : List Write :=
  ps.map Placed.blockData

/-- Everything the writer streams out: the inode area, then the blocks of data. -/
def emission (l : Layout) : List Write :=
  recordWrites l.placed ++ dataWrites l.placed

/-- The image after one more write: the bytes of `w` over what was below. -/
def write (below : Nat → Nat) (w : Write) : Nat → Nat :=
  fun p => if w.start ≤ p ∧ p < w.start + w.len then w.bytes (p - w.start) else below p

/-- The image (the byte at each position) after the writes `ws`, in this order, to an image
of zeros: a later write over an earlier one wins.  The real image is written once, so the
proofs show that no write is over another. -/
def image (ws : List Write) : Nat → Nat :=
  ws.foldl write (fun _ => 0)

/-- The writes `ws` go up the image from `floor`: each starts at or after the end of the
one before (the first at or after `floor`) and the last ends by `ceiling`.  So the
writer never goes back, and no write is over another. -/
def Ascending : Nat → List Write → Nat → Prop
  | floor, [], ceiling => floor ≤ ceiling
  | floor, w :: ws, ceiling => floor ≤ w.start ∧ Ascending (w.start + w.len) ws ceiling

/-! ## What is recorded: the extents -/

/-- A held file of a layer, as the table `inlined_files` has it: its digest, and where its
content is in the image of the layer (`offset`), for `size` bytes. -/
structure Extent where
  digest : Digest
  offset : Nat
  size : Nat

/-- The extent of a held file: in its record when it went there, in its blocks otherwise
(one of `tail` and `dataLen` is its size, the other is 0). -/
def Placed.extent (p : Placed) (d : Digest) : Extent :=
  ⟨d, if 0 < p.node.tail then p.inlineData.start else p.blockData.start,
    p.node.tail + p.node.dataLen⟩

/-- The extents of a layer, in the order of its entries: one for each held file. -/
def extents (l : Layout) : List Extent :=
  l.placed.filterMap fun p => p.node.held.map p.extent

/-- Adds a file to the table of a layer unless its digest is there (the key of the table
is the digest and the layer: the first extent of a digest wins). -/
def addRow (rows : List Extent) (e : Extent) : List Extent :=
  if rows.any (·.digest == e.digest) then rows else rows ++ [e]

/-- The rows of `inlined_files` of a layer. -/
def rows (l : Layout) : List Extent :=
  (extents l).foldl addRow []

/-! ## The content of a digest in a store -/

/-- What a store holds: the digests of its objects (`objects/`) and the rows of its table
`inlined_files`, each with the layer it belongs to, in the order the store reads them
(`ORDER BY layer_id` in `inlined_file_here`). -/
structure Store where
  objects : List Digest
  rows : List (Nat × Extent)

/-- Where the content of a file is: a whole object, or the extent of a layer image. -/
inductive Source where
  | object (d : Digest)
  | extent (layer : Nat) (e : Extent)

/-- The answer of one store: the object if it has it, otherwise the first row of its table
for the digest. -/
def Store.find (s : Store) (d : Digest) : Option Source :=
  if d ∈ s.objects then some (.object d)
  else (s.rows.find? (·.2.digest == d)).map fun r => .extent r.1 r.2

/-- The answer of the stores of a node, this store first, then the read-only ones in order:
the first store that has an answer. -/
def lookup : List Store → Digest → Option Source
  | [], _ => none
  | s :: ss, d => (s.find d).or (lookup ss d)

end InlineModel
