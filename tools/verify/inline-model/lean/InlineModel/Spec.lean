-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of the inline threshold, in words and in
-- statements, with no proof.  This is the file a reviewer reads; Lean checks the
-- rest (the model is in Model.lean, the proofs in Layout.lean, Rows.lean, Lookup.lean
-- and Claims.lean).
--
-- Why it is needed: with a threshold `N`, a layer image holds the files of at most `N`
-- bytes itself, and the store has to find them again by digest.  A wrong offset or a
-- clobbered byte reads a file wrong with no error; the claims below say that the layout
-- of the writer cannot do that, for EVERY layer (every list of entries, every sizes and
-- attribute lengths) and every `N`.  A proof is worth what its statement says, so each
-- claim has a comment of what it claims and of what it does NOT.
--
-- Read before this file: the design of the inline threshold, and Model.lean: the
-- writer as functions.  The model follows `layer_image` of
-- crates/fuse/src/layer_erofs.rs: the inode records from the end of the superblock, a
-- record that fits in a block is not cut by its end, the blocks of data after the last
-- record, in the order of the entries.
--
-- Index.  What each claim is about:
--   The rule      NothingAtZero, EveryFileAtMinusOne, UpToAndIncludingN
--   The files     ExtentsAreTheHeldFiles, ZeroIsTheImageOfToday, TheThresholdIsInclusive
--   The layout    ExtentsAreInTheImage, ExtentsDoNotOverlap, ExtentsKeepTheirBytes,
--                 TheBlockRules, TheWriterNeverGoesBack
--   The table     TheTableHasEachDigestOnce, TheRowIsTheFirstExtent
--   The lookup    AnObjectBeatsAnExtent, FirstStoreWins, FirstRowWins,
--                 AnAnswerIsHeld, NoAnswerMeansNothingIsHeld
--
-- Assumed (the model is not the code, and these are what the code must keep):
--   - the numbers are `Nat`: no overflow.  The code returns an error when the image
--     does not fit its 32 bit block numbers; the claims say nothing of an image that
--     does not.
--   - a `file` entry is a regular file WITH content (a non-empty file; one with no
--     content is `other 0 0`, it has no extent and is held by no `N`);
--   - the bytes of the extent are the content that the pull hashed against the digest:
--     the model carries them in `content d`, it does not hash;
--   - the order of the rows of the table in a store is fixed (`ORDER BY layer_id` in
--     `inlined_file_here`), as the first row wins; the claims hold for ANY order, but the
--     answer must be the same for the same store.
--
-- Not claimed: that the content of a digest is the file of that digest (that is the
-- check of the pull and of `velarx check`); the real EROFS headers (the inode fields, the
-- directory entries, the superblock); the kernel and FUSE reading the image; the
-- database (a table of a store is a list); gc; the p2p protocol.
--
-- Notation: `∀ x, P` is "for every x, P"; `∃` "there is"; `∧` "and"; `∨` "or"; `→` "if
-- ... then"; `↔` "exactly when"; `¬` "not"; `∈` "is an element of"; `xs.map f` applies `f`
-- to each element; `a ≤ b` is "at most"; `e.offset` is the field `offset` of `e`.
-- `layout content n es` is the layout of the entries `es` with the threshold `n`, and
-- `extents l` its list of extents.
import InlineModel.Model

namespace InlineModel

/-! ## The rule -/

/-- Threshold 0 holds no file: today's behaviour (the default). -/
def NothingAtZero : Prop :=
  ∀ size, ¬ HoldsInline 0 size

/-- Threshold -1 holds every file that has content, whatever its size.  It does NOT say
that an empty file is held: it has no content, and no extent. -/
def EveryFileAtMinusOne : Prop :=
  ∀ size, 0 < size → HoldsInline (-1) size

/-- A threshold above zero holds a file when it has content and its size is at most the
threshold: the size equal to the threshold is held, one byte more is not. -/
def UpToAndIncludingN : Prop :=
  ∀ n : Int, 0 < n → ∀ size, HoldsInline n size ↔ (0 < size ∧ (size : Int) ≤ n)

/-! ## The files that get an extent -/

/-- The files the rule says a layer holds, with their sizes, in the order of its
entries.  This is the rule written out, not the layout. -/
def heldFiles (n : Int) (es : List Entry) : List (Digest × Nat) :=
  es.filterMap fun e =>
    match e.kind with
    | .file d size => if HoldsInline n size then some (d, size) else none
    | .other .. => none

/-- The extents of a layer are the held files, each once, in the order of the entries,
with the size of the file and nothing else.  It does NOT say where they are. -/
def ExtentsAreTheHeldFiles : Prop :=
  ∀ content n es,
    (extents (layout content n es)).map (fun e => (e.digest, e.size)) = heldFiles n es

/-- With the threshold 0 the layout is the one of today: every file with content is a hole
with a four byte tail, whatever its size or its content, and there is no extent. -/
def ZeroIsTheImageOfToday : Prop :=
  ∀ content content' n es,
    layout content 0 es = layout content' n (es.map Entry.asHole) ∧
    extents (layout content 0 es) = []

/-- A file of exactly `n` bytes is held with the threshold `n` and a file of `n + 1` bytes
is not, whatever the attributes of its inode, so the rule is `size ≤ n` and no other
bound (the size of a block, say) plays a part in WHICH files are held. -/
def TheThresholdIsInclusive : Prop :=
  ∀ content (n : Int) (attrs : Nat) d (size : Nat), 0 < n → size = n.toNat →
    (extents (layout content n [⟨attrs, .file d size⟩])).length = 1 ∧
    (extents (layout content n [⟨attrs, .file d (size + 1)⟩])).length = 0

/-! ## Where the extents are -/

/-- Every extent is in the image: after the superblock and inside the blocks of the image
(whose size is a whole number of blocks). -/
def ExtentsAreInTheImage : Prop :=
  ∀ content n es, ∀ e ∈ extents (layout content n es),
    firstFree ≤ e.offset ∧ e.offset + e.size ≤ (layout content n es).blocks * block

/-- Two extents of a layer never share a byte. -/
def ExtentsDoNotOverlap : Prop :=
  ∀ content n es, (extents (layout content n es)).Pairwise fun a b =>
    a.offset + a.size ≤ b.offset ∨ b.offset + b.size ≤ a.offset

/-- Reading the image where an extent says gives the content of its file: after all the
writes of the writer, in its order, the byte `i` of the extent is the byte `i` of the
content of the digest.  So nothing else the writer streams (an inode header, a directory,
the data of another file) is over a held file.  It does NOT say that the content is the
one of the digest, only that the bytes the writer was given are the ones read back. -/
def ExtentsKeepTheirBytes : Prop :=
  ∀ content n es, ∀ e ∈ extents (layout content n es), ∀ i < e.size,
    image (emission (layout content n es)) (e.offset + i) = content e.digest i

/-- The EROFS rules of a block: an extent that starts at a block is a run of blocks, and a
file of a block or more always does; an extent that does not is inside one block (it is
a record's tail, which the kernel reads from one block). -/
def TheBlockRules : Prop :=
  ∀ content n es, ∀ e ∈ extents (layout content n es),
    (e.offset % block = 0 ∨
      (e.size < block ∧ e.offset / block = (e.offset + e.size - 1) / block)) ∧
    (block ≤ e.size → e.offset % block = 0)

/-- The writer streams: the writes go up the image, each at or after the end of the one
before, from the end of the superblock to the end of the image, so it never seeks back
and the image is never held whole in memory by the order of its writes.  It does NOT
say anything of the memory the real code uses. -/
def TheWriterNeverGoesBack : Prop :=
  ∀ content n es,
    Ascending firstFree (emission (layout content n es)) ((layout content n es).blocks * block)

/-! ## The table `inlined_files` of a layer -/

/-- A layer has one row for each digest it holds, even when two of its files are equal
(the key of the table is the digest and the layer). -/
def TheTableHasEachDigestOnce : Prop :=
  ∀ content n es,
    ((rows (layout content n es)).map (·.digest)).Nodup ∧
    ∀ e ∈ extents (layout content n es), ∃ r ∈ rows (layout content n es), r.digest = e.digest

/-- The row of a digest is the first extent of the layer with that digest, in the order
of the entries, and the rows are extents of the layer: a row is never made up. -/
def TheRowIsTheFirstExtent : Prop :=
  ∀ content n es, ∀ d,
    (rows (layout content n es)).find? (·.digest == d) =
      (extents (layout content n es)).find? (·.digest == d) ∧
    ∀ r ∈ rows (layout content n es), r ∈ extents (layout content n es)

/-! ## The content of a digest in the stores -/

/-- A store that has the object of a digest answers with the object, whatever its table
says: the whole file is the better source. -/
def AnObjectBeatsAnExtent : Prop :=
  ∀ (s : Store) d, d ∈ s.objects → s.find d = some (.object d)

/-- The stores are asked in order and the first that has an answer decides: a store that
has one is the answer; a store that has none leaves the answer to the next. -/
def FirstStoreWins : Prop :=
  ∀ (s : Store) ss d,
    (s.find d ≠ none → lookup (s :: ss) d = s.find d) ∧
    (s.find d = none → lookup (s :: ss) d = lookup ss d)

/-- With no object, the answer of a store is its first row for the digest, in the order it
reads its table (by layer id), and there is one when any row has the digest. -/
def FirstRowWins : Prop :=
  ∀ (s : Store) d, d ∉ s.objects →
    ∀ r ∈ s.rows, r.2.digest = d →
      ∃ r' ∈ s.rows, r'.2.digest = d ∧ s.find d = some (.extent r'.1 r'.2) ∧
        s.rows.find? (·.2.digest == d) = some r'

/-- An answer is something a store holds: an object of that digest, or a row of that digest
(with its layer).  The lookup never makes up a source. -/
def AnAnswerIsHeld : Prop :=
  ∀ (stores : List Store) d src, lookup stores d = some src →
    ∃ s ∈ stores,
      (src = .object d ∧ d ∈ s.objects) ∨
      (∃ r ∈ s.rows, src = .extent r.1 r.2 ∧ r.2.digest = d)

/-- No answer means no store has an object of that digest nor a row for it: a file that is
held somewhere is never reported missing. -/
def NoAnswerMeansNothingIsHeld : Prop :=
  ∀ (stores : List Store) d, lookup stores d = none →
    ∀ s ∈ stores, d ∉ s.objects ∧ ∀ r ∈ s.rows, r.2.digest ≠ d

end InlineModel
