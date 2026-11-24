-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `old_length`, `old`, `piece_length`, `new` (with its loop) and
-- `packets` (with its loop) answer: the pieces they read are laid out after the header, in order,
-- inside the data, and no more than the room allows.
-- Why it is needed: it is the framing of OpenPGP data (rules 2 to 5 of the header of src/lib.rs).
-- The loop of `new` keeps in `PacketRead` the pieces of one packet, and the loop of `packets` keeps
-- in `PacketsRead` those of all the packets read.
-- Read before this file: PiecesFrom.lean, BigEndian.lean and Spans.lean.
-- Notation: a refusal is held in the variable `fail1` of a loop, and the turn after it ends the
-- loop (the measure that goes down counts it).
import SigparseCore.PiecesFrom
import SigparseCore.BigEndian
import SigparseCore.Spans
import SigparseCore.Subpacket
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- `old_length` gives the offset where the body begins within the data. -/
theorem old_length_reads (data : Slice Std.U8) (at_ : Std.Usize) (first : Std.U8)
    (inside : at_.val ≤ data.val.length) :
    packet.old_length data at_ first ⦃ r =>
      ∀ len begin_, r = core.result.Result.Ok (len, begin_) →
        at_.val ≤ begin_.val ∧ begin_.val ≤ data.val.length ⦄ := by
  unfold packet.old_length
  step as ⟨ kind, hkind ⟩
  have := data.property
  split
  all_goals first
    | (step with be_reads as ⟨ r, ok_case, err_case ⟩
       cases r with
       | Ok val =>
         obtain ⟨fits, _⟩ := ok_case val rfl
         simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
         step as ⟨ begin_, hbegin ⟩
         simp only [Prod.mk.injEq, core.result.Result.Ok.injEq]
         rintro len b ⟨_, rfl⟩
         scalar_tac
       | Err e =>
         simp [core.result.Result.Insts.CoreOpsTry.branch,
           core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual])
    | (step as ⟨ room, hroom ⟩
       simp only [Prod.mk.injEq, core.result.Result.Ok.injEq]
       rintro len b ⟨_, rfl⟩
       scalar_tac)

/-- The packet of an old format header: a body of one piece that begins after the header byte, and
the offset after it, which is where the body ends, within the data. -/
theorem old_reads (data : Slice Std.U8) (start : Std.Usize) (first : Std.U8)
    (inside : start.val < data.val.length) :
    packet.old data start first ⦃ r =>
      ∀ packet next, r = core.result.Result.Ok (packet, next) →
        PiecesFrom start.val (packet.body :: packet.more.val) next.val ∧
        packet.more.val = [] ∧ next.val ≤ data.val.length ⦄ := by
  unfold packet.old
  have := data.property
  step as ⟨ at_, hat ⟩
  step with old_length_reads as ⟨ r, lengths ⟩
  cases r with
  | Ok found =>
    obtain ⟨len, begin_⟩ := found
    obtain ⟨after_start, within⟩ := lengths len begin_ rfl
    simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
    step with take_gives_the_span as ⟨ r, taken, refused ⟩
    cases r with
    | Ok piece =>
      obtain ⟨off_is, len_is, fits⟩ := taken piece rfl
      have off_val := congrArg UScalar.val off_is
      have len_val := congrArg UScalar.val len_is
      simp only [Std.bind_ok]
      step as ⟨ shifted, hshifted ⟩
      step as ⟨ tag, htag ⟩
      step with span_end_is_the_sum as ⟨ stop, hstop ⟩
      simp only [Prod.mk.injEq, core.result.Result.Ok.injEq]
      rintro packet next ⟨rfl, rfl⟩
      have empty : (alloc.vec.Vec.new Span).val = [] := rfl
      simp only [empty, PiecesFrom]
      exact ⟨⟨by omega, by omega⟩, trivial, by omega⟩
    | Err e =>
      simp [
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]

/-- A power of two, `1 << k` for a `k` of at most 31, is computed. -/
theorem one_shifted_by_a_few (k : Std.U8) (few : k.val < 32) :
    1#usize <<< k ⦃ _ => True ⦄ := by
  step as ⟨ r, hr ⟩
  cases System.Platform.numBits_eq <;> simp [*]
  scalar_tac

/-- `piece_length` gives the offset where the piece begins: after the byte `at_` that begins the
length, and within the data. -/
theorem piece_length_reads (data : Slice Std.U8) (at_ : Std.Usize) (tag : Std.U8)
    (inside : at_.val < data.val.length) :
    packet.piece_length data at_ tag ⦃ r =>
      ∀ len begin_ is_partial, r = core.result.Result.Ok (len, begin_, is_partial) →
        at_.val < begin_.val ∧ begin_.val ≤ data.val.length ⦄ := by
  unfold packet.piece_length
  have := data.property
  step as ⟨ o1, ho1 ⟩
  split
  · -- a length of one byte
    step with widen_a_byte as ⟨ len, hlen ⟩
    step as ⟨ begin_, hbegin ⟩
    simp only [Prod.mk.injEq, core.result.Result.Ok.injEq]
    rintro len' begin' is_partial ⟨_, rfl, _⟩
    scalar_tac
  split
  · -- a length of two bytes
    step as ⟨ next, hnext ⟩
    step with be_reads as ⟨ r, ok_case, err_case ⟩
    cases r with
    | Ok val =>
      obtain ⟨fits, value⟩ := ok_case val rfl
      have small : val.val < 256 := by
        rw [value]
        simpa using big_endian_below data.val next.val 1 fits
      simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
      step with widen_a_byte as ⟨ wide, hwide ⟩
      step as ⟨ above, habove ⟩
      step with shift_left_a_byte as ⟨ shifted, hshifted ⟩
      step as ⟨ sum, hsum ⟩
      step as ⟨ len, hlen ⟩
      step as ⟨ begin_, hbegin ⟩
      simp only [Prod.mk.injEq, core.result.Result.Ok.injEq]
      rintro len' begin' is_partial ⟨_, rfl, _⟩
      scalar_tac
    | Err e =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  split
  · -- a length of five bytes
    step as ⟨ next, hnext ⟩
    step with be_reads as ⟨ r, ok_case, err_case ⟩
    cases r with
    | Ok val =>
      obtain ⟨fits, value⟩ := ok_case val rfl
      simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
      step as ⟨ begin_, hbegin ⟩
      simp only [Prod.mk.injEq, core.result.Result.Ok.injEq]
      rintro len' begin' is_partial ⟨_, rfl, _⟩
      scalar_tac
    | Err e =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  · -- a partial length, which a compressed packet and a literal packet may have
    split
    · step as ⟨ k, hk ⟩
      step with one_shifted_by_a_few as ⟨ len ⟩
      step as ⟨ begin_, hbegin ⟩
      simp only [Prod.mk.injEq, core.result.Result.Ok.injEq]
      rintro len' begin' is_partial ⟨_, rfl, _⟩
      scalar_tac
    · split
      · step as ⟨ k, hk ⟩
        step with one_shifted_by_a_few as ⟨ len ⟩
        step as ⟨ begin_, hbegin ⟩
        simp only [Prod.mk.injEq, core.result.Result.Ok.injEq]
        rintro len' begin' is_partial ⟨_, rfl, _⟩
        scalar_tac
      · simp [WP.spec_ok]

/-- `piece_length` reads a length of one octet, below 192: the piece is that long, begins just after
the octet, and is not partial. -/
theorem piece_length_one_octet (data : Slice Std.U8) (at_ : Std.Usize) (tag : Std.U8)
    (inside : at_.val < data.val.length) (octet : Std.U8)
    (is_octet : data.val[at_.val]? = some octet) (short : octet.val < 192) :
    packet.piece_length data at_ tag ⦃ r => ∃ len begin_,
      r = core.result.Result.Ok (len, begin_, false) ∧ len.val = octet.val ∧
        begin_.val = at_.val + 1 ⦄ := by
  unfold packet.piece_length
  have := data.property
  step as ⟨ o1, ho1 ⟩
  have same : o1 = octet := by
    have : data.val[at_.val]? = some o1 := by simp [ho1]
    rw [this] at is_octet
    exact Option.some.inj is_octet
  subst same
  split
  · step with widen_a_byte as ⟨ len, hlen ⟩
    step as ⟨ begin_, hbegin ⟩
    exact ⟨len, begin_, rfl, hlen, hbegin⟩
  · rename_i not_short
    scalar_tac

/-- The bits of the first byte of a new format header, from 192 up: the top two bits are set (a
packet, in the new format), and the low six are the tag. -/
theorem new_header_bits (x : Nat) (new_format : 192 ≤ x) (byte : x < 256) :
    x &&& 128 ≠ 0 ∧ x &&& 64 ≠ 0 ∧ x &&& 63 = x - 192 := by
  have all : ∀ y : Fin 256, 192 ≤ y.val → y.val &&& 128 ≠ 0 ∧ y.val &&& 64 ≠ 0 ∧
      y.val &&& 63 = y.val - 192 := by decide +kernel
  exact all ⟨x, byte⟩ new_format

/-- What the loop of `new` knows at each turn, the position `at_` being where the next length
begins: it is after the header byte at `start` and within the data; when a piece has been read, the
pieces (`body`, then `more`) are laid out from `start` to `at_`, and they are no more than `room`;
when none has, `at_` is just after the header and `more` is empty; and the loop is only done when a
piece has been read. -/
def PacketRead (data : Slice Std.U8) (start room at_ : Std.Usize) (body : Span)
    (more : alloc.vec.Vec Span) (have_ done : Bool) : Prop :=
  start.val + 1 ≤ at_.val ∧ at_.val ≤ data.val.length ∧
  (have_ = true → PiecesFrom start.val (body :: more.val) at_.val
    ∧ 1 + more.val.length ≤ room.val) ∧
  (have_ = false → at_.val = start.val + 1 ∧ more.val = []) ∧
  (done = true → have_ = true)

/-- The loop of `new` returns, and when it ends with no refusal, the pieces it holds are laid out
from the header at `start` to the offset it returns, which is within the data, and they are no more
than `room`.  One turn reads one length and one piece, or holds a refusal (the data ends, the length
is wrong, there are too many pieces, the piece is cut) and the next turn ends the loop. -/
theorem new_loop_reads (data : Slice Std.U8) (start room : Std.Usize) (tag : Std.U8)
    (at_ : Std.Usize) (body : Span) (more : alloc.vec.Vec Span) (have_ : Bool)
    (fail1 : Option velarx_sigparse_core.Error) (done1 : Bool) (some_room : 1 ≤ room.val)
    (read : PacketRead data start room at_ body more have_ done1) :
    packet.new_loop data room tag at_ body more have_ fail1 done1 ⦃ r =>
      r.2.2.2 = none →
        PiecesFrom start.val (r.2.1 :: r.2.2.1.val) r.1.val ∧ 1 + r.2.2.1.val.length ≤ room.val ∧
        r.1.val ≤ data.val.length ⦄ := by
  unfold packet.new_loop
  apply loop.spec_decr_nat
    (fun q => 2 * (data.val.length - q.1.val) + (if q.2.2.2.2.1.isNone then 1 else 0))
    (fun q => PacketRead data start room q.1 q.2.1 q.2.2.1 q.2.2.2.1 q.2.2.2.2.2)
  · rintro ⟨at_, body, more, have_, fail1, done1⟩ read
    simp only at read ⊢
    obtain ⟨from_start, in_data, taken, untaken, finished⟩ := read
    unfold packet.new_loop.body
    dsimp only
    have := data.property
    split
    · rename_i unrefused
      have unrefused : fail1 = none := by cases fail1 <;> simp_all [core.option.Option.is_none]
      subst unrefused
      split
      · -- the last piece has been read
        rename_i finished_now
        have : have_ = true := finished (by simpa using finished_now)
        subst this
        obtain ⟨laid, few⟩ := taken rfl
        simp only [WP.spec_ok]
        intro _
        exact ⟨laid, few, in_data⟩
      · rename_i not_finished
        dsimp only [Slice.len]
        split
        · -- the data ends where a length should be
          simp only [WP.spec_ok]
          exact ⟨⟨from_start, in_data, taken, untaken, finished⟩, by simp⟩
        · rename_i inside
          have inside : at_.val < data.val.length := by scalar_tac
          step with piece_length_reads as ⟨ r, lengths ⟩
          cases r with
          | Ok found =>
            obtain ⟨len, begin_, is_partial⟩ := found
            obtain ⟨after_at, within⟩ := lengths len begin_ is_partial rfl
            simp only
            -- the piece after the length is taken, if the room allows
            cases have_ with
            | false =>
              obtain ⟨at_is, more_empty⟩ := untaken rfl
              simp only [Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
              change Std.bind _ _ ⦃ _ ⦄
              step with take_gives_the_span as ⟨ r, taken_piece, refused ⟩
              cases r with
              | Ok piece =>
                obtain ⟨off_is, len_is, fits⟩ := taken_piece piece rfl
                have off_val := congrArg UScalar.val off_is
                have len_val := congrArg UScalar.val len_is
                step with span_end_is_the_sum as ⟨ at1, hat1 ⟩
                refine ⟨⟨by omega, by omega, fun _ => ⟨?_, ?_⟩, by simp, by simp⟩, by omega⟩
                · rw [more_empty]
                  simp only [PiecesFrom]
                  omega
                · rw [more_empty]
                  simpa using some_room
              | Err e =>
                simp only [WP.spec_ok]
                exact ⟨⟨from_start, in_data, taken, untaken, finished⟩, by simp⟩
            | true =>
              obtain ⟨laid, few⟩ := taken rfl
              have count := pieces_from_count _ _ _ laid
              simp only [List.length_cons] at count
              simp only [↓reduceIte]
              change Std.bind _ _ ⦃ _ ⦄
              step as ⟨ more_plus_two, hmore_plus_two ⟩
              split
              · -- too many pieces for the room
                simp only [WP.spec_ok]
                exact ⟨⟨from_start, in_data, taken, untaken, finished⟩, by simp⟩
              · rename_i room_left
                have room_left : more.val.length + 2 ≤ room.val := by scalar_tac
                step with take_gives_the_span as ⟨ r, taken_piece, refused ⟩
                cases r with
                | Ok piece =>
                  obtain ⟨off_is, len_is, fits⟩ := taken_piece piece rfl
                  have off_val := congrArg UScalar.val off_is
                  have len_val := congrArg UScalar.val len_is
                  step as ⟨ more1, hmore1 ⟩
                  step with span_end_is_the_sum as ⟨ at1, hat1 ⟩
                  have next_piece : PiecesFrom start.val (body :: (more1.val)) at1.val := by
                    rw [hmore1]
                    refine pieces_from_append (body :: more.val) [piece] _ _ _ laid ?_
                    simp only [PiecesFrom]
                    omega
                  refine ⟨⟨by omega, by omega, fun _ => ⟨next_piece, ?_⟩, by simp, by simp⟩,
                    by omega⟩
                  rw [hmore1]
                  simp only [List.length_append, List.length_singleton]
                  omega
                | Err e =>
                  simp only [WP.spec_ok]
                  exact ⟨⟨from_start, in_data, taken, untaken, finished⟩, by simp⟩
          | Err e =>
            simp only [WP.spec_ok]
            exact ⟨⟨from_start, in_data, taken, untaken, finished⟩, by simp⟩
    · rename_i refused
      simp only [WP.spec_ok]
      intro none_refused
      simp_all [core.option.Option.is_none]
  · exact read

/-- The loop of `new` reads a packet of one piece, with a length of one octet below 192: it ends
with no refusal, the piece is the octet's length of bytes after the octet, and there is no other
piece.  (The first turn reads the piece, which is not partial, so the second turn ends the loop.) -/
theorem new_loop_one_piece (data : Slice Std.U8) (room : Std.Usize) (tag : Std.U8)
    (at_ : Std.Usize) (inside : at_.val < data.val.length) (octet : Std.U8)
    (is_octet : data.val[at_.val]? = some octet) (short : octet.val < 192)
    (fits : at_.val + 1 + octet.val ≤ data.val.length) :
    packet.new_loop data room tag at_ ⟨0#usize, 0#usize⟩ (alloc.vec.Vec.new Span) false none false
      ⦃ r => r.2.2.2 = none ∧ r.1.val = at_.val + 1 + octet.val ∧ r.2.1.off.val = at_.val + 1 ∧
        r.2.1.len.val = octet.val ∧ r.2.2.1.val = [] ⦄ := by
  unfold packet.new_loop
  have := data.property
  apply loop.spec_decr_nat (fun q => if q.2.2.2.2.2 then 0 else 1)
    (fun q => q = (at_, ⟨0#usize, 0#usize⟩, alloc.vec.Vec.new Span, false, none, false) ∨
      (q.2.2.2.2.1 = none ∧ q.1.val = at_.val + 1 + octet.val ∧ q.2.1.off.val = at_.val + 1 ∧
        q.2.1.len.val = octet.val ∧ q.2.2.1.val = [] ∧ q.2.2.2.2.2 = true))
  · rintro ⟨at1, body, more, have1, fail1, done1⟩ state
    simp only at state ⊢
    unfold packet.new_loop.body
    dsimp only
    rcases state with first | last
    · simp only [Prod.mk.injEq] at first
      obtain ⟨start_at, rfl, rfl, rfl, rfl, rfl⟩ := first
      rw [start_at]
      simp only [core.option.Option.is_none, Option.isNone_none, ↓reduceIte]
      dsimp only [Slice.len]
      have not_past : ¬ (at_ ≥ Usize.ofNatCore data.val.length (by scalar_tac)) := by
        scalar_tac
      simp only [not_past, Bool.false_eq_true, ↓reduceIte]
      · step with piece_length_one_octet data at_ tag inside octet is_octet short as
          ⟨ r, len, begin_, is_ok, len_is, begin_is ⟩
        subst is_ok
        simp only [Bool.false_eq_true, ↓reduceIte]
        step with take_gives_the_span as ⟨ r1, taken, refused ⟩
        cases r1 with
        | Ok piece =>
          obtain ⟨off_is, len_is', fits_piece⟩ := taken piece rfl
          simp only [Bool.false_eq_true]
          step with span_end_is_the_sum as ⟨ at2, hat2 ⟩
          have off_val := congrArg UScalar.val off_is
          have len_val := congrArg UScalar.val len_is'
          refine ⟨Or.inr ⟨by omega, by omega, by omega, rfl, by simp⟩, by simp⟩
        | Err e =>
          have := refused e rfl
          omega
    · obtain ⟨_, _, _, _, _, finished⟩ := last
      simp only [finished, core.option.Option.is_none, ↓reduceIte]
      simp_all
  · exact Or.inl rfl

/-- The packet of a new format header: its pieces are laid out from the header byte at `start` to
the offset it returns, which is within the data, and they are no more than `room`. -/
theorem new_reads (data : Slice Std.U8) (start : Std.Usize) (first : Std.U8) (room : Std.Usize)
    (inside : start.val < data.val.length) (some_room : 1 ≤ room.val) :
    packet.new data start first room ⦃ r =>
      ∀ packet next, r = core.result.Result.Ok (packet, next) →
        PiecesFrom start.val (packet.body :: packet.more.val) next.val ∧
        1 + packet.more.val.length ≤ room.val ∧ next.val ≤ data.val.length ⦄ := by
  unfold packet.new
  have := data.property
  step as ⟨ tag, htag ⟩
  step as ⟨ at_, hat ⟩
  have loop_reads := new_loop_reads data start room tag at_ ⟨0#usize, 0#usize⟩
    (alloc.vec.Vec.new Span) false none false some_room
    ⟨by omega, by omega, by simp, fun _ => ⟨by omega, by simp [alloc.vec.Vec.new]⟩, by simp⟩
  step with loop_reads as ⟨ at1, body, more, fail1, finished ⟩
  cases fail1 with
  | none =>
    simp only [WP.spec_ok, Prod.mk.injEq, core.result.Result.Ok.injEq]
    rintro packet next ⟨rfl, rfl⟩
    exact finished rfl
  | some e =>
    simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true]

/-- `new` reads a packet of a new format header with a length of one octet below 192: the tag is the
low six bits of the header byte, the body is the octet's length of bytes after the octet, there is
no other piece, and the offset after it is the end of the body. -/
theorem new_reads_one_octet (data : Slice Std.U8) (start : Std.Usize) (first : Std.U8)
    (room : Std.Usize) (octet : Std.U8) (is_octet : data.val[start.val + 1]? = some octet)
    (short : octet.val < 192) (fits : start.val + 2 + octet.val ≤ data.val.length) :
    packet.new data start first room ⦃ r => ∃ packet next,
      r = core.result.Result.Ok (packet, next) ∧ packet.tag.val = first.val &&& 63 ∧
        packet.body.off.val = start.val + 2 ∧ packet.body.len.val = octet.val ∧
        packet.more.val = [] ∧ next.val = start.val + 2 + octet.val ⦄ := by
  unfold packet.new
  have := data.property
  step as ⟨ tag, htag ⟩
  step as ⟨ at_, hat ⟩
  step with new_loop_one_piece data room tag at_ (by omega) octet (by rw [hat]; exact is_octet)
    short (by omega) as ⟨ at1, body, more, fail1, no_fail, at1_is, off_is, len_is, more_is ⟩
  subst no_fail
  simp only [WP.spec_ok]
  refine ⟨_, _, rfl, ?_, by show body.off.val = _; omega, len_is, more_is, by omega⟩
  rw [htag, UScalar.val_and]
  rfl

/-- The most pieces `packets` reads is the number written in the code. -/
theorem max_packets_is : packet.MAX_PACKETS.val = 100000 := by
  unfold packet.MAX_PACKETS
  rfl

/-- What the loop of `packets` knows at each turn: the pieces of the packets it holds are laid out
from the start of the data to `at_`, which is within the data, and `pieces` counts them, no more
than the most it reads. -/
def PacketsRead (data : Slice Std.U8) (out : alloc.vec.Vec packet.Packet) (at_ pieces : Std.Usize) :
    Prop :=
  at_.val ≤ data.val.length ∧ PiecesFrom 0 (Pieces out.val) at_.val ∧
  pieces.val = (Pieces out.val).length ∧ pieces.val ≤ 100000

/-- The loop of `packets` returns, and when it ends with no refusal, the pieces of the packets it
holds are laid out over all the data, and they are no more than the most it reads.  One turn reads
one packet at `at_`, or holds a refusal (too many pieces, a byte that does not begin a packet, a cut
packet) and the next turn ends the loop. -/
theorem packets_loop_reads (data : Slice Std.U8) (out : alloc.vec.Vec packet.Packet)
    (at_ pieces : Std.Usize) (fail1 : Option velarx_sigparse_core.Error)
    (read : PacketsRead data out at_ pieces) :
    packet.packets_loop data out at_ pieces fail1 ⦃ r =>
      r.2 = none → PiecesFrom 0 (Pieces r.1.val) data.val.length ∧
        (Pieces r.1.val).length ≤ 100000 ⦄ := by
  unfold packet.packets_loop
  apply loop.spec_decr_nat
    (fun q => 2 * (data.val.length - q.2.1.val) + (if q.2.2.2.isNone then 1 else 0))
    (fun q => PacketsRead data q.1 q.2.1 q.2.2.1)
  · rintro ⟨out, at_, pieces, fail1⟩ read
    simp only at read ⊢
    obtain ⟨in_data, laid, counted, few⟩ := read
    unfold packet.packets_loop.body
    dsimp only
    have := data.property
    split
    · rename_i unrefused
      have unrefused : fail1 = none := by cases fail1 <;> simp_all [core.option.Option.is_none]
      subst unrefused
      dsimp only [Slice.len]
      split
      · rename_i below
        have below : at_.val < data.val.length := by scalar_tac
        split
        · rename_i full
          simp only [WP.spec_ok]
          exact ⟨⟨in_data, laid, counted, few⟩, by simp⟩
        · rename_i not_full
          have not_full : pieces.val < 100000 := by
            have : pieces.val < packet.MAX_PACKETS.val := by scalar_tac
            rwa [max_packets_is] at this
          step as ⟨ first, hfirst ⟩
          step as ⟨ top, htop ⟩
          split
          · simp only [WP.spec_ok]
            exact ⟨⟨in_data, laid, counted, few⟩, by simp⟩
          · rename_i top_bit
            step as ⟨ second, hsecond ⟩
            -- the packet is read by the old or the new format
            refine WP.spec_bind (Pₘ := fun r => ∀ packet next, r = core.result.Result.Ok (packet,
              next) →
                PiecesFrom at_.val (packet.body :: packet.more.val) next.val ∧
                1 + packet.more.val.length ≤ 100000 - pieces.val ∧ next.val ≤ data.val.length) ?_ ?_
            · split
              · step with old_reads as ⟨ r, read_old ⟩
                rename_i packet next found
                obtain ⟨laid_packet, more_empty, fits⟩ := read_old packet next found
                refine ⟨laid_packet, ?_, fits⟩
                rw [more_empty]
                simp only [List.length_nil]
                omega
              · step as ⟨ room, hroom ⟩
                rw [max_packets_is] at hroom
                step with new_reads as ⟨ r, read_new ⟩
                rename_i packet next found
                obtain ⟨laid_packet, few_pieces, fits⟩ := read_new packet next found
                exact ⟨laid_packet, by omega, fits⟩
            · intro read found
              cases read with
              | Ok taken_packet =>
                obtain ⟨packet, next⟩ := taken_packet
                obtain ⟨laid_packet, few_pieces, fits⟩ := found packet next rfl
                obtain ⟨_, inside_packet⟩ := pieces_from_inside _ _ _ laid_packet
                have after_at := (inside_packet packet.body List.mem_cons_self)
                simp only
                step as ⟨ more_pieces, hmore_pieces ⟩
                step as ⟨ pieces1, hpieces1 ⟩
                have count := packets_have_pieces out.val
                step as ⟨ out1, hout1 ⟩
                have all_pieces : Pieces out1.val = Pieces out.val ++
                  (packet.body :: packet.more.val) := by
                  rw [hout1]
                  exact pieces_of_one_more out.val packet
                have grown : (Pieces out1.val).length =
                    (Pieces out.val).length + (1 + packet.more.val.length) := by
                  rw [all_pieces]
                  simp only [List.length_append, List.length_cons]
                  omega
                have len_is : packet.more.len.val = packet.more.val.length := by
                  simp [alloc.vec.Vec.len]
                refine ⟨⟨fits, ?_, by omega, by omega⟩, by omega⟩
                rw [all_pieces]
                exact pieces_from_append _ _ _ _ _ laid laid_packet
              | Err e =>
                simp only [WP.spec_ok]
                exact ⟨⟨in_data, laid, counted, few⟩, by simp⟩
      · rename_i not_below
        have at_end : at_.val = data.val.length := by scalar_tac
        simp only [WP.spec_ok]
        intro _
        rw [at_end] at laid
        exact ⟨laid, by omega⟩
    · rename_i refused
      simp only [WP.spec_ok]
      intro none_refused
      simp_all [core.option.Option.is_none]
  · exact read

/-- What the loop of `packets` knows at each turn, when it reads packets in the new format with
one-byte lengths that the list `parts` says (`SimplePackets`): the data is what was read, then what
is left, which is the packets of the rest of the list; `at_` is where what is left begins, the
packets held are those of the part of the list that was read, and none has a second piece. -/
def SimplePacketsRead (data : Slice Std.U8) (parts : List (Nat × List Std.U8))
    (out : alloc.vec.Vec packet.Packet) (at_ pieces : Std.Usize) : Prop :=
  ∃ done rest before left, done ++ rest = parts ∧ data.val = before ++ left ∧
    at_.val = before.length ∧ SimplePackets left rest ∧
    out.val.map (fun packet => (packet.tag.val, SpanBytes data.val packet.body)) = done ∧
    (∀ packet ∈ out.val, packet.more.val = []) ∧ pieces.val = done.length

/-- The loop of `packets` does not refuse packets in the new format with one-byte lengths: given the
list `parts` that says them, and data that is what was read and then those, it ends with no refusal
and the packets it holds are those of the list. -/
theorem packets_loop_accepts (data : Slice Std.U8) (parts : List (Nat × List Std.U8))
    (few : parts.length ≤ 100000) (out : alloc.vec.Vec packet.Packet) (at_ pieces : Std.Usize)
    (read : SimplePacketsRead data parts out at_ pieces) :
    packet.packets_loop data out at_ pieces none ⦃ r => r.2 = none ∧
      (∀ packet ∈ r.1.val, packet.more.val = []) ∧
      r.1.val.map (fun packet => (packet.tag.val, SpanBytes data.val packet.body)) = parts ⦄ := by
  unfold packet.packets_loop
  apply loop.spec_decr_nat
    (fun q => 2 * (data.val.length - q.2.1.val) + (if q.2.2.2.isNone then 1 else 0))
    (fun q => q.2.2.2 = none ∧ SimplePacketsRead data parts q.1 q.2.1 q.2.2.1)
  · rintro ⟨out, at_, pieces, fail1⟩ ⟨unrefused, read⟩
    simp only at unrefused read ⊢
    subst unrefused
    obtain ⟨done, rest, before, left, parts_are, data_is, at_is, simple, mapped, one_piece,
      pieces_are⟩ := read
    unfold packet.packets_loop.body
    dsimp only
    have := data.property
    simp only [core.option.Option.is_none, Option.isNone_none, ↓reduceIte]
    dsimp only [Slice.len]
    by_cases below : at_.val < data.val.length
    · have below' : at_ < Usize.ofNatCore data.val.length (by scalar_tac) := by scalar_tac
      simp only [below', ↓reduceIte]
      cases rest with
      | nil =>
        have nothing_left : left = [] := simple
        subst nothing_left
        simp only [List.append_nil] at data_is
        have := congrArg List.length data_is
        omega
      | cons part rest' =>
        obtain ⟨tag, body⟩ := part
        obtain ⟨tag_small, body_small, header, length, after, left_is, header_is, length_is,
          simple_after⟩ := simple
        have pieces_small : pieces.val < 100000 := by
          have := congrArg List.length parts_are
          simp only [List.length_append, List.length_cons] at this
          omega
        have not_full : ¬ (pieces ≥ packet.MAX_PACKETS) := by
          have max_is := max_packets_is
          scalar_tac
        simp only [not_full, ↓reduceIte]
        have is_header : data.val[at_.val]? = some header := by
          rw [data_is, left_is, at_is]
          simp
        have is_length : data.val[at_.val + 1]? = some length := by
          rw [data_is, left_is, at_is, List.getElem?_append_right (by omega)]
          simp
        have header_bits := new_header_bits header.val (by omega) (by scalar_tac)
        have data_length := congrArg List.length data_is
        rw [left_is] at data_length
        simp only [List.length_append, List.length_cons] at data_length
        step as ⟨ first, hfirst ⟩
        have first_is : first = header := by
          have : data.val[at_.val]? = some first := by simp [hfirst]
          rw [is_header] at this
          exact (Option.some.inj this).symm
        subst first_is
        step as ⟨ top, htop ⟩
        have top_set : ¬ top = 0#u8 := by
          intro zero
          have := congrArg UScalar.val zero
          rw [htop, UScalar.val_and] at this
          exact header_bits.1 (by simpa using this)
        simp only [top_set, ↓reduceIte]
        step as ⟨ bit6, hbit6 ⟩
        have bit6_set : ¬ bit6 = 0#u8 := by
          intro zero
          have := congrArg UScalar.val zero
          rw [hbit6, UScalar.val_and] at this
          exact header_bits.2.1 (by simpa using this)
        simp only [bit6_set, ↓reduceIte]
        step as ⟨ room, hroom ⟩
        step with new_reads_one_octet data at_ first room length is_length (by scalar_tac)
          (by omega) as ⟨ r, packet, next, found, tag_is, off_is, len_is, more_is, next_is ⟩
        subst found
        simp only
        step as ⟨ more_pieces, hmore_pieces ⟩
        step as ⟨ pieces1, hpieces1 ⟩
        step as ⟨ out1, hout1 ⟩
        have more_empty : packet.more.len.val = 0 := by simp [alloc.vec.Vec.len, more_is]
        have tag_value : packet.tag.val = tag := by
          rw [tag_is]
          have := header_bits.2.2
          omega
        have body_bytes : SpanBytes data.val packet.body = body := by
          unfold SpanBytes
          rw [data_is, left_is, show packet.body.off.val = before.length + 2 by omega, len_is,
            show length.val = body.length from length_is]
          simp [List.drop_append]
        refine ⟨⟨done ++ [(tag, body)], rest', before ++ [first, length] ++ body, after,
          ?_, ?_, ?_, simple_after, ?_, ?_, ?_⟩, by simp; omega⟩
        · rw [← parts_are]
          simp
        · rw [data_is, left_is]
          simp
        · simp only [List.length_append, List.length_cons, List.length_nil]
          omega
        · rw [hout1, List.map_append, mapped]
          simp [tag_value, body_bytes]
        · intro packet' member
          rw [hout1] at member
          rcases List.mem_append.mp member with old | new
          · exact one_piece packet' old
          · rw [List.mem_singleton] at new
            subst new
            exact more_is
        · simp only [List.length_append, List.length_singleton]
          omega
    · have not_below : ¬ (at_ < Usize.ofNatCore data.val.length (by scalar_tac)) := by
        scalar_tac
      simp only [not_below, ↓reduceIte, WP.spec_ok]
      cases rest with
      | nil =>
        simp only [List.append_nil] at parts_are
        exact ⟨trivial, one_piece, by rw [mapped, parts_are]⟩
      | cons part rest' =>
        obtain ⟨tag, body⟩ := part
        obtain ⟨_, _, header, length, after, left_is, _⟩ := simple
        have := congrArg List.length data_is
        rw [left_is] at this
        simp at this
        omega
  · exact ⟨rfl, read⟩

/-- `packets` returns, and when it accepts, the pieces of the bodies of its packets are laid out
over all the data (`PiecesFrom`), and they are no more than the most it reads. -/
theorem packets_reads (data : Slice Std.U8) :
    packet.packets data ⦃ r =>
      ∀ packets, r = core.result.Result.Ok packets →
        PiecesFrom 0 (Pieces packets.val) data.val.length ∧
        (Pieces packets.val).length ≤ 100000 ⦄ := by
  unfold packet.packets
  have loop_reads := packets_loop_reads data (alloc.vec.Vec.new packet.Packet) 0#usize 0#usize none
    ⟨by simp, by simp [alloc.vec.Vec.new, Pieces, PiecesFrom], by simp [alloc.vec.Vec.new, Pieces],
      by simp⟩
  step with loop_reads as ⟨ out, fail1, finished ⟩
  cases fail1 with
  | none =>
    simp only [WP.spec_ok, core.result.Result.Ok.injEq]
    rintro packets rfl
    exact finished rfl
  | some e =>
    simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true]

end SigparseCore
