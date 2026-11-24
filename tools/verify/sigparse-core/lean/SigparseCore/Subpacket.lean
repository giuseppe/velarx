-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `header`, `time` and `one` answer: the subpacket at a position is the
-- one `LengthAt` finds, and what it adds to the answer (`Applied`).
-- Why it is needed: a subpacket is where rules 7 to 10 of the header of src/lib.rs are applied: the
-- times and the flags are read in the hashed area only, an unknown critical subpacket of that area
-- refuses the signature, and the hints are read in both areas.
-- Read before this file: BigEndian.lean, Spans.lean and Spec.lean (`LengthAt`, `Sub`).
-- Notation: `Applied bytes hashed sub before after` is "reading the subpacket `sub` of an area (the
-- hashed one when `hashed` is true) turns the answer `before` into `after`".
import SigparseCore.BigEndian
import SigparseCore.Spans
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- A first octet below 192 is the whole length. -/
theorem length_at_one_octet (bytes : List Std.U8) (p stop : Nat) (first : Std.U8)
    (is_first : bytes[p]? = some first) (short : first.val < 192) :
    LengthAt bytes p stop = some (first.val, 1) := by
  simp [LengthAt, is_first, short]

/-- A first octet from 192 to 254 and the one after it make the length. -/
theorem length_at_two_octets (bytes : List Std.U8) (p stop : Nat) (first second : Std.U8)
    (is_first : bytes[p]? = some first) (is_second : bytes[p + 1]? = some second)
    (middle : 192 ≤ first.val ∧ first.val < 255) (room : p + 1 < stop) :
    LengthAt bytes p stop = some ((first.val - 192) * 256 + second.val + 192, 2) := by
  simp [LengthAt, is_first, is_second, room, show ¬ first.val < 192 by omega, middle.2]

/-- A first octet 255 and the 4 octets after it make the length. -/
theorem length_at_five_octets (bytes : List Std.U8) (p stop : Nat) (first : Std.U8)
    (is_first : bytes[p]? = some first) (long : first.val = 255) (room : p + 5 ≤ stop) :
    LengthAt bytes p stop = some (BigEndian bytes (p + 1) 4, 5) := by
  simp [LengthAt, is_first, room, long]

/-- The length written at `p` is not one the reader takes when there is room for none: no length
of `LengthAt` leaves the subpacket (its octets, then its `len` bytes) inside the area. -/
def NoSubpacketAt (bytes : List Std.U8) (p stop : Nat) : Prop :=
  ¬ ∃ len octets, LengthAt bytes p stop = some (len, octets) ∧ 1 ≤ len ∧ p + octets + len ≤ stop

/-- `header` reads the length of the subpacket at `at_` as `LengthAt` says: it returns, and when it
accepts, the length is at least one, it ends before `end_`, and the offset it gives is where the
kind byte is.  When it refuses, there is no such length (`NoSubpacketAt`): a length that `LengthAt`
finds, of at least one, that fits in the area, is accepted. -/
theorem header_reads (body : Slice Std.U8) (at_ end_ : Std.Usize) (below : at_.val < end_.val)
    (inside : end_.val ≤ body.val.length) :
    sig.header body at_ end_ ⦃ r =>
      (∀ len kind_at, r = core.result.Result.Ok (len, kind_at) →
        ∃ octets, LengthAt body.val at_.val end_.val = some (len.val, octets) ∧
          kind_at.val = at_.val + octets ∧ 1 ≤ len.val ∧ kind_at.val + len.val ≤ end_.val) ∧
      (∀ e, r = core.result.Result.Err e → NoSubpacketAt body.val at_.val end_.val) ⦄ := by
  unfold sig.header
  have := body.property
  step as ⟨ o1, ho1 ⟩
  have is_first : body.val[at_.val]? = some o1 := by simp [ho1]
  split
  · -- a length of one octet
    rename_i short
    have short : o1.val < 192 := by scalar_tac
    step with widen_a_byte as ⟨ len, hlen ⟩
    step as ⟨ at1, hat1 ⟩
    split
    · rename_i empty
      simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
      rintro e _ ⟨len', octets', found, nonempty, _⟩
      rw [length_at_one_octet _ _ _ o1 is_first short] at found
      simp only [Option.some.injEq, Prod.mk.injEq] at found
      have : len.val = 0 := by scalar_tac
      omega
    · rename_i not_empty
      step as ⟨ room, hroom ⟩
      split
      · rename_i too_long
        simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
        rintro e _ ⟨len', octets', found, _, fits⟩
        rw [length_at_one_octet _ _ _ o1 is_first short] at found
        simp only [Option.some.injEq, Prod.mk.injEq] at found
        scalar_tac
      · rename_i fits
        simp only [WP.spec_ok, Prod.mk.injEq, core.result.Result.Ok.injEq, reduceCtorEq,
          false_implies, implies_true, and_true]
        rintro len' kind_at ⟨rfl, rfl⟩
        refine ⟨1, ?_, by omega, by scalar_tac, by scalar_tac⟩
        rw [length_at_one_octet _ _ _ o1 is_first short, hlen]
  split
  · -- a length of two octets
    rename_i middle
    have middle : 192 ≤ o1.val ∧ o1.val < 255 := by scalar_tac
    step as ⟨ next, hnext ⟩
    split
    · rename_i no_second
      simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
      rintro e _ ⟨len', octets', found, _⟩
      unfold LengthAt at found
      simp only [is_first, show ¬ o1.val < 192 by omega, middle.2, ↓reduceIte] at found
      split at found
      · scalar_tac
      · simp at found
    · rename_i second_inside
      have second_inside : next.val < end_.val := by scalar_tac
      step with widen_a_byte as ⟨ wide, hwide ⟩
      step as ⟨ above, habove ⟩
      step with shift_left_a_byte as ⟨ shifted, hshifted ⟩
      step as ⟨ o2, ho2 ⟩
      step with widen_a_byte as ⟨ wide2, hwide2 ⟩
      step as ⟨ sum, hsum ⟩
      step as ⟨ len, hlen ⟩
      step as ⟨ at1, hat1 ⟩
      have is_second : body.val[at_.val + 1]? = some o2 := by simp [ho2, hnext]
      have found_len := length_at_two_octets body.val at_.val end_.val o1 o2 is_first is_second
        middle (by omega)
      split
      · rename_i empty
        simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
        rintro e _ ⟨len', octets', found, nonempty, _⟩
        rw [found_len] at found
        simp only [Option.some.injEq, Prod.mk.injEq] at found
        scalar_tac
      · rename_i not_empty
        step as ⟨ room, hroom ⟩
        split
        · rename_i too_long
          simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
          rintro e _ ⟨len', octets', found, _, fits⟩
          rw [found_len] at found
          simp only [Option.some.injEq, Prod.mk.injEq] at found
          scalar_tac
        · rename_i fits
          simp only [WP.spec_ok, Prod.mk.injEq, core.result.Result.Ok.injEq, reduceCtorEq,
            false_implies, implies_true, and_true]
          rintro len' kind_at ⟨rfl, rfl⟩
          refine ⟨2, ?_, by omega, by scalar_tac, by scalar_tac⟩
          rw [found_len]
          simp only [Option.some.injEq, Prod.mk.injEq]
          scalar_tac
  · -- a length of five octets
    rename_i long
    have long : o1.val = 255 := by scalar_tac
    step as ⟨ room, hroom ⟩
    split
    · rename_i short_room
      simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
      rintro e _ ⟨len', octets', found, _, fits⟩
      unfold LengthAt at found
      simp only [is_first, show ¬ o1.val < 192 by omega, show ¬ o1.val < 255 by omega,
        ↓reduceIte] at found
      split at found
      · simp at found
        scalar_tac
      · simp at found
    · rename_i five
      have five : 5 ≤ end_.val - at_.val := by scalar_tac
      step as ⟨ next, hnext ⟩
      step with be_reads as ⟨ r, ok_case, err_case ⟩
      cases r with
      | Ok val =>
        obtain ⟨fits, value⟩ := ok_case val rfl
        simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
        step as ⟨ at1, hat1 ⟩
        have found_len := length_at_five_octets body.val at_.val end_.val o1 is_first long
          (by omega)
        split
        · rename_i empty
          simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
          rintro e _ ⟨len', octets', found, nonempty, _⟩
          rw [found_len] at found
          simp only [Option.some.injEq, Prod.mk.injEq] at found
          scalar_tac
        · rename_i not_empty
          step as ⟨ room_left, hroom_left ⟩
          split
          · rename_i too_long
            simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
            rintro e _ ⟨len', octets', found, _, fits⟩
            rw [found_len] at found
            simp only [Option.some.injEq, Prod.mk.injEq] at found
            scalar_tac
          · rename_i fits_in_area
            simp only [WP.spec_ok, Prod.mk.injEq, core.result.Result.Ok.injEq, reduceCtorEq,
              false_implies, implies_true, and_true]
            rintro len' kind_at ⟨rfl, rfl⟩
            refine ⟨5, ?_, by omega, by scalar_tac, by scalar_tac⟩
            rw [found_len, ← hnext, ← value]
      | Err e =>
        simp only [core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
        have := err_case e rfl
        omega

/-- `time` reads the 4 bytes of the value of a time subpacket: it returns, and when it accepts, the
value is 4 bytes inside the data and the time is their number.  When it refuses, the value is not 4
bytes or does not lie inside the data. -/
theorem time_reads (body : Slice Std.U8) (value : Span) :
    sig.time body value ⦃ r =>
      (∀ time, r = core.result.Result.Ok time →
        value.len.val = 4 ∧ value.off.val + 4 ≤ body.val.length ∧
        time.val = BigEndian body.val value.off.val 4) ∧
      (∀ e, r = core.result.Result.Err e →
        value.len.val ≠ 4 ∨ body.val.length < value.off.val + 4) ⦄ := by
  unfold sig.time
  split
  · rename_i not_four
    simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
    intro e _
    left
    scalar_tac
  · rename_i four
    have four : value.len.val = 4 := by scalar_tac
    step with be_reads as ⟨ r, ok_case, err_case ⟩
    cases r with
    | Ok val =>
      obtain ⟨fits, number⟩ := ok_case val rfl
      simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
      have small : val.val < 2 ^ 32 := by
        rw [number]
        simpa using big_endian_below body.val value.off.val 4 fits
      step as ⟨ time, htime ⟩
      simp only [core.result.Result.Ok.injEq, reduceCtorEq, false_implies, implies_true, and_true]
      rintro _ rfl
      refine ⟨four, by omega, ?_⟩
      rw [htime, UScalar.cast_val_eq, ← number]
      simp [UScalarTy.numBits]
      omega
    | Err e =>
      have := err_case e rfl
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
      right
      exact this

/-- `known` says a kind is one of `IgnoredKinds` (the ones that may be critical although they are
not read). -/
theorem known_is_the_list (kind : Std.U8) :
    sig.known kind ⦃ b => b = true ↔ kind.val ∈ IgnoredKinds ⦄ := by
  unfold sig.known
  split
  all_goals first
    | (simp only [WP.spec_ok, IgnoredKinds, List.mem_cons, List.not_mem_nil, or_false]; decide)
    | (simp only [WP.spec_ok, Bool.false_eq_true, false_iff, IgnoredKinds, List.mem_cons,
      List.not_mem_nil,
        or_false, not_or, imp_false, UScalar.eq_equiv] at *
       simp only [UScalar.val, BitVec.reduceToNat] at *
       omega)

/-- The top bit of a byte is set exactly when the byte is at least 128. -/
theorem top_bit_of_a_byte (x : Nat) (byte : x < 256) : x &&& 128 ≠ 0 ↔ 128 ≤ x := by
  have all : ∀ y : Fin 256, y.val &&& 128 ≠ 0 ↔ 128 ≤ y.val := by decide +kernel
  exact all ⟨x, byte⟩

/-- The low seven bits of a byte are its remainder by 128. -/
theorem low_bits_of_any_byte (x : Nat) : x &&& 127 = x % 128 := by
  have := Nat.and_two_pow_sub_one_eq_mod x 7
  norm_num at this
  exact this

/-- What one subpacket `sub` does to a time field of the answer, of the kind `kind`: in the hashed
area a subpacket of that kind sets it to its time (and its value has 4 bytes: the length is the kind
byte and them); anything else leaves it as it was. -/
def TimeAfter (bytes : List Std.U8) (hashed : Bool) (kind : Nat) (sub : Sub)
    (before after : Option Std.U32) : Prop :=
  if hashed = true ∧ sub.kind bytes = kind then
    sub.len = 5 ∧ ∃ time : Std.U32, after = some time ∧ time.val = sub.Time bytes
  else after = before

/-- What one subpacket does to the key flags of the answer: in the hashed area a subpacket of kind
27 sets them to its flags; anything else leaves them as they were. -/
def FlagsAfter (bytes : List Std.U8) (hashed : Bool) (sub : Sub)
    (before after : Option Std.U8) : Prop :=
  if hashed = true ∧ sub.kind bytes = 27 then
    ∃ flags : Std.U8, after = some flags ∧ flags.val = sub.Flags bytes
  else after = before

/-- What one subpacket does to the embedded signatures of the answer: a subpacket of kind 32, in
either area, adds its value (the bytes after the kind byte) at the end; anything else leaves them.
-/
def EmbeddedAfter (bytes : List Std.U8) (sub : Sub) (before after : alloc.vec.Vec Span) : Prop :=
  if sub.kind bytes = 32 then
    SpanPairs after = SpanPairs before ++ [(sub.body + 1, sub.len - 1)]
  else after = before

/-- What one subpacket does to the answer: the times and the flags (`TimeAfter`, `FlagsAfter`), the
embedded signatures (`EmbeddedAfter`), and the issuer fingerprint, which, if it is a new one, lies
inside the value of the subpacket. -/
def Applied (bytes : List Std.U8) (hashed : Bool) (sub : Sub) (before after : sig.Subpackets) :
    Prop :=
  TimeAfter bytes hashed 2 sub before.created after.created ∧
  TimeAfter bytes hashed 3 sub before.expires after.expires ∧
  TimeAfter bytes hashed 9 sub before.key_expires after.key_expires ∧
  FlagsAfter bytes hashed sub before.key_flags after.key_flags ∧
  EmbeddedAfter bytes sub before.embedded after.embedded ∧
  (∀ span, after.issuer_fpr = some span → before.issuer_fpr = some span ∨
    span.off.val + span.len.val ≤ sub.body + sub.len)

/-- A subpacket that changes none of the fields the answer tells about (the times, the flags, the
embedded signatures, the issuer fingerprint) has been applied, if it is not of a kind that would
change them in the area it is in. -/
theorem applied_when_nothing_changes (bytes : List Std.U8) (hashed : Bool) (sub : Sub)
    (out out' : sig.Subpackets)
    (not_read : hashed = true → ¬ (sub.kind bytes = 2 ∨ sub.kind bytes = 3 ∨ sub.kind bytes = 9 ∨
      sub.kind bytes = 27))
    (not_embedded : sub.kind bytes ≠ 32)
    (created : out'.created = out.created) (expires : out'.expires = out.expires)
    (key_expires : out'.key_expires = out.key_expires) (key_flags : out'.key_flags = out.key_flags)
    (embedded : out'.embedded = out.embedded) (fingerprint : out'.issuer_fpr = out.issuer_fpr) :
    Applied bytes hashed sub out out' := by
  unfold Applied TimeAfter FlagsAfter EmbeddedAfter
  have no_time (kind : Nat) (other : sub.kind bytes ≠ kind) : ¬ (hashed = true ∧ sub.kind bytes
    = kind) :=
    fun both => other both.2
  by_cases is_hashed : hashed = true
  · have := not_read is_hashed
    simp only [not_or] at this
    simp [is_hashed, this, not_embedded, created, expires, key_expires, key_flags, embedded,
      fingerprint]
    exact fun span found => Or.inl found
  · simp [is_hashed, not_embedded, created, expires, key_expires, key_flags, embedded, fingerprint]
    exact fun span found => Or.inl found

/-- A creation time subpacket of the hashed area, with a time of 4 bytes, has been applied when the
creation time is set. -/
theorem applied_created (bytes : List Std.U8) (sub : Sub) (out : sig.Subpackets) (time : Std.U32)
    (kind : sub.kind bytes = 2) (five : sub.len = 5) (value : time.val = sub.Time bytes) :
    Applied bytes true sub out { out with created := some time } := by
  unfold Applied TimeAfter FlagsAfter EmbeddedAfter
  simp [kind, five, value]
  exact fun span found => Or.inl found

/-- The same for a signature expiration time subpacket. -/
theorem applied_expires (bytes : List Std.U8) (sub : Sub) (out : sig.Subpackets) (time : Std.U32)
    (kind : sub.kind bytes = 3) (five : sub.len = 5) (value : time.val = sub.Time bytes) :
    Applied bytes true sub out { out with expires := some time } := by
  unfold Applied TimeAfter FlagsAfter EmbeddedAfter
  simp [kind, five, value]
  exact fun span found => Or.inl found

/-- The same for a key expiration time subpacket. -/
theorem applied_key_expires (bytes : List Std.U8) (sub : Sub) (out : sig.Subpackets)
    (time : Std.U32) (kind : sub.kind bytes = 9) (five : sub.len = 5)
    (value : time.val = sub.Time bytes) :
    Applied bytes true sub out { out with key_expires := some time } := by
  unfold Applied TimeAfter FlagsAfter EmbeddedAfter
  simp [kind, five, value]
  exact fun span found => Or.inl found

/-- A key flags subpacket of the hashed area has been applied when the flags are set. -/
theorem applied_key_flags (bytes : List Std.U8) (sub : Sub) (out : sig.Subpackets)
    (flags : Std.U8) (kind : sub.kind bytes = 27) (value : flags.val = sub.Flags bytes) :
    Applied bytes true sub out { out with key_flags := some flags } := by
  unfold Applied TimeAfter FlagsAfter EmbeddedAfter
  simp [kind, value]
  exact fun span found => Or.inl found

/-- An embedded signature subpacket of either area has been applied when its value is added. -/
theorem applied_embedded (bytes : List Std.U8) (hashed : Bool) (sub : Sub) (out : sig.Subpackets)
    (embedded : alloc.vec.Vec Span) (kind : sub.kind bytes = 32)
    (added : SpanPairs embedded = SpanPairs out.embedded ++ [(sub.body + 1, sub.len - 1)]) :
    Applied bytes hashed sub out { out with embedded := embedded } := by
  unfold Applied TimeAfter FlagsAfter EmbeddedAfter
  simp [kind, added]
  exact fun span found => Or.inl found

/-- An issuer fingerprint subpacket of either area has been applied when the span is set, if the
span is inside the subpacket. -/
theorem applied_fingerprint (bytes : List Std.U8) (hashed : Bool) (sub : Sub)
    (out : sig.Subpackets) (span : Span) (kind : sub.kind bytes = 33)
    (inside : span.off.val + span.len.val ≤ sub.body + sub.len) :
    Applied bytes hashed sub out { out with issuer_fpr := some span } := by
  unfold Applied TimeAfter FlagsAfter EmbeddedAfter
  simp [kind]
  exact Or.inr inside

/-- The kinds the reader reads, as numbers. -/
theorem kind_constants :
    sig.SUB_CREATED.val = 2 ∧ sig.SUB_EXPIRES.val = 3 ∧ sig.SUB_KEY_EXPIRES.val = 9 ∧
    sig.SUB_ISSUER.val = 16 ∧ sig.SUB_KEY_FLAGS.val = 27 ∧ sig.SUB_EMBEDDED.val = 32 ∧
    sig.SUB_ISSUER_FPR.val = 33 := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> first
    | (unfold sig.SUB_CREATED; rfl) | (unfold sig.SUB_EXPIRES; rfl)
    | (unfold sig.SUB_KEY_EXPIRES; rfl) | (unfold sig.SUB_ISSUER; rfl)
    | (unfold sig.SUB_KEY_FLAGS; rfl) | (unfold sig.SUB_EMBEDDED; rfl)
    | (unfold sig.SUB_ISSUER_FPR; rfl)

/-- What the bytes must say for `one` to accept the subpacket at `at_` of an area that ends at
`end_`: a subpacket (`Sub`) begins there, with a length `LengthAt` finds, of at least one, ending
inside the area, and, in the hashed area, it is one that the reader accepts (`Sub.Acceptable`). -/
def OneAcceptable (bytes : List Std.U8) (at_ end_ : Nat) (hashed : Bool) : Prop :=
  ∃ sub : Sub, sub.start = at_ ∧
    (∃ octets, LengthAt bytes at_ end_ = some (sub.len, octets) ∧ sub.body = at_ + octets) ∧
    1 ≤ sub.len ∧ sub.body + sub.len ≤ end_ ∧ (hashed = true → sub.Acceptable bytes)

/-- A subpacket is determined by where it begins: two that begin at `at_` and have the length
`LengthAt` finds there are the same. -/
theorem sub_is_determined (bytes : List Std.U8) (at_ end_ : Nat) (sub sub' : Sub)
    (start : sub.start = at_) (start' : sub'.start = at_)
    (found : ∃ octets, LengthAt bytes at_ end_ = some (sub.len, octets) ∧ sub.body = at_ + octets)
    (found' : ∃ octets, LengthAt bytes at_ end_ = some (sub'.len, octets) ∧
      sub'.body = at_ + octets) :
    sub = sub' := by
  obtain ⟨octets, length, body⟩ := found
  obtain ⟨octets', length', body'⟩ := found'
  rw [length] at length'
  simp only [Option.some.injEq, Prod.mk.injEq] at length'
  cases sub; cases sub'
  simp only [Sub.mk.injEq] at *
  omega

/-- What `one` answers, for the subpacket at `at_`: when it accepts, the subpacket is the one at
`at_` as `LengthAt` says, it ends where `next` is, within the area, it has been applied to the
answer (`Applied`), and, in the hashed area, a critical subpacket is of a known kind.  When it
refuses, the bytes do not say a subpacket the reader accepts there (`OneAcceptable`). -/
def OneRead (bytes : List Std.U8) (at_ end_ : Nat) (hashed : Bool) (out : sig.Subpackets)
    (r : core.result.Result Std.Usize velarx_sigparse_core.Error × sig.Subpackets) : Prop :=
  (∀ next, r.1 = core.result.Result.Ok next →
    ∃ sub : Sub, sub.start = at_ ∧
      (∃ octets, LengthAt bytes at_ end_ = some (sub.len, octets) ∧ sub.body = at_ + octets) ∧
      1 ≤ sub.len ∧ sub.body + sub.len ≤ end_ ∧ next.val = sub.body + sub.len ∧
      Applied bytes hashed sub out r.2 ∧
      (hashed = true → sub.Critical bytes → sub.kind bytes ∈ KnownKinds)) ∧
  (∀ e, r.1 = core.result.Result.Err e → ¬ OneAcceptable bytes at_ end_ hashed)

-- (The proof follows the nine-way chain of `one` in one piece, and splitting it would copy the
-- context of each branch into a lemma; it needs more than the default heartbeats, and checks in
-- seconds.)
set_option maxHeartbeats 4000000 in
/-- `one` reads one subpacket (`OneRead`), and returns. -/
theorem one_reads (body : Slice Std.U8) (at_ end_ : Std.Usize) (hashed : Bool)
    (out : sig.Subpackets) (below : at_.val < end_.val) (inside : end_.val ≤ body.val.length)
    (room : out.embedded.val.length < Usize.max) :
    sig.one body at_ end_ hashed out ⦃ r => OneRead body.val at_.val end_.val hashed out r ⦄ := by
  unfold sig.one
  have := body.property
  step with header_reads as ⟨ r, found, header_refused ⟩
  cases r with
  | Ok located =>
    obtain ⟨len, kind_at⟩ := located
    obtain ⟨octets, length_at, kind_at_is, nonempty, fits⟩ := found len kind_at rfl
    simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
    step as ⟨ first, hfirst ⟩
    step as ⟨ kind, hkind ⟩
    step as ⟨ top, htop ⟩
    step as ⟨ value_at, hvalue_at ⟩
    step as ⟨ value_len, hvalue_len ⟩
    -- the subpacket, as the bytes say it
    obtain ⟨sub, is_sub⟩ : ∃ sub : Sub, sub = ⟨at_.val, kind_at.val, len.val⟩ := ⟨_, rfl⟩
    have in_data : kind_at.val < body.val.length := by omega
    have byte_is : ByteAt body.val kind_at.val = first.val := by
      simp [ByteAt, hfirst, in_data]
    have kind_is : sub.kind body.val = kind.val := by
      rw [is_sub, hkind, UScalar.val_and]
      simp only [Sub.kind, byte_is]
      exact (low_bits_of_any_byte _).symm
    have finish : ∀ (next : Usize) (out' : sig.Subpackets),
        next.val = kind_at.val + len.val → Applied body.val hashed sub out out' →
        (hashed = true → sub.Critical body.val → sub.kind body.val ∈ KnownKinds) →
        OneRead body.val at_.val end_.val hashed out (core.result.Result.Ok next, out') := by
      intro next out' next_is applied known
      refine ⟨fun next' same => ?_, fun e same => by simp at same⟩
      simp only [core.result.Result.Ok.injEq] at same
      subst same
      exact ⟨sub, by simp [is_sub], ⟨octets, by simpa [is_sub] using length_at,
        by simp [is_sub]; omega⟩,
        by simp [is_sub]; omega, by simp [is_sub]; omega, by simp [is_sub]; omega, applied, known⟩
    -- what the bytes say of the subpacket that `one` found is what any subpacket there says
    have acceptable : OneAcceptable body.val at_.val end_.val hashed → hashed = true →
        sub.Acceptable body.val := by
      rintro ⟨sub', start', found', _, _, accepted⟩ is_hashed
      have same : sub = sub' := sub_is_determined body.val at_.val end_.val sub sub'
        (by simp [is_sub]) start' ⟨octets, by simpa [is_sub] using length_at,
          by simp [is_sub]; omega⟩ found'
      subst same
      exact accepted is_hashed
    obtain ⟨c2, c3, c9, c16, c27, c32, c33⟩ := kind_constants
    have sub_len : sub.len = len.val := by simp [is_sub]
    have sub_body : sub.body = kind_at.val := by simp [is_sub]
    have value_len_is : value_len.val = len.val - 1 := by scalar_tac
    split
    · -- a creation time
      rename_i is_created
      have is_kind : sub.kind body.val = 2 := by
        rw [kind_is, ← c2]; exact congrArg UScalar.val is_created
      split
      · rename_i hashed_area
        step with time_reads as ⟨ r, time_ok, time_err ⟩
        cases r with
        | Ok t =>
          obtain ⟨four, _, time_is⟩ := time_ok t rfl
          simp only [Std.bind_ok]
          step as ⟨ next, hnext ⟩
          have hashed_true : hashed = true := by simpa using hashed_area
          subst hashed_true
          refine finish next _ (by omega) (applied_created _ sub out t is_kind (by omega) ?_) ?_
          · rw [time_is, hvalue_at, Sub.Time, sub_body]
          · intro _ _
            simp [KnownKinds, ReadKinds, is_kind]
        | Err e =>
          simp [
            core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, OneRead]
          intro accepted
          have five := (acceptable accepted hashed_area).1 (Or.inl is_kind)
          have := time_err e rfl
          omega
      · rename_i unhashed_area
        step as ⟨ next, hnext ⟩
        have hashed_false : hashed = false := by simpa using unhashed_area
        subst hashed_false
        refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _
          (by simp) ?_ rfl rfl rfl rfl rfl rfl) (by simp)
        omega
    · split
      · -- a signature expiration time
        rename_i is_expires
        have is_kind : sub.kind body.val = 3 := by
          rw [kind_is, ← c3]; exact congrArg UScalar.val is_expires
        split
        · rename_i hashed_area
          step with time_reads as ⟨ r, time_ok, time_err ⟩
          cases r with
          | Ok t =>
            obtain ⟨four, _, time_is⟩ := time_ok t rfl
            simp only [Std.bind_ok]
            step as ⟨ next, hnext ⟩
            have hashed_true : hashed = true := by simpa using hashed_area
            subst hashed_true
            refine finish next _ (by omega) (applied_expires _ sub out t is_kind (by omega) ?_) ?_
            · rw [time_is, hvalue_at, Sub.Time, sub_body]
            · intro _ _
              simp [KnownKinds, ReadKinds, is_kind]
          | Err e =>
            simp [
              core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, OneRead]
            intro accepted
            have five := (acceptable accepted hashed_area).1 (Or.inr (Or.inl is_kind))
            have := time_err e rfl
            omega
        · rename_i unhashed_area
          step as ⟨ next, hnext ⟩
          have hashed_false : hashed = false := by simpa using unhashed_area
          subst hashed_false
          refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _
            (by simp) ?_ rfl rfl rfl rfl rfl rfl) (by simp)
          omega
      · split
        · -- a key expiration time
          rename_i is_key_expires
          have is_kind : sub.kind body.val = 9 := by
            rw [kind_is, ← c9]; exact congrArg UScalar.val is_key_expires
          split
          · rename_i hashed_area
            step with time_reads as ⟨ r, time_ok, time_err ⟩
            cases r with
            | Ok t =>
              obtain ⟨four, _, time_is⟩ := time_ok t rfl
              simp only [Std.bind_ok]
              step as ⟨ next, hnext ⟩
              have hashed_true : hashed = true := by simpa using hashed_area
              subst hashed_true
              refine finish next _ (by omega) (applied_key_expires _ sub out t is_kind
                (by omega) ?_) ?_
              · rw [time_is, hvalue_at, Sub.Time, sub_body]
              · intro _ _
                simp [KnownKinds, ReadKinds, is_kind]
            | Err e =>
              simp [
                core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, OneRead]
              intro accepted
              have five := (acceptable accepted hashed_area).1 (Or.inr (Or.inr is_kind))
              have := time_err e rfl
              omega
          · rename_i unhashed_area
            step as ⟨ next, hnext ⟩
            have hashed_false : hashed = false := by simpa using unhashed_area
            subst hashed_false
            refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _
              (by simp) ?_ rfl rfl rfl rfl rfl rfl) (by simp)
            omega
        · split
          · -- key flags
            rename_i is_flags
            have is_kind : sub.kind body.val = 27 := by
              rw [kind_is, ← c27]; exact congrArg UScalar.val is_flags
            -- the flags are read in the hashed area only
            by_cases is_hashed : hashed = true
            · subst is_hashed
              by_cases has_byte : value_len > 0#usize
              · simp only [has_byte, ↓reduceIte]
                have in_value : value_at.val < body.val.length := by scalar_tac
                step as ⟨ flag, hflag ⟩
                step as ⟨ next, hnext ⟩
                refine finish next _ (by omega) (applied_key_flags _ sub out flag is_kind ?_) ?_
                · have two : 2 ≤ len.val := by scalar_tac
                  have in_bytes : kind_at.val + 1 < body.val.length := by omega
                  simp [Sub.Flags, ByteAt, hflag, sub_len, sub_body, hvalue_at, two, in_bytes]
                · intro _ _
                  simp [KnownKinds, ReadKinds, is_kind]
              · simp only [has_byte, ↓reduceIte, Std.bind_ok]
                step as ⟨ next, hnext ⟩
                refine finish next _ (by omega) (applied_key_flags _ sub out 0#u8 is_kind ?_) ?_
                · have one : len.val = 1 := by scalar_tac
                  simp [Sub.Flags, sub_len, one]
                · intro _ _
                  simp [KnownKinds, ReadKinds, is_kind]
            · have is_unhashed : hashed = false := by simpa using is_hashed
              subst is_unhashed
              simp only [Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
              step as ⟨ next, hnext ⟩
              refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _
                (by simp) ?_ rfl rfl rfl rfl rfl rfl) (by simp)
              omega
          · split
            · -- an issuer key ID, which is a hint
              rename_i is_issuer
              have is_kind : sub.kind body.val = 16 := by
                rw [kind_is, ← c16]; exact congrArg UScalar.val is_issuer
              by_cases eight : value_len = 8#usize
              · simp only [eight, ↓reduceIte]
                have eight_val : value_len.val = 8 := by scalar_tac
                step as ⟨ s, back, hs ⟩
                -- the id is copied: the answer keeps all it says of the times and the rest
                refine WP.spec_bind (Pₘ := fun out1 : sig.Subpackets =>
                  out1.created = out.created ∧ out1.expires = out.expires ∧
                  out1.key_expires = out.key_expires ∧ out1.key_flags = out.key_flags ∧
                  out1.embedded = out.embedded ∧ out1.issuer_fpr = out.issuer_fpr) ?_ ?_
                · change Std.bind _ _ ⦃ _ ⦄
                  step with span_end_is_the_sum as ⟨ value_end, hvalue_end ⟩
                  step as ⟨ s1, hs1 ⟩
                  step as ⟨ s2, hs2 ⟩
                · rintro out1 ⟨same_created, same_expires, same_key_expires, same_flags,
                    same_embedded, same_fingerprint⟩
                  step as ⟨ next, hnext ⟩
                  refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _ ?_ ?_
                    same_created same_expires same_key_expires same_flags same_embedded
                    same_fingerprint) (by simp [is_kind, KnownKinds, ReadKinds])
                  · intro _
                    simp [is_kind]
                  · simp [is_kind]
              · simp only [eight, ↓reduceIte, Std.bind_ok]
                step as ⟨ next, hnext ⟩
                refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _ ?_ ?_
                  rfl rfl rfl rfl rfl rfl) (by simp [is_kind, KnownKinds, ReadKinds])
                · intro _
                  simp [is_kind]
                · simp [is_kind]
            · split
              · -- an issuer fingerprint, which is a hint
                rename_i is_fingerprint
                have is_kind : sub.kind body.val = 33 := by
                  rw [kind_is, ← c33]; exact congrArg UScalar.val is_fingerprint
                by_cases has_byte : value_len > 0#usize
                · simp only [has_byte, ↓reduceIte]
                  have in_value : value_at.val < body.val.length := by scalar_tac
                  step as ⟨ version, hversion ⟩
                  by_cases four : version = 4#u8
                  · simp only [four, ↓reduceIte]
                    step as ⟨ span_at, hspan_at ⟩
                    step as ⟨ span_len, hspan_len ⟩
                    step as ⟨ next, hnext ⟩
                    refine finish next _ (by omega) (applied_fingerprint _ _ sub out ⟨span_at,
                      span_len⟩
                      is_kind ?_) (by simp [is_kind, KnownKinds, ReadKinds])
                    simp only [sub_len, sub_body]
                    scalar_tac
                  · simp only [four, ↓reduceIte, Std.bind_ok]
                    step as ⟨ next, hnext ⟩
                    refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _ ?_ ?_
                      rfl rfl rfl rfl rfl rfl) (by simp [is_kind, KnownKinds, ReadKinds])
                    · intro _
                      simp [is_kind]
                    · simp [is_kind]
                · simp only [has_byte, ↓reduceIte, Std.bind_ok]
                  step as ⟨ next, hnext ⟩
                  refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _ ?_ ?_
                    rfl rfl rfl rfl rfl rfl) (by simp [is_kind, KnownKinds, ReadKinds])
                  · intro _
                    simp [is_kind]
                  · simp [is_kind]
              · split
                · -- an embedded signature
                  rename_i is_embedded
                  have is_kind : sub.kind body.val = 32 := by
                    rw [kind_is, ← c32]; exact congrArg UScalar.val is_embedded
                  step as ⟨ more, hmore ⟩
                  step as ⟨ next, hnext ⟩
                  refine finish next _ (by omega) (applied_embedded _ _ sub out more is_kind ?_)
                    (by simp [is_kind, KnownKinds, ReadKinds])
                  simp only [SpanPairs, hmore, List.map_append, List.map_cons, List.map_nil]
                  simp [sub_len, sub_body, hvalue_at, value_len_is]
                · -- a subpacket of a kind that is not read
                  rename_i not_created not_expires not_key_expires not_flags not_issuer
                    not_fingerprint not_embedded
                  have k2 : kind.val ≠ 2 := fun same =>
                    not_created (UScalar.eq_of_val_eq (by rw [same, c2]))
                  have k3 : kind.val ≠ 3 := fun same =>
                    not_expires (UScalar.eq_of_val_eq (by rw [same, c3]))
                  have k9 : kind.val ≠ 9 := fun same =>
                    not_key_expires (UScalar.eq_of_val_eq (by rw [same, c9]))
                  have k27 : kind.val ≠ 27 := fun same =>
                    not_flags (UScalar.eq_of_val_eq (by rw [same, c27]))
                  have k32 : kind.val ≠ 32 := fun same =>
                    not_embedded (UScalar.eq_of_val_eq (by rw [same, c32]))
                  have k16 : kind.val ≠ 16 := fun same =>
                    not_issuer (UScalar.eq_of_val_eq (by rw [same, c16]))
                  have k33 : kind.val ≠ 33 := fun same =>
                    not_fingerprint (UScalar.eq_of_val_eq (by rw [same, c33]))
                  have unread : (hashed = true → ¬ (sub.kind body.val = 2 ∨ sub.kind body.val = 3 ∨
                      sub.kind body.val = 9 ∨ sub.kind body.val = 27)) ∧ sub.kind body.val ≠ 32
                        := by
                    rw [kind_is]
                    exact ⟨fun _ => by omega, k32⟩
                  by_cases is_critical : top != 0#u8
                  · simp only [is_critical, ↓reduceIte]
                    by_cases is_hashed : hashed = true
                    · subst is_hashed
                      simp only [↓reduceIte]
                      step with known_is_the_list as ⟨ b, hb ⟩
                      split
                      · rename_i is_known
                        step as ⟨ next, hnext ⟩
                        refine finish next _ (by omega)
                          (applied_when_nothing_changes _ _ _ _ _ unread.1
                          unread.2 rfl rfl rfl rfl rfl rfl) ?_
                        intro _ _
                        have : kind.val ∈ IgnoredKinds := hb.mp is_known
                        simp [KnownKinds, ← kind_is] at this ⊢
                        exact Or.inr this
                      · rename_i not_known
                        simp [OneRead]
                        intro accepted
                        have critical : sub.Critical body.val := by
                          have top_set : first.val &&& 128 ≠ 0 := by
                            have not_zero : top.val ≠ 0 := by simpa using is_critical
                            rwa [htop, UScalar.val_and] at not_zero
                          have first_small : first.val < 256 := by scalar_tac
                          simpa [Sub.Critical, sub_body, byte_is] using
                            (top_bit_of_a_byte first.val first_small).mp top_set
                        have in_known := (acceptable accepted rfl).2 critical
                        rw [kind_is] at in_known
                        simp only [KnownKinds, ReadKinds, List.mem_append, List.mem_cons,
                          List.not_mem_nil, or_false] at in_known
                        rcases in_known with read | ignored
                        · omega
                        · exact not_known (hb.mpr ignored)
                    · have is_unhashed : hashed = false := by simpa using is_hashed
                      subst is_unhashed
                      simp only [Bool.false_eq_true, ↓reduceIte]
                      step as ⟨ next, hnext ⟩
                      refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _
                        (by simp)
                        unread.2 rfl rfl rfl rfl rfl rfl) (by simp)
                  · simp only [is_critical, Bool.false_eq_true, ↓reduceIte]
                    step as ⟨ next, hnext ⟩
                    refine finish next _ (by omega) (applied_when_nothing_changes _ _ _ _ _ unread.1
                      unread.2 rfl rfl rfl rfl rfl rfl) ?_
                    intro _ critical
                    exfalso
                    have no_top : top.val = 0 := by simpa using is_critical
                    rw [htop, UScalar.val_and] at no_top
                    have first_small : first.val < 256 := by scalar_tac
                    simp only [Sub.Critical, sub_body, byte_is] at critical
                    have : first.val &&& 128 ≠ 0 :=
                      (top_bit_of_a_byte first.val first_small).mpr critical
                    exact this (by simpa using no_top)
  | Err e =>
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual, OneRead]
    intro accepted
    obtain ⟨sub, _, ⟨octets, length_at, body_is⟩, nonempty, fits, _⟩ := accepted
    exact header_refused e rfl ⟨sub.len, octets, length_at, nonempty, by omega⟩

end SigparseCore
