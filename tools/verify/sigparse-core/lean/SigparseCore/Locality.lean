-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the subpackets of an area say depends only on the bytes before the end
-- of the area (`LengthAt`, `BigEndian`, `ByteAt` and the splitting of the area into subpackets
-- look at no byte at or after `stop`), and so two signatures that begin with the same bytes up to
-- the end of the hashed area have the same times and key flags.
-- Why it is needed: the times and the flags are the signer's only when they come from the hashed
-- area, which the signature covers; a verifier that hashes those bytes and reads the times from the
-- bytes it hashed can rely on this.
-- Read before this file: Spec.lean, Subpacket.lean and AreaUnique.lean.
-- Notation: `agree` is "the two lists have the same element at every position before `stop`".
import SigparseCore.Signature
import SigparseCore.AreaUnique
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- The bytes read from a position, for a few of them before `stop`, are the same in two lists that
agree before `stop`. -/
theorem bytes_agree_before (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (start count : Nat)
    (inside : start + count ≤ stop) :
    (bytes.drop start).take count = (bytes'.drop start).take count := by
  apply List.ext_getElem?
  intro j
  rw [List.getElem?_take, List.getElem?_take]
  by_cases below : j < count
  · simp only [below, ↓reduceIte, List.getElem?_drop]
    exact agree _ (by omega)
  · simp [below]

/-- A big endian number read before `stop` is the same in two lists that agree before `stop`. -/
theorem big_endian_agrees (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (start count : Nat)
    (inside : start + count ≤ stop) :
    BigEndian bytes start count = BigEndian bytes' start count := by
  unfold BigEndian
  rw [bytes_agree_before bytes bytes' stop agree start count inside]

/-- A byte read before `stop` is the same in two lists that agree before `stop`. -/
theorem byte_at_agrees (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (p : Nat) (inside : p < stop) :
    ByteAt bytes p = ByteAt bytes' p := by
  simp [ByteAt, agree p inside]

/-- The length written at a position before `stop` is the same in two lists that agree before
`stop`. -/
theorem length_at_agrees (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (p : Nat) (inside : p < stop) :
    LengthAt bytes p stop = LengthAt bytes' p stop := by
  unfold LengthAt
  rw [agree p inside]
  cases bytes'[p]? with
  | none => rfl
  | some first =>
    simp only
    split
    · rfl
    · split
      · split
        · rename_i room
          rw [agree (p + 1) room]
        · rfl
      · split
        · rw [big_endian_agrees bytes bytes' stop agree _ _ (by omega)]
        · rfl

/-- Subpackets that make up an area before `stop` in one list make it up in another list that agrees
before `stop`. -/
theorem subs_run_agrees (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (start finish : Nat) (subs : List Sub)
    (run : SubsRun bytes stop start finish subs) : SubsRun bytes' stop start finish subs := by
  induction subs generalizing start with
  | nil => exact run
  | cons sub rest ih =>
    obtain ⟨below, starts, ⟨octets, found, body_is⟩, nonempty, fits, rest_run⟩ := run
    refine ⟨below, starts, ⟨octets, ?_, body_is⟩, nonempty, fits, ih _ rest_run⟩
    rw [← length_at_agrees bytes bytes' stop agree start below]
    exact found

/-- The subpackets that make up an area before `stop` have their kind byte and their value before
`stop`, and are at least a byte long. -/
theorem subs_run_inside (bytes : List Std.U8) (stop start finish : Nat) (subs : List Sub)
    (run : SubsRun bytes stop start finish subs) :
    ∀ sub ∈ subs, 1 ≤ sub.len ∧ sub.body + sub.len ≤ stop := by
  induction subs generalizing start with
  | nil => intro sub member; simp at member
  | cons first rest ih =>
    obtain ⟨_, _, _, nonempty, fits, rest_run⟩ := run
    intro sub member
    rcases List.mem_cons.mp member with same | later
    · subst same
      exact ⟨nonempty, fits⟩
    · exact ih _ rest_run sub later

/-- The last subpacket of a kind is one of the subpackets, of that kind. -/
theorem last_of_kind_is_one (bytes : List Std.U8) (subs : List Sub) (kind : Nat) (sub : Sub)
    (found : LastOfKind bytes subs kind = some sub) : sub ∈ subs ∧ sub.kind bytes = kind := by
  unfold LastOfKind at found
  have member := List.mem_of_getLast? found
  rw [List.mem_filter] at member
  exact ⟨member.1, by simpa using member.2⟩

/-- The kind of a subpacket that lies before `stop` is the same in two lists that agree before
`stop`. -/
theorem kind_agrees (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (sub : Sub) (inside : sub.body < stop) :
    sub.kind bytes = sub.kind bytes' := by
  simp only [Sub.kind, byte_at_agrees bytes bytes' stop agree _ inside]

/-- The last subpacket of a kind is the same one in two lists that agree before `stop`, when the
subpackets lie before `stop`. -/
theorem last_of_kind_agrees (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (subs : List Sub)
    (inside : ∀ sub ∈ subs, sub.body < stop) (kind : Nat) :
    LastOfKind bytes subs kind = LastOfKind bytes' subs kind := by
  unfold LastOfKind
  rw [List.filter_congr (q := fun sub => sub.kind bytes' == kind)]
  intro sub member
  rw [kind_agrees bytes bytes' stop agree sub (inside sub member)]

/-- The time a time subpacket of 4 bytes of value says is the same in two lists that agree before
`stop`. -/
theorem time_agrees (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (sub : Sub) (five : sub.len = 5)
    (inside : sub.body + sub.len ≤ stop) : sub.Time bytes = sub.Time bytes' := by
  simp only [Sub.Time]
  exact big_endian_agrees bytes bytes' stop agree _ _ (by omega)

/-- The key flags a subpacket says are the same in two lists that agree before `stop`. -/
theorem flags_agree (bytes bytes' : List Std.U8) (stop : Nat)
    (agree : ∀ i, i < stop → bytes[i]? = bytes'[i]?) (sub : Sub)
    (inside : sub.body + sub.len ≤ stop) : sub.Flags bytes = sub.Flags bytes' := by
  simp only [Sub.Flags]
  split
  · exact byte_at_agrees bytes bytes' stop agree _ (by omega)
  · rfl

/-- Two signature packets that agree up to the end of the hashed area (the bytes the signature
hashes) have the same creation time, expirations and key flags: they are read from the subpackets
of the hashed area, which no byte after it changes. -/
theorem signatures_that_agree_say_the_same (bytes bytes' : List Std.U8)
    (first second : sig.Signature)
    (read : SignatureRead bytes first) (read' : SignatureRead bytes' second)
    (same : bytes.take (HashedEnd bytes) = bytes'.take (HashedEnd bytes)) :
    first.sub.created = second.sub.created ∧ first.sub.expires = second.sub.expires ∧
    first.sub.key_expires = second.sub.key_expires ∧
    first.sub.key_flags = second.sub.key_flags := by
  have agree : ∀ i, i < HashedEnd bytes → bytes[i]? = bytes'[i]? := by
    intro i below
    have := congrArg (fun list => list[i]?) same
    simpa [List.getElem?_take, below] using this
  obtain ⟨_, _, _, _, hashed_off, hashed_len, _, _, _, _, _, _, _, _, hashed_subs, _, hashed_made,
    _, created, expires, key_expires, key_flags, five, _⟩ := read
  obtain ⟨_, _, _, _, hashed_off', hashed_len', _, _, _, _, _, _, _, _, hashed_subs', _,
    hashed_made', _, created', expires', key_expires', key_flags', _⟩ := read'
  have same_end : HashedEnd bytes' = HashedEnd bytes := by
    simp only [HashedEnd]
    rw [← big_endian_agrees bytes bytes' (HashedEnd bytes) agree 4 2 (by simp [HashedEnd])]
  have hashed_end : first.hashed.off.val + first.hashed.len.val = HashedEnd bytes := by
    simp only [HashedEnd]
    omega
  have hashed_end' : second.hashed.off.val + second.hashed.len.val = HashedEnd bytes := by
    rw [← same_end]
    simp only [HashedEnd]
    omega
  rw [hashed_end, hashed_off] at hashed_made
  rw [hashed_end', hashed_off'] at hashed_made'
  have moved := subs_run_agrees bytes bytes' (HashedEnd bytes) agree _ _ _ hashed_made
  have subs_same : hashed_subs = hashed_subs' := area_made_of_unique _ _ _ _ _ moved hashed_made'
  subst subs_same
  have inside := subs_run_inside _ _ _ _ _ hashed_made
  have starts : ∀ sub ∈ hashed_subs, sub.body < HashedEnd bytes :=
    fun sub member => by have := inside sub member; omega
  have time_of (kind : Nat) (is_time : kind = 2 ∨ kind = 3 ∨ kind = 9) :
      (LastOfKind bytes hashed_subs kind).map (·.Time bytes) =
        (LastOfKind bytes' hashed_subs kind).map (·.Time bytes') := by
    rw [last_of_kind_agrees bytes bytes' _ agree _ starts]
    cases found : LastOfKind bytes' hashed_subs kind with
    | none => rfl
    | some sub =>
      obtain ⟨member, is_kind⟩ := last_of_kind_is_one _ _ _ _ found
      have is_kind' : sub.kind bytes = kind := by
        rw [kind_agrees bytes bytes' _ agree sub (starts sub member)]
        exact is_kind
      have five_bytes := five sub member (by omega)
      simp only [Option.map_some, Option.some.injEq]
      exact time_agrees bytes bytes' _ agree sub five_bytes (inside sub member).2
  have unsigned : Function.Injective (fun time : Std.U32 => time.val) :=
    fun a b same => UScalar.eq_of_val_eq same
  have unsigned8 : Function.Injective (fun flags : Std.U8 => flags.val) :=
    fun a b same => UScalar.eq_of_val_eq same
  refine ⟨Option.map_injective unsigned
      (created.trans ((time_of 2 (by omega)).trans created'.symm)),
    Option.map_injective unsigned (expires.trans ((time_of 3 (by omega)).trans expires'.symm)),
    Option.map_injective unsigned
      (key_expires.trans ((time_of 9 (by omega)).trans key_expires'.symm)),
    Option.map_injective unsigned8 (key_flags.trans (Eq.trans ?_ key_flags'.symm))⟩
  rw [last_of_kind_agrees bytes bytes' _ agree _ starts]
  cases found : LastOfKind bytes' hashed_subs 27 with
  | none => rfl
  | some sub =>
    obtain ⟨member, _⟩ := last_of_kind_is_one _ _ _ _ found
    simp only [Option.map_some, Option.some.injEq]
    exact flags_agree bytes bytes' _ agree sub (inside sub member).2

end SigparseCore
