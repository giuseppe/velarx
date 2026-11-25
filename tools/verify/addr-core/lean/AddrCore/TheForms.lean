-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the facts about the forms that carry an IPv4 address: two forms never hold the same
--   address, the only addresses both in a form and in a local prefix (`::` and `::1`) carry a local IPv4
--   address, the number in a form is the number of 4 bytes of the address.
-- Why it is needed: these make the address inside the form the whole judgement of the address (rule 4 of
--   lib.rs), in both directions, and tie the number of the statement to the bytes of the address.
-- Read before this file: TheV6.lean.
-- Notation: `l.drop k` and `l.take k` cut a list; `Number l` is the number of the bytes `l`; `omega`
--   settles statements of whole numbers with sums and comparisons.
import AddrCore.TheV6
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

/-- two embedded forms that hold the same address are the same form -/
theorem forms_unique (n : Nat) (e f : Nat × Nat × Nat) (e_in : e ∈ Embedded) (f_in : f ∈ Embedded)
    (in_e : InPrefix 128 n e.1 e.2.1) (in_f : InPrefix 128 n f.1 f.2.1) : e = f := by
  have apart : ∀ e ∈ Embedded, ∀ f ∈ Embedded, e = f ∨ e.1 + 2 ^ (128 - e.2.1) ≤ f.1 ∨
      f.1 + 2 ^ (128 - f.2.1) ≤ e.1 := by
    unfold Embedded Ipv6
    decide +kernel
  rcases apart e e_in f f_in with same | before | after
  · exact same
  · obtain ⟨_, _⟩ := in_e; obtain ⟨_, _⟩ := in_f; omega
  · obtain ⟨_, _⟩ := in_e; obtain ⟨_, _⟩ := in_f; omega

/-- an address in an embedded form that is also in a local prefix embeds a local IPv4 address:
only `::` and `::1` are in both, and they embed 0.0.0.0 and 0.0.0.1 -/
theorem local_prefix_in_form (n : Nat) (q : Nat × Nat) (e : Nat × Nat × Nat) (q_in : q ∈ LocalV6)
    (e_in : e ∈ Embedded) (in_q : InPrefix 128 n q.1 q.2) (in_e : InPrefix 128 n e.1 e.2.1) :
    IsLocalV4 (EmbeddedV4 n e.2.2) := by
  unfold LocalV6 at q_in
  unfold Embedded at e_in
  simp only [List.mem_cons, List.not_mem_nil, or_false] at q_in e_in
  obtain ⟨q_lo, q_hi⟩ := in_q
  obtain ⟨e_lo, e_hi⟩ := in_e
  rcases q_in with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
  rcases e_in with rfl | rfl | rfl | rfl | rfl <;>
  simp only [Ipv6] at * <;> norm_num at * <;> try omega

  -- what is left: `::` and `::1`, which embed 0.0.0.0 and 0.0.0.1, in 0.0.0.0/8
  all_goals
    refine ⟨(Ipv4 0 0 0 0, 8), by simp [LocalV4], ?_⟩
    simp only [InPrefix, EmbeddedV4, Ipv4]
    omega

/-- Reading the bytes of `y` after a number `n` already read: `n` moved up by the length of `y`, plus the number of `y`. -/
theorem number_fold (y : List Std.U8) (n : Nat) :
    y.foldl (fun n b => 256 * n + b.val) n = n * 256 ^ y.length + Number y := by
  induction y generalizing n with
  | nil => simp [Number]
  | cons b y ih =>
    have start : Number (b :: y) = b.val * 256 ^ y.length + Number y := by
      have := ih b.val
      simpa [Number] using this
    rw [List.foldl_cons, ih, start, List.length_cons, pow_succ]
    ring

/-- The number of two lists of bytes one after the other: the first moved up by the length of the second, plus the second. -/
theorem number_append (x y : List Std.U8) : Number (x ++ y) = Number x * 256 ^ y.length + Number y := by
  unfold Number
  rw [List.foldl_append, number_fold]
  rfl

/-- the four bytes at `off` of a list are the number of the list divided by what comes after them,
modulo 2^32 -/
theorem number_of_four_bytes (l : List Std.U8) (off : Nat) (fits : off + 4 ≤ l.length) :
    Number l / 256 ^ (l.length - off - 4) % 2 ^ 32 = Number ((l.drop off).take 4) := by
  set before := l.take off
  set middle := (l.drop off).take 4
  set after := (l.drop off).drop 4
  have whole : l = before ++ (middle ++ after) := by
    simp only [before, middle, after, List.take_append_drop]
  have middle_length : middle.length = 4 := by simp [middle]; omega
  have after_length : after.length = l.length - off - 4 := by simp [after]; omega
  have middle_small : Number middle < 2 ^ 32 := by
    have := number_lt middle
    rw [middle_length] at this
    simpa using this
  have after_small := number_lt after
  rw [after_length] at after_small
  have : Number l = (Number before * 2 ^ 32 + Number middle) * 256 ^ (l.length - off - 4) + Number after := by
    have same : Number l = Number (before ++ (middle ++ after)) := by rw [← whole]
    rw [same, number_append, number_append, List.length_append, middle_length, after_length, pow_add]
    norm_num
    ring
  rw [this, Nat.mul_comm _ (256 ^ _), Nat.mul_add_div (by positivity) _ _,
    Nat.div_eq_of_lt after_small, Nat.add_zero, Nat.add_mod, Nat.mul_mod_left, Nat.zero_add,
    Nat.mod_mod, Nat.mod_eq_of_lt middle_small]

/-- an address in a form is local exactly when the IPv4 address in it is -/
theorem v6_in_form (n : Nat) (e : Nat × Nat × Nat) (e_in : e ∈ Embedded)
    (in_e : InPrefix 128 n e.1 e.2.1) : IsLocalV6 n ↔ IsLocalV4 (EmbeddedV4 n e.2.2) := by
  constructor
  · rintro (⟨q, q_in, in_q⟩ | ⟨f, f_in, in_f, local_v4⟩)
    · exact local_prefix_in_form n q e q_in e_in in_q in_e
    · rw [forms_unique n e f e_in f_in in_e in_f]
      exact local_v4
  · intro local_v4
    exact Or.inr ⟨e, e_in, in_e, local_v4⟩

/-- the IPv4 address in a form, as a number, is the number of its four bytes -/
theorem embedded_v4_is_its_bytes (a : List Std.U8) (length : a.length = 16) (e : Nat × Nat × Nat)
    (e_in : e ∈ Embedded) :
    EmbeddedV4 (Number a) e.2.2 = Number ((a.drop ((96 - e.2.2) / 8)).take 4) := by
  have shifts : e.2.2 = 0 ∨ e.2.2 = 80 := by
    unfold Embedded at e_in
    simp only [List.mem_cons, List.not_mem_nil, or_false] at e_in
    rcases e_in with rfl | rfl | rfl | rfl | rfl <;> simp
  unfold EmbeddedV4
  rcases shifts with shift | shift <;> rw [shift]
  · have := number_of_four_bytes a 12 (by omega)
    simpa [length] using this
  · have := number_of_four_bytes a 2 (by omega)
    simpa [length] using this

end AddrCore
