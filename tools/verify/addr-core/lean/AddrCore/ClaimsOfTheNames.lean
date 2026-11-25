-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about named classes and addresses
--   (`TheNamedV4ClassesAreLocal`, `TheMetadataAddressesAreLocal`, `TheNamedV6ClassesAreLocal`).
-- Why it is needed: they say which addresses a reader knows by name are refused: the loopback, the private
--   networks, the metadata services of the clouds.
-- Read before this file: Spec.lean, ClaimsOfTheV6.lean.
-- Notation: `omega` settles statements of whole numbers with sums and comparisons; `simp only [Ipv4]`
--   writes `Ipv4 a b c d` as the number `a * 2^24 + ...`.
import AddrCore.ClaimsOfTheV6
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

/-- a number is local exactly when it is in one of the prefixes, written out -/
theorem is_local_v4_as_numbers (n : Nat) : IsLocalV4 n ↔
    (Ipv4 0 0 0 0 ≤ n ∧ n < Ipv4 0 0 0 0 + 2 ^ 24) ∨ (Ipv4 10 0 0 0 ≤ n ∧ n < Ipv4 10 0 0 0 + 2 ^ 24) ∨
    (Ipv4 100 64 0 0 ≤ n ∧ n < Ipv4 100 64 0 0 + 2 ^ 22) ∨ (Ipv4 127 0 0 0 ≤ n ∧ n < Ipv4 127 0 0 0 + 2 ^ 24) ∨
    (Ipv4 169 254 0 0 ≤ n ∧ n < Ipv4 169 254 0 0 + 2 ^ 16) ∨ (Ipv4 172 16 0 0 ≤ n ∧ n < Ipv4 172 16 0 0 + 2 ^ 20) ∨
    (Ipv4 192 168 0 0 ≤ n ∧ n < Ipv4 192 168 0 0 + 2 ^ 16) ∨ (Ipv4 192 0 0 0 ≤ n ∧ n < Ipv4 192 0 0 0 + 2 ^ 8) ∨
    (Ipv4 192 0 2 0 ≤ n ∧ n < Ipv4 192 0 2 0 + 2 ^ 8) ∨ (Ipv4 198 18 0 0 ≤ n ∧ n < Ipv4 198 18 0 0 + 2 ^ 17) ∨
    (Ipv4 198 51 100 0 ≤ n ∧ n < Ipv4 198 51 100 0 + 2 ^ 8) ∨ (Ipv4 203 0 113 0 ≤ n ∧ n < Ipv4 203 0 113 0 + 2 ^ 8) ∨
    (Ipv4 168 63 129 16 ≤ n ∧ n < Ipv4 168 63 129 16 + 2 ^ 0) ∨ (Ipv4 224 0 0 0 ≤ n ∧ n < Ipv4 224 0 0 0 + 2 ^ 28) ∨
    (Ipv4 240 0 0 0 ≤ n ∧ n < Ipv4 240 0 0 0 + 2 ^ 28) := by
  simp [IsLocalV4, LocalV4, InPrefix]

/-- Proof of `TheNamedV4ClassesAreLocal`: each range lies inside a prefix of the table, which `omega` checks on the numbers. -/
theorem the_named_v4_classes_are_local : TheNamedV4ClassesAreLocal := by
  intro a
  refine WP.spec_mono (local_v4_is a) ?_
  intro r same
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩ <;> intro inside <;> apply same.mpr <;>
  rw [is_local_v4_as_numbers] <;> simp only [Ipv4] at inside ⊢ <;> omega

/-- Proof of `TheMetadataAddressesAreLocal`: each address lies inside a prefix of the table. -/
theorem the_metadata_addresses_are_local : TheMetadataAddressesAreLocal := by
  intro a
  refine WP.spec_mono (local_v4_is a) ?_
  intro r same
  refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;> intro is_it <;> apply same.mpr <;>
  rw [is_local_v4_as_numbers] <;> simp only [Ipv4] at is_it ⊢ <;> omega

/-- Proof of `TheNamedV6ClassesAreLocal`: each class is a prefix of the table, so an address in it is in a prefix of `LocalV6`. -/
theorem the_named_v6_classes_are_local : TheNamedV6ClassesAreLocal := by
  intro a
  refine WP.spec_mono (local_v6_is a) ?_
  intro r same
  have local_in (q : Nat × Nat) (q_in : q ∈ LocalV6) (inside : InPrefix 128 (Number a.val) q.1 q.2) :
      r = true := same.mpr (Or.inl ⟨q, q_in, inside⟩)
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · intro is_it
    exact local_in (Ipv6 0 0 0 0 0 0 0 0, 128) (by simp [LocalV6]) (by simp [InPrefix, is_it])
  · intro is_it
    exact local_in (Ipv6 0 0 0 0 0 0 0 1, 128) (by simp [LocalV6]) (by simp [InPrefix, is_it])
  · exact local_in (Ipv6 0xfc00 0 0 0 0 0 0 0, 7) (by simp [LocalV6])
  · exact local_in (Ipv6 0xfe80 0 0 0 0 0 0 0, 10) (by simp [LocalV6])
  · exact local_in (Ipv6 0xfec0 0 0 0 0 0 0 0, 10) (by simp [LocalV6])
  · exact local_in (Ipv6 0xff00 0 0 0 0 0 0 0, 8) (by simp [LocalV6])
  · exact local_in (Ipv6 0x100 0 0 0 0 0 0 0, 64) (by simp [LocalV6])
  · exact local_in (Ipv6 0x2001 0 0 0 0 0 0 0, 32) (by simp [LocalV6])
  · exact local_in (Ipv6 0x2001 2 0 0 0 0 0 0, 48) (by simp [LocalV6])
  · exact local_in (Ipv6 0x2001 0xdb8 0 0 0 0 0 0, 32) (by simp [LocalV6])
  · exact local_in (Ipv6 0x64 0xff9b 1 0 0 0 0 0, 48) (by simp [LocalV6])

end AddrCore
