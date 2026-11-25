-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `worked_examples`, the examples of Spec.lean: the hostile text
-- of the report in both orders, a tie, numbers that are not newer, and an issuer of which
-- nothing is held.  Each is worked out from the claim about which parts are adopted
-- (`the_places_are_the_adopted`), by reading what `Adopts` says of the parts of the example, not by
-- running the code.
-- Why it is needed: Theorems.lean ties each claim of Spec.lean to a proof, and this is the one for
-- the examples; they show that the claims can be met by the cases that matter (the junk that
-- claims the highest number is not adopted and hides nothing, the same lists are adopted
-- whatever the order).
-- Read before this file: Spec.lean, ClaimsOfWhichPartsAreAdopted.lean.
-- Notation: `simp [...]` computes with the facts it is given; `decide` computes a statement about
-- small numbers.
import RevokeCore.ClaimsOfWhichPartsAreAdopted

open Aeneas Aeneas.Std Result velarx_revoke_core

open Classical

namespace RevokeCore

/-- The parts of an example as a slice are the list of the example. -/
theorem parts_of_val (parts : List Part) (few : parts.length ≤ 255) :
    (PartsOf parts few).val = parts := Slice.from_val _ _

/-- The entries held of an example as a slice are the list of the example. -/
theorem held_of_list_val (held : List Held) (few : held.length ≤ 255) :
    (HeldOfList held few).val = held := Slice.from_val _ _

theorem worked_examples : WorkedExamples := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩ <;>
  · refine WP.spec_mono (the_places_are_the_adopted _ _) ?_
    intro r ⟨places, _⟩
    simp only [places, parts_of_val, held_of_list_val]
    simp [AdoptedAt, Adopts, NewerThanHeld, NumbersHeld, PartOf, HeldWith]

end RevokeCore
