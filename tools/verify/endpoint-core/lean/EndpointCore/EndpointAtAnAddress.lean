-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `folded`, `endpoint` and `at` make: the host as an endpoint says it
-- (the Hub under its API host), the endpoint for a host and a path with the flags it was given and
-- the credentials of the command line only when its host is the host the user named, and the
-- endpoint at an address `host/path` (nothing when the address has no `/`).
-- Why it is needed: every endpoint of the answer, the registry and each mirror, is made by `at`.
-- Read before this file: Spec.lean, ComparingBytes.lean, CopyingBytes.lean, ScanningTheName.lean.
-- Notation: `step as ⟨ x, hx ⟩` runs one line of a Rust function and names its result `x` and what
-- is known of it `hx`; `l.takeWhile p` and `l.dropWhile p` are the elements of `l` before and from
-- the first one that does not satisfy `p`.
import EndpointCore.Spec
import EndpointCore.ComparingBytes
import EndpointCore.CopyingBytes
import EndpointCore.ScanningTheName
import EndpointCore.TakeWhileFacts
import EndpointCore.VectorsAreSlices

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- **`folded`** makes the host as an endpoint says it: `registry-1.docker.io` for `docker.io`, the
host itself for another. -/
theorem folded_is_the_host_of_the_endpoint (host : Slice Std.U8) :
    folded host ⦃ v => v.val = Folded host.val ⦄ := by
  unfold folded
  step as ⟨ hub, is_hub ⟩
  step with same_is_equality as ⟨ is_same, is_same_says ⟩
  by_cases same : is_same = true
  · simp only [same, ite_true]
    step as ⟨ api, is_api ⟩
    step with tail_is_the_end as ⟨ copy, is_copy ⟩
    have : host.val = HubName := by
      have := is_same_says.mp same
      rw [this, is_hub]
      rfl
    simp [Folded, this, is_copy, is_api, HubApi]
  · have not_same : is_same = false := by simpa using same
    simp only [not_same, Bool.false_eq_true, ↓reduceIte]
    step with tail_is_the_end as ⟨ copy, is_copy ⟩
    have : ¬ host.val = HubName := by
      intro eq
      exact same (is_same_says.mpr (by rw [eq, is_hub]; rfl))
    simp [Folded, this, is_copy]

/-- Where the scan to the first `/` stops short of the end of the name there is a `/`, and only
then. -/
theorem a_slash_is_there_when_the_scan_stops_short (ref : Bytes) :
    (ref.takeWhile fun b => b ≠ Slash).length < ref.length ↔ Slash ∈ ref := by
  rw [take_while_stops_short]
  constructor
  · rintro ⟨x, x_in, no⟩
    have : x = Slash := not_not.mp (of_decide_eq_false no)
    rw [this] at x_in
    exact x_in
  · intro is_in
    exact ⟨Slash, is_in, by simp⟩

/-- **`endpoint`** makes the endpoint for a host and a path with the flags it was given: the host
as an endpoint says it, the path, no digest, and the credentials of the command line exactly when
this host is the host the user named (`typed`, folded in the same way). -/
theorem endpoint_has_what_it_was_given (host path typed : Slice Std.U8)
    (insecure allow_private : Bool) :
    endpoint host path insecure allow_private typed ⦃ e =>
      e.host.val = Folded host.val ∧ e.path.val = path.val ∧ e.insecure = insecure ∧
      e.allow_private = allow_private ∧
      (e.creds = Creds.CommandLine ↔ e.host.val = Folded typed.val) ∧ e.by_digest = false ⦄ := by
  unfold endpoint
  step with folded_is_the_host_of_the_endpoint as ⟨ host1, is_host1 ⟩
  step with folded_is_the_host_of_the_endpoint as ⟨ typed1, is_typed1 ⟩
  step with same_is_equality as ⟨ is_same, is_same_says ⟩
  by_cases same : is_same = true
  · simp only [same, ite_true]
    step with tail_is_the_end as ⟨ copy, is_copy ⟩
    refine ⟨is_host1, by simpa using is_copy, ?_⟩
    simp only [true_iff]
    simpa [is_typed1] using is_same_says.mp same
  · have not_same : is_same = false := by simpa using same
    simp only [not_same, Bool.false_eq_true, ↓reduceIte]
    step with tail_is_the_end as ⟨ copy, is_copy ⟩
    refine ⟨is_host1, by simpa using is_copy, ?_⟩
    constructor
    · intro absurd
      cases absurd
    · intro same_host
      exact absurd (is_same_says.mpr (by simpa [is_typed1] using same_host)) same

/-- **`at`** makes the endpoint at an address `host/path`, with the flags it was given: there is
none when the address has no `/`; else it is at the host before the first `/` and the path after
it (`Located`). -/
theorem at_makes_the_endpoint_of_an_address (ref typed : Slice Std.U8) (insecure reach : Bool) :
    «at» ref insecure reach typed ⦃ o =>
      (Slash ∉ ref.val ∧ o = none) ∨
      ∃ e, Slash ∈ ref.val ∧ o = some e ∧ Located ref.val = some e.Where ∧
        e.insecure = insecure ∧ e.allow_private = reach ∧
        (e.creds = Creds.CommandLine ↔ e.host.val = Folded typed.val) ∧ e.by_digest = false ⦄ := by
  unfold «at»
  step with slash_goes_to_the_first as ⟨ i, is_i ⟩
  have ref_length : ref.val.length = ref.length := rfl
  have ref_len : (Slice.len ref).val = ref.length := Slice.len_val ref
  by_cases at_end : i = Slice.len ref
  · simp only [at_end, ite_true]
    refine (WP.spec_ok _).mpr (Or.inl ⟨?_, rfl⟩)
    rw [← a_slash_is_there_when_the_scan_stops_short]
    have : i.val = ref.length := by rw [at_end, ref_len]
    omega
  · simp only [at_end, ite_false]
    have short : i.val < ref.length := by
      have := take_while_is_not_longer (fun b => decide (b ≠ Slash)) ref.val
      have : i.val ≠ ref.length := fun same => at_end (UScalar.eq_of_val_eq (by rw [same, ref_len]))
      omega
    have is_in : Slash ∈ ref.val := by
      rw [← a_slash_is_there_when_the_scan_stops_short]
      omega
    step as ⟨ host_part, is_host_part, host_part_length ⟩
    step as ⟨ next, is_next ⟩
    step as ⟨ path_part, is_path_part, path_part_length ⟩
    step with endpoint_has_what_it_was_given as
      ⟨ e, host_is, path_is, e_insecure, e_reach, e_creds, e_digest ⟩
    refine Or.inr ⟨e, is_in, rfl, ?_, e_insecure, e_reach, e_creds, e_digest⟩
    have host_bytes : host_part.val = ref.val.takeWhile (fun b => decide (b ≠ Slash)) := by
      rw [is_host_part, List.slice_zero_j, is_i]
      exact take_while_is_the_beginning _ _
    have path_bytes : e.path.val = (ref.val.dropWhile (fun b => decide (b ≠ Slash))).drop 1 := by
      rw [path_is, is_path_part, is_next, drop_while_is_the_rest, List.drop_drop, is_i,
        Nat.add_comm]
    simp [Located, is_in, Endpoint.Where, host_is, host_bytes, path_bytes]

end EndpointCore
