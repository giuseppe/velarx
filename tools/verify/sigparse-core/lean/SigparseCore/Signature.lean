-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `signature` answers (`SignatureRead`): the layout of a version 4
-- packet, the subpackets of the two areas, and what the answer says of them.
-- Why it is needed: it joins the theorems of the files before it: the hashed area is read first,
-- the unhashed area after it, and the unhashed one leaves the times and the flags of the answer as
-- the hashed one made them.
-- Read before this file: Subpacket.lean, SubpacketLoop.lean and Values.lean.
-- Notation: as in the files before it.
import SigparseCore.SubpacketLoop
import SigparseCore.Values
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- What a signature that `signature` accepts says of its bytes: the layout of a version 4 signature
packet (the version, the type, the algorithm, the hash, the hashed area with its length, the
unhashed area with its length, 16 bits of the hash, the values), the subpackets that make up the two
areas, and what the answer says of them (the times and the flags are of the hashed area only: the
last subpacket of the kind counts). -/
def SignatureRead (bytes : List Std.U8) (sig : sig.Signature) : Prop :=
  ByteAt bytes 0 = 4 ∧ sig.sig_type.val = ByteAt bytes 1 ∧ sig.algo.val = ByteAt bytes 2 ∧
  sig.hash.val = ByteAt bytes 3 ∧
  sig.hashed.off.val = 6 ∧ sig.hashed.len.val = BigEndian bytes 4 2 ∧
  sig.hashed.off.val + sig.hashed.len.val + 2 ≤ bytes.length ∧
  sig.unhashed.off.val = sig.hashed.off.val + sig.hashed.len.val + 2 ∧
  sig.unhashed.len.val = BigEndian bytes (sig.hashed.off.val + sig.hashed.len.val) 2 ∧
  sig.unhashed.off.val + sig.unhashed.len.val + 2 ≤ bytes.length ∧
  (sig.left16.val.map (fun byte => byte.val) = [ByteAt bytes
    (sig.unhashed.off.val + sig.unhashed.len.val),
    ByteAt bytes (sig.unhashed.off.val + sig.unhashed.len.val + 1)]) ∧
  (∃ finish, Follow (sig.unhashed.off.val + sig.unhashed.len.val + 2) sig.values.val finish ∧
    finish ≤ bytes.length) ∧
  ValueCount sig.algo.val = some sig.values.val.length ∧
  ValuesFrom bytes sig.algo.val (sig.unhashed.off.val + sig.unhashed.len.val + 2) ∧
  ∃ hashed_subs unhashed_subs,
    AreaMadeOf bytes sig.hashed.off.val (sig.hashed.off.val + sig.hashed.len.val) hashed_subs ∧
    AreaMadeOf bytes sig.unhashed.off.val (sig.unhashed.off.val + sig.unhashed.len.val)
      unhashed_subs ∧
    (sig.sub.created.map (fun time => time.val) = (LastOfKind bytes hashed_subs 2).map
      (·.Time bytes)) ∧
    (sig.sub.expires.map (fun time => time.val) = (LastOfKind bytes hashed_subs 3).map
      (·.Time bytes)) ∧
    (sig.sub.key_expires.map (fun time => time.val) =
      (LastOfKind bytes hashed_subs 9).map (·.Time bytes)) ∧
    (sig.sub.key_flags.map (fun flags => flags.val) =
      (LastOfKind bytes hashed_subs 27).map (·.Flags bytes)) ∧
    (∀ sub ∈ hashed_subs, (sub.kind bytes = 2 ∨ sub.kind bytes = 3 ∨ sub.kind bytes = 9) →
      sub.len = 5) ∧
    (∀ sub ∈ hashed_subs, sub.Critical bytes → sub.kind bytes ∈ KnownKinds) ∧
    SpanPairs sig.sub.embedded = ((hashed_subs ++ unhashed_subs).filter
      (fun sub => sub.kind bytes == 32)).map (fun sub => (sub.body + 1, sub.len - 1)) ∧
    (∀ span, sig.sub.issuer_fpr = some span →
      span.off.val + span.len.val ≤ sig.unhashed.off.val + sig.unhashed.len.val)

/-- The byte at a position that is in the bytes is the number the list has there. -/
theorem byte_at_of_index (bytes : List Std.U8) (p : Nat) (inside : p < bytes.length) :
    ByteAt bytes p = (bytes[p]).val := by
  simp [ByteAt, inside]

/-- `signature` reads a signature packet (`SignatureRead`), and returns. -/
theorem signature_reads (body : Slice Std.U8) :
    sig.signature body ⦃ r => ∀ signature, r = core.result.Result.Ok signature →
      SignatureRead body.val signature ⦄ := by
  unfold sig.signature
  have := body.property
  step as ⟨ empty, hempty ⟩
  split
  · simp [WP.spec_ok]
  · rename_i not_empty
    have not_empty : ¬ body.val.length = 0 := fun nothing => not_empty
      (by simpa using hempty.mpr nothing)
    step as ⟨ version, hversion ⟩
    split
    · simp [WP.spec_ok]
    · rename_i is_four
      have is_four : version.val = 4 := by scalar_tac
      step with be_reads as ⟨ r, ok_case, err_case ⟩
      cases r with
      | Ok hashed_len =>
        obtain ⟨fits_len, hashed_len_is⟩ := ok_case hashed_len rfl
        simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
        step with take_gives_the_span as ⟨ r, taken, refused ⟩
        cases r with
        | Ok hashed =>
          obtain ⟨hashed_off, hashed_len_eq, hashed_fits⟩ := taken hashed rfl
          have hashed_off_val : hashed.off.val = 6 := by simpa using congrArg UScalar.val hashed_off
          have hashed_len_val : hashed.len.val = hashed_len.val
            := congrArg UScalar.val hashed_len_eq
          simp only [Std.bind_ok]
          generalize hstart : sig.Subpackets.mk none none none none none none
            (alloc.vec.Vec.new Span) = start
          have nothing : start.created = none := by rw [← hstart]
          have no_expires : start.expires = none := by rw [← hstart]
          have no_key_expires : start.key_expires = none := by rw [← hstart]
          have no_flags : start.key_flags = none := by rw [← hstart]
          have no_fingerprint : start.issuer_fpr = none := by rw [← hstart]
          have no_embedded : start.embedded.val = [] := by rw [← hstart]; rfl
          have hashed_inside : hashed.off.val + hashed.len.val ≤ body.val.length := by omega
          have hashed_room : start.embedded.val.length + hashed.len.val < Usize.max := by
            rw [no_embedded]; simp; omega
          have hashed_empty : true = true → start.created = none ∧ start.expires = none ∧
              start.key_expires = none ∧ start.key_flags = none :=
            fun _ => ⟨nothing, no_expires, no_key_expires, no_flags⟩
          step with subpackets_reads as ⟨ r2, sub1, said1 ⟩
          cases r2 with
          | Ok u =>
            obtain ⟨hashed_subs, hashed_made, said1⟩ := said1 () rfl
            simp only [Std.bind_ok]
            step with span_end_is_the_sum as ⟨ hashed_end, hhashed_end ⟩
            step with be_reads as ⟨ r3, ok3, err3 ⟩
            cases r3 with
            | Ok unhashed_len =>
              obtain ⟨fits_unhashed_len, unhashed_len_is⟩ := ok3 unhashed_len rfl
              simp only [Std.bind_ok]
              step as ⟨ unhashed_at, hunhashed_at ⟩
              step with take_gives_the_span as ⟨ r4, taken4, refused4 ⟩
              cases r4 with
              | Ok unhashed =>
                obtain ⟨unhashed_off, unhashed_len_eq, unhashed_fits⟩ := taken4 unhashed rfl
                have unhashed_off_val : unhashed.off.val = hashed_end.val + 2 := by
                  rw [congrArg UScalar.val unhashed_off]; exact hunhashed_at
                have unhashed_len_val : unhashed.len.val = unhashed_len.val :=
                  congrArg UScalar.val unhashed_len_eq
                simp only [Std.bind_ok]
                have hashed_count := subs_run_count _ _ _ _ _ hashed_made
                have embedded_count : sub1.embedded.val.length ≤ hashed.len.val := by
                  have pairs := said1.2.2.2.2.2.1
                  have := congrArg List.length pairs
                  simp only [SpanPairs, List.length_map, List.length_append, no_embedded,
                    List.length_nil, zero_add] at this
                  have := List.length_filter_le (fun sub => sub.kind body.val == 32) hashed_subs
                  omega
                have unhashed_inside : unhashed.off.val + unhashed.len.val ≤ body.val.length
                  := by omega
                have unhashed_room : sub1.embedded.val.length + unhashed.len.val < Usize.max := by
                  omega
                have unhashed_empty : false = true → sub1.created = none ∧ sub1.expires = none ∧
                    sub1.key_expires = none ∧ sub1.key_flags = none := fun same => by simp at same
                step with subpackets_reads as ⟨ r5, sub2, said2 ⟩
                cases r5 with
                | Ok u2 =>
                  obtain ⟨unhashed_subs, unhashed_made, said2⟩ := said2 () rfl
                  simp only [Std.bind_ok]
                  step with span_end_is_the_sum as ⟨ unhashed_end, hunhashed_end ⟩
                  step with take_gives_the_span as ⟨ r6, taken6, refused6 ⟩
                  cases r6 with
                  | Ok left =>
                    obtain ⟨left_off, left_len, left_fits⟩ := taken6 left rfl
                    have left_off_val : left.off.val = unhashed_end.val :=
                      congrArg UScalar.val left_off
                    simp only [Std.bind_ok]
                    step as ⟨ algo, halgo ⟩
                    step with integers_count as ⟨ r7, counted ⟩
                    cases r7 with
                    | Ok n =>
                      obtain ⟨value_count, ed_n⟩ := counted n rfl
                      simp only [Std.bind_ok]
                      step with span_end_is_the_sum as ⟨ values_at, hvalues_at ⟩
                      step with values_reads as ⟨ r8, values_ok ⟩
                      cases r8 with
                      | Ok values =>
                        obtain ⟨finish, follow, finish_fits, values_len, ed_there, ints_there⟩ :=
                          values_ok values rfl
                        simp only [Std.bind_ok]
                        step as ⟨ sig_type, hsig_type ⟩
                        step as ⟨ hash, hhash ⟩
                        step as ⟨ left_0, hleft_0 ⟩
                        step as ⟨ left_next, hleft_next ⟩
                        step as ⟨ left_1, hleft_1 ⟩
                        simp only [core.result.Result.Ok.injEq]
                        rintro signature rfl
                        have in_left : left.off.val + 1 < body.val.length := by omega
                        have in_head : 3 < body.val.length := by omega
                        unfold SignatureRead
                        simp only
                        have hashed_end_val : hashed_end.val = hashed.off.val + hashed.len.val
                          := hhashed_end
                        have in_0 : 0 < body.val.length := by omega
                        have in_1 : 1 < body.val.length := by omega
                        have in_2 : 2 < body.val.length := by omega
                        have in_3 : 3 < body.val.length := by omega
                        have left_off_is : left.off.val = unhashed.off.val + unhashed.len.val := by
                          rw [left_off_val, hunhashed_end]
                        have values_at_is : values_at.val = left.off.val + 2 := by
                          rw [hvalues_at]; simp [left_len]
                        refine ⟨?_, ?_, ?_, ?_, hashed_off_val, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
                          ?_⟩
                        · rw [byte_at_of_index _ _ in_0, ← hversion]; exact is_four
                        · rw [byte_at_of_index _ _ in_1, hsig_type]
                        · rw [byte_at_of_index _ _ in_2, halgo]
                        · rw [byte_at_of_index _ _ in_3, hhash]
                        · rw [hashed_len_val, hashed_len_is]
                        · omega
                        · omega
                        · rw [← hashed_end_val, unhashed_len_val, unhashed_len_is]
                        · omega
                        · have first : ByteAt body.val (unhashed.off.val + unhashed.len.val)
                          = left_0.val := by
                            rw [← left_off_is, byte_at_of_index _ _ (by omega), hleft_0]
                          have second : ByteAt body.val (unhashed.off.val + unhashed.len.val + 1) =
                              left_1.val := by
                            rw [← left_off_is, byte_at_of_index _ _ in_left, hleft_1]
                            simp only [hleft_next]
                          rw [first, second]
                          rfl
                        · refine ⟨finish, ?_, finish_fits⟩
                          rw [← show values_at.val
                            = unhashed.off.val + unhashed.len.val + 2 by omega]
                          exact follow
                        · rw [values_len]
                          exact value_count
                        · have values_start : values_at.val =
                              unhashed.off.val + unhashed.len.val + 2 := by omega
                          unfold ValuesFrom
                          rw [value_count, ← values_start]
                          dsimp only
                          split
                          · rename_i is_ed
                            exact ed_there is_ed
                          · rename_i not_ed
                            simpa [not_ed] using ints_there not_ed
                        · obtain ⟨c1, c2, c3, c4, c5, c6, c7, c8⟩ := said1
                          obtain ⟨d1, d2, d3, d4, d5, d6, d7, d8⟩ := said2
                          simp only [TimeSaid, FlagsSaid, ite_true] at c1 c2 c3 c4
                          simp only [TimeSaid, FlagsSaid, Bool.false_eq_true,
                            ite_false] at d1 d2 d3 d4
                          refine ⟨hashed_subs, unhashed_subs, hashed_made, unhashed_made, ?_, ?_,
                            ?_, ?_,
                            c5 rfl, c8 rfl, ?_, ?_⟩
                          · rw [d1]; exact c1
                          · rw [d2]; exact c2
                          · rw [d3]; exact c3
                          · rw [d4]; exact c4
                          · rw [d6, c6, List.filter_append, List.map_append]
                            simp [SpanPairs, no_embedded]
                          · intro span found
                            rcases d7 span found with before | inside_unhashed
                            · rcases c7 span before with start_one | inside_hashed
                              · rw [no_fingerprint] at start_one
                                simp at start_one
                              · omega
                            · exact inside_unhashed
                      | Err e =>
                        simp [
                    core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
                    | Err e =>
                      simp [
                    core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
                  | Err e =>
                    simp [
                    core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
                | Err e =>
                  simp [
                    core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
              | Err e =>
                simp [
              core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
            | Err e =>
              simp [
              core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
          | Err e =>
            simp [
              core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
        | Err e =>
          simp [
              core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
      | Err e =>
        simp [core.result.Result.Insts.CoreOpsTry.branch,
              core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]

/-- `signature` does not refuse a well formed signature packet (`WellFormedSignature`): it returns
with an answer.  (The converse of `signature_reads`, which says what an answer means.) -/
theorem signature_accepts (body : Slice Std.U8) (good : WellFormedSignature body.val) :
    sig.signature body ⦃ r => ∃ signature, r = core.result.Result.Ok signature ⦄ := by
  obtain ⟨version_four, hashed_inside, ⟨hashed_subs, hashed_made, hashed_fine⟩, unhashed_inside,
    ⟨unhashed_subs, unhashed_made⟩, values_there⟩ := good
  simp only [UnhashedEnd, HashedEnd] at *
  unfold sig.signature
  have := body.property
  have not_empty : ¬ body.val.length = 0 := by
    intro nothing
    simp [ByteAt, nothing] at version_four
  have in_0 : 0 < body.val.length := by omega
  step as ⟨ empty, hempty ⟩
  split
  · rename_i is_empty
    exact absurd (by simpa using hempty.mp (by simpa using is_empty)) not_empty
  · rename_i not_empty'
    step as ⟨ version, hversion ⟩
    have is_four : version.val = 4 := by
      rw [hversion, ← byte_at_of_index _ _ in_0]
      exact version_four
    split
    · rename_i not_four
      have : version = 4#u8 := UScalar.eq_of_val_eq (by simpa using is_four)
      simp [this] at not_four
    · step with be_reads as ⟨ r, ok_case, err_case ⟩
      cases r with
      | Err e =>
        have := err_case e rfl
        omega
      | Ok hashed_len =>
        obtain ⟨fits_len, hashed_len_is⟩ := ok_case hashed_len rfl
        simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
        step with take_gives_the_span as ⟨ r, taken, refused ⟩
        cases r with
        | Err e =>
          have := refused e rfl
          omega
        | Ok hashed =>
          obtain ⟨hashed_off, hashed_len_eq, hashed_fits⟩ := taken hashed rfl
          have hashed_off_val : hashed.off.val = 6 := by simpa using congrArg UScalar.val hashed_off
          have hashed_len_val : hashed.len.val = hashed_len.val
            := congrArg UScalar.val hashed_len_eq
          simp only [Std.bind_ok]
          generalize hstart : sig.Subpackets.mk none none none none none none
            (alloc.vec.Vec.new Span) = start
          have nothing : start.created = none := by rw [← hstart]
          have no_expires : start.expires = none := by rw [← hstart]
          have no_key_expires : start.key_expires = none := by rw [← hstart]
          have no_flags : start.key_flags = none := by rw [← hstart]
          have no_embedded : start.embedded.val = [] := by rw [← hstart]; rfl
          have hashed_room : start.embedded.val.length + hashed.len.val < Usize.max := by
            rw [no_embedded]; simp; omega
          have hashed_empty : true = true → start.created = none ∧ start.expires = none ∧
              start.key_expires = none ∧ start.key_flags = none :=
            fun _ => ⟨nothing, no_expires, no_key_expires, no_flags⟩
          have hashed_made_here : AreaMadeOf body.val hashed.off.val
              (hashed.off.val + hashed.len.val) hashed_subs := by
            rw [hashed_off_val, hashed_len_val, hashed_len_is]
            exact hashed_made
          have both := WP.spec_and
            (subpackets_reads body hashed true start (by omega) hashed_room hashed_empty)
            (subpackets_accepts body hashed true start (by omega) hashed_room hashed_subs
              hashed_made_here (fun _ => hashed_fine))
          step with both as ⟨ r2, sub1, said1, u, hu ⟩
          obtain ⟨hashed_subs', hashed_made', said_hashed⟩ := said1 u hu
          subst hu
          simp only [Std.bind_ok]
          step with span_end_is_the_sum as ⟨ hashed_end, hhashed_end ⟩
          have hashed_end_is : hashed_end.val = 6 + BigEndian body.val 4 2 := by
            rw [hhashed_end, hashed_off_val, hashed_len_val, hashed_len_is]
          step with be_reads as ⟨ r3, ok3, err3 ⟩
          cases r3 with
          | Err e =>
            have := err3 e rfl
            omega
          | Ok unhashed_len =>
            obtain ⟨fits_unhashed_len, unhashed_len_is⟩ := ok3 unhashed_len rfl
            rw [hashed_end_is] at unhashed_len_is fits_unhashed_len
            simp only [Std.bind_ok]
            step as ⟨ unhashed_at, hunhashed_at ⟩
            step with take_gives_the_span as ⟨ r4, taken4, refused4 ⟩
            cases r4 with
            | Err e =>
              have := refused4 e rfl
              omega
            | Ok unhashed =>
              obtain ⟨unhashed_off, unhashed_len_eq, unhashed_fits⟩ := taken4 unhashed rfl
              have hashed_end_val : hashed_end.val = hashed.off.val + hashed.len.val
                := hhashed_end
              have unhashed_off_val : unhashed.off.val = hashed_end.val + 2 := by
                rw [congrArg UScalar.val unhashed_off]; exact hunhashed_at
              have unhashed_len_val : unhashed.len.val = unhashed_len.val :=
                congrArg UScalar.val unhashed_len_eq
              simp only [Std.bind_ok]
              have hashed_count := subs_run_count _ _ _ _ _ hashed_made'
              have embedded_count : sub1.embedded.val.length ≤ hashed.len.val := by
                have pairs := said_hashed.2.2.2.2.2.1
                have := congrArg List.length pairs
                simp only [SpanPairs, List.length_map, List.length_append, no_embedded,
                  List.length_nil, zero_add] at this
                have := List.length_filter_le (fun sub => sub.kind body.val == 32) hashed_subs'
                omega
              have unhashed_room : sub1.embedded.val.length + unhashed.len.val < Usize.max := by
                omega
              have unhashed_made_here : AreaMadeOf body.val unhashed.off.val
                  (unhashed.off.val + unhashed.len.val) unhashed_subs := by
                rw [unhashed_off_val, unhashed_len_val, unhashed_len_is, hashed_end_val,
                  hashed_off_val, hashed_len_val, hashed_len_is]
                exact unhashed_made
              have both2 := WP.spec_and
                (subpackets_reads body unhashed false sub1 (by omega) unhashed_room
                  (fun same => by simp at same))
                (subpackets_accepts body unhashed false sub1 (by omega) unhashed_room
                  unhashed_subs unhashed_made_here (fun same => by simp at same))
              step with both2 as ⟨ r5, sub2, said2, u2, hu2 ⟩
              subst hu2
              simp only [Std.bind_ok]
              step with span_end_is_the_sum as ⟨ unhashed_end, hunhashed_end ⟩
              step with take_gives_the_span as ⟨ r6, taken6, refused6 ⟩
              cases r6 with
              | Err e =>
                have := refused6 e rfl
                omega
              | Ok left =>
                obtain ⟨left_off, left_len, left_fits⟩ := taken6 left rfl
                have left_off_val : left.off.val = unhashed_end.val :=
                  congrArg UScalar.val left_off
                simp only [Std.bind_ok]
                step as ⟨ algo, halgo ⟩
                step with integers_count as ⟨ r7, counted, counted_err ⟩
                cases r7 with
                | Err e =>
                  have none_count := counted_err e rfl
                  have algo_is : ByteAt body.val 2 = algo.val := by
                    rw [halgo, ← byte_at_of_index body.val 2 (by omega)]
                  rw [algo_is] at values_there
                  simp [ValuesFrom, none_count] at values_there
                | Ok n =>
                  obtain ⟨value_count, ed_n⟩ := counted n rfl
                  simp only [Std.bind_ok]
                  step with span_end_is_the_sum as ⟨ values_at, hvalues_at ⟩
                  have algo_is : ByteAt body.val 2 = algo.val := by
                    rw [halgo, ← byte_at_of_index body.val 2 (by omega)]
                  rw [algo_is] at values_there
                  simp only [ValuesFrom, value_count] at values_there
                  have left_len_val : left.len.val = 2 := by
                    simpa using congrArg UScalar.val left_len
                  have values_pos : 6 + BigEndian body.val 4 2 + 2 +
                      BigEndian body.val (6 + BigEndian body.val 4 2) 2 + 2 = values_at.val := by
                    omega
                  rw [values_pos] at values_there
                  have values_accept := values_accepts body values_at algo n ed_n
                    (fun is_ed => by simpa [is_ed] using values_there)
                    (fun not_ed => by simpa [not_ed] using values_there)
                  step with values_accept as ⟨ r8, vs, hvs ⟩
                  subst hvs
                  simp only [Std.bind_ok]
                  have in_1 : 1 < body.val.length := by omega
                  have in_3 : 3 < body.val.length := by omega
                  have in_left : left.off.val + 1 < body.val.length := by omega
                  step as ⟨ sig_type, hsig_type ⟩
                  step as ⟨ hash, hhash ⟩
                  step as ⟨ left_0, hleft_0 ⟩
                  step as ⟨ left_next, hleft_next ⟩
                  step as ⟨ left_1, hleft_1 ⟩
                  exact ⟨_, rfl⟩

end SigparseCore
