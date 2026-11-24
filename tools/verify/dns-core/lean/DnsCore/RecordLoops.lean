-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loop of `reply` that writes the records does: it writes the
-- records in order, each whole, as long as they fit under the limit, counts them, and stops at
-- the first that does not fit.
--
-- Why it is needed: this is where a reply is made no longer than the size and where the count of
-- the header is the number of records written.  `RecordOf` (Spec.lean) says what a whole record is.
--
-- Read before this file: Spec.lean, Words.lean, and `reply` in lib.rs.
--
-- Notation: as in LabelLoop.lean; `rrs.val.take n` is the first `n` records; `l.flatMap f` is the
-- lists `f` of each, one after the other.
import DnsCore.Words

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- The loop of `reply` that copies the data of a record copies its bytes. -/
theorem data_loop_copies (rrs : Slice Rr) (out : alloc.vec.Vec Std.U8) (k n j : Std.Usize)
    (record : k.val < rrs.length) (length : n.val = rrs.val[k.val].data.length)
    (in_order : j.val ≤ n.val) (room : out.length + (n.val - j.val) ≤ 65535) :
    reply_loop1_loop0 rrs out k n j ⦃ r =>
      Bytes r.val = Bytes out.val ++
        ((Bytes rrs.val[k.val].data.val).drop j.val).take (n.val - j.val) ⦄ := by
  unfold reply_loop1_loop0
  apply loop.spec_decr_nat (fun q => n.val - q.2.val)
    (fun q => q.2.val ≤ n.val ∧ j.val ≤ q.2.val ∧
      q.1.length ≤ out.length + (q.2.val - j.val) ∧
      Bytes q.1.val = Bytes out.val ++
        ((Bytes rrs.val[k.val].data.val).drop j.val).take (q.2.val - j.val))
  · rintro ⟨written, p⟩ ⟨p_le, ge_j, short, copied⟩
    simp only at p_le ge_j short copied ⊢
    unfold reply_loop1_loop0.body
    split
    · rename_i below
      step as ⟨ record, record_post ⟩
      step as ⟨ byte, byte_post ⟩
      step as ⟨ written', written'_post ⟩
      step as ⟨ p', p'_post ⟩
      have below' : p.val < n.val := by scalar_tac
      have data_inside : p.val < rrs.val[k.val].data.length := by omega
      have byte_is : (Bytes rrs.val[k.val].data.val)[p.val]? = some byte.val := by
        simp [Bytes, byte_post, record_post, List.getElem?_eq_getElem data_inside]
      have taken : ((Bytes rrs.val[k.val].data.val).drop j.val).take (p'.val - j.val) =
          ((Bytes rrs.val[k.val].data.val).drop j.val).take (p.val - j.val) ++ [byte.val] := by
        have : p'.val - j.val = (p.val - j.val) + 1 := by omega
        rw [this, List.take_add_one]
        simp [List.getElem?_drop, byte_is, show j.val + (p.val - j.val) = p.val by omega]
      refine ⟨by omega, by omega, ?_, ?_, by omega⟩
      · have longer : written'.val.length = written.val.length + 1 := by simp [written'_post]
        have same_written : written.length = written.val.length := rfl
        have same_written' : written'.length = written'.val.length := rfl
        omega
      · rw [taken, ← List.append_assoc, ← copied, written'_post]
        simp [Bytes]
    · rename_i not_below
      simp only [WP.spec_ok]
      have : p.val = n.val := by scalar_tac
      rw [copied, this]
  · exact ⟨in_order, Nat.le_refl _, by simp, by simp⟩

/-- A record is 12 bytes and its data. -/
theorem record_length (rr : Rr) : (RecordOf rr).length = 12 + rr.data.length := by
  simp [RecordOf, Bytes]
  omega

/-- The loop of `reply` that writes the records writes the first of them that fit, whole. -/
theorem records_loop_writes_whole_records (rrs : Slice Rr) (limit : Std.Usize)
    (out : alloc.vec.Vec Std.U8) (limit_is_small : limit.val ≤ 65535)
    (fits : out.length ≤ limit.val) :
    reply_loop1 rrs limit out 0#u16 false 0#usize ⦃ r =>
      Bytes r.1.val = Bytes out.val ++ (rrs.val.take r.2.1.val).flatMap RecordOf ∧
      r.1.length ≤ limit.val ∧ r.2.1.val ≤ rrs.length ∧
      (r.2.2 = true ↔ r.2.1.val < rrs.length) ∧
      (r.2.2 = true → ∀ rr, rrs.val[r.2.1.val]? = some rr →
        limit.val < r.1.length + (RecordOf rr).length) ⦄ := by
  unfold reply_loop1
  have rrs_length : (↑rrs : List Rr).length = rrs.length := rfl
  apply loop.spec_decr_nat (fun q => if q.2.2.1 = true then 0 else rrs.length + 1 - q.2.2.2.val)
    (fun q => q.2.1.val = q.2.2.2.val ∧ q.2.2.2.val ≤ rrs.length ∧ q.1.length ≤ limit.val ∧
      out.length + 12 * q.2.2.2.val ≤ q.1.length ∧
      Bytes q.1.val = Bytes out.val ++ (rrs.val.take q.2.2.2.val).flatMap RecordOf ∧
      (q.2.2.1 = true → q.2.2.2.val < rrs.length ∧ ∀ rr, rrs.val[q.2.2.2.val]? = some rr →
        limit.val < q.1.length + (RecordOf rr).length))
  · rintro ⟨written, count, cut, k⟩ ⟨count_is, k_le, written_fits, enough, written_is, stopped⟩
    simp only at count_is k_le written_fits enough written_is stopped ⊢
    unfold reply_loop1.body
    dsimp only
    split
    · rename_i below
      split
      · -- the loop has stopped
        rename_i has_stopped
        simp only [WP.spec_ok]
        obtain ⟨left_out, doesnt_fit⟩ := stopped has_stopped
        refine ⟨by rw [count_is]; exact written_is, written_fits, by omega,
          ⟨fun _ => by omega, fun _ => has_stopped⟩, fun _ => by rw [count_is]; exact doesnt_fit⟩
      · rename_i not_stopped
        step as ⟨ record, record_post ⟩
        have k_below : k.val < rrs.length := by scalar_tac
        have record_is : rrs.val[k.val]? = some record := by
          simp [record_post, List.getElem?_eq_getElem k_below]
        have rr_fixed : RR_FIXED.val = 12 := by simp [global_simps]
        have header : HEADER.val = 12 := header_is_12
        have ttl : TTL.val = 60 := by simp [global_simps]
        have class_in : CLASS_IN.val = 1 := by simp [global_simps]
        have data_length : record.data.length = record.data.val.length := rfl
        have written_length : written.length = written.val.length := rfl
        have data_fits : record.data.val.length ≤ Usize.max := record.data.property
        split
        · -- the data alone is too long
          rename_i too_long
          have doesnt_fit : limit.val < written.length + (RecordOf record).length := by
            rw [record_length]
            scalar_tac
          simp only [WP.spec_ok]
          refine ⟨count_is, k_le, written_fits, enough, written_is,
            fun _ => ⟨k_below, fun rr is_rr => ?_⟩, by simp; omega⟩
          rw [record_is] at is_rr
          obtain rfl := Option.some.inj is_rr
          exact doesnt_fit
        · rename_i not_too_long
          step as ⟨ with_fixed, with_fixed_post ⟩
          step as ⟨ with_data, with_data_post ⟩
          split
          · -- the record does not fit: the loop stops here
            rename_i too_long
            have doesnt_fit : limit.val < written.length + (RecordOf record).length := by
              rw [record_length]
              scalar_tac
            simp only [WP.spec_ok]
            refine ⟨count_is, k_le, written_fits, enough, written_is,
              fun _ => ⟨k_below, fun rr is_rr => ?_⟩, by simp; omega⟩
            rw [record_is] at is_rr
            obtain rfl := Option.some.inj is_rr
            exact doesnt_fit
          · -- the record fits: it is written
            rename_i fits_the_limit
            have room : written.length + 12 + record.data.length ≤ limit.val := by
              scalar_tac
            simp only [lift, bind_ok]
            have usize_big : 100000 ≤ Usize.max := by scalar_tac
            have written_room : written.length + 2 ≤ Usize.max := by omega
            step with push16_writes written _ written_room as ⟨ with_pointer, with_pointer_post ⟩
            have pointer_length := length_after_adding _ _ _ with_pointer_post
            simp only [List.length_cons, List.length_nil] at pointer_length
            step with push16_writes with_pointer record.ty (by omega)
              as ⟨ with_type, with_type_post ⟩
            have type_length := length_after_adding _ _ _ with_type_post
            simp only [List.length_cons, List.length_nil] at type_length
            step with push16_writes with_type CLASS_IN (by omega)
              as ⟨ with_class, with_class_post ⟩
            have class_length := length_after_adding _ _ _ with_class_post
            simp only [List.length_cons, List.length_nil] at class_length
            -- the time to live, 60, is the four bytes 0, 0, 0, 60
            have push_room : ∀ v : alloc.vec.Vec Std.U8, v.length ≤ limit.val →
                v.val.length < Usize.max := fun v small => by
              rw [← vec_length_is_the_list_length]
              omega
            step as ⟨ hours, hours_post ⟩
            have hours_byte : (UScalar.cast .U8 hours).val = 0 := by
              simp [UScalar.cast_val_eq, hours_post, ttl]
            step with alloc.vec.Vec.push_spec with_class _ (push_room _ (by omega))
              as ⟨ with_hours, with_hours_post ⟩
            have hours_bytes : Bytes with_hours.val = Bytes with_class.val ++ [0] := by
              simp [Bytes, with_hours_post, hours_byte]
            have hours_length := length_after_adding_a_byte _ _ _ hours_bytes
            step as ⟨ shifted16, shifted16_post ⟩
            have minutes_byte : (UScalar.cast .U8 (shifted16 &&& 255#u32)).val = 0 := by
              simp [UScalar.cast_val_eq, shifted16_post, ttl]
            step with alloc.vec.Vec.push_spec with_hours _
              (push_room _ (by omega))
              as ⟨ with_minutes, with_minutes_post ⟩
            have minutes_bytes : Bytes with_minutes.val = Bytes with_hours.val ++ [0] := by
              simp [Bytes, with_minutes_post, minutes_byte]
            have minutes_length := length_after_adding_a_byte _ _ _ minutes_bytes
            step as ⟨ shifted8, shifted8_post ⟩
            have seconds_byte : (UScalar.cast .U8 (shifted8 &&& 255#u32)).val = 0 := by
              simp [UScalar.cast_val_eq, shifted8_post, ttl]
            step with alloc.vec.Vec.push_spec with_minutes _
              (push_room _ (by omega))
              as ⟨ with_seconds, with_seconds_post ⟩
            have seconds_bytes : Bytes with_seconds.val = Bytes with_minutes.val ++ [0] := by
              simp [Bytes, with_seconds_post, seconds_byte]
            have seconds_length := length_after_adding_a_byte _ _ _ seconds_bytes
            have last_byte : (UScalar.cast .U8 (TTL &&& 255#u32)).val = 60 := by
              simp [UScalar.cast_val_eq, ttl]
            step with alloc.vec.Vec.push_spec with_seconds _
              (push_room _ (by omega))
              as ⟨ with_ttl, with_ttl_post ⟩
            have ttl_bytes : Bytes with_ttl.val = Bytes with_seconds.val ++ [60] := by
              simp [Bytes, with_ttl_post, last_byte]
            have ttl_length := length_after_adding_a_byte _ _ _ ttl_bytes
            have size_val : (UScalar.cast .U16 record.data.len).val = record.data.length := by
              simp only [UScalar.cast_val_eq]
              have := record.data.property
              scalar_tac
            step with push16_writes with_ttl (UScalar.cast .U16 record.data.len) (by omega)
              as ⟨ with_size, with_size_post ⟩
            have size_length := length_after_adding _ _ _ with_size_post
            simp only [List.length_cons, List.length_nil] at size_length
            have data_len_val : record.data.len.val = record.data.length :=
              alloc.vec.Vec.len_val _
            have with_size_length : with_size.length = written.length + 12 := by omega
            step with data_loop_copies rrs with_size k record.data.len 0#usize k_below
              (by rw [data_len_val, record_post]) (by scalar_tac)
              (by show with_size.length + (record.data.len.val - 0) ≤ 65535; omega)
              as ⟨ with_data_bytes, copied ⟩
            have pointer_value : (49152#u16 ||| UScalar.cast .U16 HEADER).val = 49164 := by
              simp [UScalar.val_or, UScalar.cast_val_eq, header]
            have data_bytes_length : (Bytes record.data.val).length = record.data.length := by
              simp [Bytes]
            have record_written :
                Bytes with_data_bytes.val = Bytes written.val ++ RecordOf record := by
              have same_record : rrs.val[k.val] = record := record_post.symm
              rw [copied, with_size_post, ttl_bytes, seconds_bytes, minutes_bytes, hours_bytes,
                with_class_post, with_type_post, with_pointer_post, pointer_value, size_val,
                same_record, Nat.sub_zero, List.drop_zero, data_len_val,
                List.take_of_length_le (by omega), class_in]
              simp [RecordOf, List.append_assoc]
            have written_length' :
                with_data_bytes.length = written.length + (RecordOf record).length := by
              exact length_after_adding _ _ _ record_written
            rw [record_length] at written_length'
            have count_room : count.val + 1 ≤ U16.max := by scalar_tac
            step as ⟨ count1, count1_post ⟩
            step as ⟨ k1, k1_post ⟩
            refine ⟨by omega, by omega, by omega, by omega, ?_, fun h => absurd h not_stopped, ?_⟩
            · rw [record_written, written_is, List.append_assoc]
              congr 1
              rw [show k1.val = k.val + 1 by omega, List.take_add_one, List.flatMap_append]
              simp [record_is]
            · simp [not_stopped]
              omega
    · -- every record has been looked at
      rename_i past_the_end
      simp only [WP.spec_ok]
      have at_the_end : k.val = rrs.length := by scalar_tac
      have not_cut : cut = false := by
        cases cut
        · rfl
        · exact absurd (stopped rfl).1 (by omega)
      refine ⟨by rw [← count_is] at written_is; exact written_is, written_fits, by omega, ?_,
        fun h => by simp [not_cut] at h⟩
      simp [not_cut]
      omega
  · simp only
    exact ⟨rfl, by simp, fits, by simp, by simp, fun h => by simp at h⟩

end DnsCore
