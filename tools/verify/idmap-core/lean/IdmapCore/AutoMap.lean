-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `auto_map`, the mapping of `--userns=auto`, in the pieces its proof is
-- made of: the loop that adds the extra mappings, and, put together, what the answer is when it is
-- a mapping (`AutoMapAnswer`: it is valid, it uses only the user's extra parent ids and the free
-- ids of the pool, and it maps the container ids asked for), and that it answers with a mapping
-- when there are no extra mappings and the free ids begin with a run of `size` ids.
--
-- Read before this file: Spec.lean, Zip.lean, SortAndMerge.lean, IdSetSubtract.lean,
-- IdSetFindAvailable.lean.
import IdmapCore.Zip
import IdmapCore.SortAndMerge
import IdmapCore.IdSetSubtract
import IdmapCore.IdSetFindAvailable
import IdmapCore.IdSetSize
import IdmapCore.OfMaps
import IdmapCore.Validate
import IdmapCore.ValidMeansFunction
import IdmapCore.Limits

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The loop of `auto_map` that adds the extra entries at the end of the mappings made so far. -/
theorem auto_map_adds_the_extra_entries (extra : Slice Map) (maps : alloc.vec.Vec Map)
    (i : Usize) (bound : i.val ≤ extra.val.length)
    (room : maps.val.length + extra.val.length - i.val ≤ Usize.max) :
    auto_map_loop extra maps i ⦃ r => r.val = maps.val ++ extra.val.drop i.val ⦄ := by
  unfold auto_map_loop
  apply loop.spec_decr_nat (fun q => extra.length - q.2.val)
    (fun q => q.2.val ≤ extra.val.length ∧ q.1.val ++ extra.val.drop q.2.val =
      maps.val ++ extra.val.drop i.val ∧ q.1.val.length + extra.val.length - q.2.val ≤ Usize.max)
  · rintro ⟨out, j⟩ ⟨bound, same, room⟩
    simp only at bound same room ⊢
    unfold auto_map_loop.body
    dsimp only [Slice.len]
    have same_length : extra.length = extra.val.length := rfl
    split
    · rename_i inside
      have inside : j.val < extra.val.length := by scalar_tac
      step as ⟨ m, is_m ⟩
      have room_push : out.val.length < Usize.max := by omega
      step as ⟨ out1, is_out1 ⟩
      step as ⟨ j1, is_j1 ⟩
      refine ⟨by omega, ?_, by simp [is_out1]; omega, by omega⟩
      rw [is_out1, is_j1, List.append_assoc]
      have : extra.val.drop j.val = m :: extra.val.drop (j.val + 1) := by
        rw [List.drop_eq_getElem_cons inside, is_m]
      rw [this] at same
      simpa using same
    · rename_i outside
      have : j.val = extra.val.length := by scalar_tac
      refine (WP.spec_ok _).mpr ?_
      rw [this] at same
      simpa using same
  · exact ⟨bound, rfl, by simpa using room⟩

/-- Exactly `n` ids and exactly `m` ids satisfy the same property only when `n = m`. -/
theorem exactly_ids_is_unique (P : Nat → Prop) (n m : Nat) (one : ExactlyIds P n)
    (other : ExactlyIds P m) : n = m := by
  obtain ⟨ids_n, nodup_n, has_n, len_n⟩ := one
  obtain ⟨ids_m, nodup_m, has_m, len_m⟩ := other
  have : ids_n.Perm ids_m :=
    (List.perm_ext_iff_of_nodup nodup_n nodup_m).mpr (fun id => by rw [has_n, has_m])
  rw [← len_n, ← len_m, this.length_eq]

/-- Ids that satisfy `P` are no more than the ids that satisfy `Q` when each one that satisfies
`P` satisfies `Q`. -/
theorem exactly_ids_in_a_set_are_no_more (P Q : Nat → Prop) (a b : Nat) (some : ExactlyIds P a)
    (more : ExactlyIds Q b) (inside : ∀ id, P id → Q id) : a ≤ b := by
  obtain ⟨ids_a, nodup_a, has_a, len_a⟩ := some
  obtain ⟨ids_b, nodup_b, has_b, len_b⟩ := more
  have := (nodup_a.subperm (fun id in_a =>
    (has_b id).mpr (inside id ((has_a id).mp in_a)))).length_le
  omega

/-- A set that has the `m` ids `first`, `first + 1`, ... has at least `m` ids. -/
theorem a_run_of_ids_is_no_more_than_the_ids (Q : Nat → Prop) (first m b : Nat)
    (more : ExactlyIds Q b) (run : ∀ k, k < m → Q (first + k)) : m ≤ b := by
  refine exactly_ids_in_a_set_are_no_more (fun id => first ≤ id ∧ id < first + m) Q m b
    ⟨List.range' first m, List.nodup_range', fun id => by simp [List.mem_range'_1], by simp⟩
    more (fun id ⟨low, high⟩ => ?_)
  have := run (id - first) (by omega)
  rwa [show first + (id - first) = id by omega] at this

/-- If the first interval of an ordered set starts where the lowest id of the set is, and the
ids that follow it are `n` in a row, the first interval has at least `n` ids (it ends at the first
id past it, which the set cannot have: the next interval begins further). -/
theorem the_first_interval_has_the_run (runs : List (U64 × U64)) (ordered : Ordered runs)
    (first n : Nat) (run : ∀ k, k < n → HasId runs (first + k))
    (lowest : ∀ id, id < first → ¬ HasId runs id) (iv : U64 × U64) (is_first : runs[0]? = some iv) :
    n ≤ iv.2.val - iv.1.val := by
  obtain ⟨rest, is_runs⟩ : ∃ rest, runs = iv :: rest := by
    cases runs with
    | nil => simp at is_first
    | cons head rest =>
      obtain rfl : head = iv := by simpa using is_first
      exact ⟨rest, rfl⟩
  subst is_runs
  have non_empty := ordered.1 iv List.mem_cons_self
  have later : ∀ r ∈ rest, iv.2.val < r.1.val := fun r r_in =>
    (List.pairwise_cons.mp ordered.2).1 r r_in
  by_contra short
  have not_below : first ≤ iv.1.val := by
    by_contra below
    exact lowest iv.1.val (by omega) ⟨iv, List.mem_cons_self, by simp only [InRun]; omega⟩
  have starts_there : first = iv.1.val := by
    obtain ⟨r, r_in, in_r⟩ := run 0 (by omega)
    rcases List.mem_cons.mp r_in with is_iv | in_rest
    · subst is_iv
      simp only [InRun] at in_r
      omega
    · have := later r in_rest
      simp only [InRun] at in_r
      omega
  obtain ⟨r, r_in, in_r⟩ := run (iv.2.val - iv.1.val) (by omega)
  rcases List.mem_cons.mp r_in with is_iv | in_rest
  · subst is_iv
    simp only [InRun] at in_r
    omega
  · have := later r in_rest
    simp only [InRun] at in_r
    omega

/-- An answer that is a mapping is no refusal: the refusals say nothing of it. -/
theorem a_mapping_is_no_refusal (size : Nat) (pool used : List (U64 × U64)) (extra : List Map)
    (m : alloc.vec.Vec Map) :
    AutoMapRefusedForAReason size pool used extra (core.result.Result.Ok m) := by
  unfold AutoMapRefusedForAReason
  exact ⟨(fun _ h => by cases h), (fun _ h => by cases h), fun _ h => by cases h⟩

/-- What `auto_map` has promised when it answers with a mapping `m`, for the container ids
`[0, size)`, the user's `pool` and the ids `used` by others, and the `extra` mappings of the user:
`m` is valid; every parent id of `m` is one of the extra mappings or is a free id of the pool; the
container ids of `m` are those below `size` and those of the extra mappings, all of them; and the
extra mappings are in it. -/
def AutoMapAnswer (size : Nat) (pool used : List (U64 × U64)) (extra m : List Map) : Prop :=
  Valid m ∧
  (∀ c p, Maps m c p → (∃ e ∈ extra, InParents e p) ∨ (HasId pool p ∧ ¬ HasId used p)) ∧
  (∀ c p, Maps m c p → c < size ∨ ∃ e ∈ extra, InContainers e c) ∧
  (∀ c, c < size → ∃ p, Maps m c p) ∧
  (∀ c p, Maps extra c p → Maps m c p)

/-- **The automatic part is apart from the extra mappings.**  In an answer `m` that is what
`AutoMapAnswer` says, every pair (container id, parent id) is either a pair of the extra mappings,
or has a container id below `size` that no extra mapping has, and a parent id that is a free id of
the pool and that no extra mapping has.  (The answer is valid, so each id is mapped one way only:
a pair that uses a parent id or a container id of an extra mapping is that mapping's.) -/
theorem the_automatic_part_is_apart_from_the_extra (size : Nat) (pool used : List (U64 × U64))
    (extra m : List Map) (answer : AutoMapAnswer size pool used extra m) :
    ∀ c p, Maps m c p → Maps extra c p ∨
      (c < size ∧ (∀ e ∈ extra, ¬ InContainers e c) ∧ (∀ e ∈ extra, ¬ InParents e p) ∧
        HasId pool p ∧ ¬ HasId used p) := by
  obtain ⟨valid, uses, containers, _, keeps⟩ := answer
  have both := valid_lists_are_functions_both_ways m valid
  intro c p is_map
  -- a container id of an extra mapping goes where that mapping sends it
  have is_extras : ∀ e ∈ extra, InContainers e c → Maps extra c p := by
    intro e e_in in_e
    have sent : Maps extra c (e.parent_id.val + (c - e.container_id.val)) := ⟨e, e_in, in_e, rfl⟩
    rw [both.1 c p _ is_map (keeps c _ sent)]
    exact sent
  by_cases c_in : ∃ e ∈ extra, InContainers e c
  · obtain ⟨e, e_in, in_e⟩ := c_in
    exact Or.inl (is_extras e e_in in_e)
  · have below : c < size := by
      rcases containers c p is_map with below | in_extra
      · exact below
      · exact absurd in_extra c_in
    -- a parent id of an extra mapping is the image of a container id of that mapping, not `c`
    have not_extra_parent : ∀ e ∈ extra, ¬ InParents e p := by
      intro e e_in in_p
      have back : Maps extra (e.container_id.val + (p - e.parent_id.val)) p := by
        refine ⟨e, e_in, ?_, ?_⟩
        · unfold InParents at in_p
          unfold InContainers
          omega
        · unfold InParents at in_p
          omega
      have same := both.2 c _ p is_map (keeps _ p back)
      refine c_in ⟨e, e_in, ?_⟩
      rw [same]
      unfold InParents at in_p
      unfold InContainers
      omega
    refine Or.inr ⟨below, fun e e_in in_e => c_in ⟨e, e_in, in_e⟩, not_extra_parent, ?_⟩
    rcases uses c p is_map with ⟨e, e_in, in_p⟩ | free
    · exact absurd in_p (not_extra_parent e e_in)
    · exact free

/-- **From the pieces to the answer.**  `zipped` pairs ids that are free (not used, not parent ids
of the extra mappings) with container ids that are asked for (below `size`, not container ids of
the extra mappings); `merged` maps what `zipped` and `extra` map, and has at most `ExtentLimit`
entries.  Then `merged` is what `auto_map` promises. -/
theorem the_answer_is_what_it_promises (size : Nat) (pool used taken wanted : List (U64 × U64))
    (extra zipped merged : List Map) (valid_extra : Valid extra)
    (wanted_ids : ∀ id, HasId wanted id ↔ id < size ∧ ¬ ∃ e ∈ extra, InContainers e id)
    (taken_ids : ∀ id, HasId taken id →
      HasId pool id ∧ ¬ HasId used id ∧ ¬ ∃ e ∈ extra, InParents e id)
    (zipped_sane : ∀ e ∈ zipped, Sane e) (zipped_apart : zipped.Pairwise Apart)
    (zipped_sound : ∀ c p, Maps zipped c p →
      (HasId taken p ∧ p < IdLimit) ∧ (HasId wanted c ∧ c < IdLimit))
    (zipped_covers : ∀ c, HasId wanted c → ∃ p, Maps zipped c p)
    (merged_pairs : ∀ c p, Maps merged c p ↔ Maps (zipped ++ extra) c p)
    (merged_valid : (∀ e ∈ zipped ++ extra, Sane e) → (zipped ++ extra).Pairwise Apart →
      (∀ e ∈ merged, Sane e) ∧ merged.Pairwise Apart)
    (few : merged.length ≤ ExtentLimit) : AutoMapAnswer size pool used extra merged := by
  obtain ⟨_, extra_sane, extra_apart⟩ := valid_extra
  have zipped_has_wanted : ∀ z ∈ zipped, ∀ c, InContainers z c → HasId wanted c := by
    intro z z_in c in_z
    exact (zipped_sound c _ ⟨z, z_in, in_z, rfl⟩).2.1
  have zipped_has_taken : ∀ z ∈ zipped, ∀ p, InParents z p → HasId taken p := by
    intro z z_in p in_z
    have : Maps zipped (z.container_id.val + (p - z.parent_id.val)) p := by
      refine ⟨z, z_in, ?_, ?_⟩
      · unfold InParents at in_z
        unfold InContainers
        omega
      · unfold InParents at in_z
        omega
    exact (zipped_sound _ _ this).1.1
  have apart_from_extra : ∀ z ∈ zipped, ∀ x ∈ extra, Apart z x := by
    intro z z_in x x_in
    constructor
    · intro c ⟨in_z, in_x⟩
      exact ((wanted_ids c).mp (zipped_has_wanted z z_in c in_z)).2 ⟨x, x_in, in_x⟩
    · intro p ⟨in_z, in_x⟩
      exact (taken_ids p (zipped_has_taken z z_in p in_z)).2.2 ⟨x, x_in, in_x⟩
  obtain ⟨merged_sane, merged_apart⟩ := merged_valid
    (fun e e_in => by
      rcases List.mem_append.mp e_in with e_in | e_in
      · exact zipped_sane e e_in
      · exact extra_sane e e_in)
    (List.pairwise_append.mpr ⟨zipped_apart, extra_apart, apart_from_extra⟩)
  refine ⟨⟨few, merged_sane, merged_apart⟩, ?_, ?_, ?_, ?_⟩
  · intro c p is_map
    rcases (maps_of_append _ _ c p).mp ((merged_pairs c p).mp is_map) with in_zipped | in_extra
    · exact Or.inr ⟨((taken_ids p (zipped_sound c p in_zipped).1.1)).1,
        (taken_ids p (zipped_sound c p in_zipped).1.1).2.1⟩
    · obtain ⟨e, e_in, in_e, is_p⟩ := in_extra
      exact Or.inl ⟨e, e_in, by unfold InContainers at in_e; unfold InParents; omega⟩
  · intro c p is_map
    rcases (maps_of_append _ _ c p).mp ((merged_pairs c p).mp is_map) with in_zipped | in_extra
    · exact Or.inl ((wanted_ids c).mp (zipped_sound c p in_zipped).2.1).1
    · obtain ⟨e, e_in, in_e, _⟩ := in_extra
      exact Or.inr ⟨e, e_in, in_e⟩
  · intro c below
    by_cases in_extra : ∃ e ∈ extra, InContainers e c
    · obtain ⟨e, e_in, in_e⟩ := in_extra
      exact ⟨e.parent_id.val + (c - e.container_id.val),
        (merged_pairs c _).mpr ((maps_of_append _ _ c _).mpr (Or.inr ⟨e, e_in, in_e, rfl⟩))⟩
    · obtain ⟨p, is_map⟩ := zipped_covers c ((wanted_ids c).mpr ⟨below, in_extra⟩)
      exact ⟨p, (merged_pairs c p).mpr ((maps_of_append _ _ c p).mpr (Or.inl is_map))⟩
  · intro c p is_map
    exact (merged_pairs c p).mpr ((maps_of_append _ _ c p).mpr (Or.inr is_map))

/-- **`auto_map`**: when it answers with a mapping, the mapping is what `AutoMapAnswer` says; when
it refuses, the refusal is true (`AutoMapRefusedForAReason`); and when there are no extra mappings
and the free ids of the pool begin with a run of `size` ids, it answers with a mapping. -/
theorem auto_map_answers_with_what_it_promises (size : U32) (pool used : IdSet)
    (extra : Slice Map) (pool_ordered : Ordered pool.intervals.val)
    (used_ordered : Ordered used.intervals.val)
    (fits : pool.intervals.val.length * (used.intervals.val.length + 1) * 341 ≤ Usize.max)
    (wide : 4294967636 ≤ Usize.max) :
    auto_map size pool used extra ⦃ answer =>
      (∀ m, answer = core.result.Result.Ok m →
        AutoMapAnswer size.val pool.intervals.val used.intervals.val extra.val m.val) ∧
      AutoMapRefusedForAReason size.val pool.intervals.val used.intervals.val extra.val
        answer ∧
      (extra.val = [] → FreeIdsBeginWithARunOf size.val pool.intervals.val used.intervals.val →
        ∃ m, answer = core.result.Result.Ok m) ⦄ := by
  unfold auto_map
  step with validate_accepts_exactly_the_valid_lists extra as ⟨ checked, is_valid ⟩
  split
  · rename_i accepted
    have valid_extra : Valid extra.val := is_valid.mp rfl
    have extra_few : extra.val.length ≤ 340 := valid_extra.1
    have hsize := core.convert.num.FromU64U32.from_val_eq size
    have size_le : size.val ≤ IdLimit := by
      have := size.hBounds
      simp [UScalarTy.numBits] at this
      unfold IdLimit
      omega
    simp only [Std.lift, Std.bind_ok]
    step with from_intervals_is_the_union_with_few_intervals as ⟨ target, target_ordered,
      target_ids, target_few ⟩
    have target_ids' : ∀ id, HasId target.intervals.val id ↔ id < size.val := by
      intro id
      rw [target_ids id]
      simp [HasId, InRun, hsize]
    have target_few' : target.intervals.val.length ≤ 1 := by simpa using target_few
    step with of_container_ids_has_the_container_ids_in_few_intervals extra as ⟨ is,
      is_ordered, is_ids, is_few ⟩
    step with subtract_has_the_ids_of_the_first_not_in_the_second target is target_ordered
      is_ordered (by nlinarith) as ⟨ wanted, wanted_ordered, wanted_ids, wanted_few ⟩
    rw [id_limit_is_the_largest_u32]
    step with below_is_the_ids_under_the_limit pool 4294967295#u64 pool_ordered as ⟨ is1,
      is1_ordered, is1_ids, is1_few ⟩
    step with subtract_has_the_ids_of_the_first_not_in_the_second is1 used is1_ordered
      used_ordered (by nlinarith) as ⟨ is2, is2_ordered, is2_ids, is2_few ⟩
    step with of_parent_ids_has_the_parent_ids_in_few_intervals extra as ⟨ is3,
      is3_ordered, is3_ids, is3_few ⟩
    step with subtract_has_the_ids_of_the_first_not_in_the_second is2 is3 is2_ordered
      is3_ordered (by nlinarith) as ⟨ free, free_ordered, free_ids, free_few ⟩
    step with size_is_the_number_of_ids wanted wanted_ordered as ⟨ n, n_exactly ⟩
    step with find_available_gives_n_ids_or_says_there_are_fewer free n free_ordered as ⟨ o,
      o_spec ⟩
    have free_exactly : ExactlyIds (fun p => HasId pool.intervals.val p ∧ p < IdLimit ∧
        ¬ HasId used.intervals.val p ∧ ¬ ∃ e ∈ extra.val, InParents e p)
        (Total free.intervals.val) := by
      refine exactly_ids_are_the_same_for_equivalent_properties _ _ _ (fun id => ?_)
        (ordered_runs_have_total_ids _ free_ordered)
      rw [free_ids id, is2_ids id, is1_ids id, is3_ids id]
      unfold IdLimit
      tauto
    have wanted_exactly : ExactlyIds (fun c => c < size.val ∧ ¬ ∃ e ∈ extra.val,
        InContainers e c) n.val :=
      exactly_ids_are_the_same_for_equivalent_properties _ _ _ (fun id => by
        rw [wanted_ids id, target_ids' id, is_ids id]) n_exactly
    have run_facts : extra.val = [] →
        FreeIdsBeginWithARunOf size.val pool.intervals.val used.intervals.val →
        n.val = size.val ∧ FirstIntervalHolds free n ∧ size.val ≤ Total free.intervals.val := by
      intro e_nil ⟨first, run, lowest⟩
      have free_is : ∀ id, HasId free.intervals.val id ↔
          FreeInPool pool.intervals.val used.intervals.val id := by
        intro id
        rw [free_ids id, is2_ids id, is1_ids id, is3_ids id, e_nil]
        simp only [FreeInPool, IdLimit, List.mem_nil_iff]
        tauto
      have n_is : n.val = size.val := by
        have range_exactly : ExactlyIds (fun c => c < size.val ∧
            ¬ ∃ e ∈ extra.val, InContainers e c) size.val :=
          ⟨List.range size.val, List.nodup_range, by simp [e_nil], by simp⟩
        exact exactly_ids_is_unique _ _ _ wanted_exactly range_exactly
      have run_in_free : ∀ k, k < size.val → HasId free.intervals.val (first + k) :=
        fun k below => (free_is _).mpr (run k below)
      refine ⟨n_is, fun iv is_first => ?_, ?_⟩
      · exact the_first_interval_has_the_run free.intervals.val free_ordered first n.val
          (fun k below => run_in_free k (by omega)) (fun id below has =>
            lowest id below ((free_is id).mp has)) iv is_first
      · exact a_run_of_ids_is_no_more_than_the_ids (HasId free.intervals.val) first size.val _
          (ordered_runs_have_total_ids _ free_ordered) run_in_free
    cases o with
    | none =>
      refine (WP.spec_ok _).mpr ⟨(fun m is_ok => by cases is_ok), ?_, fun e_nil first => ?_⟩
      · unfold AutoMapRefusedForAReason
        refine ⟨(fun f is_err => by cases is_err), fun n' is_err => ?_,
          fun n' is_err => by cases is_err⟩
        have same : n = n' := by injection (core.result.Result.Err.inj is_err)
        subst same
        exact ⟨valid_extra, _, free_exactly, o_spec, wanted_exactly⟩
      · -- the free ids begin with a run of `size`, so there are enough
        obtain ⟨n_is, _, enough⟩ := run_facts e_nil first
        exfalso
        omega
    | some taken =>
      obtain ⟨taken_ordered, taken_in_free, taken_exactly, taken_one⟩ := o_spec
      have taken_ids : ∀ id, HasId taken.intervals.val id →
          HasId pool.intervals.val id ∧ ¬ HasId used.intervals.val id ∧
            ¬ ∃ e ∈ extra.val, InParents e id := by
        intro id has
        have in_free := (free_ids id).mp (taken_in_free id has)
        have in_is2 := (is2_ids id).mp in_free.1
        have in_is1 := (is1_ids id).mp in_is2.1
        exact ⟨in_is1.1, in_is2.2, fun in_extra => in_free.2 ((is3_ids id).mpr in_extra)⟩
      have taken_below : ∀ id, HasId taken.intervals.val id → id < IdLimit := by
        intro id has
        have in_free := (free_ids id).mp (taken_in_free id has)
        have in_is2 := (is2_ids id).mp in_free.1
        exact ((is1_ids id).mp in_is2.1).2
      have wanted_ids' : ∀ id, HasId wanted.intervals.val id ↔
          id < size.val ∧ ¬ ∃ e ∈ extra.val, InContainers e id := by
        intro id
        rw [wanted_ids id, target_ids' id, is_ids id]
      have wanted_below : ∀ id, HasId wanted.intervals.val id → id < IdLimit :=
        fun id has => Nat.lt_of_lt_of_le ((wanted_ids' id).mp has).1 size_le
      have taken_total : Total taken.intervals.val = n.val :=
        exactly_ids_is_unique _ _ _ (ordered_runs_have_total_ids _ taken_ordered) taken_exactly
      have wanted_total : Total wanted.intervals.val = n.val :=
        exactly_ids_is_unique _ _ _ (ordered_runs_have_total_ids _ wanted_ordered) n_exactly
      step with zip_pairs_the_ids_in_order taken wanted taken_ordered wanted_ordered as ⟨ maps,
        zipped_sane, zipped_apart, zipped_sound, zipped_covers, zipped_few, zipped_pieces ⟩
      have taken_exactly' : ExactlyIds (fun id => HasId taken.intervals.val id ∧ id < IdLimit)
          n.val :=
        exactly_ids_are_the_same_for_equivalent_properties _ _ _
          (fun id => ⟨fun has => ⟨has, taken_below id has⟩, fun both => both.1⟩) taken_exactly
      have wanted_exactly' : ExactlyIds (fun id => HasId wanted.intervals.val id ∧ id < IdLimit)
          n.val :=
        exactly_ids_are_the_same_for_equivalent_properties _ _ _
          (fun id => ⟨fun has => ⟨has, wanted_below id has⟩, fun both => both.1⟩) n_exactly
      have zipped_covers' : ∀ c, HasId wanted.intervals.val c → ∃ p, Maps maps.val c p :=
        fun c has => zipped_covers (fun k m is_k is_m => by
          have := exactly_ids_is_unique _ _ _ is_k taken_exactly'
          have := exactly_ids_is_unique _ _ _ is_m wanted_exactly'
          omega) c has (wanted_below c has)
      have room : maps.val.length + extra.val.length - (0#usize).val ≤ Usize.max := by
        have zero : (0#usize).val = 0 := rfl
        unfold IdLimit at zipped_few
        omega
      step with auto_map_adds_the_extra_entries extra maps 0#usize (by simp) room as ⟨ maps1,
        is_maps1 ⟩
      have maps1_is : (alloc.vec.Vec.deref maps1).val = maps.val ++ extra.val := by
        simpa [alloc.vec.Vec.deref] using is_maps1
      step with sort_and_merge_keeps_the_pairs as ⟨ maps2, same_pairs, still_valid, few_entries ⟩
      split
      · rename_i too_many
        refine (WP.spec_ok _).mpr ⟨(fun m is_ok => by cases is_ok), ?_, fun e_nil first => ?_⟩
        swap
        · -- the free ids begin with a run: the mapping has one entry per interval, so few
          obtain ⟨n_is, first_holds, _⟩ := run_facts e_nil first
          exfalso
          have taken_few := taken_one first_holds
          have no_extra : is.intervals.val.length = 0 := by
            have := is_few
            rw [e_nil] at this
            simpa using this
          have wanted_one : wanted.intervals.val.length ≤ 1 := by
            have := wanted_few
            rw [no_extra] at this
            omega
          have no_more : maps2.val.length ≤ 2 := by
            have := few_entries
            rw [maps1_is, e_nil] at this
            simp only [List.append_nil] at this
            omega
          have := (UScalar.lt_equiv MAX_EXTENTS (alloc.vec.Vec.len maps2)).mp too_many
          have := max_extents_is_340
          have same : (alloc.vec.Vec.len maps2).val = maps2.val.length := rfl
          omega
        unfold AutoMapRefusedForAReason
        refine ⟨(fun f is_err => by cases is_err), (fun n' is_err => by cases is_err),
          fun n' is_err => ?_⟩
        have same : maps2.len = n' := by injection (core.result.Result.Err.inj is_err)
        subst same
        refine ⟨valid_extra, ?_, _, _, free_exactly, wanted_exactly, ?_⟩
        · have := (UScalar.lt_equiv MAX_EXTENTS (alloc.vec.Vec.len maps2)).mp too_many
          have := max_extents_is_340
          unfold ExtentLimit
          omega
        · exact exactly_ids_in_a_set_are_no_more _ _ _ _ taken_exactly free_exactly (fun id has =>
            ⟨(taken_ids id has).1, taken_below id has, (taken_ids id has).2.1,
              (taken_ids id has).2.2⟩)
      · rename_i not_too_many
        refine (WP.spec_ok _).mpr ⟨?_, a_mapping_is_no_refusal _ _ _ _ _, fun _ _ => ⟨maps2, rfl⟩⟩
        intro m is_ok
        have is_m : maps2 = m := by injection is_ok
        subst is_m
        have few : maps2.val.length ≤ ExtentLimit := by
          have := (UScalar.lt_equiv MAX_EXTENTS (alloc.vec.Vec.len maps2)).not.mp not_too_many
          have same : (alloc.vec.Vec.len maps2).val = maps2.val.length := rfl
          have := max_extents_is_340
          unfold ExtentLimit
          omega
        refine the_answer_is_what_it_promises size.val pool.intervals.val used.intervals.val
          taken.intervals.val wanted.intervals.val extra.val maps.val maps2.val valid_extra
          wanted_ids' taken_ids zipped_sane zipped_apart
          (fun c p h => ⟨⟨(zipped_sound c p h).1, (zipped_sound c p h).2.1⟩,
            (zipped_sound c p h).2.2.1, (zipped_sound c p h).2.2.2⟩) zipped_covers'
          (fun c p => by rw [same_pairs c p, maps1_is]) (fun sane apart => ?_) few
        rw [maps1_is] at still_valid
        exact still_valid sane apart
  · rename_i fault
    refine (WP.spec_ok _).mpr ⟨(fun m is_ok => by cases is_ok), ?_, fun e_nil _ => ?_⟩
    · unfold AutoMapRefusedForAReason
      refine ⟨fun f is_err valid => ?_, (fun n is_err => by cases is_err),
        fun n is_err => by cases is_err⟩
      have := is_valid.mpr valid
      cases this
    · have := is_valid.mpr (by rw [e_nil]; exact ⟨by simp [ExtentLimit], by simp, by simp⟩)
      cases this

end IdmapCore
