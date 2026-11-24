-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `sets` of crates/caps-core returns, written as a plain function
-- of the request (`answer_of`), and the proof that `sets` returns exactly that, for every
-- request (`sets_eq`).  After it, a claim is a question about `answer_of`, with no
-- translated code in sight.
--
-- Why it is needed: Aeneas translates `sets` with the flag tests spread in three copies
-- (`!r.privileged && r.add_all && r.drop_all` is split into nested `if`s).  Here the code is
-- proved equal to a straight reading, once; the claims of Spec.lean are then proved of the
-- straight reading.  `sets_eq` is a theorem: nothing in `answer_of` is trusted.  If it did not
-- say what the code does, `sets_eq` would not be provable.
--
-- Read before this file: Spec.lean, Bits.lean, and `sets` of src/lib.rs.
--
-- Notation: `x ||| y` is "in x or in y", `x &&& ~~~y` is "in x and not in y"; `if c then a else b`
-- as usual; `ok x` is "the function returned x".
import CapsCore.Bits

open Aeneas Aeneas.Std Result velarx_caps_core

namespace CapsCore

/-- The ambient capabilities after `--cap-drop` (a privileged container drops nothing). -/
def ambient_of (r : Request) : Std.U64 :=
  if r.privileged then r.ambient else r.ambient &&& ~~~r.drop

/-- The bounding set of the process: the base (all of the engine's for `--privileged` and `all`,
none for `--cap-drop all`, else the defaults the engine has), plus `add`, minus `drop` (not for
`--privileged`), plus the ambient capabilities left. -/
def bounding_of (r : Request) : Std.U64 :=
  let base := if r.privileged then r.bounding
    else if r.add_all then r.bounding
    else if r.drop_all then 0#u64 else r.defaults &&& r.bounding
  let caps := base ||| r.add
  (if r.privileged then caps else caps &&& ~~~r.drop) ||| ambient_of r

/-- The five sets when the request is satisfied: root has the bounding set as effective and
permitted, and the ambient capabilities as inheritable and ambient; another user has, in each
of those four, what was asked for (`add`, all of the bounding set for `all`) and the ambient
capabilities. -/
def sets_of (r : Request) : Sets :=
  if r.root then
    { bounding := bounding_of r, effective := bounding_of r, permitted := bounding_of r,
      inheritable := ambient_of r, ambient := ambient_of r }
  else
    let given := (if r.add_all then bounding_of r else bounding_of r &&& r.add) ||| ambient_of r
    { bounding := bounding_of r, effective := given, permitted := given,
      inheritable := given, ambient := given }

/-- For root, `sets_of` is: the bounding set for effective and permitted, the ambient
capabilities for inheritable and ambient. -/
theorem sets_of_root {r : Request} (root : r.root = true) :
    sets_of r = { bounding := bounding_of r, effective := bounding_of r, permitted := bounding_of r,
                  inheritable := ambient_of r, ambient := ambient_of r } := by
  simp only [sets_of, root, ↓reduceIte]

/-- For another user, `sets_of` is: what was given in each of the four sets. -/
theorem sets_of_user {r : Request} (user : r.root = false) :
    sets_of r = { bounding := bounding_of r,
                  effective := (if r.add_all then bounding_of r else bounding_of r &&& r.add) ||| ambient_of r,
                  permitted := (if r.add_all then bounding_of r else bounding_of r &&& r.add) ||| ambient_of r,
                  inheritable := (if r.add_all then bounding_of r else bounding_of r &&& r.add) ||| ambient_of r,
                  ambient := (if r.add_all then bounding_of r else bounding_of r &&& r.add) ||| ambient_of r } := by
  simp only [sets_of, user, Bool.false_eq_true, ↓reduceIte]

/-- `Contradicts` is a test on three flags, so the code of `answer_of` can branch on it. -/
instance (r : Request) : Decidable (Contradicts r) := by
  unfold Contradicts
  infer_instance

/-- The answer: the refusals in the order of the code, else the sets. -/
def answer_of (r : Request) : core.result.Result Sets Refusal :=
  if Contradicts r then .Err .AddAndDropAll
  else if r.add &&& ~~~r.bounding != 0#u64 then .Err (.Add (r.add &&& ~~~r.bounding))
  else if r.ambient &&& ~~~r.bounding != 0#u64 then .Err (.Ambient (r.ambient &&& ~~~r.bounding))
  else .Ok (sets_of r)

/-- **`sets` returns `answer_of`, for every request.**  The code is unfolded, each flag is
tried in turn, and what is left in each case is the same on both sides. -/
theorem sets_eq (r : Request) : sets r = ok (answer_of r) := by
  unfold sets answer_of Contradicts sets_of bounding_of ambient_of
  simp only [lift, Std.bind_ok]
  cases privileged : r.privileged <;> cases add_all : r.add_all <;>
    cases drop_all : r.drop_all <;> cases root : r.root <;>
    simp_all <;> split_ifs <;> rfl

/-- A contradiction is the first refusal. -/
theorem answer_contradicts {r : Request} (contradicts : Contradicts r) :
    answer_of r = core.result.Result.Err Refusal.AddAndDropAll := by
  simp only [answer_of, contradicts, ↓reduceIte]

/-- With no contradiction, an `add` the engine lacks is the second. -/
theorem answer_add_lacks {r : Request} (free : ¬ Contradicts r)
    (lacks : ¬ Within r.add r.bounding) :
    answer_of r = core.result.Result.Err (Refusal.Add (r.add &&& ~~~r.bounding)) := by
  simp only [answer_of, free, (and_not_ne_zero _ _).mpr lacks, ↓reduceIte]

/-- With neither, an ambient capability the engine lacks is the third. -/
theorem answer_ambient_lacks {r : Request} (free : ¬ Contradicts r)
    (add_in : Within r.add r.bounding) (lacks : ¬ Within r.ambient r.bounding) :
    answer_of r = core.result.Result.Err (Refusal.Ambient (r.ambient &&& ~~~r.bounding)) := by
  simp only [answer_of, free, mt (and_not_ne_zero _ _).mp (not_not.mpr add_in),
    (and_not_ne_zero _ _).mpr lacks, ↓reduceIte, Bool.false_eq_true]

/-- With none of the three, the answer is the sets. -/
theorem answer_sets {r : Request} (free : ¬ Contradicts r)
    (add_in : Within r.add r.bounding) (ambient_in : Within r.ambient r.bounding) :
    answer_of r = core.result.Result.Ok (sets_of r) := by
  simp only [answer_of, free, mt (and_not_ne_zero _ _).mp (not_not.mpr add_in),
    mt (and_not_ne_zero _ _).mp (not_not.mpr ambient_in), ↓reduceIte, Bool.false_eq_true]

/-- If the answer is sets `s`, they are `sets_of r` and none of the three refusals holds. -/
theorem ok_sets {r : Request} {s : Sets} (given : answer_of r = core.result.Result.Ok s) :
    s = sets_of r ∧ ¬ Contradicts r ∧ Within r.add r.bounding ∧ Within r.ambient r.bounding := by
  by_cases contradicts : Contradicts r
  · rw [answer_contradicts contradicts] at given
    cases given
  by_cases add_in : Within r.add r.bounding
  swap
  · rw [answer_add_lacks contradicts add_in] at given
    cases given
  by_cases ambient_in : Within r.ambient r.bounding
  swap
  · rw [answer_ambient_lacks contradicts add_in ambient_in] at given
    cases given
  rw [answer_sets contradicts add_in ambient_in] at given
  cases given
  exact ⟨rfl, contradicts, add_in, ambient_in⟩

/-- The opening of every claim about the sets: to show that `sets r` returns and its answer, when
it is sets `s`, satisfies `P`, it is enough to show that `sets_of r` satisfies `P` when none of
the three refusals holds. -/
theorem sets_ok_spec {P : Sets → Prop} (r : Request)
    (holds : ¬ Contradicts r → Within r.add r.bounding → Within r.ambient r.bounding →
      P (sets_of r)) :
    sets r ⦃ answer => ∀ s, answer = core.result.Result.Ok s → P s ⦄ := by
  rw [sets_eq, WP.spec_ok]
  intro s given
  obtain ⟨rfl, free, add_in, ambient_in⟩ := ok_sets given
  exact holds free add_in ambient_in

end CapsCore
