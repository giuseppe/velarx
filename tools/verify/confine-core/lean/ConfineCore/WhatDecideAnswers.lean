-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `decide` answers for each request, as one equation written with the
-- options of the request: `decide r = ok (answer r)`.  Every claim about `decide` is proved from
-- it.
-- Why it is needed: `decide` as Aeneas extracts it is a chain of `let ... ←` steps on the options;
-- the equation says once what they add up to, and `simp` (computation) checks it case by case, so
-- nothing is assumed: it is a theorem about the extracted code, not a model of it.
-- Read before this file: Spec.lean.
-- Notation: `!b` is "not b" on a Boolean and `||`, `&&` are "or", "and" on Booleans; `if c then x
-- else y` is the choice on `c`; `ok d` is "returns `d`"; `simp [f]` computes with the definition
-- of `f`.
import ConfineCore.Spec

open Aeneas Aeneas.Std Result
open velarx_confine_core hiding decide

namespace ConfineCore

/-- Which of the default paths a container has, from its options: none when privileged or with
`unmask=ALL`, all but those named with `unmask=` names, all otherwise. -/
def pathsOf (r : Request) : Paths :=
  if r.privileged || r.unmask_all then Paths.None
  else if r.unmask_some then Paths.Without
  else Paths.Default

/-- The seccomp filter, from the options: a profile of the user always applies, `unconfined` is
none, and the default profile is the default filter unless the container is privileged. -/
def filterOf (r : Request) : Filter :=
  match r.seccomp with
  | Seccomp.Custom => Filter.Custom
  | Seccomp.Unconfined => Filter.None
  | Seccomp.Default => if r.privileged then Filter.None else Filter.Default

/-- The decision for a request, part by part, written with its options. -/
def answer (r : Request) : Decision :=
  { deny_all_devices := !r.privileged
    seccomp := filterOf r
    masked := pathsOf r
    readonly := pathsOf r
    sys_readonly := !r.privileged
    mask_sys_kernel := !r.privileged && r.host_sysfs
    no_new_privileges := r.no_new_privileges }

/-- `decide` returns `answer r`, for every request: checked by computing each of the 96
combinations of the six options. -/
theorem decide_answers (r : Request) : decideRequest r = ok (answer r) := by
  rcases r with ⟨privileged, seccomp, unmask_all, unmask_some, host_sysfs, nnp⟩
  cases privileged <;> cases seccomp <;> cases unmask_all <;> cases unmask_some <;>
    cases host_sysfs <;> cases nnp <;>
    simp [decideRequest, velarx_confine_core.decide, answer, pathsOf, filterOf]

end ConfineCore
