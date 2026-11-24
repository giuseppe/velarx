-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/pull-core, the decisions
-- of a pull of the storage server (its phases and the layers it claims), in
-- words and in statements, with no proof.  This file and ../Models.lean are
-- what a reviewer reads; Lean checks the rest (the proofs are in Ends.lean,
-- Phases.lean and Claims.lean, each after the files that say what the
-- functions it is about do: Loops.lean for the library calls, Table.lean for
-- the table, Starts.lean for the functions that start a pull).
--
-- Why it is needed: a proof is worth what its statement says.  Each
-- statement here is a `def ... : Prop`: a claim, which `Theorems.lean`
-- asks Lean to prove.  Each has a comment of what it claims and of what it
-- does NOT.  The small definitions before the claims (`phaseOf`, `live`,
-- `Event`, `runs`, `Each`, `Numbered`, `Sound`) are their vocabulary, with `PullId` and
-- `LayerId`, the names lib.rs gives to a `u32`.  The walk of the crate (src/walk.rs)
-- checks the rules of the core on every state
-- of a small world; these four claims are proved for every core, whatever
-- the pulls and the layers: that no layer has two claimants, that a pull is
-- published only after a commit, that the first decision of a pull stands,
-- and that an end frees the layers once.
--
-- Read before this file: lib.rs of crates/pull-core (every function is a
-- few lines), then ../Models.lean.
--
-- Index.  What each claim is about (the Rust function of crates/pull-core), what is trusted,
-- and what is not claimed, in one place.
--
--   Claimed (about a call that RETURNS):
--     ALayerHasOneLiveClaimant            every call that changes the core: one claimant a layer
--     APullIsPublishedOnlyFromCommitting  `asked` and every call: published only from committing
--     TheFirstDecisionStands              every call: a stop or a commit is not replaced
--     AnEndFreesTheClaimsOnce             `end`: the claims go, a second `end` is a no-op
--
--   Trusted: ../Models.lean (`position`, `retain`), Charon and Aeneas (../../pins), and the
--   models of the standard library Aeneas itself has (`Vec` and slice indexing, the integer
--   operations).  The run also prints `Option::eq`, which Aeneas has no model of: the derived
--   `==` of `Phase` calls it for two `Over`, and the crate compares a phase only with `Waiting`
--   or `Fetching`, so nothing is assumed of it.
--
--   Not claimed: that a call returns (a panic or a loop that does not end is outside every claim;
--   for one, `begin` adds one to the `u32` number of the last pull, which past 2^32 - 1 pulls of
--   one core panics, or wraps where overflow is not checked);
--   that a pull ever gets its layers or is ever published (no liveness); that the shell calls the
--   core as `Each` says; the rules that only the walk checks, which the claims name.
--
--   To check that a claim is not trivial: (a) its hypotheses can hold: `Sound` of the empty core
--   is the first half of the first claim; for the others find a state of the walk (src/walk.rs)
--   that has them; (b) put in a bug the claim excludes, by hand in
--   crates/pull-core, and `tools/verify/run pull-core` must fail; (c) take a hypothesis out of
--   the claim, or make its conclusion stronger, and `run` must fail.
--
--   To see what `Core.end` looks like to Lean, side by side with the Rust: run
--   `tools/verify/run pull-core`, then read $VERIFY_CACHE/pull-core/work/Extracted/Funs.lean
--   (the functions, `Core.end` among them, as Aeneas wrote them) and Types.lean (the types);
--   `run` prints the directory when it ends.  Nothing generated is in the tree.
--
-- Notation:
--   - `Core.end c p published = ok c'` reads: the Rust `Core::end`, told to
--     end the pull `p` of the core `c`, returns (a claim says nothing of a
--     call that does not return: a panic, or a loop that does not end), and
--     leaves the core `c'`.  Aeneas turns a call that changes the core into
--     a function that gives the new core back (with the answer, if there
--     is one: `Core.claim c p layers = ok (answer, c')`).
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that
--     P"; `∀ h ∈ l, P` is "P for every element h of the list l"; `¬ P` is
--     "not P"; `∧` is "and", `∨` is "or", `→` is "if ... then".
--   - `c.pulls.val` and `c.claims.val` are the list of the pulls and the
--     list of the claims of the core `c`; `l.Nodup` is "no element of `l`
--     is in it twice"; `a ≠ b` is "`a` is not `b`".
--   - `some x` and `none` are Rust's `Some(x)` and `None`.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_pull_core

namespace PullCore

-- The names the Rust gives its types (`pub type` in lib.rs).  Aeneas does not keep them (it writes
-- `Std.U32` for a pull and a layer alike); here a statement says which one a number is.

/-- The name of a pull (`PullId`, a `u32`). -/
abbrev PullId := Std.U32

/-- The name of a layer (`LayerId`, a `u32`). -/
abbrev LayerId := Std.U32

/-- The phase of the pull `p`, if the core holds one (the first, if it held
two: `pull_at` finds that one). -/
def phaseOf (c : Core) (p : PullId) : Option Phase :=
  (c.pulls.val.find? (fun q => q.id = p)).map (·.phase)

/-- The core holds the pull `p` and it is not over: only such a pull holds
layers. -/
def live (c : Core) (p : PullId) : Prop :=
  ∃ ph, phaseOf c p = some ph ∧ ∀ o, ph ≠ Phase.Over o

/-- What the server may do to the core: one call of `Core` that changes it,
with its arguments.  (`finish` is the Rust `end`, a word of Lean.) -/
inductive Event where
  | begin (old : Option PullId)
  | claim (p : PullId) (layers : Slice LayerId)
  | staged (p : PullId)
  | commit (p : PullId)
  | stop (p : PullId) (why : Why)
  | finish (p : PullId) (published : Bool)
  | forget (p : PullId)

/-- The call `e` returns, and leaves the core `c'`. -/
def runs (c : Core) : Event → Core → Prop
  | .begin old, c' => ∃ b, Core.begin c old = ok (b, c')
  | .claim p layers, c' => ∃ a, Core.claim c p layers = ok (a, c')
  | .staged p, c' => ∃ a, Core.staged c p = ok (a, c')
  | .commit p, c' => ∃ a, Core.commit c p = ok (a, c')
  | .stop p why, c' => Core.stop c p why = ok c'
  | .finish p published, c' => Core.end c p published = ok c'
  | .forget p, c' => Core.forget c p = ok c'

/-- The call is made as the server makes it: the layers of a claim are each
named once (`begin_pull` sorts them and drops the repeats, and the table of
layer numbers gives a layer one number). -/
def Each : Event → Prop
  | .claim _ layers => layers.val.Nodup
  | _ => True

/-- No pull has a number above `last`, the number of the last pull started:
a pull that begins gets a number nobody had. -/
def Numbered (c : Core) : Prop :=
  ∀ q ∈ c.pulls.val, q.id.val ≤ c.last.val

/-- The table of the core is as it should be: the pulls are numbered, no layer
is claimed twice, and a pull that claims is live. -/
def Sound (c : Core) : Prop :=
  Numbered c ∧ (c.claims.val.map (·.layer)).Nodup ∧ ∀ h ∈ c.claims.val, live c h.pull

/-- **A layer has one claimant, and it is live.**  A core with no pull and no
claim is sound, and so is the core any call leaves, when the core was sound.
So, for the core the server builds, which starts empty, no two pulls share a
layer (a layer two pulls both want is claimed by one of them, and the other
waits), and a pull that ended or was forgotten holds none.

Not said: that a pull claims all the layers it asked for or none (the walk
checks it); that a pull that wants layers gets them in the end (nothing is
said of time); that the server calls the core as `Each` says (`begin_pull` sorts
the layers of a pull and drops the repeats, the shell is not proved). -/
def ALayerHasOneLiveClaimant : Prop :=
  (∀ c : Core, c.pulls.val = [] → c.claims.val = [] → Sound c) ∧
  ∀ (c : Core) (e : Event) (c' : Core), Sound c → Each e → runs c e c' → Sound c'

/-- **A pull is published only from committing.**  Whatever the call, on a core
whose pulls are numbered (`Numbered`):
- `asked` tells a pull to publish only when it is committing;
- a pull that is published after the call (over, with no reason of failure)
  was published before it, or was committing and the call was the end of it
  as published;
- a pull that is committing after the call was committing before it, or was
  staged and the call was the commit of it.
So no call publishes a pull that fetches, waits, stops or was not committed,
and the only way to commit one is to commit a staged one.

Not said: that the engine's commit comes after the staging (a commit of a
pull that fetches answers `Early` and changes nothing: the walk checks it);
that the shell publishes only when `asked` says so. -/
def APullIsPublishedOnlyFromCommitting : Prop :=
  (∀ (c : Core) (p : PullId), Core.asked c p = ok Asked.Publish →
    phaseOf c p = some Phase.Committing) ∧
  ∀ (c : Core) (e : Event) (c' : Core) (q : PullId), Numbered c → runs c e c' →
    (phaseOf c' q = some (Phase.Over none) →
      phaseOf c q = some (Phase.Over none) ∨
      (phaseOf c q = some Phase.Committing ∧ e = Event.finish q true)) ∧
    (phaseOf c' q = some Phase.Committing →
      phaseOf c q = some Phase.Committing ∨
      (phaseOf c q = some Phase.Staged ∧ e = Event.commit q))

/-- **The first decision stands.**  Whatever the call, on a core whose pulls are
numbered (`Numbered`), a pull that is
stopping for the reason `w` is, after it, still stopping for `w`, or over
with `w` as its outcome, or forgotten: no second stop replaces the reason,
and nothing turns a stop into a commit or a publish.  A pull that is
committing is, after the call, committing, or over, or forgotten: an abort
that comes while the layers are published does not stop it.

Not said: which of the answers the engine gets (`commit` of a stopping pull
answers `Wait`: the walk checks it); that a stop of a pull that is
waiting, fetching or staged takes (the walk checks it); that a call leaves
alone a waiting, fetching or staged pull it is not about. -/
def TheFirstDecisionStands : Prop :=
  ∀ (c : Core) (e : Event) (c' : Core) (q : PullId), Numbered c → runs c e c' →
    (∀ w, phaseOf c q = some (Phase.Stopping w) →
      phaseOf c' q = some (Phase.Stopping w) ∨ phaseOf c' q = some (Phase.Over (some w)) ∨
      phaseOf c' q = none) ∧
    (phaseOf c q = some Phase.Committing →
      phaseOf c' q = some Phase.Committing ∨ (∃ o, phaseOf c' q = some (Phase.Over o)) ∨
      phaseOf c' q = none)

/-- **An end frees the claims, and a second end changes nothing.**  After
`end` of the pull `p`, however it ended (published or not): no claim is of
`p`, the pull `p` is over if the core held it, and an `end` of it again, with
either answer, leaves the core as it was.

Not said: with what outcome the pull is over (a pull that is not committing
is over as failed even when the shell says published: the walk checks it);
anything of the other pulls (a call moves only its own pull: the walk
checks it). -/
def AnEndFreesTheClaimsOnce : Prop :=
  ∀ (c : Core) (p : PullId) (published : Bool) (c' : Core),
    Core.end c p published = ok c' →
    (∀ h ∈ c'.claims.val, h.pull ≠ p) ∧
    (∀ ph, phaseOf c p = some ph → ∃ o, phaseOf c' p = some (Phase.Over o)) ∧
    ∀ (published' : Bool) (c'' : Core), Core.end c' p published' = ok c'' → c'' = c'

end PullCore
