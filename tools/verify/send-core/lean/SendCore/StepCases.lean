-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what each Rust function of the send loop returns, case by case, in the
-- words of Spec.lean: `send`, `retry`, `redirect` and `step` (which has `got` in it).  Each is
-- a statement "it returns, and the state and the action it gives are one of these cases" (the
-- types `SendMoves`, `RetryMoves`, `RedirectMoves` and `Moves`).
--
-- Why it is needed: the claims of Spec.lean are about every run.  Their proofs would otherwise
-- unfold the code of `step` each time; they read the cases of this file instead, where each case
-- is a line that says what the answer is and when it is given.
--
-- Read before this file: Spec.lean, and `begin`, `step` and what they call in src/lib.rs.
--
-- Notation: `f x = ok (n, a)` is "the function `f` returns the state `n` and the action `a`";
-- `{ s with f := v }` is "the state `s` with its field `f` set to `v`"; an `inductive` lists the
-- ways something can be (`cases moves` goes through them); `x.val` is the number a counter holds.
import SendCore.Spec
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- Adding one to a counter below 255 returns, and gives the next number. -/
theorem increment (x : U8) (below : x.val < 255) : ∃ i, x + 1#u8 = ok i ∧ i.val = x.val + 1 := by
  have spec := U8.add_spec (x := x) (y := 1#u8) (by scalar_tac)
  cases sum : x + 1#u8 with
  | ret i =>
    rw [sum] at spec
    simp at spec
    exact ⟨i, rfl, by simpa using spec⟩
  | vis e k => rw [sum] at spec; simp at spec
  | div => rw [sum] at spec; simp at spec

/-- The comparison of the Rust code with `MAX_RETRIES` is the one on the numbers: 3. -/
theorem retries_reach_the_limit (x : U8) : (x ≥ MAX_RETRIES) ↔ 3 ≤ x.val := by
  simp [MAX_RETRIES]

/-- The comparison of the Rust code with `MAX_REDIRECTS` is the one on the numbers: 10. -/
theorem hops_reach_the_limit (x : U8) : (x ≥ MAX_REDIRECTS) ↔ 10 ≤ x.val := by
  simp [MAX_REDIRECTS]

/-- The state `send` leaves after a send to `t`: whether the request is at the registry's origin,
whether it has left it (a send to another origin, or any send after one), and the scheme of the
last send. -/
def moved (s : State) (t : Target) : State :=
  { s with at_home := !s.left_home && t.home, left_home := s.left_home || !t.home,
           https := t.https }

/-- What `send` answers: refuse a downgrade, refuse a target the policy did not allow, send
`Home` to the registry's origin of a request that never left it, else send `Away`. -/
def sendAction (s : State) (t : Target) (remember : Bool) : Action :=
  if (s.https || s.begin.home_https) && !t.https then .Refuse .Downgrade
  else if !t.allowed then .Refuse .Policy
  else if !s.left_home && t.home then .Send (.Home s.held s.method s.body)
  else .Send (.Away s.method s.body remember)

/-- `send` returns the state `moved s t` and the action `sendAction s t remember`: it never
panics, whatever the state. -/
theorem send_eq (s : State) (t : Target) (remember : Bool) :
    send s t remember = ok (moved s t, sendAction s t remember) := by
  unfold send moved sendAction
  cases hs : s.https <;> cases ht : t.https <;> cases ha : t.allowed <;> cases hh : t.home <;>
    cases hl : s.left_home <;> cases hb : s.begin.home_https <;> simp [*]

/-- The four ways `send` can end: it refuses a downgrade (the request is, or was, on https and the
target is not), it refuses a target the policy did not allow, it sends to the registry's own origin
(`Home`, with the `Authorization` of the pass), or it sends to another origin (`Away`). -/
inductive SendMoves (s : State) (t : Target) (remember : Bool) : State → Action → Prop
  | downgrade : ((s.https || s.begin.home_https) && !t.https) = true →
      SendMoves s t remember (moved s t) (.Refuse .Downgrade)
  | policy : ((s.https || s.begin.home_https) && !t.https) = false → t.allowed = false →
      SendMoves s t remember (moved s t) (.Refuse .Policy)
  | home : ((s.https || s.begin.home_https) && !t.https) = false → t.allowed = true →
      (!s.left_home && t.home) = true →
      SendMoves s t remember (moved s t) (.Send (.Home s.held s.method s.body))
  | away : ((s.https || s.begin.home_https) && !t.https) = false → t.allowed = true →
      (!s.left_home && t.home) = false →
      SendMoves s t remember (moved s t) (.Send (.Away s.method s.body remember))

/-- `send` returns, and its answer is one of the four cases. -/
theorem send_moves (s : State) (t : Target) (remember : Bool) :
    ∃ n a, send s t remember = ok (n, a) ∧ SendMoves s t remember n a := by
  refine ⟨_, _, send_eq s t remember, ?_⟩
  unfold sendAction
  by_cases downgrade : ((s.https || s.begin.home_https) && !t.https) = true
  · simp only [downgrade, ite_true]; exact .downgrade downgrade
  · have no_downgrade : ((s.https || s.begin.home_https) && !t.https) = false := by
      simpa using downgrade
    by_cases allowed : t.allowed = true
    · by_cases at_home : (!s.left_home && t.home) = true
      · simp [no_downgrade, allowed, at_home]; exact .home no_downgrade allowed at_home
      · have away : (!s.left_home && t.home) = false := by simpa using at_home
        simp [no_downgrade, allowed, away]; exact .away no_downgrade allowed away
    · have refused : t.allowed = false := by simpa using allowed
      simp [no_downgrade, refused]; exact .policy no_downgrade refused

/-- The two ways `retry` can end: the passes are used up and the request is `Done`, or a new pass
is asked with one more retry counted. -/
inductive RetryMoves (s : State) : State → Action → Prop
  | exhausted : 3 ≤ s.retries.val → RetryMoves s s .Done
  | again (i : U8) : s.retries.val < 3 → i.val = s.retries.val + 1 →
      RetryMoves s { s with retries := i } (.Pass s.refreshed)

/-- `retry` returns when the retries are in range, and does one of the two. -/
theorem retry_moves (s : State) (bounded : s.retries.val ≤ 3) :
    ∃ n a, retry s = ok (n, a) ∧ RetryMoves s n a := by
  unfold retry
  by_cases full : s.retries ≥ MAX_RETRIES
  · have limit := (retries_reach_the_limit _).mp full
    exact ⟨s, .Done, by simp [full], .exhausted limit⟩
  · have below : s.retries.val < 3 := by
      have := (retries_reach_the_limit s.retries).not.mp full
      omega
    obtain ⟨i, incremented, val_i⟩ := increment s.retries (by omega)
    exact ⟨_, _, by simp [full, incremented], .again i below val_i⟩

/-- The state `redirect` gives to `send`: one more hop, and the method and the body after the
answer. -/
def redirected (s : State) (hops : U8) (keeps : Bool) : State :=
  { s with hops := hops, method := methodAfter keeps s.method, body := keeps && s.body }

/-- Whether the shell may remember a redirect (the Rust `remember` of `redirect`): the target is
not the origin the request started on, the redirect is the first of the pass, the request is
cacheable, and the target is allowed. -/
def remembers (s : State) (next : Target) : Bool :=
  !next.start && decide (s.hops.val = 0) && s.begin.cacheable && next.allowed

/-- The three ways `redirect` can end: too many hops, a body that would go to another origin, or
the send to the target (with a new hop). -/
inductive RedirectMoves (s : State) (keeps : Bool) (next : Target) : State → Action → Prop
  | too_many : 10 ≤ s.hops.val → RedirectMoves s keeps next s (.Refuse .TooMany)
  | body_refused : s.hops.val < 10 → (keeps && s.body && !next.start) = true →
      RedirectMoves s keeps next s (.Refuse .Body)
  | sent (hops : U8) (n : State) (a : Action) : s.hops.val < 10 →
      (keeps && s.body && !next.start) = false → hops.val = s.hops.val + 1 →
      SendMoves (redirected s hops keeps) next (remembers s next) n a →
      RedirectMoves s keeps next n a

/-- `redirect` returns when the hops are in range, and does one of the three. -/
theorem redirect_moves (s : State) (keeps : Bool) (next : Target) (bounded : s.hops.val ≤ 10) :
    ∃ n a, redirect s keeps next = ok (n, a) ∧ RedirectMoves s keeps next n a := by
  unfold redirect
  -- too many hops
  by_cases full : s.hops ≥ MAX_REDIRECTS
  · have limit := (hops_reach_the_limit _).mp full
    exact ⟨s, _, by simp [full], .too_many limit⟩
  · have below : s.hops.val < 10 := by
      have := (hops_reach_the_limit s.hops).not.mp full
      omega
    -- a body that would go to another origin
    by_cases refused : (keeps && s.body && !next.start) = true
    · refine ⟨s, _, ?_, .body_refused below refused⟩
      simp at refused
      simp [full, refused]
    -- the send to the target: the hop is counted, then every combination of what the code reads
    · have sent : (keeps && s.body && !next.start) = false := by simpa using refused
      obtain ⟨i, incremented, val_i⟩ := increment s.hops (by omega)
      obtain ⟨n, a, sends, moves⟩ := send_moves (redirected s i keeps) next (remembers s next)
      refine ⟨n, a, ?_, .sent i n a below sent val_i moves⟩
      rw [← sends]
      simp [full, incremented, redirected, methodAfter, remembers]
      have zero_iff : s.hops = 0#u8 ↔ s.hops.val = 0 := by
        constructor
        · intro h; simp [h]
        · intro h; scalar_tac
      by_cases zero : s.hops.val = 0 <;>
      cases keeps <;> cases hb : s.body <;> cases hn : next.start <;> cases hm : s.method <;>
        cases hc : s.begin.cacheable <;> cases ha : next.allowed <;> simp_all

/-- The state a new pass starts from (the `Authed` case of `step`). -/
def newPass (s : State) (probe held : Bool) : State :=
  { s with probe := probe, held := held, hops := 0#u8, https := false,
           method := s.begin.method, body := s.begin.body }

/-- The ways `step` can end, one for each answer of the registry it can be given.  Each says
which event it is for, what the state must say, and the state and the action that follow.  The
case `authed` is a pass that goes to its first URL; `hinted`, `challenged` and `refused` are
the answers that ask for a new pass (`refused` asks for a token other than the one that was
refused; a hint or a `/v2/` challenge after that one ends the request: `hinted_refreshed`,
`v2_refreshed`); `probe_missing` asks the `/v2/` challenge; `redirect` follows a redirect; the
others stop the request (`Done` or `Refuse`). -/
inductive Moves (s : State) : Event → State → Action → Prop
  | authed (probe held : Bool) (n : State) (a : Action) :
      SendMoves (newPass s probe held) s.begin.start false n a →
      Moves s (.Authed probe held) n a
  | hinted (n : State) (a : Action) : s.at_home = true → s.refreshed = false →
      RetryMoves s n a → Moves s (.Got .Hinted) n a
  | hinted_refreshed : s.at_home = true → s.refreshed = true → Moves s (.Got .Hinted) s .Done
  | challenged (n : State) (a : Action) : s.at_home = true → s.refreshed = false →
      s.probe = true → RetryMoves s n a → Moves s (.Got (.Unauthorized true)) n a
  | refused (challenge : Bool) (n : State) (a : Action) : s.at_home = true →
      s.refreshed = false → (s.probe && challenge) = false →
      RetryMoves { s with refreshed := true } n a → Moves s (.Got (.Unauthorized challenge)) n a
  | probe_missing : s.at_home = true → s.probe = true → Moves s (.Got .Missing) s .AskV2
  | redirect (keeps : Bool) (next : Target) (n : State) (a : Action) :
      RedirectMoves s keeps next n a → Moves s (.Got (.Redirect keeps next)) n a
  | unusable_too_many : 10 ≤ s.hops.val → Moves s (.Got .Unusable) s (.Refuse .TooMany)
  | unusable_location : s.hops.val < 10 → Moves s (.Got .Unusable) s (.Refuse .Location)
  | v2_learned (n : State) (a : Action) : s.refreshed = false → RetryMoves s n a →
      Moves s (.V2 true) n a
  | v2_refreshed : s.refreshed = true → Moves s (.V2 true) s .Done
  | served : Moves s (.Got .Served) s .Done
  | v2_unknown : Moves s (.V2 false) s .Done
  | hinted_away : s.at_home = false → Moves s (.Got .Hinted) s .Done
  | unauthorized_closed (challenge : Bool) : (s.at_home = false ∨ s.refreshed = true) →
      Moves s (.Got (.Unauthorized challenge)) s .Done
  | missing_closed : (s.at_home = false ∨ s.probe = false) → Moves s (.Got .Missing) s .Done

/-- `step` returns at a state whose counters are in range, and does one of the cases of `Moves`.
This is the one fact about the code that the proofs of the other files rest on. -/
theorem advance_moves (s : State) (e : Event) (retries_bounded : s.retries.val ≤ 3)
    (hops_bounded : s.hops.val ≤ 10) : ∃ n a, advance s e = ok (n, a) ∧ Moves s e n a := by
  unfold advance
  cases e with
  -- a pass: it goes to the URL the request started at
  | Authed probe held =>
    obtain ⟨n, a, sends, moves⟩ := send_moves (newPass s probe held) s.begin.start false
    exact ⟨n, a, sends, .authed probe held n a moves⟩
  -- the `/v2/` challenge: asked again with a retry, or dropped
  | V2 learned =>
    cases learned
    · exact ⟨s, .Done, rfl, .v2_unknown⟩
    · by_cases refreshed : s.refreshed = true
      · exact ⟨s, .Done, by simp [refreshed], .v2_refreshed refreshed⟩
      · have unrefreshed : s.refreshed = false := by simpa using refreshed
        obtain ⟨n, a, retries, moves⟩ := retry_moves s retries_bounded
        exact ⟨n, a, by simp [refreshed, retries], .v2_learned n a unrefreshed moves⟩
  -- an answer to a send, one case for each kind of answer
  | Got answer =>
    unfold got
    cases answer with
    | Hinted =>
      by_cases at_home : s.at_home = true
      · by_cases refreshed : s.refreshed = true
        · exact ⟨s, .Done, by simp [at_home, refreshed], .hinted_refreshed at_home refreshed⟩
        · have unrefreshed : s.refreshed = false := by simpa using refreshed
          obtain ⟨n, a, retries, moves⟩ := retry_moves s retries_bounded
          exact ⟨n, a, by simp [at_home, refreshed, retries], .hinted n a at_home unrefreshed moves⟩
      · have away : s.at_home = false := by simpa using at_home
        exact ⟨s, .Done, by simp [away], .hinted_away away⟩
    | Unauthorized challenge =>
      by_cases at_home : s.at_home = true
      · by_cases refreshed : s.refreshed = true
        · exact ⟨s, .Done, by simp [at_home, refreshed],
            .unauthorized_closed challenge (.inr refreshed)⟩
        · have unrefreshed : s.refreshed = false := by simpa using refreshed
          by_cases learned : (s.probe && challenge) = true
          · have probing : s.probe = true := by simp_all
            have challenged : challenge = true := by simp_all
            obtain ⟨n, a, retries, moves⟩ := retry_moves s retries_bounded
            subst challenged
            exact ⟨n, a, by simp [at_home, unrefreshed, probing, retries],
              .challenged n a at_home unrefreshed probing moves⟩
          · have unlearned : (s.probe && challenge) = false := by simpa using learned
            obtain ⟨n, a, retries, moves⟩ :=
              retry_moves { s with refreshed := true } retries_bounded
            refine ⟨n, a, ?_, .refused challenge n a at_home unrefreshed unlearned moves⟩
            cases hp : s.probe <;> cases challenge <;> simp_all
      · have away : s.at_home = false := by simpa using at_home
        exact ⟨s, .Done, by simp [away], .unauthorized_closed challenge (.inl away)⟩
    | Missing =>
      by_cases at_home : s.at_home = true
      · by_cases probing : s.probe = true
        · exact ⟨s, .AskV2, by simp [at_home, probing], .probe_missing at_home probing⟩
        · have blind : s.probe = false := by simpa using probing
          exact ⟨s, .Done, by simp [at_home, blind], .missing_closed (.inr blind)⟩
      · have away : s.at_home = false := by simpa using at_home
        exact ⟨s, .Done, by simp [away], .missing_closed (.inl away)⟩
    | Redirect keeps next =>
      obtain ⟨n, a, redirects, moves⟩ := redirect_moves s keeps next hops_bounded
      exact ⟨n, a, redirects, .redirect keeps next n a moves⟩
    | Unusable =>
      by_cases full : s.hops ≥ MAX_REDIRECTS
      · exact ⟨s, _, by simp [full], .unusable_too_many ((hops_reach_the_limit _).mp full)⟩
      · have below : s.hops.val < 10 := by
          have := (hops_reach_the_limit s.hops).not.mp full
          omega
        exact ⟨s, _, by simp [full], .unusable_location below⟩
    | Served => exact ⟨s, .Done, rfl, .served⟩

/-- What the core waits for after it gave the action `a` (the Rust function `waits_after`). -/
def waitAfter : Action → Wait
  | .Pass _ => .Pass
  | .Send _ => .Answer
  | .AskV2 => .V2
  | .Done => .Over
  | .Refuse _ => .Over

/-- The event is the one the core waits for (the Rust function `answers`). -/
def Answers : Wait → Event → Prop
  | .Pass, .Authed _ _ => True
  | .Answer, .Got _ => True
  | .V2, .V2 _ => True
  | _, _ => False

/-- The event answers the last action exactly when the core, which waits for what the action
asked, is waiting for it. -/
theorem fits_is_answers (a : Action) (e : Event) : Fits a e ↔ Answers (waitAfter a) e := by
  cases a <;> cases e <;> simp [Fits, Answers, waitAfter]

/-- `answers` returns, and its answer is true exactly when the event is the one waited for. -/
theorem answers_is (w : Wait) (e : Event) : ∃ b, answers w e = ok b ∧ (b = true ↔ Answers w e) := by
  cases w <;> cases e <;> simp [answers, Answers]

/-- `waits_after` returns `waitAfter`. -/
theorem waits_after_is (a : Action) : waits_after a = ok (waitAfter a) := by
  cases a <;> simp [waits_after, waitAfter]

/-- The two ways `step` can end: the event is the one waited for and the request goes on as
`advance` says (the state then waits for what the new action asks), or it is not and the request
is refused as out of turn, with the state left as it was and waiting for nothing. -/
inductive StepMoves (s : State) (e : Event) : State → Action → Prop
  | in_turn (n : State) (a : Action) : Answers s.wait e → Moves s e n a →
      StepMoves s e { n with wait := waitAfter a } a
  | out_of_turn : ¬ Answers s.wait e →
      StepMoves s e { s with wait := .Over } (.Refuse .OutOfTurn)

/-- `step` returns at a state whose counters are in range, and does one of the two cases. -/
theorem step_moves (s : State) (e : Event) (retries_bounded : s.retries.val ≤ 3)
    (hops_bounded : s.hops.val ≤ 10) : ∃ n a, step s e = ok (n, a) ∧ StepMoves s e n a := by
  unfold step
  obtain ⟨flag, flagged, flag_iff⟩ := answers_is s.wait e
  rw [flagged]
  cases flag
  · refine ⟨_, _, ?_, .out_of_turn (by simpa using flag_iff)⟩
    simp [settle, waits_after_is, waitAfter]
  · obtain ⟨n, a, advanced, moves⟩ := advance_moves s e retries_bounded hops_bounded
    refine ⟨_, _, ?_, .in_turn n a (flag_iff.mp rfl) moves⟩
    simp [advanced, settle, waits_after_is]
