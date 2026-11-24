-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/send-core, the send loop of the registry client,
-- in words and in statements, with no proof.  This file is what a reviewer reads; Lean checks the
-- rest (the proofs are in the other files of SendCore/, and Theorems.lean ties each claim below
-- to its proof).
--
-- The loop.  A request to a registry is a series of PASSES.  A pass starts at the URL the request
-- was made for, with an `Authorization` or without, and follows redirects.  The shell (the
-- registry client, crates/registry) sends one request at a time and tells the core what came back;
-- the core (`begin` and `step` of src/lib.rs) answers with what to do next: begin a pass (`Pass`),
-- send a request (`Send`, which is `Home` when it goes to the registry's own origin and may carry
-- the `Authorization`, and `Away` otherwise, and has no field for one), ask the `/v2/` challenge
-- (`AskV2`), stop with the last answer (`Done`) or refuse (`Refuse`).
--
-- Why it is needed: a registry, and the hosts it names (the token realm, the CDN of a blob, the
-- host of an upload) may be hostile or broken.  The credentials and the body of a request must go
-- only where the request was meant to go, whatever they answer, and a request must end.  The
-- tests of the crate (src/walk.rs, src/rules.rs) check the rules on every state that a small
-- world reaches (about three million).  Each claim below is a rule for EVERY run: every series of
-- events the shell may tell, in any order, with any facts it reports.
-- A proof is worth what its statement says, so each claim has a comment of what it claims and of
-- what it does NOT.
--
-- Runs.  A `Run b tr s a` is what happens when the shell starts a request `b` (`begin`) and then
-- tells events: `tr` is the list of the turns so far (an event the shell told, the action `step`
-- gave), and `s` and `a` are the state and the last action.  The events are ANY events: the
-- shell is not assumed to tell the one that answers the last action (`Fits`: `Authed` after a
-- `Pass`, an answer after a `Send`, `V2` after an `AskV2`, nothing after a `Done` or a `Refuse`):
-- an event that does not is refused by the core (`EventsOutOfTurnAreRefused`), and the rules
-- hold for every series.  The facts it tells are any too: a redirect to anywhere, a 401 at any
-- time, and so on.  Everything the claims say about "who got the request" is read from the facts
-- the shell reported in the run (`targetOf`), never from the core's own flags.
--
-- Both directions: "no Authorization to another origin" alone is satisfied by a core that refuses
-- everything.  So the last claims say that the honest exchanges are carried out.
--
-- Read before this file: the header of crates/send-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every run):
--
--   The functions return, and an event out of turn is refused
--     BeginAndStepAlwaysReturn         `begin` returns, and `step` returns for every event at
--                                      every state of a run (no panic, no overflow of a counter)
--     EventsOutOfTurnAreRefused        an event that answers the last action is never refused as
--                                      out of turn, and one that does not is
--
--   The Authorization stays at home
--     AnAwayRequestHasNoAuthorization  a request to another origin has no `Authorization` (by its
--                                      type)
--     AuthorizationOnlyBeforeLeavingHome
--                                      a send that carries it goes to the registry's origin, and
--                                      no earlier send of the run went anywhere else
--     NoAuthorizationAfterLeavingHome  after a send to another origin, no later send carries it
--     AHomeSendCarriesItsPassesAuthorization
--                                      a send to the registry's origin carries the
--                                      `Authorization` exactly when the pass it belongs to holds
--                                      one (as the shell told in the `Authed` of the pass)
--
--   No downgrade
--     NoDowngrade                      a run that began on https sends nothing to http
--     NoDowngradeAfterHttps            a redirect that follows a send to an https target goes to
--                                      https (also for an http registry)
--
--   The address policy comes first
--     EverySendIsAllowed               every send is to a target the policy allowed
--     OnlyAnAllowedRedirectIsRemembered
--                                      what the shell may remember is the first redirect of a
--                                      request for a blob, to an allowed target away from the
--                                      origin of the start
--
--   The body
--     BodyOnlyToTheStartOrigin         a request has a body only when it goes to the origin the
--                                      request started on
--     RedirectsRewriteTheRequest       after a redirect the method and the body are what the
--                                      code says (a 301, 302 or 303 drops the body)
--     APassStartsFromTheRequest        the first send of a pass has the method and the body of
--                                      the request as it began
--
--   The loop ends
--     AtMostSoManySends                a run has at most (MAX_RETRIES + 1) * (MAX_REDIRECTS + 1)
--                                      sends: 44
--     AtMostSoManyTurns                a run has at most (MAX_RETRIES + 1) * (MAX_REDIRECTS + 3)
--                                      turns that are not refused as out of turn, and one of
--                                      that length is at `Done` or `Refuse`: 52
--
--   Tokens
--     AsksOnlyAfterAHomeAnswer         a new pass, and the `/v2/` challenge, come only after an
--                                      answer of the registry's own origin, before the request
--                                      left it
--     AFreshTokenIsAskedAtMostOnce     at most one turn of a run asks for a token other than the
--                                      one that was refused (a `Pass` with `refresh`)
--
--   The honest exchanges are carried out (so refusing everything fails)
--     ASuccessIsDone                   a 200 to the first request: `Done`
--     AChallengeThenSuccessGetsOneToken
--                                      a 401 with a challenge to a probe: one new pass, with the
--                                      `Authorization`, and `Done` on the 200
--     ARedirectToAnAllowedHttpsHostIsFollowed
--                                      a redirect that turns the request into a GET (301,
--                                      302, 303) to an allowed https host: sent, with no body,
--                                      and `Done` on the 200
--     AnUploadKeepsItsBodyOnItsOwnHost
--                                      a request that starts on another host than the registry
--                                      (an upload) is sent there with its body, also after a
--                                      redirect that keeps the method inside that host
--
--   The rules of rules.rs, and where each is claimed (rules.rs numbers them in its comments):
--     1 credentials                    AuthorizationOnlyBeforeLeavingHome, NoAuthorizationAfter...,
--                                      AHomeSendCarriesItsPassesAuthorization
--     2 body                           BodyOnlyToTheStartOrigin, RedirectsRewriteTheRequest,
--                                      APassStartsFromTheRequest
--     3 no http after https            NoDowngrade, NoDowngradeAfterHttps
--     4 allowed, remembered            EverySendIsAllowed, OnlyAnAllowedRedirectIsRemembered
--     5 counters                       AtMostSoManySends, AtMostSoManyTurns,
--                                      BeginAndStepAlwaysReturn (the counters stay in range, so
--                                      no addition overflows)
--     6 new pass, token, `/v2/`        AsksOnlyAfterAHomeAnswer, AFreshTokenIsAskedAtMostOnce
--     7 events out of turn             EventsOutOfTurnAreRefused (and every claim being for any
--                                      series of events)
--     8 honest exchanges               the four liveness claims
--
--   Of the rules, not claimed:
--   - that the counters only grow (they are only claimed to stay in range, and the number of
--     sends and turns is bounded, which is what the growth is for);
--   - that EVERY honest redirect is followed (rules.rs `honest`), and that a 200 to any request,
--     a 401 or a 404 after the request left home, are `Done`: the liveness claims say it for the
--     exchanges they state, and `AsksOnlyAfterAHomeAnswer` says that no such answer asks for
--     anything else;
--   - which `Why` a refusal carries (except that of an event out of turn);
--   - that a 401 or a `/v2/` challenge after a fresh token ends the request with the answer it
--     has (the claim is that no second fresh token is asked; the shell cannot reach that answer
--     after a refresh, since it drops a hint of the cache only once).
--
--   Trusted: Charon and Aeneas (../../pins) and nothing else: no function of the standard library
--   is assumed.
--
--   Not claimed:
--   - that the shell reports the facts truthfully: that `home` is the comparison of the origin
--     (scheme, host, port) of the URL with the registry's, that `start` is the comparison with
--     the URL the request began at, that `https` is the scheme, and that `allowed` is the verdict
--     of the address policy for the very URL it then sends to;
--   - that the shell upgrades an http location on the registry's own host to https before the
--     core sees it (`NoDowngradeAfterHttps` is about the targets the shell reports);
--   - that the registry's own origin is marked `allowed` without asking the address policy (its
--     URL is the configured endpoint, not something the registry said), that `allowed` is
--     computed by the shell on the URL it then sends to, and that `start` is computed as "same
--     origin as the URL the request began at": a shell that told `start` for another origin
--     could send a body there (`BodyOnlyToTheStartOrigin` is about the facts it reports);
--   - that the shell does what the action says (sends the request to that URL, with that method,
--     that body and that `Authorization` only when it is told to), and that the only credentials
--     it attaches are this registry's own;
--   - that the address the policy checked is the one the connection goes to (DNS between the
--     check and the send);
--   - what the setting `insecure` covers (it is the shell's: the core is told `https` and
--     `allowed` and applies them);
--   - that the token service, or the realm it is at, is honest or reachable;
--   - the list of endpoints the registry is asked, and which of the requests is made when.
--
-- Notation:
--   - `step s e = ok (n, a)` reads: the Rust function `step`, given the state `s` and the event
--     `e`, returns (it does not panic) the state `n` and the action `a`.
--   - `Run b tr s a`: see above.  `tr = pre ++ x :: post` is "`x` is one of the turns of the run,
--     `pre` those before it and `post` those after it".
--   - `∀ x ∈ tr, P` is "for every turn `x` of `tr`, P"; `∃` is "there is"; `∧` "and"; `∨` "or";
--     `→` "if ... then"; `¬` "not"; `l.countP p` is the number of the elements of `l` that `p`
--     accepts; `(MAX_RETRIES).val` is the number the constant stands for.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_send_core

namespace SendCore

/-! ### Runs -/

/-- One turn of a run: the event the shell told and the action `step` answered. -/
structure Turn where
  event : Event
  action : Action

/-- The event answers the action: `Authed` follows a `Pass`, an answer (`Got`) follows a `Send`,
`V2` follows an `AskV2`; nothing follows a `Done` or a `Refuse`.  The core refuses any other
event (`EventsOutOfTurnAreRefused`); the honest exchanges are made of events that fit. -/
def Fits : Action → Event → Prop
  | .Pass _, .Authed _ _ => True
  | .Send _, .Got _ => True
  | .AskV2, .V2 _ => True
  | _, _ => False

/-- The URL a send goes to, as the shell reported it: the core sends it to the URL of the event that
led to it: the start URL after an `Authed` (the `start` of `Begin`), the resolved `Location`
(`next`) after a redirect.  An event that is not one of these leads to no send. -/
def targetOf (b : Begin) : Event → Option Target
  | .Authed _ _ => some b.start
  | .Got (.Redirect _ next) => some next
  | _ => none

/-- A run of the request `b`: `begin` returns the first state and action, and each event, any
event, given to `step`, gives the next.  `tr` has the turns in order. -/
inductive Run (b : Begin) : List Turn → State → Action → Prop
  | begins {s : State} {a : Action} : begin b = ok (s, a) → Run b [] s a
  | answers {tr : List Turn} {s : State} {a : Action} {e : Event} {n : State} {a' : Action} :
      Run b tr s a → step s e = ok (n, a') → Run b (tr ++ [⟨e, a'⟩]) n a'

/-- The turn is a send of the request `r` to the target `t`. -/
def SendsTo (b : Begin) (x : Turn) (r : Request) (t : Target) : Prop :=
  x.action = .Send r ∧ targetOf b x.event = some t

/-- The request left the registry's origin: one of the turns is a send to a target that is not
the registry's.  This is read from what the shell reported, not from the flag `left_home` of the
state. -/
def Left (b : Begin) (tr : List Turn) : Prop :=
  ∃ x ∈ tr, ∃ r t, SendsTo b x r t ∧ t.home = false

/-- Some turn is a send to the registry's own origin (the request is at home). -/
def WasAtHome (b : Begin) (tr : List Turn) : Prop :=
  ∃ x ∈ tr, ∃ r t, SendsTo b x r t ∧ t.home = true

/-- The request has an `Authorization`. -/
def CarriesAuthorization (r : Request) : Prop :=
  ∃ m body, r = .Home true m body

/-- The method of a request. -/
def methodOf : Request → Method
  | .Home _ m _ => m
  | .Away m _ _ => m

/-- Whether a request has a body. -/
def bodyOf : Request → Bool
  | .Home _ _ body => body
  | .Away _ body _ => body

/-- The method after an answer: a redirect that `keeps` it (a 307 or a 308) leaves it; the others
(301, 302, 303) turn a request into a GET, except a HEAD, which stays one. -/
def methodAfter : Bool → Method → Method
  | true, m => m
  | false, .Head => .Head
  | false, _ => .Get

/-- A send of the action: the request is a send of a `Send`. -/
def isSend : Action → Bool
  | .Send _ => true
  | _ => false

/-- The run is over: the action is `Done` or `Refuse`. -/
def Finished : Action → Prop
  | .Done => True
  | .Refuse _ => True
  | _ => False

/-- The turn asks for a token other than the one that was refused: a `Pass` that `refresh`es. -/
def asksAFreshToken (x : Turn) : Bool :=
  match x.action with
  | .Pass true => true
  | _ => false

/-- The core refused the turn because its event does not answer the last action. -/
def isOutOfTurn (x : Turn) : Bool :=
  match x.action with
  | .Refuse .OutOfTurn => true
  | _ => false

/-- Whether the pass the run is in holds an `Authorization`, as the shell told it: the `held` of
the last `Authed` the core did not refuse.  None before the first pass. -/
def passHeld (tr : List Turn) : Option Bool :=
  tr.reverse.findSome? fun x =>
    match x.event, isOutOfTurn x with
    | .Authed _ held, false => some held
    | _, _ => none

/-- The request as the shell knows it is well formed: its start is the origin it started on (the
shell reports `start` true for the URL a request starts at). -/
def StartsOnItsOrigin (b : Begin) : Prop :=
  b.start.start = true

/-- A request to the registry's own origin that the policy allows, on an https registry only if
its URL is https: the kind of request the honest exchanges are made of. -/
def AtTheRegistry (b : Begin) : Prop :=
  b.start.home = true ∧ b.start.start = true ∧ b.start.allowed = true ∧
    (b.home_https = true → b.start.https = true)

/-! ### The claims -/

/-- **The functions return.**  `begin` returns for every request, and `step` returns at every
state of every run, for every event: no panic, no overflow of a counter, whatever the shell
tells.

Not said: what they return (the claims below). -/
def BeginAndStepAlwaysReturn : Prop :=
  (∀ b : Begin, ∃ s a, begin b = ok (s, a)) ∧
  (∀ (b : Begin) (tr : List Turn) (s : State) (a : Action) (e : Event),
    Run b tr s a → ∃ n a', step s e = ok (n, a'))

/-- **An event out of turn is refused.**  At every state of every run, an event that answers the
last action (`Fits`) is not refused as out of turn, and one that does not (an `Authed` after a
send, an answer after a `Done`, ...) is, and nothing else is done.  So the claims below, which
say what is sent, hold whatever order the shell tells its events in.

Not said: that the shell tells them in order (it is not assumed; a shell that does not ends the
request with an error). -/
def EventsOutOfTurnAreRefused : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action) (e : Event), Run b tr s a →
    ∃ n a', step s e = ok (n, a') ∧
      ((Fits a e ∧ a' ≠ .Refuse .OutOfTurn) ∨ (¬ Fits a e ∧ a' = .Refuse .OutOfTurn))

/-- **A request to another origin has no `Authorization`.**  The type `Away` has no field for
one: whatever the core does, a send that is `Away` carries none.

Not said: that the shell attaches nothing else (it does what the action says: not claimed). -/
def AnAwayRequestHasNoAuthorization : Prop :=
  ∀ (m : Method) (body remember : Bool), ¬ CarriesAuthorization (.Away m body remember)

/-- **The `Authorization` is only for the registry, before the request left it.**  In every run,
a send that carries an `Authorization` is to a target the shell reported as the registry's own
origin, and no earlier send of the run went to another origin (`Left` is read from the reports
of the run, not from the state of the core).

Not said: that the report is true (the shell compares the origins); that the `Authorization` is
the registry's own and not another's. -/
def AuthorizationOnlyBeforeLeavingHome : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ (pre : List Turn) (x : Turn) (post : List Turn), tr = pre ++ x :: post →
      ∀ (r : Request) (t : Target), SendsTo b x r t → CarriesAuthorization r →
        t.home = true ∧ ¬ Left b pre

/-- **Never again after another origin.**  In every run, once a send went to another origin, no
later send carries an `Authorization`, not even one back to the registry (the URL is the one the
other origin chose).

Not said: anything of the sends to another origin themselves (`Away`: none). -/
def NoAuthorizationAfterLeavingHome : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ (pre : List Turn) (x : Turn) (post : List Turn), tr = pre ++ x :: post → Left b pre →
      ∀ (r : Request) (t : Target), SendsTo b x r t → ¬ CarriesAuthorization r

/-- **A `Home` send carries its pass's own `Authorization`.**  In every run, a send to the
registry's origin carries an `Authorization` exactly when the `Authed` that began the pass it
belongs to said the shell holds one (a hint of the cache that was dropped, a probe, and so on, are
the shell's business: the core sends what the shell said).

Not said: that the shell attaches the credentials of this registry only. -/
def AHomeSendCarriesItsPassesAuthorization : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ (pre : List Turn) (x : Turn) (post : List Turn), tr = pre ++ x :: post →
      ∀ (auth : Bool) (m : Method) (body : Bool), x.action = .Send (.Home auth m body) →
        passHeld (pre ++ [x]) = some auth

/-- **No downgrade.**  In every run that began on https (the registry is https, or the URL the
request started at is), no send goes to a target the shell reported as not https: neither a
redirect nor a new pass.

Not said: that the shell reports `https` truthfully; that a request of an http registry that
never was on https stays off http (it may go anywhere the policy allows: the next claim says what
happens once it was). -/
def NoDowngrade : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    (b.home_https = true ∨ b.start.https = true) →
      ∀ x ∈ tr, ∀ (r : Request) (t : Target), SendsTo b x r t → t.https = true

/-- **No downgrade once on https.**  In every run, a redirect that follows a send to a target the
shell reported as https goes to an https target, whatever the registry is: a request of an http
registry that was sent to https is not sent back to http.

Not said: that the shell upgrades an http location of the registry's own host to https before
the core sees it (see "Not claimed"). -/
def NoDowngradeAfterHttps : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ (pre : List Turn) (p x : Turn) (post : List Turn), tr = pre ++ p :: x :: post →
      ∀ (rp r : Request) (tp next : Target) (keeps : Bool),
        SendsTo b p rp tp → tp.https = true → x.event = .Got (.Redirect keeps next) →
          x.action = .Send r → next.https = true

/-- **Every send is allowed by the policy.**  In every run, each send has a target (it follows a
pass or a redirect, the two events that name one) and the policy allowed it, as the shell
reported in the event.

Not said: that the verdict is for the URL the shell then connects to (the shell's, and DNS). -/
def EverySendIsAllowed : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ x ∈ tr, ∀ (r : Request), x.action = .Send r →
      ∃ t, SendsTo b x r t ∧ t.allowed = true

/-- **Only an allowed redirect is remembered.**  In every run, a send that tells the shell it may
remember the URL (`Away` with `remember`) answers a redirect of the first send of its pass (the
send just after the `Authed` that began the pass: there is always a turn before it), for a request that asked for it
(`cacheable`), to a target the policy allowed and that is not the origin of the start.

Not said: that the shell remembers nothing else; what it does with the URL it remembers. -/
def OnlyAnAllowedRedirectIsRemembered : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ (pre : List Turn) (x : Turn) (post : List Turn), tr = pre ++ x :: post →
      ∀ (m : Method) (body : Bool), x.action = .Send (.Away m body true) →
        (∃ pre' p probe held, pre = pre' ++ [p] ∧ p.event = .Authed probe held) ∧
        (∃ keeps next, x.event = .Got (.Redirect keeps next) ∧ next.allowed = true ∧
          next.start = false) ∧ b.cacheable = true

/-- **A body only to the origin the request started on.**  In every run of a request that starts
on its own origin (`StartsOnItsOrigin`), a send that has a body goes to a target the shell
reported as the origin the request started on.

Not said: that the shell sends what the request says (the body of `Request` is a flag). -/
def BodyOnlyToTheStartOrigin : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a → StartsOnItsOrigin b →
    ∀ x ∈ tr, ∀ (r : Request) (t : Target), SendsTo b x r t → bodyOf r = true → t.start = true

/-- **A redirect rewrites the request as the code says.**  In every run, a send that follows a
send of the request `rp` because of a redirect that `keeps` (307, 308) or not (301, 302, 303) has
the method `methodAfter keeps (method of rp)` (a 301, 302 or 303 makes it a GET, a HEAD stays a
HEAD, any other method becomes a GET) and has a body exactly when it keeps and `rp` had one.  So
after a 301, 302 or 303 no body is sent.

Not said: that the shell sends the method the request names (a flag of `Request`). -/
def RedirectsRewriteTheRequest : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ (pre : List Turn) (p x : Turn) (post : List Turn), tr = pre ++ p :: x :: post →
      ∀ (rp r : Request) (keeps : Bool) (next : Target),
        p.action = .Send rp → x.event = .Got (.Redirect keeps next) → x.action = .Send r →
          methodOf r = methodAfter keeps (methodOf rp) ∧ bodyOf r = (keeps && bodyOf rp) ∧
          (keeps = false → bodyOf r = false)

/-- **A pass starts from the request.**  In every run, the send that follows an `Authed` has the
method and the body the request had when it began: a body dropped by a redirect is back for the
next pass, which starts again at the URL the request began at.

Not said: which of the passes the request needs. -/
def APassStartsFromTheRequest : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ x ∈ tr, ∀ (probe held : Bool) (r : Request), x.event = .Authed probe held →
      x.action = .Send r → methodOf r = b.method ∧ bodyOf r = b.body

/-- **At most so many sends.**  Every run has at most `(MAX_RETRIES + 1) * (MAX_REDIRECTS + 1)`
sends (a pass of at most `MAX_REDIRECTS` redirects has `MAX_REDIRECTS + 1` sends, and there are
at most `MAX_RETRIES + 1` passes): 44 of the constants of the crate.

Not said: that each pass does as many (the walk finds the longest request has 44). -/
def AtMostSoManySends : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    tr.countP (fun x => isSend x.action) ≤ (MAX_RETRIES.val + 1) * (MAX_REDIRECTS.val + 1)

/-- **At most so many turns, and then it is over.**  Every run has at most
`(MAX_RETRIES + 1) * (MAX_REDIRECTS + 3)` turns that are not refused as out of turn (in a pass: the
`Authed`, at most `MAX_REDIRECTS + 1` answers to its sends and a `V2`): 52.  A run with that
many is at `Done` or `Refuse`.  So every series of events ends, whatever the shell says (an event
after the end is refused as out of turn and does nothing).

Not said: that it ends as early as the honest exchanges do. -/
def AtMostSoManyTurns : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    tr.countP (fun x => !isOutOfTurn x) ≤ (MAX_RETRIES.val + 1) * (MAX_REDIRECTS.val + 3) ∧
    ((MAX_RETRIES.val + 1) * (MAX_REDIRECTS.val + 3) ≤ tr.countP (fun x => !isOutOfTurn x) →
      Finished a)

/-- **A token, and the `/v2/` challenge, only after the registry answered.**  In every run, a
turn that begins a new pass (`Pass`) answers a 401 or a 403 (`Hinted`, `Unauthorized`) or the
learned `/v2/` challenge (`V2 true`), and a turn that asks the `/v2/` challenge (`AskV2`)
answers a 403 or 404 (`Missing`); in both, the request has not left the registry's origin (no
earlier send went elsewhere, `¬ Left`) and has been sent to it (`WasAtHome`).

Not said: that the answer was honest; that the token service is (it is the shell's). -/
def AsksOnlyAfterAHomeAnswer : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    ∀ (pre : List Turn) (x : Turn) (post : List Turn), tr = pre ++ x :: post →
      ((∃ refresh, x.action = .Pass refresh) →
        (x.event = .Got .Hinted ∨ (∃ c, x.event = .Got (.Unauthorized c)) ∨ x.event = .V2 true) ∧
        ¬ Left b pre ∧ WasAtHome b pre) ∧
      (x.action = .AskV2 → x.event = .Got .Missing ∧ ¬ Left b pre ∧ WasAtHome b pre)

/-- **A fresh token at most once.**  In every run, at most one turn has the action `Pass` with
`refresh`, that asks for a token other than the one that was refused.

Not said: that the token service gives one; how many passes without `refresh` there are (they
are bounded by the retries). -/
def AFreshTokenIsAskedAtMostOnce : Prop :=
  ∀ (b : Begin) (tr : List Turn) (s : State) (a : Action), Run b tr s a →
    tr.countP asksAFreshToken ≤ 1

/-- **A success is done.**  For a request to the registry (`AtTheRegistry`), after the first
pass (any `held`, `probe`) the core sends the request with the method and the body of the request
and the `Authorization` of the pass, and a 200 (`Served`) to it is `Done`.

Not said: the other answers (the claims below), and what the shell does with the answer. -/
def ASuccessIsDone : Prop :=
  ∀ (b : Begin), AtTheRegistry b → ∀ (s : State) (a : Action), begin b = ok (s, a) →
    ∀ probe held : Bool, ∃ s1 s2, step s (.Authed probe held) =
        ok (s1, .Send (.Home held b.method b.body)) ∧ step s1 (.Got .Served) = ok (s2, .Done)

/-- **A challenge, then a success, gets one token.**  For a request to the registry: a probe
(a pass without the `Authorization`) that is answered by a 401 with a challenge gives one new pass
that does not ask for a fresh token; the shell then tells it holds the token, the request is sent
again with the `Authorization`, and a 200 is `Done`.

Not said: that the token is obtained (the shell and the token service). -/
def AChallengeThenSuccessGetsOneToken : Prop :=
  ∀ (b : Begin), AtTheRegistry b → ∀ (s : State) (a : Action), begin b = ok (s, a) →
    ∃ s1 s2 s3 s4,
      step s (.Authed true false) = ok (s1, .Send (.Home false b.method b.body)) ∧
      step s1 (.Got (.Unauthorized true)) = ok (s2, .Pass false) ∧
      step s2 (.Authed false true) = ok (s3, .Send (.Home true b.method b.body)) ∧
      step s3 (.Got .Served) = ok (s4, .Done)

/-- **A redirect to an allowed https host is followed.**  For a request to the registry: a 301,
302 or 303 (it does not keep the method) to a target that is another origin, https and allowed by
the policy is sent, as a request with no body and the method after the redirect, that may be
remembered when the request is cacheable; and a 200 to it is `Done`.

Not said: every redirect (the claims above refuse some on purpose: http, not allowed, with a body
to another origin). -/
def ARedirectToAnAllowedHttpsHostIsFollowed : Prop :=
  ∀ (b : Begin), AtTheRegistry b → ∀ (s : State) (a : Action), begin b = ok (s, a) →
    ∀ next : Target, next.home = false → next.start = false → next.https = true →
      next.allowed = true →
        ∃ s1 s2 s3,
          step s (.Authed false true) = ok (s1, .Send (.Home true b.method b.body)) ∧
          step s1 (.Got (.Redirect false next)) =
            ok (s2, .Send (.Away (methodAfter false b.method) false b.cacheable)) ∧
          step s2 (.Got .Served) = ok (s3, .Done)

/-- **An upload is sent on its own host.**  For a request that starts on another host than the
registry (an upload session), whose URL the policy allows (and is https if the registry is): the
first send is `Away` with the method and the body of the request; and a 307 or 308 to the same
origin, with the same scheme and allowed, is sent with the same method and the body; and a 200
after either is `Done`.

Not said: that a redirect to another origin keeps the body (it is refused: `BodyOnlyTo...`). -/
def AnUploadKeepsItsBodyOnItsOwnHost : Prop :=
  ∀ (b : Begin), b.start.home = false → b.start.start = true → b.start.allowed = true →
    (b.home_https = true → b.start.https = true) → ∀ (s : State) (a : Action),
    begin b = ok (s, a) → ∀ probe held : Bool,
      (∃ s1 s2, step s (.Authed probe held) = ok (s1, .Send (.Away b.method b.body false)) ∧
        step s1 (.Got .Served) = ok (s2, .Done)) ∧
      ∀ next : Target, next.home = false → next.start = true → next.https = b.start.https →
        next.allowed = true →
          ∃ s1 s2 s3,
            step s (.Authed probe held) = ok (s1, .Send (.Away b.method b.body false)) ∧
            step s1 (.Got (.Redirect true next)) = ok (s2, .Send (.Away b.method b.body false)) ∧
            step s2 (.Got .Served) = ok (s3, .Done)

end SendCore
