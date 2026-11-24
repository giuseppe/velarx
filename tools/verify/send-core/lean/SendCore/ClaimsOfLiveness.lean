-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the four claims that the honest exchanges are carried out:
-- ASuccessIsDone, AChallengeThenSuccessGetsOneToken, ARedirectToAnAllowedHttpsHostIsFollowed and
-- AnUploadKeepsItsBodyOnItsOwnHost.
--
-- Why it is needed: a core that refuses everything would satisfy every claim that says what is
-- never sent.  These say what is always done, so it does not.
--
-- Read before this file: Spec.lean, StepCases.lean, RunCounters.lean.
--
-- Each proof is a computation: the state after `begin` is known (`begin_state`), the answer of a
-- step is read from the cases of `Moves` (or from the code, for the first pass), and the next
-- step starts from the state this gives.
--
-- Notation: `step s e = ok (n, a)` is "`step` returns `n` and `a`"; `∃` is "there is"; `simp`
-- computes with the definitions it is given.
import SendCore.ClaimsOfTokens
open Aeneas Aeneas.Std Result velarx_send_core
namespace SendCore

/-- What `step` does for a pass: it is `send` to the URL of the request, from the state of a new
pass. -/
theorem step_of_a_pass {s : State} (waits : s.wait = .Pass) (probe held : Bool) :
    step s (.Authed probe held) = ok (
      { moved (newPass s probe held) s.begin.start with
        wait := waitAfter (sendAction (newPass s probe held) s.begin.start false) },
      sendAction (newPass s probe held) s.begin.start false) := by
  unfold step
  simp only [answers, waits]
  have sent := send_eq (newPass s probe held) s.begin.start false
  simp only [newPass] at sent ⊢
  simp [advance, sent, settle, waits_after_is]

/-- What `step` does for a success: it is `Done`, and the state is left alone. -/
theorem step_of_a_success {s : State} (waits : s.wait = .Answer) :
    step s (.Got .Served) = ok ({ s with wait := .Over }, .Done) := by
  simp [step, answers, waits, advance, got, settle, waits_after_is, waitAfter]

/-- A pass of a request to the registry is sent `Home` with the pass's own `Authorization`, the
method and the body of the request. -/
theorem a_pass_at_the_registry {b : Begin} (at_the_registry : AtTheRegistry b) {s : State}
    (begun : s.begin = b) (waits : s.wait = .Pass) (unleft : s.left_home = false)
    (probe held : Bool) :
    step s (.Authed probe held) = ok (
      { moved (newPass s probe held) b.start with wait := .Answer },
      .Send (.Home held b.method b.body)) := by
  obtain ⟨home, _, allowed, scheme⟩ := at_the_registry
  subst begun
  have no_downgrade : ¬ (s.begin.home_https = true ∧ s.begin.start.https = false) :=
    fun ⟨home_https, plain⟩ => by simp [scheme home_https] at plain
  rw [step_of_a_pass waits]
  simp [sendAction, newPass, home, allowed, no_downgrade, unleft, waitAfter]

/-- The first pass is sent `Home`, and the success to it is `Done`. -/
theorem a_success_is_done : ASuccessIsDone := by
  intro b at_the_registry s a started probe held
  obtain ⟨begun, _, _, _, unleft, _, _, _, _, _, waits⟩ := begin_state b s a started
  exact ⟨_, _, a_pass_at_the_registry at_the_registry begun waits unleft probe held,
    step_of_a_success rfl⟩

/-- A 401 with a challenge to a probe of a request at home asks one new pass with no fresh token. -/
theorem step_of_a_challenge {s : State} (at_home : s.at_home = true)
    (unrefreshed : s.refreshed = false) (probing : s.probe = true) (retries : s.retries.val < 3)
    (waits : s.wait = .Answer) :
    ∃ s2 : State, step s (.Got (.Unauthorized true)) = ok (s2, .Pass false) ∧
      s2.begin = s.begin ∧ s2.wait = .Pass ∧ s2.left_home = s.left_home := by
  obtain ⟨i, incremented, _⟩ := increment s.retries (by omega)
  have below : ¬ s.retries ≥ MAX_RETRIES := by
    rw [retries_reach_the_limit]
    omega
  exact ⟨{ s with retries := i, wait := .Pass }, by simp [step, answers, waits, advance, got,
    retry, at_home, unrefreshed, probing, below, incremented, settle, waits_after_is, waitAfter],
    rfl, rfl, rfl⟩

/-- Probe, 401 with a challenge, one new pass with the `Authorization`, success. -/
theorem a_challenge_then_success_gets_one_token : AChallengeThenSuccessGetsOneToken := by
  intro b at_the_registry s a started
  -- the probe, sent home without the `Authorization`
  obtain ⟨begun, no_retries, _, _, unleft, unrefreshed, _, _, _, _, waits⟩ :=
    begin_state b s a started
  have first := a_pass_at_the_registry at_the_registry begun waits unleft true false
  have home := at_the_registry.1
  obtain ⟨s2, challenge, begun2, waits2, unleft2⟩ :=
    step_of_a_challenge (s := { moved (newPass s true false) b.start with wait := .Answer })
      (by simp [moved, newPass, home, unleft]) (by simp [moved, newPass, unrefreshed])
      (by simp [moved, newPass]) (by simp [moved, newPass, no_retries]) rfl
  -- the new pass, sent home with the `Authorization`
  have second := a_pass_at_the_registry at_the_registry (s := s2) (by simp_all [moved, newPass])
    waits2 (by rw [unleft2]; simp [moved, newPass, unleft, home]) false true
  exact ⟨_, _, _, _, first, challenge, second, step_of_a_success rfl⟩

/-- A redirect that is allowed, not to http from https, keeps the body only to the origin of the
start, and is to a target the request is not at home to, is sent as a request to another origin. -/
theorem a_redirect_is_followed {s : State} {keeps : Bool} {next : Target}
    (retries : s.retries.val ≤ 3) (hops : s.hops.val < 10)
    (no_body_refusal : (keeps && s.body && !next.start) = false)
    (no_downgrade : ((s.https || s.begin.home_https) && !next.https) = false)
    (allowed : next.allowed = true) (away : (!s.left_home && next.home) = false)
    (waits : s.wait = .Answer) :
    ∃ n, n.wait = .Answer ∧ step s (.Got (.Redirect keeps next)) =
      ok (n, .Send (.Away (methodAfter keeps s.method) (keeps && s.body) (remembers s next))) := by
  obtain ⟨n, a, stepped, moves⟩ := step_moves s (.Got (.Redirect keeps next)) retries (by omega)
  cases moves with
  | in_turn _ _ _ inner =>
    cases inner with
    | redirect _ _ _ _ redirects =>
      cases redirects with
      | too_many limit => omega
      | body_refused _ refused => simp_all
      | sent _ _ _ _ _ _ sends =>
        cases sends <;> first | exact ⟨_, rfl, stepped⟩ | simp_all [redirected]
  | out_of_turn not_answers => simp_all [Answers]

/-- The first pass is sent `Home`, the redirect is sent `Away`, and the success to it is `Done`. -/
theorem a_redirect_to_an_allowed_https_host_is_followed :
    ARedirectToAnAllowedHttpsHostIsFollowed := by
  intro b at_the_registry s a started next not_home not_start https allowed
  obtain ⟨begun, no_retries, _, _, unleft, _, _, _, _, _, waits⟩ := begin_state b s a started
  have first := a_pass_at_the_registry at_the_registry begun waits unleft false true
  -- the redirect, from the state the first pass left
  obtain ⟨n, waits_n, redirected⟩ :=
    a_redirect_is_followed (s := { moved (newPass s false true) b.start with wait := .Answer })
      (keeps := false) (next := next) (by simp [moved, newPass, no_retries])
      (by simp [moved, newPass]) (by simp) (by simp [https]) allowed (by simp [not_home]) rfl
  refine ⟨_, n, _, first, ?_, step_of_a_success waits_n⟩
  simpa [moved, newPass, remembers, not_start, allowed, begun] using redirected

/-- A pass of a request that starts on another host than the registry is sent there as a request
to another origin, with the method and the body of the request. -/
theorem a_pass_on_the_start_host {b : Begin} {s : State} (begun : s.begin = b)
    (away : b.start.home = false) (allowed : b.start.allowed = true)
    (scheme : b.home_https = true → b.start.https = true) (waits : s.wait = .Pass)
    (probe held : Bool) :
    step s (.Authed probe held) = ok (
      { moved (newPass s probe held) b.start with wait := .Answer },
      .Send (.Away b.method b.body false)) := by
  subst begun
  have no_downgrade : ¬ (s.begin.home_https = true ∧ s.begin.start.https = false) :=
    fun ⟨home_https, plain⟩ => by simp [scheme home_https] at plain
  rw [step_of_a_pass waits]
  simp [sendAction, newPass, away, allowed, no_downgrade, waitAfter]

/-- The first pass of an upload is sent `Away` with the body; a redirect that keeps the method
inside the host is sent `Away` with the body too; and the success to either is `Done`. -/
theorem an_upload_keeps_its_body_on_its_own_host : AnUploadKeepsItsBodyOnItsOwnHost := by
  intro b away _ allowed scheme s a started probe held
  obtain ⟨begun, no_retries, _, _, _, _, _, _, _, _, waits⟩ := begin_state b s a started
  have first := a_pass_on_the_start_host begun away allowed scheme waits probe held
  refine ⟨⟨_, _, first, step_of_a_success rfl⟩, ?_⟩
  intro next next_away next_start next_https next_allowed
  obtain ⟨n, waits_n, redirected⟩ :=
    a_redirect_is_followed (s := { moved (newPass s probe held) b.start with wait := .Answer })
      (keeps := true) (next := next) (by simp [moved, newPass, no_retries])
      (by simp [moved, newPass]) (by simp [next_start])
      (by cases hs : b.start.https <;> simp_all [moved, newPass]) next_allowed
      (by simp [moved, newPass, away]) rfl
  refine ⟨_, n, _, first, ?_, step_of_a_success waits_n⟩
  simpa [moved, newPass, remembers, next_start, begun, methodAfter] using redirected
