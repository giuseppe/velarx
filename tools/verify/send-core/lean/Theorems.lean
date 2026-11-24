-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/send-core.  The statements are in
-- SendCore/Spec.lean; the proofs are in SendCore/ClaimsOf*.lean, which use what the other files of
-- SendCore/ say of the steps (StepCases.lean), of the runs (RunLemmas.lean) and of what a run
-- keeps true (HomeFacts.lean, RequestFacts.lean, BudgetFacts.lean, FreshFacts.lean,
-- HeldFacts.lean).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- (the run prints no function of the standard library for this crate).
--
-- Read before this file: SendCore/Spec.lean.
import Proved
import SendCore.ClaimsOfAuthorization
import SendCore.ClaimsOfTheTarget
import SendCore.ClaimsOfTheBody
import SendCore.ClaimsOfTheLimits
import SendCore.ClaimsOfTokens
import SendCore.ClaimsOfLiveness

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : SendCore.BeginAndStepAlwaysReturn :=
  SendCore.begin_and_step_always_return
example : SendCore.EventsOutOfTurnAreRefused :=
  SendCore.events_out_of_turn_are_refused
example : SendCore.AnAwayRequestHasNoAuthorization :=
  SendCore.an_away_request_has_no_authorization
example : SendCore.AuthorizationOnlyBeforeLeavingHome :=
  SendCore.authorization_only_before_leaving_home
example : SendCore.NoAuthorizationAfterLeavingHome :=
  SendCore.no_authorization_after_leaving_home
example : SendCore.AHomeSendCarriesItsPassesAuthorization :=
  SendCore.a_home_send_carries_its_passes_authorization
example : SendCore.NoDowngrade :=
  SendCore.no_downgrade
example : SendCore.NoDowngradeAfterHttps :=
  SendCore.no_downgrade_after_https
example : SendCore.EverySendIsAllowed :=
  SendCore.every_send_is_allowed
example : SendCore.OnlyAnAllowedRedirectIsRemembered :=
  SendCore.only_an_allowed_redirect_is_remembered
example : SendCore.BodyOnlyToTheStartOrigin :=
  SendCore.body_only_to_the_start_origin
example : SendCore.RedirectsRewriteTheRequest :=
  SendCore.redirects_rewrite_the_request
example : SendCore.APassStartsFromTheRequest :=
  SendCore.a_pass_starts_from_the_request
example : SendCore.AtMostSoManySends :=
  SendCore.at_most_so_many_sends
example : SendCore.AtMostSoManyTurns :=
  SendCore.at_most_so_many_turns
example : SendCore.AsksOnlyAfterAHomeAnswer :=
  SendCore.asks_only_after_a_home_answer
example : SendCore.AFreshTokenIsAskedAtMostOnce :=
  SendCore.a_fresh_token_is_asked_at_most_once
example : SendCore.ASuccessIsDone :=
  SendCore.a_success_is_done
example : SendCore.AChallengeThenSuccessGetsOneToken :=
  SendCore.a_challenge_then_success_gets_one_token
example : SendCore.ARedirectToAnAllowedHttpsHostIsFollowed :=
  SendCore.a_redirect_to_an_allowed_https_host_is_followed
example : SendCore.AnUploadKeepsItsBodyOnItsOwnHost :=
  SendCore.an_upload_keeps_its_body_on_its_own_host

#proved SendCore.begin_and_step_always_return
#proved SendCore.events_out_of_turn_are_refused
#proved SendCore.an_away_request_has_no_authorization
#proved SendCore.authorization_only_before_leaving_home
#proved SendCore.no_authorization_after_leaving_home
#proved SendCore.a_home_send_carries_its_passes_authorization
#proved SendCore.no_downgrade
#proved SendCore.no_downgrade_after_https
#proved SendCore.every_send_is_allowed
#proved SendCore.only_an_allowed_redirect_is_remembered
#proved SendCore.body_only_to_the_start_origin
#proved SendCore.redirects_rewrite_the_request
#proved SendCore.a_pass_starts_from_the_request
#proved SendCore.at_most_so_many_sends
#proved SendCore.at_most_so_many_turns
#proved SendCore.asks_only_after_a_home_answer
#proved SendCore.a_fresh_token_is_asked_at_most_once
#proved SendCore.a_success_is_done
#proved SendCore.a_challenge_then_success_gets_one_token
#proved SendCore.a_redirect_to_an_allowed_https_host_is_followed
#proved SendCore.an_upload_keeps_its_body_on_its_own_host
