-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/confine-core, which confinement a container gets:
-- `decide` turns the request of a container (`--privileged`, `--security-opt seccomp=`,
-- `unmask=`, a host `/sys`, no-new-privileges) into a decision, and `cri.from_cri` turns the
-- security context of the kubelet into the seccomp request and the choice of path lists that
-- `decide` takes.  This file is what a reviewer reads, in words and in statements, with no proof;
-- Lean checks the rest (the proofs are in ClaimsOfTheDecision.lean, ClaimsOfIndependence.lean
-- and ClaimsOfTheCri.lean), and Theorems.lean ties each claim below to its proof.
--
-- Why it is needed: the confinement of a container is the sum of several switches (the device
-- rule, the seccomp filter, the masked paths, the read-only paths, `/sys`), and the danger is a
-- switch that turns off when nobody asked for it: `--privileged` is meant to open everything, but
-- `unmask=ALL` must not open the device rule, and an `unconfined` seccomp must not unmask a path.
-- The tests of the crate (src/walk.rs, src/rules.rs) check each rule on every request.  There are
-- few requests, so each claim below is the same rule for EVERY request, stated against the flags
-- of the request itself, in the words a security reader checks.  A proof is worth what its
-- statement says, so each claim has a comment of what it claims and of what it does NOT.
--
-- Words.  A REQUEST has six options: `privileged`, `seccomp` (`Default`: none named, `Unconfined`,
-- `Custom`: a profile of the user), `unmask_all` (`unmask=ALL`), `unmask_some` (`unmask=` names
-- paths), `host_sysfs` (the `/sys` of the container is a bind of the host's) and
-- `no_new_privileges`.  A DECISION has seven parts: `deny_all_devices` (the device cgroup denies
-- everything first), `seccomp` (the FILTER: `Filter.Default`, `Filter.Custom` or `Filter.None`),
-- `masked` and `readonly` (which of the default masked and read-only paths the container has:
-- `Paths.Default` all of them, `Paths.Without` all but those named by `unmask=`, `Paths.None`
-- none), `sys_readonly`, `mask_sys_kernel` (`/sys/kernel` is masked on top of the default paths)
-- and `no_new_privileges`.
--
-- Totality: each claim says that the function RETURNS (no panic) and what its answer is.  Nothing
-- is assumed of the input beyond the one condition a claim names (for example "not privileged"):
-- every combination of the options is covered.
--
-- Both directions: "a filter applies" alone is satisfied by a `decide` that always filters, and
-- "no path is masked when privileged" by one that never masks.  So each claim about what stays on
-- says exactly which case gives which answer: a `decide` that turns everything on, or everything
-- off, fails one of them.
--
-- Read before this file: the header of crates/confine-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every request, or every security context):
--
--   The functions return
--     DecideAndFromCriAlwaysReturn      `decide` and `cri.from_cri` return (no panic)
--
--   A container that is NOT privileged
--     NotPrivilegedDeniesAllDevicesFirst  the device rule that denies everything is first
--     NotPrivilegedHasAFilterUnlessUnconfined
--                                       a seccomp filter applies unless unconfined was asked;
--                                       a custom profile applies; the default one is the default
--     NotPrivilegedKeepsTheDefaultPaths the default masked and read-only paths are all kept, but
--                                       those unmasked by name; none only with `unmask=ALL`
--     NotPrivilegedHasSysReadOnly       `/sys` is read-only
--     TheHostSysKernelIsMasked          with a host `/sys`, `/sys/kernel` is masked, whatever is
--                                       unmasked, and it is masked for no other reason
--
--   A container that IS privileged
--     PrivilegedTurnsOffExactlyThese    no device rule, no default filter (a custom profile still
--                                       applies), no masked or read-only path, `/sys` writable
--
--   No two unrelated options turn something off (each part follows the options named, only)
--     TheDevicePartFollowsPrivilegedOnly
--     TheSeccompPartFollowsPrivilegedAndSeccompOnly
--     TheMaskedPathsFollowPrivilegedAndUnmaskOnly
--     TheReadonlyPathsFollowPrivilegedAndUnmaskOnly
--     TheSysReadonlyPartFollowsPrivilegedOnly
--     TheSysKernelPartFollowsPrivilegedAndHostSysfsOnly
--     TheNoNewPrivilegesPartFollowsItsOptionOnly
--
--   No new privileges
--     NoNewPrivilegesPassesThrough      the decision has what the request asked, unchanged
--
--   The CRI (the security context of the kubelet)
--     NoContextGivesTheEngineDefaults   no context: the default profile and the default paths
--     APrivilegedContextGivesUnconfinedAndNoPaths
--                                       privileged: unconfined, and no path list of its own
--     AProfileMeansWhatItNames          a context that is not privileged and the profile it names:
--                                       what applies, one case each (none named: none, as the API says)
--     ANamedProfileNeverGivesUnconfined `RuntimeDefault` or a localhost profile is never unconfined
--     OwnPathsOnlyWithAContext          the path lists of the context are used exactly when there
--                                       is a context that is not privileged
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; the crate calls no function of the standard
--   library that has to be modelled by hand.
--
--   Not claimed:
--   - the default lists of paths themselves: they depend on the host, and the shell removes a path
--     from them by name; here a list is `Default`, `Without` or `None`;
--   - that the shell applies the decision to the OCI spec (it reads the flags and builds the spec);
--   - AppArmor and SELinux: the crate does not decide them;
--   - capabilities (crates/caps-core);
--   - what the kernel then enforces of a filter, a mask or a device rule;
--   - that the profile of the kubelet is read correctly (the shell turns the CRI message into a
--     `Context`);
--   - the infra container of a sandbox: the shell gives it the default profile when it names
--     none, without `cri.from_cri`.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic) and
--     its answer `r` satisfies `P r`.
--   - `r.privileged` is the field `privileged` of the request `r`; `d.masked` of the decision `d`.
--     `r.privileged = false` reads "the request is not privileged".
--   - `∀ x, P` is "for every x, P"; `∧` is "and", `∨` is "or", `→` is "if ... then", `↔` is
--     "exactly when", `¬` is "not", `≠` is "is not equal to".
import Extracted.Funs

open Aeneas Aeneas.Std Result
open velarx_confine_core hiding decide

namespace ConfineCore

/-- The decision of the engine for a request: the Rust function `decide`.  (The short name is
taken by a function of Lean, so the claims use this one.) -/
abbrev decideRequest := velarx_confine_core.decide

/-- What a path list (`d.masked` or `d.readonly`) is for a request that is NOT privileged:
`unmask=ALL` leaves none of the default paths, a name in `unmask=` leaves all but those, and with
no unmask the container has all of them. -/
def PathsKept (r : Request) (paths : Paths) : Prop :=
  (r.unmask_all = true → paths = Paths.None) ∧
  (r.unmask_all = false → r.unmask_some = true → paths = Paths.Without) ∧
  (r.unmask_all = false → r.unmask_some = false → paths = Paths.Default)

/-- **`decide` and `from_cri` always return.**  For every request and every security context: no
panic, whatever the combination of options.

Not said: what they return (the claims below). -/
def DecideAndFromCriAlwaysReturn : Prop :=
  (∀ r : Request, decideRequest r ⦃ _ => True ⦄) ∧
  (∀ c : cri.Context, cri.from_cri c ⦃ _ => True ⦄)

/-- **A container that is not privileged has the device rule that denies everything first.**
Whatever else is asked (seccomp, unmask, a host `/sys`).

Not said: which devices are then allowed (the shell adds the ones a container needs). -/
def NotPrivilegedDeniesAllDevicesFirst : Prop :=
  ∀ r : Request, r.privileged = false → decideRequest r ⦃ d => d.deny_all_devices = true ⦄

/-- **A container that is not privileged has a seccomp filter unless it asked for none.**  The
default profile gives the default filter, a profile of the user gives that filter (so a custom
profile applies and is never replaced), and only `unconfined` gives no filter.

Not said: what the filter lets through (that is the profile's, not the core's). -/
def NotPrivilegedHasAFilterUnlessUnconfined : Prop :=
  ∀ r : Request, r.privileged = false → decideRequest r ⦃ d =>
    (r.seccomp = Seccomp.Default → d.seccomp = Filter.Default) ∧
    (r.seccomp = Seccomp.Custom → d.seccomp = Filter.Custom) ∧
    (r.seccomp = Seccomp.Unconfined → d.seccomp = Filter.None) ⦄

/-- **A container that is not privileged keeps the default masked paths and the default read-only
paths**, both lists alike: all of them with no unmask, all but those named by `unmask=`, and none
only with `unmask=ALL`.  Neither `unconfined` nor a host `/sys` nor no-new-privileges changes
them.

Not said: which paths the lists hold, and which are named (the shell takes them out by name). -/
def NotPrivilegedKeepsTheDefaultPaths : Prop :=
  ∀ r : Request, r.privileged = false → decideRequest r ⦃ d =>
    PathsKept r d.masked ∧ PathsKept r d.readonly ⦄

/-- **A container that is not privileged has `/sys` read-only.**

Not said: what is mounted at `/sys` (a sysfs of its own or a bind of the host's). -/
def NotPrivilegedHasSysReadOnly : Prop :=
  ∀ r : Request, r.privileged = false → decideRequest r ⦃ d => d.sys_readonly = true ⦄

/-- **On a host `/sys`, `/sys/kernel` is masked, whatever is unmasked.**  For a request that is not
privileged: `/sys/kernel` is masked exactly when the `/sys` of the container is a bind of the
host's, so `unmask=ALL` or a name in `unmask=` does not unmask it, and it is not masked for any
other reason.

Not said: anything of a privileged request (`PrivilegedTurnsOffExactlyThese`). -/
def TheHostSysKernelIsMasked : Prop :=
  ∀ r : Request, r.privileged = false →
    decideRequest r ⦃ d => d.mask_sys_kernel = true ↔ r.host_sysfs = true ⦄

/-- **A privileged container has exactly this much turned off.**  No device rule; no default
filter (it has none, or the custom profile that was asked for, which applies privileged or not);
no masked path and no read-only path; `/sys` is not read-only, and `/sys/kernel` is not masked.

Not said: what `--privileged` gives besides these (capabilities, devices of the host: other
crates and the shell). -/
def PrivilegedTurnsOffExactlyThese : Prop :=
  ∀ r : Request, r.privileged = true → decideRequest r ⦃ d =>
    d.deny_all_devices = false ∧
    (r.seccomp = Seccomp.Custom → d.seccomp = Filter.Custom) ∧
    (r.seccomp ≠ Seccomp.Custom → d.seccomp = Filter.None) ∧
    d.masked = Paths.None ∧ d.readonly = Paths.None ∧
    d.sys_readonly = false ∧ d.mask_sys_kernel = false ⦄

/-- **The device part follows `privileged` only.**  Two requests that agree on `privileged` have the
same `deny_all_devices`, whatever else they ask: no other option turns the device rule off.

Not said: which way it follows `privileged` (`NotPrivilegedDeniesAllDevicesFirst` and
`PrivilegedTurnsOffExactlyThese` say). -/
def TheDevicePartFollowsPrivilegedOnly : Prop :=
  ∀ r r' : Request, r.privileged = r'.privileged →
    decideRequest r ⦃ d => decideRequest r' ⦃ d' => d.deny_all_devices = d'.deny_all_devices ⦄ ⦄

/-- **The seccomp part follows `privileged` and the seccomp request only.**  Two requests that agree
on these two have the same filter: `unmask=`, a host `/sys` and no-new-privileges never turn the
filter off. -/
def TheSeccompPartFollowsPrivilegedAndSeccompOnly : Prop :=
  ∀ r r' : Request, r.privileged = r'.privileged → r.seccomp = r'.seccomp →
    decideRequest r ⦃ d => decideRequest r' ⦃ d' => d.seccomp = d'.seccomp ⦄ ⦄

/-- **The masked paths follow `privileged` and the unmask request only.**  Two requests that agree
on `privileged`, `unmask_all` and `unmask_some` have the same masked paths: neither `unconfined`
nor a host `/sys` nor no-new-privileges unmasks anything. -/
def TheMaskedPathsFollowPrivilegedAndUnmaskOnly : Prop :=
  ∀ r r' : Request, r.privileged = r'.privileged → r.unmask_all = r'.unmask_all →
    r.unmask_some = r'.unmask_some →
    decideRequest r ⦃ d => decideRequest r' ⦃ d' => d.masked = d'.masked ⦄ ⦄

/-- **The read-only paths follow `privileged` and the unmask request only.**  The same as for the
masked paths, for the list of the read-only ones. -/
def TheReadonlyPathsFollowPrivilegedAndUnmaskOnly : Prop :=
  ∀ r r' : Request, r.privileged = r'.privileged → r.unmask_all = r'.unmask_all →
    r.unmask_some = r'.unmask_some →
    decideRequest r ⦃ d => decideRequest r' ⦃ d' => d.readonly = d'.readonly ⦄ ⦄

/-- **`/sys` read-only follows `privileged` only.**  Two requests that agree on `privileged` agree
on it, whatever else they ask. -/
def TheSysReadonlyPartFollowsPrivilegedOnly : Prop :=
  ∀ r r' : Request, r.privileged = r'.privileged →
    decideRequest r ⦃ d => decideRequest r' ⦃ d' => d.sys_readonly = d'.sys_readonly ⦄ ⦄

/-- **The mask of `/sys/kernel` follows `privileged` and `host_sysfs` only.**  Two requests that
agree on these two agree on it: no unmask turns it off. -/
def TheSysKernelPartFollowsPrivilegedAndHostSysfsOnly : Prop :=
  ∀ r r' : Request, r.privileged = r'.privileged → r.host_sysfs = r'.host_sysfs →
    decideRequest r ⦃ d => decideRequest r' ⦃ d' => d.mask_sys_kernel = d'.mask_sys_kernel ⦄ ⦄

/-- **The no-new-privileges part follows its own option only.**  Two requests that agree on
`no_new_privileges` agree on it, even when one is privileged. -/
def TheNoNewPrivilegesPartFollowsItsOptionOnly : Prop :=
  ∀ r r' : Request, r.no_new_privileges = r'.no_new_privileges →
    decideRequest r ⦃ d => decideRequest r' ⦃ d' => d.no_new_privileges = d'.no_new_privileges ⦄ ⦄

/-- **No-new-privileges passes through unchanged.**  The decision has exactly what the request
asked, privileged or not.

Not said: what the shell does with it. -/
def NoNewPrivilegesPassesThrough : Prop :=
  ∀ r : Request, decideRequest r ⦃ d => d.no_new_privileges = r.no_new_privileges ⦄

/-- **No security context gives the engine's defaults.**  The seccomp request is the default
profile and the container has no path lists of its own (so the default lists of the engine apply).
A context that is not there says nothing, whatever its other fields hold.

Not said: what the default profile and the default lists are. -/
def NoContextGivesTheEngineDefaults : Prop :=
  ∀ c : cri.Context, c.present = false →
    cri.from_cri c ⦃ a => a.seccomp = Seccomp.Default ∧ a.own_paths = false ⦄

/-- **A privileged context gives no profile and no path lists.**  For a context that is present and
privileged the seccomp request is `unconfined` (the profile it names does not apply); and the lists
of paths of the kubelet are not used by any context that says it is privileged, present or not.

Not said: that the container then runs unconfined: `decide` says it
(`PrivilegedTurnsOffExactlyThese`). -/
def APrivilegedContextGivesUnconfinedAndNoPaths : Prop :=
  ∀ c : cri.Context, c.privileged = true →
    cri.from_cri c ⦃ a => (c.present = true → a.seccomp = Seccomp.Unconfined) ∧
      a.own_paths = false ⦄

/-- **A profile means what it names.**  For a context that is present and not privileged: the
profile `RuntimeDefault` gives the default profile, a localhost profile gives a profile of the
user, `Unconfined` gives unconfined, and no profile named gives unconfined (as the API says of the
deprecated path; the kubelet names one always). -/
def AProfileMeansWhatItNames : Prop :=
  ∀ c : cri.Context, c.present = true → c.privileged = false →
    cri.from_cri c ⦃ a =>
      (c.seccomp = cri.Profile.RuntimeDefault → a.seccomp = Seccomp.Default) ∧
      (c.seccomp = cri.Profile.Localhost → a.seccomp = Seccomp.Custom) ∧
      (c.seccomp = cri.Profile.Unconfined → a.seccomp = Seccomp.Unconfined) ∧
      (c.seccomp = cri.Profile.Absent → a.seccomp = Seccomp.Unconfined) ⦄

/-- **A named default or localhost profile is never unconfined.**  For a context that is present
and not privileged, and names `RuntimeDefault` or a localhost profile, the request is not
unconfined.  (It is the "never" side of `AProfileMeansWhatItNames`, said by itself because it is
the one a security reader looks for.) -/
def ANamedProfileNeverGivesUnconfined : Prop :=
  ∀ c : cri.Context, c.present = true → c.privileged = false →
    (c.seccomp = cri.Profile.RuntimeDefault ∨ c.seccomp = cri.Profile.Localhost) →
    cri.from_cri c ⦃ a => a.seccomp ≠ Seccomp.Unconfined ⦄

/-- **The path lists of the context are used exactly with a context that is not privileged.**  The
container has its own lists (they replace the defaults, even empty ones) exactly when there is a
context and it is not privileged. -/
def OwnPathsOnlyWithAContext : Prop :=
  ∀ c : cri.Context, cri.from_cri c ⦃ a =>
    a.own_paths = true ↔ (c.present = true ∧ c.privileged = false) ⦄

end ConfineCore
