-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/auth-core, which credential of an auth file
-- (`auths`, `credHelpers`) a request to a registry carries, in words and in statements, with no
-- proof.  A KEY is the text a user or a tool wrote in auth.json; `normalize` writes it the way it is
-- kept, `matches` says whether a key is for the repository `repo` of the host `host` and how
-- specific it is, `pick` takes the most specific key of a list, `exact` finds the key of a helper
-- (the host alone).  This file is what a reviewer reads; Lean checks the rest (the proofs are in the
-- other files of AuthCore/, and Theorems.lean ties each claim below to its proof).
--
-- Why it is needed: the credential of a key is sent to the registry the request is for.  A key that
-- matched a host it does not name (`r.io` for `r.io.evil`, a prefix, a sub-domain, another port)
-- would send a password to another party.  The tests of the crate (src/rules.rs, src/walk.rs) check
-- the rules on every small input over a small alphabet, against a reference written with the string
-- methods of the standard library; each claim below is the same rule for EVERY input.  A proof is
-- worth what its statement says, so each claim has a comment of what it claims and of what it does
-- NOT.
--
-- Words.  A key, a host, a repository is a list of BYTES (`Bytes`; `Slash` is `/`, `Colon` is `:`,
-- `Question` is `?` and `Hash` is `#`).  The vocabulary of the claims is written first, by what
-- things ARE, not by how the code computes them:
--   - the HUB is one host with three names (`HubOf`): `docker.io`, `index.docker.io` and
--     `registry-1.docker.io` are all `docker.io`, in a key and in the host of a request; every other
--     host is itself (with a port, `docker.io:5000` is not the Hub);
--   - a key is for a request (`Matches`) when it is the host alone, or the host, a `/` and a path
--     that is the beginning of the repository by whole components (`r.io/ns` is for `ns` and
--     `ns/x`, not for `nsx`), and a key with a path is for no request that has no repository;
--   - a key is NORMALIZED (`Normalized`) the way rule 7 of the crate says: a key with an `http://` or
--     `https://` scheme (in any case) is its host, the Hub under its one name; a key with another
--     scheme has its scheme and authority in lower case, its `://` and its path as written; a key
--     with no scheme keeps its path, with the Hub under its one name; no key keeps a trailing `/`
--     after its `://`.
--
-- Totality: each claim about a function says that it RETURNS (no panic, no overflow of a `usize`, no
-- byte read outside a list, every loop ends) and what its answer is.  There is no assumption: every
-- addition the code makes is bounded by a length that already fits.
--
-- Both directions: "no key matches a wrong host" alone is satisfied by a function that matches
-- nothing.  So `matches` is claimed to answer exactly when the definition says, `pick` to answer
-- none exactly when no key matches, `exact` to find the key when there is one.
--
-- Found while proving `NormalizeTwiceIsNormalize`: the cut of the trailing `/` of a key of another
-- scheme took its `://` too when nothing followed it, so `index.docker.io/a://` was kept as
-- `index.docker.io/a:`, a key with no scheme, which a second `normalize` turned into
-- `docker.io/a:`.  The cut now stops at the `://` (`s3:///` is `s3://`).
--
-- Read before this file: the header of crates/auth-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every input):
--
--   The functions return
--     EveryFunctionReturns              `normalize`, `matches`, `pick`, `exact` and `hub_alias`
--                                       return (no panic, no overflow), for any bytes and lists
--
--   Which host a key is for
--     MatchesIsExactlyTheDefinition     `matches` answers the length of the key when the key is for
--                                       the request (`Matches`), and none otherwise
--     AKeyIsForItsHostOnly              a key that matches a request starts with the host of the
--                                       request (the Hub under its one name), up to its first `/`
--     HubAliasIsTheTwoOtherNames        `hub_alias` is true exactly for `index.docker.io` and
--                                       `registry-1.docker.io`
--     TheHubIsOneHost                   the three names of the Hub give the same answers of
--                                       `matches`, `pick` and `exact`
--     AHubNameWithAPortIsNotTheHub      with a port a name of the Hub is another host: its key
--                                       `docker.io` is not for it, nor `docker.io:5000` for the Hub
--
--   The most specific key
--     PickIsTheMostSpecificKey          `pick` answers a key that matches, of which no matching key
--                                       is longer; of the longest, one written as it is kept if
--                                       there is one, and then the last; none exactly when no key
--                                       matches
--
--   The helper of a host
--     ExactIsTheHostAlone               `exact` answers the first key that is the host (the Hub
--                                       under its one name) and nothing else; none when there is
--                                       none
--
--   The key as it is kept
--     NormalizeIsTheRuleOfTheKey        `normalize` answers `Normalized` of the key
--     NormalizeTwiceIsNormalize         `normalize` of a key `normalize` answered is that key
--     AWebKeyIsItsHost                  for `http://` or `https://` in any case, the answer is the
--                                       host (the bytes up to the next `/`), the Hub under its one
--                                       name, and nothing of the path
--
--   Examples
--     WorkedExamples                    keys of the Hub, a namespace, a web key, `s3://`
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; nothing else (the crate calls no function of
--   the standard library that has to be modelled by hand).
--
--   Not claimed:
--   - that the keys of a file are the right ones, how they are read (the JSON, `auth`, the helpers)
--     and what is done with the credential: the claims are about the bytes the shell hands over;
--   - that the host and the repository are good ones (the reader of references makes them): the
--     claims hold for any bytes, so for a host that has a `/` or an empty host too, but
--     `AKeyIsForItsHostOnly` says "the first component" for a host with no `/`;
--   - the case of the letters of a host in a key (`R.io` is another host than `r.io`: nothing folds
--     them, as the rule says; `Normalized` folds only the scheme, and the authority of a key of
--     another scheme).
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic and does
--     not loop for ever) and its answer `r` satisfies `P r`.
--   - `s : Slice Std.U8` is a Rust slice of bytes; `s.val` is the list inside it; `v.val` the same
--     for a vector (`Vec`).  `l[i]?` is `some` of the element at the place `i` of `l`, or `none`.
--   - `l ++ l'` is `l` and then `l'`; `x :: l` is `l` with `x` before; `l <+: l'` is "l is the
--     beginning of l'"; `l.takeWhile p` and `l.dropWhile p` are what is before and what is from the
--     first element that does not satisfy `p`; `l.drop n` is `l` without its first `n`; `l.map f` is
--     `f` of each element; `l.reverse` is `l` backwards.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `∈` is "is in".
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

open Classical

noncomputable section

/-! ### Bytes -/

/-- A key, a host, a repository or a path, as the list of its bytes. -/
abbrev Bytes := List Std.U8

/-- The byte `/`. -/
def Slash : Std.U8 := 47#u8
/-- The byte `:`. -/
def Colon : Std.U8 := 58#u8
/-- The byte `?`. -/
def Question : Std.U8 := 63#u8
/-- The byte `#`. -/
def Hash : Std.U8 := 35#u8

/-- The bytes of `docker.io`, the one name of the Hub. -/
def HubName : Bytes :=
  [100#u8, 111#u8, 99#u8, 107#u8, 101#u8, 114#u8, 46#u8, 105#u8, 111#u8]

/-- The bytes of `index.docker.io`, a name of the Hub. -/
def HubIndex : Bytes :=
  [105#u8, 110#u8, 100#u8, 101#u8, 120#u8, 46#u8, 100#u8, 111#u8, 99#u8, 107#u8, 101#u8, 114#u8,
    46#u8, 105#u8, 111#u8]

/-- The bytes of `registry-1.docker.io`, a name of the Hub. -/
def HubRegistry : Bytes :=
  [114#u8, 101#u8, 103#u8, 105#u8, 115#u8, 116#u8, 114#u8, 121#u8, 45#u8, 49#u8, 46#u8, 100#u8,
    111#u8, 99#u8, 107#u8, 101#u8, 114#u8, 46#u8, 105#u8, 111#u8]

/-- The bytes `://`. -/
def SchemeEnd : Bytes := [Colon, Slash, Slash]

/-- The bytes `http`. -/
def Http : Bytes := [104#u8, 116#u8, 116#u8, 112#u8]

/-- The bytes `https`. -/
def Https : Bytes := [104#u8, 116#u8, 116#u8, 112#u8, 115#u8]

/-! ### Which host a key is for -/

/-- The host as a key names it: the three names of the Hub are `docker.io`, every other host is
itself.  So `docker.io:5000`, `Docker.io` and `index.docker.io.evil` are not the Hub. -/
def HubOf (host : Bytes) : Bytes :=
  if host = HubIndex ∨ host = HubRegistry then HubName else host

/-- The key `key` is FOR the repository `repo` of `host`: it is the host (the Hub under its one name)
alone, or the host, a `/` and a path that is the beginning of the repository by whole components
(the repository is the path, or the path and a `/` and more).  A key with a path is for no request
that has no repository.  So `r.io` is not `r.io.evil`, nor `xr.io`, `r.io` is not `r.io:5000`, and
`r.io/ns` is for `ns` and `ns/x`, not for `nsx`.

Not said: that the key is normalized or the host a good host. -/
def Matches (key host repo : Bytes) : Prop :=
  key = HubOf host ∨
    ∃ path, key = HubOf host ++ Slash :: path ∧ repo ≠ [] ∧
      (repo = path ∨ ∃ rest, repo = path ++ Slash :: rest)

/-! ### The most specific key -/

/-- The key was written as it is kept (`pick` prefers `docker.io` to `index.docker.io`, which
normalize alike). -/
def AsWritten (k : Key) : Prop := k.kept.val = k.written.val

/-- The key `k` at the place `i` is not beaten by `k'` at the place `j`: `k'` is shorter, or as long
and not written as it is kept while `k` is, or as long and as much written as kept and not later. -/
def NotBeaten (k : Key) (i : Nat) (k' : Key) (j : Nat) : Prop :=
  k'.kept.length < k.kept.length ∨
    (k'.kept.length = k.kept.length ∧
      ((¬ AsWritten k' ∧ AsWritten k) ∨ ((AsWritten k' ↔ AsWritten k) ∧ j ≤ i)))

/-- `found` is the key PICKED for the repository `repo` of `host` among `keys` (a key is the text kept
and the text it was written as): a key that matches, that no other matching key beats (`NotBeaten`:
none is longer; of the longest, one written as it is kept wins over one that is not, and the later
over the earlier).  `none` exactly when no key matches. -/
def Picks (keys : List Key) (host repo : Bytes) (found : Option Nat) : Prop :=
  (∀ i, found = some i → ∃ k, keys[i]? = some k ∧ Matches k.kept.val host repo ∧
      ∀ j k', keys[j]? = some k' → Matches k'.kept.val host repo → NotBeaten k i k' j) ∧
  (found = none ↔ ∀ k ∈ keys, ¬ Matches k.kept.val host repo)

/-- `found` is the key of a helper for `host`: the first key that is the host alone, the Hub under
its one name; `none` exactly when there is none. -/
def FindsTheHost (keys : List Bytes) (host : Bytes) (found : Option Nat) : Prop :=
  (∀ i, found = some i → keys[i]? = some (HubOf host) ∧
      ∀ j k, j < i → keys[j]? = some k → k ≠ HubOf host) ∧
  (found = none ↔ ∀ k ∈ keys, k ≠ HubOf host)

/-! ### The key as it is kept -/

/-- The byte `b` in lower case (ASCII): `A` to `Z` become `a` to `z`, any other byte stays. -/
def LowerByte (b : Std.U8) : Std.U8 :=
  if 65 ≤ b.val ∧ b.val ≤ 90 then UScalar.mk (BitVec.ofNat 8 (b.val + 32)) else b

/-- The bytes without the `/` at the end. -/
def TrimSlashes (l : Bytes) : Bytes :=
  (l.reverse.dropWhile (fun b => decide (b = Slash))).reverse

/-- The key cut at its first `://`: what is before it (the scheme) and what is after it; `none` when
it has no `://`. -/
def SchemeSplit : Bytes → Option (Bytes × Bytes)
  | [] => none
  | b :: l =>
    if SchemeEnd <+: b :: l then some ([], (b :: l).drop 3)
    else (SchemeSplit l).map fun p => (b :: p.1, p.2)

/-- `scheme` is `http` or `https`, in any case. -/
def IsWeb (scheme : Bytes) : Prop :=
  scheme.map LowerByte = Http ∨ scheme.map LowerByte = Https

instance (scheme : Bytes) : Decidable (IsWeb scheme) :=
  inferInstanceAs (Decidable (_ ∨ _))

/-- The authority of what follows the `://`: the bytes up to the first `/`, `?` or `#`. -/
def Authority (rest : Bytes) : Bytes :=
  rest.takeWhile fun b => decide (b ≠ Slash ∧ b ≠ Question ∧ b ≠ Hash)

/-- The key as it is KEPT (rule 7 of the crate).
- With an `http://` or `https://` scheme (in any case): the host, the bytes after the `://` up to
  the next `/`, the Hub under its one name; the path goes.  (`https://index.docker.io/v1/` is
  `docker.io`.)
- With another scheme: the scheme in lower case and the `://`, then what follows with no `/` at its
  end: its authority (up to a `/`, `?` or `#`) in lower case and the rest as written.
- With no `://`: the bytes before the first `/` (the Hub under its one name), then the rest as it
  is, with no `/` at the end.

Not said: anything of a key that is not a registry (`s3://Bucket/Key` keeps `Key` as written). -/
def Normalized (key : Bytes) : Bytes :=
  match SchemeSplit key with
  | some (scheme, rest) =>
    if IsWeb scheme then HubOf (rest.takeWhile fun b => decide (b ≠ Slash))
    else scheme.map LowerByte ++ SchemeEnd ++ (Authority (TrimSlashes rest)).map LowerByte ++
      (TrimSlashes rest).drop (Authority (TrimSlashes rest)).length
  | none =>
    HubOf ((TrimSlashes key).takeWhile fun b => decide (b ≠ Slash)) ++
      (TrimSlashes key).dropWhile fun b => decide (b ≠ Slash)

/-! ### The claims -/

/-- Every function of the crate returns, for any bytes and any list of keys: it does not panic, no
addition overflows, every loop ends.

Not said: what the answers are (the claims below). -/
def EveryFunctionReturns : Prop :=
  (∀ key : Slice Std.U8, ∃ r, normalize key = ok r) ∧
  (∀ key host repo : Slice Std.U8, ∃ r, «matches» key host repo = ok r) ∧
  (∀ (keys : Slice Key) (host repo : Slice Std.U8), ∃ r, pick keys host repo = ok r) ∧
  (∀ (keys : Slice (alloc.vec.Vec Std.U8)) (host : Slice Std.U8), ∃ r, exact keys host = ok r) ∧
  (∀ host : Slice Std.U8, ∃ r, hub_alias host = ok r)

/-- **`matches`** answers the length of the key, which is how specific it is, exactly when the key is
for the request (`Matches`), and none otherwise.  So a key of another host, a prefix of the host, a
sub-domain, a host with another port or in another case, and a path that is not made of whole
components of the repository all answer none.

Not said: that a more specific key (a longer one) is the better one: `pick` says what is picked. -/
def MatchesIsExactlyTheDefinition : Prop :=
  ∀ key host repo : Slice Std.U8,
    «matches» key host repo ⦃ r =>
      (Matches key.val host.val repo.val ∧ r = some key.len) ∨
      (¬ Matches key.val host.val repo.val ∧ r = none) ⦄

/-- A key that matches a request starts with the host of the request, the Hub under its one name, up
to the key's first `/`: no credential is for a host other than the one its key names.  (For a host
with no `/`; a host that has one is no host.)

Not said: that the rest of the key is a path of the repository (`MatchesIsExactlyTheDefinition`). -/
def AKeyIsForItsHostOnly : Prop :=
  ∀ key host repo : Slice Std.U8, Slash ∉ host.val →
    «matches» key host repo ⦃ r =>
      r ≠ none → key.val.takeWhile (fun b => decide (b ≠ Slash)) = HubOf host.val ⦄

/-- **`hub_alias`** is true exactly for `index.docker.io` and `registry-1.docker.io`, the two names of
the Hub that are not `docker.io`. -/
def HubAliasIsTheTwoOtherNames : Prop :=
  ∀ host : Slice Std.U8,
    hub_alias host ⦃ r => r = true ↔ (host.val = HubIndex ∨ host.val = HubRegistry) ⦄

/-- The three names of the Hub, `docker.io`, `index.docker.io` and `registry-1.docker.io`, as the
host of a request, give the same answer of `matches`, of `pick` and of `exact`, for any key, list of
keys and repository.

Not said: that the answers are the right ones (the claims on each). -/
def TheHubIsOneHost : Prop :=
  ∀ a b : Slice Std.U8,
    (a.val = HubName ∨ a.val = HubIndex ∨ a.val = HubRegistry) →
    (b.val = HubName ∨ b.val = HubIndex ∨ b.val = HubRegistry) →
    (∀ key repo : Slice Std.U8, «matches» key a repo = «matches» key b repo) ∧
    (∀ (keys : Slice Key) (repo : Slice Std.U8), pick keys a repo = pick keys b repo) ∧
    (∀ keys : Slice (alloc.vec.Vec Std.U8), exact keys a = exact keys b)

/-- With a port, a name of the Hub is another host: for the host `index.docker.io:5000` (any name of
the Hub and any text after the `:`) a key `docker.io`, `index.docker.io` or `registry-1.docker.io`
is for nothing. -/
def AHubNameWithAPortIsNotTheHub : Prop :=
  ∀ (hub port : Bytes) (host key repo : Slice Std.U8),
    (hub = HubName ∨ hub = HubIndex ∨ hub = HubRegistry) →
    host.val = hub ++ Colon :: port →
    (key.val = HubName ∨ key.val = HubIndex ∨ key.val = HubRegistry) →
    «matches» key host repo ⦃ r => r = none ⦄

/-- **`pick`** answers the key picked (`Picks`): the most specific of those that match, none exactly
when no key matches. -/
def PickIsTheMostSpecificKey : Prop :=
  ∀ (keys : Slice Key) (host repo : Slice Std.U8),
    pick keys host repo ⦃ found => Picks keys.val host.val repo.val (found.map (·.val)) ⦄

/-- **`exact`** answers the first key that is the host alone, the Hub under its one name
(`FindsTheHost`): a key with a path, another host or another case of the letters is no helper of this
host. -/
def ExactIsTheHostAlone : Prop :=
  ∀ (keys : Slice (alloc.vec.Vec Std.U8)) (host : Slice Std.U8),
    exact keys host ⦃ found =>
      FindsTheHost (keys.val.map (·.val)) host.val (found.map (·.val)) ⦄

/-- **`normalize`** answers the key as it is kept (`Normalized`), for any key. -/
def NormalizeIsTheRuleOfTheKey : Prop :=
  ∀ key : Slice Std.U8, normalize key ⦃ out => out.val = Normalized key.val ⦄

/-- **`normalize`** of a key it answered answers that key again: a key is kept as it is written once
it is kept (rule 7 of the crate), so a client and the engine that both normalize a key agree.

Not said: anything of a key that `normalize` did not answer (`index.docker.io` is not kept as it is
written). -/
def NormalizeTwiceIsNormalize : Prop :=
  ∀ key kept : Slice Std.U8,
    normalize key ⦃ out => kept.val = out.val → normalize kept ⦃ again => again.val = kept.val ⦄ ⦄

/-- A key with the scheme `http` or `https`, in any case, is normalized to its host, the bytes after
the `://` up to the next `/` (or the end), the Hub under its one name: nothing of its path stays.

Not said: what a key with the scheme in another form is (that is `Normalized`). -/
def AWebKeyIsItsHost : Prop :=
  ∀ (key : Slice Std.U8) (scheme rest : Bytes), IsWeb scheme → key.val = scheme ++ SchemeEnd ++ rest →
    normalize key ⦃ out => out.val = HubOf (rest.takeWhile fun b => decide (b ≠ Slash)) ⦄

/-- Keys the rules are about, on the model: the Hub in a key and in a host, a key that is a prefix of
a host, a path by whole components, a web key, a key of another scheme, `s3://` and `s3:///` that
keep their `://`. -/
def WorkedExamples : Prop :=
  -- the Hub, under its one name, in the key and in the host
  Normalized (HubIndex ++ [Slash]) = HubName ∧
  Normalized (Https ++ SchemeEnd ++ HubIndex ++ [Slash, 118#u8, 49#u8, Slash]) = HubName ∧
  -- a web key in capitals is its host
  Normalized ([72#u8, 84#u8, 84#u8, 80#u8, 83#u8] ++ SchemeEnd ++ [97#u8, Slash, 98#u8]) =
    [97#u8] ∧
  -- a key is for its host, and a path by whole components
  Matches [97#u8] [97#u8] [] ∧
  ¬ Matches [97#u8] [97#u8, 98#u8] [] ∧
  ¬ Matches [97#u8, 98#u8] [97#u8] [] ∧
  Matches [97#u8, Slash, 110#u8] [97#u8] [110#u8, Slash, 120#u8] ∧
  ¬ Matches [97#u8, Slash, 110#u8] [97#u8] [110#u8, 120#u8] ∧
  ¬ Matches [97#u8, Slash, 110#u8] [97#u8] [] ∧
  Matches HubName HubIndex [] ∧
  -- another scheme: lower case up to the authority, the path as written; `s3://` keeps its `://`
  Normalized [83#u8, 51#u8] = [83#u8, 51#u8] ∧
  Normalized ([83#u8, 51#u8] ++ SchemeEnd ++ [66#u8, Slash, 75#u8]) =
    [115#u8, 51#u8] ++ SchemeEnd ++ [98#u8, Slash, 75#u8] ∧
  Normalized ([115#u8, 51#u8] ++ SchemeEnd) = [115#u8, 51#u8] ++ SchemeEnd ∧
  Normalized ([115#u8, 51#u8] ++ SchemeEnd ++ [Slash]) = [115#u8, 51#u8] ++ SchemeEnd

end

end AuthCore
