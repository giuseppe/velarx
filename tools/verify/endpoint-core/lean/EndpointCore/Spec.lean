-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/endpoint-core, which registries a reference is
-- fetched from, in words and in statements, with no proof.  `select` finds the block of
-- registries.conf that governs a name, and `endpoints` makes, for a pull or a push of `host/path`,
-- the list of the endpoints to try, in order: the mirrors that may serve the request, then the
-- registry itself.  This file is what a reviewer reads; Lean checks the rest (the proofs are in the
-- other files of EndpointCore/, and Theorems.lean ties each claim below to its proof).
--
-- Why it is needed: the engine asks the endpoints in this order, with the credentials the user
-- typed on the command line only for the host the user named, and with the flags (`insecure`,
-- `allow_private`) each endpoint was given.  A wrong list sends a password to another host, or
-- asks a mirror that was blocked.  The tests of the crate (src/rules.rs, src/walk.rs) check the
-- rules on every small input over a small alphabet, against a reference written with the string
-- methods of the standard library; each claim below is the same rule for EVERY input.  A proof is
-- worth what its statement says, so each claim has a comment of what it claims and of what it
-- does NOT.
--
-- Words.  A name, a prefix, a location, a path is a list of BYTES (`Bytes`; `Slash` is `/`,
-- `AtSign` is `@`, `Colon` is `:`, `Dot` is `.`, `Star` is `*`).  The vocabulary of the claims is
-- written first, by what things ARE, not by how the code computes them:
--   - a prefix GOVERNS a name (`Governs`): a plain prefix when the name is it or goes on with `/`
--     or `@` right after it (so `example.com` governs `example.com/x`, and does not govern
--     `example.community/x` nor `example.com:5000/x`: a `:` is not a boundary, in a name it starts
--     a port); a wildcard prefix `*.domain` when the host of the name (the bytes before its first
--     `/` or `@`, without the last `:` and the port after it) is some bytes, a `.` and the domain;
--   - a block is CHOSEN for a name (`Chooses`): the one whose prefix governs the name and is the
--     longest of those that do, the first of them when two are as long, none when none governs;
--   - a name is REWRITTEN (`Rewritten`, `RegistryName`): the prefix is replaced by the location,
--     what follows the prefix stays;
--   - an address `host/path` is LOCATED (`Located`): at the host before its first `/` (the Hub,
--     `docker.io`, as `registry-1.docker.io`) and the path after it; with no `/` it has no
--     repository;
--   - a mirror is ASKED (`Asked`) when the request is not a push, its mode serves the request (a
--     mirror for digests only serves a request that has a digest, one for tags only a request
--     that has none) and the block chosen for its own address is not blocked; it is LISTED
--     (`Listed`) when it is asked and its address is not the registry's own (host and path).
--
-- Totality: each claim about a function says that it RETURNS (no panic, no overflow of a
-- `usize`, no byte read outside a name, every loop ends) and what its answer is.  The only
-- assumption is `Fits`: the name, and the name with any location in front of it, fit in a `usize`
-- (the copies the code makes are that long); every call that exists satisfies it, since all the
-- bytes are in memory.
--
-- Both directions: "the mirrors listed are asked" alone is satisfied by a function that refuses
-- everything.  So the claims say what is in the list (every mirror listed, and no other), and that
-- a refusal is made exactly in the cases that the code states, and that otherwise a list is
-- answered and it is not empty.
--
-- Two inputs at the edge, on which the code and the reference of src/rules.rs agree: a block with
-- an EMPTY prefix is never chosen (the loop of `select` compares the length of a prefix with the
-- best so far, which starts at 0), and a wildcard prefix `*.test` governs the host `.test` (an
-- empty label before the dot, as in containers/image).  The reader of registries.conf never
-- makes them: an empty prefix is refused or replaced by the location, and the grammar of
-- references refuses an empty label.  The claims below state what the code does.
--
-- Read before this file: the header of crates/endpoint-core/src/lib.rs, and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every input):
--
--   The functions return
--     SelectAndEndpointsAlwaysReturn      `select` and `endpoints` return (no panic, no overflow)
--
--   The block of a name
--     SelectReturnsTheBlockChosen         `select` returns the block chosen: it governs the name,
--                                         no governing prefix is longer, the first of equals;
--                                         none exactly when no block governs
--     NoBlockIsChosenWithoutABoundary     a plain prefix is chosen only for a name that is it or
--                                         goes on with `/` or `@` right after it
--
--   The credentials
--     CommandLineCredentialsAreForTheHostNamed
--                                         an endpoint is marked to have the credentials of the
--                                         command line exactly when its host is the host the
--                                         user named (the Hub folded in both)
--
--   The list
--     TheListIsTheListedMirrorsThenTheRegistry
--                                         the registry (the rewrite by the chosen block, or the
--                                         name itself) is last; before it, exactly the listed
--                                         mirrors, in the order of the block, each at its own
--                                         address (a push has none)
--
--   The flags and `by_digest`
--     FlagsAreTheirOwn                    the registry is insecure by its block or by the request;
--                                         a mirror by its own entry or by the request; private
--                                         addresses by the block of the registry (and for a
--                                         mirror also the block of its own address); nothing else
--     ByDigestIsForADigestMirror          `by_digest` exactly for a mirror for digests only, and
--                                         only for a request that has a digest
--
--   The refusals
--     BlockedIsRefusedExactly             `Blocked` exactly when the block chosen is blocked
--     NoRepositoryIsRefusedExactly        `NoRepository` exactly when the registry's address, or
--                                         that of a mirror that is asked, has no `/`
--     OtherwiseAListIsAnswered            in every other case a list is answered
--     AnAnswerIsNeverEmpty                and a list is never empty
--
--   Examples
--     WorkedExamples                      the Hub with a mirror, a push, a prefix and a port
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; nothing else (the crate calls no function
--   of the standard library that has to be modelled by hand).
--
--   Not claimed:
--   - the reading of registries.conf: the TOML, and the normalisation of prefixes and locations
--     through the reference grammar (that every prefix and location is a good host and path, that
--     a block with no prefix has its location for prefix, what `pull-from-mirror` settles); the
--     claims are about the blocks the shell hands over;
--   - the lookup of stored credentials, and what the shell does with `CommandLine` and `Stored`
--     (that it gives the credentials of the command line only to an endpoint marked so, and the
--     realm of a token);
--   - that the shell asks the endpoints in the order of the list and stops as it should (at the
--     first answer, or at the last), and the digest check of what a mirror answers and the fall
--     to the next endpoint when it differs;
--   - short names and search registries (the shell makes the host and the path of a name);
--   - what TLS verification does with `insecure`, and what the address policy does with
--     `allow_private`: the claims say which flag an endpoint is given, not what the shell then
--     lets it do;
--   - that a mirror and a registry are asked at a good URL: the host and the path are bytes, the
--     shell makes the URL;
--   - the names that the grammar makes impossible: an empty prefix and a host that starts with a
--     dot (see above);
--   - the registry of a block with a wildcard prefix and a `location`: the reader of
--     registries.conf (crates/registry/src/config.rs) refuses such a block when the file is read,
--     so the claims are not about a block like that (containers/image accepts it, and this
--     engine does not).  Were it handed over, the location would not be used for the registry
--     (the prefix `*.x` is not the beginning of a name), and it would be for the mirrors
--     (`Rewritten`);
--   - that the shell passes as `host` the host the user typed (`docker.io`, not a short name
--     already completed), and how it builds `Ask` (a push asks for no mirrors, in
--     crates/registry/src/target.rs); that only the exact bytes `docker.io` are folded to the Hub
--     in the core, `index.docker.io` being folded by the shell before;
--   - the number of mirrors that the rules test (`all.len() <= mirrors + 1`): it follows from the
--     list claim (there are as many endpoints as listed mirrors, and the listed are among the
--     mirrors of the block), but it is not a claim of its own.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic and
--     does not loop for ever) and its answer `r` satisfies `P r`.
--   - `s : Slice Std.U8` is a Rust slice of bytes; `s.val` is the list inside it; `v.val` the same
--     for a vector.  `l[i]?` is `some` of the element at the place `i` of `l`, or `none`.
--   - `l ++ l'` is `l` and then `l'`; `x :: l` is `l` with `x` before; `l <+: l'` is "l is the
--     beginning of l'"; `l.takeWhile p` and `l.dropWhile p` are what is before and what is from
--     the first element that does not satisfy `p`; `l.drop n` is `l` without its first `n`.
--   - `List.Forall₂ R l m` reads: `l` and `m` are as long, and `R` holds of the elements at each
--     place.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `∧` is "and", `∨` is
--     "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not", `∈` is "is in".
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

open Classical

noncomputable section

/-! ### Bytes -/

/-- A name, a prefix, a location or a path, as the list of its bytes. -/
abbrev Bytes := List Std.U8

/-- The byte `/`. -/
def Slash : Std.U8 := 47#u8
/-- The byte `@`. -/
def AtSign : Std.U8 := 64#u8
/-- The byte `:`. -/
def Colon : Std.U8 := 58#u8
/-- The byte `.`. -/
def Dot : Std.U8 := 46#u8
/-- The byte `*`. -/
def Star : Std.U8 := 42#u8

/-- The bytes of `docker.io`, the name of the Hub. -/
def HubName : Bytes :=
  [100#u8, 111#u8, 99#u8, 107#u8, 101#u8, 114#u8, 46#u8, 105#u8, 111#u8]

/-- The bytes of `registry-1.docker.io`, the host that answers for the Hub. -/
def HubApi : Bytes :=
  [114#u8, 101#u8, 103#u8, 105#u8, 115#u8, 116#u8, 114#u8, 121#u8, 45#u8, 49#u8, 46#u8, 100#u8,
    111#u8, 99#u8, 107#u8, 101#u8, 114#u8, 46#u8, 105#u8, 111#u8]

/-- The name asked for, as `endpoints` builds it: the host, a `/` and the path. -/
def NameOf (host path : Bytes) : Bytes := host ++ Slash :: path

/-! ### Which prefix governs which name -/

/-- A wildcard prefix: `*.` and a domain, for example `*.example.com`. -/
def IsWildcard (pfx : Bytes) : Prop := ∃ domain, pfx = Star :: Dot :: domain

/-- `host` is the host of the name `ref` as a wildcard prefix reads it: the bytes of the name before
its first `/` or `@`, without the last `:` and what follows it (the port).  So `a.test:5000/x` has
the host `a.test`, and `a.test/x:5` has the host `a.test`. -/
def HostOf (ref host : Bytes) : Prop :=
  ∃ authority, authority = ref.takeWhile (fun b => b ≠ Slash ∧ b ≠ AtSign) ∧
    ((Colon ∉ authority ∧ host = authority) ∨
      ∃ port, authority = host ++ Colon :: port ∧ Colon ∉ port)

/-- The prefix `pfx` GOVERNS the name `ref`.
- A plain prefix governs the names that are it, and those that go on with a `/` or an `@` right
  after it: `example.com` governs `example.com` and `example.com/a/b`, and does not govern
  `example.community/x`, nor `example.com:5000/x` (a `:` is not a boundary: in a name it starts
  a port; the prefix `example.com:5000` governs that name).
- A wildcard prefix `*.domain` governs the names whose host (`HostOf`) is some bytes, a `.` and
  the domain, whatever the port: `*.example.com` governs `a.example.com/x` and
  `a.example.com:5000/x`, not `example.com/x`.

Not said: that the prefix is a good prefix (that is the reader of registries.conf's). -/
def Governs (pfx ref : Bytes) : Prop :=
  (IsWildcard pfx ∧ ∃ domain host front,
      pfx = Star :: Dot :: domain ∧ HostOf ref host ∧ host = front ++ Dot :: domain) ∨
  (¬ IsWildcard pfx ∧
      (ref = pfx ∨ ∃ boundary rest,
        (boundary = Slash ∨ boundary = AtSign) ∧ ref = pfx ++ boundary :: rest))

/-- `found` is the block CHOSEN for the name `ref` among `blocks`: the one whose prefix governs the
name and is the longest of those that do, the first of them when several have the longest prefix
(the TIE RULE: of two blocks with prefixes as long, the one that comes first in the file).  `none`
is chosen exactly when no block's prefix governs the name.  A block with an empty prefix is never
chosen (see the header). -/
def Chooses (blocks : List Block) (ref : Bytes) (found : Option Nat) : Prop :=
  (∀ b, found = some b → ∃ block, blocks[b]? = some block ∧
      block.prefix.val ≠ [] ∧ Governs block.prefix.val ref ∧
      (∀ other ∈ blocks, other.prefix.val ≠ [] → Governs other.prefix.val ref →
        other.prefix.length ≤ block.prefix.length) ∧
      (∀ j earlier, j < b → blocks[j]? = some earlier → earlier.prefix.val ≠ [] →
        Governs earlier.prefix.val ref → earlier.prefix.length < block.prefix.length)) ∧
  (found = none ↔ ∀ other ∈ blocks, other.prefix.val ≠ [] → ¬ Governs other.prefix.val ref)

/-- The block that the place `found` names among `blocks`, if there is one. -/
def ChosenBlock (blocks : List Block) (found : Option Nat) : Option Block :=
  found.bind fun b => blocks[b]?

/-! ### Where a block or a mirror puts a name -/

/-- The name `ref` REWRITTEN for a mirror at `location` of a block with prefix `pfx`: the location,
and what follows the prefix.  For a wildcard prefix what is replaced is the host, up to the first
`/` of the name, so the port goes with it: `a.test:5000/x` under `*.test` with the location `cache`
becomes `cache/x`. -/
def Rewritten (pfx location ref : Bytes) : Bytes :=
  if IsWildcard pfx then location ++ ref.dropWhile (fun b => b ≠ Slash)
  else if pfx <+: ref then location ++ ref.drop pfx.length
  else ref

/-- Where the registry of a block has the name `ref`: at the location of the block with what
follows the prefix, when the block has a location and its prefix is the beginning of the name;
else where the name is.  (A wildcard prefix is never the beginning of a name, so the location of a
block with a wildcard prefix is not used for its registry.) -/
def RegistryName (block : Block) (ref : Bytes) : Bytes :=
  match block.location with
  | some location =>
    if block.prefix.val <+: ref then location.val ++ ref.drop block.prefix.length else ref
  | none => ref

/-- Where the registry is asked for the name `ref`, when the block `found` is chosen: the rewrite by
the block, or the name itself when no block governs it. -/
def RegistryOf (blocks : List Block) (found : Option Nat) (ref : Bytes) : Bytes :=
  match ChosenBlock blocks found with
  | some block => RegistryName block ref
  | none => ref

/-! ### Endpoints -/

/-- The host as an endpoint says it: the Hub, `docker.io`, is `registry-1.docker.io`, every other
host is itself. -/
def Folded (host : Bytes) : Bytes := if host = HubName then HubApi else host

/-- Where an address `host/path` LOCATES an endpoint: at the host (the part before the first `/`,
the Hub folded) and the path (the part after it).  An address with no `/` has no repository, so
nothing. -/
def Located (address : Bytes) : Option (Bytes × Bytes) :=
  if Slash ∈ address then
    some (Folded (address.takeWhile (fun b => b ≠ Slash)),
      (address.dropWhile (fun b => b ≠ Slash)).drop 1)
  else none

/-- Where an endpoint is: its host and its path. -/
def _root_.velarx_endpoint_core.Endpoint.Where (e : Endpoint) : Bytes × Bytes :=
  (e.host.val, e.path.val)

/-! ### The mirrors -/

/-- A mirror of this mode serves a request that has a digest (`has_digest`), or has none: every
request for a mirror for all, one with a digest for a mirror for digests only, one with none for
a mirror for tags only. -/
def Serves (mode : Mode) (has_digest : Bool) : Prop :=
  match mode with
  | .All => True
  | .DigestOnly => has_digest = true
  | .TagOnly => has_digest = false

/-- The address of the mirror `m` of `block` for the name `ref`: the name rewritten by the block at
the location of the mirror. -/
def MirrorAddress (block : Block) (m : Mirror) (ref : Bytes) : Bytes :=
  Rewritten block.prefix.val m.location.val ref

/-- The block chosen for `address` among `blocks` is blocked. -/
def BlockedAt (blocks : List Block) (address : Bytes) : Prop :=
  ∃ b block, Chooses blocks address (some b) ∧ blocks[b]? = some block ∧ block.blocked = true

/-- The block chosen for `address` among `blocks` lets its endpoints reach private addresses. -/
def AllowsPrivateAt (blocks : List Block) (address : Bytes) : Prop :=
  ∃ b block, Chooses blocks address (some b) ∧ blocks[b]? = some block ∧
    block.allow_private = true

/-- The mirror `m` of `block` is ASKED for the name `ref`: the request is not a push, the mode of
the mirror serves the request, and the block chosen for the address of the mirror is not
blocked. -/
def Asked (blocks : List Block) (block : Block) (ask : Ask) (ref : Bytes) (m : Mirror) : Prop :=
  ask.push = false ∧ Serves m.mode ask.has_digest ∧
    ¬ BlockedAt blocks (MirrorAddress block m ref)

/-- The mirror `m` of `block` is LISTED among the endpoints: it is asked, and its address is not
the registry's own (the same host, the Hub folded, and the same path). -/
def Listed (blocks : List Block) (block : Block) (ask : Ask) (ref registry : Bytes)
    (m : Mirror) : Prop :=
  Asked blocks block ask ref m ∧ Located (MirrorAddress block m ref) ≠ Located registry

/-- Of the mirrors `ms` of `block`, those that are listed, each with its address, in order. -/
def ListedAmong (blocks : List Block) (block : Block) (ask : Ask) (ref registry : Bytes)
    (ms : List Mirror) : List (Mirror × Bytes) :=
  (ms.filter fun m => decide (Listed blocks block ask ref registry m)).map
    fun m => (m, MirrorAddress block m ref)

/-- The mirrors that are listed for the name `ref` when the block `found` is chosen, each with its
address, in the order of the block (none when no block is chosen: a name that no block governs
has no mirror). -/
def ListedMirrors (blocks : List Block) (found : Option Nat) (ask : Ask) (ref : Bytes) :
    List (Mirror × Bytes) :=
  match ChosenBlock blocks found with
  | some block =>
    ListedAmong blocks block ask ref (RegistryOf blocks found ref) block.mirrors.val
  | none => []

/-! ### What the chosen block says -/

/-- The block chosen is blocked. -/
def ChosenIsBlocked (blocks : List Block) (found : Option Nat) : Prop :=
  ∃ block, ChosenBlock blocks found = some block ∧ block.blocked = true

/-- The block chosen says its registry may be reached insecurely. -/
def ChosenIsInsecure (blocks : List Block) (found : Option Nat) : Prop :=
  ∃ block, ChosenBlock blocks found = some block ∧ block.insecure = true

/-- The block chosen lets its endpoints reach private addresses. -/
def ChosenAllowsPrivate (blocks : List Block) (found : Option Nat) : Prop :=
  ∃ block, ChosenBlock blocks found = some block ∧ block.allow_private = true

/-- A mirror of the block chosen is asked for the name `ref`, and its address has no repository
(no `/`). -/
def AMirrorHasNoRepository (blocks : List Block) (found : Option Nat) (ask : Ask) (ref : Bytes) :
    Prop :=
  ∃ block, ChosenBlock blocks found = some block ∧ ∃ m ∈ block.mirrors.val,
    Asked blocks block ask ref m ∧ Slash ∉ MirrorAddress block m ref

/-! ### What the caller gives -/

/-- Room for the bytes: the name `host/path` fits in a `usize`, and so does the name with a
location of a block or of a mirror in front of it (the copies the code makes are that long), and
a block has fewer mirrors than a `usize` counts.  Every call that exists satisfies it, and it
excludes no input: the host, the path and a location are separate buffers alive at the same time
in one address space, so their lengths add up to no more than a `usize` holds. -/
def Fits (blocks : Slice Block) (host path : Slice Std.U8) : Prop :=
  host.length + 1 + path.length ≤ Std.Usize.max ∧
  ∀ block ∈ blocks.val,
    (∀ location, block.location = some location →
      host.length + 1 + path.length + location.length ≤ Std.Usize.max) ∧
    (∀ m ∈ block.mirrors.val, host.length + 1 + path.length + m.location.length ≤ Std.Usize.max) ∧
    block.mirrors.length < Std.Usize.max

/-! ### The claims -/

/-- **`select` and `endpoints` always return.**  `select` returns for every blocks and every
name; `endpoints` for every blocks, host, path and request that `Fits`: no panic, no overflow of a
`usize`, no byte read outside a name, every loop ends.  (The claims after this one say what they
answer.)

Not said: what they answer. -/
def SelectAndEndpointsAlwaysReturn : Prop :=
  (∀ (blocks : Slice Block) (ref : Slice Std.U8), select blocks ref ⦃ _ => True ⦄) ∧
  (∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    endpoints blocks host path ask ⦃ _ => True ⦄)

/-- **`select` returns the block chosen** (`Chooses`): the block it returns governs the name, no
block that governs the name has a longer prefix, a block before it with a prefix as long does not
govern it; and it returns none exactly when no block's prefix governs the name.  So a function
that returns `none` always, or the first block, fails this claim.

Not said: the case of an empty prefix: such a block is never chosen (see the header). -/
def SelectReturnsTheBlockChosen : Prop :=
  ∀ (blocks : Slice Block) (ref : Slice Std.U8),
    select blocks ref ⦃ found => Chooses blocks.val ref.val (found.map (·.val)) ⦄

/-- **A prefix does not govern a name it only starts.**  `select` never returns a block with a
plain prefix for a name that goes on after the prefix with a byte other than `/` and `@`: with
the block `example.com` alone, `example.community/x` and `example.com:5000/x` have no block (see
`WorkedExamples`).  (It is the "no boundary" half of `Governs`, said of `select`; the other half
is in `SelectReturnsTheBlockChosen`.)

Not said: the case of a wildcard prefix. -/
def NoBlockIsChosenWithoutABoundary : Prop :=
  ∀ (blocks : Slice Block) (ref : Slice Std.U8),
    select blocks ref ⦃ found => ∀ b, found = some b → ∀ block, blocks.val[b.val]? = some block →
      ¬ IsWildcard block.prefix.val → ∀ c rest, ref.val = block.prefix.val ++ c :: rest →
        c = Slash ∨ c = AtSign ⦄

/-- **THE CREDENTIALS CLAIM.**  In every list `endpoints` answers, an endpoint is marked to receive
the credentials of the command line (`Creds.CommandLine`) exactly when its host is the host the
user named, the Hub, `docker.io`, being `registry-1.docker.io` for both (`Folded`).  So a mirror
on another host, and a registry that a `location` moved to another host, are marked `Stored`
(they have the credentials stored for them, if any); a mirror on the same host, with another path,
is marked `CommandLine`.

Not said: what the shell does with the mark (that it gives the credentials of the command line
to no endpoint marked `Stored`), the stored credentials, the realm of a token. -/
def CommandLineCredentialsAreForTheHostNamed : Prop :=
  ∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    endpoints blocks host path ask ⦃ r => ∀ es, r = .Ok es → ∀ e ∈ es.val,
      (e.creds = Creds.CommandLine ↔ e.host.val = Folded host.val) ⦄

/-- **THE ENDPOINT LIST.**  For the block chosen for the name (`found`), when `endpoints` answers
a list: the registry is last, at the rewrite of the name by the chosen block (the name itself when
no block governs it, `RegistryOf`); before it come the endpoints of the listed mirrors
(`ListedMirrors`), in the order of the block, each at its own address, and no other: a push has
none, a mirror for digests only is there only for a request that has a digest, one for tags only
for a request that has none, a mirror whose own address is governed by a blocked block is
skipped, and a mirror at the registry's own host and path is left out.  Every endpoint's host and
path are the host and the path of its address (`Located`): the rewrite of the name by its own
location.

Not said: that the list is answered (the claims about refusals say when), the flags, `by_digest`,
the credentials (each has its own claim). -/
def TheListIsTheListedMirrorsThenTheRegistry : Prop :=
  ∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    ∀ found, Chooses blocks.val (NameOf host.val path.val) found →
      endpoints blocks host path ask ⦃ r => ∀ es, r = .Ok es →
        ∃ mirrors primary, es.val = mirrors ++ [primary] ∧
          Located (RegistryOf blocks.val found (NameOf host.val path.val)) = some primary.Where ∧
          List.Forall₂ (fun p e => Located p.2 = some e.Where)
            (ListedMirrors blocks.val found ask (NameOf host.val path.val)) mirrors ⦄

/-- **THE FLAGS.**  The registry (the last endpoint) is insecure exactly when its block says so or
the request turned the verification of TLS off; it may reach private addresses exactly when its
block says so (with no block governing the name, the registry may not reach private addresses).
A mirror is insecure exactly when its own entry says so or the request turned the verification
off; it may reach private addresses exactly when the block that lists it says so or the block
chosen for its own address does.  Nothing else
turns a flag on: not the `insecure` of the registry's block for a mirror, not the entry of
another mirror.

Not said: what the shell does with the flags (TLS verification, the address policy). -/
def FlagsAreTheirOwn : Prop :=
  ∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    ∀ found, Chooses blocks.val (NameOf host.val path.val) found →
      endpoints blocks host path ask ⦃ r => ∀ es, r = .Ok es →
        ∃ mirrors primary, es.val = mirrors ++ [primary] ∧
          (primary.insecure = true ↔
            ChosenIsInsecure blocks.val found ∨ ask.tls_verify = false) ∧
          (primary.allow_private = true ↔ ChosenAllowsPrivate blocks.val found) ∧
          List.Forall₂ (fun p e =>
              (e.insecure = true ↔ p.1.insecure = true ∨ ask.tls_verify = false) ∧
              (e.allow_private = true ↔
                ChosenAllowsPrivate blocks.val found ∨ AllowsPrivateAt blocks.val p.2))
            (ListedMirrors blocks.val found ask (NameOf host.val path.val)) mirrors ⦄

/-- **`by_digest`.**  An endpoint is asked by the digest of the manifest (`by_digest`) exactly
when it is the endpoint of a mirror for digests only, whatever the algorithm of the digest; the
registry never is; and no endpoint is unless the request has a digest.

Not said: what the shell asks for the others (the tag, or the digest when the request has one). -/
def ByDigestIsForADigestMirror : Prop :=
  ∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    ∀ found, Chooses blocks.val (NameOf host.val path.val) found →
      endpoints blocks host path ask ⦃ r => ∀ es, r = .Ok es →
        (∀ e ∈ es.val, e.by_digest = true → ask.has_digest = true) ∧
        ∃ mirrors primary, es.val = mirrors ++ [primary] ∧ primary.by_digest = false ∧
          List.Forall₂ (fun p e => e.by_digest = true ↔ p.1.mode = Mode.DigestOnly)
            (ListedMirrors blocks.val found ask (NameOf host.val path.val)) mirrors ⦄

/-- **`Blocked`.**  `endpoints` refuses with `Blocked` exactly when the block chosen for the
name is blocked, for a push too, whatever the mirrors are. -/
def BlockedIsRefusedExactly : Prop :=
  ∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    ∀ found, Chooses blocks.val (NameOf host.val path.val) found →
      endpoints blocks host path ask ⦃ r => r = .Err .Blocked ↔ ChosenIsBlocked blocks.val found ⦄

/-- **`NoRepository`.**  When the block chosen is not blocked, `endpoints` refuses with
`NoRepository` exactly when the registry's address has no `/` (the name that is the prefix, with a
location that has no path: e.g. prefix `a.test/x`, location `m.test`, name `a.test/x` gives
`m.test`, no repository), or the address of a mirror that is asked has no `/`: a mirror that is
asked is never ignored silently.  A mirror that is not asked (a push, a mode that does not serve,
a blocked block) is not looked at.  Never otherwise. -/
def NoRepositoryIsRefusedExactly : Prop :=
  ∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    ∀ found, Chooses blocks.val (NameOf host.val path.val) found →
      endpoints blocks host path ask ⦃ r => r = .Err .NoRepository ↔
        (¬ ChosenIsBlocked blocks.val found ∧
          (Slash ∉ RegistryOf blocks.val found (NameOf host.val path.val) ∨
            AMirrorHasNoRepository blocks.val found ask (NameOf host.val path.val))) ⦄

/-- **Otherwise a list.**  In every other case `endpoints` answers a list: the block chosen is not
blocked, the registry's address has a `/` and no mirror that is asked is without one.  With the
two claims before, a function that refuses everything fails. -/
def OtherwiseAListIsAnswered : Prop :=
  ∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    ∀ found, Chooses blocks.val (NameOf host.val path.val) found →
      endpoints blocks host path ask ⦃ r => (∃ es, r = .Ok es) ↔
        (¬ ChosenIsBlocked blocks.val found ∧
          Slash ∈ RegistryOf blocks.val found (NameOf host.val path.val) ∧
          ¬ AMirrorHasNoRepository blocks.val found ask (NameOf host.val path.val)) ⦄

/-- **A list is not empty.**  Every list `endpoints` answers has at least the registry. -/
def AnAnswerIsNeverEmpty : Prop :=
  ∀ (blocks : Slice Block) (host path : Slice Std.U8) (ask : Ask), Fits blocks host path →
    endpoints blocks host path ask ⦃ r => ∀ es, r = .Ok es → es.val ≠ [] ⦄

/-! ### Worked examples -/

/-- The bytes of a text, for the examples. -/
def Ascii (text : String) : Bytes := text.toList.map fun c => ⟨BitVec.ofNat _ c.toNat⟩

/-- A short text as a vector of bytes, for the examples. -/
def TextVec (text : String) (short : text.toList.length ≤ 255 := by decide) :
    alloc.vec.Vec Std.U8 :=
  alloc.vec.Vec.from (Ascii text) (by simp [Ascii]; scalar_tac)

/-- A short text as a slice of bytes, for the examples. -/
def TextSlice (text : String) (short : text.toList.length ≤ 255 := by decide) : Slice Std.U8 :=
  (TextVec text short).deref

/-- A block with this prefix, no location, none of the flags, and these mirrors, for the
examples. -/
def PlainBlock (pfx : String) (mirrors : List Mirror := [])
    (short : pfx.toList.length ≤ 255 := by decide) (few : mirrors.length ≤ 255 := by decide) :
    Block where
  «prefix» := TextVec pfx short
  location := none
  insecure := false
  blocked := false
  allow_private := false
  mirrors := alloc.vec.Vec.from mirrors (by scalar_tac)

/-- A block with this prefix and this location, none of the flags and no mirror, for the
examples. -/
def MovedBlock (pfx location : String) (short : pfx.toList.length ≤ 255 := by decide)
    (short_location : location.toList.length ≤ 255 := by decide) : Block where
  «prefix» := TextVec pfx short
  location := some (TextVec location short_location)
  insecure := false
  blocked := false
  allow_private := false
  mirrors := alloc.vec.Vec.from [] (by scalar_tac)

/-- A mirror at this location, with no flag and for every request, for the examples. -/
def PlainMirror (location : String) (short : location.toList.length ≤ 255 := by decide) :
    Mirror where
  location := TextVec location short
  insecure := false
  mode := .All

/-- Some blocks as a slice, for the examples. -/
def BlocksOf (blocks : List Block) (few : blocks.length ≤ 255 := by decide) : Slice Block :=
  Slice.from blocks (by scalar_tac)

/-- **A few examples**, worked out from the claims above (not by running the code).
1. For the block `docker.io` with the mirror `mirror.example.com/hub`, a pull of
   `docker.io/library/alpine` is asked at `mirror.example.com`, path `hub/library/alpine`, and
   then at `registry-1.docker.io`, path `library/alpine`; only the Hub is marked to have the
   credentials of the command line.
2. A push of the same name is asked at the Hub only.
3. With the block `example.com` alone, no block is chosen for `example.community/x`, nor for
   `example.com:5000/x`: a prefix does not govern a name it only starts.
4. With the blocks `example.com` and `example.com:5000`, the second is chosen for
   `example.com:5000/x`: a prefix that names the port governs it.
5. The security case.  For the block `a.test` with the location `b.test` (another host), a pull
   of `a.test/x` is asked at `b.test`, path `x`, and that registry has the credentials stored for
   it, not those of the command line: the user typed them for `a.test`.
6. For the block `a.test` with a mirror at `a.test/m` (the host the user named, another path), a
   pull of `a.test/x` is asked at `a.test`, path `m/x`, and then at `a.test`, path `x`, and both
   have the credentials of the command line. -/
def WorkedExamples : Prop :=
  (endpoints (BlocksOf [PlainBlock "docker.io" [PlainMirror "mirror.example.com/hub"]])
      (TextSlice "docker.io") (TextSlice "library/alpine")
      { has_digest := false, push := false, tls_verify := true } ⦃ r =>
    ∃ es, r = .Ok es ∧
      es.val.map Endpoint.Where = [(Ascii "mirror.example.com", Ascii "hub/library/alpine"),
        (Ascii "registry-1.docker.io", Ascii "library/alpine")] ∧
      es.val.map (·.creds) = [Creds.Stored, Creds.CommandLine] ⦄) ∧
  (endpoints (BlocksOf [PlainBlock "docker.io" [PlainMirror "mirror.example.com/hub"]])
      (TextSlice "docker.io") (TextSlice "library/alpine")
      { has_digest := false, push := true, tls_verify := true } ⦃ r =>
    ∃ es, r = .Ok es ∧
      es.val.map Endpoint.Where = [(Ascii "registry-1.docker.io", Ascii "library/alpine")] ⦄) ∧
  (select (BlocksOf [PlainBlock "example.com"]) (TextSlice "example.community/x") ⦃ found =>
    found = none ⦄) ∧
  (select (BlocksOf [PlainBlock "example.com"]) (TextSlice "example.com:5000/x") ⦃ found =>
    found = none ⦄) ∧
  (select (BlocksOf [PlainBlock "example.com", PlainBlock "example.com:5000"])
      (TextSlice "example.com:5000/x") ⦃ found => found = some 1#usize ⦄) ∧
  (endpoints (BlocksOf [MovedBlock "a.test" "b.test"]) (TextSlice "a.test") (TextSlice "x")
      { has_digest := false, push := false, tls_verify := true } ⦃ r =>
    ∃ es, r = .Ok es ∧
      es.val.map Endpoint.Where = [(Ascii "b.test", Ascii "x")] ∧
      es.val.map (·.creds) = [Creds.Stored] ⦄) ∧
  (endpoints (BlocksOf [PlainBlock "a.test" [PlainMirror "a.test/m"]])
      (TextSlice "a.test") (TextSlice "x")
      { has_digest := false, push := false, tls_verify := true } ⦃ r =>
    ∃ es, r = .Ok es ∧
      es.val.map Endpoint.Where = [(Ascii "a.test", Ascii "m/x"), (Ascii "a.test", Ascii "x")] ∧
      es.val.map (·.creds) = [Creds.CommandLine, Creds.CommandLine] ⦄)

end

end EndpointCore
