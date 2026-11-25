-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what is proved of crates/addr-core, the judgement of which network addresses
-- are LOCAL, that is, of this machine, of a private network or of the metadata service of a cloud:
-- `local_v4` judges an IPv4 address (4 bytes), `local_v6` an IPv6 address (16 bytes), and the second
-- also judges the IPv6 forms that carry an IPv4 address inside (`::ffff:10.0.0.1` and the like) by
-- the address inside.  This file is what a reviewer reads, in words and in statements, with no proof;
-- Lean checks the rest (the proofs are in the other files of AddrCore/, and Theorems.lean ties each
-- claim below to its proof).
--
-- Why it is needed: a registry names a token realm, a redirect or a CDN, and a name may resolve to an
-- address the machine must not connect to for it: the loopback, a private network, the link-local
-- address 169.254.169.254 where clouds serve the credentials of the machine, 168.63.129.16 where
-- Azure does.  The registry client (crates/registry/src/netpolicy.rs) asks this crate about every
-- address.  A mistake in a bit shift or in a table is a request forgery that no test of a few
-- addresses may catch; the tests of the crate (src/walk.rs, src/rules.rs) check the edges of every
-- prefix, each claim below is the same rule for EVERY address.  A proof is worth what its statement
-- says, so each claim has a comment of what it claims and of what it does NOT.
--
-- Words.  An ADDRESS is its bytes, first byte first; its NUMBER is the bytes read as one number
-- (`Number`): 10.0.0.1 is 10 * 2^24 + 1, `::1` is 1.  `Ipv4 a b c d` is the number of the address
-- a.b.c.d, `Ipv6 g0 .. g7` that of the eight groups of 16 bits g0:g1:...:g7.  A PREFIX is an address
-- and a length, `10.0.0.0/8`: the addresses that begin with the first 8 bits of 10.0.0.0, in numbers
-- the block from the first number up to, not including, the first plus 2^(32 - 8) (`InPrefix`).
-- An address is LOCAL when the function answers `true` (the registry client refuses it) and PUBLIC
-- when it answers `false`.  `LocalV4` and `LocalV6` are the two tables of the crate, written again
-- here as in the registries of the internet; `Embedded` is the table of the IPv6 prefixes that carry
-- an IPv4 address: compatible `::a.b.c.d`, mapped `::ffff:a.b.c.d`, translated `::ffff:0:a.b.c.d`,
-- NAT64 `64:ff9b::a.b.c.d` and 6to4 `2002:a.b.c.d::` (each with the number of bits the IPv4 address
-- is from the end of the address).
--
-- Total correctness: each claim says that the function RETURNS (no panic, no overflow, no byte read
-- outside the address) and what its answer is.  Nothing is assumed of an address beyond its length.
--
-- Both directions: "an address of 10.0.0.0/8 is never public" alone is satisfied by a function that
-- refuses everything.  So the claims come in two kinds: what must be local (the named classes, the
-- metadata addresses, WhatIsLocalExactly) and what must be public (ThePublicV4Addresses,
-- ThePublicV6Addresses, the examples of public addresses such as 8.8.8.8, and the addresses next to
-- each edge of each range), and the answer is exactly one of the two for every address.
--
-- Read before this file: the header of crates/addr-core/src/lib.rs (its numbered rules), and rules.rs.
--
-- Index.  What each claim is about:
--
--   Claimed (each for every address):
--
--   The functions return
--     TheFunctionsAlwaysReturn            `local_v4` and `local_v6` return, whatever the bytes
--
--   The rules of the crate (lib.rs, rules 2 and 3)
--     WhatIsLocalExactly                  an IPv4 address is local exactly when it is in a prefix of
--                                         `LocalV4`; an IPv6 address exactly when it is in a prefix of
--                                         `LocalV6` or in a form of `Embedded` whose IPv4 address is local
--
--   IPv4
--     ThePublicV4Addresses                public: in no prefix of the table; every address in no
--                                         prefix of the table is public
--     TheTableAsNumbers                   the 15 prefixes of `LocalV4`, each as its first and its
--                                         last number
--     TheNamedV4ClassesAreLocal           0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12,
--                                         192.168/16, 224/4 and 240/4, as the numbers they span, and
--                                         168.63.129.16
--     TheMetadataAddressesAreLocal        169.254.169.254, 169.254.170.2, 168.63.129.16,
--                                         100.100.100.200, 192.0.0.192
--     ThePublicV4Examples                 8.8.8.8, 1.1.1.1, 9.9.9.9 and the address on the outer side
--                                         of the edge of each range are public; the first and the
--                                         last of each range are local
--
--   IPv6
--     ThePublicV6Addresses                public: in no prefix of `LocalV6` and, in a form of
--                                         `Embedded`, with a public IPv4 address inside; and the
--                                         converse
--     TheEmbeddedAddressesAreJudgedAsTheirV4   an address in a form of `Embedded` is judged exactly as
--                                         the four bytes of IPv4 address in it, whatever the other bits
--     NoFormOfALocalV4IsPublic            so no form of a local IPv4 address is public
--     TheNamedV6ClassesAreLocal           `::`, `::1`, fc00::/7, fe80::/10, fec0::/10, ff00::/8,
--                                         100::/64, 2001::/32 (Teredo), 2001:2::/48, 2001:db8::/32,
--                                         64:ff9b:1::/48
--     TheV6Examples                       the forms of the metadata address and of the loopback are
--                                         local, `fd00:ec2::254` is local; the DNS of Google and of
--                                         Cloudflare and the forms of 8.8.8.8 are public; the edges
--
--   Trusted: Charon and Aeneas (../../pins) and Lean; the crate calls the standard library for the
--   length of a slice only, which Aeneas models; no model is written by hand.
--
--   Not claimed:
--   - that the table is the right one (that every address that must be refused is in it): it is the
--     list of the crate, stated again; the claims say that the code is exactly that list, and what
--     the list contains is the owner's to judge;
--   - IPv6 forms of an IPv4 address that the crate does not know: ISATAP (`::5efe:a.b.c.d` as the
--     last 64 bits of any prefix), a NAT64 with a prefix of the network (RFC 6052 allows 32 to 96
--     bits) other than `64:ff9b::/96`, IPv4 in the interface identifier of any other scheme.  An
--     address of these forms is judged by its own bits, as a public IPv6 address;
--   - the rule of the caller ("a name that was public may not turn local"), where addresses come from
--     (names, URLs, literals) and what is done with the answer: that is the registry client's
--     (netpolicy.rs); this crate judges one address, the same answer for the same bytes, and says
--     nothing of two addresses of one name;
--   - that an address that is public is safe: only that it is in none of the ranges of the table.
--
-- Notation:
--   - `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns (it does not panic) and
--     its answer `r` satisfies `P r`.
--   - `a : Std.Array Std.U8 4#usize` is an array of 4 bytes; `a.val` is the list inside it.
--   - `∀ x, P` is "for every x, P"; `∃ x, P` is "there is an x such that P"; `x ∈ l` is "x is in the
--     list l"; `∧` is "and", `∨` is "or", `→` is "if ... then", `↔` is "exactly when", `¬` is "not".
--   - `q.1`, `q.2` are the first and the second of a pair `q`; `a ^ b` is a to the power b; `n / m`
--     and `n % m` are the whole quotient and the remainder.
import Extracted.Funs

open Aeneas Aeneas.Std Result velarx_addr_core

namespace AddrCore

/-- The number an address is: its bytes, first byte first, read as one number (the first byte is the
most significant). -/
def Number (bytes : List Std.U8) : Nat := bytes.foldl (fun n b => 256 * n + b.val) 0

/-- The number of the IPv4 address a.b.c.d. -/
def Ipv4 (a b c d : Nat) : Nat := a * 2 ^ 24 + b * 2 ^ 16 + c * 2 ^ 8 + d

/-- The number of the IPv6 address whose eight groups of 16 bits are g0:g1:g2:g3:g4:g5:g6:g7. -/
def Ipv6 (g0 g1 g2 g3 g4 g5 g6 g7 : Nat) : Nat :=
  g0 * 2 ^ 112 + g1 * 2 ^ 96 + g2 * 2 ^ 80 + g3 * 2 ^ 64 + g4 * 2 ^ 48 + g5 * 2 ^ 32 + g6 * 2 ^ 16 + g7

/-- The number `n` of an address of `bits` bits (32 or 128) is in the prefix of the address whose
number is `first` and of the length `len`: it is from `first` up to, not including, `first` plus
the number of the addresses that begin with the same `len` bits (`first` is the first of them). -/
def InPrefix (bits n first len : Nat) : Prop := first ≤ n ∧ n < first + 2 ^ (bits - len)

/-- The local IPv4 prefixes, as (first address, length), in the order of the table `LOCAL_V4` of
lib.rs (RFC 6890: this network, private, shared, loopback, link-local with the metadata services,
private, private, protocol assignments, documentation, benchmarking, documentation, documentation,
the wire server of Azure, multicast, reserved with the broadcast address). -/
def LocalV4 : List (Nat × Nat) :=
  [(Ipv4 0 0 0 0, 8), (Ipv4 10 0 0 0, 8), (Ipv4 100 64 0 0, 10), (Ipv4 127 0 0 0, 8),
   (Ipv4 169 254 0 0, 16), (Ipv4 172 16 0 0, 12), (Ipv4 192 168 0 0, 16), (Ipv4 192 0 0 0, 24),
   (Ipv4 192 0 2 0, 24), (Ipv4 198 18 0 0, 15), (Ipv4 198 51 100 0, 24), (Ipv4 203 0 113 0, 24),
   (Ipv4 168 63 129 16, 32), (Ipv4 224 0 0 0, 4), (Ipv4 240 0 0 0, 4)]

/-- The number `n` is the number of a local IPv4 address: it is in a prefix of `LocalV4`. -/
def IsLocalV4 (n : Nat) : Prop := ∃ q ∈ LocalV4, InPrefix 32 n q.1 q.2

/-- The local IPv6 prefixes, as (first address, length), in the order of `LOCAL_V6` of lib.rs:
unspecified, loopback, unique local, link-local, site-local (deprecated), multicast, discard-only,
Teredo, benchmarking, documentation, NAT64 for local use. -/
def LocalV6 : List (Nat × Nat) :=
  [(Ipv6 0 0 0 0 0 0 0 0, 128), (Ipv6 0 0 0 0 0 0 0 1, 128), (Ipv6 0xfc00 0 0 0 0 0 0 0, 7),
   (Ipv6 0xfe80 0 0 0 0 0 0 0, 10), (Ipv6 0xfec0 0 0 0 0 0 0 0, 10), (Ipv6 0xff00 0 0 0 0 0 0 0, 8),
   (Ipv6 0x100 0 0 0 0 0 0 0, 64), (Ipv6 0x2001 0 0 0 0 0 0 0, 32), (Ipv6 0x2001 2 0 0 0 0 0 0, 48),
   (Ipv6 0x2001 0xdb8 0 0 0 0 0 0, 32), (Ipv6 0x64 0xff9b 1 0 0 0 0 0, 48)]

/-- The IPv6 prefixes that carry an IPv4 address, as (first address, length, how many bits the IPv4
address is from the end of the address), in the order of `EMBEDDED` of lib.rs: compatible
`::a.b.c.d`, mapped `::ffff:a.b.c.d`, translated `::ffff:0:a.b.c.d`, NAT64 `64:ff9b::a.b.c.d`, and
6to4 `2002:a.b.c.d::` (the IPv4 address is the 32 bits after the first 16, so 80 bits from the end). -/
def Embedded : List (Nat × Nat × Nat) :=
  [(Ipv6 0 0 0 0 0 0 0 0, 96, 0), (Ipv6 0 0 0 0 0 0xffff 0 0, 96, 0), (Ipv6 0 0 0 0 0xffff 0 0 0, 96, 0),
   (Ipv6 0x64 0xff9b 0 0 0 0 0 0, 96, 0), (Ipv6 0x2002 0 0 0 0 0 0 0, 16, 80)]

/-- The number of the IPv4 address inside the IPv6 address of number `n`, when it is `shift` bits
from the end: the 32 bits there. -/
def EmbeddedV4 (n shift : Nat) : Nat := n / 2 ^ shift % 2 ^ 32

/-- The address `b` (4 bytes) is the IPv4 address inside the address `a` (16 bytes) of the form `e`
of `Embedded`: `a` is in the prefix of the form, and `b` is the 4 bytes of `a` from the byte
(96 - shift) / 8 (the byte 12 for the last four bytes, the byte 2 for 6to4). -/
def EmbedsIn (a b : List Std.U8) (e : Nat × Nat × Nat) : Prop :=
  InPrefix 128 (Number a) e.1 e.2.1 ∧ b = (a.drop ((96 - e.2.2) / 8)).take 4

/-- **The functions always return.**  `local_v4` for every 4 bytes and `local_v6` for every 16 bytes:
no panic, no overflow, no byte read outside the address.

Not said: what they return (the claims below). -/
def TheFunctionsAlwaysReturn : Prop :=
  (∀ a : Std.Array Std.U8 4#usize, local_v4 a ⦃ _ => True ⦄) ∧
  (∀ a : Std.Array Std.U8 16#usize, local_v6 a ⦃ _ => True ⦄)

/-- **What is local, exactly** (the rules 2 and 3 of lib.rs).  `local_v4` returns, and says `true`
exactly when the address is in a prefix of `LocalV4`.  `local_v6` returns, and says `true` exactly
when the address is in a prefix of `LocalV6`, or is in a form of `Embedded` and the IPv4 address
inside (the 32 bits `shift` bits from the end) is local.  There is no other way to be local, and no
other way to be public.

Not said: whether the tables are the right ones (the claims below spell out what they hold). -/
def WhatIsLocalExactly : Prop :=
  (∀ a : Std.Array Std.U8 4#usize, local_v4 a ⦃ r =>
    r = true ↔ ∃ q ∈ LocalV4, InPrefix 32 (Number a.val) q.1 q.2 ⦄) ∧
  (∀ a : Std.Array Std.U8 16#usize, local_v6 a ⦃ r =>
    r = true ↔ (∃ q ∈ LocalV6, InPrefix 128 (Number a.val) q.1 q.2) ∨
      ∃ e ∈ Embedded, InPrefix 128 (Number a.val) e.1 e.2.1 ∧
        IsLocalV4 (EmbeddedV4 (Number a.val) e.2.2) ⦄)

/-- **The public IPv4 addresses.**  `local_v4` returns, and
- (public is outside) when it says `false`, the address is in no prefix of `LocalV4`: not 0/8, 10/8,
  100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16, 192.0.0/24, 192.0.2/24, 198.18/15,
  198.51.100/24, 203.0.113/24, not 168.63.129.16, not 224/4 or 240/4;
- (everything else is public) when the address is in none of them, it says `false`.
So a function that refuses everything fails the second half.

Not said: that these are all the addresses a registry must not reach. -/
def ThePublicV4Addresses : Prop :=
  ∀ a : Std.Array Std.U8 4#usize, local_v4 a ⦃ r =>
    (r = false → ∀ q ∈ LocalV4, ¬ InPrefix 32 (Number a.val) q.1 q.2) ∧
    ((∀ q ∈ LocalV4, ¬ InPrefix 32 (Number a.val) q.1 q.2) → r = false) ⦄

/-- **The table as numbers.**  The 15 prefixes of `LocalV4` span exactly these numbers, as (first,
last): 0.0.0.0-0.255.255.255 (0/8), 10.0.0.0-10.255.255.255, 100.64.0.0-100.127.255.255,
127.0.0.0-127.255.255.255, 169.254.0.0-169.254.255.255, 172.16.0.0-172.31.255.255,
192.168.0.0-192.168.255.255, 192.0.0.0-192.0.0.255, 192.0.2.0-192.0.2.255, 198.18.0.0-198.19.255.255,
198.51.100.0-198.51.100.255, 203.0.113.0-203.0.113.255, 168.63.129.16 alone,
224.0.0.0-239.255.255.255, 240.0.0.0-255.255.255.255.

Not said: anything of the code (this is a fact of the table of the statement; the claims above tie
the code to the table). -/
def TheTableAsNumbers : Prop :=
  LocalV4.map (fun q => (q.1, q.1 + 2 ^ (32 - q.2) - 1)) =
    [(0, 16777215), (167772160, 184549375), (1681915904, 1686110207), (2130706432, 2147483647),
     (2851995648, 2852061183), (2886729728, 2887778303), (3232235520, 3232301055),
     (3221225472, 3221225727), (3221225984, 3221226239), (3323068416, 3323199487),
     (3325256704, 3325256959), (3405803776, 3405804031), (2822734096, 2822734096),
     (3758096384, 4026531839), (4026531840, 4294967295)]

/-- **The named IPv4 classes are local.**  `local_v4` returns, and says `true` for every address
- of this network 0.0.0.0-0.255.255.255 (the unspecified address is in it),
- of the private networks 10.0.0.0-10.255.255.255, 172.16.0.0-172.31.255.255 and
  192.168.0.0-192.168.255.255,
- of the shared space 100.64.0.0-100.127.255.255,
- of the loopback 127.0.0.0-127.255.255.255,
- of the link-local 169.254.0.0-169.254.255.255,
- of the multicast 224.0.0.0-239.255.255.255 and the reserved 240.0.0.0-255.255.255.255 (the
  broadcast address 255.255.255.255 is in it),
- and 168.63.129.16.

Not said: that these are the only local ones (`ThePublicV4Addresses`). -/
def TheNamedV4ClassesAreLocal : Prop :=
  ∀ a : Std.Array Std.U8 4#usize, local_v4 a ⦃ r =>
    (Ipv4 0 0 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 0 255 255 255 → r = true) ∧
    (Ipv4 10 0 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 10 255 255 255 → r = true) ∧
    (Ipv4 172 16 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 172 31 255 255 → r = true) ∧
    (Ipv4 192 168 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 192 168 255 255 → r = true) ∧
    (Ipv4 100 64 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 100 127 255 255 → r = true) ∧
    (Ipv4 127 0 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 127 255 255 255 → r = true) ∧
    (Ipv4 169 254 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 169 254 255 255 → r = true) ∧
    (Ipv4 224 0 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 239 255 255 255 → r = true) ∧
    (Ipv4 240 0 0 0 ≤ Number a.val ∧ Number a.val ≤ Ipv4 255 255 255 255 → r = true) ∧
    (Number a.val = Ipv4 168 63 129 16 → r = true) ⦄

/-- **The metadata addresses of the clouds are local.**  `local_v4` returns, and says `true` for
169.254.169.254 (AWS, GCP, Azure, DigitalOcean and others), 169.254.170.2 (the task credentials of
AWS ECS), 168.63.129.16 (the wire server of Azure, a public address), 100.100.100.200 (Alibaba
Cloud, in the shared space) and 192.0.0.192 (Oracle Cloud).

Not said: that every cloud's address is in the table. -/
def TheMetadataAddressesAreLocal : Prop :=
  ∀ a : Std.Array Std.U8 4#usize, local_v4 a ⦃ r =>
    (Number a.val = Ipv4 169 254 169 254 → r = true) ∧
    (Number a.val = Ipv4 169 254 170 2 → r = true) ∧
    (Number a.val = Ipv4 168 63 129 16 → r = true) ∧
    (Number a.val = Ipv4 100 100 100 200 → r = true) ∧
    (Number a.val = Ipv4 192 0 0 192 → r = true) ⦄

/-- **Public IPv4 examples, and the edges.**  `local_v4` returns, and says `false` for 8.8.8.8,
1.1.1.1, 9.9.9.9 and for the address next to each range on its outer side: 9.255.255.255 and
11.0.0.0, 100.63.255.255 and 100.128.0.0, 126.255.255.255 and 128.0.0.0, 169.253.255.255 and
169.255.0.0, 172.15.255.255 and 172.32.0.0, 192.167.255.255 and 192.169.0.0, 198.17.255.255 and
198.20.0.0, 198.51.99.255 and 198.51.101.0, 203.0.112.255 and 203.0.114.0, 192.0.1.0 (between the two /24 of
192.0), 168.63.129.15 and 168.63.129.17, and 223.255.255.255 (just below the multicast).  The first
and the last address of each range are local: among them 0.0.0.0, 10.0.0.0, 172.16.0.0,
172.31.255.255, 224.0.0.0 and 255.255.255.255.

Not said: anything of other addresses (the claims above are for all). -/
def ThePublicV4Examples : Prop :=
  ∀ a : Std.Array Std.U8 4#usize, local_v4 a ⦃ r =>
    (Number a.val ∈ [Ipv4 8 8 8 8, Ipv4 1 1 1 1, Ipv4 9 9 9 9, Ipv4 9 255 255 255, Ipv4 11 0 0 0,
        Ipv4 100 63 255 255, Ipv4 100 128 0 0, Ipv4 126 255 255 255, Ipv4 128 0 0 0,
        Ipv4 169 253 255 255, Ipv4 169 255 0 0, Ipv4 172 15 255 255, Ipv4 172 32 0 0,
        Ipv4 192 167 255 255, Ipv4 192 169 0 0, Ipv4 198 17 255 255, Ipv4 198 20 0 0,
        Ipv4 198 51 99 255, Ipv4 198 51 101 0, Ipv4 203 0 112 255, Ipv4 203 0 114 0,
        Ipv4 192 0 1 0, Ipv4 168 63 129 15, Ipv4 168 63 129 17, Ipv4 223 255 255 255] →
      r = false) ∧
    (Number a.val ∈ [Ipv4 172 16 0 0, Ipv4 172 31 255 255, Ipv4 10 0 0 0, Ipv4 10 255 255 255,
        Ipv4 100 64 0 0, Ipv4 100 127 255 255, Ipv4 127 0 0 0, Ipv4 127 255 255 255,
        Ipv4 169 254 0 0, Ipv4 169 254 255 255, Ipv4 192 168 0 0, Ipv4 192 168 255 255,
        Ipv4 198 18 0 0, Ipv4 198 19 255 255, Ipv4 224 0 0 0, Ipv4 239 255 255 255,
        Ipv4 240 0 0 0, Ipv4 255 255 255 255, Ipv4 0 0 0 0, Ipv4 0 255 255 255] →
      r = true) ⦄

/-- **The public IPv6 addresses.**  `local_v6` returns, and
- (public is outside) when it says `false`, the address is in no prefix of `LocalV6` and, for each
  form of `Embedded` it is in, the IPv4 address inside is public;
- (everything else is public) when the address is in no prefix of `LocalV6` and the IPv4 address
  inside each form it is in is public, it says `false`.
So a function that refuses everything fails the second half.

Not said: that an address of a form the crate does not know (see the head of this file) is judged by
the address inside. -/
def ThePublicV6Addresses : Prop :=
  ∀ a : Std.Array Std.U8 16#usize, local_v6 a ⦃ r =>
    (r = false → (∀ q ∈ LocalV6, ¬ InPrefix 128 (Number a.val) q.1 q.2) ∧
      ∀ e ∈ Embedded, InPrefix 128 (Number a.val) e.1 e.2.1 →
        ¬ IsLocalV4 (EmbeddedV4 (Number a.val) e.2.2)) ∧
    (((∀ q ∈ LocalV6, ¬ InPrefix 128 (Number a.val) q.1 q.2) ∧
      ∀ e ∈ Embedded, InPrefix 128 (Number a.val) e.1 e.2.1 →
        ¬ IsLocalV4 (EmbeddedV4 (Number a.val) e.2.2)) → r = false) ⦄

/-- **An address that embeds an IPv4 one is judged as that one** (the rule 4 of lib.rs).  For every
form `e` of `Embedded` (compatible, mapped, translated, NAT64, 6to4), every IPv6 address `a` in it
and the 4 bytes `b` of IPv4 address inside it (the last four bytes, for 6to4 the bytes 2 to 5),
`local_v4 b` returns and `local_v6 a` returns the same answer: whatever the other bits of `a` are.
So `::ffff:127.0.0.1` is local as 127.0.0.1 is, and `::ffff:8.8.8.8` is public as 8.8.8.8 is.

Not said: the forms the crate does not know (see the head of this file). -/
def TheEmbeddedAddressesAreJudgedAsTheirV4 : Prop :=
  ∀ (a : Std.Array Std.U8 16#usize) (b : Std.Array Std.U8 4#usize), ∀ e ∈ Embedded,
    EmbedsIn a.val b.val e → local_v4 b ⦃ s => local_v6 a ⦃ r => r = s ⦄ ⦄

/-- **No form of a local IPv4 address is public.**  For every form of `Embedded`, every IPv6 address
`a` in it and the IPv4 address `b` inside it: if `local_v4 b` says `true`, then `local_v6 a` says
`true`.  (The converse is in the claim above: a public IPv4 address inside makes a public IPv6
address.)

Not said: the forms the crate does not know. -/
def NoFormOfALocalV4IsPublic : Prop :=
  ∀ (a : Std.Array Std.U8 16#usize) (b : Std.Array Std.U8 4#usize), ∀ e ∈ Embedded,
    EmbedsIn a.val b.val e → local_v4 b ⦃ s => s = true → local_v6 a ⦃ r => r = true ⦄ ⦄

/-- **The named IPv6 classes are local.**  `local_v6` returns, and says `true` for every address
- `::` (unspecified) and `::1` (loopback),
- of the unique local fc00::/7 (the numbers from fc00:: to fdff:ffff:...),
- of the link-local fe80::/10, the site-local fec0::/10 and the multicast ff00::/8,
- of the discard-only 100::/64, of Teredo 2001::/32, of the benchmarking 2001:2::/48, of the
  documentation 2001:db8::/32 and of the NAT64 prefix for local use 64:ff9b:1::/48.

Not said: that these are the only local ones (`ThePublicV6Addresses`). -/
def TheNamedV6ClassesAreLocal : Prop :=
  ∀ a : Std.Array Std.U8 16#usize, local_v6 a ⦃ r =>
    (Number a.val = Ipv6 0 0 0 0 0 0 0 0 → r = true) ∧
    (Number a.val = Ipv6 0 0 0 0 0 0 0 1 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0xfc00 0 0 0 0 0 0 0) 7 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0xfe80 0 0 0 0 0 0 0) 10 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0xfec0 0 0 0 0 0 0 0) 10 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0xff00 0 0 0 0 0 0 0) 8 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0x100 0 0 0 0 0 0 0) 64 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0x2001 0 0 0 0 0 0 0) 32 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0x2001 2 0 0 0 0 0 0) 48 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0x2001 0xdb8 0 0 0 0 0 0) 32 → r = true) ∧
    (InPrefix 128 (Number a.val) (Ipv6 0x64 0xff9b 1 0 0 0 0 0) 48 → r = true) ⦄

/-- **IPv6 examples.**  `local_v6` returns, and says
- `true` for the forms of the loopback and of the metadata address: `::ffff:127.0.0.1`,
  `::ffff:169.254.169.254` (mapped), `::10.0.0.1` (compatible), `::ffff:0:10.0.0.1` (translated),
  `64:ff9b::a9fe:a9fe` (NAT64, 169.254.169.254), `2002:a9fe:a9fe::1` (6to4), and for `fd00:ec2::254`
  (the metadata address of AWS), `fe80::1`, `::1`;
- `false` for the public DNS servers `2001:4860:4860::8888` and `2606:4700:4700::1111`, and for the
  forms of 8.8.8.8: `::ffff:8.8.8.8`, `::8.8.8.8`, `::ffff:0:8.8.8.8`, `64:ff9b::808:808`,
  `2002:808:808::1`;
- `false` for the address next to the edge of a prefix: `2001:1::` (after Teredo), `2001:3::`,
  `2001:db9::`, `2001:2:1::`, `fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff` (before fe80::/10),
  `fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff` (before fc00::/7), `64:ff9b:2::`, and for `64:ff9b:0:1::`
  (not in the /96 of NAT64, so not an IPv4 address inside).

Not said: anything of other addresses (the claims above are for all). -/
def TheV6Examples : Prop :=
  ∀ a : Std.Array Std.U8 16#usize, local_v6 a ⦃ r =>
    (Number a.val ∈ [Ipv6 0 0 0 0 0 0xffff 0x7f00 1, Ipv6 0 0 0 0 0 0xffff 0xa9fe 0xa9fe,
        Ipv6 0 0 0 0 0 0 0x0a00 1, Ipv6 0 0 0 0 0xffff 0 0x0a00 1, Ipv6 0x64 0xff9b 0 0 0 0 0xa9fe 0xa9fe,
        Ipv6 0x2002 0xa9fe 0xa9fe 0 0 0 0 1, Ipv6 0xfd00 0xec2 0 0 0 0 0 0x254, Ipv6 0xfe80 0 0 0 0 0 0 1,
        Ipv6 0 0 0 0 0 0 0 1] → r = true) ∧
    (Number a.val ∈ [Ipv6 0x2001 0x4860 0x4860 0 0 0 0 0x8888, Ipv6 0x2606 0x4700 0x4700 0 0 0 0 0x1111,
        Ipv6 0 0 0 0 0 0xffff 0x0808 0x0808, Ipv6 0 0 0 0 0 0 0x0808 0x0808,
        Ipv6 0 0 0 0 0xffff 0 0x0808 0x0808, Ipv6 0x64 0xff9b 0 0 0 0 0x0808 0x0808,
        Ipv6 0x2002 0x0808 0x0808 0 0 0 0 1, Ipv6 0x2001 1 0 0 0 0 0 0, Ipv6 0x2001 3 0 0 0 0 0 0,
        Ipv6 0x2001 0xdb9 0 0 0 0 0 0, Ipv6 0x2001 2 1 0 0 0 0 0,
        Ipv6 0xfe7f 0xffff 0xffff 0xffff 0xffff 0xffff 0xffff 0xffff,
        Ipv6 0xfbff 0xffff 0xffff 0xffff 0xffff 0xffff 0xffff 0xffff, Ipv6 0x64 0xff9b 2 0 0 0 0 0,
        Ipv6 0x64 0xff9b 0 1 0 0 0 0] → r = false) ⦄

end AddrCore
