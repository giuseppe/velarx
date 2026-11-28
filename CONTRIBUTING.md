<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to Velarx

Thank you for helping.  This file is what you need to build the project, run
its tests and send a change.  [README.md](README.md) says what Velarx is and
how to use it; [AGENTS.md](AGENTS.md) has the same rules in the short form
that the coding agents of the project read.

## Build

You need a Rust toolchain, `pkg-config` and the development packages of
sqlite, zstd and openssl (the CRI frontend also needs `protoc`).  To run
containers you need Linux 7.3 or later and `crun` 1.30 or later; see "Requirements" in the
README.

```sh
make build-debug          # every binary, debug profile (what the e2e tests run)
make                      # the same, release
make build-client         # the thin client only
make help                 # every target and variable
```

The Makefile is the one entry point.  Use it instead of
a plain `cargo build`: the thin client and the optional services have to be
built with their own flags (`make build-client` is `cargo build -p velarx-bin
--no-default-features --bin velarx-client`).  `cargo build` and `cargo
test` alone build and test the default members of the workspace; the
peer-to-peer service, the REST API frontend and the CRI frontend are built
by `make build-p2p`, `make build-api` and `make build-cri`.

`make setup-env` is optional: it writes a git-ignored `.velarx-dev.mk` that
uses the `mold` linker when it is installed.  Builds go through the `kache`
cache when it is installed.

## The test tiers

| Command | What it runs | When |
| --- | --- | --- |
| `make fmt-check` | `cargo fmt --check` (`make fmt` formats) | every change |
| `cargo test -p PKG`, `make e2e T="..."` | the tests of the area: the packages you touched and the bats files of the area (`tools/tests-for-diff BASE` prints them) | while you write a series, each commit |
| `make test` | the quick tier: `fmt-check`, `clippy`, `check` (every target of the workspace, also with `--features fuzzing`), the debug build, then side by side `test-unit` (`cargo test`, velarx-api's tests) and `e2e-rootless` (every bats file but the p2p ones, as your user) | once per series, on its final tree |
| `make test-full` | everything: the lint tools, `clippy`, `check`, one build, then side by side the cargo tests of every package with the tests that wait (`VELARX_SLOW_TESTS=1`) and fs-verity (`VELARX_VERITY_DIR`), the fuzz corpora, the rootless bats files, the p2p ones (`e2e-p2p`, under `P2P_LOCK`) and the Lean proofs (`test-lean`, `LEAN=0` leaves them out); then the root bats files (`e2e-root`) | before a push to GitHub, and nightly |
| `make e2e T="..."` | some end to end (bats) files | a change in the area they cover |
| `make licenses-binary` | `THIRD-PARTY-LICENSES.<binary>`: the crates each binary links, with their license texts | a change to the dependencies, a release |
| `make audit` | advisories and licenses of the dependencies (needs `cargo-deny`) | a change to the dependencies |
| `make fuzz FUZZ=name` | one fuzz target (needs `cargo-fuzz`) | a change to a parser |

Useful variants: `make test-unit TESTARGS=pull_tests::` runs one area of the
integration tests, `make test-pkg PKG=velarx-core` one package,
`make test-lint` the lint tests of the sources (licenses, forbidden calls,
no bare issue numbers: name the fact, not `#NNN`; upstream issues are
`owner/repo#NNN` or `podman #NNN`); it fails on a test that keeps its
temporary directory (`tempdir().keep()`, `into_path`, `mem::forget`).
`make test-leaks` runs the library tests of every package (`PKG=name` of one)
in a private `TMPDIR` and fails on the `.tmp*` directories they leave.
`make test-verity VELARX_VERITY_DIR=dir` runs the cargo tests of `make test-unit`
(minutes; `TESTARGS=filter` for fewer) with that directory on a file system
with fs-verity: the tests that need one, spread over several packages and
named for what they check, skip their fs-verity part without it.  The target
fails when `VELARX_VERITY_DIR` is not a directory.
`make test-all` is the old name of `make test-full`.
Binaries and dependency counts are kept small on purpose; there is no size
limit that fails a build: `make bench-startup` prints the stripped sizes, and a
change that is expected to move them says by how much in its commit message.

## One verification per series

A full run takes long, so it is done once per series of commits, on the
tree that is sent, and not again for what did not change:

* While you write the series, run the tests of what you touch: `cargo test
  -p` of the packages and the bats files of the area (`make e2e T="..."`, as
  root `make e2e-root T="..."` for the root ones).  `tools/tests-for-diff
  BASE` prints them for the files changed since BASE; it is a floor, add
  what you know the change touches.  A reviewer runs the same, for the diff
  under review.
* On the final tree of the series, once: `make test`, and `make test-full`
  before a push to GitHub.  Note the tree that passed: `git rev-parse
  HEAD^{tree}`.
* After a rebase, a fixup or an amend, compare the new tree with the one
  that passed.  The same tree hash (a reworded message, a squash, a
  reordering that ends on the same files): nothing runs again.  Otherwise
  `tools/tests-for-diff VERIFIED` (VERIFIED: the commit that passed) gives
  what the difference asks for, and only that runs again; when it says
  `make test` (the difference is in code every bats file runs, or a
  rebase brought in such changes), the quick tier runs again, and
  `make test-full` again only before a push to GitHub.

## The checks before a pull request

There is no CI that builds or tests a pull request yet: run these yourself
before you push (a GitHub workflow checks only the DCO sign-offs):

```sh
make fmt-check reuse issue-refs docs-check clippy   # format, licenses, bare issue numbers, documents, lints
make build-default PROFILE=debug                    # the build
make test                                           # the quick tier (the thin client too)
make audit                                          # advisories, bans, licenses (needs cargo-deny)
make check-dco BASE=origin/main                     # every commit signed off
```

`make ci` runs most of them, and `make docs-commands` too, which checks the
commands the documents show against the binaries and needs `make
build-debug` first.  On Debian and Ubuntu the system packages are
`build-essential pkg-config libsqlite3-dev libzstd-dev libssl-dev
protobuf-compiler python3 git crun` (the unit tests need the crun binary to
exist, none starts a container).  Run `cargo fetch --locked` once: a lint
test reads `cargo metadata --offline`, which needs the crates of every
platform.  The toolchain is the one `rust-toolchain.toml` pins, which is the
`rust-version` of `Cargo.toml`.  A fast-tier test that needs root, FUSE, a
user namespace or a kernel feature the machine lacks prints `skipped: ...`
and passes; a change to the runtime, the monitor, storage, networking or
the systemd integration also runs the end to end tier (`make e2e`) and says
in its pull request what it ran.  A change to a crate with Lean proofs (the
directories of `tools/verify`) runs `tools/verify/run` for that crate.

The integration tests are modules of `tests/integration/main.rs`: one
binary, all tests in parallel in one process.  A test must not change the
state of the process (environment, current directory, signals), must not
sleep for a fixed time or poll, and waits for an event (a pidfd, a socket, a
channel).  A test that must wait long runs only with `VELARX_SLOW_TESTS=1`.

## End to end tests

The files of `tests/e2e/bats` run the real binaries, so they need
[`bats`](https://bats-core.readthedocs.io/), the debug binaries, and what
each file says in its header.  Build first, then run them from a copy of the
binaries if another build can replace them meanwhile:

```sh
make build-debug
make e2e-list                                      # the names usable as T=
make e2e T="run-lifecycle kube"                    # rootless, as your user
make e2e T=kube BATS_ARGS="--filter NAME"          # one test of a file
VELARX_BINDIR=/path/to/copy make e2e T=kube        # binaries of a copy
make e2e-root                                      # as root (through sudo)
```

Rootless needs sub ids in `/etc/subuid` and `/etc/subgid`, `newuidmap` and
`newgidmap`, a systemd user session for the files that test the units, and
`/dev/fuse`.  `make e2e-root` also runs the files that need root (mounts,
fs-verity, cgroups of the system manager); `SUDO=` changes how root is
reached, and it is empty when you already are root.  Without `T` it runs
the files with root tests (`tools/run-bats root`; `tools/run-bats list
root` names them) six at a time: as root a file shares the host, so each
has a default bridge and subnets of its own (`e2e_bridge_toml` of
`tests/e2e/bats/helpers.bash`, in every configuration a root file writes),
units and ports with names and numbers of its own, and
`tests/e2e/run-all.sh` runs the files that cannot share the host (`ALONE`)
with no other file.  A root file that needs a fixed port, unit name or
subnet takes one no other file uses; one that looks at the whole host
(every process of root, every unit) goes in `ALONE`.  `make e2e-rootless`
runs every file but the p2p ones as your user, five at a time, and `make
e2e-p2p` the p2p ones one at a time, holding the lock file `P2P_LOCK`.
The files that pull images use a registry that has an `alpine:chunked`
image whose TOCs give the fs-verity digest of every file (what `velarx image push --compression-format
zstd:chunked` writes; a zstd:chunked layer without those digests, as
containers/storage writes it, is refused) and, for the tests of that refusal,
an `alpine-plain:chunked` image made by containers/storage (they skip without
it): `E2E_REGISTRY`
(host:port, plain HTTP, default `localhost:5000`; `tests/e2e/bats/helpers.bash`
reads it once and every file uses the variable, so a registry on another port
needs no edit; `E2E_IMAGE` defaults to `$E2E_REGISTRY/alpine:chunked`, and
`E2E_TLS_REGISTRY`, default `localhost:5001`, is the TLS one of the `--cert-dir`
checks, with its CA file in `E2E_TLS_CA`); a test that cannot find what it needs is skipped,
and says so.  Every file has a work directory, a daemon and a store of its
own under `E2E_TMPDIR` (default `/var/tmp`), so `E2E_JOBS` of them run side
by side; `E2E_LOGDIR` keeps the output of each.

`make e2e` runs the debug binaries of `VELARX_BINDIR` (default
`target/debug`) through `tests/e2e/run-all.sh`, which runs the files several at
a time with a timeout (do not use a plain `bats --jobs`). The tests wait for
events, not for time; each file says in its header what it needs.

## Rules of the code

* Every source file starts with
  `SPDX-License-Identifier: Apache-2.0`
  and every `*.md` with the same line as an HTML comment (a unit test fails
  without it).  Do not copy code under a license that is not compatible with
  Apache-2.0 (GPL, LGPL); code of another origin keeps its notice and is
  listed in [NOTICE](NOTICE).
* `unsafe` lives in `crates/sys` only (the workspace forbids it elsewhere),
  and the peer-to-peer stack only in `crates/p2p`; lint tests fail otherwise.
* No warnings and no unused symbols: find out why a symbol is unused before
  deleting it.
* Comments only where they are strictly necessary, and no history in them.
  Code that fails after a long time must be easy to debug: errors name what
  failed and on what.
* No backward compatibility with older versions (stores, databases, wire
  formats, configuration): change a format and its readers together.  What
  is not implemented is an error, never silently ignored.
* No polling and no fixed sleeps.  Every knob is a setting of `config.toml`
  and is in `config.toml.example`.
* OCI images are the only ones written (Docker schema 2 ones are read).  Do not add the `regex` crate (`regex-lite` is used).
* Do not commit test generated data.  Add a `.md` file only when it is
  strictly necessary: findings, designs and status go to the issue tracker.

## Commits and sign-off

* One logical change per commit, committed when it is complete.  Do not
  batch unrelated changes.  Every commit builds and passes the tests of
  its area; the series passes `make test` on its final tree (see "One
  verification per series").
* Run `make fmt` before you commit.
* A short subject that says what the commit does, and a body that says why.
* Velarx has no contributor license agreement.  It uses the [Developer
  Certificate of Origin, version 1.1](https://developercertificate.org/):
  every commit has a line

      Signed-off-by: Your Name <you@example.com>

  which `git commit -s` adds from `user.name` and `user.email`.  Forgot it?
  `git commit --amend -s` for the last commit, `git rebase --signoff
  origin/main` for several.  `make check-dco BASE=origin/main` checks the
  commits you made; CI refuses a pull request with an unsigned commit. A
  server that hosts the repository can refuse unsigned pushes with
  `tests/dco-pre-receive.sh` as its `pre-receive` hook (its header says how).
* The copyright of a contribution stays with its author.

## Pull requests

Rebase on the main branch before you open the pull request.  Say what was
wrong or missing, what the change does, how you tested it, and what you
could not test (a root-only file, a kernel feature your machine lacks).
Check `git diff --stat origin/main...HEAD`: it must show only the files of
your change.
