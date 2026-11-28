# SPDX-License-Identifier: Apache-2.0
# The one entry point of velarx for a contributor and for CI: build, format,
# test, end to end tests, fuzzing, install.  `make help` lists every target.
#
#   make                                  # build everything (release)
#   make build PROFILE=debug              # the same, debug (also: make build-debug)
#   make fmt-check clippy test            # what every change passes
#   make e2e T=run-lifecycle              # one end to end file
#   make install DESTDIR=/tmp/root PREFIX=/usr
#
# Variables (set them on the command line or in the environment):
#
#. PROFILE      release (default) or debug: the cargo profile of the build targets
#. CARGO        the cargo command (default cargo; a wrapper or `cargo +nightly`)
#. CARGOFLAGS   extra flags for every cargo call of this file
#. TESTARGS     arguments of `cargo test`, e.g. TESTARGS=pull_tests:: (test, test-slow, test-all)
#. COVERAGE_OUT  where `make coverage` puts its report (default target/coverage)
#. PKG          the package of `make test-pkg` and `make build-pkg` (velarx-core, ...)
#. TARGETDIR    where the built binaries are: $CARGO_TARGET_DIR (else target/) + PROFILE
#. DEBUGDIR     the debug build directory ($CARGO_TARGET_DIR/debug, else target/debug)
#. VELARX_BINDIR  the binaries the end to end tests run (default DEBUGDIR); point it at
#.              a copy of the binaries when another build may replace them meanwhile
#. T            e2e: the bats files to run, space separated (T="run-lifecycle kube"); all if empty
#. E2E_JOBS     e2e: files run side by side (default 6)
#. BATS_ARGS    e2e: arguments for bats, e.g. BATS_ARGS="--filter pull"
#. E2E_TIMEOUT  e2e: seconds a file may take (default 1800); E2E_LOGDIR keeps the logs
#. SUDO         e2e-root: how to become root (default sudo; nothing when already root)
#. KUBELET      cri-kubelet: the kubelet binary (default: kubelet in the PATH); IMAGE, REGISTRY_INSECURE: see tests/cri/kubelet.sh
#. CRI_ARGS     cri-tests: the options of tests/cri/run-all.sh (--only STEP, --skip-STEP, --focus REGEXP, --own-registry; --help)
#. PERF_ARGS   perf-compare: the options of tools/perf-compare (--out DIR, --runs N, --big-image REF, --only REGEXP; --help)
#. CRITEST_FOCUS critest-root: a ginkgo focus regexp
#. FUZZ         fuzz: the target (see make fuzz-list); FUZZ_TIME the seconds (default 60)
#. DISTDIR      dist: where the tarball and SHA256SUMS go (default dist); DIST_CHECK=0 skips the build from the tarball
#. BASE         check-dco: the revision the commits are counted from (BASE=origin/main)
#. PREFIX BINDIR LIBDIR SYSTEMDDIR TMPFILESDIR DOCDIR LICENSEDIR DESTDIR   install locations
#. LICENSESOUT  licenses-binary: where THIRD-PARTY-LICENSES.<binary> go (default THIRD-PARTY-LICENSES/)
#. MANDIR BASHCOMPDIR ZSHCOMPDIR FISHCOMPDIR   man pages and completions
#. KACHE=0      (environment, read by tools/rustc-wrapper) bypass the kache build cache
#. INSTALL_KACHE=1  setup-env: also `cargo install` kache when it is missing
#
# The binaries: velarx (the engine and the command line; the
# engine service is `velarx varlink`), velarx-client (the command line as a
# thin client, built without the engine), velarx-monitor (one per
# container), velarx-registry (the registry fetcher: the package crates/registry-lib/bin,
# which the engine finds next to itself and starts), velarx-kube (play, down,
# generate and apply of Kubernetes YAML: the packages crates/kube and crates/kube/bin,
# a frontend that calls the engine over varlink and links no engine code), velarx-p2p (the packages crates/p2p and crates/p2p/bin, the only one that links
# a peer-to-peer stack and QUIC; `cargo build` does not build it), velarx-cri (the packages
# crates/cri and crates/cri/bin, the Kubernetes CRI frontend: gRPC, needs protoc to build) and
# velarx-api (the packages crates/api and crates/api/bin: the REST API, a
# frontend that calls the engine over varlink and links no engine code).
#
# install puts the binaries in $(BINDIR), the units of the system and of
# the users' managers in $(SYSTEMDDIR)/{system,user} (with their ExecStart
# pointing at $(BINDIR)), the Quadlet generators in
# $(SYSTEMDDIR)/{system,user}-generators, the tmpfiles.d file in
# $(TMPFILESDIR) and config.toml.example in $(DOCDIR).  It installs no
# signature policy: without /etc/velarx/policy.json velarx accepts every
# image, the administrator's file hardens it.
# `make install-files` installs what is already built (PROFILE's directory
# of CARGO_TARGET_DIR, else target/, or TARGETDIR) after `make man` wrote
# the man pages and the completions (`man/` holds the hand-written ones,
# share/man the generated ones: nothing generated is in git); `make list`
# prints what install lays out.
#
# The tests, in two tiers:
#
#   make test        # the fast tier, what every change passes: cargo test
#                    # (the unit tests and the one integration binary),
#                    # and the tests of velarx-api (the size of the
#                    # arguments of the calls of the frontends, the pumps)
#   make test-all    # and the slow tier: the tests that wait
#                    # (VELARX_SLOW_TESTS), the p2p feature, the thin
#                    # client, and the end to end bats tests side by side
#                    # (tests/e2e/run-all.sh; as root, the root-only ones)

PROFILE ?= release
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
SYSTEMDDIR ?= $(LIBDIR)/systemd
TMPFILESDIR ?= $(LIBDIR)/tmpfiles.d
DOCDIR ?= $(PREFIX)/share/doc/velarx
# the license texts and the third-party licenses of the binaries (empty: not installed)
LICENSEDIR ?= $(PREFIX)/share/licenses/velarx
LICENSESOUT ?= THIRD-PARTY-LICENSES
MANDIR ?= $(PREFIX)/share/man
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR ?= $(PREFIX)/share/zsh/site-functions
FISHCOMPDIR ?= $(PREFIX)/share/fish/vendor_completions.d
# Where `make man` writes (share/man of the source tree, git ignored) and
# the shells it writes the completions of (bash, zsh, fish).
GENMANDIR ?= share/man
# The pages install lays out from it: section 1 always, section 8 for the
# binaries that are installed (the monitor always, the API frontend and the
# peers service when they were built).
MANPAGES = *.1 velarx-monitor.8 $(if $(API),velarx-api.8,) $(if $(P2P),velarx-p2p*.8,)
COMPLETIONS = bash zsh fish
DESTDIR ?=
CARGO ?= cargo
DISTDIR ?= dist
DEVENV_MK ?= .velarx-dev.mk
-include $(DEVENV_MK)
CARGOFLAGS ?=
TESTARGS ?=
PKG ?=
TARGETBASE = $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)
TARGETDIR ?= $(TARGETBASE)/$(PROFILE)
DEBUGDIR ?= $(TARGETBASE)/debug
VELARX_BINDIR ?= $(DEBUGDIR)
export VELARX_BINDIR
INSTALL ?= install
T ?=
BATS_ARGS ?=
SUDO ?= $(if $(filter 0,$(shell id -u)),,sudo)
FUZZ ?=
FUZZ_TIME ?= 60
FUZZ_DIRS = fuzz crates/p2p/fuzz
FUZZ_TARGETS = $(sort $(basename $(notdir $(wildcard $(addsuffix /fuzz_targets/*.rs,$(FUZZ_DIRS))))))
FUZZ_DIR = $(firstword $(foreach d,$(FUZZ_DIRS),$(if $(wildcard $(d)/fuzz_targets/$(FUZZ).rs),$(d))))
# E2E_JOBS, E2E_TIMEOUT and E2E_LOGDIR are read by tests/e2e/run-all.sh
# from the environment.
export E2E_JOBS E2E_TIMEOUT E2E_LOGDIR

# cargo's profile flag: release builds get --release; `debug` is cargo's default.
PROFILEFLAG = $(if $(filter release,$(PROFILE)),--release,$(if $(filter debug,$(PROFILE)),,--profile $(PROFILE)))
BUILD = $(CARGO) build $(PROFILEFLAG) $(CARGOFLAGS)
RUNALL = tests/e2e/run-all.sh $(T) $(if $(BATS_ARGS),-- $(BATS_ARGS))

# velarx-p2p and its unit when it was built.
P2P ?= $(if $(wildcard $(TARGETDIR)/velarx-p2p),yes,)
CRI ?= $(if $(wildcard $(TARGETDIR)/velarx-cri),yes,)
# velarx-api and its units when it was built.
API ?= $(if $(wildcard $(TARGETDIR)/velarx-api),yes,)
BINARIES = velarx velarx-registry velarx-dir velarx-kube velarx-client velarx-monitor $(if $(P2P),velarx-p2p,) $(if $(CRI),velarx-cri,) $(if $(API),velarx-api,)
# The Quadlet generators: podman's with PODMAN=velarx, once
# `velarx quadlet enable` masked podman's.
GENERATORS = system user
SYSTEM_UNITS = $(filter-out $(if $(P2P),,velarx-p2p.service velarx-p2p-overlay.service) $(if $(API),,velarx-api.service velarx-api.socket) $(if $(CRI),,velarx-cri.service velarx-cri.socket),$(sort $(notdir $(wildcard systemd/system/*.service systemd/system/*.socket systemd/system/*.timer))))
USER_UNITS = $(filter-out $(if $(P2P),,velarx-p2p.service) $(if $(API),,velarx-api.service velarx-api.socket) $(if $(CRI),,velarx-cri.service velarx-cri.socket),$(sort $(notdir $(wildcard systemd/user/*.service systemd/user/*.socket systemd/user/*.timer))))

.DEFAULT_GOAL := all
.PHONY: all help reuse licenses-binary issue-refs features-check patches-check deps-check docs-check docs-commands build build-debug build-default build-engine build-kube build-client build-p2p \
	build-api build-cri build-pkg man \
	fmt fmt-check clippy check install install-files uninstall list \
	test test-leaks test-slow test-lint test-pkg test-p2p test-api test-cri cri-tests critest-root cri-kubelet test-workspace test-all \
	test-fuzz-corpus e2e e2e-root p2p-rig e2e-list fuzz fuzz-list fuzz-all \
	coverage \
	check-dco audit licenses ci bench-startup perf-compare test-perf-compare dist clean setup-env unsetup-env

all: build ## build every binary (PROFILE=release by default)

help: ## list the targets and the variables
	@echo "Targets (make TARGET [VAR=value ...]):"
	@awk -F':.*## ' '/^[a-zA-Z0-9_-]+:.*## / { printf "  %-18s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo
	@echo "Variables:"
	@sed -n 's/^#\. \{0,1\}/  /p' $(MAKEFILE_LIST)

# ---- optional developer environment ----

# The repository builds with the default tools. This optional rule detects the
# faster ones on this machine and writes $(DEVENV_MK) (git ignored, read by
# this Makefile): mold as the linker when it is installed (a release build also
# merges identical functions, --icf=safe: 1.4% smaller; never forced, the
# default linker of the repository stays). kache is already
# used by every build through tools/rustc-wrapper when it is installed.
setup-env: ## optional: detect mold and kache, write .velarx-dev.mk (INSTALL_KACHE=1 installs kache)
	@host=$$(rustc -vV | sed -n 's/^host: //p'); \
	var=CARGO_TARGET_$$(echo "$$host" | tr 'a-z-' 'A-Z_')_RUSTFLAGS; \
	{ echo "# written by make setup-env; remove with make unsetup-env"; \
	  if command -v mold > /dev/null 2>&1; then \
	    echo "ifeq (\$$(PROFILE),release)"; \
	    echo "export $$var ?= -C link-arg=-fuse-ld=mold -C link-arg=-Wl,--icf=safe"; \
	    echo "else"; echo "export $$var ?= -C link-arg=-fuse-ld=mold"; echo "endif"; \
	    echo "mold: found ($$(command -v mold)), used as the linker (release builds also merge identical functions: --icf=safe, 1.4% smaller)" >&2; \
	  else echo "mold: not found (dnf install mold / apt install mold): the default linker is used" >&2; fi; \
	} > $(DEVENV_MK); \
	if command -v kache > /dev/null 2>&1 || [ -x "$$HOME/.local/bin/kache" ] || [ -x "$$HOME/.cargo/bin/kache" ]; then \
	  echo "kache: found, every build uses it (KACHE=0 bypasses it)"; \
	elif [ -n "$(INSTALL_KACHE)" ]; then \
	  echo "kache: installing with cargo"; $(CARGO) install --locked kache; \
	else echo "kache: not found (make setup-env INSTALL_KACHE=1, or cargo install --locked kache): builds are not cached" >&2; fi; \
	echo "wrote $(DEVENV_MK)"

unsetup-env: ## remove .velarx-dev.mk written by setup-env
	rm -f $(DEVENV_MK)

# ---- build ----

build: build-engine build-kube build-client build-p2p build-api build-cri ## all binaries, per package (velarx, monitor, client, p2p, api, cri)

build-debug: ## all binaries, debug profile (what the e2e tests run)
	$(MAKE) build PROFILE=debug

build-default: ## cargo build of the default members (what CI builds); PROFILE=debug for CI
	$(BUILD)

build-engine: ## velarx, velarx-monitor, velarx-registry and velarx-dir (the engine and the helpers it starts)
	$(BUILD) -p velarx-bin --bin velarx
	$(BUILD) -p velarx-monitor-bin
	$(BUILD) -p velarx-registry-bin
	$(BUILD) -p velarx-dir

# Without -p the other default members switch the engine features of their
# dependencies on: the thin client must be built on its own.
build-client: ## velarx-client, the thin client (no engine feature)
	$(BUILD) -p velarx-bin --no-default-features --bin velarx-client

build-p2p: ## velarx-p2p, the peer-to-peer service
	$(BUILD) -p velarx-p2p-bin

build-kube: ## velarx-kube, play, down, generate and apply of Kubernetes YAML
	$(BUILD) -p velarx-kube-bin

build-api: ## velarx-api, the REST API frontend
	$(BUILD) -p velarx-api-bin

build-cri: ## velarx-cri, the Kubernetes CRI frontend (skipped without protoc)
	@if command -v protoc > /dev/null; then $(BUILD) -p velarx-cri-bin; \
	else echo "protoc is missing: velarx-cri is not built"; fi

build-pkg: ## one package: make build-pkg PKG=velarx-core
	@test -n "$(PKG)" || { echo "usage: make build-pkg PKG=<package>" >&2; exit 2; }
	$(BUILD) -p $(PKG)

# ---- man pages and completions ----

# The pages that a clap definition writes (examples/generate-man.rs: the
# command line itself and the thin client in section 1;
# crates/p2p/examples/generate-man-p2p.rs: the service of the peers in
# section 8) go to $(GENMANDIR);
# man/ holds the hand-written ones (velarx-kube(1), velarx-registry(1), velarx-dir(1), velarx-monitor(8), velarx-api(8),
# velarx.conf(5)).  The completions come from the built `velarx` itself
# (`velarx completion SHELL`, clap_complete): they need PROFILE's build of
# it ($(TARGETDIR)/velarx), which `make install` has built already.  A
# test of the velarx package fails when the sections of config.toml.example
# and velarx.conf(5) drift apart.
man: ## write the man pages of share/man and man/ and the completions (never in git)
	$(CARGO) run $(CARGOFLAGS) -p velarx --no-default-features --example generate-man -- $(GENMANDIR)
	$(if $(P2P),$(CARGO) run $(CARGOFLAGS) -p velarx-p2p --example generate-man-p2p -- $(GENMANDIR))
	$(INSTALL) -m 0644 man/velarx-kube.1 man/velarx-registry.1 man/velarx-dir.1 man/velarx-monitor.8 man/velarx-api.8 man/velarx.conf.5 $(GENMANDIR)/
	$(if $(wildcard $(TARGETDIR)/velarx),,\
		$(error make man needs $(TARGETDIR)/velarx (make build-engine or make install) for the completions))
	for s in $(COMPLETIONS); do \
		$(TARGETDIR)/velarx completion $$s > $(GENMANDIR)/completion.$$s || exit 1; \
	done

# ---- format and check ----

fmt: ## cargo fmt: format the code (the fuzz crate too)
	$(CARGO) fmt --all
	for d in $(FUZZ_DIRS); do $(CARGO) fmt --manifest-path $$d/Cargo.toml || exit 1; done

fmt-check: ## cargo fmt --check, what CI runs
	$(CARGO) fmt --check

clippy: ## cargo clippy of the workspace with the tests, and of the thin client; warnings are errors (what CI runs)
	$(CARGO) clippy --workspace --all-targets $(CARGOFLAGS) -- -D warnings
	$(CARGO) clippy -p velarx-bin --no-default-features --bin velarx-client $(CARGOFLAGS) -- -D warnings

check: ## cargo check of the whole workspace with the tests, and of the thin client
	$(CARGO) check --workspace --tests $(CARGOFLAGS)
	$(CARGO) check -p velarx-bin --no-default-features --bin velarx-client $(CARGOFLAGS)

# ---- install ----

install: build man licenses-binary install-files ## build, then install into DESTDIR/PREFIX

install-files: ## install what is already built into DESTDIR/PREFIX (make man first)
	$(INSTALL) -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SYSTEMDDIR)/system \
		$(DESTDIR)$(SYSTEMDDIR)/user $(DESTDIR)$(TMPFILESDIR) $(DESTDIR)$(DOCDIR)
	for b in $(BINARIES); do \
		$(INSTALL) -m 0755 $(TARGETDIR)/$$b $(DESTDIR)$(BINDIR)/$$b || exit 1; \
	done
	for u in $(SYSTEM_UNITS); do \
		sed 's|/usr/bin/velarx|$(BINDIR)/velarx|g' systemd/system/$$u > $(DESTDIR)$(SYSTEMDDIR)/system/$$u && \
		chmod 0644 $(DESTDIR)$(SYSTEMDDIR)/system/$$u || exit 1; \
	done
	for u in $(USER_UNITS); do \
		sed 's|/usr/bin/velarx|$(BINDIR)/velarx|g' systemd/user/$$u > $(DESTDIR)$(SYSTEMDDIR)/user/$$u && \
		chmod 0644 $(DESTDIR)$(SYSTEMDDIR)/user/$$u || exit 1; \
	done
	$(INSTALL) -m 0644 systemd/tmpfiles.d/velarx.conf $(DESTDIR)$(TMPFILESDIR)/velarx.conf
	$(INSTALL) -m 0644 config.toml.example $(DESTDIR)$(DOCDIR)/config.toml.example
	$(if $(LICENSEDIR),$(INSTALL) -d $(DESTDIR)$(LICENSEDIR) && \
		$(INSTALL) -m 0644 LICENSE NOTICE $(DESTDIR)$(LICENSEDIR)/ && \
		for b in $(BINARIES); do \
			$(INSTALL) -m 0644 $(LICENSESOUT)/THIRD-PARTY-LICENSES.$$b $(DESTDIR)$(LICENSEDIR)/ || exit 1; \
		done)
	for k in $(GENERATORS); do \
		$(INSTALL) -d $(DESTDIR)$(SYSTEMDDIR)/$$k-generators && \
		sed 's|/usr/bin/velarx|$(BINDIR)/velarx|g' systemd/generators/velarx-generator \
			> $(DESTDIR)$(SYSTEMDDIR)/$$k-generators/velarx-$$k-generator && \
		chmod 0755 $(DESTDIR)$(SYSTEMDDIR)/$$k-generators/velarx-$$k-generator || exit 1; \
	done
	for p in `cd $(GENMANDIR) && ls $(MANPAGES) 2>/dev/null`; do \
		$(INSTALL) -d $(DESTDIR)$(MANDIR)/man$${p##*.} && \
		$(INSTALL) -m 0644 $(GENMANDIR)/$$p \
			$(DESTDIR)$(MANDIR)/man$${p##*.}/$$p || exit 1; \
	done
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) -m 0644 $(GENMANDIR)/velarx.conf.5 $(DESTDIR)$(MANDIR)/man5/velarx.conf.5
	$(INSTALL) -d $(DESTDIR)$(BASHCOMPDIR) $(DESTDIR)$(ZSHCOMPDIR) $(DESTDIR)$(FISHCOMPDIR)
	$(INSTALL) -m 0644 $(GENMANDIR)/completion.bash $(DESTDIR)$(BASHCOMPDIR)/velarx
	$(INSTALL) -m 0644 $(GENMANDIR)/completion.zsh $(DESTDIR)$(ZSHCOMPDIR)/_velarx
	$(INSTALL) -m 0644 $(GENMANDIR)/completion.fish $(DESTDIR)$(FISHCOMPDIR)/velarx.fish

# (the completions of the thin client are the same file: the command line is
# the same, and `velarx` and `velarx-client` answer `velarx completion` alike)

list: ## print what install lays out (without DESTDIR)
	@for b in $(BINARIES); do echo $(BINDIR)/$$b; done
	@for u in $(SYSTEM_UNITS); do echo $(SYSTEMDDIR)/system/$$u; done
	@for u in $(USER_UNITS); do echo $(SYSTEMDDIR)/user/$$u; done
	@echo $(TMPFILESDIR)/velarx.conf
	@echo $(DOCDIR)/config.toml.example
	@$(if $(LICENSEDIR),for f in LICENSE NOTICE; do echo $(LICENSEDIR)/$$f; done; \
		for b in $(BINARIES); do echo $(LICENSEDIR)/THIRD-PARTY-LICENSES.$$b; done)
	@for k in $(GENERATORS); do echo $(SYSTEMDDIR)/$$k-generators/velarx-$$k-generator; done
	@for p in `cd $(GENMANDIR) && ls $(MANPAGES) 2>/dev/null`; do \
		echo $(MANDIR)/man$${p##*.}/$$p; \
	done
	@echo $(MANDIR)/man5/velarx.conf.5
	@echo $(BASHCOMPDIR)/velarx
	@echo $(ZSHCOMPDIR)/_velarx
	@echo $(FISHCOMPDIR)/velarx.fish

uninstall: ## remove what install laid out (DESTDIR/PREFIX as for install)
	@for f in `$(MAKE) --no-print-directory list`; do rm -f $(DESTDIR)$$f; done

# ---- tests ----

test: ## fast tier: cargo test (fuzz corpora replayed), unit tests and the integration binary, velarx-api's, and a check of the thin client (TESTARGS=filter)
	$(CARGO) test --features fuzzing $(CARGOFLAGS) $(TESTARGS)
	$(CARGO) test -p velarx-api $(CARGOFLAGS) $(TESTARGS)
	$(CARGO) check -p velarx-bin --no-default-features --bin velarx-client $(CARGOFLAGS)

test-leaks: ## fail when the library tests of a package leave a .tmp* directory in TMPDIR (PKG="velarx-core ..." for some; slow: every package, about 5 min)
	CARGO="$(CARGO)" CARGOFLAGS="$(CARGOFLAGS)" tools/check-test-leaks $(PKG)

test-slow: ## the tests that wait (VELARX_SLOW_TESTS=1) of the whole workspace
	VELARX_SLOW_TESTS=1 $(CARGO) test --workspace $(CARGOFLAGS) $(TESTARGS)

test-lint: reuse issue-refs features-check patches-check deps-check docs-check ## the lint tests of the sources (licenses, issue numbers, features kept by hand, stale statements in the documents, forbidden calls: src/testing.rs)
	$(CARGO) test --lib testing:: $(CARGOFLAGS)

reuse: ## fail when a tracked file has no license information (SPDX line or REUSE.toml)
	tools/check-spdx

issue-refs: ## fail when a tracked file names an issue or pull request by a bare number (#NNN)
	tools/check-issue-refs

features-check: ## fail when a feature probe is kept by hand instead of through monitor::features
	tools/check-features

patches-check: ## fail when the [patch] sections of the fuzz workspaces differ from the root's
	tools/check-patches

deps-check: ## fail when the engine links an HTTP client, TLS, QUIC or libp2p (only the fetchers may)
	tools/check-deps

docs-check: ## fail on stale names and options, broken links and anchors and missing paths in the documents
	tools/check-docs

docs-commands: ## fail when a command or option shown in the documents is not in the --help of the binaries of VELARX_BINDIR
	tools/check-docs --commands $(abspath $(VELARX_BINDIR))

test-fuzz-corpus: ## replay and mutate the fuzz corpora without cargo-fuzz (the p2p targets too)
	$(CARGO) test --features fuzzing --test integration fuzz_corpus:: $(CARGOFLAGS)
	$(CARGO) test -p velarx-p2p --test p2p fuzz_corpus_tests:: $(CARGOFLAGS)

# The tests that need a directory on a file system with fs-verity (ext4,
# btrfs or f2fs, the feature on, blocks of 4096 bytes): they skip their
# fs-verity part when VELARX_VERITY_DIR is not set, so this runs the tests of
# `make test` with it set; without the directory the target fails.
test-verity: ## the fast tier with fs-verity: VELARX_VERITY_DIR=dir make test-verity (TESTARGS=filter)
	@test -d "$(VELARX_VERITY_DIR)" || { echo "make test-verity: VELARX_VERITY_DIR must name a directory on a file system with fs-verity" >&2; exit 2; }
	VELARX_VERITY_DIR=$(abspath $(VELARX_VERITY_DIR)) $(CARGO) test --features fuzzing $(CARGOFLAGS) $(TESTARGS)

test-workspace: ## cargo test --workspace: every package, p2p, api and cri included
	$(CARGO) test --workspace $(CARGOFLAGS) $(TESTARGS)

test-pkg: ## one package: make test-pkg PKG=velarx-core
	@test -n "$(PKG)" || { echo "usage: make test-pkg PKG=<package>" >&2; exit 2; }
	$(CARGO) test -p $(PKG) $(CARGOFLAGS) $(TESTARGS)

test-p2p: ## the p2p service (crates/p2p)
	$(CARGO) test -p velarx-p2p -p velarx-p2p-bin $(CARGOFLAGS) $(TESTARGS)

test-api: ## the REST API frontend (crates/api)
	$(CARGO) test -p velarx-api $(CARGOFLAGS) $(TESTARGS)

# The CRI frontend (crates/cri): the mapping tests with a mock engine; needs
# protoc. tests/e2e/bats/cri.bats runs it with crictl against a daemon.
test-cri: ## the CRI frontend (crates/cri), needs protoc
	$(CARGO) test -p velarx-cri $(CARGOFLAGS) $(TESTARGS)

# Every CRI test in one idempotent command (tests/cri/run-all.sh --help): the build,
# the mapping tests, the bats files, the images of critest, critest and a kubelet,
# all as root where the CRI needs it. The steps alone: critest-root and
# cri-kubelet, which need the debug build of every binary (make build-debug),
# critest, crictl, skopeo and a registry with the test images (tests/cri/critest.sh
# mirror). docs/CRI.md says what they prove.
cri-tests: ## all CRI tests, idempotent: make cri-tests [CRI_ARGS="--only critest --focus regexp --own-registry"]
	tests/cri/run-all.sh $(CRI_ARGS)

critest-root: ## critest as root, in a mount namespace of its own (SUDO=... to change how)
	$(SUDO) env PATH="$$PATH" CRITEST_KNOWN_FAILURES=$(abspath tests/cri/critest-known-failures-root.txt) $(if $(CRITEST_OUT),CRITEST_OUT=$(CRITEST_OUT)) tests/cri/critest.sh run-root $(abspath $(VELARX_BINDIR)) "$(CRITEST_FOCUS)"

cri-kubelet: ## a kubelet (KUBELET=path) runs a static pod on velarx-cri, as root (tests/cri/kubelet.sh)
	$(SUDO) env PATH="$$PATH" $(if $(KUBELET),KUBELET=$(KUBELET)) $(if $(IMAGE),IMAGE=$(IMAGE)) $(if $(REGISTRY_INSECURE),REGISTRY_INSECURE=$(REGISTRY_INSECURE)) $(if $(KUBELET_LOGS),KUBELET_LOGS=$(KUBELET_LOGS)) tests/cri/kubelet.sh $(abspath $(VELARX_BINDIR))

# --workspace adds the tests of the P2P service (crates/p2p); the binaries
# it leaves include velarx-p2p, which lazy-peers.bats needs.
test-all: ## slow tier: slow tests, workspace, thin client, every e2e file (about 7 min)
	VELARX_SLOW_TESTS=1 $(CARGO) test --workspace $(CARGOFLAGS)
	VELARX_BINDIR=$(DEBUGDIR) tests/e2e/run-all.sh lazy-peers
	$(MAKE) build-client PROFILE=debug
	$(CARGO) build --workspace --bins $(CARGOFLAGS)
	$(MAKE) docs-commands
	$(MAKE) e2e-man VELARX_BINDIR=$(DEBUGDIR)
	VELARX_BINDIR=$(DEBUGDIR) tests/e2e/run-all.sh

# ---- coverage ----

# The fast tier under cargo-llvm-cov: the tests of the default
# members and of velarx-api in instrumented builds, an lcov tracefile, HTML
# pages and a per-package summary (the baseline).  Needs cargo-llvm-cov
# (cargo install --locked cargo-llvm-cov) and the LLVM tools of the
# compiler (rustup's llvm-tools-preview, or LLVM_COV/LLVM_PROFDATA for a
# compiler without them).  No gating: the numbers are information.
coverage: ## line coverage of the fast tier (cargo-llvm-cov): lcov, HTML, per-package table
	tools/coverage

# ---- end to end (bats) ----

# They run the binaries of VELARX_BINDIR (default: the debug build, see
# build-debug); make e2e does not build.  The install tests (make
# install-files) need the man pages and completions that make man writes and
# the THIRD-PARTY-LICENSES that make licenses-binary writes, of the binaries
# of VELARX_BINDIR: the man pages are made when missing, the licenses (a
# second) always.
e2e-man:
	@test -e $(GENMANDIR)/velarx.conf.5 || $(MAKE) man PROFILE=debug
	@$(MAKE) --no-print-directory licenses-binary TARGETDIR=$(VELARX_BINDIR)

e2e: e2e-man ## bats suites side by side: make e2e [T="run-lifecycle kube"] [BATS_ARGS=...] [E2E_JOBS=n]
	$(RUNALL)

e2e-root: e2e-man ## e2e as root, which runs the root-only files too (SUDO=... to change how)
	$(SUDO) env VELARX_BINDIR=$(abspath $(VELARX_BINDIR)) $(if $(E2E_JOBS),E2E_JOBS=$(E2E_JOBS)) $(if $(E2E_TIMEOUT),E2E_TIMEOUT=$(E2E_TIMEOUT)) $(if $(E2E_LOGDIR),E2E_LOGDIR=$(E2E_LOGDIR)) $(RUNALL)

p2p-rig: ## real-process swarm in network namespaces, as root: make p2p-rig [SCENARIO=rollout|holder-loss|certificates|netem|overlay|repull|mute-member|inline] [RIG_ARGS="-n 20"] (tests/p2p-rig)
	$(SUDO) env VELARX_BINDIR=$(abspath $(VELARX_BINDIR)) tests/p2p-rig/$(or $(SCENARIO),rollout).sh $(RIG_ARGS)

e2e-list: ## the names usable as T=
	@cd tests/e2e/bats && find . -name '*.bats' | sed 's|^\./||; s|\.bats$$||' | sort

# ---- fuzz ----

# cargo-fuzz needs a nightly compiler (RUSTC_BOOTSTRAP=1 with a stable one)
# and a C++ compiler; -s none builds without the address sanitizer.
fuzz-list: ## the fuzz targets (fuzz/fuzz_targets and the other packages')
	@for t in $(FUZZ_TARGETS); do echo $$t; done

fuzz: ## one fuzz target: make fuzz FUZZ=tar [FUZZ_TIME=60]; needs cargo-fuzz
	@test -n "$(FUZZ)" || { echo "usage: make fuzz FUZZ=<target> (make fuzz-list)" >&2; exit 2; }
	@test -n "$(FUZZ_DIR)" || { echo "no fuzz target $(FUZZ) (make fuzz-list)" >&2; exit 2; }
	cd $(FUZZ_DIR) && RUSTC_BOOTSTRAP=1 $(CARGO) fuzz run -s none $(FUZZ) -- -max_total_time=$(FUZZ_TIME)

fuzz-dir: # the directory of the fuzz package of FUZZ
	@echo $(FUZZ_DIR)

fuzz-all: ## every fuzz target for FUZZ_TIME seconds each
	for t in $(FUZZ_TARGETS); do \
		$(MAKE) --no-print-directory fuzz FUZZ=$$t || exit 1; \
	done

# ---- checks and CI ----

# The commits of BASE..HEAD carry a Signed-off-by line (the DCO,
# CONTRIBUTING.md): make check-dco BASE=origin/main
check-dco: ## every commit of BASE..HEAD is signed off: make check-dco BASE=origin/main
	@test -n "$(BASE)" || { echo "usage: make check-dco BASE=<revision>" >&2; exit 2; }
	tests/check-dco.sh $(BASE) $(or $(HEAD),HEAD)

# The dependencies against deny.toml (needs cargo-deny): the RustSec
# advisories, the bans, the sources and the licenses.
audit: ## advisories, bans, sources and licenses of the dependencies (needs cargo-deny)
	$(CARGO) deny --workspace check

licenses: ## only the licenses of the dependencies against deny.toml (needs cargo-deny)
	$(CARGO) deny --workspace check licenses

ci: fmt-check issue-refs features-check patches-check deps-check docs-check clippy ## the checks of a change before a merge: fmt-check, issue-refs, features-check, docs-check, clippy, debug build, docs-commands, make test, thin client
	$(MAKE) build-default PROFILE=debug
	$(MAKE) docs-commands
	$(MAKE) test
	$(MAKE) build-client PROFILE=debug

# ---- size ----

# The stripped size, the shared libraries and the hyperfine -N startup time
# of every release binary.
bench-startup: ## release build of velarx, velarx-monitor and velarx-client, then their size and hyperfine --version startup
	$(MAKE) build-engine build-kube build-client PROFILE=release
	tools/bench-startup $(TARGETBASE)/release

# Velarx against podman on the same operations, measured by hyperfine, both
# rootless in private stores with crun and a private registry (see the header
# of tools/perf-compare).  Writes json, summary.md and graphs to the --out dir.
perf-compare: ## release build, then velarx vs podman timed by hyperfine: make perf-compare PERF_ARGS="--out DIR [--runs N] [--only REGEXP]"
	$(MAKE) build-engine PROFILE=release
	tools/perf-compare --velarx $(TARGETBASE)/release/velarx $(PERF_ARGS)

test-perf-compare: ## the unit tests of the summary and graphs of tools/perf-compare (no engine needed)
	python3 -I tests/perf/test_perf_compare.py

# ---- release ----

licenses-binary: ## THIRD-PARTY-LICENSES.<binary> in LICENSESOUT for each of BINARIES: the crates it links with their license texts (tools/licenses-binary)
	CARGO="$(CARGO)" CARGOFLAGS="$(CARGOFLAGS)" tools/licenses-binary "$(LICENSESOUT)" $(BINARIES)

dist: ## source tarball and SHA256SUMS of HEAD in DISTDIR (dist/); builds velarx-monitor from it and checks --version (DIST_CHECK=0 skips); DISTDIR/licenses gets THIRD-PARTY-LICENSES.<binary> (DIST_LICENSES=0 skips)
	CARGO="$(CARGO)" tools/dist "$(DISTDIR)"

# ---- clean ----

clean: ## cargo clean (CARGO_TARGET_DIR if set, else target/) and fuzz/target
	$(CARGO) clean
	rm -rf $(addsuffix /target,$(FUZZ_DIRS))
