# SPDX-License-Identifier: Apache-2.0
# The Fedora/COPR spec of velarx.  It builds from the release tarball that
# `make dist` makes (git archive of the tag, plus Cargo.lock
# and a .git-commit file that gives `--version` the tag without a git
# repository) and installs exactly what `make install-files PREFIX=/usr`
# lays out: the binaries, the systemd units of the system and of the users'
# managers, the Quadlet generators, the tmpfiles.d file and
# config.toml.example (the Makefile is the one entry point of the build:
# it knows the per-binary cargo flags, e.g. the thin client is built with
# -p velarx-bin --no-default-features).
#
# The tarball carries no crates.io dependencies: they come vendored in a
# second source (Source1, below), which %%prep makes the crates-io source
# of cargo, so the build runs without a network, as Fedora and COPR
# builders do.
# velarx-p2p (libp2p, QUIC) and velarx-cri (gRPC, protoc) are not packaged:
# add `make build-p2p`/`make build-cri` and the units and files of the
# Makefile's list.

%global debug_package %{nil}

ExclusiveArch:  %{rust_arches}

Name:           velarx
Version:        0.1.0
Release:        1%{?dist}
Summary:        A container engine for Linux that runs OCI images

# The effective license of the package: Apache-2.0 for the project, and the
# licenses of the crates of THIRD-PARTY-LICENSES (a permissive option picked
# for each: MIT, BSD-3-Clause, Zlib, ...).
License:        Apache-2.0 AND BSD-3-Clause AND BSL-1.0 AND MIT AND Unicode-3.0 AND Zlib
URL:            https://github.com/giuseppe/velarx
# The tarball of the release, made with `make dist` on the signed tag and
# attached to it with its SHA256SUMS; the download location is not decided
# yet, so the file name only.
Source0:        %{name}-%{version}.tar.gz
# The crates.io crates of Cargo.lock, made from the tarball above with:
#   tar -xzf velarx-VERSION.tar.gz && cd velarx-VERSION &&
#   cargo vendor --locked --versioned-dirs cargo-vendor > /dev/null &&
#   tar -cJf ../velarx-VERSION-vendor.tar.xz cargo-vendor
# (cargo-vendor/, not vendor/: vendor/ holds the patched crates of the
# [patch.crates-io] of the tree, zlink-core, zlink-macros, zlink-idl and tar.)
Source1:        %{name}-%{version}-vendor.tar.xz

# The workspace needs rust 1.99 (rust-version of Cargo.toml).
BuildRequires:  rust >= 1.99
BuildRequires:  cargo >= 1.99
BuildRequires:  gcc
BuildRequires:  make
# tools/licenses-binary
BuildRequires:  python3
BuildRequires:  pkgconf-pkg-config
BuildRequires:  pkgconfig(libzstd)
# pkgconfig(sqlite3): rusqlite bundles it only without pkg-config; the
# workspace links the system libraries (zstd via the pkg-config feature).
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(openssl)
# The units, the generators and the tmpfiles.d file: the systemd macros
# and the directory macros (%%{_unitdir} and friends).
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}

# What a running velarx wants on the host (README.md, Requirements).
Recommends:     crun
Recommends:     passt
Recommends:     podman
# ADD of an xz or bzip2 archive runs them
Recommends:     xz
Recommends:     bzip2

%description
Velarx is a container engine for Linux written in Rust.  It runs OCI
containers with an OCI runtime such as crun, as root or rootless, with or
without a long-running daemon.  This package carries the velarx engine and
command line, the velarx-client thin client, the velarx-monitor process
that owns one container and the velarx-api REST API frontend,
with the systemd units of the engine services, the Quadlet generators and
the tmpfiles.d file.

%prep
%autosetup -n %{name}-%{version} -a 1
# the vendored crates replace crates.io (a relative directory of a cargo
# configuration is one of the directory that holds .cargo/)
cat >> .cargo/config.toml << 'EOF'

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "cargo-vendor"
EOF

%build
# Offline, exactly the versions of the lock file, with the release profile
# of the workspace (fat LTO, opt-level z, stripped: no debuginfo package is
# made).  rpm's %%build exports RUSTFLAGS (%%build_rustflags: -Cdebuginfo=2,
# -Copt-level=3, -Cstrip=none), which would override that profile, and full
# debug info under fat LTO takes more than 10 GB of memory to link velarx:
# unset.  KACHE=0: tools/rustc-wrapper (.cargo/config.toml) never uses a
# build cache that the builder happens to have.
unset RUSTFLAGS
export KACHE=0
make build-engine build-kube build-client build-api CARGOFLAGS="--locked --offline"
# the licenses of the crates that the binaries link (cargo metadata, offline)
make licenses-binary BINARIES="velarx velarx-registry velarx-dir velarx-kube velarx-client velarx-monitor velarx-api" \
	CARGOFLAGS="--locked --offline"

%install
# LICENSEDIR empty: %%license below installs the license files
make install-files DESTDIR=%{buildroot} PREFIX=%{_prefix} LICENSEDIR=

%check
target/release/velarx --version
target/release/velarx-client --version
target/release/velarx-monitor --version
target/release/velarx-registry --version
target/release/velarx-dir --version
target/release/velarx-kube --version
target/release/velarx-api --version

# The units are not enabled by the package (no preset file): whoever wants
# the engine as a service enables velarx-engine.socket.  The user units are
# picked up by the users' managers at their next start (the user scriptlets
# only apply the global presets, of which there are none), and the engine is
# never restarted on an upgrade: it may run containers.  The man pages and
# completions of `make man` are not packaged yet; this list gains them
# when they are.
%files
%license LICENSE NOTICE THIRD-PARTY-LICENSES
%doc README.md
%{_bindir}/velarx
%{_bindir}/velarx-client
%{_bindir}/velarx-monitor
%{_bindir}/velarx-registry
%{_bindir}/velarx-dir
%{_bindir}/velarx-kube
%{_bindir}/velarx-api
%{_unitdir}/velarx-api.service
%{_unitdir}/velarx-api.socket
%{_unitdir}/velarx-auto-update.service
%{_unitdir}/velarx-auto-update.timer
%{_unitdir}/velarx-engine.service
%{_unitdir}/velarx-engine.socket
%{_unitdir}/velarx-pulls.service
%{_unitdir}/velarx-restart.service
%{_unitdir}/velarx-store.service
%{_unitdir}/velarx-store.socket
%{_userunitdir}/velarx-api.service
%{_userunitdir}/velarx-api.socket
%{_userunitdir}/velarx-auto-update.service
%{_userunitdir}/velarx-auto-update.timer
%{_userunitdir}/velarx-engine.service
%{_userunitdir}/velarx-engine.socket
%{_userunitdir}/velarx-pulls.service
%{_userunitdir}/velarx-restart.service
%{_userunitdir}/velarx-store.service
%{_userunitdir}/velarx-store.socket
%{_userunitdir}/velarx-user-wait-network-online.service
%{_tmpfilesdir}/velarx.conf
# made at boot by the tmpfiles.d file (and by %%post): owned, not shipped
%ghost %dir %attr(0700,root,root) %{_rundir}/velarx
%{_systemdgeneratordir}/velarx-system-generator
%{_systemdusergeneratordir}/velarx-user-generator
# rpm 4.20 (Fedora 42 and later) leaves %%{_docdir} unversioned, which is the
# share/doc/velarx of the Makefile's install; config.toml.example is a
# template, not a file the program reads.
%{_docdir}/%{name}/config.toml.example

%post
%systemd_post velarx-api.service velarx-api.socket velarx-auto-update.service velarx-auto-update.timer velarx-engine.service velarx-engine.socket velarx-pulls.service velarx-restart.service velarx-store.service velarx-store.socket
%systemd_user_post velarx-api.service velarx-api.socket velarx-auto-update.service velarx-auto-update.timer velarx-engine.service velarx-engine.socket velarx-pulls.service velarx-restart.service velarx-store.service velarx-store.socket velarx-user-wait-network-online.service
%tmpfiles_create velarx.conf

%preun
%systemd_preun velarx-api.service velarx-api.socket velarx-auto-update.service velarx-auto-update.timer velarx-engine.service velarx-engine.socket velarx-pulls.service velarx-restart.service velarx-store.service velarx-store.socket
%systemd_user_preun velarx-api.service velarx-api.socket velarx-auto-update.service velarx-auto-update.timer velarx-engine.service velarx-engine.socket velarx-pulls.service velarx-restart.service velarx-store.service velarx-store.socket velarx-user-wait-network-online.service

%changelog
* Tue Nov 03 2026 Giuseppe Scrivano <giuseppe@scrivano.org> - 0.1.0-1
- First spec: builds the release tarball of make dist
