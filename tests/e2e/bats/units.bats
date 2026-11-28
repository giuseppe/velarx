# SPDX-License-Identifier: Apache-2.0
# The units, tmpfiles.d file and binaries `make install` ships: the
# layout of an install in a scratch DESTDIR is what `make list` says,
# `systemd-analyze verify` accepts every unit of the system and of the user
# manager, and the socket of the installed units starts the engine.
#
#   VELARX_BINDIR=target/debug bats tests/e2e/bats/units.bats
#                          # user units (rootless), or as root the system units
#
# The activation test links copies of velarx-engine.socket/.service, renamed
# shi-<pid>.*, with the paths of $WORKDIR (socket, store, binaries) into the
# runtime unit directory; they are stopped and unlinked at the end.
#
# This file talks to the user's systemd manager and reloads it (daemon-reload):
# unit.bats times its units' start (TimeoutStartSec) and a daemon-reload of the
# manager in the middle cuts the extension, so the files that reload it
# (this one, quadlet.bats, engine.bats and engine-api.bats) have to end before
# unit.bats starts; do not run them alongside it.

load helpers
source "$BATS_TEST_DIRNAME/../cleanup.sh"

vars () {
    top_srcdir=$(cd "$E2E_DIR/../.." && pwd)
    P=$WORKDIR/pfx
    SOCK=$WORKDIR/run/velarx/velarx.sock
    CONF=$WORKDIR/config.toml
    if [ "$(id -u)" = 0 ]; then
        MODE=system
        SCTL=(systemctl)
    else
        MODE=user
        SCTL=(env XDG_RUNTIME_DIR="$REAL_RUNTIME_DIR" systemctl --user)
    fi
    # (what `make licenses-binary` and `make man` generate, none of it in
    # git: the license files of the binaries and the page of section 1 are
    # stand-ins, the hand-written pages and the completions are the real
    # ones; installed as they would be)
    local b s
    if [ ! -d "$WORKDIR/licenses" ]; then
        mkdir -p "$WORKDIR/licenses" "$WORKDIR/man"
        # (the binaries are the ones `make list` installs: one list, the Makefile's)
        for b in $(make -s -C "$top_srcdir" TARGETDIR="$BIN" BINDIR=/bindir list | sed -n 's|^/bindir/||p'); do
            echo "$b" > "$WORKDIR/licenses/THIRD-PARTY-LICENSES.$b"
        done
        printf '.TH VELARX 1\n.SH NAME\nvelarx\n' > "$WORKDIR/man/velarx.1"
        printf '.TH VELARX-P2P 8\n.SH NAME\nvelarx-p2p\n' > "$WORKDIR/man/velarx-p2p.8"
        cp "$top_srcdir"/man/* "$WORKDIR/man/"
        for s in bash zsh fish; do
            "$BIN/velarx" completion "$s" > "$WORKDIR/man/completion.$s"
        done
    fi
    MAKE=(make -s -C "$top_srcdir" TARGETDIR="$BIN" LICENSESOUT="$WORKDIR/licenses" GENMANDIR="$WORKDIR/man")
}

# the prefix install of the verify and activation tests
install_prefix () {
    [ -e "$P/lib/systemd/system/velarx-engine.socket" ] || "${MAKE[@]}" install-files PREFIX="$P"
}

setup () { set +e; [ -z "${WORKDIR:-}" ] || vars; }

setup_file () {
    export E2E_DIR; E2E_DIR=$(cd "$BATS_TEST_DIRNAME/.." && pwd)
    export BIN; BIN=$(realpath "${BIN:-${VELARX_BINDIR:-target/debug}}")
    export WORKDIR; WORKDIR=$(realpath "$(mktemp -d "${E2E_TMPDIR:-/var/tmp}/velarx-units.XXXXXX")")
    export REAL_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
    export U=shi-$$
}

teardown_file () {
    set +e
    [ -n "${WORKDIR:-}" ] || return 0
    vars
    if [ -e "$WORKDIR/units/$U.socket" ]; then
        "${SCTL[@]}" stop "$U.socket" "$U.service" 2> /dev/null
        "${SCTL[@]}" disable --runtime "$U.socket" "$U.service" > /dev/null 2>&1
        "${SCTL[@]}" reset-failed "$U.socket" "$U.service" 2> /dev/null
        "${SCTL[@]}" daemon-reload
    fi
    [ -n "${E2E_KEEP:-}" ] || e2e_remove_workdir "$WORKDIR"
    e2e_teardown_file
}

@test "make install into a DESTDIR installs what make list says" {
    # The layout of a package: DESTDIR and PREFIX=/usr.
    "${MAKE[@]}" install-files DESTDIR="$WORKDIR/dest" PREFIX=/usr
    check "install into a DESTDIR" 0 $?
    listed=$("${MAKE[@]}" list PREFIX=/usr | sort)
    installed=$(cd "$WORKDIR/dest" && find . \( -type f -o -type l \) | sed 's|^\.||' | sort)
    check "the files installed are those listed" "$listed" "$installed"
    for f in /usr/lib/systemd/system/velarx-engine.socket /usr/lib/systemd/user/velarx-engine.socket \
        /usr/lib/systemd/user/velarx-engine.service /usr/lib/systemd/user/velarx-api.socket \
        /usr/lib/systemd/user/velarx-restart.service \
        /usr/lib/systemd/user/velarx-user-wait-network-online.service /usr/lib/tmpfiles.d/velarx.conf; do
        check "installed $f" yes "$([ -f "$WORKDIR/dest$f" ] && echo yes)"
    done
    check "the units start the binaries of BINDIR" "/usr/bin/velarx varlink" \
        "$(sed -n 's/^ExecStart=//p' "$WORKDIR/dest/usr/lib/systemd/user/velarx-engine.service")"
    check "velarx-client is installed" yes "$([ -x "$WORKDIR/dest/usr/bin/velarx-client" ] && echo yes)"
    check "units are not executable" "-rw-r--r--" \
        "$(stat -c %A "$WORKDIR/dest/usr/lib/systemd/user/velarx-engine.socket")"
}

@test "systemd-analyze verifies every unit and the tmpfiles.d file" {
    # The units verify, with their ExecStart in a prefix where they exist and
    # the pages they name (Documentation=) in its man path.
    "${MAKE[@]}" install-files PREFIX="$P"
    check "install into a PREFIX" 0 $?
    for unit in "$P"/lib/systemd/system/*; do
        out=$(MANPATH="$P/share/man" systemd-analyze verify "$unit" 2>&1)
        check "system: verify $(basename "$unit")" "" "$out"
    done
    for unit in "$P"/lib/systemd/user/*; do
        out=$(MANPATH="$P/share/man" systemd-analyze --user verify "$unit" 2>&1)
        check "user: verify $(basename "$unit")" "" "$out"
    done
    out=$(systemd-tmpfiles --dry-run --create "$P/lib/tmpfiles.d/velarx.conf" 2>&1 | grep -iv "would\|skip" )
    check "tmpfiles: the file parses" "" "$out"
}

@test "a client of the socket of the installed units starts the daemon" {
    # Socket activation of the installed units of this manager.
    [ "$MODE" = system ] || skip_unless_systemd_user
    install_prefix || exit 1
    if [ "$MODE" = system ] && command -v selinuxenabled > /dev/null && selinuxenabled; then
        # System services may only run binaries labelled as such.
        chcon -t bin_t "$P"/bin/* || exit 1
    fi
    mkdir -p "$WORKDIR/home" "$WORKDIR/run" "$WORKDIR/units"
    chmod 700 "$WORKDIR/run"
    if [ "$MODE" = user ]; then
        # The daemon has the scratch runtime directory; it reaches the user
        # manager through it.
        ln -sfn "$REAL_RUNTIME_DIR/systemd" "$WORKDIR/run/systemd"
    fi
    cat > "$CONF" <<TOML
$(e2e_bridge_toml)
[engine]
socket = "$SOCK"
idle_exit = 2
[server]
socket = "$SOCK"
state_dir = "$WORKDIR/state"
root_dir = "$WORKDIR/data/root"
[storage]
root = "$WORKDIR/data/storage"
TOML
    sed -e "s|^ListenStream=.*|ListenStream=$SOCK|" \
        "$P/lib/systemd/$MODE/velarx-engine.socket" > "$WORKDIR/units/$U.socket"
    # (not the host's /run/velarx and /var/lib/velarx: systemd would make
    # them, and remove the first when the unit stops)
    # (the engine of the installed unit leaves after [engine] idle_exit: the copy waits 2 seconds)
    sed -e "s|^ExecStart=\(.*\) varlink$|ExecStart=\1 --config $CONF varlink|" \
        -e "s|^Requires=velarx-engine.socket|Requires=$U.socket|" -e "s|^After=\(.*\)velarx-engine.socket|After=\1$U.socket|" \
        -e "/^\[Service\]/a Environment=HOME=$WORKDIR/home XDG_RUNTIME_DIR=$WORKDIR/run" \
        -e '/^RuntimeDirectory=/d' -e '/^StateDirectory=/d' \
        "$P/lib/systemd/$MODE/velarx-engine.service" > "$WORKDIR/units/$U.service"
    "${SCTL[@]}" link --runtime "$WORKDIR/units/$U.socket" "$WORKDIR/units/$U.service" > /dev/null 2>&1
    "${SCTL[@]}" start "$U.socket"
    check "the socket listens" active "$("${SCTL[@]}" show -P ActiveState "$U.socket")"
    check "the daemon waits for a client" inactive "$("${SCTL[@]}" show -P ActiveState "$U.service")"
    # (a client that names the socket: the command line alone runs its own engine)
    out=$(timeout 60 "$P/bin/velarx" --config "$CONF" --socket "$SOCK" container list 2>&1)
    check "a client starts the daemon" 0 $?
    check "the daemon runs" active "$("${SCTL[@]}" show -P ActiveState "$U.service")"
    # (the YAML of `info`: `host.systemd`, the state of this user's manager)
    info=$(timeout 30 "$P/bin/velarx" --config "$CONF" --socket "$SOCK" info 2> "$WORKDIR/info.err")
    if [ "$MODE" = user ]; then
        linger=no
        [ -e "/var/lib/systemd/linger/$(id -un)" ] && linger=yes
        check "info: the user manager answers" yes \
            "$(printf '%s' "$info" | grep -q 'userManager: true' && echo yes)"
        check "info: lingering" "$linger" \
            "$(printf '%s' "$info" | grep -q 'linger: true' && echo yes || echo no)"
        if [ "$linger" = no ]; then
            # (in the document only: lingering off is the default, nothing
            # is printed on stderr for it)
            check "info: says that the units do not start at boot" yes \
                "$(printf '%s' "$info" | grep -q 'warning: .*enable-linger' && echo yes)"
            check "info: no warning on stderr for lingering" "" "$(cat "$WORKDIR/info.err")"
        fi
    else
        check "info: no user manager for root" yes \
            "$(printf '%s' "$info" | grep -q 'systemd: null' && echo yes)"
    fi
}

@test "the idle daemon exits and the next client starts it again" {
    [ "$MODE" = system ] || skip_unless_systemd_user
    [ -e "$WORKDIR/units/$U.socket" ] || { echo "needs the units of the test 'a client of the socket of the installed units starts the daemon'" >&2; exit 1; }
    # [engine] idle_exit: idle, the engine exits (the copy waits 2 seconds, not 30):
    # its process ends by itself (a pidfd), then the manager says the unit is
    # inactive
    local mainpid
    mainpid=$("${SCTL[@]}" show -P MainPID "$U.service")
    [ "${mainpid:-0}" -le 0 ] || e2e_wait_exit "$mainpid" 30
    e2e_wait_unit_state "$U.service" inactive 20
    check "the idle daemon exits" inactive "$("${SCTL[@]}" show -P ActiveState "$U.service")"
    check "cleanly" success "$("${SCTL[@]}" show -P Result "$U.service")"
    check "the socket stays when the daemon exits" active "$("${SCTL[@]}" show -P ActiveState "$U.socket")"
    timeout 60 "$P/bin/velarx" --config "$CONF" --socket "$SOCK" container list > /dev/null 2>&1
    check "the next client starts it again" active "$("${SCTL[@]}" show -P ActiveState "$U.service")"
    "${SCTL[@]}" stop "$U.service" 2> /dev/null
}
