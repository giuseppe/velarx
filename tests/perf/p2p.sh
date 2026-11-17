#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# p2p.sh BIN [PROFILE...]: run the P2P benchmarks of crates/p2p/tests/p2p/p2p_sources_tests.rs
# (bench_transport, bench_peer_transfer) under emulated networks.
#
# BIN is the test executable, built optimised:
#   cargo test --release -p velarx-p2p --test p2p --no-run
# Each profile runs in a network namespace of its own (unshare -rn, no root
# needed), with tc netem on its loopback (MTU 1500, so that TCP and QUIC lose
# packets of the same size).  Profiles: name=DELAY_MS/LOSS_PERCENT, the delay
# one way (the round trip is twice it), e.g. lan=0/0 rtt20=10/0
# rtt20loss=10/0.5 rtt100loss=50/0.5.
# RATE (e.g. 100mbit) caps what each serving node sends (they listen on
# 127.0.0.2, 127.0.0.3...), to see what several peers give.
# The knobs of the benchmarks: BENCH_SERVERS, BENCH_SMALL, BENCH_BIG_MB, BENCH_BATCH, BENCH_BIG_BATCH,
# BENCH_QUIC_STREAMS;
# BENCH (the benchmarks to run, default "p2p_sources_tests::bench_").
set -eu
bin=${1:?test executable}
shift
[ $# -gt 0 ] || set -- lan=0/0 rtt20=10/0 rtt20loss=10/0.5 rtt100loss=50/0.5
servers=${BENCH_SERVERS:-1}
for profile in "$@"; do
    name=${profile%%=*}
    spec=${profile#*=}
    delay=${spec%%/*}
    loss=${spec#*/}
    echo "== $name: one way delay ${delay} ms, loss ${loss}%, rate ${RATE:-none}, servers $servers"
    unshare -rn sh -eu -c '
        ip link set lo up
        ip link set lo mtu 1500
        netem="netem delay ${2}ms loss ${3}% limit 100000"
        if [ -n "${RATE:-}" ]; then
            tc qdisc add dev lo root handle 1: htb default 99
            tc class add dev lo parent 1: classid 1:99 htb rate 100gbit
            tc qdisc add dev lo parent 1:99 handle 99: $netem
            i=0
            while [ $i -lt "$4" ]; do
                c=$((i + 2))
                tc class add dev lo parent 1: classid 1:$c htb rate "$RATE"
                tc qdisc add dev lo parent 1:$c handle $c: $netem
                tc filter add dev lo parent 1: protocol ip u32 match ip src 127.0.0.$c/32 flowid 1:$c
                i=$((i + 1))
            done
        elif [ "$2" != 0 ] || [ "$3" != 0 ]; then
            tc qdisc add dev lo root $netem
        fi
        exec "$1" --ignored --nocapture --test-threads 1 "${BENCH:-p2p_sources_tests::bench_}" 2>&1
    ' sh "$bin" "$delay" "$loss" "$servers" | grep -o "bench .*" | sed "s/^bench /$name /"
done
