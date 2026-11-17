#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
# The velarx configuration CONFIG with the settings of the podman
# containers.conf files that podman's apiv2 suite starts its service with
# (velarx reads only its own files: tests/e2e/bats/podman-apiv2.bats starts
# velarx-api on the configuration this prints).
#
#   containers-conf-to-velarx.py CONFIG CONTAINERS.CONF...
#
# The files are read in order, a later one overriding an earlier.  A setting
# that is not listed here is an error: a new one in the suite shows up as a
# failure of the run, not as a test that quietly passes.  CONFIG must end in
# its [api] table and have no [containers] and [network] tables (checked).
import sys
import tomllib


def quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main(base, paths):
    conf = {}
    for path in paths:
        with open(path, "rb") as f:
            for table, values in tomllib.load(f).items():
                conf.setdefault(table, {}).update(values)

    api, containers, pools = [], [], []
    for table, values in conf.items():
        for key, value in values.items():
            if (table, key) == ("engine", "compat_api_enforce_docker_hub"):
                api.append("compat_api_enforce_docker_hub = " + str(bool(value)).lower())
            elif table == "containers" and key in ("no_hosts",):
                containers.append(f"{key} = " + str(bool(value)).lower())
            elif table == "containers" and key in ("netns", "base_hosts_file"):
                containers.append(f"{key} = {quote(value)}")
            elif (table, key) == ("network", "default_subnet_pools"):
                for pool in value:
                    pools.append(
                        "[[network.subnet_pools]]\n"
                        f"base = {quote(pool['base'])}\nsize = {int(pool['size'])}"
                    )
            else:
                sys.exit(f"containers.conf [{table}] {key}: not translated to velarx")

    with open(base, encoding="utf-8") as f:
        text = f.read()
    out = [text.rstrip("\n")] + api
    if containers:
        out += ["[containers]"] + containers
    out += pools
    text = "\n".join(out) + "\n"
    # (each setting is where it was meant to be: a CONFIG that does not end
    # in [api], or that has the tables already, is refused)
    try:
        merged = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        sys.exit(f"{base}: the settings cannot be added: {e}")
    for line in api:
        key = line.split(" = ")[0]
        if key not in merged.get("api", {}):
            sys.exit(f"{base}: does not end in its [api] table")
    if len(merged.get("network", {}).get("subnet_pools", [])) != len(pools):
        sys.exit(f"{base}: has subnet pools already")
    sys.stdout.write(text)


main(sys.argv[1], sys.argv[2:])
