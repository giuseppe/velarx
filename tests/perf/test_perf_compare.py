#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""Unit tests of the summary of tools/perf-compare: the reading of the
hyperfine JSON, the ratio, the table, the list of slower operations and
the graphs.  No engine, no hyperfine.

    python3 -I tests/perf/test_perf_compare.py
"""

import importlib.machinery
import importlib.util
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import unittest
from unittest import mock

# (no tools/__pycache__ in the source tree)
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "..", "..", "tools", "perf-compare")


def load():
    loader = importlib.machinery.SourceFileLoader("perf_compare", PATH)
    spec = importlib.util.spec_from_loader("perf_compare", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


pc = load()


def hyperfine_json(times):
    n = len(times)
    mean = sum(times) / n
    sd = (sum((t - mean) ** 2 for t in times) / (n - 1)) ** 0.5 if n > 1 else None
    return {"results": [{"command": "x", "mean": mean, "stddev": sd,
                         "median": sorted(times)[n // 2], "min": min(times),
                         "max": max(times), "times": times}]}


def write(outdir, bench, engine, times):
    os.makedirs(os.path.join(outdir, "json"), exist_ok=True)
    with open(os.path.join(outdir, "json", "%s.%s.json" % (bench, engine)), "w") as f:
        json.dump(hyperfine_json(times), f)


class Summary(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="perfcmp-test-")
        write(self.dir, "run-small", "velarx", [0.1, 0.1, 0.1])
        write(self.dir, "run-small", "podman", [0.2, 0.2, 0.2])
        write(self.dir, "ps", "velarx", [0.06, 0.06])
        write(self.dir, "ps", "podman", [0.03, 0.03])
        write(self.dir, "images", "velarx", [0.05])
        write(self.dir, "exec", "podman", [0.1, 0.1])
        # not a result: ignored
        with open(os.path.join(self.dir, "json", "notes.txt"), "w") as f:
            f.write("x")
        self.res = pc.load_results(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_load(self):
        self.assertEqual(sorted(self.res), ["exec", "images", "ps", "run-small"])
        self.assertAlmostEqual(self.res["run-small"]["velarx"]["mean"], 0.1)
        self.assertEqual(self.res["ps"]["podman"]["runs"], 2)
        self.assertEqual(self.res["images"]["velarx"]["stddev"], 0.0)

    def test_ratio(self):
        self.assertAlmostEqual(pc.ratio(self.res, "run-small"), 0.5)
        self.assertAlmostEqual(pc.ratio(self.res, "ps"), 2.0)
        self.assertIsNone(pc.ratio(self.res, "images"))
        self.assertIsNone(pc.ratio(self.res, "exec"))
        self.assertIsNone(pc.ratio(self.res, "nothing"))

    def test_slower(self):
        self.assertEqual(pc.slower(self.res), ["ps"])

    def test_table(self):
        t = pc.table(self.res).splitlines()
        self.assertEqual(t[0], "| operation | velarx | podman | velarx/podman |")
        rows = {l.split("|")[1].strip(): l for l in t[2:]}
        self.assertIn("0.50 (faster)", rows["run-small"])
        self.assertIn("100.0 ms ± 0.0 ms (n=3)", rows["run-small"])
        self.assertIn("2.00 (slower)", rows["ps"])
        self.assertIn("n/a", rows["images"])
        # the order of BENCHMARKS first
        names = [l.split("|")[1].strip() for l in t[2:]]
        self.assertEqual(names, ["run-small", "ps", "images", "exec"])

    def test_fmt_time(self):
        self.assertEqual(pc.fmt_time(1.5), "1.500 s")
        self.assertEqual(pc.fmt_time(0.0123), "12.3 ms")

    def test_graphs(self):
        paths = pc.write_graphs(self.res, self.dir)
        names = {os.path.basename(p) for p in paths}
        self.assertLessEqual({"times.svg", "ratio.svg"}, names)
        with open(os.path.join(self.dir, "ratio.svg")) as f:
            svg = f.read()
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn("run-small", svg)
        self.assertNotIn(">images<", svg)  # no ratio, no bar in the ratio chart

    def test_benchmarks_are_wellformed(self):
        names = [b["name"] for b in pc.BENCHMARKS]
        self.assertEqual(len(names), len(set(names)))
        for b in pc.BENCHMARKS:
            for c in b["setup"] + [b["command"]] + ([b["prepare"]] if "prepare" in b else []) \
                    + b.get("cleanup", []):
                c.format(e="E", small="S", big="B", ctx="C")


class Private(unittest.TestCase):
    """podman runs only with the private store and home of the scratch
    directory, and the script aborts when podman reports other ones."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="perfcmp-test-")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def fake_podman(self, graph, run):
        p = os.path.join(self.dir, "fake-podman")
        with open(p, "w") as f:
            f.write("#!/bin/sh\nprintf '%%s\\n%%s\\noverlay\\n' %s %s\n"
                    % (shlex.quote(graph), shlex.quote(run)))
        os.chmod(p, 0o755)
        return p

    def test_argv_and_env(self):
        # (the user's own variables are set: none reaches the engine)
        with mock.patch.dict(os.environ, {k: "/nowhere" for k in pc.OTHER_CONFIG_VARS}):
            e = pc.Engine("podman", "podman", self.dir, "crun")
        for opt in ("--root", "--runroot", "--tmpdir"):
            i = e.argv.index(opt)
            self.assertTrue(e.argv[i + 1].startswith(self.dir + "/"), opt)
        for k in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
                  "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "TMPDIR"):
            self.assertTrue(e.env[k].startswith(self.dir + "/"), k)
        for k in pc.OTHER_CONFIG_VARS:
            self.assertNotIn(k, e.env)
        self.assertTrue(e.prefix.startswith("podman --root "))

    def test_run_roots_are_in_the_run_base(self):
        # what is of one boot is on the tmpfs of the run base, for both
        # engines, as their defaults have it; the stores stay in the scratch
        run = tempfile.mkdtemp(prefix="perfcmp-run-")
        self.addCleanup(shutil.rmtree, run)
        for name in ("velarx", "podman"):
            e = pc.Engine(name, name, self.dir, "crun", run)
            for opt in ("--runroot", "--tmpdir"):
                self.assertTrue(e.argv[e.argv.index(opt) + 1].startswith(run + "/"), opt)
            self.assertTrue(e.env["XDG_RUNTIME_DIR"].startswith(run + "/"))
            self.assertTrue(e.argv[e.argv.index("--root") + 1].startswith(self.dir + "/"))
            self.assertTrue(e.env["TMPDIR"].startswith(self.dir + "/"))

    def test_verify_private(self):
        e = pc.Engine("podman", "podman", self.dir, "crun")
        e.argv[0] = self.fake_podman(e.root, e.runroot)
        e.verify_private()
        e.argv[0] = self.fake_podman(os.path.expanduser("~/.local/share/containers/storage"),
                                     e.runroot)
        with self.assertRaises(SystemExit):
            e.verify_private()
        e.argv[0] = self.fake_podman(e.root, "/run/user/0/containers")
        with self.assertRaises(SystemExit):
            e.verify_private()

    def test_commands_use_the_engine_prefix(self):
        # every engine command of a benchmark is {e}, which carries the
        # private options: no bare podman or velarx
        for b in pc.BENCHMARKS:
            for c in b["setup"] + [b["command"]] + ([b["prepare"]] if "prepare" in b else []) \
                    + b.get("cleanup", []):
                self.assertNotRegex(c, r"\b(podman|velarx)\b", b["name"])
                for part in re.split(r"&&|;", c):
                    self.assertTrue(part.strip().startswith("{e} "), (b["name"], part))


if __name__ == "__main__":
    unittest.main()
