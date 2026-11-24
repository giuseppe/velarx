# SPDX-License-Identifier: Apache-2.0
"""Check the chain of trust in a debug log (`--log-level=debug`) mechanically.

Reads the log on standard input; the lines with `verity chain: ` are the
chain's.  Each chain starts at its `root` line (one per image of a start, the
ones of `--mount type=image` labelled `image mount DEST: `).  For each chain
the digests must connect: the root is the digest the first index or the
manifest is named by, each index names the next, the manifest names the
configuration and the blob of each layer, the annotation of each layer has the
digest its EROFS image measured, every measured image is in the overlay, and
the closing line lists the same digests; where the overlay line says the FUSE
file system checks the files of the layers above the lowest, it names every
one of them (`layer 2`, `layers 2-N`).  A chain is COMPLETE (every link
held and said), BROKEN (a `BROKEN` line, and no `COMPLETE` after it, or a
`BROKEN fuse object` line after the `COMPLETE` of a chain whose files the FUSE
file system checks) or INCOMPLETE.

Prints a line per chain: `SCOPE STATUS KIND ROOT LAYERS [BROKEN-LINK]`
(SCOPE is `-` for the root file system).  Exit status: 0 if every chain is
COMPLETE (`--expect complete`, the default) or if the last one is BROKEN with
no COMPLETE line after its BROKEN one (`--expect broken`); 1 otherwise, with
the reason on standard error.

    velarx --log-level=debug run --rm NAME@sha256:D true 2>&1 | python3 -I verity_chain.py

The `BROKEN fuse object` lines are said at the debug level by the FUSE file
system that refused the file (the image server, which keeps them in
`image-server.log` in the bundle directory of the container: cat it after the
output of the start, with its timestamps and levels in front).
"""

import re
import sys

D = r"(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})"
LISTED = rf"{D}(?:,{D})*"
SCOPE = re.compile(r"^image mount (\S+): (.*)$")
ROOT = re.compile(rf"^root (typed|RECORDED|NONE|SIGNATURE) ({D})$")
INDEX = re.compile(rf"^({D}) index -> ({D}) (index|manifest)$")
CONFIG = re.compile(rf"^({D}) manifest -> ({D}) config$")
SETTINGS = re.compile(rf"^({D}) config -> settings$")
LAYER = re.compile(rf"^({D}) manifest -> ({D}) layer ([0-9]+) blob -> ({LISTED}) (annotation|record)$")
MEASURED = re.compile(rf"^layer ([0-9]+) (annotation|record) ({D}) == erofs fd ({D})$")
# (the files of the layers above the lowest are checked by the FUSE file
# system where the overlay follows the stubs of the lowest layer only)
OVERLAY = re.compile(
    rf"^erofs fd ({LISTED}) -> overlay verity=require"
    r"(?: \(files of layer 1\), fuse verity=require \(files of (layer 2|layers 2-([0-9]+))\))?$"
)
# (a file the FUSE file system finds wrong at an open, after the start)
FUSE_BROKEN = re.compile(r"^BROKEN fuse object [0-9a-f]{2}/[0-9a-f]{62} expected (.+) found (.+)$")
COMPLETE = re.compile(r"^COMPLETE (.*)$")
BROKEN = re.compile(r"^BROKEN (.+?) expected (.+) found (.+)$")


class Bad(Exception):
    pass


class Chain:
    def __init__(self, scope, kind, root):
        self.scope, self.kind, self.root = scope, kind, root
        self.head = root  # the digest the next link must start from
        self.manifest = root if kind in ("NONE", "SIGNATURE") else None
        self.trail = [root]
        self.config = None
        self.settings = False
        self.layers = {}  # n -> (blob, annotation digests)
        self.measured = {}  # n -> erofs digest
        self.overlay = False
        self.fuse = False  # the FUSE file system checks the layers above the lowest
        self.status = "INCOMPLETE"
        self.broken = None

    def where(self):
        return self.scope or "-"

    def need(self, ok, why):
        if not ok:
            raise Bad(f"{self.where()}: {why}")

    def manifest_digest(self, m):
        # (the root is the manifest when no index line came before)
        if self.manifest is None:
            self.need(m == self.head, f"manifest {m} is not named by {self.head}")
            self.manifest = m
        self.need(m == self.manifest, f"manifest {m}, the chain's is {self.manifest}")

    def line(self, text):
        if self.status == "COMPLETE" and self.fuse and FUSE_BROKEN.match(text):
            # (the FUSE file system refused a file it checks: the chain is
            # broken from that open on)
            self.status, self.broken = "BROKEN", text[len("BROKEN "):].split(" expected ")[0]
            return
        self.need(self.status != "COMPLETE", f"a line after COMPLETE: {text}")
        if self.status == "BROKEN":
            self.need(not text.startswith("COMPLETE"), "COMPLETE after BROKEN")
            return
        if m := INDEX.match(text):
            self.need(self.manifest is None, "an index after the manifest")
            self.need(m[1] == self.head, f"index {m[1]} is not named by {self.head}")
            self.head = m[2]
            self.trail.append(m[2])
            if m[3] == "manifest":
                self.manifest = m[2]
        elif m := CONFIG.match(text):
            self.manifest_digest(m[1])
            self.need(self.config is None, "a second config")
            self.config = m[2]
            self.trail.append(m[2])
        elif m := SETTINGS.match(text):
            self.need(m[1] == self.config, f"settings from {m[1]}, the config is {self.config}")
            self.settings = True
        elif text == "settings -> spec process":
            self.need(self.config is not None, "spec process before the config")
        elif m := LAYER.match(text):
            self.manifest_digest(m[1])
            n = int(m[3])
            self.need(n not in self.layers, f"layer {n} twice")
            self.layers[n] = (m[2], m[4].split(","), m[5])
        elif m := MEASURED.match(text):
            n = int(m[1])
            self.need(n in self.layers, f"layer {n} measured, no manifest line names it")
            self.need(m[3] == m[4], f"layer {n}: {m[2]} {m[3]} != erofs fd {m[4]}")
            self.need(m[2] == self.layers[n][2], f"layer {n}: measured as its {m[2]}, the manifest line says {self.layers[n][2]}")
            self.need(m[3] in self.layers[n][1], f"layer {n}: {m[3]} is not in its {m[2]}")
            self.need(n not in self.measured, f"layer {n} measured twice")
            self.measured[n] = m[4]
        elif m := OVERLAY.match(text):
            want = [self.measured[n] for n in sorted(self.measured, reverse=True)]
            self.need(m[1].split(",") == want, f"overlay of {m[1]}, measured {','.join(want)}")
            self.need(len(want) == len(self.layers), "an overlay before every layer was measured")
            if m[2]:
                # the FUSE file system checks the files of every layer above
                # the lowest, and there is one
                last = 2 if m[2] == "layer 2" else int(m[3])
                self.need(last > 2 or m[2] == "layer 2", f"fuse checks {m[2]}")
                self.need(last == len(self.layers), f"fuse checks {m[2]} of {len(self.layers)} layers")
            self.fuse = bool(m[2])
            self.overlay = True
        elif m := COMPLETE.match(text):
            self.need(self.overlay, "COMPLETE without the overlay")
            self.need(self.kind in ("NONE", "SIGNATURE") or self.config is not None, "COMPLETE without the config")
            self.need(self.layers and len(self.measured) == len(self.layers), "COMPLETE without every layer")
            want = [" -> ".join(self.trail)] + [
                f"{self.layers[n][0]} -> {self.measured[n]}" for n in sorted(self.layers)
            ]
            self.need(m[1] == " ; ".join(want), f"COMPLETE {m[1]}, the links say {' ; '.join(want)}")
            self.status = "COMPLETE"
        elif m := BROKEN.match(text):
            self.status, self.broken = "BROKEN", m[1]
        else:
            raise Bad(f"{self.where()}: not a line of the chain: {text}")


def chains(lines):
    found, open_ = [], {}
    for line in lines:
        at = line.find("verity chain: ")
        if at < 0:
            continue
        text = line[at + len("verity chain: "):].rstrip("\n")
        scope = ""
        if m := SCOPE.match(text):
            scope, text = m[1], m[2]
        if text == "OFF" or text.startswith(("OFF (", "signature ")):
            continue
        if m := ROOT.match(text):
            open_[scope] = Chain(scope, m[1], m[2])
            found.append(open_[scope])
            continue
        if scope not in open_:
            # (a BROKEN line before any root: a chain that broke at its root)
            if BROKEN.match(text):
                c = Chain(scope, "-", "-")
                c.line(text)
                found.append(c)
                continue
            raise Bad(f"{scope or '-'}: a line before the root: {text}")
        open_[scope].line(text)
    return found


def main():
    expect = "complete"
    if sys.argv[1:] in (["--expect", "complete"], ["--expect", "broken"]):
        expect = sys.argv[2]
    elif sys.argv[1:]:
        sys.exit(__doc__)
    try:
        found = chains(sys.stdin)
    except Bad as e:
        print(f"verity_chain: {e}", file=sys.stderr)
        return 1
    for c in found:
        print(c.where(), c.status, c.kind, c.root, len(c.layers), c.broken or "")
    if not found:
        print("verity_chain: no chain", file=sys.stderr)
        return 1
    if expect == "complete":
        bad = [c for c in found if c.status != "COMPLETE"]
        if bad:
            print(f"verity_chain: {bad[0].where()} is {bad[0].status}", file=sys.stderr)
            return 1
    elif found[-1].status != "BROKEN":
        print(f"verity_chain: the last chain is {found[-1].status}, not BROKEN", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
