#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Giuseppe Scrivano <giuseppe@scrivano.org>
#
# Run a command in a pseudo terminal, feed it the given inputs (one every
# half second) and print its output.  Exits with the exit code of the
# command.
#
#   pty_run.py [--size ROWS,COLS] [--input DATA | --resize ROWS,COLS | --expect TEXT]... -- COMMAND [ARG...]
#
# DATA is a Python bytes literal body, e.g. 'exit 3\r' or '\x10\x11'.
# --size is the size of the terminal at the start, --resize changes it at
# its turn among the inputs.  --expect waits, at its turn, for the output
# to have TEXT (a shell's prompt: what is typed before it may be thrown
# away when the shell sets up its terminal); the next input follows at once.

import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time


def set_size(fd, spec):
    rows, cols = (int(x) for x in spec.split(","))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def main():
    args = sys.argv[1:]
    inputs = []
    size = None
    while args and args[0] != "--":
        if args[0] == "--input":
            inputs.append(args[1].encode().decode("unicode_escape").encode("latin-1"))
            args = args[2:]
        elif args[0] == "--expect":
            inputs.append(("expect", args[1].encode()))
            args = args[2:]
        elif args[0] == "--resize":
            inputs.append(("resize", args[1]))
            args = args[2:]
        elif args[0] == "--size":
            size = args[1]
            args = args[2:]
        else:
            sys.stderr.write("invalid argument %s\n" % args[0])
            return 2
    args = args[1:]

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(args[0], args)
    if size:
        set_size(fd, size)

    out = b""
    seen = 0
    deadline = time.time() + 30
    last = time.time()
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            out += data
        if inputs and isinstance(inputs[0], tuple) and inputs[0][0] == "expect":
            at = out.find(inputs[0][1], seen)
            if at >= 0:
                seen = at + len(inputs.pop(0)[1])
                last = 0
            continue
        if inputs and time.time() - last > 0.5:
            item = inputs.pop(0)
            if isinstance(item, tuple):
                set_size(fd, item[1])
            else:
                os.write(fd, item)
            last = time.time()

    _, status = os.waitpid(pid, 0)
    sys.stdout.write(out.decode("utf-8", "replace"))
    sys.stdout.flush()
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    return 255


if __name__ == "__main__":
    sys.exit(main())
