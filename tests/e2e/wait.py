#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""Waits of the end to end tests that an event ends, with no loop of sleeps.

  wait.py ready SOCKET LIMIT   bind the datagram socket SOCKET and print
                               "bound"; then print "ready" when a process
                               notifies READY=1 on it (sd_notify), exit 1
                               after LIMIT seconds
  wait.py path PATH LIMIT [PID]
                               until PATH exists (inotify on its directory);
                               with PID, fail as soon as that process ends
  wait.py glob PATTERN LIMIT   until a file of the directory of PATTERN
                               matches it
  wait.py gone PATH LIMIT      until PATH does not exist (inotify on its directory)
  wait.py exit PID LIMIT       until the process PID has ended (a pidfd)
  wait.py group PGID LIMIT     until no process of the group PGID is left
  wait.py line FILE REGEX LIMIT [COUNT]
                               until COUNT (default 1) lines of FILE match
                               REGEX (inotify on the file, which may not
                               exist yet)
  wait.py content FILE REGEX LIMIT
                               until FILE, read as a whole, matches REGEX
                               (cgroup.events: its changes are notified)

LIMIT is an upper bound, not a delay; the exit status is 0 when the event
came and 1 when the limit passed (with what was waited for, and what was
seen, on stderr); 2 for arguments that name nothing to wait for.
"""
import ctypes, ctypes.util, os, re, select, socket, struct, sys, time

IN_MODIFY, IN_CREATE, IN_MOVED_TO, IN_CLOSE_WRITE, IN_DELETE, IN_MOVED_FROM = 0x2, 0x100, 0x80, 0x8, 0x200, 0x40
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def timed_out(what, limit, seen=None):
    """Say on stderr what did not come within LIMIT seconds (and the end of
    what was seen instead): the output of the failed test shows it."""
    print("wait.py: %s within %g s" % (what, limit), file=sys.stderr)
    if seen:
        for l in seen.splitlines()[-5:]:
            print("wait.py:   %s" % l, file=sys.stderr)
    return 1


def tail(file):
    try:
        with open(file, "rb") as f:
            return f.read()[-2000:].decode(errors="replace")
    except OSError as e:
        return str(e)


def inotify(path, mask):
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    if fd < 0 or libc.inotify_add_watch(fd, os.fsencode(path), mask) < 0:
        raise OSError(ctypes.get_errno(), "inotify " + path)
    return fd


def drain(fd):
    try:
        while os.read(fd, 4096):
            pass
    except BlockingIOError:
        pass


def wait_fd(fd, deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        return False
    r, _, _ = select.select([fd], [], [], left)
    return bool(r)


def ready(sock_path, limit):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    s.bind(sock_path)
    print("bound", flush=True)
    deadline = time.monotonic() + limit
    while wait_fd(s, deadline):
        if b"READY=1" in s.recv(4096):
            print("ready", flush=True)
            return 0
    return timed_out("no READY=1 on " + sock_path, limit)


def path(p, limit, pid=None):
    p = os.path.abspath(p)
    deadline = time.monotonic() + limit
    pidfd = None
    if pid is not None:
        try:
            pidfd = os.pidfd_open(int(pid))
        except ProcessLookupError:
            pass
    try:
        while True:
            # (the nearest directory above that exists: a directory the daemon makes
            # is a creation too; watched before it is looked at, no creation is lost)
            above = os.path.dirname(p)
            while not os.path.isdir(above):
                above = os.path.dirname(above)
            fd = inotify(above, IN_CREATE | IN_MOVED_TO)
            try:
                if os.path.lexists(p):
                    return 0
                if pid is not None and (pidfd is None or select.select([pidfd], [], [], 0)[0]):
                    print("wait.py: the process %s ended before %s came" % (pid, p), file=sys.stderr)
                    return 1
                left = deadline - time.monotonic()
                fds = [fd] + ([pidfd] if pidfd is not None else [])
                if left <= 0 or not select.select(fds, [], [], left)[0]:
                    return timed_out("no " + p, limit)
                drain(fd)
            finally:
                os.close(fd)
    finally:
        if pidfd is not None:
            os.close(pidfd)


def glob_(pattern, limit):
    import glob
    d = os.path.dirname(os.path.abspath(pattern))
    fd = inotify(d, IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE)
    deadline = time.monotonic() + limit
    try:
        while not glob.glob(pattern):
            if not wait_fd(fd, deadline):
                return timed_out("nothing matches " + pattern, limit)
            drain(fd)
        return 0
    finally:
        os.close(fd)


def gone(p, limit):
    p = os.path.abspath(p)
    fd = inotify(os.path.dirname(p), IN_DELETE | IN_MOVED_FROM)
    deadline = time.monotonic() + limit
    try:
        while os.path.lexists(p):
            if not wait_fd(fd, deadline):
                return timed_out(p + " is still there", limit)
            drain(fd)
        return 0
    finally:
        os.close(fd)


def process_exit(pid, limit):
    # (no pid, or 0, is a bug of the caller: a wait for it would pass for nothing)
    if not pid.isdigit() or int(pid) == 0:
        print("wait.py: no process to wait for: %r" % pid, file=sys.stderr)
        return 2
    try:
        fd = os.pidfd_open(int(pid))
    except ProcessLookupError:
        return 0
    if wait_fd(fd, time.monotonic() + limit):
        return 0
    try:
        with open("/proc/%s/cmdline" % pid, "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        cmd = ""
    return timed_out("the process %s (%s) did not end" % (pid, cmd.strip()), limit)


def group(pgid, limit):
    deadline = time.monotonic() + limit
    while True:
        members = []
        for d in os.listdir("/proc"):
            if d.isdigit():
                try:
                    with open("/proc/%s/stat" % d) as f:
                        rest = f.read().rsplit(")", 1)[1].split()
                    if int(rest[2]) == int(pgid) and rest[0] != "Z":
                        members.append(int(d))
                except (OSError, IndexError, ValueError):
                    pass
        if not members:
            return 0
        try:
            fd = os.pidfd_open(members[0])
        except ProcessLookupError:
            continue
        if not wait_fd(fd, deadline):
            return timed_out("the process group %s still has %s" % (pgid, members), limit)
        os.close(fd)


def line(file, regex, limit, count=1):
    file = os.path.abspath(file)
    rx = re.compile(regex)
    fd = inotify(os.path.dirname(file), IN_MODIFY | IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE)
    deadline = time.monotonic() + limit
    offset = 0
    pending = b""
    seen = 0
    while True:
        try:
            with open(file, "rb") as f:
                f.seek(offset)
                data = f.read()
                offset += len(data)
        except FileNotFoundError:
            data = b""
        pending += data
        *lines, pending = pending.split(b"\n")
        seen += sum(1 for l in lines if rx.search(l.decode(errors="replace")))
        if seen >= count:
            return 0
        if not wait_fd(fd, deadline):
            return timed_out("%d of %d lines of %s match %r" % (seen, count, file, regex), limit, tail(file))
        drain(fd)


def content(file, regex, limit):
    """Until FILE as a whole matches REGEX (a file of a pseudo file system,
    such as cgroup.events, is read again from its start)."""
    file = os.path.abspath(file)
    rx = re.compile(regex, re.M)
    fd = inotify(os.path.dirname(file), IN_MODIFY | IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE)
    deadline = time.monotonic() + limit
    while True:
        try:
            with open(file, "rb") as f:
                if rx.search(f.read().decode(errors="replace")):
                    return 0
        except FileNotFoundError:
            pass
        if not wait_fd(fd, deadline):
            return timed_out("%s does not match %r" % (file, regex), limit, tail(file))
        drain(fd)


def main(argv):
    cmd = argv[1]
    if cmd == "ready":
        return ready(argv[2], float(argv[3]))
    if cmd == "path":
        return path(argv[2], float(argv[3]), argv[4] if len(argv) > 4 else None)
    if cmd == "glob":
        return glob_(argv[2], float(argv[3]))
    if cmd == "gone":
        return gone(argv[2], float(argv[3]))
    if cmd == "exit":
        return process_exit(argv[2], float(argv[3]))
    if cmd == "group":
        return group(argv[2], float(argv[3]))
    if cmd == "line":
        return line(argv[2], argv[3], float(argv[4]), int(argv[5]) if len(argv) > 5 else 1)
    if cmd == "content":
        return content(argv[2], argv[3], float(argv[4]))
    sys.exit(__doc__)


sys.exit(main(sys.argv))
