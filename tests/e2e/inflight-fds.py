#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""Estimate the unix fds in flight of this uid: the smallest RLIMIT_NOFILE at which
sending one fd over SCM_RIGHTS does not fail with ETOOMANYREFS (kernel: user->unix_inflight > rlimit).
The count is the user's, over all of its sockets: the session bus of the user dies when it is over the
limit of its broker (1024).  Prints "inflight <= 8" or "inflight ~ N"; the number is the last word."""
import socket, resource, errno, os, sys
def ok(n):
    pid = os.fork()
    if pid == 0:
        a, b = socket.socketpair()
        resource.setrlimit(resource.RLIMIT_NOFILE, (n, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
        try:
            socket.send_fds(a, [b"x"], [0]); os._exit(0)
        except OSError as e:
            os._exit(1 if e.errno == errno.ETOOMANYREFS else 2)
    _, st = os.waitpid(pid, 0); rc = os.waitstatus_to_exitcode(st)
    if rc == 2: sys.exit("other error")
    return rc == 0
lo, hi = 8, resource.getrlimit(resource.RLIMIT_NOFILE)[1]
if ok(lo): print("inflight <= %d" % lo); sys.exit()
while lo + 1 < hi:
    mid = (lo + hi) // 2
    if ok(mid): hi = mid
    else: lo = mid
print("inflight ~ %d" % hi)
