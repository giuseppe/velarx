# SPDX-License-Identifier: Apache-2.0
# storage-activate.py SOCKET COMMAND...: what a .socket unit does for a .service
# that leaves when idle (systemd-socket-activate does not: it ends with its
# first child).  Listens on SOCKET (0600) and, whenever a connection waits and
# the service is not running, starts COMMAND with the socket as descriptor 3
# (LISTEN_PID, LISTEN_FDS=1); COMMAND's output is its own.  Ends with SIGTERM
# (the service it started is left to the test).
import os, select, signal, socket, sys

path, cmd = sys.argv[1], sys.argv[2:]
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
listener = socket.socket(socket.AF_UNIX)
old = os.umask(0o177)
listener.bind(path)
os.umask(old)
listener.listen(128)
while True:
    select.select([listener], [], [])
    pid = os.fork()
    if pid == 0:
        os.dup2(listener.fileno(), 3)
        os.set_inheritable(3, True)
        os.environ["LISTEN_PID"] = str(os.getpid())
        os.environ["LISTEN_FDS"] = "1"
        os.execvp(cmd[0], cmd)
    os.waitpid(pid, 0)
