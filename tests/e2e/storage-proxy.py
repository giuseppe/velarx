# SPDX-License-Identifier: Apache-2.0
# storage-proxy.py LISTEN UPSTREAM FAULTS [PIDFILE]: a storage service that
# is the real one with a fault in the way, for the tests of an engine that is
# faced with a service that crashes, stalls or lies.  It listens on LISTEN,
# connects each client to the service on UPSTREAM and relays the messages with
# their descriptors in both directions, so that the engine runs a real pull
# and a real container through it; a line of the file FAULTS
#
#   METHOD ACTION [ARGUMENT...]
#
# is used once, by the next call of METHOD (the name without the interface),
# and the line is removed from the file; the lines of one method that are in
# the file together are all made in that call, in their order.  The file can be written while the
# proxy runs.  FAULTS.hit gets the line when it is used, FAULTS.log every call with its time.
#
# Actions on the call (it is forwarded unless said):
#   kill-server [MS]  forward, SIGKILL the service after MS milliseconds (0) and
#                     end the connections
#   stop-server       forward, SIGSTOP the service (the test continues or kills it)
#   hold SECS         forward, hand the replies to the client after SECS seconds
#   blackhole         do not forward, never answer
#   refuse            do not forward, end the connection
#   morebytes N       forward with a pipe of the proxy in place of the client's
#                     (the descriptor 0 of ReadObjects): the client's pipe gets N
#                     bytes of its own first, then what the service writes
# Actions on the reply (descriptors: the reply that has some, else the last;
# patch and error: the last; the others: the first):
#   garbage           bytes that are not a message
#   huge              a message of 3 MiB
#   stall             the first half of the reply, then nothing
#   nofds             no descriptor
#   extrafds N        N descriptors of /dev/null more
#   filefd [PATH]     a descriptor of a file (/etc/passwd), for each of its own
#   sockfd            a descriptor of a socket, for each of its own
#   reversefds        its descriptors in the opposite order
#   patch NAME=JSON...  the value at each dotted NAME of `parameters` set (JSON,
#                     without spaces)
#   dupkey NAME=JSON  `parameters` with the key NAME twice: JSON first, then
#                     the service's value
#   error NAME        the varlink error org.velarx.Storage.NAME in its place
import json, os, select, signal, socket, sys, threading, time

listen_path, upstream_path, faults_path = sys.argv[1:4]
pid_path = sys.argv[4] if len(sys.argv) > 4 else None
lock = threading.Lock()


def server_pid():
    # (the file of the pid of the service: it is started again)
    return int(open(pid_path).read())


def take_faults(method):
    """The faults of `method` in the file, removed from it, in order."""
    found = []
    with lock:
        try:
            lines = open(faults_path).read().splitlines()
        except FileNotFoundError:
            return found
        keep = []
        for line in lines:
            words = line.split(None, 2)
            if len(words) >= 2 and words[0] == method:
                found.append((words[1], words[2] if len(words) > 2 else ""))
                with open(faults_path + ".hit", "a") as f:
                    f.write(line + "\n")
            else:
                keep.append(line)
        if found:
            with open(faults_path, "w") as f:
                f.write("".join(l + "\n" for l in keep))
    return found


def set_path(obj, name, value):
    keys = name.split(".")
    for k in keys[:-1]:
        obj = obj[int(k)] if isinstance(obj, list) else obj.setdefault(k, {})
    last = keys[-1]
    if isinstance(obj, list):
        obj[int(last)] = value
    else:
        obj[last] = value


def mutate(action, arg, msg, fds):
    """The reply and descriptors the client gets in place of (msg, fds)."""
    if action == "garbage":
        return b"this is not json {{{", []
    if action == "huge":
        return b'{"parameters":{"x":"' + b"A" * (3 << 20) + b'"}}', []
    if action == "nofds":
        return msg, []
    if action == "extrafds":
        return msg, fds + [os.open("/dev/null", os.O_RDONLY) for _ in range(int(arg or 1))]
    if action == "filefd":
        return msg, [os.open(arg or "/etc/passwd", os.O_RDONLY) for _ in (fds or [0])]
    if action == "sockfd":
        out = []
        for _ in fds or [0]:
            a, b = socket.socketpair()
            out.append(a.detach())
            b.close()
        return msg, out
    if action == "reversefds":
        return msg, fds[::-1]
    if action == "patch":
        d = json.loads(msg)
        for word in arg.split():
            name, _, value = word.partition("=")
            set_path(d.setdefault("parameters", {}), name, json.loads(value))
        return json.dumps(d).encode(), fds
    if action == "dupkey":
        name, _, value = arg.partition("=")
        head = b'"parameters": {'
        text = json.dumps(json.loads(msg)).encode()
        if head + b"}" in text or head not in text:
            return msg, fds
        return text.replace(head, head + json.dumps(name).encode() + b": " + value.encode() + b", ", 1), fds
    if action == "error":
        return json.dumps({"error": "org.velarx.Storage." + arg, "parameters": {"reason": "injected"}}).encode(), []
    return msg, fds


class Relay:
    def __init__(self, client):
        self.client = client
        self.up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.up.connect(upstream_path)
        self.faults = []
        self.cur = ""
        self.bufs = {client: b"", self.up: b""}
        self.held = []

    def run(self):
        socks = [self.client, self.up]
        try:
            while True:
                ready, _, _ = select.select(socks, [], [], 0.2)
                for s in ready:
                    data, fds, _, _ = socket.recv_fds(s, 1 << 16, 253)
                    if not data:
                        return
                    self.feed(s, data, fds)
        except OSError:
            pass
        finally:
            for s in socks:
                s.close()

    def feed(self, s, data, fds):
        buf = self.bufs[s] + data
        parts = buf.split(b"\0")
        self.bufs[s] = parts.pop()
        for msg in parts:
            if s is self.client:
                self.request(msg, fds)
            else:
                self.reply(msg, fds)
            fds = []
        for fd in fds:
            os.close(fd)

    def send(self, s, msg, fds, end=b"\0"):
        try:
            if fds:
                socket.send_fds(s, [msg + end], fds)
            else:
                s.sendall(msg + end)
        finally:
            # (the proxy keeps none: an end of a pipe it holds is never at its end)
            for fd in fds:
                os.close(fd)

    def request(self, msg, fds):
        pull = ""
        try:
            call = json.loads(msg)
            self.cur = call["method"].rsplit(".", 1)[-1]
            pull = call.get("parameters", {}).get("pull", "")
        except (ValueError, KeyError, TypeError, AttributeError):
            self.cur = ""
        self.faults = take_faults(self.cur) if self.cur else []
        with open(faults_path + ".log", "a") as f:
            note = "".join(" (fault: %s %s)" % a for a in self.faults)
            f.write("%.3f %s %s%s\n" % (time.time(), self.cur, pull, note))
        actions = [a for a, _ in self.faults]
        if "refuse" in actions:
            raise OSError("refused")
        if "blackhole" in actions:
            return
        if "morebytes" in actions and fds:
            n = int(dict(self.faults)["morebytes"] or 1)
            r, w = os.pipe()
            threading.Thread(target=prefix_pipe, args=(fds[0], r, n), daemon=True).start()
            fds = [w] + fds[1:]
        self.send(self.up, msg, fds)
        for action, arg in self.faults:
            if action == "kill-server":
                time.sleep(int(arg or 0) / 1000)
                os.kill(server_pid(), signal.SIGKILL)
                raise OSError("killed")
            if action == "stop-server":
                os.kill(server_pid(), signal.SIGSTOP)

    def reply(self, msg, fds):
        last = b'"continues":true' not in msg.replace(b" ", b"")
        later = []
        for action, arg in self.faults:
            if action == "hold":
                time.sleep(float(arg))
            elif action in ("garbage", "huge"):
                msg, fds = mutate(action, arg, msg, fds)
            elif action == "stall":
                half = msg[: max(1, len(msg) // 2)]
                self.send(self.client, half, fds, end=b"")
                # (the client gives up: it ends the connection)
                while self.client.recv(1):
                    pass
                raise OSError("stalled")
            elif action in ("nofds", "extrafds", "filefd", "sockfd", "reversefds"):
                if fds or last:
                    msg, fds = mutate(action, arg, msg, fds)
                else:
                    later.append((action, arg))
            elif action in ("patch", "dupkey", "error"):
                if last:
                    msg, fds = mutate(action, arg, msg, fds)
                else:
                    later.append((action, arg))
        self.faults = later
        self.send(self.client, msg, fds)


def prefix_pipe(out, src, n):
    """N bytes into `out`, then what comes from `src`, until its end."""
    try:
        os.write(out, b"X" * n)
        while True:
            data = os.read(src, 1 << 16)
            if not data:
                break
            os.write(out, data)
    except OSError:
        pass
    finally:
        os.close(out)
        os.close(src)


def serve(client):
    try:
        Relay(client).run()
    except OSError:
        client.close()


if os.path.exists(listen_path):
    os.unlink(listen_path)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(listen_path)
os.chmod(listen_path, 0o600)
srv.listen(64)
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
