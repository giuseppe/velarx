#!/usr/bin/python3 -I
# SPDX-License-Identifier: Apache-2.0
"""A TCP proxy that adds a delay to every byte stream in both directions
(half of RTT_MS each way), to try the network paths of a registry that is on
this machine.  Bytes are released at the time they arrived plus the delay, so
a big body is not slowed down.

    delay-proxy.py LISTEN_PORT TARGET_HOST:TARGET_PORT RTT_MS
"""
import asyncio
import sys
import time


async def pipe(reader, writer, delay):
    queue = asyncio.Queue()

    async def release():
        while True:
            item = await queue.get()
            if item is None:
                break
            at, data = item
            wait = at - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            writer.write(data)
            await writer.drain()
        writer.close()

    task = asyncio.create_task(release())
    try:
        while data := await reader.read(262144):
            queue.put_nowait((time.monotonic() + delay, data))
    except ConnectionError:
        pass
    queue.put_nowait(None)
    try:
        await task
    except ConnectionError:
        pass


async def main(port, target, rtt_ms):
    host, _, tport = target.rpartition(":")
    delay = rtt_ms / 2000.0

    async def handle(reader, writer):
        try:
            up_r, up_w = await asyncio.open_connection(host, int(tport))
        except OSError:
            writer.close()
            return
        await asyncio.gather(pipe(reader, up_w, delay), pipe(up_r, writer, delay))

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2], float(sys.argv[3])))
