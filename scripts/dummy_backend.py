#!/usr/bin/env python3
"""Minimal non-blocking HTTP/1.1 keep-alive backend for benchmarking.

Serves a fixed 1 KB body for any request on 127.0.0.1:3000.  asyncio keeps
per-request overhead far below `python3 -m http.server` (which renders a
directory listing per request), so the backend stops being the bottleneck.
"""
import asyncio

BODY = (b"0123456789" * 103)[:1024]
RESP = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        b"Content-Length: " + str(len(BODY)).encode() + b"\r\n"
        b"Connection: keep-alive\r\n\r\n") + BODY

async def handle(reader, writer):
    try:
        while True:
            # Consume until end of HEADERS; bodies unsupported (GET only).
            while (await reader.readline()) not in (b"\r\n", b"", b"\n"):
                pass
            if reader.at_eof():
                break
            writer.write(RESP)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()

async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 3000)
    print("dummy backend on 127.0.0.1:3000")
    async with server:
        await server.serve_forever()

asyncio.run(main())
