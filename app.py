#!/usr/bin/env python3

import asyncio
import logging
import os
import socket
import struct
import sys
import base64
import aiohttp
from aiohttp import web

# =========================
# Config
# =========================

UUID = os.environ.get("UUID", "087a99ec-dd5b-4fa1-aaf5-5ecb1c0f01fa")

if not UUID:
    raise RuntimeError("UUID is required")


DOMAIN = os.environ.get("DOMAIN", "xxx.com")


SUB_PATH = os.environ.get("SUB_PATH", "sub")


NODE_NAME = os.environ.get("NODE_NAME", "")


WS_PATH = os.environ.get("WS_PATH", UUID.replace("-", "")[:8])


PORT = int(os.environ.get("PORT", 3000))


MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS", 100))


DEBUG = os.environ.get("DEBUG", "false").lower() == "true"


# =========================
# Logging
# =========================


logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


logger = logging.getLogger("vless")


# =========================
# Global
# =========================


UUID_BYTES = bytes.fromhex(UUID.replace("-", ""))


LIMITER = asyncio.Semaphore(MAX_CONNECTIONS)


# =========================
# Utils
# =========================


def port_available(port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.bind(("0.0.0.0", port))

        return True

    except OSError:
        return False

    finally:
        sock.close()


async def resolve_host(host):

    try:
        socket.inet_aton(host)

        return host

    except:
        pass

    try:
        loop = asyncio.get_running_loop()

        result = await loop.getaddrinfo(host, None, family=socket.AF_INET)

        return result[0][4][0]

    except Exception:
        return host


# =========================
# VLESS Parser
# =========================


async def parse_vless(data):

    if len(data) < 22:
        return None

    # version

    if data[0] != 0:
        return None

    # UUID

    if data[1:17] != UUID_BYTES:
        return None

    index = 17

    # addons length

    addons_length = data[index]

    index += 1

    # skip addons

    index += addons_length

    if index >= len(data):
        return None

    # command

    command = data[index]

    index += 1

    # only TCP

    if command != 1:
        return None

    # port

    if index + 2 > len(data):
        return None

    port = struct.unpack("!H", data[index : index + 2])[0]

    index += 2

    # address type

    if index >= len(data):
        return None

    atyp = data[index]

    index += 1

    host = ""

    # IPv4

    if atyp == 1:
        if index + 4 > len(data):
            return None

        host = ".".join(str(x) for x in data[index : index + 4])

        index += 4

    # Domain

    elif atyp == 2:
        if index >= len(data):
            return None

        length = data[index]

        index += 1

        if index + length > len(data):
            return None

        host = data[index : index + length].decode("utf-8", errors="ignore")

        index += length

    else:
        return None

    if not host:
        return None

    return {"host": host, "port": port, "payload": data[index:]}


# =========================
# Relay
# =========================


async def relay(websocket, reader, writer):

    async def ws_to_tcp():

        try:
            async for msg in websocket:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    writer.write(msg.data)

                    await writer.drain()

        except Exception:
            pass

        finally:
            writer.close()

    async def tcp_to_ws():

        try:
            while True:
                data = await reader.read(8192)

                if not data:
                    break

                await websocket.send_bytes(data)

        except Exception:
            pass

        finally:
            await websocket.close()

    await asyncio.gather(ws_to_tcp(), tcp_to_ws())


# =========================
# WebSocket Handler
# =========================


async def websocket_handler(request):

    if request.path.rstrip("/") != "/" + WS_PATH:
        return web.Response(status=404)

    await LIMITER.acquire()

    websocket = web.WebSocketResponse()

    await websocket.prepare(request)

    try:
        message = await asyncio.wait_for(websocket.receive(), timeout=5)

        if message.type != aiohttp.WSMsgType.BINARY:
            await websocket.close()

            return websocket

        target = await parse_vless(message.data)

        if not target:
            await websocket.close()

            return websocket

        # VLESS response

        await websocket.send_bytes(b"\x00\x00")

        host = await resolve_host(target["host"])

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, target["port"]), timeout=10
        )

        if target["payload"]:
            writer.write(target["payload"])

            await writer.drain()

        await relay(websocket, reader, writer)

    except Exception as e:
        if DEBUG:
            logger.error(str(e))

        await websocket.close()

    finally:
        LIMITER.release()

    return websocket


# =========================
# Subscription
# =========================


async def subscription(request):

    host = DOMAIN

    port = 443

    security = "tls"

    if not host:
        host = request.host.split(":")[0]

        port = PORT

        security = "none"

    vless_url = (
        f"vless://{UUID}@{host}:{port}"
        "?encryption=none"
        f"&security={security}"
        f"&sni={host}"
        "&fp=chrome"
        "&type=ws"
        f"&host={host}"
        f"&path=%2F{WS_PATH}"
        f"#{NODE_NAME}"
    )
    base64_content = base64.b64encode(vless_url.encode()).decode()
    return web.Response(text=base64_content, content_type="text/plain")


# =========================
# Index
# =========================


async def index(request):

    return web.Response(text="OK")


# =========================
# Main
# =========================


async def main():

    if not port_available(PORT):
        logger.error(f"Port {PORT} already used")

        sys.exit(1)

    app = web.Application()

    app.router.add_get("/", index)

    app.router.add_get("/" + SUB_PATH, subscription)

    app.router.add_get("/" + WS_PATH, websocket_handler)

    runner = web.AppRunner(app)

    await runner.setup()

    site = web.TCPSite(runner, "0.0.0.0", PORT)

    await site.start()

    logger.info(f"VLESS WS running on {PORT}")

    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        pass
