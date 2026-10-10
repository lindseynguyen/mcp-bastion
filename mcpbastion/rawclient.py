"""Lenient MCP client: speaks plain JSON-RPC and accepts whatever the server
returns, so non-conforming (or deliberately malformed) servers can still be
analysed. Supports stdio and Streamable HTTP (JSON or SSE responses)."""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
from typing import Any

from .models import ServerConfig, ToolInfo

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcp-bastion", "version": "raw"}


class _Stdio:
    def __init__(self, server: ServerConfig):
        self.server = server
        self.proc: asyncio.subprocess.Process | None = None
        self._id = 0

    async def __aenter__(self):
        env = {**os.environ, **self.server.env}
        self.proc = await asyncio.create_subprocess_exec(
            self.server.command or "", *self.server.args, cwd=self.server.cwd, env=env,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, limit=16 * 1024 * 1024)
        return self

    async def __aexit__(self, *exc):
        if self.proc and self.proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                self.proc.stdin.close()
                try:
                    await asyncio.wait_for(self.proc.wait(), 2)
                except asyncio.TimeoutError:
                    self.proc.kill()
                    await self.proc.wait()

    async def notify(self, method: str, params: dict | None = None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()

    async def request(self, method: str, params: dict | None = None) -> Any:
        self._id += 1
        my_id = self._id
        msg = {"jsonrpc": "2.0", "id": my_id, "method": method, "params": params or {}}
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                raise ConnectionError("server closed stdout")
            try:
                reply = json.loads(line)
            except ValueError:
                continue                         # log noise on stdout
            if not isinstance(reply, dict):
                continue
            if reply.get("id") == my_id:
                if "error" in reply:
                    raise RuntimeError(reply["error"].get("message", "error"))
                return reply.get("result", {})
            if "method" in reply and "id" in reply:  # server->client request: answer politely
                await self._send({"jsonrpc": "2.0", "id": reply["id"],
                                  "error": {"code": -32601, "message": "not supported"}})

    async def _send(self, msg):
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self.proc.stdin.drain()


class _Http:
    def __init__(self, server: ServerConfig, timeout: float):
        self.server = server
        self.timeout = timeout
        self.session_id: str | None = None
        self._id = 0
        self.client = None

    async def __aenter__(self):
        import httpx
        self.client = httpx.AsyncClient(timeout=self.timeout, headers=self.server.headers or {})
        return self

    async def __aexit__(self, *exc):
        await self.client.aclose()

    def _headers(self):
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
             "MCP-Protocol-Version": PROTOCOL_VERSION}
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    async def notify(self, method: str, params: dict | None = None):
        msg = {"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})}
        await self.client.post(self.server.url, json=msg, headers=self._headers())

    async def request(self, method: str, params: dict | None = None) -> Any:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        resp = await self.client.post(self.server.url, json=msg, headers=self._headers())
        resp.raise_for_status()
        if resp.headers.get("mcp-session-id"):
            self.session_id = resp.headers["mcp-session-id"]
        if "text/event-stream" in resp.headers.get("content-type", ""):
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    with contextlib.suppress(ValueError):
                        data = json.loads(line[5:].strip())
                        if data.get("id") == self._id:
                            return _result(data)
            raise RuntimeError("no matching response in event stream")
        return _result(resp.json())


def _result(data: dict) -> Any:
    if "error" in data:
        raise RuntimeError(data["error"].get("message", "error"))
    return data.get("result", {})


async def _list(conn, method: str, key: str) -> list:
    items, cursor = [], None
    for _ in range(50):
        res = await conn.request(method, {"cursor": cursor} if cursor else {})
        items += (res or {}).get(key, []) or []
        cursor = (res or {}).get("nextCursor")
        if not cursor:
            break
    return items


async def inspect(server: ServerConfig, timeout: float = 20.0) -> list[ToolInfo]:
    conn = _Stdio(server) if server.transport == "stdio" else _Http(server, timeout)
    out: list[ToolInfo] = []
    async with conn:
        init = await conn.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO})
        await conn.notify("notifications/initialized")
        if init.get("instructions"):
            out.append(ToolInfo(server.name, "server-instructions", str(init["instructions"]),
                                kind="instructions"))
        caps = init.get("capabilities") or {}
        for t in await _list(conn, "tools/list", "tools"):
            if isinstance(t, dict):
                out.append(ToolInfo(server.name, str(t.get("name", "")), str(t.get("description") or ""),
                                    t.get("inputSchema") or t.get("input_schema") or {}, "tool",
                                    t.get("annotations") or {}))
        if "prompts" in caps:
            with contextlib.suppress(Exception):
                for p in await _list(conn, "prompts/list", "prompts"):
                    args = {a.get("name", ""): a for a in p.get("arguments") or [] if isinstance(a, dict)}
                    out.append(ToolInfo(server.name, str(p.get("name", "")),
                                        str(p.get("description") or ""), {"properties": args}, "prompt"))
        if "resources" in caps:
            with contextlib.suppress(Exception):
                for r in await _list(conn, "resources/list", "resources"):
                    out.append(ToolInfo(server.name, str(r.get("name") or r.get("uri", "")),
                                        str(r.get("description") or ""), {"uri": r.get("uri", "")},
                                        "resource"))
    return out
