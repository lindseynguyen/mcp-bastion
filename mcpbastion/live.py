"""Connect to MCP servers and collect what they expose to the model.

Starting a stdio server runs its command on this machine, so live scanning is
opt-in (--live). Works with the official `mcp` SDK 1.x and 2.x."""
from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from typing import Any

from .models import ServerConfig, ToolInfo


class LiveScanUnavailable(RuntimeError):
    pass


def _get(obj: Any, *names: str, default: Any = None) -> Any:
    for n in names:
        if isinstance(obj, dict) and n in obj:
            return obj[n]
        if hasattr(obj, n):
            v = getattr(obj, n)
            if v is not None:
                return v
    return default


def _dump(obj: Any) -> dict:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    # by_alias: SDK 2.x models use snake_case attributes, but the protocol
    # (and our rules) use camelCase names such as readOnlyHint / inputSchema
    for m in ("model_dump", "dict"):
        if hasattr(obj, m):
            for kwargs in ({"exclude_none": True, "by_alias": True}, {"exclude_none": True}, {}):
                try:
                    return getattr(obj, m)(**kwargs)
                except TypeError:
                    continue
    return dict(getattr(obj, "__dict__", {}))


async def _paginate(call, attr: str) -> list:
    items, cursor = [], None
    for _ in range(50):
        try:
            res = await (call(cursor=cursor) if cursor else call())
        except TypeError:
            res = await call()
        items += list(_get(res, attr, default=[]) or [])
        cursor = _get(res, "nextCursor", "next_cursor")
        if not cursor:
            break
    return items


@contextlib.asynccontextmanager
async def _open(server: ServerConfig):
    try:
        from mcp import ClientSession
    except ImportError as exc:  # pragma: no cover
        raise LiveScanUnavailable("install the 'mcp' package for live scanning") from exc

    if server.transport == "stdio":
        from mcp import StdioServerParameters
        from mcp.client.stdio import stdio_client
        env = {**os.environ, **server.env} if server.env else None
        params = StdioServerParameters(command=server.command or "", args=server.args,
                                       env=env, cwd=server.cwd)
        cm = stdio_client(params, errlog=open(os.devnull, "w"))
    elif server.transport == "sse":
        from mcp.client.sse import sse_client
        cm = sse_client(server.url, headers=server.headers or None)
    else:
        import mcp.client.streamable_http as sh
        factory = getattr(sh, "streamablehttp_client", None)
        if factory is not None:                       # SDK 1.x
            cm = factory(server.url, headers=server.headers or None)
        else:                                         # SDK 2.x
            factory = sh.streamable_http_client
            client = None
            if server.headers:
                client = sh.create_mcp_http_client(headers=server.headers)
            cm = factory(server.url, http_client=client) if client else factory(server.url)
    async with cm as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            yield session


async def inspect_server(server: ServerConfig, timeout: float = 20.0) -> list[ToolInfo]:
    """Use the official SDK; if it rejects the server's replies (strict schema
    validation - which a malicious server can trigger on purpose to hide its
    tools), fall back to a lenient raw JSON-RPC client."""
    try:
        return await _inspect_sdk(server, timeout)
    except asyncio.TimeoutError:
        raise
    except BaseException as exc:  # noqa: BLE001
        if isinstance(exc, (KeyboardInterrupt, LiveScanUnavailable)):
            raise
        first = _unwrap(exc)
        try:
            from . import rawclient
            return await asyncio.wait_for(rawclient.inspect(server, timeout), timeout=timeout)
        except asyncio.TimeoutError:
            raise
        except Exception as raw_exc:  # noqa: BLE001
            raise RuntimeError(f"{type(first).__name__}: {first} | raw client: {raw_exc}") from raw_exc


async def _inspect_sdk(server: ServerConfig, timeout: float = 20.0) -> list[ToolInfo]:
    async def _run() -> list[ToolInfo]:
        out: list[ToolInfo] = []
        async with _open(server) as session:
            init = await session.initialize()
            instructions = _get(init, "instructions")
            if instructions:
                out.append(ToolInfo(server.name, "server-instructions", str(instructions),
                                    kind="instructions"))
            caps = _dump(_get(init, "capabilities"))
            for t in await _paginate(session.list_tools, "tools"):
                ann = _dump(_get(t, "annotations"))
                schema = _dump(_get(t, "inputSchema", "input_schema"))
                out.append(ToolInfo(server.name, str(_get(t, "name", default="")),
                                    str(_get(t, "description", default="") or ""), schema,
                                    "tool", ann))
            if caps.get("prompts") is not None or not caps:
                with contextlib.suppress(Exception):
                    for p in await _paginate(session.list_prompts, "prompts"):
                        args = [_dump(a) for a in (_get(p, "arguments", default=[]) or [])]
                        out.append(ToolInfo(server.name, str(_get(p, "name", default="")),
                                            str(_get(p, "description", default="") or ""),
                                            {"properties": {a.get("name", ""): a for a in args}},
                                            "prompt"))
            if caps.get("resources") is not None or not caps:
                with contextlib.suppress(Exception):
                    for r in await _paginate(session.list_resources, "resources"):
                        out.append(ToolInfo(server.name, str(_get(r, "name", "uri", default="")),
                                            str(_get(r, "description", default="") or ""),
                                            {"uri": str(_get(r, "uri", default=""))}, "resource"))
        return out
    return await asyncio.wait_for(_run(), timeout=timeout)


def inspect_all(servers: list[ServerConfig], timeout: float = 20.0, concurrency: int = 4
                ) -> tuple[list[ToolInfo], dict[str, str]]:
    """Inspect servers concurrently. Returns (tools, {server_name: error})."""
    errors: dict[str, str] = {}
    tools: list[ToolInfo] = []
    sem = asyncio.Semaphore(concurrency)

    async def one(s: ServerConfig):
        async with sem:
            try:
                return await inspect_server(s, timeout)
            except asyncio.TimeoutError:
                errors[s.name] = f"timed out after {timeout:.0f}s"
            except LiveScanUnavailable as exc:
                errors[s.name] = str(exc)
            except BaseException as exc:  # noqa: BLE001 - report any server failure
                if isinstance(exc, KeyboardInterrupt):
                    raise
                msg = _unwrap(exc)
                errors[s.name] = f"{type(msg).__name__}: {msg}"[:300]
            return []

    async def main():
        return await asyncio.gather(*(one(s) for s in servers))

    if sys.platform == "win32":  # pragma: no cover
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    for result in asyncio.run(main()):
        tools += result
    return tools, errors


def _unwrap(exc: BaseException) -> BaseException:
    while getattr(exc, "exceptions", None):   # ExceptionGroup (3.11+ / anyio)
        exc = exc.exceptions[0]
    return exc
