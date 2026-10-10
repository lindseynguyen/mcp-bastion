"""Tool pinning: remember a hash of every tool definition and report changes
(rug pulls) on later scans."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, ToolInfo
from .rules.catalog import make

LOCK_VERSION = 1


def _key(t: ToolInfo) -> str:
    return f"{t.server}::{t.kind}::{t.name}"


def load_lock(path: Path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and "entries" in data else {"entries": {}}
    except (OSError, ValueError):
        return {"entries": {}}


def compare(tools: list[ToolInfo], lock: dict, servers_scanned: set[str]) -> list[Finding]:
    entries = lock.get("entries", {})
    if not entries:
        return []
    out: list[Finding] = []
    current = {_key(t): t for t in tools}
    pinned_servers = {e["server"] for e in entries.values()}
    for key, t in current.items():
        old = entries.get(key)
        if old is None:
            if t.server in pinned_servers:
                out.append(make("MB702", t.server, f"New {t.kind} '{t.name}' was not present when "
                                "the server was pinned.", location=f"{t.kind}:{t.name}",
                                evidence=(t.description or "")[:200]))
        elif old["sha256"] != t.fingerprint():
            changed = []
            if old.get("description") != t.description:
                changed.append("description")
            if old.get("schema_sha256") != _schema_hash(t):
                changed.append("input schema")
            out.append(make("MB701", t.server, f"{t.kind.capitalize()} '{t.name}' changed since "
                            f"{old.get('pinned_at', 'it was pinned')} ({', '.join(changed) or 'definition'}).",
                            location=f"{t.kind}:{t.name}",
                            evidence=_diff_hint(old.get("description", ""), t.description)))
    for key, old in entries.items():
        if key not in current and old["server"] in servers_scanned:
            out.append(make("MB703", old["server"], f"{old['kind'].capitalize()} '{old['name']}' "
                            "is no longer offered.", location=f"{old['kind']}:{old['name']}"))
    return out


def update_lock(path: Path, tools: list[ToolInfo], lock: dict | None = None) -> dict:
    lock = lock or {"entries": {}}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    servers = {t.server for t in tools}
    entries = {k: v for k, v in lock.get("entries", {}).items() if v["server"] not in servers}
    for t in tools:
        entries[_key(t)] = {
            "server": t.server, "kind": t.kind, "name": t.name,
            "sha256": t.fingerprint(), "schema_sha256": _schema_hash(t),
            "description": t.description, "pinned_at": now,
        }
    data = {"version": LOCK_VERSION, "generator": "mcp-bastion", "updated": now,
            "entries": dict(sorted(entries.items()))}
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return data


def _schema_hash(t: ToolInfo) -> str:
    import hashlib
    return hashlib.sha256(json.dumps(t.input_schema, sort_keys=True).encode()).hexdigest()


def _diff_hint(old: str, new: str) -> str:
    old, new = old or "", new or ""
    i = 0
    while i < min(len(old), len(new)) and old[i] == new[i]:
        i += 1
    return f"…{new[max(0, i - 30): i + 170]}" if new else "(description removed)"
