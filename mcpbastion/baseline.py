"""Baselines: accept today's findings once, then only report what is new.

    mcp-bastion scan . --write-baseline .mcp-bastion-baseline.json   # once
    mcp-bastion scan . --baseline .mcp-bastion-baseline.json         # in CI

Fingerprints ignore line numbers, so editing the file around a finding does not
resurface it. CRITICAL findings are never hidden by a baseline."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import Finding, Severity


def fingerprint(f: Finding) -> str:
    key = "|".join([f.rule_id, f.server, f.location, " ".join(f.evidence.split())[:160]])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def write(path: Path, findings: list[Finding]) -> int:
    entries = sorted({fingerprint(f): {"rule": f.rule_id, "server": f.server, "location": f.location,
                                       "severity": f.severity.name.lower()}
                      for f in findings if f.severity < Severity.CRITICAL}.items())
    Path(path).write_text(json.dumps({
        "version": 1, "generator": "mcp-bastion",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "findings": {k: v for k, v in entries}}, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def load(path: Path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return set((data.get("findings") or {}).keys())


def apply(findings: list[Finding], known: set[str]) -> tuple[list[Finding], int]:
    kept, hidden = [], 0
    for f in findings:
        if f.severity < Severity.CRITICAL and fingerprint(f) in known:
            hidden += 1
        else:
            kept.append(f)
    return kept, hidden
