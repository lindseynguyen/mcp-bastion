"""Semgrep with bundled MCP-specific rules (command injection, path traversal,
SSRF in tool handlers, SQL injection, unsafe deserialization, TLS off).
Runs fully offline: --metrics=off and only the local rule file.

Install semgrep in its own environment (it pins an older `mcp` SDK):
    pipx install semgrep"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import Finding, Severity
from ..rules.catalog import make
from . import Context, Integration, run_cmd, which

RULES = Path(__file__).with_name("semgrep_rules.yml")
SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


class Semgrep(Integration):
    name = "semgrep"
    description = "Semgrep with bundled MCP server rules (+ your own via MCP_BASTION_SEMGREP_CONFIG)"

    def available(self):
        return (True, "") if which("semgrep") else (False, "pipx install semgrep")

    def run(self, ctx: Context) -> list[Finding]:
        sources = ctx.sources()
        if not sources:
            return []
        configs = ["--config", str(RULES)]
        extra = os.environ.get("MCP_BASTION_SEMGREP_CONFIG")
        if extra:
            for c in extra.split(os.pathsep):
                configs += ["--config", c]
        out = []
        for server, root in sources:
            proc = run_cmd([which("semgrep"), "scan", *configs, "--json", "--metrics=off",
                            "--quiet", "--disable-version-check", "--no-git-ignore", "--timeout", "30",
                            "--exclude", "node_modules", "--exclude", ".venv",
                            "--exclude", "venv", "--exclude", "dist", str(root)], ctx.timeout * 3)
            try:
                data = json.loads(proc.stdout or "{}")
            except ValueError as exc:
                raise RuntimeError((proc.stderr or "semgrep produced no JSON").strip()[:150]) from exc
            fatal = [e.get("message", "") for e in data.get("errors", [])
                     if "config" in e.get("message", "").lower() or e.get("level") == "error"
                     and "Syntax error" not in e.get("message", "")]
            if fatal and not data.get("results"):
                raise RuntimeError(fatal[0].splitlines()[0][:150])
            for r in data.get("results", []):
                extra_ = r.get("extra", {})
                rule = r.get("check_id", "").rsplit(".", 1)[-1]
                out.append(make("MB801", server, extra_.get("message", rule),
                                location=_rel(r.get("path", ""), root),
                                line=(r.get("start") or {}).get("line"),
                                evidence=(extra_.get("lines") or "").strip()[:200],
                                severity=SEV.get(extra_.get("severity", "WARNING"), Severity.MEDIUM),
                                source=self.name, title=f"Semgrep {rule}"))
        return out


def _rel(path: str, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve().parent))
    except ValueError:
        return path
