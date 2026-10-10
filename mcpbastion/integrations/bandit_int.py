"""PyCQA Bandit on Python MCP server source code."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ..models import Finding, Severity
from ..rules.catalog import make
from . import Context, Integration, run_cmd, which

SEV = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
# Secrets are covered by detect-secrets/gitleaks; import-blacklist warnings (B4xx)
# only say "this module exists" and drown the real findings.
SKIP = ("B105", "B106", "B107", "B4")


class Bandit(Integration):
    name = "bandit"
    description = "Bandit static analysis for Python server code"

    def _cmd(self) -> list[str] | None:
        exe = which("bandit")
        if exe:
            return [exe]
        try:
            import bandit  # noqa: F401
            return [sys.executable, "-m", "bandit"]
        except ImportError:
            return None

    def available(self):
        return (True, "") if self._cmd() else (False, "pip install bandit")

    def run(self, ctx: Context) -> list[Finding]:
        out = []
        for server, root in ctx.sources():
            if root.is_file() and root.suffix != ".py":
                continue
            if root.is_dir() and not any(root.rglob("*.py")):
                continue
            cmd = [*self._cmd(), "-f", "json", "-q"]
            if root.is_dir():
                cmd += ["-r", str(root), "-x", ",".join(str(root / d) for d in
                                                        (".venv", "venv", "node_modules", "build"))]
            else:
                cmd.append(str(root))
            proc = run_cmd(cmd, ctx.timeout)
            try:
                data = json.loads(proc.stdout or "{}")
            except ValueError as exc:
                raise RuntimeError((proc.stderr or "bandit produced no JSON").strip()[:150]) from exc
            for r in data.get("results", []):
                tid = r.get("test_id", "")
                if r.get("issue_confidence") == "LOW" or tid.startswith(SKIP):
                    continue
                sev = SEV.get(r.get("issue_severity", "LOW"), Severity.LOW)
                out.append(make("MB801", server, f"{tid} {r.get('issue_text')}",
                                location=_rel(r.get("filename", ""), root), line=r.get("line_number"),
                                evidence=_line(r), severity=sev, source=self.name,
                                title=f"Bandit {tid}: {r.get('test_name')}"))
        return out


def _line(r: dict) -> str:
    """Only the flagged line from bandit's numbered code excerpt."""
    want = str(r.get("line_number"))
    for ln in (r.get("code") or "").splitlines():
        num, _, code = ln.partition(" ")
        if num == want:
            return code.strip()[:200]
    return (r.get("code") or "").strip().splitlines()[0][:200] if r.get("code") else ""


def _rel(path: str, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve().parent))
    except ValueError:
        return path
