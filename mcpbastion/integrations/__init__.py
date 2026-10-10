"""Optional third-party security engines.

Each integration declares whether it is installed and runs only when it is.
Every engine's results are mapped onto mcp-bastion rule IDs so reports, policy
suppressions and SARIF output treat them like built-in findings."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..launch import Launch, source_roots
from ..models import Finding, ServerConfig, ToolInfo


@dataclass
class Context:
    servers: list[ServerConfig]
    launches: dict[str, Launch]
    tools: list[ToolInfo]
    online: bool = False
    source_dirs: list[Path] = field(default_factory=list)
    timeout: float = 60.0

    def sources(self) -> list[tuple[str, Path]]:
        """(server name, directory) pairs to scan as source code."""
        out: list[tuple[str, Path]] = [("source", Path(p)) for p in self.source_dirs]
        for s in self.servers:
            for root in source_roots(self.launches[s.key]):
                out.append((s.name, root))
        resolved: list[tuple[str, Path, Path]] = []
        for name, p in out:
            try:
                if p.exists():
                    resolved.append((name, p, p.resolve()))
            except OSError:
                continue
        uniq = []
        for name, p, rp in resolved:
            # skip anything already covered by another (broader) root
            covered = any(other != rp and (other == rp or other in rp.parents)
                          for _, _, other in resolved)
            if not covered and rp not in [r for _, _, r in uniq]:
                uniq.append((name, p, rp))
        return [(n, p) for n, p, _ in uniq]


class Integration:
    name = "base"
    description = ""
    needs_network = False

    def available(self) -> tuple[bool, str]:
        return False, "not implemented"

    def run(self, ctx: Context) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


def which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def run_cmd(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")


def registry() -> list[Integration]:
    from .bandit_int import Bandit
    from .detect_secrets_int import DetectSecrets
    from .gitleaks_int import Gitleaks
    from .llm_guard_int import LLMGuard
    from .osv_int import OSV
    from .semgrep_int import Semgrep
    return [DetectSecrets(), LLMGuard(), Semgrep(), Bandit(), Gitleaks(), OSV()]


def available_integrations(selected: list[str] | None) -> list[Integration]:
    plugins = registry()
    if selected is None:
        return plugins
    wanted = {s.strip().lower() for s in selected}
    if "all" in wanted:
        return plugins
    return [p for p in plugins if p.name in wanted]


def run_integrations(plugins: list[Integration], ctx: Context
                     ) -> tuple[list[Finding], dict[str, str]]:
    findings: list[Finding] = []
    status: dict[str, str] = {}
    for p in plugins:
        if p.needs_network and not ctx.online:
            status[p.name] = "skipped: needs --online"
            continue
        ok, why = p.available()
        if not ok:
            status[p.name] = f"skipped: {why}"
            continue
        try:
            got = p.run(ctx)
        except Exception as exc:  # noqa: BLE001 - one engine must not break the scan
            status[p.name] = f"error: {type(exc).__name__}: {exc}"[:200]
            continue
        findings += got
        status[p.name] = f"ok ({len(got)} finding{'s' if len(got) != 1 else ''})"
    return findings, status
