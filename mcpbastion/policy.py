"""Organisation policy: allow/block lists, suppressions and severity overrides.

Example (YAML or JSON):

    fail_on: high
    allowed_servers: ["filesystem", "github", "internal-*"]
    allowed_packages: ["@modelcontextprotocol/*", "mcp-server-fetch"]
    blocked_packages: ["*-mcp-free", "mcp-*-crack*"]
    blocked_urls: ["*.ngrok*", "*webhook.site*"]
    severity_overrides: {MB202: info}
    ignore:
      - rule: MB402
        server: "internal-*"
        reason: "OAuth handled by the gateway"
"""
from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .launch import Launch
from .models import Finding, ServerConfig, Severity
from .rules.catalog import make


@dataclass
class Policy:
    fail_on: Severity = Severity.HIGH
    allowed_servers: list[str] = field(default_factory=list)
    allowed_packages: list[str] = field(default_factory=list)
    blocked_packages: list[str] = field(default_factory=list)
    blocked_urls: list[str] = field(default_factory=list)
    ignore: list[dict] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    extra_injection_patterns: list[re.Pattern] = field(default_factory=list)
    inline_ignores: bool = True
    max_risk_score: int | None = None

    @classmethod
    def load(cls, path: str | Path | None) -> "Policy":
        if not path:
            return cls()
        text = Path(path).read_text(encoding="utf-8")
        if str(path).endswith((".yml", ".yaml")):
            try:
                import yaml
            except ImportError as exc:
                raise SystemExit("PyYAML is needed for YAML policies: pip install pyyaml") from exc
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        return cls(
            fail_on=Severity.parse(data.get("fail_on", "high")),
            allowed_servers=list(data.get("allowed_servers", [])),
            allowed_packages=list(data.get("allowed_packages", [])),
            blocked_packages=list(data.get("blocked_packages", [])),
            blocked_urls=list(data.get("blocked_urls", [])),
            ignore=list(data.get("ignore", [])),
            severity_overrides={k: Severity.parse(v) for k, v in
                                (data.get("severity_overrides") or {}).items()},
            extra_injection_patterns=[re.compile(p, re.I) for p in
                                      data.get("extra_injection_patterns", [])],
            inline_ignores=bool(data.get("inline_ignores", True)),
            max_risk_score=data.get("max_risk_score"),
        )

    # ------------------------------------------------------------------ checks
    def check_server(self, srv: ServerConfig, launch: Launch) -> list[Finding]:
        out = []
        base = srv.name.split(" [")[0]
        pkgs = [p.name for p in launch.packages] + [p.raw for p in launch.packages]
        for pat in self.blocked_packages:
            hit = next((p for p in pkgs if fnmatch.fnmatch(p.lower(), pat.lower())), None)
            if hit:
                out.append(make("MB404", srv.name, f"Package '{hit}' matches blocked pattern '{pat}'.",
                                location=srv.config_path, evidence=srv.command_line()))
        for pat in self.blocked_urls:
            if srv.url and fnmatch.fnmatch(srv.url.lower(), pat.lower()):
                out.append(make("MB404", srv.name, f"URL matches blocked pattern '{pat}'.",
                                location=srv.config_path, evidence=srv.url))
        if self.allowed_servers or self.allowed_packages:
            ok = any(fnmatch.fnmatch(base, p) for p in self.allowed_servers) or (
                pkgs and all(any(fnmatch.fnmatch(p, a) for a in self.allowed_packages)
                             for p in [x.name for x in launch.packages]))
            if not ok:
                out.append(make("MB403", srv.name, f"'{base}' is not on the approved list.",
                                location=srv.config_path, evidence=srv.command_line()))
        return out

    def apply(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        kept, dropped = [], 0
        for f in findings:
            if f.rule_id in self.severity_overrides:
                f.severity = self.severity_overrides[f.rule_id]
            if any(self._matches(rule, f) for rule in self.ignore):
                dropped += 1
                continue
            kept.append(f)
        return kept, dropped

    @staticmethod
    def _matches(rule: dict, f: Finding) -> bool:
        if not isinstance(rule, dict):
            return False
        checks = [("rule", f.rule_id), ("server", f.server.split(" [")[0]), ("location", f.location)]
        return all(fnmatch.fnmatch(val, str(rule[key])) for key, val in checks if key in rule)
