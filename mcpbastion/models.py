"""Core data structures shared by every part of the scanner."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        return cls[str(value).strip().upper()]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name.lower()


@dataclass
class ServerConfig:
    """One MCP server entry found in a client configuration file."""

    name: str
    client: str                      # "claude-desktop", "cursor", "vscode", "file", ...
    config_path: str
    transport: str = "stdio"         # stdio | http | sse
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    disabled: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.client}:{self.name}"

    def command_line(self) -> str:
        if self.transport != "stdio":
            return self.url or ""
        return " ".join([self.command or "", *self.args]).strip()


@dataclass
class ToolInfo:
    """A tool, prompt or resource exposed by a live server."""

    server: str
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    kind: str = "tool"               # tool | prompt | resource | instructions
    annotations: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        payload = json.dumps(
            {"kind": self.kind, "name": self.name, "description": self.description,
             "schema": self.input_schema},
            sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def all_text(self) -> str:
        """Description plus every description/title nested in the input schema."""
        parts = [self.description or ""]
        parts.extend(_schema_texts(self.input_schema))
        return "\n".join(p for p in parts if p)


def _schema_texts(node: Any) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("description", "title", "default", "examples") and isinstance(v, str):
                out.append(v)
            elif k == "enum" and isinstance(v, list):
                out.extend(str(x) for x in v)
            else:
                out.extend(_schema_texts(v))
    elif isinstance(node, list):
        for item in node:
            out.extend(_schema_texts(item))
    return out


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    server: str
    message: str
    location: str = ""               # config path, "tool:<name>", file:line ...
    evidence: str = ""
    remediation: str = ""
    owasp_mcp: list[str] = field(default_factory=list)
    owasp_asi: list[str] = field(default_factory=list)
    source: str = "mcp-bastion"      # which engine produced it
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name.lower()
        return d

    @property
    def dedup_key(self) -> tuple:
        return (self.rule_id, self.server, self.location, self.evidence[:120])


@dataclass
class ScanResult:
    servers: list[ServerConfig] = field(default_factory=list)
    tools: list[ToolInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    integrations: dict[str, str] = field(default_factory=dict)   # name -> status
    instruction_files: list[str] = field(default_factory=list)
    suppressed: int = 0
    inline_suppressed: int = 0
    baselined: int = 0

    def add(self, findings: list[Finding] | Finding) -> None:
        items = [findings] if isinstance(findings, Finding) else findings
        seen = {f.dedup_key for f in self.findings}
        for f in items:
            if f.dedup_key not in seen:
                self.findings.append(f)
                seen.add(f.dedup_key)

    def counts(self) -> dict[str, int]:
        c = {s.name.lower(): 0 for s in reversed(Severity)}
        for f in self.findings:
            c[f.severity.name.lower()] += 1
        return c

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity, f.server, f.rule_id, f.location))
