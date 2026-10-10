"""Orchestrates discovery, static checks, live inspection, pinning and plugins."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import discovery, instructions, live, pinning
from .integrations import Context, available_integrations, run_integrations
from .launch import analyse
from .models import ScanResult, ServerConfig, ToolInfo
from .policy import Policy
from .rules import config_rules, tool_rules
from .rules.catalog import make


@dataclass
class ScanOptions:
    paths: list[Path] = field(default_factory=list)
    project_dir: Path | None = None
    live: bool = False
    online: bool = False                 # allow network lookups (OSV)
    timeout: float = 20.0
    include_disabled: bool = False
    servers: list[str] = field(default_factory=list)   # only these names
    lockfile: Path | None = None
    update_lock: bool = False
    integrations: list[str] | None = None              # None = all available, [] = none
    source_dirs: list[Path] = field(default_factory=list)
    policy: Policy = field(default_factory=Policy)
    tools_file: Path | None = None       # offline: JSON dump of tools/list results
    instructions: bool = True            # scan CLAUDE.md, AGENTS.md, rules, skills, agent settings


def scan(opts: ScanOptions) -> ScanResult:
    result = ScanResult()
    paths = [Path(p) for p in opts.paths]
    instr_files = [p for p in paths if p.is_file() and (instructions.is_instruction_file(p)
                                                        or p.suffix.lower() in (".md", ".mdc"))]
    config_paths = [p for p in paths if p not in instr_files]
    if paths and not config_paths:
        servers, files, errors = [], [], []
    else:
        servers, files, errors = discovery.load_servers(config_paths or None, opts.project_dir)
    result.errors += errors
    if opts.servers:
        wanted = {s.lower() for s in opts.servers}
        servers = [s for s in servers if s.name.split(" [")[0].lower() in wanted]
    if not opts.include_disabled:
        servers = [s for s in servers if not s.disabled]
    result.servers = servers

    # ---------------- static configuration checks
    launches = {s.key: analyse(s) for s in servers}
    for s in servers:
        result.add(config_rules.check_server(s, launches[s.key]))
        result.add(opts.policy.check_server(s, launches[s.key]))
    result.add(config_rules.check_cross_client(servers))
    secret_files = {f.location for f in result.findings if f.rule_id in ("MB101", "MB102")}
    for path in sorted(set(files)):
        result.add(config_rules.check_file_permissions(path, path in secret_files))

    # ---------------- agent instruction files, skills and agent settings
    skill_dirs: list[Path] = []
    if opts.instructions:
        roots = [p for p in paths if p.is_dir()] if paths else [Path(opts.project_dir or Path.cwd())]
        ins = instructions.scan(roots, include_user=not paths, extra_files=instr_files)
        result.add(ins.findings)
        result.errors += ins.errors
        result.instruction_files = [t.display for t in ins.targets]
        skill_dirs = ins.skill_dirs

    # ---------------- tools: live or from a saved dump
    tools: list[ToolInfo] = []
    if opts.tools_file:
        tools += load_tools_file(opts.tools_file)
    if opts.live and servers:
        live_tools, live_errors = live.inspect_all(_unique(servers), opts.timeout)
        tools += live_tools
        for name, err in live_errors.items():
            result.add(make("MB901", name, f"Live inspection failed: {err}", location="live"))
    result.tools = tools
    if tools:
        _tool_checks(result, tools, servers, opts)

    # ---------------- pinning (rug-pull detection)
    if opts.lockfile and tools:
        lock = pinning.load_lock(opts.lockfile)
        result.add(pinning.compare(tools, lock, {t.server for t in tools}))
        if opts.update_lock or not lock.get("entries"):
            pinning.update_lock(opts.lockfile, tools, lock)

    # ---------------- external security engines
    ctx = Context(servers=servers, launches=launches, tools=tools, online=opts.online,
                  source_dirs=list(opts.source_dirs) + skill_dirs, timeout=max(opts.timeout, 60))
    names = opts.integrations
    plugins = available_integrations(names)
    findings, status = run_integrations(plugins, ctx)
    result.add(findings)
    result.integrations = status

    # ---------------- policy
    result.findings, result.suppressed = opts.policy.apply(result.findings)
    return result


def _unique(servers: list[ServerConfig]) -> list[ServerConfig]:
    """The same server is often configured in several clients; start it once."""
    seen, out = set(), []
    for s in servers:
        k = (s.name, s.command_line(), tuple(sorted(s.env.items())))
        if k not in seen:
            seen.add(k)
            out.append(s)
    return out


def _tool_checks(result: ScanResult, tools: list[ToolInfo], servers: list[ServerConfig],
                 opts: ScanOptions) -> None:
    by_server: dict[str, set[str]] = defaultdict(set)
    for t in tools:
        if t.kind == "tool":
            by_server[t.server].add(t.name)
    for t in tools:
        others = set().union(*(names for s, names in by_server.items() if s != t.server)) \
            if len(by_server) > 1 else set()
        result.add(tool_rules.check_tool(t, others))
        for pat in opts.policy.extra_injection_patterns:
            m = pat.search(t.all_text())
            if m:
                result.add(make("MB501", t.server, f"'{t.name}' matches policy pattern "
                                f"'{pat.pattern}'.", location=f"{t.kind}:{t.name}",
                                evidence=m.group(0)))
    result.add(tool_rules.check_collisions(tools))
    # toxic flows are evaluated per client (one agent = one client config)
    clients: dict[str, set[str]] = defaultdict(set)
    for s in servers:
        clients[s.client].add(s.name)
    if not clients:
        clients["agent"] = {t.server for t in tools}
    for client, names in clients.items():
        scoped = [t for t in tools if t.server in names]
        result.add(tool_rules.check_capabilities(scoped, scope=client))


def load_tools_file(path: Path) -> list[ToolInfo]:
    """Load tools from JSON: {"server": {"tools": [...]}} or [{"server":..,"name":..}]."""
    import json
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: list[ToolInfo] = []
    if isinstance(data, dict):
        for server, body in data.items():
            items = body.get("tools", body) if isinstance(body, dict) else body
            for t in items or []:
                out.append(_tool_from_dict(t, server, "tool"))
            if isinstance(body, dict):
                for p in body.get("prompts", []):
                    out.append(_tool_from_dict(p, server, "prompt"))
                if body.get("instructions"):
                    out.append(ToolInfo(server, "server-instructions", body["instructions"],
                                        kind="instructions"))
    else:
        for t in data:
            out.append(_tool_from_dict(t, t.get("server", "unknown"), t.get("kind", "tool")))
    return out


def _tool_from_dict(t: dict, server: str, kind: str) -> ToolInfo:
    return ToolInfo(server=server, name=str(t.get("name", "")),
                    description=str(t.get("description") or ""),
                    input_schema=t.get("inputSchema") or t.get("input_schema") or {},
                    kind=kind, annotations=t.get("annotations") or {})
