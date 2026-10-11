"""Command line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, discovery, live, report
from .integrations import registry
from .models import Severity
from .rules.catalog import OWASP_ASI, OWASP_MCP, RULES
from .rules.tool_rules import decode_tag_chars, invisible_chars
from .options import ScanRequest, verdict
from .options import build as build_request
from .scanner import scan
from .secrets import scrub

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
FORMATS = ("console", "json", "sarif", "html", "md")


def _sev(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except KeyError as exc:
        raise argparse.ArgumentTypeError(f"unknown severity {value!r}") from exc


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-bastion",
        description="Offline security scanner for MCP servers and AI-agent tool configurations.")
    p.add_argument("--version", action="version", version=f"mcp-bastion {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan MCP configurations (default command)")
    s.add_argument("paths", nargs="*", type=Path,
                   help="config files or folders (default: auto-discover all known clients)")
    s.add_argument("--live", action="store_true",
                   help="start/connect to each server and analyse its tools (runs server commands!)")
    s.add_argument("--online", action="store_true",
                   help="allow network lookups (OSV vulnerability / malicious-package database)")
    s.add_argument("--server", action="append", default=[], metavar="NAME",
                   help="only scan this server (repeatable)")
    s.add_argument("--include-disabled", action="store_true")
    s.add_argument("--timeout", type=float, default=20.0, help="per-server live timeout (s)")
    s.add_argument("--lock", type=Path, metavar="FILE",
                   help="tool pin file for rug-pull detection (created on first run)")
    s.add_argument("--update-lock", action="store_true", help="accept current tools into the pin file")
    s.add_argument("--tools-file", type=Path, metavar="JSON",
                   help="analyse saved tools/list output instead of (or in addition to) --live")
    s.add_argument("--source", action="append", default=[], type=Path, metavar="DIR",
                   help="server source folder to scan with code engines (repeatable)")
    s.add_argument("--engines", default="all",
                   help="comma list of engines to use, 'all' (default) or 'none'")
    s.add_argument("--baseline", type=Path, metavar="FILE",
                   help="only report findings that are not in this baseline file")
    s.add_argument("--write-baseline", type=Path, metavar="FILE",
                   help="accept the current findings: write them to a baseline file (CRITICAL is never baselined)")
    g = s.add_argument_group("LLM judge (any OpenAI-compatible endpoint; API key from MCP_BASTION_LLM_API_KEY)")
    g.add_argument("--llm-url", metavar="URL", help="e.g. http://localhost:11434/v1 or your LiteLLM gateway "
                   "(or MCP_BASTION_LLM_URL)")
    g.add_argument("--llm-model", metavar="NAME", help="model name (or MCP_BASTION_LLM_MODEL)")
    g.add_argument("--llm-mode", choices=("review", "all"), default="review",
                   help="review: only flagged or risky-looking items (default); all: every tool and file")
    g.add_argument("--llm-no-downgrade", action="store_true",
                   help="never lower a rule finding, even when the judge says benign")
    g.add_argument("--llm-timeout", type=float, default=60.0)
    s.add_argument("--fail-score", type=int, metavar="N",
                   help="exit 1 if any server/file risk score reaches N (0-100)")
    s.add_argument("--no-instructions", action="store_true",
                   help="skip agent instruction files (CLAUDE.md, AGENTS.md, rules, skills, agent settings)")
    s.add_argument("--policy", type=Path, help="policy file (YAML or JSON)")
    s.add_argument("--project", type=Path, help="project folder for project-level configs (default: cwd)")
    s.add_argument("-f", "--format", choices=FORMATS, default="console")
    s.add_argument("-o", "--output", action="append", default=[], type=Path,
                   help="write report to file; format from extension (.json .sarif .html .md). Repeatable")
    s.add_argument("--fail-on", type=_sev, help="exit 1 if a finding reaches this severity "
                   "(default from policy, else high)")
    s.add_argument("--min-severity", type=_sev, default=Severity.LOW,
                   help="hide console findings below this severity (default low)")
    s.add_argument("-v", "--verbose", action="store_true")

    i = sub.add_parser("inspect", help="print full tool descriptions as the model sees them")
    i.add_argument("paths", nargs="*", type=Path)
    i.add_argument("--server", action="append", default=[])
    i.add_argument("--timeout", type=float, default=20.0)

    d = sub.add_parser("discover", help="list config files and servers that would be scanned")
    d.add_argument("paths", nargs="*", type=Path)
    d.add_argument("--project", type=Path)

    gu = sub.add_parser("gui", help="open the graphical interface in your browser (local only)")
    gu.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: a free one)")
    gu.add_argument("--no-browser", action="store_true", help="print the address instead of opening a browser")

    sub.add_parser("rules", help="list detection rules and OWASP mappings")
    sub.add_parser("engines", help="show which third-party engines are installed")
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):      # Windows consoles default to cp1252
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    known = {"scan", "inspect", "discover", "rules", "engines", "gui", "-h", "--help", "--version"}
    if not argv or argv[0] not in known:
        argv = ["scan", *argv]
    args = build_parser().parse_args(argv)
    try:
        return {"scan": cmd_scan, "inspect": cmd_inspect, "discover": cmd_discover, "gui": cmd_gui,
                "rules": cmd_rules, "engines": cmd_engines}[args.cmd](args)
    except KeyboardInterrupt:
        return EXIT_ERROR
    except (OSError, ValueError) as exc:
        print(f"mcp-bastion: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def request_from_args(args) -> ScanRequest:
    s = lambda v: str(v) if v is not None else None  # noqa: E731
    return ScanRequest(
        paths=[str(p) for p in args.paths], project=s(args.project), live=args.live, online=args.online,
        timeout=args.timeout, include_disabled=args.include_disabled, servers=list(args.server),
        lock=s(args.lock), update_lock=args.update_lock, tools_file=s(args.tools_file),
        sources=[str(p) for p in args.source], engines=args.engines, policy=s(args.policy),
        instructions=not args.no_instructions, baseline=s(args.baseline), llm_url=args.llm_url,
        llm_model=args.llm_model, llm_mode=args.llm_mode, llm_no_downgrade=args.llm_no_downgrade,
        llm_timeout=args.llm_timeout, fail_on=args.fail_on.name if args.fail_on else None,
        fail_score=args.fail_score)


def cmd_scan(args) -> int:
    if args.live:
        print("mcp-bastion: --live starts every configured stdio server on this machine.",
              file=sys.stderr)
    built = build_request(request_from_args(args))
    if built.options.judge:
        j = built.options.judge
        print(f"mcp-bastion: LLM judge {j.model} at {j.url} ({j.mode} mode; secrets are masked "
              "before sending)", file=sys.stderr)
    result = scan(built.options)
    if args.write_baseline:
        from . import baseline
        n = baseline.write(args.write_baseline, result.findings)
        print(f"baseline written: {args.write_baseline} ({n} findings accepted)", file=sys.stderr)

    if args.format == "console":
        report.console(result, verbose=args.verbose, min_sev=args.min_severity)
    else:
        sys.stdout.write(report.WRITERS[args.format](result) + "\n")
    for out in args.output:
        fmt = out.suffix.lstrip(".").lower()
        fmt = {"htm": "html", "markdown": "md"}.get(fmt, fmt)
        if fmt not in report.WRITERS:
            raise ValueError(f"cannot infer report format from {out}")
        out.write_text(report.WRITERS[fmt](result), encoding="utf-8")
        print(f"report written: {out}", file=sys.stderr)

    if not result.servers and not result.tools and not result.instruction_files:
        print("mcp-bastion: nothing to scan found. Pass config paths or run `mcp-bastion discover`.",
              file=sys.stderr)
    return EXIT_FINDINGS if verdict(result, built.fail_on, built.fail_score)["failed"] else EXIT_OK


def cmd_inspect(args) -> int:
    servers, _, errors = discovery.load_servers(args.paths or None)
    for e in errors:
        print(f"! {e}", file=sys.stderr)
    if args.server:
        wanted = {s.lower() for s in args.server}
        servers = [s for s in servers if s.name.split(" [")[0].lower() in wanted]
    servers = [s for s in servers if not s.disabled]
    print("mcp-bastion: starting servers to read their tools…", file=sys.stderr)
    tools, errs = live.inspect_all(servers, args.timeout)
    for name, err in errs.items():
        print(f"! {name}: {err}", file=sys.stderr)
    current = None
    for t in tools:
        if t.server != current:
            current = t.server
            print(f"\n=== {current} ===")
        print(f"\n[{t.kind}] {t.name}   sha256:{t.fingerprint()[:12]}")
        inv = invisible_chars(t.all_text())
        if inv:
            print(f"  ⚠ invisible characters: {inv}")
            hidden = decode_tag_chars(t.all_text())
            if hidden:
                print(f"  ⚠ hidden text: {hidden}")
        print(_visible(t.description) or "  (no description)")
        props = (t.input_schema or {}).get("properties") or {}
        for pname, spec in props.items():
            desc = spec.get("description", "") if isinstance(spec, dict) else ""
            print(f"  - {pname}: {_visible(desc)}")
    return EXIT_OK if not errs else EXIT_ERROR


def _visible(text: str) -> str:
    """Show invisible characters as <U+XXXX> so reviewers can see them."""
    out = []
    for ch in text or "":
        cp = ord(ch)
        if cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF) or 0x202A <= cp <= 0x202E \
                or 0x2066 <= cp <= 0x2069 or 0xE0000 <= cp <= 0xE007F:
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    return "".join(out)


def cmd_discover(args) -> int:
    servers, files, errors = discovery.load_servers(args.paths or None, args.project)
    if not files:
        print("No MCP client configuration found.")
    else:
        print("MCP configurations:")
    for f in files:
        print(f"{f}")
        for s in (x for x in servers if x.config_path == f):
            state = " (disabled)" if s.disabled else ""
            print(f"  - {s.name} [{s.transport}]{state}: {scrub(s.command_line())}")
    from . import instructions
    roots = [p for p in args.paths if p.is_dir()] if args.paths else [args.project or Path.cwd()]
    targets = instructions.discover(roots, include_user=not args.paths)
    if targets:
        print("\nAgent instruction files:")
        for t in targets:
            print(f"  - {t.display} [{t.kind}]")
    for e in errors:
        print(f"! {e}", file=sys.stderr)
    return EXIT_OK


def cmd_gui(args) -> int:
    from .gui.server import run
    return run(port=args.port, open_browser=not args.no_browser)


def cmd_rules(_args) -> int:
    for r in RULES.values():
        tags = ", ".join([*r.mcp, *r.asi])
        print(f"{r.id}  {r.severity.name:<8} {r.title}  [{tags}]")
    print("\nOWASP MCP Top 10:")
    for k, v in OWASP_MCP.items():
        print(f"  {k} {v}")
    print("OWASP Top 10 for Agentic Applications:")
    for k, v in OWASP_ASI.items():
        print(f"  {k} {v}")
    return EXIT_OK


def cmd_engines(_args) -> int:
    for p in registry():
        ok, why = p.available()
        net = " (needs --online)" if p.needs_network else ""
        print(f"{'✓' if ok else '✗'} {p.name:<15} {p.description}{net}" + ("" if ok else f"  → {why}"))
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
