"""Report writers: console, JSON, SARIF 2.1.0, Markdown and self-contained HTML."""
from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .models import ScanResult, Severity
from .rules.catalog import OWASP_ASI, OWASP_MCP, RULES
from .secrets import scrub

COLORS = {Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m",
          Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[36m", Severity.INFO: "\033[2m"}
RESET = "\033[0m"


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


# --------------------------------------------------------------------- console
def console(result: ScanResult, stream=None, verbose: bool = False, min_sev: Severity = Severity.INFO) -> None:
    stream = stream or sys.stdout
    color = _use_color(stream)

    def c(sev: Severity, text: str) -> str:
        return f"{COLORS[sev]}{text}{RESET}" if color else text

    w = stream.write
    w(f"mcp-bastion {__version__} - {len(result.servers)} server(s), {len(result.tools)} "
      f"tool/prompt definition(s), {len(result.instruction_files)} agent instruction file(s) inspected\n")
    for e in result.errors:
        w(f"  ! {e}\n")
    findings = [f for f in result.sorted_findings() if f.severity >= min_sev]
    worst: dict[str, int] = {}
    for f in findings:
        worst[f.server] = max(worst.get(f.server, 0), int(f.severity))
    findings.sort(key=lambda f: (-worst[f.server], f.server, -f.severity, f.rule_id))
    current = None
    for f in findings:
        if f.server != current:
            current = f.server
            w(f"\n■ {current}\n")
        tag = c(f.severity, f"[{f.severity.name}]")
        loc = f"  ({f.location}{':' + str(f.line) if f.line else ''})" if f.location else ""
        w(f"  {tag} {f.rule_id} {f.title}{loc}\n")
        w(f"      {f.message}\n")
        if f.evidence and (verbose or f.severity >= Severity.MEDIUM):
            w(f"      ↳ {f.evidence}\n")
        if verbose:
            w(f"      fix: {f.remediation}\n")
            w(f"      OWASP: {', '.join(f.owasp_mcp + f.owasp_asi)}  [{f.source}]\n")
    counts = result.counts()
    w("\n" + "  ".join(c(Severity[k.upper()], f"{k}: {v}") for k, v in counts.items()))
    if result.suppressed:
        w(f"  (suppressed by policy: {result.suppressed})")
    w("\n")
    if result.integrations:
        w("engines: " + "; ".join(f"{k} {v}" for k, v in result.integrations.items()) + "\n")


# --------------------------------------------------------------------- JSON
def to_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "mcp-bastion", "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": result.counts(), "suppressed": result.suppressed,
        "integrations": result.integrations, "errors": result.errors,
        "servers": [{"name": s.name, "client": s.client, "config": s.config_path,
                     "transport": s.transport, "command": scrub(s.command_line())} for s in result.servers],
        "tools": [{"server": t.server, "kind": t.kind, "name": t.name,
                   "sha256": t.fingerprint()} for t in result.tools],
        "instruction_files": result.instruction_files,
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------- SARIF
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}
SECURITY_SCORE = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                  Severity.LOW: "3.0", Severity.INFO: "1.0"}


def to_sarif(result: ScanResult) -> str:
    used = sorted({f.rule_id for f in result.findings})
    rules = []
    for rid in used:
        r = RULES[rid]
        rules.append({
            "id": rid, "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.title},
            "help": {"text": r.remediation, "markdown": f"**Fix:** {r.remediation}\n\nOWASP: "
                     + ", ".join(f"{m} {OWASP_MCP[m]}" for m in r.mcp)},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity]},
            "properties": {"tags": ["security", *r.mcp, *r.asi],
                           "security-severity": SECURITY_SCORE[r.severity]},
        })
    results = []
    for f in result.sorted_findings():
        uri = f.location if f.location and not f.location.startswith(("tool:", "prompt:", "resource:",
                                                                      "instructions:", "live")) else None
        loc: dict = {"physicalLocation": {"artifactLocation": {"uri": _uri(uri or f.location or "mcp")}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": int(f.line)}
        results.append({
            "ruleId": f.rule_id, "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"[{f.server}] {f.message}" + (f" — {f.evidence}" if f.evidence else "")},
            "locations": [loc],
            "partialFingerprints": {"mcpBastion/v1": "|".join(map(str, f.dedup_key))},
            "properties": {"server": f.server, "engine": f.source,
                           "security-severity": SECURITY_SCORE[f.severity]},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "mcp-bastion", "version": __version__,
                                      "informationUri": "https://github.com/lindseynguyen/mcp-bastion",
                                      "rules": rules}},
                  "results": results}],
    }, indent=2, ensure_ascii=False)


def _uri(path: str) -> str:
    p = path.replace("\\", "/")
    try:
        rel = os.path.relpath(p) if os.path.isabs(p) else p
        if not rel.startswith(".."):
            return rel
    except ValueError:
        pass
    return p


# --------------------------------------------------------------------- Markdown
def to_markdown(result: ScanResult) -> str:
    counts = result.counts()
    lines = ["## 🛡️ mcp-bastion report", "",
             " · ".join(f"**{k}** {v}" for k, v in counts.items()), "",
             f"{len(result.servers)} servers · {len(result.tools)} tool definitions · "
             f"{len(result.instruction_files)} instruction files", ""]
    findings = result.sorted_findings()
    if not findings:
        lines.append("No findings. ✅")
    else:
        lines += ["| Severity | Rule | Server | Finding |", "|---|---|---|---|"]
        for f in findings:
            msg = f.message.replace("|", "\\|")
            lines.append(f"| {f.severity.name} | {f.rule_id} | `{f.server}` | {msg} |")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------- HTML
def to_html(result: ScanResult) -> str:
    counts = result.counts()
    esc = html.escape
    rows = []
    for f in result.sorted_findings():
        sev = f.severity.name.lower()
        owasp = " ".join(f'<span class="tag" title="{esc(OWASP_MCP.get(t) or OWASP_ASI.get(t, ""))}">{t}</span>'
                         for t in f.owasp_mcp + f.owasp_asi)
        loc = esc(f.location) + (f":{f.line}" if f.line else "")
        rows.append(f"""
<details class="f {sev}" data-sev="{sev}">
  <summary><span class="sev {sev}">{f.severity.name}</span><code>{f.rule_id}</code>
  <span class="title">{esc(f.title)}</span><span class="srv">{esc(f.server)}</span></summary>
  <div class="body">
    <p>{esc(f.message)}</p>
    {f'<pre>{esc(f.evidence)}</pre>' if f.evidence else ''}
    <p class="fix"><b>Fix:</b> {esc(f.remediation)}</p>
    <p class="meta">{owasp} <span class="loc">{loc}</span> <span class="eng">{esc(f.source)}</span></p>
  </div>
</details>""")
    servers = "".join(
        f"<tr><td>{esc(s.name)}</td><td>{esc(s.client)}</td><td>{esc(s.transport)}</td>"
        f"<td><code>{esc(scrub(s.command_line())[:140])}</code></td></tr>" for s in result.servers)
    engines = "".join(f"<li><b>{esc(k)}</b> {esc(v)}</li>" for k, v in result.integrations.items())
    tiles = "".join(f'<button class="tile {k}" data-filter="{k}"><b>{v}</b>{k}</button>'
                    for k, v in counts.items())
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Bastion Report</title>
<style>
:root{{--bg:#f7f7f5;--card:#fff;--fg:#1d1f23;--mut:#666b73;--line:#e3e3df;
--crit:#b3261e;--high:#d9480f;--med:#b8860b;--low:#1c7ed6;--info:#868e96}}
@media (prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#121316;--card:#1b1d21;--fg:#e8e8e6;
--mut:#9aa0a8;--line:#2c2f35;--crit:#ff6b6b;--high:#ff922b;--med:#fcc419;--low:#4dabf7;--info:#adb5bd}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1040px;margin:0 auto;padding:28px 16px 60px}}
h1{{font-size:24px;margin:0}}h2{{font-size:17px;margin:32px 0 10px}}
.sub{{color:var(--mut);margin:4px 0 20px}}
.tiles{{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px;
color:var(--mut);font:inherit;text-transform:capitalize;cursor:pointer;text-align:left}}
.tile b{{display:block;font-size:26px;color:var(--fg)}}.tile.on{{outline:2px solid var(--fg)}}
.tile.critical b{{color:var(--crit)}}.tile.high b{{color:var(--high)}}.tile.medium b{{color:var(--med)}}
.tile.low b{{color:var(--low)}}
details.f{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);
border-radius:8px;margin:6px 0}}
details.critical{{border-left-color:var(--crit)}}details.high{{border-left-color:var(--high)}}
details.medium{{border-left-color:var(--med)}}details.low{{border-left-color:var(--low)}}
summary{{cursor:pointer;padding:10px 12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}}
.sev{{font-size:11px;font-weight:700;letter-spacing:.04em;min-width:64px}}
.sev.critical{{color:var(--crit)}}.sev.high{{color:var(--high)}}.sev.medium{{color:var(--med)}}
.sev.low{{color:var(--low)}}.sev.info{{color:var(--info)}}
.title{{flex:1;min-width:200px}}.srv{{color:var(--mut);font-family:ui-monospace,monospace;font-size:13px}}
.body{{padding:0 14px 12px 14px}}pre{{white-space:pre-wrap;word-break:break-word;background:var(--bg);
border:1px solid var(--line);padding:8px 10px;border-radius:6px;font-size:13px}}
.tag{{display:inline-block;font-size:11px;border:1px solid var(--line);border-radius:4px;padding:0 5px;margin-right:3px}}
.meta{{color:var(--mut);font-size:13px}}.loc,.eng{{margin-left:8px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;
overflow:hidden;font-size:13px}}td{{padding:6px 10px;border-top:1px solid var(--line);vertical-align:top}}
td code{{word-break:break-all}}ul{{padding-left:18px;color:var(--mut)}}
.empty{{background:var(--card);border:1px solid var(--line);padding:24px;border-radius:8px;text-align:center}}
@media (max-width:600px){{.tiles{{grid-template-columns:repeat(3,1fr)}}td:nth-child(4){{display:none}}}}
</style></head><body><main>
<h1>MCP Bastion report</h1>
<p class="sub">{len(result.servers)} servers · {len(result.tools)} tool definitions · {len(result.instruction_files)} instruction files · {generated} · v{__version__}</p>
<div class="tiles">{tiles}</div>
<h2>Findings</h2>
{''.join(rows) or '<div class="empty">No findings ✅</div>'}
<h2>Servers</h2><table>{servers or '<tr><td>No servers found</td></tr>'}</table>
<h2>Engines</h2><ul>{engines or '<li>none</li>'}</ul>
{'<h2>Errors</h2><ul>' + ''.join(f'<li>{esc(e)}</li>' for e in result.errors) + '</ul>' if result.errors else ''}
</main>
<script>
document.querySelectorAll('.tile').forEach(t=>t.addEventListener('click',()=>{{
 const on=!t.classList.contains('on');document.querySelectorAll('.tile').forEach(x=>x.classList.remove('on'));
 if(on)t.classList.add('on');const k=on?t.dataset.filter:null;
 document.querySelectorAll('details.f').forEach(d=>d.style.display=!k||d.dataset.sev===k?'':'none');}}));
</script></body></html>"""


WRITERS = {"json": to_json, "sarif": to_sarif, "md": to_markdown, "markdown": to_markdown,
           "html": to_html}
