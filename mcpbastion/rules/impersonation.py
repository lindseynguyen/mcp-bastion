"""Impersonation: typosquatted / look-alike MCP packages and homoglyph tool names.

A malicious package only has to look like a popular one ("@modelcontextprotocol/server-githb",
"@modelcontextprotoco1/server-github", "server-filesystem" without its scope) to be launched by
an `npx -y` line copied from a blog post. Tool names that mix scripts ("send_emаil" with a
Cyrillic а) let one server impersonate another server's tool."""
from __future__ import annotations

import re
import unicodedata

from ..launch import Package
from ..models import Finding, Severity, ToolInfo
from .catalog import make

# Widely used MCP server packages (official reference servers and vendor servers).
KNOWN_NPM = {
    "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab", "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything", "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-puppeteer", "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-slack", "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-gdrive", "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-redis", "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-aws-kb-retrieval", "@modelcontextprotocol/server-everart",
    "@modelcontextprotocol/inspector", "@playwright/mcp", "@upstash/context7-mcp",
    "@notionhq/notion-mcp-server", "@stripe/mcp", "@supabase/mcp-server-supabase",
    "@sentry/mcp-server", "@cloudflare/mcp-server-cloudflare", "@azure/mcp", "@heroku/mcp-server",
    "@browsermcp/mcp", "@executeautomation/playwright-mcp-server", "@wonderwhy-er/desktop-commander",
    "@21st-dev/magic", "@atlassian/mcp-server", "@shopify/dev-mcp", "@vercel/mcp-adapter",
    "@figma/mcp", "@hubspot/mcp-server", "@paypal/mcp", "@twilio-alpha/mcp", "@neondatabase/mcp-server-neon",
    "@kimtaeyoon83/mcp-server-youtube-transcript", "@benborla29/mcp-server-mysql",
    "firecrawl-mcp", "exa-mcp-server", "mcp-remote", "tavily-mcp", "mongodb-mcp-server",
    "chrome-devtools-mcp", "figma-developer-mcp", "mcp-server-kubernetes", "airtable-mcp-server",
    "@anthropic-ai/claude-code", "@openai/codex", "@google/gemini-cli",
}
KNOWN_PYPI = {
    "mcp-server-fetch", "mcp-server-time", "mcp-server-git", "mcp-server-sqlite",
    "mcp-server-sentry", "mcp-server-qdrant", "mcp-server-motherduck", "mcp-server-docker",
    "mcp-server-kubernetes", "mcp", "fastmcp", "mcp-proxy", "mcp-atlassian", "mcp-obsidian",
    "awslabs.core-mcp-server", "awslabs.aws-documentation-mcp-server", "awslabs.cdk-mcp-server",
    "awslabs.terraform-mcp-server", "awslabs.cost-analysis-mcp-server", "serena-agent",
    "zen-mcp-server", "blender-mcp", "markitdown-mcp", "duckduckgo-mcp-server", "arxiv-mcp-server",
    "mcp-server-elasticsearch", "mcp-clickhouse", "mcp-snowflake-server", "mcp-grafana",
}
KNOWN_SCOPES = {p.split("/")[0] for p in KNOWN_NPM if p.startswith("@")}
KNOWN_PYPI = {re.sub(r"[-_.]+", "-", p) for p in KNOWN_PYPI}      # PEP 503 normal form

# Latin look-alikes from Cyrillic, Greek, Armenian and others (subset of Unicode confusables)
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ү": "y", "ҽ": "e",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c",
    "Т": "t", "Х": "x", "У": "y", "І": "i", "Ј": "j", "Ѕ": "s",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "κ": "k", "ι": "i", "υ": "u", "ε": "e",
    "Α": "a", "Β": "b", "Ε": "e", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
    "Ρ": "p", "Τ": "t", "Χ": "x", "Υ": "y", "Ζ": "z",
    "օ": "o", "ս": "u", "ց": "g", "ı": "i", "ℓ": "l", "ⅼ": "l", "ꓲ": "i",
    "0": "o", "1": "l", "|": "l", "5": "s", "_": "-", ".": "-",
})


def skeleton(name: str) -> str:
    """Normalise a name so look-alikes compare equal (NFKC, confusables, digit swaps)."""
    s = unicodedata.normalize("NFKC", name).translate(_CONFUSABLES).lower()
    s = "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))
    return s.replace("rn", "m").replace("vv", "w")


def non_ascii_letters(name: str) -> list[str]:
    return sorted({c for c in name if ord(c) > 127 and unicodedata.category(c).startswith("L")})


def distance(a: str, b: str, limit: int = 3) -> int:
    """Damerau-Levenshtein (adjacent transpositions), stops early above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def check_package(pkg: Package, server: str, location: str) -> list[Finding]:
    if pkg.ecosystem not in ("npm", "PyPI") or pkg.source != "registry":
        return []
    name = pkg.name
    known = KNOWN_NPM if pkg.ecosystem == "npm" else KNOWN_PYPI
    lname = name.lower()
    if pkg.ecosystem == "PyPI":                       # PEP 503: -, _ and . are the same name
        lname = re.sub(r"[-_.]+", "-", lname)
    if lname in known:
        return []

    def hit(msg, sev, target):
        return [make("MB206", server, msg + f" Did you mean {target}?", location=location,
                     evidence=pkg.raw, severity=sev)]

    odd = non_ascii_letters(name)
    if odd:
        target = next((k for k in known if skeleton(k) == skeleton(name)), None)
        return hit(f"Package name {name!r} contains non-ASCII letters {''.join(odd)}.",
                   Severity.CRITICAL if target else Severity.HIGH, target or "an ASCII name")
    sk = skeleton(name)
    for k in sorted(known):
        if skeleton(k) == sk:
            return hit(f"{pkg.ecosystem} package {name} is a look-alike of {k}.", Severity.HIGH, k)
    if pkg.ecosystem == "npm":
        scope, _, base = name.partition("/") if name.startswith("@") else ("", "", name)
        if scope and scope not in KNOWN_SCOPES:
            near = next((s for s in sorted(KNOWN_SCOPES) if distance(scope, s, 2) <= 2), None)
            if near:
                return hit(f"Scope {scope} imitates {near}.", Severity.HIGH, f"{near}/{base}")
        for k in sorted(known):
            k_scope, _, k_base = k.partition("/") if k.startswith("@") else ("", "", k)
            if k_scope and base == k_base and scope != k_scope and len(base) >= 8:
                return hit(f"{name} reuses the name of {k} under a different scope.", Severity.HIGH, k)
    for k in sorted(known):
        limit = 1
        if len(lname) >= 6 and 0 < distance(lname, k, limit) <= limit:
            return hit(f"{pkg.ecosystem} package {name} is one typo away from {k}.", Severity.MEDIUM, k)
    return []


def check_tool_name(tool: ToolInfo) -> list[Finding]:
    odd = non_ascii_letters(tool.name)
    if not odd:
        return []
    return [make("MB512", tool.server, f"{tool.kind.capitalize()} name {tool.name!r} contains "
                 f"non-ASCII letters ({''.join(odd)}) that look like Latin ones.",
                 location=f"{tool.kind}:{tool.name}", evidence=f"reads as {skeleton(tool.name)}")]


def check_lookalike_collisions(tools: list[ToolInfo]) -> list[Finding]:
    """Different servers exposing tools whose names look the same but are not."""
    groups: dict[str, dict[str, set[str]]] = {}
    for t in tools:
        if t.kind == "tool":
            groups.setdefault(skeleton(t.name), {}).setdefault(t.name, set()).add(t.server)
    out = []
    for names in groups.values():
        if len(names) < 2:
            continue
        servers = set().union(*names.values())
        if len(servers) < 2:
            continue
        for name, srvs in names.items():
            others = [f"{n!r} ({', '.join(sorted(s))})" for n, s in names.items() if n != name]
            plain = {re.sub(r"[-_.]", "", n.lower()) for n in names}
            sev = (Severity.CRITICAL if any(non_ascii_letters(n) for n in names)
                   else Severity.MEDIUM if len(plain) == 1 else Severity.HIGH)
            for s in sorted(srvs):
                out.append(make("MB512", s, f"Tool {name!r} looks identical to {', '.join(others)}.",
                                location=f"tool:{name}", evidence=" vs ".join(sorted(names)), severity=sev))
    return out
