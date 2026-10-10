"""Checks for agent instruction files (CLAUDE.md, AGENTS.md, Cursor/Windsurf/Cline
rules, Copilot instructions, Claude skills/commands) and agent settings.

Instruction files are legitimately imperative ("always run the tests"), so these
rules look for what a normal file never needs: hidden text, exfiltration,
concealment, authority claims, safety bypasses and dangerous commands.
Statements that forbid something ("never run rm -rf /") are not reported."""
from __future__ import annotations

import re
import unicodedata

from ..models import Finding, Severity
from .catalog import make
from .tool_rules import (COLLECTOR_HOSTS, CONCEAL, EXFIL_OBJECT, EXFIL_SINK, EXFIL_VERB,
                         SENSITIVE, _decode_blobs)

_F = re.IGNORECASE | re.UNICODE

OVERRIDE = [re.compile(p, _F) for p in (
    r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system|user'?s?)\s+"
    r"(?:instructions?|prompts?|rules|messages?)",
    r"\bdisregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|system|user)",
    r"\bforget\s+(?:all\s+|everything\s+)?(?:previous|prior|your)\s+(?:instructions?|rules)",
    r"<\s*/?\s*(?:system|admin|hidden|secret)(?:[\s_-]?(?:prompt|instructions?))?\s*>",
    r"\[\s*(?:system|admin)\s*(?:message|prompt)?\s*\]",
    r"\b(?:new|updated|real|actual)\s+system\s+(?:prompt|instructions?)\b",
    r"\boverride\s+(?:the\s+|your\s+)?(?:system|safety|previous)\s+(?:prompt|instructions?|rules)",
    r"\b(?:these|this)\s+instructions?\s+(?:take|takes)\s+precedence\s+over\s+(?:the\s+)?(?:system|user|anthropic|openai)",
    r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|god|unrestricted)\s*mode",
    r"bỏ\s+qua\s+(?:mọi|tất\s+cả|các|toàn\s+bộ)?\s*(?:các\s+)?(?:hướng\s+dẫn|chỉ\s+dẫn|chỉ\s+thị)\s+"
    r"(?:trước|hệ\s+thống|của\s+người\s+dùng)",
)]

BYPASS_STRONG = [re.compile(p, _F) for p in (
    r"--dangerously-skip-permissions", r"--dangerously-bypass-approvals-and-sandbox",
    r"--yolo\b", r"--approval-mode[= ]yolo", r"--trust-all-tools", r"--allow-all-tools",
    r"\bbypassPermissions\b", r"\bdanger-full-access\b",
    r"\bapproval[_-]policy\s*=\s*[\"']?never",
    r"\b(?:disable|turn\s+off|bypass|circumvent|skip|evade)\s+(?:the\s+|any\s+|all\s+)?"
    r"(?:sandbox(?:ing)?|guardrails?|safety\s+(?:checks?|filters?|guidelines|rules)|"
    r"permission\s+(?:checks?|prompts?|system)|content\s+filters?|security\s+(?:checks?|controls?|scanning)|"
    r"secret\s+scanning|push\s+protection)",
    r"\bauto-?approve\s+(?:all|every|any)\b",
    r"(?:tắt|vô\s+hiệu\s+hóa|bỏ\s+qua)\s+(?:sandbox|kiểm\s+tra\s+bảo\s+mật|cơ\s+chế\s+an\s+toàn|guardrail)",
)]

BYPASS_SOFT = [re.compile(p, _F) for p in (
    r"\b(?:without|no\s+need\s+to)\s+(?:asking|ask|requesting|waiting\s+for)\s+(?:the\s+user\s+)?"
    r"(?:for\s+)?(?:permission|confirmation|approval)",
    r"\bnever\s+ask\s+(?:the\s+user\s+)?(?:for\s+)?(?:permission|confirmation|approval)",
    r"\b(?:do\s+not|don'?t)\s+(?:ask|wait)\s+(?:the\s+user\s+)?for\s+(?:permission|confirmation|approval)",
    r"không\s+cần\s+(?:hỏi|xin)\s+(?:xác\s+nhận|phép|ý\s+kiến)",
)]

DESTRUCTIVE = [re.compile(p, _F) for p in (
    r"\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME|\*|/\*|\.\./\.\.)(?=[\s;&|`'\")]|$)",
    r"\bmkfs(?:\.\w+)?\s+/dev/", r"\bdd\s+if=\S+\s+of=/dev/(?:sd|nvme|disk|hd)",
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
    r"\bchmod\s+-R\s+0?777\s+/(?=\s|$)",
    r"\bRemove-Item\b[^\n]*-Recurse[^\n]*(?:C:\\(?:\s|$)|\$env:USERPROFILE|~(?:\s|$))",
    r"\bformat\s+[a-z]:\s*/[qy]",
)]

PERSISTENCE = [re.compile(p, _F) for p in (
    r">>?\s*(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|zshrc|profile|bash_profile|zprofile)",
    r"\bauthorized_keys\b",
    r"\|\s*crontab\s+-(?:\s|$)|\bcrontab\s+-l\s*[;|]",
    r"\blaunchctl\s+(?:load|bootstrap)\b", r"\bschtasks\s+/create\b",
    r"\\CurrentVersion\\Run\b",
    r"\bgit\s+config\s+(?:--global\s+)?core\.hooksPath\b",
)]

# curl/wget/etc. sending file contents, environment or secret variables
CMD_EXFIL = [re.compile(p, _F) for p in (
    r"\b(?:curl|wget|http|https|iwr|irm|invoke-webrequest|invoke-restmethod|nc|ncat|socat)\b[^\n]{0,200}?"
    r"(?:\$\(\s*(?:cat|env|printenv|base64|tar|gpg)\b|`(?:cat|env|printenv)\b|"
    r"@\s*[\"']?(?:~|\$HOME|\.)?/?[\w./-]*(?:\.env\b|id_rsa|id_ed25519|id_ecdsa|credentials|\.npmrc|\.pypirc|"
    r"\.netrc|\.git-credentials|\.kube/config|\.aws/))",
    r"\b(?:env|printenv|set)\b\s*\|\s*(?:curl|wget|nc|ncat|base64)\b",
    r"\bcat\s+[^|\n]*(?:\.env\b|id_rsa|id_ed25519|credentials|\.npmrc|\.netrc|\.aws/)[^|\n]*\|\s*(?:curl|wget|nc|ncat)",
    r"(?:-d|--data(?:-\w+)?|-F|--form|--upload-file|[?&]\w+=)\s*[\"']?[^\s\"']*\$\{?[A-Z_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY)",
)]

SENSITIVE_READ = re.compile(
    r"\b(?:cat|type|less|more|head|tail|read|open|print|echo|output|show|display|dump|include|"
    r"paste|copy|attach|base64|get-content|đọc|in\s+ra|hiển\s+thị)\b[^\n.]{0,60}?"
    r"(?:~/?\.ssh/|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\.aws/credentials|\.netrc\b|\.git-credentials|"
    r"\.kube/config|\.docker/config\.json|\.npmrc\b|\.pypirc\b|(?<![\w.])\.env(?:\.\w+)?\b|"
    r"/etc/shadow\b|\bwallet\.dat\b|\bkeychain\b|\bcredentials?\.json\b|"
    r"claude_desktop_config|\.cursor/mcp\.json|\.claude\.json\b)", _F)

# the same in code: no sentence boundaries, so dots are allowed
SENSITIVE_READ_CODE = re.compile(
    r"\b(?:open|read_text|read_bytes|readFile(?:Sync)?|fs\.promises\.readFile|Get-Content|cat|type|"
    r"File\.ReadAll\w*|io\.open)\b[^\n]{0,80}?(?:\.ssh[/\\]|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|"
    r"\.aws[/\\]credentials|(?<![\w.])\.env\b|\.netrc\b|\.npmrc\b|\.kube[/\\]config|"
    r"\.git-credentials|credentials\.json|claude_desktop_config|\.cursor[/\\]mcp\.json)", _F)

# Claude Code memory imports: "@path" pulls the file into context
IMPORT = re.compile(r"(?:^|\s)@((?:~|\.{1,2}|\$HOME)?/[^\s)\]`'\"]+)", re.M)

NEGATION = re.compile(r"\b(?:never|not|no|avoid|don'?t|doesn'?t|mustn'?t|shouldn'?t|forbid(?:den)?|"
                      r"prohibit(?:ed)?|under\s+no\s+circumstances|không|đừng|cấm|tránh)\b"
                      r"|n't\b", _F)

# download-and-execute as written in docs/shell; Markdown tables use "|" too, so a
# pipe only counts when a download command precedes it on the same line
DOWNLOAD_EXEC = re.compile(
    r"(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n]*?\|\s*(?:sudo\s+)?"
    r"(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby|iex|invoke-expression|pwsh|powershell)\b"
    r"|\b(?:iex|invoke-expression)\s*\(?\s*\(?\s*(?:iwr|irm|invoke-webrequest|invoke-restmethod|"
    r"new-object\s+(?:system\.)?net\.webclient)"
    r"|(?:ba|z)?sh\s+-c\s+[\"']?\$\(\s*(?:curl|wget)"
    r"|(?:ba|z)?sh\s+<\(\s*(?:curl|wget)"
    r"|\bbase64\s+(?:-d|--decode)\b[^\n]*\|\s*(?:ba|z)?sh\b"
    r"|-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}", _F)

TRUSTED_INSTALLERS = re.compile(
    r"https://(?:astral\.sh/|sh\.rustup\.rs|get\.docker\.com|bun\.sh/install|deno\.land/install|"
    r"install\.python-poetry\.org|get\.pnpm\.io|raw\.githubusercontent\.com/(?:nvm-sh|Homebrew)/|"
    r"ollama\.com/install\.sh|pyenv\.run|get\.sdkman\.io|claude\.ai/install\.sh|mise\.run|"
    r"cli\.github\.com|fnm\.vercel\.app/install)", _F)

HIDDEN_BLOCKS = [
    ("HTML comment", re.compile(r"<!--(.*?)-->", re.S)),
    ("Markdown comment", re.compile(r"^\[(?://|comment|_)\]:\s*#\s*[(\"'](.*?)[)\"']\s*$", re.M | re.I)),
    ("hidden HTML element", re.compile(
        r"<(\w+)[^>]*style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
        r"font-size\s*:\s*0|opacity\s*:\s*0(?:[;\"'\s]))[^\"']*[\"'][^>]*>(.*?)</\1>", re.S | re.I)),
]
AGENT_DIRECTED = re.compile(
    r"\b(?:you|your|agents?|assistants?|claude|copilot|cursor|gemini|codex|ai|llms?|models?|always|must|never|"
    r"run|execute|read|send|upload|ignore|tool|bạn|luôn|phải|chạy|gửi|đọc)\b", _F)


# --------------------------------------------------------------------- helpers

def hidden_characters(text: str) -> tuple[dict[str, int], str]:
    """Invisible characters that matter, ignoring the ones emoji legitimately use.
    Returns (counts, decoded hidden payload)."""
    counts: dict[str, int] = {}
    smuggled = []
    prev = ""
    chars = list(text)
    for i, ch in enumerate(chars):
        cp = ord(ch)
        kind = None
        if 0xE0000 <= cp <= 0xE007F:
            # tag sequences after U+1F3F4 are subdivision flags (e.g. England)
            j = i
            while j > 0 and 0xE0000 <= ord(chars[j - 1]) <= 0xE007F:
                j -= 1
            if not (j > 0 and ord(chars[j - 1]) == 0x1F3F4):
                kind = "unicode tag (ASCII smuggling)"
                if 0xE0020 <= cp <= 0xE007E:
                    smuggled.append(chr(cp - 0xE0000))
        elif 0xE0100 <= cp <= 0xE01EF:
            kind = "variation selector (emoji smuggling)"
        elif cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
            kind = "bidi control"
        elif cp in (0x200B, 0x200C, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E):
            kind = "zero-width"
        elif cp == 0xFEFF and i > 0:
            kind = "zero-width"
        elif cp == 0x200D:
            nxt = chars[i + 1] if i + 1 < len(chars) else ""
            if not (_is_emoji(prev) and _is_emoji(nxt)):
                kind = "zero-width"
        elif unicodedata.category(ch) == "Co" and not 0xE000 <= cp <= 0xF8FF:
            kind = "private-use"
        if kind:
            counts[kind] = counts.get(kind, 0) + 1
        if not (0xFE00 <= cp <= 0xFE0F):
            prev = ch
    payload = "".join(smuggled) or decode_variation_selectors(text)
    return counts, payload


def _is_emoji(ch: str) -> bool:
    if not ch:
        return False
    cp = ord(ch)
    return cp >= 0x1F000 or 0x2600 <= cp <= 0x27BF or 0x2190 <= cp <= 0x21FF or cp in (0x2640, 0x2642)


def decode_variation_selectors(text: str) -> str:
    """'Emoji smuggling': bytes hidden as variation selectors after a visible char
    (VS1-16 = 0-15, VS17-256 = 16-255)."""
    data = bytearray()
    for ch in text:
        cp = ord(ch)
        if 0xE0100 <= cp <= 0xE01EF:
            data.append(cp - 0xE0100 + 16)
        elif 0xFE00 <= cp <= 0xFE0F and data:
            data.append(cp - 0xFE00)
    if len(data) < 4:
        return ""
    decoded = data.decode("utf-8", "ignore")
    return decoded if sum(c.isprintable() for c in decoded) >= 0.9 * len(decoded) else ""


def _strip_invisible(text: str) -> str:
    out = []
    for ch in unicodedata.normalize("NFKC", text):
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F or 0xE0100 <= cp <= 0xE01EF or cp in (
                0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                0x2066, 0x2067, 0x2068, 0x2069, 0x00AD):
            continue
        out.append(ch)
    return "".join(out)


def _negated(text: str, start: int) -> bool:
    """True when the match sits in a sentence that forbids it."""
    line_start = text.rfind("\n", 0, start) + 1
    window = text[max(line_start, start - 70):start]
    window = re.split(r"[.!?;]\s", window)[-1]       # same sentence only
    return bool(NEGATION.search(window))


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snip(text: str, start: int, end: int, width: int = 70) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    return ("…" if a else "") + " ".join(text[a:b].split()) + ("…" if b < len(text) else "")


def _paragraphs(text: str):
    """(offset, paragraph) pairs; fenced code blocks stay whole."""
    pos = 0
    for block in re.split(r"(\n\s*\n)", text):
        if block.strip():
            yield pos, block
        pos += len(block)


# --------------------------------------------------------------------- analysis

class _Hit:
    __slots__ = ("rule", "start", "end", "message", "severity")

    def __init__(self, rule, start, end, message, severity=None):
        self.rule, self.start, self.end, self.message, self.severity = rule, start, end, message, severity


def _analyse(text: str, kind: str) -> list[_Hit]:
    """Run every detector on one piece of text. kind: instructions | script."""
    hits: list[_Hit] = []
    prose = kind != "script"

    def first_unnegated(patterns, rule, msg, sev=None, allow_negation=False):
        for p in patterns:
            for m in p.finditer(text):
                if allow_negation or not _negated(text, m.start()):
                    hits.append(_Hit(rule, m.start(), m.end(), msg, sev))
                    return

    if prose:
        first_unnegated(OVERRIDE, "MB1106", "claims authority over system or user instructions")
        first_unnegated(CONCEAL, "MB1102", "tells the agent to keep actions from the user",
                        allow_negation=True)
        first_unnegated(BYPASS_STRONG, "MB1105", "turns off agent safety controls")
        if not any(h.rule == "MB1105" for h in hits):
            first_unnegated(BYPASS_SOFT, "MB1105", "tells the agent to act without asking for approval",
                            Severity.MEDIUM)

    # exfiltration: shell commands anywhere, natural language per paragraph
    for p in CMD_EXFIL:
        m = p.search(text)
        if m and not _negated(text, m.start()):
            hits.append(_Hit("MB1103", m.start(), m.end(), "sends files, environment or secrets over the network"))
            break
    if prose and not any(h.rule == "MB1103" for h in hits):
        for off, para in _paragraphs(text):
            verb = EXFIL_VERB.search(para)
            if not verb or _negated(para, verb.start()):
                continue
            host = COLLECTOR_HOSTS.search(para)
            sens = SENSITIVE.search(para)
            obj = EXFIL_OBJECT.search(para)
            sink = EXFIL_SINK.search(para)
            if host or ((sens or obj) and sink and (sens or obj).start() > verb.start() - 80):
                anchor = host or verb
                hits.append(_Hit("MB1103", off + anchor.start(), off + anchor.end(),
                                 "tells the agent to send data to an outside destination"))
                break

    # dangerous commands
    for m in DOWNLOAD_EXEC.finditer(text):
        if _negated(text, m.start()):
            continue
        line = text[text.rfind("\n", 0, m.start()) + 1: text.find("\n", m.end()) if "\n" in text[m.end():] else len(text)]
        if TRUSTED_INSTALLERS.search(line):
            continue
        hits.append(_Hit("MB1104", m.start(), m.end(), "downloads and executes remote code"))
        break
    for patterns, msg in ((DESTRUCTIVE, "runs a destructive command"),
                          (PERSISTENCE, "installs persistence (shell profile, SSH keys, scheduled tasks or hooks)")):
        for p in patterns:
            m = p.search(text)
            if m and not _negated(text, m.start()):
                hits.append(_Hit("MB1104", m.start(), m.end(), msg))
                break

    # credentials into context
    if not any(h.rule == "MB1103" for h in hits):
        m = (SENSITIVE_READ_CODE if not prose else SENSITIVE_READ).search(text)
        if m and (not prose or not _negated(text, m.start())):
            hits.append(_Hit("MB1109", m.start(), m.end(), "tells the agent to read or print credentials"))
    if prose:
        for m in IMPORT.finditer(text):
            if SENSITIVE.search(m.group(1)) or re.search(r"\.ssh|\.aws|\.env\b|credentials|\.netrc", m.group(1)):
                hits.append(_Hit("MB1109", m.start(1) - 1, m.end(1),
                                 f"imports {m.group(1)} into the agent's context", Severity.HIGH))
                break
    return hits


def check_text(text: str, display: str, kind: str = "instructions") -> list[Finding]:
    """Analyse one instruction file / skill / script. `display` is the path shown in reports."""
    findings: list[Finding] = []
    raw = text

    # 1) hidden characters (+ decoded payload)
    counts, payload = hidden_characters(raw)
    if counts:
        detail = ", ".join(f"{n}× {k}" for k, n in counts.items())
        first = next((i for i, ch in enumerate(raw) if _strip_invisible(ch) == "" and ord(ch) > 0x7F), 0)
        sev = Severity.CRITICAL if payload.strip() else (
            Severity.LOW if set(counts) == {"private-use"} else None)
        findings.append(make("MB1101", display, f"Invisible characters: {detail}.", location=display,
                             line=_line(raw, first), severity=sev,
                             evidence=f"hidden text: {payload}" if payload.strip() else detail))

    visible = _strip_invisible(raw)
    rendered = visible                 # what a human sees: hidden blocks blanked, lines kept
    segments: list[tuple[str, str, int]] = []   # (origin, text, line offset)
    hidden_blocks: list[tuple[str, str, int]] = []

    # 2) text hidden from rendered Markdown
    if kind != "script":
        for label, pat in HIDDEN_BLOCKS:
            for m in pat.finditer(visible):
                inner = m.group(m.lastindex or 1).strip()
                if len(inner) < 20:
                    continue
                line0 = _line(visible, m.start())
                hidden_blocks.append((label, inner, line0))
                inner_start = m.start(m.lastindex or 1)
                segments.append((label, m.group(m.lastindex or 1), _line(visible, inner_start) - 1))
                rendered = rendered[:m.start()] + re.sub(r"[^\n]", " ", m.group(0)) + rendered[m.end():]
    segments.insert(0, ("", rendered, 0))

    # 3) encoded payloads
    for decoded in _decode_blobs(visible):
        if len(re.findall(r"[A-Za-zÀ-ỹ]{3,}", decoded)) >= 3:
            findings.append(make("MB1108", display, "Base64/hex blob decodes to readable text.",
                                 location=display, evidence=decoded[:200]))
            segments.append(("encoded payload", decoded, 0))
    if payload.strip():
        segments.append(("invisible characters", payload, 0))

    # 4) run detectors on every segment
    seen: set[tuple[str, str]] = set()
    flagged_hidden: set[int] = set()
    for origin, seg, line_offset in segments:
        hits = _analyse(seg, kind)
        if hits and origin in ("HTML comment", "Markdown comment", "hidden HTML element"):
            flagged_hidden.add(line_offset)
        for h in hits:
            if (h.rule, origin) in seen:
                continue
            seen.add((h.rule, origin))
            hidden = bool(origin)
            msg = h.message[0].upper() + h.message[1:]
            if hidden:
                msg += f" — hidden in {origin}"
            sev = h.severity
            if hidden and (sev or make(h.rule, "", "").severity) < Severity.CRITICAL:
                sev = Severity(min(int(sev or make(h.rule, "", "").severity) + 1, int(Severity.CRITICAL)))
            line = (line_offset + _line(seg, h.start)) if origin in ("", "HTML comment", "Markdown comment",
                                                                     "hidden HTML element") else None
            findings.append(make(h.rule, display, msg + ".", location=display, line=line,
                                 evidence=_snip(seg, h.start, h.end), severity=sev))

    # 5) hidden blocks: always worth a look when they hold agent-directed text
    for label, inner, line0 in hidden_blocks:
        dangerous = any(line0 - 1 <= off <= line0 + inner.count("\n") for off in flagged_hidden)
        if dangerous or (len(inner) >= 60 and len(AGENT_DIRECTED.findall(inner)) >= 3):
            findings.append(make("MB1107", display, f"{label} holds instructions that do not show when "
                                 "the file is rendered.", location=display, line=line0,
                                 evidence=" ".join(inner.split())[:200],
                                 severity=Severity.HIGH if dangerous else Severity.LOW))
    return findings
