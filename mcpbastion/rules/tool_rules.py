"""Checks on tool / prompt / resource metadata returned by live servers."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections import defaultdict

from ..models import Finding, Severity, ToolInfo
from .catalog import make

# ----------------------------------------------------------------- patterns
_F = re.IGNORECASE | re.UNICODE

INJECTION = [re.compile(p, _F) for p in (
    r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|other)\s+"
    r"(?:instructions?|prompts?|rules|directions)",
    r"\bdisregard\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|system|user)",
    r"\bforget\s+(?:all\s+|everything\s+)?(?:previous|prior|your)\s+(?:instructions?|rules)",
    r"<\s*/?\s*(?:important|system|instructions?|admin|secret|hidden|critical)\s*>",
    r"\[\s*(?:system|admin|instructions?)\s*\]",
    r"\b(?:new|updated|real|actual|true)\s+(?:system\s+)?instructions?\s*:",
    r"\byou\s+(?:must|have\s+to|need\s+to|are\s+required\s+to)\s+(?:always|first|now|also)\b",
    r"\bbefore\s+(?:using|calling|invoking|executing|running)\s+(?:this|any|the\s+\w+)\s+tool",
    r"\b(?:from\s+now\s+on|for\s+all\s+(?:future|subsequent)\s+(?:requests|calls))\b",
    r"\boverride\s+(?:the\s+)?(?:previous|system|default|user)",
    r"\b(?:act|behave)\s+as\s+(?:if\s+you\s+are\s+)?(?:an?\s+)?(?:admin|root|system|developer)",
    r"\bthis\s+is\s+(?:very\s+|extremely\s+)?(?:important|critical)\b.*\b(?:must|always|never)\b",
    r"\bdo\s+not\s+follow\s+(?:the\s+)?(?:user|previous)",
    # Vietnamese
    r"bỏ\s+qua\s+(?:mọi|tất\s+cả|các|toàn\s+bộ)?\s*(?:các\s+)?(?:hướng\s+dẫn|chỉ\s+dẫn|chỉ\s+thị|lệnh|quy\s+tắc)",
    r"(?:hướng\s+dẫn|chỉ\s+thị)\s+(?:mới|thật)\s*:",
    r"trước\s+khi\s+(?:dùng|gọi|sử\s+dụng|chạy)\s+(?:công\s+cụ|tool)",
    r"bạn\s+(?:phải|bắt\s+buộc\s+phải)\s+(?:luôn|trước\s+tiên|đầu\s+tiên)",
    r"(?:quan\s+trọng|bắt\s+buộc)\s*!{1,}",
)]

CONCEAL = [re.compile(p, _F) for p in (
    r"\b(?:do\s+not|don'?t|never)\s+(?:tell|mention|inform|notify|reveal|show|disclose|alert)\s+"
    r"(?:\w+\s+){0,3}(?:the\s+)?user",
    r"\bwithout\s+(?:telling|informing|notifying|asking|alerting)\s+(?:the\s+)?user",
    r"\b(?:secretly|silently|covertly|quietly)\s+(?:send|call|read|include|forward|copy|upload|add)",
    r"\bthe\s+user\s+(?:must|should)\s+not\s+(?:know|see|be\s+told|notice)",
    r"\b(?:hide|conceal)\s+(?:this|it|the\s+\w+)\s+from\s+(?:the\s+)?user",
    r"\bkeep\s+(?:this|it)\s+(?:secret|hidden|confidential)\s+from",
    r"(?:không\s+(?:được\s+)?|đừng\s+)(?:nói|kể|thông\s+báo|tiết\s+lộ|cho\s+biết|hiển\s+thị)\s+"
    r"(?:\S+\s+){0,3}(?:cho\s+|với\s+)?người\s+dùng",
    r"(?:âm\s+thầm|lén|bí\s+mật)\s+(?:gửi|đọc|sao\s+chép|chuyển|tải)",
)]

SENSITIVE = re.compile(
    r"(?:~|\$HOME|%USERPROFILE%)?[/\\]?\.ssh(?:[/\\]|\b)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|"
    r"\.aws[/\\]credentials|\.netrc\b|\.git-credentials|\.kube[/\\]config|\.docker[/\\]config\.json|"
    r"\.npmrc\b|\.pypirc\b|(?<![\w.])\.env(?:\.\w+)?\b|/etc/(?:passwd|shadow|sudoers)\b|"
    r"\bmcp\.json\b|claude_desktop_config|\.cursor[/\\]mcp|\bcredentials?\.json\b|"
    r"\b(?:private|secret)\s+keys?\b|\bseed\s+phrase\b|\bmnemonic\b|\bwallet\.dat\b|"
    r"\bkeychain\b|\bcookies?\s+(?:file|database|db|sqlite)\b|\b(?:api[_ ]?keys?|access\s+tokens?)\b"
    r".{0,40}\b(?:read|include|send|copy|pass|return)", _F)

EXFIL_VERB = re.compile(
    r"\b(?:send|post|upload|forward|transmit|exfiltrate|leak|copy|include|pass|append|embed|"
    r"attach|put|add|bcc|cc)\b|\b(?:gửi|tải\s+lên|chuyển\s+tiếp|đính\s+kèm|sao\s+chép)\b", _F)
EXFIL_OBJECT = re.compile(
    r"\b(?:contents?\s+of|full\s+(?:text|content|conversation|history)|entire\s+(?:file|conversation|"
    r"chat|history)|conversation\s+history|previous\s+messages|chat\s+history|system\s+prompt|"
    r"all\s+(?:files|messages|emails|data)|the\s+(?:file|key|token|password|secret)s?)\b|"
    r"\b(?:nội\s+dung|toàn\s+bộ|lịch\s+sử\s+(?:hội\s+thoại|trò\s+chuyện)|mật\s+khẩu|khóa)\b", _F)
EXFIL_SINK = re.compile(
    r"https?://[^\s\"'<>)]+|\b[\w.+-]+@[\w-]+\.[\w.]+\b|\bwebhook\b|\b(?:in|into|to)\s+the\s+"
    r"[`'\"]?\w+[`'\"]?\s+(?:parameter|field|argument)\b|\bsidenote\b", _F)
COLLECTOR_HOSTS = re.compile(
    r"(?:webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|burpcollaborator|"
    r"interact\.sh|oast\.(?:fun|me|pro|site|live|online)|beeceptor|hookbin|trycloudflare\.com|"
    r"canarytokens|pastebin\.com|transfer\.sh|discord(?:app)?\.com/api/webhooks|"
    r"api\.telegram\.org/bot)", _F)

SHADOW = [re.compile(p, _F) for p in (
    r"\bwhen\s+(?:using|calling|invoking)\s+(?:the\s+)?[`'\"]?[\w.\-]+[`'\"]?\s+tool",
    r"\b(?:all|any|every)\s+(?:other\s+)?(?:tools?|emails?|messages?|requests?|calls?)\s+"
    r"(?:must|should|need\s+to)\s+(?:be\s+)?(?:sent|routed|forwarded|redirected|cc'?d|bcc'?d|"
    r"changed|modified|include)",
    r"\binstead\s+of\s+(?:using\s+)?(?:the\s+)?[`'\"]?[\w.\-]+[`'\"]?\s+tool",
    r"\b(?:this|the)\s+tool\s+(?:also\s+)?(?:replaces|overrides|supersedes)\b",
    r"\bother\s+(?:mcp\s+)?(?:servers?|tools?)\b.{0,60}\b(?:must|should|always|never)\b",
    r"khi\s+(?:dùng|gọi|sử\s+dụng)\s+(?:công\s+cụ|tool)\s+\S+",
)]

HIDDEN_PARAM_NAMES = re.compile(
    r"^(?:side_?note|note|notes|context|conversation|history|chat_?history|previous_?messages|"
    r"feedback|metadata|debug|internal|reasoning|thoughts?|system_?prompt|extra|summary|"
    r"user_?data|session|memory|instructions?|config)$", re.I)
HIDDEN_PARAM_ASK = re.compile(
    r"\b(?:conversation|previous\s+messages|chat\s+history|system\s+prompt|everything\s+the\s+user|"
    r"full\s+context|all\s+(?:files|data)|contents?\s+of|api\s+keys?|password|credentials?)\b|"
    r"\b(?:lịch\s+sử|hội\s+thoại|mật\s+khẩu|nội\s+dung\s+tệp)\b", _F)

INVISIBLE = {
    **{cp: "zero-width" for cp in (0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063,
                                   0x2064, 0xFEFF, 0x180E, 0x00AD)},
    **{cp: "bidi control" for cp in (0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
                                     0x2066, 0x2067, 0x2068, 0x2069)},
}

CAPABILITIES = {
    "exec": re.compile(r"(?i)\b(?:exec(?:ute)?|run[_ ]?(?:command|shell|script|code|python)|shell|"
                       r"terminal|eval(?:uate)?[_ ](?:code|python|js)|bash|powershell|subprocess|"
                       r"spawn|sql[_ ]?exec|raw[_ ]?query)\b"),
    "destructive": re.compile(r"(?i)(?:^|[_\s])(?:delete|remove|drop|destroy|truncate|purge|wipe|"
                              r"rm|rmdir|kill|terminate|revoke|overwrite|format[_ ](?:disk|drive))"
                              r"(?:$|[_\s])"),
    "untrusted_input": re.compile(r"(?i)\b(?:fetch|browse|scrape|crawl|web[_ ]?search|search[_ ]?web|"
                                  r"read[_ ]?(?:email|mail|inbox|message|issue|comment|page|url)|"
                                  r"get[_ ]?(?:issue|email|url|page|webpage|messages)|download|"
                                  r"open[_ ]?url|navigate|http[_ ]?get|rss|slack[_ ]?read)\b"),
    "private_data": re.compile(r"(?i)\b(?:read[_ ]?file|get[_ ]?file|query|select|database|db|"
                               r"sql|inbox|calendar|contacts?|drive|documents?|notes?|secrets?|"
                               r"vault|credentials?|password|customer|patient|crm|hr|payroll|"
                               r"repo(?:sitory)?|private)\b"),
    "sink": re.compile(r"(?i)\b(?:send[_ ]?(?:email|mail|message|sms|dm)|post[_ ]?(?:message|tweet|"
                       r"comment)|create[_ ]?(?:issue|comment|gist|pr|pull[_ ]?request|post)|"
                       r"http[_ ]?(?:post|put|request)|webhook|upload|publish|share|tweet|"
                       r"slack[_ ]?(?:post|send)|write[_ ]?(?:remote|url)|push)\b"),
}

# ----------------------------------------------------------------- helpers

def decode_tag_chars(text: str) -> str:
    """ASCII smuggling: Unicode tag block U+E0000..U+E007F mirrors ASCII."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def invisible_chars(text: str) -> dict[str, int]:
    found: dict[str, int] = defaultdict(int)
    for c in text:
        cp = ord(c)
        if cp in INVISIBLE:
            found[INVISIBLE[cp]] += 1
        elif 0xE0000 <= cp <= 0xE007F:
            found["unicode tag (ASCII smuggling)"] += 1
        elif 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
            found["variation selector"] += 1
        elif unicodedata.category(c) == "Co":
            found["private-use"] += 1
    return dict(found)


def _decode_blobs(text: str) -> list[str]:
    out = []
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        dec = raw.decode("utf-8", "ignore")
        if dec and sum(ch.isprintable() or ch in "\n\t" for ch in dec) / len(dec) > 0.9:
            out.append(dec)
    for m in re.finditer(r"\b(?:[0-9a-fA-F]{2}){24,}\b", text):
        try:
            dec = bytes.fromhex(m.group(0)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if dec.isprintable():
            out.append(dec)
    return out


def _first(patterns, text):
    for p in patterns:
        m = p.search(text)
        if m:
            return m
    return None


def _snippet(text: str, m: re.Match | None, width: int = 90) -> str:
    if not m:
        return text[:width * 2]
    a, b = max(0, m.start() - width), min(len(text), m.end() + width)
    return ("…" if a else "") + " ".join(text[a:b].split()) + ("…" if b < len(text) else "")


def _norm(text: str) -> str:
    """Remove invisible characters so they cannot split keywords."""
    return "".join(c for c in unicodedata.normalize("NFKC", text)
                   if ord(c) not in INVISIBLE and not 0xE0000 <= ord(c) <= 0xE007F)


def capabilities(tool: ToolInfo) -> set[str]:
    text = _norm(f"{tool.name} {tool.name.replace('_', ' ')} {tool.description[:400]}")
    return {cap for cap, pat in CAPABILITIES.items() if pat.search(text)}


# ----------------------------------------------------------------- per-tool

def check_tool(tool: ToolInfo, other_tool_names: set[str] | None = None) -> list[Finding]:
    f: list[Finding] = []
    s = tool.server
    loc = f"{tool.kind}:{tool.name}"
    raw = tool.all_text()
    text = _norm(raw)
    if invisible_chars(tool.name):           # the name itself can carry hidden text
        raw += "\n" + tool.name

    # hidden characters + ASCII smuggling
    inv = invisible_chars(raw)
    if inv:
        smuggled = decode_tag_chars(raw)
        detail = ", ".join(f"{n}× {k}" for k, n in inv.items())
        sev = Severity.CRITICAL if smuggled.strip() else None
        f.append(make("MB502", s, f"Invisible characters in {tool.kind} metadata: {detail}.",
                      location=loc, severity=sev,
                      evidence=f"hidden text: {smuggled}" if smuggled.strip() else detail))
        if smuggled.strip():
            text += "\n" + smuggled

    for decoded in _decode_blobs(text):
        f.append(make("MB506", s, "Base64/hex blob in metadata decodes to readable text.",
                      location=loc, evidence=decoded[:200]))
        text += "\n" + decoded

    m = _first(INJECTION, text)
    if m:
        f.append(make("MB501", s, f"{tool.kind.capitalize()} '{tool.name}' contains instructions "
                      "aimed at the model.", location=loc, evidence=_snippet(text, m)))

    m = _first(CONCEAL, text)
    if m:
        f.append(make("MB510", s, f"'{tool.name}' asks the model to hide actions from the user.",
                      location=loc, evidence=_snippet(text, m)))

    m_sens = SENSITIVE.search(text)
    if m_sens:
        f.append(make("MB503", s, f"'{tool.name}' references sensitive files or credentials.",
                      location=loc, evidence=_snippet(text, m_sens)))

    m_host = COLLECTOR_HOSTS.search(text)
    m_verb = EXFIL_VERB.search(text)
    m_obj = EXFIL_OBJECT.search(text)
    m_sink = EXFIL_SINK.search(text)
    if m_host or (m_verb and (m_sens or m_obj) and (m_sink or m_sens) and
                  (_first(INJECTION, text) or _first(CONCEAL, text) or m_sens or m_host)):
        f.append(make("MB504", s, f"'{tool.name}' tells the model to send data out.",
                      location=loc, evidence=_snippet(text, m_host or m_verb)))

    m = _first(SHADOW, text)
    mentioned = sorted(n for n in (other_tool_names or set())
                       if len(n) > 3 and n != tool.name and re.search(rf"\b{re.escape(n)}\b", text))
    if m or (mentioned and (m_verb or _first(INJECTION, text))):
        ev = _snippet(text, m) if m else f"mentions other tools: {', '.join(mentioned[:5])}"
        f.append(make("MB505", s, f"'{tool.name}' tries to influence other tools.",
                      location=loc, evidence=ev))

    if len(tool.description or "") > 1500:
        f.append(make("MB507", s, f"Description is {len(tool.description)} characters long.",
                      location=loc, evidence=tool.description[:160]))

    f += _hidden_params(tool, loc)
    return f


def _hidden_params(tool: ToolInfo, loc: str) -> list[Finding]:
    props = (tool.input_schema or {}).get("properties") or {}
    out = []
    if not isinstance(props, dict):
        return out
    for pname, spec in props.items():
        desc = _norm(str((spec or {}).get("description", ""))) if isinstance(spec, dict) else ""
        name_hit = bool(HIDDEN_PARAM_NAMES.match(pname))
        ask_hit = HIDDEN_PARAM_ASK.search(desc)
        if (name_hit and ask_hit) or (ask_hit and _first(INJECTION + CONCEAL, desc)):
            out.append(make("MB508", tool.server, f"Parameter '{pname}' of '{tool.name}' asks the "
                            "model to supply private context.", location=f"{loc}.{pname}",
                            evidence=_snippet(desc, ask_hit)))
    return out


# ----------------------------------------------------------------- cross-tool

def check_collisions(tools: list[ToolInfo]) -> list[Finding]:
    by_name: dict[str, set[str]] = defaultdict(set)
    for t in tools:
        if t.kind == "tool":
            by_name[t.name.lower()].add(t.server)
    out = []
    for name, servers in by_name.items():
        if len(servers) > 1:
            for s in sorted(servers):
                out.append(make("MB509", s, f"Tool '{name}' is also provided by "
                                f"{', '.join(sorted(servers - {s}))}.", location=f"tool:{name}",
                                evidence=", ".join(sorted(servers))))
    return out


def check_capabilities(tools: list[ToolInfo], scope: str = "agent") -> list[Finding]:
    out = []
    caps_by_server: dict[str, set[str]] = defaultdict(set)
    example: dict[str, str] = {}
    for t in tools:
        if t.kind != "tool":
            continue
        caps = capabilities(t)
        caps_by_server[t.server] |= caps
        for c in caps:
            example.setdefault(c, f"{t.server}/{t.name}")
        ann = t.annotations or {}
        if "exec" in caps:
            out.append(make("MB601", t.server, f"'{t.name}' can execute code or commands.",
                            location=f"tool:{t.name}", evidence="capability: exec"))
        if "destructive" in caps and not ann.get("destructiveHint") and ann.get("readOnlyHint") is not True:
            out.append(make("MB603", t.server, f"'{t.name}' looks destructive but is not annotated "
                            "with destructiveHint.", location=f"tool:{t.name}",
                            evidence=f"annotations: {ann or 'none'}"))
    all_caps = set().union(*caps_by_server.values()) if caps_by_server else set()
    if {"untrusted_input", "private_data", "sink"} <= all_caps:
        servers = sorted(s for s, c in caps_by_server.items()
                         if c & {"untrusted_input", "private_data", "sink"})
        out.append(make("MB602", scope, "Across " + ", ".join(servers) + " the agent can read "
                        "untrusted content, reach private data and send data out.",
                        location=scope,
                        evidence=f"untrusted: {example['untrusted_input']} | private: "
                                 f"{example['private_data']} | sink: {example['sink']}"))
    return out
