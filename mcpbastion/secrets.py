"""Built-in secret detection used when detect-secrets is not installed.
Values are always masked before they reach a report."""
from __future__ import annotations

import math
import re

# (label, pattern) - provider formats with low false-positive rates
PROVIDER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Anthropic API key", re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}"
                                  r"|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("Notion token", re.compile(r"\b(?:secret|ntn)_[A-Za-z0-9]{40,}\b")),
    ("Atlassian token", re.compile(r"\bATATT3x[A-Za-z0-9_\-=]{50,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("Connection string with password",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)://[^:/\s]+:[^@/\s]{3,}@")),
]

SECRET_NAME = re.compile(
    r"(?i)(?:^|[_\-.])(?:api[_\-]?key|apikey|secret|token|passw(?:or)?d|pwd|auth|credential|"
    r"private[_\-]?key|access[_\-]?key|client[_\-]?secret|bearer|cookie|session)(?:$|[_\-.])")

PLACEHOLDER = re.compile(
    r"(?i)^(?:<.*>|\$\{.*\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_]+%|\{\{.*\}\}|x{4,}|\*{3,}|"
    r"your[_\- ].*|changeme|change[_\-]me|example|placeholder|todo|none|null|true|false|"
    r"secret|password|token|redacted|dummy|test|xxx.*|\.\.\.)$")

# references to a secret store / env indirection are fine
INDIRECTION = re.compile(r"\$\{(?:env|input|secret|keychain|op)[:.][^}]+\}|^op://|^vault:|^keychain:")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {c: value.count(c) for c in set(value)}
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in freq.values())


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-2:]} (len {len(value)})"


_URL_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.\-]*://[^:/\s@]+:)([^@/\s]+)(@)", re.I)
_URL_SECRET_PARAM = re.compile(
    r"([?&](?:[\w\-]*(?:key|token|secret|sig|signature|auth|pass(?:word)?|pwd|code)[\w\-]*)=)([^&#\s\"'<]+)",
    re.I)
_FLAG_SECRET = re.compile(
    r"(--?[\w\-]*(?:key|token|secret|pass(?:word)?|pwd|auth|credential)[\w\-]*[= ]\s*)([^\s\"']{8,})", re.I)


def scrub(text: str) -> str:
    """Mask every secret-looking value in free text before it reaches a report."""
    if not text:
        return text
    for _, pat in PROVIDER_PATTERNS:
        text = pat.sub(lambda m: mask(m.group(0)), text)
    text = _URL_USERINFO.sub(lambda m: m.group(1) + "****" + m.group(3), text)
    text = _URL_SECRET_PARAM.sub(lambda m: m.group(1) + "****", text)
    text = _FLAG_SECRET.sub(lambda m: m.group(1) + (m.group(2) if INDIRECTION.search(m.group(2))
                                                     else mask(m.group(2))), text)
    return text


def find_provider_secrets(text: str) -> list[tuple[str, str]]:
    hits = []
    for label, pat in PROVIDER_PATTERNS:
        for m in pat.finditer(text or ""):
            hits.append((label, m.group(0)))
    return hits


def looks_like_secret_value(name: str, value: str) -> str | None:
    """Return a label if `value` stored under `name` looks like a real secret."""
    value = (value or "").strip()
    if not value or INDIRECTION.search(value) or PLACEHOLDER.match(value):
        return None
    hits = find_provider_secrets(value)
    if hits:
        return hits[0][0]
    if SECRET_NAME.search(name or "") and len(value) >= 12 and entropy(value) >= 3.0 \
            and not value.startswith(("http://", "https://", "/", "./", "~")):
        return "Generic secret"
    return None
