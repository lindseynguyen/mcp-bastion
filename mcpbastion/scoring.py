"""Risk score per subject (MCP server, instruction file, agent scope) and overall.

Each distinct rule contributes once, at its highest severity; findings combine like
independent risks:  score = 100 * (1 - prod(1 - weight)).  So one CRITICAL is 60,
two HIGH are ~58, five LOW stay under 25. A grade makes it readable at a glance:
A 0-9 · B 10-29 · C 30-49 · D 50-69 · F 70-100.

The overall score is the weakest link: the riskiest subject's score, plus 5 for every
other subject that is also at D or F."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .models import Finding, ScanResult, Severity

WEIGHT = {Severity.CRITICAL: 0.60, Severity.HIGH: 0.35, Severity.MEDIUM: 0.15,
          Severity.LOW: 0.05, Severity.INFO: 0.0}
# findings that describe the scanner, not the subject
IGNORED = {"MB901"}


@dataclass
class Score:
    subject: str
    kind: str                      # server | file | agent | config
    score: int
    grade: str
    findings: int
    top: list[str] = field(default_factory=list)   # "MB501 critical" …

    def to_dict(self) -> dict:
        return {"subject": self.subject, "kind": self.kind, "score": self.score, "grade": self.grade,
                "findings": self.findings, "top": self.top}


def grade(score: int) -> str:
    return "A" if score < 10 else "B" if score < 30 else "C" if score < 50 else "D" if score < 70 else "F"


def _combine(findings: list[Finding]) -> tuple[int, list[str]]:
    worst: dict[str, Severity] = {}
    for f in findings:
        if f.rule_id in IGNORED:
            continue
        worst[f.rule_id] = max(worst.get(f.rule_id, Severity.INFO), f.severity)
    remaining = 1.0
    for sev in worst.values():
        remaining *= 1 - WEIGHT[sev]
    ranked = sorted(worst.items(), key=lambda kv: (-kv[1], kv[0]))
    return round(100 * (1 - remaining)), [f"{r} {s.name.lower()}" for r, s in ranked[:4]]


def score(result: ScanResult) -> tuple[list[Score], dict]:
    servers = {s.name for s in result.servers} | {t.server for t in result.tools}
    files = set(result.instruction_files)
    clients = {s.client for s in result.servers}
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        groups[f.server].append(f)
    out = []
    for subject, items in groups.items():
        s, top = _combine(items)
        kind = ("server" if subject in servers else "file" if subject in files or "/" in subject
                or subject.endswith((".md", ".mdc", ".json", ".toml")) else
                "agent" if subject in clients else "config")
        out.append(Score(subject, kind, s, grade(s), len(items), top))
    for subject in sorted((servers | files) - set(groups)):
        out.append(Score(subject, "server" if subject in servers else "file", 0, "A", 0))
    out.sort(key=lambda x: (-x.score, x.subject))
    # weakest link: the riskiest subject, +5 for every other subject that is also D or F
    at_risk = [x for x in out if x.score >= 50]
    worst = out[0].score if out else 0
    overall_score = min(100, worst + 5 * max(0, len(at_risk) - 1))
    _, overall_top = _combine(result.findings)
    overall = {"score": overall_score, "grade": grade(overall_score), "worst_subject": worst,
               "subjects": len(out), "at_risk": len(at_risk), "top": overall_top}
    return out, overall
