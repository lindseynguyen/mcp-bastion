"""Protect AI LLM Guard: ML prompt-injection classifier run locally on tool
metadata. Catches paraphrased injections that regexes miss. Heavy install
(transformers + a DeBERTa model), so it is opt-in: pip install llm-guard."""
from __future__ import annotations

import os

from ..models import Finding, Severity
from ..rules.catalog import make
from . import Context, Integration

THRESHOLD = float(os.environ.get("MCP_BASTION_PI_THRESHOLD", "0.92"))


class LLMGuard(Integration):
    name = "llm-guard"
    description = "LLM Guard PromptInjection scanner (local DeBERTa model)"

    def __init__(self, scanner=None):
        self._scanner = scanner          # injectable for tests

    def available(self):
        if self._scanner is not None:
            return True, ""
        try:
            import llm_guard.input_scanners  # noqa: F401
            return True, ""
        except ImportError:
            return False, "pip install llm-guard"

    def _get_scanner(self):
        if self._scanner is None:
            from llm_guard.input_scanners import PromptInjection
            from llm_guard.input_scanners.prompt_injection import MatchType
            self._scanner = PromptInjection(threshold=THRESHOLD, match_type=MatchType.SENTENCE)
        return self._scanner

    def run(self, ctx: Context) -> list[Finding]:
        if not ctx.tools:
            return []
        scanner = self._get_scanner()
        out = []
        for t in ctx.tools:
            text = t.all_text().strip()
            if len(text) < 25:
                continue
            _, valid, score = scanner.scan(text[:4000])
            if not valid and score >= THRESHOLD:
                out.append(make("MB511", t.server, f"Classifier scored '{t.name}' as prompt "
                                f"injection (score {score:.2f}).", location=f"{t.kind}:{t.name}",
                                evidence=text[:200], source=self.name,
                                severity=Severity.CRITICAL if score >= 0.99 else None))
        return out
