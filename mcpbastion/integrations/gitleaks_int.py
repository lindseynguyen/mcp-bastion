"""Gitleaks (Go binary) for secrets in server source trees."""
from __future__ import annotations

import json
import os
import tempfile

from .. import secrets as builtin
from ..models import Finding
from ..rules.catalog import make
from . import Context, Integration, run_cmd, which


class Gitleaks(Integration):
    name = "gitleaks"
    description = "Gitleaks secret scanner (binary on PATH)"

    def available(self):
        return (True, "") if which("gitleaks") else (False, "install gitleaks (github.com/gitleaks/gitleaks)")

    def run(self, ctx: Context) -> list[Finding]:
        exe = which("gitleaks")
        out = []
        for server, root in ctx.sources():
            fd, report = tempfile.mkstemp(suffix=".json")
            os.close(fd)
            try:
                proc = run_cmd([exe, "dir", str(root), "--report-format", "json",
                                "--report-path", report, "--no-banner", "--exit-code", "0"],
                               ctx.timeout)
                if proc.returncode not in (0, 1) or "unknown command" in (proc.stderr or ""):
                    proc = run_cmd([exe, "detect", "--no-git", "--source", str(root),
                                    "--report-format", "json", "--report-path", report,
                                    "--exit-code", "0"], ctx.timeout)
                with open(report, encoding="utf-8") as fh:
                    items = json.load(fh) or []
            except (OSError, ValueError):
                items = []
            finally:
                os.unlink(report)
            for it in items:
                out.append(make("MB802", server, f"{it.get('Description') or it.get('RuleID')} "
                                "(gitleaks).", location=it.get("File", ""), line=it.get("StartLine"),
                                evidence=builtin.mask(it.get("Secret", "")), source=self.name))
        return out
