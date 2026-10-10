"""Yelp detect-secrets: 25+ secret detectors with entropy and keyword plugins.
Scans server env/args/headers and any server source folders."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .. import secrets as builtin
from ..models import Finding
from ..rules.catalog import make
from . import Context, Integration

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}
TEXT_EXT = {".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml", ".env",
            ".ini", ".cfg", ".txt", ".md", ".sh", ".ps1", ""}


class DetectSecrets(Integration):
    name = "detect-secrets"
    description = "Yelp detect-secrets: provider, keyword and high-entropy secret detectors"

    def available(self):
        try:
            import detect_secrets  # noqa: F401
            return True, ""
        except ImportError:
            return False, "pip install detect-secrets"

    def run(self, ctx: Context) -> list[Finding]:
        from detect_secrets import SecretsCollection
        from detect_secrets.settings import default_settings

        out: list[Finding] = []
        with tempfile.TemporaryDirectory() as tmp, default_settings():
            # 1) configuration values, one "KEY=value" line each
            for srv in ctx.servers:
                lines: list[tuple[str, str]] = []
                lines += [(k, v) for k, v in srv.env.items()]
                lines += [(k, v) for k, v in srv.headers.items()]
                lines += [(f"arg{i}", a) for i, a in enumerate(srv.args)]
                if srv.url:
                    lines.append(("url", srv.url))
                if not lines:
                    continue
                path = Path(tmp) / f"{abs(hash(srv.key))}.env"
                path.write_text("\n".join(f'{k}="{v}"' for k, v in lines), encoding="utf-8")
                sc = SecretsCollection()
                sc.scan_file(str(path))
                for _, items in sc.data.items():
                    for s in items:
                        key, value = lines[s.line_number - 1]
                        # skip what the built-in detector already reported
                        if builtin.looks_like_secret_value(key, value):
                            continue
                        if builtin.PLACEHOLDER.match(value) or builtin.INDIRECTION.search(value):
                            continue
                        out.append(make("MB101", srv.name, f"{s.type} in '{key}' "
                                        "(detect-secrets).", location=srv.config_path,
                                        evidence=f"{key}={builtin.mask(s.secret_value or value)}",
                                        source=self.name))
            # 2) server source trees
            for server, root in ctx.sources():
                sc = SecretsCollection()
                for f in _files(root):
                    sc.scan_file(str(f))
                for fname, items in sc.data.items():
                    by_line: dict[int, list] = {}
                    for s in items:
                        if s.type == "Secret Keyword" and _is_test_file(fname):
                            continue
                        by_line.setdefault(s.line_number, []).append(s)
                    for line_no, group in sorted(by_line.items()):
                        # one finding per line; prefer a named detector over raw entropy
                        group.sort(key=lambda s: "Entropy" in s.type)
                        types = ", ".join(dict.fromkeys(s.type for s in group))
                        value = max((s.secret_value or "" for s in group), key=len)
                        out.append(make("MB802", server, f"{types} in server source "
                                        "(detect-secrets).", location=_rel(fname, root),
                                        line=line_no, evidence=builtin.mask(value),
                                        source=self.name))
        return out


def _files(root: Path, limit: int = 5000):
    if root.is_file():
        yield root
        return
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in TEXT_EXT and p.stat().st_size < 1_000_000:
                yield p
                n += 1
                if n >= limit:
                    return


def _is_test_file(name: str) -> bool:
    n = name.replace("\\", "/").lower()
    return "/test" in n or "fixture" in n or "example" in n


def _rel(path: str, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve().parent))
    except ValueError:
        return path
