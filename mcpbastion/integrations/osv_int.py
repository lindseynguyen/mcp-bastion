"""OSV.dev (Google's open vulnerability database, includes the OpenSSF
malicious-packages feed as MAL-* IDs).

- npm / PyPI packages launched by npx / uvx / pipx are looked up via the OSV API.
  Pinned versions: every vulnerability affecting that version.
  Unpinned: only MAL-* entries (the package itself is malicious).
- If the osv-scanner binary is installed, server source folders' lockfiles are
  scanned too.
Needs network, so it only runs with --online."""
from __future__ import annotations

import json
import os
import urllib.request

from ..models import Finding, Severity
from ..rules.catalog import make
from . import Context, Integration, run_cmd, which

API = os.environ.get("MCP_BASTION_OSV_URL", "https://api.osv.dev/v1/querybatch")


class OSV(Integration):
    name = "osv"
    description = "OSV.dev vulnerabilities + malicious-package feed for launched packages"
    needs_network = True

    def __init__(self, fetch=None):
        self._fetch = fetch or _post_json     # injectable for tests

    def available(self):
        return True, ""

    def run(self, ctx: Context) -> list[Finding]:
        queries, owners = [], []
        index: dict[tuple, int] = {}
        for srv in ctx.servers:
            for pkg in ctx.launches[srv.key].packages:
                if pkg.ecosystem not in ("npm", "PyPI") or pkg.source != "registry":
                    continue
                key = (pkg.ecosystem, pkg.name, pkg.version if pkg.pinned else None)
                if key not in index:
                    q = {"package": {"name": pkg.name, "ecosystem": pkg.ecosystem}}
                    if pkg.pinned:
                        q["version"] = pkg.version.lstrip("=")
                    index[key] = len(queries)
                    queries.append(q)
                    owners.append([])
                owners[index[key]].append((srv, pkg))
        out: list[Finding] = []
        if queries:
            data = self._fetch(API, {"queries": queries}, ctx.timeout)
            for q, res, own in zip(queries, data.get("results", []), owners, strict=False):
                ids = [v.get("id", "") for v in (res or {}).get("vulns", []) or []]
                if "version" not in q:
                    ids = [i for i in ids if i.startswith("MAL-")]
                if not ids:
                    continue
                malicious = [i for i in ids if i.startswith("MAL-")]
                for srv, pkg in own:
                    if malicious:
                        msg = f"{pkg.ecosystem} package {pkg.name} is listed as MALICIOUS ({', '.join(malicious[:3])})."
                        sev = Severity.CRITICAL
                    else:
                        msg = (f"{pkg.ecosystem} {pkg.name}@{q.get('version')} has {len(ids)} known "
                               f"vulnerabilit{'y' if len(ids) == 1 else 'ies'}: {', '.join(ids[:5])}"
                               f"{'…' if len(ids) > 5 else ''}.")
                        sev = Severity.HIGH
                    out.append(make("MB205", srv.name, msg, location=srv.config_path,
                                    evidence=pkg.raw, severity=sev, source=self.name))
        out += self._scan_sources(ctx)
        return out

    def _scan_sources(self, ctx: Context) -> list[Finding]:
        exe = which("osv-scanner")
        if not exe:
            return []
        out = []
        for server, root in ctx.sources():
            proc = run_cmd([exe, "scan", "source", "--format", "json", "-r", str(root)], ctx.timeout * 2)
            try:
                data = json.loads(proc.stdout or "{}")
            except ValueError:
                continue
            for res in data.get("results", []):
                for p in res.get("packages", []):
                    info = p.get("package", {})
                    ids = [v.get("id") for v in p.get("vulnerabilities", [])]
                    if ids:
                        out.append(make("MB205", server, f"Dependency {info.get('name')}@"
                                        f"{info.get('version')} has {len(ids)} known vulnerabilities: "
                                        f"{', '.join(ids[:5])}.",
                                        location=(res.get("source") or {}).get("path", str(root)),
                                        evidence=f"{info.get('ecosystem')} {info.get('name')}",
                                        severity=Severity.CRITICAL if any(i.startswith("MAL-") for i in ids)
                                        else Severity.HIGH, source="osv-scanner"))
        return out


def _post_json(url: str, payload: dict, timeout: float) -> dict:
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https OSV endpoint: {url}")
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),  # noqa: S310 - https only
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "mcp-bastion"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
        return json.loads(resp.read().decode("utf-8"))
