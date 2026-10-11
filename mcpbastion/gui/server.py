"""Local web GUI: `mcp-bastion gui`.

A small HTTP server on 127.0.0.1 serving one page and a JSON API. Scans go through the
same ScanRequest -> build() -> scan() -> verdict() path as the CLI, so both always agree.

Safety: loopback only; every API call needs the per-session token embedded in the page;
Host and Origin headers must match the local address (blocks DNS rebinding and other
websites); live scans, which start server commands, need an explicit confirmation flag."""
from __future__ import annotations

import json
import os
import platform
import secrets
import sys
import threading
import time
import uuid
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import __version__, baseline, discovery, instructions, pinning, report
from ..integrations import registry
from ..options import ScanRequest, build, verdict
from ..rules.catalog import OWASP_ASI, OWASP_MCP, RULES
from ..rules.tool_rules import decode_tag_chars, invisible_chars
from ..scanner import scan
from ..secrets import scrub

STATIC = Path(__file__).with_name("index.html")
MAX_BODY = 1_000_000
EXPORTS = {"json": ("application/json", "json"), "sarif": ("application/sarif+json", "sarif"),
           "html": ("text/html; charset=utf-8", "html"), "md": ("text/markdown; charset=utf-8", "md")}


class Job:
    def __init__(self, req: ScanRequest):
        self.id = uuid.uuid4().hex[:12]
        self.req = req
        self.state = "running"
        self.started = time.time()
        self.finished: float | None = None
        self.error: str | None = None
        self.result = None
        self.payload: dict | None = None


class App:
    def __init__(self):
        self.token = secrets.token_hex(24)
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.port = 0

    # ------------------------------------------------------------------ scans
    def start_scan(self, data: dict) -> Job:
        confirm_live = bool(data.pop("confirm_live", False))
        req = ScanRequest.from_dict(data)
        if req.live and not confirm_live:
            raise PermissionError("live scans start every configured server command on this machine; "
                                  "confirm to continue")
        built = build(req, env_judge=False)          # validate fully before starting
        with self.lock:
            if any(j.state == "running" for j in self.jobs.values()):
                raise RuntimeError("a scan is already running")
            job = Job(req)
            self.jobs[job.id] = job
        threading.Thread(target=self._run, args=(job, built), daemon=True).start()
        return job

    def _run(self, job: Job, built) -> None:
        try:
            result = scan(built.options)
            job.result = result
            payload = json.loads(report.to_json(result))
            payload["verdict"] = verdict(result, built.fail_on, built.fail_score)
            payload["thresholds"] = {"fail_on": built.fail_on.name.lower(), "fail_score": built.fail_score}
            payload["tool_details"] = [_tool_detail(t) for t in result.tools]
            job.payload = payload
            job.state = "done"
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            job.error = f"{type(exc).__name__}: {exc}"
            job.state = "error"
        finally:
            job.finished = time.time()

    def job_view(self, job: Job) -> dict:
        end = job.finished or time.time()
        return {"id": job.id, "state": job.state, "elapsed": round(end - job.started, 1),
                "error": job.error, "result": job.payload if job.state == "done" else None}

    # ------------------------------------------------------------------ other API
    def meta(self) -> dict:
        engines = []
        for p in registry():
            ok, why = p.available()
            engines.append({"name": p.name, "description": p.description, "available": ok,
                            "hint": "" if ok else why, "needs_network": p.needs_network})
        return {"version": __version__, "cwd": str(Path.cwd()), "home": str(Path.home()),
                "platform": platform.system(), "python": platform.python_version(), "engines": engines,
                "rules": [{"id": r.id, "title": r.title, "severity": r.severity.name.lower(),
                           "category": r.category, "remediation": r.remediation,
                           "owasp": list(r.mcp) + list(r.asi)} for r in RULES.values()],
                "owasp": {**OWASP_MCP, **OWASP_ASI},
                "llm_env": {"url": os.environ.get("MCP_BASTION_LLM_URL", ""),
                            "model": os.environ.get("MCP_BASTION_LLM_MODEL", ""),
                            "key_set": bool(os.environ.get("MCP_BASTION_LLM_API_KEY"))}}

    def discover(self, data: dict) -> dict:
        paths = [Path(p).expanduser() for p in data.get("paths") or []]
        for p in paths:
            if not p.exists():
                raise ValueError(f"path not found: {p}")
        project = Path(data["project"]).expanduser() if data.get("project") else None
        cfg_paths = [p for p in paths if not (p.is_file() and instructions.is_instruction_file(p))]
        servers, files, errors = ([], [], []) if paths and not cfg_paths else \
            discovery.load_servers(cfg_paths or None, project)
        roots = [p for p in paths if p.is_dir()] if paths else [project or Path.cwd()]
        targets = instructions.discover(roots, include_user=not paths)
        return {"configs": [{"path": f, "servers": [
                    {"name": s.name, "client": s.client, "transport": s.transport, "disabled": s.disabled,
                     "command": scrub(s.command_line())} for s in servers if s.config_path == f]}
                    for f in files],
                "instruction_files": [{"path": t.display, "kind": t.kind, "scope": t.scope} for t in targets],
                "errors": errors}

    def write_baseline(self, job: Job, data: dict) -> dict:
        if job.state != "done":
            raise ValueError("scan has not finished")
        path = Path(str(data.get("path") or "")).expanduser()
        if not path.name:
            raise ValueError("baseline path is required")
        n = baseline.write(path, job.result.findings)
        return {"path": str(path), "accepted": n}

    def accept_tools(self, job: Job, data: dict) -> dict:
        if job.state != "done" or not job.result.tools:
            raise ValueError("this scan has no tool definitions to pin (run with live or a tools file)")
        path = Path(str(data.get("path") or job.req.lock or "")).expanduser()
        if not path.name:
            raise ValueError("lock file path is required")
        pinning.update_lock(path, job.result.tools, pinning.load_lock(path))
        return {"path": str(path), "pinned": len(job.result.tools)}

    @staticmethod
    def list_dir(data: dict) -> dict:
        base = Path(str(data.get("path") or Path.cwd())).expanduser()
        if base.is_file():
            base = base.parent
        if not base.is_dir():
            raise ValueError(f"not a folder: {base}")
        entries = []
        try:
            for p in sorted(base.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))[:500]:
                entries.append({"name": p.name, "path": str(p), "dir": p.is_dir()})
        except PermissionError as exc:
            raise ValueError(f"cannot read {base}: {exc}") from exc
        return {"path": str(base), "parent": str(base.parent), "entries": entries}


def _visible(text: str) -> str:
    out = []
    for ch in text or "":
        cp = ord(ch)
        if cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF) or 0x202A <= cp <= 0x202E \
                or 0x2066 <= cp <= 0x2069 or 0xE0000 <= cp <= 0xE007F:
            out.append(f"<U+{cp:04X}>")
        else:
            out.append(ch)
    return "".join(out)


def _tool_detail(t) -> dict:
    props = (t.input_schema or {}).get("properties") or {}
    return {"server": t.server, "kind": t.kind, "name": t.name, "sha256": t.fingerprint(),
            "description": scrub(_visible(t.description)),
            "hidden_text": decode_tag_chars(t.all_text()), "invisible": invisible_chars(t.all_text()),
            "params": [{"name": k, "description": scrub(_visible(v.get("description", "")))
                        if isinstance(v, dict) else ""} for k, v in props.items()],
            "annotations": t.annotations}


# ---------------------------------------------------------------------- HTTP

def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "mcp-bastion-gui"

        def log_message(self, fmt, *args):  # quiet
            pass

        # -------------------------------------------------------------- guards
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            allowed = {f"127.0.0.1:{app.port}", f"localhost:{app.port}"}
            if host not in allowed:
                return False
            origin = self.headers.get("Origin")
            return origin is None or origin.lower() in {f"http://{h}" for h in allowed}

        def _auth_ok(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Bastion-Token", ""), app.token)

        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                             "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                             "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, obj) -> None:
            self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _error(self, status: int, msg: str) -> None:
            self._json(status, {"error": msg})

        def _body(self) -> dict:
            if "application/json" not in (self.headers.get("Content-Type") or ""):
                raise ValueError("Content-Type must be application/json")
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                raise ValueError("request too large")
            data = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("JSON object expected")
            return data

        # -------------------------------------------------------------- routes
        def do_GET(self):
            if not self._host_ok():
                return self._error(HTTPStatus.FORBIDDEN, "bad host")
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                page = STATIC.read_text(encoding="utf-8").replace("__BASTION_TOKEN__", app.token)
                return self._send(200, page.encode("utf-8"), "text/html; charset=utf-8")
            if not url.path.startswith("/api/"):
                return self._error(404, "not found")
            if not self._auth_ok():
                return self._error(HTTPStatus.UNAUTHORIZED, "missing or wrong token")
            parts = url.path.strip("/").split("/")
            try:
                if parts == ["api", "meta"]:
                    return self._json(200, app.meta())
                if len(parts) >= 3 and parts[1] == "jobs":
                    job = app.jobs.get(parts[2])
                    if not job:
                        return self._error(404, "unknown job")
                    if len(parts) == 3:
                        return self._json(200, app.job_view(job))
                    if parts[3] == "export":
                        fmt = parse_qs(url.query).get("format", ["json"])[0]
                        if fmt not in EXPORTS:
                            return self._error(400, f"format must be one of {', '.join(EXPORTS)}")
                        if job.state != "done":
                            return self._error(409, "scan has not finished")
                        ctype, ext = EXPORTS[fmt]
                        body = report.WRITERS[fmt](job.result).encode("utf-8")
                        return self._send(200, body, ctype, {
                            "Content-Disposition": f'attachment; filename="mcp-bastion-report.{ext}"'})
                return self._error(404, "not found")
            except Exception as exc:  # noqa: BLE001
                return self._error(500, f"{type(exc).__name__}: {exc}")

        def do_POST(self):
            if not self._host_ok():
                return self._error(HTTPStatus.FORBIDDEN, "bad host")
            if not self._auth_ok():
                return self._error(HTTPStatus.UNAUTHORIZED, "missing or wrong token")
            parts = urlparse(self.path).path.strip("/").split("/")
            try:
                data = self._body()
                if parts == ["api", "scan"]:
                    job = app.start_scan(data)
                    return self._json(202, {"id": job.id})
                if parts == ["api", "discover"]:
                    return self._json(200, app.discover(data))
                if parts == ["api", "ls"]:
                    return self._json(200, app.list_dir(data))
                if len(parts) == 4 and parts[1] == "jobs":
                    job = app.jobs.get(parts[2])
                    if not job:
                        return self._error(404, "unknown job")
                    if parts[3] == "baseline":
                        return self._json(200, app.write_baseline(job, data))
                    if parts[3] == "accept-tools":
                        return self._json(200, app.accept_tools(job, data))
                return self._error(404, "not found")
            except PermissionError as exc:
                return self._error(HTTPStatus.PRECONDITION_REQUIRED, str(exc))
            except RuntimeError as exc:
                return self._error(HTTPStatus.CONFLICT, str(exc))
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                return self._error(400, str(exc))
            except Exception as exc:  # noqa: BLE001
                return self._error(500, f"{type(exc).__name__}: {exc}")

    return Handler


def create_server(port: int = 0) -> tuple[ThreadingHTTPServer, App]:
    app = App()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    httpd.daemon_threads = True
    app.port = httpd.server_address[1]
    return httpd, app


def run(port: int = 0, open_browser: bool = True) -> int:
    httpd, app = create_server(port)
    url = f"http://127.0.0.1:{app.port}/"
    print(f"mcp-bastion GUI running at {url}  (Ctrl+C to stop)", file=sys.stderr)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0
