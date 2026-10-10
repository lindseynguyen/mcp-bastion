"""Find MCP client configuration files and parse the servers they declare."""
from __future__ import annotations

import json
import os
import platform
import re
from pathlib import Path
from typing import Any, Iterable

from .models import ServerConfig


def _home() -> Path:
    return Path(os.environ.get("MCP_BASTION_HOME") or Path.home())


def _appdata() -> Path:
    if os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"])
    return _home() / "AppData" / "Roaming"


def _vscode_user_dirs() -> list[Path]:
    system = platform.system()
    names = ["Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf"]
    if system == "Darwin":
        base = _home() / "Library" / "Application Support"
    elif system == "Windows":
        base = _appdata()
    else:
        base = _home() / ".config"
    return [base / n / "User" for n in names]


def known_config_paths(project_dir: Path | None = None) -> list[tuple[str, Path]]:
    """(client, path) pairs for every config location we know, existing or not."""
    h = _home()
    system = platform.system()
    if system == "Darwin":
        claude_desktop = h / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        claude_desktop = _appdata() / "Claude" / "claude_desktop_config.json"
    else:
        claude_desktop = h / ".config" / "Claude" / "claude_desktop_config.json"

    paths: list[tuple[str, Path]] = [
        ("claude-desktop", claude_desktop),
        ("claude-code", h / ".claude.json"),
        ("claude-code", h / ".claude" / "settings.json"),
        ("cursor", h / ".cursor" / "mcp.json"),
        ("windsurf", h / ".codeium" / "windsurf" / "mcp_config.json"),
        ("gemini-cli", h / ".gemini" / "settings.json"),
        ("zed", h / ".config" / "zed" / "settings.json"),
        ("amazon-q", h / ".aws" / "amazonq" / "mcp.json"),
    ]
    for user_dir in _vscode_user_dirs():
        client = user_dir.parent.name.lower().replace(" - insiders", "").replace(" ", "-")
        client = "vscode" if client in ("code", "vscodium") else client
        paths.append((client, user_dir / "mcp.json"))
        paths.append((client, user_dir / "settings.json"))
        paths.append(("cline", user_dir / "globalStorage" / "saoudrizwan.claude-dev"
                      / "settings" / "cline_mcp_settings.json"))
    if project_dir is not None:
        p = Path(project_dir)
        paths += [
            ("claude-code", p / ".mcp.json"),
            ("cursor", p / ".cursor" / "mcp.json"),
            ("vscode", p / ".vscode" / "mcp.json"),
            ("gemini-cli", p / ".gemini" / "settings.json"),
        ]
    return paths


def discover(project_dir: Path | None = None) -> list[tuple[str, Path]]:
    seen: set[Path] = set()
    found = []
    for client, path in known_config_paths(project_dir):
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        found.append((client, path))
    return found


# --------------------------------------------------------------------- parsing
def load_jsonc(text: str) -> Any:
    """Parse JSON that may contain // and /* */ comments and trailing commas
    (VS Code, Zed). Comment markers inside strings are preserved."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        else:
            out.append(c)
            i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned)


def _server_maps(data: Any) -> Iterable[tuple[str, dict]]:
    """Yield (scope, {name: entry}) for every server map in a config document."""
    if not isinstance(data, dict):
        return
    for key in ("mcpServers", "servers", "context_servers"):
        if isinstance(data.get(key), dict):
            yield ("", data[key])
    # VS Code user settings: {"mcp": {"servers": {...}}}
    if isinstance(data.get("mcp"), dict) and isinstance(data["mcp"].get("servers"), dict):
        yield ("", data["mcp"]["servers"])
    # Claude Code ~/.claude.json: {"projects": {"/path": {"mcpServers": {...}}}}
    if isinstance(data.get("projects"), dict):
        for proj, cfg in data["projects"].items():
            if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                yield (proj, cfg["mcpServers"])


def _str_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in value.items()}


def parse_entry(name: str, entry: dict, client: str, config_path: str) -> ServerConfig | None:
    if not isinstance(entry, dict):
        return None
    command = entry.get("command")
    args = entry.get("args") or []
    env = _str_dict(entry.get("env"))
    # Zed: "command": {"path": ..., "args": [...], "env": {...}}
    if isinstance(command, dict):
        args = command.get("args") or args
        env = env or _str_dict(command.get("env"))
        command = command.get("path") or command.get("command")
    url = entry.get("url") or entry.get("serverUrl") or entry.get("httpUrl")
    declared = str(entry.get("type") or entry.get("transport") or "").lower()
    if url and not command:
        transport = "sse" if "sse" in declared or str(url).rstrip("/").endswith("/sse") else "http"
    else:
        transport = "stdio"
    if isinstance(args, str):
        args = args.split()
    disabled = bool(entry.get("disabled")) or entry.get("enabled") is False
    return ServerConfig(
        name=str(name), client=client, config_path=str(config_path), transport=transport,
        command=str(command) if command else None, args=[str(a) for a in args], env=env,
        url=str(url) if url else None, headers=_str_dict(entry.get("headers")),
        cwd=entry.get("cwd"), disabled=disabled, raw=entry,
    )


def parse_config(path: Path, client: str = "file") -> tuple[list[ServerConfig], list[str]]:
    errors: list[str] = []
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError as exc:
        return [], [f"{path}: cannot read ({exc})"]
    if not text.strip():
        return [], []
    try:
        data = load_jsonc(text)
    except (ValueError, json.JSONDecodeError) as exc:
        return [], [f"{path}: invalid JSON ({exc})"]
    servers: list[ServerConfig] = []
    for scope, mapping in _server_maps(data):
        for name, entry in mapping.items():
            label = f"{name}" if not scope else f"{name} [{Path(scope).name or scope}]"
            srv = parse_entry(label, entry, client, str(path))
            if srv is not None:
                servers.append(srv)
    return servers, errors


def load_servers(paths: list[Path] | None, project_dir: Path | None = None
                 ) -> tuple[list[ServerConfig], list[str], list[str]]:
    """Load servers from explicit paths, or auto-discover. Returns (servers, files, errors)."""
    targets: list[tuple[str, Path]]
    if paths:
        targets = []
        for p in paths:
            p = Path(p)
            if p.is_dir():
                targets += [(c, q) for c, q in discover(p) if str(q).startswith(str(p))] or \
                           [("file", q) for q in sorted(p.glob("*.json"))]
            else:
                targets.append((_guess_client(p), p))
    else:
        targets = discover(project_dir or Path.cwd())
    servers, errors, files = [], [], []
    for client, path in targets:
        found, errs = parse_config(path, client)
        servers += found
        errors += errs
        files.append(str(path))
    return servers, files, errors


def _guess_client(path: Path) -> str:
    s = str(path).lower().replace("\\", "/")
    for marker, client in (("claude_desktop", "claude-desktop"), (".claude", "claude-code"),
                           (".mcp.json", "claude-code"), ("cursor", "cursor"),
                           ("windsurf", "windsurf"), ("cline", "cline"), (".vscode", "vscode"),
                           ("/code/user", "vscode"), ("gemini", "gemini-cli"), ("zed", "zed")):
        if marker in s:
            return client
    return "file"
