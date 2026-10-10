import json

from mcpbastion import discovery


def test_jsonc_comments_trailing_commas_and_urls_in_strings():
    text = '{ // c\n "a": "http://x//y", /* block */ "b": [1,2,],\n}'
    assert discovery.load_jsonc(text) == {"a": "http://x//y", "b": [1, 2]}


def test_parse_all_client_shapes(tmp_path):
    cfg = {
        "mcpServers": {"claude": {"command": "npx", "args": ["-y", "pkg"]}},
        "servers": {"vscode": {"type": "http", "url": "https://h/mcp"}},
        "context_servers": {"zed": {"command": {"path": "uvx", "args": ["tool"], "env": {"A": "1"}}}},
        "mcp": {"servers": {"vs-settings": {"command": "node", "args": ["s.js"]}}},
        "projects": {"/home/u/proj": {"mcpServers": {"proj": {"command": "python", "args": ["s.py"]}}}},
    }
    p = tmp_path / "c.json"
    p.write_text(json.dumps(cfg))
    servers, errors = discovery.parse_config(p)
    by = {s.name: s for s in servers}
    assert not errors
    assert by["claude"].command == "npx" and by["claude"].transport == "stdio"
    assert by["vscode"].transport == "http" and by["vscode"].url == "https://h/mcp"
    assert by["zed"].command == "uvx" and by["zed"].args == ["tool"] and by["zed"].env == {"A": "1"}
    assert "vs-settings" in by
    assert "proj [proj]" in by


def test_sse_and_disabled(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"mcpServers": {
        "s": {"url": "https://h/sse"}, "d": {"command": "x", "disabled": True},
        "w": {"serverUrl": "https://w/mcp"}}}))
    by = {s.name: s for s in discovery.parse_config(p)[0]}
    assert by["s"].transport == "sse"
    assert by["d"].disabled
    assert by["w"].url == "https://w/mcp"


def test_invalid_json_reported(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{nope")
    servers, errors = discovery.parse_config(p)
    assert servers == [] and "invalid JSON" in errors[0]


def test_auto_discovery_uses_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_BASTION_HOME", str(tmp_path))
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text('{"mcpServers": {"x": {"command": "a"}}}')
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".mcp.json").write_text('{"mcpServers": {"y": {"command": "b"}}}')
    servers, files, _ = discovery.load_servers(None, proj)
    assert {s.name for s in servers} == {"x", "y"}
    assert {s.client for s in servers} == {"cursor", "claude-code"}
