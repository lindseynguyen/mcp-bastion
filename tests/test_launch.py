import pytest

from mcpbastion.launch import analyse, parse_npm_spec, parse_py_spec
from mcpbastion.models import ServerConfig


def srv(cmd, *args, **kw):
    return ServerConfig(name="s", client="t", config_path="c", command=cmd, args=list(args), **kw)


@pytest.mark.parametrize("spec,name,version,pinned", [
    ("@modelcontextprotocol/server-github", "@modelcontextprotocol/server-github", None, False),
    ("@scope/pkg@1.2.3", "@scope/pkg", "1.2.3", True),
    ("pkg@latest", "pkg", "latest", False),
    ("pkg@^1.2.0", "pkg", "^1.2.0", False),
    ("pkg@1.x", "pkg", "1.x", False),
    ("pkg@2.0.1", "pkg", "2.0.1", True),
])
def test_npm_specs(spec, name, version, pinned):
    p = parse_npm_spec(spec)
    assert (p.name, p.version, p.pinned) == (name, version, pinned)


@pytest.mark.parametrize("spec,name,pinned", [
    ("mcp-server-fetch", "mcp-server-fetch", False),
    ("mcp-server-fetch==2025.4.7", "mcp-server-fetch", True),
    ("mcp-server-fetch>=1.0", "mcp-server-fetch", False),
    ("pkg[extra]==1.0", "pkg", True),
])
def test_py_specs(spec, name, pinned):
    p = parse_py_spec(spec)
    assert (p.name, p.pinned) == (name, pinned)


def test_npx_with_flags():
    la = analyse(srv("npx", "-y", "--registry", "https://r", "@a/b@1.0.0", "--port", "3"))
    assert [p.raw for p in la.packages] == ["@a/b@1.0.0"] and la.auto_install


def test_npx_package_flag():
    la = analyse(srv("npx", "-y", "-p", "tool@2.0.0", "tool-cli"))
    assert la.packages[0].name == "tool"


def test_uvx_from_and_with():
    la = analyse(srv("uvx", "--from", "git+https://github.com/x/y", "y", "--with", "dep==1"))
    assert la.packages[0].source == "git"
    assert la.packages[1].name == "dep" and la.packages[1].pinned


def test_pipx_run():
    la = analyse(srv("pipx", "run", "some-mcp"))
    assert la.packages[0].name == "some-mcp"


def test_docker_image_tag_and_digest():
    la = analyse(srv("docker", "run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/a/b:1.2"))
    assert la.packages[0].name == "ghcr.io/a/b" and la.packages[0].version == "1.2"
    assert not la.packages[0].pinned
    la = analyse(srv("docker", "run", "img@sha256:" + "a" * 64))
    assert la.packages[0].pinned


def test_shell_wrapped_npx_is_unwrapped():
    la = analyse(srv("cmd", "/c", "npx", "-y", "pkg"))
    assert la.via_shell and la.packages[0].name == "pkg"
    la = analyse(srv("bash", "-c", "npx -y other@1.0.0"))
    assert la.via_shell and la.packages[0].pinned


def test_local_script_paths(tmp_path):
    script = tmp_path / "server.py"
    script.write_text("print(1)")
    la = analyse(srv("python", str(script)))
    assert la.local_paths == [script]
    la = analyse(srv("uv", "run", "--directory", str(tmp_path), "server.py"))
    assert tmp_path in la.local_paths
