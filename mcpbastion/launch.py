"""Understand how a stdio server is launched: which package/image it runs,
whether it is pinned, and which local source files it points at."""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .models import ServerConfig

NPM_RUNNERS = {"npx", "bunx", "pnpx"}
PY_RUNNERS = {"uvx", "pipx"}
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "cmd.exe", "powershell",
          "powershell.exe", "pwsh", "pwsh.exe"}


@dataclass
class Package:
    ecosystem: str          # npm | PyPI | docker
    name: str
    version: str | None     # exact version if pinned
    raw: str                # spec as written
    source: str = "registry"  # registry | url | git | path

    @property
    def pinned(self) -> bool:
        if self.ecosystem == "docker":
            return "@sha256:" in self.raw
        return bool(self.version) and self.version not in ("latest", "next", "*") \
            and not re.search(r"[\^~<>=*xX|]", self.version.replace("==", "", 1))


@dataclass
class Launch:
    runner: str                               # basename of the command
    packages: list[Package] = field(default_factory=list)
    local_paths: list[Path] = field(default_factory=list)
    auto_install: bool = False                # npx -y / uvx / pipx run
    via_shell: bool = False
    shell_script: str = ""
    docker_flags: list[str] = field(default_factory=list)


def _base(cmd: str | None) -> str:
    if not cmd:
        return ""
    return os.path.basename(cmd.replace("\\", "/")).lower()


def parse_npm_spec(spec: str) -> Package:
    if re.match(r"^(https?:|git\+|github:|git:|file:)", spec) or spec.endswith(".tgz"):
        return Package("npm", spec, None, spec, "git" if "git" in spec.split(":")[0] else "url")
    if spec.startswith("@"):
        scope, _, rest = spec[1:].partition("/")
        name, _, ver = rest.partition("@")
        return Package("npm", f"@{scope}/{name}", ver or None, spec)
    name, _, ver = spec.partition("@")
    return Package("npm", name, ver or None, spec)


def parse_py_spec(spec: str) -> Package:
    if re.match(r"^(https?:|git\+)", spec) or spec.endswith((".whl", ".tar.gz", ".zip")):
        return Package("PyPI", spec, None, spec, "git" if spec.startswith("git+") else "url")
    m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|@)?\s*([^\s;]+)?", spec)
    if not m:
        return Package("PyPI", spec, None, spec)
    name, op, ver = m.group(1), m.group(3), m.group(4)
    if ver and op != "==" and op != "@":
        ver = None
    if op is None and "==" not in spec and any(ch in spec for ch in "<>~=!"):
        ver = None
    return Package("PyPI", name, ver, spec)


def _first_positional(args: list[str], value_flags: set[str]) -> tuple[int, str] | None:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return (i + 1, args[i + 1]) if i + 1 < len(args) else None
        if a.startswith("-"):
            if a.split("=")[0] in value_flags and "=" not in a:
                i += 2
                continue
            i += 1
            continue
        return i, a
    return None


def analyse(server: ServerConfig) -> Launch:
    runner = _base(server.command)
    args = list(server.args)
    launch = Launch(runner=runner)
    if not runner:
        return launch

    # unwrap "cmd /c npx ..." and "bash -c '...'"
    if runner in SHELLS:
        launch.via_shell = True
        script = ""
        for flag in ("-c", "/c", "/C", "-Command", "-command", "-EncodedCommand", "-enc", "-e"):
            if flag in args:
                idx = args.index(flag)
                script = " ".join(args[idx + 1:])
                break
        if not script and args:
            script = " ".join(args)
        launch.shell_script = script
        try:
            inner = shlex.split(script, posix=True)
        except ValueError:
            inner = script.split()
        if inner and _base(inner[0]) not in SHELLS:
            nested = analyse(ServerConfig(name=server.name, client=server.client,
                                          config_path=server.config_path, command=inner[0],
                                          args=inner[1:], cwd=server.cwd))
            nested.via_shell = True
            nested.shell_script = script
            return nested
        return launch

    if runner in NPM_RUNNERS or (runner in ("pnpm", "yarn", "bun") and args[:1] in (["dlx"], ["x"])):
        rest = args[1:] if runner in ("pnpm", "yarn", "bun") else args
        launch.auto_install = True
        pkgs = []
        i = 0
        while i < len(rest):
            a = rest[i]
            if a in ("-p", "--package") and i + 1 < len(rest):
                pkgs.append(rest[i + 1])
                i += 2
                continue
            if a.startswith("--package="):
                pkgs.append(a.split("=", 1)[1])
            i += 1
        pos = _first_positional(rest, {"-p", "--package", "--registry", "--cache"})
        if pos and not pkgs:
            pkgs.append(pos[1])
        launch.packages = [parse_npm_spec(p) for p in pkgs]
    elif runner in PY_RUNNERS:
        rest = args[1:] if runner == "pipx" and args[:1] == ["run"] else args
        launch.auto_install = True
        spec = None
        if "--from" in rest:
            idx = rest.index("--from")
            spec = rest[idx + 1] if idx + 1 < len(rest) else None
        else:
            for a in rest:
                if a.startswith("--from="):
                    spec = a.split("=", 1)[1]
        if spec is None:
            pos = _first_positional(rest, {"--python", "-p", "--with", "--index-url",
                                           "--index", "--spec"})
            spec = pos[1] if pos else None
        if spec:
            launch.packages.append(parse_py_spec(spec))
        for i, a in enumerate(rest):
            if a == "--with" and i + 1 < len(rest):
                launch.packages.append(parse_py_spec(rest[i + 1]))
    elif runner in ("uv",):
        # uv run --directory X server.py / uv --directory X run ...
        for i, a in enumerate(args):
            if a == "--directory" and i + 1 < len(args):
                launch.local_paths.append(Path(args[i + 1]))
            if a == "--with" and i + 1 < len(args):
                launch.packages.append(parse_py_spec(args[i + 1]))
        launch.local_paths += _script_paths(args, server.cwd)
    elif runner in ("docker", "podman", "nerdctl"):
        if args[:1] == ["run"]:
            value_flags = {"-e", "--env", "-v", "--volume", "--name", "--network", "--net",
                           "-p", "--publish", "--user", "-u", "--mount", "-w", "--workdir",
                           "--entrypoint", "--env-file", "--cap-add", "--pid", "--ipc",
                           "--security-opt", "--device", "--label", "-l", "--platform"}
            pos = _first_positional(args[1:], value_flags)
            if pos:
                image = pos[1]
                name = image.split("@")[0]
                last = name.rsplit("/", 1)[-1]
                tag = None
                if ":" in last:
                    tag = last.split(":", 1)[1]
                    name = name[: -(len(tag) + 1)]
                launch.packages.append(Package("docker", name, tag, image))
            launch.docker_flags = args[1:pos[0] + 1] if pos else args[1:]
    elif runner.startswith("python") or runner in ("node", "deno", "bun", "ts-node", "tsx"):
        if "-m" in args and runner.startswith("python"):
            pass
        launch.local_paths += _script_paths(args, server.cwd)
    else:
        # a direct binary path is itself local code
        if server.command and ("/" in server.command or "\\" in server.command):
            launch.local_paths.append(Path(server.command))
    return launch


_SRC_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".mts")


def _script_paths(args: list[str], cwd: str | None) -> list[Path]:
    out = []
    for a in args:
        if a.startswith("-"):
            continue
        if a.endswith(_SRC_EXT) or "/" in a or "\\" in a:
            p = Path(a)
            if not p.is_absolute() and cwd:
                p = Path(cwd) / p
            out.append(p)
    return out


PROJECT_MARKERS = ("pyproject.toml", "package.json", "setup.py", "requirements.txt", "go.mod")


def source_roots(launch: Launch) -> list[Path]:
    """Local files/directories that hold the server's source code: the project
    root when the script sits in one, otherwise just the script itself."""
    roots: list[Path] = []
    for p in launch.local_paths:
        p = p.expanduser()
        if p.is_file():
            if p.suffix.lower() not in _SRC_EXT:
                continue                       # a compiled binary: nothing to read
            root = p
            for parent in [p.parent, *p.parents][:3]:
                if any((parent / m).exists() for m in PROJECT_MARKERS):
                    root = parent
                    break
            roots.append(root)
        elif p.is_dir():
            roots.append(p)
    uniq: list[Path] = []
    for r in roots:
        if r.resolve() not in [u.resolve() for u in uniq]:
            uniq.append(r)
    return uniq
