"""Static checks on server configuration entries (no server is started)."""
from __future__ import annotations

import ipaddress
import os
import re
import stat
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from .. import secrets as sec
from ..launch import Launch, analyse
from ..models import Finding, ServerConfig, Severity
from .catalog import make
from .impersonation import check_package

DOWNLOAD_EXEC = re.compile(
    r"(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;&]*\|\s*(?:sudo\s+)?"
    r"(?:ba|z|da)?sh\b|(?:iex|invoke-expression)\b|\|\s*(?:python3?|node|perl|ruby)\b|"
    r"-encodedcommand\b|\s-enc\s|base64\s+(?:-d|--decode)", re.I)
SUDO = re.compile(r"(?:^|[\s;&|])(?:sudo|doas|runas|gsudo)(?:\s|$)", re.I)
TLS_OFF = {
    "NODE_TLS_REJECT_UNAUTHORIZED": {"0"},
    "PYTHONHTTPSVERIFY": {"0"},
    "CURL_CA_BUNDLE": {""},
    "REQUESTS_CA_BUNDLE": {""},
    "GIT_SSL_NO_VERIFY": {"1", "true"},
    "SSL_VERIFY": {"0", "false"},
    "VERIFY_SSL": {"0", "false"},
    "INSECURE": {"1", "true"},
}
SHELL_SERVER = re.compile(
    r"(?i)(?:server-shell|mcp-shell|shell-mcp|terminal-mcp|mcp-terminal|desktop-commander|"
    r"mcp-server-commands|code-?runner|run-?python|exec-mcp|cmd-mcp|mcp-run-python|"
    r"computer-use|mcp-server-ssh|ssh-mcp)")
FS_SERVER = re.compile(r"(?i)(?:server-filesystem|filesystem|fs-mcp|mcp-fs|file-?system)")


def _broad_path(p: str) -> bool:
    p = p.strip().strip('"').rstrip("/\\") or "/"
    home = str(Path.home()).rstrip("/\\")
    if p in ("/", "~", "$HOME", "${HOME}", "%USERPROFILE%", home, "/home", "/Users", "/root",
             "/etc", "/var", "C:", "C:\\", "C:\\Users", "/mnt", "/mnt/c"):
        return True
    return bool(re.fullmatch(r"[A-Za-z]:", p))


def _is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host in ("localhost",) or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_server(srv: ServerConfig, launch: Launch | None = None) -> list[Finding]:
    f: list[Finding] = []
    s = srv.name
    loc = srv.config_path
    launch = launch or analyse(srv)

    # ---- secrets in env / args / headers
    for k, v in srv.env.items():
        label = sec.looks_like_secret_value(k, v)
        if label:
            f.append(make("MB101", s, f"{label} stored in plain text in env var {k}.",
                          location=loc, evidence=f"{k}={sec.mask(v)}"))
    for i, a in enumerate(srv.args):
        name = srv.args[i - 1] if i and srv.args[i - 1].startswith("-") else ""
        if "=" in a and a.startswith("-"):
            name, a_val = a.split("=", 1)
        else:
            a_val = a
        label = sec.looks_like_secret_value(name, a_val) if name else None
        hits = sec.find_provider_secrets(a_val)
        if hits or label:
            f.append(make("MB101", s, f"{hits[0][0] if hits else label} passed on the command line "
                          "(visible in process lists).", location=loc,
                          evidence=f"{name + ' ' if name else ''}{sec.mask(hits[0][1] if hits else a_val)}"))
    for k, v in srv.headers.items():
        token = v.split(" ", 1)[1] if v.lower().startswith(("bearer ", "basic ", "token ")) else v
        label = sec.looks_like_secret_value(k if k.lower() != "authorization" else "auth_token", token)
        if label:
            f.append(make("MB101", s, f"{label} hard-coded in HTTP header {k}.",
                          location=loc, evidence=f"{k}: {sec.mask(token)}"))

    # ---- URL checks (remote transport)
    if srv.url:
        u = urlparse(srv.url)
        if u.password or any(sec.looks_like_secret_value(k, v) or
                             re.search(r"(?i)key|token|secret|sig|auth", k) and len(v) >= 12
                             for k, v in parse_qsl(u.query)):
            f.append(make("MB102", s, "Credential found in the server URL.", location=loc,
                          evidence=_mask_url(srv.url)))
        if u.scheme == "http" and not _is_loopback(u.hostname):
            f.append(make("MB401", s, f"Remote MCP endpoint {u.hostname} uses unencrypted HTTP.",
                          location=loc, evidence=_mask_url(srv.url)))
        if not _is_loopback(u.hostname):
            has_auth = any(k.lower() in ("authorization", "x-api-key", "api-key", "cookie")
                           for k in srv.headers) or u.password or "oauth" in str(srv.raw).lower() \
                or any(re.search(r"(?i)key|token", k) for k, _ in parse_qsl(u.query))
            if not has_auth:
                f.append(make("MB402", s, "No authentication configured for remote server "
                              f"{u.hostname}. If it relies on OAuth in the client this is expected.",
                              location=loc, evidence=_mask_url(srv.url), severity=Severity.LOW))

    # ---- execution / privilege
    full = srv.command_line()
    if launch.via_shell and DOWNLOAD_EXEC.search(launch.shell_script or full):
        f.append(make("MB301", s, "Server is started by downloading and executing code in a shell.",
                      location=loc, evidence=full))
    elif launch.via_shell:
        f.append(make("MB301", s, "Server is started through a shell wrapper; arguments may be "
                      "interpreted by the shell.", location=loc, evidence=full, severity=Severity.LOW))
    elif DOWNLOAD_EXEC.search(full):
        f.append(make("MB301", s, "Command line downloads and executes code.", location=loc,
                      evidence=full))
    if SUDO.search(full):
        f.append(make("MB303", s, "Server is launched with sudo / administrator rights.",
                      location=loc, evidence=full))
    for k, v in srv.env.items():
        bad = TLS_OFF.get(k.upper())
        if bad is not None and v.strip().lower() in bad:
            f.append(make("MB305", s, f"{k}={v} disables TLS verification for this server.",
                          location=loc, evidence=f"{k}={v}"))

    if launch.runner in ("docker", "podman", "nerdctl"):
        f += _docker_checks(srv, launch)

    # filesystem scope
    joined = " ".join(p.raw for p in launch.packages) + " " + full
    if FS_SERVER.search(joined):
        broad = [a for a in srv.args if _broad_path(os.path.expandvars(a))]
        if broad:
            f.append(make("MB304", s, f"Filesystem server can reach {', '.join(broad)}.",
                          location=loc, evidence=full))
    if SHELL_SERVER.search(joined):
        f.append(make("MB306", s, "This server gives the agent shell / code execution.",
                      location=loc, evidence=full))

    # ---- supply chain
    for pkg in launch.packages:
        f += check_package(pkg, s, loc)
        if pkg.source in ("url", "git"):
            f.append(make("MB204", s, f"{pkg.ecosystem} package installed from {pkg.source}: {pkg.raw}",
                          location=loc, evidence=pkg.raw))
        elif pkg.ecosystem == "docker":
            if not pkg.pinned:
                f.append(make("MB203", s, f"Image {pkg.raw} is referenced by tag, not digest.",
                              location=loc, evidence=pkg.raw,
                              severity=Severity.MEDIUM if pkg.version in (None, "latest") else None))
        elif not pkg.pinned:
            f.append(make("MB201", s, f"{pkg.ecosystem} package {pkg.name} runs "
                          f"{'the latest release' if not pkg.version or pkg.version == 'latest' else 'a version range ' + pkg.version}"
                          " on every launch.", location=loc, evidence=pkg.raw))
    if launch.auto_install and launch.packages and launch.runner in ("npx", "bunx", "pnpx") \
            and any(a in ("-y", "--yes") for a in srv.args):
        f.append(make("MB202", s, "npx -y installs and runs the package without confirmation.",
                      location=loc, evidence=full))
    return f


def _docker_checks(srv: ServerConfig, launch: Launch) -> list[Finding]:
    f = []
    flags = launch.docker_flags
    text = " ".join(flags)
    risky = []
    if "--privileged" in flags:
        risky.append("--privileged")
    for flag in ("--network", "--net", "--pid", "--ipc", "--userns", "--uts"):
        for i, a in enumerate(flags):
            val = flags[i + 1] if a == flag and i + 1 < len(flags) else (a.split("=", 1)[1] if a.startswith(flag + "=") else None)
            if val == "host":
                risky.append(f"{flag}=host")
    if re.search(r"--cap-add[= ](?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN)", text, re.I):
        risky.append("dangerous --cap-add")
    if re.search(r"(?:-v|--volume)[= ]\s*/var/run/docker\.sock", text) or "docker.sock" in text:
        risky.append("docker socket mounted")
    for i, a in enumerate(flags):
        if a in ("-v", "--volume") and i + 1 < len(flags):
            host = flags[i + 1].split(":")[0]
            if _broad_path(host):
                risky.append(f"host path {host} mounted")
        if a.startswith("--mount") and "source=/," in a + ",":
            risky.append("host root mounted")
    if re.search(r"seccomp[=:]unconfined|apparmor[=:]unconfined", text):
        risky.append("security profile disabled")
    if risky:
        f.append(make("MB302", srv.name, "Container is given host-level access: " + ", ".join(sorted(set(risky))),
                      location=srv.config_path, evidence=srv.command_line()))
    return f


def check_file_permissions(path: str, has_secrets: bool = False) -> list[Finding]:
    """World/group-writable configs let other users inject servers; world-readable
    ones leak the secrets they contain."""
    if os.name != "posix":
        return []
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return []
    if mode & (stat.S_IWOTH | stat.S_IWGRP):
        return [make("MB103", "-", f"{path} is writable by other users (mode {oct(mode & 0o777)}); "
                     "anyone with that access can add a malicious server.", location=path,
                     evidence=oct(mode & 0o777), title="Configuration file writable by other users")]
    if has_secrets and mode & stat.S_IROTH:
        return [make("MB103", "-", f"{path} contains secrets and is readable by every local user "
                     f"(mode {oct(mode & 0o777)}).", location=path, evidence=oct(mode & 0o777))]
    return []


def check_cross_client(servers: list[ServerConfig]) -> list[Finding]:
    by_name: dict[str, list[ServerConfig]] = defaultdict(list)
    for s in servers:
        by_name[s.name.split(" [")[0]].append(s)
    out = []
    for name, group in by_name.items():
        variants = {(g.command_line(), tuple(sorted(g.env))) for g in group}
        if len(group) > 1 and len(variants) > 1:
            where = ", ".join(sorted({g.client for g in group}))
            out.append(make("MB405", name, f"'{name}' is defined {len(variants)} different ways "
                            f"across {where}.", location=group[0].config_path,
                            evidence=" | ".join(sorted(v[0] for v in variants))[:300]))
    return out


def _mask_url(url: str) -> str:
    u = urlparse(url)
    netloc = u.netloc
    if u.password:
        netloc = netloc.replace(u.password, "****")
    query = "&".join(f"{k}=****" if re.search(r"(?i)key|token|secret|sig|auth|pass", k) else f"{k}={v}"
                     for k, v in parse_qsl(u.query))
    return u._replace(netloc=netloc, query=query).geturl()
