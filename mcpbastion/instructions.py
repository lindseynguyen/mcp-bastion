"""Find agent instruction files, skills and agent settings, and check them."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import secrets as sec
from .discovery import _home, load_jsonc
from .models import Finding, Severity
from .rules.catalog import make
from .rules.instruction_rules import CMD_EXFIL, DOWNLOAD_EXEC, check_text

MAX_BYTES = 512 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox",
             "site-packages", "vendor", "target", ".next"}
SCRIPT_EXT = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb", ".pl"}

# names that are instruction files wherever they appear in the tree
NESTED_NAMES = {"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md", "GEMINI.md"}
ROOT_FILES = ["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md", "GEMINI.md", ".cursorrules",
              ".windsurfrules", ".clinerules", ".roorules", ".goosehints", "CONVENTIONS.md",
              ".github/copilot-instructions.md", ".junie/guidelines.md", ".claude/CLAUDE.md"]
ROOT_GLOBS = [".cursor/rules/**/*.mdc", ".cursor/rules/**/*.md", ".windsurf/rules/**/*.md",
              ".clinerules/**/*.md", ".roo/rules*/**/*.md", ".continue/rules/**/*.md",
              ".kiro/steering/**/*.md", ".github/instructions/**/*.instructions.md",
              ".github/prompts/**/*.prompt.md", ".github/chatmodes/**/*.chatmode.md",
              ".github/agents/**/*.md", ".claude/commands/**/*.md", ".claude/agents/**/*.md",
              ".gemini/commands/**/*.toml", ".codex/prompts/**/*.md"]
SKILL_GLOBS = [".claude/skills/*/SKILL.md", ".agents/skills/*/SKILL.md", "skills/*/SKILL.md"]
SETTINGS = [".claude/settings.json", ".claude/settings.local.json", ".vscode/settings.json",
            ".vscode/tasks.json", ".codex/config.toml", ".gemini/settings.json"]
HOME_FILES = [".claude/CLAUDE.md", ".codex/AGENTS.md", ".gemini/GEMINI.md", ".config/AGENTS.md"]
HOME_GLOBS = [".claude/commands/**/*.md", ".claude/agents/**/*.md", ".codex/prompts/**/*.md"]
HOME_SKILLS = [".claude/skills/*/SKILL.md"]
HOME_SETTINGS = [".claude/settings.json", ".codex/config.toml"]


@dataclass
class Target:
    path: Path
    kind: str            # instructions | skill | script | settings
    scope: str           # project | user
    display: str


@dataclass
class InstructionScan:
    targets: list[Target] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skill_dirs: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    inline_suppressed: int = 0


INLINE_IGNORE = re.compile(r"mcp-bastion-ignore(?:\[\s*([A-Za-z0-9,\s]+?)\s*\])?")


def _inline_ignores(text: str) -> dict[int, set[str] | None]:
    """line -> rule ids (None = all) for `mcp-bastion-ignore[MB1104]` markers. A marker covers
    its own line and the next one."""
    out: dict[int, set[str] | None] = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = INLINE_IGNORE.search(line)
        if m:
            rules = {r.strip().upper() for r in m.group(1).split(",")} if m.group(1) else None
            for n in (i, i + 1):
                prev = out.get(n, set())
                out[n] = None if (rules is None or prev is None) else prev | rules
    return out


def _display(path: Path, root: Path, scope: str) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve())
        return ("~/" if scope == "user" else "") + rel.as_posix()
    except ValueError:
        return str(path)


def _walk_named(root: Path, names: set[str], max_depth: int = 5):
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        if len(Path(dirpath).parts) - root_depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn in names:
                yield Path(dirpath) / fn


def discover(roots: list[Path], include_user: bool) -> list[Target]:
    found: dict[Path, Target] = {}

    def add(p: Path, kind: str, scope: str, base: Path):
        try:
            rp = p.resolve()
        except OSError:
            return
        if rp not in found and p.is_file():
            found[rp] = Target(p, kind, scope, _display(p, base, scope))

    def scan_root(base: Path, scope: str, files, globs, skills, settings):
        for f in files:
            add(base / f, "instructions", scope, base)
        for g in globs:
            for p in sorted(base.glob(g)):
                add(p, "instructions", scope, base)
        for g in skills:
            for skill_md in sorted(base.glob(g)):
                add(skill_md, "skill", scope, base)
                for dirpath, dirnames, filenames in os.walk(skill_md.parent):
                    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                    for fn in filenames:
                        p = Path(dirpath) / fn
                        if p.suffix.lower() in SCRIPT_EXT:
                            add(p, "script", scope, base)
                        elif p.suffix.lower() == ".md" and p != skill_md:
                            add(p, "instructions", scope, base)
        for s in settings:
            add(base / s, "settings", scope, base)

    for root in roots:
        root = Path(root)
        if root.is_file():
            add(root, _kind_for(root), "project", root.parent)
            continue
        if not root.is_dir():
            continue
        scan_root(root, "project", ROOT_FILES, ROOT_GLOBS, SKILL_GLOBS, SETTINGS)
        for p in _walk_named(root, NESTED_NAMES):
            add(p, "instructions", "project", root)
    if include_user:
        h = _home()
        scan_root(h, "user", HOME_FILES, HOME_GLOBS, HOME_SKILLS, HOME_SETTINGS)
    return list(found.values())


def _kind_for(path: Path) -> str:
    name = path.name
    if name == "SKILL.md":
        return "skill"
    if path.suffix.lower() in SCRIPT_EXT:
        return "script"
    if name in ("settings.json", "settings.local.json", "tasks.json", "config.toml"):
        return "settings"
    return "instructions"


def is_instruction_file(path: Path) -> bool:
    n = path.name
    return (n in NESTED_NAMES or n in (".cursorrules", ".windsurfrules", ".clinerules", "SKILL.md")
            or n.endswith((".mdc", ".instructions.md", ".prompt.md", ".chatmode.md"))
            or (path.parent.name in ("commands", "agents", "rules") and path.suffix in (".md", ".mdc")))


# --------------------------------------------------------------------- scan

def scan(roots: list[Path], include_user: bool = False, extra_files: list[Path] | None = None,
         inline_ignores: bool = True) -> InstructionScan:
    out = InstructionScan()
    out.targets = discover(roots + list(extra_files or []), include_user)
    skill_dirs = set()
    scripts_per_skill: dict[Path, int] = {}
    for t in out.targets:
        try:
            if t.path.stat().st_size > MAX_BYTES:
                out.errors.append(f"{t.display}: skipped (larger than {MAX_BYTES // 1024} KB)")
                continue
            text = t.path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            out.errors.append(f"{t.display}: cannot read ({exc})")
            continue
        if t.kind == "settings":
            out.findings += check_settings(t, text)
            continue
        found = check_text(text, t.display, "script" if t.kind == "script" else "instructions")
        if inline_ignores and "mcp-bastion-ignore" in text:
            marks = _inline_ignores(text)
            kept = []
            for f in found:
                rules = marks.get(f.line or -1, set())
                # CRITICAL is never suppressible inline: an attacker controls this file too
                if f.severity < Severity.CRITICAL and (rules is None or f.rule_id in rules):
                    out.inline_suppressed += 1
                else:
                    kept.append(f)
            found = kept
        if t.scope == "user":
            for f in found:            # the user's own files: still report, one notch lower
                if f.severity > Severity.INFO and f.rule_id not in ("MB1102", "MB1103"):
                    f.severity = Severity(int(f.severity) - 1)
        out.findings += found
        if t.kind == "skill":
            skill_dirs.add(t.path.parent)
        if t.kind == "script":
            skill = next((p for p in t.path.parents if (p / "SKILL.md").exists()), None)
            if skill:
                scripts_per_skill[skill] = scripts_per_skill.get(skill, 0) + 1
    for skill, n in scripts_per_skill.items():
        disp = next((t.display for t in out.targets if t.path.parent == skill and t.kind == "skill"), str(skill))
        out.findings.append(make("MB1113", disp, f"Skill ships {n} executable script"
                                 f"{'s' if n != 1 else ''}.", location=disp))
    out.skill_dirs = sorted(skill_dirs)
    return out


# --------------------------------------------------------------------- settings

def _cmd_severity(cmd: str, base: Severity) -> Severity:
    if DOWNLOAD_EXEC.search(cmd) or any(p.search(cmd) for p in CMD_EXFIL):
        return Severity.CRITICAL
    if re.search(r"\b(?:curl|wget|nc|ncat|invoke-webrequest|iwr|irm|ssh|scp)\b", cmd, re.I):
        return Severity.HIGH
    return base


def check_settings(t: Target, text: str) -> list[Finding]:
    name = t.path.name
    parent = t.path.parent.name
    d = t.display
    base = Severity.MEDIUM if t.scope == "project" else Severity.LOW
    hook_base = Severity.LOW
    out: list[Finding] = []

    if name.endswith(".toml"):
        policy = re.search(r"(?m)^\s*approval_policy\s*=\s*[\"']([\w-]+)", text)
        sandbox = re.search(r"(?m)^\s*sandbox_mode\s*=\s*[\"']([\w-]+)", text)
        never = policy and policy.group(1) == "never"
        full = sandbox and sandbox.group(1) == "danger-full-access"
        if never or full:
            what = " and ".join(x for x in (
                "approval_policy = never" if never else "", "sandbox_mode = danger-full-access" if full else "") if x)
            out.append(make("MB1111", d, f"Codex runs commands with {what}.", location=d,
                            line=_line_of(text, (policy if never else sandbox).start()),
                            severity=Severity.HIGH if (never and full) else Severity.MEDIUM))
        return out

    try:
        data = load_jsonc(text) if text.strip() else {}
    except ValueError as exc:
        return [make("MB901", d, f"Cannot parse settings: {exc}", location=d)]
    if not isinstance(data, dict):
        return out

    if parent == ".claude":
        hooks = data.get("hooks") or {}
        if isinstance(hooks, dict):
            for event, groups in hooks.items():
                for g in groups if isinstance(groups, list) else []:
                    for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                        cmd = str(h.get("command") or "") if isinstance(h, dict) else ""
                        if cmd:
                            out.append(make("MB1110", d, f"Hook runs on every {event}"
                                            f"{' (' + g.get('matcher') + ')' if g.get('matcher') else ''}.",
                                            location=d, line=_find_line(text, cmd), evidence=cmd,
                                            severity=_cmd_severity(cmd, hook_base)))
                            out += _scan_hook_scripts(cmd, t)
        if data.get("apiKeyHelper"):
            cmd = str(data["apiKeyHelper"])
            out.append(make("MB1110", d, "apiKeyHelper runs a command whenever credentials are needed.",
                            location=d, line=_find_line(text, cmd), evidence=cmd,
                            severity=_cmd_severity(cmd, base)))
        if data.get("enableAllProjectMcpServers") is True:
            out.append(make("MB1112", d, "Every server in the project's .mcp.json starts without review.",
                            location=d, line=_find_line(text, "enableAllProjectMcpServers")))
        perms = data.get("permissions") or {}
        if isinstance(perms, dict):
            if perms.get("defaultMode") == "bypassPermissions":
                out.append(make("MB1111", d, "permissions.defaultMode is bypassPermissions: no prompts at all.",
                                location=d, line=_find_line(text, "bypassPermissions")))
            allow = [str(a) for a in perms.get("allow") or []]
            broad = [a for a in allow if re.fullmatch(r"Bash(?:\((?:\*|\*:\*|:\*)?\))?", a)]
            risky = [a for a in allow if re.match(r"Bash\((?:curl|wget|sudo|rm|bash|sh|python|node|nc)\b", a)]
            if broad or risky:
                out.append(make("MB1111", d, "Shell commands are pre-approved: " + ", ".join(broad + risky) + ".",
                                location=d, line=_find_line(text, (broad + risky)[0]),
                                severity=Severity.HIGH if broad else Severity.MEDIUM))
        out += _env_secrets(data.get("env"), d, text)

    elif name == "settings.json" and parent == ".vscode":
        for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
            if data.get(key) is True:
                out.append(make("MB1111", d, f"{key} lets the agent run every tool without asking.",
                                location=d, line=_find_line(text, key)))
        term = data.get("chat.tools.terminal.autoApprove")
        if isinstance(term, dict):
            wild = [k for k, v in term.items() if v is True and k.strip("/") in (".*", "*", ".+", "")]
            if wild:
                out.append(make("MB1111", d, "Every terminal command is auto-approved.", location=d,
                                line=_find_line(text, "chat.tools.terminal.autoApprove")))
        if data.get("task.allowAutomaticTasks") == "on":
            out.append(make("MB1111", d, "Tasks marked runOn: folderOpen start as soon as the folder opens.",
                            location=d, line=_find_line(text, "task.allowAutomaticTasks"),
                            severity=Severity.MEDIUM))

    elif name == "tasks.json":
        for task in data.get("tasks") or []:
            if not isinstance(task, dict):
                continue
            if (task.get("runOptions") or {}).get("runOn") == "folderOpen":
                cmd = " ".join(str(x) for x in [task.get("command", ""), *(task.get("args") or [])]).strip()
                out.append(make("MB1110", d, f"Task '{task.get('label', '?')}' runs when the folder is opened.",
                                location=d, line=_find_line(text, "folderOpen"), evidence=cmd,
                                severity=_cmd_severity(cmd, Severity.HIGH if t.scope == "project" else base)))

    elif parent == ".gemini":
        out += _env_secrets(data.get("env"), d, text)
    return out


def _scan_hook_scripts(cmd: str, t: Target) -> list[Finding]:
    """Hooks usually call a script in the repo: scan that script too."""
    project = t.path.parent.parent            # .claude/settings.json -> project root
    out = []
    for token in re.findall(r"[\w$\"{}./\\-]+\.(?:sh|bash|py|js|mjs|ts|ps1)\b", cmd):
        rel = re.sub(r"^[\"']?\$\{?CLAUDE_PROJECT_DIR\}?[\"']?[/\\]?", "", token).strip("\"'")
        p = (project / rel) if not Path(rel).is_absolute() else Path(rel)
        try:
            if p.is_file() and p.stat().st_size <= MAX_BYTES:
                disp = _display(p, project, t.scope)
                out += check_text(p.read_text(encoding="utf-8", errors="replace"), disp, "script")
        except OSError:
            continue
    return out


def _env_secrets(env, display: str, text: str) -> list[Finding]:
    out = []
    if isinstance(env, dict):
        for k, v in env.items():
            label = sec.looks_like_secret_value(str(k), str(v))
            if label:
                out.append(make("MB101", display, f"{label} stored in agent settings env var {k}.",
                                location=display, line=_find_line(text, str(k)),
                                evidence=f"{k}={sec.mask(str(v))}"))
    return out


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _find_line(text: str, needle: str) -> int | None:
    i = text.find(needle) if needle else -1
    if i < 0:
        i = text.find(json.dumps(needle)[1:-1])
    return _line_of(text, i) if i >= 0 else None
