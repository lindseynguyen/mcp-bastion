"""One definition of a scan request, shared by the CLI and the GUI so both run exactly
the same logic: option parsing, defaults, policy precedence and the pass/fail verdict."""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path

from .models import ScanResult, Severity
from .policy import Policy
from .scanner import ScanOptions


@dataclass
class ScanRequest:
    paths: list[str] = field(default_factory=list)
    project: str | None = None
    live: bool = False
    online: bool = False
    timeout: float = 20.0
    include_disabled: bool = False
    servers: list[str] = field(default_factory=list)
    lock: str | None = None
    update_lock: bool = False
    tools_file: str | None = None
    sources: list[str] = field(default_factory=list)
    engines: str = "all"                 # all | none | comma list
    policy: str | None = None
    instructions: bool = True
    baseline: str | None = None
    llm_url: str | None = None
    llm_model: str | None = None
    llm_mode: str = "review"
    llm_no_downgrade: bool = False
    llm_timeout: float = 60.0
    llm_api_key: str | None = None       # GUI only; the CLI reads MCP_BASTION_LLM_API_KEY
    fail_on: str | None = None           # overrides policy
    fail_score: int | None = None        # overrides policy

    @classmethod
    def from_dict(cls, data: dict) -> "ScanRequest":
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"unknown option(s): {', '.join(sorted(unknown))}")
        req = cls(**{k: v for k, v in data.items() if k in known})
        req.validate()
        return req

    def validate(self) -> None:
        def strs(v, name):
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError(f"{name} must be a list of strings")
        strs(self.paths, "paths")
        strs(self.servers, "servers")
        strs(self.sources, "sources")
        if self.llm_mode not in ("review", "all"):
            raise ValueError("llm_mode must be 'review' or 'all'")
        if self.fail_on is not None:
            Severity.parse(self.fail_on)
        if self.fail_score is not None and not (0 <= int(self.fail_score) <= 100):
            raise ValueError("fail_score must be between 0 and 100")
        if not (0 < float(self.timeout) <= 600) or not (0 < float(self.llm_timeout) <= 600):
            raise ValueError("timeouts must be between 0 and 600 seconds")
        if bool(self.llm_url) != bool(self.llm_model):
            raise ValueError("LLM judge needs both a URL and a model")
        for name in ("lock", "tools_file", "policy", "baseline", "project"):
            v = getattr(self, name)
            if v is not None and not isinstance(v, str):
                raise ValueError(f"{name} must be a path string")
        for p in [self.policy, self.tools_file, self.baseline]:
            if p and not Path(p).expanduser().is_file():
                raise ValueError(f"file not found: {p}")
        for p in self.paths + self.sources:
            if not Path(p).expanduser().exists():
                raise ValueError(f"path not found: {p}")


@dataclass
class Built:
    options: ScanOptions
    policy: Policy
    fail_on: Severity
    fail_score: int | None


def build(req: ScanRequest, env_judge: bool = True) -> Built:
    from .judge import JudgeConfig
    policy = Policy.load(_p(req.policy))
    e = req.engines.strip().lower()
    engines = None if e == "all" else ([] if e == "none" else [x.strip() for x in req.engines.split(",") if x.strip()])
    judge = None
    if req.llm_url or req.llm_model or env_judge:
        judge = JudgeConfig.from_env(req.llm_url, req.llm_model, mode=req.llm_mode,
                                     timeout=req.llm_timeout, allow_downgrade=not req.llm_no_downgrade,
                                     api_key=req.llm_api_key)
        if (req.llm_url or req.llm_model) and judge is None:
            raise ValueError("LLM judge needs both a URL and a model")
    opts = ScanOptions(
        paths=[_p(x) for x in req.paths], project_dir=_p(req.project), live=req.live, online=req.online,
        timeout=float(req.timeout), include_disabled=req.include_disabled, servers=list(req.servers),
        lockfile=_p(req.lock), update_lock=req.update_lock, integrations=engines,
        source_dirs=[_p(x) for x in req.sources], policy=policy, tools_file=_p(req.tools_file),
        instructions=req.instructions, baseline=_p(req.baseline), judge=judge)
    fail_on = Severity.parse(req.fail_on) if req.fail_on else policy.fail_on
    fail_score = req.fail_score if req.fail_score is not None else policy.max_risk_score
    return Built(opts, policy, fail_on, fail_score)


def verdict(result: ScanResult, fail_on: Severity, fail_score: int | None) -> dict:
    """Same rule the CLI uses for its exit code."""
    worst = result.max_severity()
    if worst is not None and worst >= fail_on:
        return {"failed": True, "reason": f"a finding reached {fail_on.name.lower()} (worst: {worst.name.lower()})"}
    if fail_score is not None:
        over = [s for s in result.scores if s.score >= fail_score]
        if over:
            return {"failed": True, "reason": f"{over[0].subject} scored {over[0].score} (limit {fail_score})"}
    return {"failed": False, "reason": f"no finding at {fail_on.name.lower()} or above"
            + (f" and no score ≥ {fail_score}" if fail_score is not None else "")}


def _p(v) -> Path | None:
    return Path(v).expanduser() if v else None
