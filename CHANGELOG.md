# Changelog

## [0.4.0] - 2026-10-11

### Added
- **LLM judge** (`--llm-url`, `--llm-model`, `--llm-mode review|all`): any OpenAI-compatible endpoint
  (LiteLLM, Ollama, vLLM, OpenAI) classifies the intent of tool metadata and instruction files.
  New findings as MB513 with English and Vietnamese reasons; confirms rule findings; can lower a
  HIGH/MEDIUM finding one level when confident it is benign (`--llm-no-downgrade`). Untrusted text
  is delimited with a random nonce, secrets are masked before sending, CRITICAL / hidden-text /
  typosquat / rug-pull findings are never lowered, verdicts are cached, failures never stop a scan.
- **Risk score** 0-100 and grade A-F per server, file and agent, plus a weakest-link overall score,
  in console, JSON, HTML and Markdown. `--fail-score N` and policy `max_risk_score`.
- GitHub Action input `fail-score`.

## [0.3.0] - 2026-10-11

### Added
- **Typosquat / look-alike package detection** (MB206): look-alike scopes, official package
  names re-published under another scope or none, digit and homoglyph swaps, one-character
  typos, against ~80 widely used MCP servers (npm and PyPI, PEP 503 aware).
- **Homoglyph tool names** (MB512): non-Latin look-alike letters in tool names, and tools on
  different servers whose names look identical.
- **Baselines**: `--write-baseline` / `--baseline` to report only new findings; line-independent
  fingerprints; CRITICAL is never baselined.
- **Inline ignores** in instruction files: `mcp-bastion-ignore[MB1104]`; never applies to CRITICAL;
  `inline_ignores: false` policy switch; suppressed counts shown in every report.
- **pre-commit hook** (`.pre-commit-hooks.yaml`).

## [0.2.0] - 2026-10-11

### Added
- **Agent instruction file scanning** (rules MB1101–MB1113): `CLAUDE.md`, `AGENTS.md`,
  `GEMINI.md`, Cursor / Windsurf / Cline / Roo / Continue / Kiro rules, Copilot instructions and
  prompts, Claude Code commands, agents, skills (with their scripts) and settings (hooks,
  `apiKeyHelper`, permissions, `enableAllProjectMcpServers`), VS Code auto-approve and
  folder-open tasks, Codex approval / sandbox settings.
- Detection of Unicode-tag ASCII smuggling and variation-selector "emoji smuggling", with the
  hidden text decoded and analysed; instructions hidden in HTML comments and hidden markup.
- Scripts called by hooks and shipped in skills are analysed and sent to the code engines.
- `--no-instructions`; `discover` lists instruction files; reports count them.
- English and Vietnamese patterns; negated statements ("never run …") are not reported.

### Changed
- GitHub Action scans `.` by default (MCP configs and instruction files).

## [0.1.0] - 2026-10-10
- First release: MCP config, live tool, rug-pull and code scanning with six engines.
