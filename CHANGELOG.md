# Changelog

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
