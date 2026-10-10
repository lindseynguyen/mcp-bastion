# AGENTS.md

## Setup
- Install deps: `pnpm install`
- Start dev server: `pnpm dev`

## Testing
- Run `pnpm turbo run test --filter <project_name>` before you commit.
- The commit should pass all tests before you merge.

## PR instructions
- Title format: [<project_name>] <Title>
- Always run `pnpm lint` and `pnpm test` before committing.
- Tiếng Việt: luôn chạy kiểm thử trước khi tạo pull request. Không commit file .env.
