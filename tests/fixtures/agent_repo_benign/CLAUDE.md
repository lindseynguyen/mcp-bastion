<!-- markdownlint-disable MD013 -->
# CLAUDE.md

This file guides AI coding agents working in this repository. 👨‍💻 Made with ❤️ in Đà Nẵng and London 🏴󠁧󠁢󠁥󠁮󠁧󠁿.

## Commands

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # install uv once
uv sync
make test
curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/acme/app/pulls
```

## Rules

- IMPORTANT: You must always run `make test` before committing. Never skip failing tests.
- Never commit `.env` files or credentials. Do not print secrets in logs.
- Never run `rm -rf /` or `rm -rf ~`; only delete files inside `build/`. Use `rm -rf build/` to clean.
- Do NOT use `--dangerously-skip-permissions`, and never disable the sandbox.
- Ask for confirmation before running anything that writes outside the repo.
- Use ngrok to expose the local server when testing webhooks from Stripe.
- Send a short summary of your changes in the PR description.
- Read `docs/architecture.md` before changing the event bus.

<example>
User: add a field to the session model
Assistant: updates `session.py`, adds a test, runs `make test`.
</example>

See @docs/architecture.md for the module layout.
