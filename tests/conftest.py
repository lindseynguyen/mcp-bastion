import json
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
MOCK = FIXTURES / "mock_server.py"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def live_config(tmp_path):
    """Write a config with mock stdio servers. Usage: live_config({"name": "poisoned"})."""
    def make(profiles: dict[str, str], extra_env: dict | None = None) -> Path:
        servers = {}
        for name, profile in profiles.items():
            servers[name] = {"command": sys.executable, "args": [str(MOCK)],
                             "env": {"MOCK_PROFILE": profile, **(extra_env or {})}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps({"mcpServers": servers}))
        path.chmod(0o600)
        return path
    return make


def rule_ids(result_or_findings) -> set[str]:
    findings = getattr(result_or_findings, "findings", result_or_findings)
    return {f.rule_id for f in findings}
