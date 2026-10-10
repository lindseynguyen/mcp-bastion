import json

from conftest import rule_ids

from mcpbastion import report
from mcpbastion.cli import main
from mcpbastion.policy import Policy
from mcpbastion.scanner import ScanOptions, scan


def test_sarif_structure(fixtures):
    res = scan(ScanOptions(paths=[fixtures / "risky_config.json"], integrations=[]))
    sarif = json.loads(report.to_sarif(res))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids_declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= rule_ids_declared
    for r in run["tool"]["driver"]["rules"]:
        assert float(r["properties"]["security-severity"]) > 0
        assert any(t.startswith("MCP") for t in r["properties"]["tags"])
    assert all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in run["results"])
    assert len({json.dumps(r["partialFingerprints"]) for r in run["results"]}) == len(run["results"])


def test_json_html_markdown(fixtures):
    res = scan(ScanOptions(paths=[fixtures / "risky_config.json"], integrations=[]))
    data = json.loads(report.to_json(res))
    assert data["summary"]["high"] >= 5 and data["findings"][0]["severity"] in ("critical", "high")
    page = report.to_html(res)
    assert page.startswith("<!doctype html>") and "MB101" in page and "prefers-color-scheme" in page
    assert "ghp_aBcDeFg" not in page                     # secrets never reach reports
    assert "| HIGH |" in report.to_markdown(res)


def test_cli_exit_codes_and_outputs(fixtures, tmp_path, capsys):
    out = tmp_path / "r.sarif"
    code = main(["scan", str(fixtures / "risky_config.json"), "--engines", "none", "-o", str(out),
                 "-o", str(tmp_path / "r.html")])
    assert code == 1 and out.exists() and (tmp_path / "r.html").exists()
    assert main([str(fixtures / "clean_config.json"), "--engines", "none"]) == 0
    assert main([str(fixtures / "risky_config.json"), "--engines", "none", "--fail-on", "critical"]) == 0
    capsys.readouterr()
    assert main(["scan", str(fixtures / "risky_config.json"), "--engines", "none", "-f", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["summary"]["high"] > 0


def test_cli_misc_commands(fixtures, capsys):
    assert main(["rules"]) == 0 and "MB501" in capsys.readouterr().out
    assert main(["engines"]) == 0 and "detect-secrets" in capsys.readouterr().out
    assert main(["discover", str(fixtures / "risky_config.json")]) == 0
    assert "docker-tool" in capsys.readouterr().out


def test_policy_ignore_override_allow_block(fixtures, tmp_path):
    pol = tmp_path / "p.json"
    pol.write_text(json.dumps({
        "fail_on": "critical",
        "allowed_servers": ["github", "filesystem"],
        "blocked_packages": ["mcp-shell*"],
        "severity_overrides": {"MB202": "info"},
        "ignore": [{"rule": "MB401", "server": "remote-*"}],
    }))
    policy = Policy.load(pol)
    res = scan(ScanOptions(paths=[fixtures / "risky_config.json"], integrations=[], policy=policy))
    ids = rule_ids(res)
    assert "MB401" not in ids and res.suppressed >= 1
    assert all(f.severity.name == "INFO" for f in res.findings if f.rule_id == "MB202")
    blocked = [f for f in res.findings if f.rule_id == "MB404"]
    assert [f.server for f in blocked] == ["shell"]
    not_allowed = {f.server for f in res.findings if f.rule_id == "MB403"}
    assert "github" not in not_allowed and "docker-tool" in not_allowed


def test_yaml_policy_example_loads():
    from pathlib import Path
    p = Policy.load(Path(__file__).parents[1] / "examples" / "policy.yml")
    assert p.fail_on.name == "HIGH" and p.extra_injection_patterns


def test_no_secret_reaches_any_report(fixtures, capsys):
    secrets = ["ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "S3cr3tPassw0rd", "Zx9Qm2LpW8vRt4KdN7yB"]
    res = scan(ScanOptions(paths=[fixtures / "risky_config.json"], integrations=[]))
    outputs = [report.to_html(res), report.to_json(res), report.to_sarif(res), report.to_markdown(res)]
    report.console(res, verbose=True)
    main(["discover", str(fixtures / "risky_config.json")])
    outputs.append(capsys.readouterr().out)
    for out in outputs:
        for s in secrets:
            assert s not in out


def test_scrub():
    from mcpbastion.secrets import scrub
    assert "hunter2xyz" not in scrub("postgres://u:hunter2xyz@h/db")
    assert scrub("https://h/x?api_key=abcdef123456&page=2").endswith("api_key=****&page=2")
    assert "s3cr3tv4lue99" not in scrub("--api-key s3cr3tv4lue99")
    assert scrub("--token ${env:TOKEN}") == "--token ${env:TOKEN}"
