"""Rule catalogue: one place for IDs, titles, default severity, remediation and
mappings to the OWASP MCP Top 10 (MCP01-MCP10) and the OWASP Top 10 for
Agentic Applications (ASI01-ASI10)."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding, Severity

OWASP_MCP = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

OWASP_ASI = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    remediation: str
    mcp: tuple[str, ...] = field(default_factory=tuple)
    asi: tuple[str, ...] = field(default_factory=tuple)
    category: str = "config"


_RULES = [
    # ------------------------------------------------------------ config: secrets
    Rule("MB101", "Hard-coded secret in server configuration", Severity.HIGH,
         "Move the secret to an OS keychain / secret manager or an env var resolved at "
         "launch (e.g. ${env:VAR}); rotate the exposed value.",
         ("MCP01",), ("ASI03",)),
    Rule("MB102", "Credential embedded in URL", Severity.HIGH,
         "Send credentials in an Authorization header loaded from a secret store, "
         "never in the URL (it ends up in logs and history).",
         ("MCP01",), ("ASI03",)),
    Rule("MB103", "Configuration file readable by other users", Severity.MEDIUM,
         "Restrict permissions: chmod 600 on the config file.",
         ("MCP01",), ("ASI03",)),
    # ------------------------------------------------------------ config: supply chain
    Rule("MB201", "Package launched without a pinned version", Severity.MEDIUM,
         "Pin an exact version (pkg@1.2.3 / pkg==1.2.3) so a compromised new release "
         "cannot run automatically.",
         ("MCP04",), ("ASI04",), "supply-chain"),
    Rule("MB202", "Package auto-installed and executed on launch", Severity.LOW,
         "Prefer installing once and running a pinned, verified binary instead of "
         "npx -y / uvx fetching code on every start.",
         ("MCP04",), ("ASI04",), "supply-chain"),
    Rule("MB203", "Container image not pinned by digest", Severity.LOW,
         "Reference the image as image@sha256:<digest>.",
         ("MCP04",), ("ASI04",), "supply-chain"),
    Rule("MB204", "Package installed from an untrusted or direct URL", Severity.HIGH,
         "Install from the official registry with a pinned version, or vendor and review the code.",
         ("MCP04",), ("ASI04",), "supply-chain"),
    Rule("MB205", "Known vulnerability or malicious package (OSV)", Severity.HIGH,
         "Upgrade to a fixed version or remove the server. Malicious (MAL-) entries must be "
         "removed immediately and the host investigated.",
         ("MCP04",), ("ASI04",), "supply-chain"),
    # ------------------------------------------------------------ config: execution
    Rule("MB301", "Server launched through a shell or download-and-execute", Severity.HIGH,
         "Launch the server binary directly; never pipe remote content into a shell.",
         ("MCP05",), ("ASI05",)),
    Rule("MB302", "Container runs with elevated privileges or host access", Severity.HIGH,
         "Drop --privileged / host namespaces, mount only the folders the tool needs, read-only.",
         ("MCP02", "MCP05"), ("ASI03", "ASI05")),
    Rule("MB303", "Server runs with administrator rights", Severity.HIGH,
         "Run MCP servers as an unprivileged user.",
         ("MCP02",), ("ASI03",)),
    Rule("MB304", "Over-broad filesystem access", Severity.HIGH,
         "Scope filesystem servers to a project folder, never /, the home directory or a drive root.",
         ("MCP02", "MCP10"), ("ASI03",)),
    Rule("MB305", "TLS certificate verification disabled", Severity.HIGH,
         "Remove NODE_TLS_REJECT_UNAUTHORIZED=0 / *_VERIFY=0 style settings; trust the "
         "proxy CA explicitly instead.",
         ("MCP07",), ("ASI07",)),
    Rule("MB306", "Unrestricted shell / code execution capability", Severity.MEDIUM,
         "Only enable shell/code-execution servers in sandboxes, with an allow-list of commands "
         "and human approval for every call.",
         ("MCP05", "MCP02"), ("ASI05", "ASI02")),
    # ------------------------------------------------------------ config: transport / auth
    Rule("MB401", "Remote server over plain HTTP", Severity.HIGH,
         "Use HTTPS for every non-loopback MCP endpoint.",
         ("MCP07",), ("ASI07",)),
    Rule("MB402", "Remote server without authentication", Severity.MEDIUM,
         "Require OAuth 2.1 / bearer tokens for remote MCP servers.",
         ("MCP07",), ("ASI03", "ASI07")),
    Rule("MB403", "Server not on the approved list", Severity.MEDIUM,
         "Review the server and add it to the policy allow-list, or remove it.",
         ("MCP09",), ("ASI04", "ASI10")),
    Rule("MB404", "Server blocked by policy", Severity.CRITICAL,
         "Remove the server; it matches a package or URL your policy forbids.",
         ("MCP09", "MCP04"), ("ASI04",)),
    Rule("MB405", "Same server name configured differently across clients", Severity.LOW,
         "Keep one reviewed definition per server; diverging copies hide shadow servers.",
         ("MCP09",), ("ASI04",)),
    # ------------------------------------------------------------ tools: poisoning
    Rule("MB501", "Prompt-injection instructions in tool metadata", Severity.CRITICAL,
         "Do not use this server. Tool descriptions must describe the tool, not instruct the model.",
         ("MCP03", "MCP06"), ("ASI01", "ASI02"), "tool"),
    Rule("MB502", "Hidden or invisible characters in tool metadata", Severity.HIGH,
         "Reject descriptions containing zero-width, bidi-override or Unicode tag characters.",
         ("MCP03",), ("ASI01",), "tool"),
    Rule("MB503", "Tool metadata references sensitive files or secrets", Severity.HIGH,
         "A tool should never ask the model to read keys, .env files or other servers' configs.",
         ("MCP03", "MCP01", "MCP10"), ("ASI01", "ASI03"), "tool"),
    Rule("MB504", "Tool metadata instructs data exfiltration", Severity.CRITICAL,
         "Remove the server and review recent tool calls for leaked data.",
         ("MCP03", "MCP10"), ("ASI01", "ASI02"), "tool"),
    Rule("MB505", "Tool shadowing: description targets another tool", Severity.HIGH,
         "A tool must not change how other servers' tools behave. Remove or isolate the server.",
         ("MCP03", "MCP06"), ("ASI01", "ASI07"), "tool"),
    Rule("MB506", "Encoded payload in tool metadata", Severity.MEDIUM,
         "Decode and review; legitimate descriptions rarely carry base64/hex blobs.",
         ("MCP03",), ("ASI01",), "tool"),
    Rule("MB507", "Unusually long tool description", Severity.LOW,
         "Review the full text with `mcp-bastion inspect`; long descriptions hide instructions.",
         ("MCP03",), ("ASI01",), "tool"),
    Rule("MB508", "Suspicious hidden parameter", Severity.HIGH,
         "Parameters such as 'sidenote' or 'context' that ask the model for extra data are a "
         "classic exfiltration channel.",
         ("MCP03", "MCP10"), ("ASI01", "ASI02"), "tool"),
    Rule("MB509", "Tool name collides with another server's tool", Severity.MEDIUM,
         "Rename or remove one of the tools; the model may call the wrong (malicious) one.",
         ("MCP03", "MCP09"), ("ASI02",), "tool"),
    Rule("MB510", "Tool metadata asks to hide actions from the user", Severity.CRITICAL,
         "Instructions to keep actions secret are a strong sign of malicious intent.",
         ("MCP03", "MCP06"), ("ASI09", "ASI01"), "tool"),
    Rule("MB511", "ML prompt-injection classifier flagged tool metadata", Severity.HIGH,
         "Review the flagged text; the classifier score is attached as evidence.",
         ("MCP03", "MCP06"), ("ASI01",), "tool"),
    # ------------------------------------------------------------ tools: capability / flows
    Rule("MB601", "Dangerous capability exposed", Severity.INFO,
         "Require human confirmation for destructive or code-executing tools.",
         ("MCP02",), ("ASI02", "ASI05"), "capability"),
    Rule("MB602", "Toxic flow: untrusted input + private data + exfiltration sink", Severity.HIGH,
         "The same agent can read untrusted content, access private data and send data out "
         "(the 'lethal trifecta'). Split these servers across agents or gate the sink.",
         ("MCP06", "MCP10"), ("ASI01", "ASI02", "ASI08"), "capability"),
    Rule("MB603", "Destructive tool not annotated as such", Severity.LOW,
         "Set destructiveHint / readOnlyHint annotations so clients can ask for confirmation.",
         ("MCP02", "MCP08"), ("ASI02",), "capability"),
    # ------------------------------------------------------------ rug pull
    Rule("MB701", "Tool definition changed since it was pinned (rug pull)", Severity.HIGH,
         "Review the diff with `mcp-bastion inspect`; re-pin only if the change is expected.",
         ("MCP03", "MCP04"), ("ASI04", "ASI10"), "pinning"),
    Rule("MB702", "New tool appeared since last pin", Severity.MEDIUM,
         "Review the new tool before allowing the agent to use it.",
         ("MCP02", "MCP04"), ("ASI04",), "pinning"),
    Rule("MB703", "Pinned tool disappeared", Severity.INFO,
         "Confirm the removal is expected, then re-pin.",
         ("MCP08",), ("ASI04",), "pinning"),
    # ------------------------------------------------------------ source code
    Rule("MB801", "Insecure code in server source", Severity.MEDIUM,
         "Fix the flagged code; see the engine's message for details.",
         ("MCP05",), ("ASI05",), "source"),
    Rule("MB802", "Secret committed in server source", Severity.HIGH,
         "Remove the secret from source and history, then rotate it.",
         ("MCP01",), ("ASI03",), "source"),
    # ------------------------------------------------------------ agent instruction files
    Rule("MB1101", "Hidden characters in agent instruction file", Severity.HIGH,
         "Remove invisible / bidi / Unicode-tag characters. Agents read them; reviewers do not.",
         ("MCP06", "MCP10"), ("ASI01", "ASI06"), "instructions"),
    Rule("MB1102", "Instruction file tells the agent to hide actions from the user", Severity.CRITICAL,
         "Delete the instruction and review recent agent activity in this repository.",
         ("MCP06",), ("ASI01", "ASI09"), "instructions"),
    Rule("MB1103", "Instruction file tells the agent to send data out", Severity.CRITICAL,
         "Delete the instruction, check commit history for who added it and rotate any exposed secrets.",
         ("MCP06", "MCP10", "MCP01"), ("ASI01", "ASI02", "ASI06"), "instructions"),
    Rule("MB1104", "Instruction file runs a dangerous command", Severity.HIGH,
         "Agents execute what these files say. Remove download-and-execute, destructive and "
         "persistence commands, or replace them with pinned, reviewed scripts.",
         ("MCP05",), ("ASI05", "ASI06"), "instructions"),
    Rule("MB1105", "Instruction file disables agent safety controls", Severity.HIGH,
         "Keep permission prompts and sandboxing on; never ship bypass flags in shared instructions.",
         ("MCP02", "MCP06"), ("ASI02", "ASI03", "ASI09"), "instructions"),
    Rule("MB1106", "Instruction file overrides system or user instructions", Severity.HIGH,
         "Project instructions must not claim system authority or cancel earlier instructions.",
         ("MCP06",), ("ASI01", "ASI06"), "instructions"),
    Rule("MB1107", "Instructions hidden from human readers", Severity.MEDIUM,
         "Text in HTML comments or hidden markup is invisible in rendered Markdown but read by "
         "agents. Make it visible or remove it.",
         ("MCP06", "MCP10"), ("ASI01", "ASI06"), "instructions"),
    Rule("MB1108", "Encoded payload in instruction file", Severity.MEDIUM,
         "Decode and review; instruction files have no reason to carry base64/hex blobs.",
         ("MCP06",), ("ASI01", "ASI06"), "instructions"),
    Rule("MB1109", "Instruction file pulls credentials into the agent's context", Severity.MEDIUM,
         "Never tell an agent to read, print or import keys, .env files or credential stores.",
         ("MCP01", "MCP10"), ("ASI03", "ASI06"), "instructions"),
    Rule("MB1110", "Command runs automatically through agent hooks or tasks", Severity.MEDIUM,
         "Review every hook / auto-run task in shared settings; they execute without a prompt.",
         ("MCP05",), ("ASI05", "ASI04"), "instructions"),
    Rule("MB1111", "Workspace auto-approves agent actions", Severity.HIGH,
         "Remove auto-approval / bypass-permission settings from shared configuration.",
         ("MCP02",), ("ASI02", "ASI03", "ASI09"), "instructions"),
    Rule("MB1112", "Project auto-enables every MCP server it declares", Severity.MEDIUM,
         "Approve project MCP servers individually instead of enableAllProjectMcpServers.",
         ("MCP09", "MCP02"), ("ASI04",), "instructions"),
    Rule("MB1113", "Agent skill ships executable scripts", Severity.INFO,
         "Skills run their scripts with the agent's permissions; the code engines scanned them.",
         ("MCP04", "MCP05"), ("ASI04", "ASI05"), "instructions"),
    # ------------------------------------------------------------ scanner
    Rule("MB901", "Server could not be inspected", Severity.INFO,
         "Run with --live in an environment where the server can start, or check the command.",
         ("MCP08",), (), "scanner"),
]

RULES: dict[str, Rule] = {r.id: r for r in _RULES}


def make(rule_id: str, server: str, message: str, *, location: str = "",
         evidence: str = "", severity: Severity | None = None, source: str = "mcp-bastion",
         line: int | None = None, title: str | None = None) -> Finding:
    from ..secrets import scrub
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=title or rule.title,
        severity=severity if severity is not None else rule.severity,
        server=server,
        message=scrub(message),
        location=location,
        evidence=_clip(scrub(evidence)),
        remediation=rule.remediation,
        owasp_mcp=list(rule.mcp),
        owasp_asi=list(rule.asi),
        source=source,
        line=line,
    )


def _clip(text: str, limit: int = 300) -> str:
    text = (text or "").replace("\r", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
