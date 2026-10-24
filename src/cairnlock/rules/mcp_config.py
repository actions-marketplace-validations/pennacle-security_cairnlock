"""Enhanced MCP configuration security analysis.

Rule IDs: MCP001, MCP002, MCP003, MCP004
"""

from __future__ import annotations

import json
import re

from cairnlock.models import Finding

RULE_ID_001 = "MCP001"
RULE_ID_002 = "MCP002"
RULE_ID_003 = "MCP003"
RULE_ID_004 = "MCP004"

RULE_IDS = ("MCP001", "MCP002", "MCP003", "MCP004")

_AUTO_APPROVE_FLAGS = {
    "--auto-approve", "--yolo", "--dangerously-skip-permissions",
    "--dangerously", "--no-verify", "--insecure", "--allow-all",
    "--disable-auth", "--no-auth", "--trust-all",
}

# Shell and infrastructure commands are risky as MCP servers regardless of
# arguments. Package runners (npx, uvx, bunx, pnpm, yarn, pipx) are handled
# by UNP001 so one issue yields one finding.
_INFRA_COMMANDS = {
    "bash", "sh", "zsh", "fish", "powershell", "pwsh", "cmd",
    "curl", "wget", "docker", "podman", "kubectl", "helm",
}

_SENSITIVE_ENVS = {
    "AWS_", "AZURE_", "GOOGLE_", "GCP_", "KUBECONFIG",
    "DATABASE_", "DB_", "REDIS_", "MONGO_", "POSTGRES_",
    "SECRET_", "KEY_", "TOKEN_", "PASSWORD", "PASSWD",
    "PRIVATE_", "CERT_", "SSL_", "TLS_",
}


def _extract_servers(text: str) -> list[tuple[str, dict]]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    servers: list[tuple[str, dict]] = []
    for key in ("mcpServers", "mcp"):
        if key in data and isinstance(data[key], dict):
            for name, cfg in data[key].items():
                if isinstance(cfg, dict):
                    servers.append((name, cfg))
    return servers


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith(".json")


def check(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for name, cfg in _extract_servers(text):
        # MCP001: auto-approve / permission-skipping
        if cfg.get("autoApprove") is True:
            findings.append(Finding(rule_id=RULE_ID_001, severity="high", path=rel_path, line=0, message=f'server "{name}" enables autoApprove'))
        args = cfg.get("args", [])
        if isinstance(args, list):
            for arg in args:
                if isinstance(arg, str) and arg in _AUTO_APPROVE_FLAGS:
                    findings.append(Finding(rule_id=RULE_ID_001, severity="high", path=rel_path, line=0, message=f'server "{name}" uses permission-skipping flag: {arg}'))

        # MCP002: filesystem at root
        cmd = cfg.get("command", "")
        if cmd in ("npx", "uvx", "bunx") and isinstance(args, list):
            arg_str = " ".join(str(a) for a in args)
            if "server-filesystem" in arg_str:
                for arg in args:
                    if isinstance(arg, str) and re.match(r"^([A-Za-z]:\\?|/|~)$", arg):
                        findings.append(Finding(rule_id=RULE_ID_002, severity="medium", path=rel_path, line=0, message=f'filesystem server "{name}" mounted at root: {arg}'))
                        break

        # MCP003: shell or infrastructure command as the server executable
        if isinstance(cmd, str) and cmd in _INFRA_COMMANDS:
            findings.append(Finding(rule_id=RULE_ID_003, severity="medium", path=rel_path, line=0, message=f'server "{name}" runs infrastructure command: {cmd}'))

        # MCP004: sensitive environment variables passed to server
        env = cfg.get("env", {})
        if isinstance(env, dict):
            for env_key in env:
                if any(env_key.upper().startswith(p) for p in _SENSITIVE_ENVS):
                    findings.append(Finding(rule_id=RULE_ID_004, severity="high", path=rel_path, line=0, message=f'server "{name}" passes sensitive env var: {env_key}'))

    return findings
