"""Risky MCP server configurations.

Rule IDs: MCP001 (auto-approve / permission-skipping flags)
          MCP002 (filesystem server mounted at a filesystem root)
"""

from __future__ import annotations

import json
import re

from cairnlock.models import Finding

RULE_ID_001 = "MCP001"
RULE_ID_002 = "MCP002"

# Flags that indicate auto-approve / permission bypass
_AUTO_APPROVE_FLAGS = {
    "--auto-approve",
    "--yolo",
    "--dangerously-skip-permissions",
    "--dangerously",
}


def _extract_servers(text: str) -> list[tuple[str, dict]]:
    """Return list of (server_name, config_dict) from MCP JSON text."""
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
        # MCP001: auto-approve flag in args or explicit autoApprove
        if cfg.get("autoApprove") is True:
            findings.append(
                Finding(
                    rule_id=RULE_ID_001,
                    severity="high",
                    path=rel_path,
                    line=0,
                    message=f'server "{name}" enables auto-approve',
                )
            )
        args = cfg.get("args", [])
        if isinstance(args, list):
            for arg in args:
                if isinstance(arg, str) and arg in _AUTO_APPROVE_FLAGS:
                    findings.append(
                        Finding(
                            rule_id=RULE_ID_001,
                            severity="high",
                            path=rel_path,
                            line=0,
                            message=f'server "{name}" uses permission-skipping flag: {arg}',
                        )
                    )
        # MCP002: filesystem server mounted at a root path
        cmd = cfg.get("command", "")
        if cmd in ("npx", "uvx", "bunx") and isinstance(args, list):
            arg_str = " ".join(str(a) for a in args)
            if "server-filesystem" in arg_str:
                for arg in args:
                    if isinstance(arg, str) and re.match(r"^([A-Za-z]:\\?|/|~)$", arg):
                        findings.append(
                            Finding(
                                rule_id=RULE_ID_002,
                                severity="medium",
                                path=rel_path,
                                line=0,
                                message=f'filesystem server "{name}" mounted at root path: {arg}',
                            )
                        )
                        break
    return findings
