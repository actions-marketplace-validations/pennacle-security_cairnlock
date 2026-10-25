"""Risky permission allowlists in Claude Code settings.

Rule ID: CLD001
Claude Code's .claude/settings.json carries a permissions.allow list. An
entry like Bash(curl:*) or a bare Bash hands the agent unrestricted shell
and network access, and defaultMode "bypassPermissions" turns the whole
permission system off. All three are configuration, not accidents, so they
are reported at high severity.
"""

from __future__ import annotations

import json
import re

from cairnlock.models import Finding

RULE_ID = "CLD001"

RULE_IDS = ("CLD001",)

# Shell and network commands that must not be blanket-allowed for an agent.
_RISKY_COMMANDS = {
    "bash", "sh", "zsh", "fish", "powershell", "pwsh",
    "curl", "wget", "ssh", "scp", "nc", "ncat", "netcat", "eval",
}

_BASH_ENTRY = re.compile(r"^Bash\(\s*([A-Za-z0-9_.\-]+)\s*(?::[^)]*)?\)\s*$")


def _find_permissions(node: object) -> dict | None:
    """Return the first permissions object found anywhere in the JSON tree."""
    if isinstance(node, dict):
        perms = node.get("permissions")
        if isinstance(perms, dict):
            return perms
        for value in node.values():
            found = _find_permissions(value)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_permissions(item)
            if found is not None:
                return found
    return None


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith(".json")


def check(rel_path: str, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    perms = _find_permissions(data)
    if perms is None:
        return []

    findings: list[Finding] = []

    mode = perms.get("defaultMode")
    if mode == "bypassPermissions":
        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity="high",
                path=rel_path,
                line=0,
                message="permission defaultMode bypasses all permission checks",
            )
        )

    allow = perms.get("allow", [])
    if not isinstance(allow, list):
        return findings

    for entry in allow:
        if not isinstance(entry, str):
            continue
        stripped = entry.strip()
        if stripped == "Bash" or stripped.startswith("Bash(*"):
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    severity="high",
                    path=rel_path,
                    line=0,
                    message="allowlist grants unrestricted Bash access",
                )
            )
            continue
        match = _BASH_ENTRY.match(stripped)
        if match:
            command = match.group(1).lower()
            if command in _RISKY_COMMANDS:
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity="high",
                        path=rel_path,
                        line=0,
                        message=f"allowlist grants network or shell command: {command}",
                    )
                )
    return findings
