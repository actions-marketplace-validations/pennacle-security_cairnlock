"""Rules package: exports all detection rules and metadata."""

from __future__ import annotations

from cairnlock.rules import (
    config_injection,
    crypto_weakness,
    embedded_secrets,
    env_manipulation,
    filesystem_access,
    hidden_unicode,
    mcp_config,
    network_exfil,
    obfuscation,
    privilege_escalation,
    prompt_injection,
    remote_download,
    shell_commands,
    supply_chain,
    tool_injection,
    unpinned_exec,
)

# Order matters for deterministic output
RULES = [
    hidden_unicode,
    prompt_injection,
    remote_download,
    mcp_config,
    unpinned_exec,
    embedded_secrets,
    shell_commands,
    network_exfil,
    filesystem_access,
    env_manipulation,
    privilege_escalation,
    obfuscation,
    supply_chain,
    config_injection,
    tool_injection,
    crypto_weakness,
]

RULE_META = {
    "HUC001": "hidden or bidirectional Unicode in instruction files",
    "PIN001": "prompt-injection phrase in a tool or skill description",
    "REM001": "remote download or pipe-to-shell in a skill file",
    "MCP001": "auto-approve or permission-skipping flag in an MCP config",
    "MCP002": "MCP filesystem server mounted at a filesystem root",
    "MCP003": "MCP server runs a shell or infrastructure command",
    "MCP004": "MCP server passed sensitive environment variable",
    "UNP001": "package-runner package without a version pin",
    "SEC001": "possible embedded credential",
    "SHC001": "shell command execution pattern",
    "NET001": "suspicious network or data exfiltration pattern",
    "FSY001": "suspicious file system access",
    "ENV001": "environment variable manipulation or credential access",
    "PRI001": "privilege escalation or process injection pattern",
    "OBF001": "encoding, obfuscation, or data hiding pattern",
    "SUP001": "supply chain attack risk in dependencies",
    "CFG001": "configuration or template injection",
    "TOO001": "tool or function calling injection",
    "CRY001": "cryptographic weakness or insecure randomness",
}

# Profiles are exclusive: exactly one runs per scan. core covers agent
# context files; extended covers source and dependency files.
PROFILE_RULES = {
    "core": {
        "HUC001", "PIN001", "REM001",
        "MCP001", "MCP002", "MCP003", "MCP004",
        "UNP001", "TOO001",
    },
    "extended": {
        "SEC001", "SHC001", "NET001", "FSY001", "ENV001",
        "PRI001", "OBF001", "SUP001", "CFG001", "CRY001",
    },
}

PROFILE_NAMES = ("core", "extended")


def rule_ids(rule) -> set[str]:
    """Return the rule ids a module can emit."""
    ids = getattr(rule, "RULE_IDS", None)
    if ids:
        return set(ids)
    rid = getattr(rule, "RULE_ID", None)
    return {rid} if rid else set()
