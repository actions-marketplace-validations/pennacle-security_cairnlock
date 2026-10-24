"""Rules package: exports all detection rules and metadata."""

from __future__ import annotations

from cairnlock.rules import (
    embedded_secrets,
    hidden_unicode,
    mcp_config,
    prompt_injection,
    remote_download,
    unpinned_exec,
)

# Order matters only for deterministic output
RULES = [
    hidden_unicode,
    prompt_injection,
    remote_download,
    mcp_config,
    unpinned_exec,
    embedded_secrets,
]

RULE_META = {
    "HUC001": "hidden or bidirectional Unicode in instruction files",
    "PIN001": "prompt-injection phrase in a tool or skill description",
    "REM001": "remote download or pipe-to-shell in a skill file",
    "MCP001": "auto-approve or permission-skipping flag in an MCP config",
    "MCP002": "MCP filesystem server mounted at a filesystem root",
    "UNP001": "npx or uvx package without a version pin",
    "SEC001": "possible embedded credential",
}
