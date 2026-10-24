"""Tool and function calling injection patterns.

Rule ID: TOO001
Detects injection risks in tool/function calling definitions.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "TOO001"

RULE_IDS = ("TOO001",)

_PATTERNS = [
    # OpenAI function calling
    (r"\"function_call\"\s*:", "OpenAI function_call - verify schema", "medium"),
    (r"\"tool_choice\"\s*:", "OpenAI tool_choice - verify restrictions", "medium"),
    (r"\"functions\"\s*:\s*\[", "OpenAI functions array - verify each schema", "medium"),

    # Anthropic tool use
    (r"\"tool_use\"\s*:", "Anthropic tool_use - verify permissions", "medium"),
    (r"\"tool_choice\"\s*:\s*\{", "Anthropic tool_choice object - verify", "medium"),

    # LangChain / LangGraph
    (r"AgentExecutor|create_react_agent|create_tool_calling_agent", "LangChain agent - verify tool permissions", "medium"),
    (r"StructuredTool|Tool\(|@tool", "LangChain tool definition - verify", "medium"),
    (r"bind_tools\s*\(", "bind_tools - verify tool schemas", "medium"),

    # AutoGPT / BabyAGI style
    (r"auto_gpt|AutoGPT|baby_agi|BabyAGI", "Autonomous agent framework - high risk", "high"),

    # Dangerous tool patterns
    (r"\"name\"\s*:\s*[\"'](?:shell|exec|command|bash|python|eval|subprocess)[\"']", "Tool with shell/exec name - high risk", "high"),
    (r"\"description\"\s*:\s*[\"'][^\"]*(?:exec|shell|command|arbitrary)[^\"]*[\"']", "Tool description indicates arbitrary execution", "high"),
    (r"\"parameters\"\s*:\s*\{[^}]*\"type\"\s*:\s*[\"']object[\"']", "Tool with object params - verify schema", "medium"),

    # MCP tool risks
    (r"\"mcp\"\s*:\s*\{[^}]*\"tools\"\s*:", "MCP tools configuration - verify each", "medium"),
    (r"\"server\"\s*:\s*\{[^}]*\"command\"\s*:", "MCP server command - verify safety", "high"),

    # Function calling without restrictions
    (r"\"strict\"\s*:\s*false", "Strict mode disabled - injection risk", "high"),
    (r"\"allow_arbitrary\"\s*:\s*true", "Arbitrary function calling enabled", "high"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith((".json", ".yaml", ".yml", ".toml", ".py", ".js", ".ts", ".md", ".txt"))


def check(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pat, message, severity in _COMPILED:
            if pat.search(line):
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity=severity,
                        path=rel_path,
                        line=lineno,
                        message=message,
                    )
                )
                break
    return findings
