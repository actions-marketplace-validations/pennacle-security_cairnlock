"""Configuration injection and template injection patterns.

Rule ID: CFG001
Detects configuration/template injection vulnerabilities.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "CFG001"

RULE_IDS = ("CFG001",)

_PATTERNS = [
    # Template injection
    (r"\{\{.*\}\}", "Double curly braces - template injection risk", "high"),
    (r"\{\%.*\%\}", "Template control structures - injection risk", "high"),
    (r"\$\{.*\}", "Dollar-brace template - injection risk", "high"),
    (r"#\{.*\}", "Hash-brace template - injection risk", "medium"),

    # Jinja2 specific
    (r"\{\{\s*config\s*\.", "Jinja2 config access - potential exposure", "medium"),
    (r"\{\{\s*request\s*\.", "Jinja2 request access - potential SSRF", "high"),
    (r"\{\{\s*session\s*\.", "Jinja2 session access - potential exposure", "medium"),
    (r"\{\{\s*g\s*\.", "Jinja2 g object - potential exposure", "medium"),
    (r"\{\{\s*url_for\s*\(", "Jinja2 url_for - open redirect risk", "medium"),
    (r"\{\{\s*get_flashed_messages\s*\(", "Jinja2 flashed messages - info leak", "low"),

    # YAML/JSON injection
    (r"!!python/object|!!python/name|!!python/module", "YAML unsafe tags - deserialization risk", "high"),
    (r"__import__|__builtins__|__globals__|__locals__", "Python dunder in config - injection risk", "high"),

    # Spring/SpEL injection
    (r"#\{.*T\(.*\)", "Spring SpEL type access - injection risk", "high"),
    (r"#\{.*@.*\}", "Spring SpEL bean reference - injection risk", "high"),

    # Config file credentials travel over connection strings; plain
    # assignments belong to SEC001 so one issue yields one finding.
    (r"(?:jdbc|mongodb|redis|postgres|mysql)://[^:\s]+:[^@\s]+@", "Connection string with credentials", "high"),

    # Environment-specific configs
    (r"\.env\.(?:prod|production|staging|dev|local)", "Environment-specific config file", "low"),
    (r"config\.(?:prod|production|staging)\.(?:json|yaml|yml)", "Production config file", "medium"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith((".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".html", ".htm", ".j2", ".jinja", ".jinja2", ".md", ".txt"))


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
