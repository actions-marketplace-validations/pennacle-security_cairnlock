"""Embedded credentials in agent context files.

Rule ID: SEC001
Detects common secret patterns (API keys, tokens, passwords) in all scanned files.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "SEC001"

# (regex, kind, severity)
_PATTERNS = [
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "OpenAI-style API key", "high"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub personal access token", "high"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "GitHub fine-grained token", "high"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token", "high"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID", "high"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key", "high"),
]

# Generic assignment: api_key = "value", secret = 'value', etc.
_GENERIC_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*["']([^"'{<]{16,})["']"
)

# Placeholder substrings that indicate a non-secret example
_PLACEHOLDERS = (
    "your",
    "example",
    "changeme",
    "replace",
    "xxx",
    "todo",
    "<",
    "${",
    "env",
    "process.env",
    "$env:",
    "%(",
    "os.environ",
)


def applies_to(rel_path: str) -> bool:
    return True


def check(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []

    # Provider-specific patterns
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pat, kind, severity in _PATTERNS:
            if pat.search(line):
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity=severity,
                        path=rel_path,
                        line=lineno,
                        message=f"possible {kind}",
                    )
                )
                break  # one finding per line for provider patterns

    # Generic assignment pattern with placeholder filtering
    for lineno, line in enumerate(text.splitlines(), start=1):
        for m in _GENERIC_RE.finditer(line):
            value = m.group(2)
            low = value.lower()
            if any(ph in low for ph in _PLACEHOLDERS):
                continue
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    severity="medium",
                    path=rel_path,
                    line=lineno,
                    message="possible hardcoded credential assignment",
                )
            )
            break  # one per line
    return findings
