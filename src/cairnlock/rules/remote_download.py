"""Remote downloads, pipe-to-shell, and base64 payloads in skill files.

Rule ID: REM001
Applies to SKILL.md files and files under any skills/ directory.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "REM001"

RULE_IDS = ("REM001",)

# (regex, message, severity)
_PATTERNS = [
    (
        r"\bcurl\s+[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
        "curl piped into a shell",
        "high",
    ),
    (
        r"\bwget\s+[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
        "wget piped into a shell",
        "high",
    ),
    (
        r"\bcurl\s+[^|\n]*\|\s*(?:python3?|pwsh|powershell)\b",
        "curl piped into an interpreter",
        "high",
    ),
    (
        r"\binvoke-(?:webrequest|restmethod)\b[^|\n]*\|\s*(?:iex|invoke-expression)\b",
        "PowerShell download piped into Invoke-Expression",
        "high",
    ),
    (
        r"\biwr\b[^|\n]*\|\s*iex\b",
        "PowerShell download piped into iex",
        "high",
    ),
    (
        r"\bbase64\s+(?:-d|--decode|-D)\b[^|\n]*\|\s*(?:ba)?sh\b",
        "base64 decode piped into a shell",
        "high",
    ),
    (
        r"\bcertutil\s+-urlcache\b",
        "certutil remote download",
        "high",
    ),
    (
        r"[A-Za-z0-9+/]{200,}={0,2}",
        "long base64 blob (possible encoded payload)",
        "high",
    ),
    (
        r"\bgit\s+clone\s+https?://",
        "git clone from a remote URL",
        "medium",
    ),
    (
        r"\bpip\s+install\b[^|\n]*git\+https?://",
        "pip install from a remote git URL",
        "medium",
    ),
    (
        r"\bnpm\s+install\b[^|\n]*https?://",
        "npm install from a remote URL",
        "medium",
    ),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    name = rel_path.rsplit("/", 1)[-1]
    return name == "SKILL.md" or "skills" in rel_path.split("/")[:-1]


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
                break  # one finding per line
    return findings
