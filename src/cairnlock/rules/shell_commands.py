"""Dangerous shell command execution patterns.

Rule ID: SHC001
Detects shell command execution patterns that could lead to RCE.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "SHC001"

# Shell command execution patterns with severity
_PATTERNS = [
    # Direct shell execution
    (r"\beval\s*\(\s*[\"']", "eval() with string - potential code injection", "high"),
    (r"\bexec\s*\(\s*[\"']", "exec() with string - potential code injection", "high"),
    (r"\bexecfile\s*\(", "execfile() - deprecated dangerous function", "high"),
    (r"\bcompile\s*\(\s*[\"']", "compile() with string - potential code injection", "high"),
    (r"__import__\s*\(\s*[\"']", "__import__() with string - dynamic import", "medium"),

    # Shell command execution
    (r"\bos\.system\s*\(", "os.system() - shell command execution", "high"),
    (r"\bsubprocess\.(run|call|Popen|check_output)\s*\(", "subprocess execution - verify shell=False", "medium"),
    (r"\bcommands\.(getstatusoutput|getoutput)\s*\(", "commands module - deprecated shell execution", "high"),
    (r"\bpop\w+\s*\(", "popen family - shell command execution", "high"),

    # Shell injection via formatting
    (r"(subprocess|os)\.[\w]+\s*\([^)]*[%+]\s*[\"']", "Shell command with string formatting - injection risk", "high"),
    (r"f[\"'].*\{.*\}.*[\"']\s*\)", "f-string in command - potential injection", "medium"),

    # Shell metacharacters in commands
    (r"(system|popen|run|call|Popen)\s*\([^)]*[;&|`$]", "Shell metacharacters in command - injection risk", "high"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    # Apply to all text-based files
    return rel_path.endswith((".py", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".js", ".ts", ".md", ".txt", ".json", ".yaml", ".yml"))


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
