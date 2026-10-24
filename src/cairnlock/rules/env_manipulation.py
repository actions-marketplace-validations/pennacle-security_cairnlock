"""Environment variable manipulation and credential access.

Rule ID: ENV001
Detects suspicious environment variable access patterns.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "ENV001"

_PATTERNS = [
    # Direct credential access
    (r"\bos\.environ\s*\[\s*[\"'](?:AWS|AZURE|GCP|GOOGLE|DATABASE|DB|SECRET|KEY|TOKEN|PASSWORD|API)", "Direct env var access for credentials", "high"),
    (r"\bos\.getenv\s*\(\s*[\"'](?:AWS|AZURE|GCP|GOOGLE|DATABASE|DB|SECRET|KEY|TOKEN|PASSWORD|API)", "os.getenv() for credentials", "high"),
    (r"\bos\.getenv\s*\(\s*[\"'][A-Z_]{10,}[\"']\s*\)", "os.getenv() for long uppercase vars - likely secrets", "medium"),

    # Credential dumping
    (r"\bos\.environ\s*\.items?\s*\(\s*\)", "Iterating all environment variables - potential dump", "high"),
    (r"for\s+\w+\s+in\s+os\.environ", "Iterating os.environ - potential credential enumeration", "high"),
    (r"list\s*\(\s*os\.environ\s*\)", "Converting os.environ to list - potential dump", "high"),
    (r"json\.dumps\s*\(\s*os\.environ", "Serializing os.environ to JSON - credential exposure", "high"),
    (r"print\s*\(\s*os\.environ", "Printing os.environ - credential exposure", "high"),
    (r"logging\.\w+\s*\(\s*.*os\.environ", "Logging os.environ - credential exposure in logs", "high"),

    # Credential construction
    (r"(?:aws_access_key_id|aws_secret_access_key|aws_session_token)", "AWS credential construction", "high"),
    (r"(?:GOOGLE_APPLICATION_CREDENTIALS|AZURE_CLIENT_SECRET)", "Cloud credential env vars", "high"),
    (r"(?:DATABASE_URL|DB_PASSWORD|DB_URI)", "Database credential construction", "high"),

    # Shell env access
    (r"\$\{?[A-Z_]{10,}\}?", "Shell variable expansion for long vars - potential secrets", "medium"),
    (r"process\.env\.[A-Z_]{10,}", "Node.js process.env for long vars - potential secrets", "medium"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith((".py", ".js", ".ts", ".go", ".rs", ".java", ".kt", ".sh", ".bash", ".ps1", ".md", ".txt", ".json", ".yaml", ".yml"))


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
