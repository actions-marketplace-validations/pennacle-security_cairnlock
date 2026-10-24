"""Suspicious file system access patterns.

Rule ID: FSY001
Detects dangerous file system operations.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "FSY001"

_PATTERNS = [
    # Dangerous file operations
    (r"\bopen\s*\([^)]*[\"']w[\"']", "File write operation - verify path safety", "medium"),
    (r"\bopen\s*\([^)]*[\"']a[\"']", "File append operation - verify path safety", "medium"),
    (r"\bpathlib\.Path\([^)]*\)\.write_(text|bytes)\s*\(", "Pathlib write - verify path safety", "medium"),
    (r"\bshutil\.(copy|move|rmtree|copytree)\s*\(", "Shutil file operation - verify paths", "medium"),
    (r"\bos\.(remove|unlink|rmdir|mkdir|makedirs|rename|replace)\s*\(", "OS file operation - verify safety", "medium"),

    # Path traversal
    (r"\.\./|\.\.\\", "Path traversal sequence - potential directory escape", "high"),
    (r"os\.path\.(join|abspath|realpath)\s*\([^)]*\.\.", "Path join with traversal - potential escape", "high"),

    # Sensitive file access
    (r"(?:/etc/(?:passwd|shadow|sudoers|ssh)|~/\.ssh/|%USERPROFILE%\\\\\.ssh)", "Sensitive system file access", "high"),
    (r"(?:id_rsa|id_ed25519|id_dsa|\.pem|\.key|\.crt|\.pfx)", "Private key/certificate file access", "high"),
    (r"(?:\.env|\.env\.\w+|config\.json|secrets\.yaml)", "Configuration/secrets file access", "high"),

    # Archive extraction
    (r"\btarfile\.open\s*\(", "Tar archive extraction - verify path safety", "medium"),
    (r"\bzipfile\.ZipFile\s*\(", "ZIP archive extraction - verify path safety (zip slip)", "high"),
    (r"\bshutil\.unpack_archive\s*\(", "Archive extraction - verify path safety", "medium"),

    # Temporary file creation
    (r"\btempfile\.(mkstemp|mkdtemp|NamedTemporaryFile)\s*\(", "Temp file/dir creation - verify cleanup", "low"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith((".py", ".js", ".ts", ".go", ".rs", ".java", ".kt", ".sh", ".bash", ".ps1", ".md", ".txt"))


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
