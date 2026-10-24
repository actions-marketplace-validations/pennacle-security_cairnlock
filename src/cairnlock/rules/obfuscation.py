"""Suspicious encoding, obfuscation, and data hiding patterns.

Rule ID: OBF001
Detects encoding/obfuscation techniques used to hide malicious content.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "OBF001"

RULE_IDS = ("OBF001",)

_PATTERNS = [
    # Base64 encoding/decoding
    (r"\bbase64\.(b64encode|b64decode|standard_b64encode|standard_b64decode)\s*\(", "Base64 encode/decode - verify purpose", "medium"),
    (r"\bbase64\.urlsafe_b64(encode|decode)\s*\(", "URL-safe Base64 - verify purpose", "medium"),
    (r"\bbinascii\.(b2a_base64|a2b_base64)\s*\(", "binascii Base64 - verify purpose", "medium"),

    # Other encodings
    (r"\bcodecs\.(encode|decode)\s*\([^)]*[\"']base64[\"']", "codecs Base64 - verify purpose", "medium"),
    (r"\brot13\b|rot_13", "ROT13 encoding - simple obfuscation", "low"),
    (r"\bquopri\.(encodestring|decodestring)\s*\(", "Quoted-printable encoding", "low"),
    (r"\bbase64\.b32(encode|decode)\s*\(", "Base32 encoding", "low"),
    (r"\bbase64\.b16(encode|decode)\s*\(", "Base16/Hex encoding", "low"),

    # Compression + encoding (common for obfuscation)
    (r"\bzlib\.compress\s*\(.*\.encode\s*\(", "Compress + encode - potential obfuscation", "high"),
    (r"\bgzip\.compress\s*\(.*\.encode\s*\(", "Gzip + encode - potential obfuscation", "high"),
    (r"\bbz2\.compress\s*\(.*\.encode\s*\(", "Bzip2 + encode - potential obfuscation", "high"),
    (r"\blzma\.compress\s*\(.*\.encode\s*\(", "LZMA + encode - potential obfuscation", "high"),

    # PowerShell obfuscation
    (r"\bFromBase64String\s*\(", "PowerShell FromBase64String - encoded command", "high"),
    (r"\bToBase64String\s*\(", "PowerShell ToBase64String - encoding", "medium"),
    (r"\bSystem\.Text\.Encoding\b.*GetString\s*\(", "PowerShell .NET encoding", "medium"),
    (r"\bIEX\s*\(\s*\[", "PowerShell IEX with array - obfuscation", "high"),

    # XOR / simple cipher
    (r"\bchr\s*\(\s*\d+\s*\^\s*\d+", "XOR with chr() - simple cipher", "medium"),
    (r"\b\^\s*0x[0-9a-fA-F]+\s*$", "XOR with hex constant - simple cipher", "low"),

    # String obfuscation patterns
    (r"[\"'][A-Za-z0-9+/]{200,}={0,2}[\"']", "Long base64 string literal - potential payload", "high"),
    (r"[\"'][A-Fa-f0-9]{200,}[\"']", "Long hex string literal - potential payload", "medium"),

    # Homoglyph / unicode obfuscation
    (r"[\u0430-\u044F]", "Cyrillic characters in identifiers - homoglyph risk", "medium"),
    (r"[\u03B1-\u03C9]", "Greek characters in identifiers - homoglyph risk", "medium"),
    (r"[\uFF10-\uFF19\uFF21-\uFF3A\uFF41-\uFF5A]", "Fullwidth characters - homoglyph risk", "medium"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    name = rel_path.rsplit("/", 1)[-1]
    if name == "SKILL.md" or "skills" in rel_path.split("/")[:-1]:
        return False  # REM001 owns skill files; avoids duplicate base64 findings
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
