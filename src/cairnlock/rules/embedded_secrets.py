"""Comprehensive secret detection with entropy validation.

Rule ID: SEC001 (enhanced)
Detects embedded credentials with entropy validation.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from cairnlock.models import Finding

RULE_ID = "SEC001"

RULE_IDS = ("SEC001",)

# High-confidence provider patterns
_PROVIDER_PATTERNS = [
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "OpenAI API key", "high"),
    (re.compile(r"\bsk-proj-[A-Za-z0-9]{20,}\b"), "OpenAI project API key", "high"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "GitHub personal access token (classic)", "high"),
    (re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), "GitHub OAuth token", "high"),
    (re.compile(r"\bghu_[A-Za-z0-9]{36}\b"), "GitHub user-to-server token", "high"),
    (re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), "GitHub server-to-server token", "high"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "GitHub fine-grained PAT", "high"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token", "high"),
    (re.compile(r"\bxoxe\.[A-Za-z0-9_-]{30,}\b"), "Slack app-level token", "high"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID", "high"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Google API key", "high"),
    (re.compile(r"\bya29\.[A-Za-z0-9_-]{30,}\b"), "Google OAuth2 token", "high"),
    (re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"), "UUID - potential API key", "medium"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._-]{20,}\b"), "Bearer token", "high"),
    (re.compile(r"\bapi[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9+/=_-]{20,}[\"']"), "Generic API key assignment", "high"),
]

# Generic assignment with entropy check
_GENERIC_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?key|access[_-]?token)\b\s*[:=]\s*[\"']([^\"'<>{}\s]{16,})[\"']"
)

# Placeholder filters
_PLACEHOLDERS = (
    "your", "example", "changeme", "replace", "xxx", "todo",
    "<", "${", "env", "process.env", "$env:", "%(", "os.environ",
    "test", "dummy", "fake", "mock", "sample", "placeholder",
    "redacted", "hidden", "secret", "****", "xxxx",
)

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_likely_secret(value: str) -> tuple[bool, float]:
    """Check if value looks like a secret using entropy and patterns."""
    if len(value) < 16:
        return False, 0.0
    low = value.lower()
    if any(ph in low for ph in _PLACEHOLDERS):
        return False, 0.0
    # High entropy threshold for secrets
    entropy = _shannon_entropy(value)
    return entropy > 3.5, entropy


def applies_to(rel_path: str) -> bool:
    return True


def check(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []

    # Provider-specific patterns
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pat, kind, severity in _PROVIDER_PATTERNS:
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
                break

    # Generic assignment with entropy validation
    for lineno, line in enumerate(text.splitlines(), start=1):
        for m in _GENERIC_RE.finditer(line):
            value = m.group(2)
            is_secret, entropy = _is_likely_secret(value)
            if is_secret:
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity="high" if entropy > 4.0 else "medium",
                        path=rel_path,
                        line=lineno,
                        message=f"possible hardcoded credential assignment (entropy: {entropy:.1f})",
                    )
                )
                break

    return findings
