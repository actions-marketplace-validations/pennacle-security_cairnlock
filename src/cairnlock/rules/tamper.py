"""Agent context files attempting to defeat cairnlock itself.

Rule ID: TAM001
An instruction file that tells the agent to run `cairnlock approve`, delete
the lockfile, or disable the scanner is asking the agent to bless its own
tampering. The scanner treats instructions about itself the same way it
treats instructions about anything else: as content, and here as a finding.

Ordinary usage — running `cairnlock scan`, linking the repository, naming
the lockfile — stays clean.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "TAM001"

RULE_IDS = ("TAM001",)

# Each pattern is a specific self-tampering instruction, kept narrow so
# normal documentation about the tool never matches.
_PATTERNS = [
    (
        re.compile(r"\bcairnlock\s+approve\b", re.IGNORECASE),
        "instruction runs cairnlock approve (self-blessing a change)",
        "high",
    ),
    (
        re.compile(r"\b(?:delete|remove|rm|erase)\b[^.\n]{0,40}\bcairnlock\.lock\b", re.IGNORECASE),
        "instruction removes the lockfile",
        "high",
    ),
    (
        re.compile(r"\b(?:uninstall|remove|delete|disable|bypass|skip|ignore)\b[^.\n]{0,40}\bcairnlock\b(?!\.lock)", re.IGNORECASE),
        "instruction disables or bypasses the scanner",
        "high",
    ),
    (
        re.compile(r"\bgit\s+(?:checkout|restore)\b[^.\n]{0,40}\bcairnlock\.lock\b", re.IGNORECASE),
        "instruction reverts the lockfile with git",
        "high",
    ),
    (
        re.compile(r"\b(?:add|use|append)\b[^.\n]{0,30}\bcairnlock:ignore\b", re.IGNORECASE),
        "instruction suppresses scanner findings",
        "medium",
    ),
    (
        re.compile(r"\b--no-fail\b|\b--fail-on\s+never\b", re.IGNORECASE),
        "instruction weakens the scan gate",
        "medium",
    ),
]


def applies_to(rel_path: str) -> bool:
    return True


def check(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pat, message, severity in _PATTERNS:
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
