"""Supply chain attack patterns in dependencies and configurations.

Rule ID: SUP001
Detects patterns indicating supply chain compromise risks.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "SUP001"

RULE_IDS = ("SUP001",)

_PATTERNS = [
    # Dependency confusion / typosquatting
    (r"(?:pip|npm|yarn|pnpm)\s+install\s+.*@[\d.]+", "Pinned version install - good practice", "low"),
    (r"(?:pip|npm|yarn|pnpm)\s+install\s+(?!.*@[\d.]+)[\w-]+(?:\s|$)", "Unpinned dependency install - supply chain risk", "medium"),
    (r"requirements\.txt.*[<>]=?[^#\n]*$", "Unpinned requirement - supply chain risk", "medium"),
    (r"package\.json.*\"version\":\s*[\"']\*[\"']", "Wildcard version in package.json - supply chain risk", "high"),

    # Git dependency risks
    (r"(?:pip|npm|yarn)\s+install\s+.*git\+(?:https?|ssh)://", "Git dependency - verify commit hash pinned", "medium"),
    (r"github\.com/[\w-]+/[\w-]+(?:\.git)?(?:@|#)[\w]+", "Git dependency with ref - verify commit hash", "medium"),

    # Private registry / internal packages
    (r"(?:--index-url|--extra-index-url|--find-links)\s+\S+", "Custom package index - verify trust", "medium"),
    (r"registry\.npmjs\.org|pypi\.org|crates\.io", "Public registry - generally safe", "low"),

    # Post-install scripts
    (r"\"postinstall\"\s*:", "npm postinstall script - supply chain risk", "high"),
    (r"\"preinstall\"\s*:", "npm preinstall script - supply chain risk", "high"),
    (r"\"prepare\"\s*:", "npm prepare script - runs on install", "medium"),
    (r"scripts\s*:\s*\{[^}]*install", "Install scripts in package.json", "medium"),

    # Python setup.py / pyproject.toml risks
    (r"setup_requires\s*=", "setup_requires - executes at install time", "high"),
    (r"\[tool\.setuptools\]", "setuptools config - verify no arbitrary code", "medium"),

    # Compromise indicators
    (r"(?:malicious|backdoor|exploit|payload|shellcode|rootkit)", "Malware-related keywords in deps", "high"),
    (r"(?:typosquat|dependency.confusion|supply.chain)", "Supply chain attack references", "high"),

    # Lockfile integrity
    (r"package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock", "Lockfile present - good practice", "low"),
    (r"requirements\.txt.*sha256\s*=", "Hash-pinned requirement - good practice", "low"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]

# A bare requirement line: package name with optional extras, no pin.
# Comments, options (-r, --index-url), and pinned lines do not match.
_BARE_REQUIREMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._]*(\[[\w,.-]+\])?\s*$")


def applies_to(rel_path: str) -> bool:
    name = rel_path.rsplit("/", 1)[-1]
    if name == "SKILL.md" or "skills" in rel_path.split("/")[:-1]:
        return False  # REM001 owns remote-install findings in skill files
    return rel_path.endswith((".txt", ".json", ".toml", ".yaml", ".yml", ".lock", ".md"))


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

    name = rel_path.rsplit("/", 1)[-1]
    if name.startswith("requirements") and name.endswith(".txt"):
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            if _BARE_REQUIREMENT.match(stripped):
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity="medium",
                        path=rel_path,
                        line=lineno,
                        message=f"unpinned requirement: {stripped}",
                    )
                )
    return findings
