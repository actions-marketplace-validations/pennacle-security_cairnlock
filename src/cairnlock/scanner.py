"""Scanner: file discovery, rule execution, inline ignores, deduplication."""

from __future__ import annotations

import os
import re
from pathlib import Path

from cairnlock.config import ScanConfig, is_ignored
from cairnlock.models import Finding
from cairnlock.rules import PROFILE_RULES, RULES, rule_ids

CONTEXT_FILENAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    "copilot-instructions.md",
    "opencode.json",
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
}
AGENT_DIRS = {
    ".cursor",
    ".opencode",
    ".claude",
    ".roo",
    ".continue",
    ".gemini",
    ".vscode",
    ".clinerules",
    "skills",
}
MAX_FILE_SIZE = 1_000_000
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}

# Extended profile scans source and dependency files so its generic rules
# see the files they were written for.
CODE_SUFFIXES = {".py", ".js", ".ts"}
CODE_FILENAMES = {"package.json", "pyproject.toml", "setup.py", "setup.cfg"}

# Inline suppression: `cairnlock:ignore` on a line suppresses all rules for
# that line; `cairnlock:ignore HUC001,SEC001` suppresses only those rules.
_IGNORE_TOKEN = re.compile(r"cairnlock:ignore\b([A-Z0-9,\t ]*)")


def _is_context_file(parts: tuple[str, ...], name: str) -> bool:
    if name in CONTEXT_FILENAMES or name == "SKILL.md":
        return True
    suffix = Path(name).suffix
    if suffix not in {".md", ".json"}:
        return False
    # parts is the directory chain relative to the scan root; a file directly
    # inside an agent directory has that directory as the only entry.
    return any(p in AGENT_DIRS for p in parts)


def _is_code_file(name: str) -> bool:
    if name in CODE_FILENAMES:
        return True
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    return Path(name).suffix in CODE_SUFFIXES


def discover_files(root: Path, include_code: bool = False) -> list[Path]:
    """Return agent context files (and optionally code files), sorted."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = Path(dirpath).relative_to(root)
        parts = rel_dir.parts
        for name in sorted(filenames):
            if _is_context_file(parts, name):
                found.append(Path(dirpath) / name)
            elif include_code and _is_code_file(name):
                found.append(Path(dirpath) / name)
    return found


def _suppression_map(text: str) -> dict[int, set[str]]:
    """Line number -> rule ids to suppress; an empty set suppresses all."""
    suppress: dict[int, set[str]] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = _IGNORE_TOKEN.search(line)
        if not match:
            continue
        ids = {tid.strip().upper() for tid in re.split(r"[,\s]+", match.group(1).strip()) if tid.strip()}
        suppress[lineno] = ids
    return suppress


def check_file(
    rel_path: str,
    text: str,
    disabled_rules: set[str] | None = None,
    allowed_rules: set[str] | None = None,
) -> list[Finding]:
    """Run applicable rules on one file, honoring disables, profiles,
    inline ignores, and deduplication."""
    disabled = disabled_rules or set()
    findings: list[Finding] = []
    for rule in RULES:
        ids = rule_ids(rule)
        if allowed_rules is not None and allowed_rules and not (ids & allowed_rules):
            continue
        if not rule.applies_to(rel_path):
            continue
        for finding in rule.check(rel_path, text):
            if finding.rule_id in disabled:
                continue
            if allowed_rules is not None and finding.rule_id not in allowed_rules:
                continue
            findings.append(finding)

    suppress = _suppression_map(text)
    if suppress:
        findings = [
            f
            for f in findings
            if f.line not in suppress or (suppress[f.line] and f.rule_id not in suppress[f.line])
        ]

    unique: dict[tuple[str, str, int, str], Finding] = {}
    for f in findings:
        unique.setdefault((f.rule_id, f.path, f.line, f.message), f)
    return list(unique.values())


def scan(root: Path, config: ScanConfig | None = None) -> list[Finding]:
    """Scan context files (plus code files under the extended profile)."""
    ignore: list[str] = []
    disabled: set[str] = set()
    allowed: set[str] | None = None
    include_code = False
    if config is not None:
        ignore = config.ignore
        disabled = set(config.disabled_rules)
        allowed = PROFILE_RULES.get(config.profile)
        include_code = config.profile == "extended"

    findings: list[Finding] = []
    for p in discover_files(root, include_code=include_code):
        rel = p.relative_to(root).as_posix()
        if ignore and is_ignored(rel, ignore):
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(check_file(rel, text, disabled, allowed))
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))
