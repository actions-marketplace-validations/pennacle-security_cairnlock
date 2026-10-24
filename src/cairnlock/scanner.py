"""Scanner: file discovery and rule execution."""

from __future__ import annotations

import os
from pathlib import Path

from cairnlock.models import Finding
from cairnlock.rules import RULES

CONTEXT_FILENAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
    "opencode.json",
    ".mcp.json",
    "mcp.json",
}
AGENT_DIRS = {".cursor", ".opencode", ".claude", "skills"}
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
}


def _is_context_file(parts: tuple[str, ...], name: str) -> bool:
    if name in CONTEXT_FILENAMES or name == "SKILL.md":
        return True
    suffix = Path(name).suffix
    if suffix not in {".md", ".json"}:
        return False
    return any(p in AGENT_DIRS for p in parts[:-1])


def discover_files(root: Path) -> list[Path]:
    """Return all agent context files under root, sorted for determinism."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = Path(dirpath).relative_to(root)
        parts = rel_dir.parts
        for name in sorted(filenames):
            if _is_context_file(parts, name):
                found.append(Path(dirpath) / name)
    return found


def check_file(rel_path: str, text: str) -> list[Finding]:
    """Run all applicable rules on a single file's text."""
    findings: list[Finding] = []
    for rule in RULES:
        if rule.applies_to(rel_path):
            findings.extend(rule.check(rel_path, text))
    return findings


def scan(root: Path) -> list[Finding]:
    """Scan all context files under root and return sorted findings."""
    findings: list[Finding] = []
    for p in discover_files(root):
        rel = p.relative_to(root).as_posix()
        try:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(check_file(rel, text))
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))
