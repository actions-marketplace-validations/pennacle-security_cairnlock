"""Scanner: file discovery and rule execution."""

from __future__ import annotations

import os
from pathlib import Path

from cairnlock.config import ScanConfig, is_ignored
from cairnlock.models import Finding
from cairnlock.rules import RULES

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


def _is_context_file(parts: tuple[str, ...], name: str) -> bool:
    if name in CONTEXT_FILENAMES or name == "SKILL.md":
        return True
    suffix = Path(name).suffix
    if suffix not in {".md", ".json"}:
        return False
    # parts is the directory chain relative to the scan root; a file directly
    # inside an agent directory has that directory as the only entry.
    return any(p in AGENT_DIRS for p in parts)


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


def check_file(rel_path: str, text: str, disabled_rules: set[str] | None = None) -> list[Finding]:
    """Run all applicable rules on a single file's text."""
    disabled = disabled_rules or set()
    findings: list[Finding] = []
    for rule in RULES:
        if not rule.applies_to(rel_path):
            continue
        for finding in rule.check(rel_path, text):
            if finding.rule_id not in disabled:
                findings.append(finding)
    return findings


def scan(root: Path, config: ScanConfig | None = None) -> list[Finding]:
    """Scan all context files under root and return sorted findings."""
    ignore: list[str] = []
    disabled: set[str] = set()
    if config is not None:
        ignore = config.ignore
        disabled = set(config.disabled_rules)

    findings: list[Finding] = []
    for p in discover_files(root):
        rel = p.relative_to(root).as_posix()
        if ignore and is_ignored(rel, ignore):
            continue
        try:
            if p.stat().st_size > MAX_FILE_SIZE:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(check_file(rel, text, disabled))
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))
