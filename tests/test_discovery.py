"""Tests for file discovery across agent tool ecosystems."""

from __future__ import annotations

from pathlib import Path

from cairnlock.scanner import discover_files

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "discovery"

EXPECTED = {
    "AGENTS.md",
    ".github/copilot-instructions.md",
    "GEMINI.md",
    ".windsurfrules",
    ".clinerules/rules.md",
    ".roo/rules/foo.md",
    ".continue/rules/bar.md",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
    "claude_desktop_config.json",
    ".claude/settings.json",
    ".opencode/agent.md",
}

IGNORED = {
    ".git/AGENTS.md",
    "node_modules/SKILL.md",
    ".venv/mcp.json",
}


def test_discovery_fixture_patterns() -> None:
    found = {p.relative_to(FIXTURE_ROOT).as_posix() for p in discover_files(FIXTURE_ROOT)}
    for path in EXPECTED:
        assert path in found, f"missing from discovery: {path}"
    for path in IGNORED:
        assert path not in found, f"should be ignored: {path}"


def test_hidden_agent_dirs_are_scanned(tmp_path: Path) -> None:
    """Hidden agent directories are walked; .git, .venv, node_modules are not."""
    root = tmp_path / "repo"
    root.mkdir()
    files = {
        ".claude/skills/x.md": True,
        ".opencode/plugins/y.md": True,
        ".cursor/rules/z.md": True,
        ".roo/rules/a.md": True,
        ".continue/rules/b.md": True,
        ".gemini/c.md": True,
        ".github/copilot-instructions.md": True,
        ".git/config.md": False,
        ".venv/notes.md": False,
        "node_modules/pkg/readme.md": False,
    }
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("content\n", encoding="utf-8")
    found = {p.relative_to(root).as_posix() for p in discover_files(root)}
    for rel, expected in files.items():
        if expected:
            assert rel in found, f"should be discovered: {rel}"
        else:
            assert rel not in found, f"should be skipped: {rel}"


def test_clinerules_file_and_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".clinerules").write_text("file form\n", encoding="utf-8")
    other = tmp_path / "repo2"
    other.mkdir()
    rules = other / ".clinerules"
    rules.mkdir()
    (rules / "extra.md").write_text("dir form\n", encoding="utf-8")
    assert (root / ".clinerules") in discover_files(root)
    assert (other / ".clinerules" / "extra.md") in discover_files(other)
