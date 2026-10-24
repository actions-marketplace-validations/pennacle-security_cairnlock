"""Anti-false-positive and anti-false-negative accuracy tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cairnlock.config import ScanConfig
from cairnlock.scanner import scan

runner = CliRunner()


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_mcp003_fires_for_infrastructure_commands(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(
        '{"mcpServers": {"shell": {"command": "bash", "args": ["-c", "echo hi"]},'
        ' "ops": {"command": "docker", "args": ["ps"]}}}',
        encoding="utf-8",
    )
    findings = scan(root, ScanConfig())
    mcp003 = [f for f in findings if f.rule_id == "MCP003"]
    assert len(mcp003) == 2
    assert all(f.severity == "medium" for f in mcp003)


def test_unpinned_npx_reports_unp001_only(tmp_path: Path) -> None:
    """The old MCP003/UNP001 duplicate: one issue, one finding."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(
        '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "./data"]}}}',
        encoding="utf-8",
    )
    findings = scan(root, ScanConfig())
    mcp003 = [f for f in findings if f.rule_id == "MCP003"]
    unp001 = [f for f in findings if f.rule_id == "UNP001"]
    assert len(unp001) == 1, "UNP001 must report the unpinned package"
    assert not mcp003, "MCP003 must not duplicate the package-runner finding"


def test_unp001_handles_dlx_subcommands(tmp_path: Path) -> None:
    """pnpm/yarn dlx take the package as the next argument, not 'dlx' itself."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".mcp.json").write_text(
        '{"mcpServers": {"a": {"command": "pnpm", "args": ["dlx", "some-server"]},'
        ' "b": {"command": "yarn", "args": ["dlx", "other-server"]}}}',
        encoding="utf-8",
    )
    findings = scan(root, ScanConfig())
    messages = [f.message for f in findings if f.rule_id == "UNP001"]
    assert any("some-server" in m for m in messages), messages
    assert any("other-server" in m for m in messages), messages
    assert not any("dlx" in m for m in messages), "dlx itself must not be flagged"


def test_cfg001_template_pattern_no_longer_fires_on_markdown(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.md").write_text(
        "# Agents\n\nUse templates like {{user.name}} in prompts.\n",
        encoding="utf-8",
    )
    findings = scan(root, ScanConfig())
    assert "CFG001" not in _ids(findings), "template braces in prose are not injection"


def test_obf001_leaves_skill_files_to_rem001(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    blob = "A" * 220
    skill = root / "skills" / "s" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(f"payload: {blob}\n", encoding="utf-8")
    findings = scan(root, ScanConfig())
    assert "REM001" in _ids(findings)
    assert "OBF001" not in _ids(findings), "duplicate base64 finding in skill files"


def test_extended_discovers_code_files(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "server.py").write_text('import os\n\nos.system("ls")\n', encoding="utf-8")
    (root / "requirements.txt").write_text("requests\n", encoding="utf-8")
    core = scan(root, ScanConfig(profile="core"))
    extended = scan(root, ScanConfig(profile="extended"))
    assert "SHC001" not in _ids(core), "code files are not discovered under core"
    assert "SHC001" in _ids(extended), "extended discovers and scans source files"
    assert "SUP001" in _ids(extended), "requirements.txt is discovered under extended"


def test_code_files_ignored_under_core(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "server.py").write_text('import os\n\nos.system("ls")\n', encoding="utf-8")
    findings = scan(root, ScanConfig(profile="core"))
    assert findings == []


def test_inline_ignore_suppresses_whole_line(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.md").write_text(
        "# Agents\n\n\btext\u202ehere <!-- cairnlock:ignore -->\n",
        encoding="utf-8",
    )
    findings = scan(root, ScanConfig())
    assert findings == []


def test_inline_ignore_with_rule_ids_is_selective(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    blob = "B" * 220
    (root / "AGENTS.md").write_text(
        "# Agents\n\n"
        'api_key = "AKIA0000000000000000" cairnlock:ignore SEC001\n'
        f'blob = "{blob}"\n',
        encoding="utf-8",
    )
    findings = scan(root, ScanConfig(profile="extended"))
    same_line = [f for f in findings if f.rule_id == "SEC001"]
    assert not same_line, "suppressed rule must not fire on its line"
    assert "OBF001" in _ids(findings), "a different rule on another line still fires"


def test_inline_ignore_without_ids_token_is_exact(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.md").write_text(
        "# Agents\n\n\btext\u202ecairnlock:ignored-note\n",
        encoding="utf-8",
    )
    findings = scan(root, ScanConfig())
    assert "HUC001" in _ids(findings), "cairnlock:ignored must not count as the token"


def test_findings_are_deduplicated(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.md").write_text("# Agents\n\n\btext\u202ehere\n", encoding="utf-8")
    findings = scan(root, ScanConfig())
    keys = [(f.rule_id, f.path, f.line, f.message) for f in findings]
    assert len(keys) == len(set(keys))


def test_action_profile_input_is_documented() -> None:
    text = Path("action.yml").read_text(encoding="utf-8")
    assert "profile:" in text
