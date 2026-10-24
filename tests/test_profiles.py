"""Tests for rule profiles: core (default) and extended."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from cairnlock.cli import app
from cairnlock.config import ScanConfig
from cairnlock.scanner import scan

runner = CliRunner()


@pytest.fixture
def mixed_repo(tmp_path: Path) -> Path:
    """One core finding, one extended finding, one code file for extended."""
    root = tmp_path / "repo"
    root.mkdir()
    # HUC001 high (core) and SEC001 high (extended) in the same file.
    (root / "AGENTS.md").write_text(
        "# Agents\n\n\btext\u202ehere\n\napi_key = \"AKIA0000000000000000\"\n",
        encoding="utf-8",
    )
    # SHC001 (extended) in a source file; core never discovers .py files.
    (root / "script.py").write_text('import os\n\nos.system("ls")\n', encoding="utf-8")
    return root


def test_core_is_default(mixed_repo: Path) -> None:
    findings = scan(mixed_repo, ScanConfig())
    ids = {f.rule_id for f in findings}
    assert "HUC001" in ids          # core rule fires
    assert "SEC001" not in ids      # extended rule does not
    assert "SHC001" not in ids      # .py is not discovered under core


def test_extended_profile_selects_generic_rules(mixed_repo: Path) -> None:
    findings = scan(mixed_repo, ScanConfig(profile="extended"))
    ids = {f.rule_id for f in findings}
    assert "SEC001" in ids          # extended rule fires
    assert "SHC001" in ids          # code files are discovered under extended
    assert "HUC001" not in ids      # core rule does not run under extended


def test_profiles_are_exclusive(mixed_repo: Path) -> None:
    core_ids = {f.rule_id for f in scan(mixed_repo, ScanConfig(profile="core"))}
    extended_ids = {f.rule_id for f in scan(mixed_repo, ScanConfig(profile="extended"))}
    assert not (core_ids & extended_ids), "profiles must not overlap"


def test_no_duplicate_findings_same_line_and_issue(mixed_repo: Path) -> None:
    for profile in ("core", "extended"):
        findings = scan(mixed_repo, ScanConfig(profile=profile))
        keys = [(f.rule_id, f.path, f.line, f.message) for f in findings]
        assert len(keys) == len(set(keys)), f"duplicate findings under {profile}: {keys}"


def test_cli_profile_flag(mixed_repo: Path) -> None:
    core = runner.invoke(app, ["--no-banner", "scan", str(mixed_repo), "--format", "json"])
    assert core.exit_code == 1
    assert "HUC001" in core.stdout
    assert "SEC001" not in core.stdout

    extended = runner.invoke(
        app, ["--no-banner", "scan", str(mixed_repo), "--format", "json", "--profile", "extended"]
    )
    assert "SEC001" in extended.stdout
    assert "HUC001" not in extended.stdout


def test_profile_from_config_file(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.md").write_text('api_key = "AKIA0000000000000000"\n', encoding="utf-8")
    (root / "cairnlock.toml").write_text('profile = "extended"\n', encoding="utf-8")
    result = runner.invoke(app, ["--no-banner", "scan", str(root), "--format", "json"])
    assert "SEC001" in result.stdout


def test_invalid_profile_exits_two(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
    result = runner.invoke(
        app, ["--no-banner", "scan", str(root), "--profile", "everything"]
    )
    assert result.exit_code == 2
    assert "profile" in result.output.lower()


def test_every_rule_id_belongs_to_exactly_one_profile() -> None:
    from cairnlock.rules import PROFILE_RULES, RULE_META

    assigned = [rid for ids in PROFILE_RULES.values() for rid in ids]
    assert len(assigned) == len(set(assigned)), "a rule id appears in two profiles"
    assert set(assigned) == set(RULE_META), "profiles must cover every rule id"


def test_rules_command_lists_profile(tmp_path: Path) -> None:
    result = runner.invoke(app, ["--no-banner", "rules"])
    assert result.exit_code == 0
    assert "core" in result.stdout.lower()
    assert "extended" in result.stdout.lower()
