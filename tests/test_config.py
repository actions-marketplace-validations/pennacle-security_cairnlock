"""Tests for config loading: cairnlock.toml, [tool.cairnlock], .cairnlockignore."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cairnlock.cli import app

runner = CliRunner()


def make_repo(tmp_path: Path, name: str = "repo") -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "AGENTS.md").write_text("# Agents\n\nzero\u200bwidth\n", encoding="utf-8")
    return root


def test_cairnlock_toml_ignore_glob(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    (root / "scratch").mkdir()
    (root / "scratch" / "AGENTS.md").write_text("# x\n\nzero\u200bwidth\n", encoding="utf-8")
    (root / "cairnlock.toml").write_text('ignore = ["scratch/**"]\n', encoding="utf-8")
    result = runner.invoke(app, ["--no-banner", "scan", str(root), "--format", "json"])
    data = _json(result)
    paths = {f["path"] for f in data["findings"]}
    assert "AGENTS.md" in paths
    assert not any(p.startswith("scratch/") for p in paths)


def test_cairnlock_toml_disabled_rules(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    (root / "cairnlock.toml").write_text('disabled_rules = ["HUC001"]\n', encoding="utf-8")
    result = runner.invoke(app, ["--no-banner", "scan", str(root), "--format", "json"])
    data = _json(result)
    assert data["total"] == 0


def test_pyproject_tool_table(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "x"\n\n[tool.cairnlock]\ndisabled_rules = ["HUC001"]\n',
        encoding="utf-8",
    )
    result = runner.invoke(app, ["--no-banner", "scan", str(root), "--format", "json"])
    data = _json(result)
    assert data["total"] == 0


def test_cairnlockignore_glob(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    (root / "vendor").mkdir()
    (root / "vendor" / "CLAUDE.md").write_text("# x\n\nzero\u200bwidth\n", encoding="utf-8")
    (root / ".cairnlockignore").write_text("# comment\n\nvendor/**\n", encoding="utf-8")
    result = runner.invoke(app, ["--no-banner", "scan", str(root), "--format", "json"])
    data = _json(result)
    paths = {f["path"] for f in data["findings"]}
    assert "AGENTS.md" in paths
    assert not any(p.startswith("vendor/") for p in paths)


def test_invalid_fail_on_exits_two(tmp_path: Path) -> None:
    root = make_repo(tmp_path)
    (root / "cairnlock.toml").write_text('fail_on = "catastrophic"\n', encoding="utf-8")
    result = runner.invoke(app, ["--no-banner", "scan", str(root), "--format", "json"])
    assert result.exit_code == 2
    assert "fail_on" in result.output.lower()


def _json(result) -> dict:
    import json

    return json.loads(result.stdout)
