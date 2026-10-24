"""Tests for cairnlock verify --base.

Each fixture builds a temporary git repository. All git calls use an argument
list, never a shell.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cairnlock.cli import app

runner = CliRunner()


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git in root with an argument list and fail loudly on error."""
    proc = subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        shell=False,
    )
    assert proc.returncode == 0, f"git {args} failed: {proc.stderr}"
    return proc


def commit_all(root: Path, message: str) -> None:
    git(root, "add", "-A")
    git(root, "commit", "-m", message)


def edit_lock(root: Path) -> None:
    """Re-run cairnlock init --force so the lockfile matches the working tree."""
    result = runner.invoke(app, ["--no-banner", "init", str(root), "--force"])
    assert result.exit_code == 0


def new_repo(tmp_path: Path, name: str, with_lock: bool = True) -> Path:
    """Create a git repo; optionally track AGENTS.md with a lockfile at base."""
    root = tmp_path / name
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.name", "Test")
    git(root, "config", "user.email", "test@example.com")
    if with_lock:
        (root / "AGENTS.md").write_text("# Agents\n\nhello\n", encoding="utf-8")
        result = runner.invoke(app, ["--no-banner", "init", str(root)])
        assert result.exit_code == 0
    else:
        (root / "README.md").write_text("no lock yet\n", encoding="utf-8")
    commit_all(root, "base")
    return root


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return new_repo(tmp_path, "repo")


def test_clean_change_vs_base(repo: Path) -> None:
    """A commit that touches no tracked file and no lockfile passes."""
    (repo / "notes.txt").write_text("unrelated\n", encoding="utf-8")
    commit_all(repo, "unrelated change")
    result = runner.invoke(app, ["--no-banner", "verify", str(repo), "--base", "HEAD~1"])
    assert result.exit_code == 0, result.output
    assert "no changes" in result.output.lower()


def test_modified_tracked_file(repo: Path) -> None:
    (repo / "AGENTS.md").write_text("# Agents\n\nchanged\n", encoding="utf-8")
    commit_all(repo, "edit agents")
    result = runner.invoke(app, ["--no-banner", "verify", str(repo), "--base", "HEAD~1"])
    assert result.exit_code == 1
    assert "modified" in result.output.lower()
    assert "AGENTS.md" in result.output


def test_lockfile_edited_with_tracked_file_must_fail(repo: Path) -> None:
    """Rehashing the lockfile in the same change cannot hide a tracked edit."""
    (repo / "AGENTS.md").write_text("# Agents\n\nchanged\n", encoding="utf-8")
    edit_lock(repo)
    commit_all(repo, "edit agents and rehash lockfile")
    result = runner.invoke(app, ["--no-banner", "verify", str(repo), "--base", "HEAD~1"])
    assert result.exit_code == 1
    assert "lockfile modified in this change" in result.output.lower()
    assert "modified" in result.output.lower()


def test_allow_lock_change_passes_lock_only_edit(repo: Path) -> None:
    """A lockfile-only semantic change fails without the flag, passes with it."""
    lock_path = repo / "cairnlock.lock"
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    data["version"] = 2
    lock_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    commit_all(repo, "bump lockfile version")

    without_flag = runner.invoke(app, ["--no-banner", "verify", str(repo), "--base", "HEAD~1"])
    assert without_flag.exit_code == 1
    assert "lockfile modified in this change" in without_flag.output.lower()

    with_flag = runner.invoke(
        app,
        ["--no-banner", "verify", str(repo), "--base", "HEAD~1", "--allow-lock-change"],
    )
    assert with_flag.exit_code == 0, with_flag.output


def test_missing_base_lockfile(tmp_path: Path) -> None:
    """First adoption: the base commit predates the lockfile."""
    root = new_repo(tmp_path, "repo", with_lock=False)
    base_sha = git(root, "rev-parse", "HEAD").stdout.strip()

    (root / "AGENTS.md").write_text("# Agents\n\nhello\n", encoding="utf-8")
    result = runner.invoke(app, ["--no-banner", "init", str(root)])
    assert result.exit_code == 0
    commit_all(root, "adopt cairnlock")

    result = runner.invoke(app, ["--no-banner", "verify", str(root), "--base", base_sha])
    assert result.exit_code == 2
    assert "no cairnlock.lock" in result.output.lower()
    assert "init" in result.output.lower()


def test_invalid_ref(repo: Path) -> None:
    result = runner.invoke(app, ["--no-banner", "verify", str(repo), "--base", "no-such-ref"])
    assert result.exit_code == 2
    assert "not found" in result.output.lower() or "no-such-ref" in result.output


def test_ref_starting_with_dash_is_rejected(repo: Path) -> None:
    result = runner.invoke(app, ["--no-banner", "verify", str(repo), "--base", "--version"])
    assert result.exit_code == 2
    assert "invalid git ref" in result.output.lower()


def test_shallow_clone_mentions_fetch_depth(repo: Path, tmp_path: Path) -> None:
    """A shallow clone cannot see the base commit; the message names fetch-depth."""
    old_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
    (repo / "AGENTS.md").write_text("# Agents\n\nsecond\n", encoding="utf-8")
    commit_all(repo, "second")

    shallow = tmp_path / "shallow"
    origin_url = "file:///" + repo.as_posix().lstrip("/")
    git(tmp_path, "clone", "-q", "--depth", "1", origin_url, shallow.name)
    git(shallow, "config", "user.name", "Test")
    git(shallow, "config", "user.email", "test@example.com")

    result = runner.invoke(app, ["--no-banner", "verify", str(shallow), "--base", old_sha])
    assert result.exit_code == 2
    assert "fetch-depth" in result.output.lower()


def test_not_a_git_repo(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
    result = runner.invoke(app, ["--no-banner", "verify", str(plain), "--base", "HEAD"])
    assert result.exit_code == 2
    assert "git" in result.output.lower()
