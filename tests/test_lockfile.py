"""Tests for lockfile commands."""

from __future__ import annotations

import tempfile
from pathlib import Path

from cairnlock import lockfile


def test_init_writes_lockfile() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "AGENTS.md").write_text("# Agents\n\nHello.\n", encoding="utf-8")
        lockfile.write(root, lockfile.hashes(root))
        lock_path = root / lockfile.LOCKFILE_NAME
        assert lock_path.is_file()
        data = lockfile.load(root)
        assert data is not None
        assert "AGENTS.md" in data["files"]


def test_verify_ok_when_unchanged() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "AGENTS.md").write_text("# Agents\n\nHello.\n", encoding="utf-8")
        lockfile.write(root, lockfile.hashes(root))
        lock = lockfile.load(root)
        changes = lockfile.changes(root, lock)
        assert not any(changes.values())


def test_verify_fails_on_modified() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "AGENTS.md").write_text("# Agents\n\nHello.\n", encoding="utf-8")
        lockfile.write(root, lockfile.hashes(root))
        (root / "AGENTS.md").write_text("# Agents\n\nChanged.\n", encoding="utf-8")
        lock = lockfile.load(root)
        changes = lockfile.changes(root, lock)
        assert changes["modified"] == ["AGENTS.md"]


def test_verify_fails_on_added() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "AGENTS.md").write_text("# Agents\n\nHello.\n", encoding="utf-8")
        lockfile.write(root, lockfile.hashes(root))
        (root / "CLAUDE.md").write_text("# Claude\n\nNew.\n", encoding="utf-8")
        lock = lockfile.load(root)
        changes = lockfile.changes(root, lock)
        assert changes["added"] == ["CLAUDE.md"]


def test_verify_fails_on_deleted() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "AGENTS.md").write_text("# Agents\n\nHello.\n", encoding="utf-8")
        lockfile.write(root, lockfile.hashes(root))
        (root / "AGENTS.md").unlink()
        lock = lockfile.load(root)
        changes = lockfile.changes(root, lock)
        assert changes["deleted"] == ["AGENTS.md"]


def test_approve_updates_hash() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "AGENTS.md").write_text("# Agents\n\nHello.\n", encoding="utf-8")
        lockfile.write(root, lockfile.hashes(root))
        (root / "AGENTS.md").write_text("# Agents\n\nChanged.\n", encoding="utf-8")
        approved, unknown = lockfile.approve(root, [Path("AGENTS.md")])
        assert approved == ["AGENTS.md"]
        assert not unknown
        lock = lockfile.load(root)
        changes = lockfile.changes(root, lock)
        assert not any(changes.values())


def test_approve_deletion() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "AGENTS.md").write_text("# Agents\n\nHello.\n", encoding="utf-8")
        lockfile.write(root, lockfile.hashes(root))
        (root / "AGENTS.md").unlink()
        approved, unknown = lockfile.approve(root, [Path("AGENTS.md")])
        assert approved == ["AGENTS.md"]
        lock = lockfile.load(root)
        assert "AGENTS.md" not in lock["files"]


def test_diff_findings_on_changed() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # Create a file with a hidden unicode char
        (root / "AGENTS.md").write_text("# Agents\n\nHello\u200b world.\n", encoding="utf-8")
        lockfile.write(root, lockfile.hashes(root))
        # Modify it
        (root / "AGENTS.md").write_text("# Agents\n\nChanged\u200b text.\n", encoding="utf-8")
        lock = lockfile.load(root)
        changes = lockfile.changes(root, lock)
        findings = lockfile.diff_findings(root, changes["modified"])
        assert any(f.rule_id == "HUC001" for f in findings)


def test_discover_respects_skip_dirs() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "AGENTS.md").write_text("# A\n", encoding="utf-8")
        (root / ".git").mkdir()
        (root / ".git" / "AGENTS.md").write_text("# B\n", encoding="utf-8")
        (root / "node_modules").mkdir()
        (root / "node_modules" / "AGENTS.md").write_text("# C\n", encoding="utf-8")
        from cairnlock.scanner import discover_files
        found = {p.relative_to(root).as_posix() for p in discover_files(root)}
        assert found == {"AGENTS.md"}
