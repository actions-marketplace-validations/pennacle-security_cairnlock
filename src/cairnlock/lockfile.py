"""Lockfile: cairnlock.lock read/write and change detection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cairnlock.scanner import discover_files

LOCKFILE_NAME = "cairnlock.lock"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def hashes(root: Path) -> dict[str, str]:
    """Return {rel_path: sha256} for all tracked files."""
    return {p.relative_to(root).as_posix(): _sha256(p) for p in discover_files(root)}


def write(root: Path, files: dict[str, str]) -> None:
    """Write cairnlock.lock with sorted entries."""
    payload = {"version": 1, "files": dict(sorted(files.items()))}
    (root / LOCKFILE_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def loads(text: str) -> dict | None:
    """Parse lockfile content from a string; return None if invalid."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        return None
    return data


def load(root: Path) -> dict | None:
    """Load and validate cairnlock.lock; return None if missing/invalid."""
    p = root / LOCKFILE_NAME
    if not p.is_file():
        return None
    try:
        text = p.read_text(encoding="utf-8")
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        return None
    return loads(text)


def changes(root: Path, lock: dict) -> dict[str, list[str]]:
    """Compare current hashes to lockfile; return modified/added/deleted."""
    current = hashes(root)
    old = lock.get("files", {})
    modified = sorted(p for p in current if p in old and current[p] != old[p])
    added = sorted(p for p in current if p not in old)
    deleted = sorted(p for p in old if p not in current)
    return {"modified": modified, "added": added, "deleted": deleted}


def diff_findings(root: Path, rel_paths: list[str]) -> list:
    """Run rules on current content of changed files; return findings."""
    from cairnlock.scanner import check_file

    findings: list = []
    for rel in rel_paths:
        p = root / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(check_file(rel, text))
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule_id))


def approve(root: Path, targets: list[Path]) -> tuple[list[str], list[str]]:
    """Mark files as reviewed (update hash) or approve deletion.

    Returns (approved_rel_paths, unknown_targets).
    """
    lock = load(root)
    if lock is None:
        raise FileNotFoundError(f"no {LOCKFILE_NAME}; run cairnlock init first")

    files = lock["files"]
    root_res = root.resolve()
    approved: list[str] = []
    unknown: list[str] = []

    for target in targets:
        try:
            rel = (root / target).resolve().relative_to(root_res).as_posix()
        except ValueError:
            unknown.append(str(target))
            continue

        t = root / rel
        if t.is_file():
            files[rel] = _sha256(t)
            approved.append(rel)
        elif rel in files:
            del files[rel]
            approved.append(rel)
        else:
            unknown.append(str(target))

    if approved:
        write(root, files)
    return approved, unknown
