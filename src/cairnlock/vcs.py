"""Local git helpers for cairnlock.verify --base.

Every git call uses an argument list and never a shell. Refs are validated
before git sees them: a ref starting with "-" is rejected as a usage error.
`git show <ref>:<path>` is called without "--" because in that position git
treats everything after "--" as a path, which changes the command's meaning.
No git call here touches the network.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class GitUsageError(Exception):
    """Invalid user input, such as a ref starting with '-'. Exit code 2."""


class GitEnvError(Exception):
    """Git missing, not a repository, or ref unavailable. Exit code 2."""


def _git(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise GitEnvError("git executable not found on PATH") from exc


def validate_ref(ref: str) -> None:
    """Reject refs that could be parsed as git options."""
    if not ref or ref.startswith("-"):
        raise GitUsageError(f"invalid git ref: {ref!r} (must not start with '-')")


def _is_shallow(root: Path) -> bool:
    return (root / ".git" / "shallow").is_file()


def read_file_at(root: Path, ref: str, path: str) -> str | None:
    """Return the file content at ref, or None when the path is absent there.

    Raises GitUsageError for malformed refs and GitEnvError when the ref does
    not resolve or root is not a git repository.
    """
    validate_ref(ref)
    probe = _git(root, ["cat-file", "-t", ref])
    if probe.returncode != 0:
        stderr = probe.stderr.strip()
        if "not a git repository" in stderr:
            raise GitEnvError(f"{root} is not a git repository")
        if _is_shallow(root):
            raise GitEnvError(
                f"git ref {ref!r} is not available in this shallow clone; "
                "set fetch-depth: 0 on the actions/checkout step in GitHub Actions"
            )
        raise GitEnvError(f"git ref {ref!r} not found in this repository")

    blob = _git(root, ["show", f"{ref}:{path}"])
    if blob.returncode != 0:
        if "does not exist" in blob.stderr or "exists on disk, but not in" in blob.stderr:
            return None
        raise GitEnvError(f"could not read {path} at ref {ref!r}: {blob.stderr.strip()}")
    return blob.stdout
