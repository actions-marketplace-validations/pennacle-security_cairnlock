"""The package version and pyproject version must agree."""

from __future__ import annotations

import tomllib
from pathlib import Path

import cairnlock

PYPROJECT = Path(__file__).parents[1] / "pyproject.toml"


def test_pyproject_version_matches_package() -> None:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert data["project"]["version"] == cairnlock.__version__
