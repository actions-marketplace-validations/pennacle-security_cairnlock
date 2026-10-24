"""Configuration loading for cairnlock.

Sources, in precedence order:

1. ``cairnlock.toml`` in the scan root (top-level keys).
2. ``[tool.cairnlock]`` in ``pyproject.toml`` in the scan root.
3. ``.cairnlockignore`` in the scan root (gitignore-style globs, merged with
   ``ignore`` from either config file).

Keys: ``ignore`` (list of glob patterns), ``disabled_rules`` (list of rule
ids), ``fail_on`` (``low``, ``medium``, ``high``, or ``never``).
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

VALID_FAIL_ON = {"low", "medium", "high", "never"}


class ConfigError(Exception):
    """Invalid configuration. Maps to exit code 2."""


@dataclass
class ScanConfig:
    ignore: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    fail_on: str = "low"


def load_config(root: Path) -> ScanConfig:
    """Load and merge configuration; raises ConfigError on invalid input."""
    table: dict = {}
    source = None

    toml_path = root / "cairnlock.toml"
    if toml_path.is_file():
        table = _read_table(toml_path)
        source = "cairnlock.toml"

    if not table:
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            data = _read_table(pyproject)
            table = data.get("tool", {}).get("cairnlock", {})
            if isinstance(table, dict) and table:
                source = "pyproject.toml"
            else:
                table = {}

    config = _from_table(table, source)
    config.ignore.extend(_load_cairnlockignore(root))
    return config


def _read_table(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read {path.name}: {exc}") from exc


def _from_table(table: dict, source: str | None) -> ScanConfig:
    config = ScanConfig()
    if not table:
        return config

    where = f" in {source}" if source else ""

    ignore = table.get("ignore", [])
    if not isinstance(ignore, list) or not all(isinstance(p, str) for p in ignore):
        raise ConfigError(f"config 'ignore' must be a list of strings{where}")
    config.ignore = list(ignore)

    disabled = table.get("disabled_rules", table.get("disabled-rules", []))
    if not isinstance(disabled, list) or not all(isinstance(r, str) for r in disabled):
        raise ConfigError(f"config 'disabled_rules' must be a list of strings{where}")
    config.disabled_rules = [r.upper() for r in disabled]

    fail_on = table.get("fail_on", "low")
    if fail_on not in VALID_FAIL_ON:
        valid = ", ".join(sorted(VALID_FAIL_ON))
        raise ConfigError(f"config 'fail_on' must be one of: {valid}{where}")
    config.fail_on = fail_on
    return config


def _load_cairnlockignore(root: Path) -> list[str]:
    path = root / ".cairnlockignore"
    if not path.is_file():
        return []
    patterns: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    except (OSError, UnicodeDecodeError):
        return []
    return patterns


def is_ignored(rel_path: str, patterns: list[str]) -> bool:
    """Match a repo-relative path against glob patterns.

    A pattern matches the full path or any leading directory chain, so
    ``vendor`` and ``vendor/**`` both exclude files inside vendor/.
    """
    parts = rel_path.split("/")
    for pattern in patterns:
        cleaned = pattern.strip().strip("/")
        if not cleaned:
            continue
        if fnmatch.fnmatch(rel_path, cleaned):
            return True
        for i in range(1, len(parts)):
            if fnmatch.fnmatch("/".join(parts[:i]), cleaned):
                return True
    return False
