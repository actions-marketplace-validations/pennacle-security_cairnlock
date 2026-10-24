"""Unpinned npx/uvx package execution in MCP configs.

Rule ID: UNP001
Flags npx/uvx/bunx packages without a version pin (or pinned to @latest).
"""

from __future__ import annotations

import json
import re

from cairnlock.models import Finding

RULE_ID = "UNP001"

# Match a package spec with a version pin: pkg@version, @scope/pkg@version, or pkg==version
_PINNED_RE = re.compile(r"(?:@[^/]+/)?[^@/]+@.+|^[^@/]+==.+$")


def _is_pinned(pkg: str) -> tuple[bool, bool]:
    """Return (is_pinned, is_latest)."""
    if pkg == "latest" or pkg.endswith("@latest"):
        return True, True
    if _PINNED_RE.match(pkg):
        return True, False
    return False, False


def _first_package(args: list) -> str | None:
    """Return first non-flag argument (the package name)."""
    for a in args:
        if isinstance(a, str) and not a.startswith("-"):
            return a
    return None


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith(".json")


def check(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    for key in ("mcpServers", "mcp"):
        if key not in data or not isinstance(data[key], dict):
            continue
        for _name, cfg in data[key].items():
            if not isinstance(cfg, dict):
                continue
            cmd = cfg.get("command")
            if cmd not in ("npx", "uvx", "bunx"):
                continue
            args = cfg.get("args", [])
            if not isinstance(args, list):
                continue
            pkg = _first_package(args)
            if pkg is None:
                continue
            pinned, is_latest = _is_pinned(pkg)
            if not pinned:
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity="medium",
                        path=rel_path,
                        line=0,
                        message=f'{cmd} package "{pkg}" has no version pin',
                    )
                )
            elif is_latest:
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity="medium",
                        path=rel_path,
                        line=0,
                        message=f'{cmd} package "{pkg}" is pinned to @latest',
                    )
                )
    return findings
