"""Baseline fingerprints so recurring findings do not mask new ones."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cairnlock.models import Finding


def fingerprint(finding: Finding) -> str:
    key = f"{finding.rule_id}|{finding.path}|{finding.line}|{finding.message}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def write_baseline(path: Path, findings: list[Finding]) -> None:
    payload = {"version": 1, "fingerprints": sorted({fingerprint(f) for f in findings})}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"could not read baseline file: {path}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("fingerprints"), list):
        raise ValueError(f"invalid baseline file: {path}")
    return {fp for fp in data["fingerprints"] if isinstance(fp, str)}
