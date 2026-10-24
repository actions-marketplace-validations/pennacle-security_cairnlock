"""Output renderers: text, JSON, SARIF 2.1.0."""

from __future__ import annotations

import json

from cairnlock.models import Finding
from cairnlock.rules import RULE_META

SEVERITY_TO_SARIF = {"high": "error", "medium": "warning", "low": "note", "info": "note"}


def render_text(findings: list[Finding]) -> str:
    """Human-readable grouped output."""
    if not findings:
        return "no findings"
    lines: list[str] = []
    for f in findings:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"{loc}: [{f.rule_id}] {f.message} ({f.severity})")
    lines.append("")
    n_files = len({f.path for f in findings})
    lines.append(f"{len(findings)} findings in {n_files} files")
    return "\n".join(lines)


def render_json(findings: list[Finding]) -> str:
    """Compact JSON with findings array and total."""
    return json.dumps(
        {"findings": [f.model_dump() for f in findings], "total": len(findings)},
        indent=2,
    )


def render_sarif(findings: list[Finding]) -> str:
    """SARIF 2.1.0 output for GitHub Code Scanning."""
    # Build unique rules list
    rule_ids = sorted({f.rule_id for f in findings})
    rules = [
        {
            "id": rid,
            "name": RULE_META.get(rid, rid),
            "shortDescription": {"text": RULE_META.get(rid, rid)},
        }
        for rid in rule_ids
    ]

    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": SEVERITY_TO_SARIF.get(f.severity, "note"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cairnlock",
                        "informationUri": "https://github.com/pennacle-security/cairnlock",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
