"""Output renderers: text, JSON, SARIF 2.1.0, HTML, Markdown."""

from __future__ import annotations

import html
import json
from datetime import datetime

from cairnlock.models import Finding
from cairnlock.rules import RULE_META

SEVERITY_TO_SARIF = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
SEVERITY_COLOR = {"high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}
SEVERITY_ICON = {"high": "🔴", "medium": "🟡", "low": "🔵", "info": "⚪"}


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
    rule_ids = sorted({f.rule_id for f in findings})
    rules = [
        {
            "id": rid,
            "name": RULE_META.get(rid, rid),
            "shortDescription": {"text": RULE_META.get(rid, rid)},
            "helpUri": f"https://github.com/pennacle-security/cairnlock/blob/main/docs/rules/{rid.lower()}.md",
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
                            "region": {"startLine": max(1, f.line), "startColumn": max(1, f.col or 1)},
                        }
                    }
                ],
                "partialFingerprints": {"ruleId": f.rule_id, "path": f.path, "line": str(f.line)},
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
                        "version": "0.2.0",
                        "informationUri": "https://github.com/pennacle-security/cairnlock",
                        "rules": rules,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_html(findings: list[Finding]) -> str:
    """Self-contained HTML report with styling."""
    from cairnlock import __version__

    if not findings:
        findings_html = '<tr><td colspan="6" style="text-align:center;color:#6b7280;padding:2rem">No findings</td></tr>'
    else:
        rows = []
        for f in findings:
            color = SEVERITY_COLOR.get(f.severity, "#6b7280")
            icon = SEVERITY_ICON.get(f.severity, "⚪")
            rows.append(f"""
                <tr>
                    <td><code>{html.escape(f.path)}</code></td>
                    <td style="text-align:center">{f.line or '-'}</td>
                    <td><span class="badge" style="background:{color}">{f.severity.upper()}</span></td>
                    <td><code>{html.escape(f.rule_id)}</code></td>
                    <td>{html.escape(f.message)}</td>
                    <td>{icon}</td>
                </tr>
            """)
        findings_html = "\n".join(rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>cairnlock Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 2rem; background: #f8fafc; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); overflow: hidden; }}
        header {{ background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: white; padding: 2rem; }}
        header h1 {{ margin: 0; font-size: 1.75rem; }}
        header p {{ margin: 0.5rem 0 0; opacity: 0.8; }}
        .meta {{ display: flex; gap: 2rem; margin-top: 1rem; font-size: 0.875rem; opacity: 0.9; }}
        .summary {{ display: flex; gap: 1rem; padding: 1.5rem 2rem; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }}
        .stat {{ text-align: center; padding: 0 1rem; }}
        .stat-value {{ font-size: 1.5rem; font-weight: 700; color: #1e293b; }}
        .stat-label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.875rem 1rem; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f8fafc; font-weight: 600; color: #334155; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        tr:hover {{ background: #f8fafc; }}
        code {{ background: #f1f5f9; padding: 0.125rem 0.375rem; border-radius: 4px; font-size: 0.8125rem; }}
        .badge {{ display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; font-size: 0.625rem; font-weight: 600; color: white; text-transform: uppercase; }}
        .footer {{ padding: 1.5rem 2rem; color: #64748b; font-size: 0.875rem; border-top: 1px solid #e2e8f0; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🏔️ cairnlock Scan Report</h1>
            <p>Static analyzer & lockfile for AI-agent context files</p>
            <div class="meta">
                <span>Version: {__version__}</span>
                <span>Generated: {datetime.now().isoformat(timespec='seconds')}</span>
                <span>Files scanned: {len({f.path for f in findings}) if findings else 0}</span>
            </div>
        </header>
        <div class="summary">
            <div class="stat"><div class="stat-value">{len(findings)}</div><div class="stat-label">Total Findings</div></div>
            <div class="stat"><div class="stat-value" style="color:#dc2626">{sum(1 for f in findings if f.severity=='high')}</div><div class="stat-label">High</div></div>
            <div class="stat"><div class="stat-value" style="color:#d97706">{sum(1 for f in findings if f.severity=='medium')}</div><div class="stat-label">Medium</div></div>
            <div class="stat"><div class="stat-value" style="color:#2563eb">{sum(1 for f in findings if f.severity=='low')}</div><div class="stat-label">Low</div></div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th style="width:60px">Line</th>
                    <th style="width:100px">Severity</th>
                    <th style="width:80px">Rule</th>
                    <th>Message</th>
                    <th style="width:40px"></th>
                </tr>
            </thead>
            <tbody>
                {findings_html}
            </tbody>
        </table>
        <div class="footer">
            Generated by <a href="https://github.com/pennacle-security/cairnlock">cairnlock</a> v{__version__}
        </div>
    </div>
</body>
</html>"""


def render_markdown(findings: list[Finding]) -> str:
    """Markdown report for PR comments or documentation."""
    from cairnlock import __version__

    if not findings:
        return f"# cairnlock Scan Report\n\n**No findings** ✅\n\n---\n*Generated by cairnlock v{__version__} on {datetime.now().isoformat(timespec='seconds')}*"

    by_severity = {"high": [], "medium": [], "low": []}
    for f in findings:
        if f.severity in by_severity:
            by_severity[f.severity].append(f)

    lines = [
        "# 🏔️ cairnlock Scan Report",
        f"**Version:** {__version__}  ",
        f"**Generated:** {datetime.now().isoformat(timespec='seconds')}  ",
        f"**Total findings:** {len(findings)}  ",
        f"**Files scanned:** {len({f.path for f in findings})}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
        f"| 🔴 High | {len(by_severity['high'])} |",
        f"| 🟡 Medium | {len(by_severity['medium'])} |",
        f"| 🔵 Low | {len(by_severity['low'])} |",
        f"| **Total** | **{len(findings)}** |",
        "",
    ]

    for sev in ("high", "medium", "low"):
        items = by_severity[sev]
        if not items:
            continue
        icon = {"high": "🔴", "medium": "🟡", "low": "🔵"}[sev]
        lines.append(f"## {icon} {sev.capitalize()} ({len(items)})")
        lines.append("")
        lines.append("| File | Line | Rule | Message |")
        lines.append("|---|---:|---|---|")
        for f in items:
            lines.append(f"| `{f.path}` | {f.line or '-'} | `{f.rule_id}` | {f.message} |")
        lines.append("")

    lines.append("---")
    lines.append(f"*Generated by [cairnlock](https://github.com/pennacle-security/cairnlock) v{__version__}*")
    return "\n".join(lines)
