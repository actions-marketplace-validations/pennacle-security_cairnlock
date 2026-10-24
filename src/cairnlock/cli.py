"""Typer CLI entry points with rich UX."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from cairnlock import __version__, lockfile
from cairnlock.ascii_art import get_banner
from cairnlock.output import render_html, render_json, render_markdown, render_sarif, render_text
from cairnlock.scanner import discover_files

app = typer.Typer(
    add_completion=False,
    help="Static analyzer and lockfile for AI-agent context files.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

console = Console()


class OutputFormat(StrEnum):
    text = "text"
    json = "json"
    sarif = "sarif"
    html = "html"
    markdown = "md"


class SeverityFilter(StrEnum):
    all = "all"
    high = "high"
    medium = "medium"
    low = "low"


def _version_callback(value: bool) -> None:
    if value:
        console.print(get_banner(__version__, compact=True))
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-error output."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Hide ASCII banner."),
) -> None:
    """Static analyzer and lockfile for AI-agent context files."""
    if not no_banner and not quiet and not version:
        console.print(get_banner(__version__))


def _render(findings: list, fmt: OutputFormat) -> str:
    if fmt is OutputFormat.json:
        return render_json(findings)
    if fmt is OutputFormat.sarif:
        return render_sarif(findings)
    if fmt is OutputFormat.html:
        return render_html(findings)
    if fmt is OutputFormat.markdown:
        return render_markdown(findings)
    return render_text(findings)


def _filter_findings(findings: list, severity: SeverityFilter) -> list:
    if severity == SeverityFilter.all:
        return findings
    return [f for f in findings if f.severity == severity.value]


def _print_summary(findings: list, verbose: bool = False) -> None:
    if not findings:
        console.print("[green]✓[/green] No findings")
        return

    by_severity = {"high": 0, "medium": 0, "low": 0}
    by_rule = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

    table = Table(title="Scan Summary", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ("high", "medium", "low"):
        if by_severity.get(sev, 0):
            color = {"high": "red", "medium": "yellow", "low": "blue"}[sev]
            table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(by_severity[sev]))
    table.add_row("TOTAL", str(len(findings)), style="bold")
    console.print(table)

    if verbose and by_rule:
        rule_table = Table(title="By Rule", show_header=True, header_style="bold cyan")
        rule_table.add_column("Rule ID")
        rule_table.add_column("Count", justify="right")
        for rid, count in sorted(by_rule.items(), key=lambda x: -x[1]):
            rule_table.add_row(rid, str(count))
        console.print(rule_table)


@app.command(name="scan")
def scan_cmd(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Directory to scan.")] = Path("."),
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")] = OutputFormat.text,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write report to file.")] = None,
    no_fail: Annotated[bool, typer.Option("--no-fail", help="Exit 0 even when findings exist.")] = False,
    severity: Annotated[SeverityFilter, typer.Option("--severity", "-s", help="Filter by minimum severity.")] = SeverityFilter.all,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
    show_progress: Annotated[bool, typer.Option("--progress/--no-progress", help="Show progress bar.")] = True,
) -> None:
    """Scan agent context files under PATH for risk patterns."""
    if verbose:
        console.print(f"[dim]Scanning: {path.absolute()}[/dim]")

    files = list(discover_files(path))
    if not files:
        console.print("[yellow]No agent context files found[/yellow]")
        return

    findings: list = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        disable=not show_progress or len(files) < 5,
    ) as progress:
        task = progress.add_task("Scanning files...", total=len(files))
        for p in files:
            rel = p.relative_to(path).as_posix()
            try:
                if p.stat().st_size > 1_000_000:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            from cairnlock.scanner import check_file
            findings.extend(check_file(rel, text))
            progress.advance(task)

    findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    findings = _filter_findings(findings, severity)

    report = _render(findings, fmt)
    if output is not None:
        output.write_text(report + "\n", encoding="utf-8")
        console.print(f"[green]✓[/green] Wrote {len(findings)} findings to {output}")
    else:
        console.print(report)

    if verbose or fmt == OutputFormat.text:
        console.print()
        _print_summary(findings, verbose=verbose)

    if findings and not no_fail:
        raise typer.Exit(1)


@app.command()
def init(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Repository root.")] = Path("."),
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing lockfile.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
) -> None:
    """Record SHA-256 hashes of all tracked agent context files in cairnlock.lock."""
    lock_path = path / lockfile.LOCKFILE_NAME
    if lock_path.exists() and not force:
        console.print(f"[red]✗[/red] {lockfile.LOCKFILE_NAME} already exists; use --force to overwrite")
        raise typer.Exit(1)
    files = lockfile.hashes(path)
    if not files:
        console.print("[yellow]⚠[/yellow] No agent context files found")
    lockfile.write(path, files)
    console.print(f"[green]✓[/green] Wrote {lockfile.LOCKFILE_NAME} with {len(files)} files")
    if verbose:
        for rel, h in sorted(files.items()):
            console.print(f"  {rel}  [dim]{h[:16]}...[/dim]")


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
) -> None:
    """Fail if any tracked file changed, was added, or deleted since last init."""
    lock = lockfile.load(path)
    if lock is None:
        console.print(f"[red]✗[/red] No {lockfile.LOCKFILE_NAME}; run 'cairnlock init' first")
        raise typer.Exit(1)
    changes = lockfile.changes(path, lock)
    tracked = len(lock.get("files", {}))
    if not any(changes.values()):
        console.print(f"[green]✓[/green] OK: {tracked} files unchanged")
        return
    for kind in ("modified", "added", "deleted"):
        for rel in changes[kind]:
            icon = {"modified": "📝", "added": "➕", "deleted": "🗑️"}[kind]
            console.print(f"  {icon} {kind}: {rel}")
    total = sum(len(v) for v in changes.values())
    console.print(f"[red]✗[/red] Verify failed: {total} changed files")
    console.print("Review with 'cairnlock diff', then approve with 'cairnlock approve <file>'")
    raise typer.Exit(1)


@app.command()
def diff(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
) -> None:
    """Show changes against the lockfile, with findings inside changed files."""
    lock = lockfile.load(path)
    if lock is None:
        console.print(f"[red]✗[/red] No {lockfile.LOCKFILE_NAME}; run 'cairnlock init' first")
        raise typer.Exit(1)
    changes = lockfile.changes(path, lock)
    if not any(changes.values()):
        console.print("[green]✓[/green] No changes")
        return
    changed = [rel for kind in ("modified", "added") for rel in changes[kind]]
    findings = lockfile.diff_findings(path, changed)
    for kind in ("modified", "added", "deleted"):
        for rel in changes[kind]:
            count = sum(1 for f in findings if f.path == rel)
            icon = {"modified": "📝", "added": "➕", "deleted": "🗑️"}[kind]
            suffix = f" ({count} finding{'s' if count != 1 else ''})" if kind != "deleted" else ""
            console.print(f"  {icon} {kind}: {rel}{suffix}")
    if findings:
        console.print()
        _print_summary(findings, verbose=verbose)


@app.command()
def approve(
    paths: Annotated[list[Path], typer.Argument(..., help="File(s) to approve (relative to --root).")],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False, help="Repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
) -> None:
    """Mark changed files as reviewed (update hash) or approve deletion (remove entry)."""
    try:
        approved, unknown = lockfile.approve(root, paths)
    except FileNotFoundError as e:
        console.print(f"[red]✗[/red] {e}")
        raise typer.Exit(1) from e
    for rel in approved:
        console.print(f"[green]✓[/green] Approved: {rel}")
    for unk in unknown:
        console.print(f"[yellow]⚠[/yellow] Not tracked or missing: {unk}")
    if unknown:
        raise typer.Exit(1)


@app.command()
def rules(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show detailed rule info.")] = False,
) -> None:
    """List all detection rules with metadata."""
    from cairnlock.rules import RULE_META, RULES

    table = Table(title="Detection Rules", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Scope")
    if verbose:
        table.add_column("Description")

    for rule in RULES:
        rid = getattr(rule, "RULE_ID", getattr(rule, "RULE_ID_001", "?"))
        name = RULE_META.get(rid, rid)
        sev = "high"  # default
        if rid == "MCP002":
            sev = "medium"
        elif rid == "UNP001":
            sev = "medium"
        elif rid == "HUC001":
            sev = "high/med/low"
        elif rid == "SEC001":
            sev = "high/med"

        scope_map = {
            "HUC001": "All files",
            "PIN001": "JSON descriptions, SKILL.md",
            "REM001": "SKILL.md, skills/",
            "MCP001": "MCP JSON configs",
            "MCP002": "MCP JSON configs",
            "UNP001": "MCP JSON configs",
            "SEC001": "All files",
        }
        scope = scope_map.get(rid, "Various")

        if verbose:
            table.add_row(rid, name, sev, scope, getattr(rule, "__doc__", "").strip() or "-")
        else:
            table.add_row(rid, name, sev, scope)

    console.print(table)


@app.command()
def stats(
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Repository root.")] = Path("."),
) -> None:
    """Show repository statistics for tracked files."""
    files = list(discover_files(path))
    if not files:
        console.print("[yellow]No agent context files found[/yellow]")
        return

    total_size = sum(p.stat().st_size for p in files)
    by_ext = {}
    for p in files:
        ext = p.suffix or "no-ext"
        by_ext[ext] = by_ext.get(ext, 0) + 1

    table = Table(title="Repository Stats", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Total files", str(len(files)))
    table.add_row("Total size", f"{total_size:,} bytes ({total_size/1024:.1f} KB)")
    for ext, count in sorted(by_ext.items(), key=lambda x: -x[1]):
        table.add_row(f"  {ext}", str(count))
    console.print(table)
