"""Typer CLI entry points."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import typer

from cairnlock import __version__, lockfile
from cairnlock.output import render_json, render_sarif, render_text
from cairnlock.scanner import scan as run_scan

app = typer.Typer(
    add_completion=False,
    help="Static analyzer and lockfile for AI-agent context files.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


class OutputFormat(StrEnum):
    text = "text"
    json = "json"
    sarif = "sarif"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cairnlock {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Static analyzer and lockfile for AI-agent context files."""


def _render(findings: list, fmt: OutputFormat) -> str:
    if fmt is OutputFormat.json:
        return render_json(findings)
    if fmt is OutputFormat.sarif:
        return render_sarif(findings)
    return render_text(findings)


@app.command(name="scan")
def scan_cmd(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, help="Directory to scan."),
    fmt: OutputFormat = typer.Option(OutputFormat.text, "--format", "-f", help="Output format."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file."),
    no_fail: bool = typer.Option(False, "--no-fail", help="Exit 0 even when findings exist."),
) -> None:
    """Scan agent context files under PATH for risk patterns."""
    result = run_scan(path)
    report = _render(result, fmt)
    if output is not None:
        output.write_text(report + "\n", encoding="utf-8")
        typer.echo(f"wrote {len(result)} findings to {output}")
    else:
        typer.echo(report)
    if result and not no_fail:
        raise typer.Exit(1)


@app.command()
def init(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, help="Repository root."),
    force: bool = typer.Option(False, "--force", help="Overwrite existing lockfile."),
) -> None:
    """Record SHA-256 hashes of all tracked agent context files in cairnlock.lock."""
    lock_path = path / lockfile.LOCKFILE_NAME
    if lock_path.exists() and not force:
        typer.echo(f"{lockfile.LOCKFILE_NAME} already exists; use --force to overwrite")
        raise typer.Exit(1)
    files = lockfile.hashes(path)
    if not files:
        typer.echo("warning: no agent context files found")
    lockfile.write(path, files)
    typer.echo(f"wrote {lockfile.LOCKFILE_NAME} with {len(files)} files")


@app.command()
def verify(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, help="Repository root."),
) -> None:
    """Fail if any tracked file changed, was added, or deleted since last init."""
    lock = lockfile.load(path)
    if lock is None:
        typer.echo(f"no {lockfile.LOCKFILE_NAME}; run 'cairnlock init' first")
        raise typer.Exit(1)
    changes = lockfile.changes(path, lock)
    tracked = len(lock.get("files", {}))
    if not any(changes.values()):
        typer.echo(f"ok: {tracked} files unchanged")
        return
    for kind in ("modified", "added", "deleted"):
        for rel in changes[kind]:
            typer.echo(f"{kind}: {rel}")
    total = sum(len(v) for v in changes.values())
    typer.echo(f"verify failed: {total} changed files")
    typer.echo("review with 'cairnlock diff', then approve with 'cairnlock approve <file>'")
    raise typer.Exit(1)


@app.command()
def diff(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, help="Repository root."),
) -> None:
    """Show changes against the lockfile, with findings inside changed files."""
    lock = lockfile.load(path)
    if lock is None:
        typer.echo(f"no {lockfile.LOCKFILE_NAME}; run 'cairnlock init' first")
        raise typer.Exit(1)
    changes = lockfile.changes(path, lock)
    if not any(changes.values()):
        typer.echo("no changes")
        return
    changed = [rel for kind in ("modified", "added") for rel in changes[kind]]
    findings = lockfile.diff_findings(path, changed)
    for kind in ("modified", "added", "deleted"):
        for rel in changes[kind]:
            count = sum(1 for f in findings if f.path == rel)
            suffix = f" ({count} finding{'s' if count != 1 else ''})" if kind != "deleted" else ""
            typer.echo(f"{kind}: {rel}{suffix}")
    if findings:
        typer.echo("")
        typer.echo(render_text(findings))


@app.command()
def approve(
    paths: list[Path] = typer.Argument(..., help="File(s) to approve (relative to --root)."),
    root: Path = typer.Option(
        Path("."), "--root", exists=True, file_okay=False, help="Repository root."
    ),
) -> None:
    """Mark changed files as reviewed (update hash) or approve deletion (remove entry)."""
    try:
        approved, unknown = lockfile.approve(root, paths)
    except FileNotFoundError as e:
        typer.echo(str(e))
        raise typer.Exit(1) from e
    for rel in approved:
        typer.echo(f"approved: {rel}")
    for unk in unknown:
        typer.echo(f"not tracked or missing: {unk}")
    if unknown:
        raise typer.Exit(1)