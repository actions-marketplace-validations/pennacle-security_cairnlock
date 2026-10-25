"""Typer CLI entry points with rich UX."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from cairnlock import __version__, lockfile, vcs
from cairnlock import baseline as baseline_mod
from cairnlock.ascii_art import get_banner
from cairnlock.config import ConfigError, is_ignored, load_config
from cairnlock.output import (
    render_github,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_text,
)
from cairnlock.rules import PROFILE_NAMES, PROFILE_RULES
from cairnlock.scanner import check_file, discover_files

app = typer.Typer(
    add_completion=False,
    help="Static analyzer and lockfile for AI-agent context files.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

console = Console()
err_console = Console(stderr=True)

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


class OutputFormat(StrEnum):
    text = "text"
    json = "json"
    sarif = "sarif"
    html = "html"
    markdown = "md"
    github = "github"


class SeverityFilter(StrEnum):
    all = "all"
    high = "high"
    medium = "medium"
    low = "low"


class FailOn(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    never = "never"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(get_banner(__version__, compact=True), err=True)
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-error output."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Hide ASCII banner."),
) -> None:
    """Static analyzer and lockfile for AI-agent context files."""
    # The banner prints lazily from each command, so options placed after the
    # subcommand (e.g. `cairnlock scan --no-banner`) still suppress it.
    ctx.obj = {"no_banner": bool(no_banner or quiet)}


def _print_banner(ctx: typer.Context, want: bool = True) -> None:
    """Print the full banner when wanted and not suppressed."""
    if want and not ctx.obj.get("no_banner"):
        typer.echo(get_banner(__version__), err=True)


def _render(findings: list, fmt: OutputFormat) -> str:
    if fmt is OutputFormat.json:
        return render_json(findings)
    if fmt is OutputFormat.sarif:
        return render_sarif(findings)
    if fmt is OutputFormat.html:
        return render_html(findings)
    if fmt is OutputFormat.markdown:
        return render_markdown(findings)
    if fmt is OutputFormat.github:
        return render_github(findings)
    return render_text(findings)


def _filter_findings(findings: list, severity: SeverityFilter) -> list:
    if severity == SeverityFilter.all:
        return findings
    return [f for f in findings if f.severity == severity.value]


def _print_summary(findings: list, verbose: bool = False) -> None:
    if not findings:
        console.print("[green]no findings[/green]")
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
    ctx: typer.Context,
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Directory to scan.")] = Path("."),
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")] = OutputFormat.text,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write report to file.")] = None,
    no_fail: Annotated[bool, typer.Option("--no-fail", help="Exit 0 even when findings exist.")] = False,
    fail_on: Annotated[
        FailOn | None,
        typer.Option(
            "--fail-on",
            help="Exit 1 only when a finding at or above this severity exists. "
            "Overrides cairnlock.toml.",
        ),
    ] = None,
    severity: Annotated[SeverityFilter, typer.Option("--severity", "-s", help="Report only this severity.")] = SeverityFilter.all,
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help="Rule set: core (agent context files, default) or extended "
            "(generic rules plus source and dependency files). Overrides cairnlock.toml.",
        ),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option("--baseline", help="JSON file of known finding fingerprints; only new findings are reported."),
    ] = None,
    write_baseline: Annotated[
        Path | None,
        typer.Option("--write-baseline", help="Save current finding fingerprints to this file and exit 0."),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
    show_progress: Annotated[bool, typer.Option("--progress/--no-progress", help="Show progress bar.")] = True,
    no_banner: Annotated[bool, typer.Option("--no-banner", help="Hide ASCII banner.")] = False,
    changed: Annotated[
        str | None,
        typer.Option(
            "--changed",
            help="Scan only files changed since this git ref (plus untracked files).",
        ),
    ] = None,
) -> None:
    """Scan agent context files under PATH for risk patterns."""
    # Machine formats and file output never get the banner; text on stdout does.
    want_banner = fmt is OutputFormat.text and output is None and not no_banner
    _print_banner(ctx, want_banner)
    try:
        config = load_config(path)
    except ConfigError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc

    changed_set: set[str] | None = None
    if changed is not None:
        try:
            changed_set = vcs.changed_paths(path, changed)
        except vcs.GitUsageError as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(2) from exc
        except vcs.GitEnvError as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(2) from exc

    if profile is not None:
        if profile not in PROFILE_NAMES:
            err_console.print(
                f"[red]error:[/red] --profile must be one of: {', '.join(PROFILE_NAMES)}"
            )
            raise typer.Exit(2)
        config.profile = profile
    allowed = PROFILE_RULES.get(config.profile)
    include_code = config.profile == "extended"

    if verbose:
        err_console.print(f"Scanning: {path.absolute()} (profile: {config.profile})")

    files = list(discover_files(path, include_code=include_code))
    if changed_set is not None:
        files = [p for p in files if p.relative_to(path).as_posix() in changed_set]
    if not files:
        # Status goes to stderr; machine formats still emit a valid document.
        if changed_set is not None:
            err_console.print(f"no changed context files vs '{changed}'")
        else:
            err_console.print("[yellow]No agent context files found[/yellow]")
        if fmt is OutputFormat.text:
            return
        typer.echo(_render([], fmt))
        return

    disabled = set(config.disabled_rules)
    ignore = config.ignore
    findings: list = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=err_console,
        disable=not show_progress or fmt is not OutputFormat.text or len(files) < 5,
    ) as progress:
        task = progress.add_task("Scanning files...", total=len(files))
        for p in files:
            rel = p.relative_to(path).as_posix()
            progress.advance(task)
            if ignore and is_ignored(rel, ignore):
                continue
            try:
                if p.stat().st_size > 1_000_000:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            findings.extend(check_file(rel, text, disabled, allowed))

    findings.sort(key=lambda f: (f.path, f.line, f.rule_id))
    findings = _filter_findings(findings, severity)

    baseline_fps: set[str] = set()
    if baseline is not None:
        try:
            baseline_fps = baseline_mod.load_baseline(baseline)
        except ValueError as exc:
            err_console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(2) from exc
        before = len(findings)
        findings = [f for f in findings if baseline_mod.fingerprint(f) not in baseline_fps]
        suppressed = before - len(findings)
    else:
        suppressed = 0

    if write_baseline is not None:
        baseline_mod.write_baseline(write_baseline, findings)
        err_console.print(
            f"[green]OK:[/green] Wrote {len(findings)} fingerprints to {write_baseline}"
        )
        return

    report = _render(findings, fmt)
    if output is not None:
        output.write_text(report + "\n", encoding="utf-8")
        err_console.print(f"[green]OK:[/green] Wrote {len(findings)} findings to {output}")
    elif fmt is OutputFormat.text:
        console.print(report)
    else:
        typer.echo(report)

    if fmt is OutputFormat.text:
        console.print()
        _print_summary(findings, verbose=verbose)
        if baseline is not None:
            console.print(f"suppressed by baseline: {suppressed}")

    effective_fail_on = fail_on.value if fail_on is not None else config.fail_on
    if no_fail or effective_fail_on == "never":
        return
    threshold = SEVERITY_RANK[effective_fail_on]
    if any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in findings):
        raise typer.Exit(1)


@app.command()
def init(
    ctx: typer.Context,
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Repository root.")] = Path("."),
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing lockfile.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
) -> None:
    """Record SHA-256 hashes of all tracked agent context files in cairnlock.lock."""
    _print_banner(ctx)
    lock_path = path / lockfile.LOCKFILE_NAME
    if lock_path.exists() and not force:
        console.print(f"[red]error:[/red] {lockfile.LOCKFILE_NAME} already exists; use --force to overwrite")
        raise typer.Exit(1)
    files = lockfile.hashes(path)
    if not files:
        console.print("[yellow]warning:[/yellow] no agent context files found")
    lockfile.write(path, files)
    console.print(f"[green]OK:[/green] Wrote {lockfile.LOCKFILE_NAME} with {len(files)} files")
    if verbose:
        for rel, h in sorted(files.items()):
            console.print(f"  {rel}  [dim]{h[:16]}...[/dim]")


def _lock_changed_vs_base(root: Path, base_lock: dict) -> bool:
    """Compare the working lockfile to the base lockfile semantically."""
    working = lockfile.load(root)
    if working is None:
        return True  # deleted or unreadable in the working tree
    return (working.get("version"), working.get("files")) != (
        base_lock.get("version"),
        base_lock.get("files"),
    )


def _verify_against_base(root: Path, base: str, allow_lock_change: bool) -> None:
    """Compare the working tree against the lockfile stored at a git ref.

    Exit codes: 0 clean, 1 changes found, 2 usage or environment error.
    """
    try:
        base_text = vcs.read_file_at(root, base, lockfile.LOCKFILE_NAME)
    except vcs.GitUsageError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc
    except vcs.GitEnvError as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(2) from exc

    if base_text is None:
        console.print(
            f"[red]error:[/red] no {lockfile.LOCKFILE_NAME} at ref '{base}'; "
            "run 'cairnlock init' on the base branch first"
        )
        raise typer.Exit(2)

    base_lock = lockfile.loads(base_text)
    if base_lock is None:
        console.print(
            f"[red]error:[/red] {lockfile.LOCKFILE_NAME} at ref '{base}' is not a valid lockfile"
        )
        raise typer.Exit(2)

    current_hashes = lockfile.hashes(root)
    base_files = base_lock["files"]
    findings: list[str] = []
    for rel in sorted(p for p in current_hashes if p in base_files and current_hashes[p] != base_files[p]):
        findings.append(f"modified: {rel}")
    for rel in sorted(p for p in current_hashes if p not in base_files):
        findings.append(f"added: {rel}")
    for rel in sorted(p for p in base_files if p not in current_hashes):
        findings.append(f"deleted: {rel}")

    lock_changed = _lock_changed_vs_base(root, base_lock)
    if lock_changed and not allow_lock_change:
        findings.insert(0, "lockfile modified in this change")

    if not findings:
        console.print(f"ok: no changes vs base '{base}'")
        return

    for line in findings:
        console.print(f"  {line}")
    console.print(f"[red]verify failed:[/red] {len(findings)} findings vs base '{base}'")
    if lock_changed and allow_lock_change:
        console.print("note: lockfile change allowed by --allow-lock-change")
    raise typer.Exit(1)


@app.command()
def verify(
    ctx: typer.Context,
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Repository root.")] = Path("."),
    base: Annotated[
        str | None,
        typer.Option("--base", help="Git ref to read the base cairnlock.lock from."),
    ] = None,
    allow_lock_change: Annotated[
        bool,
        typer.Option(
            "--allow-lock-change",
            help="Do not fail when cairnlock.lock itself differs from --base.",
        ),
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
) -> None:
    """Fail if tracked files changed without approval, or differ from --base.

    Exit codes: 0 clean, 1 changes found, 2 usage or environment error.
    """
    _print_banner(ctx)
    if base is not None:
        _verify_against_base(path, base, allow_lock_change)
        return
    lock = lockfile.load(path)
    if lock is None:
        console.print(f"[red]error:[/red] no {lockfile.LOCKFILE_NAME}; run 'cairnlock init' first")
        raise typer.Exit(2)
    changes = lockfile.changes(path, lock)
    tracked = len(lock.get("files", {}))
    if not any(changes.values()):
        console.print(f"ok: {tracked} files unchanged")
        return
    for kind in ("modified", "added", "deleted"):
        for rel in changes[kind]:
            console.print(f"  {kind}: {rel}")
    total = sum(len(v) for v in changes.values())
    console.print(f"[red]verify failed:[/red] {total} changed files")
    console.print("review with 'cairnlock diff', then approve with 'cairnlock approve <file>'")
    raise typer.Exit(1)


@app.command()
def diff(
    ctx: typer.Context,
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
) -> None:
    """Show changes against the lockfile, with findings inside changed files."""
    _print_banner(ctx)
    lock = lockfile.load(path)
    if lock is None:
        console.print(f"[red]error:[/red] no {lockfile.LOCKFILE_NAME}; run 'cairnlock init' first")
        raise typer.Exit(1)
    changes = lockfile.changes(path, lock)
    if not any(changes.values()):
        console.print("ok: no changes")
        return
    changed = [rel for kind in ("modified", "added") for rel in changes[kind]]
    findings = lockfile.diff_findings(path, changed)
    for kind in ("modified", "added", "deleted"):
        for rel in changes[kind]:
            count = sum(1 for f in findings if f.path == rel)
            suffix = f" ({count} finding{'s' if count != 1 else ''})" if kind != "deleted" else ""
            console.print(f"  {kind}: {rel}{suffix}")
    if findings:
        console.print()
        _print_summary(findings, verbose=verbose)


@app.command()
def approve(
    ctx: typer.Context,
    paths: Annotated[list[Path], typer.Argument(..., help="File(s) to approve (relative to --root).")],
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False, help="Repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output.")] = False,
) -> None:
    """Mark changed files as reviewed (update hash) or approve deletion (remove entry)."""
    _print_banner(ctx)
    try:
        approved, unknown = lockfile.approve(root, paths)
    except FileNotFoundError as e:
        console.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    for rel in approved:
        console.print(f"[green]OK:[/green] Approved: {rel}")
    for unk in unknown:
        console.print(f"[yellow]warning:[/yellow] not tracked or missing: {unk}")
    if unknown:
        raise typer.Exit(1)


@app.command()
def rules(
    ctx: typer.Context,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show detailed rule info.")] = False,
) -> None:
    """List all detection rules with profile and scope."""
    _print_banner(ctx)
    from cairnlock.rules import RULE_META, RULES, rule_ids

    profile_of: dict[str, str] = {}
    for name, ids in PROFILE_RULES.items():
        for rid in ids:
            profile_of[rid] = name

    table = Table(title="Detection Rules", show_header=True, header_style="bold magenta")
    table.add_column("ID", style="bold")
    table.add_column("Profile")
    table.add_column("Scope")
    table.add_column("Description")
    if verbose:
        table.add_column("Module")

    for rule in RULES:
        for rid in sorted(rule_ids(rule)):
            profile = profile_of.get(rid, "?")
            scope = {
                "HUC001": "all context files",
                "PIN001": "JSON descriptions, SKILL.md frontmatter",
                "REM001": "SKILL.md, skills/ files",
                "MCP001": "MCP JSON configs",
                "MCP002": "MCP JSON configs",
                "MCP003": "MCP JSON configs",
                "MCP004": "MCP JSON configs",
                "UNP001": "MCP JSON configs",
                "SEC001": "all scanned files",
                "SHC001": "source files (extended)",
                "NET001": "source files (extended)",
                "FSY001": "source files (extended)",
                "ENV001": "source files (extended)",
                "PRI001": "source files (extended)",
                "OBF001": "source files, non-skill (extended)",
                "SUP001": "dependency files (extended)",
                "CFG001": "config files, non-markdown (extended)",
                "TOO001": "tool definitions, JSON configs",
                "CRY001": "source files (extended)",
            }.get(rid, "varies")
            if verbose:
                table.add_row(rid, profile, scope, RULE_META.get(rid, rid), rule.__name__)
            else:
                table.add_row(rid, profile, scope, RULE_META.get(rid, rid))

    console.print(table)


hook_app = typer.Typer(help="Install or remove the pre-commit hook.", no_args_is_help=True)
app.add_typer(hook_app, name="hook")

HOOK_MARKER = "# installed by cairnlock"
HOOK_SCRIPT = (
    "#!/bin/sh\n"
    + HOOK_MARKER
    + "\n# Blocks commits with unreviewed agent context file changes.\n"
    "cairnlock verify || exit 1\n"
)


@hook_app.command()
def install(
    ctx: typer.Context,
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False, help="Repository root.")] = Path("."),
) -> None:
    """Write the cairnlock pre-commit hook into .git/hooks/pre-commit."""
    _print_banner(ctx)
    hooks_dir = root / ".git" / "hooks"
    if not (root / ".git").is_dir():
        err_console.print(f"[red]error:[/red] {root} is not a git repository")
        raise typer.Exit(2)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    target = hooks_dir / "pre-commit"
    if target.is_file():
        existing = target.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER not in existing and existing.strip():
            err_console.print(
                "[red]error:[/red] an existing pre-commit hook is not managed by"
                " cairnlock; merge it manually or remove it first"
            )
            raise typer.Exit(1)
    target.write_text(HOOK_SCRIPT, encoding="utf-8")
    console.print(f"[green]OK:[/green] installed pre-commit hook at {target}")


@hook_app.command()
def uninstall(
    ctx: typer.Context,
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False, help="Repository root.")] = Path("."),
) -> None:
    """Remove the cairnlock pre-commit hook (only if cairnlock manages it)."""
    _print_banner(ctx)
    target = root / ".git" / "hooks" / "pre-commit"
    if not target.is_file():
        console.print("no pre-commit hook present")
        return
    existing = target.read_text(encoding="utf-8", errors="replace")
    if HOOK_MARKER not in existing:
        err_console.print(
            "[red]error:[/red] the pre-commit hook is not managed by cairnlock;"
            " refusing to remove it"
        )
        raise typer.Exit(1)
    target.unlink()
    console.print("[green]OK:[/green] removed pre-commit hook")


@app.command()
def mcp(ctx: typer.Context) -> None:
    """Run cairnlock as an MCP stdio server (scan, verify, rules, stats)."""
    from cairnlock.mcp_server import serve

    serve()


@app.command()
def stats(
    ctx: typer.Context,
    path: Annotated[Path, typer.Argument(exists=True, file_okay=False, help="Repository root.")] = Path("."),
) -> None:
    """Show repository statistics for tracked files."""
    _print_banner(ctx)
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
