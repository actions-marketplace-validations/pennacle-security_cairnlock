# cairnlock

<p align="center">
  <img src="assets/logo.svg" alt="cairnlock logo" width="128">
</p>

Static analyzer and lockfile for AI-agent context files.

Agent instruction files (AGENTS.md, CLAUDE.md, .cursorrules, MCP configs, skill
folders) are executable in practice: agents read them and act on them. They
usually bypass code review. cairnlock scans them for known risk patterns and
keeps a lockfile so unreviewed changes fail CI.

cairnlock does not execute, import, or install anything it scans. It makes no
network requests. Base verification reads from the local git clone only.

## Install

Python 3.11 or newer.

```bash
pipx install cairnlock
```

Or run it without installing:

```bash
uvx cairnlock scan
```

Fallback, straight from the repository:

```bash
pipx install git+https://github.com/pennacle-security/cairnlock.git@v0.5.0
```

## Quick start

```bash
# Initialize lockfile (records current hashes of all tracked files)
cairnlock init

# Scan for risks in current directory
cairnlock scan

# Verify no unreviewed changes since last init
cairnlock verify

# Show changes with findings inside modified files
cairnlock diff

# Approve a changed file (updates its hash in the lockfile)
cairnlock approve AGENTS.md

# List detection rules and repository statistics
cairnlock rules --verbose
cairnlock stats
```

Example scan output:

```
  ┌──────────────────────────────────────────────────────────────┐
  │  ▄▀█ █▄ █ █▀▄ █░█ █▀▀ █▀█ █░█ █▀▀ ▀█▀ ▄▀█ █▀▄▀█ ▄▀█ █▄ █    │
  │  █▀█ █ ▀█ █▄▀ █▄█ █▄▄ █▀▄ █▄█ ██▄ ░█░ █▀█ █░▀░█ █▀█ █ ▀█    │
  └──────────────────────────────────────────────────────────────┘
  cairnlock v0.5.0 — Static analyzer & lockfile for AI-agent contexts

SKILL.md:9: [REM001] curl piped into a shell (high)
SKILL.md:13: [REM001] long base64 blob (possible encoded payload) (high)
SKILL.md:16: [REM001] git clone from a remote URL (medium)

3 findings in 1 files
```

## Verify against a base ref

Plain `verify` compares the working tree against the lockfile on disk. That
can be defeated: a pull request can edit `AGENTS.md` and rehash
`cairnlock.lock` in the same commit, and verify passes. Base verification
closes that hole.

```bash
cairnlock verify --base origin/main
```

This reads `cairnlock.lock` as it exists at the base ref with `git show`,
not from the working tree, then compares the working tree against it. If the
lockfile itself differs from the base version, that is reported as its own
finding and verify exits 1:

```
  lockfile modified in this change
  modified: AGENTS.md
verify failed: 2 findings vs base 'origin/main'
```

Pass `--allow-lock-change` when the lockfile change is the whole point of
the branch. The tracked-file comparison still runs against the base lockfile
either way.

Exit codes for `verify --base`:

| Exit | Meaning |
|---|---|
| 0 | Nothing differs from the base lockfile |
| 1 | Tracked file changed, added, or deleted; or lockfile differs from base |
| 2 | Usage or environment error (bad ref, missing base lockfile, shallow clone) |

Notable error messages:

- No lockfile at the base ref: suggests running `cairnlock init` on the base
  branch first.
- Shallow clone: suggests setting `fetch-depth: 0` on the checkout step.
- Ref starting with `-`: rejected before git runs.

All git calls use an argument list, never a shell. cairnlock never makes
network calls; base verification reads only from the local clone.

## File discovery

cairnlock scans these files (anywhere in the repo):

| Pattern | Description |
|---|---|
| `AGENTS.md` / `CLAUDE.md` / `GEMINI.md` | Agent instructions |
| `.cursorrules` / `.windsurfrules` | Cursor and Windsurf rules files |
| `.clinerules` (file or directory) | Cline rules |
| `.github/copilot-instructions.md` | Copilot instructions |
| `opencode.json` | opencode configuration |
| `.mcp.json` / `mcp.json` | MCP server configurations |
| `.cursor/mcp.json` / `.vscode/mcp.json` | Editor MCP configurations |
| `.gemini/settings.json` | Gemini CLI settings |
| `claude_desktop_config.json` | Claude Desktop configuration |
| `.cursor/**` `.claude/**` `.opencode/**` | Agent settings, rules, and skills (md/json) |
| `.roo/**` `.continue/**` | Roo Code and Continue rules (md/json) |
| `skills/**/*.md` `**/SKILL.md` | Skill definitions |

Files over 1 MB are skipped. `.git`, `.venv`, `node_modules`, and similar
directories are ignored, while the agent directories above are scanned even
though they are hidden.

## Detection rules

Rules run in one of two exclusive profiles. `core` (default) covers agent
context files. `extended` swaps in the generic rules and widens discovery
to source files (`.py`, `.js`, `.ts`) and dependency files (`requirements*`,
`package.json`, `pyproject.toml`, `setup.py`, `setup.cfg`). Full details in
[docs/rules.md](docs/rules.md); scope audit in [docs/rules-audit.md](docs/rules-audit.md).

| ID | Profile | Files it runs on | Severity | Check |
|---|---|---|---|---|
| HUC001 | core | all context files | high/med/low | invisible or bidirectional Unicode |
| PIN001 | core | JSON descriptions, SKILL.md frontmatter | high | prompt-injection phrases |
| REM001 | core | SKILL.md, skills/ files | high/med | pipe-to-shell, base64 blobs, remote downloads |
| MCP001 | core | MCP JSON configs | high | auto-approve or permission-skipping flags |
| MCP002 | core | MCP JSON configs | medium | filesystem server at a filesystem root |
| MCP003 | core | MCP JSON configs | medium | shell or infrastructure command as the server |
| MCP004 | core | MCP JSON configs | high | sensitive env vars passed to a server |
| UNP001 | core | MCP JSON configs | medium | package-runner package without a version pin |
| TOO001 | core | tool definitions, JSON configs | high/med | tool and function calling injection |
| SEC001 | extended | all scanned files | high/med | embedded credentials (entropy-validated) |
| SHC001 | extended | source files | high/med | shell command execution patterns |
| NET001 | extended | source files | high/med | network exfiltration patterns |
| FSY001 | extended | source files | high/med | path traversal, sensitive files, unsafe archives |
| ENV001 | extended | source files | high/med | environment variable credential access |
| PRI001 | extended | source files | high/med | privilege escalation, container escape, injection |
| OBF001 | extended | source files (non-skill) | high/med/low | encoding, obfuscation, homoglyphs |
| SUP001 | extended | dependency files (non-skill) | high/med/low | supply chain risks |
| CFG001 | extended | structured config files (non-markdown) | high/med | template and configuration injection |
| CRY001 | extended | source files | high/med/low | weak cryptography, insecure randomness |

## Lockfile workflow

`cairnlock.lock` stores SHA-256 hashes of every tracked file.

| Command | Purpose | Exit codes |
|---|---|---|
| `init` | Create lockfile from current state | 0; 1 if it exists (use `--force`) |
| `verify` | Fail on unreviewed changes | 0 clean, 1 changes, 2 usage/environment |
| `diff` | List changes + run rules on modified files | always 0 |
| `approve <file>...` | Update hash (or remove entry for deletions) | 0; 1 for unknown files |

## Protecting cairnlock.lock

Treat `cairnlock.lock` like a dependency lockfile. Add a CODEOWNERS file so
changes to it require review from a designated owner:

```
# .github/CODEOWNERS
/cairnlock.lock @your-org/security-team
```

Combined with `cairnlock verify --base origin/main` in CI, a pull request
cannot silently rewrite which agent files count as approved.

## Output formats

```bash
cairnlock scan                          # text (default)
cairnlock scan --format json            # machine-readable JSON
cairnlock scan --format sarif --output results.sarif   # GitHub Code Scanning
cairnlock scan --format html --output report.html      # self-contained page
cairnlock scan --format md              # markdown for PR comments
cairnlock scan --severity high          # filter findings
```

SARIF output includes rule help URIs pointing at docs/rules.md and partial
fingerprints for result deduplication.

## Noise controls

Large repositories do not need every finding on day one.

**Thresholds.** `scan` exits 1 only when a finding at or above the threshold
exists. The CLI flag wins over the config file:

```bash
cairnlock scan --fail-on medium    # low and medium findings pass
cairnlock scan --fail-on never     # report, never fail
```

**Config file.** `cairnlock.toml` in the scan root, or `[tool.cairnlock]` in
`pyproject.toml`:

```toml
# cairnlock.toml
fail_on = "medium"
disabled_rules = ["CFG001"]
ignore = ["scratch/**", "vendor/**"]
```

`.cairnlockignore` in the scan root holds gitignore-style globs (comments
with `#`, one pattern per line). Patterns match full paths and any leading
directory chain.

**Baseline.** Record today's findings, then fail only on what is new:

```bash
cairnlock scan --write-baseline cairnlock-baseline.json --no-fail
git add cairnlock-baseline.json
# later runs:
cairnlock scan --baseline cairnlock-baseline.json
```

Known findings are suppressed from the report and from the exit decision.
Text output prints the suppressed count; JSON, SARIF, HTML, and Markdown
contain only new findings.

**Inline ignore.** Any line can opt out of specific rules:

```
api_key = "AKIA..." <!-- cairnlock:ignore SEC001 -->
os.system("ls")  # cairnlock:ignore SHC001,NET001
```

`cairnlock:ignore` with no rule ids suppresses every rule for that line;
with ids, only the listed ones. This works in markdown, code, and config
alike because the token is matched anywhere in the line.

**Profiles.** `--profile core` (default) scans agent context files with the
agent-specific rules. `--profile extended` swaps in the generic rules and
adds source and dependency files to discovery, so supply chain and code
rules actually see code. The two profiles never overlap, and every scan
deduplicates findings with the same rule, path, line, and message.

**Banner.** The ASCII banner goes to stderr, so `cairnlock scan --format json`
and the other machine formats always emit clean, parseable output on stdout.

## CI integration

The repository ships a composite action with marketplace metadata. It
verifies the lockfile and writes SARIF:

```yaml
# .github/workflows/cairnlock.yml
name: cairnlock
on:
  push:
    branches: [main]
  pull_request:
permissions:
  security-events: write
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: pennacle-security/cairnlock@v0.5.0
        with:
          base-ref: ${{ github.event.pull_request.base.ref }}
          output: cairnlock.sarif
          fail: "false"
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cairnlock.sarif
```

Action inputs: `path`, `output`, `fail`, `fail-on`, `base-ref`,
`allow-lock-change`. Use `fetch-depth: 0` when you set `base-ref`; a
shallow checkout cannot resolve the base ref.

Pre-commit hook:

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Documentation

The `docs/` directory is a plain HTML site with no build step: a landing
page, a guide (lockfile workflow, base verification, CODEOWNERS, CI), and
the full rule reference. Enable GitHub Pages from the main branch with
`/docs` as the source to publish it. `docs/rules-audit.md` tracks which
rules are agent-specific versus generic SAST. `docs/rules-audit.md` tracks which
rules are agent-specific versus generic SAST.

## Limitations

- Detection is pattern-based; false positives and false negatives occur.
- English-only phrase lists for prompt injection.
- MCP config checks are heuristics (key names, flag strings).
- Secrets rule catches accidental copies; not a full secret scanner.
- Files over 1 MB are skipped.
- No semantic analysis; does not execute or import scanned content.

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
cairnlock scan
```

## Security

Report vulnerabilities through GitHub's private vulnerability reporting on
this repository. See [SECURITY.md](SECURITY.md) for scope.

## License

MIT
