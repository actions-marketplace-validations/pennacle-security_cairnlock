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
network requests.

## Install

Python 3.11 or newer.

```bash
pipx install git+https://github.com/pennacle-security/cairnlock.git@v0.2.0
```

Or with pip:

```bash
pip install git+https://github.com/pennacle-security/cairnlock.git@v0.2.0
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
```

Example scan output:

```
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  █  ▄▀█ █▄ █ █▀▄ █░█ █▀▀ █▀█ █░█ █▀▀ ▀█▀ ▄▀█ █▀▄▀█ ▄▀█ █▄ █ ▀░
  █  █▀█ █ ▀█ █▄▀ █▄█ █▄▄ █▀▄ █▄█ ██▄ ░█░ █▀█ █░▀░█ █▀█ █ ▀█ █░
  █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  cairnlock v0.2.0 — Static analyzer & lockfile for AI-agent contexts
  pennacle-security/cairnlock

SKILL.md:9: [REM001] curl piped into a shell (high)
SKILL.md:13: [REM001] long base64 blob (possible encoded payload) (high)
SKILL.md:16: [REM001] git clone from a remote URL (medium)

3 findings in 1 files
```

## File discovery

cairnlock scans these files (anywhere in the repo):

| Pattern | Description |
|---|---|
| `AGENTS.md` / `CLAUDE.md` | Root agent instructions |
| `.cursorrules` | Cursor rules file |
| `opencode.json` | opencode configuration |
| `.mcp.json` / `mcp.json` | MCP server configurations |
| `.cursor/rules/**/*.md` | Cursor rule files |
| `.opencode/**/*.md` `.opencode/**/*.json` | opencode agents/plugins |
| `.claude/**/*.md` `.claude/**/*.json` | Claude Code settings/skills |
| `skills/**/*.md` `**/SKILL.md` | Skill definitions |

Files over 1 MB are skipped. Hidden directories (`.git`, `.venv`, `node_modules`, etc.) are ignored.

## Detection rules

| ID | Name | Scope | Severity | Description |
|---|---|---|---|---|
| HUC001 | hidden-unicode | all files | high/med/low | Invisible/bidirectional Unicode control characters (Trojan Source) |
| PIN001 | prompt-injection | JSON `description` fields, SKILL.md frontmatter | high | Prompt-injection phrases in tool/skill descriptions |
| REM001 | remote-download | SKILL.md, files under `skills/` | high/med | Pipe-to-shell, base64 payloads, remote fetches |
| MCP001 | mcp-auto-approve | MCP JSON configs | high | Auto-approve or permission-skipping flags |
| MCP002 | mcp-fs-root | MCP JSON configs | medium | Filesystem server mounted at root path |
| MCP003 | mcp-unpinned-cmd | MCP JSON configs | medium | Unpinned dangerous command (npx, uvx, docker, etc.) |
| MCP004 | mcp-sensitive-env | MCP JSON configs | high | Sensitive environment variable passed to server |
| UNP001 | unpinned-exec | MCP JSON configs | medium | npx/uvx/bunx packages without version pin |
| SEC001 | embedded-secrets | all files | high/med | Embedded API keys, tokens, passwords |
| SHC001 | shell-commands | code and config files | high/med | Shell command execution (eval, exec, subprocess) |
| NET001 | network-exfil | code and config files | high/med | Suspicious network/exfiltration patterns |
| FSY001 | filesystem-access | code and config files | high/med | Path traversal, sensitive files, archive extraction |
| ENV001 | env-manipulation | code and config files | high/med | Environment variable manipulation, credential access |
| PRI001 | privilege-escalation | code and config files | high/med | Privilege escalation, process injection, container escape |
| OBF001 | obfuscation | code and config files | high/med/low | Encoding, obfuscation, homoglyphs, compression+encoding |
| SUP001 | supply-chain | dependency files | high/med/low | Dependency confusion, unpinned deps, post-install scripts |
| CFG001 | config-injection | config and template files | high/med | Template injection, YAML unsafe tags, hardcoded secrets |
| TOO001 | tool-injection | tool/function definitions | high/med | Injection risks in tool/function calling schemas |
| CRY001 | crypto-weakness | code and config files | high/med/low | Weak hashes, ciphers, randomness, hardcoded keys |

Severity mapping: `high` = bidirectional controls, auto-approve, known secret formats, RCE patterns; `medium` = zero-width chars, unpinned packages, generic credentials, supply chain risks; `low` = soft hyphen, good practices.

## Lockfile workflow

`cairnlock.lock` stores SHA-256 hashes of every tracked file.

| Command | Purpose | Exit code |
|---|---|---|
| `init` | Create lockfile from current state | 0 on success, 1 if exists (use `--force`) |
| `verify` | Fail if any tracked file changed/added/deleted | 0 if clean, 1 if changes |
| `diff` | List changes + run rules on modified files | Always 0 |
| `approve <file>...` | Update hash (or remove entry for deletions) | 0 on success, 1 if unknown |

Typical CI pipeline:

```bash
# On first run / new repo
cairnlock init
git add cairnlock.lock
git commit -m "chore: add cairnlock lockfile"

# On every push/PR
cairnlock verify || exit 1
```

## Output formats

```bash
# Human-readable (default)
cairnlock scan

# Machine-readable JSON
cairnlock scan --format json

# SARIF 2.1.0 for GitHub Code Scanning
cairnlock scan --format sarif --output results.sarif

# HTML report for sharing
cairnlock scan --format html --output report.html

# Markdown for PR comments
cairnlock scan --format markdown
```

SARIF output includes rule metadata, help URIs, and partial fingerprints for deduplication.

## New CLI commands (v0.2.0)

```bash
# List all detection rules with metadata
cairnlock rules --verbose

# Show repository statistics
cairnlock stats
```

## CI integration

GitHub Action (composite) for SARIF upload to Code Scanning:

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
      - uses: pennacle-security/cairnlock@v0.2.0
        with:
          output: cairnlock.sarif
          fail: "false"
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cairnlock.sarif
```

Pre-commit hook (blocks commits with unreviewed changes):

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## MCP integration

cairnlock includes dedicated MCP security rules (MCP001-004):

- Validates `autoApprove` and permission-skipping flags
- Detects filesystem servers mounted at root paths
- Flags unpinned dangerous commands (npx, uvx, docker, kubectl, etc.)
- Detects sensitive environment variables passed to MCP servers

Run `cairnlock scan` on your `.mcp.json` or `opencode.json` to audit MCP configurations.

## Limitations

- Detection is pattern-based; false positives and false negatives occur.
- English-only phrase lists for prompt injection.
- MCP config checks are heuristics (key names, flag strings).
- Secrets rule catches accidental copies; not a full secret scanner.
- Files over 1 MB are skipped.
- No semantic analysis; does not execute or import scanned content.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest -q

# Lint
ruff check .

# Run locally
cairnlock scan
```

## License

MIT