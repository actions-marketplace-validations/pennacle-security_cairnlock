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
pipx install git+https://github.com/pennacle-security/cairnlock.git@v0.1.0
```

Or with pip:

```bash
pip install git+https://github.com/pennacle-security/cairnlock.git@v0.1.0
```

## Quick start

```bash
# Initialize lockfile (commits current hashes)
cairnlock init

# Scan for risks
cairnlock scan

# Verify no unreviewed changes
cairnlock verify

# Show changes with findings
cairnlock diff

# Approve a changed file
cairnlock approve AGENTS.md
```

Example scan output:

```
SKILL.md:9: [REM001] curl piped into a shell (high)
SKILL.md:13: [REM001] long base64 blob (possible encoded payload) (high)
SKILL.md:16: [REM001] git clone from a remote URL (medium)

3 findings in 1 files
```

## Rules

| ID | Check | Severity |
|---|---|---|
| HUC001 | invisible or bidirectional Unicode in instruction files | high (bidi) / medium |
| PIN001 | prompt-injection phrases in tool/skill descriptions | high |
| REM001 | pipe-to-shell, base64 blobs, remote downloads in skill files | high / medium |
| MCP001 | auto-approve or permission-skipping flags in MCP configs | high |
| MCP002 | filesystem server mounted at a filesystem root | medium |
| UNP001 | unpinned npx/uvx package | medium |
| SEC001 | embedded credentials | high / medium |

## Lockfile

- `cairnlock.init` records SHA-256 of every tracked file in `cairnlock.lock`.
- `cairnlock.verify` exits 1 if any tracked file changed, was added, or deleted.
- `cairnlock.diff` lists changes and runs rules on modified/added files.
- `cairnlock.approve <file>` updates the hash (or removes entry for deletions).

## CI

GitHub Action (composite) for SARIF upload to Code Scanning:

```yaml
- uses: pennacle-security/cairnlock@v0.1.0
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

## Limitations

- Detection is pattern-based; false positives and false negatives occur.
- English-only phrase lists for prompt injection.
- MCP config checks are heuristics (key names, flag strings).
- Secrets rule catches accidental copies; not a full secret scanner.
- Files over 1 MB are skipped.
- No semantic analysis; does not execute or import scanned content.

## License

MIT
