# Cairnlock — agent instructions

## Project
Cairnlock is an open-source CLI by Pennacle Security. It statically audits
AI-agent context files in a repository (AGENTS.md, CLAUDE.md, .cursorrules,
opencode.json, MCP configs, skill folders) and maintains a lockfile
(cairnlock.lock) so unreviewed changes fail CI.

## Hard rules
- Static analysis only. Never execute, import, or install scanned content.
- Offline by default. No network calls unless a flag explicitly enables them.
- Never invent CVE IDs, URLs, benchmarks, or statistics. If unsure, leave it out.
- Every detection rule ships with a "bad" fixture (must trigger) and a
  "good" fixture (must not trigger). No fixture, no merge.
- Work on one module per session. Write the test first, then the code.
- Python 3.11+, typer, pydantic, pyyaml, pytest, ruff. Keep dependencies minimal.
- Output formats: text, JSON, SARIF 2.1.0.

## Writing style (code, comments, README, commits, issues)
- Plain, specific language. Say what the thing does and what it does not do.
- No marketing words (seamless, robust, powerful, cutting-edge, comprehensive).
- No emoji in code, commits, or docs. No decorative headers or banner comments.
- Comments explain why, not what. Skip comments that restate the code.
- Commit messages: imperative, under 72 chars, e.g. "add hidden-unicode rule".
- README: problem, install, one real example with real output, limitations.
  State limitations honestly, including false-positive risk.
- Vary sentence length. Prefer short sentences. Avoid lists of three adjectives.
- Do not end docs with summaries or "in conclusion" paragraphs.

## Layout
- `src/cairnlock/cli.py` — typer CLI and exit codes
- `src/cairnlock/scanner.py` — file discovery and scan loop
- `src/cairnlock/rules/` — one module per detection rule
- `src/cairnlock/lockfile.py` — cairnlock.lock read/write and change detection
- `src/cairnlock/output.py` — text, JSON, and SARIF renderers
- `tests/fixtures/<rule>/bad|good/` — one fixture pair per rule