# Rules audit

Step 1 (audit) was reviewed and approved. Step 2 (rule profiles) is now
implemented; the bottom section records what shipped and what changed
compared to the original proposal.

## How to read "actual files"

A rule only ever sees files that pass through two filters:

1. **Discovery** decides which files are collected at all (see the File
   discovery table in the README).
2. **`applies_to`** inside each rule module filters by extension or path.

So the effective scope of every rule is *discovery intersected with
applies_to*. Several rules list code extensions such as `.py` or `.js` in
`applies_to`, but discovery never collects those files today. Those
extensions are currently dead.

## Audit table

| ID | Detects | Actual files (discovery ∩ applies_to) | Overlaps | Class |
|---|---|---|---|---|
| HUC001 | invisible/bidirectional Unicode | every discovered file | none | agent-specific |
| PIN001 | injection phrases in description fields | JSON configs, `SKILL.md` frontmatter | none | agent-specific |
| REM001 | pipe-to-shell, base64 blobs, remote fetches | `SKILL.md`, files under `skills/` | long-base64 pattern duplicates OBF001 | agent-specific |
| MCP001 | auto-approve / permission-skipping flags | discovered JSON configs | none | agent-specific |
| MCP002 | filesystem server at a root path | discovered JSON configs | none | agent-specific |
| MCP003 | unpinned dangerous command | discovered JSON configs | **MCP003 vs UNP001: both fire for the same unpinned npx/uvx/bunx package** | agent-specific |
| MCP004 | sensitive env vars to a server | discovered JSON configs | none | agent-specific |
| UNP001 | unpinned npx/uvx/bunx package | discovered JSON configs | duplicates MCP003 for package runners | agent-specific |
| SEC001 | embedded credentials (entropy-checked) | every discovered file | generic-assignment pattern duplicates CFG001 on config files | generic SAST |
| SHC001 | eval/exec/os.system/subprocess patterns | discovered md/json only; listed code extensions are dead | weak overlap with REM001 in skill files | generic SAST |
| NET001 | exfiltration endpoints, raw sockets, encoded URLs | discovered md/json only; code extensions dead | none | generic SAST |
| FSY001 | traversal, sensitive files, unsafe archives | discovered md/json only; code extensions dead | `../` pattern fires on path examples in prose (false-positive risk) | generic SAST |
| ENV001 | environment credential access | discovered md/json only; code extensions dead | `${VAR}` pattern fires on placeholder examples in prose (false-positive risk, proven during fixture work) | generic SAST |
| PRI001 | privilege escalation, container escape | discovered md/json only; code extensions dead | fires on documentation that mentions these commands (false-positive risk) | generic SAST |
| OBF001 | encoding, obfuscation, homoglyphs | discovered md/json only; code extensions dead | long-base64 pattern duplicates REM001 in skill files; homoglyph ranges fire on non-English prose | generic SAST |
| SUP001 | dependency supply-chain risks | discovered md/json only; requirements.txt/package.json never discovered | `payload`/`malicious` keyword pattern fires on prose (our own CHANGELOG triggered it) | generic SAST |
| CFG001 | template/config injection | discovered md/json and any discovered config | `{{...}}` delimiter pattern fires on ordinary markdown that documents templates; secret-in-config pattern duplicates SEC001 | generic SAST |
| TOO001 | tool/function-calling schema risks | discovered md/json; listed code extensions dead | MCP-config patterns overlap MCP001 conceptually | agent-specific |
| CRY001 | weak crypto, insecure randomness | discovered md/json only; code extensions dead | none | generic SAST |

## Findings

1. **MCP003 vs UNP001 duplicates.** A server with `command: npx` and an
   unpinned package produces two findings for one issue (MCP003 and
   UNP001). Proposed merge: UNP001 keeps npx/uvx/bunx package pins; MCP003
   keeps only non-package dangerous commands (docker, kubectl, curl, wget,
   shells). Rule IDs stay stable.
2. **Generic rules cannot do their job.** SHC001, NET001, FSY001, ENV001,
   PRI001, OBF001, SUP001, and CRY001 were written for source code and
   dependency files, but discovery collects only agent context files. They
   run on markdown and JSON, where their patterns mostly cause false
   positives instead of findings.
3. **False-positive hot spots.** CFG001 (`{{...}}` in markdown), ENV001
   (`${VAR}` placeholders), OBF001 (homoglyph ranges on non-English text),
   SUP001 (security-keyword prose), FSY001 (`../` in path examples).
4. **Fixture rule violations.** The project rules require a bad/good fixture
   pair per rule. The original seven rules have them. SHC001, NET001,
   FSY001, ENV001, PRI001, OBF001, SUP001, CFG001, TOO001, CRY001, MCP003,
   and MCP004 have none.

## Profiles (Step 2, implemented)

- `core` (default): HUC001, PIN001, REM001, MCP001, MCP002, MCP003, MCP004,
  UNP001, TOO001 — agent context files only.
- `extended`: SEC001, SHC001, NET001, FSY001, ENV001, PRI001, OBF001,
  SUP001, CFG001, CRY001 — selected with `--profile extended` or
  `profile = "extended"` in config. Extended also widens discovery to
  source files (`.py`, `.js`, `.ts`) and dependency files (`requirements*`,
  `package.json`, `pyproject.toml`, `setup.py`, `setup.cfg`) so the generic
  rules see the files they were written for.
- Profiles are exclusive: one runs per scan. `SEC001` landed in `extended`
  per classification.
- MCP003/UNP001 merged as proposed: UNP001 owns package runners (now
  including pnpm, yarn, pipx, with `dlx`/`run` subcommand handling);
  MCP003 flags shell and infrastructure commands as the server executable
  regardless of arguments, which removed both the duplicate findings and
  the false positives on subcommands like `docker compose`.

### Accuracy fixes shipped with Step 2

- OBF001 no longer scans skill files (REM001's scope), removing the
  duplicated long-base64 finding.
- CFG001 no longer scans markdown and text files; the hardcoded-secret
  pattern moved out entirely (SEC001 owns credentials), removing template
  prose false positives.
- CRY001 hardcoded-key pattern requires crypto-specific names
  (`secret_key`, `encryption_key`, `private_key`, `iv`, `nonce`, `salt`);
  a plain `key =` no longer duplicates SEC001 on `api_key` lines.
- SUP001 now reads requirements files line by line (bare requirement names
  are flagged), instead of searching for the literal text
  "requirements.txt" inside lines, which never matched real files.
- New suppression mechanism: `cairnlock:ignore` on a line suppresses all
  rules for that line; `cairnlock:ignore RULE1,RULE2` suppresses only the
  listed rules.
- All scans deduplicate findings with identical rule, path, line, and
  message.
