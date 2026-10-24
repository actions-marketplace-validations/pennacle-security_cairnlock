# Changelog

All notable changes to cairnlock are documented in this file.

The format is based on Keep a Changelog 1.1.0, and the project follows
Semantic Versioning 2.0.0.

## [Unreleased]

## [0.2.0] - 2026-10-24

### Added
- `cairnlock scan` with 18 static detection rules:
  - HUC001: invisible and bidirectional Unicode control characters in instruction files
  - PIN001: prompt-injection phrases in tool and skill descriptions
  - REM001: pipe-to-shell downloads, base64 payloads, and remote fetches in skill files
  - MCP001: auto-approve or permission-skipping flags in MCP server configs
  - MCP002: MCP filesystem servers mounted at a filesystem root
  - MCP003: MCP server with unpinned dangerous command
  - MCP004: MCP server passed sensitive environment variable
  - UNP001: npx and uvx packages without a version pin
  - SEC001: embedded credentials in agent context files
  - SHC001: shell command execution patterns (eval, exec, subprocess, os.system)
  - NET001: suspicious network or data exfiltration patterns
  - FSY001: suspicious file system access (path traversal, sensitive files, archives)
  - ENV001: environment variable manipulation and credential access
  - PRI001: privilege escalation and process injection patterns
  - OBF001: encoding, obfuscation, and data hiding patterns
  - SUP001: supply chain attack risks in dependencies
  - CFG001: configuration and template injection vulnerabilities
  - TOO001: tool and function calling injection risks
  - CRY001: cryptographic weaknesses and insecure randomness
- Lockfile commands: `init`, `verify`, `diff`, `approve`
- Output formats: text, JSON, SARIF 2.1.0, HTML, Markdown
- New CLI commands: `rules` (list all rules), `stats` (repository statistics)
- Enhanced CLI UX: ASCII banner, colored output, progress bars, verbose mode
- Composite GitHub Action (`action.yml`) for CI and Code Scanning upload
- Example pre-commit hook in `hooks/`
- CI workflow running ruff and pytest on Python 3.11 and 3.13

### Changed
- Enhanced SARIF output with rule help URIs and partial fingerprints
- Improved embedded secret detection with Shannon entropy validation
- Expanded MCP config analysis with 4 rule IDs
- Refined supply chain detection for dependency confusion risks

### Fixed
- Secret detection false positives on placeholder values
- Cross-rule false positives in good fixtures

[Unreleased]: https://github.com/pennacle-security/cairnlock/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/pennacle-security/cairnlock/releases/tag/v0.2.0