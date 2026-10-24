# Changelog

All notable changes to cairnlock are documented in this file.

The format is based on Keep a Changelog 1.1.0, and the project follows
Semantic Versioning 2.0.0.

## [Unreleased]

## [0.1.0] - 2026-10-24

### Added

- `cairnlock scan` with seven static detection rules:
  - HUC001: invisible and bidirectional Unicode control characters in instruction files
  - PIN001: prompt-injection phrases in tool and skill descriptions
  - REM001: pipe-to-shell downloads, base64 payloads, and remote fetches in skill files
  - MCP001: auto-approve or permission-skipping flags in MCP server configs
  - MCP002: MCP filesystem servers mounted at a filesystem root
  - UNP001: npx and uvx packages without a version pin
  - SEC001: embedded credentials in agent context files
- Lockfile commands: `init`, `verify`, `diff`, `approve`
- Output formats: text, JSON, SARIF 2.1.0
- Composite GitHub Action (`action.yml`) for CI and Code Scanning upload
- Example pre-commit hook in `hooks/`
- CI workflow running ruff and pytest on Python 3.11 and 3.13

[Unreleased]: https://github.com/pennacle-security/cairnlock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pennacle-security/cairnlock/releases/tag/v0.1.0
