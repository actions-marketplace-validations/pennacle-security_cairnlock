# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Security tab, then "Report a vulnerability"). Do not open a public issue
for something exploitable.

## Scope

cairnlock is an offline static analyzer. It reads files in the target
directory, computes SHA-256 hashes, parses JSON/YAML, and shells out to
local `git` for `verify --base`. In-scope surfaces:

- Git invocation in `src/cairnlock/vcs.py` (argument handling, ref validation)
- Path handling during file discovery
- HTML report escaping (`render_html`)
- Dependency issues in the runtime dependencies (typer, pydantic, pyyaml)

Out of scope: false positives or missed detections in rule patterns.
Open a regular issue for those, with a fixture that reproduces the case.
