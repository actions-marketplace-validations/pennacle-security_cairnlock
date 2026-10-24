# Rule reference

SARIF results link here by rule id anchor. The rendered version lives at
`docs/rules.html`.

| ID | Scope | Severity | Detects |
|---|---|---|---|
| [HUC001](#huc001) | all files | high/medium/low | Invisible and bidirectional Unicode control characters |
| [PIN001](#pin001) | JSON description fields, SKILL.md frontmatter | high | Prompt-injection phrases in tool and skill descriptions |
| [REM001](#rem001) | SKILL.md, files under skills/ | high/medium | Pipe-to-shell downloads, base64 payloads, remote fetches |
| [MCP001](#mcp001) | MCP JSON configs | high | Auto-approve or permission-skipping flags |
| [MCP002](#mcp002) | MCP JSON configs | medium | Filesystem server mounted at a filesystem root |
| [MCP003](#mcp003) | MCP JSON configs | medium | Unpinned dangerous command |
| [MCP004](#mcp004) | MCP JSON configs | high | Sensitive environment variables passed to a server |
| [UNP001](#unp001) | MCP JSON configs | medium | npx, uvx, or bunx packages without a version pin |
| [SEC001](#sec001) | all files | high/medium | Embedded credentials with entropy validation |
| [SHC001](#shc001) | code and config files | high/medium | Shell command execution patterns |
| [NET001](#net001) | code and config files | high/medium | Data exfiltration patterns |
| [FSY001](#fsy001) | code and config files | high/medium | Path traversal, sensitive files, unsafe archives |
| [ENV001](#env001) | code and config files | high/medium | Credential access through environment variables |
| [PRI001](#pri001) | code and config files | high/medium | Privilege escalation and process injection |
| [OBF001](#obf001) | code and config files | high/medium/low | Encoding and obfuscation |
| [SUP001](#sup001) | dependency files | high/medium/low | Supply chain risks |
| [CFG001](#cfg001) | config and template files | high/medium | Template and configuration injection |
| [TOO001](#too001) | tool and function definitions | high/medium | Tool calling injection risks |
| [CRY001](#cry001) | code and config files | high/medium/low | Cryptographic weaknesses |

## HUC001 — hidden Unicode

Zero-width characters and bidirectional controls make rendered text differ
from what a parser or an agent reads. Bidirectional controls score high
because they enable Trojan Source style tricks. A UTF-8 BOM at byte zero is
not flagged.

## PIN001 — prompt injection

Matches injection phrases such as "ignore previous instructions" or "reveal
the system prompt" inside tool and skill description fields only.

## REM001 — remote downloads in skills

curl or wget piped into a shell or interpreter, PowerShell
Invoke-Expression chains, base64 decode into a shell, certutil downloads,
long base64 literals, and remote git or pip sources inside skill files.

## MCP001 — auto-approve flags

`autoApprove: true` and permission-skipping flags such as
`--dangerously-skip-permissions`, `--yolo`, and `--no-auth`.

## MCP002 — filesystem root mounts

A filesystem server given `/`, `~`, or a drive root can read anything the
process can. Repo-relative mounts are fine.

## MCP003 — unpinned dangerous commands

Extends UNP001 beyond package runners to docker, kubectl, helm, curl, wget,
and shells used as MCP server commands without a version pin.

## MCP004 — sensitive env vars

Server definitions that receive environment variables with credential-like
prefixes: cloud keys, database URLs, tokens, certificates.

## UNP001 — unpinned packages

npx, uvx, and bunx run whatever the registry serves today. A pin such as
`pkg@1.2.3` or `pkg==1.2.3` satisfies the rule; `@latest` does not.

## SEC001 — embedded credentials

Provider formats (OpenAI, GitHub, Slack, AWS, Google, Bearer) score high.
Generic assignments require Shannon entropy above 3.5 so placeholders such
as `"changeme"` do not fire.

## SHC001 — shell command execution

String-form eval, exec, and compile, os.system, subprocess calls with shell
metacharacters or string formatting, and deprecated command modules.

## NET001 — exfiltration channels

Cloud metadata addresses, pastebin and webhook endpoints, tunneling
services, raw sockets, DNS resolution, HTTP calls carrying data payloads,
and long encoded fragments in URL paths.

## FSY001 — filesystem access

Traversal sequences, writes and deletes, SSH keys and certificates, env and
secrets files, and archive extraction with zip-slip risk.

## ENV001 — credential access

Iteration, serialization, printing, or logging of the whole environment,
direct reads of cloud and database variables, and shell expansions of long
uppercase variables.

## PRI001 — escalation and injection

Docker and Kubernetes privileged modes, host namespace sharing, docker
socket access, LD_PRELOAD, ptrace attach, Windows registry run keys,
scheduled tasks, and encoded PowerShell.

## OBF001 — obfuscation

Base64 round trips combined with compression, PowerShell encoded commands,
XOR ciphers, long encoded literals, and Cyrillic, Greek, or fullwidth
homoglyphs.

## SUP001 — supply chain

Unpinned installs, wildcard versions, git-sourced dependencies, custom
package indexes, and install-time scripts in package definitions.

## CFG001 — config and template injection

Template delimiters, unsafe YAML python tags, dunder references in config,
connection strings with inline credentials, and hardcoded secrets in config
files.

## TOO001 — tool calling

Tools named shell, exec, or similar; descriptions that advertise arbitrary
execution; autonomous agent frameworks; disabled strict mode.

## CRY001 — cryptography

MD5 and SHA1, DES and RC4, AES-ECB, RSA keys at 1024 bits or below, the
random module for security purposes, disabled certificate verification, and
hardcoded keys or IVs.
