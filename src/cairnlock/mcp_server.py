"""Minimal MCP stdio server exposing cairnlock as agent-callable tools.

Speaks newline-delimited JSON-RPC 2.0 per the Model Context Protocol:
initialize, notifications/initialized, tools/list, tools/call, ping. Tool
handlers reuse the same building blocks as the CLI (scanner, lockfile,
config) but never print the banner or progress: stdout carries protocol
messages only.

Run with `cairnlock mcp` or `python -m cairnlock.mcp_server`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cairnlock import __version__, lockfile, vcs
from cairnlock.config import ConfigError, load_config
from cairnlock.output import render_text
from cairnlock.rules import PROFILE_NAMES, PROFILE_RULES, RULE_META, RULES, rule_ids
from cairnlock.scanner import discover_files, scan

PROTOCOL_VERSION = "2024-11-05"

MAX_FILE_SIZE = 1_000_000


def _tool_scan(args: dict) -> str:
    path = Path(args.get("path", "."))
    if not path.is_dir():
        raise ValueError(f"not a directory: {path}")
    try:
        config = load_config(path)
        profile = args.get("profile")
        if profile is not None:
            if profile not in PROFILE_NAMES:
                raise ValueError(f"profile must be one of: {', '.join(PROFILE_NAMES)}")
            config.profile = profile
    except ConfigError as exc:
        raise ValueError(str(exc)) from exc
    include_ancestors = bool(args.get("include_ancestors", False))
    return render_text(scan(path, config, include_ancestors=include_ancestors))


def _tool_verify(args: dict) -> str:
    root = Path(args.get("path", "."))
    base = args.get("base")

    if base is not None:
        base_text = vcs.read_file_at(root, base, lockfile.LOCKFILE_NAME)
        if base_text is None:
            return f"error: no {lockfile.LOCKFILE_NAME} at ref '{base}'"
        base_lock = lockfile.loads(base_text)
        if base_lock is None:
            return f"error: {lockfile.LOCKFILE_NAME} at ref '{base}' is not valid"
        current = lockfile.hashes(root)
        base_files = base_lock["files"]
        lines = []
        for rel in sorted(p for p in current if p in base_files and current[p] != base_files[p]):
            lines.append(f"modified: {rel}")
        for rel in sorted(p for p in current if p not in base_files):
            lines.append(f"added: {rel}")
        for rel in sorted(p for p in base_files if p not in current):
            lines.append(f"deleted: {rel}")
        working = lockfile.load(root)
        if working is None or (working.get("version"), working.get("files")) != (
            base_lock.get("version"),
            base_lock.get("files"),
        ):
            lines.insert(0, "lockfile modified in this change")
        if not lines:
            return f"ok: no changes vs base '{base}'"
        return "\n".join(lines) + f"\nverify failed: {len(lines)} findings vs base '{base}'"

    lock = lockfile.load(root)
    if lock is None:
        return f"error: no {lockfile.LOCKFILE_NAME}; run cairnlock init first"
    changes = lockfile.changes(root, lock)
    if not any(changes.values()):
        return f"ok: {len(lock.get('files', {}))} files unchanged"
    lines = []
    for kind in ("modified", "added", "deleted"):
        for rel in changes[kind]:
            lines.append(f"{kind}: {rel}")
    total = sum(len(v) for v in changes.values())
    return "\n".join(lines) + f"\nverify failed: {total} changed files"


def _tool_rules(_args: dict) -> str:
    profile_of: dict[str, str] = {}
    for name, ids in PROFILE_RULES.items():
        for rid in ids:
            profile_of[rid] = name
    lines = []
    for rule in RULES:
        for rid in sorted(rule_ids(rule)):
            lines.append(f"{rid} [{profile_of.get(rid, '?')}] {RULE_META.get(rid, rid)}")
    return "\n".join(lines)


def _tool_stats(args: dict) -> str:
    root = Path(args.get("path", "."))
    files = discover_files(root)
    if not files:
        return "no agent context files found"
    total_size = sum(p.stat().st_size for p in files)
    lines = [f"files: {len(files)}", f"total size: {total_size:,} bytes"]
    return "\n".join(lines)


TOOL_HANDLERS = {
    "scan": _tool_scan,
    "verify": _tool_verify,
    "rules": _tool_rules,
    "stats": _tool_stats,
}

TOOLS_SPEC = [
    {
        "name": "scan",
        "description": (
            "Scan agent context files (AGENTS.md, CLAUDE.md, MCP configs, "
            "skills) for risk patterns and return the findings report."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory to scan (default .)"},
                "profile": {
                    "type": "string",
                    "enum": ["core", "extended"],
                    "description": "Rule set to run (default from config, else core)",
                },
                "include_ancestors": {
                    "type": "boolean",
                    "description": "Also scan context files in parent directories — agents read AGENTS.md up the tree",
                },
            },
        },
    },
    {
        "name": "verify",
        "description": (
            "Check the cairnlock.lock lockfile: pass with no unreviewed "
            "changes, or report modified/added/deleted files. With 'base', "
            "compares against the lockfile at that git ref and reports "
            "lockfile tampering."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repository root (default .)"},
                "base": {"type": "string", "description": "Git ref to compare against"},
            },
        },
    },
    {
        "name": "rules",
        "description": "List all detection rules with their profile and description.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "stats",
        "description": "Show repository statistics for tracked agent context files.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Repository root (default .)"}},
        },
    },
]


def _dispatch(method: str, params: dict) -> tuple[dict | None, dict | None]:
    """Return (result, error); exactly one is non-None."""
    if method == "initialize":
        return (
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "cairnlock", "version": __version__},
            },
            None,
        )
    if method == "ping":
        return {}, None
    if method == "tools/list":
        return {"tools": TOOLS_SPEC}, None
    if method == "tools/call":
        name = params.get("name", "")
        handler = TOOL_HANDLERS.get(name)
        if handler is None:
            return None, {"code": -32602, "message": f"unknown tool: {name}"}
        try:
            text = handler(params.get("arguments") or {})
        except Exception as exc:  # noqa: BLE001 - tools must not crash the server
            return {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True}, None
        return {"content": [{"type": "text", "text": text}]}, None
    return None, {"code": -32601, "message": f"method not found: {method}"}


def serve() -> None:
    """Read JSON-RPC messages from stdin, write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            _write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        if not isinstance(message, dict) or "method" not in message:
            continue
        method = message["method"]
        message_id = message.get("id")
        if message_id is None:
            # Notification (e.g. notifications/initialized): no response.
            continue
        params = message.get("params") or {}
        if not isinstance(params, dict):
            params = {}
        result, error = _dispatch(method, params)
        if error is not None:
            _write({"jsonrpc": "2.0", "id": message_id, "error": error})
        else:
            _write({"jsonrpc": "2.0", "id": message_id, "result": result})


def _write(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    serve()
