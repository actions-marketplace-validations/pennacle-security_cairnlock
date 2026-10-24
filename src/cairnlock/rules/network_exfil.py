"""Suspicious network and data exfiltration patterns.

Rule ID: NET001
Detects network calls that could exfiltrate data.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "NET001"

_PATTERNS = [
    # HTTP exfiltration
    (r"\brequests\.(get|post|put|patch|delete)\s*\([^)]*(?:data|json|files)\s*=", "HTTP request with data payload - potential exfiltration", "high"),
    (r"\burllib\.(request|parse)\.", "urllib usage - verify no data exfiltration", "medium"),
    (r"\bhttpx\.(get|post|put|patch|delete)\s*\(", "httpx request - verify destination", "medium"),
    (r"\baiohttp\.", "aiohttp usage - verify no data exfiltration", "medium"),

    # DNS exfiltration
    (r"\bdns\.(query|resolver)\.", "DNS query - potential DNS exfiltration", "high"),
    (r"\bsocket\.(gethostbyname|getaddrinfo)\s*\(", "DNS resolution - potential exfiltration", "medium"),

    # Raw sockets
    (r"\bsocket\.socket\s*\(", "Raw socket creation - verify purpose", "high"),
    (r"\bAF_INET\b|\bSOCK_RAW\b", "Raw socket constants - potential low-level network access", "high"),

    # WebSocket exfiltration
    (r"\bwebsockets?\.(connect|serve)\s*\(", "WebSocket connection - potential exfiltration channel", "medium"),

    # Cloud metadata services
    (r"169\.254\.169\.254", "Cloud metadata service access - potential credential theft", "high"),
    (r"metadata\.google\.internal", "GCP metadata service access", "high"),
    (r"metadata\.azure\.com", "Azure metadata service access", "high"),

    # Common exfiltration destinations
    (r"(?:pastebin|ghostbin|hastebin|rentry|gist)\.(com|co)", "Pastebin-like service - potential exfiltration", "high"),
    (r"(?:webhook|requestbin|hook)\.(site|io|com)", "Webhook testing service - potential exfiltration", "high"),
    (r"(?:ngrok|localtunnel|serveo)\.(io|com)", "Tunneling service - potential exfiltration", "medium"),

    # Base64 encoded data in URLs
    (r"https?://[^/\s]*/[A-Za-z0-9+/]{100,}={0,2}", "Long base64 in URL path - potential encoded exfiltration", "high"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith((".py", ".js", ".ts", ".go", ".rs", ".java", ".kt", ".sh", ".bash", ".ps1", ".md", ".txt", ".json", ".yaml", ".yml"))


def check(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for pat, message, severity in _COMPILED:
            if pat.search(line):
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity=severity,
                        path=rel_path,
                        line=lineno,
                        message=message,
                    )
                )
                break
    return findings
