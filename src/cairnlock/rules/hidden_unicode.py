"""Hidden Unicode / bidirectional control characters in instruction files.

Rule ID: HUC001
Detects invisible and bidirectional Unicode control characters that can hide
malicious content from reviewers (Trojan Source class).
"""

from __future__ import annotations

from cairnlock.models import Finding

RULE_ID = "HUC001"

RULE_IDS = ("HUC001",)

# display name -> (character, severity)
# Bidirectional controls are high (Trojan Source); zero-widths are medium/low.
_CHARS: dict[str, tuple[str, str]] = {
    "zero-width space": ("\u200b", "medium"),
    "zero-width non-joiner": ("\u200c", "medium"),
    "zero-width joiner": ("\u200d", "medium"),
    "word joiner": ("\u2060", "medium"),
    "soft hyphen": ("\u00ad", "low"),
    "zero-width no-break space": ("\ufeff", "medium"),
    "left-to-right embedding": ("\u202a", "high"),
    "right-to-left embedding": ("\u202b", "high"),
    "pop directional formatting": ("\u202c", "high"),
    "left-to-right override": ("\u202d", "high"),
    "right-to-left override": ("\u202e", "high"),
    "left-to-right isolate": ("\u2066", "high"),
    "right-to-left isolate": ("\u2067", "high"),
    "first strong isolate": ("\u2068", "high"),
    "pop directional isolate": ("\u2069", "high"),
    "arabic letter mark": ("\u061c", "high"),
}


def applies_to(rel_path: str) -> bool:
    return True


def check(rel_path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    # Skip BOM at position 0 (legitimate UTF-8 BOM)
    start = 1 if text.startswith("\ufeff") else 0
    for name, (char, severity) in _CHARS.items():
        seen_lines: set[int] = set()
        idx = text.find(char, start)
        while idx != -1:
            line = text.count("\n", 0, idx) + 1
            if line not in seen_lines:
                seen_lines.add(line)
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity=severity,
                        path=rel_path,
                        line=line,
                        message=f"{name} (U+{ord(char):04X})",
                    )
                )
            idx = text.find(char, idx + 1)
    return findings
