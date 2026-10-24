"""Process injection and privilege escalation patterns.

Rule ID: PRI001
Detects patterns that could lead to privilege escalation or process injection.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "PRI001"

RULE_IDS = ("PRI001",)

_PATTERNS = [
    # Linux privilege escalation
    (r"\bsudo\s+(?:-u|-g)\s+\w+", "sudo with user/group - verify necessity", "medium"),
    (r"\bsudo\s+(?:-n|--non-interactive)", "sudo non-interactive - potential automation abuse", "medium"),
    (r"\bsu\s+(?:-|-l|--login)\s+\w+", "su to another user - verify necessity", "medium"),
    (r"\bdoas\s+", "doas usage - verify configuration", "medium"),
    (r"\bpolkit\s+", "polkit usage - verify policy", "medium"),

    # Capability manipulation
    (r"\bsetcap\s+", "setcap - capability manipulation", "high"),
    (r"\bgetcap\s+", "getcap - capability inspection", "low"),
    (r"\bcapsh\s+", "capsh - capability shell", "high"),

    # Container escape patterns
    (r"\bdocker\s+(?:run|exec)\s+.*--privileged", "Docker privileged container - escape risk", "high"),
    (r"\bpodman\s+(?:run|exec)\s+.*--privileged", "Podman privileged container - escape risk", "high"),
    (r"\bkubectl\s+(?:exec|run)\s+.*--privileged", "Kubernetes privileged pod - escape risk", "high"),
    (r"hostPID:\s*true|hostNetwork:\s*true|hostIPC:\s*true", "Kubernetes host namespace sharing - escape risk", "high"),
    (r"\.docker\.sock", "Docker socket access - container escape risk", "high"),

    # Windows privilege escalation
    (r"\brunas\s+/user:", "runas - user impersonation", "medium"),
    (r"\bschtasks\s+/create", "Scheduled task creation - persistence risk", "high"),
    (r"\bsc\s+create", "Windows service creation - persistence risk", "high"),
    (r"\breg\s+add\s+.*Run", "Registry Run key - persistence risk", "high"),
    (r"\bwmic\s+process\s+call\s+create", "WMI process creation - lateral movement", "high"),
    (r"\bpowershell\s+-enc\s+", "PowerShell encoded command - obfuscation", "high"),
    (r"\bInvoke-Expression\s+\(|\biex\s+\(", "PowerShell Invoke-Expression - code execution", "high"),

    # LD_PRELOAD / DYLD_INSERT_LIBRARIES
    (r"LD_PRELOAD\s*=", "LD_PRELOAD - library injection", "high"),
    (r"DYLD_INSERT_LIBRARIES\s*=", "DYLD_INSERT_LIBRARIES - macOS library injection", "high"),

    # Process injection
    (r"\bptrace\s*\(\s*PTRACE_ATTACH", "ptrace attach - process injection", "high"),
    (r"\bCreateRemoteThread\s*\(", "CreateRemoteThread - Windows process injection", "high"),
    (r"\bVirtualAllocEx\s*\(|\bWriteProcessMemory\s*\(", "Windows memory manipulation - injection", "high"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith((".py", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".yaml", ".yml", ".json", ".md", ".txt"))


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
