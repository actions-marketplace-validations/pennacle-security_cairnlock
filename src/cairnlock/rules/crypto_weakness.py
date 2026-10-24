"""Cryptographic weaknesses and insecure randomness.

Rule ID: CRY001
Detects weak cryptography and insecure randomness patterns.
"""

from __future__ import annotations

import re

from cairnlock.models import Finding

RULE_ID = "CRY001"

_PATTERNS = [
    # Weak hashes
    (r"\bhashlib\.(md5|sha1)\s*\(", "Weak hash algorithm (MD5/SHA1)", "high"),
    (r"\bhashlib\.new\s*\(\s*[\"'](md5|sha1)[\"']", "Weak hash via new()", "high"),
    (r"\bCrypto\.Hash\.(MD5|SHA1)\b", "PyCrypto weak hash", "high"),

    # Weak ciphers
    (r"\bCrypto\.Cipher\.(DES|ARC4|RC2|RC4|Blowfish)\b", "Weak cipher algorithm", "high"),
    (r"\bDES\.new\b|\bARC4\.new\b", "Weak cipher instantiation", "high"),
    (r"\bAES\.new\s*\([^)]*MODE_ECB\b", "AES-ECB mode - insecure", "high"),

    # Insecure randomness
    (r"\brandom\.(random|randint|choice|uniform|randrange)\s*\(", "random module - not cryptographically secure", "medium"),
    (r"\bnumpy\.random\.", "numpy.random - not cryptographically secure", "medium"),
    (r"\bsecrets\.", "secrets module - good practice", "low"),
    (r"\bos\.urandom\s*\(", "os.urandom - cryptographically secure", "low"),

    # Hardcoded keys/IVs
    (r"(?:key|iv|nonce|salt)\s*[:=]\s*[\"'][A-Za-z0-9+/=]{16,}[\"']", "Hardcoded crypto key/IV", "high"),
    (r"[\"'][A-Za-z0-9+/=]{32,}[\"']\s*.*(?:aes|encrypt|decrypt)", "Potential hardcoded AES key", "high"),

    # RSA weak key sizes
    (r"RSA\.generate\s*\(\s*(?:512|1024)\s*\)", "RSA key size <= 1024 bits - weak", "high"),
    (r"\bDSA\b|\bECDSA\b.*(?:192|224|256)", "DSA/ECDSA with weak curves", "medium"),

    # Insecure protocols
    (r"\bssl\.(PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1|PROTOCOL_TLSv1_1)\b", "Insecure SSL/TLS protocol version", "high"),
    (r"\bssl\.CERT_NONE\b", "Certificate verification disabled", "high"),
    (r"verify\s*=\s*False", "SSL verification disabled", "high"),
    (r"check_hostname\s*=\s*False", "Hostname verification disabled", "high"),

    # Password hashing
    (r"\bbcrypt\.", "bcrypt - good practice", "low"),
    (r"\bscrypt\.", "scrypt - good practice", "low"),
    (r"\bargon2\.", "argon2 - good practice", "low"),
    (r"\bpbkdf2_hmac\s*\(", "PBKDF2 - acceptable with high iterations", "low"),
    (r"hashlib\.pbkdf2_hmac\s*\(", "PBKDF2 via hashlib - acceptable", "low"),
]

_COMPILED = [(re.compile(rx, re.IGNORECASE), msg, sev) for rx, msg, sev in _PATTERNS]


def applies_to(rel_path: str) -> bool:
    return rel_path.endswith((".py", ".js", ".ts", ".go", ".rs", ".java", ".kt", ".md", ".txt", ".json", ".yaml", ".yml"))


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
