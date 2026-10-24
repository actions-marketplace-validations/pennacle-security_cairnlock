"""Pydantic models for findings and scan results."""

from __future__ import annotations

from pydantic import BaseModel


class Finding(BaseModel):
    """A single rule finding."""

    rule_id: str
    severity: str  # low | medium | high
    path: str      # repo-relative, forward slashes
    line: int      # 1-based; 0 when unknown
    col: int = 0
    message: str
