"""Iconic ASCII art for cairnlock CLI."""

from __future__ import annotations

ASCII_LOGO = r"""
    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    █  ▄▀█ █▄ █ █▀▄ █░█ █▀▀ █▀█ █░█ █▀▀ ▀█▀ ▄▀█ █▀▄▀█ ▄▀█ █▄ █ ▀░
    █  █▀█ █ ▀█ █▄▀ █▄█ █▄▄ █▀▄ █▄█ ██▄ ░█░ █▀█ █░▀░█ █▀█ █ ▀█ █░
    █▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
"""

ASCII_LOGO_SMALL = r"""
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █ ▄▀█ █▄ █ █▀▄
   █ █▀█ █ ▀█ █▄▀
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""

ASCII_CAIRN = r"""
         ▄▄▄▄▄▄▄▄▄▄▄▄
        █ ▄▀█ █▄ █ █▀▄
       █ █▀█ █ ▀█ █▄▀
      █▀▀▀▀▀▀▀▀▀▀▀▀▀
        ▄▄▄▄▄▄▄▄▄▄▄
       █ ▄▀█ █▄ █ █▀▄
      █ █▀█ █ ▀█ █▄▀
     ▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""

ASCII_LOCK = r"""
    ▄▄▄▄▄▄▄
   █ ▄▄▄ █
   █ ███ █
   █ ▀▀▀ █
   ▀▀▀▀▀▀▀
"""

BANNER = f"""{ASCII_LOGO}
    cairnlock — Static analyzer & lockfile for AI-agent context files
    Version: {{version}} | pennacle-security/cairnlock
    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""

BANNER_COMPACT = f"""{ASCII_LOGO_SMALL}
  cairnlock v{{version}} — Static analyzer & lockfile for AI-agent contexts
  pennacle-security/cairnlock
"""

def get_banner(version: str, compact: bool = False) -> str:
    """Get banner with version."""
    if compact:
        return BANNER_COMPACT.format(version=version)
    return BANNER.format(version=version)


def get_cairn_lock_art() -> str:
    """Get combined cairn + lock art."""
    return f"""{ASCII_CAIRN}
{ASCII_LOCK}
"""
