"""ASCII art for the cairnlock CLI banner.

Letters use the standard 5-row block font so CAIRNLOCK reads unambiguously.
CAIRN sits on top of LOCK the way stones stack on a cairn.
"""

from __future__ import annotations

ASCII_LOGO = r"""
     ██████  █████  ██ ██████  ██   ██
    ██▄▄▄▄  ██   ██ ██ ██  ██  ███  ██
    ██▀▀▀▀  ███████ ██ ██████  ████ ██
    ██▄▄▄▄  ██   ██ ██ ██  ██  ██ ████
     ▀▀▀▀▀  ██   ██ ██ ██  ██  ██   ██
      ██      █████  ██████  ██   ██
      ██      ██   ██ ██▄▄▄▄  ██  ██
      ██      ██   ██ ██▀▀▀▀  █████
      ██      ██   ██ ██▄▄▄▄  ██  ██
      ███████  █████   ▀▀▀▀▀  ██   ██
"""

ASCII_MARK = r"""
   /\
  /  \   cairnlock v{version}
 /_/\_\  static analyzer and lockfile for AI-agent context files
"""

BANNER = f"""{ASCII_LOGO}
    cairnlock — static analyzer and lockfile for AI-agent context files
    version {{version}} | pennacle-security/cairnlock
"""


def get_banner(version: str, compact: bool = False) -> str:
    """Return the banner with the version filled in."""
    if compact:
        return ASCII_MARK.format(version=version)
    return BANNER.format(version=version)


def get_cairn_lock_art() -> str:
    """Return the stacked CAIRN/LOCK wordmark without the tagline."""
    return ASCII_LOGO
