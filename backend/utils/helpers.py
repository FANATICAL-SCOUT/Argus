"""Miscellaneous helper functions."""
from __future__ import annotations

from datetime import datetime


def now_str(fmt: str = "%Y%m%d_%H%M%S") -> str:
    """Return the current local time formatted as a string."""
    return datetime.now().strftime(fmt)


def truncate(text: str, max_len: int = 100) -> str:
    """Truncate *text* to *max_len* characters, appending '…' if cut."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."
