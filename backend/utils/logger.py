"""Centralised logging setup."""
from __future__ import annotations

import logging
import sys
from pathlib import Path


def get_logger(name: str = "pscan") -> logging.Logger:
    """Return a configured logger. Call once at app startup."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")

    # Console handler (INFO+)
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger
