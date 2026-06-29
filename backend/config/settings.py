"""Centralised path and runtime settings.

All data-directory paths are defined here so no module hard-codes a location.
Call Settings.ensure_dirs() before writing any runtime file.
"""
from __future__ import annotations

from pathlib import Path


class Settings:
    # pscan/config/settings.py  →  .parent = pscan/config/
    #                              .parent.parent = pscan/  (package root)
    #                              .parent.parent.parent = project root
    _PKG_ROOT: Path = Path(__file__).parent.parent        # pscan/ package
    PROJECT_ROOT: Path = _PKG_ROOT.parent                  # outer project root

    # Runtime data directories (all under data/)
    DATA_DIR: Path = PROJECT_ROOT / "data"
    RECORDS_DIR: Path = DATA_DIR / "records"
    DB_DIR: Path = DATA_DIR / "database"
    EXPORTS_DIR: Path = DATA_DIR / "exports"
    LOGS_DIR: Path = DATA_DIR / "logs"

    # Key file paths
    DB_PATH: Path = DB_DIR / "backend.db"
    VULN_DB_PATH: Path = DATA_DIR / "vuln_database.json"

    # Web settings (used in Phase 2+)
    WEB_HOST: str = "127.0.0.1"
    WEB_PORT: int = 8000

    # Auth — change these before exposing to a network
    SECRET_KEY: str = "pscan-secret-change-me-in-production"
    AUTH_USERNAME: str = "admin"
    AUTH_PASSWORD: str = "pscan2024"

    @classmethod
    def ensure_dirs(cls) -> None:
        """Create all data subdirectories if they do not exist."""
        for d in (cls.RECORDS_DIR, cls.DB_DIR, cls.EXPORTS_DIR, cls.LOGS_DIR):
            d.mkdir(parents=True, exist_ok=True)
