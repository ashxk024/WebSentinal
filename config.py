"""Central configuration for WebSentinel.

Every setting can be overridden with an environment variable so the same code
runs unchanged on Windows and Kali Linux.
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _get_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _get_list(name: str) -> tuple:
    """Parse a comma-separated environment variable into a lowercase tuple."""
    raw = os.environ.get(name, "")
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


class Config:
    """Default application settings."""

    # Flask. Bind to loopback by default: the API has no authentication yet.
    SECRET_KEY = os.environ.get("WEBSENTINEL_SECRET_KEY") or secrets.token_hex(32)
    DEBUG = False
    HOST = os.environ.get("WEBSENTINEL_HOST", "127.0.0.1")
    PORT = _get_int("WEBSENTINEL_PORT", 5000)

    # Storage and logging
    DATABASE_PATH = Path(os.environ.get("WEBSENTINEL_DB", BASE_DIR / "websentinel.db"))
    REPORTS_DIR = BASE_DIR / "reports"
    LOG_DIR = BASE_DIR / "logs"
    LOG_LEVEL = os.environ.get("WEBSENTINEL_LOG_LEVEL", "INFO").upper()

    # Outbound request behaviour (conservative on purpose)
    REQUEST_TIMEOUT = _get_float("WEBSENTINEL_TIMEOUT", 10.0)  # seconds
    REQUEST_DELAY = _get_float("WEBSENTINEL_REQUEST_DELAY", 0.5)  # seconds between requests
    MAX_REDIRECTS = _get_int("WEBSENTINEL_MAX_REDIRECTS", 5)
    USER_AGENT = "WebSentinel/0.1 (authorized security assessment)"

    # Target restrictions
    ALLOWED_PORTS = (80, 443, 8080, 8443)
    MAX_URL_LENGTH = 2048
    # Optional allowlist, e.g. WEBSENTINEL_ALLOWED_TARGETS="example.com,myapp.test".
    # When set, only these hosts (and their subdomains) can be scanned.
    ALLOWED_TARGETS = _get_list("WEBSENTINEL_ALLOWED_TARGETS")
    ALLOW_CROSS_HOST_REDIRECTS = False
