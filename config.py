"""
config.py — centralised configuration for the Telegram Virus Detection Bot.

All secrets are loaded from environment variables (see .env.example).
Nothing here should ever contain a hard-coded token or credential.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()  # loads variables from a local .env file if present


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _env_id_set(name: str) -> set[int]:
    raw = os.getenv(name, "")
    ids: set[int] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if chunk:
            try:
                ids.add(int(chunk))
            except ValueError:
                continue
    return ids


# ---------------------------------------------------------------------------
# Required secrets
# ---------------------------------------------------------------------------

BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")

# ---------------------------------------------------------------------------
# Bot-owner / super-admin IDs (can always use /settings regardless of group
# admin status — useful for the bot operator). Comma separated Telegram user
# IDs, e.g. "111111111,222222222"
# ---------------------------------------------------------------------------

SUPER_ADMIN_IDS: set[int] = _env_id_set("SUPER_ADMIN_IDS")

# ---------------------------------------------------------------------------
# ClamAV connection (clamd daemon, reached over TCP — works across Docker
# containers without sharing a filesystem, since we stream file bytes with
# INSTREAM rather than asking clamd to open a path itself).
# ---------------------------------------------------------------------------

CLAMAV_HOST: str = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT: int = _env_int("CLAMAV_PORT", 3310)
CLAMAV_TIMEOUT: int = _env_int("CLAMAV_TIMEOUT_SECONDS", 60)

# ---------------------------------------------------------------------------
# File handling defaults (overridable per group via /settings, stored in DB)
# ---------------------------------------------------------------------------

DEFAULT_MAX_FILE_SIZE_MB: int = _env_int("DEFAULT_MAX_FILE_SIZE_MB", 50)

DEFAULT_BLOCKED_EXTENSIONS: tuple[str, ...] = (
    ".exe", ".dll", ".sys", ".scr", ".pif", ".com", ".cpl",
    ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".src",
    ".jar", ".apk", ".reg", ".lnk",
    ".rar", ".zip", ".7z", ".z",
)

DEFAULT_EXTENSION_BLOCKING_ENABLED: bool = True

# Directory used for temporary downloads. Files are deleted immediately
# after scanning; nothing is ever persisted here long-term.
TEMP_DIR: str = os.getenv("TEMP_DIR", "/tmp/telegram_virus_bot")

# SQLite database path (scan logs + per-group settings only — never file
# contents).
DB_PATH: str = os.getenv("DB_PATH", os.path.join("data", "bot.db"))

# Absolute ceiling regardless of any per-group setting, to protect the host.
HARD_MAX_FILE_SIZE_MB: int = _env_int("HARD_MAX_FILE_SIZE_MB", 200)

# Telegram HTTP timeouts (seconds). File downloads need a long read timeout.
TELEGRAM_CONNECT_TIMEOUT: int = _env_int("TELEGRAM_CONNECT_TIMEOUT", 30)
TELEGRAM_READ_TIMEOUT: int = _env_int("TELEGRAM_READ_TIMEOUT", 120)


@dataclass(frozen=True)
class RuntimeConfig:
    bot_token: str = BOT_TOKEN
    super_admin_ids: set[int] = field(default_factory=lambda: SUPER_ADMIN_IDS)
    clamav_host: str = CLAMAV_HOST
    clamav_port: int = CLAMAV_PORT
    clamav_timeout: int = CLAMAV_TIMEOUT
    default_max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB
    hard_max_file_size_mb: int = HARD_MAX_FILE_SIZE_MB
    default_blocked_extensions: tuple[str, ...] = DEFAULT_BLOCKED_EXTENSIONS
    default_extension_blocking_enabled: bool = DEFAULT_EXTENSION_BLOCKING_ENABLED
    temp_dir: str = TEMP_DIR
    db_path: str = DB_PATH
    telegram_connect_timeout: int = TELEGRAM_CONNECT_TIMEOUT
    telegram_read_timeout: int = TELEGRAM_READ_TIMEOUT


CONFIG = RuntimeConfig()


def validate_config() -> list[str]:
    """Return a list of human-readable problems with the current config."""
    problems = []
    if not CONFIG.bot_token:
        problems.append(
            "TELEGRAM_BOT_TOKEN is not set. Set it in your environment or .env file."
        )
    if CONFIG.default_max_file_size_mb > CONFIG.hard_max_file_size_mb:
        problems.append(
            "DEFAULT_MAX_FILE_SIZE_MB exceeds HARD_MAX_FILE_SIZE_MB; lower one of them."
        )
    return problems
