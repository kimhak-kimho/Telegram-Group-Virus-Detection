"""
database.py — SQLite persistence layer.

Stores:
  * scan_logs     — metadata about every scan performed (never file contents)
  * group_settings — per-group configuration (max file size, blocklist on/off,
                      custom extension list)

Uses the stdlib sqlite3 module with parameterised queries throughout —
no string-formatted SQL, to avoid injection entirely.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

from config import CONFIG

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    chat_id         INTEGER NOT NULL,
    user_id         INTEGER,
    file_name       TEXT,
    file_size       INTEGER,
    result          TEXT NOT NULL,      -- 'safe' | 'infected' | 'error' | 'blocked_extension' | 'too_large'
    signature       TEXT,               -- ClamAV detection name, if any
    action_taken    TEXT NOT NULL       -- e.g. 'deleted', 'kept', 'notified_admin'
);

CREATE INDEX IF NOT EXISTS idx_scan_logs_chat ON scan_logs (chat_id);

CREATE TABLE IF NOT EXISTS group_settings (
    chat_id                         INTEGER PRIMARY KEY,
    max_file_size_mb                INTEGER NOT NULL,
    extension_blocking_enabled      INTEGER NOT NULL,
    blocked_extensions_json         TEXT NOT NULL
);
"""


def init_db(db_path: str = CONFIG.db_path) -> None:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    with _connect(db_path) as conn:
        conn.executescript(_SCHEMA)
        conn.commit()


@contextmanager
def _connect(db_path: str = CONFIG.db_path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path, timeout=10)
    try:
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scan log
# ---------------------------------------------------------------------------

def log_scan(
    chat_id: int,
    user_id: Optional[int],
    file_name: str,
    file_size: int,
    result: str,
    action_taken: str,
    signature: Optional[str] = None,
    db_path: str = CONFIG.db_path,
) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scan_logs
                (ts, chat_id, user_id, file_name, file_size, result, signature, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (time.time(), chat_id, user_id, file_name, file_size, result, signature, action_taken),
        )
        conn.commit()


@dataclass
class Stats:
    total: int = 0
    safe: int = 0
    infected: int = 0
    errors: int = 0
    blocked_extension: int = 0
    too_large: int = 0


def get_stats(chat_id: Optional[int] = None, db_path: str = CONFIG.db_path) -> Stats:
    query = "SELECT result, COUNT(*) as c FROM scan_logs"
    params: tuple = ()
    if chat_id is not None:
        query += " WHERE chat_id = ?"
        params = (chat_id,)
    query += " GROUP BY result"

    stats = Stats()
    with _connect(db_path) as conn:
        for row in conn.execute(query, params):
            result, count = row["result"], row["c"]
            stats.total += count
            if result == "safe":
                stats.safe = count
            elif result == "infected":
                stats.infected = count
            elif result == "error":
                stats.errors = count
            elif result == "blocked_extension":
                stats.blocked_extension = count
            elif result == "too_large":
                stats.too_large = count
    return stats


# ---------------------------------------------------------------------------
# Per-group settings
# ---------------------------------------------------------------------------

@dataclass
class GroupSettings:
    chat_id: int
    max_file_size_mb: int
    extension_blocking_enabled: bool
    blocked_extensions: list[str]


def get_group_settings(chat_id: int, db_path: str = CONFIG.db_path) -> GroupSettings:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM group_settings WHERE chat_id = ?", (chat_id,)
        ).fetchone()

        if row is None:
            settings = GroupSettings(
                chat_id=chat_id,
                max_file_size_mb=CONFIG.default_max_file_size_mb,
                extension_blocking_enabled=CONFIG.default_extension_blocking_enabled,
                blocked_extensions=list(CONFIG.default_blocked_extensions),
            )
            _insert_default_settings(conn, settings)
            conn.commit()
            return settings

        return GroupSettings(
            chat_id=chat_id,
            max_file_size_mb=row["max_file_size_mb"],
            extension_blocking_enabled=bool(row["extension_blocking_enabled"]),
            blocked_extensions=json.loads(row["blocked_extensions_json"]),
        )


def _insert_default_settings(conn: sqlite3.Connection, settings: GroupSettings) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO group_settings
            (chat_id, max_file_size_mb, extension_blocking_enabled, blocked_extensions_json)
        VALUES (?, ?, ?, ?)
        """,
        (
            settings.chat_id,
            settings.max_file_size_mb,
            int(settings.extension_blocking_enabled),
            json.dumps(settings.blocked_extensions),
        ),
    )


def save_group_settings(settings: GroupSettings, db_path: str = CONFIG.db_path) -> None:
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO group_settings
                (chat_id, max_file_size_mb, extension_blocking_enabled, blocked_extensions_json)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(chat_id) DO UPDATE SET
                max_file_size_mb = excluded.max_file_size_mb,
                extension_blocking_enabled = excluded.extension_blocking_enabled,
                blocked_extensions_json = excluded.blocked_extensions_json
            """,
            (
                settings.chat_id,
                settings.max_file_size_mb,
                int(settings.extension_blocking_enabled),
                json.dumps(settings.blocked_extensions),
            ),
        )
        conn.commit()
