"""
db.py — SQLite-backed persistence for connection_monitor.

Stores everything connection_monitor.py used to write to
connection_monitor_data.json: ping samples, site samples, accessibility samples,
speed tests, outages, degraded periods, router events, AI diagnoses, dismissed
IDs, daily summaries, network uptime, and meta.

The runtime model stays in-memory (state.* deques and lists). This module is the
persistence layer underneath: each save tick inserts only the rows that are new
since the previous flush, and pruning is a per-table DELETE WHERE ts < ?
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SCHEMA_VERSION = 3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS ping_samples (
    ts           TEXT PRIMARY KEY,
    ping_ms      REAL,
    monitor_host TEXT NOT NULL DEFAULT '',
    ingested_at  TEXT
);

CREATE TABLE IF NOT EXISTS accessibility_samples (
    ts             TEXT PRIMARY KEY,
    pct_accessible REAL NOT NULL,
    monitor_host   TEXT NOT NULL DEFAULT '',
    ingested_at    TEXT
);

CREATE TABLE IF NOT EXISTS site_samples (
    ts           TEXT NOT NULL,
    host         TEXT NOT NULL,
    ping_ms      REAL,
    monitor_host TEXT NOT NULL DEFAULT '',
    ingested_at  TEXT,
    PRIMARY KEY (ts, host)
);
CREATE INDEX IF NOT EXISTS idx_site_samples_host_ts ON site_samples(host, ts);

CREATE TABLE IF NOT EXISTS speed_samples (
    ts            TEXT PRIMARY KEY,
    download_mbps REAL,
    upload_mbps   REAL,
    ping_ms       REAL,
    label         TEXT NOT NULL DEFAULT '',
    network       TEXT NOT NULL DEFAULT '',
    monitor_host  TEXT NOT NULL DEFAULT '',
    ingested_at   TEXT
);

CREATE TABLE IF NOT EXISTS outages (
    start_ts     TEXT PRIMARY KEY,
    end_ts       TEXT,
    monitor_host TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS degraded_periods (
    start_ts     TEXT NOT NULL,
    kind         TEXT NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',
    end_ts       TEXT,
    monitor_host TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (start_ts, kind, detail)
);

CREATE TABLE IF NOT EXISTS router_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    src          TEXT,
    dst          TEXT,
    proto        TEXT,
    reason       TEXT,
    source       TEXT,
    monitor_host TEXT NOT NULL DEFAULT '',
    UNIQUE(ts, src, dst, proto, reason, source)
);
CREATE INDEX IF NOT EXISTS idx_router_events_ts ON router_events(ts);

CREATE TABLE IF NOT EXISTS diagnoses (
    id                    TEXT PRIMARY KEY,
    evaluated_at          TEXT NOT NULL,
    ok                    INTEGER NOT NULL,
    window                TEXT,
    error                 TEXT,
    model                 TEXT,
    outage_id             TEXT,
    result_json           TEXT,
    raw_text              TEXT,
    usage_json            TEXT,
    snapshot_summary_json TEXT,
    monitor_host          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_diagnoses_eval ON diagnoses(evaluated_at);

CREATE TABLE IF NOT EXISTS dismissed_outage_ids (
    id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS daily_summary (
    date         TEXT PRIMARY KEY,
    uptime_pct   REAL,
    p10          REAL,
    p50          REAL,
    p90          REAL,
    monitor_host TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS network_uptime (
    network      TEXT NOT NULL,
    monitor_host TEXT NOT NULL DEFAULT '',
    secs         REAL NOT NULL DEFAULT 0,
    color        TEXT,
    PRIMARY KEY (network, monitor_host)
);

CREATE TABLE IF NOT EXISTS hosts (
    monitor_host TEXT PRIMARY KEY,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    display_name TEXT
);

CREATE TABLE IF NOT EXISTS networks (
    fingerprint    TEXT PRIMARY KEY,
    display_name   TEXT,
    interface_type TEXT NOT NULL DEFAULT 'wifi',
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL
);

-- Multi-tenant accounts (cloud/server role only). Empty on single-tenant
-- installs. pw_hash is a salted KDF digest produced in the app layer
-- (werkzeug.security); this layer never sees plaintext passwords.
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL UNIQUE,
    pw_hash    TEXT NOT NULL,
    handle     TEXT NOT NULL,
    is_admin   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

-- Per-agent enrollment tokens. Each token is bound server-side to one owner
-- and one host label, so ingest can force the stored monitor_host and one user
-- can't push data as another. Only a hash of the token is stored (like a
-- password); the plaintext is shown to the user once at creation.
CREATE TABLE IF NOT EXISTS agent_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash   TEXT NOT NULL UNIQUE,
    user_id      INTEGER NOT NULL,
    monitor_host TEXT NOT NULL,
    label        TEXT,
    created_at   TEXT NOT NULL,
    last_used    TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_agent_tokens_user ON agent_tokens(user_id);
"""


@dataclass
class RetentionConfig:
    pings_days: int = 30
    site_pings_days: int = 30
    outages_days: int = 30
    degraded_days: int = 30
    router_days: int = 30
    diagnoses_days: int = 30
    speed_hours: int = 24
    daily_days: int = 7


@dataclass
class PersistCursors:
    """High-water marks for append-only tables, so we only INSERT new rows."""
    ping: str = ""
    accessibility: str = ""
    site: Dict[str, str] = field(default_factory=dict)
    router: str = ""
    speed: str = ""


def _safe_json(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return None


def _parse_json(blob: Optional[str], default: Any) -> Any:
    if not blob:
        return default
    try:
        return json.loads(blob)
    except (TypeError, ValueError):
        return default


class Storage:
    """Thread-safe wrapper around the persistence DB.

    Multiple threads call into a single Storage instance; an internal lock
    serializes writes (SQLite would do this anyway in WAL mode, but the lock
    keeps cursor updates consistent with the rows that were inserted).
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        # check_same_thread=False lets us share the connection across the
        # persistence thread and any future read-path callers; the _lock
        # serializes all access.
        self._conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.row_factory = sqlite3.Row

    # ──────────────────────────────────────────────────────────────────────
    # Schema / lifecycle
    # ──────────────────────────────────────────────────────────────────────
    def init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA_SQL)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES (?, ?)",
                ("schema_version", str(SCHEMA_VERSION)),
            )
            self._conn.commit()
        self._migrate_schema()

    def _migrate_schema(self) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
        current_version = int(row["value"]) if row else 0
        if current_version < 2:
            self._migrate_v1_to_v2()
        if current_version < 3:
            self._migrate_v2_to_v3()

    def _migrate_v1_to_v2(self) -> None:
        """v1→v2: rename provider→network, add monitor_host/ingested_at to all tables."""
        hostname = socket.gethostname()
        now_iso = datetime.now().isoformat()

        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")

                # ── speed_samples: rename provider→network, add monitor_host/ingested_at ──
                cols = [r[1] for r in cur.execute(
                    "PRAGMA table_info(speed_samples)"
                ).fetchall()]
                if "provider" in cols:
                    cur.execute("""
                        CREATE TABLE speed_samples_new (
                            ts            TEXT PRIMARY KEY,
                            download_mbps REAL,
                            upload_mbps   REAL,
                            ping_ms       REAL,
                            label         TEXT NOT NULL DEFAULT '',
                            network       TEXT NOT NULL DEFAULT '',
                            monitor_host  TEXT NOT NULL DEFAULT '',
                            ingested_at   TEXT
                        )
                    """)
                    cur.execute("""
                        INSERT INTO speed_samples_new
                            (ts, download_mbps, upload_mbps, ping_ms,
                             label, network, ingested_at)
                        SELECT ts, download_mbps, upload_mbps, ping_ms,
                               label, provider, ts
                        FROM speed_samples
                    """)
                    cur.execute("DROP TABLE speed_samples")
                    cur.execute("ALTER TABLE speed_samples_new RENAME TO speed_samples")

                # ── provider_uptime → network_uptime ──────────────────────────────────
                tables = {r[0] for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
                if "provider_uptime" in tables:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS network_uptime (
                            network      TEXT NOT NULL,
                            monitor_host TEXT NOT NULL DEFAULT '',
                            secs         REAL NOT NULL DEFAULT 0,
                            color        TEXT,
                            PRIMARY KEY (network, monitor_host)
                        )
                    """)
                    cur.execute("""
                        INSERT OR IGNORE INTO network_uptime
                            (network, monitor_host, secs, color)
                        SELECT provider, '', secs, color FROM provider_uptime
                    """)
                    cur.execute("DROP TABLE provider_uptime")

                # ── Add monitor_host/ingested_at to other tables via ALTER TABLE ────────
                def _add_col_if_missing(table: str, col_def: str, col_name: str) -> None:
                    existing = [r[1] for r in cur.execute(
                        f"PRAGMA table_info({table})"
                    ).fetchall()]
                    if col_name not in existing:
                        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")

                for tbl in ("ping_samples", "accessibility_samples", "site_samples",
                            "outages", "degraded_periods", "diagnoses",
                            "router_events", "daily_summary"):
                    _add_col_if_missing(tbl,
                                        "monitor_host TEXT NOT NULL DEFAULT ''",
                                        "monitor_host")

                for tbl in ("ping_samples", "accessibility_samples", "site_samples"):
                    _add_col_if_missing(tbl, "ingested_at TEXT", "ingested_at")

                # ── hosts table ───────────────────────────────────────────────────────
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS hosts (
                        monitor_host TEXT PRIMARY KEY,
                        first_seen   TEXT NOT NULL,
                        last_seen    TEXT NOT NULL,
                        display_name TEXT
                    )
                """)

                # ── schema_version = 2 ────────────────────────────────────────────────
                cur.execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', '2') "
                    "ON CONFLICT(key) DO UPDATE SET value = '2'"
                )

                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

        # Backfill monitor_host for all existing rows (separate transaction)
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                for tbl in ("speed_samples", "ping_samples", "accessibility_samples",
                            "site_samples", "outages", "degraded_periods",
                            "diagnoses", "daily_summary", "network_uptime"):
                    cur.execute(
                        f"UPDATE {tbl} SET monitor_host = ? WHERE monitor_host = ''",
                        (hostname,)
                    )
                cur.execute(
                    "INSERT INTO hosts(monitor_host, first_seen, last_seen) "
                    "VALUES(?, ?, ?) ON CONFLICT(monitor_host) DO NOTHING",
                    (hostname, now_iso, now_iso)
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

        logging.info("db: migrated schema v1→v2 (provider→network, monitor_host added)")

    def _migrate_v2_to_v3(self) -> None:
        """v2→v3: add networks table for gateway fingerprint → display name mapping."""
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS networks (
                        fingerprint    TEXT PRIMARY KEY,
                        display_name   TEXT,
                        interface_type TEXT NOT NULL DEFAULT 'wifi',
                        first_seen     TEXT NOT NULL,
                        last_seen      TEXT NOT NULL
                    )
                """)
                cur.execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', '3') "
                    "ON CONFLICT(key) DO UPDATE SET value = '3'"
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        logging.info("db: migrated schema v2→v3 (networks table added)")

    # ──────────────────────────────────────────────────────────────────────
    # Network fingerprint registry
    # ──────────────────────────────────────────────────────────────────────
    def register_network(self, fingerprint: str, interface_type: str) -> None:
        now = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO networks(fingerprint, interface_type, first_seen, last_seen) "
                "VALUES(?, ?, ?, ?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET last_seen = ?",
                (fingerprint, interface_type, now, now, now),
            )
            self._conn.commit()

    def load_network_names(self) -> Dict[str, str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT fingerprint, display_name FROM networks "
                "WHERE display_name IS NOT NULL"
            ).fetchall()
        return {r["fingerprint"]: r["display_name"] for r in rows}

    def rename_network(self, fingerprint: str, name: Optional[str]) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE networks SET display_name = ? WHERE fingerprint = ?",
                (name, fingerprint),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def load_all_networks(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT fingerprint, display_name, interface_type, "
                "first_seen, last_seen FROM networks ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def load_hosts(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT monitor_host, display_name, first_seen, last_seen "
                "FROM hosts ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def update_host_seen(self, monitor_host: str) -> None:
        now_iso = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO hosts(monitor_host, first_seen, last_seen) "
                "VALUES(?, ?, ?) "
                "ON CONFLICT(monitor_host) DO UPDATE SET last_seen = excluded.last_seen",
                (monitor_host, now_iso, now_iso),
            )
            self._conn.commit()

    # ──────────────────────────────────────────────────────────────────────
    # Users (multi-tenant accounts; empty on single-tenant installs)
    # ──────────────────────────────────────────────────────────────────────
    def count_users(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"]) if row else 0

    def create_user(self, email: str, pw_hash: str, handle: str,
                    is_admin: bool = False) -> Optional[int]:
        """Insert a user. Returns the new id, or None if the email already exists."""
        now_iso = datetime.now().isoformat()
        with self._lock:
            try:
                cur = self._conn.execute(
                    "INSERT INTO users(email, pw_hash, handle, is_admin, created_at) "
                    "VALUES(?, ?, ?, ?, ?)",
                    (email, pw_hash, handle, 1 if is_admin else 0, now_iso),
                )
                self._conn.commit()
                return int(cur.lastrowid)
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return None

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, email, pw_hash, handle, is_admin, created_at "
                "FROM users WHERE email = ?", (email,)
            ).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, email, pw_hash, handle, is_admin, created_at "
                "FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row else None

    # ──────────────────────────────────────────────────────────────────────
    # Agent tokens (per-agent ingest credentials, multi-tenant)
    # ──────────────────────────────────────────────────────────────────────
    def create_agent_token(self, user_id: int, monitor_host: str,
                           token_hash: str, label: Optional[str] = None) -> int:
        now_iso = datetime.now().isoformat()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO agent_tokens(token_hash, user_id, monitor_host, "
                "label, created_at) VALUES(?, ?, ?, ?, ?)",
                (token_hash, user_id, monitor_host, label, now_iso),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def get_agent_token_by_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, user_id, monitor_host, label, last_used, revoked "
                "FROM agent_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        return dict(row) if row else None

    def touch_agent_token(self, token_hash: str) -> None:
        now_iso = datetime.now().isoformat()
        with self._lock:
            self._conn.execute(
                "UPDATE agent_tokens SET last_used = ? WHERE token_hash = ?",
                (now_iso, token_hash),
            )
            self._conn.commit()

    def list_agent_tokens(self, user_id: int) -> List[Dict[str, Any]]:
        """Tokens for a user, newest first. Never returns the hash/plaintext."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, monitor_host, label, created_at, last_used, revoked "
                "FROM agent_tokens WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def revoke_agent_token(self, token_id: int, user_id: int) -> bool:
        """Revoke a token, but only if it belongs to user_id."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE agent_tokens SET revoked = 1 "
                "WHERE id = ? AND user_id = ?",
                (token_id, user_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def has_any_rows(self) -> bool:
        """True if any data table has at least one row.

        Used by the migration script to decide whether to bail out (the DB
        already holds data) vs. proceed (fresh DB)."""
        tables = (
            "ping_samples", "accessibility_samples", "site_samples",
            "speed_samples", "outages", "degraded_periods", "router_events",
            "diagnoses", "dismissed_outage_ids", "daily_summary",
            "network_uptime",
        )
        with self._lock:
            for t in tables:
                row = self._conn.execute(f"SELECT 1 FROM {t} LIMIT 1").fetchone()
                if row:
                    return True
        return False

    # ──────────────────────────────────────────────────────────────────────
    # Meta
    # ──────────────────────────────────────────────────────────────────────
    def get_meta(self, key: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    # ──────────────────────────────────────────────────────────────────────
    # Loaders — return plain Python types ready for in-memory state
    # ──────────────────────────────────────────────────────────────────────
    def load_speed_samples(self, cutoff_iso: str, monitor_host: Optional[str] = None) -> List[Dict[str, Any]]:
        if monitor_host is None:
            monitor_host = socket.gethostname()
        with self._lock:
            if monitor_host == "*":
                rows = self._conn.execute(
                    "SELECT ts, download_mbps, upload_mbps, ping_ms, label, network "
                    "FROM speed_samples WHERE ts >= ? ORDER BY ts",
                    (cutoff_iso,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ts, download_mbps, upload_mbps, ping_ms, label, network "
                    "FROM speed_samples "
                    "WHERE ts >= ? AND (monitor_host = ? OR monitor_host = '') "
                    "ORDER BY ts",
                    (cutoff_iso, monitor_host),
                ).fetchall()
        return [
            {
                "timestamp": r["ts"],
                "download_mbps": r["download_mbps"],
                "upload_mbps": r["upload_mbps"],
                "ping_ms": r["ping_ms"],
                "label": r["label"] or "",
                "network": r["network"] or "",
            }
            for r in rows
        ]

    def load_speed_values_exact(self, cutoff_iso: str, monitor_host: str
                               ) -> List[Tuple[Optional[float], Optional[float]]]:
        """(download, upload) pairs for one host, strict exact match — no legacy
        monitor_host='' rows. Used for per-user leaderboard aggregates so a
        user's numbers can't be polluted by the server's own control data."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT download_mbps, upload_mbps FROM speed_samples "
                "WHERE ts >= ? AND monitor_host = ? ORDER BY ts",
                (cutoff_iso, monitor_host),
            ).fetchall()
        return [(r["download_mbps"], r["upload_mbps"]) for r in rows]

    def load_outages(self, cutoff_iso: str, monitor_host: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if monitor_host and monitor_host != "*":
                rows = self._conn.execute(
                    "SELECT start_ts, end_ts FROM outages "
                    "WHERE start_ts >= ? AND monitor_host = ? ORDER BY start_ts",
                    (cutoff_iso, monitor_host),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT start_ts, end_ts FROM outages "
                    "WHERE start_ts >= ? ORDER BY start_ts",
                    (cutoff_iso,),
                ).fetchall()
        return [{"start": r["start_ts"], "end": r["end_ts"]} for r in rows]

    def load_degraded_periods(self, cutoff_iso: str, monitor_host: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if monitor_host and monitor_host != "*":
                rows = self._conn.execute(
                    "SELECT start_ts, end_ts, kind, detail FROM degraded_periods "
                    "WHERE start_ts >= ? AND monitor_host = ? ORDER BY start_ts",
                    (cutoff_iso, monitor_host),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT start_ts, end_ts, kind, detail FROM degraded_periods "
                    "WHERE start_ts >= ? ORDER BY start_ts",
                    (cutoff_iso,),
                ).fetchall()
        return [
            {
                "start": r["start_ts"],
                "end": r["end_ts"],
                "kind": r["kind"] or "slow",
                "detail": r["detail"] or "",
            }
            for r in rows
        ]

    def load_ping_samples(self, cutoff_iso: str, monitor_host: Optional[str] = None) -> List[Tuple[str, Optional[float]]]:
        with self._lock:
            if monitor_host and monitor_host != "*":
                rows = self._conn.execute(
                    "SELECT ts, ping_ms FROM ping_samples "
                    "WHERE ts >= ? AND monitor_host = ? ORDER BY ts",
                    (cutoff_iso, monitor_host),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ts, ping_ms FROM ping_samples WHERE ts >= ? ORDER BY ts",
                    (cutoff_iso,),
                ).fetchall()
        return [(r["ts"], r["ping_ms"]) for r in rows]

    def load_accessibility_samples(self, cutoff_iso: str, monitor_host: Optional[str] = None) -> List[Tuple[str, float]]:
        with self._lock:
            if monitor_host and monitor_host != "*":
                rows = self._conn.execute(
                    "SELECT ts, pct_accessible FROM accessibility_samples "
                    "WHERE ts >= ? AND monitor_host = ? ORDER BY ts",
                    (cutoff_iso, monitor_host),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ts, pct_accessible FROM accessibility_samples "
                    "WHERE ts >= ? ORDER BY ts",
                    (cutoff_iso,),
                ).fetchall()
        return [(r["ts"], r["pct_accessible"]) for r in rows]

    def load_site_samples(self, cutoff_iso: str, monitor_host: Optional[str] = None) -> Dict[str, List[Tuple[str, Optional[float]]]]:
        with self._lock:
            if monitor_host and monitor_host != "*":
                rows = self._conn.execute(
                    "SELECT host, ts, ping_ms FROM site_samples "
                    "WHERE ts >= ? AND monitor_host = ? ORDER BY host, ts",
                    (cutoff_iso, monitor_host),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT host, ts, ping_ms FROM site_samples "
                    "WHERE ts >= ? ORDER BY host, ts",
                    (cutoff_iso,),
                ).fetchall()
        out: Dict[str, List[Tuple[str, Optional[float]]]] = {}
        for r in rows:
            out.setdefault(r["host"], []).append((r["ts"], r["ping_ms"]))
        return out

    def load_router_events(self, cutoff_iso: str, monitor_host: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if monitor_host and monitor_host != "*":
                rows = self._conn.execute(
                    "SELECT ts, src, dst, proto, reason, source FROM router_events "
                    "WHERE ts >= ? AND monitor_host = ? ORDER BY ts",
                    (cutoff_iso, monitor_host),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT ts, src, dst, proto, reason, source FROM router_events "
                    "WHERE ts >= ? ORDER BY ts",
                    (cutoff_iso,),
                ).fetchall()
        return [
            {
                "ts": r["ts"],
                "src": r["src"] or "",
                "dst": r["dst"] or "",
                "proto": r["proto"] or "",
                "reason": r["reason"] or "",
                "source": r["source"] or "packet",
            }
            for r in rows
        ]

    def load_diagnoses(self, cutoff_iso: str, monitor_host: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if monitor_host and monitor_host != "*":
                rows = self._conn.execute(
                    "SELECT id, evaluated_at, ok, window, error, model, outage_id, "
                    "result_json, raw_text, usage_json, snapshot_summary_json "
                    "FROM diagnoses WHERE evaluated_at >= ? AND monitor_host = ? "
                    "ORDER BY evaluated_at DESC",
                    (cutoff_iso, monitor_host),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT id, evaluated_at, ok, window, error, model, outage_id, "
                    "result_json, raw_text, usage_json, snapshot_summary_json "
                    "FROM diagnoses WHERE evaluated_at >= ? ORDER BY evaluated_at DESC",
                    (cutoff_iso,),
                ).fetchall()
        out = []
        for r in rows:
            d = {
                "id": r["id"],
                "evaluated_at": r["evaluated_at"],
                "ok": bool(r["ok"]),
                "window": r["window"],
                "error": r["error"],
                "model": r["model"],
                "result": _parse_json(r["result_json"], {}),
                "raw_text": r["raw_text"],
                "usage": _parse_json(r["usage_json"], {}),
                "snapshot_summary": _parse_json(r["snapshot_summary_json"], {}),
            }
            if r["outage_id"]:
                d["outage_id"] = r["outage_id"]
            out.append(d)
        return out

    def load_dismissed_outage_ids(self) -> Set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM dismissed_outage_ids"
            ).fetchall()
        return {r["id"] for r in rows}

    def load_daily_summary(self, cutoff_date_str: str, monitor_host: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if monitor_host and monitor_host != "*":
                rows = self._conn.execute(
                    "SELECT date, uptime_pct, p10, p50, p90 FROM daily_summary "
                    "WHERE date > ? AND monitor_host = ? ORDER BY date",
                    (cutoff_date_str, monitor_host),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT date, uptime_pct, p10, p50, p90 FROM daily_summary "
                    "WHERE date > ? ORDER BY date",
                    (cutoff_date_str,),
                ).fetchall()
        return [
            {
                "date": r["date"],
                "uptime_pct": r["uptime_pct"],
                "p10": r["p10"],
                "p50": r["p50"],
                "p90": r["p90"],
            }
            for r in rows
        ]

    def load_network_uptime(self, monitor_host: Optional[str] = None) -> Tuple[Dict[str, float], Dict[str, str]]:
        if monitor_host is None:
            monitor_host = socket.gethostname()
        with self._lock:
            if monitor_host == "*":
                rows = self._conn.execute(
                    "SELECT network, secs, color FROM network_uptime"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT network, secs, color FROM network_uptime "
                    "WHERE monitor_host = ? OR monitor_host = ''",
                    (monitor_host,),
                ).fetchall()
        secs = {r["network"]: float(r["secs"]) for r in rows}
        colors = {r["network"]: r["color"] for r in rows if r["color"]}
        return secs, colors

    # ──────────────────────────────────────────────────────────────────────
    # Writers — invoked under the storage lock from flush()
    # ──────────────────────────────────────────────────────────────────────
    def flush(
        self,
        *,
        cursors: PersistCursors,
        ping_samples: List[Tuple[str, Optional[float]]],
        accessibility_samples: List[Tuple[str, float]],
        site_samples: Dict[str, List[Tuple[str, Optional[float]]]],
        speed_samples: List[Dict[str, Any]],
        outages: List[Dict[str, Any]],
        current_outage: Optional[Dict[str, Any]],
        degraded: List[Dict[str, Any]],
        router_events: List[Dict[str, Any]],
        diagnoses: List[Dict[str, Any]],
        dismissed_outage_ids: Set[str],
        daily_summary: List[Dict[str, Any]],
        network_uptime_secs: Dict[str, float],
        network_colors: Dict[str, str],
        first_seen_iso: str,
        saved_at_iso: str,
        monitor_host_override: Optional[str] = None,
    ) -> PersistCursors:
        """Write changed rows since the previous flush.

        Append-only tables (ping/site/accessibility/router/speed) skip rows
        with ts <= the corresponding cursor. Mutable tables (outages,
        degraded, daily_summary, network_uptime, dismissed_ids) are full-
        replaced under the same transaction, which is cheap because they
        are small.
        """
        hostname = monitor_host_override or socket.gethostname()
        now_iso = datetime.now().isoformat()

        new_cursors = PersistCursors(
            ping=cursors.ping,
            accessibility=cursors.accessibility,
            site=dict(cursors.site),
            router=cursors.router,
            speed=cursors.speed,
        )

        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")

                # ── Append-only series ──
                new_pings = [
                    (ts, v) for ts, v in ping_samples if ts > cursors.ping
                ]
                if new_pings:
                    cur.executemany(
                        "INSERT OR IGNORE INTO ping_samples"
                        "(ts, ping_ms, monitor_host, ingested_at) VALUES (?, ?, ?, ?)",
                        [(ts, v, hostname, now_iso) for ts, v in new_pings],
                    )
                    new_cursors.ping = max(ts for ts, _ in new_pings)

                new_access = [
                    (ts, v) for ts, v in accessibility_samples if ts > cursors.accessibility
                ]
                if new_access:
                    cur.executemany(
                        "INSERT OR IGNORE INTO accessibility_samples"
                        "(ts, pct_accessible, monitor_host, ingested_at) VALUES (?, ?, ?, ?)",
                        [(ts, v, hostname, now_iso) for ts, v in new_access],
                    )
                    new_cursors.accessibility = max(ts for ts, _ in new_access)

                for host, samples in site_samples.items():
                    prev = cursors.site.get(host, "")
                    new_site = [(ts, host, v) for ts, v in samples if ts > prev]
                    if new_site:
                        cur.executemany(
                            "INSERT OR IGNORE INTO site_samples"
                            "(ts, host, ping_ms, monitor_host, ingested_at) VALUES (?, ?, ?, ?, ?)",
                            [(ts, h, v, hostname, now_iso) for ts, h, v in new_site],
                        )
                        new_cursors.site[host] = max(ts for ts, _, _ in new_site)

                new_speed = [
                    s for s in speed_samples if s["timestamp"] > cursors.speed
                ]
                if new_speed:
                    cur.executemany(
                        "INSERT OR IGNORE INTO speed_samples"
                        "(ts, download_mbps, upload_mbps, ping_ms, label, network,"
                        " monitor_host, ingested_at)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        [
                            (
                                s["timestamp"],
                                s["download_mbps"],
                                s["upload_mbps"],
                                s["ping_ms"],
                                s.get("label", ""),
                                s.get("network", ""),
                                hostname,
                                now_iso,
                            )
                            for s in new_speed
                        ],
                    )
                    new_cursors.speed = max(s["timestamp"] for s in new_speed)

                new_router = [
                    r for r in router_events if r["ts"] > cursors.router
                ]
                if new_router:
                    cur.executemany(
                        "INSERT OR IGNORE INTO router_events"
                        "(ts, src, dst, proto, reason, source) VALUES (?, ?, ?, ?, ?, ?)",
                        [
                            (r["ts"], r["src"], r["dst"], r["proto"], r["reason"], r["source"])
                            for r in new_router
                        ],
                    )
                    new_cursors.router = max(r["ts"] for r in new_router)

                # ── Mutable tables: full replace ──
                # outages — UPSERT (closed ones get their end_ts written; current_outage stays NULL)
                if outages or current_outage:
                    rows = [(o["start"], o["end"]) for o in outages]
                    if current_outage:
                        rows.append((current_outage["start"], current_outage["end"]))
                    cur.executemany(
                        "INSERT INTO outages(start_ts, end_ts) VALUES (?, ?) "
                        "ON CONFLICT(start_ts) DO UPDATE SET end_ts = excluded.end_ts",
                        rows,
                    )

                # degraded_periods — UPSERT by (start, kind, detail)
                if degraded:
                    cur.executemany(
                        "INSERT INTO degraded_periods(start_ts, kind, detail, end_ts) "
                        "VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(start_ts, kind, detail) "
                        "DO UPDATE SET end_ts = excluded.end_ts",
                        [
                            (d["start"], d["kind"], d.get("detail", ""), d.get("end"))
                            for d in degraded
                        ],
                    )

                # diagnoses — INSERT OR IGNORE (never edited in place)
                if diagnoses:
                    cur.executemany(
                        "INSERT OR IGNORE INTO diagnoses"
                        "(id, evaluated_at, ok, window, error, model, outage_id, "
                        " result_json, raw_text, usage_json, snapshot_summary_json)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [
                            (
                                d.get("id"),
                                d.get("evaluated_at"),
                                1 if d.get("ok") else 0,
                                d.get("window"),
                                d.get("error"),
                                d.get("model"),
                                d.get("outage_id"),
                                _safe_json(d.get("result")),
                                d.get("raw_text"),
                                _safe_json(d.get("usage")),
                                _safe_json(d.get("snapshot_summary")),
                            )
                            for d in diagnoses
                            if d.get("id")
                        ],
                    )

                # dismissed_outage_ids — full replace; tiny set
                cur.execute("DELETE FROM dismissed_outage_ids")
                if dismissed_outage_ids:
                    cur.executemany(
                        "INSERT INTO dismissed_outage_ids(id) VALUES (?)",
                        [(i,) for i in dismissed_outage_ids],
                    )

                # daily_summary — INSERT OR REPLACE keyed by date
                if daily_summary:
                    cur.executemany(
                        "INSERT INTO daily_summary"
                        "(date, uptime_pct, p10, p50, p90, monitor_host) "
                        "VALUES (?, ?, ?, ?, ?, ?) "
                        "ON CONFLICT(date) DO UPDATE SET "
                        "  uptime_pct = excluded.uptime_pct, "
                        "  p10 = excluded.p10, p50 = excluded.p50, p90 = excluded.p90,"
                        "  monitor_host = excluded.monitor_host",
                        [
                            (
                                e["date"],
                                e.get("uptime_pct"),
                                e.get("p10"),
                                e.get("p50"),
                                e.get("p90"),
                                hostname,
                            )
                            for e in daily_summary
                        ],
                    )

                # network_uptime — replace this host's rows only (small dict)
                cur.execute(
                    "DELETE FROM network_uptime WHERE monitor_host = ?", (hostname,)
                )
                if network_uptime_secs:
                    cur.executemany(
                        "INSERT INTO network_uptime"
                        "(network, monitor_host, secs, color) VALUES (?, ?, ?, ?)",
                        [
                            (n, hostname, float(s), network_colors.get(n))
                            for n, s in network_uptime_secs.items()
                        ],
                    )

                # hosts — heartbeat for this monitor
                cur.execute(
                    "INSERT INTO hosts(monitor_host, first_seen, last_seen) "
                    "VALUES(?, ?, ?) "
                    "ON CONFLICT(monitor_host) DO UPDATE SET last_seen = excluded.last_seen",
                    (hostname, first_seen_iso, now_iso),
                )

                # meta
                cur.executemany(
                    "INSERT INTO meta(key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [("first_seen", first_seen_iso), ("saved_at", saved_at_iso)],
                )

                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

        return new_cursors

    # ──────────────────────────────────────────────────────────────────────
    # Pruning
    # ──────────────────────────────────────────────────────────────────────
    def prune(self, retention: RetentionConfig) -> Dict[str, int]:
        """Delete rows older than each table's retention window.

        Returns a dict of {table: rows_deleted} for logging.
        """
        now = datetime.now()
        ping_cut       = (now - timedelta(days=retention.pings_days)).isoformat()
        site_cut       = (now - timedelta(days=retention.site_pings_days)).isoformat()
        outage_cut     = (now - timedelta(days=retention.outages_days)).isoformat()
        degraded_cut   = (now - timedelta(days=retention.degraded_days)).isoformat()
        router_cut     = (now - timedelta(days=retention.router_days)).isoformat()
        diagnoses_cut  = (now - timedelta(days=retention.diagnoses_days)).isoformat()
        speed_cut      = (now - timedelta(hours=retention.speed_hours)).isoformat()
        daily_cut      = (now - timedelta(days=retention.daily_days)).strftime("%Y-%m-%d")

        deleted: Dict[str, int] = {}
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
                for table, col, cut in (
                    ("ping_samples",          "ts",       ping_cut),
                    ("accessibility_samples", "ts",       ping_cut),
                    ("site_samples",          "ts",       site_cut),
                    ("speed_samples",         "ts",       speed_cut),
                    # outages: keep ongoing (end_ts NULL) regardless of age
                    ("outages",               "start_ts", outage_cut),
                    ("degraded_periods",      "start_ts", degraded_cut),
                    ("router_events",         "ts",       router_cut),
                    ("diagnoses",             "evaluated_at", diagnoses_cut),
                    ("daily_summary",         "date",     daily_cut),
                ):
                    cur.execute(f"DELETE FROM {table} WHERE {col} < ?", (cut,))
                    deleted[table] = cur.rowcount
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return deleted

    def vacuum(self) -> None:
        """Reclaim space after large deletes. Call sparingly."""
        with self._lock:
            self._conn.execute("VACUUM")


# ──────────────────────────────────────────────────────────────────────────
# Env-driven config
# ──────────────────────────────────────────────────────────────────────────
def retention_from_env() -> RetentionConfig:
    def _int(key: str, default: int) -> int:
        try:
            return max(1, int(os.environ.get(key, str(default))))
        except (TypeError, ValueError):
            return default
    return RetentionConfig(
        pings_days      = _int("RETAIN_PINGS_DAYS", 30),
        site_pings_days = _int("RETAIN_SITE_PINGS_DAYS", 30),
        outages_days    = _int("RETAIN_OUTAGES_DAYS", 30),
        degraded_days   = _int("RETAIN_DEGRADED_DAYS", 30),
        router_days     = _int("RETAIN_ROUTER_DAYS", 30),
        diagnoses_days  = _int("RETAIN_DIAGNOSES_DAYS", 30),
        speed_hours     = _int("RETAIN_SPEED_HOURS", 24),
        daily_days      = _int("RETAIN_DAILY_DAYS", 7),
    )


def db_path_from_env(default_path: str) -> str:
    override = os.environ.get("DATA_DB", "").strip()
    return override or default_path
