"""
db.py — SQLite-backed persistence for connection_monitor.

Stores everything connection_monitor.py used to write to
connection_monitor_data.json: ping samples, site samples, accessibility samples,
speed tests, outages, degraded periods, router events, AI diagnoses, dismissed
IDs, daily summaries, provider uptime, and meta.

The runtime model stays in-memory (state.* deques and lists). This module is the
persistence layer underneath: each save tick inserts only the rows that are new
since the previous flush, and pruning is a per-table DELETE WHERE ts < ?
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS ping_samples (
    ts      TEXT PRIMARY KEY,
    ping_ms REAL
);

CREATE TABLE IF NOT EXISTS accessibility_samples (
    ts             TEXT PRIMARY KEY,
    pct_accessible REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS site_samples (
    ts      TEXT NOT NULL,
    host    TEXT NOT NULL,
    ping_ms REAL,
    PRIMARY KEY (ts, host)
);
CREATE INDEX IF NOT EXISTS idx_site_samples_host_ts ON site_samples(host, ts);

CREATE TABLE IF NOT EXISTS speed_samples (
    ts            TEXT PRIMARY KEY,
    download_mbps REAL,
    upload_mbps   REAL,
    ping_ms       REAL,
    label         TEXT NOT NULL DEFAULT '',
    provider      TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS outages (
    start_ts TEXT PRIMARY KEY,
    end_ts   TEXT
);

CREATE TABLE IF NOT EXISTS degraded_periods (
    start_ts TEXT NOT NULL,
    kind     TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '',
    end_ts   TEXT,
    PRIMARY KEY (start_ts, kind, detail)
);

CREATE TABLE IF NOT EXISTS router_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    src    TEXT,
    dst    TEXT,
    proto  TEXT,
    reason TEXT,
    source TEXT,
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
    snapshot_summary_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_diagnoses_eval ON diagnoses(evaluated_at);

CREATE TABLE IF NOT EXISTS dismissed_outage_ids (
    id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS daily_summary (
    date       TEXT PRIMARY KEY,
    uptime_pct REAL,
    p10        REAL,
    p50        REAL,
    p90        REAL
);

CREATE TABLE IF NOT EXISTS provider_uptime (
    provider TEXT PRIMARY KEY,
    secs     REAL NOT NULL DEFAULT 0,
    color    TEXT
);
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
            "provider_uptime",
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
    def load_speed_samples(self, cutoff_iso: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, download_mbps, upload_mbps, ping_ms, label, provider "
                "FROM speed_samples WHERE ts >= ? ORDER BY ts",
                (cutoff_iso,),
            ).fetchall()
        return [
            {
                "timestamp": r["ts"],
                "download_mbps": r["download_mbps"],
                "upload_mbps": r["upload_mbps"],
                "ping_ms": r["ping_ms"],
                "label": r["label"] or "",
                "provider": r["provider"] or "",
            }
            for r in rows
        ]

    def load_outages(self, cutoff_iso: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT start_ts, end_ts FROM outages "
                "WHERE start_ts >= ? ORDER BY start_ts",
                (cutoff_iso,),
            ).fetchall()
        return [{"start": r["start_ts"], "end": r["end_ts"]} for r in rows]

    def load_degraded_periods(self, cutoff_iso: str) -> List[Dict[str, Any]]:
        with self._lock:
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

    def load_ping_samples(self, cutoff_iso: str) -> List[Tuple[str, Optional[float]]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, ping_ms FROM ping_samples WHERE ts >= ? ORDER BY ts",
                (cutoff_iso,),
            ).fetchall()
        return [(r["ts"], r["ping_ms"]) for r in rows]

    def load_accessibility_samples(self, cutoff_iso: str) -> List[Tuple[str, float]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, pct_accessible FROM accessibility_samples "
                "WHERE ts >= ? ORDER BY ts",
                (cutoff_iso,),
            ).fetchall()
        return [(r["ts"], r["pct_accessible"]) for r in rows]

    def load_site_samples(self, cutoff_iso: str) -> Dict[str, List[Tuple[str, Optional[float]]]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT host, ts, ping_ms FROM site_samples "
                "WHERE ts >= ? ORDER BY host, ts",
                (cutoff_iso,),
            ).fetchall()
        out: Dict[str, List[Tuple[str, Optional[float]]]] = {}
        for r in rows:
            out.setdefault(r["host"], []).append((r["ts"], r["ping_ms"]))
        return out

    def load_router_events(self, cutoff_iso: str) -> List[Dict[str, Any]]:
        with self._lock:
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

    def load_diagnoses(self, cutoff_iso: str) -> List[Dict[str, Any]]:
        with self._lock:
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

    def load_daily_summary(self, cutoff_date_str: str) -> List[Dict[str, Any]]:
        with self._lock:
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

    def load_provider_uptime(self) -> Tuple[Dict[str, float], Dict[str, str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT provider, secs, color FROM provider_uptime"
            ).fetchall()
        secs = {r["provider"]: float(r["secs"]) for r in rows}
        colors = {r["provider"]: r["color"] for r in rows if r["color"]}
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
        provider_uptime_secs: Dict[str, float],
        provider_colors: Dict[str, str],
        first_seen_iso: str,
        saved_at_iso: str,
    ) -> PersistCursors:
        """Write changed rows since the previous flush.

        Append-only tables (ping/site/accessibility/router/speed) skip rows
        with ts <= the corresponding cursor. Mutable tables (outages,
        degraded, daily_summary, provider_uptime, dismissed_ids) are full-
        replaced under the same transaction, which is cheap because they
        are small.
        """
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
                        "INSERT OR IGNORE INTO ping_samples(ts, ping_ms) VALUES (?, ?)",
                        new_pings,
                    )
                    new_cursors.ping = max(ts for ts, _ in new_pings)

                new_access = [
                    (ts, v) for ts, v in accessibility_samples if ts > cursors.accessibility
                ]
                if new_access:
                    cur.executemany(
                        "INSERT OR IGNORE INTO accessibility_samples(ts, pct_accessible) VALUES (?, ?)",
                        new_access,
                    )
                    new_cursors.accessibility = max(ts for ts, _ in new_access)

                for host, samples in site_samples.items():
                    prev = cursors.site.get(host, "")
                    new_site = [(ts, host, v) for ts, v in samples if ts > prev]
                    if new_site:
                        cur.executemany(
                            "INSERT OR IGNORE INTO site_samples(ts, host, ping_ms) VALUES (?, ?, ?)",
                            new_site,
                        )
                        new_cursors.site[host] = max(ts for ts, _, _ in new_site)

                new_speed = [
                    s for s in speed_samples if s["timestamp"] > cursors.speed
                ]
                if new_speed:
                    cur.executemany(
                        "INSERT OR IGNORE INTO speed_samples"
                        "(ts, download_mbps, upload_mbps, ping_ms, label, provider)"
                        " VALUES (?, ?, ?, ?, ?, ?)",
                        [
                            (
                                s["timestamp"],
                                s["download_mbps"],
                                s["upload_mbps"],
                                s["ping_ms"],
                                s.get("label", ""),
                                s.get("provider", ""),
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
                        "INSERT INTO daily_summary(date, uptime_pct, p10, p50, p90) "
                        "VALUES (?, ?, ?, ?, ?) "
                        "ON CONFLICT(date) DO UPDATE SET "
                        "  uptime_pct = excluded.uptime_pct, "
                        "  p10 = excluded.p10, p50 = excluded.p50, p90 = excluded.p90",
                        [
                            (
                                e["date"],
                                e.get("uptime_pct"),
                                e.get("p10"),
                                e.get("p50"),
                                e.get("p90"),
                            )
                            for e in daily_summary
                        ],
                    )

                # provider_uptime — full replace (small dict)
                cur.execute("DELETE FROM provider_uptime")
                if provider_uptime_secs:
                    cur.executemany(
                        "INSERT INTO provider_uptime(provider, secs, color) VALUES (?, ?, ?)",
                        [
                            (p, float(s), provider_colors.get(p))
                            for p, s in provider_uptime_secs.items()
                        ],
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
