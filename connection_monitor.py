#!/usr/bin/env python3
"""
connection_monitor.py — Internet Connection Monitor (Web Dashboard)

Monitors connectivity and speed, serving a live dashboard at:
  http://localhost:8765

Usage:  python3 connection_monitor.py
Stop:   Ctrl+C
"""

import sys
import os
import time
import threading
import socket
import json
import urllib.request
import urllib.error
import logging
import statistics
import subprocess
import hmac
import secrets
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────────────────────
# Timestamped logs
#   Prefix every stdout/stderr line + every `logging` record with an
#   ISO-ish local timestamp so monitor.out.log / monitor.err.log are
#   readable after the fact. Done at import time so even early prints
#   (e.g. the "Installing flask…" line) are stamped.
# ─────────────────────────────────────────────────────────────
class _TimestampedStream:
    """File-like wrapper that prepends a timestamp to each output line."""
    def __init__(self, stream):
        self._stream = stream
        self._at_line_start = True

    def write(self, data):
        if not data:
            return 0
        # Some libraries (click) write bytes; pass those through unchanged
        # rather than try to timestamp them — iterating bytes yields ints
        # which would crash this wrapper.
        if not isinstance(data, str):
            try:
                return self._stream.write(data)
            except TypeError:
                # underlying stream is text-mode; decode best-effort
                return self._stream.write(data.decode("utf-8", "replace"))
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{ts}] "
        out_parts = []
        for ch in data:
            if self._at_line_start and ch != "\n":
                out_parts.append(prefix)
                self._at_line_start = False
            out_parts.append(ch)
            if ch == "\n":
                self._at_line_start = True
        self._stream.write("".join(out_parts))
        return len(data)

    def flush(self):
        self._stream.flush()

    def isatty(self):
        return getattr(self._stream, "isatty", lambda: False)()

    def __getattr__(self, name):
        return getattr(self._stream, name)


sys.stdout = _TimestampedStream(sys.stdout)
sys.stderr = _TimestampedStream(sys.stderr)

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s",
)


# ─────────────────────────────────────────────────────────────
# Auto-install Flask
# ─────────────────────────────────────────────────────────────
def _pip_install(pkg: str) -> None:
    # In an immutable container (or any locked-down deploy) we must never
    # pip-install at runtime — dependencies come from the image's
    # requirements.txt. NO_AUTO_INSTALL=1 (set in the Dockerfile) turns the
    # convenience auto-install into a clear, fail-fast error. Native installs
    # leave it unset and keep the auto-install behaviour.
    if os.environ.get("NO_AUTO_INSTALL", "").lower() in ("true", "1", "yes"):
        sys.stderr.write(
            f"Missing dependency {pkg!r} and NO_AUTO_INSTALL is set. "
            f"Install dependencies with: pip install -r requirements.txt\n"
        )
        sys.exit(1)
    import subprocess
    print(f"Installing {pkg!r}…", flush=True)
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-q", pkg],
        stdout=subprocess.DEVNULL,
    )

try:
    from flask import Flask, jsonify, request, session, redirect, Response
except ImportError:
    _pip_install("flask")
    from flask import Flask, jsonify, request, session, redirect, Response
# Werkzeug ships with Flask; its security helpers give a salted KDF for
# password hashing (no extra dependency, no hand-rolled crypto).
from werkzeug.security import generate_password_hash, check_password_hash

# Load configuration from connection_monitor.env (next to this script) before
# reading any constants. Existing shell environment variables take precedence —
# load_dotenv() only fills in values that aren't already set.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE   = os.path.join(SCRIPT_DIR, "connection_monitor.env")
try:
    from dotenv import load_dotenv
except ImportError:
    _pip_install("python-dotenv")
    from dotenv import load_dotenv
if os.path.exists(ENV_FILE):
    load_dotenv(ENV_FILE)

from lib import router_log
from lib import ai_diagnosis
from lib import db

# Optional: speedtest-cli for more accurate measurements
try:
    import speedtest as _st
    SPEEDTEST_AVAILABLE = True
except ImportError:
    SPEEDTEST_AVAILABLE = False

PORT = int(os.environ.get("PORT", "8765"))
# Interface the dashboard binds to. Defaults to loopback so a fresh install is
# NOT silently exposed to the whole LAN (and so a VPS deployment only accepts
# connections via its local nginx reverse proxy). Set BIND_HOST=0.0.0.0 to allow
# access from other devices on your network — pair that with DASHBOARD_USER/PASS.
BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")
DB_FILE      = os.path.join(SCRIPT_DIR, "var", "connection_monitor.db")
CONFIG_FILE  = os.path.join(SCRIPT_DIR, "ping_targets.conf")
_24H = timedelta(hours=24)
_30D = timedelta(days=30)

# Router log scraping (all values from connection_monitor.env or shell env).
GATEWAY_URL            = os.environ.get("GATEWAY_URL", "")
ROUTER_PACKET_LOG_PATH = os.environ.get("ROUTER_PACKET_LOG_PATH", "")
ROUTER_SYSLOG_PATH     = os.environ.get("ROUTER_SYSLOG_PATH", "")
ROUTER_POLL_INTERVAL   = int(os.environ.get("ROUTER_POLL_INTERVAL", "30"))

# ── Multi-host / VPS sync ──────────────────────────────────────
SERVER_URL             = os.environ.get("SERVER_URL", "").rstrip("/")
INGEST_API_KEY         = os.environ.get("INGEST_API_KEY", "")
DASHBOARD_USER         = os.environ.get("DASHBOARD_USER", "")
DASHBOARD_PASS         = os.environ.get("DASHBOARD_PASS", "")
DISABLE_SPEED_TESTS    = os.environ.get("DISABLE_SPEED_TESTS", "").lower() in ("true", "1", "yes")
MONITOR_HOST           = os.environ.get("MONITOR_HOST", "") or socket.gethostname()
AGGREGATOR             = os.environ.get("AGGREGATOR", "").lower() in ("true", "1", "yes")

# ── Multi-tenant accounts (cloud/server role) ──────────────────
# When enabled, the dashboard requires a per-user email+password login and
# the legacy single-shared-password Basic Auth (DASHBOARD_USER/PASS) is not
# used. Off by default so standalone/agent installs keep their simple,
# loopback-only, no-login dashboard.
MULTI_TENANT           = os.environ.get("MULTI_TENANT", "").lower() in ("true", "1", "yes")
# Invite code required to register an account. Blank = registration closed
# (accounts must already exist). Share this with friends so strangers who
# find the URL can't sign themselves up.
SIGNUP_CODE            = os.environ.get("SIGNUP_CODE", "")
# Secret used to sign session cookies. If unset, a random one is generated
# once and persisted in the DB (meta table) so logins survive restarts.
SECRET_KEY             = os.environ.get("SECRET_KEY", "")

# Degraded-period detection thresholds (tuning knobs, not deployment config).
# ─────────────────────────────────────────────────────────────
# Outage / degradation definitions (single source of truth)
# ─────────────────────────────────────────────────────────────
# An OUTAGE is a complete blackout: all 3 DNS-port probes (8.8.8.8, 1.1.1.1,
# 208.67.222.222) fail in a single 2-second probe cycle. Resolves on the next
# successful probe; "true return to normal" (recovery_end) additionally
# requires speed and ping signals back to baseline (computed in ai_diagnosis).
#
# DEGRADATION is a brownout — service responds but quality is below baseline.
# Three independent signals can open a degraded period; each closes on its own
# streak rule. Open rules are strict (so we only flag genuine degradation);
# close rules are generous (so periods clear once we're "out of the bad tail"
# rather than requiring full restoration to the median).
#
# Slow:
#   Open  — single speed sample with dl < 7d-P10 (true tail of recent
#           experience: a sample worse than 90% of the last week).
#   Close — SLOW_CLOSE_STREAK consecutive non-Outage samples ≥ 7d-P10.
#
# High ping:
#   Open  — rolling p90 of last 30 connectivity probes (≈60s @ 2s) ≥
#           max(HIGH_PING_FLOOR_MS, HIGH_PING_OPEN_MULT × 7d median ping),
#           sustained for HIGH_PING_DURATION_S.
#   Close — HIGH_PING_CLOSE_STREAK consecutive non-None pings ≤ 7d-P90. A
#           None probe (failed connectivity) breaks the streak.
#
# SITE LOSS is a distinct class — a specific site is unreachable while
# everything else looks fine. Surfaced in teal so it visually reads as
# "this isn't your internet, it's that one service":
#   Open  — a tracked site has SITE_LOSS_OPEN_STREAK consecutive failed
#           TCP:443 checks (≈30s of loss at the 10s site-check cadence) AND
#           there is no concurrent outage / slow / high_ping period (those
#           subsume site flakiness already).
#   Close — that site has SITE_LOSS_CLOSE_STREAK consecutive successful
#           checks (≈60s clean).
SLOW_MIN_HISTORY     = 5      # need at least N prior samples to use percentiles
# High-ping detection. The trigger compares the rolling p90 of the last 30
# connectivity probes against max(HIGH_PING_FLOOR_MS, 7d-P{HIGH_PING_BASELINE_PCT}).
# P99 (default) makes the threshold "your normal worst" — self-calibrating
# across networks. The floor protects users with very fast baselines so a
# trivial 50ms ping doesn't get flagged.
# Both knobs are env-overridable so a user with a noisier baseline can dial
# down (P95) or up (P99.5) without code edits.
try:
    HIGH_PING_FLOOR_MS = float(os.environ.get("HIGH_PING_FLOOR_MS", "75"))
except ValueError:
    HIGH_PING_FLOOR_MS = 75.0

# Site-tile verdict thresholds. Each site is graded relative to the union of
# all sites' successful pings over the baseline window (24h, falling back to
# 7d when 24h has fewer than SITE_VERDICT_MIN_SAMPLES). The percentile knobs
# define the band edges; the reachability knobs are independent floors.
# Final verdict = worst of (latency_band, reachability_band).
def _env_pct(key: str, default: float) -> float:
    try:
        return max(0.0, min(100.0, float(os.environ.get(key, str(default)))))
    except ValueError:
        return float(default)
def _env_int(key: str, default: int) -> int:
    try:
        return max(1, int(float(os.environ.get(key, str(default)))))
    except ValueError:
        return int(default)

SITE_VERDICT_BASELINE_HOURS = _env_int("SITE_VERDICT_BASELINE_HOURS", 24)
SITE_VERDICT_FALLBACK_HOURS = _env_int("SITE_VERDICT_FALLBACK_HOURS", 24 * 7)
SITE_VERDICT_MIN_SAMPLES    = _env_int("SITE_VERDICT_MIN_SAMPLES", 200)
SITE_VERDICT_GREAT_PCT  = _env_pct("SITE_VERDICT_GREAT_PCT", 10)
SITE_VERDICT_SLOW_PCT   = _env_pct("SITE_VERDICT_SLOW_PCT",  90)
SITE_VERDICT_POOR_PCT   = _env_pct("SITE_VERDICT_POOR_PCT",  99)
SITE_VERDICT_GREAT_REACH = _env_pct("SITE_VERDICT_GREAT_REACH", 99)
SITE_VERDICT_OK_REACH    = _env_pct("SITE_VERDICT_OK_REACH",    95)
SITE_VERDICT_SLOW_REACH  = _env_pct("SITE_VERDICT_SLOW_REACH",  80)
try:
    HIGH_PING_BASELINE_PCT = max(50.0, min(99.9, float(
        os.environ.get("HIGH_PING_BASELINE_PCT", "99"))))
except ValueError:
    HIGH_PING_BASELINE_PCT = 99.0
HIGH_PING_MIN_BASELINE_SAMPLES = 1000  # need this many probes before P99 is meaningful
HIGH_PING_BASELINE_TTL_S       = 60    # cache P99 calc; recompute at most once/min
HIGH_PING_DURATION_S = 60     # sustained-condition window for opening
SLOW_OPEN_STREAK          = 2   # consecutive non-Outage samples below 7d-P10
                                # required to OPEN slow (sustainment, ≈10min @
                                # 5min cadence) — prevents single-sample blips
                                # from tripping the detector
SLOW_CLOSE_STREAK         = 3   # samples (≈15min @ 5min cadence)
HIGH_PING_CLOSE_STREAK    = 30  # probes (≈60s @ 2s)
SITE_LOSS_OPEN_STREAK     = 3   # consecutive failed checks (≈30s @ 10s)
SITE_LOSS_CLOSE_STREAK    = 6   # consecutive successful checks (≈60s @ 10s)
# Outage open requires sustained connectivity loss — single failed cycles
# (Wi-Fi roam, brief gateway flap, laptop wake artifact) shouldn't show up
# as outage records on the timeline. The OutageRecord's start is backdated
# to the FIRST failure in the streak so timing stays honest.
OUTAGE_OPEN_STREAK        = 4   # consecutive failed probe cycles (≈8s @ 2s)

# Speed-test scheduling — fixed wall-clock slots, never drifting. The 10/25/40/55
# pattern keeps tests every 15 minutes and intentionally avoids the xx:00–xx:05
# window where Ookla's hourly cron-aligned load tends to fail. Exceptions:
# (a) HTTP fallback always runs immediately when primary fails; (b) during an
# active outage the speed-test thread records a 0-Mbps sample every 60s
# instead of running a real test. The aligned cadence resumes after either.
SPEED_TEST_SLOTS = (10, 25, 40, 55)

# Monitor-downtime gap rendering. The detection floor is 120s (any
# inter-heartbeat delta above that = "process not writing"); the report
# floor below decides which detected gaps actually surface as dim segments
# on the timeline.
#
# Default 60 min: macOS App Nap regularly fully-suspends background python
# processes for 15–30 min at a stretch overnight; those windows are real
# "process was suspended" but rarely interesting to a user reviewing their
# uptime ("yes, my Mac was asleep, I knew that"). Raising the report floor
# above the typical App Nap envelope keeps the feature focused on its
# original purpose: flagging genuine script crashes / long away-from-keyboard
# windows / laptop-fully-asleep stretches measured in hours.
#
# Override at launch with env var MONITOR_GAP_MIN_REPORT_MIN=<minutes>; set
# to a low value (e.g. 5) on always-on machines where any gap is news.
try:
    MONITOR_GAP_MIN_REPORT_S = max(0, int(float(
        os.environ.get("MONITOR_GAP_MIN_REPORT_MIN", "60")
    ) * 60))
except ValueError:
    MONITOR_GAP_MIN_REPORT_S = 60 * 60   # fallback default: 60 minutes

_DEFAULT_PING_TARGETS = [
    "netflix.com",
    "disneyplus.com",
    "primevideo.com",
    "outlook.office365.com",
    "google.com",
    "youtube.com",
    "spotify.com",
    "amazon.com",
]

def _friendly_name(host: str) -> str:
    """Auto-generate a display name from a hostname (fallback when conf has no name)."""
    h = host.removeprefix("www.")
    return h.split(".")[0].replace("-", " ").title()

def load_ping_targets() -> Tuple[List[str], Dict[str, str]]:
    """Load site ping targets and optional friendly names from config file.

    Each non-comment line is:  hostname [whitespace friendly name]
    Returns (list_of_hostnames, dict_of_hostname_to_name).
    """
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            f.write(
                "# Connection Monitor — site targets\n"
                "#\n"
                "# One entry per line. Format:\n"
                "#   hostname\n"
                "#   hostname  Friendly Name\n"
                "#\n"
                "# Everything after the first whitespace is used as the display name.\n"
                "# If no name is given, one is generated from the hostname.\n"
                "# Lines starting with # are ignored.\n\n"
            )
            for t in _DEFAULT_PING_TARGETS:
                f.write(t + "\n")
        return list(_DEFAULT_PING_TARGETS), {}

    targets: List[str] = []
    names: Dict[str, str] = {}
    with open(CONFIG_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)   # split on first whitespace only
            host = parts[0]
            targets.append(host)
            if len(parts) == 2:
                names[host] = parts[1].strip()

    if not targets:
        return list(_DEFAULT_PING_TARGETS), {}
    return targets, names


# ─────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────
@dataclass
class SpeedSample:
    timestamp: datetime
    download_mbps: float
    upload_mbps: float
    ping_ms: float
    label: str = ""
    network: str = ""


@dataclass
class OutageRecord:
    start: datetime
    end: Optional[datetime] = None

    @property
    def duration(self) -> timedelta:
        return (self.end or datetime.now()) - self.start

    @property
    def duration_str(self) -> str:
        s = int(self.duration.total_seconds())
        if s < 60:
            return f"{s}s"
        return f"{s // 60}m {s % 60:02d}s"

    @property
    def ongoing(self) -> bool:
        return self.end is None

    @property
    def id(self) -> str:
        # Stable identifier — pinned to the start instant. If an in-progress
        # outage's start ever shifted (which it doesn't), this would change.
        return "out:" + self.start.isoformat(timespec="seconds")


@dataclass
class DegradedPeriod:
    start: datetime
    kind: str   # "slow" | "high_ping"
    end: Optional[datetime] = None
    detail: str = ""

    @property
    def ongoing(self) -> bool:
        return self.end is None

    @property
    def id(self) -> str:
        return f"deg:{self.kind}:" + self.start.isoformat(timespec="seconds")


# ─────────────────────────────────────────────────────────────
# Shared state (thread-safe)
# ─────────────────────────────────────────────────────────────
class MonitorState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = True

        # Connectivity
        self.connected: bool = True
        self.last_ping_ms: Optional[float] = None
        self.ping_history: deque = deque(maxlen=60)
        # Connectivity probe latencies, retained 30 days at 2s cadence so AI
        # diagnoses run on older incidents have full ping data. ~50 MB on disk.
        self.ping_history_ts: deque = deque(maxlen=1_400_000)  # 30d @ 2s + headroom

        # Outages
        self.outages: List[OutageRecord] = []
        self.current_outage: Optional[OutageRecord] = None

        # Speeds
        self.speed_history: List[SpeedSample] = []
        self.speed_in_progress: bool = False
        self.speed_status: str = ""
        self.last_speed_test: Optional[datetime] = None    # last attempt (success or fail)
        self.last_speed_success: Optional[datetime] = None # last successful result
        # Vestigial — kept for backwards-compat with any persisted snapshot
        # that referenced it. Active scheduling now uses SPEED_TEST_SLOTS.
        self.speed_interval_secs: int = 900                # 15 min nominal
        self.trigger_post_outage_test: bool = False

        # Events
        self.events: deque = deque(maxlen=500)

        # Multi-site accessibility
        self.site_targets, self.site_names = load_ping_targets()
        self.site_states: Dict[str, bool] = {}          # hostname -> currently up?
        self.current_site_outages: Dict[str, OutageRecord] = {}
        self.site_outages: List[Tuple[str, OutageRecord]] = []
        # parallel history to ping_history_ts: (iso_ts, pct_accessible).
        # 10s cadence × 30d = ~260k entries.
        self.ping_accessibility_ts: deque = deque(maxlen=270_000)
        # per-site latency history: hostname -> deque of (iso_ts, ms_or_None).
        # 10s cadence × 30d = ~260k entries per host. With ~12 hosts that's
        # ~75 MB on disk, the bulk of the long-term ping retention budget.
        self.site_ping_history: Dict[str, deque] = {}

        # Network
        self.current_network: str = ""
        self.network_uptime_secs: Dict[str, float] = {}
        self.network_start_time: Dict[str, datetime] = {}
        self.network_colors: Dict[str, str] = {}
        self.network_changes: deque = deque(maxlen=200)
        self._network_color_palette: List[str] = [
            "#58a6ff", "#3fb950", "#bc8cff", "#39c5cf",
            "#d29922", "#f85149", "#e3b341", "#79c0ff",
        ]

        # Daily history (7-day uptime chart)
        self.daily_history: List[Dict] = []

        # Degraded periods (yellow on timeline)
        self.degraded_periods: deque = deque(maxlen=2000)
        self.current_slow: Optional[DegradedPeriod] = None
        self.current_high_ping: Optional[DegradedPeriod] = None
        # Per-host site_loss DegradedPeriods — keyed by hostname so multiple
        # sites can be in site_loss simultaneously without stomping each other.
        self.current_site_loss: Dict[str, DegradedPeriod] = {}
        # Rolling latency window for high-ping detection (last 30 samples ≈ 60s @ 2s)
        self._recent_pings: deque = deque(maxlen=30)
        self._high_ping_started_above: Optional[datetime] = None
        self._high_ping_below_since: Optional[datetime] = None
        # Streak counters for percentile-based open / close criteria.
        # Slow open is also streak-based now to filter single-sample blips.
        self._slow_open_streak: int = 0
        self._slow_open_first_at: Optional[datetime] = None
        self._slow_close_streak: int = 0
        self._high_ping_close_streak: int = 0
        # Cached P99 of recent connectivity-probe pings (used by high-ping
        # detector). Recomputed at most once every HIGH_PING_BASELINE_TTL_S
        # because the calc walks ~190k samples on a 30d-retained network.
        self._high_ping_baseline_ms: Optional[float] = None
        self._high_ping_baseline_at: Optional[datetime] = None
        # Per-host streaks for site_loss open/close.
        self._site_fail_streaks: Dict[str, int] = {}
        self._site_pass_streaks: Dict[str, int] = {}
        # Sustained-failure tracking for outage opens.
        self._outage_fail_streak: int = 0
        self._outage_first_failure_at: Optional[datetime] = None
        # Speed-test attempt counters (primary = speedtest-cli; fallback =
        # built-in HTTP). The chart shows the rolling primary success count.
        self.speed_attempts: List[Dict] = []   # rolling list of attempt dicts
        # Set by run_speed_test when primary fails; speed_test_thread uses
        # this to back off retries past the top-of-hour failure window.
        self._primary_failed_at: Optional[datetime] = None
        # Rolling list of recent primary-speedtest failure dicts —
        # {ts, type, code, phase, msg}. Surfaced via /api/state so the
        # dashboard / API can show "last failure was a 429 at top of hour."
        # Cap small; this is for spot-checking, not full history.
        self.primary_fail_reasons: deque = deque(maxlen=50)

        # Router log scraper — stores router_log.RouterEvent objects
        # Sized for 30 days at ~500 events/hour observed peak rate. At ~176
        # bytes/event JSON, the persisted router_events array is ~35–60 MB —
        # well within "local-disk OK" territory. Time-based pruning (drop
        # > 30d) runs each save tick, so the deque rarely approaches maxlen.
        self.router_events: deque = deque(maxlen=400_000)
        self.last_router_poll: Optional[datetime] = None
        self.router_poll_error: Optional[str] = None
        self._router_warned_at: Optional[datetime] = None

        # AI diagnosis — rolling 30-day history, newest first.
        # Each entry is the dict returned by ai_diagnosis.diagnose() with an
        # added "id" field (millisecond timestamp string).
        self.diagnoses: deque = deque(maxlen=500)
        self.diagnosis_in_progress: bool = False
        # Cluster IDs (e.g., "cluster:2026-05-04T19:00:55") the user has
        # dismissed after reviewing the AI analysis. Hidden from the
        # timeline + history by default; a "show dismissed" toggle reveals
        # them again. Persisted across restarts.
        self.dismissed_outage_ids: set = set()

        # Timing
        self.start_time: datetime = datetime.now()
        # Earliest time we have data for. Persisted across restarts so that the
        # timeline's "no data" shading reflects when the monitor was first
        # installed, not the most recent process boot.
        self.first_seen: datetime = self.start_time

    def log(self, msg: str, level: str = "info") -> None:
        ts = datetime.now().isoformat(timespec="seconds")
        with self.lock:
            self.events.appendleft((ts, level, msg))

    def assign_network_color(self, network: str) -> str:
        """Return (and cache) a stable color for this network. Call with lock held."""
        if network not in self.network_colors:
            idx = len(self.network_colors) % len(self._network_color_palette)
            self.network_colors[network] = self._network_color_palette[idx]
        return self.network_colors[network]

    def avg_ping(self) -> Optional[float]:
        with self.lock:
            if not self.ping_history:
                return None
            return sum(self.ping_history) / len(self.ping_history)

    def all_network_uptimes(self) -> Dict[str, float]:
        with self.lock:
            now = datetime.now()
            result: Dict[str, float] = dict(self.network_uptime_secs)
            if self.current_network and self.current_network in self.network_start_time:
                result[self.current_network] = result.get(self.current_network, 0.0) + (
                    now - self.network_start_time[self.current_network]
                ).total_seconds()
            return result

    def total_outage_secs(self) -> float:
        with self.lock:
            total = sum(
                (o.end - o.start).total_seconds()
                for o in self.outages
                if o.end
            )
            if self.current_outage:
                total += (datetime.now() - self.current_outage.start).total_seconds()
            return total

    @staticmethod
    def _fmt_dur(secs: float) -> str:
        s = int(secs)
        minutes, sec = divmod(s, 60)
        hours, minute = divmod(minutes, 60)
        days, hour = divmod(hours, 24)
        total_weeks, day = divmod(days, 7)
        months, week = divmod(total_weeks, 4)

        if months:
            return f"{months}mo {week}w" if week else f"{months}mo"
        if total_weeks:
            return f"{total_weeks}w {day}d" if day else f"{total_weeks}w"
        if days:
            return f"{days}d {hour}h"
        if hours:
            return f"{hours}h {minute:02d}m"
        if minutes:
            return f"{minutes}m {sec:02d}s"
        return f"{sec}s"

    def to_dict(self) -> dict:
        """Serialize state to a JSON-safe dict for the API."""
        with self.lock:
            connected        = self.connected
            last_ping        = self.last_ping_ms
            ping_hist        = list(self.ping_history)
            ping_ts          = list(self.ping_history_ts)
            access_ts        = list(self.ping_accessibility_ts)
            speed_history    = list(self.speed_history)
            outages          = list(self.outages)
            cur_out          = self.current_outage
            in_progress       = self.speed_in_progress
            speed_status      = self.speed_status
            last_speed_test   = self.last_speed_test
            last_speed_success = self.last_speed_success
            events           = list(self.events)
            start_time       = self.start_time
            current_network = self.current_network
            network_colors  = dict(self.network_colors)
            site_targets_snap = list(self.site_targets)[:12]
            site_names_snap   = dict(self.site_names)
            site_ping_hist_snap = {
                h: list(self.site_ping_history.get(h, []))
                for h in site_targets_snap
            }
            site_states_snap = dict(self.site_states)
            daily_history_snap = list(self.daily_history)
            router_events_snap = list(self.router_events)
            router_poll_error_snap = self.router_poll_error
            last_router_poll_snap = self.last_router_poll
            last_diagnosis_snap = self.diagnoses[0] if self.diagnoses else None
            speed_attempts_snap = list(self.speed_attempts)

        now = datetime.now()
        runtime_secs = (now - start_time).total_seconds()
        avg_p = (sum(ping_hist) / len(ping_hist)) if ping_hist else None
        network_uptimes = self.all_network_uptimes()
        total_out = self.total_outage_secs()
        all_outages = outages + ([cur_out] if cur_out else [])

        # Aligned cadence: if we haven't yet completed the most recent
        # scheduled slot, the next test is "now" (0); otherwise it's the
        # countdown to the next slot.
        next_test_in = None
        if not in_progress:
            prev_slot = _previous_scheduled_slot(now)
            next_slot = _next_scheduled_slot(now)
            if last_speed_test is None or last_speed_test < prev_slot:
                next_test_in = 0
            else:
                next_test_in = max(0, (next_slot - now).total_seconds())

        # Current uptime: time since last outage ended (or since start if none)
        if cur_out:
            current_uptime_secs = 0.0
        else:
            last_end = max((o.end for o in outages if o.end), default=None)
            since = last_end if last_end else start_time
            current_uptime_secs = (now - since).total_seconds()

        # 5-minute slices (before downsampling)
        # ping_ts is sorted (ts_str, value) tuples; bisect on the tuple list
        # using a 1-element sentinel — shorter tuple is always < any matching
        # 2-element tuple, so this finds the first entry with ts >= cutoff.
        import bisect as _bisect
        cutoff_1h = now - timedelta(hours=1)
        cutoff_5m = now - timedelta(minutes=5)
        _cutoff_5m_iso = cutoff_5m.isoformat()
        _5m_start = _bisect.bisect_left(ping_ts, (_cutoff_5m_iso,))
        ping_ts_5m = ping_ts[_5m_start:]

        # Downsample 24h ping to max 300 points for chart performance
        MAX_PING_CHART = 300
        ping_ts_all = ping_ts  # keep full list for hourly percentile calc
        if len(ping_ts) > MAX_PING_CHART:
            step = len(ping_ts) / MAX_PING_CHART
            ping_ts = [ping_ts[int(i * step)] for i in range(MAX_PING_CHART)]

        def _percentile(sorted_vals: List[float], p: float) -> float:
            n = len(sorted_vals)
            if n == 1:
                return sorted_vals[0]
            idx = p / 100 * (n - 1)
            lo, hi = int(idx), min(int(idx) + 1, n - 1)
            return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo)

        # Rolling 24-hour ping+accessibility buckets — 24 complete past hours
        # ending at the current top-of-hour, ordered chronologically. The old
        # implementation bucketed by hour-of-day, which collapsed pings from
        # the same clock hour on different days and rendered the chart out of
        # order (e.g. 12am-2pm on the left, yesterday's 3pm-11pm on the right).
        # Excluding the current partial hour leaves a visible gap between the
        # 24h chart's last bucket and the 5m chart's first sample.
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        first_slot_start = current_hour - timedelta(hours=24)
        # ping_ts_all is sorted (ts_str, value) tuples; bisect directly on the
        # tuple list to find the 24h window start — O(log N), no key copy.
        import bisect as _bisect
        first_slot_iso = first_slot_start.isoformat()
        _slot_start_idx = _bisect.bisect_left(ping_ts_all, (first_slot_iso,))
        ping_ts_24h = ping_ts_all[_slot_start_idx:]
        ping_buckets: List[List[float]] = [[] for _ in range(24)]
        access_buckets: List[List[float]] = [[] for _ in range(24)]
        for ts_str, v in ping_ts_24h:
            try:
                dt = datetime.fromisoformat(ts_str)
            except ValueError:
                continue
            if dt >= current_hour:
                break
            idx = int((dt - first_slot_start).total_seconds() // 3600)
            if 0 <= idx < 24:
                ping_buckets[idx].append(v)
        # Slice access_ts to the same 24h window — bisect on tuples directly.
        _access_start_idx = _bisect.bisect_left(access_ts, (first_slot_iso,))
        access_ts_24h = access_ts[_access_start_idx:]
        for ts_str, p in access_ts_24h:
            try:
                dt = datetime.fromisoformat(ts_str)
            except ValueError:
                continue
            if dt < first_slot_start or dt >= current_hour:
                continue
            idx = int((dt - first_slot_start).total_seconds() // 3600)
            if 0 <= idx < 24:
                access_buckets[idx].append(p)

        ping_hourly = []
        for i in range(24):
            slot_start = first_slot_start + timedelta(hours=i)
            h_int = slot_start.hour
            hour_label = f"{h_int % 12 or 12}{'am' if h_int < 12 else 'pm'}"
            pv = sorted(ping_buckets[i])
            if pv:
                p10 = round(_percentile(pv, 10), 1)
                p50 = round(_percentile(pv, 50), 1)
                p90 = round(_percentile(pv, 90), 1)
            else:
                p10 = p50 = p90 = None
            av = access_buckets[i]
            access_pct = round(sum(av) / len(av), 1) if av else None
            ping_hourly.append({
                "hour":   hour_label,
                "p10":    p10,
                "p50":    p50,
                "p90":    p90,
                "access": access_pct,
            })

        # Filter speed history to last 24 hours only
        cutoff_24h = now - timedelta(hours=24)
        speed_history = [s for s in speed_history if s.timestamp >= cutoff_24h]
        speed_history_5m = [s for s in speed_history if s.timestamp >= cutoff_5m]
        speed_history_1h = [s for s in speed_history if s.timestamp >= cutoff_1h]

        # Build 24 complete past hourly speed buckets with p10/p50/p90
        current_hour = now.replace(minute=0, second=0, microsecond=0)
        speed_hourly = []
        for h in range(24, 0, -1):
            slot_start = current_hour - timedelta(hours=h)
            slot_end   = slot_start + timedelta(hours=1)
            tests = [s for s in speed_history if slot_start <= s.timestamp < slot_end]
            if tests:
                dls = sorted(s.download_mbps for s in tests)
                uls = sorted(s.upload_mbps   for s in tests)
                dl_p10 = round(_percentile(dls, 10), 1)
                dl_p90 = round(_percentile(dls, 90), 1)
                dl_max = round(dls[-1], 1)
                ul_p10 = round(_percentile(uls, 10), 1)
                ul_p90 = round(_percentile(uls, 90), 1)
                ul_max = round(uls[-1], 1)
                network = tests[-1].network
            else:
                dl_p10 = dl_p90 = dl_max = None
                ul_p10 = ul_p90 = ul_max = None
                network = None
            h_int = slot_start.hour
            speed_hourly.append({
                "hour":        f"{h_int % 12 or 12}{'am' if h_int < 12 else 'pm'}",
                "dl_p10":      dl_p10,
                "dl_p10_90d":  round(max(0, dl_p90 - dl_p10), 1) if dl_p10 is not None else None,
                "dl_p90_maxd": round(max(0, dl_max - dl_p90), 1) if dl_p90 is not None else None,
                "dl_p90":      dl_p90,
                "dl_max":      dl_max,
                "ul_p10":      ul_p10,
                "ul_p10_90d":  round(max(0, ul_p90 - ul_p10), 1) if ul_p10 is not None else None,
                "ul_p90_maxd": round(max(0, ul_max - ul_p90), 1) if ul_p90 is not None else None,
                "ul_p90":      ul_p90,
                "ul_max":      ul_max,
                "network":     network,
            })

        # Most recent individual test result (bar 25 on combined chart)
        speed_latest = None
        if speed_history:
            latest = speed_history[-1]
            v_dl = round(latest.download_mbps, 1)
            v_ul = round(latest.upload_mbps,   1)

            # Perf colour: compare latest vs 1h history (excl. the latest itself)
            def _perf(val, ref_vals):
                if len(ref_vals) < 2:
                    return "neutral"
                p33 = _percentile(ref_vals, 33)
                p67 = _percentile(ref_vals, 67)
                return "good" if val >= p67 else "ok" if val >= p33 else "poor"

            ref_dls_1h = sorted(s.download_mbps for s in speed_history_1h if s is not latest)
            ref_uls_1h = sorted(s.upload_mbps   for s in speed_history_1h if s is not latest)
            # Fall back to full 24h window if 1h has fewer than 2 reference points
            if len(ref_dls_1h) < 2:
                ref_dls_1h = sorted(s.download_mbps for s in speed_history if s is not latest)
                ref_uls_1h = sorted(s.upload_mbps   for s in speed_history if s is not latest)

            speed_latest = {
                "hour":        latest.timestamp.strftime("%H:%M"),
                "dl_p10":      v_dl, "dl_p10_90d": 0, "dl_p90_maxd": 0,
                "dl_p90":      v_dl, "dl_max": v_dl,
                "ul_p10":      v_ul, "ul_p10_90d": 0, "ul_p90_maxd": 0,
                "ul_p90":      v_ul, "ul_max": v_ul,
                "network":     latest.network,
                "is_latest":   True,
                "dl_perf":     _perf(v_dl, ref_dls_1h),
                "ul_perf":     _perf(v_ul, ref_uls_1h),
            }

        # ── Uptime % for last 24h ──────────────────────────────────
        window_start_24h = now - timedelta(hours=24)
        outage_secs_24h = 0.0
        for o in all_outages:
            o_start = max(o.start, window_start_24h)
            o_end   = min(o.end if o.end else now, now)
            if o_end > o_start:
                outage_secs_24h += (o_end - o_start).total_seconds()
        window_secs = min(runtime_secs, 86400.0)
        uptime_pct_24h = round(
            max(0.0, (window_secs - outage_secs_24h) / window_secs * 100), 2
        ) if window_secs > 0 else 100.0

        # ── Per-site ping traffic board ────────────────────────────
        def _site_stats(entries):
            """Return (pct_returned, p10, p50, p90) for a list of (ts, ms_or_None)."""
            if not entries:
                return None, None, None, None
            total = len(entries)
            successes = sorted(ms for _, ms in entries if ms is not None)
            pct = round(len(successes) / total * 100, 1)
            if successes:
                p10 = round(_percentile(successes, 10), 1)
                p50 = round(_percentile(successes, 50), 1)
                p90 = round(_percentile(successes, 90), 1)
            else:
                p10 = p50 = p90 = None
            return pct, p10, p50, p90


        # Pool baseline for verdicts — shared with /api/site_history so the
        # modal threshold band cannot drift from the tile colors.
        _pool_thresh = _site_pool_thresholds(site_ping_hist_snap, now)
        ovr_p_great = _pool_thresh["great_ms"]
        ovr_p_slow  = _pool_thresh["slow_ms"]
        ovr_p_poor  = _pool_thresh["poor_ms"]
        pool_window_used = _pool_thresh["window_hours"]
        pool_sample_count = _pool_thresh["samples"]

        # Verdict ranking — used to take the worst of the two axes.
        _ORDER = {"GREAT": 0, "OK": 1, "SLOW": 2, "POOR": 3}
        _COLOR = {"GREAT": "s-green", "OK": "s-green",
                  "SLOW":  "s-yellow", "POOR": "s-red"}

        def _verdict_for(up: bool, pct: Optional[float], p50: Optional[float]
                         ) -> Tuple[Optional[str], str]:
            if not up:
                return "DOWN", "s-red"
            if pct is None or p50 is None or ovr_p_great is None:
                return None, ""
            # Latency band — pool-percentile based.
            if   p50 <= ovr_p_great: lat = "GREAT"
            elif p50 <= ovr_p_slow:  lat = "OK"
            elif p50 <= ovr_p_poor:  lat = "SLOW"
            else:                    lat = "POOR"
            # Reachability band.
            if   pct >= SITE_VERDICT_GREAT_REACH: reach = "GREAT"
            elif pct >= SITE_VERDICT_OK_REACH:    reach = "OK"
            elif pct >= SITE_VERDICT_SLOW_REACH:  reach = "SLOW"
            else:                                 reach = "POOR"
            worst = lat if _ORDER[lat] >= _ORDER[reach] else reach
            return worst, _COLOR[worst]

        site_matrix = []
        cutoff_5m_site  = now - timedelta(minutes=5)
        cutoff_1h_site  = now - timedelta(hours=1)
        cutoff_24h_site = now - timedelta(hours=24)
        _cut_24h_iso = cutoff_24h_site.isoformat()
        _cut_1h_iso  = cutoff_1h_site.isoformat()
        _cut_5m_iso  = cutoff_5m_site.isoformat()
        for host in site_targets_snap:
            hist = site_ping_hist_snap.get(host, [])
            # hist is sorted (ts_str, ms_or_None); bisect on tuples O(log N)
            h24h = hist[_bisect.bisect_left(hist, (_cut_24h_iso,)):]
            h1h  = h24h[_bisect.bisect_left(h24h, (_cut_1h_iso,)):]
            h5m  = h1h[_bisect.bisect_left(h1h,  (_cut_5m_iso,)):]
            p5m,  p10_5m,  p50_5m,  p90_5m  = _site_stats(h5m)
            p1h,  p10_1h,  p50_1h,  p90_1h  = _site_stats(h1h)
            p24h, p10_24h, p50_24h, p90_24h = _site_stats(h24h)
            up = site_states_snap.get(host, True)
            # Pick the freshest available window for the verdict's inputs.
            recent_pct = p5m if p5m is not None else p1h if p1h is not None else p24h
            recent_p50 = p50_5m if p50_5m is not None else p50_1h if p50_1h is not None else p50_24h
            verdict, verdict_class = _verdict_for(up, recent_pct, recent_p50)
            site_matrix.append({
                "host":    host,
                "name":    site_names_snap.get(host) or _friendly_name(host),
                "up":      up,
                "pct_5m":  p5m,  "p10_5m":  p10_5m,  "p50_5m":  p50_5m,  "p90_5m":  p90_5m,
                "pct_1h":  p1h,  "p10_1h":  p10_1h,  "p50_1h":  p50_1h,  "p90_1h":  p90_1h,
                "pct_24h": p24h, "p10_24h": p10_24h, "p50_24h": p50_24h, "p90_24h": p90_24h,
                "verdict": verdict,
                "verdict_class": verdict_class,
            })

        site_pool_thresholds = {
            "great_ms": ovr_p_great,
            "slow_ms":  ovr_p_slow,
            "poor_ms":  ovr_p_poor,
            "great_reach_pct": SITE_VERDICT_GREAT_REACH,
            "ok_reach_pct":    SITE_VERDICT_OK_REACH,
            "slow_reach_pct":  SITE_VERDICT_SLOW_REACH,
            "window_hours": pool_window_used,
            "samples":      pool_sample_count,
        }

        # Build 7-day calendar array for chart
        now_date = now.date()
        uptime_7d = []
        hist_by_date = {e["date"]: e for e in daily_history_snap}
        for d_offset in range(6, -1, -1):
            day = now_date - timedelta(days=d_offset)
            day_str = day.strftime("%Y-%m-%d")
            entry = hist_by_date.get(day_str)
            month = day.month
            dom = day.day
            date_label = f"{month}/{dom}"
            if entry:
                uptime_7d.append({
                    "label": day.strftime("%a"),
                    "date":  date_label,
                    "uptime_pct": entry["uptime_pct"],
                    "p10": entry["p10"], "p50": entry["p50"], "p90": entry["p90"],
                })
            else:
                uptime_7d.append({
                    "label": day.strftime("%a"),
                    "date":  date_label,
                    "uptime_pct": None, "p10": None, "p50": None, "p90": None,
                })

        return {
            "connected": connected,
            "last_ping_ms": round(last_ping, 1) if last_ping else None,
            "avg_ping_ms": round(avg_p, 1) if avg_p else None,
            "current_network": current_network,
            "monitor_host": socket.gethostname(),
            "runtime_secs": round(runtime_secs),
            "runtime_str": self._fmt_dur(runtime_secs),
            "current_uptime_str": self._fmt_dur(current_uptime_secs) if current_uptime_secs else None,
            "total_outage_secs": round(total_out),
            "outage_count": len(all_outages),
            "ping_chart": [
                {"t": t[11:19] if len(t) > 8 else t, "v": round(v, 1)}
                for t, v in ping_ts
            ],
            "ping_chart_5m": [
                {"t": t[11:19] if len(t) > 8 else t, "v": round(v, 1)}
                for t, v in ping_ts_5m
            ],
            "access_chart_5m": [
                {"t": t[11:19] if len(t) > 8 else t, "v": round(p, 1)}
                for t, p in access_ts
                if datetime.fromisoformat(t) >= cutoff_5m
            ],
            "ping_hourly": ping_hourly,
            "speed_hourly": speed_hourly,
            "speed_latest": speed_latest,
            "speed_history": [
                {
                    "timestamp": s.timestamp.strftime("%H:%M"),
                    "download_mbps": round(s.download_mbps, 1),
                    "upload_mbps": round(s.upload_mbps, 1),
                    "ping_ms": round(s.ping_ms, 1),
                    "label": s.label,
                    "network": s.network,
                }
                for s in speed_history
            ],
            "speed_history_5m": [
                {
                    "timestamp": s.timestamp.strftime("%H:%M:%S"),
                    "download_mbps": round(s.download_mbps, 1),
                    "upload_mbps": round(s.upload_mbps, 1),
                    "ping_ms": round(s.ping_ms, 1),
                    "label": s.label,
                    "network": s.network,
                }
                for s in speed_history_5m
            ],
            "outages": [
                {
                    "start": o.start.strftime("%H:%M:%S"),
                    "end": o.end.strftime("%H:%M:%S") if o.end else None,
                    "duration_str": o.duration_str,
                    "ongoing": o.ongoing,
                }
                for o in all_outages[-10:]
            ],
            "events": [
                {"ts": ts[11:19], "level": level, "msg": msg}
                for ts, level, msg in events
                if datetime.fromisoformat(ts) >= cutoff_1h
                and not msg.startswith("Speed [")
                and not msg.startswith("Speed: 0 Mbps")
            ][:20],
            "speed_history_1h": [
                {
                    "timestamp": s.timestamp.strftime("%H:%M"),
                    "download_mbps": round(s.download_mbps, 1),
                    "upload_mbps": round(s.upload_mbps, 1),
                    "ping_ms": round(s.ping_ms, 1),
                    "label": s.label,
                    "network": s.network,
                }
                for s in speed_history_1h
            ],
            "speed_in_progress": in_progress,
            "speed_status": speed_status,
            "next_test_in": int(next_test_in) if next_test_in is not None else None,
            "network_uptimes": {
                k: {"pct": min(100.0, round(v / runtime_secs * 100, 1)) if runtime_secs > 0 else 0.0}
                for k, v in network_uptimes.items()
            },
            "network_colors": network_colors,
            "network_names": _db.load_network_names(),
            "uptime_pct_24h": uptime_pct_24h,
            "site_matrix": site_matrix,
            "site_pool_thresholds": site_pool_thresholds,
            "uptime_7d": uptime_7d,
            "router": _router_stats(router_events_snap, last_router_poll_snap, router_poll_error_snap, now),
            # Primary speed-test success counts. Falls back to HTTP when the
            # primary (speedtest-cli) endpoint is unreachable; fallback
            # successes are NOT counted as primary OK.
            "speed_attempts_24h": {
                "primary_ok": sum(1 for a in speed_attempts_snap if a.get("primary_ok")),
                "fallback_ok": sum(1 for a in speed_attempts_snap if not a.get("primary_ok") and a.get("fallback_ok")),
                "total": len(speed_attempts_snap),
            },
            # Recent primary-speedtest failure details for inspection — the
            # most recent N entries with HTTP code, exception type, and the
            # phase (init / get_best_server / download / upload).
            "primary_fail_reasons": list(self.primary_fail_reasons)[:25],
            "last_diagnosis_at": (last_diagnosis_snap.get("evaluated_at") if last_diagnosis_snap else None),
            "vps_url": SERVER_URL or None,
        }


# ─────────────────────────────────────────────────────────────
# Connectivity check
# ─────────────────────────────────────────────────────────────
_PING_TARGETS: List[Tuple[str, int]] = [
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
    ("208.67.222.222", 53),
]

def check_connectivity(timeout: float = 2.0) -> Tuple[bool, Optional[float]]:
    for host, port in _PING_TARGETS:
        try:
            t0 = time.perf_counter()
            sock = socket.create_connection((host, port), timeout=timeout)
            latency_ms = (time.perf_counter() - t0) * 1000
            sock.close()
            return True, latency_ms
        except OSError:
            continue
    return False, None


def check_multi_site(targets: List[str], port: int = 443, timeout: float = 2.0
                     ) -> Tuple[Dict[str, Optional[float]], float, Optional[float]]:
    """
    Parallel TCP check to each site on port 443.
    Returns (per_site_ms_or_None, pct_accessible 0-100, avg_ms_or_None).
    """
    results: Dict[str, Optional[float]] = {}

    def _check(host: str) -> Tuple[str, Optional[float]]:
        try:
            t0 = time.perf_counter()
            s = socket.create_connection((host, port), timeout=timeout)
            ms = (time.perf_counter() - t0) * 1000
            s.close()
            return host, ms
        except OSError:
            return host, None

    with ThreadPoolExecutor(max_workers=max(1, len(targets))) as ex:
        for host, ms in ex.map(_check, targets):
            results[host] = ms

    reachable = [v for v in results.values() if v is not None]
    pct = len(reachable) / len(targets) * 100 if targets else 0.0
    avg_ms = sum(reachable) / len(reachable) if reachable else None
    return results, pct, avg_ms


# ─────────────────────────────────────────────────────────────
# Speed measurement
# ─────────────────────────────────────────────────────────────
_DL_URLS = [
    "https://speed.cloudflare.com/__down?bytes=10000000",
    "https://proof.ovh.net/files/10Mb.dat",
    "http://speedtest.tele2.net/10MB.zip",
]

_UL_URLS = [
    "https://speed.cloudflare.com/__up",
    "https://httpbin.org/post",
]

_HEADERS = {"User-Agent": "ConnectionMonitor/1.0"}


def _quick_gateway() -> str:
    """Return the default gateway IP, or '' on failure. Single subprocess call."""
    try:
        out = subprocess.check_output(
            ["route", "-n", "get", "default"],
            stderr=subprocess.DEVNULL, timeout=3,
        ).decode()
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("gateway:"):
                return stripped.split(":", 1)[1].strip()
    except (subprocess.SubprocessError, OSError):
        pass
    return ""


_network_cache: Tuple[Tuple[str, str], float] = (("", ""), 0.0)
_NETWORK_CACHE_TTL = 120.0


def _detect_network() -> Tuple[str, str]:
    """Detect the network via gateway IP + subnet mask fingerprint.

    Returns (fingerprint, interface_type) where fingerprint is
    "gateway/prefix" (e.g. "192.168.1.254/24") and interface_type is
    "wifi" or "wired".  Runs in a daemon thread with a hard 20s cap so
    subprocess stalls cannot block the speed-test thread.
    """
    global _network_cache
    cached_result, cached_ts = _network_cache
    if cached_result[0] and (time.time() - cached_ts) < _NETWORK_CACHE_TTL:
        return cached_result

    result: List[Tuple[str, str]] = [("unknown", "unknown")]

    def _inner() -> None:
        hw_map: Dict[str, str] = {}
        try:
            hw_out = subprocess.check_output(
                ["networksetup", "-listallhardwareports"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode()
            port: Optional[str] = None
            for line in hw_out.splitlines():
                if line.startswith("Hardware Port:"):
                    port = line.split(":", 1)[1].strip()
                elif line.startswith("Device:"):
                    iface = line.split(":", 1)[1].strip()
                    if port:
                        hw_map[iface] = port
                        port = None
        except (subprocess.SubprocessError, OSError):
            pass

        active_iface: Optional[str] = None
        for idx in range(10):
            iface = f"en{idx}"
            try:
                ip = subprocess.check_output(
                    ["ipconfig", "getifaddr", iface],
                    stderr=subprocess.DEVNULL, timeout=2,
                ).decode().strip()
                if ip:
                    active_iface = iface
                    break
            except (subprocess.SubprocessError, OSError):
                continue

        if not active_iface:
            return

        port_type = hw_map.get(active_iface, "")
        if "Wi-Fi" in port_type or "AirPort" in port_type:
            iface_type = "wifi"
        elif port_type:
            iface_type = "wired"
        else:
            iface_type = "wifi"

        gateway = ""
        try:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"],
                stderr=subprocess.DEVNULL, timeout=3,
            ).decode()
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.startswith("gateway:"):
                    gateway = stripped.split(":", 1)[1].strip()
                    break
        except (subprocess.SubprocessError, OSError):
            pass

        if not gateway:
            result[0] = (iface_type, iface_type)
            return

        prefix = "24"
        try:
            mask = subprocess.check_output(
                ["ipconfig", "getoption", active_iface, "subnet_mask"],
                stderr=subprocess.DEVNULL, timeout=2,
            ).decode().strip()
            if mask:
                prefix = str(sum(bin(int(x)).count("1") for x in mask.split(".")))
        except (subprocess.SubprocessError, OSError, ValueError):
            pass

        result[0] = (f"{gateway}/{prefix}", iface_type)

    t = threading.Thread(target=_inner, daemon=True, name="network-detect")
    t.start()
    t.join(timeout=20)

    _network_cache = (result[0], time.time())
    return result[0]


def _http_download_mbps() -> Optional[float]:
    for url in _DL_URLS:
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            elapsed = time.perf_counter() - t0
            if elapsed > 0.2 and len(data) > 500_000:
                return (len(data) * 8) / (elapsed * 1_000_000)
        except Exception:
            continue
    return None


def _http_upload_mbps() -> Optional[float]:
    payload = os.urandom(3 * 1024 * 1024)
    size = len(payload)
    for url in _UL_URLS:
        try:
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={**_HEADERS, "Content-Type": "application/octet-stream",
                         "Content-Length": str(size)},
            )
            t0 = time.perf_counter()
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp.read()
            elapsed = time.perf_counter() - t0
            if elapsed > 0.2:
                return (size * 8) / (elapsed * 1_000_000)
        except Exception:
            continue
    return None


def _speedtest_lib() -> Tuple[Optional[float], Optional[float], Optional[float], Optional[dict]]:
    """Run a speedtest-cli measurement.
    Returns (dl_mbps, ul_mbps, ping_ms, error_info).
    On success, error_info is None. On failure, it's:
      {type: <ExceptionClassName>, code: <HTTP status or None>,
       phase: <which step failed>, msg: <stringified exception>}

    HTTP status codes most commonly seen here:
      429 — Too Many Requests (Ookla rate-limiting; cron-aligned bursts)
      503 — Service Unavailable (no servers accepting)
      529 — Site Is Overloaded (non-standard, used by some CDNs)
    """
    phase = "init"
    try:
        s = _st.Speedtest()
        phase = "get_best_server"
        s.get_best_server()
        phase = "download"
        dl = s.download() / 1_000_000
        phase = "upload"
        ul = s.upload() / 1_000_000
        return dl, ul, s.results.ping, None
    except Exception as exc:
        # Walk the exception chain looking for an underlying urllib HTTPError
        # (speedtest-cli often wraps these as SpeedtestHTTPError).
        code = None
        cur = exc
        while cur is not None:
            if hasattr(cur, "code") and isinstance(getattr(cur, "code", None), int):
                code = cur.code; break
            cur = getattr(cur, "__cause__", None) or getattr(cur, "__context__", None)
        info = {
            "type": type(exc).__name__,
            "code": code,
            "phase": phase,
            "msg": str(exc)[:200],
        }
        logging.warning("speedtest-cli error: %s", info)
        return None, None, None, info


def run_speed_test(state: MonitorState, label: str) -> None:
    with state.lock:
        if state.speed_in_progress:
            return
        state.speed_in_progress = True
        state.speed_status = "Detecting network…"

    try:
        fingerprint, iface_type = _detect_network()
    except Exception as exc:
        state.log(f"Network detection error: {exc}", "error")
        fingerprint, iface_type = "unknown", "unknown"
        with state.lock:
            state.speed_in_progress = False
            state.speed_status = ""
            state.last_speed_test = datetime.now()
        return
    _db.register_network(fingerprint, iface_type)
    network = fingerprint
    with state.lock:
        old_network = state.current_network
        now = datetime.now()
        if old_network and old_network != network:
            if old_network in state.network_start_time:
                elapsed = (now - state.network_start_time[old_network]).total_seconds()
                state.network_uptime_secs[old_network] = (
                    state.network_uptime_secs.get(old_network, 0.0) + elapsed
                )
            state.network_changes.append({
                "ts": now.isoformat(timespec="seconds"),
                "from": old_network,
                "to": network,
            })
        if not old_network or old_network != network:
            state.network_start_time[network] = now
        state.current_network = network
        state.assign_network_color(network)
        state.speed_status = "Initialising speed test…"

    primary_dl: Optional[float] = None
    primary_ul: Optional[float] = None
    primary_ping: Optional[float] = None
    fallback_dl: Optional[float] = None
    fallback_ul: Optional[float] = None
    fallback_ping: Optional[float] = None
    primary_error: Optional[dict] = None
    test_start = datetime.now()

    try:
        # ── Primary: speedtest-cli (when available) ────────────────
        if SPEEDTEST_AVAILABLE:
            with state.lock:
                state.speed_status = "Running speedtest-cli (≈30s)…"
            primary_dl, primary_ul, primary_ping, primary_error = _speedtest_lib()

        primary_ok = (primary_dl is not None and primary_dl > 0) or \
                     (primary_ul is not None and primary_ul > 0)

        # ── Fallback: built-in HTTP — only when primary failed ─────
        # Rate-limit codes (429 = Too Many Requests, 529 = Site Overloaded)
        # are particularly common at top-of-hour because cron jobs across
        # the world default to xx:00:00, all hitting Ookla simultaneously.
        # Treat these as expected, jump straight to fallback without noise.
        if not primary_ok:
            is_rate_limited = (primary_error and primary_error.get("code") in (429, 529))
            if SPEEDTEST_AVAILABLE and not is_rate_limited:
                state.log("speedtest-cli failed — trying HTTP fallback…", "warning")
            with state.lock:
                state.speed_status = "Measuring fallback download…"
            fallback_dl = _http_download_mbps()
            with state.lock:
                state.speed_status = "Measuring fallback upload…"
            fallback_ul = _http_upload_mbps()
            _, fallback_ping = check_connectivity()
        fallback_ok = (fallback_dl is not None and fallback_dl > 0) or \
                      (fallback_ul is not None and fallback_ul > 0)

        test_end = datetime.now()

        # ── Record the attempt ─────────────────────────────────────
        cutoff_24h_iso = (datetime.now() - timedelta(hours=24)).isoformat()
        with state.lock:
            state.speed_attempts.append({
                "ts": test_start.isoformat(timespec="seconds"),
                "primary_ok": primary_ok,
                "fallback_ok": fallback_ok,
                "label": label,
            })
            state.speed_attempts = [a for a in state.speed_attempts
                                    if a.get("ts", "") >= cutoff_24h_iso]

        if primary_ok:
            # ── Normal path: store as a SpeedSample (drives baselines) ──
            sample = SpeedSample(
                timestamp=test_end,
                download_mbps=primary_dl or 0.0,
                upload_mbps=primary_ul or 0.0,
                ping_ms=primary_ping or 0.0,
                label=label,
                network=network,
            )
            slow_event: Optional[Tuple[str, str]] = None
            with state.lock:
                state.speed_history.append(sample)
                state.last_speed_success = test_end
                slow_event = _update_slow_degraded(state, sample, test_end)
            dl_str = f"↓{primary_dl:.1f}" if primary_dl else "↓?"
            ul_str = f"↑{primary_ul:.1f}" if primary_ul else "↑?"
            state.log(f"Speed [{label}] via {network}: {dl_str} {ul_str} Mbps")
            if slow_event:
                state.log(*slow_event)
        elif fallback_ok:
            # ── Primary failed but fallback worked. Don't record this as
            # a site_loss — we proved the connection was up (HTTP fallback
            # succeeded), so it's purely a third-party speedtest endpoint
            # hiccup. Surface the captured exception type / HTTP status
            # so we can investigate the pattern (429 rate-limit at xx:00,
            # 503 no-servers, etc.).
            with state.lock:
                state._primary_failed_at = datetime.now()
                if primary_error:
                    state.primary_fail_reasons.appendleft({
                        "ts": datetime.now().isoformat(timespec="seconds"),
                        **primary_error,
                    })
            err_tag = ""
            if primary_error:
                code = primary_error.get("code")
                err_tag = f" [{primary_error.get('type')}"
                if code is not None: err_tag += f" {code}"
                err_tag += f" @ {primary_error.get('phase')}]"
            state.log(
                f"Speed [{label}]: primary endpoint failed{err_tag}; "
                f"HTTP fallback succeeded (connection verified up)", "info",
            )
        else:
            # Both failed — likely concurrent with an outage; just log it.
            state.log(f"Speed [{label}]: both primary and fallback failed", "warning")

    except Exception as exc:
        state.log(f"Speed test error: {exc}", "error")
    finally:
        with state.lock:
            state.speed_in_progress = False
            state.speed_status = ""
            # Always record the attempt time so periodic tests keep firing
            # even after a failed baseline or failed periodic test
            state.last_speed_test = datetime.now()


# ─────────────────────────────────────────────────────────────
# Degraded-period detectors (call with state.lock held)
# ─────────────────────────────────────────────────────────────
def _percentile(sorted_vals: List[float], q: float) -> float:
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    idx = q / 100 * (len(sorted_vals) - 1)
    lo, hi = int(idx), min(int(idx) + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo)


def _recent_download_pcts(state: "MonitorState", days: int = 7
                          ) -> Optional[Tuple[float, float]]:
    """Return (p10, p50) of download speeds over the last `days`. None if
    insufficient history. Excludes zero-Mbps samples (Outage / failed tests).
    """
    cutoff = datetime.now() - timedelta(days=days)
    vals = sorted(s.download_mbps for s in state.speed_history
                  if s.timestamp >= cutoff and s.download_mbps > 0)
    if len(vals) < SLOW_MIN_HISTORY:
        return None
    return _percentile(vals, 10), _percentile(vals, 50)


def _median_recent_downloads(state: "MonitorState", days: int = 7) -> Optional[float]:
    pcts = _recent_download_pcts(state, days)
    return pcts[1] if pcts else None


def _p90_recent_pings(state: "MonitorState", days: int = 7) -> Optional[float]:
    """Return P90 of recent ping latencies (from speed-test pings + connectivity
    probe latencies in ping_history_ts). Excludes None/zero. Used to define
    'normal range' for closing high-ping periods."""
    cutoff = datetime.now() - timedelta(days=days)
    cutoff_iso = cutoff.isoformat()
    pings: List[float] = []
    pings.extend(s.ping_ms for s in state.speed_history
                 if s.timestamp >= cutoff and s.ping_ms and s.ping_ms > 0)
    pings.extend(v for ts, v in state.ping_history_ts
                 if v is not None and v > 0 and ts >= cutoff_iso)
    if len(pings) < SLOW_MIN_HISTORY:
        return None
    pings.sort()
    return _percentile(pings, 90)


def _update_slow_degraded(state: "MonitorState", sample: SpeedSample,
                          now: datetime) -> Optional[Tuple[str, str]]:
    """Open or close a 'slow' DegradedPeriod based on this speed sample.
    Returns an optional (msg, level) for state.log() (called outside the lock).

    Open: dl < 50% × 7d-P50 (single sample, strict — only flag real slowness).
    Close: SLOW_CLOSE_STREAK consecutive non-Outage samples ≥ 7d-P10. P10 is
    the bottom-tail floor — anything above it is "out of the bad zone," even
    if not fully back to median. Outage-labeled samples reset the streak so a
    transient drop during recovery doesn't falsely close.
    """
    pcts = _recent_download_pcts(state)
    if pcts is None:
        return None
    p10, p50 = pcts
    dl = sample.download_mbps
    is_outage_sample = (sample.label or "") == "Outage"

    # Open: SLOW_OPEN_STREAK consecutive non-Outage samples below 7d-P10
    # (sustainment — single-sample blips don't trigger). Period start is
    # backdated to the FIRST sub-P10 sample so the recorded duration is
    # honest. Outage-labeled samples reset the open streak.
    if state.current_slow is None:
        if is_outage_sample:
            state._slow_open_streak = 0
            state._slow_open_first_at = None
        elif dl < p10:
            state._slow_open_streak += 1
            if state._slow_open_first_at is None:
                state._slow_open_first_at = now
            if state._slow_open_streak >= SLOW_OPEN_STREAK:
                period = DegradedPeriod(
                    start=state._slow_open_first_at, kind="slow",
                    detail=f"download {dl:.1f} Mbps < 7d-P10 ({p10:.1f} Mbps) "
                           f"for {SLOW_OPEN_STREAK} consecutive tests; 7d median {p50:.1f}",
                )
                state.current_slow = period
                state.degraded_periods.append(period)
                state._slow_open_streak = 0
                state._slow_open_first_at = None
                state._slow_close_streak = 0
                return (f"Degraded: slow ({dl:.1f} Mbps, P10 {p10:.1f}, P50 {p50:.1f})", "warning")
        else:
            state._slow_open_streak = 0
            state._slow_open_first_at = None
        # While the open streak is being built, don't fall through to the
        # close path (state.current_slow is still None).
        return None

    # Close path — streak of non-Outage samples ≥ 7d-P10.
    if state.current_slow is not None:
        if is_outage_sample:
            state._slow_close_streak = 0
        elif dl >= p10:
            state._slow_close_streak += 1
            if state._slow_close_streak >= SLOW_CLOSE_STREAK:
                state.current_slow.end = now
                msg = (f"Degraded ended: {SLOW_CLOSE_STREAK} consecutive samples "
                       f"≥ 7d-P10 ({p10:.1f} Mbps); latest {dl:.1f} Mbps")
                state.current_slow = None
                state._slow_close_streak = 0
                return (msg, "success")
        else:
            state._slow_close_streak = 0
    return None


def _high_ping_baseline(state: "MonitorState", now: datetime) -> Optional[float]:
    """Return the P{HIGH_PING_BASELINE_PCT} of the user's connectivity-probe
    pings over the last 7 days, EXCLUDING samples that fell within an already-
    recorded high_ping degraded period (so a long bad event doesn't pollute
    the baseline that would catch the next bad event).

    Returns None if we don't yet have HIGH_PING_MIN_BASELINE_SAMPLES probes
    in the eligible window — caller falls back to the floor.

    Cached for HIGH_PING_BASELINE_TTL_S because the calc walks ~190k samples.
    """
    if (state._high_ping_baseline_at is not None
        and (now - state._high_ping_baseline_at).total_seconds()
            < HIGH_PING_BASELINE_TTL_S):
        return state._high_ping_baseline_ms

    cutoff = now - timedelta(days=7)
    # Build exclusion windows from any recorded high_ping degraded periods
    # within the last 7 days (closed or ongoing).
    excl: List[Tuple[datetime, datetime]] = []
    for p in state.degraded_periods:
        if p.kind != "high_ping":
            continue
        if p.start >= cutoff:
            excl.append((p.start, p.end or now))
    if state.current_high_ping is not None and state.current_high_ping not in (None,):
        # current_high_ping is also in degraded_periods, already added above
        pass
    excl.sort()

    def in_excl(ts: datetime) -> bool:
        # Linear scan is fine — there are typically < 30 high_ping windows in 7d.
        for s, e in excl:
            if s <= ts <= e:
                return True
        return False

    eligible: List[float] = []
    for ts_iso, v in state.ping_history_ts:
        if v is None:
            continue
        try:
            ts = datetime.fromisoformat(ts_iso)
        except (TypeError, ValueError):
            continue
        if ts < cutoff:
            continue
        if excl and in_excl(ts):
            continue
        eligible.append(float(v))

    if len(eligible) < HIGH_PING_MIN_BASELINE_SAMPLES:
        state._high_ping_baseline_ms = None
        state._high_ping_baseline_at = now
        return None

    eligible.sort()
    idx = min(len(eligible) - 1,
              int(HIGH_PING_BASELINE_PCT / 100.0 * (len(eligible) - 1)))
    p = eligible[idx]
    state._high_ping_baseline_ms = p
    state._high_ping_baseline_at = now
    return p


def _update_high_ping_degraded(state: "MonitorState", latency_ms: Optional[float],
                               now: datetime) -> Optional[Tuple[str, str]]:
    """Track high-ping windows. Called from connectivity_thread under state.lock.
    Returns optional (msg, level) to log outside the lock.

    Open: rolling p90 of last 30 connectivity probes ≥ max(HIGH_PING_FLOOR_MS,
    7d-P{HIGH_PING_BASELINE_PCT} of own pings excluding prior high_ping
    periods), sustained for HIGH_PING_DURATION_S.
    Close: HIGH_PING_CLOSE_STREAK consecutive non-None pings ≤ 7d-P90 (the
    "normal range" floor — anything inside the 90th percentile of typical
    pings counts as recovered). A None ping (probe failure) breaks the
    streak — we're not 'back to normal' if the connection is dropping probes.
    """
    if latency_ms is not None:
        state._recent_pings.append(latency_ms)

    # ── CLOSE PATH ── runs every probe, including None, so the streak can
    # both increment on each good ping and break on each missed one.
    if state.current_high_ping is not None:
        normal_p90 = _p90_recent_pings(state)
        if latency_ms is None:
            state._high_ping_close_streak = 0
        elif normal_p90 is not None and latency_ms <= normal_p90:
            state._high_ping_close_streak += 1
            if state._high_ping_close_streak >= HIGH_PING_CLOSE_STREAK:
                state.current_high_ping.end = now
                state.current_high_ping = None
                state._high_ping_close_streak = 0
                return (f"Degraded ended: {HIGH_PING_CLOSE_STREAK} consecutive "
                        f"pings ≤ 7d-P90 ({normal_p90:.0f}ms)", "success")
        else:
            state._high_ping_close_streak = 0
        # While in a high-ping period, the open detector below is a no-op.
        return None

    # ── OPEN PATH ── needs a full rolling window before evaluating.
    if len(state._recent_pings) < state._recent_pings.maxlen:
        return None
    pings = sorted(state._recent_pings)
    p90 = pings[int(0.9 * (len(pings) - 1))]

    # Open threshold = max(floor, 7d-P{pct} of own connectivity-probe pings,
    # excluding samples inside prior high_ping windows). If we don't yet have
    # enough history, the floor stands alone.
    baseline = _high_ping_baseline(state, now)
    if baseline is not None:
        open_threshold = max(HIGH_PING_FLOOR_MS, baseline)
        baseline_label = f"P{HIGH_PING_BASELINE_PCT:g} {baseline:.0f}ms"
    else:
        open_threshold = HIGH_PING_FLOOR_MS
        baseline_label = "floor"

    if p90 >= open_threshold:
        if state._high_ping_started_above is None:
            state._high_ping_started_above = now
        elif (now - state._high_ping_started_above).total_seconds() >= HIGH_PING_DURATION_S:
            period = DegradedPeriod(
                start=state._high_ping_started_above, kind="high_ping",
                detail=f"p90 {p90:.0f}ms ≥ {open_threshold:.0f}ms threshold ({baseline_label})",
            )
            state.current_high_ping = period
            state.degraded_periods.append(period)
            state._high_ping_started_above = None
            state._high_ping_close_streak = 0
            return (f"Degraded: high ping (p90 {p90:.0f}ms)", "warning")
    else:
        state._high_ping_started_above = None
    return None


# ─────────────────────────────────────────────────────────────
# Persistence — save/load to disk, purge data older than 24 h
# ─────────────────────────────────────────────────────────────
def _build_flush_payload(state: MonitorState) -> dict:
    """Snapshot state into a dict suitable for db.flush() kwargs and sync POST."""
    cutoff = datetime.now() - _24H
    cutoff_30d = datetime.now() - _30D
    with state.lock:
        speed_samples = [
            {
                "timestamp": s.timestamp.isoformat(),
                "download_mbps": s.download_mbps,
                "upload_mbps": s.upload_mbps,
                "ping_ms": s.ping_ms,
                "label": s.label,
                "network": s.network,
            }
            for s in state.speed_history
            if s.timestamp >= cutoff
        ]
        outages_list = [
            {
                "start": o.start.isoformat(),
                "end": o.end.isoformat() if o.end else None,
            }
            for o in state.outages
            if o.start >= cutoff_30d
        ]
        degraded = [
            {
                "start": d.start.isoformat(),
                "end": d.end.isoformat() if d.end else None,
                "kind": d.kind,
                "detail": d.detail,
            }
            for d in state.degraded_periods
            if d.start >= cutoff_30d
        ]
        cutoff_30d_iso = cutoff_30d.isoformat()
        ping_ts = [
            (ts, v)
            for ts, v in state.ping_history_ts
            if ts >= cutoff_30d_iso
        ]
        access_ts = [
            (ts, v)
            for ts, v in state.ping_accessibility_ts
            if ts >= cutoff_30d_iso
        ]
        site_ping_save = {
            host: [
                (ts, v) for ts, v in hist
                if ts >= cutoff_30d_iso
            ]
            for host, hist in state.site_ping_history.items()
        }
        network_uptime = dict(state.network_uptime_secs)
        network_colors = dict(state.network_colors)
        current_outage = state.current_outage
        daily_history_snap = list(state.daily_history)
        router_cutoff_iso = (datetime.now() - _30D).isoformat()
        router_events_to_save = [
            ev.to_dict()
            for ev in state.router_events
            if ev.timestamp >= router_cutoff_iso
        ]
        if len(state.router_events) != len(router_events_to_save):
            state.router_events = deque(
                (ev for ev in state.router_events if ev.timestamp >= router_cutoff_iso),
                maxlen=state.router_events.maxlen,
            )
        diagnoses_to_save = [
            d for d in state.diagnoses
            if (d.get("evaluated_at") or "") >= cutoff_30d_iso
        ]
        dismissed_ids_snap = set(state.dismissed_outage_ids)
        first_seen_iso = state.first_seen.isoformat()

    now_dt = datetime.now()
    today_start = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    today_str = today_start.strftime("%Y-%m-%d")

    all_today = [o for o in outages_list if o["start"][:10] == today_str]
    today_outage_secs = 0.0
    for o_dict in all_today:
        o_start = max(datetime.fromisoformat(o_dict["start"]), today_start)
        o_end_raw = datetime.fromisoformat(o_dict["end"]) if o_dict.get("end") else now_dt
        o_end = min(o_end_raw, now_dt)
        if o_end > o_start:
            today_outage_secs += (o_end - o_start).total_seconds()
    if current_outage and current_outage.start.date() == now_dt.date():
        o_start = max(current_outage.start, today_start)
        today_outage_secs += (now_dt - o_start).total_seconds()

    today_window = (now_dt - today_start).total_seconds()
    today_uptime = round(max(0.0, (today_window - today_outage_secs) / today_window * 100), 2) if today_window > 0 else 100.0

    today_pings = sorted(v for ts, v in ping_ts if datetime.fromisoformat(ts) >= today_start)

    def _pct_simple(sorted_vals, p):
        n = len(sorted_vals)
        if n == 1:
            return sorted_vals[0]
        idx = p / 100 * (n - 1)
        lo, hi = int(idx), min(int(idx) + 1, n - 1)
        return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo)

    p10_t = round(_pct_simple(today_pings, 10), 1) if len(today_pings) >= 2 else None
    p50_t = round(_pct_simple(today_pings, 50), 1) if len(today_pings) >= 2 else None
    p90_t = round(_pct_simple(today_pings, 90), 1) if len(today_pings) >= 2 else None

    today_entry = {"date": today_str, "uptime_pct": today_uptime,
                   "p10": p10_t, "p50": p50_t, "p90": p90_t}

    cutoff_7d_str = (now_dt - timedelta(days=7)).strftime("%Y-%m-%d")
    hist_dict = {e["date"]: e for e in daily_history_snap if e["date"] > cutoff_7d_str}
    hist_dict[today_str] = today_entry
    new_daily_history = sorted(hist_dict.values(), key=lambda e: e["date"])

    return {
        "ping_samples": ping_ts,
        "accessibility_samples": access_ts,
        "site_samples": site_ping_save,
        "speed_samples": speed_samples,
        "outages": outages_list,
        "degraded": degraded,
        "router_events": router_events_to_save,
        "diagnoses": diagnoses_to_save,
        "dismissed_outage_ids": dismissed_ids_snap,
        "daily_summary": new_daily_history,
        "network_uptime_secs": network_uptime,
        "network_colors": network_colors,
        "first_seen_iso": first_seen_iso,
    }


def save_state(state: MonitorState) -> None:
    """Flush state deltas to the SQLite store."""
    if _db is None:
        return
    try:
        payload = _build_flush_payload(state)
        with state.lock:
            state.daily_history = payload["daily_summary"]

        global _cursors
        _cursors = _db.flush(
            cursors=_cursors,
            ping_samples=payload["ping_samples"],
            accessibility_samples=payload["accessibility_samples"],
            site_samples=payload["site_samples"],
            speed_samples=payload["speed_samples"],
            outages=payload["outages"],
            current_outage=None,
            degraded=payload["degraded"],
            router_events=payload["router_events"],
            diagnoses=payload["diagnoses"],
            dismissed_outage_ids=payload["dismissed_outage_ids"],
            daily_summary=payload["daily_summary"],
            network_uptime_secs=payload["network_uptime_secs"],
            network_colors=payload["network_colors"],
            first_seen_iso=payload["first_seen_iso"],
            saved_at_iso=datetime.now().isoformat(),
        )
    except Exception as exc:
        logging.warning("Failed to save state: %s", exc)


def _reconstruct_slow_periods_from_speed(
    speed: List["SpeedSample"],
    existing: List["DegradedPeriod"],
) -> List["DegradedPeriod"]:
    """Recover slow degraded periods that aren't in the persisted record but
    are clearly visible in speed_history.

    A "run" is consecutive non-Outage successful samples whose download is
    below 50% × median(successful loaded samples). Open at SLOW_OPEN_STREAK
    consecutive sub-threshold samples; close when ANY sample ≥ threshold or
    on a >2h gap. Skip the run if any existing degraded period overlaps.
    Returns possibly-empty list of new DegradedPeriod records.
    """
    if not speed:
        return []
    successes = [s for s in speed if (s.label or "") != "Outage"
                 and s.download_mbps is not None]
    if len(successes) < SLOW_MIN_HISTORY:
        return []
    dls = sorted(s.download_mbps for s in successes)
    median = dls[len(dls) // 2]
    threshold = median * 0.5

    existing_slow = [(d.start, d.end) for d in existing
                     if d.kind == "slow" and d.end is not None]

    def overlaps_existing(a: datetime, b: datetime) -> bool:
        for s, e in existing_slow:
            if a <= e and s <= b:
                return True
        return False

    out: List["DegradedPeriod"] = []
    GAP_LIMIT = timedelta(hours=2)
    run_start: Optional[datetime] = None
    run_first_sample: Optional[datetime] = None
    run_count = 0
    last_ts: Optional[datetime] = None

    successes_sorted = sorted(successes, key=lambda s: s.timestamp)
    for s in successes_sorted:
        ts = s.timestamp
        if last_ts is not None and (ts - last_ts) > GAP_LIMIT:
            # Force-close any open run at the previous sample.
            if run_count >= SLOW_OPEN_STREAK and run_first_sample is not None:
                start_t, end_t = run_first_sample, last_ts
                if not overlaps_existing(start_t, end_t):
                    out.append(DegradedPeriod(
                        start=start_t, end=end_t, kind="slow",
                        detail=f"reconstructed from speed_history "
                               f"(median {median:.0f} Mbps, threshold "
                               f"{threshold:.0f} Mbps, {run_count} samples)",
                    ))
            run_first_sample = None
            run_count = 0

        if s.download_mbps < threshold:
            if run_first_sample is None:
                run_first_sample = ts
            run_count += 1
        else:
            if run_count >= SLOW_OPEN_STREAK and run_first_sample is not None and last_ts is not None:
                start_t, end_t = run_first_sample, last_ts
                if not overlaps_existing(start_t, end_t):
                    out.append(DegradedPeriod(
                        start=start_t, end=end_t, kind="slow",
                        detail=f"reconstructed from speed_history "
                               f"(median {median:.0f} Mbps, threshold "
                               f"{threshold:.0f} Mbps, {run_count} samples)",
                    ))
            run_first_sample = None
            run_count = 0

        last_ts = ts

    # Tail-end run that never closed.
    if run_count >= SLOW_OPEN_STREAK and run_first_sample is not None and last_ts is not None:
        start_t, end_t = run_first_sample, last_ts
        if not overlaps_existing(start_t, end_t):
            out.append(DegradedPeriod(
                start=start_t, end=end_t, kind="slow",
                detail=f"reconstructed from speed_history "
                       f"(median {median:.0f} Mbps, threshold "
                       f"{threshold:.0f} Mbps, {run_count} samples)",
            ))
    return out


def load_state(state: MonitorState) -> None:
    """Load history from the SQLite store into in-memory deques."""
    if _db is None:
        return
    try:
        cutoff = datetime.now() - _24H
        cutoff_30d = datetime.now() - _30D
        cutoff_24h_iso = cutoff.isoformat()
        cutoff_30d_iso = cutoff_30d.isoformat()
        cutoff_7d_str = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")

        speed_rows     = _db.load_speed_samples(cutoff_24h_iso)
        outages_raw    = _db.load_outages(cutoff_30d_iso)
        degraded_raw   = _db.load_degraded_periods(cutoff_30d_iso)
        ping_ts_raw    = _db.load_ping_samples(cutoff_30d_iso)
        access_ts_raw  = _db.load_accessibility_samples(cutoff_30d_iso)
        site_ts_raw    = _db.load_site_samples(cutoff_30d_iso)
        router_raw     = _db.load_router_events(cutoff_30d_iso)
        diag_raw       = _db.load_diagnoses(cutoff_30d_iso)
        dismissed_set  = _db.load_dismissed_outage_ids()
        daily          = _db.load_daily_summary(cutoff_7d_str)
        prov_secs, prov_colors = _db.load_network_uptime()
        saved_at_meta  = _db.get_meta("saved_at") or ""
        first_seen_meta = _db.get_meta("first_seen")

        speed: List[SpeedSample] = []
        for s in speed_rows:
            speed.append(SpeedSample(
                timestamp=datetime.fromisoformat(s["timestamp"]),
                download_mbps=s["download_mbps"],
                upload_mbps=s["upload_mbps"],
                ping_ms=s["ping_ms"],
                label=s["label"],
                network=s["network"],
            ))

        # Re-apply the flap filter so legacy short-outage records from before
        # the OUTAGE_OPEN_STREAK rule still get filtered out on load. Closed
        # outages shorter than 8s are flaps (Wi-Fi roams, gateway blips); the
        # ongoing one (if any) is loaded as state.current_outage.
        FLAP_THRESHOLD = timedelta(seconds=OUTAGE_OPEN_STREAK * 2)
        outages: List[OutageRecord] = []
        current_outage_from_disk: Optional[OutageRecord] = None
        flap_dropped = 0
        for o in outages_raw:
            start = datetime.fromisoformat(o["start"])
            end = datetime.fromisoformat(o["end"]) if o["end"] else None
            if end is None:
                current_outage_from_disk = OutageRecord(start=start, end=None)
                continue
            if (end - start) < FLAP_THRESHOLD:
                flap_dropped += 1
                continue
            outages.append(OutageRecord(start=start, end=end))
        if flap_dropped:
            logging.info("load_state: dropped %d flap outage(s) shorter than %s",
                         flap_dropped, FLAP_THRESHOLD)

        try:
            saved_at_dt = datetime.fromisoformat(saved_at_meta) if saved_at_meta else datetime.now()
        except ValueError:
            saved_at_dt = datetime.now()

        degraded_loaded: List[DegradedPeriod] = []
        closed_orphans = 0
        for d in degraded_raw:
            start = datetime.fromisoformat(d["start"])
            end_raw = d["end"]
            if end_raw:
                try:
                    end = datetime.fromisoformat(end_raw)
                except ValueError:
                    end = saved_at_dt
                    closed_orphans += 1
            else:
                end = saved_at_dt if saved_at_dt > start else start + timedelta(seconds=1)
                closed_orphans += 1
            degraded_loaded.append(DegradedPeriod(
                start=start, end=end,
                kind=d["kind"], detail=d["detail"],
            ))
        if closed_orphans:
            logging.info("load_state: closed %d orphan degraded period(s) at saved_at",
                         closed_orphans)

        ping_ts = list(ping_ts_raw)
        access_ts = list(access_ts_raw)

        site_ping_loaded: Dict[str, deque] = {
            host: deque(samples, maxlen=270_000)
            for host, samples in site_ts_raw.items()
        }

        router_events_loaded: List = [
            router_log.RouterEvent(
                timestamp=r["ts"],
                src=r["src"], dst=r["dst"], proto=r["proto"],
                reason=r["reason"], source=r["source"],
            )
            for r in router_raw
        ]

        with state.lock:
            state.speed_history = speed
            state.outages = outages
            if current_outage_from_disk:
                state.current_outage = current_outage_from_disk
            state.ping_history_ts = deque(ping_ts, maxlen=1_400_000)
            state.ping_accessibility_ts = deque(access_ts, maxlen=270_000)
            state.site_ping_history = site_ping_loaded
            state.network_uptime_secs = prov_secs
            state.network_colors = prov_colors
            state.daily_history = daily
            state.router_events = deque(router_events_loaded, maxlen=400_000)
            state.degraded_periods = deque(degraded_loaded, maxlen=2000)

            # Restore first_seen — min of (persisted meta, current process
            # start, earliest piece of persisted data) so long-running installs
            # retain their full history across restarts and code versions.
            candidates: List[datetime] = [state.first_seen]
            try:
                if first_seen_meta:
                    candidates.append(datetime.fromisoformat(first_seen_meta))
            except (ValueError, TypeError):
                pass
            if outages:           candidates.append(min(o.start for o in outages))
            if speed:             candidates.append(min(s.timestamp for s in speed))
            if ping_ts:
                try:
                    candidates.append(datetime.fromisoformat(ping_ts[0][0]))
                except (ValueError, TypeError):
                    pass
            if degraded_loaded:   candidates.append(min(d.start for d in degraded_loaded))
            if daily:
                try:
                    candidates.append(datetime.strptime(min(e["date"] for e in daily), "%Y-%m-%d"))
                except (ValueError, KeyError):
                    pass
            state.first_seen = min(candidates)

            state.diagnoses = deque(diag_raw, maxlen=500)
            state.dismissed_outage_ids = set(dismissed_set)
            if speed:
                state.last_speed_test = max(s.timestamp for s in speed)
                successes = [s for s in speed if s.label != "Outage"]
                if successes:
                    state.last_speed_success = max(s.timestamp for s in successes)

            # Reconstruct missing slow degraded periods from speed_history —
            # same recovery path the JSON loader had, for sustained-slow runs
            # that aren't in the persisted record but are visible in speed.
            reconstructed = _reconstruct_slow_periods_from_speed(
                speed, list(state.degraded_periods))
            if reconstructed:
                state.degraded_periods.extend(reconstructed)
                ordered = sorted(state.degraded_periods, key=lambda d: d.start)
                state.degraded_periods = deque(ordered, maxlen=2000)
                logging.info("load_state: reconstructed %d slow degraded period(s) "
                             "from speed_history", len(reconstructed))

        # Initialise the persist cursors so the next save_state only inserts
        # rows the DB doesn't already have.
        global _cursors
        _cursors = db.PersistCursors(
            ping          = ping_ts[-1][0] if ping_ts else "",
            accessibility = access_ts[-1][0] if access_ts else "",
            site          = {h: s[-1][0] for h, s in site_ts_raw.items() if s},
            router        = router_events_loaded[-1].timestamp if router_events_loaded else "",
            speed         = speed_rows[-1]["timestamp"] if speed_rows else "",
        )

        print(f"  Loaded {len(speed)} speed samples, {len(outages)} outages, "
              f"{len(ping_ts)} ping points from DB.", flush=True)
    except Exception as exc:
        logging.warning("Failed to load state: %s", exc)


def site_check_thread(state: MonitorState) -> None:
    """Check multi-site accessibility every 10 seconds."""
    time.sleep(6)  # stagger after startup
    while state.running:
        with state.lock:
            targets = list(state.site_targets)

        if targets:
            site_results, pct, avg_ms = check_multi_site(targets)
            now = datetime.now()
            iso_now = now.isoformat(timespec="seconds")
            events_to_log: List[Tuple[str, str]] = []

            with state.lock:
                # Record accessibility history
                state.ping_accessibility_ts.append((iso_now, pct))

                # Track per-site up/down transitions and latency history
                for host, ms in site_results.items():
                    up = ms is not None
                    was_up = state.site_states.get(host, True)  # assume up at start
                    state.site_states[host] = up

                    # Record per-site latency (None = unreachable)
                    if host not in state.site_ping_history:
                        state.site_ping_history[host] = deque(maxlen=270_000)  # 30d @ 10s
                    state.site_ping_history[host].append((iso_now, ms))

                    if was_up and not up:
                        # Site just went down
                        state.current_site_outages[host] = OutageRecord(start=now)
                        events_to_log.append((f"Site unreachable: {host}", "warning"))
                    elif not was_up and up:
                        # Site came back
                        if host in state.current_site_outages:
                            out = state.current_site_outages.pop(host)
                            out.end = now
                            state.site_outages.append((host, out))
                        events_to_log.append((f"Site restored: {host}", "success"))

                    # Site-loss DegradedPeriod tracking (the teal-hashed class).
                    # Only opened when the rest of the system looks fine —
                    # otherwise site flakiness is already represented by an
                    # ongoing outage / high_ping / slow period and adding a
                    # site_loss layer would be redundant.
                    if up:
                        state._site_fail_streaks[host] = 0
                        state._site_pass_streaks[host] = state._site_pass_streaks.get(host, 0) + 1
                        if (host in state.current_site_loss
                                and state._site_pass_streaks[host] >= SITE_LOSS_CLOSE_STREAK):
                            period = state.current_site_loss.pop(host)
                            period.end = now
                            events_to_log.append(
                                (f"Site loss ended: {host}", "success"))
                    else:
                        state._site_pass_streaks[host] = 0
                        state._site_fail_streaks[host] = state._site_fail_streaks.get(host, 0) + 1
                        if (host not in state.current_site_loss
                                and state._site_fail_streaks[host] >= SITE_LOSS_OPEN_STREAK
                                and state.current_outage is None
                                and state.current_slow is None
                                and state.current_high_ping is None):
                            period = DegradedPeriod(
                                start=now, kind="site_loss",
                                detail=f"{host} unreachable for "
                                       f"{state._site_fail_streaks[host]} consecutive checks",
                            )
                            state.current_site_loss[host] = period
                            state.degraded_periods.append(period)
                            events_to_log.append(
                                (f"Site loss: {host} ({state._site_fail_streaks[host]} consecutive failures)",
                                 "warning"))

            for msg, level in events_to_log:
                state.log(msg, level)

        time.sleep(10)


def persistence_thread(state: MonitorState) -> None:
    """Flush deltas to the SQLite store every 60s. Prune at most once/hour."""
    global _last_pruned_at
    while state.running:
        time.sleep(60)
        if not state.running:
            break
        save_state(state)
        # Hourly pruning sweep — SQLite handles cheap incremental writes, but
        # without periodic DELETE-by-time the historical tables would grow
        # past their retention windows until the next process restart.
        if _db is not None and (time.time() - _last_pruned_at) >= 3600:
            try:
                deleted = _db.prune(db.retention_from_env())
                total = sum(deleted.values())
                if total:
                    logging.info("persistence_thread: pruned %d rows (%s)",
                                 total, ", ".join(f"{k}={v}" for k, v in deleted.items() if v))
                _last_pruned_at = time.time()
            except Exception as exc:
                logging.warning("Prune failed: %s", exc)


_sync_cursors: db.PersistCursors = db.PersistCursors()


def sync_thread(state: MonitorState) -> None:
    """Push local data to the central VPS every 60s. Runs in addition to
    persistence_thread — local DB writes are never affected by sync status."""
    global _sync_cursors
    time.sleep(90)  # stagger vs persistence_thread (60s offset)
    while state.running:
        if not SERVER_URL:
            break
        try:
            payload = _build_flush_payload(state)
            payload["monitor_host"] = MONITOR_HOST

            # Convert sets to lists for JSON serialization
            if isinstance(payload.get("dismissed_outage_ids"), set):
                payload["dismissed_outage_ids"] = list(payload["dismissed_outage_ids"])

            body = json.dumps(payload, default=str).encode("utf-8")
            req = urllib.request.Request(
                f"{SERVER_URL}/api/ingest",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {INGEST_API_KEY}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read())
                if result.get("ok"):
                    logging.info("sync: pushed to %s (%s)", SERVER_URL, MONITOR_HOST)
                else:
                    logging.warning("sync: server returned error: %s", result)
        except Exception as exc:
            logging.warning("sync: push to %s failed: %s", SERVER_URL, exc)

        time.sleep(60)


def _router_stats(events: List, last_poll: Optional[datetime],
                  poll_error: Optional[str], now: datetime) -> dict:
    """Summarize router_events for the dashboard /api/state response."""
    if not events and last_poll is None:
        return {
            "available": False,
            "poll_error": poll_error,
            "last_poll": None,
            "count_1h": 0,
            "count_24h": 0,
            "dns_drops_1h": 0,
            "dns_drops_24h": 0,
        }
    cutoff_1h_iso = (now - timedelta(hours=1)).isoformat()
    cutoff_24h_iso = (now - timedelta(hours=24)).isoformat()
    c1 = c24 = d1 = d24 = 0
    for ev in events:
        is_24h = ev.timestamp >= cutoff_24h_iso
        is_1h  = ev.timestamp >= cutoff_1h_iso
        if is_24h:
            c24 += 1
            if ev.dst in router_log.DNS_PROBE_TARGETS and "Invalid" in ev.reason:
                d24 += 1
        if is_1h:
            c1 += 1
            if ev.dst in router_log.DNS_PROBE_TARGETS and "Invalid" in ev.reason:
                d1 += 1
    return {
        "available": True,
        "poll_error": poll_error,
        "last_poll": last_poll.isoformat(timespec="seconds") if last_poll else None,
        "count_1h": c1,
        "count_24h": c24,
        "dns_drops_1h": d1,
        "dns_drops_24h": d24,
    }


def router_log_thread(state: MonitorState) -> None:
    """Poll the gateway's log pages every ROUTER_POLL_INTERVAL seconds and
    append new events to state.router_events. Disabled if GATEWAY_URL is empty."""
    if not GATEWAY_URL or not ROUTER_PACKET_LOG_PATH:
        state.log("Router log scraping disabled (set GATEWAY_URL and ROUTER_PACKET_LOG_PATH in connection_monitor.env)", "info")
        return

    time.sleep(8)  # stagger after startup
    while state.running:
        try:
            events = router_log.fetch_and_parse(
                GATEWAY_URL,
                packet_path=ROUTER_PACKET_LOG_PATH,
                syslog_path=ROUTER_SYSLOG_PATH,
                timeout=5.0,
            )
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            should_warn = False
            with state.lock:
                state.router_poll_error = err
                if (state._router_warned_at is None
                        or (datetime.now() - state._router_warned_at).total_seconds() >= 60):
                    state._router_warned_at = datetime.now()
                    should_warn = True
            if should_warn:
                state.log(f"Router log fetch failed: {err}", "warning")
            time.sleep(ROUTER_POLL_INTERVAL)
            continue

        with state.lock:
            existing_keys = {ev.key() for ev in state.router_events}
            fresh = router_log.dedupe(existing_keys, events)
            for ev in fresh:
                state.router_events.append(ev)
            state.last_router_poll = datetime.now()
            had_error = state.router_poll_error
            state.router_poll_error = None

        if had_error:
            state.log("Router log fetch recovered", "success")
        if fresh:
            # Surface gateway-side rejection of monitor probes immediately.
            dns_drops = [
                ev for ev in fresh
                if ev.dst in router_log.DNS_PROBE_TARGETS and "Invalid" in ev.reason
            ]
            if dns_drops:
                state.log(
                    f"Gateway rejected {len(dns_drops)} probe packet(s) to DNS targets",
                    "warning",
                )

        time.sleep(ROUTER_POLL_INTERVAL)


# ─────────────────────────────────────────────────────────────
# Background threads
# ─────────────────────────────────────────────────────────────
def connectivity_thread(state: MonitorState) -> None:
    while state.running:
        online, latency = check_connectivity()
        event: Optional[Tuple[str, str]] = None
        ping_event: Optional[Tuple[str, str]] = None

        with state.lock:
            state.connected = online   # always reflect the latest probe
            now = datetime.now()

            if latency is not None:
                state.last_ping_ms = latency
                state.ping_history.append(latency)
                state.ping_history_ts.append(
                    (now.isoformat(timespec="seconds"), latency)
                )
            elif not online:
                state.last_ping_ms = None

            # ── Sustained-failure outage gating ───────────────────────
            # A single failed probe (Wi-Fi roam, brief gateway flap, laptop
            # wake artifact) shouldn't open an outage. Require
            # OUTAGE_OPEN_STREAK consecutive failures (≈8s @ 2s) before
            # creating the OutageRecord, and backdate its start to the FIRST
            # failure so timing stays honest.
            if online:
                # Recovery: only fire "restored" if a sustained outage was
                # actually open. Brief blips (streak < threshold) recover
                # silently — no record, no log.
                if state.current_outage is not None:
                    state.current_outage.end = now
                    state.outages.append(state.current_outage)
                    state.current_outage = None
                    state.trigger_post_outage_test = True
                    event = ("Connection restored!", "success")
                state._outage_fail_streak = 0
                state._outage_first_failure_at = None
            else:
                state._outage_fail_streak += 1
                if state._outage_first_failure_at is None:
                    state._outage_first_failure_at = now
                if (state._outage_fail_streak == OUTAGE_OPEN_STREAK
                        and state.current_outage is None):
                    state.current_outage = OutageRecord(
                        start=state._outage_first_failure_at
                    )
                    event = ("Connection LOST!", "error")

            ping_event = _update_high_ping_degraded(state, latency, now)

        if event:
            state.log(*event)
        if ping_event:
            state.log(*ping_event)

        time.sleep(2)


def _previous_scheduled_slot(now: datetime) -> datetime:
    """Return the most recent SPEED_TEST_SLOTS minute mark at or before `now`.
    If we're earlier than every slot in this hour, falls back to the prior
    hour's last slot (xx:55)."""
    for m in reversed(SPEED_TEST_SLOTS):
        slot = now.replace(minute=m, second=0, microsecond=0)
        if slot <= now:
            return slot
    last_m = SPEED_TEST_SLOTS[-1]
    return (now - timedelta(hours=1)).replace(minute=last_m, second=0, microsecond=0)


def _next_scheduled_slot(now: datetime) -> datetime:
    """Return the next SPEED_TEST_SLOTS minute mark strictly after `now`."""
    for m in SPEED_TEST_SLOTS:
        slot = now.replace(minute=m, second=0, microsecond=0)
        if slot > now:
            return slot
    first_m = SPEED_TEST_SLOTS[0]
    return (now + timedelta(hours=1)).replace(minute=first_m, second=0, microsecond=0)


def speed_test_thread(state: MonitorState) -> None:
    time.sleep(4)
    if state.running:
        run_speed_test(state, "Baseline")

    while state.running:
        time.sleep(5)

        with state.lock:
            online        = state.connected
            in_progress   = state.speed_in_progress
            trigger_post  = state.trigger_post_outage_test
            last_attempt  = state.last_speed_test
            outage_active = state.current_outage is not None
            cur_network   = state.current_network

        # Quick gateway check — detect network switches within 5s
        gw = _quick_gateway()
        if gw and cur_network and gw not in cur_network:
            try:
                global _network_cache
                _network_cache = (("", ""), 0.0)
                fingerprint, iface_type = _detect_network()
                if fingerprint != cur_network:
                    _db.register_network(fingerprint, iface_type)
                    with state.lock:
                        now = datetime.now()
                        if cur_network and cur_network in state.network_start_time:
                            elapsed = (now - state.network_start_time[cur_network]).total_seconds()
                            state.network_uptime_secs[cur_network] = (
                                state.network_uptime_secs.get(cur_network, 0.0) + elapsed
                            )
                        state.network_start_time[fingerprint] = now
                        state.current_network = fingerprint
                        state.assign_network_color(fingerprint)
                        state.network_changes.append({
                            "ts": now.isoformat(timespec="seconds"),
                            "from": cur_network,
                            "to": fingerprint,
                        })
                    state.log(f"Network changed → {fingerprint}")
            except Exception as exc:
                logging.warning("network re-detect failed: %s", exc)

        if in_progress:
            continue

        # Active outage (no connectivity): record 0-bandwidth sample every 60s
        # instead of attempting a live test. This is one of the documented
        # exceptions to the fixed xx:10/25/40/55 cadence.
        if not online and outage_active:
            secs_since_attempt = (
                (datetime.now() - last_attempt).total_seconds() if last_attempt else 9999
            )
            if secs_since_attempt >= 60:
                now = datetime.now()
                sample = SpeedSample(
                    timestamp=now,
                    download_mbps=0.0,
                    upload_mbps=0.0,
                    ping_ms=0.0,
                    label="Outage",
                    network=cur_network,
                )
                with state.lock:
                    state.speed_history.append(sample)
                    state.last_speed_test = now
                state.log("Speed: 0 Mbps (outage in progress)", "warning")
            continue

        if not online:
            continue

        # Post-outage: immediate test after connectivity is restored.
        # Documented exception to the fixed cadence — we want to know how
        # quickly speeds returned to baseline. The aligned schedule resumes
        # naturally on the next loop iteration after this fires.
        if trigger_post:
            with state.lock:
                state.trigger_post_outage_test = False
            for _ in range(6):
                if not state.running:
                    return
                time.sleep(1)
            run_speed_test(state, "Post-outage")
            continue

        # ── Aligned-cadence scheduling ─────────────────────────────
        # Tests run at the wall-clock minute marks in SPEED_TEST_SLOTS
        # (10, 25, 40, 55). If we haven't already attempted a test at or
        # after the most recent slot, fire one. The 5-second tick means
        # tests land within 5 seconds of each scheduled mark.
        now = datetime.now()
        prev_slot = _previous_scheduled_slot(now)
        if last_attempt is None or last_attempt < prev_slot:
            run_speed_test(state, "Periodic")


# ─────────────────────────────────────────────────────────────
# Shared timeline JS component
# ─────────────────────────────────────────────────────────────
# Inlined into both DASHBOARD_HTML (7d view) and DIAGNOSE_HTML (30d view).
# Renders a per-day vertical bar timeline on a <canvas>, with hit-testing and
# tooltips. The caller passes `onIncidentClick(incident)`; the component does
# not assume how clicks are handled (confirm, navigate, etc.).
TIMELINE_JS = r"""
window.UptimeTimeline = (function () {
  const COLORS = {
    bg:       '#0d1117',
    bar_ok:   'rgba(63,185,80,0.55)',   // muted green
    bar_no:   '#161b22',                 // future / no data / monitor down
    outage:   '#f85149',
    outage_seen: 'rgba(248,81,73,0.45)',     // lighter red = analyzed outage
    degraded: '#d29922',
    degraded_seen: 'rgba(210,153,34,0.45)',  // lighter yellow = analyzed degraded
    site_loss:      '#39c5cf',                  // teal = single site flaky alone
    site_loss_seen: 'rgba(57,197,207,0.45)',    // lighter teal = analyzed site_loss
    today:    '#58a6ff',
    text:     '#e6edf3',
    dim:      '#8b949e',
    grid:     'rgba(255,255,255,0.06)',
    weekend:  'rgba(255,255,255,0.04)',
    now:      '#39c5cf',
  };

  // Tooltip lives once at body level, fixed-positioned, so it never affects
  // page layout (and therefore never causes the canvas to resize-loop).
  let _tooltip = null;
  function getTooltip() {
    if (_tooltip) return _tooltip;
    _tooltip = document.createElement('div');
    _tooltip.className = 'timeline-tooltip';
    _tooltip.style.cssText =
      'position:fixed;display:none;z-index:1000;' +
      'background:#1c2128;border:1px solid #30363d;border-radius:5px;' +
      'padding:7px 10px;font-size:11px;line-height:1.5;color:#e6edf3;' +
      'pointer-events:none;white-space:nowrap;' +
      'box-shadow:0 4px 14px rgba(0,0,0,0.5);max-width:280px;';
    document.body.appendChild(_tooltip);
    return _tooltip;
  }
  function placeTooltip(clientX, clientY) {
    const tt = getTooltip();
    tt.style.display = 'block';
    // Measure after display.
    const w = tt.offsetWidth, h = tt.offsetHeight;
    const margin = 8;
    let left = clientX + 14;
    let top  = clientY + 14;
    const vw = window.innerWidth, vh = window.innerHeight;
    if (left + w + margin > vw) left = clientX - w - 14;
    if (left < margin) left = margin;
    if (top + h + margin > vh)  top = clientY - h - 14;
    if (top < margin) top = margin;
    tt.style.left = left + 'px';
    tt.style.top  = top  + 'px';
  }
  function hideTooltip() {
    if (_tooltip) _tooltip.style.display = 'none';
  }

  function startOfDay(d) {
    const x = new Date(d);
    x.setHours(0, 0, 0, 0);
    return x;
  }
  function fmtDuration(s) {
    s = Math.max(0, Math.floor(s));
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ' + (s % 60).toString().padStart(2, '0') + 's';
    const h = Math.floor(m / 60);
    return h + 'h ' + (m % 60).toString().padStart(2, '0') + 'm';
  }
  function fmtTimeOfDay(iso) {
    if (!iso) return '—';
    return iso.slice(11, 19);
  }
  function fmtDate(d) {
    return (d.getMonth() + 1) + '/' + d.getDate();
  }

  function makeStripePattern(ctx, color) {
    const off = document.createElement('canvas');
    off.width = 8; off.height = 8;
    const c = off.getContext('2d');
    c.strokeStyle = color;
    c.lineWidth = 2;
    c.beginPath();
    c.moveTo(-2, 10); c.lineTo(10, -2);
    c.moveTo(-2, 18); c.lineTo(18, -2);
    c.stroke();
    return ctx.createPattern(off, 'repeat');
  }

  function render(canvas, opts) {
    const days        = opts.days || 7;
    const clusters    = opts.clusters  || opts.outages || [];
    const analyzedIds = new Set(opts.analyzedIds || []);
    const titles      = opts.titles || {};
    const monitorStartedAt = opts.monitorStartedAt
      ? new Date(opts.monitorStartedAt) : null;
    // Periods when the monitor process itself wasn't running. Rendered as
    // dim "no data" overlay on the green covered band, with hover tooltip.
    const monitorGaps = (opts.monitorGaps || []).map(g => ({
      start: new Date(g.start),
      end:   new Date(g.end),
      duration_s: g.duration_s,
    }));
    const gapRects = [];
    const onClick = opts.onIncidentClick || null;
    // ID of the cluster currently being viewed in the diagnosis panel —
    // when set, we draw a bright-yellow outline around its members and
    // pipe the bounding box back via onSelectedBounds so a popover can be
    // positioned to point at it.
    const selectedClusterId = opts.selectedClusterId || null;
    const onSelectedBounds  = opts.onSelectedBounds || null;
    const selectedBoundsAcc = { x: Infinity, y: Infinity, x2: -Infinity, y2: -Infinity, found: false };
    // Highlight an arbitrary time slice on the timeline (used when the
    // selected diagnosis is window-based — 1h / 24h — and isn't tied to
    // a single cluster). { start, end } as ISO strings.
    const selectedWindow = opts.selectedWindow || null;
    // Per-kind member filter. `kindFilter` is a Set of kinds to HIDE
    // (e.g., new Set(['slow', 'site_loss'])). Outage members are never
    // hidden — those are always relevant.
    const kindFilter = opts.kindFilter instanceof Set ? opts.kindFilter : new Set();
    // Cluster IDs the user has dismissed. Hidden by default; shown when
    // showDismissed is true (the user toggled "show dismissed").
    const dismissedIds = opts.dismissedClusterIds instanceof Set
      ? opts.dismissedClusterIds : new Set();
    const showDismissed = !!opts.showDismissed;
    const showHourLabels = days <= 7;

    const dpr = window.devicePixelRatio || 1;
    const cssW = canvas.clientWidth || canvas.offsetWidth;
    const cssH = canvas.clientHeight || canvas.offsetHeight;
    canvas.width  = Math.floor(cssW * dpr);
    canvas.height = Math.floor(cssH * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);

    const marginL = showHourLabels ? 26 : 22;
    const marginR = 4;
    const marginT = 14;   // for severity badges
    // 30d shows a two-line label (weekday letter + date), 7d shows one.
    const marginB = days <= 7 ? 18 : 32;
    const innerW = cssW - marginL - marginR;
    const innerH = cssH - marginT - marginB;

    const today = startOfDay(new Date());
    const dayStarts = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(today); d.setDate(today.getDate() - i);
      dayStarts.push(d);
    }

    // Insert a small visual gap between weeks. We treat "week" as ending on
    // Saturday — i.e. a gap before each Sunday (other than the first column).
    const weekGapPx = days > 7 ? Math.max(4, innerW * 0.012) : 0;
    const numWeekGaps = days > 7
      ? dayStarts.slice(1).filter(d => d.getDay() === 0).length
      : 0;
    const usableW = innerW - weekGapPx * numWeekGaps;
    const colW = usableW / days;
    const barW = Math.max(2, colW - 2);

    // Resolve x-position for each day, accounting for inserted week gaps.
    const dayX = [];
    let cursor = marginL;
    dayStarts.forEach((day, idx) => {
      if (idx > 0 && days > 7 && day.getDay() === 0) cursor += weekGapPx;
      dayX.push(cursor);
      cursor += colW;
    });

    // Y maps minutes-of-day [0..1440] → pixels.  BOTTOM = midnight (00:00),
    // TOP = 23:59 — bottom-up reading.
    const yOf = (min) => marginT + innerH - (min / 1440) * innerH;
    const minutesOfDay = (date) =>
      date.getHours() * 60 + date.getMinutes() + date.getSeconds() / 60;

    const dowLetter = ['S','M','T','W','T','F','S'];
    const incidentRects = [];

    // Bars
    dayStarts.forEach((day, idx) => {
      const dayEnd = new Date(day); dayEnd.setDate(day.getDate() + 1);
      const isToday = day.getTime() === today.getTime();
      const dow = day.getDay();
      const colX = dayX[idx];
      const x = colX + (colW - barW) / 2;

      // Weekend tint
      if (dow === 0 || dow === 6) {
        ctx.fillStyle = COLORS.weekend;
        ctx.fillRect(colX, marginT, colW, innerH);
      }

      // Determine "covered" portion (we have data) vs "uncovered."
      // Today: covered up to "now". Past days: covered if monitor was running.
      const now = new Date();
      let coveredFrom = day;
      let coveredTo   = isToday ? now : dayEnd;
      if (monitorStartedAt && monitorStartedAt > coveredFrom) coveredFrom = monitorStartedAt;
      if (coveredTo < coveredFrom) coveredTo = coveredFrom;

      // Background: green where covered, dim where not.
      ctx.fillStyle = COLORS.bar_no;
      ctx.fillRect(x, marginT, barW, innerH);
      const fromMin = (coveredFrom <= day)    ? 0    : minutesOfDay(coveredFrom);
      const toMin   = (coveredTo   >= dayEnd) ? 1440 : minutesOfDay(coveredTo);
      if (toMin > fromMin) {
        ctx.fillStyle = COLORS.bar_ok;
        // yOf(toMin) is higher visually than yOf(fromMin), so width = fromMin's y - toMin's y
        const yA = yOf(toMin);
        const yB = yOf(fromMin);
        ctx.fillRect(x, yA, barW, yB - yA);
      }

      // Monitor downtime: overlay each gap that intersects this day with
      // the dim "no data" color so the user can see when the monitor wasn't
      // running. Each rect is also recorded for tooltip hit-testing.
      monitorGaps.forEach(g => {
        if (g.end <= day || g.start >= dayEnd) return;
        const segStart = g.start < day    ? day    : g.start;
        const segEnd   = g.end   > dayEnd ? dayEnd : g.end;
        const fm = (segStart <= day)    ? 0    : minutesOfDay(segStart);
        const tm = (segEnd   >= dayEnd) ? 1440 : minutesOfDay(segEnd);
        if (tm <= fm) return;
        const yA = yOf(tm);
        const yB = yOf(fm);
        ctx.fillStyle = COLORS.bar_no;
        ctx.fillRect(x, yA, barW, yB - yA);
        gapRects.push({
          x: x, y: yA, w: barW, h: yB - yA,
          start: g.start, end: g.end, duration_s: g.duration_s,
        });
      });

      // Day label(s)
      ctx.fillStyle = COLORS.dim;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      if (days <= 7) {
        ctx.font = '10px ui-monospace, monospace';
        const dowName = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
        ctx.fillText(dowName[dow], x + barW / 2, marginT + innerH + 3);
      } else {
        // 30d: two-line label — weekday letter on top, date below.
        ctx.font = 'bold 9px ui-monospace, monospace';
        ctx.fillText(dowLetter[dow], x + barW / 2, marginT + innerH + 3);
        ctx.font = '9px ui-monospace, monospace';
        ctx.fillStyle = (dow === 1 || idx === 0 || idx === dayStarts.length - 1)
          ? COLORS.text : COLORS.dim;
        // Show date on Mondays + first/last column to anchor without clutter.
        if (dow === 1 || idx === 0 || idx === dayStarts.length - 1) {
          ctx.fillText(fmtDate(day), x + barW / 2, marginT + innerH + 16);
        }
        ctx.fillStyle = COLORS.dim;
      }
    });

    // Hour gridlines (and labels on 7d). Lines span the whole inner area on
    // both views; labels only on 7d (no room on 30d).
    ctx.strokeStyle = COLORS.grid;
    ctx.lineWidth = 1;
    [0, 6, 12, 18, 24].forEach(h => {
      const y = yOf(h * 60);
      ctx.beginPath();
      ctx.moveTo(marginL, y); ctx.lineTo(cssW - marginR, y);
      ctx.stroke();
    });
    if (showHourLabels) {
      ctx.fillStyle = COLORS.dim;
      ctx.font = '9px ui-monospace, monospace';
      ctx.textAlign = 'right';
      ctx.textBaseline = 'middle';
      [0, 6, 12, 18].forEach(h => {
        const y = yOf(h * 60);
        const lbl = h === 0 ? '12a' : (h === 12 ? '12p' : (h < 12 ? h + 'a' : (h - 12) + 'p'));
        ctx.fillText(lbl, marginL - 4, y);
      });
    }

    // Render every cluster member individually in its own category color
    // (outage red, degraded yellow stripes), instead of painting the entire
    // cluster span in one color. Cross-kind clustering still groups members
    // for click-to-diagnose, but visually a mostly-degraded cluster reads as
    // mostly yellow — only the actual outage segments paint red.
    function drawSpan(cluster) {
      const isAnalyzed = analyzedIds.has(cluster.id);
      const clusterCategory = cluster.category || 'outage';
      // Backwards-compat: if `members` not present (older API response),
      // synthesize a single member from the cluster span itself.
      const members = (cluster.members && cluster.members.length)
        ? cluster.members
        : [{
            kind: clusterCategory === 'outage' ? 'outage' : 'slow',
            start: cluster.start,
            end: cluster.end || new Date().toISOString(),
            ongoing: !!cluster.ongoing,
          }];

      members.forEach(m => {
        // Per-kind filter — outage members are never hidden.
        if (m.kind !== 'outage' && kindFilter.has(m.kind)) return;
        const memStart = new Date(m.start);
        const memEnd   = m.end ? new Date(m.end) : new Date();
        // Per-member coloring: outage = solid red (or lighter when analyzed),
        // slow / high_ping = yellow stripes, site_loss = teal stripes.
        let memColor, useStripes;
        if (m.kind === 'outage') {
          memColor = isAnalyzed ? COLORS.outage_seen : COLORS.outage;
          useStripes = false;
        } else if (m.kind === 'site_loss') {
          memColor = isAnalyzed ? COLORS.site_loss_seen : COLORS.site_loss;
          useStripes = true;
        } else { // 'slow' | 'high_ping'
          memColor = isAnalyzed ? COLORS.degraded_seen : COLORS.degraded;
          useStripes = true;
        }
        const pattern = useStripes ? makeStripePattern(ctx, memColor) : null;

        dayStarts.forEach((day, idx) => {
          const dayEnd = new Date(day); dayEnd.setDate(day.getDate() + 1);
          if (memEnd <= day || memStart >= dayEnd) return;
          const segStart = (memStart > day) ? memStart : day;
          const segEnd   = (memEnd   < dayEnd) ? memEnd : dayEnd;
          const yA = yOf(minutesOfDay(segEnd >= dayEnd ? new Date(dayEnd.getTime() - 1) : segEnd));
          const yB = yOf(minutesOfDay(segStart));
          const x = dayX[idx] + (colW - barW) / 2;
          // Natural height with a min-height floor so single-sample events
          // remain visible. Matches the 7d rendering — earlier 30d also
          // multiplied by 1.5x, which made long events overflow above/below
          // the day cell since the expansion lifted bars past midnight.
          const minH = days > 7 ? 3 : 2;
          const naturalH = yB - yA;
          let h = Math.max(minH, naturalH);
          let yTop = yA - (h - naturalH) / 2;
          // Clamp inside this day's 24h cell so the min-height pad doesn't
          // push the bar above the top or below the bottom of the column.
          if (yTop < marginT) yTop = marginT;
          if (yTop + h > marginT + innerH) yTop = marginT + innerH - h;
          ctx.fillStyle = useStripes ? pattern : memColor;
          ctx.fillRect(x, yTop, barW, h);
          const HIT_PAD_TOP = 4, HIT_PAD_BOT = 3, HIT_PAD_X = 1;
          incidentRects.push({
            x: x - HIT_PAD_X,
            y: yTop - HIT_PAD_TOP,
            w: barW + 2 * HIT_PAD_X,
            h: h + HIT_PAD_TOP + HIT_PAD_BOT,
            // The hit-target carries the cluster (not the member) so clicks
            // open the same diagnosis regardless of which member was hit.
            incident: { ...cluster, category: clusterCategory, analyzed: isAnalyzed,
                        title: titles[cluster.id] || null, dayIndex: idx },
          });
        });
      });
    }

    // Apply dismissed-cluster filter unless the user has toggled "show
    // dismissed" on. Dismissed clusters render with a translucent dim
    // overlay when shown, so they're visible-but-distinguishable.
    const visibleClusters = clusters.filter(c =>
      showDismissed || !dismissedIds.has(c.id)
    );
    // Clip every event-driven primitive (bars, selection outlines, dismissed
    // overlay, "now" tick) to the 24h day-cell area so short events and 2px
    // selection padding don't leak into the badge/label margins.
    ctx.save();
    ctx.beginPath();
    ctx.rect(marginL - 3, marginT, innerW + 6, innerH);
    ctx.clip();
    // Draw degraded clusters first (so outage clusters render on top, just in
    // case any future data shape allows overlap — server-side they're merged).
    visibleClusters.filter(c => c.category !== 'outage').forEach(drawSpan);
    visibleClusters.filter(c => c.category === 'outage').forEach(drawSpan);
    // Visually mark dismissed clusters with a thin gray overlay so they
    // read as "acknowledged, kept around for history."
    if (showDismissed) {
      ctx.save();
      ctx.fillStyle = 'rgba(139,148,158,0.45)';
      visibleClusters.forEach(c => {
        if (!dismissedIds.has(c.id)) return;
        const sMs = new Date(c.start).getTime();
        const eMs = c.end ? new Date(c.end).getTime() : new Date().getTime();
        dayStarts.forEach((day, idx) => {
          const dayEnd = new Date(day); dayEnd.setDate(day.getDate() + 1);
          if (eMs <= day.getTime() || sMs >= dayEnd.getTime()) return;
          const segStart = new Date(Math.max(sMs, day.getTime()));
          const segEnd   = new Date(Math.min(eMs, dayEnd.getTime() - 1));
          const yA = yOf(minutesOfDay(segEnd));
          const yB = yOf(minutesOfDay(segStart));
          const x = dayX[idx] + (colW - barW) / 2;
          ctx.fillRect(x, yA, barW, yB - yA);
        });
      });
      ctx.restore();
    }

    // Draw a single yellow outline around the selected cluster's full
    // evaluated timeframe (one rect per day column it spans) rather than one
    // outline per member — clusters with multiple chained events otherwise
    // showed several adjacent boxes that read as separate selections.
    const drawTimeframeOutline = (sMs, eMs) => {
      ctx.save();
      ctx.strokeStyle = '#f1e05a';
      ctx.lineWidth = 1.5;
      dayStarts.forEach((day, idx) => {
        const dayEnd = new Date(day); dayEnd.setDate(day.getDate() + 1);
        if (eMs <= day.getTime() || sMs >= dayEnd.getTime()) return;
        const segStart = new Date(Math.max(sMs, day.getTime()));
        const segEnd   = new Date(Math.min(eMs, dayEnd.getTime() - 1));
        const yA = yOf(minutesOfDay(segEnd));
        const yB = yOf(minutesOfDay(segStart));
        const x = dayX[idx] + (colW - barW) / 2 - 2;
        const w = barW + 4;
        const yTop = yA - 2;
        const h = (yB - yA) + 4;
        ctx.strokeRect(x, yTop, w, h);
        selectedBoundsAcc.found = true;
        selectedBoundsAcc.x  = Math.min(selectedBoundsAcc.x,  x);
        selectedBoundsAcc.y  = Math.min(selectedBoundsAcc.y,  yTop);
        selectedBoundsAcc.x2 = Math.max(selectedBoundsAcc.x2, x + w);
        selectedBoundsAcc.y2 = Math.max(selectedBoundsAcc.y2, yTop + h);
      });
      ctx.restore();
    };
    if (selectedClusterId) {
      const sel = visibleClusters.find(c => c.id === selectedClusterId);
      if (sel) {
        drawTimeframeOutline(
          new Date(sel.start).getTime(),
          sel.end ? new Date(sel.end).getTime() : new Date().getTime(),
        );
      }
    }
    // Window-based diagnoses (1h / 24h) aren't tied to a specific cluster —
    // outline the analyzed window the same way.
    if (selectedWindow && selectedWindow.start && selectedWindow.end) {
      drawTimeframeOutline(
        new Date(selectedWindow.start).getTime(),
        new Date(selectedWindow.end).getTime(),
      );
    }

    // "Now" tick on today's column
    const now = new Date();
    const todayIdx = dayStarts.findIndex(d => d.getTime() === today.getTime());
    if (todayIdx >= 0) {
      const xL = dayX[todayIdx] + (colW - barW) / 2;
      const yN = yOf(minutesOfDay(now));
      ctx.strokeStyle = COLORS.now;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(xL - 1, yN); ctx.lineTo(xL + barW + 1, yN);
      ctx.stroke();
    }
    // End of clip established before the event-drawing pass.
    ctx.restore();

    // Severity badges: longest *outage* (downtime) per day, derived from
    // clusters' total_outage_s. Only shown on 7d to avoid clutter.
    if (days <= 7) {
      const longestPerDay = {};
      clusters.forEach(c => {
        if (c.category !== 'outage') return;
        const d = startOfDay(new Date(c.start)).getTime();
        const sec = c.total_outage_s || 0;
        if (!longestPerDay[d] || sec > longestPerDay[d]) longestPerDay[d] = sec;
      });
      ctx.font = 'bold 9px ui-monospace, monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'bottom';
      ctx.fillStyle = COLORS.outage;
      dayStarts.forEach((day, idx) => {
        const sec = longestPerDay[day.getTime()];
        if (!sec) return;
        const x = dayX[idx] + colW / 2;
        ctx.fillText(fmtDuration(sec), x, marginT - 1);
      });
    }

    // Notify caller of the bounding box of the selected cluster's bars (in
    // CSS pixels relative to the canvas) so it can position a popover that
    // points at the highlighted incident. null when nothing is selected or
    // the selected id wasn't found in the rendered clusters.
    if (onSelectedBounds) {
      if (selectedBoundsAcc.found) {
        onSelectedBounds({
          x: selectedBoundsAcc.x,
          y: selectedBoundsAcc.y,
          w: selectedBoundsAcc.x2 - selectedBoundsAcc.x,
          h: selectedBoundsAcc.y2 - selectedBoundsAcc.y,
        });
      } else {
        onSelectedBounds(null);
      }
    }

    // Hover/click handlers
    let activeIncident = null;
    function hitTest(evt) {
      const rect = canvas.getBoundingClientRect();
      const px = evt.clientX - rect.left;
      const py = evt.clientY - rect.top;
      // Incident rects are checked first — they're drawn on top of gaps.
      for (const r of incidentRects) {
        if (px >= r.x && px <= r.x + r.w && py >= r.y && py <= r.y + r.h) return r.incident;
      }
      return null;
    }
    function hitTestGap(evt) {
      const rect = canvas.getBoundingClientRect();
      const px = evt.clientX - rect.left;
      const py = evt.clientY - rect.top;
      for (const r of gapRects) {
        if (px >= r.x && px <= r.x + r.w && py >= r.y && py <= r.y + r.h) return r;
      }
      return null;
    }

    function escapeHtml(s) {
      return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    canvas.onmousemove = (e) => {
      const inc = hitTest(e);
      const tt = getTooltip();
      if (inc) {
        canvas.style.cursor = 'pointer';
        const start = new Date(inc.start);
        const end   = inc.end ? new Date(inc.end) : new Date();
        const span  = (end - start) / 1000;
        const parts = [];
        if (inc.outage_count)    parts.push(inc.outage_count + ' outage' + (inc.outage_count > 1 ? 's' : ''));
        if (inc.high_ping_count) parts.push(inc.high_ping_count + ' high-ping');
        if (inc.slow_count)      parts.push(inc.slow_count + ' slow');
        if (inc.site_loss_count) parts.push(inc.site_loss_count + ' site-loss');
        const headline = parts.length ? parts.join(' · ')
          : (inc.category === 'outage' ? 'Outage' : 'Degraded');
        const lines = [];
        if (inc.analyzed && inc.title) {
          lines.push('<strong style="color:#bc8cff">' + escapeHtml(inc.title) + '</strong>');
          lines.push('<span style="color:var(--dim)">' + escapeHtml(headline) + '</span>');
        } else {
          lines.push('<strong>' + escapeHtml(headline) + '</strong>');
        }
        lines.push(start.toLocaleDateString() + ' ' +
          fmtTimeOfDay(inc.start) + ' → ' + fmtTimeOfDay(inc.end || ''));
        lines.push('Span: ' + fmtDuration(span));
        if (inc.total_outage_s) {
          lines.push('Outage time in cluster: ' + fmtDuration(inc.total_outage_s));
        }
        if (inc.analyzed) {
          lines.push('<span style="color:#bc8cff">✓ Click to view analysis</span>');
        } else if (inc.category === 'outage') {
          lines.push('<span style="color:var(--dim)">Click to diagnose</span>');
        }
        tt.innerHTML = lines.join('<br>');
        placeTooltip(e.clientX, e.clientY);
      } else {
        // No incident under cursor — check for monitor-down gaps.
        const g = hitTestGap(e);
        if (g) {
          canvas.style.cursor = 'default';
          const lines = [
            '<strong style="color:var(--dim)">Monitor not running</strong>',
            new Date(g.start).toLocaleString() + ' → ' +
              new Date(g.end).toLocaleString(),
            'Duration: ' + fmtDuration(g.duration_s),
          ];
          tt.innerHTML = lines.join('<br>');
          placeTooltip(e.clientX, e.clientY);
        } else {
          canvas.style.cursor = 'default';
          hideTooltip();
        }
      }
    };
    canvas.onmouseleave = hideTooltip;
    canvas.onclick = (e) => {
      const inc = hitTest(e);
      if (inc && onClick) {
        hideTooltip();
        onClick(inc);
      }
    };
  }

  return { render };
})();
"""


# ─────────────────────────────────────────────────────────────
# Web dashboard (HTML template)
# ─────────────────────────────────────────────────────────────
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connection Monitor</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script src="/static/timeline.js"></script>
<style>
:root {
  --bg:      #0d1117;
  --card:    #161b22;
  --border:  #30363d;
  --text:    #e6edf3;
  --dim:     #8b949e;
  --green:   #3fb950;
  --red:     #f85149;
  --yellow:  #d29922;
  --blue:    #58a6ff;
  --cyan:    #39c5cf;
  --magenta: #bc8cff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: ui-monospace, 'SF Mono', 'Fira Code', monospace;
  font-size: 13px;
  padding: 14px;
  min-height: 100vh;
  transition: background 0.6s ease, color 0.3s ease;
}

body.offline {
  --bg:     #1c0a09;
  --card:   #2a1110;
  --border: #5c2120;
}

/* ── Header ─────────────────────────────────────────────────── */
header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
}

#status-dot {
  width: 10px; height: 10px;
  border-radius: 50%;
  background: var(--green);
  flex-shrink: 0;
  transition: background 0.3s;
}
#status-dot.offline { background: var(--red); animation: blink 1s step-start infinite; }

@keyframes blink { 50% { opacity: 0.2; } }

#status-text { font-size: 13px; font-weight: 700; letter-spacing: 0.05em; }
#status-text.online  { color: var(--green); }
#status-text.offline { color: var(--red); }

#header-network { color: var(--dim); font-size: 12px; }
#header-ping      { color: var(--cyan); font-size: 12px; }

.spacer { flex: 1; }

#last-updated { color: var(--dim); font-size: 11px; }

/* ── Grid ───────────────────────────────────────────────────── */
.grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 10px;
}

.col-3  { grid-column: span 3; }
.col-4  { grid-column: span 4; }
.col-5  { grid-column: span 5; }
.col-6  { grid-column: span 6; }
.col-8  { grid-column: span 8; }
.col-12 { grid-column: span 12; }

@media (max-width: 900px) {
  .col-3, .col-4, .col-5, .col-6, .col-8 { grid-column: span 12; }
}

/* ── Phone-only layout (touch device ≤600px) ────────────────── */
@media (pointer: coarse) and (max-width: 600px) {
  body { padding: 8px; }
  .tab-bar { display: flex !important; }
  .tab-panel { display: none !important; }
  .tab-panel.tab-active { display: block !important; }
}

/* ── Cards ──────────────────────────────────────────────────── */
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  min-width: 0;
}

.card-title {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--dim);
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

/* ── Status stats ───────────────────────────────────────────── */
.stat-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 4px 0;
  border-bottom: 1px solid rgba(255,255,255,0.03);
}
.stat-row:last-child { border-bottom: none; }
.stat-label { color: var(--dim); }
.stat-value { font-weight: 600; text-align: right; }

#speed-status {
  color: var(--yellow);
  font-size: 11px;
  font-style: italic;
  margin-top: 8px;
  min-height: 16px;
}

/* ── Tables ─────────────────────────────────────────────────── */
table { width: 100%; border-collapse: collapse; }

th {
  text-align: left;
  color: var(--dim);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 0 8px 8px 0;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}

td {
  padding: 5px 8px 5px 0;
  border-bottom: 1px solid rgba(255,255,255,0.04);
  vertical-align: middle;
  font-size: 12px;
}
tr:last-child td { border-bottom: none; }

.badge {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.badge-green   { background: rgba(63,185,80,0.15);  color: var(--green); }
.badge-red     { background: rgba(248,81,73,0.15);  color: var(--red); }
.badge-yellow  { background: rgba(210,153,34,0.15); color: var(--yellow); }
.badge-blue    { background: rgba(88,166,255,0.15); color: var(--blue); }
.badge-magenta { background: rgba(188,140,255,0.15);color: var(--magenta); }

/* ── Chart containers ───────────────────────────────────────── */
.chart-wrap {
  position: relative;
  height: 180px;
}

/* ── Log link ───────────────────────────────────────────────── */
.log-link {
  display: inline-block;
  padding: 5px 14px;
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--dim);
  font-family: inherit;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  text-decoration: none;
  margin-right: 8px;
  transition: color 0.15s, border-color 0.15s;
}
.log-link:hover { color: var(--blue); border-color: var(--blue); }

/* ── Chart split-view layout ────────────────────────────────── */
.chart-controls-row {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  padding: 0;
  margin-bottom: 0;
  min-height: 0;
}
.chart-view-toggle {
  display: flex;
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}
.chart-view-toggle button {
  background: none;
  border: none;
  border-right: 1px solid var(--border);
  color: var(--dim);
  font-family: inherit;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 5px 14px;
  cursor: pointer;
  transition: color 0.15s, background 0.15s;
}
.chart-view-toggle button:last-child { border-right: none; }
.chart-view-toggle button.active {
  background: rgba(88,166,255,0.15);
  color: var(--blue);
}
.ping-panels {
  display: flex;
  align-items: stretch;
  gap: 10px;
}
.chart-panel {
  display: flex;
  flex-direction: column;
  gap: 10px;
  flex: 1 1 0;
  min-width: 0;
  overflow: hidden;
}
.ping-panels.view-24h #panel-5m  { display: none; }
.ping-panels.view-5m  #panel-24h { display: none; }
@media (max-width: 700px) {
  .ping-panels { flex-direction: column; }
  .chart-divider { display: none !important; }
  .chart-panel { overflow: visible; flex: 0 0 auto; width: 100%; }
  .speed-row { flex-direction: column; }
}

/* ── Side-by-side upload / download row ─────────────────────── */
.speed-row {
  display: flex;
  gap: 10px;
}
.speed-attempts-line {
  font-size: 10px;
  color: var(--dim);
  margin-top: 6px;
  letter-spacing: 0.02em;
}
.speed-attempts-line strong { color: var(--text); font-weight: 600; }
.speed-attempts-line .sa-warn { color: var(--yellow); }

.speed-row .card {
  flex: 1;
  min-width: 0;
}


/* ── Mobile tab bar (hidden on desktop) ─────────────────────── */
.tab-bar {
  display: none;
  grid-column: span 12;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 0;
}
.tab-bar button {
  flex: 1;
  background: none;
  border: none;
  border-right: 1px solid var(--border);
  color: var(--dim);
  font-family: inherit;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 10px 6px;
  cursor: pointer;
  transition: color 0.2s, background 0.2s;
}
.tab-bar button:last-child { border-right: none; }
.tab-bar button.tab-active {
  color: var(--blue);
  background: rgba(88,166,255,0.1);
}

/* ── Site Status Matrix ─────────────────────────────────────── */
.site-matrix {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
  gap: 6px;
}
.site-tile {
  border-radius: 8px;
  padding: 9px 10px 8px;
  border: 1px solid rgba(139,148,158,0.15);
  background: rgba(139,148,158,0.06);
  min-width: 0;
  position: relative;
  cursor: default;
}
.site-tile.s-green  { background: rgba(63,185,80,0.10);  border-color: rgba(63,185,80,0.35); }
.site-tile.s-yellow { background: rgba(210,153,34,0.10); border-color: rgba(210,153,34,0.35); }
.site-tile.s-red    { background: rgba(248,81,73,0.10);  border-color: rgba(248,81,73,0.35); }
.site-tile-host {
  font-size: 9px;
  font-weight: 600;
  color: var(--dim);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}
.site-tile-verdict {
  display: flex;
  align-items: center;
  gap: 5px;
  font-size: 13px;
  font-weight: 800;
  letter-spacing: 0.05em;
  line-height: 1;
  margin-bottom: 3px;
}
.site-tile-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  background: var(--dim);
}
.s-green  .site-tile-dot { background: #3fb950; }
.s-yellow .site-tile-dot { background: #d29922; }
.s-red    .site-tile-dot { background: #f85149; }
.s-green  .site-tile-verdict { color: #3fb950; }
.s-yellow .site-tile-verdict { color: #d29922; }
.s-red    .site-tile-verdict { color: #f85149; }
.site-tile-trend { font-size: 11px; margin-left: auto; line-height: 1; }
.trend-up   { color: #3fb950; }
.trend-down { color: #f85149; }
.trend-flat { color: var(--dim); }
.site-tile-sub {
  font-size: 10px;
  font-family: monospace;
  color: var(--dim);
  margin-left: 13px;
}
/* Tooltip shown on hover */
.site-tile-tooltip {
  display: none;
  position: absolute;
  bottom: calc(100% + 7px);
  left: 50%;
  transform: translateX(-50%);
  background: #1c2128;
  border: 1px solid #30363d;
  border-radius: 6px;
  padding: 8px 11px;
  font-size: 10px;
  white-space: nowrap;
  z-index: 200;
  color: var(--text);
  pointer-events: none;
  box-shadow: 0 4px 18px rgba(0,0,0,0.5);
}
.site-tile:hover .site-tile-tooltip { display: block; }
.site-tile { cursor: pointer; }
.site-tile:hover { transform: translateY(-1px); transition: transform 0.1s ease; }

/* Per-site ping history modal */
.site-modal-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.6);
  display: flex; align-items: center; justify-content: center;
  z-index: 100;
}
.site-modal {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  width: min(900px, 92vw);
  max-height: 90vh;
  display: flex; flex-direction: column;
  box-shadow: 0 8px 32px rgba(0,0,0,0.6);
}
.site-modal-head {
  display: flex; justify-content: space-between; align-items: flex-start;
  margin-bottom: 12px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}
.site-modal-title {
  font-size: 15px; font-weight: 600; color: var(--text);
}
.site-modal-sub {
  font-size: 11px; color: var(--dim); margin-top: 4px;
}
.site-modal-sub strong { color: var(--text); font-weight: 600; }
.site-modal-close {
  background: transparent; border: none; color: var(--dim);
  font-size: 22px; cursor: pointer; line-height: 1;
  padding: 0 4px;
}
.site-modal-close:hover { color: var(--text); }
.site-modal-canvas-wrap {
  width: 100%; height: 280px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
}
#site-modal-canvas { width: 100%; height: 100%; display: block; }
.site-modal-legend {
  display: flex; gap: 14px; flex-wrap: wrap;
  font-size: 10px; color: var(--dim);
  margin-top: 8px;
}
.site-modal-legend > span { display: inline-flex; align-items: center; gap: 4px; }
.site-modal-legend > span[data-layer] { cursor: pointer; user-select: none; }
.site-modal-legend > span[data-layer]:hover { color: var(--text); }
.site-modal-legend > span[data-layer].layer-off {
  opacity: 0.35;
  text-decoration: line-through;
}
.site-modal-legend .lg-cross {
  display: inline-block;
  width: 10px; height: 10px;
  position: relative;
}
.site-modal-legend .lg-cross::before,
.site-modal-legend .lg-cross::after {
  content: ''; position: absolute;
  left: 50%; top: 0;
  width: 1.4px; height: 100%;
  background: var(--red);
  transform-origin: center;
}
.site-modal-legend .lg-cross::before { transform: translateX(-50%) rotate(45deg); }
.site-modal-legend .lg-cross::after  { transform: translateX(-50%) rotate(-45deg); }
.site-modal-legend .lg-spike {
  display: inline-block;
  width: 6px; height: 6px;
  background: var(--red);
  border: 1px solid var(--text);
  border-radius: 50%;
}
.tt-head { font-weight: 700; color: var(--dim); text-transform: uppercase;
           letter-spacing: 0.06em; font-size: 9px; margin-bottom: 5px; }
.tt-row {
  display: grid;
  grid-template-columns: 26px 32px 1fr;
  gap: 3px;
  line-height: 1.75;
}
.tt-win { color: var(--dim); font-weight: 700; }
.tt-pct { text-align: right; }
.tt-pct.good { color: #3fb950; }
.tt-pct.warn { color: #d29922; }
.tt-pct.bad  { color: #f85149; }
.tt-lat { color: var(--dim); padding-left: 4px; }
.tt-pool {
  margin-top: 6px;
  padding-top: 6px;
  border-top: 1px solid var(--border);
  font-size: 10px;
  line-height: 1.5;
  color: var(--text);
}
.tt-pool-lbl { color: var(--dim); margin-right: 4px; }
.tt-pool .s-green  { color: #3fb950; }
.tt-pool .s-yellow { color: #d29922; }
.tt-pool .s-red    { color: #f85149; }
.tt-pool-sub { color: var(--dim); font-size: 9px; }

/* Kind-filter toggles next to the timeline title (mirrors /diagnose) */
.kind-filter {
  display: inline-flex;
  gap: 10px;
  font-size: 11px;
  color: var(--dim);
  font-weight: normal;
  letter-spacing: 0.02em;
}
.kind-filter label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
  user-select: none;
}
.kind-filter input[type="checkbox"] {
  accent-color: var(--blue);
  margin: 0;
  cursor: pointer;
}
</style>
</head>
<body>

<header>
  <div id="status-dot"></div>
  <span id="status-text" class="online">ONLINE</span>
  <span id="header-network"></span>
  <span id="header-ping"></span>
  <span id="host-selector-wrap" style="display:none; margin-left:8px;">
    <select id="host-selector" style="background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:2px 6px;font-family:inherit;font-size:12px;">
      <option value="">All hosts</option>
    </select>
    <span id="host-last-seen" style="color:var(--dim);font-size:11px;margin-left:6px;"></span>
  </span>
  <span id="control-status" style="display:none; margin-left:8px; font-size:11px;"></span>
  <div class="spacer"></div>
  <a id="vps-link" href="" target="_blank" style="display:none; color:var(--blue); font-size:11px; text-decoration:none; margin-right:10px;">Central Dashboard</a>
  <span id="last-updated">Connecting…</span>
</header>

<div class="grid">

  <!-- ── Status Stats ──────────────────────────────────────── -->
  <div class="card col-3">
    <div class="card-title"><a href="https://github.com/hjordanh/Connection-test" target="_blank" rel="noopener" aria-label="View project on GitHub"><img src="/static/favicon.svg" alt="" style="height:1em;vertical-align:middle;margin-right:6px"></a>Status</div>
    <div class="stat-row">
      <span class="stat-label">Runtime</span>
      <span class="stat-value" id="stat-runtime">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Network</span>
      <span class="stat-value" id="stat-network" style="color:var(--magenta)">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Ping (live)</span>
      <span class="stat-value" id="stat-ping" style="color:var(--cyan)">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Avg ping (60s)</span>
      <span class="stat-value" id="stat-avg-ping" style="color:var(--cyan)">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Uptime (24h)</span>
      <span class="stat-value" id="stat-uptime-pct" style="color:var(--green)">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Current uptime</span>
      <span class="stat-value" id="stat-cur-uptime" style="color:var(--green)">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Outages</span>
      <span class="stat-value" id="stat-outages" style="color:var(--yellow)">0</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Total downtime</span>
      <span class="stat-value" id="stat-downtime" style="color:var(--yellow)">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Next speed test</span>
      <span class="stat-value" id="stat-next-test" style="color:var(--dim)">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Router rejections (1h)</span>
      <span class="stat-value" id="stat-router-1h" style="color:var(--dim)">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">↳ to DNS probes</span>
      <span class="stat-value" id="stat-router-dns" style="color:var(--dim)">—</span>
    </div>
    <div id="speed-status"></div>
  </div>

  <!-- ── Site Status Matrix ───────────────────────────────── -->
  <div class="card col-6">
    <div class="card-title">Site Status</div>
    <div class="site-matrix" id="site-matrix">
      <div style="color:var(--dim);font-size:11px;grid-column:span 3">Waiting for first site check…</div>
    </div>
  </div>

  <!-- ── 7-Day Uptime Timeline ──────────────────────────────── -->
  <div class="card col-3" id="uptime-card" style="display:flex;flex-direction:column">
    <div class="card-title" style="display:flex;justify-content:space-between;align-items:baseline;gap:8px;flex-wrap:wrap">
      <span>7-Day Uptime</span>
      <span class="kind-filter">
        <label><input type="checkbox" data-kind="slow" checked> slow</label>
        <label><input type="checkbox" data-kind="site_loss" checked> site loss</label>
        <label><input type="checkbox" data-show-dismissed> dismissed</label>
      </span>
    </div>
    <div class="chart-wrap" style="height:280px;flex:1;position:relative">
      <canvas id="uptimeTimeline" style="width:100%;height:100%"></canvas>
    </div>
    <a href="/diagnose" id="diag-link" style="display:block;margin-top:10px;padding:8px 10px;
        text-align:center;background:var(--bg);border:1px solid var(--border);
        border-radius:5px;color:var(--blue);text-decoration:none;font-size:12px">
      AI-assisted diagnostics →
    </a>
    <div id="diag-last-run" style="color:var(--dim);font-size:10px;text-align:center;margin-top:4px">
      Never run
    </div>
  </div>

  <!-- ── Chart view toggle ────────────────────────────────────── -->
  <div class="chart-controls-row col-12">
    <a class="log-link" href="/log" target="_blank">Log</a>
    <div class="chart-view-toggle">
      <button id="btn-view-5m"    onclick="setChartView('5m')">5m</button>
      <button id="btn-view-split" onclick="setChartView('split')" class="active">Split</button>
      <button id="btn-view-24h"   onclick="setChartView('24h')">24h</button>
    </div>
  </div>

  <!-- ── Ping chart panels ──────────────────────────────────────── -->
  <div class="ping-panels col-12" id="ping-panels">

    <!-- Left (or only): 24h ping -->
    <div class="chart-panel" id="panel-24h">
      <div class="card">
        <div class="card-title">Ping &amp; Accessibility — 24h (hourly p10 / p50 / p90)</div>
        <div class="chart-wrap" style="height:200px"><canvas id="pingChart24h"></canvas></div>
      </div>
    </div>

    <!-- Right (or only): 5m ping -->
    <div class="chart-panel" id="panel-5m">
      <div class="card">
        <div class="card-title">Ping &amp; Accessibility — 5m</div>
        <div class="chart-wrap" style="height:200px"><canvas id="pingChart5m"></canvas></div>
      </div>
    </div>

  </div>

  <!-- ── Bandwidth charts (always full width) ───────────────────── -->
  <div class="col-12">
    <div class="speed-row">
      <div class="card">
        <div class="card-title" id="upload-chart-title">Upload — 24h hourly avg + latest (Mbps)</div>
        <div class="chart-wrap"><canvas id="uploadChartCombined"></canvas></div>
        <div id="speed-attempts-line" class="speed-attempts-line" title="Primary speed test = speedtest-cli; fallback = built-in HTTP. Fallback successes do not count as primary OK."></div>
      </div>
      <div class="card">
        <div class="card-title" id="download-chart-title">Download — 24h hourly avg + latest (Mbps)</div>
        <div class="chart-wrap"><canvas id="downloadChartCombined"></canvas></div>
      </div>
    </div>
  </div>


</div><!-- /.grid -->

<script>
// ── Shared chart defaults ─────────────────────────────────────
const sharedScaleX = {
  ticks: { color: '#8b949e', font: { size: 10, family: 'monospace' }, maxTicksLimit: 10, maxRotation: 0 },
  grid: { color: 'rgba(255,255,255,0.04)' },
};
const sharedScaleY = {
  ticks: { color: '#8b949e', font: { size: 10, family: 'monospace' } },
  grid: { color: 'rgba(255,255,255,0.06)' },
  beginAtZero: true,
};
const sharedTooltip = {
  backgroundColor: '#161b22', borderColor: '#30363d', borderWidth: 1,
  titleColor: '#e6edf3', bodyColor: '#8b949e',
};
const sharedLegend = { labels: { color: '#8b949e', font: { family: 'monospace', size: 11 }, boxWidth: 12 } };

// ── 24h Ping chart: hourly lines (p10 / p50 / p90) + % accessible line ──
function makePingConfig24h() {
  return {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'p10 (ms)',
          data: [],
          borderColor: 'rgba(57,197,207,0.5)',
          backgroundColor: 'transparent',
          borderWidth: 1.5,
          pointRadius: 2,
          fill: false,
          tension: 0.3,
          yAxisID: 'yMs',
          order: 3,
        },
        // p50 (median) line — drawn slightly heavier than the p10/p90
        // edges so the median reads as the headline stat. Toggleable via
        // the legend; the dataset stays in slot 1 either way so the
        // p10/p90 fill anchor (`fill: '-2'` two slots back) keeps working.
        // Color matches the teal family used by p10/p90 for visual
        // consistency, just at higher opacity.
        {
          label: 'p50 (ms)',
          data: [],
          borderColor: 'rgba(57,197,207,0.95)',
          backgroundColor: 'transparent',
          borderWidth: 2,
          pointRadius: 2,
          fill: false,
          tension: 0.3,
          yAxisID: 'yMs',
          order: 2,
        },
        {
          label: 'p90 (ms)',
          data: [],
          borderColor: 'rgba(57,197,207,0.5)',
          backgroundColor: 'rgba(57,197,207,0.05)',
          borderWidth: 1.5,
          pointRadius: 2,
          fill: '-2',
          tension: 0.3,
          yAxisID: 'yMs',
          order: 1,
        },
        {
          label: '% Accessible',
          data: [],
          borderColor: '#d29922',
          backgroundColor: 'rgba(210,153,34,0.08)',
          borderWidth: 2,
          pointRadius: 2,
          fill: false,
          tension: 0.3,
          yAxisID: 'yPct',
          order: 0,
        },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: {
        legend: sharedLegend,
        tooltip: {
          ...sharedTooltip,
          callbacks: {
            title: ctx => ctx[0]?.label || '',
            label: ctx => {
              const ds = ctx.dataset;
              if (ds.yAxisID === 'yPct') return ` % Accessible: ${ctx.parsed.y.toFixed(1)}%`;
              const chart = ctx.chart;
              const raw = chart._pingHourlyRaw;
              if (!raw) return '';
              const pt = raw[ctx.dataIndex];
              if (!pt) return '';
              if (ctx.datasetIndex === 0) return ` p10: ${pt.p10} ms`;
              if (ctx.datasetIndex === 1) return ` p50: ${pt.p50} ms`;
              if (ctx.datasetIndex === 2) return ` p90: ${pt.p90} ms`;
              return '';
            },
          },
        },
      },
      scales: {
        x: sharedScaleX,
        yMs: { ...sharedScaleY, position: 'left',
          title: { display: true, text: 'ms', color: '#8b949e', font: { size: 11 } } },
        yPct: { type: 'linear', position: 'right', min: 0, max: 100,
          ticks: { color: '#d29922', font: { size: 10, family: 'monospace' }, callback: v => v + '%' },
          grid: { drawOnChartArea: false },
          title: { display: true, text: '% up', color: '#d29922', font: { size: 11 } } },
      },
    },
  };
}

// ── 5m Ping chart: line for avg ping + line for % accessible ──
function makePingConfig5m() {
  return {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Ping (ms)',
          data: [],
          borderColor: '#39c5cf',
          backgroundColor: 'rgba(57,197,207,0.07)',
          borderWidth: 1.5,
          pointRadius: 0,
          fill: true,
          tension: 0.3,
          yAxisID: 'yMs',
        },
        {
          label: '% Accessible',
          data: [],
          borderColor: '#d29922',
          backgroundColor: 'rgba(210,153,34,0.05)',
          borderWidth: 1.5,
          pointRadius: 0,
          fill: false,
          tension: 0.3,
          yAxisID: 'yPct',
        },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: sharedLegend, tooltip: sharedTooltip },
      scales: {
        x: sharedScaleX,
        yMs: { ...sharedScaleY, position: 'left',
          title: { display: true, text: 'ms', color: '#8b949e', font: { size: 11 } } },
        yPct: { type: 'linear', position: 'right', min: 0, max: 100,
          ticks: { color: '#d29922', font: { size: 10, family: 'monospace' }, callback: v => v + '%' },
          grid: { drawOnChartArea: false },
          title: { display: true, text: '% up', color: '#d29922', font: { size: 11 } } },
      },
    },
  };
}

// ── Latest-bar value label plugin ─────────────────────────────
// Draws the most-recent test's actual value above the rightmost bar.
// Chart.js plugins receive the chart instance; we read the raw slots that
// updateSpeedBar() stashes on the chart (chart._speedRaw + chart._isUl).
const latestValuePlugin = {
  id: 'latestValueLabel',
  afterDatasetsDraw(chart) {
    const slots = chart._speedRaw;
    if (!slots || !slots.length) return;
    const last = slots.length - 1;
    const pt = slots[last];
    if (!pt) return;
    const isUl = chart._isUl;
    // For the most-recent bar (single sample), p10 == p50 == p90 == the
    // actual measured value. Pick whichever stack is non-zero.
    const v = (isUl ? pt.ul_p10 : pt.dl_p10);
    const top = (isUl ? pt.ul_p90 : pt.dl_p90) ?? v;
    if (v == null) return;

    const meta = chart.getDatasetMeta(2);   // top stack segment
    const bar  = meta && meta.data && meta.data[last];
    if (!bar) return;

    // Format: 1 decimal under 100, whole number above (consistent with
    // dashboard's other speed readouts).
    const text = (top != null && top >= 100) ? `${Math.round(top)}` : `${(top ?? v).toFixed(1)}`;
    const ctx = chart.ctx;
    ctx.save();
    ctx.font = 'bold 11px ui-monospace, monospace';
    ctx.fillStyle = '#e6edf3';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    // Position 4px above the top of the bar.
    const x = bar.x;
    const y = Math.min(bar.y, bar.base) - 4;
    ctx.fillText(text, x, y);
    ctx.restore();
  },
};

// ── Speed bar chart: stacked p10 / p10→p50 / p50→p90 per hour + latest bar ──
function makeSpeedBarConfig(label, defaultColor) {
  return {
    type: 'bar',
    data: {
      labels: [],
      datasets: [
        { label: 'P10 floor',  data: [], backgroundColor: [], borderColor: 'transparent', borderWidth: 0, stack: 's', borderRadius: 0 },
        { label: 'P10–P90',   data: [], backgroundColor: [], borderColor: [], borderWidth: 1, stack: 's', borderRadius: 0 },
        { label: 'Top 10%',   data: [], backgroundColor: [], borderColor: [], borderWidth: 1, stack: 's', borderRadius: 3 },
      ],
    },
    plugins: [latestValuePlugin],
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: 'index', intersect: false },
      // Reserve a few pixels at the top so the latest-value label drawn by
      // latestValuePlugin isn't clipped against the chart's top edge.
      layout: { padding: { top: 14 } },
      plugins: {
        legend: { display: false },
        tooltip: {
          ...sharedTooltip,
          filter: item => item.datasetIndex === 0,
          callbacks: {
            title: ctx => ctx[0]?.label || '',
            label: ctx => {
              const raw = ctx.chart._speedRaw;
              const pt  = raw && raw[ctx.dataIndex];
              if (!pt) return ' no data';
              const isUl = ctx.chart._isUl;
              if (pt.is_latest) {
                const v = isUl ? pt.ul_p10 : pt.dl_p10;
                return v != null ? ` ${label}: ${v} Mbps (latest)` : ' no data';
              }
              const p10  = isUl ? pt.ul_p10  : pt.dl_p10;
              const p90  = isUl ? pt.ul_p90  : pt.dl_p90;
              const pmax = isUl ? pt.ul_max  : pt.dl_max;
              if (p10 == null) return ' no data';
              return [` p10: ${p10} Mbps`, ` p90: ${p90} Mbps`, ` max: ${pmax} Mbps`];
            },
          },
        },
      },
      scales: {
        x: { ...sharedScaleX, maxTicksLimit: 25, stacked: true },
        y: { ...sharedScaleY, stacked: true, title: { display: true, text: 'Mbps', color: '#8b949e', font: { size: 11 } } },
      },
    },
    _defaultColor: defaultColor,
  };
}

const sharedPlugins = {
  legend: sharedLegend,
  tooltip: sharedTooltip,
};

const pingChart24h    = new Chart(document.getElementById('pingChart24h'),    makePingConfig24h());
const pingChart5m     = new Chart(document.getElementById('pingChart5m'),     makePingConfig5m());
const uploadChartCombined   = new Chart(document.getElementById('uploadChartCombined'),   makeSpeedBarConfig('↑ Upload (Mbps)',   '#3fb950'));
const downloadChartCombined = new Chart(document.getElementById('downloadChartCombined'), makeSpeedBarConfig('↓ Download (Mbps)', '#58a6ff'));

// 7-day uptime is now a custom-canvas timeline (see updateUptimeTimeline below).
const uptimeTimelineCanvas = document.getElementById('uptimeTimeline');

const allCharts = [pingChart24h, pingChart5m, uploadChartCombined, downloadChartCombined];

// ── Chart view toggle ─────────────────────────────────────────
let currentView = 'split';
let lastData = null;

// ── Speed bar updater (global so updateBandwidthCharts can call it) ──
const _perfColors = { good: '#3fb950', ok: '#d29922', poor: '#f85149', neutral: null };

function updateSpeedBar(chart, slots, pc, isUl, highlightLast) {
  const defColor = chart.config._defaultColor || '#58a6ff';
  const last = slots.length - 1;
  chart._speedRaw = slots;
  chart._isUl     = isUl;

  const p10f     = isUl ? 'ul_p10'      : 'dl_p10';
  const p1090df  = isUl ? 'ul_p10_90d'  : 'dl_p10_90d';
  const p90maxdf = isUl ? 'ul_p90_maxd' : 'dl_p90_maxd';

  chart.data.labels = slots.map(s => s.hour);

  // Per-bar base color: latest bar uses perf color, others use network color
  const barColor = slots.map((s, i) => {
    if (highlightLast && i === last && s.is_latest) {
      const perf = isUl ? s.ul_perf : s.dl_perf;
      return _perfColors[perf] || defColor;
    }
    return pc[s.network] || defColor;
  });
  const isLast = slots.map((_, i) => highlightLast && i === last);

  chart.data.datasets[0].data            = slots.map(s => s[p10f]);
  chart.data.datasets[0].backgroundColor = barColor.map((c, i) => c + (isLast[i] ? 'cc' : '22'));

  chart.data.datasets[1].data            = slots.map(s => s[p1090df]);
  chart.data.datasets[1].backgroundColor = barColor.map((c, i) => isLast[i] ? 'transparent' : c + '8c');
  chart.data.datasets[1].borderColor     = barColor.map((c, i) => isLast[i] ? 'transparent' : c + '99');

  chart.data.datasets[2].data            = slots.map(s => s[p90maxdf]);
  chart.data.datasets[2].backgroundColor = barColor.map((c, i) => isLast[i] ? 'transparent' : c + '44');
  chart.data.datasets[2].borderColor     = barColor.map((c, i) => isLast[i] ? 'transparent' : c + '55');

  chart.update('none');
}

function updateBandwidthCharts(d, mode) {
  const pc = d.network_colors || {};
  const titles = {
    '5m':    ['Upload — 5m recent (Mbps)',               'Download — 5m recent (Mbps)'],
    'split': ['Upload — 24h hourly avg + latest (Mbps)', 'Download — 24h hourly avg + latest (Mbps)'],
    '24h':   ['Upload — 24h hourly avg (Mbps)',          'Download — 24h hourly avg (Mbps)'],
  };
  const [ulTitle, dlTitle] = titles[mode] || titles['split'];
  const ulEl = document.getElementById('upload-chart-title');
  const dlEl = document.getElementById('download-chart-title');
  if (ulEl) ulEl.textContent = ulTitle;
  if (dlEl) dlEl.textContent = dlTitle;

  let slots;
  if (mode === '5m') {
    const hist5m = d.speed_history_5m || [];
    slots = hist5m.map(s => ({
      hour:          s.timestamp,
      dl_p10:        s.download_mbps, dl_p10_90d: 0, dl_p90_maxd: 0,
      dl_p90:        s.download_mbps, dl_max:     s.download_mbps,
      ul_p10:        s.upload_mbps,   ul_p10_90d: 0, ul_p90_maxd: 0,
      ul_p90:        s.upload_mbps,   ul_max:     s.upload_mbps,
      network: s.network, is_latest: true,
    }));
    updateSpeedBar(uploadChartCombined,   slots, pc, true,  false);
    updateSpeedBar(downloadChartCombined, slots, pc, false, false);
  } else if (mode === '24h') {
    slots = d.speed_hourly || [];
    updateSpeedBar(uploadChartCombined,   slots, pc, true,  false);
    updateSpeedBar(downloadChartCombined, slots, pc, false, false);
  } else {
    // split: 24h hourly + latest individual test
    slots = [...(d.speed_hourly || []), ...(d.speed_latest ? [d.speed_latest] : [])];
    updateSpeedBar(uploadChartCombined,   slots, pc, true,  !!d.speed_latest);
    updateSpeedBar(downloadChartCombined, slots, pc, false, !!d.speed_latest);
  }
}

function setChartView(mode) {
  currentView = mode;
  const panels = document.getElementById('ping-panels');
  panels.classList.remove('view-24h', 'view-5m');
  if (mode !== 'split') panels.classList.add('view-' + mode);
  ['5m', 'split', '24h'].forEach(m =>
    document.getElementById('btn-view-' + m).classList.toggle('active', m === mode)
  );
  if (lastData) updateBandwidthCharts(lastData, mode);
  allCharts.forEach(c => c.resize());
}


// ── DOM helpers ───────────────────────────────────────────────
function setEl(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

// ── Network name resolution ───────────────────────────────────
function networkDisplayName(fp) {
  if (!fp) return '—';
  const names = lastData?.network_names || {};
  if (names[fp]) return names[fp];
  if (!/^\\d+\\.\\d+\\.\\d+\\.\\d+\\/\\d+$/.test(fp)) return fp;
  return 'Unnamed Wi-Fi';
}

// ── State update ──────────────────────────────────────────────
function update(d) {
  lastData = d;
  const pc = d.network_colors || {};
  const curNetColor = (d.current_network && pc[d.current_network]) ? pc[d.current_network] : '#bc8cff';

  // Header
  const dot  = document.getElementById('status-dot');
  const stxt = document.getElementById('status-text');
  if (d.connected) {
    dot.className  = '';
    stxt.className = 'online';
    stxt.textContent = 'ONLINE';
    document.body.classList.remove('offline');
  } else {
    dot.className  = 'offline';
    stxt.className = 'offline';
    stxt.textContent = 'OFFLINE';
    document.body.classList.add('offline');
  }
  setEl('header-network', d.current_network
    ? `&nbsp;<span style="color:var(--dim)">via</span>&nbsp;<span style="color:${curNetColor}">${networkDisplayName(d.current_network)}</span>`
    : '');
  setEl('header-ping',     d.last_ping_ms ? `&nbsp;${d.last_ping_ms} ms` : '');
  document.getElementById('last-updated').textContent =
    'Updated ' + new Date().toLocaleTimeString();

  // Speed attempts strip (under the upload chart) — primary vs fallback.
  const sa = d.speed_attempts_24h;
  const saEl = document.getElementById('speed-attempts-line');
  if (saEl) {
    if (!sa || !sa.total) {
      saEl.innerHTML = '<span style="color:var(--dim)">No speed tests in last 24h yet</span>';
    } else {
      const parts = [
        'Primary speed tests: <strong>' + sa.primary_ok + ' / ' + sa.total + '</strong> ok in last 24h',
      ];
      if (sa.fallback_ok > 0) {
        parts.push('<span class="sa-warn">' + sa.fallback_ok + ' fell back to HTTP (recorded as site-loss; not graphed)</span>');
      }
      saEl.innerHTML = parts.join(' &nbsp;·&nbsp; ');
    }
  }

  // Status card
  setEl('stat-runtime',  d.runtime_str || '—');
  const statNetEl = document.getElementById('stat-network');
  if (statNetEl) {
    const netName = networkDisplayName(d.current_network);
    statNetEl.textContent = netName;
    statNetEl.style.color = curNetColor;
    statNetEl.style.cursor = d.current_network ? 'pointer' : '';
    statNetEl.title = d.current_network ? 'Click to rename' : '';
  }
  setEl('stat-ping',     d.last_ping_ms  ? `${d.last_ping_ms} ms`  : '—');
  setEl('stat-avg-ping', d.avg_ping_ms   ? `${d.avg_ping_ms} ms`   : '—');
  if (d.uptime_pct_24h != null) {
    const upEl = document.getElementById('stat-uptime-pct');
    if (upEl) {
      upEl.textContent = d.uptime_pct_24h + '%';
      upEl.style.color = d.uptime_pct_24h >= 99 ? 'var(--green)'
                       : d.uptime_pct_24h >= 95 ? 'var(--yellow)'
                       : 'var(--red)';
    }
  }
  setEl('stat-cur-uptime', d.current_uptime_str || (d.connected ? '—' : 'DOWN'));
  setEl('stat-outages',  d.outage_count  != null ? String(d.outage_count) : '0');
  setEl('stat-downtime', d.total_outage_secs > 0 ? `${d.total_outage_secs}s` : '—');
  setEl('stat-next-test',
    d.speed_in_progress ? '…'
    : d.next_test_in != null ? `in ${d.next_test_in}s`
    : '—'
  );
  setEl('speed-status', d.speed_in_progress ? (d.speed_status || 'Testing…') : '');

  // ── AI diagnostics "last run" ────────────────────────────────
  updateDiagLastRun(d.last_diagnosis_at);

  // ── Router rejections tile ───────────────────────────────────
  const r = d.router || {};
  if (r.available) {
    setEl('stat-router-1h', String(r.count_1h || 0));
    const dnsEl = document.getElementById('stat-router-dns');
    if (dnsEl) {
      dnsEl.textContent = String(r.dns_drops_1h || 0);
      dnsEl.style.color = (r.dns_drops_1h > 0) ? 'var(--red)' : 'var(--dim)';
    }
    document.getElementById('stat-router-1h').style.color =
      (r.count_1h > 50) ? 'var(--yellow)' : 'var(--dim)';
  } else if (r.poll_error) {
    setEl('stat-router-1h', 'err');
    setEl('stat-router-dns', '—');
  }

  // ── 24h Ping chart: hourly p10/p50/p90 + % accessible ────────
  if (d.ping_hourly && d.ping_hourly.length > 0) {
    const raw = d.ping_hourly;
    pingChart24h._pingHourlyRaw = raw;
    pingChart24h.data.labels           = raw.map(h => h.hour);
    pingChart24h.data.datasets[0].data = raw.map(h => h.p10);
    pingChart24h.data.datasets[1].data = raw.map(h => h.p50);
    pingChart24h.data.datasets[2].data = raw.map(h => h.p90);
    // Accessibility is now bucketed server-side alongside ping percentiles
    // (same rolling 24h slots) instead of being re-bucketed here by
    // hour-of-day. The old client-side bucketing collided across days.
    pingChart24h.data.datasets[3].data = raw.map(h => h.access);
    pingChart24h.update('none');
  }

  // ── 5m Ping chart: ping line + % accessible line ─────────────
  if (d.ping_chart_5m !== undefined) {
    const pings  = d.ping_chart_5m   || [];
    const access = d.access_chart_5m || [];

    const tToSecs = t => {
      const parts = t.split(':').map(Number);
      return parts[0] * 3600 + parts[1] * 60 + (parts[2] || 0);
    };
    const accessPcts = pings.map(p => {
      if (!access.length) return null;
      let best = null, bestDelta = Infinity;
      access.forEach(a => {
        const delta = Math.abs(tToSecs(a.t) - tToSecs(p.t));
        if (delta < bestDelta) { bestDelta = delta; best = a.v; }
      });
      return best;
    });

    pingChart5m.data.labels           = pings.map(p => p.t);
    pingChart5m.data.datasets[0].data = pings.map(p => p.v);
    pingChart5m.data.datasets[1].data = accessPcts;
    pingChart5m.update('none');
  }

  // Bandwidth charts — mode-aware (5m / split / 24h)
  if (d.speed_hourly) {
    updateBandwidthCharts(d, currentView);
  }

  // 7-day uptime timeline rendered separately via /api/timeline (see below).

  // Site status matrix
  if (d.site_matrix && d.site_matrix.length > 0) {
    const fmtMs  = v => v != null ? Math.round(v) + 'ms' : '—';
    const fmtPct = v => v != null ? Math.round(v) + '%'  : '—';
    const pctCls = v => v == null ? '' : v >= 90 ? 'good' : v >= 60 ? 'warn' : 'bad';
    const fmtLat = (p10, p50, p90) => {
      if (p10 == null && p50 == null && p90 == null) return '—';
      return [p10, p50, p90].map(v => v != null ? Math.round(v) : '—').join('/') + 'ms';
    };

    // Pool thresholds footer — helps the user see what GREAT/OK/SLOW/POOR
    // mean tonight. Same string appears on every tile so we build it once.
    const pt = d.site_pool_thresholds || {};
    const ptFooter = (pt.great_ms != null) ? `
      <div class="tt-pool">
        <span class="tt-pool-lbl">band:</span>
        <span class="s-green">≤${pt.great_ms}ms</span>
        ·
        <span>${pt.great_ms}–${pt.slow_ms}ms</span>
        ·
        <span class="s-yellow">${pt.slow_ms}–${pt.poor_ms}ms</span>
        ·
        <span class="s-red">>${pt.poor_ms}ms</span>
        <div class="tt-pool-sub">from ${pt.samples} pings · ${pt.window_hours}h pool</div>
      </div>` : '';

    const tiles = d.site_matrix.map(s => {
      // Best available window for the displayed sub-line (prefer fresh).
      const pct = s.pct_5m ?? s.pct_1h ?? s.pct_24h;
      const p50 = s.p50_5m ?? s.p50_1h ?? s.p50_24h;

      // Verdict comes from the server now — pool-percentile based, see
      // SITE_VERDICT_* constants in connection_monitor.py.
      let verdict = s.verdict;
      let colorCls = s.verdict_class || '';
      if (verdict == null) {
        // Server returned no verdict (cold start before pool exists).
        verdict = (pct == null) ? '…' : '…';
      }

      // Trend: compare 5m median to 1h median (need both to show arrow)
      let trendHtml = '';
      if (s.p50_5m != null && s.p50_1h != null && s.p50_1h > 0) {
        const ratio = s.p50_5m / s.p50_1h;
        if (ratio < 0.8) {
          trendHtml = '<span class="site-tile-trend trend-up"  title="Improving">↑</span>';
        } else if (ratio > 1.3) {
          trendHtml = '<span class="site-tile-trend trend-down" title="Degrading">↓</span>';
        } else {
          trendHtml = '<span class="site-tile-trend trend-flat" title="Stable">→</span>';
        }
      }

      // Single subtitle: current latency or status
      const sub = !s.up ? 'unreachable'
                : p50  != null ? fmtMs(p50)
                : 'no data';

      // Tooltip rows
      const mkTtRow = (win, pctV, p10, p50v, p90) => `
        <div class="tt-row">
          <span class="tt-win">${win}</span>
          <span class="tt-pct ${pctCls(pctV)}">${fmtPct(pctV)}</span>
          <span class="tt-lat">${fmtLat(p10, p50v, p90)}</span>
        </div>`;

      // Escape host/name before interpolating into HTML. These can originate
      // from remote collectors via /api/ingest (aggregator mode), so treat them
      // as untrusted. Quotes are escaped too since host lands in an attribute.
      const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g,
        c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      const displayName = esc(s.name || s.host.replace(/^www\\./, ''));
      const hostEsc = esc(s.host);
      return `<div class="site-tile ${colorCls}" data-host="${hostEsc}" title="Click for ping history">
        <div class="site-tile-host">${displayName}</div>
        <div class="site-tile-verdict">
          <span class="site-tile-dot"></span>${verdict}${trendHtml}
        </div>
        <div class="site-tile-sub">${sub}</div>
        <div class="site-tile-tooltip">
          <div class="tt-head">${hostEsc}</div>
          ${mkTtRow('5m',  s.pct_5m,  s.p10_5m,  s.p50_5m,  s.p90_5m)}
          ${mkTtRow('1h',  s.pct_1h,  s.p10_1h,  s.p50_1h,  s.p90_1h)}
          ${mkTtRow('24h', s.pct_24h, s.p10_24h, s.p50_24h, s.p90_24h)}
          ${ptFooter}
        </div>
      </div>`;
    }).join('');
    setEl('site-matrix', tiles);
  }

}

// ── Uptime timeline (7d) ─────────────────────────────────────
function fmtIncidentDuration(s) {
  s = Math.max(0, Math.floor(s));
  if (s < 60) return s + ' seconds';
  if (s < 3600) return Math.floor(s / 60) + ' minutes';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

function onTimelineClick(inc) {
  if (!inc) return;
  if (inc.analyzed) {
    window.location = '/diagnose?show=' + encodeURIComponent(inc.id);
    return;
  }
  const start = new Date(inc.start);
  const end   = inc.end ? new Date(inc.end) : new Date();
  const sec   = (end - start) / 1000;
  const kindLabel = inc.category === 'outage' ? 'outage'
                   : inc.category === 'site_loss' ? 'site-loss period'
                   : 'degraded period';
  const ok = window.confirm(
    'Run AI diagnosis on this ' + fmtIncidentDuration(sec) +
    ' ' + kindLabel + ' at ' + start.toLocaleString() + '?\\n\\n' +
    'This will use ~$0.02 of API credit and take ~5–10 seconds.'
  );
  if (!ok) return;
  window.location = '/diagnose?run=' + encodeURIComponent(inc.id);
}

let _timelineCache = null;

// Per-page kind filter, persisted (shared key with /diagnose so the
// preference flows across pages).
function loadKindFilter() {
  const set = new Set();
  try {
    const raw = localStorage.getItem('diagKindFilter');
    if (raw) JSON.parse(raw).forEach(k => set.add(k));
  } catch (e) {}
  return set;
}
function saveKindFilter(set) {
  try { localStorage.setItem('diagKindFilter', JSON.stringify([...set])); } catch (e) {}
}
let _kindFilter = loadKindFilter();
let _showDismissed = (function() {
  try { return localStorage.getItem('diagShowDismissed') === '1'; }
  catch (e) { return false; }
})();
document.querySelectorAll('.kind-filter input[type="checkbox"]').forEach(cb => {
  if (cb.dataset.kind) {
    cb.checked = !_kindFilter.has(cb.dataset.kind);
    cb.addEventListener('change', () => {
      if (cb.checked) _kindFilter.delete(cb.dataset.kind);
      else            _kindFilter.add(cb.dataset.kind);
      saveKindFilter(_kindFilter);
      paintTimeline();
    });
  } else if (cb.hasAttribute('data-show-dismissed')) {
    cb.checked = _showDismissed;
    cb.addEventListener('change', () => {
      _showDismissed = cb.checked;
      try { localStorage.setItem('diagShowDismissed', _showDismissed ? '1' : '0'); }
      catch (e) {}
      paintTimeline();
    });
  }
});

function paintTimeline() {
  if (!_timelineCache) return;
  const dismissedSet = new Set(_timelineCache.dismissed_ids || []);
  UptimeTimeline.render(uptimeTimelineCanvas, {
    days: 7,
    clusters: _timelineCache.clusters,
    analyzedIds: _timelineCache.analyzed_ids,
    titles: _timelineCache.titles || {},
    monitorStartedAt: _timelineCache.monitor_started_at,
    monitorGaps: _timelineCache.monitor_gaps || [],
    onIncidentClick: onTimelineClick,
    kindFilter: _kindFilter,
    dismissedClusterIds: dismissedSet,
    showDismissed: _showDismissed,
  });
}
async function refreshTimeline() {
  try {
    const resp = await fetch('/api/timeline?days=7');
    if (!resp.ok) return;
    _timelineCache = await resp.json();
    paintTimeline();
  } catch (e) {}
}
// Resize re-renders from cache; never refetches (avoids the layout-thrash loop
// that caused tooltip flicker on the rightmost bar).
window.addEventListener('resize', paintTimeline);

// ── AI Diagnostics last-run subtext ──────────────────────────
function fmtRelative(iso) {
  if (!iso) return 'Never run';
  const then = new Date(iso);
  if (isNaN(then.getTime())) return 'Never run';
  const secs = Math.floor((Date.now() - then.getTime()) / 1000);
  if (secs < 60)   return 'Last run: just now';
  if (secs < 3600) return 'Last run: ' + Math.floor(secs / 60) + 'm ago';
  if (secs < 86400) return 'Last run: ' + Math.floor(secs / 3600) + 'h ago';
  return 'Last run: ' + Math.floor(secs / 86400) + 'd ago';
}
function updateDiagLastRun(iso) {
  const el = document.getElementById('diag-last-run');
  if (el) el.textContent = fmtRelative(iso);
}

// ── Polling loop ──────────────────────────────────────────────
let _selectedHost = '';

async function poll() {
  try {
    const url = _selectedHost ? '/api/state?host=' + encodeURIComponent(_selectedHost) : '/api/state';
    const resp = await fetch(url);
    if (resp.ok) {
      const d = await resp.json();
      update(d);
      // Aggregator: show control ping status
      if (d.control_ping_ms !== undefined) {
        const ctrl = document.getElementById('control-status');
        ctrl.style.display = '';
        const ok = d.control_connected;
        ctrl.innerHTML = 'Control: ' + (ok
          ? '<span style="color:var(--green)">' + d.control_ping_ms.toFixed(0) + 'ms</span>'
          : '<span style="color:var(--red)">down</span>');
      }
      // Show last_seen for remote hosts
      if (d.last_seen && _selectedHost) {
        const el = document.getElementById('host-last-seen');
        const ago = Math.round((Date.now() - new Date(d.last_seen).getTime()) / 1000);
        el.textContent = ago < 120 ? 'synced ' + ago + 's ago'
                       : ago < 7200 ? 'synced ' + Math.round(ago/60) + 'm ago'
                       : 'synced ' + Math.round(ago/3600) + 'h ago';
      } else {
        document.getElementById('host-last-seen').textContent = '';
      }
    }
  } catch {
    document.getElementById('last-updated').textContent = 'Reconnecting…';
  }
}

// On narrow screens default to single-panel (5m) so charts always have full width
if (window.innerWidth <= 700) setChartView('5m');

// Re-fit charts on resize / orientation change
window.addEventListener('resize', () => allCharts.forEach(c => c.resize()));

poll();
setInterval(poll, 2000);

// Timeline refreshes less often; outages don't change every 2 seconds.
refreshTimeline();
setInterval(refreshTimeline, 30000);

// ── Multi-host support ───────────────────────────────────────
(async function initMultiHost() {
  try {
    const resp = await fetch('/api/hosts');
    if (!resp.ok) return;
    const data = await resp.json();
    const hosts = data.hosts || [];
    if (hosts.length > 1) {
      const wrap = document.getElementById('host-selector-wrap');
      const sel = document.getElementById('host-selector');
      wrap.style.display = '';
      hosts.forEach(h => {
        const opt = document.createElement('option');
        opt.value = h.monitor_host;
        opt.textContent = h.display_name || h.monitor_host;
        sel.appendChild(opt);
      });
      sel.addEventListener('change', () => {
        _selectedHost = sel.value;
        poll();
      });
    }
    // Show VPS link for local instances that have SERVER_URL configured
    const stateResp = await fetch('/api/state');
    if (stateResp.ok) {
      const st = await stateResp.json();
      // The server injects vps_url into the state if SERVER_URL is set
      if (st.vps_url) {
        const link = document.getElementById('vps-link');
        link.href = st.vps_url;
        link.style.display = '';
      }
    }
  } catch {}
})();

// ── Per-site ping history modal ───────────────────────────────
function _siteCss(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// ── Site-modal layer toggles (persistent across all sites) ────
// Layer keys:
//   band        — per-bin p10–p90 fill (off by default; was previously the
//                 default but noisy at short bin widths)
//   mean        — per-bin mean (white line)
//   threshold   — pool P10–P90 horizontal band (the "OK zone" tonight)
//   threshold_p99 — pool P99 horizontal line (the POOR threshold)
//   slow_zone   — yellow shading where bin-mean > pool P90 (SLOW)
//   poor_zone   — orange shading where bin-mean > pool P99 (POOR)
//   outliers    — red dots for raw spikes above the in-window p99/2×p90
//   noresp      — red ✕ marks for null samples (no response)
//   outage      — red bands for sustained unreachable runs
const SITE_LAYER_KEYS = ['band', 'mean', 'threshold', 'threshold_p99',
                         'slow_zone', 'poor_zone',
                         'outliers', 'noresp', 'outage'];
const SITE_LAYER_DEFAULT_OFF = ['band'];
const SITE_LAYER_STORAGE_KEY = 'siteModalLayersOff_v2';
function _loadSiteLayersOff() {
  const off = new Set();
  try {
    const raw = localStorage.getItem(SITE_LAYER_STORAGE_KEY);
    if (raw !== null) {
      JSON.parse(raw).forEach(k => off.add(k));
    } else {
      // First-time defaults reflect the new layer set: hide the per-bin
      // band in favor of the pool-threshold reference.
      SITE_LAYER_DEFAULT_OFF.forEach(k => off.add(k));
    }
  } catch (e) {}
  return off;
}
function _saveSiteLayersOff(off) {
  try { localStorage.setItem(SITE_LAYER_STORAGE_KEY, JSON.stringify([...off])); }
  catch (e) {}
}
let _siteLayersOff = _loadSiteLayersOff();
let _siteModalData = null;
function isSiteLayerOn(key) { return !_siteLayersOff.has(key); }
function refreshSiteLegendStrikes() {
  document.querySelectorAll('.site-modal-legend > span[data-layer]').forEach(el => {
    const k = el.dataset.layer;
    el.classList.toggle('layer-off', !isSiteLayerOn(k));
  });
}
// Document-level delegation so the listener works even though the modal
// is hidden until first opened.
document.addEventListener('click', (evt) => {
  const lg = evt.target.closest('.site-modal-legend > span[data-layer]');
  if (!lg) return;
  evt.stopPropagation();   // don't bubble into the tile/overlay handlers
  const k = lg.dataset.layer;
  if (_siteLayersOff.has(k)) _siteLayersOff.delete(k);
  else                        _siteLayersOff.add(k);
  _saveSiteLayersOff(_siteLayersOff);
  refreshSiteLegendStrikes();
  if (_siteModalData) paintSiteHistory(_siteModalData);
});

// Click network name to rename
document.addEventListener('click', (evt) => {
  const el = evt.target.closest('#stat-network');
  if (!el || !lastData?.current_network) return;
  const fp = lastData.current_network;
  const cur = networkDisplayName(fp);
  const name = prompt('Name this network:', cur === 'Unnamed Wi-Fi' ? '' : cur);
  if (name === null) return;
  fetch('/api/network/rename', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({fingerprint: fp, name: name.trim() || null})
  }).then(r => r.json()).then(() => {
    fetch('/api/state').then(r => r.json()).then(d => update(d));
  });
});

async function openSiteModal(host) {
  const overlay = document.getElementById('site-modal-overlay');
  const titleEl = document.getElementById('site-modal-title');
  const subEl = document.getElementById('site-modal-sub');
  const statsEl = document.getElementById('site-modal-stats');
  titleEl.textContent = host;
  subEl.textContent = 'Loading…';
  statsEl.innerHTML = '';
  overlay.style.display = 'flex';
  // Clear any prior canvas paint to avoid flashes of stale data.
  const canvas = document.getElementById('site-modal-canvas');
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  try {
    // hours intentionally omitted → server auto-selects: 24h primary,
    // falls back to 7d when 24h has too few samples (matches the site-tile
    // verdict baseline). This stabilizes the p10–p90 band on quiet sites.
    const resp = await fetch('/api/site_history?host=' + encodeURIComponent(host));
    if (!resp.ok) throw new Error('http ' + resp.status);
    const data = await resp.json();
    titleEl.textContent = data.name + (data.name !== data.host ? '  (' + data.host + ')' : '');
    const ps = data.ping_stats || {};
    const parts = [];
    parts.push('reachable <strong>' + (data.reachable_pct != null ? data.reachable_pct + '%' : '—') + '</strong>');
    if (ps.p50 != null) parts.push('median <strong>' + ps.p50 + ' ms</strong>');
    if (ps.p10 != null && ps.p90 != null) parts.push('p10–p90 <strong>' + ps.p10 + '–' + ps.p90 + ' ms</strong>');
    const winLabel = data.hours >= 48 ? Math.round(data.hours / 24) + 'd' : data.hours + 'h';
    const winNote = data.auto_window && data.hours !== data.primary_hours
      ? ' <span style="color:var(--dim)">(extended from ' + data.primary_hours + 'h)</span>' : '';
    parts.push('<strong>' + (data.samples ? data.samples.length : 0) + '</strong> samples · last ' + winLabel + winNote);
    const ptd = data.pool_thresholds || {};
    if (ptd.great_ms != null) {
      parts.push('pool <strong>P10 ' + ptd.great_ms + ' / P90 ' + ptd.slow_ms + ' / P99 ' + ptd.poor_ms + '</strong> ms');
    }
    subEl.innerHTML = parts.join(' &nbsp;·&nbsp; ');
    _siteModalData = data;
    refreshSiteLegendStrikes();
    paintSiteHistory(data);
  } catch (e) {
    subEl.textContent = 'Failed to load: ' + e.message;
  }
}

function closeSiteModal() {
  const overlay = document.getElementById('site-modal-overlay');
  overlay.style.display = 'none';
}

function paintSiteHistory(data) {
  const canvas = document.getElementById('site-modal-canvas');
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth;
  const cssH = canvas.clientHeight;
  if (cssW <= 0 || cssH <= 0) return;
  canvas.width = Math.floor(cssW * dpr);
  canvas.height = Math.floor(cssH * dpr);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const C = {
    text: _siteCss('--text'),  dim: _siteCss('--dim'),
    border: _siteCss('--border'), green: _siteCss('--green'),
    red: _siteCss('--red'), cyan: _siteCss('--cyan'),
  };

  const ML = 42, MR = 12, MT = 10, MB = 22;
  const W = cssW - ML - MR;
  const H = cssH - MT - MB;
  if (W <= 10 || H <= 20) return;

  const samples = data.samples || [];
  if (!samples.length) {
    ctx.fillStyle = C.dim;
    ctx.font = '12px ui-monospace, monospace';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText('No samples in window', cssW / 2, cssH / 2);
    return;
  }

  const t0 = new Date(samples[0][0]).getTime();
  const t1 = new Date(samples[samples.length - 1][0]).getTime();
  const span = Math.max(1, t1 - t0);
  const xOf = (ms) => ML + ((ms - t0) / span) * W;

  // Pool thresholds — drawn as horizontal reference lines + drive the
  // SLOW/POOR shading. Same data that powers the GREAT/OK/SLOW/POOR tile.
  const pool = data.pool_thresholds || {};
  const poolP10 = pool.great_ms;   // edge of GREAT
  const poolP90 = pool.slow_ms;    // edge of SLOW
  const poolP99 = pool.poor_ms;    // edge of POOR

  // Y scale: include the pool thresholds so they're never clipped, plus
  // the in-window p99 (or p90 if outliers hidden) so the chart fits the
  // visible data without leaving wasted headroom.
  const pings = samples.map(s => s[1]).filter(v => v != null && isFinite(v));
  let yMax = 100;
  const yMaxCandidates = [];
  if (pings.length) {
    const sorted = [...pings].sort((a, b) => a - b);
    const useTop = isSiteLayerOn('outliers') ? 0.99 : 0.90;
    yMaxCandidates.push(sorted[Math.floor(useTop * (sorted.length - 1))]);
  }
  if (isSiteLayerOn('threshold_p99') && poolP99 != null) yMaxCandidates.push(poolP99);
  if (isSiteLayerOn('threshold')     && poolP90 != null) yMaxCandidates.push(poolP90);
  if (yMaxCandidates.length) {
    yMax = Math.max(100, Math.ceil(Math.max(...yMaxCandidates) * 1.15 / 50) * 50);
  }
  const yOf = (ms) => MT + H - (Math.min(Math.max(0, ms), yMax) / yMax) * H;

  // ── Bin samples first so we can shade SLOW/POOR zones alongside the
  // outage tints. Aim for ~80 bins across the chart width.
  const N_BINS = Math.min(120, Math.max(20, Math.floor(W / 6)));
  const binSpan = span / N_BINS;
  const bins = [];   // each: { t, vals: [..], p10, p50, p90, mean }
  for (let i = 0; i < N_BINS; i++) bins.push({ t: t0 + (i + 0.5) * binSpan, vals: [] });
  samples.forEach(([ts, v]) => {
    if (v == null) return;
    const idx = Math.min(N_BINS - 1, Math.floor((new Date(ts).getTime() - t0) / binSpan));
    if (idx >= 0) bins[idx].vals.push(v);
  });
  function _pctOf(sorted, q) {
    if (!sorted.length) return null;
    if (sorted.length === 1) return sorted[0];
    const idx = q / 100 * (sorted.length - 1);
    const lo = Math.floor(idx), hi = Math.min(lo + 1, sorted.length - 1);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (idx - lo);
  }
  bins.forEach(b => {
    if (!b.vals.length) { b.p10 = b.p50 = b.p90 = b.mean = null; return; }
    const s = [...b.vals].sort((a, b) => a - b);
    b.p10  = _pctOf(s, 10);
    b.p50  = _pctOf(s, 50);
    b.p90  = _pctOf(s, 90);
    b.mean = b.vals.reduce((a, c) => a + c, 0) / b.vals.length;
  });

  // ── SLOW / POOR zone shading: contiguous runs of >=2 bins where the
  // bin-mean is above the corresponding pool threshold. Yellow = SLOW
  // (above pool P90), orange = POOR (above pool P99). Distinct from the
  // red "unreachable" outage bands (those are reachability events). When
  // POOR overlaps SLOW, POOR wins (drawn second).
  function shadeRuns(threshold, color, minRunBins, layerKey) {
    if (!isSiteLayerOn(layerKey) || threshold == null) return;
    let runStart = -1;
    const closeRun = (endIdx) => {
      if (runStart < 0) return;
      const runLen = endIdx - runStart;
      if (runLen >= minRunBins) {
        const tStart = bins[runStart].t - binSpan / 2;
        const tEnd   = bins[endIdx - 1].t + binSpan / 2;
        const x0 = Math.max(ML, xOf(tStart));
        const x1 = Math.min(ML + W, xOf(tEnd));
        if (x1 > x0) {
          ctx.fillStyle = color;
          ctx.fillRect(x0, MT, x1 - x0, H);
        }
      }
      runStart = -1;
    };
    bins.forEach((b, i) => {
      const above = b.mean != null && b.mean > threshold;
      if (above) { if (runStart < 0) runStart = i; }
      else       { closeRun(i); }
    });
    closeRun(bins.length);
  }
  shadeRuns(poolP90, 'rgba(210,153,34,0.16)', 2, 'slow_zone');  // SLOW
  shadeRuns(poolP99, 'rgba(247,140,55,0.22)', 2, 'poor_zone');  // POOR

  // Outage tints (red bands for periods when site was unreachable).
  if (isSiteLayerOn('outage')) {
    (data.outages || []).forEach(o => {
      const sMs = new Date(o.start).getTime();
      const eMs = o.end ? new Date(o.end).getTime() : t1;
      const x0 = Math.max(ML, xOf(Math.max(t0, sMs)));
      const x1 = Math.min(ML + W, xOf(Math.min(t1, eMs)));
      if (x1 <= x0) return;
      ctx.fillStyle = 'rgba(248,81,73,0.18)';
      ctx.fillRect(x0, MT, x1 - x0, H);
    });
  }

  // Y gridlines + labels.
  ctx.strokeStyle = C.border;
  ctx.font = '9px ui-monospace, monospace';
  ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
  for (let i = 0; i <= 4; i++) {
    const v = (yMax / 4) * i;
    const y = yOf(v);
    ctx.beginPath();
    ctx.moveTo(ML, y); ctx.lineTo(ML + W, y);
    ctx.globalAlpha = i === 0 ? 0.6 : 0.2;
    ctx.stroke();
    ctx.globalAlpha = 1;
    ctx.fillStyle = C.dim;
    ctx.fillText(Math.round(v) + 'ms', ML - 4, y);
  }

  // X tick labels.
  const spanMin = span / 60000;
  const stepMin = spanMin <= 60 ? 10 : spanMin <= 360 ? 60 : spanMin <= 720 ? 120 : 180;
  const stepMs = stepMin * 60000;
  let firstTick = Math.ceil(t0 / stepMs) * stepMs;
  ctx.textAlign = 'center'; ctx.textBaseline = 'top';
  ctx.fillStyle = C.dim;
  for (let tx = firstTick; tx <= t1; tx += stepMs) {
    const x = xOf(tx);
    if (x < ML || x > ML + W) continue;
    const d = new Date(tx);
    ctx.fillText(String(d.getHours()).padStart(2, '0') + ':' +
                 String(d.getMinutes()).padStart(2, '0'),
                 x, MT + H + 4);
  }

  // ── Pool threshold reference lines — horizontal lines at pool P10,
  // P90, P99. These are the verdict thresholds: a site whose recent p50
  // sits in the band [P10, P90] is OK; above P90 it's SLOW; above P99 it's
  // POOR. Drawn in the same teal family as the per-bin band so the user
  // can see at a glance "where do I sit relative to the rest?"
  if (isSiteLayerOn('threshold') && poolP10 != null && poolP90 != null) {
    ctx.save();
    // Light cyan filled band between P10 and P90.
    const yTop = yOf(poolP90), yBot = yOf(poolP10);
    if (yBot > yTop) {
      ctx.fillStyle = 'rgba(57,197,207,0.10)';
      ctx.fillRect(ML, yTop, W, yBot - yTop);
    }
    // Dashed P10 + P90 lines.
    ctx.strokeStyle = 'rgba(57,197,207,0.55)';
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 3]);
    [poolP10, poolP90].forEach(v => {
      const y = yOf(v);
      ctx.beginPath();
      ctx.moveTo(ML, y); ctx.lineTo(ML + W, y);
      ctx.stroke();
    });
    ctx.setLineDash([]);
    // Right-edge labels.
    ctx.fillStyle = 'rgba(57,197,207,0.85)';
    ctx.font = '9px ui-monospace, monospace';
    ctx.textAlign = 'right'; ctx.textBaseline = 'bottom';
    ctx.fillText('pool P90 ' + Math.round(poolP90) + 'ms', ML + W - 2, yOf(poolP90) - 1);
    ctx.textBaseline = 'top';
    ctx.fillText('pool P10 ' + Math.round(poolP10) + 'ms', ML + W - 2, yOf(poolP10) + 1);
    ctx.restore();
  }
  if (isSiteLayerOn('threshold_p99') && poolP99 != null) {
    ctx.save();
    ctx.strokeStyle = 'rgba(248,81,73,0.65)';
    ctx.lineWidth = 1;
    ctx.setLineDash([2, 4]);
    const y = yOf(poolP99);
    ctx.beginPath();
    ctx.moveTo(ML, y); ctx.lineTo(ML + W, y);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = 'rgba(248,81,73,0.85)';
    ctx.font = '9px ui-monospace, monospace';
    ctx.textAlign = 'right'; ctx.textBaseline = 'bottom';
    ctx.fillText('pool P99 ' + Math.round(poolP99) + 'ms', ML + W - 2, y - 1);
    ctx.restore();
  }

  // ── Per-bin p10–p90 band (off by default; opt-in via legend). ──
  if (isSiteLayerOn('band')) {
    const BAND_FILL = 'rgba(57,197,207,0.28)';
    let seg = [];
    function flushBand(seg) {
      if (seg.length < 2) return;
      ctx.beginPath();
      ctx.moveTo(xOf(seg[0].t), yOf(seg[0].p90));
      for (let i = 1; i < seg.length; i++) ctx.lineTo(xOf(seg[i].t), yOf(seg[i].p90));
      for (let i = seg.length - 1; i >= 0; i--) ctx.lineTo(xOf(seg[i].t), yOf(seg[i].p10));
      ctx.closePath();
      ctx.fillStyle = BAND_FILL;
      ctx.fill();
    }
    bins.forEach(b => {
      if (b.p50 == null) { flushBand(seg); seg = []; return; }
      seg.push(b);
    });
    flushBand(seg);
  }

  // ── Mean line on top of the band.
  if (isSiteLayerOn('mean')) {
    ctx.strokeStyle = C.text;
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    let drawing = false;
    bins.forEach(b => {
      if (b.mean == null) { drawing = false; return; }
      const x = xOf(b.t), y = yOf(b.mean);
      if (!drawing) { ctx.moveTo(x, y); drawing = true; }
      else          { ctx.lineTo(x, y); }
    });
    ctx.stroke();
  }

  // ── Outlier dots (raw samples above the in-window p99 / 2× p90). ──
  // Drawn at the sample's actual y position so they sit above the band,
  // matching the diagnose-page ping-spike style.
  let outlierThreshold = null;
  if (pings.length >= 20) {
    const sorted = [...pings].sort((a, b) => a - b);
    const p99 = sorted[Math.floor(0.99 * (sorted.length - 1))];
    const p90 = sorted[Math.floor(0.90 * (sorted.length - 1))];
    outlierThreshold = Math.max(p99, p90 * 2);
  }
  if (outlierThreshold != null && isSiteLayerOn('outliers')) {
    ctx.save();
    ctx.fillStyle = C.red;
    ctx.strokeStyle = C.text;
    ctx.lineWidth = 0.75;
    samples.forEach(([ts, v]) => {
      if (v == null || v < outlierThreshold) return;
      const x = xOf(new Date(ts).getTime()), y = yOf(v);
      ctx.beginPath();
      ctx.arc(x, y, 2, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
    });
    ctx.restore();
  }

  // ── No-response ✕ marks at the bottom of the chart. ──
  // One ✕ per contiguous run of null samples, positioned at the run's
  // start. Avoids cluttering long unreachable stretches with hundreds of
  // overlapping marks while still flagging every transition into "no
  // response" state.
  if (isSiteLayerOn('noresp')) {
    ctx.save();
    ctx.strokeStyle = C.red;
    ctx.lineWidth = 1.4;
    const noRespY = MT + H - 4;
    let inRun = false;
    samples.forEach(([ts, v]) => {
      if (v == null) {
        if (!inRun) {
          const x = xOf(new Date(ts).getTime());
          if (x >= ML && x <= ML + W) {
            ctx.beginPath();
            ctx.moveTo(x - 3, noRespY - 3); ctx.lineTo(x + 3, noRespY + 3);
            ctx.moveTo(x + 3, noRespY - 3); ctx.lineTo(x - 3, noRespY + 3);
            ctx.stroke();
          }
          inRun = true;
        }
      } else {
        inRun = false;
      }
    });
    ctx.restore();
  }
}

// All handlers below use delegation on document so they don't depend on the
// referenced elements existing at script-evaluation time. (The site-matrix
// is rendered async after the first /api/state poll, and the modal overlay
// HTML lives outside this script block — both can be missing when this
// code first runs.)
// (NB: do not put a literal closing-script tag in a comment here — the HTML
// parser will end the script element early, silently breaking everything.)
document.addEventListener('click', (evt) => {
  // Site tile click → open per-site ping history modal.
  const tile = evt.target.closest('.site-tile');
  if (tile) {
    const host = tile.dataset.host;
    if (host) openSiteModal(host);
    return;
  }
  // Click on the dim modal background → close.
  if (evt.target.id === 'site-modal-overlay') closeSiteModal();
});
document.addEventListener('keydown', (evt) => {
  if (evt.key === 'Escape') closeSiteModal();
});
</script>

<!-- Per-site ping-history modal (hidden by default) -->
<div id="site-modal-overlay" class="site-modal-overlay" style="display:none">
  <div class="site-modal">
    <div class="site-modal-head">
      <div>
        <div class="site-modal-title" id="site-modal-title">—</div>
        <div class="site-modal-sub" id="site-modal-sub"></div>
      </div>
      <button class="site-modal-close" onclick="closeSiteModal()" aria-label="Close">×</button>
    </div>
    <div class="site-modal-canvas-wrap">
      <canvas id="site-modal-canvas"></canvas>
    </div>
    <div class="site-modal-stats" id="site-modal-stats"></div>
    <div class="site-modal-legend" title="Click a legend entry to toggle that layer (saved across sites)">
      <span data-layer="threshold"><span style="background:rgba(57,197,207,0.10);border:1px dashed rgba(57,197,207,0.55);display:inline-block;width:14px;height:8px;border-radius:1px"></span> pool P10–P90</span>
      <span data-layer="threshold_p99"><span style="border-top:1px dashed rgba(248,81,73,0.85);display:inline-block;width:14px;height:0"></span> pool P99</span>
      <span data-layer="mean"><span style="color:var(--text)">─</span> mean</span>
      <span data-layer="slow_zone"><span style="background:rgba(210,153,34,0.16);display:inline-block;width:14px;height:8px;border-radius:1px"></span> SLOW (mean &gt; P90)</span>
      <span data-layer="poor_zone"><span style="background:rgba(247,140,55,0.22);display:inline-block;width:14px;height:8px;border-radius:1px"></span> POOR (mean &gt; P99)</span>
      <span data-layer="band"><span style="background:rgba(57,197,207,0.28);display:inline-block;width:14px;height:8px;border-radius:1px"></span> per-bin p10–p90</span>
      <span data-layer="outliers"><span class="lg-spike"></span> high-ping outlier</span>
      <span data-layer="noresp"><span class="lg-cross"></span> no response</span>
      <span data-layer="outage"><span style="background:rgba(248,81,73,0.4);display:inline-block;width:14px;height:8px;border-radius:1px"></span> sustained unreachable</span>
    </div>
  </div>
</div>
</body>
</html>
"""


LOG_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connection Monitor — Log</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<style>
:root {
  --bg:      #0d1117;
  --card:    #161b22;
  --border:  #30363d;
  --text:    #e6edf3;
  --dim:     #8b949e;
  --green:   #3fb950;
  --red:     #f85149;
  --yellow:  #d29922;
  --blue:    #58a6ff;
  --cyan:    #39c5cf;
  --magenta: #bc8cff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: ui-monospace, 'SF Mono', 'Fira Code', monospace;
  font-size: 13px;
  padding: 14px;
  min-height: 100vh;
}
header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
}
.header-title { font-weight: 700; font-size: 13px; letter-spacing: 0.05em; }
.spacer { flex: 1; }
#last-updated { color: var(--dim); font-size: 11px; }
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  margin-bottom: 12px;
}
.card-title {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--dim);
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}
table { width: 100%; border-collapse: collapse; }
th {
  text-align: left;
  color: var(--dim);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 0 8px 8px 0;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
td {
  padding: 5px 8px 5px 0;
  border-bottom: 1px solid rgba(255,255,255,0.04);
  vertical-align: middle;
  font-size: 12px;
}
tr:last-child td { border-bottom: none; }
.badge {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.badge-green   { background: rgba(63,185,80,0.15);  color: var(--green); }
.badge-red     { background: rgba(248,81,73,0.15);  color: var(--red); }
.badge-yellow  { background: rgba(210,153,34,0.15); color: var(--yellow); }
.badge-blue    { background: rgba(88,166,255,0.15); color: var(--blue); }
.badge-dim     { background: rgba(139,148,158,0.15); color: var(--dim); }
a.back-link {
  display: inline-block;
  padding: 5px 14px;
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--dim);
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  text-decoration: none;
  transition: color 0.15s, border-color 0.15s;
}
a.back-link:hover { color: var(--blue); border-color: var(--blue); }
</style>
</head>
<body>
<header>
  <span class="header-title">Connection Monitor — Log</span>
  <div class="spacer"></div>
  <a class="back-link" href="/">Dashboard</a>
  &nbsp;
  <span id="last-updated">Loading…</span>
</header>

<div class="card">
  <div class="card-title">Speed Tests — last 24h</div>
  <table>
    <thead><tr>
      <th>Time</th><th>Label</th><th>Network</th>
      <th style="text-align:right">Download</th>
      <th style="text-align:right">Upload</th>
      <th style="text-align:right">Ping</th>
    </tr></thead>
    <tbody id="speed-tbody">
      <tr><td colspan="6" style="color:var(--dim)">Loading…</td></tr>
    </tbody>
  </table>
</div>

<div class="card">
  <div class="card-title">Outages — last 24h</div>
  <table>
    <thead><tr>
      <th>Started</th><th>Ended</th><th style="text-align:right">Duration</th>
    </tr></thead>
    <tbody id="outage-tbody">
      <tr><td colspan="3" style="color:var(--dim)">Loading…</td></tr>
    </tbody>
  </table>
</div>

<div class="card">
  <div class="card-title">Event Log — up to 500 events</div>
  <table>
    <thead><tr>
      <th style="width:80px">Time</th><th style="width:80px">Level</th><th>Message</th>
    </tr></thead>
    <tbody id="event-tbody">
      <tr><td colspan="3" style="color:var(--dim)">Loading…</td></tr>
    </tbody>
  </table>
</div>

<script>
function setEl(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}
let _logNetNames = {};
function networkDisplayName(fp) {
  if (!fp) return '—';
  if (_logNetNames[fp]) return _logNetNames[fp];
  if (!/^\\d+\\.\\d+\\.\\d+\\.\\d+\\/\\d+$/.test(fp)) return fp;
  return 'Unnamed Wi-Fi';
}

async function poll() {
  try {
    const resp = await fetch('/api/log');
    if (!resp.ok) return;
    const d = await resp.json();
    _logNetNames = d.network_names || {};

    document.getElementById('last-updated').textContent =
      'Updated ' + new Date().toLocaleTimeString();

    // Speed tests
    if (d.speed && d.speed.length > 0) {
      const rows = d.speed.map(s => `<tr>
        <td style="color:var(--dim)">${s.ts}</td>
        <td><span class="badge badge-blue">${s.label || '—'}</span></td>
        <td style="color:var(--magenta)">${networkDisplayName(s.network)}</td>
        <td style="text-align:right;color:var(--cyan)">&#8595; ${s.dl} Mbps</td>
        <td style="text-align:right;color:var(--green)">&#8593; ${s.ul} Mbps</td>
        <td style="text-align:right;color:var(--dim)">${s.ping ? s.ping + ' ms' : '—'}</td>
      </tr>`).join('');
      setEl('speed-tbody', rows);
    } else {
      setEl('speed-tbody', '<tr><td colspan="6" style="color:var(--dim)">No speed tests recorded</td></tr>');
    }

    // Outages
    if (d.outages && d.outages.length > 0) {
      const rows = d.outages.map(o => {
        const endCell = o.ongoing
          ? '<span class="badge badge-red">ongoing</span>'
          : (o.end || '—');
        const durStyle = o.ongoing ? 'color:var(--red)' : 'color:var(--yellow)';
        return `<tr>
          <td>${o.start}</td>
          <td>${endCell}</td>
          <td style="text-align:right;${durStyle}">${o.duration}</td>
        </tr>`;
      }).join('');
      setEl('outage-tbody', rows);
    } else {
      setEl('outage-tbody', '<tr><td colspan="3" style="color:var(--dim)">None recorded</td></tr>');
    }

    // Events
    if (d.events && d.events.length > 0) {
      const lvlBadge = {
        success: 'badge-green',
        error:   'badge-red',
        warning: 'badge-yellow',
        info:    'badge-dim',
      };
      const rows = d.events.map(e => `<tr>
        <td style="color:var(--dim)">${e.ts.substring(11, 19)}</td>
        <td><span class="badge ${lvlBadge[e.level] || 'badge-dim'}">${e.level}</span></td>
        <td>${e.msg}</td>
      </tr>`).join('');
      setEl('event-tbody', rows);
    } else {
      setEl('event-tbody', '<tr><td colspan="3" style="color:var(--dim)">No events</td></tr>');
    }
  } catch {
    document.getElementById('last-updated').textContent = 'Error fetching data';
  }
}

poll();
setInterval(poll, 5000);
</script>
</body>
</html>
"""


DIAGNOSE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connection Monitor — AI Diagnosis</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
<script src="/static/timeline.js"></script>
<style>
:root {
  --bg:      #0d1117;
  --card:    #161b22;
  --border:  #30363d;
  --text:    #e6edf3;
  --dim:     #8b949e;
  --green:   #3fb950;
  --red:     #f85149;
  --yellow:  #d29922;
  --blue:    #58a6ff;
  --cyan:    #39c5cf;
  --magenta: #bc8cff;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: ui-monospace, 'SF Mono', 'Fira Code', monospace;
  font-size: 13px;
  padding: 14px;
  min-height: 100vh;
}
header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 12px;
}
.header-title { font-weight: 700; font-size: 13px; letter-spacing: 0.05em; }
.spacer { flex: 1; }
.back-link {
  color: var(--blue);
  text-decoration: none;
  font-size: 12px;
  padding: 4px 8px;
  border: 1px solid var(--border);
  border-radius: 5px;
}
.back-link:hover { background: var(--card); border-color: var(--blue); }
.run-controls { display: flex; gap: 6px; align-items: center; }
.run-controls .label { color: var(--dim); font-size: 11px; }
.run-btn, .back-link {
  background: var(--bg); color: var(--text);
  border: 1px solid var(--border); border-radius: 5px;
  padding: 5px 10px; font-family: inherit; font-size: 12px; cursor: pointer;
}
.run-btn:hover { border-color: var(--blue); color: var(--blue); }
.run-btn:disabled { opacity: 0.4; cursor: not-allowed; }
#run-status { color: var(--dim); font-size: 11px; margin-left: 8px; }

.layout {
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 12px;
  min-height: calc(100vh - 90px);
}
@media (max-width: 700px) {
  .layout { grid-template-columns: 1fr; }
}
.card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
}
.card-title {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--dim);
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}

#history { max-height: calc(100vh - 110px); overflow-y: auto; }
.day-header {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--dim);
  padding: 10px 0 4px 0;
}
.day-header:first-child { padding-top: 0; }
.history-item {
  display: block;
  padding: 8px 10px;
  margin: 2px 0;
  border-radius: 5px;
  cursor: pointer;
  border: 1px solid transparent;
}
.history-item:hover { background: rgba(255,255,255,0.03); }
.history-item.selected {
  background: rgba(88,166,255,0.08);
  border-color: var(--blue);
}
.history-item .title {
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 4px;
  line-height: 1.3;
  overflow-wrap: break-word;
}
.history-item .row1 {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  font-size: 11px;
  color: var(--dim);
  margin-bottom: 2px;
}
.history-item .time { font-weight: 600; }
.history-item .window { color: var(--dim); font-size: 11px; }
.history-item .severity {
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.sev-NONE     { color: var(--green); }
.sev-MINOR    { color: var(--cyan); }
.sev-MODERATE { color: var(--yellow); }
.sev-SEVERE   { color: var(--red); }
.sev-ERROR    { color: var(--red); }
.sev-UNKNOWN  { color: var(--dim); }
.history-item.dismissed { opacity: 0.55; }
.history-item.dismissed .title { text-decoration: line-through; }
.dismissed-tag {
  margin-left: 6px;
  font-size: 9px;
  font-weight: 600;
  letter-spacing: 0.05em;
  color: var(--dim);
  background: rgba(139,148,158,0.18);
  border: 1px solid rgba(139,148,158,0.35);
  padding: 1px 4px;
  border-radius: 3px;
  text-transform: uppercase;
}

#detail-empty { color: var(--dim); font-size: 12px; padding: 16px; text-align: center; }
#detail-meta { color: var(--dim); font-size: 11px; margin-bottom: 16px; }
#detail-summary { font-size: 14px; line-height: 1.55; margin-bottom: 14px; }
#detail-impact  { color: var(--dim); font-size: 13px; line-height: 1.5; margin-bottom: 16px; }
.detail-cols {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 18px;
}
@media (max-width: 800px) {
  .detail-cols { grid-template-columns: 1fr; }
}
.detail-cols h3 {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--dim);
  margin-bottom: 8px;
  font-weight: 600;
}
.detail-cols ol { margin: 0; padding-left: 20px; font-size: 13px; line-height: 1.55; }
.detail-cols li { margin-bottom: 8px; }
.detail-cols .conf { color: var(--dim); font-size: 10px; margin-left: 4px; }
.detail-cols .cause-detail { color: var(--dim); display: block; margin-top: 2px; }
#detail-error {
  display: none;
  color: var(--red);
  background: rgba(248,81,73,0.08);
  border: 1px solid var(--red);
  padding: 10px;
  border-radius: 5px;
  margin-bottom: 14px;
  font-size: 12px;
}
.diag-chart-head {
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  margin-bottom: 6px;
}
.diag-chart-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--dim);
}
.diag-chart-stats {
  font-size: 11px;
  color: var(--dim);
}
.diag-chart-stats strong { color: var(--text); font-weight: 600; }
.diag-chart-canvas-wrap {
  position: relative;
  width: 100%;
  height: 200px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  overflow: hidden;
}
#diag-chart {
  width: 100%;
  height: 100%;
  display: block;
}
.diag-chart-tooltip {
  position: absolute;
  pointer-events: none;
  background: rgba(13,17,23,0.94);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 5px 8px;
  font-size: 11px;
  color: var(--text);
  line-height: 1.4;
  white-space: nowrap;
  display: none;
  z-index: 5;
  box-shadow: 0 2px 8px rgba(0,0,0,0.4);
}
.diag-chart-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 6px;
  font-size: 10px;
  color: var(--dim);
}
.diag-chart-legend > span[data-layer] {
  cursor: pointer;
  user-select: none;
  border-radius: 3px;
  padding: 1px 3px;
  margin: -1px -3px;
  transition: opacity 0.15s, background 0.15s;
}
.diag-chart-legend > span[data-layer]:hover {
  background: rgba(255,255,255,0.04);
}
.diag-chart-legend > span[data-layer].layer-off {
  opacity: 0.35;
  text-decoration: line-through;
}
.diag-chart-legend > span {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.lg-swatch {
  display: inline-block;
  width: 14px; height: 10px;
  border-radius: 2px;
}
.lg-line {
  display: inline-block;
  width: 14px; height: 2px;
}
.lg-band {
  display: inline-block;
  width: 16px; height: 8px;
  border-radius: 1px;
}
.lg-dotted {
  display: inline-block;
  width: 18px; height: 0;
  border-top: 1.5px dashed var(--text);
  vertical-align: middle;
  opacity: 0.7;
}
.lg-cross {
  display: inline-block;
  width: 10px; height: 10px;
  position: relative;
}
.lg-cross::before, .lg-cross::after {
  content: ''; position: absolute;
  left: 50%; top: 0;
  width: 1.4px; height: 100%;
  background: var(--red);
  transform-origin: center;
}
.lg-cross::before { transform: translateX(-50%) rotate(45deg); }
.lg-cross::after  { transform: translateX(-50%) rotate(-45deg); }
.lg-tri {
  display: inline-block;
  width: 0; height: 0;
  border-left: 5px solid transparent;
  border-right: 5px solid transparent;
  border-top: 7px solid #39c5cf;
}
.lg-spike {
  display: inline-block;
  width: 6px; height: 6px;
  background: var(--red);
  border: 1px solid var(--text);
  border-radius: 50%;
}
.diag-delete-btn {
  background: var(--bg);
  color: var(--dim);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 3px 9px;
  font-family: inherit;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  cursor: pointer;
  transition: all 0.15s;
}
.diag-delete-btn:hover {
  border-color: var(--red);
  color: var(--red);
  background: rgba(248,81,73,0.08);
}
.diag-delete-btn:disabled { opacity: 0.4; cursor: not-allowed; }

/* Kind-filter toggles next to the timeline title */
.kind-filter {
  display: inline-flex;
  gap: 10px;
  font-size: 11px;
  color: var(--dim);
  font-weight: normal;
  letter-spacing: 0.02em;
}
.kind-filter label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
  user-select: none;
}
.kind-filter input[type="checkbox"] {
  accent-color: var(--blue);
  margin: 0;
  cursor: pointer;
}

/* Analysis-in-progress modal — front and center while a new diagnosis is
   running. Auto-closes on completion. */
.diag-run-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.65);
  display: flex; align-items: center; justify-content: center;
  z-index: 200;
  backdrop-filter: blur(2px);
}
.diag-run-modal {
  background: var(--card);
  border: 1px solid var(--magenta);
  border-radius: 8px;
  padding: 24px 28px;
  width: min(440px, 90vw);
  text-align: center;
  box-shadow: 0 8px 32px rgba(188,140,255,0.25);
}
.diag-run-spinner {
  display: inline-block;
  width: 36px; height: 36px;
  border: 3px solid rgba(188,140,255,0.18);
  border-top-color: var(--magenta);
  border-radius: 50%;
  animation: diag-spin 0.9s linear infinite;
  margin-bottom: 14px;
}
@keyframes diag-spin { to { transform: rotate(360deg); } }
.diag-run-title {
  font-size: 14px; font-weight: 600; color: var(--text);
  margin-bottom: 6px;
}
.diag-run-target {
  font-size: 12px; color: var(--magenta);
  margin-bottom: 4px; word-break: break-word;
}
.diag-run-status {
  font-size: 11px; color: var(--dim);
  letter-spacing: 0.02em;
  font-family: ui-monospace, 'SF Mono', monospace;
}
.diag-run-elapsed {
  font-size: 10px; color: var(--dim);
  margin-top: 8px;
  font-variant-numeric: tabular-nums;
}

.analyzed-strip {
  margin-top: 6px;
  font-size: 11px;
  color: var(--dim);
  line-height: 1.55;
}
.analyzed-label {
  font-size: 9px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--dim);
  margin-right: 4px;
}
.analyzed-strip strong { color: var(--text); font-weight: 600; }
.analyzed-zero strong { color: var(--dim); font-weight: 400; }
.analyzed-warn { color: var(--yellow); }
.analyzed-warn strong { color: var(--yellow); }

.signal-chips {
  margin-top: 4px;
  font-size: 10px;
  color: var(--dim);
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}
.signal-chips-label {
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-size: 9px;
  margin-right: 2px;
}
.signal-chip {
  background: rgba(57,197,207,0.10);
  color: var(--cyan);
  border: 1px solid rgba(57,197,207,0.25);
  border-radius: 3px;
  padding: 1px 5px;
  font-family: ui-monospace, 'SF Mono', monospace;
  font-size: 10px;
}
.lg-dot {
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
}
.lg-vline {
  display: inline-block;
  width: 0; height: 12px;
  border-left: 1px dashed var(--text);
}
</style>
</head>
<body>

<header>
  <a class="back-link" href="/">← Monitor</a>
  <span class="header-title">AI DIAGNOSIS</span>
  <div class="spacer"></div>
  <div class="run-controls">
    <span class="label">Run new:</span>
    <button class="run-btn" data-window="ongoing">Ongoing (5m)</button>
    <button class="run-btn" data-window="1h">Last 1h</button>
    <button class="run-btn" data-window="24h">Last 24h</button>
    <span id="run-status"></span>
  </div>
</header>

<div class="card" id="timeline-card" style="margin-bottom:12px">
  <div class="card-title" style="display:flex;justify-content:space-between;align-items:baseline;gap:14px;flex-wrap:wrap">
    <span>30-day Uptime Timeline</span>
    <span class="kind-filter">
      <label><input type="checkbox" data-kind="slow" checked> slow</label>
      <label><input type="checkbox" data-kind="site_loss" checked> site loss</label>
      <label><input type="checkbox" data-show-dismissed> show dismissed</label>
    </span>
    <span id="timeline-stats" style="color:var(--dim);font-size:11px;font-weight:normal;margin-left:auto"></span>
  </div>
  <div style="height:240px;position:relative">
    <canvas id="timelineCanvas" style="width:100%;height:100%"></canvas>
  </div>
  <div style="color:var(--dim);font-size:10px;margin-top:6px;display:flex;gap:14px;flex-wrap:wrap">
    <span><span style="color:var(--red)">█</span> outage</span>
    <span><span style="color:var(--yellow)">▨</span> degraded (slow / high ping)</span>
    <span><span style="color:#39c5cf">▨</span> site loss (single site flaky)</span>
    <span><span style="color:rgba(248,81,73,0.45)">█</span><span style="color:rgba(210,153,34,0.45)">▨</span> already analyzed (click to view)</span>
    <span><span style="color:#39c5cf">─</span> now</span>
  </div>
</div>

<div class="layout">

  <!-- Left: History -->
  <div class="card" id="history-card">
    <div class="card-title">History (30 days)</div>
    <div id="history">
      <div style="color:var(--dim);font-size:12px">Loading…</div>
    </div>
  </div>

  <!-- Right: Detail -->
  <div class="card" id="detail-card">
    <div class="card-title" id="detail-title-bar" style="display:flex;justify-content:space-between;align-items:center;gap:6px">
      <span>Diagnosis</span>
      <span style="display:flex;gap:6px">
        <button id="diag-dismiss-btn" class="diag-delete-btn" style="display:none" title="Hide this incident from the timeline + history (toggle on the 'show dismissed' filter to see it again)">Dismiss</button>
        <button id="diag-delete-btn" class="diag-delete-btn" style="display:none" title="Delete this diagnosis (cluster becomes re-runnable)">Delete</button>
      </span>
    </div>
    <div id="detail-empty">No diagnosis selected. Run a new one or pick from history.</div>
    <div id="detail-body" style="display:none">
      <div id="detail-meta"></div>
      <div id="diag-chart-wrap" style="display:none;margin-bottom:16px">
        <div class="diag-chart-head">
          <span class="diag-chart-label">Window analyzed</span>
          <span class="diag-chart-stats" id="diag-chart-stats"></span>
        </div>
        <div class="diag-chart-canvas-wrap">
          <canvas id="diag-chart"></canvas>
          <div id="diag-chart-tooltip" class="diag-chart-tooltip"></div>
        </div>
        <div class="diag-chart-legend" id="diag-chart-legend">
          <span data-layer="bg_normal" title="Click to toggle — green normal-period background"><span class="lg-swatch" style="background:rgba(63,185,80,0.18)"></span>normal</span>
          <span data-layer="bg_degraded" title="Click to toggle"><span class="lg-swatch" style="background:rgba(210,153,34,0.22)"></span>degraded</span>
          <span data-layer="bg_site_loss" title="Click to toggle"><span class="lg-swatch" style="background:rgba(57,197,207,0.18)"></span>site loss</span>
          <span data-layer="bg_outage" title="Click to toggle"><span class="lg-swatch" style="background:rgba(248,81,73,0.28)"></span>outage</span>
          <span data-layer="ping_band" title="Click to toggle"><span class="lg-band" style="background:rgba(57,197,207,0.28)"></span>ping p10–p90 (ms · left)</span>
          <span data-layer="dl_dots" title="Click to toggle"><span class="lg-dot" style="background:#58a6ff"></span>↓ download (Mbps · right)</span>
          <span data-layer="ul_dots" title="Click to toggle"><span class="lg-dot" style="background:#3fb950"></span>↑ upload (Mbps · right)</span>
          <span data-layer="threshold_line" title="Click to toggle"><span class="lg-dotted"></span>7d-P10 / high-ping threshold (event boundary)</span>
          <span data-layer="failed_speedtest" title="Click to toggle"><span class="lg-cross"></span>primary speedtest failed (Ookla unreachable)</span>
          <span data-layer="site_outage_marks" title="Click to toggle"><span class="lg-tri"></span>per-site outage</span>
          <span data-layer="ping_spikes" title="Click to toggle"><span class="lg-spike"></span>ping spike (outlier)</span>
          <span data-layer="event_markers" title="Click to toggle"><span class="lg-vline"></span>event marker</span>
        </div>
      </div>
      <div id="detail-error"></div>
      <div id="detail-summary"></div>
      <div id="detail-impact"></div>
      <div class="detail-cols">
        <div>
          <h3>Likely causes</h3>
          <ol id="detail-causes"></ol>
        </div>
        <div>
          <h3>Recommendations</h3>
          <ol id="detail-recs"></ol>
        </div>
      </div>
    </div>
  </div>

</div>

<script>
let history = [];
let selectedId = null;

function fmtTime(iso) {
  if (!iso) return '—';
  return iso.replace('T', ' ').slice(0, 19);
}
function fmtDay(iso) {
  if (!iso) return 'Unknown';
  const d = new Date(iso);
  const today = new Date();
  const yest  = new Date(); yest.setDate(today.getDate() - 1);
  const sameDay = (a, b) => a.getFullYear()===b.getFullYear() && a.getMonth()===b.getMonth() && a.getDate()===b.getDate();
  if (sameDay(d, today)) return 'Today';
  if (sameDay(d, yest))  return 'Yesterday';
  return d.toLocaleDateString(undefined, {weekday:'short', month:'short', day:'numeric'});
}
function severityOf(diag) {
  if (!diag.ok) return 'ERROR';
  return ((diag.result || {}).severity || 'unknown').toUpperCase();
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Compact "Analyzed:" strip showing what data was actually fed to the model
// for this diagnosis. Anything zero is shown dimmed; the router section calls
// out missing-data conditions explicitly so we can tell config issues from
// honest "no events in window."
function renderAnalyzedStrip(s) {
  if (!s || typeof s !== 'object') return '';
  const dim = (label, val) => '<span class="' + (val ? '' : 'analyzed-zero') + '">'
    + label + ' <strong>' + (val == null ? '0' : val) + '</strong></span>';
  let routerPart;
  if (!s.router_available) {
    routerPart = '<span class="analyzed-warn">router log: <strong>not configured</strong></span>';
  } else if (s.router_poll_error) {
    routerPart = '<span class="analyzed-warn">router log: <strong>poll error</strong> ('
      + escapeHtml(String(s.router_poll_error).slice(0, 80)) + ')</span>';
  } else if (!s.router_last_poll) {
    routerPart = '<span class="analyzed-warn">router log: <strong>never polled</strong></span>';
  } else {
    routerPart = dim('router events', s.router_events) +
                 ' &nbsp;·&nbsp; ' + dim('DNS-probe drops', s.dns_probe_drops);
  }
  // Window + upload size — proves what was actually sent to the model.
  // Window is the analyzed slice; uploaded_bytes is the JSON payload after
  // summarization (router events are histogrammed; only top 30 DNS-probe
  // drop samples are sent verbatim — never the raw event list).
  let windowPart = '';
  if (s.window_start && s.window_end) {
    const ws = String(s.window_start).slice(0, 16).replace('T', ' ');
    const we = String(s.window_end).slice(0, 16).replace('T', ' ');
    windowPart = '<div style="margin-top:2px;color:var(--dim)"><span class="analyzed-label">Uploaded:</span> '
      + 'window <strong>' + ws + ' → ' + we + '</strong>';
    if (s.uploaded_bytes != null) {
      const kb = (s.uploaded_bytes / 1024).toFixed(1);
      windowPart += ' &nbsp;·&nbsp; payload <strong>' + kb + ' KB</strong>';
    }
    windowPart += '</div>';
  }
  return '<div class="analyzed-strip">'
    + '<span class="analyzed-label">Analyzed:</span> '
    + dim('outages', s.outages)
    + ' &nbsp;·&nbsp; ' + dim('ping samples', s.ping_samples)
    + ' &nbsp;·&nbsp; ' + dim('speed tests', s.speed_tests)
    + ' &nbsp;·&nbsp; ' + dim('sites', s.sites_checked)
    + ' &nbsp;·&nbsp; ' + routerPart
    + windowPart
    + '</div>';
}

// When did the analyzed event actually happen? Prefer the incident's start
// (real-world event time) over evaluated_at (when the human ran the analysis).
// Fall back to window_end, then evaluated_at, then 0.
function eventTimeOf(d) {
  const cd = d && d.chart_data;
  if (cd && cd.incident && cd.incident.start) return new Date(cd.incident.start).getTime();
  if (cd && cd.window_end) return new Date(cd.window_end).getTime();
  return new Date(d && d.evaluated_at || 0).getTime();
}
function eventIsoOf(d) {
  const cd = d && d.chart_data;
  if (cd && cd.incident && cd.incident.start) return cd.incident.start;
  if (cd && cd.window_end) return cd.window_end;
  return d && d.evaluated_at;
}

function renderHistory() {
  const container = document.getElementById('history');
  container.innerHTML = '';
  // Hide dismissed diagnoses unless the "show dismissed" toggle is on.
  const visible = (typeof _showDismissed !== 'undefined' && _showDismissed)
    ? history
    : history.filter(d => !d.dismissed);
  if (visible.length === 0) {
    const msg = history.length === 0
      ? 'No diagnoses yet. Run one to start.'
      : 'All diagnoses are dismissed. Toggle "show dismissed" above to view.';
    container.innerHTML = '<div style="color:var(--dim);font-size:12px">' + msg + '</div>';
    return;
  }
  let lastDay = null;
  visible.forEach(d => {
    const eventIso = eventIsoOf(d);
    const day = fmtDay(eventIso);
    if (day !== lastDay) {
      const h = document.createElement('div');
      h.className = 'day-header';
      h.textContent = day;
      container.appendChild(h);
      lastDay = day;
    }
    const item = document.createElement('div');
    item.className = 'history-item'
      + (d.id === selectedId ? ' selected' : '')
      + (d.dismissed ? ' dismissed' : '');
    const sev = severityOf(d);
    const t = (eventIso || '').slice(11, 16) || '—';
    const title = (d.result && d.result.title) ? d.result.title : null;
    const titleRow = title
      ? '<div class="title">' + escapeHtml(title) + '</div>'
      : '';
    const dismissedTag = d.dismissed
      ? '<span class="dismissed-tag" title="dismissed">dismissed</span>' : '';
    item.innerHTML =
      titleRow +
      '<div class="row1"><span class="time">' + t + '</span>' +
      '<span class="window">' + (d.window || '?') + '</span></div>' +
      '<div class="severity sev-' + sev + '">' + sev + dismissedTag + '</div>';
    item.addEventListener('click', () => selectDiagnosis(d.id));
    container.appendChild(item);
  });
}

function selectDiagnosis(id) {
  selectedId = id;
  const d = history.find(x => x.id === id);
  renderHistory();
  renderDetail(d);
  // Refresh the timeline highlight so the yellow outline + popover move
  // to whichever cluster matches this diagnosis.
  if (typeof paintTimeline === 'function') paintTimeline();
}

function renderDetail(diag) {
  const empty = document.getElementById('detail-empty');
  const body  = document.getElementById('detail-body');
  const err   = document.getElementById('detail-error');
  const delBtn = document.getElementById('diag-delete-btn');
  if (!diag) {
    empty.style.display = 'block';
    body.style.display = 'none';
    if (delBtn) delBtn.style.display = 'none';
    const dismissBtn0 = document.getElementById('diag-dismiss-btn');
    if (dismissBtn0) dismissBtn0.style.display = 'none';
    renderDiagChart(null);
    return;
  }
  empty.style.display = 'none';
  body.style.display = 'block';
  err.style.display = 'none';
  if (delBtn) {
    delBtn.style.display = 'inline-block';
    delBtn.dataset.id = diag.id || '';
  }
  // Dismiss button — only meaningful when the diagnosis is tied to a
  // specific cluster (outage_id). Window-based diagnoses (1h/24h) don't
  // have a cluster to hide.
  const dismissBtn = document.getElementById('diag-dismiss-btn');
  if (dismissBtn) {
    if (diag.outage_id) {
      dismissBtn.style.display = 'inline-block';
      dismissBtn.dataset.outageId = diag.outage_id;
      dismissBtn.dataset.dismissed = diag.dismissed ? '1' : '0';
      dismissBtn.textContent = diag.dismissed ? 'Restore' : 'Dismiss';
    } else {
      dismissBtn.style.display = 'none';
    }
  }
  renderDiagChart(diag.chart_data || null);

  const sev = severityOf(diag);
  const sevColor = {NONE:'var(--green)', MINOR:'var(--cyan)', MODERATE:'var(--yellow)', SEVERE:'var(--red)', ERROR:'var(--red)'}[sev] || 'var(--dim)';
  const r0 = diag.result || {};
  const titleHtml = r0.title
    ? '<div style="font-size:16px;font-weight:600;color:var(--text);margin-bottom:6px">' +
      escapeHtml(r0.title) + '</div>'
    : '';
  document.getElementById('detail-meta').innerHTML =
    titleHtml +
    'Evaluated ' + fmtTime(diag.evaluated_at) +
    ' · Window: <strong>' + (diag.window || '—') + '</strong>' +
    ' · Severity: <strong style="color:' + sevColor + '">' + sev + '</strong>' +
    (diag.model ? (' · Model: ' + diag.model) : '') +
    renderAnalyzedStrip(diag.snapshot_summary);

  if (!diag.ok) {
    err.style.display = 'block';
    err.textContent = diag.error || 'Diagnosis failed.';
    document.getElementById('detail-summary').textContent = '';
    document.getElementById('detail-impact').textContent = '';
    document.getElementById('detail-causes').innerHTML = '';
    document.getElementById('detail-recs').innerHTML = '';
    return;
  }
  const r = diag.result || {};
  if (!r.summary && diag.raw_text) {
    document.getElementById('detail-summary').textContent = diag.raw_text;
    document.getElementById('detail-impact').textContent = '(model did not return JSON; raw output above)';
    document.getElementById('detail-causes').innerHTML = '';
    document.getElementById('detail-recs').innerHTML = '';
    return;
  }
  document.getElementById('detail-summary').textContent = r.summary || '';
  document.getElementById('detail-impact').textContent = r.household_impact || '';
  const causesEl = document.getElementById('detail-causes');
  causesEl.innerHTML = '';
  (r.likely_causes || []).forEach(c => {
    const li = document.createElement('li');
    const conf = c.confidence ? '<span class="conf">(' + c.confidence + ')</span>' : '';
    const sigs = (c.signals || []).filter(Boolean);
    const sigHtml = sigs.length
      ? '<div class="signal-chips">' +
          '<span class="signal-chips-label">based on:</span>' +
          sigs.map(s => '<code class="signal-chip">' + escapeHtml(s) + '</code>').join('') +
        '</div>'
      : '';
    li.innerHTML = '<strong>' + escapeHtml(c.cause || '') + '</strong>' + conf +
      '<span class="cause-detail">' + escapeHtml(c.detail || '') + '</span>' +
      sigHtml;
    causesEl.appendChild(li);
  });
  const recsEl = document.getElementById('detail-recs');
  recsEl.innerHTML = '';
  (r.recommendations || []).forEach(text => {
    const li = document.createElement('li');
    li.textContent = text;
    recsEl.appendChild(li);
  });
}

// ── Diagnosis chart ─────────────────────────────────────────────
let _diagChartState = null;

// Per-layer visibility — clicking a legend entry toggles the layer.
// State persists in localStorage and is shared across reports + sessions.
const DIAG_LAYER_KEYS = [
  'bg_normal', 'bg_degraded', 'bg_site_loss', 'bg_outage',
  'ping_band', 'dl_dots', 'ul_dots', 'threshold_line',
  'failed_speedtest', 'site_outage_marks', 'ping_spikes', 'event_markers',
];
function loadDiagLayers() {
  const off = new Set();
  try {
    const raw = localStorage.getItem('diagChartLayersOff');
    if (raw) JSON.parse(raw).forEach(k => off.add(k));
  } catch (e) {}
  return off;
}
let _diagLayersOff = loadDiagLayers();
function isLayerOn(key) { return !_diagLayersOff.has(key); }
function saveDiagLayers() {
  try { localStorage.setItem('diagChartLayersOff', JSON.stringify([..._diagLayersOff])); }
  catch (e) {}
}
function refreshLegendStrikes() {
  document.querySelectorAll('#diag-chart-legend > span[data-layer]').forEach(el => {
    el.classList.toggle('layer-off', _diagLayersOff.has(el.dataset.layer));
  });
}
// Wire legend clicks once at script load. paintDiagChart re-reads
// _diagLayersOff at every paint, so toggles take effect immediately.
document.addEventListener('click', (evt) => {
  const span = evt.target.closest('#diag-chart-legend > span[data-layer]');
  if (!span) return;
  const key = span.dataset.layer;
  if (_diagLayersOff.has(key)) _diagLayersOff.delete(key);
  else                          _diagLayersOff.add(key);
  saveDiagLayers();
  refreshLegendStrikes();
  if (_diagChartState) paintDiagChart();
});

function renderDiagChart(data) {
  const wrap = document.getElementById('diag-chart-wrap');
  if (!data || !data.window_start || !data.window_end) {
    wrap.style.display = 'none';
    _diagChartState = null;
    return;
  }
  wrap.style.display = 'block';
  _diagChartState = data;
  paintDiagChart();
}

function _diagChartCss(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function paintDiagChart() {
  const data = _diagChartState;
  if (!data) return;
  const canvas = document.getElementById('diag-chart');
  if (!canvas || !canvas.offsetParent) return;
  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth;
  const cssH = canvas.clientHeight;
  if (cssW <= 0 || cssH <= 0) return;
  canvas.width  = Math.floor(cssW * dpr);
  canvas.height = Math.floor(cssH * dpr);
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const COLORS = {
    text:     _diagChartCss('--text'),
    dim:      _diagChartCss('--dim'),
    border:   _diagChartCss('--border'),
    green:    _diagChartCss('--green'),
    yellow:   _diagChartCss('--yellow'),
    red:      _diagChartCss('--red'),
    cyan:     _diagChartCss('--cyan'),
    magenta:  _diagChartCss('--magenta'),
  };
  // Background tints (slightly stronger than chart-card so the bands read).
  const BG_NORMAL    = 'rgba(63,185,80,0.10)';
  const BG_DEGRADED  = 'rgba(210,153,34,0.18)';
  const BG_OUTAGE    = 'rgba(248,81,73,0.22)';
  const BG_SITE_LOSS = 'rgba(57,197,207,0.18)';   // teal for site_loss

  const ML = 40, MR = 44, MT = 10, MB = 22;
  const W = cssW - ML - MR;
  const H = cssH - MT - MB;
  if (W <= 10 || H <= 20) return;

  const t0 = new Date(data.window_start).getTime();
  const t1 = new Date(data.window_end).getTime();
  const span = Math.max(1, t1 - t0);
  const xOf = (ms) => ML + ((ms - t0) / span) * W;

  // ── Y-scale (left): ping ms — derived from band p90, speed pings, AND
  // spike values. Without spike values, every spike clamps to the top
  // edge ("solid red line" look on long windows).
  const bands = data.ping_bands || [];
  // Y-scale pools — only include sources for layers that are currently
  // visible, so toggling a layer off rescales the chart accordingly.
  const p50s = bands.map(b => b[2]).filter(v => v != null && isFinite(v));
  const p90s = isLayerOn('ping_band')
    ? bands.map(b => b[3]).filter(v => v != null && isFinite(v))
    : [];
  const speedPings = (isLayerOn('dl_dots') || isLayerOn('ul_dots'))
    ? (data.speed_series || []).map(s => s.ping).filter(v => v != null && isFinite(v))
    : [];
  const spikePings = isLayerOn('ping_spikes')
    ? (data.ping_spikes || []).map(p => p[1]).filter(v => v != null && isFinite(v))
    : [];
  const pingPool = p90s.concat(speedPings, spikePings);
  let yMaxMs = 100;
  if (pingPool.length) {
    const sorted = [...pingPool].sort((a, b) => a - b);
    const p99 = sorted[Math.floor(0.99 * (sorted.length - 1))];
    yMaxMs = Math.max(100, Math.ceil(p99 * 1.15 / 50) * 50);
  }
  const yOfMs = (ms) => MT + H - (Math.min(Math.max(0, ms), yMaxMs) / yMaxMs) * H;

  // ── Y-scale (right): speed Mbps — from whichever of dl/ul is visible.
  const speedPool = [];
  if (isLayerOn('dl_dots')) {
    (data.speed_series || []).forEach(s => {
      if (s.dl != null && isFinite(s.dl)) speedPool.push(s.dl);
    });
  }
  if (isLayerOn('ul_dots')) {
    (data.speed_series || []).forEach(s => {
      if (s.ul != null && isFinite(s.ul)) speedPool.push(s.ul);
    });
  }
  // Keep dlVals around for the stats strip below.
  const dlVals = (data.speed_series || [])
    .map(s => s.dl).filter(v => v != null && isFinite(v));
  let yMaxMbps = 100;
  if (speedPool.length) {
    const m = Math.max(...speedPool);
    const step = m <= 50 ? 10 : m <= 200 ? 50 : m <= 500 ? 100 : 200;
    yMaxMbps = Math.max(step, Math.ceil(m * 1.1 / step) * step);
  }
  const yOfMbps = (mbps) => MT + H - (Math.min(Math.max(0, mbps), yMaxMbps) / yMaxMbps) * H;

  // ── 1. Background bands (each layer-toggleable) ───────────────
  if (isLayerOn('bg_normal')) {
    ctx.fillStyle = BG_NORMAL;
    ctx.fillRect(ML, MT, W, H);
  }

  function drawSpan(start, end, color) {
    if (!start) return;
    const sMs = new Date(start).getTime();
    const eMs = end ? new Date(end).getTime() : t1;
    const x0 = Math.max(ML, xOf(Math.max(t0, sMs)));
    const x1 = Math.min(ML + W, xOf(Math.min(t1, eMs)));
    if (x1 <= x0) return;
    ctx.fillStyle = color;
    ctx.fillRect(x0, MT, x1 - x0, H);
  }
  (data.degraded || []).forEach(d => {
    const isSite = (d.kind === 'site_loss');
    if (isSite && !isLayerOn('bg_site_loss')) return;
    if (!isSite && !isLayerOn('bg_degraded')) return;
    drawSpan(d.start, d.end, isSite ? BG_SITE_LOSS : BG_DEGRADED);
  });
  if (isLayerOn('bg_outage')) {
    (data.outages || []).forEach(o => drawSpan(o.start, o.end, BG_OUTAGE));
  }

  // ── 2. Y gridlines + left axis (ms) + right axis (Mbps) ─────────
  ctx.strokeStyle = COLORS.border;
  ctx.font = '9px ui-monospace, monospace';
  ctx.lineWidth = 1;
  const yTicks = 4;
  for (let i = 0; i <= yTicks; i++) {
    const frac = i / yTicks;
    const y = MT + H - frac * H;
    ctx.beginPath();
    ctx.moveTo(ML, y); ctx.lineTo(ML + W, y);
    ctx.globalAlpha = i === 0 ? 0.6 : 0.2;
    ctx.strokeStyle = COLORS.border;
    ctx.stroke();
    ctx.globalAlpha = 1;
    // Left: ms
    ctx.fillStyle = COLORS.cyan;
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ctx.fillText(Math.round(yMaxMs * frac) + 'ms', ML - 4, y);
    // Right: Mbps
    ctx.fillStyle = COLORS.magenta;
    ctx.textAlign = 'left';
    ctx.fillText(Math.round(yMaxMbps * frac) + 'M', ML + W + 4, y);
  }

  // ── 3. X tick labels (HH:MM) ────────────────────────────────────
  // Adaptive: target ~8 labels across the chart, snapped to a "nice"
  // 1/2/5/10/15/30/60/120/180/360-minute interval. Never pick a step so
  // small that labels overlap (≤ ~30px each), and never so large that the
  // window has < 4 ticks.
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  const spanMin = span / 60000;
  const NICE_STEPS = [1, 2, 5, 10, 15, 20, 30, 60, 120, 180, 360, 720];
  const targetTicks = 8;
  const minLabelPx = 32;
  const maxTicksByWidth = Math.max(2, Math.floor(W / minLabelPx));
  const targetMin = spanMin / Math.min(targetTicks, maxTicksByWidth);
  let stepMin = NICE_STEPS[NICE_STEPS.length - 1];
  for (const cand of NICE_STEPS) {
    if (cand >= targetMin) { stepMin = cand; break; }
  }
  // Cap: never let the window show fewer than 4 ticks, even if span is short.
  while (stepMin > 1 && spanMin / stepMin < 4) {
    const idx = NICE_STEPS.indexOf(stepMin);
    if (idx <= 0) break;
    stepMin = NICE_STEPS[idx - 1];
  }
  const stepMs = stepMin * 60000;
  let firstTick = Math.ceil(t0 / stepMs) * stepMs;
  for (let tx = firstTick; tx <= t1; tx += stepMs) {
    const x = xOf(tx);
    if (x < ML || x > ML + W) continue;
    const d = new Date(tx);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    ctx.fillStyle = COLORS.dim;
    ctx.fillText(hh + ':' + mm, x, MT + H + 4);
  }

  // ── 4. Ping band: filled p10–p90 area only (no median line) ─────
  // Walk bands; break the path into segments wherever a band is null
  // (so outage gaps stay visible). Each contiguous run becomes one fill
  // (forward through p90, back through p10).
  const bandFill = 'rgba(57,197,207,0.28)';   // cyan-ish translucent (a bit
                                              // stronger now that there's no
                                              // p50 line drawing on top)
  function flushSegment(seg) {
    if (seg.length < 2) return;
    ctx.beginPath();
    ctx.moveTo(seg[0].x, yOfMs(seg[0].p90));
    for (let i = 1; i < seg.length; i++) ctx.lineTo(seg[i].x, yOfMs(seg[i].p90));
    for (let i = seg.length - 1; i >= 0; i--) ctx.lineTo(seg[i].x, yOfMs(seg[i].p10));
    ctx.closePath();
    ctx.fillStyle = bandFill;
    ctx.fill();
  }
  let seg = [];
  if (isLayerOn('ping_band')) {
    bands.forEach(([ts, p10, p50, p90, n]) => {
      if (p50 == null) { flushSegment(seg); seg = []; return; }
      seg.push({ x: xOf(new Date(ts).getTime()), p10, p50, p90, n, ts });
    });
    flushSegment(seg);
  }

  // ── 5. Speed: separate ↓ and ↑ dots on the right Mbps axis. Colors
  //     match the dashboard's combined speed cards (blue download,
  //     green upload). Each speed test contributes two dots stacked at
  //     the same x.
  const DL_COLOR = '#58a6ff';   // matches dashboard download chart
  const UL_COLOR = '#3fb950';   // matches dashboard upload chart
  const speedMarks = [];
  (data.speed_series || []).forEach(s => {
    const x = xOf(new Date(s.ts).getTime());
    if (x < ML || x > ML + W) return;
    ctx.strokeStyle = COLORS.text;
    ctx.lineWidth = 1;
    let dlY = null, ulY = null;
    if (s.dl != null && isLayerOn('dl_dots')) {
      dlY = yOfMbps(s.dl);
      ctx.fillStyle = DL_COLOR;
      ctx.beginPath();
      ctx.arc(x, dlY, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
    }
    if (s.ul != null && isLayerOn('ul_dots')) {
      ulY = yOfMbps(s.ul);
      ctx.fillStyle = UL_COLOR;
      ctx.beginPath();
      ctx.arc(x, ulY, 3, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
    }
    speedMarks.push({ x, dlY, ulY, sample: s });
  });

  // ── 5b. Threshold lines spanning each degraded period in the window.
  //   For a `slow` period: dotted horizontal line at the 7d-P10 download
  //   speed (right Mbps axis) — visualizes "this sample fell below P10
  //   here, and recovered after 3 consecutive samples ≥ P10 here."
  //   For a `high_ping` period: same shape, anchored at the high-ping
  //   threshold (max(100ms, 3× 7d-median ping)) on the left ms axis.
  const slowThr = data.slow_threshold_mbps;
  const pingThr = data.high_ping_threshold_ms;
  if (isLayerOn('threshold_line')) {
    (data.degraded || []).forEach(d => {
      const sMs = new Date(d.start).getTime();
      const eMs = d.end ? new Date(d.end).getTime() : t1;
      const x0 = Math.max(ML, xOf(Math.max(t0, sMs)));
      const x1 = Math.min(ML + W, xOf(Math.min(t1, eMs)));
      if (x1 <= x0) return;
      let y, color;
      if (d.kind === 'slow' && slowThr != null && isFinite(slowThr)) {
        y = yOfMbps(slowThr); color = DL_COLOR;
      } else if (d.kind === 'high_ping' && pingThr != null && isFinite(pingThr)) {
        y = yOfMs(pingThr); color = COLORS.cyan;
      } else {
        return;  // site_loss has no clean numeric threshold to anchor at
      }
      ctx.save();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.2;
      ctx.setLineDash([4, 3]);
      ctx.globalAlpha = 0.85;
      ctx.beginPath();
      ctx.moveTo(x0, y); ctx.lineTo(x1, y);
      ctx.stroke();
      ctx.restore();
    });
  }

  // ── 5c. Failed primary speedtest markers (Ookla unreachable). Tiny
  //     red ✕ at the bottom of the chart so a glance distinguishes
  //     "speedtest API hiccup" from a real outage.
  const failedMarks = [];
  if (isLayerOn('failed_speedtest')) {
    (data.failed_primary_attempts || []).forEach(ts => {
      const x = xOf(new Date(ts).getTime());
      if (x < ML || x > ML + W) return;
      const y = MT + H - 4;
      ctx.save();
      ctx.strokeStyle = COLORS.red;
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.moveTo(x - 3, y - 3); ctx.lineTo(x + 3, y + 3);
      ctx.moveTo(x + 3, y - 3); ctx.lineTo(x - 3, y + 3);
      ctx.stroke();
      ctx.restore();
      failedMarks.push({ x, y, ts });
    });
  }

  // ── 5d. Per-site outage marks. Small downward-pointing triangles in
  //     teal at the top of the plot at each per-site outage start, with
  //     a thin teal underline spanning the outage duration if known.
  const siteMarks = [];
  if (isLayerOn('site_outage_marks')) {
    (data.site_outage_marks || []).forEach(m => {
      const sMs = new Date(m.start).getTime();
      const eMs = m.end ? new Date(m.end).getTime() : t1;
      const x = xOf(Math.max(t0, sMs));
      if (x < ML || x > ML + W) return;
      const y = MT + 4;
      ctx.save();
      ctx.fillStyle = '#39c5cf';   // teal (matches site_loss color)
      ctx.beginPath();
      ctx.moveTo(x, y + 5);
      ctx.lineTo(x - 4, y);
      ctx.lineTo(x + 4, y);
      ctx.closePath();
      ctx.fill();
      const x1 = Math.min(ML + W, xOf(Math.min(t1, eMs)));
      if (x1 > x + 1) {
        ctx.strokeStyle = '#39c5cf';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(x, y + 6); ctx.lineTo(x1, y + 6);
        ctx.stroke();
      }
      ctx.restore();
      siteMarks.push({ x, y, info: m });
    });
  }

  // ── 5e. Ping spike dots (outliers above the band, so they don't get
  //     averaged away by binning).
  const spikeMarks = [];
  if (isLayerOn('ping_spikes')) {
    (data.ping_spikes || []).forEach(([ts, v]) => {
      const x = xOf(new Date(ts).getTime());
      if (x < ML || x > ML + W) return;
      const y = yOfMs(v);
      ctx.save();
      ctx.fillStyle = COLORS.red;
      ctx.strokeStyle = COLORS.text;
      ctx.lineWidth = 0.75;
      ctx.beginPath();
      ctx.arc(x, y, 2, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();
      ctx.restore();
      spikeMarks.push({ x, y, ts, ms: v });
    });
  }

  // ── 6. Vertical reference lines ────────────────────────────────
  function earliestStart(items) {
    let best = null;
    (items || []).forEach(it => {
      const s = new Date(it.start).getTime();
      if (best == null || s < best) best = s;
    });
    return best;
  }
  function latestEnd(items) {
    let best = null;
    (items || []).forEach(it => {
      if (!it.end) return;
      const e = new Date(it.end).getTime();
      if (best == null || e > best) best = e;
    });
    return best;
  }
  const inc = data.incident || null;
  const degStart = earliestStart(data.degraded);
  const outStart = inc ? new Date(inc.start).getTime() : earliestStart(data.outages);
  // Connectivity-restored marker (when DNS probes started succeeding again).
  const reconnected = inc ? new Date(inc.end).getTime() : latestEnd(data.outages);
  // True return-to-normal: extended past reconnected if degraded periods
  // chained on after the outage. Falls back to reconnected if backend didn't
  // supply it (older diagnoses).
  const recovered = (inc && inc.recovery_end) ? new Date(inc.recovery_end).getTime() : reconnected;
  const refs = [];
  if (degStart != null && (outStart == null || degStart < outStart)) {
    refs.push({ ms: degStart, color: COLORS.yellow, label: 'degraded' });
  }
  if (outStart != null) refs.push({ ms: outStart, color: COLORS.red, label: 'start' });
  // Show reconnected separately from recovered if there's a meaningful gap
  // (>60s). Otherwise just one "resolved" marker at recovered.
  if (recovered != null && reconnected != null && (recovered - reconnected) > 60000) {
    refs.push({ ms: reconnected, color: COLORS.yellow, label: 'reconnected', dashed: true });
    refs.push({ ms: recovered,   color: COLORS.green,  label: 'recovered' });
  } else if (recovered != null) {
    refs.push({ ms: recovered, color: COLORS.green, label: 'resolved' });
  }
  refs.push({ ms: t1, color: COLORS.dim, label: 'window end', dashed: true });

  ctx.font = '9px ui-monospace, monospace';
  if (isLayerOn('event_markers')) {
    refs.forEach(r => {
      const x = xOf(r.ms);
      if (x < ML || x > ML + W) return;
      ctx.strokeStyle = r.color;
      ctx.globalAlpha = r.dashed ? 0.5 : 0.85;
      ctx.lineWidth = 1;
      if (r.dashed) ctx.setLineDash([3, 3]);
      ctx.beginPath();
      ctx.moveTo(x, MT); ctx.lineTo(x, MT + H);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.globalAlpha = 1;
      ctx.fillStyle = r.color;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(r.label, x + 3, MT + 1);
    });
  }

  // ── 7. Stats strip above chart ─────────────────────────────────
  const statsEl = document.getElementById('diag-chart-stats');
  if (statsEl) {
    let downSec = 0;
    (data.outages || []).forEach(o => {
      const s = new Date(o.start).getTime();
      const e = (o.end ? new Date(o.end).getTime() : t1);
      downSec += Math.max(0, (Math.min(t1, e) - Math.max(t0, s)) / 1000);
    });
    const fmtDur = (s) => s < 60 ? Math.round(s) + 's'
                       : s < 3600 ? Math.floor(s/60) + 'm ' + Math.round(s%60) + 's'
                       : Math.floor(s/3600) + 'h ' + Math.floor((s%3600)/60) + 'm';
    const med = p50s.length ? Math.round(p50s.reduce((a,b)=>a+b,0) / p50s.length) : null;
    const p90Max = p90s.length ? Math.round(Math.max(...p90s)) : null;
    const slowest = dlVals.length ? Math.min(...dlVals) : null;
    const spanMs = t1 - t0;
    const winLabel = spanMs >= 3600000
      ? (Math.round(spanMs / 3600000 * 10) / 10) + 'h'
      : Math.round(spanMs / 60000) + 'm';
    const parts = [
      'span <strong>' + winLabel + '</strong>',
      'downtime <strong>' + (downSec > 0 ? fmtDur(downSec) : '0s') + '</strong>',
    ];
    if (med != null)     parts.push('median ping <strong>' + med + 'ms</strong>');
    if (p90Max != null)  parts.push('p90 peak <strong>' + p90Max + 'ms</strong>');
    if (slowest != null) parts.push('slowest <strong>' + slowest + ' Mbps</strong>');
    statsEl.innerHTML = parts.join(' · ');
  }

  // ── 8. Hover tooltip ───────────────────────────────────────────
  const tt = document.getElementById('diag-chart-tooltip');
  canvas.onmousemove = (evt) => {
    const rect = canvas.getBoundingClientRect();
    const px = evt.clientX - rect.left;
    const py = evt.clientY - rect.top;
    // Hit-test order: site-outage triangle / failed-speedtest ✕ / spike dot
    // / speed marker. Whichever is within range of the cursor wins; the
    // tooltip then renders the matching content.
    let hit = null;
    for (const m of siteMarks) {
      if (Math.hypot(px - m.x, py - m.y) <= 7) { hit = { kind: 'site', m }; break; }
    }
    if (!hit) for (const m of failedMarks) {
      if (Math.hypot(px - m.x, py - m.y) <= 6) { hit = { kind: 'failed', m }; break; }
    }
    if (!hit) for (const m of spikeMarks) {
      if (Math.hypot(px - m.x, py - m.y) <= 5) { hit = { kind: 'spike', m }; break; }
    }
    if (!hit) for (const m of speedMarks) {
      const dx = px - m.x;
      const dDl = (m.dlY != null) ? Math.hypot(dx, py - m.dlY) : Infinity;
      const dUl = (m.ulY != null) ? Math.hypot(dx, py - m.ulY) : Infinity;
      const closest = Math.min(dDl, dUl);
      if (closest <= 6) { hit = { kind: 'speed', m }; break; }
    }
    if (hit && hit.kind === 'site') {
      const i = hit.m.info;
      const sStr = i.start.replace('T', ' ').slice(11, 19);
      const eStr = i.end ? i.end.replace('T', ' ').slice(11, 19) : 'ongoing';
      tt.innerHTML = '<strong style="color:#39c5cf">Site outage</strong>'
        + '<br>' + (i.name || i.host)
        + '<br>' + sStr + ' → ' + eStr;
    } else if (hit && hit.kind === 'failed') {
      const tStr = hit.m.ts.replace('T', ' ').slice(11, 19);
      tt.innerHTML = '<strong style="color:' + COLORS.red + '">Primary speed test failed</strong>'
        + '<br>' + tStr
        + '<br><span style="color:var(--dim)">Ookla unreachable; HTTP fallback used.<br>'
        + 'Not an internet outage — speedtest endpoint only.</span>';
    } else if (hit && hit.kind === 'spike') {
      const tStr = hit.m.ts.replace('T', ' ').slice(11, 19);
      tt.innerHTML = '<strong style="color:' + COLORS.red + '">Ping spike</strong>'
        + '<br>' + tStr
        + '<br>' + hit.m.ms + 'ms';
    } else if (hit && hit.kind === 'speed') {
      hit = hit.m;
      const s = hit.sample;
      const tStr = s.ts.replace('T', ' ').slice(11, 19);
      tt.innerHTML = '<strong>Speed test</strong>'
        + '<br>' + tStr
        + '<br><span style="color:' + DL_COLOR + '">↓ ' + s.dl + ' Mbps</span>'
        + ' · <span style="color:' + UL_COLOR + '">↑ ' + s.ul + ' Mbps</span>'
        + (s.ping != null ? '<br>ping ' + s.ping + 'ms' : '')
        + (s.label ? '<br><span style="color:var(--dim)">' + s.label + '</span>' : '');
    } else if (px >= ML && px <= ML + W && py >= MT && py <= MT + H) {
      // Find nearest band bin.
      const tHere = t0 + ((px - ML) / W) * span;
      let nearest = null, nearestDt = Infinity;
      bands.forEach(b => {
        const dt = Math.abs(new Date(b[0]).getTime() - tHere);
        if (dt < nearestDt) { nearestDt = dt; nearest = b; }
      });
      if (!nearest) { tt.style.display = 'none'; return; }
      const [ts, p10, p50, p90, n] = nearest;
      const tStr = ts.replace('T', ' ').slice(11, 19);
      if (p50 == null) {
        tt.innerHTML = '<strong style="color:' + COLORS.cyan + '">' + tStr + '</strong>'
          + '<br><span style="color:var(--red)">no response</span>';
      } else {
        tt.innerHTML = '<strong style="color:' + COLORS.cyan + '">' + tStr + '</strong>'
          + '<br>p10 ' + p10 + 'ms'
          + '<br>p50 ' + p50 + 'ms'
          + '<br>p90 ' + p90 + 'ms'
          + '<br><span style="color:var(--dim)">' + n + ' samples</span>';
      }
    } else {
      tt.style.display = 'none';
      return;
    }
    tt.style.display = 'block';
    const ttW = tt.offsetWidth, ttH = tt.offsetHeight;
    let lx = px + 10, ly = py + 10;
    if (lx + ttW > cssW) lx = px - ttW - 10;
    if (ly + ttH > cssH) ly = py - ttH - 10;
    tt.style.left = Math.max(0, lx) + 'px';
    tt.style.top  = Math.max(0, ly) + 'px';
  };
  canvas.onmouseleave = () => { tt.style.display = 'none'; };
}

window.addEventListener('resize', () => { if (_diagChartState) paintDiagChart(); });

async function loadHistory() {
  try {
    const resp = await fetch('/api/diagnoses');
    if (!resp.ok) throw new Error('http ' + resp.status);
    const data = await resp.json();
    history = data.items || [];
    // Sort newest event first by when the event actually happened, not by
    // when the user ran the analysis.
    history.sort((a, b) => eventTimeOf(b) - eventTimeOf(a));
    if (!selectedId && history.length > 0) selectedId = history[0].id;
    renderHistory();
    renderDetail(history.find(x => x.id === selectedId));
  } catch (e) {
    document.getElementById('history').innerHTML =
      '<div style="color:var(--red);font-size:12px">Failed to load history: ' + e.message + '</div>';
  }
}

function fmtIncidentDuration(s) {
  s = Math.max(0, Math.floor(s));
  if (s < 60) return s + ' seconds';
  if (s < 3600) return Math.floor(s / 60) + ' minutes';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

// Naive local-time ISO string matching the server's
// `datetime.isoformat(timespec="seconds")`. `new Date().toISOString()` emits
// a UTC string with 'Z' suffix that Python <3.11's `datetime.fromisoformat`
// rejects — that path silently failed ongoing-incident diagnoses (server
// returned 400, client kept the previously-selected diagnosis on screen).
function localIsoNow() {
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
    + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}

function findDiagnosisForOutage(outageId) {
  return history.find(d => d.outage_id === outageId) || null;
}

function onTimelineClick(inc) {
  if (!inc) return;
  const existing = findDiagnosisForOutage(inc.id);
  if (existing) {
    selectDiagnosis(existing.id);
    return;
  }
  const start = new Date(inc.start);
  const sec   = ((inc.end ? new Date(inc.end) : new Date()) - start) / 1000;
  const kindLabel = inc.category === 'outage' ? 'outage'
                   : inc.category === 'site_loss' ? 'site-loss period'
                   : 'degraded period';
  const ok = window.confirm(
    'Run AI diagnosis on this ' + fmtIncidentDuration(sec) +
    ' ' + kindLabel + ' at ' + start.toLocaleString() + '?\\n\\n' +
    'This will use ~$0.02 of API credit and take ~5–10 seconds.'
  );
  if (!ok) return;
  runOutage(inc);
}

async function runOutage(inc) {
  const status = document.getElementById('run-status');
  const btns = document.querySelectorAll('.run-btn');
  btns.forEach(b => b.disabled = true);
  const start = new Date(inc.start);
  const end   = inc.end ? new Date(inc.end) : new Date();
  const sec   = (end - start) / 1000;
  const kindLabel = inc.category === 'outage' ? 'outage'
                   : inc.category === 'site_loss' ? 'site-loss period'
                   : 'degraded period';
  openDiagRunModal(fmtIncidentDuration(sec) + ' ' + kindLabel + ' at ' +
                   start.toLocaleString());
  status.textContent = '';
  try {
    const resp = await fetch('/api/diagnose', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        window: 'outage',
        start: inc.start,
        end:   inc.end || localIsoNow(),
        outage_id: inc.id,
      }),
    });
    const data = await resp.json().catch(() => ({}));
    // HTTP errors (400 bad input, 429 already running, 5xx) never produce a
    // saved diagnosis — surface them instead of silently leaving the
    // previously-selected diagnosis on screen. AI-step failures still come
    // back as 200 with `id` set, so the detail panel renders their error.
    if (!resp.ok) {
      status.textContent = (data && data.error)
        ? data.error
        : ('Request failed (' + resp.status + ')');
      return;
    }
    if (data.id) selectedId = data.id;
    await loadHistory();
    await refreshTimeline();
  } catch (e) {
    status.textContent = 'Request failed';
  } finally {
    btns.forEach(b => b.disabled = false);
    closeDiagRunModal();
  }
}

let _timelineData = null;

// Per-page kind filter state, persisted in localStorage so the user's
// preference survives reloads. `kindFilter` is the set of kinds to HIDE.
function loadKindFilter() {
  const set = new Set();
  try {
    const raw = localStorage.getItem('diagKindFilter');
    if (raw) JSON.parse(raw).forEach(k => set.add(k));
  } catch (e) {}
  return set;
}
function saveKindFilter(set) {
  try { localStorage.setItem('diagKindFilter', JSON.stringify([...set])); } catch (e) {}
}
let _kindFilter = loadKindFilter();
let _showDismissed = (function() {
  try { return localStorage.getItem('diagShowDismissed') === '1'; }
  catch (e) { return false; }
})();
// Reflect saved state back into the checkboxes once the DOM is parsed.
document.querySelectorAll('.kind-filter input[type="checkbox"]').forEach(cb => {
  if (cb.dataset.kind) {
    cb.checked = !_kindFilter.has(cb.dataset.kind);
    cb.addEventListener('change', () => {
      if (cb.checked) _kindFilter.delete(cb.dataset.kind);
      else            _kindFilter.add(cb.dataset.kind);
      saveKindFilter(_kindFilter);
      paintTimeline();
    });
  } else if (cb.hasAttribute('data-show-dismissed')) {
    cb.checked = _showDismissed;
    cb.addEventListener('change', () => {
      _showDismissed = cb.checked;
      try { localStorage.setItem('diagShowDismissed', _showDismissed ? '1' : '0'); }
      catch (e) {}
      renderHistory();   // history filtering also depends on this toggle
      paintTimeline();
    });
  }
});

function paintTimeline() {
  if (!_timelineData) return;
  // Find the cluster matching the currently-selected diagnosis (if any) so
  // the timeline outlines it in yellow. For window-based diagnoses (1h/24h)
  // there's no outage_id — fall back to highlighting the analyzed window.
  const selDiag = selectedId ? history.find(d => d.id === selectedId) : null;
  const selOutageId = selDiag ? selDiag.outage_id : null;
  let selWindow = null;
  if (!selOutageId && selDiag && selDiag.chart_data
      && selDiag.chart_data.window_start && selDiag.chart_data.window_end) {
    selWindow = { start: selDiag.chart_data.window_start,
                  end:   selDiag.chart_data.window_end };
  }
  const dismissedSet = new Set(_timelineData.dismissed_ids || []);
  UptimeTimeline.render(document.getElementById('timelineCanvas'), {
    days: 30,
    clusters: _timelineData.clusters,
    analyzedIds: _timelineData.analyzed_ids,
    titles: _timelineData.titles || {},
    monitorStartedAt: _timelineData.monitor_started_at,
    monitorGaps: _timelineData.monitor_gaps || [],
    onIncidentClick: onTimelineClick,
    selectedClusterId: selOutageId,
    selectedWindow: selWindow,
    kindFilter: _kindFilter,
    dismissedClusterIds: dismissedSet,
    showDismissed: _showDismissed,
  });
  const total = (_timelineData.clusters || []).length;
  const seen = (_timelineData.analyzed_ids || []).length;
  const dism = (_timelineData.dismissed_ids || []).length;
  const stats = document.getElementById('timeline-stats');
  if (stats) stats.textContent = total + ' incidents · ' + seen + ' analyzed'
    + (dism ? (' · ' + dism + ' dismissed') : '');
}

// ── Analysis-in-progress modal ────────────────────────────────
// Shown while a new /api/diagnose POST is in flight, hidden on completion.
// Single source of truth: any code path that fires a diagnosis wraps the
// fetch with openDiagRunModal() / closeDiagRunModal().
let _diagRunStartTs = null;
let _diagRunElapsedTimer = null;
const _diagRunStatusMessages = [
  'Building snapshot…',
  'Compiling ping & speed history…',
  'Summarizing router events…',
  'Asking the model to interpret…',
  'Parsing the response…',
];

function openDiagRunModal(targetLabel) {
  let overlay = document.getElementById('diag-run-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'diag-run-overlay';
    overlay.className = 'diag-run-overlay';
    overlay.innerHTML =
      '<div class="diag-run-modal">' +
        '<div class="diag-run-spinner"></div>' +
        '<div class="diag-run-title">Diagnosing</div>' +
        '<div class="diag-run-target" id="diag-run-target"></div>' +
        '<div class="diag-run-status" id="diag-run-status"></div>' +
        '<div class="diag-run-elapsed" id="diag-run-elapsed"></div>' +
      '</div>';
    document.body.appendChild(overlay);
  }
  document.getElementById('diag-run-target').textContent = targetLabel || '';
  const statusEl = document.getElementById('diag-run-status');
  const elapsedEl = document.getElementById('diag-run-elapsed');
  let stage = 0;
  statusEl.textContent = _diagRunStatusMessages[0];
  _diagRunStartTs = Date.now();
  // Cycle through stage messages and bump the elapsed clock every 250ms.
  // The stages are illustrative — there's no real backend progress event
  // stream. A typical run takes 5–10 seconds; cycling every ~2s reads as
  // "things are happening" without overpromising granularity.
  if (_diagRunElapsedTimer) clearInterval(_diagRunElapsedTimer);
  _diagRunElapsedTimer = setInterval(() => {
    const elapsed = (Date.now() - _diagRunStartTs) / 1000;
    elapsedEl.textContent = elapsed.toFixed(1) + 's elapsed';
    const newStage = Math.min(_diagRunStatusMessages.length - 1,
                              Math.floor(elapsed / 2));
    if (newStage !== stage) {
      stage = newStage;
      statusEl.textContent = _diagRunStatusMessages[stage];
    }
  }, 250);
  overlay.style.display = 'flex';
}

function closeDiagRunModal() {
  const overlay = document.getElementById('diag-run-overlay');
  if (overlay) overlay.style.display = 'none';
  if (_diagRunElapsedTimer) {
    clearInterval(_diagRunElapsedTimer);
    _diagRunElapsedTimer = null;
  }
}
async function refreshTimeline() {
  try {
    const resp = await fetch('/api/timeline?days=30');
    if (!resp.ok) return;
    _timelineData = await resp.json();
    paintTimeline();
  } catch (e) {}
}
window.addEventListener('resize', paintTimeline);

async function handleUrlParams() {
  const params = new URLSearchParams(window.location.search);
  const showId = params.get('show');
  const runId  = params.get('run');
  if (showId) {
    const existing = findDiagnosisForOutage(showId);
    if (existing) selectDiagnosis(existing.id);
    window.history.replaceState({}, '', '/diagnose');
    return;
  }
  if (runId) {
    const existing = findDiagnosisForOutage(runId);
    if (existing) {
      selectDiagnosis(existing.id);
      window.history.replaceState({}, '', '/diagnose');
      return;
    }
    // Need the outage's start/end from the timeline data
    if (!_timelineData) await refreshTimeline();
    const inc = (_timelineData?.clusters || []).find(o => o.id === runId);
    if (inc) {
      window.history.replaceState({}, '', '/diagnose');
      runOutage({ ...inc, kind: 'outage' });
    } else {
      window.history.replaceState({}, '', '/diagnose');
    }
  }
}

async function runNew(window) {
  const status = document.getElementById('run-status');
  const btns = document.querySelectorAll('.run-btn');
  btns.forEach(b => b.disabled = true);
  const labels = {ongoing: 'last 5 minutes (ongoing)',
                  '1h': 'last 1 hour', '24h': 'last 24 hours'};
  openDiagRunModal(labels[window] || window);
  status.textContent = '';
  try {
    const resp = await fetch('/api/diagnose', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({window}),
    });
    const data = await resp.json();
    if (data.id) {
      selectedId = data.id;
    }
    await loadHistory();
  } catch (e) {
    status.textContent = 'Request failed';
  } finally {
    btns.forEach(b => b.disabled = false);
    closeDiagRunModal();
  }
}

document.querySelectorAll('.run-btn').forEach(btn => {
  btn.addEventListener('click', () => runNew(btn.dataset.window));
});

document.getElementById('diag-delete-btn').addEventListener('click', async (evt) => {
  const btn = evt.currentTarget;
  const id = btn.dataset.id;
  if (!id) return;
  const diag = history.find(d => d.id === id);
  const title = (diag && diag.result && diag.result.title) || 'this diagnosis';
  if (!window.confirm('Delete "' + title + '"?\\n\\nThe cluster will go back to un-analyzed and can be re-evaluated later.')) return;
  btn.disabled = true;
  try {
    const resp = await fetch('/api/diagnoses/' + encodeURIComponent(id), { method: 'DELETE' });
    if (!resp.ok) throw new Error('http ' + resp.status);
    if (selectedId === id) selectedId = null;
    await loadHistory();
    await refreshTimeline();
  } catch (e) {
    window.alert('Delete failed: ' + e.message);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('diag-dismiss-btn').addEventListener('click', async (evt) => {
  const btn = evt.currentTarget;
  const outageId = btn.dataset.outageId;
  if (!outageId) return;
  const wasDismissed = btn.dataset.dismissed === '1';
  btn.disabled = true;
  try {
    const resp = await fetch('/api/dismiss', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ outage_id: outageId, dismissed: !wasDismissed }),
    });
    if (!resp.ok) throw new Error('http ' + resp.status);
    // Refresh history (for dismissed flags) and timeline (for dismissed_ids).
    await loadHistory();
    await refreshTimeline();
  } catch (e) {
    window.alert((wasDismissed ? 'Restore' : 'Dismiss') + ' failed: ' + e.message);
  } finally {
    btn.disabled = false;
  }
});

// Reflect saved layer-toggle state on the legend immediately at load.
refreshLegendStrikes();

(async () => {
  await loadHistory();
  await refreshTimeline();
  await handleUrlParams();
})();
setInterval(refreshTimeline, 30000);
</script>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────
# Flask app
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# Session-cookie hardening for the multi-tenant login. HttpOnly blocks JS from
# reading the cookie; SameSite=Lax blunts CSRF; Secure keeps the cookie off
# plain HTTP (the cloud server sits behind nginx TLS). ALLOW_INSECURE_COOKIES
# is an escape hatch for local http testing only.
_allow_insecure_cookies = os.environ.get("ALLOW_INSECURE_COOKIES", "").lower() in ("true", "1", "yes")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=MULTI_TENANT and not _allow_insecure_cookies,
)

_state: Optional[MonitorState] = None
_db: Optional[db.Storage] = None
_cursors: db.PersistCursors = db.PersistCursors()
# Wall-clock of the last DB prune, so the persistence thread can ratelimit
# DELETE WHERE ts < cutoff sweeps (no benefit to running them every 60s).
_last_pruned_at: float = 0.0

# Bumps every server start so the browser refetches /static/timeline.js even
# when an aggressive cache (or a proxy/extension that ignores Cache-Control)
# would otherwise stick to a previous version. The Cache-Control header on
# the JS route covers normal browsers; this covers the rest.
_ASSET_VERSION = str(int(time.time()))


def _versioned(html: str) -> str:
    return html.replace('/static/timeline.js"', f'/static/timeline.js?v={_ASSET_VERSION}"')


def _init_session_secret() -> None:
    """Set app.secret_key for signed session cookies. Prefer the SECRET_KEY env;
    otherwise generate one once and persist it in the DB so logins survive
    restarts (a fresh random key each boot would invalidate every session)."""
    key = SECRET_KEY
    if not key and _db is not None:
        key = _db.get_meta("session_secret")
        if not key:
            key = secrets.token_hex(32)
            _db.set_meta("session_secret", key)
    app.secret_key = key or secrets.token_hex(32)


def _valid_email(email: str) -> bool:
    """Minimal sanity check — not RFC-complete, just enough to reject junk."""
    if not email or len(email) > 254 or " " in email:
        return False
    parts = email.split("@")
    return len(parts) == 2 and bool(parts[0]) and "." in parts[1] and bool(parts[1])


# pbkdf2:sha256 rather than Werkzeug's scrypt default — scrypt needs OpenSSL
# support in hashlib that isn't present on every build/container base image;
# pbkdf2 is always available and still a salted, high-iteration KDF.
_PW_HASH_METHOD = "pbkdf2:sha256"


def _hash_password(pw: str) -> str:
    return generate_password_hash(pw, method=_PW_HASH_METHOD)


# Precomputed hash so a login attempt for an unknown email still spends time
# hashing — response timing then doesn't reveal which emails are registered.
_DUMMY_PW_HASH = _hash_password(secrets.token_hex(16))


def current_user():
    """Return the logged-in user row (dict) for this request, or None."""
    if _db is None:
        return None
    uid = session.get("uid")
    if not uid:
        return None
    return _db.get_user_by_id(uid)


# Self-contained styled page for login/register (the dashboard's CSS vars live
# inside DASHBOARD_HTML, so these pages carry their own copy of the palette to
# stay visually consistent).
_AUTH_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · Connection Monitor</title>
<style>
  :root {{ --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3;
           --dim:#8b949e; --green:#3fb950; --red:#f85149; }}
  * {{ box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text); font-family:-apple-system,
          BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; margin:0;
          min-height:100vh; display:flex; align-items:center; justify-content:center; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:10px;
           padding:32px; width:340px; box-shadow:0 8px 32px rgba(0,0,0,0.6); }}
  h1 {{ font-size:18px; margin:0 0 4px; }}
  p.sub {{ color:var(--dim); font-size:13px; margin:0 0 20px; }}
  label {{ display:block; font-size:12px; color:var(--dim); margin:14px 0 4px; }}
  input {{ width:100%; padding:9px 10px; background:var(--bg); color:var(--text);
           border:1px solid var(--border); border-radius:6px; font-size:14px; }}
  button {{ width:100%; margin-top:22px; padding:10px; background:var(--green);
            color:#06210d; border:none; border-radius:6px; font-size:14px;
            font-weight:600; cursor:pointer; }}
  .err {{ background:rgba(248,81,73,0.12); border:1px solid var(--red);
          color:var(--red); padding:9px 11px; border-radius:6px; font-size:13px;
          margin-bottom:16px; }}
  .alt {{ text-align:center; margin-top:18px; font-size:13px; color:var(--dim); }}
  .alt a {{ color:var(--green); text-decoration:none; }}
</style></head>
<body>
  <form class="card" method="POST" action="{action}">
    <h1>{heading}</h1>
    <p class="sub">{subtitle}</p>
    {error}
    {fields}
    <button type="submit">{button}</button>
    <div class="alt">{alt}</div>
  </form>
</body></html>"""


def _auth_page(title, heading, subtitle, action, fields, button, alt, error=""):
    err_html = f'<div class="err">{error}</div>' if error else ""
    return _AUTH_PAGE.format(
        title=title, heading=heading, subtitle=subtitle, action=action,
        fields=fields, button=button, alt=alt, error=err_html,
    )


def _check_dashboard_auth():
    """Return a 401 Response if dashboard auth is configured and the request
    doesn't carry valid HTTP Basic credentials. Returns None if OK."""
    if not DASHBOARD_USER:
        return None
    auth = request.authorization
    if auth and hmac.compare_digest(auth.username or "", DASHBOARD_USER) \
            and hmac.compare_digest(auth.password or "", DASHBOARD_PASS):
        return None
    from flask import Response
    return Response(
        "Authentication required", 401,
        {"WWW-Authenticate": 'Basic realm="Connection Monitor"'},
    )


def _check_api_key():
    """Return a 401 Response if ingest auth is configured and the request
    doesn't carry a valid Bearer token. Returns None if OK."""
    if not INGEST_API_KEY:
        return None
    auth_header = request.headers.get("Authorization", "")
    if hmac.compare_digest(auth_header, f"Bearer {INGEST_API_KEY}"):
        return None
    return jsonify({"error": "invalid or missing API key"}), 401


# Browsers were caching the page HTML and serving stale *inline* JS even after
# a restart, which made client-side fixes appear not to land. The pages are
# tiny and always need to reflect the latest server build, so opt out of all
# caching for them. (The external /static/timeline.js route already has its
# own no-cache + ?v= cache-bust.)
def _is_aggregator() -> bool:
    """True if this instance should show multi-host aggregated data.
    Only enabled via AGGREGATOR=true env var — not auto-detected by host
    count, to avoid triggering expensive DB queries on every 2s poll."""
    return AGGREGATOR


def state_from_db(storage: db.Storage, monitor_host: Optional[str] = None) -> dict:
    """Reconstruct the /api/state response from DB queries.

    Used by the aggregator to serve data for remote hosts, or the "all hosts"
    aggregate view. Produces the same top-level keys as MonitorState.to_dict()
    with sensible defaults for live-only fields.
    """
    now = datetime.now()
    cutoff_30d_iso = (now - _30D).isoformat()
    cutoff_24h_iso = (now - _24H).isoformat()
    cutoff_7d_str = (now - timedelta(days=7)).strftime("%Y-%m-%d")

    host_filter = monitor_host if monitor_host and monitor_host != "all" else "*"

    ping_ts = storage.load_ping_samples(cutoff_30d_iso, monitor_host=host_filter)
    access_ts = storage.load_accessibility_samples(cutoff_30d_iso, monitor_host=host_filter)
    site_samples = storage.load_site_samples(cutoff_30d_iso, monitor_host=host_filter)
    speed_samples = storage.load_speed_samples(cutoff_24h_iso, monitor_host=host_filter)
    outages = storage.load_outages(cutoff_30d_iso, monitor_host=host_filter)
    degraded = storage.load_degraded_periods(cutoff_30d_iso, monitor_host=host_filter)
    daily_summary = storage.load_daily_summary(cutoff_7d_str, monitor_host=host_filter)
    net_secs, net_colors = storage.load_network_uptime(monitor_host=host_filter)
    hosts_list = storage.load_hosts()

    # Determine last_seen for the selected host
    last_seen = None
    if host_filter != "*":
        for h in hosts_list:
            if h["monitor_host"] == host_filter:
                last_seen = h.get("last_seen")
                break

    def _percentile(sorted_vals, p):
        n = len(sorted_vals)
        if n == 0:
            return None
        if n == 1:
            return sorted_vals[0]
        idx = p / 100 * (n - 1)
        lo, hi = int(idx), min(int(idx) + 1, n - 1)
        return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo)

    # Recent pings for header stats
    recent_pings = [v for ts, v in ping_ts if v is not None and ts >= cutoff_24h_iso]
    avg_p = round(sum(recent_pings) / len(recent_pings), 1) if recent_pings else None
    last_ping = recent_pings[-1] if recent_pings else None

    # Connectivity: inferred from last ping sample
    connected = bool(recent_pings and recent_pings[-1] is not None)

    # Downsample ping chart
    MAX_PING_CHART = 300
    ping_ts_5m = [(t, v) for t, v in ping_ts
                  if datetime.fromisoformat(t) >= now - timedelta(minutes=5)]
    ping_chart_data = ping_ts
    if len(ping_chart_data) > MAX_PING_CHART:
        step = len(ping_chart_data) / MAX_PING_CHART
        ping_chart_data = [ping_chart_data[int(i * step)] for i in range(MAX_PING_CHART)]

    # 24-hour hourly ping buckets
    current_hour = now.replace(minute=0, second=0, microsecond=0)
    first_slot_start = current_hour - timedelta(hours=24)
    ping_buckets = [[] for _ in range(24)]
    access_buckets = [[] for _ in range(24)]
    for ts_str, v in ping_ts:
        try:
            dt = datetime.fromisoformat(ts_str)
        except ValueError:
            continue
        if dt < first_slot_start or dt >= current_hour:
            continue
        idx = int((dt - first_slot_start).total_seconds() // 3600)
        if 0 <= idx < 24:
            ping_buckets[idx].append(v)
    for ts_str, p in access_ts:
        try:
            dt = datetime.fromisoformat(ts_str)
        except ValueError:
            continue
        if dt < first_slot_start or dt >= current_hour:
            continue
        idx = int((dt - first_slot_start).total_seconds() // 3600)
        if 0 <= idx < 24:
            access_buckets[idx].append(p)

    ping_hourly = []
    for i in range(24):
        slot_start = first_slot_start + timedelta(hours=i)
        h_int = slot_start.hour
        hour_label = f"{h_int % 12 or 12}{'am' if h_int < 12 else 'pm'}"
        pv = sorted(ping_buckets[i])
        if pv:
            p10 = round(_percentile(pv, 10), 1)
            p50 = round(_percentile(pv, 50), 1)
            p90 = round(_percentile(pv, 90), 1)
        else:
            p10 = p50 = p90 = None
        av = access_buckets[i]
        access_pct = round(sum(av) / len(av), 1) if av else None
        ping_hourly.append({
            "hour": hour_label, "p10": p10, "p50": p50, "p90": p90,
            "access": access_pct,
        })

    # Speed hourly buckets
    speed_hourly = []
    for h in range(24, 0, -1):
        slot_start = current_hour - timedelta(hours=h)
        slot_end = slot_start + timedelta(hours=1)
        slot_start_iso = slot_start.isoformat()
        slot_end_iso = slot_end.isoformat()
        tests = [s for s in speed_samples
                 if slot_start_iso <= s["timestamp"] < slot_end_iso]
        if tests:
            dls = sorted(s["download_mbps"] for s in tests if s["download_mbps"] is not None)
            uls = sorted(s["upload_mbps"] for s in tests if s["upload_mbps"] is not None)
            if dls:
                dl_p10 = round(_percentile(dls, 10), 1)
                dl_p90 = round(_percentile(dls, 90), 1)
                dl_max = round(dls[-1], 1)
            else:
                dl_p10 = dl_p90 = dl_max = None
            if uls:
                ul_p10 = round(_percentile(uls, 10), 1)
                ul_p90 = round(_percentile(uls, 90), 1)
                ul_max = round(uls[-1], 1)
            else:
                ul_p10 = ul_p90 = ul_max = None
            network = tests[-1].get("network")
        else:
            dl_p10 = dl_p90 = dl_max = None
            ul_p10 = ul_p90 = ul_max = None
            network = None
        h_int = (current_hour - timedelta(hours=h)).hour
        speed_hourly.append({
            "hour": f"{h_int % 12 or 12}{'am' if h_int < 12 else 'pm'}",
            "dl_p10": dl_p10,
            "dl_p10_90d": round(max(0, dl_p90 - dl_p10), 1) if dl_p10 is not None and dl_p90 is not None else None,
            "dl_p90_maxd": round(max(0, dl_max - dl_p90), 1) if dl_p90 is not None and dl_max is not None else None,
            "dl_p90": dl_p90, "dl_max": dl_max,
            "ul_p10": ul_p10,
            "ul_p10_90d": round(max(0, ul_p90 - ul_p10), 1) if ul_p10 is not None and ul_p90 is not None else None,
            "ul_p90_maxd": round(max(0, ul_max - ul_p90), 1) if ul_p90 is not None and ul_max is not None else None,
            "ul_p90": ul_p90, "ul_max": ul_max,
            "network": network,
        })

    # Uptime % for last 24h
    outage_secs_24h = 0.0
    for o in outages:
        o_start_iso = o["start"]
        o_end_iso = o.get("end")
        o_start = max(datetime.fromisoformat(o_start_iso), now - _24H)
        o_end = min(datetime.fromisoformat(o_end_iso) if o_end_iso else now, now)
        if o_end > o_start:
            outage_secs_24h += (o_end - o_start).total_seconds()
    window_secs = 86400.0
    uptime_pct_24h = round(max(0.0, (window_secs - outage_secs_24h) / window_secs * 100), 2)

    # 7-day calendar
    now_date = now.date()
    uptime_7d = []
    hist_by_date = {e["date"]: e for e in daily_summary}
    for d_offset in range(6, -1, -1):
        day = now_date - timedelta(days=d_offset)
        day_str = day.strftime("%Y-%m-%d")
        entry = hist_by_date.get(day_str)
        date_label = f"{day.month}/{day.day}"
        if entry:
            uptime_7d.append({
                "label": day.strftime("%a"), "date": date_label,
                "uptime_pct": entry["uptime_pct"],
                "p10": entry["p10"], "p50": entry["p50"], "p90": entry["p90"],
            })
        else:
            uptime_7d.append({
                "label": day.strftime("%a"), "date": date_label,
                "uptime_pct": None, "p10": None, "p50": None, "p90": None,
            })

    return {
        "connected": connected,
        "last_ping_ms": round(last_ping, 1) if last_ping else None,
        "avg_ping_ms": avg_p,
        "current_network": None,
        "monitor_host": host_filter if host_filter != "*" else "all",
        "runtime_secs": None,
        "runtime_str": None,
        "current_uptime_str": None,
        "total_outage_secs": round(outage_secs_24h),
        "outage_count": len(outages),
        "ping_chart": [
            {"t": t[11:19] if len(t) > 8 else t, "v": round(v, 1)}
            for t, v in ping_chart_data
        ],
        "ping_chart_5m": [
            {"t": t[11:19] if len(t) > 8 else t, "v": round(v, 1)}
            for t, v in ping_ts_5m
        ],
        "access_chart_5m": [
            {"t": t[11:19] if len(t) > 8 else t, "v": round(p, 1)}
            for t, p in access_ts
            if datetime.fromisoformat(t) >= now - timedelta(minutes=5)
        ],
        "ping_hourly": ping_hourly,
        "speed_hourly": speed_hourly,
        "speed_latest": None,
        "speed_history": [
            {
                "timestamp": s["timestamp"][11:16] if len(s["timestamp"]) > 11 else s["timestamp"],
                "download_mbps": round(s["download_mbps"], 1) if s["download_mbps"] else 0,
                "upload_mbps": round(s["upload_mbps"], 1) if s["upload_mbps"] else 0,
                "ping_ms": round(s["ping_ms"], 1) if s["ping_ms"] else 0,
                "label": s.get("label", ""),
                "network": s.get("network", ""),
            }
            for s in speed_samples
        ],
        "speed_history_5m": [],
        "speed_history_1h": [],
        "outages": [
            {
                "start": o["start"][11:19] if len(o["start"]) > 8 else o["start"],
                "end": o["end"][11:19] if o.get("end") and len(o["end"]) > 8 else o.get("end"),
                "duration_str": None,
                "ongoing": o.get("end") is None,
            }
            for o in outages[-10:]
        ],
        "events": [],
        "speed_in_progress": False,
        "speed_status": None,
        "next_test_in": None,
        "network_uptimes": {},
        "network_colors": net_colors,
        "network_names": storage.load_network_names(),
        "uptime_pct_24h": uptime_pct_24h,
        "site_matrix": [],
        "site_pool_thresholds": {},
        "uptime_7d": uptime_7d,
        "router": {"available": False, "poll_error": None, "last_poll": None,
                    "count_1h": 0, "count_24h": 0, "dns_drops_1h": 0, "dns_drops_24h": 0},
        "speed_attempts_24h": {"primary_ok": 0, "fallback_ok": 0, "total": 0},
        "primary_fail_reasons": [],
        "last_diagnosis_at": None,
        "last_seen": last_seen,
        "hosts": hosts_list,
    }


_NO_CACHE_HTML = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-cache, no-store, must-revalidate",
}


@app.before_request
def _enforce_dashboard_auth():
    p = request.path
    # Ingest authenticates itself with a Bearer token inside the view; static
    # assets carry no secrets; /healthz must answer for container/LB probes.
    if p == "/api/ingest" or p == "/healthz" or p.startswith("/static/"):
        return None
    if MULTI_TENANT:
        # Login/register pages must be reachable without a session.
        if p in ("/login", "/register", "/logout"):
            return None
        if current_user() is None:
            # API callers get a clean 401; browsers get bounced to the form.
            if p.startswith("/api/"):
                return jsonify({"error": "login required"}), 401
            return redirect("/login")
        return None
    # Single-tenant: legacy shared-password Basic Auth (no-op if unset).
    return _check_dashboard_auth()


@app.route("/login", methods=["GET", "POST"])
def login():
    if not MULTI_TENANT:
        return redirect("/")
    if current_user():
        return redirect("/")
    error = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = _db.get_user_by_email(email) if _db else None
        # Always run a hash check (even on unknown email) so response time
        # doesn't reveal whether the address exists.
        ref_hash = user["pw_hash"] if user else _DUMMY_PW_HASH
        if check_password_hash(ref_hash, password) and user:
            session.clear()
            session["uid"] = user["id"]
            session.permanent = True
            return redirect("/")
        error = "Invalid email or password."
    fields = ('<label>Email</label><input type="email" name="email" required autofocus>'
              '<label>Password</label><input type="password" name="password" required>')
    alt = ('Need an account? <a href="/register">Register</a>'
           if SIGNUP_CODE else 'Registration is closed.')
    return _auth_page("Sign in", "Sign in", "Connection Monitor", "/login",
                      fields, "Sign in", alt, error)


@app.route("/register", methods=["GET", "POST"])
def register():
    if not MULTI_TENANT:
        return redirect("/")
    if not SIGNUP_CODE:
        return _auth_page(
            "Registration closed", "Registration closed",
            "Ask the server owner for an account.", "/register", "", "",
            '<a href="/login">Back to sign in</a>',
            error="Registration is not open on this server."), 403
    if current_user():
        return redirect("/")
    error = ""
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        handle = (request.form.get("handle") or "").strip()
        password = request.form.get("password") or ""
        code = request.form.get("code") or ""
        if not hmac.compare_digest(code, SIGNUP_CODE):
            error = "Invalid invite code."
        elif not _valid_email(email):
            error = "Enter a valid email address."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif not handle:
            error = "Choose a display name."
        else:
            # First account on a fresh server becomes the admin.
            is_admin = (_db.count_users() == 0) if _db else False
            uid = _db.create_user(email, _hash_password(password),
                                  handle, is_admin) if _db else None
            if uid is None:
                error = "An account with that email already exists."
            else:
                session.clear()
                session["uid"] = uid
                session.permanent = True
                return redirect("/")
    fields = ('<label>Email</label><input type="email" name="email" required autofocus>'
              '<label>Display name</label><input type="text" name="handle" required maxlength="40">'
              '<label>Password</label><input type="password" name="password" required minlength="8">'
              '<label>Invite code</label><input type="text" name="code" required>')
    alt = 'Have an account? <a href="/login">Sign in</a>'
    return _auth_page("Register", "Create account", "Connection Monitor", "/register",
                      fields, "Create account", alt, error)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect("/login" if MULTI_TENANT else "/")


@app.route("/healthz")
def healthz():
    """Unauthenticated liveness probe for containers / load balancers."""
    return "ok", 200


@app.route("/")
def index():
    return _versioned(DASHBOARD_HTML), 200, _NO_CACHE_HTML


@app.route("/api/state")
def api_state():
    host_param = request.args.get("host", "").strip()
    if host_param and _db is not None:
        return jsonify(state_from_db(_db, monitor_host=host_param))
    if _is_aggregator() and not host_param and _db is not None:
        result = state_from_db(_db, monitor_host="all")
        if _state is not None:
            result["control_ping_ms"] = _state.last_ping_ms
            result["control_connected"] = _state.connected
        return jsonify(result)
    if _state is None:
        return jsonify({"error": "not ready"}), 503
    return jsonify(_state.to_dict())


def _site_pool_pings(site_ping_hist: Dict[str, list], now: datetime,
                     hours: int) -> List[float]:
    """Union of successful pings across all sites, last N hours."""
    cut_iso = (now - timedelta(hours=hours)).isoformat()
    out: List[float] = []
    for h in site_ping_hist.values():
        for t, ms in h:
            if ms is not None and t >= cut_iso:
                out.append(ms)
    return out


def _site_pool_thresholds(site_ping_hist: Dict[str, list],
                          now: datetime) -> Dict[str, Optional[float]]:
    """Compute pool P-values used by site verdicts and the modal threshold
    band. Mirrors the auto-fallback behavior in api_state so the modal lines
    up with the tile colors exactly."""
    pool = _site_pool_pings(site_ping_hist, now, SITE_VERDICT_BASELINE_HOURS)
    window_used = SITE_VERDICT_BASELINE_HOURS
    if len(pool) < SITE_VERDICT_MIN_SAMPLES:
        pool = _site_pool_pings(site_ping_hist, now, SITE_VERDICT_FALLBACK_HOURS)
        window_used = SITE_VERDICT_FALLBACK_HOURS
    if not pool:
        return {"great_ms": None, "slow_ms": None, "poor_ms": None,
                "window_hours": window_used, "samples": 0}
    pool.sort()
    return {
        "great_ms": round(_percentile(pool, SITE_VERDICT_GREAT_PCT), 1),
        "slow_ms":  round(_percentile(pool, SITE_VERDICT_SLOW_PCT),  1),
        "poor_ms":  round(_percentile(pool, SITE_VERDICT_POOR_PCT),  1),
        "window_hours": window_used,
        "samples": len(pool),
    }


@app.route("/api/site_history")
def api_site_history():
    """Per-site ping history for the dashboard's click-to-expand site view.
    Query: ?host=<hostname>&hours=<int>
      hours unspecified → auto window: try SITE_VERDICT_BASELINE_HOURS (24h
        default), fall back to SITE_VERDICT_FALLBACK_HOURS (7d default) if
        the primary window has < SITE_VERDICT_MIN_SAMPLES successful
        samples. This matches how the site-tile verdict picks its baseline,
        so the modal's p10–p90 band reflects the same data shape that
        graded the tile.
      hours=<n> → strict — use exactly that window (capped to 30d)."""
    if _state is None:
        return jsonify({"error": "not ready"}), 503
    host = request.args.get("host", "").strip()
    if not host:
        return jsonify({"error": "host query param required"}), 400

    hours_param = request.args.get("hours")
    auto_window = hours_param is None
    if auto_window:
        primary_hours = SITE_VERDICT_BASELINE_HOURS
        fallback_hours = SITE_VERDICT_FALLBACK_HOURS
    else:
        try:
            primary_hours = max(1, min(int(hours_param), 24 * 30))
        except ValueError:
            primary_hours = SITE_VERDICT_BASELINE_HOURS
        fallback_hours = primary_hours

    now_dt = datetime.now()
    with _state.lock:
        if host not in _state.site_ping_history:
            return jsonify({"error": f"unknown host: {host}"}), 404
        hist = list(_state.site_ping_history[host])
        name = _state.site_names.get(host) or host
        all_site_outages = list(_state.site_outages)
        cur_outage = _state.current_site_outages.get(host)
        # Snapshot the per-site dict for the pool calculation outside the lock.
        all_site_hist = {h: list(v) for h, v in _state.site_ping_history.items()}

    pool_thresholds = _site_pool_thresholds(all_site_hist, now_dt)

    def _samples_for(hours: int) -> List[List]:
        cut_iso = (now_dt - timedelta(hours=hours)).isoformat()
        return [[ts, ms] for ts, ms in hist if ts >= cut_iso]

    samples = _samples_for(primary_hours)
    hours_used = primary_hours
    if auto_window:
        successes = sum(1 for _, ms in samples if ms is not None)
        if successes < SITE_VERDICT_MIN_SAMPLES and fallback_hours > primary_hours:
            samples = _samples_for(fallback_hours)
            hours_used = fallback_hours
    cutoff = (now_dt - timedelta(hours=hours_used)).isoformat()

    outages_for_host = [
        {"start": rec.start.isoformat(timespec="seconds"),
         "end":   rec.end.isoformat(timespec="seconds") if rec.end else None}
        for h, rec in all_site_outages
        if h == host and rec.start.isoformat() >= cutoff
    ]
    if cur_outage is not None and cur_outage.start.isoformat() >= cutoff:
        outages_for_host.append({
            "start": cur_outage.start.isoformat(timespec="seconds"),
            "end":   None,
        })
    # Quick stats for display.
    successes = [ms for _, ms in samples if ms is not None]
    n = len(samples)
    pct = round(len(successes) / n * 100, 1) if n else None
    if successes:
        s = sorted(successes)
        def _p(q):
            if len(s) == 1: return s[0]
            idx = q / 100 * (len(s) - 1)
            lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
            return s[lo] + (s[hi] - s[lo]) * (idx - lo)
        stats = {"p10": round(_p(10), 1), "p50": round(_p(50), 1),
                 "p90": round(_p(90), 1), "min": round(s[0], 1),
                 "max": round(s[-1], 1)}
    else:
        stats = {"p10": None, "p50": None, "p90": None, "min": None, "max": None}
    return jsonify({
        "host": host,
        "name": name,
        "hours": hours_used,
        "auto_window": auto_window,
        "primary_hours": primary_hours,
        "fallback_hours": fallback_hours,
        "samples": samples,           # [[iso_ts, ms_or_null], ...] @ ~10s cadence
        "outages": outages_for_host,
        "reachable_pct": pct,
        "ping_stats": stats,
        # Pool thresholds — same data that drives the GREAT/OK/SLOW/POOR
        # tile verdicts. Drawn as horizontal reference lines on the modal.
        "pool_thresholds": pool_thresholds,
    })


@app.route("/api/log")
def api_log():
    if _state is None:
        return jsonify({"error": "not ready"}), 503
    with _state.lock:
        speed = list(_state.speed_history)
        outages = list(_state.outages) + ([_state.current_outage] if _state.current_outage else [])
        events = list(_state.events)
    return jsonify({
        "speed": [{"ts": s.timestamp.strftime("%H:%M:%S"), "dl": round(s.download_mbps, 1),
                   "ul": round(s.upload_mbps, 1), "ping": round(s.ping_ms, 1),
                   "label": s.label, "network": s.network} for s in reversed(speed)],
        "outages": [{"start": o.start.strftime("%H:%M:%S"),
                     "end": o.end.strftime("%H:%M:%S") if o.end else None,
                     "duration": o.duration_str, "ongoing": o.ongoing}
                    for o in reversed(outages)],
        "events": [{"ts": ts, "level": lvl, "msg": msg} for ts, lvl, msg in events],
        "network_names": _db.load_network_names(),
    })


@app.route("/log")
def log_page():
    return LOG_HTML, 200, _NO_CACHE_HTML


def _diagnoses_within_30d(state: MonitorState) -> List[dict]:
    cutoff_iso = (datetime.now() - _30D).isoformat()
    with state.lock:
        return [d for d in state.diagnoses if (d.get("evaluated_at") or "") >= cutoff_iso]


@app.route("/api/diagnose", methods=["GET", "POST"])
def api_diagnose():
    if _state is None:
        return jsonify({"error": "not ready"}), 503

    if request.method == "GET":
        with _state.lock:
            latest = _state.diagnoses[0] if _state.diagnoses else {}
        return jsonify(latest)

    body = request.get_json(silent=True) or {}
    window = body.get("window", "1h")
    incident_start = incident_end = None
    outage_id = None
    if window == "outage":
        try:
            incident_start = datetime.fromisoformat(body["start"])
            incident_end   = datetime.fromisoformat(body["end"])
        except (KeyError, TypeError, ValueError):
            return jsonify({"ok": False, "error": "outage window requires ISO start and end"}), 400
        outage_id = body.get("outage_id")
    elif window not in ai_diagnosis.WINDOWS:
        return jsonify({"ok": False, "error": f"invalid window: {window!r}"}), 400

    with _state.lock:
        if _state.diagnosis_in_progress:
            return jsonify({"ok": False, "error": "diagnosis already in progress"}), 429
        _state.diagnosis_in_progress = True

    try:
        snapshot = ai_diagnosis.build_snapshot(
            _state, window,
            incident_start=incident_start,
            incident_end=incident_end,
            incident_id=outage_id,
            network_names=_db.load_network_names(),
        )
        result = ai_diagnosis.diagnose(snapshot)
        result["id"] = str(int(time.time() * 1000))
        if outage_id:
            result["outage_id"] = outage_id
        try:
            result["chart_data"] = ai_diagnosis.build_chart_data(
                _state, window,
                incident_start=incident_start,
                incident_end=incident_end,
            )
        except Exception as exc:
            logging.warning("build_chart_data failed: %s", exc)
        with _state.lock:
            _state.diagnoses.appendleft(result)
        if result.get("ok"):
            label = f"outage {outage_id}" if outage_id else window
            _state.log(f"AI diagnosis ({label}) — severity: "
                       f"{(result.get('result') or {}).get('severity', '?')}", "info")
        else:
            _state.log(f"AI diagnosis failed: {result.get('error')}", "warning")
        return jsonify(result)
    finally:
        with _state.lock:
            _state.diagnosis_in_progress = False


@app.route("/api/diagnoses")
def api_diagnoses():
    if _state is None:
        return jsonify({"error": "not ready"}), 503
    items = _diagnoses_within_30d(_state)
    # Annotate each diagnosis with its dismissed status (computed from the
    # underlying cluster id). Diagnoses without an outage_id can never be
    # dismissed via the cluster mechanism — they're window-based.
    with _state.lock:
        dismissed = set(_state.dismissed_outage_ids)
    for it in items:
        it["dismissed"] = bool(it.get("outage_id") and it["outage_id"] in dismissed)
    return jsonify({"items": items})


@app.route("/api/dismiss", methods=["POST"])
def api_dismiss():
    """Toggle the dismissed flag on a cluster. Body: {outage_id, dismissed}.
    A dismissed cluster is hidden from the timeline and the history panel
    unless the "show dismissed" toggle is on."""
    if _state is None:
        return jsonify({"error": "not ready"}), 503
    body = request.get_json(silent=True) or {}
    outage_id = (body.get("outage_id") or "").strip()
    dismissed = bool(body.get("dismissed", True))
    if not outage_id:
        return jsonify({"ok": False, "error": "outage_id required"}), 400
    with _state.lock:
        if dismissed:
            _state.dismissed_outage_ids.add(outage_id)
        else:
            _state.dismissed_outage_ids.discard(outage_id)
        n = len(_state.dismissed_outage_ids)
    _state.log(
        ("Dismissed " if dismissed else "Restored ") + outage_id +
        f" (total dismissed: {n})", "info",
    )
    return jsonify({"ok": True, "dismissed": dismissed,
                    "total_dismissed": n})


@app.route("/api/network/rename", methods=["POST"])
def api_network_rename():
    """Set or clear a friendly name for a network fingerprint.
    Body: {"fingerprint": "192.168.1.254/24", "name": "AT&T Router"}
    Pass name as null or empty string to clear."""
    body = request.get_json(silent=True) or {}
    fp = (body.get("fingerprint") or "").strip()
    if not fp:
        return jsonify({"ok": False, "error": "fingerprint required"}), 400
    raw_name = body.get("name")
    name = raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else None
    ok = _db.rename_network(fp, name)
    if not ok:
        return jsonify({"ok": False, "error": "unknown fingerprint"}), 404
    return jsonify({"ok": True, "fingerprint": fp, "display_name": name})


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """Receive monitoring data pushed from a remote collector."""
    auth_err = _check_api_key()
    if auth_err:
        return auth_err
    if _db is None:
        return jsonify({"error": "database not ready"}), 503
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "JSON body required"}), 400

    remote_host = (body.get("monitor_host") or "").strip()
    if not remote_host:
        return jsonify({"error": "monitor_host required"}), 400

    try:
        _db.flush(
            cursors=db.PersistCursors(),
            ping_samples=[(ts, v) for ts, v in body.get("ping_samples", [])],
            accessibility_samples=[(ts, v) for ts, v in body.get("accessibility_samples", [])],
            site_samples={
                host: [(ts, v) for ts, v in samples]
                for host, samples in body.get("site_samples", {}).items()
            },
            speed_samples=body.get("speed_samples", []),
            outages=body.get("outages", []),
            current_outage=None,
            degraded=body.get("degraded", []),
            router_events=body.get("router_events", []),
            diagnoses=body.get("diagnoses", []),
            dismissed_outage_ids=set(body.get("dismissed_outage_ids", [])),
            daily_summary=body.get("daily_summary", []),
            network_uptime_secs=body.get("network_uptime_secs", {}),
            network_colors=body.get("network_colors", {}),
            first_seen_iso=body.get("first_seen_iso", datetime.now().isoformat()),
            saved_at_iso=datetime.now().isoformat(),
            monitor_host_override=remote_host,
        )
        _db.update_host_seen(remote_host)
    except Exception as exc:
        logging.warning("Ingest from %s failed: %s", remote_host, exc)
        # Don't echo internal exception text (table names, paths, SQL) back to
        # the caller — log it server-side and return a generic message.
        return jsonify({"ok": False, "error": "ingest failed"}), 500

    return jsonify({"ok": True, "monitor_host": remote_host})


@app.route("/api/hosts")
def api_hosts():
    """List all known monitoring hosts and their last-seen timestamps."""
    if _db is None:
        return jsonify({"error": "database not ready"}), 503
    return jsonify({"hosts": _db.load_hosts()})


@app.route("/api/diagnoses/<diag_id>", methods=["DELETE"])
def api_delete_diagnosis(diag_id):
    if _state is None:
        return jsonify({"error": "not ready"}), 503
    with _state.lock:
        before = len(_state.diagnoses)
        _state.diagnoses = deque(
            (d for d in _state.diagnoses if d.get("id") != diag_id),
            maxlen=_state.diagnoses.maxlen,
        )
        removed = before - len(_state.diagnoses)
    if not removed:
        return jsonify({"ok": False, "error": "not found"}), 404
    _state.log(f"Deleted diagnosis {diag_id} (cluster reset to un-analyzed)", "info")
    return jsonify({"ok": True, "removed": removed})


CLUSTER_GAP_SECS = 1800  # outages OR degraded periods within 30 min = one incident


def _cluster_events(outages: List[OutageRecord],
                    degraded: List[DegradedPeriod],
                    now: datetime) -> List[Dict]:
    """Merge outages and degraded periods into unified clusters with a 30-min
    gap. Cluster category priority: outage (red) > degraded — slow/high_ping
    (yellow) > site_loss (teal). Members preserve their original kind so each
    bar renders in its own color."""
    events: List[Dict] = []
    for o in outages:
        events.append({
            "_kind": "outage",   # high severity
            "start": o.start,
            "end":   o.end or now,
            "ongoing": o.ongoing,
            "id":    o.id,
        })
    for d in degraded:
        events.append({
            "_kind": d.kind,     # "slow" | "high_ping" | "site_loss"
            "start": d.start,
            "end":   d.end or now,
            "ongoing": d.ongoing,
            "id":    d.id,
            "detail": d.detail,
        })
    if not events:
        return []
    events.sort(key=lambda e: e["start"])

    clusters: List[List[Dict]] = [[events[0]]]
    for ev in events[1:]:
        prev_end = max(m["end"] for m in clusters[-1])
        gap = (ev["start"] - prev_end).total_seconds()
        if gap <= CLUSTER_GAP_SECS:
            clusters[-1].append(ev)
        else:
            clusters.append([ev])

    out: List[Dict] = []
    for members in clusters:
        first_start = min(m["start"] for m in members)
        # Counts and total downtime per kind
        n_out  = sum(1 for m in members if m["_kind"] == "outage")
        n_slow = sum(1 for m in members if m["_kind"] == "slow")
        n_hp   = sum(1 for m in members if m["_kind"] == "high_ping")
        n_site = sum(1 for m in members if m["_kind"] == "site_loss")
        outage_secs = sum(int((m["end"] - m["start"]).total_seconds())
                          for m in members if m["_kind"] == "outage")
        degraded_secs = sum(int((m["end"] - m["start"]).total_seconds())
                            for m in members
                            if m["_kind"] in ("slow", "high_ping"))
        site_loss_secs = sum(int((m["end"] - m["start"]).total_seconds())
                             for m in members if m["_kind"] == "site_loss")
        # Category priority: outage > degraded > site_loss. A cluster with an
        # outage paints red; mixed slow/high_ping with no outage paints yellow;
        # site_loss-only clusters paint teal as their own visual class.
        if n_out > 0:
            category = "outage"
        elif (n_slow + n_hp) > 0:
            category = "degraded"
        else:
            category = "site_loss"
        # Ongoing reflects only members matching the cluster's category so an
        # open lower-priority period (e.g. a still-open slow inside an outage
        # cluster) doesn't make the bar render as a current outage when
        # connectivity is fine.
        if category == "outage":
            relevant = [m for m in members if m["_kind"] == "outage"]
        elif category == "degraded":
            relevant = [m for m in members if m["_kind"] in ("slow", "high_ping")]
        else:
            relevant = [m for m in members if m["_kind"] == "site_loss"]
        ongoing  = any(m["ongoing"] for m in relevant)
        last_end = max(m["end"] for m in relevant)
        if n_out:
            dominant_kind = "outage"
        elif n_hp >= n_slow and n_hp > 0:
            dominant_kind = "high_ping"
        elif n_slow > 0:
            dominant_kind = "slow"
        else:
            dominant_kind = "site_loss"
        out.append({
            "id": "cluster:" + first_start.isoformat(timespec="seconds"),
            "category": category,
            "dominant_kind": dominant_kind,
            "start": first_start.isoformat(timespec="seconds"),
            "end": last_end.isoformat(timespec="seconds") if not ongoing else None,
            "ongoing": ongoing,
            "duration_s": int((last_end - first_start).total_seconds()),
            "outage_count": n_out,
            "slow_count": n_slow,
            "high_ping_count": n_hp,
            "site_loss_count": n_site,
            "total_outage_s": outage_secs,
            "total_degraded_s": degraded_secs,
            "total_site_loss_s": site_loss_secs,
            "member_ids": [m["id"] for m in members],
            # Members are emitted with kind/start/end so the timeline can render
            # each in its own category color rather than painting the whole
            # cluster span in the dominant category. This keeps cross-kind
            # clustering useful for click-grouping without misrepresenting a
            # mostly-degraded cluster as a giant red outage.
            "members": [
                {
                    "kind": m["_kind"],   # "outage" | "slow" | "high_ping" | "site_loss"
                    "start": m["start"].isoformat(timespec="seconds"),
                    "end": m["end"].isoformat(timespec="seconds"),
                    "ongoing": bool(m.get("ongoing")),
                }
                for m in members
            ],
        })
    return out


def _compute_monitor_gaps(state: "MonitorState", cutoff: datetime,
                          now: datetime, threshold_s: int = 120,
                          min_report_s: int = MONITOR_GAP_MIN_REPORT_S) -> List[Dict]:
    """Find windows in [cutoff, now] when the monitor itself wasn't running.

    Uses the UNION of two heartbeats so that neither failure mode can
    produce a false gap:

      * ping_history_ts        — connectivity_thread, every 2s, appends only
                                 on probe success. Keeps firing even when the
                                 OS is throttling background processes (App
                                 Nap, etc.) — by far the most reliable
                                 indicator of "the python process is alive."
                                 But silent during real outages.
      * ping_accessibility_ts  — site_check_thread, every ~10s, appends
                                 unconditionally (records pct=0 when nothing
                                 is reachable). Survives real outages, but
                                 can stall under aggressive OS throttling.

    A gap exists only when BOTH series have nothing inside the window —
    i.e. the process truly wasn't writing anything. This matches the
    user-visible meaning of "monitor not running."

    threshold_s   — gap detection floor: any heartbeat-to-heartbeat delta
                    above this is treated as "process not running."
    min_report_s  — gap REPORTING floor: only emit gaps at least this long.
                    Genuine restarts surface; sub-threshold OS throttling
                    blips are dropped.
    """
    threshold = timedelta(seconds=threshold_s)
    min_report = timedelta(seconds=min_report_s)
    samples: List[datetime] = []
    for series in (state.ping_history_ts, state.ping_accessibility_ts):
        for entry in series:
            try:
                ts = datetime.fromisoformat(entry[0])
            except (ValueError, TypeError, IndexError):
                continue
            if ts < cutoff:
                continue
            samples.append(ts)
    samples.sort()

    install = state.first_seen
    # The "expected coverage" window is [max(cutoff, install), now]. Anything
    # before install is "not yet installed" (already rendered dim by the
    # frontend); we don't emit a gap there.
    win_start = max(cutoff, install)
    if win_start >= now:
        return []

    gaps: List[Dict] = []
    prev = win_start
    for ts in samples:
        if ts <= prev:
            prev = ts
            continue
        if ts - prev > threshold and ts - prev >= min_report:
            gaps.append({
                "start": prev.isoformat(timespec="seconds"),
                "end": ts.isoformat(timespec="seconds"),
                "duration_s": int((ts - prev).total_seconds()),
            })
        prev = ts
    # Trailing: if heartbeat stopped a while ago, treat as ongoing gap to now.
    if now - prev > threshold and now - prev >= min_report:
        gaps.append({
            "start": prev.isoformat(timespec="seconds"),
            "end": now.isoformat(timespec="seconds"),
            "duration_s": int((now - prev).total_seconds()),
        })
    return gaps


@app.route("/api/timeline")
def api_timeline():
    if _state is None:
        return jsonify({"error": "not ready"}), 503
    try:
        days = int(request.args.get("days", "7"))
    except ValueError:
        return jsonify({"error": "days must be an integer"}), 400
    days = max(1, min(days, 60))
    now = datetime.now()
    cutoff = now - timedelta(days=days)
    with _state.lock:
        in_outages = [
            o for o in (list(_state.outages) + ([_state.current_outage] if _state.current_outage else []))
            if o.start >= cutoff
        ]
        in_degraded = [d for d in list(_state.degraded_periods) if d.start >= cutoff]
        clusters = _cluster_events(in_outages, in_degraded, now)
        monitor_gaps = _compute_monitor_gaps(_state, cutoff, now)

        # For each saved diagnosis, capture its outage_id, the timestamp
        # implied by that id (the "anchor"), and its title. The anchor lets us
        # match a saved diagnosis against today's clusters even when the cluster
        # boundaries have shifted between code versions (e.g. older 5-min
        # clusters now subsumed into a wider 30-min cluster).
        diag_anchors: List[Tuple[str, Optional[datetime], str]] = []
        for d in _state.diagnoses:
            oid = d.get("outage_id")
            if not oid:
                continue
            iso = ""
            if oid.startswith("cluster:"):
                iso = oid[len("cluster:"):]
            elif oid.startswith("out:"):
                iso = oid[len("out:"):]
            elif oid.startswith("deg:"):
                rest = oid[len("deg:"):]
                if ":" in rest:
                    iso = rest.split(":", 1)[1]
            anchor: Optional[datetime] = None
            if iso:
                try:
                    anchor = datetime.fromisoformat(iso)
                except ValueError:
                    anchor = None
            title = (d.get("result") or {}).get("title") or ""
            diag_anchors.append((oid, anchor, title))
        first_seen = _state.first_seen

    analyzed_ids: List[str] = []
    titles_by_cluster: Dict[str, str] = {}
    for c in clusters:
        c_start = datetime.fromisoformat(c["start"])
        c_end = datetime.fromisoformat(c["end"]) if c.get("end") else now
        member_set = set([c["id"]] + c["member_ids"])
        matched_title = ""
        is_analyzed = False
        # state.diagnoses iterates newest-first; first matching title wins.
        for oid, anchor, title in diag_anchors:
            if oid in member_set or (anchor is not None and c_start <= anchor <= c_end):
                is_analyzed = True
                if title and not matched_title:
                    matched_title = title
        if is_analyzed:
            analyzed_ids.append(c["id"])
            if matched_title:
                titles_by_cluster[c["id"]] = matched_title

    return jsonify({
        "days": days,
        "generated_at": now.isoformat(timespec="seconds"),
        "monitor_started_at": first_seen.isoformat(timespec="seconds"),
        "clusters": clusters,
        "analyzed_ids": analyzed_ids,
        "dismissed_ids": sorted(_state.dismissed_outage_ids),
        "titles": titles_by_cluster,
        "monitor_gaps": monitor_gaps,
    })


@app.route("/diagnose")
def diagnose_page():
    return _versioned(DIAGNOSE_HTML), 200, _NO_CACHE_HTML


@app.route("/static/timeline.js")
def static_timeline_js():
    # No-cache: the JS is embedded in the Python source and ships with each
    # server restart. Without this header the browser's heuristic cache served
    # stale renderer code after fixes (e.g. timeline overflow clamping) until a
    # hard refresh — confusing because reloading the page didn't update.
    return TIMELINE_JS, 200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-cache, no-store, must-revalidate",
    }


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────
def _init_db() -> None:
    """Open the SQLite store and prune stale rows once at startup."""
    global _db, _last_pruned_at
    db_path = db.db_path_from_env(DB_FILE)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    _db = db.Storage(db_path)
    _db.init_schema()
    _init_session_secret()
    try:
        deleted = _db.prune(db.retention_from_env())
        total = sum(deleted.values())
        if total:
            print(f"  Pruned {total} stale row(s) from DB on startup.", flush=True)
    except Exception as exc:
        logging.warning("Startup prune failed: %s", exc)
    _last_pruned_at = time.time()


def main() -> None:
    global _state
    state = MonitorState()
    _state = state

    _init_db()
    load_state(state)

    conn_t    = threading.Thread(target=connectivity_thread, args=(state,), daemon=True, name="conn")
    persist_t = threading.Thread(target=persistence_thread,  args=(state,), daemon=True, name="persist")
    site_t    = threading.Thread(target=site_check_thread,   args=(state,), daemon=True, name="sites")
    router_t  = threading.Thread(target=router_log_thread,   args=(state,), daemon=True, name="router")
    conn_t.start()
    persist_t.start()
    site_t.start()
    router_t.start()

    if DISABLE_SPEED_TESTS:
        state.log("Speed tests disabled (DISABLE_SPEED_TESTS=true)", "info")
    else:
        speed_t = threading.Thread(target=speed_test_thread, args=(state,), daemon=True, name="speed")
        speed_t.start()

    if SERVER_URL:
        sync_t = threading.Thread(target=sync_thread, args=(state,), daemon=True, name="sync")
        sync_t.start()
        state.log(f"Sync enabled → {SERVER_URL}", "info")

    state.log("Monitor started", "info")
    if SPEEDTEST_AVAILABLE and not DISABLE_SPEED_TESTS:
        state.log("speedtest-cli detected — using for measurements", "info")

    if MULTI_TENANT:
        mode_label = "server · multi-tenant"
    elif AGGREGATOR:
        mode_label = "aggregator"
    elif SERVER_URL:
        mode_label = "collector"
    else:
        mode_label = "standalone"
    print(f"\n  Connection Monitor ({mode_label})")
    print(f"  Host      → {MONITOR_HOST}")
    print(f"  Dashboard → http://localhost:{PORT}  (bind {BIND_HOST})")
    if SERVER_URL:
        print(f"  Syncing   → {SERVER_URL}")
    # Loud warning if the dashboard is reachable beyond loopback with no
    # password — that exposes every endpoint (including the mutating ones) to
    # anyone on the network.
    if (BIND_HOST not in ("127.0.0.1", "localhost", "::1")
            and not DASHBOARD_USER and not MULTI_TENANT):
        print(f"  ⚠  WARNING: binding to {BIND_HOST} with no DASHBOARD_USER set —")
        print(f"     the dashboard is exposed to your whole network without a password.")
        print(f"     Set DASHBOARD_USER/DASHBOARD_PASS, enable MULTI_TENANT, or use BIND_HOST=127.0.0.1.")
    print(f"  Stop      → Ctrl+C\n", flush=True)

    try:
        app.run(
            host=BIND_HOST,
            port=PORT,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
    except KeyboardInterrupt:
        pass
    finally:
        state.running = False
        save_state(state)
        if _db is not None:
            try:
                _db.close()
            except Exception:
                pass
        print("\n  Monitor stopped.\n")


if __name__ == "__main__":
    main()
