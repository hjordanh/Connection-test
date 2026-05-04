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
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─────────────────────────────────────────────────────────────
# Auto-install Flask
# ─────────────────────────────────────────────────────────────
def _pip_install(pkg: str) -> None:
    import subprocess
    print(f"Installing {pkg!r}…", flush=True)
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-q", pkg],
        stdout=subprocess.DEVNULL,
    )

try:
    from flask import Flask, jsonify, request
except ImportError:
    _pip_install("flask")
    from flask import Flask, jsonify, request

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

import router_log
import ai_diagnosis

# Optional: speedtest-cli for more accurate measurements
try:
    import speedtest as _st
    SPEEDTEST_AVAILABLE = True
except ImportError:
    SPEEDTEST_AVAILABLE = False

PORT = int(os.environ.get("PORT", "8765"))
DATA_FILE    = os.path.join(SCRIPT_DIR, "connection_monitor_data.json")
CONFIG_FILE  = os.path.join(SCRIPT_DIR, "ping_targets.conf")
_24H = timedelta(hours=24)
_30D = timedelta(days=30)

# Router log scraping (all values from connection_monitor.env or shell env).
GATEWAY_URL            = os.environ.get("GATEWAY_URL", "")
ROUTER_PACKET_LOG_PATH = os.environ.get("ROUTER_PACKET_LOG_PATH", "")
ROUTER_SYSLOG_PATH     = os.environ.get("ROUTER_SYSLOG_PATH", "")
ROUTER_POLL_INTERVAL   = int(os.environ.get("ROUTER_POLL_INTERVAL", "30"))

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
HIGH_PING_OPEN_MULT  = 3.0
HIGH_PING_FLOOR_MS   = 100.0  # never trigger if absolute p90 below this
HIGH_PING_DURATION_S = 60     # sustained-condition window for opening
SLOW_CLOSE_STREAK         = 3   # samples (≈15min @ 5min cadence)
HIGH_PING_CLOSE_STREAK    = 30  # probes (≈60s @ 2s)
SITE_LOSS_OPEN_STREAK     = 3   # consecutive failed checks (≈30s @ 10s)
SITE_LOSS_CLOSE_STREAK    = 6   # consecutive successful checks (≈60s @ 10s)

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
    provider: str = ""


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
        self.ping_history_ts: deque = deque(maxlen=43200)  # (HH:MM:SS, float) — 24h @ 2s

        # Outages
        self.outages: List[OutageRecord] = []
        self.current_outage: Optional[OutageRecord] = None

        # Speeds
        self.speed_history: List[SpeedSample] = []
        self.speed_in_progress: bool = False
        self.speed_status: str = ""
        self.last_speed_test: Optional[datetime] = None    # last attempt (success or fail)
        self.last_speed_success: Optional[datetime] = None # last successful result
        self.speed_interval_secs: int = 300                # 5 minutes between successes
        self.trigger_post_outage_test: bool = False

        # Events
        self.events: deque = deque(maxlen=500)

        # Multi-site accessibility
        self.site_targets, self.site_names = load_ping_targets()
        self.site_states: Dict[str, bool] = {}          # hostname -> currently up?
        self.current_site_outages: Dict[str, OutageRecord] = {}
        self.site_outages: List[Tuple[str, OutageRecord]] = []
        # parallel history to ping_history_ts: (iso_ts, pct_accessible)
        self.ping_accessibility_ts: deque = deque(maxlen=43200)
        # per-site latency history: hostname -> deque of (iso_ts, ms_or_None)
        # site check runs every 10s → 8640 entries/24h per site
        self.site_ping_history: Dict[str, deque] = {}

        # Provider
        self.current_provider: str = ""
        self.provider_uptime_secs: Dict[str, float] = {}
        self.provider_start_time: Dict[str, datetime] = {}
        self.provider_colors: Dict[str, str] = {}
        self._provider_color_palette: List[str] = [
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
        # Streak counters for percentile-based close criteria.
        self._slow_close_streak: int = 0
        self._high_ping_close_streak: int = 0
        # Per-host streaks for site_loss open/close.
        self._site_fail_streaks: Dict[str, int] = {}
        self._site_pass_streaks: Dict[str, int] = {}

        # Router log scraper — stores router_log.RouterEvent objects
        self.router_events: deque = deque(maxlen=5000)
        self.last_router_poll: Optional[datetime] = None
        self.router_poll_error: Optional[str] = None
        self._router_warned_at: Optional[datetime] = None

        # AI diagnosis — rolling 30-day history, newest first.
        # Each entry is the dict returned by ai_diagnosis.diagnose() with an
        # added "id" field (millisecond timestamp string).
        self.diagnoses: deque = deque(maxlen=500)
        self.diagnosis_in_progress: bool = False

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

    def assign_provider_color(self, provider: str) -> str:
        """Return (and cache) a stable color for this provider. Call with lock held."""
        if provider not in self.provider_colors:
            idx = len(self.provider_colors) % len(self._provider_color_palette)
            self.provider_colors[provider] = self._provider_color_palette[idx]
        return self.provider_colors[provider]

    def avg_ping(self) -> Optional[float]:
        with self.lock:
            if not self.ping_history:
                return None
            return sum(self.ping_history) / len(self.ping_history)

    def all_provider_uptimes(self) -> Dict[str, float]:
        with self.lock:
            now = datetime.now()
            result: Dict[str, float] = dict(self.provider_uptime_secs)
            if self.current_provider and self.current_provider in self.provider_start_time:
                result[self.current_provider] = result.get(self.current_provider, 0.0) + (
                    now - self.provider_start_time[self.current_provider]
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
        h, rem = divmod(s, 3600)
        m, sec = divmod(rem, 60)
        if h:
            return f"{h}h {m:02d}m {sec:02d}s"
        if m:
            return f"{m}m {sec:02d}s"
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
            interval          = self.speed_interval_secs
            events           = list(self.events)
            start_time       = self.start_time
            current_provider = self.current_provider
            provider_colors  = dict(self.provider_colors)
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

        now = datetime.now()
        runtime_secs = (now - start_time).total_seconds()
        avg_p = (sum(ping_hist) / len(ping_hist)) if ping_hist else None
        provider_uptimes = self.all_provider_uptimes()
        total_out = self.total_outage_secs()
        all_outages = outages + ([cur_out] if cur_out else [])

        next_test_in = None
        if not in_progress:
            if last_speed_success:
                secs_since_success = (now - last_speed_success).total_seconds()
                if secs_since_success >= interval:
                    # Retry mode: next attempt in 60s from last attempt
                    secs_since_attempt = (now - last_speed_test).total_seconds() if last_speed_test else interval
                    next_test_in = max(0, 60 - secs_since_attempt)
                else:
                    # Normal: next test at 5-min mark from last success
                    next_test_in = max(0, interval - secs_since_success)
            elif last_speed_test:
                # No success yet (baseline failed): retry every 60s
                secs_since_attempt = (now - last_speed_test).total_seconds()
                next_test_in = max(0, 60 - secs_since_attempt)

        # Current uptime: time since last outage ended (or since start if none)
        if cur_out:
            current_uptime_secs = 0.0
        else:
            last_end = max((o.end for o in outages if o.end), default=None)
            since = last_end if last_end else start_time
            current_uptime_secs = (now - since).total_seconds()

        # 5-minute slices (before downsampling)
        cutoff_1h = now - timedelta(hours=1)
        cutoff_5m = now - timedelta(minutes=5)
        ping_ts_5m = [(t, v) for t, v in ping_ts if datetime.fromisoformat(t) >= cutoff_5m]

        # Build accessibility lookup: nearest pct for each ping timestamp
        # access_ts entries are (iso_ts, pct) at ~10s cadence
        access_map: Dict[str, float] = {t: p for t, p in access_ts}

        def nearest_pct(ts_str: str) -> Optional[float]:
            """Find nearest accessibility value for a ping timestamp."""
            if not access_ts:
                return None
            # access_ts is ordered; binary-ish search for nearest
            best = None
            best_delta = float("inf")
            target = datetime.fromisoformat(ts_str)
            for a_ts, a_pct in access_ts:
                delta = abs((datetime.fromisoformat(a_ts) - target).total_seconds())
                if delta < best_delta:
                    best_delta = delta
                    best = a_pct
                elif delta > best_delta + 30:
                    break
            return best

        # Downsample 24h ping to max 300 points for chart performance
        MAX_PING_CHART = 300
        ping_ts_all = ping_ts  # keep full list for hourly percentile calc
        if len(ping_ts) > MAX_PING_CHART:
            step = len(ping_ts) / MAX_PING_CHART
            ping_ts = [ping_ts[int(i * step)] for i in range(MAX_PING_CHART)]

        # Downsample accessibility to match ping chart points
        access_ts_ds = access_ts
        if len(access_ts) > MAX_PING_CHART:
            step = len(access_ts) / MAX_PING_CHART
            access_ts_ds = [access_ts[int(i * step)] for i in range(MAX_PING_CHART)]

        # Hourly percentile buckets for 24h ping chart
        hourly_buckets: Dict[str, List[float]] = defaultdict(list)
        for ts_str, v in ping_ts_all:
            try:
                dt = datetime.fromisoformat(ts_str)
                hour_key = dt.strftime("%H:00")
                hourly_buckets[hour_key].append(v)
            except ValueError:
                pass

        def _percentile(sorted_vals: List[float], p: float) -> float:
            n = len(sorted_vals)
            if n == 1:
                return sorted_vals[0]
            idx = p / 100 * (n - 1)
            lo, hi = int(idx), min(int(idx) + 1, n - 1)
            return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo)

        # Sort hourly keys chronologically (they are HH:00 strings)
        ping_hourly = []
        for hk in sorted(hourly_buckets.keys()):
            h_int = int(hk[:2])
            hour_label = f"{h_int % 12 or 12}{'am' if h_int < 12 else 'pm'}"
            vals = sorted(hourly_buckets[hk])
            p10 = round(_percentile(vals, 10), 1)
            p50 = round(_percentile(vals, 50), 1)
            p90 = round(_percentile(vals, 90), 1)
            ping_hourly.append({
                "hour": hour_label,
                "p10":  p10,
                "p50":  p50,
                "p90":  p90,
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
                provider = tests[-1].provider
            else:
                dl_p10 = dl_p90 = dl_max = None
                ul_p10 = ul_p90 = ul_max = None
                provider = None
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
                "provider":    provider,
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
                "provider":    latest.provider,
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

        site_matrix = []
        cutoff_5m_site  = now - timedelta(minutes=5)
        cutoff_1h_site  = now - timedelta(hours=1)
        cutoff_24h_site = now - timedelta(hours=24)
        for host in site_targets_snap:
            hist = site_ping_hist_snap.get(host, [])
            h5m  = [(t, ms) for t, ms in hist if datetime.fromisoformat(t) >= cutoff_5m_site]
            h1h  = [(t, ms) for t, ms in hist if datetime.fromisoformat(t) >= cutoff_1h_site]
            h24h = [(t, ms) for t, ms in hist if datetime.fromisoformat(t) >= cutoff_24h_site]
            p5m,  p10_5m,  p50_5m,  p90_5m  = _site_stats(h5m)
            p1h,  p10_1h,  p50_1h,  p90_1h  = _site_stats(h1h)
            p24h, p10_24h, p50_24h, p90_24h = _site_stats(h24h)
            site_matrix.append({
                "host":    host,
                "name":    site_names_snap.get(host) or _friendly_name(host),
                "up":      site_states_snap.get(host, True),
                "pct_5m":  p5m,  "p10_5m":  p10_5m,  "p50_5m":  p50_5m,  "p90_5m":  p90_5m,
                "pct_1h":  p1h,  "p10_1h":  p10_1h,  "p50_1h":  p50_1h,  "p90_1h":  p90_1h,
                "pct_24h": p24h, "p10_24h": p10_24h, "p50_24h": p50_24h, "p90_24h": p90_24h,
            })

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
            "current_provider": current_provider,
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
            "access_chart": [
                {"t": t[11:19] if len(t) > 8 else t, "v": round(p, 1)}
                for t, p in access_ts_ds
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
                    "provider": s.provider,
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
                    "provider": s.provider,
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
                    "provider": s.provider,
                }
                for s in speed_history_1h
            ],
            "speed_in_progress": in_progress,
            "speed_status": speed_status,
            "next_test_in": int(next_test_in) if next_test_in is not None else None,
            "provider_uptimes": {
                k: {"pct": min(100.0, round(v / runtime_secs * 100, 1)) if runtime_secs > 0 else 0.0}
                for k, v in provider_uptimes.items()
            },
            "provider_colors": provider_colors,
            "uptime_pct_24h": uptime_pct_24h,
            "site_matrix": site_matrix,
            "uptime_7d": uptime_7d,
            "router": _router_stats(router_events_snap, last_router_poll_snap, router_poll_error_snap, now),
            "last_diagnosis_at": (last_diagnosis_snap.get("evaluated_at") if last_diagnosis_snap else None),
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


def _detect_provider() -> str:
    endpoints: List[Tuple[str, object]] = [
        ("https://ipinfo.io/json", lambda d: " ".join(d.get("org", "").split()[1:]).strip()),
        ("http://ip-api.com/json",  lambda d: d.get("isp", "").strip()),
    ]
    for url, extract in endpoints:
        try:
            req = urllib.request.Request(url, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                name = extract(data)  # type: ignore[operator]
                if name:
                    return name
        except Exception:
            continue
    return "Unknown"


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


def _speedtest_lib() -> Tuple[Optional[float], Optional[float], Optional[float]]:
    try:
        s = _st.Speedtest()
        s.get_best_server()
        dl = s.download() / 1_000_000
        ul = s.upload() / 1_000_000
        return dl, ul, s.results.ping
    except Exception as exc:
        logging.warning("speedtest-cli error: %s", exc)
        return None, None, None


def run_speed_test(state: MonitorState, label: str) -> None:
    with state.lock:
        if state.speed_in_progress:
            return
        state.speed_in_progress = True
        state.speed_status = "Detecting provider…"

    provider = _detect_provider()
    with state.lock:
        old_provider = state.current_provider
        now = datetime.now()
        if old_provider and old_provider != provider:
            if old_provider in state.provider_start_time:
                elapsed = (now - state.provider_start_time[old_provider]).total_seconds()
                state.provider_uptime_secs[old_provider] = (
                    state.provider_uptime_secs.get(old_provider, 0.0) + elapsed
                )
        if not old_provider or old_provider != provider:
            state.provider_start_time[provider] = now
        state.current_provider = provider
        state.assign_provider_color(provider)
        state.speed_status = "Initialising speed test…"

    dl: Optional[float] = None
    ul: Optional[float] = None
    ping: Optional[float] = None

    try:
        if SPEEDTEST_AVAILABLE:
            with state.lock:
                state.speed_status = "Running speedtest-cli (≈30s)…"
            dl, ul, ping = _speedtest_lib()
            if dl is None and ul is None:
                state.log("speedtest-cli failed — trying HTTP fallback…", "warning")

        if dl is None and ul is None:
            with state.lock:
                state.speed_status = "Measuring download speed…"
            dl = _http_download_mbps()
            with state.lock:
                state.speed_status = "Measuring upload speed…"
            ul = _http_upload_mbps()
            _, ping = check_connectivity()

        if dl is not None or ul is not None:
            now = datetime.now()
            sample = SpeedSample(
                timestamp=now,
                download_mbps=dl or 0.0,
                upload_mbps=ul or 0.0,
                ping_ms=ping or 0.0,
                label=label,
                provider=provider,
            )
            slow_event: Optional[Tuple[str, str]] = None
            with state.lock:
                state.speed_history.append(sample)
                state.last_speed_success = now
                slow_event = _update_slow_degraded(state, sample, now)

            dl_str = f"↓{dl:.1f}" if dl else "↓?"
            ul_str = f"↑{ul:.1f}" if ul else "↑?"
            state.log(f"Speed [{label}] via {provider}: {dl_str} {ul_str} Mbps")
            if slow_event:
                state.log(*slow_event)
        else:
            state.log("Speed test: no results (network error?)", "warning")

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

    # Open: single sample below 7d-P10 (the bottom-tail of recent experience).
    # Stricter than the old "50% of P50" trigger — only fires on samples worse
    # than 90% of last week, dramatically reducing false positives.
    if state.current_slow is None and not is_outage_sample and dl < p10:
        period = DegradedPeriod(
            start=now, kind="slow",
            detail=f"download {dl:.1f} Mbps < 7d-P10 ({p10:.1f} Mbps); 7d median {p50:.1f}",
        )
        state.current_slow = period
        state.degraded_periods.append(period)
        state._slow_close_streak = 0
        return (f"Degraded: slow ({dl:.1f} Mbps, P10 {p10:.1f}, P50 {p50:.1f})", "warning")

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


def _update_high_ping_degraded(state: "MonitorState", latency_ms: Optional[float],
                               now: datetime) -> Optional[Tuple[str, str]]:
    """Track high-ping windows. Called from connectivity_thread under state.lock.
    Returns optional (msg, level) to log outside the lock.

    Open: rolling p90 of last 30 connectivity probes ≥ max(100ms, 3× 7d-median),
    sustained for HIGH_PING_DURATION_S (single condition, must hold).
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

    # Open threshold sized off 7d median ping (fall back to floor only).
    baseline = None
    cutoff = now - timedelta(days=7)
    medians = [s.ping_ms for s in state.speed_history
               if s.timestamp >= cutoff and s.ping_ms > 0]
    if len(medians) >= SLOW_MIN_HISTORY:
        baseline = statistics.median(medians)
    open_threshold = max(HIGH_PING_FLOOR_MS,
                         (HIGH_PING_OPEN_MULT * baseline) if baseline else HIGH_PING_FLOOR_MS)

    if p90 >= open_threshold:
        if state._high_ping_started_above is None:
            state._high_ping_started_above = now
        elif (now - state._high_ping_started_above).total_seconds() >= HIGH_PING_DURATION_S:
            period = DegradedPeriod(
                start=state._high_ping_started_above, kind="high_ping",
                detail=f"p90 {p90:.0f}ms ≥ {open_threshold:.0f}ms threshold",
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
def save_state(state: MonitorState) -> None:
    """Write speed history, outages, and ping history to disk (atomic write)."""
    try:
        cutoff = datetime.now() - _24H
        cutoff_30d = datetime.now() - _30D
        with state.lock:
            speed = [
                {
                    "timestamp": s.timestamp.isoformat(),
                    "download_mbps": s.download_mbps,
                    "upload_mbps": s.upload_mbps,
                    "ping_ms": s.ping_ms,
                    "label": s.label,
                    "provider": s.provider,
                }
                for s in state.speed_history
                if s.timestamp >= cutoff
            ]
            outages = [
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
            ping_ts = [
                [ts, v]
                for ts, v in state.ping_history_ts
                if datetime.fromisoformat(ts) >= cutoff
            ]
            access_ts = [
                [ts, v]
                for ts, v in state.ping_accessibility_ts
                if datetime.fromisoformat(ts) >= cutoff
            ]
            provider_uptime = dict(state.provider_uptime_secs)
            provider_colors = dict(state.provider_colors)
            current_outage = state.current_outage
            daily_history_snap = list(state.daily_history)
            router_events_to_save = [
                ev.to_dict()
                for ev in state.router_events
                if ev.timestamp >= cutoff.isoformat()
            ]
            cutoff_30d_iso = (datetime.now() - _30D).isoformat()
            diagnoses_to_save = [
                d for d in state.diagnoses
                if (d.get("evaluated_at") or "") >= cutoff_30d_iso
            ]

        # Compute today's daily summary
        now_dt = datetime.now()
        today_start = now_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        today_str = today_start.strftime("%Y-%m-%d")

        # Today's outage seconds (from the outages list already read + current_outage)
        all_today = [o for o in outages if o["start"][:10] == today_str]
        today_outage_secs = 0.0
        for o_dict in all_today:
            o_start = max(datetime.fromisoformat(o_dict["start"]), today_start)
            o_end_raw = datetime.fromisoformat(o_dict["end"]) if o_dict.get("end") else now_dt
            o_end = min(o_end_raw, now_dt)
            if o_end > o_start:
                today_outage_secs += (o_end - o_start).total_seconds()
        # Also account for ongoing outage
        if current_outage and current_outage.start.date() == now_dt.date():
            o_start = max(current_outage.start, today_start)
            today_outage_secs += (now_dt - o_start).total_seconds()

        today_window = (now_dt - today_start).total_seconds()
        today_uptime = round(max(0.0, (today_window - today_outage_secs) / today_window * 100), 2) if today_window > 0 else 100.0

        # Today's pings from the ping_ts list already read in save_state
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
        with state.lock:
            state.daily_history = new_daily_history

        data = {
            "speed_history": speed,
            "outages": outages,
            "ping_history_ts": ping_ts,
            "ping_accessibility_ts": access_ts,
            "provider_uptime_secs": provider_uptime,
            "provider_colors": provider_colors,
            "daily_history": new_daily_history,
            "router_events": router_events_to_save,
            "degraded_periods": degraded,
            "diagnoses": diagnoses_to_save,
            "first_seen": state.first_seen.isoformat(),
            "saved_at": datetime.now().isoformat(),
        }
        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, DATA_FILE)
    except Exception as exc:
        logging.warning("Failed to save state: %s", exc)


def load_state(state: MonitorState) -> None:
    """Load history from disk; silently skip anything older than 24 hours."""
    if not os.path.exists(DATA_FILE):
        return
    try:
        with open(DATA_FILE) as f:
            data = json.load(f)
        cutoff = datetime.now() - _24H
        cutoff_30d = datetime.now() - _30D

        speed: List[SpeedSample] = []
        for s in data.get("speed_history", []):
            ts = datetime.fromisoformat(s["timestamp"])
            if ts >= cutoff:
                speed.append(SpeedSample(
                    timestamp=ts,
                    download_mbps=s["download_mbps"],
                    upload_mbps=s["upload_mbps"],
                    ping_ms=s["ping_ms"],
                    label=s.get("label", ""),
                    provider=s.get("provider", ""),
                ))

        outages: List[OutageRecord] = []
        for o in data.get("outages", []):
            start = datetime.fromisoformat(o["start"])
            if start >= cutoff_30d:
                end = datetime.fromisoformat(o["end"]) if o.get("end") else None
                outages.append(OutageRecord(start=start, end=end))

        # Drop unreliable degraded period records on load:
        #   1. end is missing → orphan from a restart that lost current_slow /
        #      current_high_ping. We have no truthful end time.
        #   2. end - start > MAX_DEGRADED_LOAD_DURATION → almost certainly a
        #      previously force-closed orphan with a fake saved-at end time,
        #      or a runaway period from before the streak-based close logic
        #      landed. Real degraded periods clear within minutes once the
        #      P10/P90 streak conditions are met.
        # state.current_slow / state.current_high_ping start at None (existing
        # behavior); detection runs fresh against the next live sample.
        MAX_DEGRADED_LOAD_DURATION = timedelta(hours=4)
        degraded_loaded: List[DegradedPeriod] = []
        dropped_orphan = dropped_long = 0
        for d in data.get("degraded_periods", []):
            try:
                start = datetime.fromisoformat(d["start"])
            except (KeyError, ValueError):
                continue
            if start < cutoff_30d:
                continue
            end_raw = d.get("end")
            if not end_raw:
                dropped_orphan += 1
                continue
            try:
                end = datetime.fromisoformat(end_raw)
            except ValueError:
                dropped_orphan += 1
                continue
            kind = d.get("kind", "slow")
            # Slow / high_ping should clear within minutes once the new
            # streak-based close criteria are met — anything > 4h is almost
            # certainly a previously-orphaned record. site_loss is exempt:
            # a real third-party service outage can legitimately last hours.
            if kind in ("slow", "high_ping") and end - start > MAX_DEGRADED_LOAD_DURATION:
                dropped_long += 1
                continue
            degraded_loaded.append(DegradedPeriod(
                start=start, end=end,
                kind=kind,
                detail=d.get("detail", ""),
            ))
        if dropped_orphan or dropped_long:
            logging.info("load_state: dropped %d orphan + %d unrealistically long "
                         "degraded period(s) (> %s)",
                         dropped_orphan, dropped_long,
                         MAX_DEGRADED_LOAD_DURATION)

        ping_ts: List[Tuple[str, float]] = [
            (ts, v)
            for ts, v in data.get("ping_history_ts", [])
            if datetime.fromisoformat(ts) >= cutoff
        ]

        access_ts: List[Tuple[str, float]] = [
            (ts, v)
            for ts, v in data.get("ping_accessibility_ts", [])
            if datetime.fromisoformat(ts) >= cutoff
        ]

        router_events_loaded: List = []
        for r in data.get("router_events", []):
            ts = r.get("ts", "")
            try:
                if ts and datetime.fromisoformat(ts) < cutoff:
                    continue
            except ValueError:
                continue
            router_events_loaded.append(router_log.RouterEvent(
                timestamp=ts,
                src=r.get("src", ""),
                dst=r.get("dst", ""),
                proto=r.get("proto", ""),
                reason=r.get("reason", ""),
                source=r.get("source", "packet"),
            ))

        with state.lock:
            state.speed_history = speed
            state.outages = outages
            state.ping_history_ts = deque(ping_ts, maxlen=43200)
            state.ping_accessibility_ts = deque(access_ts, maxlen=43200)
            state.provider_uptime_secs = data.get("provider_uptime_secs", {})
            state.provider_colors = data.get("provider_colors", {})
            state.daily_history = data.get("daily_history", [])
            state.router_events = deque(router_events_loaded, maxlen=5000)
            state.degraded_periods = deque(degraded_loaded, maxlen=2000)

            # Restore first_seen — always take the min of (persisted value if
            # any, current process start, earliest piece of persisted data) so
            # that long-running installs retain their full history even if the
            # monitor was restarted recently or this is the first save under
            # this code version.
            candidates: List[datetime] = [state.first_seen]
            try:
                fs = data.get("first_seen")
                if fs:
                    candidates.append(datetime.fromisoformat(fs))
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
            daily = data.get("daily_history") or []
            if daily:
                try:
                    candidates.append(datetime.strptime(min(e["date"] for e in daily), "%Y-%m-%d"))
                except (ValueError, KeyError):
                    pass
            state.first_seen = min(candidates)

            cutoff_30d_iso = (datetime.now() - _30D).isoformat()
            history_raw = data.get("diagnoses")
            if history_raw is None:
                # Backward-compat: previous schema stored a single last_diagnosis.
                legacy = data.get("last_diagnosis")
                history_raw = [legacy] if legacy else []
            kept = []
            for d in history_raw:
                if (d.get("evaluated_at") or "") < cutoff_30d_iso:
                    continue
                # Backfill missing ids on legacy records so the delete UI can
                # target them. Synthesize from evaluated_at + a short hash.
                if not d.get("id"):
                    base = d.get("evaluated_at") or "unknown"
                    d["id"] = "legacy-" + str(abs(hash(base)) % 10_000_000)
                kept.append(d)
            state.diagnoses = deque(kept, maxlen=500)
            if speed:
                state.last_speed_test = max(s.timestamp for s in speed)
                successes = [s for s in speed if s.label != "Outage"]
                if successes:
                    state.last_speed_success = max(s.timestamp for s in successes)

        print(f"  Loaded {len(speed)} speed samples, {len(outages)} outages, "
              f"{len(ping_ts)} ping points from disk.", flush=True)
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
                        state.site_ping_history[host] = deque(maxlen=8640)
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
    """Save state to disk every 60 seconds."""
    while state.running:
        time.sleep(60)
        if state.running:
            save_state(state)


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
            was_connected = state.connected
            state.connected = online
            now = datetime.now()

            if latency is not None:
                state.last_ping_ms = latency
                state.ping_history.append(latency)
                state.ping_history_ts.append(
                    (now.isoformat(timespec="seconds"), latency)
                )
            elif not online:
                state.last_ping_ms = None

            if online and not was_connected:
                if state.current_outage:
                    state.current_outage.end = now
                    state.outages.append(state.current_outage)
                    state.current_outage = None
                    state.trigger_post_outage_test = True
                event = ("Connection restored!", "success")
            elif not online and was_connected:
                state.current_outage = OutageRecord(start=now)
                event = ("Connection LOST!", "error")

            ping_event = _update_high_ping_degraded(state, latency, now)

        if event:
            state.log(*event)
        if ping_event:
            state.log(*ping_event)

        time.sleep(2)


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
            last_success  = state.last_speed_success
            interval      = state.speed_interval_secs
            outage_active = state.current_outage is not None
            cur_provider  = state.current_provider

        if in_progress:
            continue

        # Active outage (no connectivity): record 0-bandwidth sample every 60s
        # instead of attempting a live test.
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
                    provider=cur_provider,
                )
                with state.lock:
                    state.speed_history.append(sample)
                    state.last_speed_test = now
                state.log("Speed: 0 Mbps (outage in progress)", "warning")
            continue

        if not online:
            continue

        # Post-outage: run a test shortly after connectivity is restored.
        if trigger_post:
            with state.lock:
                state.trigger_post_outage_test = False
            for _ in range(6):
                if not state.running:
                    return
                time.sleep(1)
            run_speed_test(state, "Post-outage")
            continue

        # Normal scheduling:
        # - If last success was < 5 min ago: wait for the 5-min mark.
        # - If last success was >= 5 min ago (or never): retry every 60s.
        now = datetime.now()
        secs_since_success = (now - last_success).total_seconds() if last_success else float("inf")
        secs_since_attempt = (now - last_attempt).total_seconds() if last_attempt else float("inf")

        if secs_since_success >= interval:
            # Past the 5-min success window — retry every 60 seconds
            if secs_since_attempt >= 60:
                run_speed_test(state, "Periodic")
        # else: still within 5-min window; wait for the loop to tick past it


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
    bar_no:   '#161b22',                 // future / no data
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
    const onClick = opts.onIncidentClick || null;
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
          // 30d view bumps bar height by 50% so short incidents are visible.
          const heightMult = days > 7 ? 1.5 : 1.0;
          const minH = days > 7 ? 3 : 2;
          const baseH = Math.max(minH, yB - yA);
          const h = baseH * heightMult;
          const yTop = yA - (h - (yB - yA)) / 2;
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

    // Draw degraded clusters first (so outage clusters render on top, just in
    // case any future data shape allows overlap — server-side they're merged).
    clusters.filter(c => c.category !== 'outage').forEach(drawSpan);
    clusters.filter(c => c.category === 'outage').forEach(drawSpan);

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

    // Hover/click handlers
    let activeIncident = null;
    function hitTest(evt) {
      const rect = canvas.getBoundingClientRect();
      const px = evt.clientX - rect.left;
      const py = evt.clientY - rect.top;
      for (const r of incidentRects) {
        if (px >= r.x && px <= r.x + r.w && py >= r.y && py <= r.y + r.h) return r.incident;
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
        canvas.style.cursor = 'default';
        hideTooltip();
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

#header-provider { color: var(--dim); font-size: 12px; }
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
</style>
</head>
<body>

<header>
  <div id="status-dot"></div>
  <span id="status-text" class="online">ONLINE</span>
  <span id="header-provider"></span>
  <span id="header-ping"></span>
  <div class="spacer"></div>
  <span id="last-updated">Connecting…</span>
</header>

<div class="grid">

  <!-- ── Status Stats ──────────────────────────────────────── -->
  <div class="card col-3">
    <div class="card-title">Status</div>
    <div class="stat-row">
      <span class="stat-label">Runtime</span>
      <span class="stat-value" id="stat-runtime">—</span>
    </div>
    <div class="stat-row">
      <span class="stat-label">Provider</span>
      <span class="stat-value" id="stat-provider" style="color:var(--magenta)">—</span>
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
    <div class="card-title">7-Day Uptime</div>
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
        {
          label: 'p50 (ms)',
          data: [],
          borderColor: 'rgba(57,197,207,1)',
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
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: 'index', intersect: false },
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

  // Per-bar base color: latest bar uses perf color, others use provider color
  const barColor = slots.map((s, i) => {
    if (highlightLast && i === last && s.is_latest) {
      const perf = isUl ? s.ul_perf : s.dl_perf;
      return _perfColors[perf] || defColor;
    }
    return pc[s.provider] || defColor;
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
  const pc = d.provider_colors || {};
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
      provider: s.provider, is_latest: true,
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

// ── State update ──────────────────────────────────────────────
function update(d) {
  lastData = d;
  const pc = d.provider_colors || {};
  const curProvColor = (d.current_provider && pc[d.current_provider]) ? pc[d.current_provider] : '#bc8cff';

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
  setEl('header-provider', d.current_provider
    ? `&nbsp;<span style="color:var(--dim)">via</span>&nbsp;<span style="color:${curProvColor}">${d.current_provider}</span>`
    : '');
  setEl('header-ping',     d.last_ping_ms ? `&nbsp;${d.last_ping_ms} ms` : '');
  document.getElementById('last-updated').textContent =
    'Updated ' + new Date().toLocaleTimeString();

  // Status card
  setEl('stat-runtime',  d.runtime_str || '—');
  const statProvEl = document.getElementById('stat-provider');
  if (statProvEl) { statProvEl.textContent = d.current_provider || '—'; statProvEl.style.color = curProvColor; }
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

  // ── 24h Ping chart: hourly stacked bars + % accessible ───────
  if (d.ping_hourly && d.ping_hourly.length > 0) {
    const raw = d.ping_hourly;
    pingChart24h._pingHourlyRaw = raw;

    // Bucket access_chart readings by hour for the overlay line
    const toHourLabel = t => {
      const h = parseInt(t.substring(0, 2), 10);
      return (h % 12 || 12) + (h < 12 ? 'am' : 'pm');
    };
    const accessByHour = {};
    (d.access_chart || []).forEach(pt => {
      const hour = toHourLabel(pt.t);
      if (!accessByHour[hour]) accessByHour[hour] = [];
      accessByHour[hour].push(pt.v);
    });
    const avgArr = arr => arr && arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;

    pingChart24h.data.labels           = raw.map(h => h.hour);
    pingChart24h.data.datasets[0].data = raw.map(h => h.p10);
    pingChart24h.data.datasets[1].data = raw.map(h => h.p50);
    pingChart24h.data.datasets[2].data = raw.map(h => h.p90);
    pingChart24h.data.datasets[3].data = raw.map(h => avgArr(accessByHour[h.hour]));
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

    const tiles = d.site_matrix.map(s => {
      // Best available window for current verdict (prefer fresh data)
      const pct = s.pct_5m ?? s.pct_1h ?? s.pct_24h;
      const p50 = s.p50_5m ?? s.p50_1h ?? s.p50_24h;

      // Verdict + color
      let verdict, colorCls;
      if (!s.up) {
        verdict = 'DOWN'; colorCls = 's-red';
      } else if (pct == null) {
        verdict = '…';    colorCls = '';
      } else if (pct >= 95 && (p50 == null || p50 < 80)) {
        verdict = 'GREAT'; colorCls = 's-green';
      } else if (pct >= 80 && (p50 == null || p50 < 250)) {
        verdict = 'OK';    colorCls = 's-green';
      } else if (pct >= 60 || (p50 != null && p50 < 500)) {
        verdict = 'SLOW';  colorCls = 's-yellow';
      } else {
        verdict = 'POOR';  colorCls = 's-red';
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

      const displayName = s.name || s.host.replace(/^www\./, '');
      return `<div class="site-tile ${colorCls}">
        <div class="site-tile-host">${displayName}</div>
        <div class="site-tile-verdict">
          <span class="site-tile-dot"></span>${verdict}${trendHtml}
        </div>
        <div class="site-tile-sub">${sub}</div>
        <div class="site-tile-tooltip">
          <div class="tt-head">${s.host}</div>
          ${mkTtRow('5m',  s.pct_5m,  s.p10_5m,  s.p50_5m,  s.p90_5m)}
          ${mkTtRow('1h',  s.pct_1h,  s.p10_1h,  s.p50_1h,  s.p90_1h)}
          ${mkTtRow('24h', s.pct_24h, s.p10_24h, s.p50_24h, s.p90_24h)}
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
function paintTimeline() {
  if (!_timelineCache) return;
  UptimeTimeline.render(uptimeTimelineCanvas, {
    days: 7,
    clusters: _timelineCache.clusters,
    analyzedIds: _timelineCache.analyzed_ids,
    titles: _timelineCache.titles || {},
    monitorStartedAt: _timelineCache.monitor_started_at,
    onIncidentClick: onTimelineClick,
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
async function poll() {
  try {
    const resp = await fetch('/api/state');
    if (resp.ok) {
      update(await resp.json());
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
</script>
</body>
</html>
"""


LOG_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Connection Monitor — Log</title>
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
      <th>Time</th><th>Label</th><th>Provider</th>
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

async function poll() {
  try {
    const resp = await fetch('/api/log');
    if (!resp.ok) return;
    const d = await resp.json();

    document.getElementById('last-updated').textContent =
      'Updated ' + new Date().toLocaleTimeString();

    // Speed tests
    if (d.speed && d.speed.length > 0) {
      const rows = d.speed.map(s => `<tr>
        <td style="color:var(--dim)">${s.ts}</td>
        <td><span class="badge badge-blue">${s.label || '—'}</span></td>
        <td style="color:var(--magenta)">${s.provider || '—'}</td>
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
  <div class="card-title" style="display:flex;justify-content:space-between;align-items:baseline">
    <span>30-day Uptime Timeline</span>
    <span id="timeline-stats" style="color:var(--dim);font-size:11px;font-weight:normal"></span>
  </div>
  <div style="height:160px;position:relative">
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
    <div class="card-title" id="detail-title-bar" style="display:flex;justify-content:space-between;align-items:center">
      <span>Diagnosis</span>
      <button id="diag-delete-btn" class="diag-delete-btn" style="display:none" title="Delete this diagnosis (cluster becomes re-runnable)">Delete</button>
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
        <div class="diag-chart-legend">
          <span><span class="lg-swatch" style="background:rgba(63,185,80,0.18)"></span>normal</span>
          <span><span class="lg-swatch" style="background:rgba(210,153,34,0.22)"></span>degraded</span>
          <span><span class="lg-swatch" style="background:rgba(57,197,207,0.18)"></span>site loss</span>
          <span><span class="lg-swatch" style="background:rgba(248,81,73,0.28)"></span>outage</span>
          <span><span class="lg-band" style="background:rgba(57,197,207,0.18);border-top:1.5px solid var(--cyan);border-bottom:1.5px solid var(--cyan)"></span>ping p10–p90 / median (ms · left)</span>
          <span><span class="lg-dot" style="background:var(--magenta)"></span>speed test (Mbps · right)</span>
          <span><span class="lg-vline"></span>event marker</span>
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
  return '<div class="analyzed-strip">'
    + '<span class="analyzed-label">Analyzed:</span> '
    + dim('outages', s.outages)
    + ' &nbsp;·&nbsp; ' + dim('ping samples', s.ping_samples)
    + ' &nbsp;·&nbsp; ' + dim('speed tests', s.speed_tests)
    + ' &nbsp;·&nbsp; ' + dim('sites', s.sites_checked)
    + ' &nbsp;·&nbsp; ' + routerPart
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
  if (history.length === 0) {
    container.innerHTML = '<div style="color:var(--dim);font-size:12px">No diagnoses yet. Run one to start.</div>';
    return;
  }
  let lastDay = null;
  history.forEach(d => {
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
    item.className = 'history-item' + (d.id === selectedId ? ' selected' : '');
    const sev = severityOf(d);
    const t = (eventIso || '').slice(11, 16) || '—';
    const title = (d.result && d.result.title) ? d.result.title : null;
    const titleRow = title
      ? '<div class="title">' + escapeHtml(title) + '</div>'
      : '';
    item.innerHTML =
      titleRow +
      '<div class="row1"><span class="time">' + t + '</span>' +
      '<span class="window">' + (d.window || '?') + '</span></div>' +
      '<div class="severity sev-' + sev + '">' + sev + '</div>';
    item.addEventListener('click', () => selectDiagnosis(d.id));
    container.appendChild(item);
  });
}

function selectDiagnosis(id) {
  selectedId = id;
  const d = history.find(x => x.id === id);
  renderHistory();
  renderDetail(d);
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

  // ── Y-scale (left): ping ms — derived from band p90 + speed pings ──
  const bands = data.ping_bands || [];
  const p50s = bands.map(b => b[2]).filter(v => v != null && isFinite(v));
  const p90s = bands.map(b => b[3]).filter(v => v != null && isFinite(v));
  const speedPings = (data.speed_series || [])
    .map(s => s.ping).filter(v => v != null && isFinite(v));
  const pingPool = p90s.concat(speedPings);
  let yMaxMs = 100;
  if (pingPool.length) {
    const sorted = [...pingPool].sort((a, b) => a - b);
    const p99 = sorted[Math.floor(0.99 * (sorted.length - 1))];
    yMaxMs = Math.max(100, Math.ceil(p99 * 1.15 / 50) * 50);
  }
  const yOfMs = (ms) => MT + H - (Math.min(Math.max(0, ms), yMaxMs) / yMaxMs) * H;

  // ── Y-scale (right): speed Mbps — from speed_series dl values ──
  const dlVals = (data.speed_series || [])
    .map(s => s.dl).filter(v => v != null && isFinite(v));
  let yMaxMbps = 100;
  if (dlVals.length) {
    const m = Math.max(...dlVals);
    // Round up to a nice scale.
    const step = m <= 50 ? 10 : m <= 200 ? 50 : m <= 500 ? 100 : 200;
    yMaxMbps = Math.max(step, Math.ceil(m * 1.1 / step) * step);
  }
  const yOfMbps = (mbps) => MT + H - (Math.min(Math.max(0, mbps), yMaxMbps) / yMaxMbps) * H;

  // ── 1. Background bands ────────────────────────────────────────
  ctx.fillStyle = BG_NORMAL;
  ctx.fillRect(ML, MT, W, H);

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
    const bg = (d.kind === 'site_loss') ? BG_SITE_LOSS : BG_DEGRADED;
    drawSpan(d.start, d.end, bg);
  });
  (data.outages  || []).forEach(o => drawSpan(o.start, o.end, BG_OUTAGE));

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
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  const spanMin = span / 60000;
  let stepMin;
  if (spanMin <= 15)       stepMin = 2;
  else if (spanMin <= 60)  stepMin = 10;
  else if (spanMin <= 180) stepMin = 30;
  else if (spanMin <= 720) stepMin = 60;
  else                     stepMin = 120;
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

  // ── 4. Ping bands: filled p10–p90 area + p50 line ───────────────
  // Walk bands; break the path into segments wherever a band is null
  // (so outage gaps stay visible). Each contiguous run becomes one fill
  // (forward through p90, back through p10) and one p50 stroke.
  const bandFill = 'rgba(57,197,207,0.18)';   // cyan-ish translucent
  function flushSegment(seg) {
    if (seg.length < 2) return;
    // Filled band p10 → p90.
    ctx.beginPath();
    ctx.moveTo(seg[0].x, yOfMs(seg[0].p90));
    for (let i = 1; i < seg.length; i++) ctx.lineTo(seg[i].x, yOfMs(seg[i].p90));
    for (let i = seg.length - 1; i >= 0; i--) ctx.lineTo(seg[i].x, yOfMs(seg[i].p10));
    ctx.closePath();
    ctx.fillStyle = bandFill;
    ctx.fill();
    // p50 line.
    ctx.beginPath();
    ctx.moveTo(seg[0].x, yOfMs(seg[0].p50));
    for (let i = 1; i < seg.length; i++) ctx.lineTo(seg[i].x, yOfMs(seg[i].p50));
    ctx.strokeStyle = COLORS.cyan;
    ctx.lineWidth = 1.4;
    ctx.stroke();
  }
  let seg = [];
  bands.forEach(([ts, p10, p50, p90, n]) => {
    if (p50 == null) { flushSegment(seg); seg = []; return; }
    seg.push({ x: xOf(new Date(ts).getTime()), p10, p50, p90, n, ts });
  });
  flushSegment(seg);

  // ── 5. Speed test markers (positioned on right Mbps axis) ──────
  const speedMarks = [];
  (data.speed_series || []).forEach(s => {
    const x = xOf(new Date(s.ts).getTime());
    if (x < ML || x > ML + W) return;
    if (s.dl == null) return;
    const y = yOfMbps(s.dl);
    ctx.fillStyle = COLORS.magenta;
    ctx.strokeStyle = COLORS.text;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(x, y, 3.5, 0, Math.PI * 2);
    ctx.fill();
    ctx.stroke();
    speedMarks.push({ x, y, sample: s });
  });

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
    // Speed marker hit first.
    let hit = null;
    for (const m of speedMarks) {
      const dx = px - m.x, dy = py - m.y;
      if (dx*dx + dy*dy <= 36) { hit = m; break; }
    }
    if (hit) {
      const s = hit.sample;
      const tStr = s.ts.replace('T', ' ').slice(11, 19);
      tt.innerHTML = '<strong style="color:' + COLORS.magenta + '">Speed test</strong>'
        + '<br>' + tStr
        + '<br>↓ ' + s.dl + ' Mbps · ↑ ' + s.ul + ' Mbps'
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
  status.textContent = 'Diagnosing outage…';
  try {
    const resp = await fetch('/api/diagnose', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        window: 'outage',
        start: inc.start,
        end:   inc.end || new Date().toISOString(),
        outage_id: inc.id,
      }),
    });
    const data = await resp.json();
    if (data.id) selectedId = data.id;
    await loadHistory();
    await refreshTimeline();
    status.textContent = '';
  } catch (e) {
    status.textContent = 'Request failed';
  } finally {
    btns.forEach(b => b.disabled = false);
  }
}

let _timelineData = null;
function paintTimeline() {
  if (!_timelineData) return;
  UptimeTimeline.render(document.getElementById('timelineCanvas'), {
    days: 30,
    clusters: _timelineData.clusters,
    analyzedIds: _timelineData.analyzed_ids,
    titles: _timelineData.titles || {},
    monitorStartedAt: _timelineData.monitor_started_at,
    onIncidentClick: onTimelineClick,
  });
  const total = (_timelineData.clusters || []).length;
  const seen = (_timelineData.analyzed_ids || []).length;
  const stats = document.getElementById('timeline-stats');
  if (stats) stats.textContent = total + ' incidents · ' + seen + ' analyzed';
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
  status.textContent = 'Diagnosing ' + window + '…';
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
    status.textContent = '';
  } catch (e) {
    status.textContent = 'Request failed';
  } finally {
    btns.forEach(b => b.disabled = false);
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

_state: Optional[MonitorState] = None


@app.route("/")
def index():
    return DASHBOARD_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/api/state")
def api_state():
    if _state is None:
        return jsonify({"error": "not ready"}), 503
    return jsonify(_state.to_dict())


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
                   "label": s.label, "provider": s.provider} for s in reversed(speed)],
        "outages": [{"start": o.start.strftime("%H:%M:%S"),
                     "end": o.end.strftime("%H:%M:%S") if o.end else None,
                     "duration": o.duration_str, "ongoing": o.ongoing}
                    for o in reversed(outages)],
        "events": [{"ts": ts, "level": lvl, "msg": msg} for ts, lvl, msg in events],
    })


@app.route("/log")
def log_page():
    return LOG_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


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
    return jsonify({"items": _diagnoses_within_30d(_state)})


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
        "titles": titles_by_cluster,
    })


@app.route("/diagnose")
def diagnose_page():
    return DIAGNOSE_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.route("/static/timeline.js")
def static_timeline_js():
    return TIMELINE_JS, 200, {"Content-Type": "application/javascript; charset=utf-8"}


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────
def main() -> None:
    global _state
    state = MonitorState()
    _state = state

    load_state(state)

    conn_t    = threading.Thread(target=connectivity_thread, args=(state,), daemon=True, name="conn")
    speed_t   = threading.Thread(target=speed_test_thread,   args=(state,), daemon=True, name="speed")
    persist_t = threading.Thread(target=persistence_thread,  args=(state,), daemon=True, name="persist")
    site_t    = threading.Thread(target=site_check_thread,   args=(state,), daemon=True, name="sites")
    router_t  = threading.Thread(target=router_log_thread,   args=(state,), daemon=True, name="router")
    conn_t.start()
    speed_t.start()
    persist_t.start()
    site_t.start()
    router_t.start()

    state.log("Monitor started", "info")
    if SPEEDTEST_AVAILABLE:
        state.log("speedtest-cli detected — using for measurements", "info")

    print(f"\n  Connection Monitor")
    print(f"  Dashboard → http://localhost:{PORT}")
    print(f"  Stop      → Ctrl+C\n", flush=True)

    try:
        app.run(
            host="0.0.0.0",
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
        print("\n  Monitor stopped.\n")


if __name__ == "__main__":
    main()
