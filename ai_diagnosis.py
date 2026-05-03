"""
ai_diagnosis.py — on-demand AI diagnosis of connection-monitor data.

Builds a compact snapshot from MonitorState for a chosen time window, then asks
Claude to interpret it qualitatively ("everything is up, but Mom's video calls
keep freezing — what's actually going on?").

The snapshot deliberately does NOT include the raw 43k-sample ping history.
Instead it ships summary stats + a windowed slice of router events, which is
where the diagnostic signal actually lives.
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import router_log


MODEL = "claude-sonnet-4-6"
WINDOWS = {
    "ongoing": timedelta(minutes=5),
    "1h":      timedelta(hours=1),
    "24h":     timedelta(hours=24),
    # "outage": handled specially in build_snapshot — start/end come from caller.
}
OUTAGE_LEAD = timedelta(minutes=30)
OUTAGE_TAIL = timedelta(minutes=30)

SYSTEM_PROMPT = """\
You are a senior network-diagnosis assistant analyzing data from a home internet \
connection monitor running behind a residential router whose firewall log may \
also be available.

The monitor records:
- DNS-port probes to 8.8.8.8 / 1.1.1.1 / 208.67.222.222 every 2 seconds (failure = "outage")
- Periodic speed tests (download/upload Mbps + ping)
- TCP:443 reachability checks to popular sites (Netflix, Gmail, etc.)
- Packet/firewall logs scraped from the gateway itself (when available)

The user's job is interpreting this data when a household member complains the \
connection feels bad even though the dashboard shows "up." Translate raw stats \
into a qualitative story: what likely happened, why the human experience would \
be poor, where to look next.

Strong rules:
1. If `router_events.dns_probe_drops` is non-empty, the gateway is rejecting the \
monitor's own liveness probes. The "outages" you see are at least partly an \
artifact of gateway-side packet rejection, NOT necessarily an upstream ISP failure. \
Prefer gateway-side root causes (firmware, MTU/MSS, uRPF, dual-stack churn) over \
upstream-ISP-flap hypotheses in this case.
2. Distinguish real degradation (collapsed throughput, sustained high latency) \
from monitoring artifacts (probes dropped at gateway).
3. If the snapshot includes an `incident` block, focus the diagnosis on that \
specific event — what caused it, how it manifested, what to check — and use the \
broader window only as context for what was normal/abnormal around it.
4. Keep recommendations concrete and ranked. Do not speculate beyond the data.
5. Output STRICT JSON matching the schema in the user message — no prose outside it.
"""


def _ensure_anthropic():
    try:
        import anthropic  # noqa: F401
        return
    except ImportError:
        pass
    print("Installing 'anthropic'…", flush=True)
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "-q", "anthropic"],
        stdout=subprocess.DEVNULL,
    )


def _percentiles(values: List[float]) -> Dict[str, Optional[float]]:
    if not values:
        return {"p10": None, "p50": None, "p90": None, "max": None, "min": None}
    s = sorted(values)
    def p(q: float) -> float:
        if len(s) == 1:
            return s[0]
        idx = q / 100 * (len(s) - 1)
        lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
        return s[lo] + (s[hi] - s[lo]) * (idx - lo)
    return {
        "p10": round(p(10), 2),
        "p50": round(p(50), 2),
        "p90": round(p(90), 2),
        "max": round(s[-1], 2),
        "min": round(s[0], 2),
    }


def build_snapshot(state, window: str,
                   incident_start: Optional[datetime] = None,
                   incident_end: Optional[datetime] = None,
                   incident_id: Optional[str] = None) -> Dict[str, Any]:
    """Build a JSON-safe snapshot for the AI. `state` is a MonitorState; we read
    under its lock and never hold it during the API call.

    For window == "outage", incident_start and incident_end define the event;
    the snapshot covers [incident_start - OUTAGE_LEAD, incident_end + OUTAGE_TAIL].
    """
    now = datetime.now()
    incident: Optional[Dict[str, Any]] = None
    if window == "outage":
        if incident_start is None or incident_end is None:
            raise ValueError("outage window requires incident_start and incident_end")
        cutoff = incident_start - OUTAGE_LEAD
        end_at = min(now, incident_end + OUTAGE_TAIL)
        # Window seconds is the snapshot span, not the outage span.
        window_secs = (end_at - cutoff).total_seconds()
        incident = {
            "id": incident_id,
            "start": incident_start.isoformat(timespec="seconds"),
            "end": incident_end.isoformat(timespec="seconds"),
            "duration_s": int((incident_end - incident_start).total_seconds()),
            "lead_window_min": int(OUTAGE_LEAD.total_seconds() / 60),
            "tail_window_min": int(OUTAGE_TAIL.total_seconds() / 60),
        }
    else:
        if window not in WINDOWS:
            window = "1h"
        delta = WINDOWS[window]
        cutoff = now - delta
        end_at = now
        window_secs = delta.total_seconds()

    with state.lock:
        ping_ts = list(state.ping_history_ts)
        speed_history = list(state.speed_history)
        outages = list(state.outages)
        cur_outage = state.current_outage
        site_targets = list(state.site_targets)
        site_names = dict(state.site_names)
        site_ping_hist = {h: list(state.site_ping_history.get(h, [])) for h in site_targets}
        provider = state.current_provider
        provider_uptime = dict(state.provider_uptime_secs)
        router_events = list(getattr(state, "router_events", []))
        router_poll_error = getattr(state, "router_poll_error", None)
        last_router_poll = getattr(state, "last_router_poll", None)

    # Pings in window
    def _in_window(ts_str: str) -> bool:
        try:
            t = datetime.fromisoformat(ts_str)
        except ValueError:
            return False
        return cutoff <= t <= end_at

    pings_in_window = [v for ts, v in ping_ts if _in_window(ts)]
    ping_stats = _percentiles(pings_in_window)
    if len(pings_in_window) > 1:
        ping_stats["jitter_stdev"] = round(statistics.pstdev(pings_in_window), 2)
    else:
        ping_stats["jitter_stdev"] = None
    ping_stats["sample_count"] = len(pings_in_window)

    # Outages in window (closed + ongoing)
    all_outages = list(outages) + ([cur_outage] if cur_outage else [])
    outages_in_window = []
    total_downtime_s = 0.0
    for o in all_outages:
        eff_end = o.end if o.end else end_at
        if eff_end < cutoff or o.start > end_at:
            continue
        clipped_start = max(o.start, cutoff)
        clipped_end = min(eff_end, end_at)
        if clipped_end > clipped_start:
            total_downtime_s += (clipped_end - clipped_start).total_seconds()
        outages_in_window.append({
            "start": o.start.isoformat(timespec="seconds"),
            "end": o.end.isoformat(timespec="seconds") if o.end else None,
            "duration_s": int((eff_end - o.start).total_seconds()),
            "ongoing": o.end is None,
        })

    uptime_pct = round(max(0.0, (window_secs - total_downtime_s) / window_secs * 100), 2)

    # Speed tests in window
    speeds = [s for s in speed_history if cutoff <= s.timestamp <= end_at]
    speed_summary = {
        "count": len(speeds),
        "download_mbps": _percentiles([s.download_mbps for s in speeds]),
        "upload_mbps":   _percentiles([s.upload_mbps   for s in speeds]),
        "ping_ms":       _percentiles([s.ping_ms       for s in speeds if s.ping_ms]),
        "samples": [
            {
                "ts": s.timestamp.isoformat(timespec="seconds"),
                "dl": round(s.download_mbps, 1),
                "ul": round(s.upload_mbps, 1),
                "ping": round(s.ping_ms, 1) if s.ping_ms else None,
                "label": s.label,
                "provider": s.provider,
            }
            for s in speeds[-20:]
        ],
    }

    # Per-site reachability in window
    site_summary = []
    for host in site_targets:
        hist = site_ping_hist.get(host, [])
        in_win = [(t, ms) for t, ms in hist if _in_window(t)]
        if not in_win:
            continue
        successes = [ms for _, ms in in_win if ms is not None]
        site_summary.append({
            "host": host,
            "name": site_names.get(host, host),
            "samples": len(in_win),
            "reachable_pct": round(len(successes) / len(in_win) * 100, 1),
            "ping_ms": _percentiles(successes),
        })

    # Router events in window
    cutoff_iso = cutoff.isoformat()
    end_at_iso = end_at.isoformat()
    router_in_window = [
        ev for ev in router_events
        if cutoff_iso <= ev.timestamp <= end_at_iso
    ]
    router_summary = router_log.summarize(router_in_window)
    router_summary["available"] = bool(router_events) or router_poll_error is None
    router_summary["poll_error"] = router_poll_error
    router_summary["last_poll"] = last_router_poll.isoformat() if last_router_poll else None

    snapshot = {
        "schema_version": 1,
        "generated_at": now.isoformat(timespec="seconds"),
        "window": window,
        "window_seconds": int(window_secs),
        "window_start": cutoff.isoformat(timespec="seconds"),
        "window_end": end_at.isoformat(timespec="seconds"),
        "current_provider": provider,
        "provider_uptime_secs_24h": provider_uptime,
        "ping": ping_stats,
        "outages": {
            "count": len(outages_in_window),
            "total_downtime_s": int(total_downtime_s),
            "uptime_pct": uptime_pct,
            "items": outages_in_window[-20:],
        },
        "speed": speed_summary,
        "sites": site_summary,
        "router_events": router_summary,
    }
    if incident is not None:
        snapshot["incident"] = incident
    return snapshot


USER_TEMPLATE = """\
Diagnose the user's home internet connection for the window: **{window}**.

Snapshot (JSON):
```json
{snapshot}
```

Respond with a single JSON object, no prose, matching this schema exactly:

{{
  "summary": "2-4 sentence plain-English description of what happened in this window",
  "severity": "none" | "minor" | "moderate" | "severe",
  "likely_causes": [
    {{"cause": "short label", "detail": "1-2 sentence explanation", "confidence": "low" | "medium" | "high"}}
  ],
  "household_impact": "1-2 sentences on what a person on a video call / game / stream would have experienced",
  "recommendations": ["concrete action 1", "concrete action 2", ...]
}}

Rank likely_causes from most to least probable. Limit to 4 causes and 5 \
recommendations. If router_events.dns_probe_drops is non-empty, the FIRST cause \
must be gateway-side.\
"""


def diagnose(snapshot: Dict[str, Any], api_key: Optional[str] = None) -> Dict[str, Any]:
    """Call Claude with the snapshot. Returns a result dict shaped for the dashboard."""
    api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "ok": False,
            "error": "ANTHROPIC_API_KEY not set. Run with `export ANTHROPIC_API_KEY=…` and restart.",
            "evaluated_at": datetime.now().isoformat(timespec="seconds"),
            "window": snapshot.get("window"),
        }

    _ensure_anthropic()
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    user_msg = USER_TEMPLATE.format(
        window=snapshot.get("window"),
        snapshot=json.dumps(snapshot, indent=2),
    )

    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=1500,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_msg}],
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Anthropic API error: {exc}",
            "evaluated_at": datetime.now().isoformat(timespec="seconds"),
            "window": snapshot.get("window"),
        }

    raw_text = "".join(b.text for b in msg.content if getattr(b, "type", None) == "text")
    parsed: Optional[dict] = None
    try:
        # The model is asked for pure JSON; tolerate ```json fences if it slips up.
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```", 2)[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
            cleaned = cleaned.rsplit("```", 1)[0].strip()
        parsed = json.loads(cleaned)
    except Exception:
        parsed = None

    usage = getattr(msg, "usage", None)
    return {
        "ok": True,
        "evaluated_at": datetime.now().isoformat(timespec="seconds"),
        "window": snapshot.get("window"),
        "model": MODEL,
        "result": parsed,
        "raw_text": raw_text if parsed is None else None,
        "usage": {
            "input_tokens": getattr(usage, "input_tokens", None),
            "output_tokens": getattr(usage, "output_tokens", None),
            "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", None),
            "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", None),
        } if usage else None,
        "snapshot_summary": {
            "outages": snapshot["outages"]["count"],
            "downtime_s": snapshot["outages"]["total_downtime_s"],
            "router_events": snapshot["router_events"].get("total", 0),
            "dns_probe_drops": snapshot["router_events"].get("dns_probe_drop_count", 0),
        },
    }
