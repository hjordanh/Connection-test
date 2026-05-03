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
# When chaining post-outage degraded periods to find the "true" recovery point.
RECOVERY_GAP = timedelta(minutes=30)   # max gap between chained events
RECOVERY_TAIL = timedelta(minutes=15)  # clean-time shown after recovery
RECOVERY_MAX  = timedelta(hours=6)     # cap on how far we'll extend a window


def _detect_speed_recovery(incident_end: datetime, speed_history,
                           cap: datetime) -> Optional[datetime]:
    """Find when download speed actually returned to baseline after an outage,
    using the speed test history directly (since degraded-period records may
    not exist for older incidents that predate the slow-detection thresholds
    being seeded).

    Baseline = median of non-Outage, non-zero speed samples in the 24h before
    `incident_end - 5min`. Recovery = first sample where this and the next two
    samples (3 in a row) all hit >= 50% of baseline. If no sustained recovery
    inside `cap`, returns the last available sample timestamp so the window
    extends to show the failure to recover.

    Returns None when there's not enough baseline data to compute a threshold.
    """
    pre = [s.download_mbps for s in speed_history
           if s.timestamp < incident_end - timedelta(minutes=5)
           and s.timestamp >= incident_end - timedelta(hours=24)
           and (s.label or "") != "Outage"
           and s.download_mbps > 5]
    if len(pre) < 3:
        return None
    pre_sorted = sorted(pre)
    baseline = pre_sorted[len(pre_sorted) // 2]
    threshold = baseline * 0.5

    post = sorted(
        [s for s in speed_history
         if s.timestamp >= incident_end and s.timestamp <= cap
         and (s.label or "") != "Outage"],
        key=lambda s: s.timestamp,
    )
    if not post:
        return None

    K = 3  # require 3 consecutive samples above threshold to call it sustained
    for i in range(len(post) - K + 1):
        if all(post[j].download_mbps >= threshold for j in range(i, i + K)):
            return post[i].timestamp

    # Never sustained recovery within cap — extend to the latest evidence so
    # the user can see the prolonged degradation, not a misleading "resolved."
    return min(post[-1].timestamp, cap)


def compute_recovery_end(incident_end: datetime, outages, degraded,
                         speed_history=None) -> datetime:
    """Estimate when things truly returned to normal after an outage.

    Combines two signals and returns whichever is LATER:
    1. Speed-based: walk forward through the actual speed test history and
       find a sustained run of samples back at >= 50% of pre-incident baseline.
    2. Event-chain: walk forward through outage + degraded period records,
       chaining any whose start is within RECOVERY_GAP of the running tail.

    The speed-based signal handles incidents that predate degraded-period
    detection (or where it didn't trigger). The event-chain signal handles
    cases where speed tests are sparse but degraded windows are recorded.
    """
    cap = incident_end + RECOVERY_MAX
    candidates = [incident_end]

    if speed_history:
        sr = _detect_speed_recovery(incident_end, speed_history, cap)
        if sr is not None:
            candidates.append(sr)

    events = []
    for o in outages:
        events.append((o.start, o.end))
    for d in degraded:
        events.append((d.start, d.end))
    events.sort(key=lambda e: e[0])

    true_end = incident_end
    for start, end in events:
        if start > true_end + RECOVERY_GAP:
            break
        if end is None:
            true_end = cap
            break
        if end > true_end:
            true_end = min(end, cap)
        if true_end >= cap:
            break
    candidates.append(true_end)

    return max(candidates)

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
broader window only as context for what was normal/abnormal around it. For an \
outage incident, `incident.start` and `incident.end` mark the connectivity \
drop; `incident.recovery_end` marks when speeds and latency actually returned \
to baseline (often later than connectivity restoration, when degraded periods \
chained after the outage). When `recovery_lag_s` is non-trivial (> 60s), \
treat the gap between `end` and `recovery_end` as the "aftermath" and explain \
why full recovery lagged restored connectivity.
4. Keep recommendations concrete and ranked. Do not speculate beyond the data.
5. Output STRICT JSON matching the schema in the user message — no prose outside it.
6. **Never recommend the user "go check" data we already collected.** The \
snapshot you receive IS the data they would otherwise look up:
   - `router_events` is the gateway's packet/firewall log — do NOT recommend \
"look at the router event log at 192.168.1.1" or "check the gateway log for \
restarts." If `router_events.total` is 0 AND `router_events.available` is true, \
the log was scraped successfully and contained nothing in this window — say \
that directly instead of recommending a re-check. Only recommend manual log \
inspection if `router_events.available` is false.
   - `ping`, `outages`, `speed`, `sites` are similarly already-collected \
signals — interpret them, do not tell the user to re-collect them.
Recommendations should be NEW actions the user could take outside this \
monitor: physical checks (cabling, modem reboot, line tester, ISP call), \
environmental observations (peak hours, weather, household usage), or \
configuration changes (router firmware update, swap DNS, contact ISP about \
line stats they can pull from their side).
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


CHART_PING_BINS = 180


def build_chart_data(state, window: str,
                     incident_start: Optional[datetime] = None,
                     incident_end: Optional[datetime] = None) -> Dict[str, Any]:
    """Build a JSON-safe time-series payload for the diagnosis chart.

    Same windowing rules as build_snapshot. Combines the global 2s connectivity
    pings with every per-site ping sample inside the window, then bins them
    into ~CHART_PING_BINS buckets and emits p10/p50/p90 per bucket. This is
    persisted on the diagnosis record so the chart can be re-rendered for
    historical diagnoses long after the live ping buffer has rolled over.
    """
    now = datetime.now()
    with state.lock:
        ping_ts = list(state.ping_history_ts)
        speed_history = list(state.speed_history)
        outages = list(state.outages)
        cur_outage = state.current_outage
        degraded_periods = list(getattr(state, "degraded_periods", []))
        site_targets = list(state.site_targets)
        site_ping_hist = {h: list(state.site_ping_history.get(h, [])) for h in site_targets}

    # Resolve the analysis window. For an outage incident, walk forward from
    # incident_end through chained degraded periods to find when things truly
    # returned to normal, then extend the window to cover that recovery + a
    # small clean-time tail.
    recovery_end: Optional[datetime] = None
    if window == "outage":
        if incident_start is None or incident_end is None:
            raise ValueError("outage window requires incident_start and incident_end")
        cutoff = incident_start - OUTAGE_LEAD
        chain_pool = list(outages) + ([cur_outage] if cur_outage else [])
        recovery_end = compute_recovery_end(
            incident_end, chain_pool, degraded_periods,
            speed_history=speed_history,
        )
        end_at = min(now, max(incident_end + OUTAGE_TAIL, recovery_end + RECOVERY_TAIL))
    else:
        delta = WINDOWS.get(window, WINDOWS["1h"])
        cutoff = now - delta
        end_at = now

    # Collect every (datetime, ms) sample in the window from BOTH the global
    # connectivity probes and every per-site ping check.
    samples: List = []  # list of (datetime, ms)
    def _ingest(ts_str, v):
        if v is None:
            return
        try:
            t = datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return
        if cutoff <= t <= end_at:
            samples.append((t, v))

    for ts_str, v in ping_ts:
        _ingest(ts_str, v)
    for hist in site_ping_hist.values():
        for ts_str, v in hist:
            _ingest(ts_str, v)

    samples.sort(key=lambda x: x[0])

    # Bin into time buckets and compute p10/p50/p90 per bin. Empty bins emit
    # nulls so outage gaps stay visible on the chart.
    window_secs = max(1.0, (end_at - cutoff).total_seconds())
    bin_secs = max(2.0, window_secs / CHART_PING_BINS)

    def _pct(sorted_vals, q):
        if len(sorted_vals) == 1:
            return sorted_vals[0]
        idx = q / 100 * (len(sorted_vals) - 1)
        lo, hi = int(idx), min(int(idx) + 1, len(sorted_vals) - 1)
        return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo)

    ping_bands: List[List[Any]] = []
    i = 0
    n_bins = int(window_secs / bin_secs) + 1
    for b in range(n_bins):
        bin_start = cutoff + timedelta(seconds=b * bin_secs)
        bin_end   = bin_start + timedelta(seconds=bin_secs)
        if bin_start >= end_at:
            break
        bin_vals: List[float] = []
        while i < len(samples) and samples[i][0] < bin_end:
            if samples[i][0] >= bin_start:
                bin_vals.append(samples[i][1])
            i += 1
        ts_iso = bin_start.isoformat(timespec="seconds")
        if bin_vals:
            s = sorted(bin_vals)
            ping_bands.append([
                ts_iso,
                round(_pct(s, 10), 1),
                round(_pct(s, 50), 1),
                round(_pct(s, 90), 1),
                len(bin_vals),
            ])
        else:
            ping_bands.append([ts_iso, None, None, None, 0])

    # Speed samples in window.
    speed_series = [
        {
            "ts": s.timestamp.isoformat(timespec="seconds"),
            "dl": round(s.download_mbps, 1),
            "ul": round(s.upload_mbps, 1),
            "ping": round(s.ping_ms, 1) if s.ping_ms else None,
            "label": s.label,
        }
        for s in speed_history
        if cutoff <= s.timestamp <= end_at
    ]

    # Outage spans clipped to window.
    all_outages = list(outages) + ([cur_outage] if cur_outage else [])
    outage_spans = []
    for o in all_outages:
        eff_end = o.end if o.end else end_at
        if eff_end < cutoff or o.start > end_at:
            continue
        outage_spans.append({
            "start": o.start.isoformat(timespec="seconds"),
            "end": o.end.isoformat(timespec="seconds") if o.end else None,
        })

    # Degraded spans (slow / high_ping) clipped to window.
    degraded_spans = []
    for d in degraded_periods:
        eff_end = d.end if d.end else end_at
        if eff_end < cutoff or d.start > end_at:
            continue
        degraded_spans.append({
            "start": d.start.isoformat(timespec="seconds"),
            "end": d.end.isoformat(timespec="seconds") if d.end else None,
            "kind": d.kind,
        })

    incident = None
    if window == "outage" and incident_start and incident_end:
        incident = {
            "start": incident_start.isoformat(timespec="seconds"),
            "end":   incident_end.isoformat(timespec="seconds"),
            "recovery_end": (recovery_end.isoformat(timespec="seconds")
                             if recovery_end else None),
        }

    return {
        "window_start": cutoff.isoformat(timespec="seconds"),
        "window_end":   end_at.isoformat(timespec="seconds"),
        "incident":     incident,
        "ping_bands":   ping_bands,    # [[ts, p10, p50, p90, n], ...]
        "speed_series": speed_series,
        "outages":      outage_spans,
        "degraded":     degraded_spans,
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
    with state.lock:
        ping_ts = list(state.ping_history_ts)
        speed_history = list(state.speed_history)
        outages = list(state.outages)
        cur_outage = state.current_outage
        degraded_periods = list(getattr(state, "degraded_periods", []))
        site_targets = list(state.site_targets)
        site_names = dict(state.site_names)
        site_ping_hist = {h: list(state.site_ping_history.get(h, [])) for h in site_targets}
        provider = state.current_provider
        provider_uptime = dict(state.provider_uptime_secs)
        router_events = list(getattr(state, "router_events", []))
        router_poll_error = getattr(state, "router_poll_error", None)
        last_router_poll = getattr(state, "last_router_poll", None)

    incident: Optional[Dict[str, Any]] = None
    if window == "outage":
        if incident_start is None or incident_end is None:
            raise ValueError("outage window requires incident_start and incident_end")
        cutoff = incident_start - OUTAGE_LEAD
        chain_pool = list(outages) + ([cur_outage] if cur_outage else [])
        recovery_end = compute_recovery_end(
            incident_end, chain_pool, degraded_periods,
            speed_history=speed_history,
        )
        end_at = min(now, max(incident_end + OUTAGE_TAIL, recovery_end + RECOVERY_TAIL))
        window_secs = (end_at - cutoff).total_seconds()
        incident = {
            "id": incident_id,
            "start": incident_start.isoformat(timespec="seconds"),
            "end": incident_end.isoformat(timespec="seconds"),
            "recovery_end": recovery_end.isoformat(timespec="seconds"),
            "duration_s": int((incident_end - incident_start).total_seconds()),
            "recovery_lag_s": int((recovery_end - incident_end).total_seconds()),
            "lead_window_min": int(OUTAGE_LEAD.total_seconds() / 60),
            "tail_window_min": int((end_at - incident_end).total_seconds() / 60),
        }
    else:
        if window not in WINDOWS:
            window = "1h"
        delta = WINDOWS[window]
        cutoff = now - delta
        end_at = now
        window_secs = delta.total_seconds()

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
  "title": "6-10 word headline a non-technical household member would understand, e.g. 'Internet briefly dropped during dinner' — avoid jargon (no 'gateway', 'flap', 'MTU', 'DNS', acronyms)",
  "summary": "2-3 sentences in plain household language describing what happened and when. Translate technical signals into everyday terms (say 'connection dropped' not 'DNS probes failed', 'speeds dipped' not 'throughput collapsed').",
  "severity": "none" | "minor" | "moderate" | "severe",
  "likely_causes": [
    {{"cause": "short label", "detail": "1-2 sentence explanation", "confidence": "low" | "medium" | "high", "signals": ["dotted.path.to.snapshot.field", ...]}}
  ],
  "household_impact": "1-2 sentences on what a person on a video call / game / stream would have experienced",
  "recommendations": ["concrete action 1", "concrete action 2"]
}}

The title and summary are read by non-technical household members. Use plain \
language, not networking jargon. The title is critical — it shows up as the \
headline in the diagnosis history and in tooltips on the timeline.

Rank likely_causes from most to least probable. **Hard limit: 2 likely_causes \
and 2 recommendations. Only include a 3rd of either if it adds genuinely \
distinct value — otherwise stop at 2.** If router_events.dns_probe_drops is \
non-empty, the FIRST cause must be gateway-side (but phrase it in plain terms, \
e.g. "router rejecting the monitor's check-ins" rather than "uRPF dropping \
DNS probes").

**For each cause, populate `signals` with 1-3 dotted-path references to the \
specific snapshot fields that grounded your conclusion** (e.g. \
"router_events.dns_probe_drop_count", "ping.p90", "ping.jitter_stdev", \
"outages.count", "outages.total_downtime_s", "speed.download_mbps.p10", \
"sites[*].reachable_pct"). These are the verifiable evidence trail. If you \
cannot point to a specific snapshot field, drop the cause — every cause must \
be grounded in named evidence. Do not invent field names; only cite paths \
that actually exist in the snapshot above.\
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
            "ping_samples": snapshot.get("ping", {}).get("sample_count", 0),
            "speed_tests": snapshot.get("speed", {}).get("count", 0),
            "sites_checked": len(snapshot.get("sites", []) or []),
            "router_available": bool(snapshot["router_events"].get("available")),
            "router_last_poll": snapshot["router_events"].get("last_poll"),
            "router_poll_error": snapshot["router_events"].get("poll_error"),
            "router_events": snapshot["router_events"].get("total", 0),
            "dns_probe_drops": snapshot["router_events"].get("dns_probe_drop_count", 0),
        },
    }
