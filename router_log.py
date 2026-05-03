"""
router_log.py — fetch and parse HTTP-exposed router log pages.

Many residential gateways expose their firewall / event logs on an unauthenticated
LAN-side HTTP path. This module is router-agnostic — paths are passed in by the
caller (typically loaded from `connection_monitor.env`).

Two row formats are supported:

1. HTML table rows with six <td> cells in order:
   index, ISO timestamp, src IP, dst IP, protocol, reason. Example:

       <tr class="a">
         <td class="heading" scope="row">1</td>
         <td>2026-05-02T21:04:01.557082</td>
         <td>192.168.1.77</td>
         <td>192.168.4.1</td>
         <td>TCP</td>
         <td>Policy (filtersets, etc.)</td>
       </tr>

2. Rendered-text dumps with the same column order, prefixed by a 5-digit row index.
"""

from __future__ import annotations

import re
import urllib.request
from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class RouterEvent:
    timestamp: str   # ISO string as reported by the gateway
    src: str
    dst: str
    proto: str
    reason: str
    source: str = "packet"   # "packet" or "syslog"

    def key(self) -> tuple:
        return (self.timestamp, self.src, self.dst, self.proto, self.reason, self.source)

    def to_dict(self) -> dict:
        return {
            "ts": self.timestamp,
            "src": self.src,
            "dst": self.dst,
            "proto": self.proto,
            "reason": self.reason,
            "source": self.source,
        }


# Matches a row in the live HTML table (logs.ha). Six <td> cells: idx, ts, src, dst, proto, reason.
_ROW_RE = re.compile(
    r"<tr[^>]*>\s*"
    r"<td[^>]*>\s*\d+\s*</td>\s*"
    r"<td[^>]*>\s*(?P<ts>[^<]+?)\s*</td>\s*"
    r"<td[^>]*>\s*(?P<src>[^<]+?)\s*</td>\s*"
    r"<td[^>]*>\s*(?P<dst>[^<]+?)\s*</td>\s*"
    r"<td[^>]*>\s*(?P<proto>[^<]+?)\s*</td>\s*"
    r"<td[^>]*>\s*(?P<reason>[^<]+?)\s*</td>\s*"
    r"</tr>",
    re.IGNORECASE | re.DOTALL,
)

# Matches the rendered-text format used in the user-supplied dump:
#   00001 2026-05-02T20:46:00.517918 192.168.1.77   192.168.4.43   TCP   Policy (filtersets, etc.)
# followed (without separator) by the next 5-digit index.
_TEXT_RE = re.compile(
    r"\d{5}\s+"
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<src>\S+)\s+"
    r"(?P<dst>\S+)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<reason>.+?)(?=\d{5}\s+\d{4}-\d{2}-\d{2}T|\Z)",
)


def parse(html_or_text: str, source: str = "packet") -> List[RouterEvent]:
    """Parse either the live HTML table or a plain-text dump."""
    events: List[RouterEvent] = []

    matches = list(_ROW_RE.finditer(html_or_text))
    if matches:
        for m in matches:
            ts = m.group("ts").strip()
            if ts in ("n/a", ""):
                continue
            events.append(RouterEvent(
                timestamp=ts,
                src=m.group("src").strip(),
                dst=m.group("dst").strip(),
                proto=m.group("proto").strip(),
                reason=m.group("reason").strip(),
                source=source,
            ))
        return events

    for m in _TEXT_RE.finditer(html_or_text):
        src = m.group("src").strip()
        if src == "n/a":
            continue
        events.append(RouterEvent(
            timestamp=m.group("ts").strip(),
            src=src,
            dst=m.group("dst").strip(),
            proto=m.group("proto").strip(),
            reason=m.group("reason").strip(),
            source=source,
        ))
    return events


def fetch(gateway_url: str, path: str, timeout: float = 5.0) -> str:
    url = gateway_url.rstrip("/") + path
    req = urllib.request.Request(url, headers={"User-Agent": "connection-monitor/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def fetch_and_parse(gateway_url: str, packet_path: str, syslog_path: str = "",
                    timeout: float = 5.0) -> List[RouterEvent]:
    """Fetch the configured log pages and return parsed events.

    Raises on network error for the packet log. The syslog page is optional —
    failures there (or an empty path) are ignored, since the packet log alone
    is still valuable.
    """
    out: List[RouterEvent] = []
    if packet_path:
        pkt = fetch(gateway_url, packet_path, timeout=timeout)
        out.extend(parse(pkt, source="packet"))
    if syslog_path:
        try:
            sys = fetch(gateway_url, syslog_path, timeout=timeout)
            out.extend(parse(sys, source="syslog"))
        except Exception:
            pass
    return out


def dedupe(existing_keys: Iterable[tuple], new_events: Iterable[RouterEvent]
           ) -> List[RouterEvent]:
    seen = set(existing_keys)
    fresh: List[RouterEvent] = []
    for ev in new_events:
        k = ev.key()
        if k in seen:
            continue
        seen.add(k)
        fresh.append(ev)
    return fresh


# DNS probe targets the connection monitor uses (kept in sync with connection_monitor.py).
DNS_PROBE_TARGETS = {"8.8.8.8", "1.1.1.1", "208.67.222.222"}


def summarize(events: List[RouterEvent]) -> dict:
    """Build a compact summary suitable for the AI diagnosis prompt."""
    by_reason: dict = {}
    by_dst: dict = {}
    dns_drops: List[dict] = []
    invalid_packet = 0
    policy_drops = 0
    for ev in events:
        by_reason[ev.reason] = by_reason.get(ev.reason, 0) + 1
        by_dst[ev.dst] = by_dst.get(ev.dst, 0) + 1
        if "Invalid IP Packet" in ev.reason:
            invalid_packet += 1
        elif "Policy" in ev.reason:
            policy_drops += 1
        if ev.dst in DNS_PROBE_TARGETS and "Invalid" in ev.reason:
            dns_drops.append(ev.to_dict())
    top_dst = sorted(by_dst.items(), key=lambda kv: -kv[1])[:10]
    return {
        "total": len(events),
        "by_reason": by_reason,
        "invalid_packet": invalid_packet,
        "policy_drops": policy_drops,
        "dns_probe_drops": dns_drops[:30],
        "dns_probe_drop_count": len(dns_drops),
        "top_destinations": [{"dst": d, "count": c} for d, c in top_dst],
    }
