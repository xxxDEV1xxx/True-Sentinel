#!/usr/bin/env python3
"""
ntp_web.py  —  CTW Web Time Reference
======================================
Scrapes current UTC from NIST time.gov instead of NTP UDP.
Returns offset between system clock and NIST reference.
Used by pluto_sweep.py and fs5000_dual.py as NTP replacement.
"""

import datetime
import re
import socket
import sys
import time
import urllib.request

# ── NIST sources in priority order ────────────────────────────────────────────
# Each entry: (url, parser_function)
# Parser receives raw response bytes, returns UTC datetime or None

def _parse_timegov(raw: bytes):
    """
    time.gov returns a JSON endpoint we can hit directly.
    https://timeapi.io/api/time/current/zone?timeZone=UTC  (fallback)
    time.gov main page has <time> tag with ISO datetime.
    """
    text = raw.decode("utf-8", errors="replace")
    # Look for ISO datetime in various formats the page embeds
    patterns = [
        r'"utc_datetime"\s*:\s*"([^"]+)"',
        r'"dateTime"\s*:\s*"([^"]+)"',
        r'<time[^>]*datetime="([^"]+)"',
        r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)',
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            s = m.group(1).strip()
            # Normalise — remove fractional seconds beyond ms
            s = re.sub(r'(\.\d{3})\d+', r'\1', s)
            if not s.endswith('Z') and '+' not in s[10:] and '-' not in s[10:]:
                s += 'Z'
            try:
                return datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
            except Exception:
                pass
    return None


def _parse_json_datetime(raw: bytes):
    """Generic JSON datetime field parser."""
    import json
    try:
        obj = json.loads(raw.decode("utf-8", errors="replace"))
        for key in ("utc_datetime", "dateTime", "datetime", "time", "currentDateTime"):
            if key in obj:
                s = str(obj[key]).strip()
                s = re.sub(r'(\.\d{3})\d+', r'\1', s)
                if not s.endswith('Z') and '+' not in s[10:]:
                    s += 'Z'
                try:
                    return datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
                except Exception:
                    pass
    except Exception:
        pass
    return None


def _parse_http_date(headers) -> datetime.datetime:
    """Parse HTTP Date response header — accurate to ~1s, always present."""
    from email.utils import parsedate_to_datetime
    date_hdr = headers.get("Date", "")
    if not date_hdr:
        return None
    try:
        return parsedate_to_datetime(date_hdr).astimezone(datetime.timezone.utc)
    except Exception:
        return None


SOURCES = [
    # (url, parser, label)
    (
        "https://timeapi.io/api/time/current/zone?timeZone=UTC",
        _parse_json_datetime,
        "timeapi.io/UTC"
    ),
    (
        "http://worldtimeapi.org/api/timezone/Etc/UTC",
        _parse_json_datetime,
        "worldtimeapi.org"
    ),
    (
        "https://www.time.gov",
        _parse_timegov,
        "NIST time.gov (HTML)"
    ),
    (
        "https://timeapi.io/api/time/current/zone?timeZone=America/New_York",
        _parse_json_datetime,
        "timeapi.io/ET"
    ),
]

# ── HTTP fallback headers ─────────────────────────────────────────────────────
# Even if body parsing fails, HTTP Date header gives ~1s accuracy

HEADER_SOURCES = [
    "https://www.cloudflare.com",
    "https://www.google.com",
    "https://www.microsoft.com",
]


def _fetch(url: str, timeout: float = 5.0):
    """
    Fetch URL. Returns (body_bytes, headers_dict) or (None, None).
    Handles TLS negotiation for older Windows Python builds.
    """
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CTW-TimeRef/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(65536), dict(r.headers)
    except Exception:
        pass

    # Retry without SSL context (http:// URLs)
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CTW-TimeRef/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(65536), dict(r.headers)
    except Exception:
        pass

    return None, None


def get_web_time() -> dict:
    """
    Query NIST/web time sources and compute system clock offset.

    Returns dict with keys:
        source          str   — which source succeeded
        utc_datetime    str   — ISO8601 UTC time from source
        system_utc      str   — system clock UTC at query moment
        offset_s        float — system_clock - web_time in seconds
                                positive = system is ahead
                                negative = system is behind
        offset_ms       float — same in milliseconds
        offset_ns       int   — same in nanoseconds
        accuracy        str   — 'body' | 'header' | 'none'
        error           str   — error message if failed
        query_wall_ns   int   — time.time_ns() at the moment of comparison
    """
    result = {
        "source":        "none",
        "utc_datetime":  None,
        "system_utc":    None,
        "offset_s":      None,
        "offset_ms":     None,
        "offset_ns":     None,
        "accuracy":      "none",
        "error":         None,
        "query_wall_ns": None,
    }

    # ── Try body-parsed sources ───────────────────────────────────────────────
    for url, parser, label in SOURCES:
        body, headers = _fetch(url, timeout=5.0)
        query_ns      = time.time_ns()

        if body is None:
            continue

        ref_dt = parser(body)

        if ref_dt is None and headers:
            # Fall through to header parse for this source
            ref_dt = _parse_http_date(headers)
            accuracy = "header"
        else:
            accuracy = "body"

        if ref_dt is None:
            continue

        # System time at the moment the response arrived
        sys_dt = datetime.datetime.fromtimestamp(
            query_ns / 1e9, tz=datetime.timezone.utc
        )

        offset_s  = (sys_dt - ref_dt).total_seconds()
        offset_ns = int(offset_s * 1e9)

        result.update({
            "source":        label,
            "utc_datetime":  ref_dt.isoformat(),
            "system_utc":    sys_dt.isoformat(),
            "offset_s":      round(offset_s, 6),
            "offset_ms":     round(offset_s * 1000, 3),
            "offset_ns":     offset_ns,
            "accuracy":      accuracy,
            "error":         None,
            "query_wall_ns": query_ns,
        })
        return result

    # ── Fall back to HTTP Date headers only ───────────────────────────────────
    for url in HEADER_SOURCES:
        body, headers = _fetch(url, timeout=4.0)
        query_ns      = time.time_ns()

        if headers is None:
            continue

        ref_dt = _parse_http_date(headers)
        if ref_dt is None:
            continue

        sys_dt   = datetime.datetime.fromtimestamp(
            query_ns / 1e9, tz=datetime.timezone.utc
        )
        offset_s = (sys_dt - ref_dt).total_seconds()

        result.update({
            "source":        f"HTTP Date header ({url})",
            "utc_datetime":  ref_dt.isoformat(),
            "system_utc":    sys_dt.isoformat(),
            "offset_s":      round(offset_s, 6),
            "offset_ms":     round(offset_s * 1000, 3),
            "offset_ns":     int(offset_s * 1e9),
            "accuracy":      "header",
            "error":         None,
            "query_wall_ns": query_ns,
        })
        return result

    result["error"] = "All web time sources failed"
    return result


def print_web_time_banner(info: dict):
    """Print a forensic-grade time reference banner."""
    print(f"\n{'='*68}")
    print(f"  CTW WEB TIME REFERENCE")
    print(f"{'='*68}")
    print(f"  Source          : {info['source']}")
    print(f"  Accuracy        : {info['accuracy']}")
    print(f"  Web UTC         : {info['utc_datetime']}")
    print(f"  System UTC      : {info['system_utc']}")
    if info['offset_s'] is not None:
        sign = '+' if info['offset_s'] >= 0 else ''
        print(f"  System offset   : {sign}{info['offset_s']:.6f} s  "
              f"({sign}{info['offset_ms']:.3f} ms)")
        print(f"  Offset note     : system clock is "
              f"{'AHEAD' if info['offset_s'] > 0 else 'BEHIND'} "
              f"web reference by {abs(info['offset_ms']):.1f} ms")
    if info['error']:
        print(f"  ERROR           : {info['error']}")
    print(f"{'='*68}\n")


# ── Drop-in replacement for get_ntp_info() ───────────────────────────────────

def get_ntp_info() -> dict:
    """
    Drop-in replacement for pluto_sweep.py and fs5000_dual.py get_ntp_info().
    Returns same key structure so no other code needs changing.
    """
    info = get_web_time()

    return {
        "ntp_source":          info["source"],
        "ntp_last_sync_utc":   info["utc_datetime"] or "unknown",
        "ntp_offset_s":        info["offset_s"],
        "ntp_offset_ns":       info["offset_ns"],
        "ntp_offset_ms":       info["offset_ms"],
        "ntp_stratum":         "web",
        "ntp_ref_id":          info["source"],
        "ntp_poll_interval_s": None,
        "ntp_query_method":    f"HTTP scrape: {info['source']}",
        "ntp_error":           info["error"],
        "ntp_raw_w32tm":       "",
        "ntp_peers":           [],
        "ntp_t1_wall_ns":      info["query_wall_ns"],
        "ntp_t2_wall_ns":      None,
        "ntp_t3_wall_ns":      None,
        "ntp_t4_wall_ns":      info["query_wall_ns"],
        "ntp_rtt_ns":          None,
        "ntp_server_queried":  info["source"],
        "ntp_utc_at_query":    info["utc_datetime"],
        "web_accuracy":        info["accuracy"],
        "system_offset_s":     info["offset_s"],
        "system_offset_ms":    info["offset_ms"],
        "system_offset_ns":    info["offset_ns"],
    }


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("CTW Web Time Reference — standalone test")
    info = get_web_time()
    print_web_time_banner(info)

    if info["offset_s"] is not None:
        print(f"Drop-in NTP result:")
        ntp = get_ntp_info()
        for k, v in ntp.items():
            print(f"  {k:<28} : {v}")