#!/usr/bin/env python3
"""
broadcast_map_server.py  —  CTW Broadcast AoA Map Server
=========================================================
Serves broadcast_map.html on :8002 with two SSE streams:

  /events/broadcast   — tails runtime/broadcast_live.jsonl
  /events/gnss        — tails runtime/gnss_live.jsonl
  /aoa                — POST endpoint: logs a manual AoA measurement
  /                   — serves broadcast_map.html

AoA POST body (JSON):
  { "freq_mhz": 88.9, "heading_deg": 247.3, "power_dbfs": -42.1,
    "callsign": "KXXX", "wall_iso": "2026-07-14T..." }

OOB GUARD: all POST fields validated before write.
"""

import os, sys, gzip, json, time, threading, math
from pathlib import Path
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── paths ──────────────────────────────────────────────────────────────────
BASE          = Path(r"C:\sdr\logs")
RUNTIME       = BASE / "runtime"
BROADCAST_LJ  = RUNTIME / "broadcast_live.jsonl"
GNSS_LJ       = RUNTIME / "gnss_live.jsonl"
AOA_LOG       = BASE / f"aoa_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
MAP_HTML      = Path(__file__).parent / "broadcast_map.html"
PORT          = 8002

RUNTIME.mkdir(parents=True, exist_ok=True)

# ── OOB guard ──────────────────────────────────────────────────────────────
def _clamp_float(v, lo, hi, name):
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise ValueError(f"OOB:{name} not numeric")
    if not (lo <= f <= hi):
        raise ValueError(f"OOB:{name}={f} outside [{lo},{hi}]")
    return f

def _validate_aoa(d: dict) -> dict:
    return {
        "type":        "aoa_measurement",
        "freq_mhz":    _clamp_float(d.get("freq_mhz"),    0.5,   1800.0, "freq_mhz"),
        "heading_deg": _clamp_float(d.get("heading_deg"), 0.0,    359.9, "heading_deg"),
        "power_dbfs":  _clamp_float(d.get("power_dbfs"), -120.0,   0.0,  "power_dbfs"),
        "callsign":    str(d.get("callsign", "UNKNOWN"))[:8].upper(),
        "wall_iso":    datetime.now(timezone.utc).isoformat(),
    }

# ── tail helper ────────────────────────────────────────────────────────────
def _tail_jsonl(path: Path, stop: threading.Event):
    """Generator: yields raw lines from a live JSONL file, blocking on new data."""
    while not path.exists() and not stop.is_set():
        time.sleep(0.5)
    if stop.is_set():
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)                    # seek to end — live tail only
        while not stop.is_set():
            line = fh.readline()
            if line:
                yield line.rstrip()
            else:
                time.sleep(0.05)

# ── HTTP handler ───────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass                             # suppress access log

    def _sse_stream(self, jsonl_path: Path):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        stop = threading.Event()
        try:
            for line in _tail_jsonl(jsonl_path, stop):
                self.wfile.write(f"data: {line}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            stop.set()

    def do_GET(self):
        if self.path == "/events/broadcast":
            self._sse_stream(BROADCAST_LJ)
        elif self.path == "/events/gnss":
            self._sse_stream(GNSS_LJ)
        elif self.path in ("/", "/broadcast_map.html"):
            try:
                html = MAP_HTML.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            except FileNotFoundError:
                self.send_error(404, "broadcast_map.html not found")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/aoa":
            try:
                length = int(self.headers.get("Content-Length", 0))
                body   = self.rfile.read(length)
                raw    = json.loads(body)
                rec    = _validate_aoa(raw)
                with open(AOA_LOG, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
                # also mirror to broadcast_live so the map picks it up
                with open(BROADCAST_LJ, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

# ── main ───────────────────────────────────────────────────────────────────
def main():
    srv = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[broadcast_map_server] Listening on http://0.0.0.0:{PORT}")
    print(f"  Map    : http://localhost:{PORT}/")
    print(f"  SSE BC : http://localhost:{PORT}/events/broadcast")
    print(f"  SSE GPS: http://localhost:{PORT}/events/gnss")
    print(f"  AoA log: {AOA_LOG}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[broadcast_map_server] Stopped.")

if __name__ == "__main__":
    main()
