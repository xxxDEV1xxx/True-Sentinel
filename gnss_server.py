#!/usr/bin/env python3
"""
gnss_server.py  —  CTW GNSS Live SSE Server
============================================
Serves gnss_live.jsonl via SSE on :8001
Serves gnss_map.html on same port.
"""

import json
import os
import threading
import time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

ROOT        = Path(__file__).parent
RUNTIME     = ROOT / "runtime"
GNSS_LIVE   = RUNTIME / "gnss_live.jsonl"
PORT        = 8001

CLIENTS = []
LOCK    = threading.Lock()


def tail_gnss():
    while True:
        if not GNSS_LIVE.exists():
            time.sleep(0.5)
            continue
        with GNSS_LIVE.open("r", encoding="utf-8") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                payload = "data: " + json.dumps(obj) + "\n\n"
                dead = []
                with LOCK:
                    for c in CLIENTS:
                        try:
                            c.wfile.write(payload.encode())
                            c.wfile.flush()
                        except Exception:
                            dead.append(c)
                    for c in dead:
                        CLIENTS.remove(c)


class Handler(SimpleHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type",  "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection",    "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            with LOCK:
                CLIENTS.append(self)
            try:
                while True:
                    time.sleep(10)
            except Exception:
                pass
            return

        if self.path in ("/", "/index.html"):
            self.send_response(302)
            self.send_header("Location", "/gnss_map.html")
            self.end_headers()
            return

        return super().do_GET()

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    threading.Thread(target=tail_gnss, daemon=True).start()
    os.chdir(ROOT)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"GNSS server running: http://localhost:{PORT}/gnss_map.html")
    server.serve_forever()