#!/usr/bin/env python3

import json
import time
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

ROOT = Path(__file__).parent
RUNTIME = ROOT / "runtime"

CLIENTS = []
LOCK = threading.Lock()


# Add to rf_server.py — replace tail_file() and __main__ block

CORR_FILE = RUNTIME / "corr_live.jsonl"

def tail_file(path, label):
    """Generic JSONL tailer — tags each record with its source label."""
    while True:
        if not path.exists():
            time.sleep(0.5)
            continue
        with path.open("r", encoding="utf-8") as f:
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
                    obj["_stream"] = label   # tag so dashboard knows source
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

CORR_FILE = RUNTIME / "corr_live.jsonl"


def tail_file(path, label):
    while True:
        if not path.exists():
            time.sleep(0.5)
            continue
        with path.open("r", encoding="utf-8") as f:
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
                    obj["_stream"] = label
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
            self.end_headers()
            with LOCK:
                CLIENTS.append(self)
            try:
                while True:
                    time.sleep(10)
            except Exception:
                pass
            return

        # Redirect root to sweep.html
        if self.path in ("/", "/index.html"):
            self.send_response(302)
            self.send_header("Location", "/sweep.html")
            self.end_headers()
            return

        return super().do_GET()

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    threading.Thread(
        target=tail_file,
        args=(RUNTIME / "sweep_live.jsonl", "rf"),
        daemon=True
    ).start()

    threading.Thread(
        target=tail_file,
        args=(CORR_FILE, "corr"),
        daemon=True
    ).start()

    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    print("RF monitor running: http://localhost:8000")
    server.serve_forever()