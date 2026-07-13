#!/usr/bin/env python3
"""
correlator.py  —  CTW RF/Geiger Correlation Engine
===================================================
Tails runtime/sweep_live.jsonl  (RF anomalies from PlutoSDR)
Tails serial_*.jsonl.gz         (DR readings from FS-5000)
Tails audio_*.jsonl.gz          (pulse detections from FS-5000)

Emits correlation events to runtime/corr_live.jsonl whenever:
  - A Geiger spike (DR > threshold) co-occurs with an RF anomaly
    within WINDOW_NS nanoseconds on the shared wall_ns clock
  - A Geiger spike occurs without RF anomaly (standalone spike log)
  - An RF anomaly occurs without Geiger spike (standalone RF log)

All records share the same ClockAnchor/NTP wall_ns epoch so
time differences are meaningful to ~microsecond precision.

Usage:
  python correlator.py
  python correlator.py --window 1.0          # 1-second correlation window
  python correlator.py --spike 0.5           # DR spike threshold uSv/h
  python correlator.py --serial-log path/to/serial_*.jsonl.gz
  python correlator.py --audio-log  path/to/audio_*.jsonl.gz
  python correlator.py --rf-live    runtime/sweep_live.jsonl
"""

import argparse
import datetime
import glob
import gzip
import json
import os
import sys
import time
import threading
from collections import deque

# ── constants ──────────────────────────────────────────────────────────────

WINDOW_NS        = int(500e6)     # 500 ms default correlation window
SPIKE_THRESHOLD  = 0.10           # uSv/h — above baseline, marks a spike
AUDIO_BURST_HZ   = 5.0           # audio pulses/sec threshold for burst flag
RING_CAPACITY    = 2000           # events per stream in the ring buffer
POLL_INTERVAL_S  = 0.15          # tail poll cadence

# ── OOB guard ──────────────────────────────────────────────────────────────

_OOB = {
    "MAX_LINE_BYTES":    8192,
    "MAX_BURST_LINES":   5000,
    "MAX_DR":            10000.0,    # uSv/h hard cap
    "MAX_CPM":           1_000_000,
    "MAX_WALL_NS":       int(4e18),  # ~year 2096
    "MAX_FREQ_HZ":       7e9,
    "MIN_FREQ_HZ":       50e6,
}

def _clamp(v, lo, hi, label):
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v

def _safe_float(v, lo, hi, label):
    try:
        f = float(v)
        if not (-1e18 < f < 1e18):
            return None
        return _clamp(f, lo, hi, label)
    except (TypeError, ValueError):
        return None

def _safe_int(v, lo, hi, label):
    try:
        i = int(v)
        return _clamp(i, lo, hi, label)
    except (TypeError, ValueError):
        return None

# ── ring buffer ─────────────────────────────────────────────────────────────

class RingBuffer:
    """Thread-safe fixed-capacity deque keyed on wall_ns."""

    def __init__(self, capacity=RING_CAPACITY):
        self._buf  = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def push(self, record):
        with self._lock:
            self._buf.append(record)

    def snapshot(self):
        with self._lock:
            return list(self._buf)

    def in_window(self, wall_ns, window_ns=WINDOW_NS):
        """Return all records within window_ns of wall_ns."""
        lo = wall_ns - window_ns
        hi = wall_ns + window_ns
        with self._lock:
            return [r for r in self._buf if lo <= r["wall_ns"] <= hi]


# ── JSONL.GZ tail reader ────────────────────────────────────────────────────

class GzipTail:
    """
    Reads new records from a growing .jsonl.gz file.
    Uses record count (not byte offset) because gzip is not
    seekable mid-stream — we re-read from start and skip seen lines.
    For large files, pairs with a line-count cursor.
    """

    def __init__(self, path, on_record, name="GzipTail"):
        self.path      = path
        self.on_record = on_record
        self.name      = name
        self._seen     = 0
        self._stop     = threading.Event()
        self._thread   = threading.Thread(
            target=self._run, daemon=True, name=name
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    def _run(self):
        while not self._stop.is_set():
            if os.path.exists(self.path):
                self._poll()
            time.sleep(POLL_INTERVAL_S)

    def _poll(self):
        try:
            with gzip.open(self.path, "rt", errors="ignore") as gz:
                for idx, line in enumerate(gz):
                    if idx < self._seen:
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    if len(line) > _OOB["MAX_LINE_BYTES"]:
                        print(f"[OOB] {self.name}: line {idx} "
                              f"len {len(line)} > MAX, skipped")
                        self._seen = idx + 1
                        continue
                    try:
                        obj = json.loads(line)
                        self.on_record(obj)
                    except json.JSONDecodeError:
                        pass
                    self._seen = idx + 1
        except EOFError:
            pass  # partial gzip write — retry next poll
        except Exception as e:
            print(f"[{self.name}] read error: {e}")


class LiveJsonlTail:
    """
    Cursor-based tail of a plain .jsonl file (runtime/sweep_live.jsonl).
    Uses byte offset — file is plain text, seekable.
    """

    def __init__(self, path, on_record, name="LiveTail"):
        self.path      = path
        self.on_record = on_record
        self.name      = name
        self._offset   = 0
        self._stop     = threading.Event()
        self._thread   = threading.Thread(
            target=self._run, daemon=True, name=name
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=5)

    def _run(self):
        while not self._stop.is_set():
            if os.path.exists(self.path):
                self._poll()
            time.sleep(POLL_INTERVAL_S)

    def _poll(self):
        try:
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._offset)
                chunk = f.read(1024 * 256)  # 256 KB max per poll
                if not chunk:
                    return
                self._offset += len(chunk.encode("utf-8"))
                lines = chunk.split("\n")
                count = 0
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if len(line) > _OOB["MAX_LINE_BYTES"]:
                        continue
                    if count >= _OOB["MAX_BURST_LINES"]:
                        break
                    try:
                        obj = json.loads(line)
                        self.on_record(obj)
                        count += 1
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"[{self.name}] error: {e}")


# ── correlation output ───────────────────────────────────────────────────────

class CorrLog:
    """Append-only plain JSONL for fast live reading by rf_server.py."""

    def __init__(self, path):
        self.path  = path
        self._lock = threading.Lock()
        # Truncate on start — this is a live session file
        with open(path, "w", encoding="utf-8") as f:
            f.write("")

    def write(self, obj):
        line = json.dumps(obj, separators=(",", ":")) + "\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line)


# ── record parsers ───────────────────────────────────────────────────────────

def parse_serial(obj):
    """Parse a FS-5000 serial record. Returns dict or None."""
    t = obj.get("type")
    if t in ("forensic_session_header", "session_end"):
        return None
    wns = _safe_int(obj.get("wall_ns"), 0, _OOB["MAX_WALL_NS"], "wall_ns")
    dr  = _safe_float(obj.get("dr"),  0, _OOB["MAX_DR"],  "dr")
    cpm = _safe_int(obj.get("cpm"),   0, _OOB["MAX_CPM"], "cpm")
    if wns is None or dr is None:
        return None
    return {
        "wall_ns": wns,
        "dr":      dr,
        "cpm":     cpm or 0,
        "cps":     _safe_int(obj.get("cps"), 0, 100000, "cps") or 0,
        "dose":    _safe_float(obj.get("dose"), 0, 1e6, "dose"),
        "seq":     obj.get("seq"),
    }

def parse_audio_pulse(obj):
    """Parse a FS-5000 audio pulse record. Returns dict or None."""
    t = obj.get("type")
    if t in ("forensic_session_header", "session_end"):
        return None
    wns = _safe_int(obj.get("wall_ns"), 0, _OOB["MAX_WALL_NS"], "wall_ns")
    amp = _safe_float(obj.get("amplitude"), 0, 100, "amplitude")
    if wns is None:
        return None
    return {
        "wall_ns":   wns,
        "amplitude": amp or 0.0,
        "seq":       obj.get("seq"),
    }

def parse_rf(obj):
    """Parse a PlutoSDR sweep record. Returns dict or None."""
    if not obj.get("freq_hz"):
        return None
    t = obj.get("type")
    if t in ("forensic_session_header", "session_end",
             "sweep_pass_end", "sweep_summary", "set_error"):
        return None
    wns  = _safe_int(obj.get("wall_ns"), 0, _OOB["MAX_WALL_NS"], "wall_ns")
    freq = _safe_float(obj.get("freq_hz"),
                       _OOB["MIN_FREQ_HZ"], _OOB["MAX_FREQ_HZ"], "freq_hz")
    if wns is None or freq is None:
        return None
    return {
        "wall_ns":        wns,
        "freq_hz":        freq,
        "dbfs":           _safe_float(obj.get("dbfs"),         -200, 10,  "dbfs"),
        "crest_factor":   _safe_float(obj.get("crest_factor"),    0, 1e4, "cf"),
        "rssi_atten_db":  _safe_float(obj.get("rssi_atten_db"),   0, 200, "atten"),
        "anomaly":        bool(obj.get("anomaly")),
        "sweep":          obj.get("sweep"),
        "rx_port":        obj.get("rx_port"),
    }


# ── correlator core ──────────────────────────────────────────────────────────

class Correlator:

    def __init__(self, corr_log, window_ns, spike_threshold):
        self.corr_log        = corr_log
        self.window_ns       = window_ns
        self.spike_threshold = spike_threshold

        # Shared ring buffers
        self.rf_ring      = RingBuffer()
        self.serial_ring  = RingBuffer()
        self.audio_ring   = RingBuffer()

        # Stats
        self.stats = {
            "rf_records":       0,
            "serial_records":   0,
            "audio_pulses":     0,
            "corr_events":      0,
            "spike_only":       0,
            "rf_only":          0,
        }
        self._lock = threading.Lock()

        # Audio burst tracker: sliding 1-second window
        self._audio_times = deque()

    # ── feed methods (called from tail threads) ─────────────────────────

    def feed_rf(self, obj):
        r = parse_rf(obj)
        if not r:
            return
        with self._lock:
            self.stats["rf_records"] += 1
        self.rf_ring.push(r)

        if r["anomaly"]:
            self._check_corr_rf_side(r)

    def feed_serial(self, obj):
        r = parse_serial(obj)
        if not r:
            return
        with self._lock:
            self.stats["serial_records"] += 1
        self.serial_ring.push(r)

        if r["dr"] >= self.spike_threshold:
            self._check_corr_geiger_side(r)
        else:
            # Still emit a standalone serial record for the dashboard
            self._emit_serial_record(r)

    def feed_audio(self, obj):
        r = parse_audio_pulse(obj)
        if not r:
            return
        with self._lock:
            self.stats["audio_pulses"] += 1
        self.audio_ring.push(r)

        # Track pulse rate in sliding 1-second window
        now_ns = r["wall_ns"]
        self._audio_times.append(now_ns)
        cutoff = now_ns - int(1e9)
        while self._audio_times and self._audio_times[0] < cutoff:
            self._audio_times.popleft()

    # ── correlation checks ──────────────────────────────────────────────

    def _audio_burst_rate(self):
        """Current audio pulses/sec in the sliding 1-second window."""
        return len(self._audio_times)

    def _check_corr_geiger_side(self, serial_rec):
        """
        Geiger spike detected. Look for RF anomalies within window.
        Emit CORR event if found, SPIKE_ONLY if not.
        """
        wns         = serial_rec["wall_ns"]
        rf_matches  = self.rf_ring.in_window(wns, self.window_ns)
        rf_anomalies = [r for r in rf_matches if r["anomaly"]]
        audio_near  = self.audio_ring.in_window(wns, self.window_ns)
        burst_rate  = self._audio_burst_rate()

        base = {
            "event_wall_ns":   wns,
            "event_wall_iso":  _fmt_ns(wns),
            "dr":              serial_rec["dr"],
            "cpm":             serial_rec["cpm"],
            "cps":             serial_rec["cps"],
            "audio_pulses_1s": burst_rate,
            "audio_burst":     burst_rate >= AUDIO_BURST_HZ,
        }

        if rf_anomalies:
            # Sort by temporal proximity to the spike
            rf_anomalies.sort(key=lambda r: abs(r["wall_ns"] - wns))
            best = rf_anomalies[0]
            dt_ms = (wns - best["wall_ns"]) / 1e6

            event = {
                "type":         "CORR",
                "source":       "geiger_led",
                **base,
                "rf_freq_hz":   best["freq_hz"],
                "rf_dbfs":      best["dbfs"],
                "rf_cf":        best["crest_factor"],
                "rf_atten":     best["rssi_atten_db"],
                "rf_dt_ms":     round(dt_ms, 3),
                "rf_count":     len(rf_anomalies),
                "all_rf_freqs": [r["freq_hz"] for r in rf_anomalies[:8]],
            }
            with self._lock:
                self.stats["corr_events"] += 1
        else:
            event = {
                "type":    "SPIKE_ONLY",
                "source":  "geiger_led",
                **base,
                "rf_in_window": len(rf_matches),
            }
            with self._lock:
                self.stats["spike_only"] += 1

        self.corr_log.write(event)
        self._print_event(event)

    def _check_corr_rf_side(self, rf_rec):
        """
        RF anomaly detected. Look for Geiger spikes within window.
        Only emits RF_ONLY if no Geiger spike found — CORR is emitted
        from the Geiger side to avoid double-counting.
        """
        wns          = rf_rec["wall_ns"]
        serial_near  = self.serial_ring.in_window(wns, self.window_ns)
        spikes       = [r for r in serial_near
                        if r["dr"] >= self.spike_threshold]

        if not spikes:
            event = {
                "type":          "RF_ONLY",
                "event_wall_ns": wns,
                "event_wall_iso":_fmt_ns(wns),
                "rf_freq_hz":    rf_rec["freq_hz"],
                "rf_dbfs":       rf_rec["dbfs"],
                "rf_cf":         rf_rec["crest_factor"],
                "rf_atten":      rf_rec["rssi_atten_db"],
                "serial_in_window": len(serial_near),
            }
            with self._lock:
                self.stats["rf_only"] += 1
            self.corr_log.write(event)

    def _emit_serial_record(self, r):
        """Emit below-threshold serial records for baseline tracking."""
        self.corr_log.write({
            "type":          "SERIAL",
            "event_wall_ns": r["wall_ns"],
            "event_wall_iso":_fmt_ns(r["wall_ns"]),
            "dr":            r["dr"],
            "cpm":           r["cpm"],
            "cps":           r["cps"],
        })

    def _print_event(self, event):
        t    = event.get("event_wall_iso", "")[-15:-4] if event.get("event_wall_iso") else "?"
        kind = event["type"]
        dr   = event.get("dr", 0)
        cpm  = event.get("cpm", 0)

        if kind == "CORR":
            freq = event.get("rf_freq_hz", 0)
            dt   = event.get("rf_dt_ms", 0)
            cf   = event.get("rf_cf") or 0
            print(
                f"\n  [{t}] *** CORR ***  "
                f"DR={dr:.4f} uSv/h  CPM={cpm}  "
                f"RF={freq/1e6:.3f}MHz  CF={cf:.1f}  Δt={dt:+.1f}ms",
                flush=True
            )
        elif kind == "SPIKE_ONLY":
            audio = event.get("audio_pulses_1s", 0)
            print(
                f"\n  [{t}]  SPIKE_ONLY   "
                f"DR={dr:.4f} uSv/h  CPM={cpm}  "
                f"AUD={audio}/s  (no RF anomaly in window)",
                flush=True
            )

    def print_stats(self):
        with self._lock:
            s = dict(self.stats)
        print(
            f"\r  RF={s['rf_records']:>7}  "
            f"SER={s['serial_records']:>6}  "
            f"AUD={s['audio_pulses']:>7}  "
            f"CORR={s['corr_events']:>4}  "
            f"SPIKE={s['spike_only']:>4}  "
            f"RF_ONLY={s['rf_only']:>4}   ",
            end="", flush=True
        )


# ── utility ──────────────────────────────────────────────────────────────────

def _fmt_ns(wall_ns):
    try:
        whole = wall_ns // 1_000_000_000
        frac  = wall_ns  % 1_000_000_000
        base  = datetime.datetime.fromtimestamp(
            whole, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%S")
        return f"{base}.{frac:09d}Z"
    except Exception:
        return "?"

def find_latest(pattern):
    """Return the most recently modified file matching glob pattern."""
    matches = glob.glob(pattern)
    if not matches:
        return None
    return max(matches, key=os.path.getmtime)


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CTW RF/Geiger Correlation Engine"
    )
    ap.add_argument("--rf-live",    default="runtime/sweep_live.jsonl",
                    help="Path to sweep_live.jsonl from gz_watch.py")
    ap.add_argument("--serial-log", default="",
                    help="Path to serial_*.jsonl.gz (auto-detect if omitted)")
    ap.add_argument("--audio-log",  default="",
                    help="Path to audio_*.jsonl.gz (auto-detect if omitted)")
    ap.add_argument("--out",        default="runtime",
                    help="Directory for corr_live.jsonl output")
    ap.add_argument("--window",     type=float, default=0.5,
                    help="Correlation window in seconds (default 0.5)")
    ap.add_argument("--spike",      type=float,
                    default=SPIKE_THRESHOLD,
                    help="DR spike threshold in uSv/h (default 0.10)")
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    window_ns = int(args.window * 1e9)

    # Resolve log paths
    serial_path = args.serial_log or find_latest("serial_*.jsonl.gz") or ""
    audio_path  = args.audio_log  or find_latest("audio_*.jsonl.gz")  or ""
    rf_path     = args.rf_live

    print(f"\n{'='*62}")
    print(f"  CTW RF/GEIGER CORRELATION ENGINE")
    print(f"{'='*62}")
    print(f"  RF live       : {rf_path}")
    print(f"  Serial log    : {serial_path or '(not found)'}")
    print(f"  Audio log     : {audio_path  or '(not found)'}")
    print(f"  Window        : {args.window*1000:.0f} ms  ({window_ns} ns)")
    print(f"  Spike thresh  : {args.spike} uSv/h")
    print(f"  Out dir       : {out_dir}")
    print(f"{'='*62}\n")

    if not os.path.exists(rf_path):
        print(f"WARNING: RF live file not found: {rf_path}")
        print("  Start pluto_sweep.py and gz_watch.py first.")

    corr_path = os.path.join(out_dir, "corr_live.jsonl")
    corr_log  = CorrLog(corr_path)
    engine    = Correlator(corr_log, window_ns, args.spike)

    # Write session header to corr log
    corr_log.write({
        "type":         "corr_session_header",
        "wall_iso":     _fmt_ns(time.time_ns()),
        "window_ns":    window_ns,
        "spike_thresh": args.spike,
        "rf_source":    rf_path,
        "serial_source":serial_path,
        "audio_source": audio_path,
    })

    # Start tails
    tails = []

    rf_tail = LiveJsonlTail(rf_path, engine.feed_rf, name="RF-tail")
    rf_tail.start()
    tails.append(rf_tail)

    if serial_path and os.path.exists(serial_path):
        ser_tail = GzipTail(serial_path, engine.feed_serial, name="Serial-tail")
        ser_tail.start()
        tails.append(ser_tail)
    else:
        print("WARNING: No serial log — Geiger DR data will be absent.")
        print("  Start fs5000_dual.py and pass --serial-log path")

    if audio_path and os.path.exists(audio_path):
        aud_tail = GzipTail(audio_path, engine.feed_audio, name="Audio-tail")
        aud_tail.start()
        tails.append(aud_tail)
    else:
        print("WARNING: No audio log — pulse burst correlation disabled.")

    print(f"  Correlation output : {corr_path}")
    print(f"  Ctrl+C to stop\n")
    print(f"  {'RF':>7}  {'SER':>6}  {'AUD':>7}  "
          f"{'CORR':>4}  {'SPIKE':>5}  {'RF_ONLY':>7}")

    try:
        while True:
            engine.print_stats()
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        for t in tails:
            t.stop()
        print(f"\n\nCorrelation session complete.")
        print(f"  Output: {corr_path}")
        engine.print_stats()
        print()


if __name__ == "__main__":
    main()