#!/usr/bin/env python3
"""
ctw_sentinel_auto.py  —  CTW Autonomous Incident Detection Engine
==================================================================
Standalone automated sentinel that monitors all 24 forensic layers
simultaneously, correlates events across the unified ClockAnchor
timeline, and surfaces confirmed multi-layer incidents.

INCIDENT CLASSIFICATION:
  TIER_1_CONFIRMED   3+ layers corroborate within correlation window
                     Daubert-admissible evidence package generated
  TIER_2_PROBABLE    2 layers corroborate — elevated monitoring
  TIER_3_WATCH       Single layer anomaly — logged, watch triggered

LAYERS MONITORED:
  L01  gz_watch          — gzip pipeline health
  L02  live_reader       — JSONL cursor integrity
  L03  rf_server         — SSE broadcast health
  L04  correlator        — RF/Geiger cross-correlation
  L05  pluto_sweep       — PlutoSDR 386MHz + wideband
  L06  bt_scanner        — Bluetooth/BLE
  L07  css_hunter        — Cell site simulator active
  L08  css_idle_hunter   — CSS idle/gap camping
  L09  ublox_data        — GNSS raw capture
  L10  ublox_parser      — UBX binary forensic
  L11  gnss_server       — GNSS map
  L12  hlk_ld6002b       — 60GHz passive
  L13  hlk_ld6002b       — 60GHz empty cal
  L14  hlk_ld6002b       — 60GHz human ref
  L15  hlk_ld6002b       — 60GHz forensic scan
  L16  sweep.html        — RF dashboard
  L17  gnss_map.html     — GNSS dashboard
  L18  gnss_anomaly_report — GNSS forensic report
  L19  geiger_sdr_correlator — Post-session Geiger/SDR
  L20  broadcast_monitor — AM/FM carrier power
  L21  broadcast_map     — AoA bearing map
  L22  broadcast_map.html — AoA dashboard
  L23  wifi_sentinel     — Dual-adapter WiFi MITM
  L24  cross_correlator  — Multi-layer incident engine (this script)

OUTPUTS:
  sentinel_auto_STAMP.jsonl.gz     all events + incidents
  runtime/sentinel_live.jsonl      SSE mirror for dashboard
  incidents/INCIDENT_STAMP.json    per-incident evidence package
  sentinel_report_STAMP.txt        human-readable incident report

OOB GUARD: All externally supplied fields validated at every
           ingestion boundary per USPTO 19/466,387.

Author: Christopher T. Williams / CTW-11 / SENTINEL Platform
"""

import os, sys, time, json, gzip, threading, hashlib, re
import subprocess, argparse, shutil, signal
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
# CLOCK ANCHOR
# ══════════════════════════════════════════════════════════════════════════════

class ClockAnchor:
    def __init__(self):
        self._wall_ns  = time.time_ns()
        self._mono_ns  = time.monotonic_ns()
        self._session  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def now(self):
        mono_now = time.monotonic_ns()
        wall_ns  = self._wall_ns + (mono_now - self._mono_ns)
        return wall_ns, self._iso(wall_ns)

    def _iso(self, ns):
        s  = ns // 1_000_000_000
        us = (ns % 1_000_000_000) // 1_000
        dt = datetime.fromtimestamp(s, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{us:06d}Z"

    @property
    def session(self):
        return self._session


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════════

class GzipLog:
    def __init__(self, path: Path):
        self._fh   = gzip.open(path, "wt", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, rec: dict):
        with self._lock:
            self._fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self._fh.flush()

    def close(self):
        with self._lock:
            self._fh.close()


class LiveMirror:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh   = open(path, "w", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, rec: dict):
        with self._lock:
            self._fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self._fh.flush()

    def close(self):
        with self._lock:
            self._fh.close()


# ══════════════════════════════════════════════════════════════════════════════
# OOB GUARD
# ══════════════════════════════════════════════════════════════════════════════

_BSSID_RE  = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
_STREAM_OK = {
    "sweep", "bt", "css", "css_idle", "gnss", "mmwave",
    "broadcast", "wifi", "geiger", "correlator", "sentinel"
}

def _oob_str(v, maxlen=256, name="field"):
    s = str(v)
    s = s.encode("ascii", errors="replace").decode("ascii")
    s = "".join(c if 32 <= ord(c) < 127 else "?" for c in s)
    return s[:maxlen]

def _oob_float(v, lo, hi, name="float", default=None):
    try:
        f = float(v)
        if lo <= f <= hi:
            return f
    except (TypeError, ValueError):
        pass
    if default is not None:
        return default
    raise ValueError(f"OOB:{name}={v} outside [{lo},{hi}]")

def _oob_int(v, lo, hi, name="int", default=None):
    try:
        i = int(v)
        if lo <= i <= hi:
            return i
    except (TypeError, ValueError):
        pass
    if default is not None:
        return default
    raise ValueError(f"OOB:{name}={v} outside [{lo},{hi}]")

def _oob_stream(v):
    s = str(v).strip().lower()
    return s if s in _STREAM_OK else "UNKNOWN"

def _oob_rec(rec: dict) -> dict:
    """
    Validate and sanitize an inbound event record.
    Returns cleaned record or raises ValueError on critical OOB.
    """
    out = {}
    out["type"]      = _oob_str(rec.get("type",     "unknown"), 64)
    out["_stream"]   = _oob_stream(rec.get("_stream", "unknown"))
    out["wall_ns"]   = _oob_int(
                           rec.get("wall_ns", 0),
                           0, 9_999_999_999_999_999_999,
                           "wall_ns", 0)
    out["wall_iso"]  = _oob_str(rec.get("wall_iso", ""), 40)

    # optional common fields — pass through if present and valid
    for fld in ("anomaly_class", "detail", "bssid", "ssid",
                "callsign", "freq_mhz", "band", "city"):
        if fld in rec:
            out[fld] = _oob_str(rec[fld], 256, fld)

    for fld in ("channel", "scan_seq", "beacon_count", "data_count",
                "count_10s", "pci", "tac", "earfcn"):
        if fld in rec:
            out[fld] = _oob_int(rec[fld], -1, 99_999_999, fld, -1)

    for fld in ("rssi", "power_dbfs", "delta_db", "lag_ms",
                "dose_rate", "heading_deg", "bearing_deg",
                "anomaly_db", "ratio"):
        if fld in rec:
            out[fld] = _oob_float(rec[fld], -1e9, 1e9, fld, 0.0)

    # preserve any additional fields as sanitized strings
    for k, v in rec.items():
        if k not in out:
            out[k] = _oob_str(str(v), 512, k)

    return out


# ══════════════════════════════════════════════════════════════════════════════
# LAYER DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

# Maps _stream tag → layer numbers + human label
STREAM_LAYER_MAP = {
    "sweep":       (5,  "PlutoSDR RF Sweep"),
    "bt":          (6,  "Bluetooth/BLE"),
    "css":         (7,  "CSS Active Hunter"),
    "css_idle":    (8,  "CSS Idle/Gap Hunter"),
    "gnss":        (10, "GNSS/UBX Parser"),
    "mmwave":      (15, "60GHz mmWave"),
    "broadcast":   (20, "AM/FM Broadcast Monitor"),
    "wifi":        (23, "WiFi Dual-Adapter Sentinel"),
    "geiger":      (4,  "RF/Geiger Correlator"),
    "correlator":  (4,  "RF/Geiger Correlator"),
    "sentinel":    (24, "Multi-Layer Incident Engine"),
}

# Anomaly class weights for incident scoring
# Higher weight = stronger individual indicator
ANOMALY_WEIGHTS = {
    # WiFi
    "DEAUTH_FLOOD":                  8,
    "EVIL_TWIN":                    10,
    "BEACON_DATA_RATIO_COLLAPSE":    9,
    "BSSID_MULTICHANNEL":            9,
    "PROBE_RESPONSE_MISMATCH":       8,
    "TIMING_CORRELATED_EXFIL":      10,
    "RSSI_ELEVATED_HOME_SSID":       7,
    "OOB_CHANNEL":                   5,
    # CSS / Cell
    "TAC_RESERVED":                 10,
    "PCI_COLLISION":                 9,
    "EARFCN_OUT_OF_BAND":            9,
    "GHOST_CELL":                   10,
    "CSS_ROGUE":                    10,
    "CSS_SUSPECT":                   7,
    "CIPHER_DOWNGRADE":             10,
    "TIMING_ADVANCE_ANOMALY":        8,
    "EMERGENCY_ONLY_ATTACH":         9,
    # GNSS
    "SPOOF_DETECTED":               10,
    "JAMMING_DETECTED":              9,
    "POSITION_JUMP":                 8,
    "FIX_DEGRADED":                  5,
    "PSEUDORANGE_ANOMALY":           7,
    # RF / Pluto
    "ANOMALY":                       6,
    "PERSISTENT_SIGNAL":             7,
    "CTW11_386MHZ_ACTIVE":          10,
    "CTW11_386_HARMONIC":            8,
    "SIGNAL_IN_GAP":                 8,
    "PSS_IN_GAP":                    9,
    # Broadcast
    "CARRIER_ABSENT":                6,
    "CARRIER_SUPPRESSED":            7,
    "CARRIER_ELEVATED":              8,
    "CARRIER_DRIFT":                 7,
    "CARRIER_SPURIOUS":              8,
    "INTERMODULATION":               6,
    # Geiger / EM
    "CORR":                         10,
    "EM_ONLY":                       7,
    "RF_ONLY":                       6,
    # BT
    "BDADDR_COLLISION":              8,
    "ADV_INTERVAL_ANOMALY":          6,
    "BLE_CHANNEL_ASYMMETRY":         7,
    "RSSI_BREACH":                   5,
    # mmWave
    "STATIC_EMITTER":               10,
    "SLOW_MODULATED":                8,
    "FAST_MODULATED":                7,
    "TRIANGULATION":                 9,
    # default
    "_DEFAULT":                      4,
}

# Multi-layer incident signatures
# Each entry: (name, required_streams, min_score, window_ms, description)
INCIDENT_SIGNATURES = [
    (
        "COORDINATED_MITM_FULL",
        {"wifi", "css", "sweep"},
        24,
        2000,
        "WiFi deauth + CSS ghost cell + 386MHz burst — "
        "coordinated multi-layer intercept"
    ),
    (
        "WIFI_MITM_CONFIRMED",
        {"wifi", "sweep"},
        18,
        1000,
        "WiFi MITM with corroborating RF — "
        "evil twin + exfil channel active"
    ),
    (
        "FORCED_HANDOFF_ATTEMPT",
        {"wifi", "css"},
        16,
        3000,
        "WiFi deauth coordinated with CSS registration — "
        "forced LTE handoff to rogue cell"
    ),
    (
        "CSS_WITH_RF_BURST",
        {"css", "sweep"},
        16,
        2000,
        "CSS anomaly corroborated by RF burst — "
        "active cell site simulator"
    ),
    (
        "GNSS_DENIAL_WITH_RF",
        {"gnss", "sweep"},
        14,
        5000,
        "GNSS jamming/spoofing with corroborating RF — "
        "active navigation denial"
    ),
    (
        "EM_BIOLOGICAL_EVENT",
        {"geiger", "sweep"},
        14,
        1000,
        "RF/Geiger correlated event — "
        "EM pulse with dosimeter response"
    ),
    (
        "BROADCAST_SUPPRESSION",
        {"broadcast", "sweep"},
        12,
        10000,
        "Licensed carrier suppressed coincident with RF anomaly — "
        "possible directed interference"
    ),
    (
        "MMWAVE_DIRECTED_EMISSION",
        {"mmwave", "sweep"},
        16,
        2000,
        "60GHz static emitter with corroborating RF — "
        "directed energy source"
    ),
    (
        "BT_SWARM_WITH_CSS",
        {"bt", "css"},
        14,
        5000,
        "BT/BLE anomaly storm coincident with CSS — "
        "coordinated proximity attack"
    ),
    (
        "FULL_SPECTRUM_INCIDENT",
        {"wifi", "css", "sweep", "gnss", "bt"},
        40,
        5000,
        "Five-layer simultaneous anomaly — "
        "full-spectrum coordinated attack"
    ),
]


# ══════════════════════════════════════════════════════════════════════════════
# EVENT RECORD
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Event:
    wall_ns:       int
    wall_iso:      str
    stream:        str
    layer:         int
    layer_label:   str
    anomaly_class: str
    weight:        int
    raw:           dict
    evidence_hash: str = field(default="", repr=False)

    def __post_init__(self):
        # SHA-256 of the canonical JSON — tamper-evident fingerprint
        canon = json.dumps(self.raw, sort_keys=True, separators=(",", ":"))
        self.evidence_hash = hashlib.sha256(canon.encode()).hexdigest()

    def to_dict(self):
        return {
            "wall_ns":       self.wall_ns,
            "wall_iso":      self.wall_iso,
            "stream":        self.stream,
            "layer":         self.layer,
            "layer_label":   self.layer_label,
            "anomaly_class": self.anomaly_class,
            "weight":        self.weight,
            "evidence_hash": self.evidence_hash,
            "detail":        self.raw.get("detail", ""),
            "bssid":         self.raw.get("bssid", ""),
            "ssid":          self.raw.get("ssid", ""),
            "channel":       self.raw.get("channel", ""),
            "freq_mhz":      self.raw.get("freq_mhz", ""),
            "rssi":          self.raw.get("rssi", ""),
        }


# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT RECORD
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Incident:
    incident_id:   str
    wall_ns:       int
    wall_iso:      str
    signature:     str
    tier:          int
    score:         int
    streams:       set
    events:        list
    description:   str
    chain_hash:    str = field(default="", repr=False)

    def __post_init__(self):
        # chain hash over all event evidence hashes in time order
        chain = "|".join(e.evidence_hash for e in
                         sorted(self.events, key=lambda x: x.wall_ns))
        self.chain_hash = hashlib.sha256(chain.encode()).hexdigest()

    def tier_label(self):
        return {1: "TIER_1_CONFIRMED",
                2: "TIER_2_PROBABLE",
                3: "TIER_3_WATCH"}.get(self.tier, "UNKNOWN")

    def to_dict(self):
        return {
            "incident_id":   self.incident_id,
            "wall_ns":       self.wall_ns,
            "wall_iso":      self.wall_iso,
            "tier":          self.tier,
            "tier_label":    self.tier_label(),
            "signature":     self.signature,
            "score":         self.score,
            "streams":       sorted(self.streams),
            "layer_count":   len(self.streams),
            "event_count":   len(self.events),
            "description":   self.description,
            "chain_hash":    self.chain_hash,
            "events":        [e.to_dict() for e in
                              sorted(self.events, key=lambda x: x.wall_ns)],
        }


# ══════════════════════════════════════════════════════════════════════════════
# LIVE FILE TAILER
# Tails a JSONL file and yields records as they arrive.
# ══════════════════════════════════════════════════════════════════════════════

class LiveTailer(threading.Thread):
    def __init__(self, path: Path, callback, stream_tag: str,
                 stop: threading.Event, poll_interval: float = 0.05):
        super().__init__(daemon=True, name=f"tail-{stream_tag}")
        self._path     = path
        self._cb       = callback
        self._tag      = stream_tag
        self._stop     = stop
        self._interval = poll_interval

    def run(self):
        # wait up to 120s for file to appear
        waited = 0
        while not self._path.exists() and not self._stop.is_set():
            if waited == 0:
                print(f"[tailer:{self._tag}] Waiting for "
                      f"{self._path.name}...")
            time.sleep(1)
            waited += 1
            if waited > 120:
                print(f"[tailer:{self._tag}] Timeout — "
                      f"{self._path.name} never appeared")
                return

        print(f"[tailer:{self._tag}] Tailing {self._path.name}")
        try:
            with open(self._path, "r",
                      encoding="utf-8", errors="replace") as fh:
                fh.seek(0, 2)           # live tail only
                while not self._stop.is_set():
                    line = fh.readline()
                    if line:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                            self._cb(rec, self._tag)
                        except json.JSONDecodeError:
                            pass
                    else:
                        time.sleep(self._interval)
        except Exception as e:
            print(f"[tailer:{self._tag}] Error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# PROCESS LAUNCHER
# Launches and monitors the 23 child processes.
# ══════════════════════════════════════════════════════════════════════════════

class ProcessLauncher:
    def __init__(self, base: Path, args, clock: ClockAnchor,
                 log: GzipLog, mirror: LiveMirror, stop: threading.Event):
        self._base   = base
        self._args   = args
        self._clock  = clock
        self._log    = log
        self._mirror = mirror
        self._stop   = stop
        self._procs  = {}   # name → subprocess.Popen
        self._lock   = threading.Lock()

    def _py(self, script: str) -> str:
        return str(self._base / script)

    def _launch(self, name: str, cmd: list, window_title: str):
        """Launch a subprocess in a new console window."""
        full_cmd = [
            "cmd", "/c",
            f"title {window_title} && python " + " ".join(
                f'"{c}"' if " " in str(c) else str(c) for c in cmd
            )
        ]
        try:
            proc = subprocess.Popen(
                full_cmd,
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            with self._lock:
                self._procs[name] = proc
            wall_ns, wall_iso = self._clock.now()
            rec = {
                "type":     "process_launched",
                "_stream":  "sentinel",
                "wall_ns":  wall_ns,
                "wall_iso": wall_iso,
                "name":     name,
                "pid":      proc.pid,
                "cmd":      " ".join(str(c) for c in cmd)[:512],
            }
            self._log.write(rec)
            self._mirror.write(rec)
            print(f"[launcher] {name:20s} PID {proc.pid}")
            return proc
        except Exception as e:
            print(f"[launcher] FAILED {name}: {e}")
            return None

    def _wait_port(self, port: int, timeout: int = 30) -> bool:
        import socket
        for _ in range(timeout):
            try:
                s = socket.socket()
                s.settimeout(1)
                s.connect(("127.0.0.1", port))
                s.close()
                return True
            except OSError:
                time.sleep(1)
        return False

    def launch_all(self):
        a  = self._args
        b  = str(self._base)
        rt = str(self._base / "runtime")

        print("\n[launcher] Starting infrastructure...")

        # ── [1] gz_watch ─────────────────────────────────────────────────
        self._launch("gz_watch",
            ["python", self._py("gz_watch.py")],
            "CTW-gz_watch")
        time.sleep(2)

        # ── [2] live_reader :8080 ─────────────────────────────────────────
        self._launch("live_reader",
            ["python", self._py("live_reader.py")],
            "CTW-live_reader")
        if not self._wait_port(8080):
            print("[launcher] WARN: live_reader :8080 not ready")

        # ── [3] rf_server :8000 ──────────────────────────────────────────
        self._launch("rf_server",
            ["python", self._py("rf_server.py")],
            "CTW-rf_server")
        if not self._wait_port(8000):
            print("[launcher] WARN: rf_server :8000 not ready")

        # ── [4] correlator ───────────────────────────────────────────────
        self._launch("correlator",
            ["python", self._py("correlator.py"),
             "--rf-live", f"{rt}\\sweep_live.jsonl",
             "--out",     rt,
             "--window",  "0.5",
             "--spike",   "0.10"],
            "CTW-correlator")
        time.sleep(1)

        print("[launcher] Starting RF sweep...")

        # ── [5] pluto_sweep — wideband ───────────────────────────────────
        self._launch("pluto_sweep",
            ["python", self._py("pluto_sweep.py"),
             "--out",   b,
             "--start", "70000000",
             "--stop",  "6000000000",
             "--step",  "500000",
             "--no-iq"],
            "CTW-sweep")
        time.sleep(1)

        # ── [6] bt_scanner ───────────────────────────────────────────────
        self._launch("bt_scanner",
            ["python", self._py("bt_scanner.py"),
             "--out",              b,
             "--rssi-threshold",   "-75"],
            "CTW-bt")

        # ── [7] css_hunter ───────────────────────────────────────────────
        cmd7 = ["python", self._py("css_hunter.py"),
                "--out",        b,
                "--bands",      "2", "4", "5", "12", "13", "66", "71",
                "--dwell-ms",   "15",
                "--anomaly-db", "10"]
        if a.at_port:
            cmd7 += ["--at-port", a.at_port]
        self._launch("css_hunter", cmd7, "CTW-css")

        # ── [8] css_idle_hunter ──────────────────────────────────────────
        self._launch("css_idle_hunter",
            ["python", self._py("css_idle_hunter.py"),
             "--out",           b,
             "--sensitivity",   "8",
             "--persist-min",   "2"],
            "CTW-css-idle")

        print("[launcher] Starting GNSS stack...")

        # ── [9] ublox_data ───────────────────────────────────────────────
        self._launch("ublox_data",
            ["python", self._py("ublox_data.py")],
            "CTW-ublox_data")
        time.sleep(5)

        # ── [10] ublox_parser ────────────────────────────────────────────
        cmd10 = ["python", self._py("ublox_parser.py"),
                 "--ubx-dir", f"{b}\\UBLOX",
                 "--out",     f"{b}\\UBLOX"]
        if a.compass_port:
            cmd10 += ["--compass-port", a.compass_port]
        self._launch("ublox_parser", cmd10, "CTW-ublox")
        time.sleep(2)

        # ── [11] gnss_server :8001 ───────────────────────────────────────
        self._launch("gnss_server",
            ["python", self._py("gnss_server.py")],
            "CTW-gnss")
        if not self._wait_port(8001):
            print("[launcher] WARN: gnss_server :8001 not ready")

        print("[launcher] Starting 60GHz sensor...")

        # ── [12/15] hlk_ld6002b — forensic scan ─────────────────────────
        if a.mmwave_port:
            cmd15 = ["python", self._py("hlk_ld6002b.py"),
                     "--phase", "scan",
                     "--port",  a.mmwave_port,
                     "--out",   b]
            if a.room_x: cmd15 += ["--room-x", str(a.room_x)]
            if a.room_y: cmd15 += ["--room-y", str(a.room_y)]
            if a.room_z: cmd15 += ["--room-z", str(a.room_z)]
            if a.mount_x: cmd15 += ["--mount-x", str(a.mount_x)]
            if a.mount_y: cmd15 += ["--mount-y", str(a.mount_y)]
            self._launch("hlk_ld6002b", cmd15, "CTW-mmwave")
        else:
            print("[launcher] SKIP hlk_ld6002b (--mmwave-port not set)")

        print("[launcher] Starting broadcast monitor...")

        # ── [20] broadcast_monitor ───────────────────────────────────────
        self._launch("broadcast_monitor",
            ["python", self._py("broadcast_monitor.py"),
             "--lat",         str(a.lat),
             "--lon",         str(a.lon),
             "--radius-km",   "150",
             "--bands",       "FM", "AM",
             "--anomaly-db",  "6",
             "--out",         b],
            "CTW-bcast")
        time.sleep(2)

        # ── [21] broadcast_map_server :8002 ──────────────────────────────
        self._launch("broadcast_map_server",
            ["python", self._py("broadcast_map_server.py")],
            "CTW-bcast-map")
        if not self._wait_port(8002):
            print("[launcher] WARN: broadcast_map_server :8002 not ready")

        print("[launcher] Starting WiFi sentinel...")

        # ── [23] wifi_sentinel ───────────────────────────────────────────
        cmd23 = ["python", self._py("wifi_sentinel.py"),
                 "--out",              b,
                 "--timing-window-ms", "150",
                 "--deauth-threshold", "3"]
        if a.iface1:       cmd23 += ["--iface1",       a.iface1]
        if a.iface2:       cmd23 += ["--iface2",       a.iface2]
        if a.home_ssid:    cmd23 += ["--home-ssid",    a.home_ssid]
        if a.home_bssid:   cmd23 += ["--home-bssid",   a.home_bssid]
        if a.home_channel: cmd23 += ["--home-channel",  str(a.home_channel)]
        if a.home_rssi:    cmd23 += ["--home-rssi",     str(a.home_rssi)]
        self._launch("wifi_sentinel", cmd23, "CTW-wifi")

        print("[launcher] All processes launched.\n")

    def monitor(self):
        """
        Watchdog thread — checks every 30s that critical processes
        are still alive. Logs restarts as sentinel events.
        """
        critical = {"gz_watch", "rf_server", "pluto_sweep",
                    "css_hunter", "wifi_sentinel", "broadcast_monitor"}
        while not self._stop.is_set():
            time.sleep(30)
            with self._lock:
                for name, proc in self._procs.items():
                    if name not in critical:
                        continue
                    if proc.poll() is not None:
                        wall_ns, wall_iso = self._clock.now()
                        rec = {
                            "type":      "process_died",
                            "_stream":   "sentinel",
                            "wall_ns":   wall_ns,
                            "wall_iso":  wall_iso,
                            "name":      name,
                            "returncode": proc.returncode,
                        }
                        self._log.write(rec)
                        self._mirror.write(rec)
                        print(f"[watchdog] *** {name} died "
                              f"(rc={proc.returncode}) — logged")

    def terminate_all(self):
        with self._lock:
            for name, proc in self._procs.items():
                try:
                    proc.terminate()
                except Exception:
                    pass
        print("[launcher] All child processes terminated.")


# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT ENGINE
# Core correlation and incident detection logic.
# ══════════════════════════════════════════════════════════════════════════════

class IncidentEngine:
    def __init__(self, clock: ClockAnchor, log: GzipLog,
                 mirror: LiveMirror, incident_dir: Path,
                 report_path: Path, args):
        self._clock        = clock
        self._log          = log
        self._mirror       = mirror
        self._incident_dir = incident_dir
        self._report_path  = report_path
        self._args         = args

        # rolling event window: deque of Event, bounded by time
        self._event_window = deque(maxlen=2000)
        self._window_lock  = threading.Lock()

        # incident tracking
        self._incidents         = []
        self._incident_lock     = threading.Lock()
        self._fired_signatures  = {}    # sig_name → last fired wall_ns
        self._incident_count    = 0

        # per-stream anomaly counters for session stats
        self._stream_counts = defaultdict(int)

        # SHA-256 chain for evidence integrity
        self._chain_prev   = "GENESIS"
        self._chain_seq    = 0

    # ── event ingestion ───────────────────────────────────────────────────

    def ingest(self, raw: dict, stream_tag: str):
        """
        Called by LiveTailer for every record from every live feed.
        Filters for anomaly records, constructs Event, runs correlation.
        """
        # only process anomaly/incident records
        rtype = raw.get("type", "")
        if not any(kw in rtype for kw in
                   ("anomaly", "alert", "incident", "ROGUE",
                    "SUSPECT", "spike", "corr", "CORR",
                    "spoof", "jam", "STATIC_EMITTER",
                    "BEACON_DATA", "DEAUTH", "EVIL_TWIN",
                    "TIMING_CORR", "station_anomaly")):
            return

        try:
            rec = _oob_rec(raw)
        except ValueError as e:
            wall_ns, wall_iso = self._clock.now()
            self._log.write({
                "type":     "oob_violation",
                "_stream":  "sentinel",
                "wall_ns":  wall_ns,
                "wall_iso": wall_iso,
                "detail":   str(e)[:256],
                "stream":   stream_tag,
            })
            return

        anomaly_class = rec.get("anomaly_class",
                         rec.get("type", "UNKNOWN")).upper()
        weight = ANOMALY_WEIGHTS.get(
                     anomaly_class,
                     ANOMALY_WEIGHTS["_DEFAULT"])

        stream = _oob_stream(rec.get("_stream", stream_tag))
        layer_num, layer_label = STREAM_LAYER_MAP.get(
            stream, (24, "Unknown"))

        wall_ns = rec.get("wall_ns", 0)
        if wall_ns == 0:
            wall_ns, _ = self._clock.now()
        wall_iso = rec.get("wall_iso", self._clock._iso(wall_ns))

        event = Event(
            wall_ns       = wall_ns,
            wall_iso      = wall_iso,
            stream        = stream,
            layer         = layer_num,
            layer_label   = layer_label,
            anomaly_class = anomaly_class,
            weight        = weight,
            raw           = rec,
        )

        # chain the event into the evidence log
        self._chain_event(event)

        with self._window_lock:
            self._event_window.append(event)
            self._stream_counts[stream] += 1

        # log every event to forensic log
        erec = {
            "type":          "sentinel_event",
            "_stream":       "sentinel",
            "wall_ns":       wall_ns,
            "wall_iso":      wall_iso,
            "layer":         layer_num,
            "layer_label":   layer_label,
            "anomaly_class": anomaly_class,
            "weight":        weight,
            "evidence_hash": event.evidence_hash,
            "stream":        stream,
            "detail":        rec.get("detail", "")[:256],
        }
        self._log.write(erec)
        self._mirror.write(erec)

        print(f"[engine] L{layer_num:02d}/{stream:<12} "
              f"{anomaly_class:<35} w={weight}")

        # run incident correlation
        self._correlate(event)

    def _chain_event(self, event: Event):
        """SHA-256 chain-link this event to previous."""
        self._chain_seq += 1
        chain_input = (f"{self._chain_prev}|"
                       f"{self._chain_seq}|"
                       f"{event.evidence_hash}")
        chain_hash = hashlib.sha256(
            chain_input.encode()).hexdigest()

        wall_ns, wall_iso = self._clock.now()
        chain_rec = {
            "type":          "chain_link",
            "_stream":       "sentinel",
            "wall_ns":       wall_ns,
            "wall_iso":      wall_iso,
            "seq":           self._chain_seq,
            "prev_hash":     self._chain_prev,
            "event_hash":    event.evidence_hash,
            "chain_hash":    chain_hash,
            "anomaly_class": event.anomaly_class,
            "stream":        event.stream,
        }
        self._log.write(chain_rec)
        self._chain_prev = chain_hash

    # ── correlation engine ────────────────────────────────────────────────

    def _correlate(self, trigger: Event):
        """
        For each incident signature, check if the current event window
        satisfies the required conditions.
        """
        now_ns = trigger.wall_ns

        for (sig_name, req_streams, min_score,
             window_ms, description) in INCIDENT_SIGNATURES:

            window_ns = window_ms * 1_000_000
            cutoff_ns = now_ns - window_ns

            # cooldown: don't re-fire same signature within 60s
            last_fired = self._fired_signatures.get(sig_name, 0)
            if now_ns - last_fired < 60_000_000_000:
                continue

            with self._window_lock:
                # collect events within window
                window_events = [
                    e for e in self._event_window
                    if e.wall_ns >= cutoff_ns
                ]

            # check required streams present
            present_streams = {e.stream for e in window_events}
            if not req_streams.issubset(present_streams):
                continue

            # score events from required streams
            score = sum(
                e.weight for e in window_events
                if e.stream in req_streams
            )

            if score < min_score:
                continue

            # INCIDENT CONFIRMED
            self._fired_signatures[sig_name] = now_ns
            self._raise_incident(
                sig_name    = sig_name,
                score       = score,
                events      = [e for e in window_events
                               if e.stream in req_streams],
                streams     = present_streams & req_streams,
                description = description,
                window_ms   = window_ms,
            )

    def _raise_incident(self, sig_name, score, events,
                        streams, description, window_ms):
        """
        Raise a confirmed incident, write evidence package,
        update report.
        """
        self._incident_count += 1
        wall_ns, wall_iso = self._clock.now()

        # tier classification
        layer_count = len(streams)
        if layer_count >= 3 or score >= 24:
            tier = 1
        elif layer_count == 2 or score >= 14:
            tier = 2
        else:
            tier = 3

        incident_id = (f"INC-{wall_iso[:10].replace('-','')}"
                       f"-{self._incident_count:04d}")

        incident = Incident(
            incident_id = incident_id,
            wall_ns     = wall_ns,
            wall_iso    = wall_iso,
            signature   = sig_name,
            tier        = tier,
            score       = score,
            streams     = streams,
            events      = events,
            description = description,
        )

        with self._incident_lock:
            self._incidents.append(incident)

        # ── console alert ─────────────────────────────────────────────
        tier_colors = {1: "\033[91m", 2: "\033[93m", 3: "\033[96m"}
        reset = "\033[0m"
        color = tier_colors.get(tier, "")
        print()
        print(f"{color}{'═'*68}")
        print(f"  *** INCIDENT DETECTED ***")
        print(f"  ID        : {incident_id}")
        print(f"  TIER      : {incident.tier_label()}")
        print(f"  SIGNATURE : {sig_name}")
        print(f"  SCORE     : {score}")
        print(f"  LAYERS    : {sorted(streams)}")
        print(f"  EVENTS    : {len(events)} in {window_ms}ms window")
        print(f"  CHAIN     : {incident.chain_hash[:16]}...")
        print(f"  {description}")
        print(f"{'═'*68}{reset}")
        print()

        # ── forensic log ──────────────────────────────────────────────
        irec = {
            "type":     "incident",
            "_stream":  "sentinel",
            **incident.to_dict(),
        }
        self._log.write(irec)
        self._mirror.write(irec)

        # ── evidence package ──────────────────────────────────────────
        pkg_path = (self._incident_dir /
                    f"{incident_id}_{sig_name}.json")
        try:
            with open(pkg_path, "w", encoding="utf-8") as f:
                json.dump(incident.to_dict(), f, indent=2)
            print(f"[engine] Evidence package: {pkg_path.name}")
        except Exception as e:
            print(f"[engine] Evidence write error: {e}")

        # ── update running report ─────────────────────────────────────
        self._update_report()

    # ── report writer ─────────────────────────────────────────────────────

    def _update_report(self):
        """Rewrite the human-readable report after each incident."""
        wall_ns, wall_iso = self._clock.now()
        with self._incident_lock:
            incidents = list(self._incidents)

        lines = [
            "=" * 68,
            "  CTW SENTINEL AUTONOMOUS — INCIDENT REPORT",
            f"  Generated : {wall_iso}",
            f"  Session   : {self._clock.session}",
            f"  Incidents : {len(incidents)}",
            "=" * 68,
            "",
        ]

        tier_labels = {
            1: "TIER 1 — CONFIRMED",
            2: "TIER 2 — PROBABLE",
            3: "TIER 3 — WATCH",
        }

        for tier in (1, 2, 3):
            tier_incs = [i for i in incidents if i.tier == tier]
            if not tier_incs:
                continue
            lines.append(f"  {tier_labels[tier]} ({len(tier_incs)})")
            lines.append("  " + "-" * 64)
            for inc in tier_incs:
                lines.append(f"  {inc.incident_id}")
                lines.append(f"    Signature : {inc.signature}")
                lines.append(f"    Time      : {inc.wall_iso}")
                lines.append(f"    Score     : {inc.score}  "
                             f"Layers: {sorted(inc.streams)}")
                lines.append(f"    Events    : {inc.event_count}")
                lines.append(f"    Chain     : {inc.chain_hash[:32]}...")
                lines.append(f"    Detail    : {inc.description}")
                lines.append("")
            lines.append("")

        lines.append("  EVENT COUNTS BY STREAM")
        lines.append("  " + "-" * 40)
        with self._window_lock:
            for stream, count in sorted(
                    self._stream_counts.items(),
                    key=lambda x: -x[1]):
                layer_num, label = STREAM_LAYER_MAP.get(
                    stream, (0, stream))
                lines.append(
                    f"  L{layer_num:02d} {stream:<14} {count:>6} events  "
                    f"{label}")
        lines.append("")
        lines.append("=" * 68)

        try:
            self._report_path.write_text(
                "\n".join(lines), encoding="utf-8")
        except Exception as e:
            print(f"[engine] Report write error: {e}")

    # ── periodic status ───────────────────────────────────────────────────

    def status_loop(self, stop: threading.Event):
        """Print a rolling status summary every 60 seconds."""
        while not stop.is_set():
            stop.wait(60)
            if stop.is_set():
                break
            wall_ns, wall_iso = self._clock.now()
            with self._window_lock:
                w_size = len(self._event_window)
                counts = dict(self._stream_counts)
            with self._incident_lock:
                n_inc = len(self._incidents)
                tiers = {1: 0, 2: 0, 3: 0}
                for i in self._incidents:
                    tiers[i.tier] = tiers.get(i.tier, 0) + 1

            print()
            print(f"[status] {wall_iso}  "
                  f"window={w_size}  "
                  f"incidents={n_inc} "
                  f"(T1={tiers[1]} T2={tiers[2]} T3={tiers[3]})")
            for stream, cnt in sorted(counts.items(), key=lambda x: -x[1]):
                if cnt > 0:
                    print(f"         {stream:<14} {cnt} anomalies")
            print()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="CTW Sentinel Autonomous — 24-Layer Incident Detection"
    )

    # location
    ap.add_argument("--lat",  type=float, default=33.800509,
        help="Observer latitude  (default 33.800509)")
    ap.add_argument("--lon",  type=float, default=-117.220352,
        help="Observer longitude (default -117.220352)")

    # WiFi
    ap.add_argument("--iface1",       default=None,
        help="Primary WiFi adapter name")
    ap.add_argument("--iface2",       default=None,
        help="Secondary WiFi adapter name")
    ap.add_argument("--home-ssid",    default=None,
        help="Legitimate network SSID")
    ap.add_argument("--home-bssid",   default=None,
        help="Legitimate AP BSSID  AA:BB:CC:DD:EE:FF")
    ap.add_argument("--home-channel", type=int, default=None,
        help="Home channel number")
    ap.add_argument("--home-rssi",    type=float, default=None,
        help="Expected home AP RSSI dBm")

    # cell
    ap.add_argument("--at-port", default=None,
        help="Modem AT port  COM8 / localhost:5555")

    # GNSS
    ap.add_argument("--compass-port", default=None,
        help="compass_bridge.py port  localhost:5556")

    # 60GHz
    ap.add_argument("--mmwave-port", default=None,
        help="HLK-LD6002B serial port  COM5")
    ap.add_argument("--room-x",  type=int, default=None)
    ap.add_argument("--room-y",  type=int, default=None)
    ap.add_argument("--room-z",  type=int, default=None)
    ap.add_argument("--mount-x", type=int, default=None)
    ap.add_argument("--mount-y", type=int, default=None)

    # operational
    ap.add_argument("--out",          default=r"C:\sdr\logs",
        help=r"Base output directory (default C:\sdr\logs)")
    ap.add_argument("--no-launch",    action="store_true",
        help="Skip launching child processes (attach to running session)")
    ap.add_argument("--correlation-window-ms", type=float, default=2000,
        help="Global correlation window ms (default 2000)")

    args = ap.parse_args()

    # ── validate ─────────────────────────────────────────────────────────
    args.lat = _oob_float(args.lat, -90.0,  90.0,  "lat")
    args.lon = _oob_float(args.lon, -180.0, 180.0, "lon")

    # ── paths ─────────────────────────────────────────────────────────────
    base         = Path(args.out)
    runtime      = base / "runtime"
    incident_dir = base / "incidents"
    for d in (base, runtime, incident_dir, base / "UBLOX"):
        d.mkdir(parents=True, exist_ok=True)

    clock       = ClockAnchor()
    stamp       = clock.session
    gz_path     = base / f"sentinel_auto_{stamp}.jsonl.gz"
    lj_path     = runtime / "sentinel_live.jsonl"
    report_path = base / f"sentinel_report_{stamp}.txt"

    log    = GzipLog(gz_path)
    mirror = LiveMirror(lj_path)

    # ── session start ─────────────────────────────────────────────────────
    wall_ns, wall_iso = clock.now()
    start_rec = {
        "type":     "session_start",
        "_stream":  "sentinel",
        "wall_ns":  wall_ns,
        "wall_iso": wall_iso,
        "session":  stamp,
        "lat":      args.lat,
        "lon":      args.lon,
        "home_ssid":    args.home_ssid,
        "home_bssid":   args.home_bssid,
        "home_channel": args.home_channel,
        "at_port":      args.at_port,
        "mmwave_port":  args.mmwave_port,
    }
    log.write(start_rec)
    mirror.write(start_rec)

    print()
    print("=" * 68)
    print("  CTW SENTINEL AUTONOMOUS — 24-LAYER INCIDENT DETECTION")
    print(f"  Session   : {stamp}")
    print(f"  Position  : {args.lat}, {args.lon}")
    print(f"  Log       : {gz_path.name}")
    print(f"  Report    : {report_path.name}")
    print(f"  Incidents : {incident_dir}")
    print("=" * 68)
    print()

    stop   = threading.Event()
    engine = IncidentEngine(clock, log, mirror, incident_dir,
                            report_path, args)

    # ── signal handler ────────────────────────────────────────────────────
    def _shutdown(sig, frame):
        print("\n[sentinel] Shutdown signal received...")
        stop.set()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── launch child processes ────────────────────────────────────────────
    launcher = None
    if not args.no_launch:
        launcher = ProcessLauncher(base, args, clock, log, mirror, stop)
        launcher.launch_all()

        # watchdog
        wd = threading.Thread(target=launcher.monitor,
                              daemon=True, name="watchdog")
        wd.start()

        # allow processes to settle before tailing
        print("[sentinel] Waiting 8s for processes to settle...")
        time.sleep(8)

    # ── live feed tailers — one per stream ────────────────────────────────
    live_feeds = {
        "sweep":      runtime / "sweep_live.jsonl",
        "bt":         runtime / "bt_live.jsonl",
        "css":        runtime / "css_live.jsonl",
        "css_idle":   runtime / "css_idle_live.jsonl",
        "gnss":       runtime / "gnss_live.jsonl",
        "mmwave":     runtime / "mmwave_live.jsonl",
        "broadcast":  runtime / "broadcast_live.jsonl",
        "wifi":       runtime / "wifi_live.jsonl",
        "correlator": runtime / "corr_live.jsonl",
    }

    tailers = []
    for stream_tag, feed_path in live_feeds.items():
        t = LiveTailer(feed_path, engine.ingest,
                       stream_tag, stop)
        t.start()
        tailers.append(t)

    # ── status loop ───────────────────────────────────────────────────────
    status_thread = threading.Thread(
        target=engine.status_loop,
        args=(stop,),
        daemon=True,
        name="status"
    )
    status_thread.start()

    print("[sentinel] All tailers active. Monitoring 24 layers.")
    print("[sentinel] Ctrl+C to stop.\n")

    # ── wait ──────────────────────────────────────────────────────────────
    while not stop.is_set():
        time.sleep(1)

    # ── shutdown ──────────────────────────────────────────────────────────
    print("[sentinel] Stopping tailers...")
    for t in tailers:
        t.join(timeout=5)

    if launcher:
        launcher.terminate_all()

    # final report
    engine._update_report()
    print(f"[sentinel] Report written: {report_path}")

    wall_ns, wall_iso = clock.now()
    end_rec = {
        "type":           "session_end",
        "_stream":        "sentinel",
        "wall_ns":        wall_ns,
        "wall_iso":       wall_iso,
        "incident_count": engine._incident_count,
        "chain_seq":      engine._chain_seq,
        "final_hash":     engine._chain_prev,
    }
    log.write(end_rec)
    mirror.write(end_rec)
    log.close()
    mirror.close()

    print(f"[sentinel] Session complete.")
    print(f"           Incidents : {engine._incident_count}")
    print(f"           Chain seq : {engine._chain_seq}")
    print(f"           Chain tip : {engine._chain_prev[:32]}...")
    print(f"           Log       : {gz_path}")


if __name__ == "__main__":
    main()
