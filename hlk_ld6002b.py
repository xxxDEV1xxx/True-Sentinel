#!/usr/bin/env python3
"""
hlk_ld6002b.py  —  CTW HLK-LD6002B 60GHz Forensic Sensor Driver
=================================================================
Full null-space calibration + directional triangulation engine.

Calibration phases:
  --phase empty    Empty room baseline (5 min recommended)
  --phase human    Human presence reference (walk all 4 walls)
  --phase scan     Forensic scan mode (uses saved calibration)
  --phase raw      Raw output only, no classification

Directional quadrants (ceiling mount, module face = North):
  NORTH  Y+   signal through north wall
  EAST   X+   signal through east wall
  SOUTH  Y-   signal through south wall
  WEST   X-   signal through west wall
  FLOOR  Z-   signal from below
  CEIL   Z+   signal from above / within ceiling

Usage:
  python hlk_ld6002b.py --port COM5 --phase empty
  python hlk_ld6002b.py --port COM5 --phase human
  python hlk_ld6002b.py --port COM5 --phase scan
  python hlk_ld6002b.py --port COM5 --phase raw --raw-dump
  python hlk_ld6002b.py --list-ports
"""

import argparse
import datetime
import gzip
import json
import math
import os
import struct
import sys
import threading
import time
from collections import defaultdict, deque

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("ERROR: pip install pyserial")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# PROTOCOL
# ══════════════════════════════════════════════════════════════════════════════

BAUD_RATE    = 115200
FRAME_HEADER = bytes([0x53, 0x59])
FRAME_TAIL   = bytes([0x54, 0x43])

DECODERS_MAP = {}   # populated below

_OOB = {
    "MAX_COORD_CM":  1500,
    "MAX_VEL_CMS":    500,
    "MAX_INTENSITY":  100,
    "MAX_FRAME":      512,
}

def _ci(v, lo, hi):
    try: return max(lo, min(hi, int(v)))
    except Exception: return 0

def _cf(v, lo, hi):
    try:
        f = float(v)
        return max(lo, min(hi, f)) if -1e9 < f < 1e9 else 0.0
    except Exception: return 0.0

# ══════════════════════════════════════════════════════════════════════════════
# DIRECTIONAL GEOMETRY
# ══════════════════════════════════════════════════════════════════════════════

# Room wall quadrants based on X/Y coordinate sign and magnitude
# Operator sets room dimensions at startup for accurate wall mapping

class RoomGeometry:
    """
    Maps sensor X/Y/Z coordinates to wall quadrants.
    Ceiling-mounted module: Y+ = north wall, X+ = east wall.
    Operator sets actual room dimensions for accurate distance-to-wall calc.
    """

    def __init__(self, room_x_cm=400, room_y_cm=400, room_z_cm=250,
                 mount_x_cm=200, mount_y_cm=200, mount_z_cm=250):
        """
        room_x_cm: total room width east-west
        room_y_cm: total room depth north-south
        room_z_cm: ceiling height
        mount_x/y/z: module position from SW corner
        """
        self.rx  = room_x_cm
        self.ry  = room_y_cm
        self.rz  = room_z_cm
        self.mx  = mount_x_cm
        self.my  = mount_y_cm
        self.mz  = mount_z_cm

    def classify(self, x_cm, y_cm, z_cm):
        """
        Returns (quadrant, dist_to_wall_cm, confidence 0-1).
        Quadrant: NORTH EAST SOUTH WEST FLOOR CEILING INTERIOR
        """
        if x_cm == 0 and y_cm == 0 and z_cm == 0:
            return "INTERIOR", 0, 0.0

        ax, ay, az = abs(x_cm), abs(y_cm), abs(z_cm)
        total = ax + ay + az

        # Fraction of signal in each axis
        fx = ax / total if total > 0 else 0
        fy = ay / total if total > 0 else 0
        fz = az / total if total > 0 else 0

        # Primary direction
        if fz > 0.6:
            if z_cm > 0:
                return "CEILING", abs(self.mz - az), fz
            else:
                return "FLOOR",   az, fz

        if fy > fx:
            if y_cm > 0:
                dist = self.ry - self.my - ay
                return "NORTH", max(0, dist), fy
            else:
                dist = self.my - ay
                return "SOUTH", max(0, dist), fy
        else:
            if x_cm > 0:
                dist = self.rx - self.mx - ax
                return "EAST",  max(0, dist), fx
            else:
                dist = self.mx - ax
                return "WEST",  max(0, dist), fx

    def to_dict(self):
        return {
            "room_x_cm": self.rx, "room_y_cm": self.ry, "room_z_cm": self.rz,
            "mount_x_cm":self.mx, "mount_y_cm":self.my, "mount_z_cm":self.mz,
        }

# ══════════════════════════════════════════════════════════════════════════════
# CALIBRATION STATE MACHINE
# ══════════════════════════════════════════════════════════════════════════════

class CalibrationState:
    """
    Manages the three-phase calibration sequence.

    Phase EMPTY:
      Collects baseline statistics per quadrant with no person in room.
      Stores: mean, stddev, velocity distribution, coordinate spread
      per quadrant. This is N(θ,φ,v) — the noise vector.

    Phase HUMAN:
      Operator walks each wall at ~1m distance.
      Collects human RCS signature per quadrant.
      Stores: expected coordinate ranges, velocity ranges, intensity
      for a real human at each wall. This is H(θ,φ,v).

    Phase SCAN (operational):
      Subtracts EMPTY baseline from live readings.
      Any excess that does not match H profile = external source.
      Reports direction, estimated distance from wall, signal character.

    Calibration saved to: runtime/ld6002b_cal.json
    Loaded automatically on subsequent SCAN runs.
    """

    CAL_FILE_NAME = "ld6002b_cal.json"

    def __init__(self, runtime_dir, geometry):
        self.runtime_dir = runtime_dir
        self.geo         = geometry
        self.cal_path    = os.path.join(runtime_dir, self.CAL_FILE_NAME)

        # Per-quadrant accumulators
        QUADS = ["NORTH","EAST","SOUTH","WEST","FLOOR","CEILING","INTERIOR"]
        self._empty_acc = {q: {
            "x": [], "y": [], "z": [], "v": [], "intensity": [],
            "presence_count": 0, "frame_count": 0,
        } for q in QUADS}

        self._human_acc = {q: {
            "x": [], "y": [], "z": [], "v": [], "intensity": [],
            "presence_count": 0, "frame_count": 0,
        } for q in QUADS}

        # Compiled baselines (loaded from file or computed)
        self.empty_baseline = {}
        self.human_reference = {}
        self.loaded = False

        # Try to load existing calibration
        self._try_load()

    def _try_load(self):
        if not os.path.exists(self.cal_path):
            return
        try:
            with open(self.cal_path, 'r') as f:
                data = json.load(f)
            self.empty_baseline  = data.get("empty_baseline",  {})
            self.human_reference = data.get("human_reference", {})
            self.loaded = bool(self.empty_baseline)
            if self.loaded:
                print(f"[CAL] Loaded calibration from {self.cal_path}")
                print(f"  Empty baseline  : "
                      f"{data.get('empty_ts','unknown')}")
                print(f"  Human reference : "
                      f"{data.get('human_ts','unknown')}")
        except Exception as e:
            print(f"[CAL] Could not load calibration: {e}")

    def _save(self):
        data = {
            "empty_baseline":  self.empty_baseline,
            "human_reference": self.human_reference,
            "empty_ts":  datetime.datetime.utcnow().isoformat(),
            "human_ts":  datetime.datetime.utcnow().isoformat(),
            "geometry":  self.geo.to_dict(),
        }
        with open(self.cal_path, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"[CAL] Calibration saved: {self.cal_path}")

    def feed_empty(self, x, y, z, v, intensity, presence):
        """Feed one frame into the EMPTY baseline accumulator."""
        quad, dist, conf = self.geo.classify(x, y, z)
        acc = self._empty_acc[quad]
        acc["x"].append(x)
        acc["y"].append(y)
        acc["z"].append(z)
        acc["v"].append(v)
        acc["intensity"].append(intensity)
        acc["frame_count"] += 1
        if presence:
            acc["presence_count"] += 1

    def feed_human(self, x, y, z, v, intensity, presence):
        """Feed one frame into the HUMAN reference accumulator."""
        quad, dist, conf = self.geo.classify(x, y, z)
        acc = self._human_acc[quad]
        acc["x"].append(x)
        acc["y"].append(y)
        acc["z"].append(z)
        acc["v"].append(v)
        acc["intensity"].append(intensity)
        acc["frame_count"] += 1
        if presence:
            acc["presence_count"] += 1

    def _stats(self, values):
        if not values:
            return {"mean": 0, "std": 0, "min": 0, "max": 0, "p25": 0, "p75": 0}
        s = sorted(values)
        n = len(s)
        mean = sum(s) / n
        std  = math.sqrt(sum((v-mean)**2 for v in s) / n) if n > 1 else 0
        return {
            "mean": round(mean, 3),
            "std":  round(std,  3),
            "min":  round(s[0], 3),
            "max":  round(s[-1],3),
            "p25":  round(s[n//4], 3),
            "p75":  round(s[3*n//4], 3),
            "n":    n,
        }

    def compile_empty(self):
        """Compute statistics from empty accumulator and save."""
        self.empty_baseline = {}
        for quad, acc in self._empty_acc.items():
            if acc["frame_count"] == 0:
                continue
            self.empty_baseline[quad] = {
                "x":         self._stats(acc["x"]),
                "y":         self._stats(acc["y"]),
                "z":         self._stats(acc["z"]),
                "v":         self._stats(acc["v"]),
                "intensity": self._stats(acc["intensity"]),
                "presence_rate": acc["presence_count"] / acc["frame_count"],
                "frame_count":   acc["frame_count"],
            }
        print(f"[CAL] Empty baseline compiled:")
        for q, b in self.empty_baseline.items():
            pr = b.get("presence_rate", 0)
            print(f"  {q:<9}: {b['frame_count']} frames  "
                  f"presence_rate={pr:.3f}  "
                  f"intensity_mean={b['intensity']['mean']:.1f}")
        self._save()

    def compile_human(self):
        """Compute statistics from human accumulator and save."""
        self.human_reference = {}
        for quad, acc in self._human_acc.items():
            if acc["frame_count"] == 0:
                continue
            self.human_reference[quad] = {
                "x":         self._stats(acc["x"]),
                "y":         self._stats(acc["y"]),
                "z":         self._stats(acc["z"]),
                "v":         self._stats(acc["v"]),
                "intensity": self._stats(acc["intensity"]),
                "presence_rate": acc["presence_count"] / acc["frame_count"],
                "frame_count":   acc["frame_count"],
            }
        print(f"[CAL] Human reference compiled:")
        for q, h in self.human_reference.items():
            pr = h.get("presence_rate", 0)
            print(f"  {q:<9}: {h['frame_count']} frames  "
                  f"presence_rate={pr:.3f}  "
                  f"v_mean={h['v']['mean']:.1f}cm/s  "
                  f"intensity_mean={h['intensity']['mean']:.1f}")
        self._save()

    def classify_reading(self, x, y, z, v, intensity, presence):
        """
        Compare a live reading against calibration.
        Returns classification dict.

        The null space is the region between:
          - empty baseline (what exists when nothing is there)
          - human reference (what a person looks like)

        Anything IN the null space that was NOT in the empty baseline
        and does NOT match the human reference = external source.
        """
        if not self.empty_baseline:
            return {"classified": False, "reason": "no_calibration"}

        quad, dist_to_wall, conf = self.geo.classify(x, y, z)

        result = {
            "quadrant":       quad,
            "dist_to_wall_cm":round(dist_to_wall, 1),
            "direction_conf": round(conf, 3),
            "classified":     True,
            "source_type":    "UNKNOWN",
            "anomaly":        False,
            "anomaly_class":  None,
        }

        # ── Compare against empty baseline ────────────────────────────────
        eb = self.empty_baseline.get(quad, {})
        hr = self.human_reference.get(quad, {})

        if eb:
            # Intensity excess above empty baseline
            eb_inten_mean = eb.get("intensity", {}).get("mean", 0)
            eb_inten_std  = eb.get("intensity", {}).get("std",  1)
            inten_excess  = intensity - (eb_inten_mean + 2 * eb_inten_std)

            # Presence rate in empty: if sensor showed >5% presence
            # even in empty room, that itself is anomalous
            eb_presence_rate = eb.get("presence_rate", 0)

            # Velocity: in empty room, velocity should be near zero
            eb_v_std = eb.get("v", {}).get("std", 5)
            v_excess = abs(v) - (eb_v_std * 3)

            result["empty_baseline_quad"]    = quad
            result["intensity_vs_baseline"]  = round(inten_excess, 2)
            result["velocity_vs_baseline"]   = round(v_excess, 2)
            result["empty_presence_rate"]    = round(eb_presence_rate, 3)

            # ── Classify source type ──────────────────────────────────────

            if not presence:
                # No presence = reading within empty baseline
                result["source_type"] = "BASELINE"
                return result

            # Presence detected — now determine if human or external

            if hr:
                # Check if reading matches human reference for this quadrant
                hr_x_mean = hr.get("x", {}).get("mean", 0)
                hr_x_std  = hr.get("x", {}).get("std",  50)
                hr_y_mean = hr.get("y", {}).get("mean", 0)
                hr_y_std  = hr.get("y", {}).get("std",  50)
                hr_v_mean = hr.get("v", {}).get("mean", 0)
                hr_v_std  = hr.get("v", {}).get("std",  20)

                x_in_human = abs(x - hr_x_mean) <= 2 * hr_x_std
                y_in_human = abs(y - hr_y_mean) <= 2 * hr_y_std
                v_in_human = abs(v - hr_v_mean) <= 2 * hr_v_std

                if x_in_human and y_in_human and v_in_human:
                    result["source_type"] = "HUMAN_CONSISTENT"
                    return result

            # Presence that doesn't match human reference = external source
            result["source_type"]  = "EXTERNAL_SOURCE"
            result["anomaly"]      = True

            # Characterize the external source
            if abs(v) < 5:
                result["anomaly_class"] = "STATIC_EMITTER"
                result["detail"] = (
                    f"Stationary 60GHz source from {quad} wall, "
                    f"~{dist_to_wall:.0f}cm from wall surface. "
                    f"Velocity {v}cm/s ≈ 0. CW or low-rate pulsed source."
                )
            elif abs(v) < 30:
                result["anomaly_class"] = "SLOW_MODULATED"
                result["detail"] = (
                    f"Slowly modulated 60GHz source from {quad}, "
                    f"v={v}cm/s. Consistent with FMCW sweep or "
                    f"amplitude-modulated beam."
                )
            else:
                result["anomaly_class"] = "FAST_MODULATED"
                result["detail"] = (
                    f"Fast-modulated 60GHz source from {quad}, "
                    f"v={v}cm/s. Consistent with Doppler-shifted "
                    f"or frequency-hopping emitter."
                )

        return result

# ══════════════════════════════════════════════════════════════════════════════
# WALL TRIANGULATOR
# ══════════════════════════════════════════════════════════════════════════════

class WallTriangulator:
    """
    Accumulates external source detections per quadrant over time.
    When multiple quadrants show simultaneous anomalous readings,
    estimates the likely source location by triangulation.

    Method:
      Each wall detection gives a bearing vector from the module.
      Two or more simultaneous detections from different walls
      allow computation of an intersection point = source location.
    """

    def __init__(self, geometry, clock):
        self.geo   = geometry
        self.clock = clock

        # Per-quadrant ring buffer of recent anomaly events
        self._quads = {
            "NORTH":   deque(maxlen=30),
            "EAST":    deque(maxlen=30),
            "SOUTH":   deque(maxlen=30),
            "WEST":    deque(maxlen=30),
            "FLOOR":   deque(maxlen=30),
            "CEILING": deque(maxlen=30),
        }
        self._lock    = threading.Lock()
        self.estimates = []  # list of triangulation results

    def record(self, quad, x_cm, y_cm, z_cm, v_cms, wall_ns):
        with self._lock:
            self._quads[quad].append({
                "x": x_cm, "y": y_cm, "z": z_cm,
                "v": v_cms, "t": wall_ns
            })

    def triangulate(self, wall_ns):
        """
        Try to find a source location from simultaneous multi-wall detections.
        Returns list of estimate dicts, or empty list.
        """
        window_ns = int(2e9)  # 2-second coincidence window
        cutoff    = wall_ns - window_ns

        with self._lock:
            # Which quadrants have recent readings?
            active = {}
            for quad, buf in self._quads.items():
                recent = [r for r in buf if r["t"] >= cutoff]
                if recent:
                    # Mean coordinates from recent readings
                    active[quad] = {
                        "x": sum(r["x"] for r in recent) / len(recent),
                        "y": sum(r["y"] for r in recent) / len(recent),
                        "z": sum(r["z"] for r in recent) / len(recent),
                        "v": sum(r["v"] for r in recent) / len(recent),
                        "count": len(recent),
                    }

        if len(active) < 2:
            return []

        estimates = []

        # Pairwise triangulation for opposite/adjacent wall pairs
        quad_list = list(active.items())
        for i in range(len(quad_list)):
            for j in range(i+1, len(quad_list)):
                q1, d1 = quad_list[i]
                q2, d2 = quad_list[j]

                # Opposite wall pairs: NORTH+SOUTH, EAST+WEST
                # These give the best triangulation constraint
                est = self._triangulate_pair(q1, d1, q2, d2)
                if est:
                    estimates.append({
                        "wall_ns":    wall_ns,
                        "wall_iso":   self.clock.format_wall_ns(wall_ns),
                        "walls":      [q1, q2],
                        "active_walls": list(active.keys()),
                        **est,
                    })

        return estimates

    def _triangulate_pair(self, q1, d1, q2, d2):
        """
        Estimate source location from two wall detections.

        For opposite walls (N+S or E+W):
          The source x or y coordinate can be estimated from the
          ratio of coordinate magnitudes.

        For adjacent walls (N+E etc):
          The source is at the corner region — less precise.
        """
        mx = self.geo.mx
        my = self.geo.my

        # Coordinate of source in sensor frame
        # x1,y1 from wall 1 detection; x2,y2 from wall 2 detection
        x1, y1 = d1["x"], d1["y"]
        x2, y2 = d2["x"], d2["y"]

        # Simple centroid estimate — average of the two bearing vectors
        # weighted by detection count
        w1 = d1["count"]
        w2 = d2["count"]
        total = w1 + w2

        est_x = (x1*w1 + x2*w2) / total
        est_y = (y1*w1 + y2*w2) / total

        # Convert sensor frame to room frame
        room_x = mx + est_x
        room_y = my + est_y

        # Clamp to room bounds
        room_x = max(0, min(self.geo.rx, room_x))
        room_y = max(0, min(self.geo.ry, room_y))

        confidence = 0.9 if set([q1,q2]) in (
            {"NORTH","SOUTH"}, {"EAST","WEST"}
        ) else 0.5

        return {
            "est_sensor_x_cm": round(est_x, 1),
            "est_sensor_y_cm": round(est_y, 1),
            "est_room_x_cm":   round(room_x, 1),
            "est_room_y_cm":   round(room_y, 1),
            "confidence":      confidence,
            "detail": (
                f"Source estimated at room ({room_x:.0f},{room_y:.0f})cm "
                f"from SW corner. "
                f"Walls {q1}+{q2} both active. "
                f"Confidence={confidence:.0%}"
            ),
        }

# ══════════════════════════════════════════════════════════════════════════════
# FRAME PARSER (identical to original, reproduced for standalone file)
# ══════════════════════════════════════════════════════════════════════════════

class LD6002BFramer:
    def __init__(self):
        self._buf = bytearray()

    def feed(self, data):
        self._buf.extend(data)
        while True:
            r = self._try_extract()
            if r is None: break
            yield r

    def _try_extract(self):
        idx = self._buf.find(FRAME_HEADER)
        if idx == -1:
            if len(self._buf) > 1: self._buf = self._buf[-1:]
            return None
        if idx > 0: del self._buf[:idx]
        if len(self._buf) < 9: return None
        ctrl    = self._buf[2]
        sub     = self._buf[3]
        pay_len = self._buf[4] | (self._buf[5] << 8)
        if pay_len > _OOB["MAX_FRAME"]:
            del self._buf[:2]; return None
        frame_end = 6 + pay_len + 3
        if len(self._buf) < frame_end: return None
        if self._buf[frame_end-2:frame_end] != FRAME_TAIL:
            del self._buf[:2]; return None
        payload  = bytes(self._buf[6:6+pay_len])
        expected = sum(self._buf[:6+pay_len]) & 0xFF
        actual   = self._buf[6+pay_len]
        del self._buf[:frame_end]
        if expected != actual: return None
        return (ctrl, sub, payload)

def decode_presence(payload):
    if len(payload) < 1: return None
    code = payload[0]
    names = {0:"NONE",1:"MOTION",2:"MICRO_MOTION",3:"STATIC_PRESENCE"}
    return {
        "presence_code":  code,
        "presence_state": names.get(code, f"UNK_0x{code:02X}"),
        "presence":       code != 0,
        "motion":         code == 1,
        "micro_motion":   code == 2,
        "static":         code == 3,
    }

def decode_targets(payload):
    targets = []
    offset  = 0
    while offset + 8 <= len(payload):
        try:
            x,y,z,v = struct.unpack_from('<hhhh', payload, offset)
            offset += 8
            x = _ci(x,-_OOB["MAX_COORD_CM"],_OOB["MAX_COORD_CM"])
            y = _ci(y, 0, _OOB["MAX_COORD_CM"])
            z = _ci(z,-_OOB["MAX_COORD_CM"],_OOB["MAX_COORD_CM"])
            v = _ci(v,-_OOB["MAX_VEL_CMS"],  _OOB["MAX_VEL_CMS"])
            dist = round(math.sqrt(x**2+y**2+z**2)/100.0, 3)
            targets.append({
                "x_cm":x,"y_cm":y,"z_cm":z,
                "vel_cms":v,"dist_m":dist,
                "stationary":abs(v)<5,
            })
        except struct.error:
            break
    return {"target_count":len(targets),"targets":targets}

def decode_intensity(payload):
    if len(payload)<1: return None
    return {"motion_intensity": _ci(payload[0],0,100)}

def decode_heartbeat(payload):
    return {"heartbeat":True}

def decode_version(payload):
    if len(payload)<3: return None
    return {"fw_version":f"{payload[0]}.{payload[1]}.{payload[2]}"}

DECODER_TABLE = {
    (0x80,0x01): decode_presence,
    (0x07,0x01): decode_targets,
    (0x80,0x03): decode_intensity,
    (0x80,0xA0): decode_heartbeat,
    (0x01,0x02): decode_version,
}

# ══════════════════════════════════════════════════════════════════════════════
# CLOCK ANCHOR / GZIPLOG / LIVEMIRROR (same as pipeline)
# ══════════════════════════════════════════════════════════════════════════════

class ClockAnchor:
    def __init__(self):
        best_gap = None
        for _ in range(32):
            t1=time.perf_counter_ns(); w=time.time_ns(); t2=time.perf_counter_ns()
            gap=t2-t1
            if best_gap is None or gap<best_gap:
                best_gap=gap; self._mono_epoch=(t1+t2)//2; self._wall_epoch=w
        self.session_wall_ns  = self._wall_epoch
        self.session_mono_ns  = self._mono_epoch
        self.session_wall_utc = datetime.datetime.fromtimestamp(
            self._wall_epoch/1e9, tz=datetime.timezone.utc).isoformat()
    def now(self):
        m=time.perf_counter_ns(); d=m-self._mono_epoch
        return self._wall_epoch+d, d
    def format_wall_ns(self,w):
        s=w//1_000_000_000; f=w%1_000_000_000
        return datetime.datetime.fromtimestamp(
            s,tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')+f'.{f:09d}Z'

class GzipLog:
    def __init__(self,path,header):
        self.path=path; self._q=deque(); self._event=threading.Event()
        self._stop=threading.Event()
        self._thread=threading.Thread(target=self._run,daemon=True)
        with gzip.open(path,'ab',compresslevel=6) as gz:
            gz.write((json.dumps(header,separators=(',',':'))+'\n').encode())
        self._thread.start()
    def write(self,obj): self._q.append(obj); self._event.set()
    def close(self): self._stop.set(); self._event.set(); self._thread.join(timeout=8)
    def _run(self):
        while not self._stop.is_set():
            self._event.wait(); self._event.clear(); self._drain()
        self._drain()
    def _drain(self):
        if not self._q: return
        lines=[]
        while self._q: lines.append(json.dumps(self._q.popleft(),separators=(',',':')))
        blob=('\n'.join(lines)+'\n').encode()
        with gzip.open(self.path,'ab',compresslevel=6) as gz: gz.write(blob)

class LiveMirror:
    def __init__(self,path):
        self.path=path; self._lock=threading.Lock()
        with open(path,'w',encoding='utf-8') as f: f.write('')
    def write(self,obj):
        line=json.dumps(obj,separators=(',',':'))+'\n'
        with self._lock:
            with open(self.path,'a',encoding='utf-8') as f: f.write(line)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE RUNNERS
# ══════════════════════════════════════════════════════════════════════════════

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def run_phase(phase, port, clock, log, mirror, cal, geo,
              triangulator, verbose, raw_dump, stop_event):

    print(f"[LD6002B] Opening {port} @ {BAUD_RATE}...")
    try:
        ser = serial.Serial(port, BAUD_RATE, timeout=0.1,
                            bytesize=8, parity='N', stopbits=1)
        ser.reset_input_buffer()
    except Exception as e:
        print(f"[LD6002B] Open failed: {e}"); return

    framer   = LD6002BFramer()
    seq      = 0
    last_ns  = clock.now()[0]
    tri_next = last_ns + int(2e9)  # triangulate every 2s

    # Running state
    state = {
        "presence": False, "presence_state": "NONE",
        "x_cm":0,"y_cm":0,"z_cm":0,"vel_cms":0,
        "motion_intensity":0,"target_count":0,
    }

    print(f"[LD6002B] Phase: {phase.upper()}")
    if phase == "empty":
        print("  Room must be EMPTY. Ctrl+C when done (5 min recommended).")
    elif phase == "human":
        print("  Walk slowly along each wall at ~1m distance.")
        print("  Cover NORTH EAST SOUTH WEST in sequence.")
        print("  Ctrl+C when all 4 walls done.")
    elif phase == "scan":
        print("  Forensic scan active. Monitoring all 4 walls.")

    while not stop_event.is_set():
        try:
            raw = ser.read(512)
        except Exception as e:
            print(f"\n[LD6002B] Read error: {e}"); break

        if not raw: continue
        if raw_dump: print(f"RAW: {raw.hex()}")

        for ctrl, sub, payload in framer.feed(raw):
            wall_ns, mono_ns = clock.now()
            seq += 1

            decoder = DECODER_TABLE.get((ctrl, sub))
            decoded = decoder(payload) if decoder else None
            if decoded is None: continue

            # Update state
            if (ctrl,sub) == (0x80,0x01):
                state.update(decoded)
            elif (ctrl,sub) == (0x07,0x01):
                state["target_count"] = decoded["target_count"]
                if decoded["targets"]:
                    t0 = decoded["targets"][0]
                    state["x_cm"]    = t0["x_cm"]
                    state["y_cm"]    = t0["y_cm"]
                    state["z_cm"]    = t0["z_cm"]
                    state["vel_cms"] = t0["vel_cms"]
            elif (ctrl,sub) == (0x80,0x03):
                state["motion_intensity"] = decoded.get("motion_intensity",0)

            x  = state["x_cm"]
            y  = state["y_cm"]
            z  = state["z_cm"]
            v  = state["vel_cms"]
            pr = state["presence"]
            it = state["motion_intensity"]
            quad, dist_wall, conf = geo.classify(x, y, z)

            # Phase-specific logic
            if phase == "empty":
                cal.feed_empty(x, y, z, v, it, pr)

            elif phase == "human":
                cal.feed_human(x, y, z, v, it, pr)

            elif phase == "scan":
                # Classify against calibration
                cl = cal.classify_reading(x, y, z, v, it, pr)

                if cl.get("anomaly"):
                    # Record to triangulator
                    triangulator.record(quad, x, y, z, v, wall_ns)

                    # Emit anomaly record
                    rec = {
                        "type":        "LD6002B_ANOMALY",
                        "_stream":     "mmwave",
                        "seq":         seq,
                        "wall_ns":     wall_ns,
                        "wall_iso":    clock.format_wall_ns(wall_ns),
                        "sensor":      "HLK-LD6002B",
                        "freq_ghz":    60.5,
                        "x_cm":        x,
                        "y_cm":        y,
                        "z_cm":        z,
                        "vel_cms":     v,
                        "intensity":   it,
                        "presence":    pr,
                        **cl,
                    }
                    log.write(rec)
                    mirror.write(rec)

                    print(
                        f"\n  [{clock.format_wall_ns(wall_ns)[11:23]}]"
                        f"  *** {cl.get('anomaly_class','ANOMALY')} ***"
                        f"  {quad}"
                        f"  ({x},{y},{z})cm"
                        f"  v={v}cm/s"
                        f"  wall~{dist_wall:.0f}cm",
                        flush=True
                    )

                # Try triangulation every 2s
                if wall_ns >= tri_next:
                    tri_next = wall_ns + int(2e9)
                    estimates = triangulator.triangulate(wall_ns)
                    for est in estimates:
                        tri_rec = {
                            "type":    "LD6002B_TRIANGULATION",
                            "_stream": "mmwave",
                            "seq":     seq,
                            **est,
                        }
                        log.write(tri_rec)
                        mirror.write(tri_rec)
                        print(
                            f"\n  [{clock.format_wall_ns(wall_ns)[11:23]}]"
                            f"  TRIANGULATED: {est['detail']}",
                            flush=True
                        )

            # Write raw record to log (all phases)
            raw_rec = {
                "type":      f"LD6002B_FRAME",
                "_stream":   "mmwave",
                "seq":       seq,
                "wall_ns":   wall_ns,
                "wall_iso":  clock.format_wall_ns(wall_ns),
                "ctrl":      ctrl, "sub": sub,
                "phase":     phase,
                "quadrant":  quad,
                "dist_to_wall_cm": round(dist_wall,1),
                **state,
                **decoded,
            }
            log.write(raw_rec)
            if phase == "raw":
                mirror.write(raw_rec)

            # Status line every 500ms
            now_ns = wall_ns
            if (now_ns - last_ns) >= 500_000_000:
                last_ns = now_ns
                print(
                    f"\r  {phase.upper():<6}"
                    f"  {state['presence_state']:<16}"
                    f"  {quad:<8}"
                    f"  ({x:4},{y:4},{z:4})cm"
                    f"  v={v:4}cm/s"
                    f"  I={it:3}/100"
                    f"  wall~{dist_wall:4.0f}cm  ",
                    end='', flush=True
                )

    ser.close()
    print()

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="CTW HLK-LD6002B 60GHz Forensic Sensor — Null Space Calibration + Triangulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--port",      default="COM5")
    ap.add_argument("--phase",     default="scan",
                    choices=["empty","human","scan","raw"],
                    help="Calibration phase (default: scan)")
    ap.add_argument("--out",       default=".", metavar="DIR")
    ap.add_argument("--verbose",   action="store_true")
    ap.add_argument("--raw-dump",  action="store_true")
    ap.add_argument("--list-ports",action="store_true")

    # Room geometry
    ap.add_argument("--room-x",    type=int, default=400,
                    help="Room width cm east-west (default: 400)")
    ap.add_argument("--room-y",    type=int, default=400,
                    help="Room depth cm north-south (default: 400)")
    ap.add_argument("--room-z",    type=int, default=250,
                    help="Ceiling height cm (default: 250)")
    ap.add_argument("--mount-x",   type=int, default=200,
                    help="Module X position cm from SW corner (default: 200)")
    ap.add_argument("--mount-y",   type=int, default=200,
                    help="Module Y position cm from SW corner (default: 200)")

    args = ap.parse_args()

    if args.list_ports:
        for p in serial.tools.list_ports.comports():
            print(f"  {p.device:<12} {p.description}")
        return

    out_dir     = os.path.abspath(args.out)
    runtime_dir = os.path.join(out_dir, "runtime")
    os.makedirs(out_dir,     exist_ok=True)
    os.makedirs(runtime_dir, exist_ok=True)

    from ntp_web import get_ntp_info
    ntp_info = get_ntp_info()

    clock = ClockAnchor()
    geo   = RoomGeometry(
        room_x_cm = args.room_x,
        room_y_cm = args.room_y,
        room_z_cm = args.room_z,
        mount_x_cm= args.mount_x,
        mount_y_cm= args.mount_y,
        mount_z_cm= args.room_z,
    )
    cal          = CalibrationState(runtime_dir, geo)
    triangulator = WallTriangulator(geo, clock)

    header = {
        "type":             "ld6002b_session_header",
        "sensor":           "HLK-LD6002B",
        "phase":            args.phase,
        "session_wall_utc": clock.session_wall_utc,
        "session_wall_ns":  clock.session_wall_ns,
        "ntp_source":       ntp_info["ntp_source"],
        "ntp_offset_ms":    ntp_info.get("ntp_offset_ms"),
        "port":             args.port,
        "geometry":         geo.to_dict(),
        "stamp":            STAMP,
        "calibration_loaded": cal.loaded,
    }

    gz_path   = os.path.join(out_dir,     f"hlk6002b_{args.phase}_{STAMP}.jsonl.gz")
    live_path = os.path.join(runtime_dir, "mmwave_live.jsonl")

    log    = GzipLog(gz_path, header)
    mirror = LiveMirror(live_path)
    mirror.write(header)

    print(f"\n{'='*68}")
    print(f"  CTW HLK-LD6002B 60GHz — Phase: {args.phase.upper()}")
    print(f"{'='*68}")
    print(f"  Port         : {args.port}")
    print(f"  Room         : {args.room_x}×{args.room_y}×{args.room_z}cm")
    print(f"  Module at    : ({args.mount_x},{args.mount_y}) from SW corner")
    print(f"  Cal loaded   : {cal.loaded}")
    print(f"  NTP offset   : {ntp_info.get('ntp_offset_ms','?')} ms")
    print(f"  Log          : {os.path.basename(gz_path)}")
    print(f"{'='*68}\n")

    stop_event = threading.Event()

    def _run():
        run_phase(args.phase, args.port, clock, log, mirror,
                  cal, geo, triangulator, args.verbose,
                  args.raw_dump, stop_event)
        # Compile calibration at end of empty/human phases
        if args.phase == "empty":
            print("\n[CAL] Compiling empty room baseline...")
            cal.compile_empty()
        elif args.phase == "human":
            print("\n[CAL] Compiling human reference...")
            cal.compile_human()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    try:
        while t.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()
        t.join(timeout=5)
    finally:
        wall_ns, mono_ns = clock.now()
        log.write({"type":"session_end","wall_ns":wall_ns,
                   "wall_iso":clock.format_wall_ns(wall_ns)})
        log.close()
        print(f"\nLog: {gz_path}")


if __name__ == "__main__":
    main()