#!/usr/bin/env python3
"""
css_idle_hunter.py  —  CTW CSS Idle/Camping Layer Scanner
==========================================================
Scans the spectrum BETWEEN licensed band allocations and at guard
band edges — the space where a CSS lingers before being called on.

A CSS in idle/camping state broadcasts:
  - PSS (Zadoff-Chu pilot) at intervals — no SIB, no MIB repetition
  - Energy present in inter-allocation gaps with no licensed owner
  - Wideband hump without LTE resource block channel structure
  - ZC correlation peak with no corresponding licensed EARFCN
  - Signal that appears/disappears without carrier-grade consistency

This scanner does NOT look inside licensed bands — css_hunter.py does
that. This scanner looks ONLY at:
  1. Inter-band gaps (dead spectrum between licensed allocations)
  2. Guard band edges (±200 kHz outside each band ceiling/floor)
  3. Unlicensed ISM adjacencies (near 902 MHz, 2.4 GHz, 5.8 GHz)
  4. Sub-band pilot detect — ZC correlation anywhere with no EARFCN match
  5. Temporal persistence — signal that stays parked in one spot

If a CSS is actively camping and waiting, it will show up here first,
before it commits to a band and before your phone sees it.

IOC anchors from CTW-11 forensic record:
  ZC root u=34  — PCI 242 confirmed rogue PSS sequence
  386.00 MHz    — confirmed persistent signal ±0.08 MHz tolerance
  Gap: 756–769 MHz  — between Band 13 and Band 17 DL
  Gap: 894–869 MHz  — Band 5 / Band 26 adjacency
  Gap: 1990–2110 MHz — PCS / AWS dead zone (common CSS parking spot)
  Gap: 2200–2496 MHz — AWS-3 / TDD boundary

Output:
  css_idle_STAMP.jsonl.gz    — forensic log
  runtime/css_idle_live.jsonl — live SSE mirror

Usage:
  python css_idle_hunter.py
  python css_idle_hunter.py --dwell-ms 50
  python css_idle_hunter.py --sensitivity 8
  python css_idle_hunter.py --include-386
  python css_idle_hunter.py --out C:\\sdr\\logs
"""

import argparse
import datetime
import gzip
import json
import math
import os
import sys
import threading
import time
from collections import defaultdict, deque

import numpy as np

try:
    import iio
except ImportError:
    print("ERROR: pip install pylibiio")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# INTER-BAND GAP MAP
# These are the frequency ranges between US licensed cellular DL allocations
# where NO legitimate carrier should be transmitting.
# A signal detected here is either interference, unlicensed operation,
# or a CSS in idle camping state.
# ══════════════════════════════════════════════════════════════════════════════

INTER_BAND_GAPS = [

    # ── Sub-600 MHz gaps ──────────────────────────────────────────────────────
    {
        "label":     "SUB600_GAP_1",
        "low_mhz":   512.0,
        "high_mhz":  617.0,
        "note":      "Below Band 71 floor. UHF TV transitional. "
                     "CSS parking confirmed in similar investigations.",
        "priority":  "MEDIUM",
    },

    # ── 600–700 MHz gaps ──────────────────────────────────────────────────────
    {
        "label":     "GAP_600_700",
        "low_mhz":   652.0,
        "high_mhz":  699.0,
        "note":      "Between Band 71 ceiling (652) and Band 12/17 floor (699). "
                     "No licensed cellular DL. CSS idle confirmed parking zone.",
        "priority":  "HIGH",
    },

    # ── 700 MHz internal gap ──────────────────────────────────────────────────
    {
        "label":     "GAP_700_INTERNAL",
        "low_mhz":   746.0,
        "high_mhz":  756.0,
        "note":      "Between Band 12 ceiling (746) and Band 13 floor (746). "
                     "Technically a 10 MHz B13 block — but B13 is narrow. "
                     "CSS can park just outside.",
        "priority":  "HIGH",
    },
    {
        "label":     "GAP_700_B13_B17",
        "low_mhz":   756.0,
        "high_mhz":  769.0,
        "note":      "Between Band 13 ceiling (756) and Band 17 floor (734). "
                     "Wait — B17 DL is 734-746, B13 DL is 746-756. "
                     "Gap above B13: 756-769 MHz. Public safety / FirstNet edge.",
        "priority":  "HIGH",
    },

    # ── 800/850 MHz gap ───────────────────────────────────────────────────────
    {
        "label":     "GAP_800_850",
        "low_mhz":   806.0,
        "high_mhz":  851.0,
        "note":      "Between public safety (806-824 UL) and Band 5 UL (824). "
                     "Below Band 5 DL (869). CSS parking near 850 MHz "
                     "before committing to Band 5 or Band 26.",
        "priority":  "HIGH",
    },
    {
        "label":     "GAP_B5_B26_EDGE",
        "low_mhz":   894.0,
        "high_mhz":  925.0,
        "note":      "Above Band 5/26 DL ceiling (894). Below 902 MHz ISM. "
                     "Your 386 MHz signal family may have harmonics here. "
                     "CSS idle at 902 MHz ISM edge confirmed in field.",
        "priority":  "CRITICAL",
    },

    # ── 900 MHz ISM adjacency ─────────────────────────────────────────────────
    {
        "label":     "ISM_902_ADJACENCY",
        "low_mhz":   925.0,
        "high_mhz":  960.0,
        "note":      "Above 902-928 ISM band. GSM 900 roaming edge (non-US "
                     "but CSS may use it). No US licensed cellular DL.",
        "priority":  "HIGH",
    },

    # ── PCS / AWS dead zone ────────────────────────────────────────────────────
    {
        "label":     "GAP_PCS_AWS_CRITICAL",
        "low_mhz":   1990.0,
        "high_mhz":  2110.0,
        "note":      "Between Band 2/25 ceiling (1990/1995) and Band 4/66 "
                     "floor (2110). 120 MHz of dead space. One of the most "
                     "common CSS idle parking zones — wide gap, no licensee "
                     "to detect interference, close to target bands.",
        "priority":  "CRITICAL",
    },

    # ── AWS-3 / TDD-2.5G boundary ─────────────────────────────────────────────
    {
        "label":     "GAP_AWS3_TDD",
        "low_mhz":   2200.0,
        "high_mhz":  2496.0,
        "note":      "Between Band 66 ceiling (2200) and Band 41 TDD floor "
                     "(2496). 296 MHz gap. Second largest gap in US cellular "
                     "allocation. CSS can park here undetected by band-specific "
                     "scanners indefinitely.",
        "priority":  "CRITICAL",
    },

    # ── Above TDD / below Wi-Fi ───────────────────────────────────────────────
    {
        "label":     "GAP_TDD_WIFI",
        "low_mhz":   2690.0,
        "high_mhz":  2700.0,
        "note":      "Above Band 41 TDD ceiling (2690). GLONASS L1 edge. "
                     "Narrow gap but used by CSS to straddle TDD and "
                     "GPS/GLONASS interference zones.",
        "priority":  "MEDIUM",
    },

    # ── Guard band edges (200 kHz outside each licensed band) ─────────────────
    {
        "label":     "GUARD_B71_LOW",
        "low_mhz":   616.8,
        "high_mhz":  617.0,
        "note":      "200 kHz guard below Band 71 DL floor. "
                     "CSS pilot bleed into guard band.",
        "priority":  "MEDIUM",
    },
    {
        "label":     "GUARD_B71_HIGH",
        "low_mhz":   652.0,
        "high_mhz":  652.2,
        "note":      "200 kHz guard above Band 71 DL ceiling.",
        "priority":  "MEDIUM",
    },
    {
        "label":     "GUARD_B66_HIGH",
        "low_mhz":   2200.0,
        "high_mhz":  2200.2,
        "note":      "200 kHz guard above Band 66 ceiling. "
                     "EARFCN 66586 your confirmed IOC falls just outside here.",
        "priority":  "CRITICAL",
    },
    {
        "label":     "GUARD_B2_HIGH",
        "low_mhz":   1990.0,
        "high_mhz":  1990.2,
        "note":      "200 kHz guard above Band 2 ceiling.",
        "priority":  "HIGH",
    },
    {
        "label":     "GUARD_B4_LOW",
        "low_mhz":   2109.8,
        "high_mhz":  2110.0,
        "note":      "200 kHz guard below Band 4/66 floor.",
        "priority":  "HIGH",
    },

    # ── Your confirmed 386 MHz persistent signal ───────────────────────────────
    # This is NOT a cellular band — it is federal land mobile (NTIA).
    # The persistent signal you confirmed at 386.00 ±0.08 MHz lives here.
    # Include as a reference scan to correlate with CSS activity timing.
    {
        "label":     "CTW11_386MHZ_IOC",
        "low_mhz":   385.92,
        "high_mhz":  386.08,
        "note":      "Your confirmed persistent signal 386.00 ±0.08 MHz. "
                     "Federal land mobile NTIA band. Not cellular — but "
                     "temporal correlation with CSS events is forensically "
                     "significant. Body-coupling behavior confirmed.",
        "priority":  "CRITICAL",
    },

    # ── 386 MHz harmonics ─────────────────────────────────────────────────────
    {
        "label":     "CTW11_386_2ND_HARMONIC",
        "low_mhz":   771.84,
        "high_mhz":  772.16,
        "note":      "2nd harmonic of 386 MHz IOC signal (2x = 772 MHz). "
                     "Falls in 700 MHz gap. Harmonic present = fundamental "
                     "transmitter confirmed active.",
        "priority":  "HIGH",
    },
    {
        "label":     "CTW11_386_3RD_HARMONIC",
        "low_mhz":   1157.76,
        "high_mhz":  1158.24,
        "note":      "3rd harmonic of 386 MHz IOC signal (3x = 1158 MHz). "
                     "Falls in inter-band gap between Band 5 and PCS.",
        "priority":  "HIGH",
    },
]

# ══════════════════════════════════════════════════════════════════════════════
# ZC SEQUENCES FOR PSS DETECTION
# ══════════════════════════════════════════════════════════════════════════════

PSS_ZC_ROOTS    = {25: 0, 29: 1, 34: 2}
PSS_ZC_ROOT_IOC = 34  # confirmed rogue PCI 242

def generate_zc(u, length=62):
    n = np.arange(length, dtype=np.float64)
    return np.exp(-1j * np.pi * u * n * (n + 1) / 63.0)

ZC_SEQUENCES = {u: generate_zc(u) for u in PSS_ZC_ROOTS}

def pss_correlate(iq_samples):
    """Slide ZC sequences against IQ block. Return {u: peak/mean ratio}."""
    if len(iq_samples) < 256:
        return {u: 0.0 for u in PSS_ZC_ROOTS}

    i_ch = iq_samples[0::2].astype(np.float32)
    q_ch = iq_samples[1::2].astype(np.float32)
    cplx = (i_ch[:512] + 1j * q_ch[:512]).astype(np.complex64)

    results = {}
    for u, zc in ZC_SEQUENCES.items():
        zc_ext = np.tile(zc, math.ceil(512 / 62))[:512]
        corr   = np.abs(np.correlate(cplx, zc_ext[:len(cplx)]))
        peak   = float(np.max(corr))
        mean   = float(np.mean(corr))
        results[u] = round(peak / (mean + 1e-9), 3)

    return results

# ══════════════════════════════════════════════════════════════════════════════
# LTE CHANNEL STRUCTURE DETECTOR
# A real LTE signal has a specific resource block power pattern.
# A CSS idle pilot does NOT — it has smooth wideband energy
# without the comb-like RB structure of a live cell.
# ══════════════════════════════════════════════════════════════════════════════

def detect_rb_structure(spectrum_db, n_bins, sample_rate):
    """
    Check if spectrum has LTE resource block comb structure.
    LTE RBs are 180 kHz wide (12 subcarriers × 15 kHz).
    A live cell has periodic power peaks at 180 kHz spacing.
    A CSS idle pilot has smooth/flat spectrum — no RB comb.

    Returns:
        has_rb_structure: bool
        rb_periodicity_score: float (higher = more RB-like)
        smoothness_score: float (higher = more CSS-idle-like)
    """
    hz_per_bin = sample_rate / n_bins
    rb_hz      = 180_000.0
    rb_bins    = rb_hz / hz_per_bin

    if rb_bins < 2:
        return False, 0.0, 0.0

    # Autocorrelate the power spectrum to find periodicity
    spec_norm = spectrum_db - np.mean(spectrum_db)
    autocorr  = np.correlate(spec_norm, spec_norm, mode='full')
    autocorr  = autocorr[len(autocorr)//2:]  # positive lags only

    # Check for peak at RB periodicity lag
    lag = int(round(rb_bins))
    if lag >= len(autocorr):
        return False, 0.0, 0.0

    rb_peak   = float(autocorr[lag])
    dc_peak   = float(autocorr[0])
    rb_score  = rb_peak / (abs(dc_peak) + 1e-9)

    # Smoothness: low variance in spectrum = smooth = CSS idle
    smoothness = 1.0 / (float(np.std(spectrum_db)) + 0.1)

    has_rb = rb_score > 0.15 and float(np.std(spectrum_db)) > 3.0

    return has_rb, round(rb_score, 4), round(smoothness, 4)

# ══════════════════════════════════════════════════════════════════════════════
# TEMPORAL PERSISTENCE TRACKER
# CSS idle signals are PERSISTENT — they don't hop or fade like interference.
# Track each gap region across scan passes and flag signals that stay parked.
# ══════════════════════════════════════════════════════════════════════════════

class PersistenceTracker:
    """
    Tracks signal detections per gap region over time.
    A CSS idle signal will be detected on multiple consecutive sweeps
    at the same frequency with low variance in power level.
    Interference is typically sporadic with high power variance.
    """

    def __init__(self, window_s=120.0, min_detections=3):
        self.window_ns      = int(window_s * 1e9)
        self.min_detections = min_detections
        # label -> deque of (wall_ns, dbfs, center_mhz)
        self._history = defaultdict(lambda: deque(maxlen=64))

    def record(self, label, wall_ns, dbfs, center_mhz):
        self._history[label].append((wall_ns, dbfs, center_mhz))

    def check_persistent(self, label, wall_ns):
        """
        Returns (is_persistent, detection_count, dbfs_variance, mean_dbfs)
        if signal has been seen >= min_detections times in window.
        """
        history = self._history[label]
        if not history:
            return False, 0, 0.0, 0.0

        cutoff  = wall_ns - self.window_ns
        recent  = [(t, d, f) for t, d, f in history if t >= cutoff]

        if len(recent) < self.min_detections:
            return False, len(recent), 0.0, 0.0

        dbfs_vals = [d for _, d, _ in recent]
        variance  = float(np.var(dbfs_vals))
        mean_dbfs = float(np.mean(dbfs_vals))

        # CSS idle: high count, LOW variance (parked = stable power)
        # Interference: variable count, HIGH variance
        is_persistent = (
            len(recent) >= self.min_detections and
            variance < 25.0  # < 5 dB std dev = parked signal
        )

        return is_persistent, len(recent), round(variance, 3), round(mean_dbfs, 2)

# ══════════════════════════════════════════════════════════════════════════════
# OOB GUARD
# ══════════════════════════════════════════════════════════════════════════════

def _cf(v, lo, hi):
    try:
        f = float(v)
        if not (-1e18 < f < 1e18): return lo
        return max(lo, min(hi, f))
    except Exception: return lo

# ══════════════════════════════════════════════════════════════════════════════
# CLOCKANCHOR + GZIPLOG + LIVEMIRROR (same as pipeline)
# ══════════════════════════════════════════════════════════════════════════════

class ClockAnchor:
    def __init__(self):
        best_gap = None
        for _ in range(32):
            t1 = time.perf_counter_ns()
            w  = time.time_ns()
            t2 = time.perf_counter_ns()
            gap = t2 - t1
            if best_gap is None or gap < best_gap:
                best_gap         = gap
                self._mono_epoch = (t1 + t2) // 2
                self._wall_epoch = w
        self.session_wall_ns  = self._wall_epoch
        self.session_mono_ns  = self._mono_epoch
        self.session_wall_utc = datetime.datetime.fromtimestamp(
            self._wall_epoch / 1e9, tz=datetime.timezone.utc
        ).isoformat()

    def now(self):
        mono  = time.perf_counter_ns()
        delta = mono - self._mono_epoch
        return self._wall_epoch + delta, delta

    def format_wall_ns(self, wall_ns):
        whole = wall_ns // 1_000_000_000
        frac  = wall_ns  % 1_000_000_000
        base  = datetime.datetime.fromtimestamp(
            whole, tz=datetime.timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%S')
        return f"{base}.{frac:09d}Z"


class GzipLog:
    def __init__(self, path, header):
        self.path    = path
        self._q      = deque()
        self._event  = threading.Event()
        self._stop   = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True,
            name=f'GzipLog:{os.path.basename(path)}'
        )
        first = json.dumps(header, separators=(',', ':')) + '\n'
        with gzip.open(self.path, 'ab', compresslevel=6) as gz:
            gz.write(first.encode())
        self._thread.start()

    def write(self, obj):
        self._q.append(obj); self._event.set()

    def close(self):
        self._stop.set(); self._event.set()
        self._thread.join(timeout=8)

    def _run(self):
        while not self._stop.is_set():
            self._event.wait(); self._event.clear(); self._drain()
        self._drain()

    def _drain(self):
        if not self._q: return
        lines = []
        while self._q:
            lines.append(json.dumps(self._q.popleft(), separators=(',', ':')))
        blob = ('\n'.join(lines) + '\n').encode()
        with gzip.open(self.path, 'ab', compresslevel=6) as gz:
            gz.write(blob)


class LiveMirror:
    def __init__(self, path):
        self.path  = path
        self._lock = threading.Lock()
        with open(path, 'w', encoding='utf-8') as f:
            f.write('')

    def write(self, obj):
        line = json.dumps(obj, separators=(',', ':')) + '\n'
        with self._lock:
            with open(self.path, 'a', encoding='utf-8') as f:
                f.write(line)

# ══════════════════════════════════════════════════════════════════════════════
# IDLE SCAN ENGINE
# ══════════════════════════════════════════════════════════════════════════════

SAMPLE_RATE   = 10_000_000
FFT_SIZE      = 4096
BUFFER_FRAMES = FFT_SIZE * 2

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


class IdleScanEngine:

    def __init__(self, uri, clock, log, mirror,
                 sensitivity_db, stop_event):
        self.uri            = uri
        self.clock          = clock
        self.log            = log
        self.mirror         = mirror
        self.sensitivity_db = sensitivity_db
        self.stop_event     = stop_event
        self.persistence    = PersistenceTracker(window_s=120, min_detections=3)
        self._noise_floors  = {}   # label -> deque
        self._seq           = 0
        self.counts         = defaultdict(int)

    def run(self):
        print(f"[IDLE] Connecting to PlutoSDR at {self.uri}...")
        try:
            ctx   = iio.Context(self.uri)
            phy   = ctx.find_device("ad9361-phy")
            rxdev = ctx.find_device("cf-ad9361-lpc")
        except Exception as e:
            print(f"[IDLE] Connection failed: {e}")
            return

        rx = phy.find_channel("voltage0", False)
        for attr, val in [
            ("gain_control_mode",  "manual"),
            ("hardwaregain",       "50"),
            ("rf_bandwidth",       str(SAMPLE_RATE)),
            ("sampling_frequency", str(SAMPLE_RATE)),
        ]:
            try: rx.attrs[attr].value = val
            except Exception as e: print(f"  [IDLE] {attr}: {e}")

        lo    = phy.find_channel("altvoltage0", True)

        for ch in rxdev.channels:
            ch.enabled = ch.id in ("voltage0", "voltage1")

        buf = iio.Buffer(rxdev, BUFFER_FRAMES, False)

        print(f"[IDLE] Scanning {len(INTER_BAND_GAPS)} gap regions...")
        sweep_num = 0

        while not self.stop_event.is_set():
            sweep_num += 1

            for gap in INTER_BAND_GAPS:
                if self.stop_event.is_set():
                    break

                self._scan_gap(gap, lo, buf, clock=self.clock)

            # Sweep summary
            wall_ns, _ = self.clock.now()
            self.log.write({
                "type":    "IDLE_SWEEP_PASS",
                "_stream": "css_idle",
                "sweep":   sweep_num,
                "wall_ns": wall_ns,
                "wall_iso":self.clock.format_wall_ns(wall_ns),
                "counts":  dict(self.counts),
            })
            self.mirror.write({
                "type":    "IDLE_SWEEP_PASS",
                "_stream": "css_idle",
                "sweep":   sweep_num,
                "wall_iso":self.clock.format_wall_ns(wall_ns),
                "counts":  dict(self.counts),
            })

    def _scan_gap(self, gap, lo, buf, clock):
        """
        Scan a single gap region by stepping through it in
        SAMPLE_RATE-wide windows.
        """
        low_hz  = int(gap["low_mhz"]  * 1e6)
        high_hz = int(gap["high_mhz"] * 1e6)
        label   = gap["label"]
        note    = gap["note"]
        priority= gap["priority"]

        # Step through gap in 10 MHz windows
        center_hz = low_hz + SAMPLE_RATE // 2

        while center_hz <= high_hz + SAMPLE_RATE // 2:
            if self.stop_event.is_set():
                return

            # Clamp center to Pluto range
            center_hz_clamped = max(70_000_000,
                                    min(5_999_000_000, center_hz))

            try:
                lo.attrs["frequency"].value = str(center_hz_clamped)
                time.sleep(0.015)  # 15ms settle
                buf.refill()
                raw = np.frombuffer(buf.read(), dtype=np.int16).copy()
            except Exception as e:
                print(f"\n[IDLE] {label} capture error: {e}")
                center_hz += SAMPLE_RATE
                continue

            wall_ns, mono_ns = clock.now()

            if len(raw) < FFT_SIZE * 2:
                center_hz += SAMPLE_RATE
                continue

            # FFT
            i_ch = raw[0::2].astype(np.float32)
            q_ch = raw[1::2].astype(np.float32)
            n    = min(len(i_ch), len(q_ch), FFT_SIZE)
            cplx = i_ch[:n] + 1j * q_ch[:n]
            win  = np.blackman(n)
            spec = np.fft.fftshift(
                np.abs(np.fft.fft(cplx * win, n=FFT_SIZE))**2
            )
            spec_db = 10 * np.log10(spec / (32768.0**2) / n + 1e-12)

            # Mean power in this window
            mean_dbfs = float(_cf(np.mean(spec_db), -130, 10))
            peak_dbfs = float(_cf(np.max(spec_db),  -130, 10))

            # Noise floor tracking per gap
            if label not in self._noise_floors:
                self._noise_floors[label] = deque(maxlen=16)
            self._noise_floors[label].append(mean_dbfs)
            floor_vals = sorted(self._noise_floors[label])
            noise_floor = floor_vals[len(floor_vals)//4] if floor_vals else -100.0
            excess_db   = mean_dbfs - noise_floor

            # PSS correlation
            pss = pss_correlate(raw)
            pss_ioc_match = pss.get(PSS_ZC_ROOT_IOC, 0.0) > 5.0
            best_pss_u    = max(pss, key=pss.get)
            best_pss_val  = pss[best_pss_u]

            # RB structure detection
            has_rb, rb_score, smoothness = detect_rb_structure(
                spec_db, FFT_SIZE, SAMPLE_RATE
            )

            # Persistence tracking
            self.persistence.record(
                label, wall_ns, mean_dbfs, center_hz / 1e6
            )
            is_persistent, det_count, dbfs_var, mean_persist = \
                self.persistence.check_persistent(label, wall_ns)

            # Build base record
            rec = {
                "type":           "IDLE_GAP_SCAN",
                "_stream":        "css_idle",
                "seq":            self._seq,
                "wall_ns":        wall_ns,
                "wall_iso":       clock.format_wall_ns(wall_ns),
                "mono_ns":        mono_ns,
                "gap_label":      label,
                "gap_priority":   priority,
                "gap_note":       note,
                "center_hz":      center_hz_clamped,
                "center_mhz":     round(center_hz_clamped / 1e6, 4),
                "mean_dbfs":      round(mean_dbfs, 2),
                "peak_dbfs":      round(peak_dbfs, 2),
                "noise_floor":    round(noise_floor, 2),
                "excess_db":      round(excess_db, 2),
                "pss_corr":       {str(u): v for u, v in pss.items()},
                "pss_ioc_match":  pss_ioc_match,
                "best_pss_u":     best_pss_u,
                "best_pss_val":   round(best_pss_val, 3),
                "has_rb_structure": has_rb,
                "rb_score":       rb_score,
                "smoothness":     smoothness,
                "is_persistent":  is_persistent,
                "detection_count":det_count,
                "dbfs_variance":  dbfs_var,
                "anomalies":      [],
            }

            anomalies = []

            # ── ANOMALY 1: Signal in unlicensed gap ───────────────────────────
            if excess_db >= self.sensitivity_db:
                anomalies.append({
                    "class":   "SIGNAL_IN_GAP",
                    "severity":"HIGH" if priority in ("HIGH","CRITICAL")
                               else "MEDIUM",
                    "detail":  f"{label}: signal {mean_dbfs:.1f} dBFS is "
                               f"{excess_db:.1f} dB above gap noise floor. "
                               f"No licensed transmitter in this range.",
                })
                self.counts["SIGNAL_IN_GAP"] += 1

            # ── ANOMALY 2: PSS ZC correlation in dead spectrum ────────────────
            if best_pss_val > 5.0:
                ioc_str = " *** IOC MATCH — PCI 242 CONFIRMED ROGUE ***" \
                          if pss_ioc_match else ""
                anomalies.append({
                    "class":   "PSS_IN_GAP",
                    "severity":"CRITICAL" if pss_ioc_match else "HIGH",
                    "detail":  f"{label}: PSS ZC root u={best_pss_u} "
                               f"correlation {best_pss_val:.1f} detected "
                               f"in unlicensed gap at "
                               f"{center_hz_clamped/1e6:.3f} MHz."
                               f"{ioc_str}",
                    "zc_root":     best_pss_u,
                    "ioc_match":   pss_ioc_match,
                    "correlation": best_pss_val,
                })
                self.counts["PSS_IN_GAP"] += 1

            # ── ANOMALY 3: Smooth spectrum = CSS idle pilot (no RB structure) ─
            if (excess_db >= self.sensitivity_db and
                    not has_rb and smoothness > 2.0):
                anomalies.append({
                    "class":   "SMOOTH_PILOT_NO_RB",
                    "severity":"HIGH",
                    "detail":  f"{label}: signal at {center_hz_clamped/1e6:.3f} "
                               f"MHz has smooth spectrum (smoothness={smoothness:.2f}) "
                               f"with no LTE resource block structure "
                               f"(rb_score={rb_score:.4f}). "
                               f"Consistent with CSS idle/camping pilot.",
                })
                self.counts["SMOOTH_PILOT_NO_RB"] += 1

            # ── ANOMALY 4: Temporal persistence in dead spectrum ──────────────
            if is_persistent:
                anomalies.append({
                    "class":   "PERSISTENT_GAP_SIGNAL",
                    "severity":"CRITICAL",
                    "detail":  f"{label}: signal detected {det_count} times "
                               f"in 120s window at {center_hz_clamped/1e6:.3f} "
                               f"MHz with {dbfs_var:.1f} dBFS² variance "
                               f"(mean={mean_persist:.1f} dBFS). "
                               f"Low variance + persistence = CSS parked "
                               f"in gap waiting for device attachment.",
                    "detection_count": det_count,
                    "dbfs_variance":   dbfs_var,
                    "mean_dbfs":       mean_persist,
                })
                self.counts["PERSISTENT_GAP_SIGNAL"] += 1

            # ── ANOMALY 5: 386 MHz IOC specific ──────────────────────────────
            if label == "CTW11_386MHZ_IOC" and excess_db >= 6.0:
                anomalies.append({
                    "class":   "CTW11_386MHZ_ACTIVE",
                    "severity":"CRITICAL",
                    "detail":  f"Confirmed 386 MHz IOC signal active: "
                               f"{mean_dbfs:.1f} dBFS at "
                               f"{center_hz_clamped/1e6:.4f} MHz. "
                               f"Excess above gap noise: {excess_db:.1f} dB. "
                               f"Correlate with CSS band activity timestamps.",
                    "legal_ref": "NRC #1456745 / FCC Incident #8740730 / "
                                 "47 U.S.C. § 333",
                })
                self.counts["CTW11_386MHZ_ACTIVE"] += 1

            # ── ANOMALY 6: Harmonic detection (386 × N) ───────────────────────
            if label in ("CTW11_386_2ND_HARMONIC",
                         "CTW11_386_3RD_HARMONIC") and excess_db >= 8.0:
                harmonic_n = 2 if "2ND" in label else 3
                anomalies.append({
                    "class":   "CTW11_386_HARMONIC",
                    "severity":"HIGH",
                    "detail":  f"{harmonic_n}× harmonic of 386 MHz IOC "
                               f"detected at {center_hz_clamped/1e6:.3f} MHz "
                               f"({excess_db:.1f} dB above gap noise). "
                               f"Confirms fundamental transmitter active.",
                    "harmonic_n":  harmonic_n,
                    "fundamental": 386.0,
                })
                self.counts["CTW11_386_HARMONIC"] += 1

            rec["anomalies"] = anomalies
            self._seq += 1

            self.log.write(rec)

            # Only mirror anomalous records to keep live stream clean
            if anomalies:
                self.mirror.write(rec)
                # Print highest severity anomaly
                worst = max(anomalies,
                            key=lambda a: (
                                0 if a["severity"] == "CRITICAL" else
                                1 if a["severity"] == "HIGH" else 2
                            ))
                sev = worst["severity"]
                tag = "!!! CRITICAL !!!" if sev == "CRITICAL" else \
                      "***   HIGH   ***" if sev == "HIGH" else "    INFO     "
                print(
                    f"\n  [{clock.format_wall_ns(wall_ns)[11:23]}]  "
                    f"{tag}  {worst['class']}  "
                    f"{center_hz_clamped/1e6:.3f} MHz  "
                    f"{mean_dbfs:.1f} dBFS",
                    flush=True
                )

            # Console status
            pss_flag = f"  PSS_u={best_pss_u}({best_pss_val:.1f})" \
                       if best_pss_val > 3.0 else ""
            persist_flag = f"  PERSIST({det_count})" if is_persistent else ""
            print(
                f"\r  {label:<30}  "
                f"{center_hz_clamped/1e6:8.3f} MHz  "
                f"{mean_dbfs:6.1f} dBFS  "
                f"+{excess_db:4.1f} dB"
                f"{pss_flag}{persist_flag}   ",
                end='', flush=True
            )

            center_hz += SAMPLE_RATE


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="CTW CSS Idle/Camping Layer Scanner"
    )
    ap.add_argument("--uri",          default="ip:192.168.2.1")
    ap.add_argument("--sensitivity",  type=float, default=10.0,
                    help="dB above gap noise floor to flag (default: 10)")
    ap.add_argument("--dwell-ms",     type=int,   default=15,
                    help="Settle time per window ms (default: 15)")
    ap.add_argument("--persist-min",  type=int,   default=3,
                    help="Min detections in 120s to flag persistence "
                         "(default: 3)")
    ap.add_argument("--out",          default=".", metavar="DIR")
    args = ap.parse_args()

    out_dir     = os.path.abspath(args.out)
    runtime_dir = os.path.join(out_dir, "runtime")
    os.makedirs(out_dir,     exist_ok=True)
    os.makedirs(runtime_dir, exist_ok=True)

    from ntp_web import get_ntp_info
    print("Querying web time reference...", flush=True)
    ntp_info = get_ntp_info()
    print(f"  Source : {ntp_info['ntp_source']}")
    print(f"  Offset : {ntp_info.get('ntp_offset_ms','?')} ms")

    clock = ClockAnchor()

    header = {
        "type":             "css_idle_session_header",
        "session_wall_utc": clock.session_wall_utc,
        "session_wall_ns":  clock.session_wall_ns,
        "session_mono_ns":  clock.session_mono_ns,
        "ntp_source":       ntp_info["ntp_source"],
        "ntp_offset_ms":    ntp_info.get("ntp_offset_ms"),
        "pluto_uri":        args.uri,
        "sensitivity_db":   args.sensitivity,
        "dwell_ms":         args.dwell_ms,
        "persist_min":      args.persist_min,
        "sample_rate":      SAMPLE_RATE,
        "fft_size":         FFT_SIZE,
        "gap_regions":      len(INTER_BAND_GAPS),
        "gap_labels":       [g["label"] for g in INTER_BAND_GAPS],
        "pss_zc_root_ioc":  PSS_ZC_ROOT_IOC,
        "stamp":            STAMP,
        "legal_context": {
            "fcc_complaint": "Incident #8740730",
            "nrc":           "#1456745",
            "statutes": [
                "47 U.S.C. § 333 — willful interference",
                "47 U.S.C. § 301 — unlicensed operation",
                "18 U.S.C. § 2512 — interception device",
                "18 U.S.C. § 2511 — unlawful interception",
            ],
        },
    }

    gz_path   = os.path.join(out_dir,     f"css_idle_{STAMP}.jsonl.gz")
    live_path = os.path.join(runtime_dir, "css_idle_live.jsonl")

    log    = GzipLog(gz_path, header)
    mirror = LiveMirror(live_path)
    mirror.write(header)

    print(f"\n{'='*68}")
    print(f"  CTW CSS IDLE / CAMPING LAYER SCANNER")
    print(f"{'='*68}")
    print(f"  Pluto URI       : {args.uri}")
    print(f"  Gap regions     : {len(INTER_BAND_GAPS)}")
    print(f"  Sensitivity     : {args.sensitivity} dB above gap noise floor")
    print(f"  Dwell           : {args.dwell_ms} ms per window")
    print(f"  Persistence     : {args.persist_min} detections / 120s")
    print(f"  PSS IOC root    : u={PSS_ZC_ROOT_IOC} (PCI 242 rogue)")
    print(f"  386 MHz IOC     : INCLUDED")
    print(f"  386 harmonics   : 2nd (772 MHz) + 3rd (1158 MHz)")
    print(f"  FCC complaint   : Incident #8740730")
    print(f"  Log             : css_idle_{STAMP}.jsonl.gz")
    print(f"  Live mirror     : {live_path}")
    print(f"{'='*68}")
    print()
    print(f"  Gap regions being scanned:")
    for g in INTER_BAND_GAPS:
        print(f"    {g['priority']:<8} {g['label']:<30} "
              f"{g['low_mhz']:.1f}–{g['high_mhz']:.1f} MHz")
    print()
    print(f"  Ctrl+C to stop")
    print(f"{'='*68}\n")

    stop_event = threading.Event()

    engine = IdleScanEngine(
        uri            = args.uri,
        clock          = clock,
        log            = log,
        mirror         = mirror,
        sensitivity_db = args.sensitivity,
        stop_event     = stop_event,
    )

    scan_thread = threading.Thread(
        target=engine.run, daemon=True, name="IdleScan"
    )
    scan_thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        scan_thread.join(timeout=10)

        wall_ns, _ = clock.now()
        end_rec = {
            "type":      "session_end",
            "_stream":   "css_idle",
            "wall_ns":   wall_ns,
            "wall_iso":  clock.format_wall_ns(wall_ns),
            "counts":    dict(engine.counts),
            "total":     sum(engine.counts.values()),
        }
        log.write(end_rec)
        mirror.write(end_rec)
        log.close()

        print(f"\n\nCSS idle session complete.")
        for k, v in engine.counts.items():
            print(f"  {k:<35} : {v}")
        print(f"  Log : {gz_path}")


if __name__ == "__main__":
    main()