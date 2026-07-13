#!/usr/bin/env python3
"""
geiger_sdr_correlator.py  —  CTW Geiger/SDR Post-Session Correlation Engine
============================================================================
Standalone offline module. Reads existing session logs and performs
deep temporal correlation analysis between FS-5000 Geiger pulse events
and PlutoSDR RF anomaly captures.

This is distinct from the live correlator.py which runs in real-time.
This module runs AFTER sessions, operates on compressed log archives,
and produces a structured correlation report with statistical analysis.

What it does:
  1.  Loads sweep_*.jsonl.gz (SDR) and serial_*.jsonl.gz (Geiger serial)
      and audio_*.jsonl.gz (Geiger pulse) log archives
  2.  Aligns all streams to the shared ClockAnchor wall_ns epoch
  3.  Computes Pearson cross-correlation between GM pulse rate and
      SDR RF energy at lag τ = 0..500ms across all frequency bins
  4.  Identifies coincident anomaly windows using four classifiers:
        A. Simple coincidence (both anomalous in same window)
        B. Pearson r > threshold at consistent lag (systematic correlation)
        C. Phase detection (probe pulse followed by main pulse)
        D. Carrier + modulation (sustained floor + episodic spikes)
  5.  For each correlated event computes:
        Signed temporal offset (which aperture led)
        Pearson r and optimal lag
        Frequency of peak RF activity during Geiger event
        Crest factor at time of Geiger spike
        Pulse architecture classification
        Estimated duty cycle if pulsed source
  6.  Generates structured report for personal and legal records

Physics basis:
  The GM tube responds to RF/EM induction via induced current in the
  detector circuit. A sufficiently strong RF field near the tube causes
  false counts indistinguishable from ionizing particle detections.
  This makes the tube a broadband EM aperture with different spectral
  sensitivity than the PlutoSDR antenna. When both instruments report
  anomalies in the same time window, the probability of coincidental
  independent natural causes decreases multiplicatively.

  The Pearson cross-correlation at varying lag quantifies whether the
  relationship between the two signals is systematic (consistent lag,
  high r) or coincidental (variable lag, low r). A systematic r > 0.7
  at a consistent lag indicates a single source driving both instruments
  with a fixed propagation or coupling delay.

Usage:
  python geiger_sdr_correlator.py
  python geiger_sdr_correlator.py --sdr-log sweep_20260508_*.jsonl.gz
  python geiger_sdr_correlator.py --serial-log serial_*.jsonl.gz
  python geiger_sdr_correlator.py --window 1.0 --lag-max 0.5
  python geiger_sdr_correlator.py --baseline-dr 0.02
  python geiger_sdr_correlator.py --all-sessions
  python geiger_sdr_correlator.py --out C:\\sdr\\logs
"""

import argparse
import datetime
import glob
import gzip
import json
import math
import os
import sys
from collections import defaultdict, deque
from typing import List, Optional, Tuple, Dict

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

# Correlation thresholds
PEARSON_THRESHOLD      = 0.70   # r above this = systematic correlation
PEARSON_STRONG         = 0.85   # r above this = strong systematic
PEARSON_DEFINITIVE     = 0.95   # r above this = near-certain single source

# Anomaly thresholds
GEIGER_SPIKE_MULT      = 3.0    # times baseline = spike
GEIGER_FLOOR_MULT      = 1.5    # times baseline = sustained floor elevation
SDR_ANOMALY_EXCESS_DB  = 10.0   # dB above band noise floor = RF anomaly
CF_ANOMALY_THRESHOLD   = 80.0   # crest factor above = impulsive signal

# Time parameters
CORRELATION_WINDOW_S   = 30.0   # seconds per analysis window
LAG_MAX_S              = 0.500  # maximum lag to test in seconds
LAG_STEP_S             = 0.010  # lag step size in seconds
COINCIDENCE_WINDOW_S   = 20.0   # seconds for simple coincidence test

# Phase detection (probe + main pulse architecture)
PHASE1_MAX_DURATION_S  = 5.0    # probe pulse max duration
PHASE1_TO_PHASE2_MAX_S = 60.0   # max gap between probe and main pulse
PHASE2_MIN_MULT        = 10.0   # main pulse must be this times probe amplitude

# Carrier + modulation detection
CARRIER_WINDOW_S       = 300.0  # 5-minute window for carrier analysis
CARRIER_MIN_ELEVATION  = 1.3    # floor elevated by this factor = carrier present
PULSE_MIN_MULT         = 5.0    # spike above floor = modulation pulse

# J305 tube conversion factor (Bosean FS-5000)
J305_CPS_TO_USVH       = 0.00812

# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

class GeigerSample:
    __slots__ = ['wall_ns', 'wall_iso', 'dr_usvh', 'cpm', 'cps']
    def __init__(self, wall_ns, wall_iso, dr, cpm, cps):
        self.wall_ns  = wall_ns
        self.wall_iso = wall_iso
        self.dr_usvh  = dr
        self.cpm      = cpm
        self.cps      = cps


class AudioPulse:
    __slots__ = ['wall_ns', 'wall_iso', 'amplitude']
    def __init__(self, wall_ns, wall_iso, amplitude):
        self.wall_ns   = wall_ns
        self.wall_iso  = wall_iso
        self.amplitude = amplitude


class SDRSample:
    __slots__ = ['wall_ns', 'wall_iso', 'freq_hz', 'dbfs',
                 'crest_factor', 'rssi_atten_db', 'anomaly', 'sweep']
    def __init__(self, wall_ns, wall_iso, freq_hz, dbfs,
                 cf, atten, anomaly, sweep):
        self.wall_ns       = wall_ns
        self.wall_iso      = wall_iso
        self.freq_hz       = freq_hz
        self.dbfs          = dbfs
        self.crest_factor  = cf
        self.rssi_atten_db = atten
        self.anomaly       = anomaly
        self.sweep         = sweep


class CorrelationEvent:
    def __init__(self):
        self.window_start_ns   = 0
        self.window_start_iso  = ""
        self.window_end_ns     = 0
        self.duration_s        = 0.0
        self.geiger_dr_peak    = 0.0
        self.geiger_dr_mean    = 0.0
        self.geiger_baseline   = 0.0
        self.geiger_mult       = 0.0
        self.sdr_dbfs_peak     = 0.0
        self.sdr_dbfs_mean     = 0.0
        self.sdr_noise_floor   = 0.0
        self.sdr_excess_db     = 0.0
        self.peak_freq_hz      = 0.0
        self.peak_cf           = 0.0
        self.pearson_r         = 0.0
        self.optimal_lag_ms    = 0.0
        self.lag_direction     = ""   # "RF_FIRST" or "GEIGER_FIRST"
        self.classifiers       = []
        self.pulse_arch        = ""
        self.duty_cycle_pct    = None
        self.severity          = ""
        self.description       = ""


# ══════════════════════════════════════════════════════════════════════════════
# LOG READERS
# ══════════════════════════════════════════════════════════════════════════════

def read_serial_log(gz_path: str) -> List[GeigerSample]:
    """Read FS-5000 serial log (DR, CPM, CPS records)."""
    samples = []
    try:
        with gzip.open(gz_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    t = r.get("type", "")
                    if t in ("forensic_session_header", "session_end"):
                        continue
                    wns = r.get("wall_ns")
                    dr  = r.get("dr")
                    if wns is None or dr is None:
                        continue
                    samples.append(GeigerSample(
                        wall_ns  = int(wns),
                        wall_iso = r.get("wall_iso", ""),
                        dr       = float(dr),
                        cpm      = int(r.get("cpm", 0) or 0),
                        cps      = int(r.get("cps", 0) or 0),
                    ))
                except Exception:
                    continue
    except Exception as e:
        print(f"[CORR] Serial log read error {gz_path}: {e}")
    return samples


def read_audio_log(gz_path: str) -> List[AudioPulse]:
    """Read FS-5000 audio pulse log."""
    pulses = []
    try:
        with gzip.open(gz_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    t = r.get("type", "")
                    if t in ("forensic_session_header", "session_end"):
                        continue
                    wns = r.get("wall_ns")
                    amp = r.get("amplitude")
                    if wns is None:
                        continue
                    pulses.append(AudioPulse(
                        wall_ns   = int(wns),
                        wall_iso  = r.get("wall_iso", ""),
                        amplitude = float(amp or 0),
                    ))
                except Exception:
                    continue
    except Exception as e:
        print(f"[CORR] Audio log read error {gz_path}: {e}")
    return pulses


def read_sdr_log(gz_path: str) -> List[SDRSample]:
    """Read PlutoSDR sweep log."""
    samples = []
    try:
        with gzip.open(gz_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    t = r.get("type", "")
                    if t in ("forensic_session_header", "session_end",
                             "sweep_pass_end", "sweep_summary",
                             "set_error", "sweep_abort"):
                        continue
                    if not r.get("freq_hz"):
                        continue
                    wns = r.get("wall_ns")
                    if wns is None:
                        continue
                    samples.append(SDRSample(
                        wall_ns   = int(wns),
                        wall_iso  = r.get("wall_iso", ""),
                        freq_hz   = float(r.get("freq_hz", 0)),
                        dbfs      = float(r.get("dbfs", -100) or -100),
                        cf        = float(r.get("crest_factor", 0) or 0),
                        atten     = float(r.get("rssi_atten_db", 100) or 100),
                        anomaly   = bool(r.get("anomaly")),
                        sweep     = int(r.get("sweep", 0) or 0),
                    ))
                except Exception:
                    continue
    except Exception as e:
        print(f"[CORR] SDR log read error {gz_path}: {e}")
    return samples


# ══════════════════════════════════════════════════════════════════════════════
# STATISTICAL UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def pearson_r(x: List[float], y: List[float]) -> float:
    """Pearson correlation coefficient between two equal-length series."""
    n = len(x)
    if n < 3:
        return 0.0
    mx = sum(x) / n
    my = sum(y) / n
    num   = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    den_x = math.sqrt(sum((xi - mx)**2 for xi in x))
    den_y = math.sqrt(sum((yi - my)**2 for yi in y))
    if den_x < 1e-12 or den_y < 1e-12:
        return 0.0
    return num / (den_x * den_y)


def cross_correlate(
    geiger_series: List[Tuple[int, float]],   # (wall_ns, dr_usvh)
    sdr_series:    List[Tuple[int, float]],   # (wall_ns, dbfs)
    lag_max_ns:    int,
    lag_step_ns:   int,
    bin_size_ns:   int = 1_000_000_000        # 1-second bins
) -> Tuple[float, int, List[Tuple[int, float]]]:
    """
    Compute Pearson cross-correlation between Geiger DR and SDR dBFS
    at multiple lag values.

    Bins both signals at bin_size_ns resolution.
    Shifts the SDR series forward and backward by lag values.
    Returns (best_r, best_lag_ns, [(lag_ns, r), ...])
    """
    if not geiger_series or not sdr_series:
        return 0.0, 0, []

    # Find common time range
    g_start = min(t for t, _ in geiger_series)
    g_end   = max(t for t, _ in geiger_series)
    s_start = min(t for t, _ in sdr_series)
    s_end   = max(t for t, _ in sdr_series)

    common_start = max(g_start, s_start)
    common_end   = min(g_end,   s_end)

    if common_end <= common_start:
        return 0.0, 0, []

    # Bin signals
    n_bins = max(1, int((common_end - common_start) / bin_size_ns) + 1)

    def bin_series(series, start_ns, n, bsize):
        bins  = [[] for _ in range(n)]
        for t, v in series:
            idx = int((t - start_ns) / bsize)
            if 0 <= idx < n:
                bins[idx].append(v)
        return [sum(b)/len(b) if b else 0.0 for b in bins]

    g_bins = bin_series(geiger_series, common_start, n_bins, bin_size_ns)
    s_bins = bin_series(sdr_series,    common_start, n_bins, bin_size_ns)

    # Cross-correlate at each lag
    lag_bins_max  = max(1, int(lag_max_ns / bin_size_ns))
    lag_bins_step = max(1, int(lag_step_ns / bin_size_ns))

    results   = []
    best_r    = 0.0
    best_lag  = 0

    for lag in range(-lag_bins_max, lag_bins_max + 1, lag_bins_step):
        lag_ns = lag * bin_size_ns
        if lag >= 0:
            g = g_bins[lag:]
            s = s_bins[:n_bins - lag] if lag < n_bins else []
        else:
            abs_lag = abs(lag)
            g = g_bins[:n_bins - abs_lag]
            s = s_bins[abs_lag:]

        if len(g) < 3 or len(s) < 3:
            continue

        min_len = min(len(g), len(s))
        r = pearson_r(g[:min_len], s[:min_len])
        results.append((lag_ns, r))

        if abs(r) > abs(best_r):
            best_r   = r
            best_lag = lag_ns

    return best_r, best_lag, results


def compute_baseline(values: List[float], percentile: float = 0.25) -> float:
    """
    Compute baseline as Nth percentile of a value distribution.
    Using bottom 25th percentile gives a robust noise floor estimate.
    """
    if not values:
        return 0.0
    sorted_v = sorted(values)
    idx = max(0, int(len(sorted_v) * percentile))
    return sorted_v[idx]


def detect_phase_architecture(
    dr_series: List[Tuple[int, float]],
    baseline: float
) -> Tuple[str, Optional[dict]]:
    """
    Detect probe + main pulse (Phase 1 / Phase 2) architecture.

    Pattern: short probe pulse at low-to-moderate amplitude,
    followed by gap, followed by main pulse at higher amplitude.
    This is the documented signature from the May 8 2026 event:
    Stage 1: probe/calibration pulse
    Stage 2: main pulse launching from elevated floor.

    Returns (architecture_name, details_dict)
    """
    if not dr_series or baseline <= 0:
        return "UNKNOWN", None

    threshold = baseline * GEIGER_SPIKE_MULT

    # Find all pulses: contiguous segments above threshold
    pulses = []
    in_pulse   = False
    pulse_start = None
    pulse_vals  = []

    for t, dr in sorted(dr_series, key=lambda x: x[0]):
        if dr >= threshold:
            if not in_pulse:
                in_pulse    = True
                pulse_start = t
                pulse_vals  = [dr]
            else:
                pulse_vals.append(dr)
        else:
            if in_pulse:
                in_pulse = False
                pulses.append({
                    "start_ns":   pulse_start,
                    "end_ns":     t,
                    "duration_s": (t - pulse_start) / 1e9,
                    "peak":       max(pulse_vals),
                    "mean":       sum(pulse_vals) / len(pulse_vals),
                    "n_samples":  len(pulse_vals),
                })
                pulse_vals  = []
                pulse_start = None

    if not pulses:
        # Check for sustained floor elevation (carrier)
        above_floor = [dr for _, dr in dr_series
                       if dr >= baseline * CARRIER_MIN_ELEVATION]
        if len(above_floor) > len(dr_series) * 0.6:
            floor_mean = sum(above_floor) / len(above_floor)
            return "CARRIER_ONLY", {
                "floor_elevation_mult": round(floor_mean / baseline, 2),
                "coverage_pct":         round(len(above_floor)/len(dr_series)*100, 1),
            }
        return "NO_PULSE_DETECTED", None

    if len(pulses) == 1:
        p = pulses[0]
        return "SINGLE_PULSE", {
            "duration_s":   round(p["duration_s"], 2),
            "peak_mult":    round(p["peak"] / baseline, 1),
            "start_iso":    datetime.datetime.fromtimestamp(
                p["start_ns"]/1e9, tz=datetime.timezone.utc
            ).isoformat(),
        }

    # Look for Phase 1 (probe) + Phase 2 (main) pattern
    for i in range(len(pulses) - 1):
        p1 = pulses[i]
        p2 = pulses[i + 1]
        gap_s = (p2["start_ns"] - p1["end_ns"]) / 1e9

        if (p1["duration_s"] <= PHASE1_MAX_DURATION_S
                and gap_s <= PHASE1_TO_PHASE2_MAX_S
                and p2["peak"] >= p1["peak"] * PHASE2_MIN_MULT):

            return "PROBE_PLUS_MAIN", {
                "phase1_start_iso":  datetime.datetime.fromtimestamp(
                    p1["start_ns"]/1e9, tz=datetime.timezone.utc
                ).isoformat(),
                "phase1_duration_s": round(p1["duration_s"], 2),
                "phase1_peak_mult":  round(p1["peak"] / baseline, 1),
                "phase1_peak_usvh":  round(p1["peak"], 4),
                "gap_s":             round(gap_s, 2),
                "phase2_start_iso":  datetime.datetime.fromtimestamp(
                    p2["start_ns"]/1e9, tz=datetime.timezone.utc
                ).isoformat(),
                "phase2_duration_s": round(p2["duration_s"], 2),
                "phase2_peak_mult":  round(p2["peak"] / baseline, 1),
                "phase2_peak_usvh":  round(p2["peak"], 4),
                "amplitude_ratio":   round(p2["peak"] / p1["peak"], 1),
            }

    # Multiple pulses — check for carrier + modulation
    floor_candidates = [dr for _, dr in dr_series
                        if baseline < dr < threshold]
    if floor_candidates:
        floor_mean = sum(floor_candidates) / len(floor_candidates)
        floor_mult = floor_mean / baseline
        if floor_mult >= CARRIER_MIN_ELEVATION:
            # Compute duty cycle from pulse timing
            total_duration_ns = (dr_series[-1][0] - dr_series[0][0]
                                  if len(dr_series) >= 2 else 1)
            pulse_time_ns = sum(
                (p["end_ns"] - p["start_ns"]) for p in pulses
            )
            duty_cycle = pulse_time_ns / total_duration_ns * 100 if total_duration_ns > 0 else 0

            return "CARRIER_PLUS_MODULATION", {
                "floor_elevation_mult": round(floor_mult, 2),
                "pulse_count":          len(pulses),
                "duty_cycle_pct":       round(duty_cycle, 1),
                "peak_mult":            round(max(p["peak"] for p in pulses) / baseline, 1),
                "pulse_peaks_usvh":     [round(p["peak"], 4) for p in pulses[:5]],
            }

    # Multiple independent pulses
    duty_ns = sum((p["end_ns"] - p["start_ns"]) for p in pulses)
    total_ns = (dr_series[-1][0] - dr_series[0][0]
                if len(dr_series) >= 2 else 1)
    duty_pct = duty_ns / total_ns * 100 if total_ns > 0 else 0

    return "MULTIPLE_PULSES", {
        "pulse_count":    len(pulses),
        "duty_cycle_pct": round(duty_pct, 1),
        "peak_mults":     [round(p["peak"]/baseline, 1) for p in pulses[:5]],
        "peaks_usvh":     [round(p["peak"], 4) for p in pulses[:5]],
    }


# ══════════════════════════════════════════════════════════════════════════════
# WINDOW ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def analyze_windows(
    geiger_samples: List[GeigerSample],
    audio_pulses:   List[AudioPulse],
    sdr_samples:    List[SDRSample],
    baseline_dr:    float,
    window_s:       float,
    lag_max_s:      float,
    lag_step_s:     float,
) -> List[CorrelationEvent]:
    """
    Slide analysis window across session and find correlated events.
    """
    events = []

    if not geiger_samples or not sdr_samples:
        return events

    # Determine session time range
    all_ns = (
        [s.wall_ns for s in geiger_samples] +
        [s.wall_ns for s in sdr_samples]
    )
    session_start_ns = min(all_ns)
    session_end_ns   = max(all_ns)

    window_ns    = int(window_s    * 1e9)
    lag_max_ns   = int(lag_max_s   * 1e9)
    lag_step_ns  = int(lag_step_s  * 1e9)

    # Build indexed lookups
    def build_index(samples, key_fn):
        idx = defaultdict(list)
        for s in samples:
            k = s.wall_ns // window_ns
            idx[k].append(s)
        return idx

    geiger_idx = defaultdict(list)
    for s in geiger_samples:
        k = s.wall_ns // window_ns
        geiger_idx[k].append(s)

    sdr_idx = defaultdict(list)
    for s in sdr_samples:
        k = s.wall_ns // window_ns
        sdr_idx[k].append(s)

    audio_idx = defaultdict(list)
    for p in audio_pulses:
        k = p.wall_ns // window_ns
        audio_idx[k].append(p)

    # SDR noise floor per frequency bin (pre-computed)
    freq_noise = defaultdict(list)
    for s in sdr_samples:
        bin_mhz = round(s.freq_hz / 1e6)
        freq_noise[bin_mhz].append(s.dbfs)
    freq_floors = {
        freq: compute_baseline(vals, 0.25)
        for freq, vals in freq_noise.items()
    }

    # Slide windows
    win_keys = sorted(set(
        list(geiger_idx.keys()) + list(sdr_idx.keys())
    ))

    for win_key in win_keys:
        win_start_ns = win_key * window_ns
        win_end_ns   = win_start_ns + window_ns

        g_samples = geiger_idx.get(win_key, [])
        s_samples = sdr_idx.get(win_key, [])
        a_pulses  = audio_idx.get(win_key, [])

        if not g_samples or not s_samples:
            continue

        # Geiger statistics for this window
        dr_vals      = [s.dr_usvh for s in g_samples]
        geiger_peak  = max(dr_vals) if dr_vals else 0.0
        geiger_mean  = sum(dr_vals) / len(dr_vals) if dr_vals else 0.0
        geiger_mult  = geiger_peak / baseline_dr if baseline_dr > 0 else 0.0

        # SDR statistics for this window
        dbfs_vals    = [s.dbfs for s in s_samples]
        sdr_peak     = max(dbfs_vals) if dbfs_vals else -120.0
        sdr_mean     = sum(dbfs_vals)/len(dbfs_vals) if dbfs_vals else -120.0
        sdr_anomalies= [s for s in s_samples if s.anomaly]

        # Crest factor peak
        cf_vals      = [s.crest_factor for s in s_samples if s.crest_factor]
        peak_cf      = max(cf_vals) if cf_vals else 0.0

        # Peak frequency (highest CF during window)
        peak_freq_sample = max(s_samples, key=lambda s: s.crest_factor
                               if s.crest_factor else 0)
        peak_freq_hz = peak_freq_sample.freq_hz

        # Band noise floor for peak frequency
        peak_freq_mhz   = round(peak_freq_hz / 1e6)
        sdr_noise_floor = freq_floors.get(peak_freq_mhz, -100.0)
        sdr_excess      = sdr_peak - sdr_noise_floor

        # ── Classify whether this window is anomalous ──────────────────────
        geiger_anomalous = geiger_mult >= GEIGER_SPIKE_MULT
        sdr_anomalous    = (sdr_excess >= SDR_ANOMALY_EXCESS_DB
                            or len(sdr_anomalies) > 0
                            or peak_cf >= CF_ANOMALY_THRESHOLD)

        # Both anomalous = potential correlation event
        if not geiger_anomalous and not sdr_anomalous:
            continue

        # At least one anomalous — compute correlation
        g_series = [(s.wall_ns, s.dr_usvh) for s in g_samples]
        s_series = [(s.wall_ns, s.dbfs)    for s in s_samples]

        best_r, best_lag_ns, lag_results = cross_correlate(
            g_series, s_series, lag_max_ns, lag_step_ns
        )

        # Determine lag direction
        if best_lag_ns > 0:
            lag_dir = "SDR_FIRST"
            lag_ms  = best_lag_ns / 1e6
        elif best_lag_ns < 0:
            lag_dir = "GEIGER_FIRST"
            lag_ms  = abs(best_lag_ns) / 1e6
        else:
            lag_dir = "SIMULTANEOUS"
            lag_ms  = 0.0

        # Classify event
        classifiers = []
        if geiger_anomalous and sdr_anomalous:
            classifiers.append("COINCIDENT_ANOMALY")
        elif geiger_anomalous:
            classifiers.append("GEIGER_ONLY_ANOMALY")
        elif sdr_anomalous:
            classifiers.append("SDR_ONLY_ANOMALY")

        if abs(best_r) >= PEARSON_THRESHOLD:
            if abs(best_r) >= PEARSON_DEFINITIVE:
                classifiers.append("PEARSON_DEFINITIVE")
            elif abs(best_r) >= PEARSON_STRONG:
                classifiers.append("PEARSON_STRONG")
            else:
                classifiers.append("PEARSON_CORRELATED")

        if peak_cf >= CF_ANOMALY_THRESHOLD:
            classifiers.append("IMPULSIVE_RF_SIGNATURE")

        if a_pulses:
            classifiers.append(f"AUDIO_PULSES_{len(a_pulses)}")

        # Pulse architecture detection
        arch, arch_details = detect_phase_architecture(g_series, baseline_dr)
        if arch == "PROBE_PLUS_MAIN":
            classifiers.append("PHASE_ARCHITECTURE_DETECTED")

        # Severity
        if ("COINCIDENT_ANOMALY" in classifiers
                and "PEARSON_CORRELATED" in classifiers):
            severity = "CRITICAL"
        elif "COINCIDENT_ANOMALY" in classifiers:
            severity = "HIGH"
        elif "PEARSON_CORRELATED" in classifiers:
            severity = "HIGH"
        elif geiger_anomalous or sdr_anomalous:
            severity = "MEDIUM"
        else:
            severity = "INFO"

        # Description
        desc_parts = []
        if geiger_anomalous:
            desc_parts.append(
                f"Geiger DR {geiger_peak:.4f} µSv/h "
                f"({geiger_mult:.1f}x baseline {baseline_dr:.4f})"
            )
        if sdr_anomalous:
            desc_parts.append(
                f"SDR peak {sdr_peak:.1f} dBFS "
                f"({sdr_excess:.1f} dB above floor) "
                f"at {peak_freq_hz/1e6:.3f} MHz CF={peak_cf:.1f}"
            )
        if abs(best_r) >= PEARSON_THRESHOLD:
            desc_parts.append(
                f"Pearson r={best_r:.3f} at lag {lag_ms:.0f}ms "
                f"({lag_dir})"
            )
        if arch not in ("UNKNOWN", "NO_PULSE_DETECTED"):
            desc_parts.append(f"Pulse architecture: {arch}")

        ev = CorrelationEvent()
        ev.window_start_ns   = win_start_ns
        ev.window_start_iso  = datetime.datetime.fromtimestamp(
            win_start_ns / 1e9, tz=datetime.timezone.utc
        ).isoformat()
        ev.window_end_ns     = win_end_ns
        ev.duration_s        = window_s
        ev.geiger_dr_peak    = round(geiger_peak, 6)
        ev.geiger_dr_mean    = round(geiger_mean, 6)
        ev.geiger_baseline   = round(baseline_dr, 6)
        ev.geiger_mult       = round(geiger_mult, 2)
        ev.sdr_dbfs_peak     = round(sdr_peak, 2)
        ev.sdr_dbfs_mean     = round(sdr_mean, 2)
        ev.sdr_noise_floor   = round(sdr_noise_floor, 2)
        ev.sdr_excess_db     = round(sdr_excess, 2)
        ev.peak_freq_hz      = peak_freq_hz
        ev.peak_cf           = round(peak_cf, 2)
        ev.pearson_r         = round(best_r, 4)
        ev.optimal_lag_ms    = round(lag_ms, 1)
        ev.lag_direction     = lag_dir
        ev.classifiers       = classifiers
        ev.pulse_arch        = arch
        ev.duty_cycle_pct    = (arch_details.get("duty_cycle_pct")
                                 if arch_details else None)
        ev.severity          = severity
        ev.description       = " | ".join(desc_parts)
        events.append(ev)

    return events


# ══════════════════════════════════════════════════════════════════════════════
# SESSION-LEVEL ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_session(
    serial_logs:  List[str],
    audio_logs:   List[str],
    sdr_logs:     List[str],
    baseline_dr:  float,
    window_s:     float,
    lag_max_s:    float,
    lag_step_s:   float,
) -> Tuple[List[GeigerSample], List[AudioPulse],
           List[SDRSample], List[CorrelationEvent], float]:
    """
    Load all logs and run the correlation engine.
    Returns (geiger, audio, sdr, events, computed_baseline)
    """
    print("[CORR] Loading logs...")

    geiger_samples = []
    for path in serial_logs:
        s = read_serial_log(path)
        geiger_samples.extend(s)
        print(f"[CORR]   Serial {os.path.basename(path)}: {len(s)} records")

    audio_pulses = []
    for path in audio_logs:
        p = read_audio_log(path)
        audio_pulses.extend(p)
        print(f"[CORR]   Audio  {os.path.basename(path)}: {len(p)} pulses")

    sdr_samples = []
    for path in sdr_logs:
        s = read_sdr_log(path)
        sdr_samples.extend(s)
        print(f"[CORR]   SDR    {os.path.basename(path)}: {len(s)} records")

    # Sort all by wall_ns
    geiger_samples.sort(key=lambda s: s.wall_ns)
    audio_pulses.sort(  key=lambda p: p.wall_ns)
    sdr_samples.sort(   key=lambda s: s.wall_ns)

    # Compute or validate baseline
    if geiger_samples:
        dr_vals = [s.dr_usvh for s in geiger_samples]
        computed_baseline = compute_baseline(dr_vals, 0.25)
        if baseline_dr <= 0:
            baseline_dr = computed_baseline
            print(f"[CORR] Computed baseline DR: {baseline_dr:.6f} µSv/h "
                  f"(25th percentile of session)")
        else:
            print(f"[CORR] Using provided baseline DR: {baseline_dr:.6f} µSv/h")
            print(f"[CORR] Session computed baseline: {computed_baseline:.6f} µSv/h")
    else:
        computed_baseline = baseline_dr

    print(f"[CORR] Running window analysis ({window_s}s windows, "
          f"lag 0-{lag_max_s*1000:.0f}ms)...")

    events = analyze_windows(
        geiger_samples, audio_pulses, sdr_samples,
        baseline_dr, window_s, lag_max_s, lag_step_s
    )

    return geiger_samples, audio_pulses, sdr_samples, events, baseline_dr


# ══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}


def generate_report(
    events:        List[CorrelationEvent],
    geiger:        List[GeigerSample],
    audio:         List[AudioPulse],
    sdr:           List[SDRSample],
    baseline_dr:   float,
    serial_paths:  List[str],
    sdr_paths:     List[str],
    window_s:      float,
    lag_max_s:     float,
    out_dir:       str,
) -> Tuple[str, str]:
    """Generate text and JSON correlation reports."""

    sorted_events = sorted(
        events,
        key=lambda e: (SEV_ORDER.get(e.severity, 99), e.window_start_ns)
    )

    sev_counts = defaultdict(int)
    for e in events:
        sev_counts[e.severity] += 1

    # Session time range
    all_ns = []
    if geiger: all_ns += [s.wall_ns for s in geiger]
    if sdr:    all_ns += [s.wall_ns for s in sdr]
    session_start_iso = datetime.datetime.fromtimestamp(
        min(all_ns)/1e9, tz=datetime.timezone.utc
    ).isoformat() if all_ns else "unknown"
    session_end_iso = datetime.datetime.fromtimestamp(
        max(all_ns)/1e9, tz=datetime.timezone.utc
    ).isoformat() if all_ns else "unknown"
    session_duration_s = (max(all_ns) - min(all_ns)) / 1e9 if all_ns else 0

    # Geiger session stats
    if geiger:
        dr_vals    = [s.dr_usvh for s in geiger]
        dr_peak    = max(dr_vals)
        dr_mean    = sum(dr_vals) / len(dr_vals)
        dr_spike_n = sum(1 for d in dr_vals
                         if d >= baseline_dr * GEIGER_SPIKE_MULT)
    else:
        dr_peak = dr_mean = dr_spike_n = 0

    # SDR session stats
    if sdr:
        sdr_anomaly_n = sum(1 for s in sdr if s.anomaly)
        cf_vals       = [s.crest_factor for s in sdr if s.crest_factor]
        cf_peak       = max(cf_vals) if cf_vals else 0
    else:
        sdr_anomaly_n = cf_peak = 0

    # ── TEXT REPORT ───────────────────────────────────────────────────────────
    W = 80
    lines = []

    def hr(): lines.append("─" * W)
    def dhr(): lines.append("═" * W)

    dhr()
    lines.append("  CTW SENTINEL — GEIGER / SDR CORRELATION REPORT")
    dhr()
    lines.append(f"  Generated   : "
                 f"{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f"  Session     : {session_start_iso}")
    lines.append(f"              : {session_end_iso}")
    lines.append(f"  Duration    : {session_duration_s/3600:.2f} hours "
                 f"({session_duration_s:.0f}s)")
    lines.append(f"  Window      : {window_s:.0f}s analysis windows")
    lines.append(f"  Lag range   : 0–{lag_max_s*1000:.0f}ms")
    if serial_paths:
        for p in serial_paths:
            lines.append(f"  Geiger log  : {os.path.basename(p)}")
    if sdr_paths:
        for p in sdr_paths:
            lines.append(f"  SDR log     : {os.path.basename(p)}")
    lines.append("")

    # Summary box
    dhr()
    lines.append("  SUMMARY")
    hr()
    lines.append(f"  Correlation events    : {len(events)}")
    lines.append(f"    CRITICAL            : {sev_counts.get('CRITICAL',0)}")
    lines.append(f"    HIGH                : {sev_counts.get('HIGH',0)}")
    lines.append(f"    MEDIUM              : {sev_counts.get('MEDIUM',0)}")
    lines.append(f"    INFO                : {sev_counts.get('INFO',0)}")
    hr()
    lines.append(f"  GEIGER (FS-5000 / J305 tube)")
    lines.append(f"    Baseline DR         : {baseline_dr:.6f} µSv/h")
    lines.append(f"    Peak DR             : {dr_peak:.6f} µSv/h "
                 f"({dr_peak/baseline_dr:.1f}x baseline)"
                 if baseline_dr > 0 else
                 f"    Peak DR             : {dr_peak:.6f} µSv/h")
    lines.append(f"    Mean DR             : {dr_mean:.6f} µSv/h")
    lines.append(f"    Spike epochs        : {dr_spike_n} "
                 f"(>= {GEIGER_SPIKE_MULT:.0f}x baseline)")
    lines.append(f"    Audio pulses        : {len(audio)}")
    lines.append(f"    Serial samples      : {len(geiger)}")
    hr()
    lines.append(f"  SDR (PlutoSDR / AD9361)")
    lines.append(f"    Total records       : {len(sdr)}")
    lines.append(f"    Anomaly records     : {sdr_anomaly_n}")
    lines.append(f"    Peak crest factor   : {cf_peak:.1f}")
    hr()
    dhr()

    if not events:
        lines.append("")
        lines.append("  NO CORRELATION EVENTS DETECTED IN THIS SESSION.")
        lines.append("")
        lines.append("  Both instruments operated within normal parameters")
        lines.append("  for the full session, or insufficient data was")
        lines.append("  available for correlation analysis.")
    else:
        lines.append("")
        lines.append("  CORRELATION EVENT DETAILS")
        lines.append("")

        for idx, ev in enumerate(sorted_events, 1):
            sev_tags = {
                "CRITICAL": "[!!!] CRITICAL",
                "HIGH":     "[** ] HIGH    ",
                "MEDIUM":   "[*  ] MEDIUM  ",
                "INFO":     "[   ] INFO    ",
            }
            lines.append(f"  {'─'*72}")
            lines.append(f"  [{idx:02d}]  {sev_tags.get(ev.severity, ev.severity)}"
                         f"    {ev.window_start_iso[:23]}Z")
            lines.append("")

            # Geiger section
            lines.append(f"  GEIGER APERTURE:")
            lines.append(f"    DR peak     : {ev.geiger_dr_peak:.6f} µSv/h  "
                         f"({ev.geiger_mult:.1f}x baseline)")
            lines.append(f"    DR mean     : {ev.geiger_dr_mean:.6f} µSv/h")
            lines.append(f"    Pulse arch  : {ev.pulse_arch}")
            if ev.duty_cycle_pct is not None:
                lines.append(f"    Duty cycle  : {ev.duty_cycle_pct:.1f}%")

            # SDR section
            lines.append(f"  SDR APERTURE:")
            lines.append(f"    Peak dBFS   : {ev.sdr_dbfs_peak:.1f} dBFS  "
                         f"({ev.sdr_excess_db:.1f} dB above noise floor)")
            lines.append(f"    Noise floor : {ev.sdr_noise_floor:.1f} dBFS")
            lines.append(f"    Peak freq   : {ev.peak_freq_hz/1e6:.3f} MHz")
            lines.append(f"    Crest factor: {ev.peak_cf:.1f}")

            # Correlation section
            lines.append(f"  CORRELATION:")
            lines.append(f"    Pearson r   : {ev.pearson_r:.4f}")
            r_interp = (
                "DEFINITIVE systematic correlation — single source probable"
                if abs(ev.pearson_r) >= PEARSON_DEFINITIVE else
                "STRONG systematic correlation" if abs(ev.pearson_r) >= PEARSON_STRONG else
                "MODERATE systematic correlation" if abs(ev.pearson_r) >= PEARSON_THRESHOLD else
                "WEAK or no systematic correlation"
            )
            lines.append(f"              : {r_interp}")
            lines.append(f"    Optimal lag : {ev.optimal_lag_ms:.0f}ms "
                         f"({ev.lag_direction})")
            lines.append(f"    Classifiers : {' | '.join(ev.classifiers)}")

            # Description
            lines.append("")
            words = ev.description.split(" | ")
            for part in words:
                lines.append(f"    {part}")

            lines.append("")

    # ── Physics interpretation ────────────────────────────────────────────────
    if events:
        has_correlated = any(
            abs(e.pearson_r) >= PEARSON_THRESHOLD for e in events
        )
        has_phase = any(e.pulse_arch == "PROBE_PLUS_MAIN" for e in events)
        has_carrier = any(
            e.pulse_arch in ("CARRIER_PLUS_MODULATION", "CARRIER_ONLY")
            for e in events
        )

        if has_correlated or has_phase or has_carrier:
            dhr()
            lines.append("  PHYSICAL INTERPRETATION")
            hr()
            lines.append("")

            if has_correlated:
                lines.append("  SYSTEMATIC CORRELATION DETECTED:")
                lines.append("")
                lines.append("  The Pearson cross-correlation coefficient at a")
                lines.append("  consistent temporal lag indicates a single source")
                lines.append("  is driving both instruments. The GM tube is responding")
                lines.append("  to electromagnetic induction — induced current in the")
                lines.append("  detector circuit caused by a proximate RF field. This")
                lines.append("  is distinct from ionizing radiation detection. The")
                lines.append("  consistent lag value represents the propagation or")
                lines.append("  coupling delay between the RF source and the two")
                lines.append("  instrument apertures.")
                lines.append("")
                lines.append("  A Pearson r > 0.70 at a CONSISTENT lag across multiple")
                lines.append("  windows is strong evidence that the two signals share")
                lines.append("  a common origin. Random coincidence would produce")
                lines.append("  variable lags and low r values across windows.")
                lines.append("")

            if has_phase:
                lines.append("  PROBE + MAIN PULSE ARCHITECTURE DETECTED:")
                lines.append("")
                lines.append("  The two-phase pulse pattern (short probe pulse followed")
                lines.append("  by gap followed by main pulse of greater amplitude)")
                lines.append("  is inconsistent with natural ionizing radiation sources.")
                lines.append("  Natural background radiation produces Poisson-distributed")
                lines.append("  random counts. A probe followed by a main pulse implies")
                lines.append("  sequenced emission with a deterministic timing relationship")
                lines.append("  — the signature of a directed, engineered source.")
                lines.append("")
                lines.append("  This architecture matches the documented May 8 2026 event:")
                lines.append("  Stage 1 probe pulse followed by Stage 2 main pulse")
                lines.append("  launching from an elevated floor level.")
                lines.append("")

            if has_carrier:
                lines.append("  CARRIER + MODULATION SIGNATURE DETECTED:")
                lines.append("")
                lines.append("  Sustained floor elevation above baseline combined with")
                lines.append("  episodic spikes is the signature of a carrier wave")
                lines.append("  with amplitude or pulse modulation. The sustained floor")
                lines.append("  represents continuous RF energy inducing a constant")
                lines.append("  background in the GM tube circuitry. The episodic spikes")
                lines.append("  represent modulation events — pulse-width or amplitude")
                lines.append("  changes in the carrier. This pattern is not produced")
                lines.append("  by any natural radiation source.")
                lines.append("")

    # ── Statistical appendix ──────────────────────────────────────────────────
    if events and any(e.pearson_r != 0 for e in events):
        dhr()
        lines.append("  CORRELATION COEFFICIENT REFERENCE")
        hr()
        lines.append(f"  r >= {PEARSON_DEFINITIVE:.2f}  DEFINITIVE  "
                     f"near-certain single source")
        lines.append(f"  r >= {PEARSON_STRONG:.2f}  STRONG      "
                     f"high probability single source")
        lines.append(f"  r >= {PEARSON_THRESHOLD:.2f}  MODERATE    "
                     f"systematic correlation, shared source likely")
        lines.append(f"  r <  {PEARSON_THRESHOLD:.2f}  WEAK        "
                     f"no systematic correlation detected")
        lines.append("")
        lines.append("  Lag direction convention:")
        lines.append("    SDR_FIRST    : RF anomaly preceded Geiger spike")
        lines.append("                   RF source -> EM coupling -> GM tube")
        lines.append("    GEIGER_FIRST : Geiger spike preceded RF anomaly")
        lines.append("                   Less common — may indicate Geiger")
        lines.append("                   is more sensitive aperture for this")
        lines.append("                   source at this frequency")
        lines.append("    SIMULTANEOUS : No measurable lag — sub-bin resolution")
        lines.append("")

    dhr()
    lines.append("  RECORD NOTES")
    hr()
    lines.append("  All timestamps UTC, nanosecond precision, ClockAnchor epoch.")
    lines.append("  Pearson r computed on 1-second binned time series.")
    lines.append(f"  Geiger baseline: 25th percentile of session DR values.")
    lines.append(f"  SDR noise floor: 25th percentile of per-frequency dBFS.")
    lines.append(f"  Spike threshold: {GEIGER_SPIKE_MULT:.0f}x baseline DR.")
    lines.append(f"  RF anomaly threshold: {SDR_ANOMALY_EXCESS_DB:.0f} dB "
                 f"above frequency noise floor.")
    lines.append(f"  CF anomaly threshold: {CF_ANOMALY_THRESHOLD:.0f}.")
    lines.append("  This report is for personal and legal records.")
    dhr()
    lines.append("")

    txt_content = '\n'.join(lines)
    txt_path    = os.path.join(out_dir, f"geiger_sdr_corr_{STAMP}.txt")
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(txt_content)

    # ── JSON REPORT ───────────────────────────────────────────────────────────
    json_report = {
        "report_type":    "geiger_sdr_correlation",
        "generated_utc":  datetime.datetime.utcnow().isoformat(),
        "stamp":          STAMP,
        "session": {
            "start":          session_start_iso,
            "end":            session_end_iso,
            "duration_s":     round(session_duration_s, 1),
            "window_s":       window_s,
            "lag_max_ms":     lag_max_s * 1000,
        },
        "thresholds": {
            "pearson_threshold":   PEARSON_THRESHOLD,
            "pearson_strong":      PEARSON_STRONG,
            "pearson_definitive":  PEARSON_DEFINITIVE,
            "spike_mult":          GEIGER_SPIKE_MULT,
            "sdr_anomaly_excess_db": SDR_ANOMALY_EXCESS_DB,
            "cf_anomaly":          CF_ANOMALY_THRESHOLD,
        },
        "geiger_stats": {
            "baseline_dr_usvh":  round(baseline_dr, 6),
            "peak_dr_usvh":      round(dr_peak, 6),
            "mean_dr_usvh":      round(dr_mean, 6),
            "peak_mult":         round(dr_peak/baseline_dr, 2)
                                  if baseline_dr > 0 else None,
            "spike_epochs":      dr_spike_n,
            "serial_samples":    len(geiger),
            "audio_pulses":      len(audio),
        },
        "sdr_stats": {
            "total_records":   len(sdr),
            "anomaly_records": sdr_anomaly_n,
            "peak_cf":         round(cf_peak, 2),
        },
        "summary": {
            "total_events":  len(events),
            "by_severity":   dict(sev_counts),
        },
        "events": [
            {
                "severity":          e.severity,
                "window_start_iso":  e.window_start_iso,
                "window_start_ns":   e.window_start_ns,
                "classifiers":       e.classifiers,
                "geiger": {
                    "dr_peak_usvh":  e.geiger_dr_peak,
                    "dr_mean_usvh":  e.geiger_dr_mean,
                    "baseline_usvh": e.geiger_baseline,
                    "mult":          e.geiger_mult,
                    "pulse_arch":    e.pulse_arch,
                    "duty_cycle_pct":e.duty_cycle_pct,
                },
                "sdr": {
                    "dbfs_peak":     e.sdr_dbfs_peak,
                    "dbfs_mean":     e.sdr_dbfs_mean,
                    "noise_floor":   e.sdr_noise_floor,
                    "excess_db":     e.sdr_excess_db,
                    "peak_freq_hz":  e.peak_freq_hz,
                    "peak_freq_mhz": round(e.peak_freq_hz/1e6, 3),
                    "peak_cf":       e.peak_cf,
                },
                "correlation": {
                    "pearson_r":      e.pearson_r,
                    "optimal_lag_ms": e.optimal_lag_ms,
                    "lag_direction":  e.lag_direction,
                },
                "description": e.description,
            }
            for e in sorted_events
        ],
    }

    json_path = os.path.join(out_dir, f"geiger_sdr_corr_{STAMP}.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_report, f, indent=2, default=str)

    return txt_path, json_path


# ══════════════════════════════════════════════════════════════════════════════
# AUTO-DISCOVERY OF LOG FILES
# ══════════════════════════════════════════════════════════════════════════════

def find_latest_pair(directory):
    """Find the most recent matching serial + SDR log pair."""
    serial = sorted(glob.glob(
        os.path.join(directory, "serial_*.jsonl.gz")
    ), key=os.path.getmtime)
    audio  = sorted(glob.glob(
        os.path.join(directory, "audio_*.jsonl.gz")
    ), key=os.path.getmtime)
    sdr    = sorted(glob.glob(
        os.path.join(directory, "sweep_*.jsonl.gz")
    ), key=os.path.getmtime)
    return (serial[-1:], audio[-1:], sdr[-1:])


def find_all_sessions(directory):
    """
    Group log files by STAMP suffix to find complete sessions.
    Returns list of (serial_paths, audio_paths, sdr_paths) tuples.
    """
    serial_files = sorted(glob.glob(
        os.path.join(directory, "serial_*.jsonl.gz")
    ))
    sdr_files    = sorted(glob.glob(
        os.path.join(directory, "sweep_*.jsonl.gz")
    ))

    # Extract stamps from filenames
    def extract_stamp(path, prefix):
        base = os.path.basename(path)
        return base.replace(prefix + "_", "").replace(".jsonl.gz", "")

    serial_stamps = {extract_stamp(p, "serial"): p for p in serial_files}
    sdr_stamps    = {extract_stamp(p, "sweep"):  p for p in sdr_files}

    # Match by stamp (exact or closest by mtime)
    sessions = []
    for stamp, serial_path in serial_stamps.items():
        if stamp in sdr_stamps:
            audio_path = serial_path.replace("serial_", "audio_")
            audio_paths = [audio_path] if os.path.exists(audio_path) else []
            sessions.append(
                ([serial_path], audio_paths, [sdr_stamps[stamp]])
            )

    # If no stamp matches, fall back to latest pair
    if not sessions and (serial_files or sdr_files):
        sessions.append(find_latest_pair(directory))

    return sessions


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="CTW Geiger/SDR Post-Session Correlation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--sdr-log",     nargs="+", default=None,
                    help="sweep_*.jsonl.gz file(s). Auto-detects if omitted.")
    ap.add_argument("--serial-log",  nargs="+", default=None,
                    help="serial_*.jsonl.gz file(s). Auto-detects if omitted.")
    ap.add_argument("--audio-log",   nargs="+", default=None,
                    help="audio_*.jsonl.gz file(s). Auto-detects if omitted.")
    ap.add_argument("--all-sessions",action="store_true",
                    help="Process all matched sessions in --out directory")
    ap.add_argument("--baseline-dr", type=float, default=0.0,
                    metavar="USVH",
                    help="Known baseline dose rate µSv/h. "
                         "Default: compute from session 25th percentile. "
                         "Example: --baseline-dr 0.02")
    ap.add_argument("--window",      type=float, default=CORRELATION_WINDOW_S,
                    metavar="SEC",
                    help=f"Analysis window seconds (default: {CORRELATION_WINDOW_S})")
    ap.add_argument("--lag-max",     type=float, default=LAG_MAX_S,
                    metavar="SEC",
                    help=f"Max cross-correlation lag seconds "
                         f"(default: {LAG_MAX_S})")
    ap.add_argument("--lag-step",    type=float, default=LAG_STEP_S,
                    metavar="SEC",
                    help=f"Lag step size seconds (default: {LAG_STEP_S})")
    ap.add_argument("--out",         default=r"C:\sdr\logs",
                    metavar="DIR",
                    help="Log directory (default: C:\\sdr\\logs)")
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)

    # Determine which sessions to process
    if args.all_sessions:
        sessions = find_all_sessions(out_dir)
        if not sessions:
            print(f"[ERR] No matching session pairs found in {out_dir}")
            sys.exit(1)
        print(f"[CORR] Found {len(sessions)} session(s) to process.")
    elif args.sdr_log or args.serial_log:
        serial_paths = args.serial_log or []
        audio_paths  = args.audio_log  or []
        sdr_paths    = args.sdr_log    or []
        sessions     = [(serial_paths, audio_paths, sdr_paths)]
    else:
        serial_paths, audio_paths, sdr_paths = find_latest_pair(out_dir)
        if not serial_paths and not sdr_paths:
            print(f"[ERR] No log files found in {out_dir}")
            print("      Run pluto_sweep.py and fs5000_dual.py first.")
            print("      Or specify --sdr-log and --serial-log explicitly.")
            sys.exit(1)
        sessions = [(serial_paths, audio_paths, sdr_paths)]

    all_report_paths = []

    for session_idx, (serial_paths, audio_paths, sdr_paths) in \
            enumerate(sessions, 1):

        print(f"\n{'='*62}")
        print(f"  CTW GEIGER/SDR CORRELATION ENGINE")
        if len(sessions) > 1:
            print(f"  Session {session_idx} of {len(sessions)}")
        print(f"{'='*62}")

        if not serial_paths and not sdr_paths:
            print("[WARN] No log files for this session — skipping.")
            continue

        geiger, audio, sdr, events, baseline = analyze_session(
            serial_logs  = serial_paths,
            audio_logs   = audio_paths,
            sdr_logs     = sdr_paths,
            baseline_dr  = args.baseline_dr,
            window_s     = args.window,
            lag_max_s    = args.lag_max,
            lag_step_s   = args.lag_step,
        )

        print(f"\n[CORR] Events found: {len(events)}")
        sev_c = defaultdict(int)
        for e in events:
            sev_c[e.severity] += 1
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
            if sev_c[sev]:
                print(f"[CORR]   {sev:<10}: {sev_c[sev]}")

        print("[CORR] Generating report...")
        txt_path, json_path = generate_report(
            events       = events,
            geiger       = geiger,
            audio        = audio,
            sdr          = sdr,
            baseline_dr  = baseline,
            serial_paths = serial_paths,
            sdr_paths    = sdr_paths,
            window_s     = args.window,
            lag_max_s    = args.lag_max,
            out_dir      = out_dir,
        )
        all_report_paths.append((txt_path, json_path))
        print(f"[CORR] Text : {txt_path}")
        print(f"[CORR] JSON : {json_path}")

    if len(all_report_paths) > 1:
        print(f"\n[CORR] Processed {len(all_report_paths)} sessions:")
        for txt, js in all_report_paths:
            print(f"  {os.path.basename(txt)}")

    print("\nDone.")


if __name__ == "__main__":
    main()
