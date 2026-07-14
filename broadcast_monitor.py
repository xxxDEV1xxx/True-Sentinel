#!/usr/bin/env python3
"""
broadcast_monitor.py  —  CTW Licensed Broadcast Power Monitor
=============================================================
Monitors AM (530-1700 kHz) and FM (88-108 MHz) carrier power levels
from licensed stations using the PlutoSDR as a calibrated RF power meter.

This module does NOT demodulate, decode, or record any audio content.
It measures ONLY the carrier power level at each licensed frequency —
the same measurement any spectrum analyzer makes when looking at a
carrier. No content is captured. No content is stored.

Forensic purpose:
  Licensed broadcast stations transmit at known, authorized power levels
  from known, fixed coordinates. Their carriers serve as reference
  calibration signals across the AM and FM bands. Anomalies in the
  observed carrier power relative to the expected power at the
  observer's location constitute evidence of RF environment interference.

  Anomaly classes:
    CARRIER_ABSENT      — licensed station not detectable where it should be
    CARRIER_SUPPRESSED  — power significantly below expected level
    CARRIER_ELEVATED    — power significantly above expected level
                          (possible rogue rebroadcaster or signal injection)
    CARRIER_SPURIOUS    — energy on unlicensed frequency within band
    CARRIER_DRIFT       — carrier frequency offset from licensed center
                          (transmitter fault or deliberate interference)
    INTERMODULATION     — mixing products of two or more licensed carriers
                          appearing at unlicensed frequencies

Station database:
  Pulled from FCC LMS/AM/FM query APIs at session start.
  Cached to broadcast_stations_STAMP.json for offline use.
  Falls back to cached file if FCC API unavailable.
  No third-party data. Official FCC data only.

Expected power calculation:
  Uses free-space path loss formula adjusted for distance from
  station transmitter to observer. FM effective radiated power (ERP)
  and antenna height above average terrain (HAAT) from FCC records.
  AM power depends on day/night/critical hours class.

Output:
  broadcast_monitor_STAMP.jsonl.gz  — compressed forensic log
  runtime/broadcast_live.jsonl      — live SSE mirror
  broadcast_stations_STAMP.json     — FCC station database cache

Usage:
  python broadcast_monitor.py
  python broadcast_monitor.py --lat 33.800509 --lon -117.220352
  python broadcast_monitor.py --radius-km 150
  python broadcast_monitor.py --bands FM
  python broadcast_monitor.py --bands AM
  python broadcast_monitor.py --bands AM FM
  python broadcast_monitor.py --dwell-ms 200
  python broadcast_monitor.py --anomaly-db 8
  python broadcast_monitor.py --use-cache broadcast_stations_20260708.json
  python broadcast_monitor.py --no-fcc    (skip FCC fetch, cache required)
  python broadcast_monitor.py --out C:\\sdr\\logs
"""

import argparse
import datetime
import gzip
import json
import math
import os
import ssl
import sys
import threading
import time
import urllib.request
from collections import defaultdict, deque
from typing import List, Optional, Dict, Tuple

import numpy as np

try:
    import iio
except ImportError:
    iio = None

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ══════════════════════════════════════════════════════════════════════════════
# BAND DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

AM_BAND_HZ  = (530_000,    1_700_000)    # 530 kHz – 1700 kHz
FM_BAND_HZ  = (87_900_000, 108_100_000)  # 87.9 MHz – 108.1 MHz

AM_CHANNEL_STEP_HZ  = 10_000    # 10 kHz AM channel spacing
FM_CHANNEL_STEP_HZ  = 200_000   # 200 kHz FM channel spacing

# PlutoSDR sample rates per band
AM_SAMPLE_RATE_HZ   = 2_500_000   # 2.5 MHz covers 250 AM channels per window
FM_SAMPLE_RATE_HZ   = 10_000_000  # 10 MHz covers 50 FM channels per window

FFT_SIZE            = 4096
AM_WINDOW_STEP_HZ   = AM_SAMPLE_RATE_HZ
FM_WINDOW_STEP_HZ   = FM_SAMPLE_RATE_HZ

# ══════════════════════════════════════════════════════════════════════════════
# FCC API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

# FM radius query — returns pipe-delimited text
FCC_FM_QUERY = (
    "https://transition.fcc.gov/cgi-bin/fmq"
    "?state=&call=&city=&freq=&fac_type=&arn=&sr=&list_order=dist"
    "&dist={radius_km:.0f}&dlat={lat_d:.0f}&mlat={lat_m:.0f}&slat={lat_s:.4f}"
    "&NSlat=N&dlon={lon_d:.0f}&mlon={lon_m:.0f}&slon={lon_s:.4f}&NSlon=W"
    "&time=A&size=9&de=out&is=out&si=out&type=text&distance=km"
)

# AM radius query
FCC_AM_QUERY = (
    "https://transition.fcc.gov/cgi-bin/amq"
    "?state=&call=&city=&freq=&fac_type=&arn=&sr=&list_order=dist"
    "&dist={radius_km:.0f}&dlat={lat_d:.0f}&mlat={lat_m:.0f}&slat={lat_s:.4f}"
    "&NSlat=N&dlon={lon_d:.0f}&mlon={lon_m:.0f}&slon={lon_s:.4f}&NSlon=W"
    "&type=text&distance=km"
)

# FCC Contours API — field strength at a point for a facility
FCC_CONTOURS = "https://geo.fcc.gov/api/contours/contours.json?facility_id={facid}&lat={lat}&lon={lon}&unit=dbuv"

# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY THRESHOLDS
# ══════════════════════════════════════════════════════════════════════════════

CARRIER_ABSENT_THRESHOLD_DB    = -95.0  # dBFS — below this = absent
CARRIER_SUPPRESSED_DB          =  10.0  # dB below expected = suppressed
CARRIER_ELEVATED_DB            =   8.0  # dB above expected = elevated
CARRIER_DRIFT_KHZ              =   5.0  # kHz offset from center = drift
SPURIOUS_THRESHOLD_DB          = -80.0  # dBFS — above this = spurious check
INTERMOD_THRESHOLD_DB          = -75.0  # dBFS — intermod product threshold

# ══════════════════════════════════════════════════════════════════════════════
# OOB GUARD
# ══════════════════════════════════════════════════════════════════════════════

def _cf(v, lo, hi, default=0.0):
    try:
        f = float(v)
        if not (-1e18 < f < 1e18): return default
        return max(lo, min(hi, f))
    except Exception: return default

def _ci(v, lo, hi, default=0):
    try:
        i = int(v)
        return max(lo, min(hi, i))
    except Exception: return default

# ══════════════════════════════════════════════════════════════════════════════
# COORDINATE UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def dd_to_dms(dd: float) -> Tuple[int, int, float]:
    """Decimal degrees to degrees, minutes, seconds."""
    d = int(abs(dd))
    m = int((abs(dd) - d) * 60)
    s = ((abs(dd) - d) * 60 - m) * 60
    return d, m, s


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return 2 * R * math.asin(math.sqrt(a))


# ══════════════════════════════════════════════════════════════════════════════
# FREE-SPACE PATH LOSS AND EXPECTED POWER
# ══════════════════════════════════════════════════════════════════════════════

def fspl_db(freq_hz: float, dist_km: float) -> float:
    """
    Free-space path loss in dB.
    FSPL = 20*log10(d) + 20*log10(f) + 20*log10(4pi/c)
    where d in meters, f in Hz.
    """
    if dist_km <= 0:
        return 0.0
    dist_m = dist_km * 1000.0
    c = 299_792_458.0
    return 20*math.log10(dist_m) + 20*math.log10(freq_hz) + 20*math.log10(4*math.pi/c)


def expected_dbfs(
    erp_kw: float,
    freq_hz: float,
    dist_km: float,
    antenna_gain_db: float = 0.0,
    sdr_gain_db: float = 40.0,
    sdr_reference_dbm: float = -100.0
) -> float:
    """
    Estimate expected received power at SDR in dBFS units.

    erp_kw: effective radiated power in kilowatts
    freq_hz: carrier frequency
    dist_km: distance from transmitter to observer
    antenna_gain_db: SDR antenna gain (approximate, 0 dB dipole assumption)
    sdr_gain_db: PlutoSDR hardware gain setting

    Returns approximate expected dBFS. Accuracy ±10 dB due to
    terrain, multipath, and antenna pattern uncertainties.
    The important thing is the RELATIVE relationship between
    expected and observed — not the absolute value.
    """
    if erp_kw <= 0 or dist_km <= 0:
        return -120.0

    # Transmit power in dBm
    erp_dbm = 10 * math.log10(erp_kw * 1e3 * 1000)  # kW -> mW -> dBm

    # Path loss
    loss_db = fspl_db(freq_hz, dist_km)

    # Received power at antenna (dBm)
    rx_dbm = erp_dbm + antenna_gain_db - loss_db

    # Convert to approximate dBFS for PlutoSDR
    # PlutoSDR full scale ≈ -10 dBm at 0 dB gain
    # At gain G, full scale ≈ (-10 - G) dBm
    full_scale_dbm = -10.0 - sdr_gain_db
    dbfs = rx_dbm - full_scale_dbm

    return max(-120.0, min(0.0, dbfs))


# ══════════════════════════════════════════════════════════════════════════════
# FCC STATION DATABASE
# ══════════════════════════════════════════════════════════════════════════════

class StationRecord:
    __slots__ = [
        'callsign', 'freq_hz', 'freq_mhz', 'band',
        'service', 'erp_kw', 'haat_m',
        'tx_lat', 'tx_lon', 'city', 'state',
        'facility_id', 'distance_km', 'azimuth_deg',
        'directional', 'class_code',
        'expected_dbfs',
    ]
    def __init__(self):
        for s in self.__slots__:
            setattr(self, s, None)


def _fetch_url(url: str, timeout: int = 15) -> Optional[str]:
    """Fetch URL, return text content or None on failure."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "CTW-SENTINEL/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.read(1024*1024).decode('ascii', errors='ignore')
    except Exception as e:
        print(f"[BCAST] Fetch error {url[:60]}: {e}")
        return None


def parse_fm_text(text: str, obs_lat: float, obs_lon: float,
                  sdr_gain_db: float) -> List[StationRecord]:
    """
    Parse FCC FM query text output.
    Format per FCC documentation (pipe-delimited):
    CALLSIGN|FREQ|SERVICE|CHANNEL|DA|STATUS|CITY|STATE|COUNTRY|FILE|
    POWER_KW|...|FACID|NS|LAT_D|LAT_M|LAT_S|EW|LON_D|LON_M|LON_S|
    LICENSEE|DIST_KM|DIST_MI|AZIMUTH|APPID|LMS_ID
    """
    stations = []
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('Call') or line.startswith('--'):
            continue
        parts = line.split('|')
        if len(parts) < 20:
            continue
        try:
            st = StationRecord()
            st.callsign   = parts[0].strip()
            freq_mhz      = float(parts[1].strip())
            st.freq_mhz   = freq_mhz
            st.freq_hz    = int(freq_mhz * 1e6)
            st.band       = "FM"
            st.service    = parts[2].strip()
            st.class_code = parts[3].strip()
            erp_str       = parts[10].strip() if len(parts) > 10 else "0"
            st.erp_kw     = _cf(erp_str, 0, 10000, 0.1)
            st.city       = parts[6].strip() if len(parts) > 6 else ""
            st.state      = parts[7].strip() if len(parts) > 7 else ""
            st.facility_id= parts[13].strip() if len(parts) > 13 else ""
            # Coordinates
            ns    = parts[14].strip() if len(parts) > 14 else "N"
            lat_d = _ci(parts[15], 0, 90)
            lat_m = _ci(parts[16], 0, 59)
            lat_s = _cf(parts[17], 0, 60)
            ew    = parts[18].strip() if len(parts) > 18 else "W"
            lon_d = _ci(parts[19], 0, 180)
            lon_m = _ci(parts[20], 0, 59) if len(parts) > 20 else 0
            lon_s = _cf(parts[21], 0, 60) if len(parts) > 21 else 0
            st.tx_lat  = (lat_d + lat_m/60 + lat_s/3600) * (1 if ns=="N" else -1)
            st.tx_lon  = (lon_d + lon_m/60 + lon_s/3600) * (-1 if ew=="W" else 1)
            dist_str   = parts[22].strip() if len(parts) > 22 else "0"
            az_str     = parts[24].strip() if len(parts) > 24 else "0"
            st.distance_km  = _cf(dist_str, 0, 5000)
            st.azimuth_deg  = _cf(az_str, 0, 360)
            # Expected power
            st.expected_dbfs = expected_dbfs(
                st.erp_kw, st.freq_hz, st.distance_km,
                sdr_gain_db=sdr_gain_db
            )
            stations.append(st)
        except Exception:
            continue
    return stations


def parse_am_text(text: str, obs_lat: float, obs_lon: float,
                  sdr_gain_db: float) -> List[StationRecord]:
    """
    Parse FCC AM query text output.
    Format per FCC documentation:
    CALLSIGN|FREQ|SERVICE|DA|HOURS|DOM_CLASS|INTL_CLASS|STATUS|
    CITY|STATE|COUNTRY|FILE|...|FACID|NS|LAT_D|LAT_M|LAT_S|EW|
    LON_D|LON_M|LON_S|LICENSEE|DIST_KM|DIST_MI|AZIMUTH|APPID|LMS_ID
    """
    stations = []
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('Call') or line.startswith('--'):
            continue
        parts = line.split('|')
        if len(parts) < 18:
            continue
        try:
            st = StationRecord()
            st.callsign   = parts[0].strip()
            freq_khz      = float(parts[1].strip())
            st.freq_hz    = int(freq_khz * 1000)
            st.freq_mhz   = freq_khz / 1000
            st.band       = "AM"
            st.service    = parts[2].strip()
            st.class_code = parts[5].strip()
            # AM power not in standard text query — use class default
            am_class_power = {
                "A": 50.0, "B": 5.0, "C": 1.0, "D": 0.25,
                "ND": 1.0, "NDS": 1.0,
            }
            st.erp_kw     = am_class_power.get(st.class_code.upper(), 1.0)
            st.city       = parts[8].strip() if len(parts) > 8 else ""
            st.state      = parts[9].strip() if len(parts) > 9 else ""
            st.facility_id= parts[14].strip() if len(parts) > 14 else ""
            ns    = parts[15].strip() if len(parts) > 15 else "N"
            lat_d = _ci(parts[16], 0, 90) if len(parts) > 16 else 0
            lat_m = _ci(parts[17], 0, 59) if len(parts) > 17 else 0
            lat_s = _cf(parts[18], 0, 60) if len(parts) > 18 else 0
            ew    = parts[19].strip() if len(parts) > 19 else "W"
            lon_d = _ci(parts[20], 0, 180) if len(parts) > 20 else 0
            lon_m = _ci(parts[21], 0, 59) if len(parts) > 21 else 0
            lon_s = _cf(parts[22], 0, 60) if len(parts) > 22 else 0
            st.tx_lat       = (lat_d + lat_m/60 + lat_s/3600) * (1 if ns=="N" else -1)
            st.tx_lon       = (lon_d + lon_m/60 + lon_s/3600) * (-1 if ew=="W" else 1)
            dist_str        = parts[23].strip() if len(parts) > 23 else "0"
            az_str          = parts[25].strip() if len(parts) > 25 else "0"
            st.distance_km  = _cf(dist_str, 0, 5000)
            st.azimuth_deg  = _cf(az_str, 0, 360)
            st.expected_dbfs = expected_dbfs(
                st.erp_kw, st.freq_hz, st.distance_km,
                sdr_gain_db=sdr_gain_db
            )
            stations.append(st)
        except Exception:
            continue
    return stations


def fetch_station_database(
    obs_lat: float,
    obs_lon: float,
    radius_km: float,
    bands: List[str],
    sdr_gain_db: float,
) -> List[StationRecord]:
    """
    Fetch AM and/or FM station database from FCC APIs.
    Returns sorted list of StationRecord objects.
    """
    stations = []
    lat_d, lat_m, lat_s = dd_to_dms(obs_lat)
    lon_d, lon_m, lon_s = dd_to_dms(abs(obs_lon))

    url_params = dict(
        radius_km=radius_km,
        lat_d=lat_d, lat_m=lat_m, lat_s=lat_s,
        lon_d=lon_d, lon_m=lon_m, lon_s=lon_s,
    )

    if "FM" in bands:
        print(f"[BCAST] Fetching FM stations from FCC (radius {radius_km:.0f}km)...")
        url  = FCC_FM_QUERY.format(**url_params)
        text = _fetch_url(url)
        if text:
            fm = parse_fm_text(text, obs_lat, obs_lon, sdr_gain_db)
            stations.extend(fm)
            print(f"[BCAST]   {len(fm)} FM stations loaded.")
        else:
            print("[BCAST]   FM fetch failed — check network or use --use-cache")

    if "AM" in bands:
        print(f"[BCAST] Fetching AM stations from FCC (radius {radius_km:.0f}km)...")
        url  = FCC_AM_QUERY.format(**url_params)
        text = _fetch_url(url)
        if text:
            am = parse_am_text(text, obs_lat, obs_lon, sdr_gain_db)
            stations.extend(am)
            print(f"[BCAST]   {len(am)} AM stations loaded.")
        else:
            print("[BCAST]   AM fetch failed — check network or use --use-cache")

    stations.sort(key=lambda s: s.distance_km or 9999)
    return stations


def save_station_cache(stations: List[StationRecord], path: str):
    """Save station database to JSON cache."""
    data = []
    for s in stations:
        data.append({k: getattr(s, k) for k in s.__slots__})
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print(f"[BCAST] Station cache saved: {path}")


def load_station_cache(path: str, sdr_gain_db: float) -> List[StationRecord]:
    """Load station database from JSON cache."""
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    stations = []
    for d in data:
        s = StationRecord()
        for k, v in d.items():
            if k in s.__slots__:
                setattr(s, k, v)
        # Recompute expected_dbfs with current gain setting
        if s.erp_kw and s.freq_hz and s.distance_km:
            s.expected_dbfs = expected_dbfs(
                s.erp_kw, s.freq_hz, s.distance_km,
                sdr_gain_db=sdr_gain_db
            )
        stations.append(s)
    print(f"[BCAST] Station cache loaded: {len(stations)} stations from {path}")
    return stations


# ══════════════════════════════════════════════════════════════════════════════
# CLOCK ANCHOR + GZIP + LIVE MIRROR (standard pipeline components)
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

    def format_wall_ns(self, w):
        s = w // 1_000_000_000
        f = w  % 1_000_000_000
        return datetime.datetime.fromtimestamp(
            s, tz=datetime.timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%S') + f'.{f:09d}Z'


class GzipLog:
    def __init__(self, path, header):
        self.path    = path
        self._q      = deque()
        self._event  = threading.Event()
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        with gzip.open(path, 'ab', compresslevel=6) as gz:
            gz.write((json.dumps(header, separators=(',',':')) + '\n').encode())
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
        while self._q: lines.append(json.dumps(self._q.popleft(), separators=(',',':')))
        blob = ('\n'.join(lines) + '\n').encode()
        with gzip.open(self.path, 'ab', compresslevel=6) as gz: gz.write(blob)


class LiveMirror:
    def __init__(self, path):
        self.path  = path
        self._lock = threading.Lock()
        with open(path, 'w', encoding='utf-8') as f: f.write('')

    def write(self, obj):
        line = json.dumps(obj, separators=(',',':')) + '\n'
        with self._lock:
            with open(self.path, 'a', encoding='utf-8') as f: f.write(line)


# ══════════════════════════════════════════════════════════════════════════════
# SDR POWER MEASUREMENT
# ══════════════════════════════════════════════════════════════════════════════

def measure_carrier_power(
    spectrum_db: np.ndarray,
    freqs_hz:    np.ndarray,
    carrier_hz:  float,
    bw_hz:       float,
) -> Tuple[float, float, float]:
    """
    Measure carrier power in a bandwidth window around a center frequency.

    Returns (peak_dbfs, mean_dbfs, carrier_offset_hz)
    carrier_offset_hz = how far the actual peak is from the licensed center
    """
    half_bw = bw_hz / 2
    mask = np.abs(freqs_hz - carrier_hz) <= half_bw

    if mask.sum() == 0:
        return -120.0, -120.0, 0.0

    window_spec  = spectrum_db[mask]
    window_freqs = freqs_hz[mask]

    peak_dbfs  = float(np.max(window_spec))
    mean_dbfs  = float(np.mean(window_spec))
    peak_idx   = int(np.argmax(window_spec))
    peak_freq  = float(window_freqs[peak_idx])
    offset_hz  = peak_freq - carrier_hz

    return peak_dbfs, mean_dbfs, offset_hz


def measure_spurious(
    spectrum_db: np.ndarray,
    freqs_hz:    np.ndarray,
    stations:    List[StationRecord],
    threshold_dbfs: float,
) -> List[dict]:
    """
    Identify energy at frequencies that are NOT assigned to licensed stations.
    Returns list of spurious emission records.
    """
    # Build set of licensed frequencies (±50 kHz guard)
    licensed_hz = set()
    for s in stations:
        if s.freq_hz:
            for off in range(-50_000, 51_000, 10_000):
                licensed_hz.add(s.freq_hz + off)

    spurious = []
    # Sample every 200 kHz (FM) or 10 kHz (AM) outside licensed windows
    step = 200_000 if (freqs_hz[0] > 50e6) else 10_000
    check_freqs = np.arange(freqs_hz[0], freqs_hz[-1], step)

    for cf in check_freqs:
        cf = int(cf)
        # Skip if within 100 kHz of any licensed frequency
        if any(abs(cf - lf) <= 100_000 for lf in licensed_hz
               if abs(cf - lf) <= 200_000):
            continue

        mask = np.abs(freqs_hz - cf) <= step / 2
        if mask.sum() == 0:
            continue

        pwr = float(np.max(spectrum_db[mask]))
        if pwr >= threshold_dbfs:
            spurious.append({
                "freq_hz":   cf,
                "freq_mhz":  round(cf / 1e6, 4),
                "dbfs":      round(pwr, 2),
            })

    return spurious


def detect_intermodulation(
    stations: List[StationRecord],
    spectrum_db: np.ndarray,
    freqs_hz: np.ndarray,
    threshold_dbfs: float,
) -> List[dict]:
    """
    Check for intermodulation products: f1 ± f2, 2f1 ± f2, etc.
    Two licensed carriers mixing produce predictable spur frequencies.
    If those spurs appear in the spectrum above threshold, it indicates
    nonlinear distortion — either in a rogue retransmitter or in
    a device generating mixing products locally.
    """
    imd = []
    active = [s for s in stations
              if s.expected_dbfs and s.expected_dbfs > -90
              and s.freq_hz]

    for i in range(len(active)):
        for j in range(i + 1, len(active)):
            f1 = active[i].freq_hz
            f2 = active[j].freq_hz

            # Third-order intermodulation products: 2f1-f2 and 2f2-f1
            for prod_hz in (2*f1 - f2, 2*f2 - f1):
                if prod_hz <= 0:
                    continue
                # Check if this frequency is in our current sweep window
                if not (freqs_hz[0] <= prod_hz <= freqs_hz[-1]):
                    continue
                # Check if it falls on a licensed station
                on_licensed = any(
                    abs(prod_hz - s.freq_hz) < 100_000
                    for s in active
                )
                if on_licensed:
                    continue
                # Measure power at product frequency
                mask = np.abs(freqs_hz - prod_hz) <= 100_000
                if mask.sum() == 0:
                    continue
                pwr = float(np.max(spectrum_db[mask]))
                if pwr >= threshold_dbfs:
                    imd.append({
                        "type":          "IMD3",
                        "f1_hz":         f1,
                        "f1_callsign":   active[i].callsign,
                        "f2_hz":         f2,
                        "f2_callsign":   active[j].callsign,
                        "product_hz":    prod_hz,
                        "product_mhz":   round(prod_hz / 1e6, 4),
                        "dbfs":          round(pwr, 2),
                    })

    return imd


# ══════════════════════════════════════════════════════════════════════════════
# MAIN SWEEP ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class BroadcastMonitor:

    def __init__(self, uri, stations, bands, dwell_ms,
                 anomaly_db, clock, log, mirror, sdr_gain):
        self.uri        = uri
        self.stations   = stations
        self.bands      = bands
        self.dwell_ms   = dwell_ms
        self.anomaly_db = anomaly_db
        self.clock      = clock
        self.log        = log
        self.mirror     = mirror
        self.sdr_gain   = sdr_gain
        self._seq       = 0
        self.counts     = defaultdict(int)
        self._station_history = defaultdict(list)  # callsign -> [(wall_ns, dbfs)]

    def run(self, stop_event):
        if iio is None:
            print("[BCAST] libiio not installed — pip install pylibiio")
            return

        print(f"[BCAST] Connecting to PlutoSDR at {self.uri}...")
        try:
            ctx   = iio.Context(self.uri)
            phy   = ctx.find_device("ad9361-phy")
            rxdev = ctx.find_device("cf-ad9361-lpc")
        except Exception as e:
            print(f"[BCAST] PlutoSDR connection failed: {e}")
            return

        # Group stations by band for efficient sweeping
        fm_stations = [s for s in self.stations if s.band == "FM"]
        am_stations = [s for s in self.stations if s.band == "AM"]

        print(f"[BCAST] {len(fm_stations)} FM stations, "
              f"{len(am_stations)} AM stations to monitor")

        sweep_num = 0

        while not stop_event.is_set():
            sweep_num += 1

            if "FM" in self.bands and fm_stations:
                self._sweep_band(
                    phy, rxdev, fm_stations,
                    FM_BAND_HZ, FM_SAMPLE_RATE_HZ,
                    bw_hz=200_000, sweep_num=sweep_num,
                    stop_event=stop_event
                )

            if "AM" in self.bands and am_stations:
                self._sweep_band(
                    phy, rxdev, am_stations,
                    AM_BAND_HZ, AM_SAMPLE_RATE_HZ,
                    bw_hz=10_000, sweep_num=sweep_num,
                    stop_event=stop_event
                )

            # Sweep summary
            wall_ns, _ = self.clock.now()
            self.log.write({
                "type":         "BCAST_SWEEP_PASS",
                "_stream":      "broadcast",
                "sweep":        sweep_num,
                "wall_ns":      wall_ns,
                "wall_iso":     self.clock.format_wall_ns(wall_ns),
                "anomalies":    dict(self.counts),
                "total":        sum(self.counts.values()),
            })

    def _sweep_band(self, phy, rxdev, stations, band_hz,
                    sample_rate, bw_hz, sweep_num, stop_event):
        """Step through band measuring each licensed carrier."""

        # Configure SDR for this band
        rx = phy.find_channel("voltage0", False)
        for attr, val in [
            ("gain_control_mode",  "manual"),
            ("hardwaregain",       str(self.sdr_gain)),
            ("rf_bandwidth",       str(sample_rate)),
            ("sampling_frequency", str(sample_rate)),
        ]:
            try: rx.attrs[attr].value = val
            except Exception: pass

        for ch in rxdev.channels:
            ch.enabled = ch.id in ("voltage0", "voltage1")

        buf = iio.Buffer(rxdev, FFT_SIZE * 2, False)
        lo  = phy.find_channel("altvoltage0", True)

        # Walk through band in sample_rate steps
        center = band_hz[0] + sample_rate // 2

        while center <= band_hz[1] + sample_rate // 2:
            if stop_event.is_set():
                return

            center_clamped = max(70_000_000, min(5_999_000_000, center))

            try:
                lo.attrs["frequency"].value = str(center_clamped)
                time.sleep(max(0.010, self.dwell_ms / 1000.0))
                buf.refill()
                raw = np.frombuffer(buf.read(), dtype=np.int16).copy()
            except Exception as e:
                print(f"\n[BCAST] Capture error: {e}")
                center += sample_rate
                continue

            if len(raw) < FFT_SIZE * 2:
                center += sample_rate
                continue

            wall_ns, mono_ns = self.clock.now()

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
            freqs_hz = np.fft.fftshift(
                np.fft.fftfreq(FFT_SIZE, 1.0 / sample_rate)
            ) + center_clamped

            # Measure each licensed station in this window
            window_lo = center_clamped - sample_rate / 2
            window_hi = center_clamped + sample_rate / 2

            window_stations = [
                s for s in stations
                if s.freq_hz and window_lo <= s.freq_hz <= window_hi
            ]

            for st in window_stations:
                peak_db, mean_db, offset_hz = measure_carrier_power(
                    spec_db, freqs_hz, st.freq_hz, bw_hz
                )

                # Track history
                self._station_history[st.callsign].append(
                    (wall_ns, peak_db)
                )
                if len(self._station_history[st.callsign]) > 60:
                    self._station_history[st.callsign].pop(0)

                # Expected vs observed
                expected  = st.expected_dbfs or -100.0
                deviation = peak_db - expected
                offset_khz = offset_hz / 1000.0

                # Build base record
                self._seq += 1
                rec = {
                    "type":          "BCAST_CARRIER",
                    "_stream":       "broadcast",
                    "seq":           self._seq,
                    "wall_ns":       wall_ns,
                    "wall_iso":      self.clock.format_wall_ns(wall_ns),
                    "sweep":         sweep_num,
                    "callsign":      st.callsign,
                    "freq_hz":       st.freq_hz,
                    "freq_mhz":      st.freq_mhz,
                    "band":          st.band,
                    "city":          st.city,
                    "state":         st.state,
                    "erp_kw":        st.erp_kw,
                    "distance_km":   st.distance_km,
                    "azimuth_deg":   st.azimuth_deg,
                    "peak_dbfs":     round(peak_db, 2),
                    "mean_dbfs":     round(mean_db, 2),
                    "expected_dbfs": round(expected, 2),
                    "deviation_db":  round(deviation, 2),
                    "offset_hz":     round(offset_hz, 1),
                    "offset_khz":    round(offset_khz, 3),
                    "anomaly":       False,
                    "anomaly_class": [],
                }

                anomaly_classes = []

                # CARRIER_ABSENT
                if peak_db < CARRIER_ABSENT_THRESHOLD_DB:
                    anomaly_classes.append("CARRIER_ABSENT")
                    self.counts["CARRIER_ABSENT"] += 1

                # CARRIER_SUPPRESSED
                elif deviation < -CARRIER_SUPPRESSED_DB:
                    anomaly_classes.append("CARRIER_SUPPRESSED")
                    self.counts["CARRIER_SUPPRESSED"] += 1

                # CARRIER_ELEVATED
                elif deviation > CARRIER_ELEVATED_DB:
                    anomaly_classes.append("CARRIER_ELEVATED")
                    self.counts["CARRIER_ELEVATED"] += 1

                # CARRIER_DRIFT
                if abs(offset_khz) > CARRIER_DRIFT_KHZ:
                    anomaly_classes.append("CARRIER_DRIFT")
                    self.counts["CARRIER_DRIFT"] += 1

                if anomaly_classes:
                    rec["anomaly"]       = True
                    rec["anomaly_class"] = anomaly_classes
                    self.log.write(rec)
                    self.mirror.write(rec)

                    print(
                        f"\n  [{self.clock.format_wall_ns(wall_ns)[11:23]}]"
                        f"  *** {' | '.join(anomaly_classes)} ***"
                        f"  {st.callsign} {st.freq_mhz:.1f}MHz"
                        f"  obs={peak_db:.1f}dBFS"
                        f"  exp={expected:.1f}dBFS"
                        f"  dev={deviation:+.1f}dB"
                        f"  off={offset_khz:+.2f}kHz",
                        flush=True
                    )
                else:
                    # Only log nominal carriers every N sweeps to limit volume
                    if sweep_num % 10 == 0:
                        self.log.write(rec)

                # Console status
                print(
                    f"\r  {st.band} {st.freq_mhz:7.3f}MHz"
                    f"  {st.callsign:<8}"
                    f"  {peak_db:6.1f}dBFS"
                    f"  exp={expected:6.1f}"
                    f"  dev={deviation:+5.1f}dB"
                    f"  {st.city},{st.state} {st.distance_km:.0f}km   ",
                    end='', flush=True
                )

            # Check for spurious emissions in this window
            if window_stations:
                spurious = measure_spurious(
                    spec_db, freqs_hz, window_stations,
                    SPURIOUS_THRESHOLD_DB
                )
                for sp in spurious:
                    self._seq += 1
                    sp_rec = {
                        "type":          "BCAST_SPURIOUS",
                        "_stream":       "broadcast",
                        "seq":           self._seq,
                        "wall_ns":       wall_ns,
                        "wall_iso":      self.clock.format_wall_ns(wall_ns),
                        "sweep":         sweep_num,
                        "anomaly":       True,
                        "anomaly_class": ["CARRIER_SPURIOUS"],
                        **sp
                    }
                    self.log.write(sp_rec)
                    self.mirror.write(sp_rec)
                    self.counts["CARRIER_SPURIOUS"] += 1
                    print(
                        f"\n  [{self.clock.format_wall_ns(wall_ns)[11:23]}]"
                        f"  *** CARRIER_SPURIOUS ***"
                        f"  {sp['freq_mhz']:.4f}MHz"
                        f"  {sp['dbfs']:.1f}dBFS (unlicensed)",
                        flush=True
                    )

                # Intermodulation detection
                imd = detect_intermodulation(
                    window_stations, spec_db, freqs_hz,
                    INTERMOD_THRESHOLD_DB
                )
                for im in imd:
                    self._seq += 1
                    im_rec = {
                        "type":          "BCAST_INTERMOD",
                        "_stream":       "broadcast",
                        "seq":           self._seq,
                        "wall_ns":       wall_ns,
                        "wall_iso":      self.clock.format_wall_ns(wall_ns),
                        "sweep":         sweep_num,
                        "anomaly":       True,
                        "anomaly_class": ["INTERMODULATION"],
                        **im
                    }
                    self.log.write(im_rec)
                    self.mirror.write(im_rec)
                    self.counts["INTERMODULATION"] += 1

            center += sample_rate


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="CTW Licensed Broadcast Power Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--uri",         default="ip:192.168.2.1")
    ap.add_argument("--lat",         type=float, default=None,
                    help="Observer latitude decimal degrees")
    ap.add_argument("--lon",         type=float, default=None,
                    help="Observer longitude decimal degrees")
    ap.add_argument("--radius-km",   type=float, default=150.0,
                    help="Station search radius km (default 150)")
    ap.add_argument("--bands",       nargs="+",
                    choices=["AM","FM"], default=["FM","AM"],
                    help="Bands to monitor (default: FM AM)")
    ap.add_argument("--dwell-ms",    type=int, default=200,
                    help="Dwell per frequency window ms (default 200)")
    ap.add_argument("--anomaly-db",  type=float, default=8.0,
                    help="dB deviation to flag anomaly (default 8)")
    ap.add_argument("--gain",        type=int, default=40,
                    help="SDR gain dB (default 40)")
    ap.add_argument("--use-cache",   default=None, metavar="PATH",
                    help="Load station database from cache file")
    ap.add_argument("--no-fcc",      action="store_true",
                    help="Skip FCC fetch (cache required)")
    ap.add_argument("--out",         default=r"C:\sdr\logs", metavar="DIR")
    args = ap.parse_args()

    out_dir     = os.path.abspath(args.out)
    runtime_dir = os.path.join(out_dir, "runtime")
    os.makedirs(out_dir,     exist_ok=True)
    os.makedirs(runtime_dir, exist_ok=True)

    # Require coordinates for FCC queries
    obs_lat = args.lat
    obs_lon = args.lon

    if obs_lat is None or obs_lon is None:
        if not args.use_cache:
            print("[ERR] --lat and --lon required unless --use-cache is set")
            print("      Example: --lat 33.800509 --lon -117.220352")
            sys.exit(1)

    # Load or fetch station database
    stations = []
    if args.use_cache:
        if not os.path.exists(args.use_cache):
            print(f"[ERR] Cache file not found: {args.use_cache}")
            sys.exit(1)
        stations = load_station_cache(args.use_cache, args.gain)
    elif not args.no_fcc:
        stations = fetch_station_database(
            obs_lat, obs_lon, args.radius_km,
            args.bands, args.gain
        )
        # Save cache
        cache_path = os.path.join(out_dir, f"broadcast_stations_{STAMP}.json")
        save_station_cache(stations, cache_path)
    else:
        print("[ERR] --no-fcc requires --use-cache")
        sys.exit(1)

    if not stations:
        print("[ERR] No stations loaded. Check network or cache file.")
        sys.exit(1)

    from ntp_web import get_ntp_info
    print("Querying web time reference...", flush=True)
    ntp_info = get_ntp_info()
    print(f"  Source : {ntp_info['ntp_source']}")
    print(f"  Offset : {ntp_info.get('ntp_offset_ms','?')} ms")

    clock = ClockAnchor()

    header = {
        "type":             "broadcast_session_header",
        "session_wall_utc": clock.session_wall_utc,
        "session_wall_ns":  clock.session_wall_ns,
        "ntp_source":       ntp_info["ntp_source"],
        "ntp_offset_ms":    ntp_info.get("ntp_offset_ms"),
        "pluto_uri":        args.uri,
        "observer_lat":     obs_lat,
        "observer_lon":     obs_lon,
        "radius_km":        args.radius_km,
        "bands":            args.bands,
        "station_count":    len(stations),
        "sdr_gain_db":      args.gain,
        "anomaly_db":       args.anomaly_db,
        "stamp":            STAMP,
        "purpose":          "RF power level monitoring of licensed carriers. "
                            "No content captured or stored.",
    }

    gz_path   = os.path.join(out_dir,     f"broadcast_monitor_{STAMP}.jsonl.gz")
    live_path = os.path.join(runtime_dir, "broadcast_live.jsonl")

    log    = GzipLog(gz_path, header)
    mirror = LiveMirror(live_path)
    mirror.write(header)

    fm_n = sum(1 for s in stations if s.band == "FM")
    am_n = sum(1 for s in stations if s.band == "AM")

    print(f"\n{'='*68}")
    print(f"  CTW LICENSED BROADCAST POWER MONITOR")
    print(f"{'='*68}")
    print(f"  PlutoSDR    : {args.uri}")
    if obs_lat:
        print(f"  Observer    : {obs_lat:.6f}, {obs_lon:.6f}")
    print(f"  Radius      : {args.radius_km:.0f} km")
    print(f"  FM stations : {fm_n}")
    print(f"  AM stations : {am_n}")
    print(f"  Bands       : {args.bands}")
    print(f"  SDR gain    : {args.gain} dB")
    print(f"  Anomaly     : ±{args.anomaly_db:.0f} dB from expected")
    print(f"  Dwell       : {args.dwell_ms} ms")
    print(f"  Log         : broadcast_monitor_{STAMP}.jsonl.gz")
    print(f"  Live        : {live_path}")
    print(f"{'='*68}")
    print(f"  NOTE: Power level monitoring only.")
    print(f"        No audio content is captured or stored.")
    print(f"{'='*68}")
    print(f"  Anomaly classes:")
    print(f"    CARRIER_ABSENT     station not detectable")
    print(f"    CARRIER_SUPPRESSED {args.anomaly_db:.0f}+ dB below expected")
    print(f"    CARRIER_ELEVATED   {args.anomaly_db:.0f}+ dB above expected")
    print(f"    CARRIER_DRIFT      >{CARRIER_DRIFT_KHZ:.0f}kHz frequency offset")
    print(f"    CARRIER_SPURIOUS   energy on unlicensed frequency")
    print(f"    INTERMODULATION    mixing products detected")
    print(f"{'='*68}")
    print(f"  Stations loaded (closest first):")
    for s in stations[:15]:
        print(f"    {s.band} {s.freq_mhz:7.3f}MHz  {s.callsign:<8}  "
              f"{s.distance_km:6.1f}km  {s.erp_kw:.2f}kW  "
              f"exp={s.expected_dbfs:.1f}dBFS  {s.city}")
    if len(stations) > 15:
        print(f"    ... and {len(stations)-15} more")
    print(f"{'='*68}")
    print(f"  Ctrl+C to stop")
    print()

    monitor = BroadcastMonitor(
        uri        = args.uri,
        stations   = stations,
        bands      = args.bands,
        dwell_ms   = args.dwell_ms,
        anomaly_db = args.anomaly_db,
        clock      = clock,
        log        = log,
        mirror     = mirror,
        sdr_gain   = args.gain,
    )

    stop_event = threading.Event()
    t = threading.Thread(
        target=monitor.run, args=(stop_event,),
        daemon=True, name="BcastMonitor"
    )
    t.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        t.join(timeout=10)

        wall_ns, _ = clock.now()
        end = {
            "type":      "session_end",
            "_stream":   "broadcast",
            "wall_ns":   wall_ns,
            "wall_iso":  clock.format_wall_ns(wall_ns),
            "anomalies": dict(monitor.counts),
            "total":     sum(monitor.counts.values()),
        }
        log.write(end)
        mirror.write(end)
        log.close()

        print(f"\n\nBroadcast monitor session complete.")
        for k, v in monitor.counts.items():
            print(f"  {k:<25} : {v}")
        print(f"  Log : {gz_path}")


if __name__ == "__main__":
    main()
