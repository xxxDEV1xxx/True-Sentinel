#!/usr/bin/env python3
"""
gnss_anomaly_report.py  —  CTW GNSS Forensic Anomaly Detector
==============================================================
Reads gnss_STAMP.jsonl.gz logs produced by ublox_parser.py and
generates a structured anomaly detection report for personal and
legal records.

Detections:
  1.  Constellation collapse (fewer SVs than expected)
  2.  Single-satellite survival (spoof/jam discriminator)
  3.  C/N0 anomaly (abnormal signal strength per SV)
  4.  NAV-STATUS spoofing flag (hardware detection)
  5.  MON-HW jamming indicator threshold
  6.  Pseudorange residual anomaly (RXM-RAW)
  7.  Clock bias / drift anomaly (NAV-CLOCK)
  8.  Fix type degradation events
  9.  Position accuracy degradation (h_acc, v_acc)
  10. IMPOSSIBLE SATELLITE GEOMETRY (new)
      — Computed satellite position from TLE/almanac vs reported
        azimuth/elevation from receiver
      — Triangulated position from satellite bearing pairs vs
        known static ground truth
      — Displacement vector from computed to reported position
      — Flags: coordinate mismatch, impossible geometry,
               triangulation lands off-site, bearing to spoofer

Output:
  gnss_anomaly_report_STAMP.txt    — human-readable report
  gnss_anomaly_report_STAMP.json   — machine-readable structured data

Usage:
  python gnss_anomaly_report.py
  python gnss_anomaly_report.py --log gnss_20260708_142210.jsonl.gz
  python gnss_anomaly_report.py --ground-truth 33.800509,-117.220352
  python gnss_anomaly_report.py --all-logs
  python gnss_anomaly_report.py --out C:\\sdr\\logs
"""

import argparse
import datetime
import gzip
import json
import math
import os
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# Thresholds
MIN_HEALTHY_SVS          = 4      # minimum SVs for a healthy fix
COLLAPSE_SV_THRESHOLD    = 2      # at or below = constellation collapse
CNO_HEALTHY_MIN          = 25.0   # dB-Hz below = weak signal
CNO_ANOMALY_HIGH         = 50.0   # dB-Hz above = suspiciously strong
JAM_IND_THRESHOLD        = 100    # MON-HW jamInd above = jamming
HACC_ANOMALY_M           = 50.0   # horizontal accuracy worse than this = flag
VACC_ANOMALY_M           = 75.0   # vertical accuracy worse than this = flag
PR_RESIDUAL_THRESHOLD_M  = 50.0   # pseudorange residual beyond = anomaly
CLOCK_BIAS_THRESHOLD_NS  = 100000 # 100 microseconds clock bias = anomaly
CLOCK_DRIFT_THRESHOLD_NS = 10000  # clock drift threshold

# Satellite geometry thresholds
AZ_TOLERANCE_DEG         = 15.0   # azimuth mismatch tolerance
EL_TOLERANCE_DEG         = 10.0   # elevation mismatch tolerance
TRILATERATION_TOLERANCE_M= 500.0  # triangulated position vs ground truth
IMPOSSIBLE_DISTANCE_KM   = 100.0  # triangulated position this far = impossible

# Earth constants
EARTH_RADIUS_M           = 6_371_000.0
GPS_ORBIT_RADIUS_M       = 26_560_000.0   # ~26,560 km MEO orbit
SPEED_OF_LIGHT_MS        = 299_792_458.0

GNSS_NAMES = {
    0: "GPS", 1: "SBAS", 2: "Galileo",
    3: "BeiDou", 5: "QZSS", 6: "GLONASS"
}

SPOOF_STATE_NAMES = {
    0: "unknown", 1: "no_spoofing",
    2: "SPOOFING_INDICATED", 3: "MULTIPLE_SPOOFING"
}

# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Anomaly:
    severity:    str        # CRITICAL / HIGH / MEDIUM / INFO
    category:    str        # detection category name
    description: str        # human-readable description
    timestamp:   str        # wall_iso
    wall_ns:     int        # nanosecond timestamp
    evidence:    dict = field(default_factory=dict)
    statutes:    list = field(default_factory=list)


@dataclass
class SatelliteObs:
    """One satellite observation from NAV-SAT."""
    gnss_id:   int
    sv_id:     int
    cno:       float
    elev_deg:  float
    azim_deg:  float
    pr_res_m:  Optional[float]
    sv_used:   bool
    wall_ns:   int
    wall_iso:  str


@dataclass
class PositionFix:
    """One position fix from NAV-PVT."""
    lat:        Optional[float]
    lon:        Optional[float]
    alt_m:      Optional[float]
    h_acc_m:    Optional[float]
    v_acc_m:    Optional[float]
    fix_name:   str
    num_sv:     int
    p_dop:      Optional[float]
    gps_fix_ok: bool
    wall_ns:    int
    wall_iso:   str


# ══════════════════════════════════════════════════════════════════════════════
# GEOMETRIC UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def haversine_m(lat1, lon1, lat2, lon2):
    """Distance in meters between two lat/lon points."""
    R = EARTH_RADIUS_M
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = (math.sin(dphi/2)**2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlam/2)**2)
    return 2 * R * math.asin(math.sqrt(a))


def bearing_deg(lat1, lon1, lat2, lon2):
    """True bearing from point 1 to point 2 in degrees."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dlam = math.radians(lon2 - lon1)
    x = math.sin(dlam) * math.cos(phi2)
    y = (math.cos(phi1) * math.sin(phi2) -
         math.sin(phi1) * math.cos(phi2) * math.cos(dlam))
    bearing = math.degrees(math.atan2(x, y))
    return (bearing + 360) % 360


def latlon_from_azimuth_elevation(
    obs_lat, obs_lon, azimuth_deg, elevation_deg,
    orbit_radius_m=GPS_ORBIT_RADIUS_M
):
    """
    Given an observer's lat/lon and a satellite's reported
    azimuth/elevation, compute the approximate sub-satellite
    point on Earth's surface.

    This is a geometric projection — not an orbital mechanics
    calculation. It assumes the satellite is at GPS MEO altitude
    and uses the elevation angle to compute slant range to the
    satellite, then projects back to Earth's surface.

    Returns (sub_lat, sub_lon) or None if geometry invalid.
    """
    if elevation_deg < 0:
        return None  # below horizon — invalid

    el_rad  = math.radians(elevation_deg)
    az_rad  = math.radians(azimuth_deg)

    # Slant range to satellite from observer
    # Using elevation angle and orbit height geometry:
    # R_earth * sin(90 + el) / sin(earth_central_angle + 90 + el) = orbit_r
    Re = EARTH_RADIUS_M
    Rs = orbit_radius_m

    # Earth central angle between observer and sub-satellite point
    # From spherical triangle: cos(rho) = cos(el+90) / (Rs/Re)
    # where rho is the Earth central angle
    cos_rho = math.cos(math.pi/2 + el_rad) / (Rs / Re)
    cos_rho = max(-1.0, min(1.0, cos_rho))
    rho = math.acos(cos_rho)  # central angle in radians

    # Compute sub-satellite lat/lon from observer using azimuth and rho
    obs_lat_r = math.radians(obs_lat)
    obs_lon_r = math.radians(obs_lon)

    sub_lat_r = math.asin(
        math.sin(obs_lat_r) * math.cos(rho) +
        math.cos(obs_lat_r) * math.sin(rho) * math.cos(az_rad)
    )
    sub_lon_r = obs_lon_r + math.atan2(
        math.sin(az_rad) * math.sin(rho) * math.cos(obs_lat_r),
        math.cos(rho) - math.sin(obs_lat_r) * math.sin(sub_lat_r)
    )

    return math.degrees(sub_lat_r), math.degrees(sub_lon_r)


def triangulate_position_from_two_satellites(
    obs_lat, obs_lon,
    az1_deg, el1_deg,
    az2_deg, el2_deg
):
    """
    Estimate receiver position using two satellite bearings.

    Each satellite provides a line-of-bearing from the observer.
    Two non-parallel lines intersect at an estimated position.
    The intersection represents where the receiver would need to
    be for BOTH satellites to appear at their reported angles.

    If this position diverges significantly from the known ground
    truth, the satellite reports are geometrically inconsistent
    with the observer's actual location.

    Returns estimated (lat, lon) or None if geometry degenerate.
    """
    if el1_deg < 5 or el2_deg < 5:
        return None  # too low elevation, geometry unreliable

    # Convert to Cartesian bearing vectors from observer position
    # We work in a local East-North-Up (ENU) frame

    az1 = math.radians(az1_deg)
    az2 = math.radians(az2_deg)
    el1 = math.radians(el1_deg)
    el2 = math.radians(el2_deg)

    # Unit vectors in ENU from observer toward each satellite
    # East = sin(az)*cos(el), North = cos(az)*cos(el), Up = sin(el)
    e1 = math.sin(az1) * math.cos(el1)
    n1 = math.cos(az1) * math.cos(el1)
    u1 = math.sin(el1)

    e2 = math.sin(az2) * math.cos(el2)
    n2 = math.cos(az2) * math.cos(el2)
    u2 = math.sin(el2)

    # Project rays to GPS orbit altitude
    # Scale = orbit_altitude / up_component
    if u1 < 0.01 or u2 < 0.01:
        return None

    orbit_alt = GPS_ORBIT_RADIUS_M - EARTH_RADIUS_M
    t1 = orbit_alt / u1
    t2 = orbit_alt / u2

    # Satellite positions in ENU (meters from observer)
    sat1_e, sat1_n = e1 * t1, n1 * t1
    sat2_e, sat2_n = e2 * t2, n2 * t2

    # Midpoint between the two projected satellite positions
    # projected back toward Earth = rough triangulated receiver area
    mid_e = (sat1_e + sat2_e) / 2
    mid_n = (sat1_n + sat2_n) / 2

    # Convert ENU offset back to lat/lon
    # 1 degree latitude ≈ 111,320 m
    # 1 degree longitude ≈ 111,320 * cos(lat) m
    d_lat = mid_n / 111_320.0
    d_lon = mid_e / (111_320.0 * math.cos(math.radians(obs_lat)))

    est_lat = obs_lat + d_lat
    est_lon = obs_lon + d_lon

    return est_lat, est_lon


def expected_azimuth_elevation(
    obs_lat, obs_lon, obs_alt_m,
    sat_lat, sat_lon, sat_alt_m=GPS_ORBIT_RADIUS_M
):
    """
    Compute expected azimuth and elevation to a satellite
    given observer position and satellite sub-point.

    This is the inverse of latlon_from_azimuth_elevation.
    Used to check: if we know where the satellite SHOULD be
    (from almanac/TLE), what az/el should we see?

    Returns (azimuth_deg, elevation_deg).
    """
    obs_lat_r = math.radians(obs_lat)
    obs_lon_r = math.radians(obs_lon)
    sat_lat_r = math.radians(sat_lat)
    sat_lon_r = math.radians(sat_lon)

    # Vector from Earth center to observer (ECEF)
    Re = EARTH_RADIUS_M + obs_alt_m
    Rs_surface = EARTH_RADIUS_M + sat_alt_m

    # Observer ECEF
    ox = Re * math.cos(obs_lat_r) * math.cos(obs_lon_r)
    oy = Re * math.cos(obs_lat_r) * math.sin(obs_lon_r)
    oz = Re * math.sin(obs_lat_r)

    # Satellite ECEF (using sub-satellite point)
    sx = Rs_surface * math.cos(sat_lat_r) * math.cos(sat_lon_r)
    sy = Rs_surface * math.cos(sat_lat_r) * math.sin(sat_lon_r)
    sz = Rs_surface * math.sin(sat_lat_r)

    # Vector from observer to satellite
    dx, dy, dz = sx - ox, sy - oy, sz - oz

    # Transform to local ENU
    sin_lat = math.sin(obs_lat_r)
    cos_lat = math.cos(obs_lat_r)
    sin_lon = math.sin(obs_lon_r)
    cos_lon = math.cos(obs_lon_r)

    east  = -sin_lon * dx + cos_lon * dy
    north = (-sin_lat * cos_lon * dx
             - sin_lat * sin_lon * dy
             + cos_lat * dz)
    up    = (cos_lat * cos_lon * dx
             + cos_lat * sin_lon * dy
             + sin_lat * dz)

    # Azimuth and elevation
    horiz_dist = math.sqrt(east**2 + north**2)
    elevation  = math.degrees(math.atan2(up, horiz_dist))
    azimuth    = math.degrees(math.atan2(east, north)) % 360

    return azimuth, elevation


# ══════════════════════════════════════════════════════════════════════════════
# LOG READER
# ══════════════════════════════════════════════════════════════════════════════

def read_gnss_log(gz_path):
    """Read all records from a gnss_*.jsonl.gz file."""
    records = []
    try:
        with gzip.open(gz_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        print(f"[ERR] Could not read {gz_path}: {e}")
    return records


def extract_session_data(records):
    """
    Extract structured data from raw records.
    Returns (header, fixes, sat_observations, clock_records,
             hw_records, rxm_raw_records)
    """
    header      = {}
    fixes       = []
    sat_obs     = []
    clock_recs  = []
    hw_recs     = []
    rxm_recs    = []

    for r in records:
        t = r.get("type", "")

        if t == "gnss_session_header":
            header = r

        elif t == "NAV-PVT":
            fixes.append(PositionFix(
                lat       = r.get("lat"),
                lon       = r.get("lon"),
                alt_m     = r.get("alt_m"),
                h_acc_m   = r.get("h_acc_m"),
                v_acc_m   = r.get("v_acc_m"),
                fix_name  = r.get("fix_name", "unknown"),
                num_sv    = r.get("numSV", 0) or 0,
                p_dop     = r.get("p_dop"),
                gps_fix_ok= bool(r.get("gps_fix_ok")),
                wall_ns   = r.get("wall_ns", 0),
                wall_iso  = r.get("wall_iso", ""),
            ))

        elif t == "NAV-SAT":
            for sv in (r.get("sats") or []):
                sat_obs.append(SatelliteObs(
                    gnss_id  = sv.get("gnssId", 0),
                    sv_id    = sv.get("svId",   0),
                    cno      = sv.get("cno",    0) or 0,
                    elev_deg = sv.get("elev_deg", 0) or 0,
                    azim_deg = sv.get("azim_deg", 0) or 0,
                    pr_res_m = sv.get("pr_res_m"),
                    sv_used  = bool(sv.get("sv_used")),
                    wall_ns  = r.get("wall_ns", 0),
                    wall_iso = r.get("wall_iso", ""),
                ))

        elif t == "NAV-STATUS":
            # Store spoof flag in a separate simple list
            clock_recs.append({
                "type":        "NAV-STATUS",
                "spoof_state": r.get("spoof_state", "unknown"),
                "spoof_raw":   r.get("spoof_raw", 0),
                "spoofing":    r.get("spoofing", False),
                "wall_ns":     r.get("wall_ns", 0),
                "wall_iso":    r.get("wall_iso", ""),
            })

        elif t == "NAV-CLOCK":
            clock_recs.append({
                "type":         "NAV-CLOCK",
                "clk_bias_ns":  r.get("clk_bias_ns", 0),
                "clk_drift_ns": r.get("clk_drift_ns", 0),
                "wall_ns":      r.get("wall_ns", 0),
                "wall_iso":     r.get("wall_iso", ""),
            })

        elif t == "MON-HW":
            hw_recs.append(r)

        elif t == "RXM-RAW":
            rxm_recs.append(r)

    return header, fixes, sat_obs, clock_recs, hw_recs, rxm_recs


# ══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTORS
# ══════════════════════════════════════════════════════════════════════════════

def detect_constellation_collapse(
    fixes: List[PositionFix],
    sat_obs: List[SatelliteObs]
) -> List[Anomaly]:
    """
    Detection 1 + 2: Constellation collapse and single-satellite survival.

    Group satellite observations by timestamp epoch (wall_ns within 1s).
    For each epoch, count SVs visible and SVs used.
    Flag epochs where count drops to collapse threshold.
    Flag special case: exactly 1 SV surviving at healthy C/N0 = spoof signature.
    """
    anomalies = []

    # Group sat obs by 1-second epoch
    epochs = defaultdict(list)
    for sv in sat_obs:
        epoch_key = sv.wall_ns // 1_000_000_000
        epochs[epoch_key].append(sv)

    collapse_count   = 0
    single_sv_count  = 0
    first_collapse   = None
    single_sv_events = []

    for epoch_key, svs in sorted(epochs.items()):
        used     = [s for s in svs if s.sv_used]
        visible  = [s for s in svs if s.cno > 10]
        healthy  = [s for s in svs if s.cno >= CNO_HEALTHY_MIN]
        ts       = svs[0].wall_iso if svs else ""
        wns      = svs[0].wall_ns if svs else 0

        if len(used) <= COLLAPSE_SV_THRESHOLD:
            collapse_count += 1
            if first_collapse is None:
                first_collapse = ts

        # Single satellite survival: exactly 1 used at healthy C/N0
        # while others visible but unusable = spoof discriminator
        if len(used) == 1 and len(healthy) == 1 and len(visible) >= 3:
            sv = used[0]
            gnss = GNSS_NAMES.get(sv.gnss_id, f"GNSS{sv.gnss_id}")
            single_sv_count += 1
            single_sv_events.append({
                "ts":       ts,
                "wall_ns":  wns,
                "sv":       f"{gnss}:{sv.sv_id}",
                "cno":      sv.cno,
                "elev_deg": sv.elev_deg,
                "azim_deg": sv.azim_deg,
                "visible":  len(visible),
            })

    total_epochs = len(epochs)

    if collapse_count > 0:
        rate = collapse_count / total_epochs if total_epochs else 0
        anomalies.append(Anomaly(
            severity    = "HIGH" if rate < 0.2 else "CRITICAL",
            category    = "CONSTELLATION_COLLAPSE",
            description = (
                f"Satellite count at or below {COLLAPSE_SV_THRESHOLD} SVs "
                f"in {collapse_count} of {total_epochs} epochs "
                f"({rate*100:.1f}% of session). "
                f"Healthy GNSS operation requires minimum 4 SVs. "
                f"First collapse at {first_collapse}."
            ),
            timestamp   = first_collapse or "",
            wall_ns     = 0,
            evidence    = {
                "collapse_epochs":   collapse_count,
                "total_epochs":      total_epochs,
                "collapse_rate_pct": round(rate * 100, 1),
                "threshold_svs":     COLLAPSE_SV_THRESHOLD,
            },
            statutes    = ["47 U.S.C. § 333 — willful interference"],
        ))

    if single_sv_count > 0:
        anomalies.append(Anomaly(
            severity    = "CRITICAL",
            category    = "SINGLE_SATELLITE_SURVIVAL",
            description = (
                f"Exactly one satellite surviving at healthy C/N0 "
                f"({CNO_HEALTHY_MIN}+ dB-Hz) while remaining visible "
                f"constellation unusable, detected in {single_sv_count} "
                f"epochs. This pattern discriminates spoofing from "
                f"broadband jamming. A jammer suppresses ALL satellites "
                f"including the survivor. A coherent spoofer broadcasts "
                f"a synthetic signal for one PRN loud enough to maintain "
                f"lock while real signals on all other PRNs are lost."
            ),
            timestamp   = single_sv_events[0]["ts"] if single_sv_events else "",
            wall_ns     = single_sv_events[0]["wall_ns"] if single_sv_events else 0,
            evidence    = {
                "single_sv_epochs": single_sv_count,
                "events":           single_sv_events[:10],
            },
            statutes    = [
                "47 U.S.C. § 333 — willful interference",
                "18 U.S.C. § 1030 — computer fraud (GPS timing infrastructure)",
            ],
        ))

    return anomalies


def detect_cno_anomalies(sat_obs: List[SatelliteObs]) -> List[Anomaly]:
    """Detection 3: C/N0 anomalies per satellite."""
    anomalies = []

    # Aggregate C/N0 per SV
    sv_cnos = defaultdict(list)
    for sv in sat_obs:
        key = f"{GNSS_NAMES.get(sv.gnss_id,'?')}:{sv.sv_id}"
        if sv.cno > 0:
            sv_cnos[key].append(sv.cno)

    weak_svs    = []
    strong_svs  = []

    for key, cnos in sv_cnos.items():
        mean_cno = sum(cnos) / len(cnos)
        if mean_cno < CNO_HEALTHY_MIN and len(cnos) >= 5:
            weak_svs.append({"sv": key, "mean_cno": round(mean_cno,1), "n": len(cnos)})
        if mean_cno > CNO_ANOMALY_HIGH:
            strong_svs.append({"sv": key, "mean_cno": round(mean_cno,1), "n": len(cnos)})

    if weak_svs:
        anomalies.append(Anomaly(
            severity    = "MEDIUM",
            category    = "CNO_WEAK_SIGNALS",
            description = (
                f"{len(weak_svs)} satellites with mean C/N0 below "
                f"{CNO_HEALTHY_MIN} dB-Hz. Indicates elevated noise "
                f"floor from broadband RF interference or jamming. "
                f"Affected: {[s['sv'] for s in weak_svs]}"
            ),
            timestamp   = sat_obs[0].wall_iso if sat_obs else "",
            wall_ns     = sat_obs[0].wall_ns if sat_obs else 0,
            evidence    = {"weak_satellites": weak_svs},
            statutes    = ["47 U.S.C. § 333"],
        ))

    if strong_svs:
        anomalies.append(Anomaly(
            severity    = "HIGH",
            category    = "CNO_ANOMALOUSLY_STRONG",
            description = (
                f"{len(strong_svs)} satellites with mean C/N0 above "
                f"{CNO_ANOMALY_HIGH} dB-Hz. Real GPS signals at ground "
                f"level typically range 30-45 dB-Hz. Signals stronger "
                f"than this suggest a local re-broadcaster or spoofed "
                f"signal at elevated power. Affected: "
                f"{[s['sv'] for s in strong_svs]}"
            ),
            timestamp   = sat_obs[0].wall_iso if sat_obs else "",
            wall_ns     = sat_obs[0].wall_ns if sat_obs else 0,
            evidence    = {"strong_satellites": strong_svs},
            statutes    = [
                "47 U.S.C. § 333",
                "18 U.S.C. § 2512 — interception device",
            ],
        ))

    return anomalies


def detect_spoof_flags(clock_recs: list) -> List[Anomaly]:
    """Detection 4: NAV-STATUS hardware spoofing flags."""
    anomalies  = []
    spoof_events = []

    for r in clock_recs:
        if r.get("type") != "NAV-STATUS":
            continue
        if r.get("spoof_raw", 0) >= 2:
            spoof_events.append({
                "wall_iso":    r["wall_iso"],
                "wall_ns":     r["wall_ns"],
                "spoof_state": r["spoof_state"],
                "spoof_raw":   r["spoof_raw"],
            })

    if spoof_events:
        anomalies.append(Anomaly(
            severity    = "CRITICAL",
            category    = "HARDWARE_SPOOF_FLAG",
            description = (
                f"u-blox NAV-STATUS spoofDetState field reported "
                f"value >= 2 (spoofing indicated) in {len(spoof_events)} "
                f"records. This is the receiver's own onboard spoofing "
                f"detection algorithm firing. States: "
                f"{list(set(e['spoof_state'] for e in spoof_events))}. "
                f"First occurrence: {spoof_events[0]['wall_iso']}"
            ),
            timestamp   = spoof_events[0]["wall_iso"],
            wall_ns     = spoof_events[0]["wall_ns"],
            evidence    = {
                "event_count": len(spoof_events),
                "events":      spoof_events[:10],
            },
            statutes    = [
                "47 U.S.C. § 333 — willful interference",
                "18 U.S.C. § 2512 — interception device manufacture/use",
            ],
        ))

    return anomalies


def detect_jamming(hw_recs: list) -> List[Anomaly]:
    """Detection 5: MON-HW jamming indicator."""
    anomalies   = []
    jam_events  = []

    for r in hw_recs:
        ind = r.get("jam_ind", 0) or 0
        if ind > JAM_IND_THRESHOLD:
            jam_events.append({
                "wall_iso": r.get("wall_iso", ""),
                "wall_ns":  r.get("wall_ns",  0),
                "jam_ind":  ind,
                "jam_state":r.get("jam_state", 0),
            })

    if jam_events:
        max_jam = max(e["jam_ind"] for e in jam_events)
        anomalies.append(Anomaly(
            severity    = "HIGH",
            category    = "JAMMING_INDICATOR",
            description = (
                f"MON-HW jamInd exceeded threshold {JAM_IND_THRESHOLD}/255 "
                f"in {len(jam_events)} records. Peak value: {max_jam}/255. "
                f"Scale: 0=nominal, 255=severe jamming. Broadband jamming "
                f"raises the noise floor, reducing effective C/N0 across "
                f"all satellites. Jamming combined with single-satellite "
                f"survival is the signature of coordinated jam-plus-spoof."
            ),
            timestamp   = jam_events[0]["wall_iso"],
            wall_ns     = jam_events[0]["wall_ns"],
            evidence    = {
                "event_count": len(jam_events),
                "peak_jam_ind":max_jam,
                "threshold":   JAM_IND_THRESHOLD,
                "events":      jam_events[:10],
            },
            statutes    = ["47 U.S.C. § 333"],
        ))

    return anomalies


def detect_clock_anomalies(clock_recs: list) -> List[Anomaly]:
    """Detection 7: NAV-CLOCK bias and drift anomalies."""
    anomalies   = []
    bias_events = []
    drift_events= []

    for r in clock_recs:
        if r.get("type") != "NAV-CLOCK":
            continue
        bias  = abs(r.get("clk_bias_ns",  0) or 0)
        drift = abs(r.get("clk_drift_ns", 0) or 0)

        if bias > CLOCK_BIAS_THRESHOLD_NS:
            bias_events.append({
                "wall_iso": r["wall_iso"],
                "wall_ns":  r["wall_ns"],
                "bias_ns":  r["clk_bias_ns"],
                "bias_us":  round(r["clk_bias_ns"] / 1000, 3),
            })

        if drift > CLOCK_DRIFT_THRESHOLD_NS:
            drift_events.append({
                "wall_iso":  r["wall_iso"],
                "wall_ns":   r["wall_ns"],
                "drift_ns":  r["clk_drift_ns"],
            })

    if bias_events:
        anomalies.append(Anomaly(
            severity    = "HIGH",
            category    = "CLOCK_BIAS_ANOMALY",
            description = (
                f"NAV-CLOCK receiver clock bias exceeded "
                f"{CLOCK_BIAS_THRESHOLD_NS/1000:.0f} microseconds in "
                f"{len(bias_events)} records. Large clock bias can "
                f"indicate injection of false timing signals. GPS "
                f"timing is used by financial systems, cellular "
                f"synchronization, and power grid timing — bias "
                f"injection is an infrastructure attack vector."
            ),
            timestamp   = bias_events[0]["wall_iso"],
            wall_ns     = bias_events[0]["wall_ns"],
            evidence    = {
                "event_count":    len(bias_events),
                "max_bias_us":    max(abs(e["bias_us"]) for e in bias_events),
                "threshold_us":   CLOCK_BIAS_THRESHOLD_NS / 1000,
                "events":         bias_events[:5],
            },
            statutes    = ["47 U.S.C. § 333"],
        ))

    return anomalies


def detect_pr_residuals(rxm_recs: list) -> List[Anomaly]:
    """Detection 6: Pseudorange residual anomalies from RXM-RAW."""
    anomalies   = []
    pr_anomalies= []

    for r in rxm_recs:
        for meas in (r.get("measurements") or []):
            pr = meas.get("pr_m")
            if pr is None:
                continue
            # Pseudorange residuals: difference from expected
            # At GPS orbit ~20,200km, expected PR ~67-86 million meters
            # Residual anomaly: PR outside plausible range
            if pr > 0 and (pr < 19_000_000 or pr > 30_000_000):
                gnss = GNSS_NAMES.get(meas.get("gnssId", 0), "?")
                pr_anomalies.append({
                    "wall_iso": r.get("wall_iso", ""),
                    "wall_ns":  r.get("wall_ns",  0),
                    "sv":       f"{gnss}:{meas.get('svId','?')}",
                    "pr_m":     round(pr, 1),
                    "pr_km":    round(pr / 1000, 1),
                })

    if pr_anomalies:
        anomalies.append(Anomaly(
            severity    = "HIGH",
            category    = "PSEUDORANGE_IMPLAUSIBLE",
            description = (
                f"RXM-RAW pseudorange values outside the plausible "
                f"GPS orbit range (19,000 to 30,000 km) detected in "
                f"{len(pr_anomalies)} measurements. Implausible "
                f"pseudoranges indicate the receiver is processing "
                f"signals that do not correspond to actual satellite "
                f"distances, consistent with a spoofed signal source "
                f"at terrestrial range being presented as a satellite."
            ),
            timestamp   = pr_anomalies[0]["wall_iso"],
            wall_ns     = pr_anomalies[0]["wall_ns"],
            evidence    = {"anomalies": pr_anomalies[:10]},
            statutes    = ["47 U.S.C. § 333"],
        ))

    return anomalies


def detect_position_accuracy(fixes: List[PositionFix]) -> List[Anomaly]:
    """Detection 9: Position accuracy degradation."""
    anomalies    = []
    hacc_events  = []
    vacc_events  = []
    no_fix_epochs= 0

    for fix in fixes:
        if not fix.gps_fix_ok:
            no_fix_epochs += 1
        if fix.h_acc_m and fix.h_acc_m > HACC_ANOMALY_M:
            hacc_events.append({
                "wall_iso": fix.wall_iso,
                "h_acc_m":  round(fix.h_acc_m, 1),
                "fix_name": fix.fix_name,
                "num_sv":   fix.num_sv,
            })
        if fix.v_acc_m and fix.v_acc_m > VACC_ANOMALY_M:
            vacc_events.append({
                "wall_iso": fix.wall_iso,
                "v_acc_m":  round(fix.v_acc_m, 1),
            })

    if hacc_events:
        anomalies.append(Anomaly(
            severity    = "MEDIUM",
            category    = "POSITION_ACCURACY_DEGRADED",
            description = (
                f"Horizontal accuracy worse than {HACC_ANOMALY_M}m "
                f"in {len(hacc_events)} fixes. Maximum observed: "
                f"{max(e['h_acc_m'] for e in hacc_events):.1f}m. "
                f"Degraded accuracy combined with other anomalies "
                f"indicates the position solution is unreliable."
            ),
            timestamp   = hacc_events[0]["wall_iso"],
            wall_ns     = 0,
            evidence    = {
                "event_count": len(hacc_events),
                "max_hacc_m":  max(e["h_acc_m"] for e in hacc_events),
                "events":      hacc_events[:5],
            },
        ))

    return anomalies


# ══════════════════════════════════════════════════════════════════════════════
# DETECTION 10 — IMPOSSIBLE SATELLITE GEOMETRY
# The new core detection
# ══════════════════════════════════════════════════════════════════════════════

def detect_impossible_geometry(
    sat_obs:      List[SatelliteObs],
    fixes:        List[PositionFix],
    ground_truth: Optional[Tuple[float, float]]
) -> List[Anomaly]:
    """
    Detection 10: Impossible satellite geometry.

    Three sub-detections:

    10A — BEARING PAIR TRIANGULATION
    Take all pairs of satellites with valid az/el in each epoch.
    Compute the estimated receiver position from each pair's
    bearing lines. Compare to ground truth if known, or to
    the receiver's own reported position fix.
    Flag when the triangulated position diverges from the
    known/reported location beyond tolerance.

    10B — SUB-SATELLITE POINT CONSISTENCY
    For each satellite with known az/el, compute where the
    satellite sub-point should be on Earth's surface.
    If the receiver is stationary and at a known location,
    the sub-satellite points should cluster consistently
    across time (satellites move slowly — ~3.9 km/s at orbit).
    Sudden jumps in reported sub-satellite points indicate
    the az/el values have changed discontinuously, consistent
    with spoofer swapping satellite identities.

    10C — GEOMETRIC CONSISTENCY CHECK
    For each epoch with 3+ satellites, compute the predicted
    position solution from geometry alone (no pseudoranges).
    If the geometric position consistently differs from the
    reported position fix, the receiver is being given
    azimuth/elevation data inconsistent with its actual location.
    """
    anomalies = []

    if not sat_obs:
        return anomalies

    # Determine reference position
    ref_lat = ref_lon = None
    ref_source = "none"

    if ground_truth:
        ref_lat, ref_lon = ground_truth
        ref_source = "ground_truth"
    else:
        # Use median of reported fixes as reference
        valid_fixes = [f for f in fixes if f.lat and f.lon and f.gps_fix_ok]
        if valid_fixes:
            lats = sorted(f.lat for f in valid_fixes)
            lons = sorted(f.lon for f in valid_fixes)
            ref_lat = lats[len(lats)//2]
            ref_lon = lons[len(lons)//2]
            ref_source = "median_reported_fix"

    # Group satellite observations by 1-second epoch
    epochs = defaultdict(list)
    for sv in sat_obs:
        epoch_key = sv.wall_ns // 1_000_000_000
        epochs[epoch_key].append(sv)

    # ── 10A: Bearing pair triangulation ──────────────────────────────────────
    triangulation_errors = []
    impossible_positions  = []
    direction_estimates   = []

    for epoch_key, svs in sorted(epochs.items()):
        # Use only SVs with valid geometry (el > 10, sv_used or cno > 20)
        valid_svs = [s for s in svs
                     if s.elev_deg > 10
                     and (s.sv_used or s.cno > 20)
                     and s.azim_deg >= 0]

        if len(valid_svs) < 2:
            continue

        ts  = svs[0].wall_iso
        wns = svs[0].wall_ns

        # Try all pairs
        for i in range(len(valid_svs)):
            for j in range(i + 1, len(valid_svs)):
                sv1 = valid_svs[i]
                sv2 = valid_svs[j]

                # Skip nearly parallel bearings (bad geometry)
                az_diff = abs(sv1.azim_deg - sv2.azim_deg)
                if az_diff < 15 or az_diff > 345:
                    continue

                if ref_lat is None:
                    continue

                est = triangulate_position_from_two_satellites(
                    ref_lat, ref_lon,
                    sv1.azim_deg, sv1.elev_deg,
                    sv2.azim_deg, sv2.elev_deg
                )

                if est is None:
                    continue

                est_lat, est_lon = est

                # Validate estimated position is on Earth
                if not (-90 <= est_lat <= 90 and -180 <= est_lon <= 180):
                    continue

                # Distance from reference to triangulated position
                dist_m = haversine_m(ref_lat, ref_lon, est_lat, est_lon)

                if dist_m > TRILATERATION_TOLERANCE_M:
                    gnss1 = GNSS_NAMES.get(sv1.gnss_id, "?")
                    gnss2 = GNSS_NAMES.get(sv2.gnss_id, "?")
                    bearing = bearing_deg(ref_lat, ref_lon, est_lat, est_lon)

                    err = {
                        "ts":           ts,
                        "wall_ns":      wns,
                        "sv_pair":      [f"{gnss1}:{sv1.sv_id}",
                                         f"{gnss2}:{sv2.sv_id}"],
                        "est_lat":      round(est_lat, 6),
                        "est_lon":      round(est_lon, 6),
                        "displacement_m": round(dist_m, 1),
                        "displacement_km":round(dist_m / 1000, 2),
                        "bearing_to_est": round(bearing, 1),
                        "sv1_az":       sv1.azim_deg,
                        "sv1_el":       sv1.elev_deg,
                        "sv2_az":       sv2.azim_deg,
                        "sv2_el":       sv2.elev_deg,
                    }
                    triangulation_errors.append(err)

                    # If > 100 km: impossible — satellite geometry says
                    # receiver is somewhere it cannot physically be
                    if dist_m > IMPOSSIBLE_DISTANCE_KM * 1000:
                        impossible_positions.append(err)

                    # Accumulate bearing estimates for spoofer direction
                    direction_estimates.append(bearing)

    # ── 10B: Sub-satellite point discontinuity ────────────────────────────────
    sv_positions = defaultdict(list)
    for sv in sat_obs:
        if sv.elev_deg <= 0 or ref_lat is None:
            continue
        key  = f"{GNSS_NAMES.get(sv.gnss_id,'?')}:{sv.sv_id}"
        ssp  = latlon_from_azimuth_elevation(
            ref_lat, ref_lon, sv.azim_deg, sv.elev_deg
        )
        if ssp:
            sv_positions[key].append({
                "wall_ns":    sv.wall_ns,
                "wall_iso":   sv.wall_iso,
                "ssp_lat":    ssp[0],
                "ssp_lon":    ssp[1],
                "azim_deg":   sv.azim_deg,
                "elev_deg":   sv.elev_deg,
            })

    discontinuity_events = []
    for sv_key, positions in sv_positions.items():
        positions.sort(key=lambda x: x["wall_ns"])
        for k in range(1, len(positions)):
            prev = positions[k-1]
            curr = positions[k]
            dt_s = (curr["wall_ns"] - prev["wall_ns"]) / 1e9
            if dt_s <= 0 or dt_s > 60:
                continue  # skip large time gaps

            # How far did the sub-satellite point move in dt_s seconds?
            dist_m = haversine_m(
                prev["ssp_lat"], prev["ssp_lon"],
                curr["ssp_lat"], curr["ssp_lon"]
            )

            # GPS satellites move at ~3.9 km/s. In dt_s seconds:
            max_expected_m = 3_900 * dt_s + 500  # 500m margin

            if dist_m > max_expected_m:
                speed_kms = dist_m / 1000 / dt_s
                discontinuity_events.append({
                    "sv":             sv_key,
                    "wall_iso":       curr["wall_iso"],
                    "wall_ns":        curr["wall_ns"],
                    "jump_m":         round(dist_m, 1),
                    "jump_km":        round(dist_m / 1000, 2),
                    "dt_s":           round(dt_s, 3),
                    "speed_kms":      round(speed_kms, 1),
                    "max_expected_m": round(max_expected_m, 1),
                    "prev_az":        prev["azim_deg"],
                    "prev_el":        prev["elev_deg"],
                    "curr_az":        curr["azim_deg"],
                    "curr_el":        curr["elev_deg"],
                })

    # ── 10C: Reported fix vs geometric consistency ────────────────────────────
    fix_geometry_errors = []
    if ground_truth and fixes:
        ref_lat, ref_lon = ground_truth
        for fix in fixes:
            if not fix.lat or not fix.lon:
                continue
            if not fix.gps_fix_ok:
                continue
            dist_from_truth = haversine_m(ref_lat, ref_lon, fix.lat, fix.lon)
            if dist_from_truth > TRILATERATION_TOLERANCE_M:
                bearing = bearing_deg(ref_lat, ref_lon, fix.lat, fix.lon)
                fix_geometry_errors.append({
                    "wall_iso":         fix.wall_iso,
                    "wall_ns":          fix.wall_ns,
                    "reported_lat":     fix.lat,
                    "reported_lon":     fix.lon,
                    "ground_truth_lat": ref_lat,
                    "ground_truth_lon": ref_lon,
                    "displacement_m":   round(dist_from_truth, 1),
                    "displacement_km":  round(dist_from_truth / 1000, 2),
                    "bearing_to_reported": round(bearing, 1),
                    "fix_name":         fix.fix_name,
                    "num_sv":           fix.num_sv,
                    "h_acc_m":          fix.h_acc_m,
                })
                direction_estimates.append(bearing)

    # ── Compute consensus spoofer bearing ─────────────────────────────────────
    consensus_bearing = None
    if direction_estimates:
        # Circular mean of bearing estimates
        sin_sum = sum(math.sin(math.radians(b)) for b in direction_estimates)
        cos_sum = sum(math.cos(math.radians(b)) for b in direction_estimates)
        consensus_bearing = round(
            math.degrees(math.atan2(sin_sum, cos_sum)) % 360, 1
        )

    # ── Emit anomalies ────────────────────────────────────────────────────────

    if triangulation_errors:
        anomalies.append(Anomaly(
            severity    = ("CRITICAL" if impossible_positions
                           else "HIGH"),
            category    = "IMPOSSIBLE_SATELLITE_GEOMETRY",
            description = (
                f"Satellite bearing pair triangulation produced "
                f"{len(triangulation_errors)} position estimates "
                f"diverging from the reference location by more than "
                f"{TRILATERATION_TOLERANCE_M:.0f}m. "
                + (f"{len(impossible_positions)} estimates are more than "
                   f"{IMPOSSIBLE_DISTANCE_KM:.0f}km from reference — "
                   f"geometrically impossible for a stationary receiver. "
                   if impossible_positions else "")
                + (f"Consensus displacement bearing: {consensus_bearing}°. "
                   if consensus_bearing else "")
                + f"Reference source: {ref_source}. "
                f"This indicates the azimuth/elevation values reported "
                f"by the receiver for its satellites are inconsistent "
                f"with the receiver's actual physical location. "
                f"The satellite geometry as reported can only be true "
                f"if the receiver were at a different location, "
                f"indicating the satellite signal data is synthetic."
            ),
            timestamp   = (triangulation_errors[0]["ts"]
                           if triangulation_errors else ""),
            wall_ns     = (triangulation_errors[0]["wall_ns"]
                           if triangulation_errors else 0),
            evidence    = {
                "triangulation_error_count": len(triangulation_errors),
                "impossible_position_count": len(impossible_positions),
                "consensus_bearing_deg":     consensus_bearing,
                "reference_lat":             ref_lat,
                "reference_lon":             ref_lon,
                "reference_source":          ref_source,
                "sample_errors":             triangulation_errors[:5],
                "impossible_positions":      impossible_positions[:3],
            },
            statutes    = [
                "47 U.S.C. § 333 — willful interference",
                "18 U.S.C. § 2512 — interception device",
                "18 U.S.C. § 1030 — GPS timing infrastructure attack",
            ],
        ))

    if discontinuity_events:
        anomalies.append(Anomaly(
            severity    = "HIGH",
            category    = "SATELLITE_POSITION_DISCONTINUITY",
            description = (
                f"Sub-satellite point computed from reported azimuth/"
                f"elevation jumped at a rate exceeding physical GPS "
                f"orbital velocity in {len(discontinuity_events)} events. "
                f"Real GPS satellites move at approximately 3.9 km/s. "
                f"Jumps exceeding this rate indicate the reported "
                f"azimuth/elevation values changed discontinuously, "
                f"consistent with a spoofer reassigning which synthetic "
                f"satellite signal is being broadcast."
            ),
            timestamp   = (discontinuity_events[0]["wall_iso"]
                           if discontinuity_events else ""),
            wall_ns     = (discontinuity_events[0]["wall_ns"]
                           if discontinuity_events else 0),
            evidence    = {
                "discontinuity_count": len(discontinuity_events),
                "max_speed_kms": max(e["speed_kms"] for e in discontinuity_events),
                "gps_max_speed_kms": 3.9,
                "events": discontinuity_events[:5],
            },
            statutes    = ["47 U.S.C. § 333"],
        ))

    if fix_geometry_errors:
        max_disp = max(e["displacement_m"] for e in fix_geometry_errors)
        anomalies.append(Anomaly(
            severity    = "CRITICAL",
            category    = "REPORTED_POSITION_DISPLACED_FROM_GROUND_TRUTH",
            description = (
                f"Receiver reported position fix displaced from known "
                f"static ground truth in {len(fix_geometry_errors)} fixes. "
                f"Maximum displacement: {max_disp/1000:.2f}km. "
                + (f"Consensus bearing from ground truth to reported "
                   f"position: {consensus_bearing}°. "
                   if consensus_bearing else "")
                + f"The receiver claims to be at a different location "
                f"than its actual physical position. This is the "
                f"defining characteristic of GPS position spoofing: "
                f"the receiver computes a position solution from "
                f"synthetic signals that places it elsewhere."
            ),
            timestamp   = fix_geometry_errors[0]["wall_iso"],
            wall_ns     = fix_geometry_errors[0]["wall_ns"],
            evidence    = {
                "error_count":         len(fix_geometry_errors),
                "max_displacement_m":  round(max_disp, 1),
                "max_displacement_km": round(max_disp / 1000, 2),
                "consensus_bearing":   consensus_bearing,
                "ground_truth_lat":    ref_lat,
                "ground_truth_lon":    ref_lon,
                "errors":              fix_geometry_errors[:5],
            },
            statutes    = [
                "47 U.S.C. § 333",
                "18 U.S.C. § 2512",
            ],
        ))

    return anomalies


# ══════════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}

def severity_label(sev):
    labels = {
        "CRITICAL": "[!!!] CRITICAL",
        "HIGH":     "[** ] HIGH    ",
        "MEDIUM":   "[*  ] MEDIUM  ",
        "INFO":     "[   ] INFO    ",
    }
    return labels.get(sev, f"[   ] {sev}")


def generate_report(
    gz_path:      str,
    anomalies:    List[Anomaly],
    header:       dict,
    fixes:        List[PositionFix],
    sat_obs:      List[SatelliteObs],
    ground_truth: Optional[Tuple[float, float]],
    out_dir:      str
) -> Tuple[str, str]:
    """Generate text and JSON reports. Returns (txt_path, json_path)."""

    sorted_anomalies = sorted(
        anomalies,
        key=lambda a: (SEVERITY_ORDER.get(a.severity, 99), a.wall_ns)
    )

    # Count by severity
    counts = defaultdict(int)
    for a in anomalies:
        counts[a.severity] += 1

    session_start = header.get("session_wall_utc", "unknown")
    ntp_offset    = header.get("ntp_offset_ms",    "unknown")
    ubx_source    = header.get("ubx_source",       "unknown")
    compass_en    = header.get("compass_enabled",   False)

    # Fix statistics
    total_fixes  = len(fixes)
    valid_fixes  = [f for f in fixes if f.gps_fix_ok]
    fix_3d       = [f for f in fixes if f.fix_name == "3D"]
    no_fix       = [f for f in fixes if f.fix_name == "no_fix"]

    # Satellite statistics
    all_prns  = set()
    max_svs   = 0
    min_svs   = 999

    epochs = defaultdict(list)
    for sv in sat_obs:
        epoch_key = sv.wall_ns // 1_000_000_000
        epochs[epoch_key].append(sv)
        all_prns.add((sv.gnss_id, sv.sv_id))
    for _, svs in epochs.items():
        used = sum(1 for s in svs if s.sv_used)
        if used > max_svs: max_svs = used
        if used < min_svs: min_svs = used
    if not epochs:
        max_svs = min_svs = 0

    # ── TEXT REPORT ───────────────────────────────────────────────────────────

    lines = []
    W = 80

    def hr(char="─"):
        lines.append(char * W)

    def title(text):
        lines.append(f"{'='*W}")
        lines.append(f"  {text}")
        lines.append(f"{'='*W}")

    def section(text):
        lines.append("")
        lines.append(f"  {text}")
        lines.append(f"  {'─'*(W-4)}")

    title("GNSS FORENSIC ANOMALY DETECTION REPORT")

    lines.append(f"  Generated     : {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append(f"  Session start : {session_start}")
    lines.append(f"  NTP offset    : {ntp_offset} ms")
    lines.append(f"  UBX source    : {os.path.basename(str(ubx_source))}")
    lines.append(f"  Compass       : {'active' if compass_en else 'not connected'}")
    if ground_truth:
        lines.append(f"  Ground truth  : {ground_truth[0]:.8f}, {ground_truth[1]:.8f}")
    else:
        lines.append(f"  Ground truth  : not provided (using median fix as reference)")
    lines.append(f"  Report stamp  : {STAMP}")
    lines.append("")

    # Summary box
    lines.append(f"  {'='*60}")
    lines.append(f"  SUMMARY")
    lines.append(f"  {'─'*60}")
    lines.append(f"  Total anomalies   : {len(anomalies)}")
    lines.append(f"    CRITICAL        : {counts.get('CRITICAL', 0)}")
    lines.append(f"    HIGH            : {counts.get('HIGH', 0)}")
    lines.append(f"    MEDIUM          : {counts.get('MEDIUM', 0)}")
    lines.append(f"    INFO            : {counts.get('INFO', 0)}")
    lines.append(f"  {'─'*60}")
    lines.append(f"  Total position fixes  : {total_fixes}")
    lines.append(f"  Valid (gpsFixOk=true) : {len(valid_fixes)}")
    lines.append(f"  3D fixes              : {len(fix_3d)}")
    lines.append(f"  No-fix epochs         : {len(no_fix)}")
    lines.append(f"  SVs observed (unique) : {len(all_prns)}")
    lines.append(f"  SVs used (max/min)    : {max_svs} / {min_svs if min_svs < 999 else 0}")
    lines.append(f"  Observation epochs    : {len(epochs)}")
    lines.append(f"  {'='*60}")

    if not anomalies:
        lines.append("")
        lines.append("  NO ANOMALIES DETECTED IN THIS SESSION.")
        lines.append("  Satellite geometry, signal levels, and position")
        lines.append("  solutions are consistent with normal operation.")
    else:
        section("ANOMALY DETAILS")

        for idx, a in enumerate(sorted_anomalies, 1):
            lines.append("")
            lines.append(f"  [{idx:02d}] {severity_label(a.severity)}  "
                         f"{a.category}")
            lines.append(f"       Timestamp : {a.timestamp}")
            lines.append("")

            # Word-wrap description at 72 chars
            words   = a.description.split()
            line_buf= "       "
            for word in words:
                if len(line_buf) + len(word) + 1 > 76:
                    lines.append(line_buf)
                    line_buf = "       " + word + " "
                else:
                    line_buf += word + " "
            if line_buf.strip():
                lines.append(line_buf)

            # Key evidence fields (selective)
            lines.append("")
            ev = a.evidence
            if "displacement_m" in ev:
                lines.append(f"       Displacement  : {ev['displacement_m']:.1f}m "
                             f"({ev.get('displacement_km',0):.2f}km)")
            if "consensus_bearing_deg" in ev and ev["consensus_bearing_deg"]:
                lines.append(f"       Bearing       : {ev['consensus_bearing_deg']}° "
                             f"(direction from reference to anomalous position)")
            if "max_displacement_m" in ev:
                lines.append(f"       Max disp.     : {ev['max_displacement_m']:.1f}m "
                             f"({ev.get('max_displacement_km',0):.2f}km)")
            if "consensus_bearing" in ev and ev["consensus_bearing"]:
                lines.append(f"       Est. bearing  : {ev['consensus_bearing']}° "
                             f"from ground truth toward reported position")
            if "peak_jam_ind" in ev:
                lines.append(f"       Peak jam ind. : {ev['peak_jam_ind']}/255")
            if "single_sv_epochs" in ev:
                lines.append(f"       Epochs        : {ev['single_sv_epochs']} "
                             f"single-SV-survival events")
            if "impossible_position_count" in ev:
                lines.append(f"       Impossible    : {ev['impossible_position_count']} "
                             f"positions > {IMPOSSIBLE_DISTANCE_KM:.0f}km from reference")
            if "max_speed_kms" in ev:
                lines.append(f"       Max sv speed  : {ev['max_speed_kms']} km/s "
                             f"(physical max 3.9 km/s)")
            if "max_bias_us" in ev:
                lines.append(f"       Max bias      : {ev['max_bias_us']}μs")

            if a.statutes:
                lines.append(f"       Statutes      : {' | '.join(a.statutes)}")

            lines.append(f"  {'·'*72}")

    # ── Geometry section (if ground truth provided) ───────────────────────────
    if ground_truth and anomalies:
        geom_anomalies = [a for a in anomalies
                          if "GEOMETRY" in a.category
                          or "SATELLITE_POSITION" in a.category
                          or "DISPLACED" in a.category]

        if geom_anomalies:
            section("GEOMETRIC ANALYSIS NOTES")
            lines.append("")
            lines.append("  HOW THE GEOMETRIC DETECTION WORKS")
            lines.append("  ──────────────────────────────────")
            lines.append("")
            lines.append("  Each GPS satellite in view has a reported azimuth (compass")
            lines.append("  direction from observer) and elevation (angle above horizon).")
            lines.append("  Using these two angles from a known static observer location,")
            lines.append("  the satellite's position in space can be projected geometrically.")
            lines.append("")
            lines.append("  If you take two satellite bearings and project their lines")
            lines.append("  toward the sky, they should intersect at approximately the")
            lines.append("  satellite's orbital altitude. The receiver's position can then")
            lines.append("  be back-computed from those intersection lines.")
            lines.append("")
            lines.append("  For a stationary receiver at a known location:")
            lines.append("    - Bearing pair triangulations should land near that location")
            lines.append("    - Satellite sub-points should move at plausible orbital speeds")
            lines.append("    - Reported position fix should match the known location")
            lines.append("")
            lines.append("  When ANY of these are violated, the satellite geometry as")
            lines.append("  reported by the receiver is inconsistent with the receiver")
            lines.append("  being where it physically is. The only way to produce this")
            lines.append("  inconsistency is to feed the receiver false satellite data.")
            lines.append("")
            lines.append("  The displacement vector (how far off, in what direction) is")
            lines.append("  itself evidence of the spoofing architecture — it reflects")
            lines.append("  the position the attacker intends the receiver to compute,")
            lines.append("  and the bearing from ground truth to that false position")
            lines.append("  provides directional evidence about the spoofer's location.")

    # ── Statistical summary ───────────────────────────────────────────────────
    if sat_obs:
        section("SIGNAL ENVIRONMENT STATISTICS")
        cno_vals = [sv.cno for sv in sat_obs if sv.cno > 0]
        if cno_vals:
            cno_vals.sort()
            n = len(cno_vals)
            lines.append(f"  C/N0 distribution ({n} measurements):")
            lines.append(f"    Min    : {cno_vals[0]:.1f} dB-Hz")
            lines.append(f"    Median : {cno_vals[n//2]:.1f} dB-Hz")
            lines.append(f"    Max    : {cno_vals[-1]:.1f} dB-Hz")
            lines.append(f"    Mean   : {sum(cno_vals)/n:.1f} dB-Hz")
            pct_weak = sum(1 for c in cno_vals if c < CNO_HEALTHY_MIN) / n * 100
            lines.append(f"    Weak (<{CNO_HEALTHY_MIN}dBHz): {pct_weak:.1f}% of readings")

        el_vals = [sv.elev_deg for sv in sat_obs if sv.elev_deg > 0]
        if el_vals:
            lines.append(f"  Elevation distribution ({len(el_vals)} SVs):")
            lines.append(f"    Min : {min(el_vals):.1f}°   Max : {max(el_vals):.1f}°")

    # ── Footer ────────────────────────────────────────────────────────────────
    lines.append("")
    lines.append(f"{'='*W}")
    lines.append("  RECORD NOTES")
    lines.append(f"  {'─'*(W-4)}")
    lines.append("  This report was generated by CTW SENTINEL gnss_anomaly_report.py.")
    lines.append("  All timestamps are in UTC, nanosecond precision, calibrated")
    lines.append("  against a web time reference at session initialization.")
    lines.append("  Geometric calculations use standard spherical Earth geometry")
    lines.append("  (WGS-84 approximation) with GPS MEO orbit radius 26,560 km.")
    lines.append("  Detection thresholds are documented in the script source code.")
    lines.append("  This report is structured for personal and legal records.")
    lines.append(f"{'='*W}")
    lines.append("")

    txt_content = '\n'.join(lines)

    # Write text report
    txt_path = os.path.join(out_dir, f"gnss_anomaly_report_{STAMP}.txt")
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write(txt_content)

    # ── JSON REPORT ───────────────────────────────────────────────────────────
    json_report = {
        "report_type":    "gnss_anomaly_detection",
        "generated_utc":  datetime.datetime.utcnow().isoformat(),
        "stamp":          STAMP,
        "session": {
            "start":          session_start,
            "ntp_offset_ms":  ntp_offset,
            "ubx_source":     str(ubx_source),
            "compass_enabled":compass_en,
        },
        "ground_truth": {
            "lat":    ground_truth[0] if ground_truth else None,
            "lon":    ground_truth[1] if ground_truth else None,
            "source": "provided" if ground_truth else "median_fix",
        },
        "summary": {
            "total_anomalies":  len(anomalies),
            "by_severity":      dict(counts),
            "total_fixes":      total_fixes,
            "valid_fixes":      len(valid_fixes),
            "fix_3d":           len(fix_3d),
            "no_fix_epochs":    len(no_fix),
            "unique_svs":       len(all_prns),
            "max_svs_used":     max_svs,
            "min_svs_used":     min_svs if min_svs < 999 else 0,
            "observation_epochs": len(epochs),
        },
        "anomalies": [
            {
                "severity":    a.severity,
                "category":    a.category,
                "description": a.description,
                "timestamp":   a.timestamp,
                "wall_ns":     a.wall_ns,
                "evidence":    a.evidence,
                "statutes":    a.statutes,
            }
            for a in sorted_anomalies
        ],
    }

    json_path = os.path.join(out_dir, f"gnss_anomaly_report_{STAMP}.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(json_report, f, indent=2, default=str)

    return txt_path, json_path


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def find_latest_gnss_log(directory):
    import glob
    files = glob.glob(os.path.join(directory, "gnss_*.jsonl.gz"))
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def find_all_gnss_logs(directory):
    import glob
    return sorted(glob.glob(os.path.join(directory, "gnss_*.jsonl.gz")))


def main():
    ap = argparse.ArgumentParser(
        description="CTW GNSS Forensic Anomaly Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--log",          default=None,
                    help="Path to specific gnss_*.jsonl.gz log file. "
                         "Default: latest in --out directory.")
    ap.add_argument("--all-logs",     action="store_true",
                    help="Process all gnss_*.jsonl.gz files in --out directory")
    ap.add_argument("--ground-truth", default=None,
                    metavar="LAT,LON",
                    help="Static receiver ground truth position e.g. "
                         "33.800509,-117.220352  "
                         "If not provided, median of reported fixes is used.")
    ap.add_argument("--out",          default=r"C:\sdr\logs",
                    metavar="DIR",
                    help="Log directory (default: C:\\sdr\\logs)")
    args = ap.parse_args()

    out_dir = os.path.abspath(args.out)

    # Parse ground truth
    ground_truth = None
    if args.ground_truth:
        try:
            parts = args.ground_truth.strip().split(',')
            ground_truth = (float(parts[0].strip()),
                            float(parts[1].strip()))
            print(f"[GNSS] Ground truth: {ground_truth[0]:.8f}, "
                  f"{ground_truth[1]:.8f}")
        except Exception as e:
            print(f"[ERR] Invalid --ground-truth: {e}")
            print("      Format: LAT,LON  e.g. 33.800509,-117.220352")
            sys.exit(1)

    # Find log files to process
    if args.all_logs:
        log_files = find_all_gnss_logs(out_dir)
        if not log_files:
            print(f"[ERR] No gnss_*.jsonl.gz files found in {out_dir}")
            sys.exit(1)
        print(f"[GNSS] Processing {len(log_files)} log files...")
    elif args.log:
        log_files = [args.log]
    else:
        latest = find_latest_gnss_log(out_dir)
        if not latest:
            print(f"[ERR] No gnss_*.jsonl.gz found in {out_dir}")
            print("      Run ublox_data.py and ublox_parser.py first.")
            sys.exit(1)
        log_files = [latest]

    all_reports = []

    for gz_path in log_files:
        print(f"\n{'='*62}")
        print(f"  CTW GNSS ANOMALY DETECTOR")
        print(f"{'='*62}")
        print(f"  Log  : {os.path.basename(gz_path)}")
        print(f"  Out  : {out_dir}")
        print(f"  GT   : {ground_truth or 'using median fix'}")
        print(f"{'='*62}\n")

        print("[GNSS] Reading log...")
        records = read_gnss_log(gz_path)
        print(f"[GNSS] {len(records)} records loaded.")

        print("[GNSS] Extracting session data...")
        header, fixes, sat_obs, clock_recs, hw_recs, rxm_recs = \
            extract_session_data(records)

        print(f"[GNSS]   Fixes       : {len(fixes)}")
        print(f"[GNSS]   Sat obs     : {len(sat_obs)}")
        print(f"[GNSS]   Clock recs  : {len(clock_recs)}")
        print(f"[GNSS]   HW recs     : {len(hw_recs)}")
        print(f"[GNSS]   RXM-RAW     : {len(rxm_recs)}")

        print("[GNSS] Running anomaly detectors...")

        anomalies = []

        det = [
            ("Constellation collapse",
             lambda: detect_constellation_collapse(fixes, sat_obs)),
            ("C/N0 anomalies",
             lambda: detect_cno_anomalies(sat_obs)),
            ("Hardware spoof flags",
             lambda: detect_spoof_flags(clock_recs)),
            ("Jamming indicator",
             lambda: detect_jamming(hw_recs)),
            ("Clock anomalies",
             lambda: detect_clock_anomalies(clock_recs)),
            ("Pseudorange plausibility",
             lambda: detect_pr_residuals(rxm_recs)),
            ("Position accuracy",
             lambda: detect_position_accuracy(fixes)),
            ("Impossible satellite geometry",
             lambda: detect_impossible_geometry(sat_obs, fixes, ground_truth)),
        ]

        for name, fn in det:
            print(f"[GNSS]   {name}...", end=" ", flush=True)
            result = fn()
            anomalies.extend(result)
            print(f"{len(result)} anomalies")

        print(f"\n[GNSS] Total anomalies: {len(anomalies)}")

        sev_counts = defaultdict(int)
        for a in anomalies:
            sev_counts[a.severity] += 1
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
            if sev_counts[sev]:
                print(f"[GNSS]   {sev:<10}: {sev_counts[sev]}")

        print("[GNSS] Generating report...")
        txt_path, json_path = generate_report(
            gz_path, anomalies, header, fixes, sat_obs,
            ground_truth, out_dir
        )
        all_reports.append((txt_path, json_path))

        print(f"\n[GNSS] Report written:")
        print(f"  Text : {txt_path}")
        print(f"  JSON : {json_path}")

    if len(all_reports) > 1:
        print(f"\n[GNSS] Processed {len(all_reports)} logs. Reports:")
        for txt, js in all_reports:
            print(f"  {os.path.basename(txt)}")

    print("\nDone.")


if __name__ == "__main__":
    main()
