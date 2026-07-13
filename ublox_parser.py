#!/usr/bin/env python3
"""
ublox_parser.py  —  CTW UBX Binary Forensic Parser
====================================================
Tails a u-blox 7 raw binary .ubx file, extracts navigation messages,
writes to gnss_STAMP.jsonl.gz using the same GzipLog/ClockAnchor
architecture as pluto_sweep.py.

Emits to runtime/gnss_live.jsonl for live dashboard consumption.

Parsed message classes:
  NAV-PVT    (0x01 0x07) — position, velocity, time, fix quality
  NAV-SAT    (0x01 0x35) — per-satellite CNR, azimuth, elevation
  NAV-STATUS (0x01 0x03) — spoofDetState, gpsFixOk
  NAV-CLOCK  (0x01 0x22) — clock bias, drift
  MON-HW     (0x0A 0x09) — jamming indicator, AGC
  RXM-RAW    (0x02 0x10) — pseudoranges per satellite
"""

import argparse
import datetime
import glob
import gzip
import json
import os
import struct
import sys
import threading
import time
from collections import deque
from pathlib import Path

# ── CONFIGURATION — change UBX_DIR to redirect parser ─────────────────────
UBX_DIR      = r"C:\sdr\logs\UBLOX"          # directory to watch
RUNTIME_DIR  = r"C:\sdr\logs\runtime"        # live mirror output
POLL_INTERVAL_S  = 0.15                       # tail poll cadence
SYNC_A, SYNC_B   = 0xB5, 0x62               # UBX frame sync bytes

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ── OOB guard ──────────────────────────────────────────────────────────────
_OOB = {
    "MAX_PAYLOAD":   4096,
    "MAX_LAT":       90.0,
    "MAX_LON":      180.0,
    "MAX_ALT_M":  100000.0,
    "MAX_SAT":       64,
    "MAX_CNR":       60,
    "MAX_AZ":       360,
    "MAX_EL":        90,
}

def _cf(v, lo, hi):
    if v is None: return None
    try:
        f = float(v)
        if not (-1e18 < f < 1e18): return None
        return max(lo, min(hi, f))
    except Exception: return None

def _ci(v, lo, hi):
    if v is None: return None
    try:
        i = int(v)
        return max(lo, min(hi, i))
    except Exception: return None

# ── ClockAnchor (same as pluto_sweep.py) ──────────────────────────────────
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
        mono_now = time.perf_counter_ns()
        delta    = mono_now - self._mono_epoch
        return self._wall_epoch + delta, delta

    def format_wall_ns(self, wall_ns):
        whole_s = wall_ns // 1_000_000_000
        frac_ns = wall_ns  % 1_000_000_000
        base = datetime.datetime.fromtimestamp(
            whole_s, tz=datetime.timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%S')
        return f"{base}.{frac_ns:09d}Z"

# ── GzipLog (same as pluto_sweep.py) ──────────────────────────────────────
class GzipLog:
    def __init__(self, path, header):
        self.path   = path
        self._q     = deque()
        self._event = threading.Event()
        self._stop  = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True,
            name=f'GzipLog:{os.path.basename(path)}'
        )
        first = json.dumps(header, separators=(',', ':')) + '\n'
        with gzip.open(self.path, 'ab', compresslevel=6) as gz:
            gz.write(first.encode())
        self._thread.start()

    def write(self, obj):
        self._q.append(obj)
        self._event.set()

    def close(self):
        self._stop.set()
        self._event.set()
        self._thread.join(timeout=8)

    def _run(self):
        while not self._stop.is_set():
            self._event.wait()
            self._event.clear()
            self._drain()
        self._drain()

    def _drain(self):
        if not self._q: return
        lines = []
        while self._q:
            lines.append(json.dumps(self._q.popleft(), separators=(',', ':')))
        blob = ('\n'.join(lines) + '\n').encode()
        with gzip.open(self.path, 'ab', compresslevel=6) as gz:
            gz.write(blob)

# ── Live JSONL mirror ──────────────────────────────────────────────────────
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

# ── UBX frame parser ───────────────────────────────────────────────────────
def ubx_checksum(payload_with_class_id_len):
    ck_a = ck_b = 0
    for b in payload_with_class_id_len:
        ck_a = (ck_a + b) & 0xFF
        ck_b = (ck_b + ck_a) & 0xFF
    return ck_a, ck_b

class UBXFramer:
    """
    Stateful framer — feeds raw bytes and yields complete verified frames
    as (cls_id, msg_id, payload_bytes).
    """
    ST_SYNC1 = 0
    ST_SYNC2 = 1
    ST_CLS   = 2
    ST_ID    = 3
    ST_LEN1  = 4
    ST_LEN2  = 5
    ST_PAY   = 6
    ST_CK_A  = 7
    ST_CK_B  = 8

    def __init__(self):
        self._state   = self.ST_SYNC1
        self._cls     = 0
        self._id      = 0
        self._len     = 0
        self._payload = bytearray()
        self._ck_a    = 0

    def feed(self, data: bytes):
        for byte in data:
            yield from self._process(byte)

    def _process(self, byte):
        s = self._state
        if s == self.ST_SYNC1:
            if byte == SYNC_A: self._state = self.ST_SYNC2
        elif s == self.ST_SYNC2:
            if byte == SYNC_B: self._state = self.ST_CLS
            else: self._state = self.ST_SYNC1
        elif s == self.ST_CLS:
            self._cls = byte; self._state = self.ST_ID
        elif s == self.ST_ID:
            self._id = byte; self._state = self.ST_LEN1
        elif s == self.ST_LEN1:
            self._len = byte; self._state = self.ST_LEN2
        elif s == self.ST_LEN2:
            self._len |= (byte << 8)
            if self._len > _OOB["MAX_PAYLOAD"]:
                self._state = self.ST_SYNC1
                return
            self._payload = bytearray()
            self._state = self.ST_PAY if self._len > 0 else self.ST_CK_A
        elif s == self.ST_PAY:
            self._payload.append(byte)
            if len(self._payload) == self._len:
                self._state = self.ST_CK_A
        elif s == self.ST_CK_A:
            self._ck_a = byte; self._state = self.ST_CK_B
        elif s == self.ST_CK_B:
            self._state = self.ST_SYNC1
            check_data = bytes([self._cls, self._id,
                                 self._len & 0xFF, (self._len >> 8) & 0xFF]
                                ) + bytes(self._payload)
            exp_a, exp_b = ubx_checksum(check_data)
            if exp_a == self._ck_a and exp_b == byte:
                yield (self._cls, self._id, bytes(self._payload))
#GPS
class CompassReceiver:
    """
    Receives compass heading from compass_bridge.py running on phone.
    Connects via ADB-forwarded TCP (adb forward tcp:5556 tcp:5556).
    Adds heading_deg to every NAV-PVT record written to gnss_live.jsonl.
    """

    def __init__(self, host="localhost", port=5556):
        self._host    = host
        self._port    = port
        self._heading = None
        self._raw     = {}
        self._lock    = threading.Lock()
        self._stop    = threading.Event()
        self._thread  = threading.Thread(
            target=self._run, daemon=True, name="Compass-RX"
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.is_set():
            try:
                import socket
                s = socket.socket()
                s.settimeout(5.0)
                s.connect((self._host, self._port))
                print(f"[Compass] Connected to {self._host}:{self._port}")
                buf = ""
                while not self._stop.is_set():
                    chunk = s.recv(1024).decode('utf-8', errors='ignore')
                    if not chunk:
                        break
                    buf += chunk
                    while '\n' in buf:
                        line, buf = buf.split('\n', 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            with self._lock:
                                self._heading = data.get("heading_deg")
                                self._raw     = data
                        except Exception:
                            pass
                s.close()
            except Exception as e:
                print(f"[Compass] Reconnecting: {e}")
                time.sleep(3)

    def get_heading(self):
        with self._lock:
            return self._heading, dict(self._raw)
# ── Message decoders ───────────────────────────────────────────────────────

GNSS_ID_NAMES = {
    0: 'GPS', 1: 'SBAS', 2: 'Galileo',
    3: 'BeiDou', 5: 'QZSS', 6: 'GLONASS'
}

SPOOF_STATES = {
    0: 'unknown', 1: 'no_spoofing',
    2: 'spoofing_indicated', 3: 'multiple_spoofing'
}


def decode_nav_pvt(payload, clock, wall_ns, mono_ns):
    if len(payload) < 84: return None
    (iTOW, year, month, day, hour, minute, second,
     valid, tAcc, nano, fixType, flags, flags2, numSV,
     lon_raw, lat_raw, height_raw, hMSL_raw,
     hAcc, vAcc, velN, velE, velD, gSpeed, headMot,
     sAcc, headAcc, pDOP) = struct.unpack_from(
        '<IHBBBBBBIiBBBBiiiiIIiiiiiII', payload, 0)

    lon  = _cf(lon_raw  * 1e-7, -180.0, 180.0)
    lat  = _cf(lat_raw  * 1e-7,  -90.0,  90.0)
    alt  = _cf(hMSL_raw * 1e-3, -1000.0, _OOB["MAX_ALT_M"])
    hacc = _cf(hAcc     * 1e-3,    0.0, 50000.0)
    vacc = _cf(vAcc     * 1e-3,    0.0, 50000.0)

    gps_fix_ok    = bool(flags & 0x01)
    diff_soln     = bool(flags & 0x02)
    psm_state     = (flags >> 2) & 0x07
    head_veh_valid= bool(flags & 0x20)
    carr_soln     = (flags >> 6) & 0x03

    fix_names = {0:'no_fix',1:'dead_reck',2:'2D',3:'3D',
                 4:'gnss_dead_reck',5:'time_only'}

    return {
        "type":         "NAV-PVT",
        "wall_ns":      wall_ns,
        "wall_iso":     clock.format_wall_ns(wall_ns),
        "mono_ns":      mono_ns,
        "iTOW":         iTOW,
        "year":         year, "month": month, "day": day,
        "hour":         hour, "minute": minute, "second": second,
        "fixType":      fixType,
        "fix_name":     fix_names.get(fixType, "unknown"),
        "gps_fix_ok":   gps_fix_ok,
        "diff_soln":    diff_soln,
        "carr_soln":    carr_soln,
        "numSV":        _ci(numSV, 0, _OOB["MAX_SAT"]),
        "lat":          lat,
        "lon":          lon,
        "alt_m":        alt,
        "h_acc_m":      hacc,
        "v_acc_m":      vacc,
        "vel_n_mm":     velN,
        "vel_e_mm":     velE,
        "vel_d_mm":     velD,
        "g_speed_mm":   gSpeed,
        "p_dop":        _cf(pDOP * 0.01, 0, 99.99),
        "t_acc_ns":     tAcc,
        "nano":         nano,
        "valid_date":   bool(valid & 0x01),
        "valid_time":   bool(valid & 0x02),
        "fully_resolved": bool(valid & 0x04),
        "valid_mag":    bool(valid & 0x08),
    }


def decode_nav_status(payload, clock, wall_ns, mono_ns):
    if len(payload) < 16: return None
    iTOW, gpsFix, flags, fixStat, flags2, ttff, msss = \
        struct.unpack_from('<IBBBBll', payload, 0)

    gps_fix_ok   = bool(flags & 0x01)
    diff_soln    = bool(flags & 0x02)
    wkn_set      = bool(flags & 0x04)
    tow_set      = bool(flags & 0x08)
    spoof_raw    = (flags2 >> 3) & 0x03

    return {
        "type":          "NAV-STATUS",
        "wall_ns":       wall_ns,
        "wall_iso":      clock.format_wall_ns(wall_ns),
        "mono_ns":       mono_ns,
        "iTOW":          iTOW,
        "gpsFix":        gpsFix,
        "gps_fix_ok":    gps_fix_ok,
        "diff_soln":     diff_soln,
        "wkn_set":       wkn_set,
        "tow_set":       tow_set,
        "spoof_raw":     spoof_raw,
        "spoof_state":   SPOOF_STATES.get(spoof_raw, "unknown"),
        "spoofing":      spoof_raw >= 2,
        "ttff_ms":       ttff,
        "msss":          msss,
    }


def decode_nav_sat(payload, clock, wall_ns, mono_ns):
    if len(payload) < 8: return None
    iTOW, version, numSvs = struct.unpack_from('<IBB', payload, 0)
    numSvs = _ci(numSvs, 0, _OOB["MAX_SAT"])
    sats = []
    offset = 8
    for _ in range(numSvs):
        if offset + 12 > len(payload): break
        gnssId, svId, cno, elev, azim_raw, prRes_raw, flags_sv = \
            struct.unpack_from('<BBBbhhi', payload, offset)
        offset += 12
        quality  = flags_sv & 0x07
        sv_used  = bool(flags_sv & 0x08)
        health   = (flags_sv >> 4) & 0x03
        diffCorr = bool(flags_sv & 0x40)
        smoothed = bool(flags_sv & 0x80)
        orb_src  = (flags_sv >> 8) & 0x07
        eph_avail= bool(flags_sv & 0x0800)
        alm_avail= bool(flags_sv & 0x1000)
        ano_avail= bool(flags_sv & 0x2000)
        sats.append({
            "gnssId":    gnssId,
            "gnss_name": GNSS_ID_NAMES.get(gnssId, f"GNSS{gnssId}"),
            "svId":      svId,
            "cno":       _ci(cno,  0, _OOB["MAX_CNR"]),
            "elev_deg":  _ci(elev, -90, 90),
            "azim_deg":  _ci(azim_raw, 0, 360),
            "pr_res_m":  _cf(prRes_raw * 0.1, -9999, 9999),
            "quality":   quality,
            "sv_used":   sv_used,
            "health":    health,
            "eph_avail": eph_avail,
        })
    return {
        "type":    "NAV-SAT",
        "wall_ns": wall_ns,
        "wall_iso":clock.format_wall_ns(wall_ns),
        "mono_ns": mono_ns,
        "iTOW":    iTOW,
        "numSvs":  numSvs,
        "sats":    sats,
    }


def decode_nav_clock(payload, clock, wall_ns, mono_ns):
    if len(payload) < 20: return None
    iTOW, clkB, clkD, tAcc, fAcc = struct.unpack_from('<Iiill', payload, 0)
    return {
        "type":      "NAV-CLOCK",
        "wall_ns":   wall_ns,
        "wall_iso":  clock.format_wall_ns(wall_ns),
        "mono_ns":   mono_ns,
        "iTOW":      iTOW,
        "clk_bias_ns":  clkB,
        "clk_drift_ns": clkD,
        "t_acc_ns":     tAcc,
        "f_acc_ps":     fAcc,
    }


def decode_mon_hw(payload, clock, wall_ns, mono_ns):
    if len(payload) < 60: return None
    (pinSel, pinBank, pinDir, pinVal, noisePerMS, agcCnt,
     aStatus, aPower, flags_hw, _, usedMask, VP,
     jamInd, _, pinIrq, pullH, pullL) = struct.unpack_from(
        '<IIIIHHBBBBIb17sBIII', payload, 0)
    return {
        "type":       "MON-HW",
        "wall_ns":    wall_ns,
        "wall_iso":   clock.format_wall_ns(wall_ns),
        "mono_ns":    mono_ns,
        "noise_per_ms": noisePerMS,
        "agc_cnt":    agcCnt,
        "jam_ind":    _ci(jamInd, 0, 255),
        "jam_state":  (flags_hw >> 2) & 0x03,
        "ant_status": aStatus,
        "ant_power":  aPower,
    }


def decode_rxm_raw(payload, clock, wall_ns, mono_ns):
    if len(payload) < 8: return None
    rcvTow, week, leapS, numMeas, recStat = \
        struct.unpack_from('<dHbBB', payload, 0)
    meas = []
    offset = 16
    for _ in range(min(numMeas, _OOB["MAX_SAT"])):
        if offset + 32 > len(payload): break
        prMes, cpMes, doMes, gnssId, svId, _, freqId, locktime, cno, \
        prStdev, cpStdev, doStdev, trkStat, _ = \
            struct.unpack_from('<ddfBBBBHBBBBBB', payload, offset)
        offset += 32
        meas.append({
            "gnssId":   gnssId,
            "gnss_name":GNSS_ID_NAMES.get(gnssId, f"GNSS{gnssId}"),
            "svId":     svId,
            "pr_m":     round(prMes, 4) if abs(prMes) < 1e12 else None,
            "cp_cycles":round(cpMes, 6) if abs(cpMes) < 1e12 else None,
            "doppler_hz":round(doMes, 4),
            "cno":      _ci(cno, 0, _OOB["MAX_CNR"]),
            "locktime_ms": locktime,
            "trkStat":  trkStat,
        })
    return {
        "type":     "RXM-RAW",
        "wall_ns":  wall_ns,
        "wall_iso": clock.format_wall_ns(wall_ns),
        "mono_ns":  mono_ns,
        "rcv_tow":  round(rcvTow, 9),
        "week":     week,
        "leap_s":   leapS,
        "num_meas": len(meas),
        "measurements": meas,
    }


DECODERS = {
    (0x01, 0x07): decode_nav_pvt,
    (0x01, 0x03): decode_nav_status,
    (0x01, 0x35): decode_nav_sat,
    (0x01, 0x22): decode_nav_clock,
    (0x0A, 0x09): decode_mon_hw,
    (0x02, 0x10): decode_rxm_raw,
}

# ── File tailer ────────────────────────────────────────────────────────────

def find_latest_ubx(directory):
    pattern = os.path.join(directory, "*.ubx")
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def tail_ubx(ubx_path, clock, gz_log, live_mirror, stop_event):
    framer   = UBXFramer()
    offset   = 0
    seq      = 0

    print(f"[UBX] Tailing: {ubx_path}")

    while not stop_event.is_set():
        try:
            with open(ubx_path, 'rb') as f:
                f.seek(offset)
                chunk = f.read(65536)
                if chunk:
                    offset += len(chunk)
                    for cls_id, msg_id, payload in framer.feed(chunk):
                        wall_ns, mono_ns = clock.now()
                        decoder = DECODERS.get((cls_id, msg_id))
                        if decoder:
                            rec = decoder(payload, clock, wall_ns, mono_ns)
                            if rec:
                                seq += 1
                                rec["seq"] = seq
                                gz_log.write(rec)
                                live_mirror.write(rec)
        except Exception as e:
            print(f"[UBX] tail error: {e}")

        time.sleep(POLL_INTERVAL_S)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="CTW UBX Binary Forensic Parser")
    ap.add_argument("--ubx-dir", default=UBX_DIR,
                    help=f"Directory containing .ubx files (default: {UBX_DIR})")
    ap.add_argument("--ubx-file", default=None,
                    help="Exact .ubx file path (overrides --ubx-dir)")
    ap.add_argument("--out", default=None,
                    help="Output directory for .jsonl.gz (default: ubx-dir)")
    args = ap.parse_args()

    ubx_dir = args.ubx_dir
    out_dir = args.out or ubx_dir
    os.makedirs(out_dir,     exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    ubx_path = args.ubx_file or find_latest_ubx(ubx_dir)
    if not ubx_path:
        print(f"[ERR] No .ubx files found in {ubx_dir}")
        print("      Start ublox_data.py first, then run this parser.")
        sys.exit(1)

    print(f"\n{'='*62}")
    print(f"  CTW UBX FORENSIC PARSER")
    print(f"{'='*62}")
    print(f"  UBX source    : {ubx_path}")
    print(f"  Output dir    : {out_dir}")
    print(f"  Runtime dir   : {RUNTIME_DIR}")
    print(f"{'='*62}\n")

    clock = ClockAnchor()

    from ntp_web import get_ntp_info
    print("Querying web time reference...")
    ntp_info = get_ntp_info()
    print(f"  Source  : {ntp_info['ntp_source']}")
    print(f"  Offset  : {ntp_info.get('ntp_offset_ms','?')} ms")

    header = {
        "type":              "gnss_session_header",
        "session_wall_utc":  clock.session_wall_utc,
        "session_wall_ns":   clock.session_wall_ns,
        "session_mono_ns":   clock.session_mono_ns,
        "ntp_source":        ntp_info["ntp_source"],
        "ntp_offset_s":      ntp_info["ntp_offset_s"],
        "ntp_offset_ms":     ntp_info.get("ntp_offset_ms"),
        "ubx_source":        ubx_path,
        "stamp":             STAMP,
    }

    gz_path      = os.path.join(out_dir, f"gnss_{STAMP}.jsonl.gz")
    live_path    = os.path.join(RUNTIME_DIR, "gnss_live.jsonl")

    gz_log       = GzipLog(gz_path, header)
    live_mirror  = LiveMirror(live_path)

    live_mirror.write(header)

    stop_event = threading.Event()

    try:
        tail_ubx(ubx_path, clock, gz_log, live_mirror, stop_event)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        wall_ns, mono_ns = clock.now()
        end = {
            "type":     "session_end",
            "wall_ns":  wall_ns,
            "wall_iso": clock.format_wall_ns(wall_ns),
            "mono_ns":  mono_ns,
        }
        gz_log.write(end)
        live_mirror.write(end)
        gz_log.close()
        print(f"\nSession complete. Log: {gz_path}")


if __name__ == "__main__":
    main()
