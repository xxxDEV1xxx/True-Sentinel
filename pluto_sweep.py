#!/usr/bin/env python3
"""
pluto_sweep.py  —  PlutoSDR IIO Forensic Sweep Logger  v2
==========================================================
STREAM A — IIO frequency sweep (iio_attr)  → sweep_STAMP.jsonl.gz
STREAM B — IIO raw IQ power (iio_readdev)  → iq_STAMP.jsonl.gz

Usage:
  python pluto_sweep.py
  python pluto_sweep.py --start 70000000 --stop 6000000000 --step 1000000
  python pluto_sweep.py --freqs 386000000 386020000
  python pluto_sweep.py --dwell-ms 0 --settle-ms 0 --out C:\\sdr\\logs
"""

import argparse
import datetime
import gzip
import json
import math
import os
import re
import struct
import subprocess
import sys
import threading
import time
from collections import deque
import iio

import numpy as np
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
# At the top of pluto_sweep.py and fs5000_dual.py

# ── constants ──────────────────────────────────────────────────────────────
DEFAULT_URI           = "ip:192.168.2.1"
DEFAULT_START_HZ      = 70_000_000
DEFAULT_STOP_HZ       = 6_000_000_000
DEFAULT_STEP_HZ       = 1_000_000
DEFAULT_DWELL_MS      = 0
DEFAULT_SETTLE_MS     = 0
DEFAULT_ANOMALY_ATTEN = 40.0
IQ_BUFFER_FRAMES      = 4096
IQ_SAMPLE_BYTES       = 4
RX_GAIN_BASELINE      = -3.0
RX_CROSSOVER_HZ       = 2_400_000_000

_current_rx_port = None
STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

_CONFIRM_RE  = re.compile(rb"value\s+'(\d+)'")
_FLOAT_DB_RE = re.compile(rb"value\s+'([+-]?[\d.]+)\s*dB'")
_FLOAT_RE    = re.compile(rb"value\s+'([+-]?[\d.]+)")

# ── IIO subprocess wrapper ─────────────────────────────────────────────────
def iio_run(args_list, timeout_s=3.0):
    try:
        r = subprocess.run(args_list, capture_output=True, timeout=timeout_s)
        raw   = r.stdout + r.stderr
        lines = [l for l in raw.split(b'\n') if b'Unknown parameter' not in l]
        return b'\n'.join(lines), r.returncode
    except subprocess.TimeoutExpired:
        return b'ERROR:timeout', -1
    except FileNotFoundError:
        return b'ERROR:iio_attr_not_found', -2
    except Exception as e:
        return f'ERROR:{e}'.encode(), -3

# ── RX port switch ─────────────────────────────────────────────────────────
def switch_rx_port(uri: str, freq_hz: int):
    global _current_rx_port
    target = "voltage0" if freq_hz < RX_CROSSOVER_HZ else "voltage1"
    if target == _current_rx_port:
        return
    print(f"\n[RX SWITCH] {freq_hz/1e6:.1f} MHz → {target}", flush=True)
    iio_run([
        "iio_attr", "-u", uri, "-i",
        "-c", "ad9361-phy", target, "hardwaregain", "50"
    ])
    inactive = "voltage1" if target == "voltage0" else "voltage0"
    iio_run([
        "iio_attr", "-u", uri, "-i",
        "-c", "ad9361-phy", inactive, "hardwaregain", "-3"
    ])
    _current_rx_port = target

# ── IIO attribute readers ──────────────────────────────────────────────────
def iio_set_freq(uri, freq_hz, timeout_s=3.0):
    out, rc = iio_run([
        "iio_attr", "-u", uri,
        "-c", "ad9361-phy", "altvoltage0", "frequency",
        str(int(freq_hz))
    ], timeout_s=timeout_s)
    matches = _CONFIRM_RE.findall(out)
    if matches:
        return int(matches[-1])
    return None

def iio_read_rssi_atten(uri, timeout_s=2.0):
    out, rc = iio_run([
        "iio_attr", "-u", uri, "-i",
        "-c", "ad9361-phy", "voltage0", "rssi"
    ], timeout_s=timeout_s)
    m = _FLOAT_DB_RE.search(out)
    return float(m.group(1)) if m else None

def iio_read_hardwaregain(uri, timeout_s=2.0):
    out, rc = iio_run([
        "iio_attr", "-u", uri, "-i",
        "-c", "ad9361-phy", "voltage0", "hardwaregain"
    ], timeout_s=timeout_s)
    m = _FLOAT_DB_RE.search(out)
    return float(m.group(1)) if m else None

def iio_read_temp(uri, timeout_s=2.0):
    out, rc = iio_run([
        "iio_attr", "-u", uri, "-i",
        "-c", "ad9361-phy", "temp0", "input"
    ], timeout_s=timeout_s)
    m = _FLOAT_RE.search(out)
    if m:
        try:
            return float(m.group(1)) / 1000.0
        except ValueError:
            return None
    return None

def probe_pluto(uri):
    info = {"uri": uri, "firmware": None, "model": None,
            "serial": None, "kernel": None}
    out, rc = iio_run(["iio_attr", "-u", uri, "-C"])
    for line in out.decode(errors='replace').splitlines():
        ll = line.lower().strip()
        if ll.startswith('fw_version:'):
            info["firmware"] = line.split(':', 1)[-1].strip()
        elif ll.startswith('hw_model:'):
            info["model"] = line.split(':', 1)[-1].strip()
        elif ll.startswith('hw_serial:'):
            info["serial"] = line.split(':', 1)[-1].strip()
        elif ll.startswith('local,kernel:'):
            info["kernel"] = line.split(':', 1)[-1].strip()
    return info

def configure_pluto_rx(uri):
    print("[+] Configuring Pluto RX frontend")
    ctx = iio.Context(uri)
    phy = ctx.find_device("ad9361-phy")
    if phy is None:
        raise RuntimeError("ad9361-phy not found")
    rx = phy.find_channel("voltage0", False)
    if rx is None:
        raise RuntimeError("RX channel voltage0 missing")
    for attr, val in [
        ("gain_control_mode",  "manual"),
        ("hardwaregain",       "50"),
        ("rf_bandwidth",       "10000000"),
        ("sampling_frequency", "20000000"),
    ]:
        try:
            rx.attrs[attr].value = val
            print(f"    {attr} = {val}")
        except Exception as e:
            print(f"    {attr} warning: {e}")
    for attr in ("rf_dc_offset_tracking_en",
                 "bb_dc_offset_tracking_en",
                 "quadrature_tracking_en"):
        try:
            rx.attrs[attr].value = "1"
        except Exception:
            pass
    print("[+] Pluto RX configuration complete")

def check_iio_readdev():
    out, rc = iio_run(["iio_readdev", "--help"], timeout_s=3.0)
    return rc != -2

from ntp_web import get_ntp_info, print_web_time_banner

def print_ntp_banner(ntp_info: dict):
    """Wrapper — delegates to ntp_web, ASCII-safe for Windows cp1252."""
    print("\n" + "="*68)
    print("  CTW WEB TIME REFERENCE")
    print("="*68)
    print(f"  Source          : {ntp_info.get('ntp_source','?')}")
    print(f"  Web UTC         : {ntp_info.get('ntp_last_sync_utc','?')}")
    print(f"  System UTC      : {ntp_info.get('ntp_utc_at_query','?')}")
    offset_s = ntp_info.get('ntp_offset_s')
    if offset_s is not None:
        sign = '+' if offset_s >= 0 else ''
        print(f"  System offset   : {sign}{offset_s:.6f} s  ({sign}{offset_s*1000:.3f} ms)")
        direction = 'AHEAD' if offset_s > 0 else 'BEHIND'
        print(f"  Offset note     : system clock is {direction} web reference by {abs(offset_s*1000):.1f} ms")
    else:
        print("  System offset   : unknown")
    err = ntp_info.get('ntp_error')
    if err:
        print(f"  ERROR           : {err}")
    print("="*68 + "\n")

class ClockAnchor:
    def __init__(self):
        best_gap = None
        for _ in range(32):
            t1  = time.perf_counter_ns()
            w   = time.time_ns()
            t2  = time.perf_counter_ns()
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
        whole_s = self._wall_epoch // 1_000_000_000
        self.session_wall_ns_remainder = (
            self._wall_epoch - whole_s * 1_000_000_000
        )

    def now(self):
        mono_now = time.perf_counter_ns()
        delta    = mono_now - self._mono_epoch
        return self._wall_epoch + delta, delta

    def format_wall_ns(self, wall_ns):
        whole_s = wall_ns // 1_000_000_000
        frac_ns = wall_ns  % 1_000_000_000
        base    = datetime.datetime.fromtimestamp(
            whole_s, tz=datetime.timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%S')
        return f"{base}.{frac_ns:09d}Z"

# ── GzipLog ────────────────────────────────────────────────────────────────
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
        if not self._q:
            return
        lines = []
        while self._q:
            lines.append(json.dumps(self._q.popleft(), separators=(',', ':')))
        blob = ('\n'.join(lines) + '\n').encode()
        with gzip.open(self.path, 'ab', compresslevel=6) as gz:
            gz.write(blob)

# ── frequency list ─────────────────────────────────────────────────────────
def build_freq_list(args):
    if args.freqs:
        return [int(float(f)) for f in args.freqs]
    start = int(float(args.start))
    stop  = int(float(args.stop))
    step  = int(float(args.step))
    freqs = []
    f = start
    while f <= stop:
        freqs.append(f)
        f += step
    return freqs

# ── IQ analysis ────────────────────────────────────────────────────────────
def analyze_iq_sweep(samples):
    if samples is None or len(samples) < 2:
        return {"rms": None, "dbfs": None, "peak_dbfs": None, "crest_factor": None}
    i         = samples[0::2].astype(np.float64)
    q         = samples[1::2].astype(np.float64)
    power     = i * i + q * q
    rms       = math.sqrt(math.sqrt(float(np.mean(power))))
    dbfs      = 20 * math.log10(rms / 32768) if rms > 0 else -999.0
    magnitude = np.sqrt(power)
    peak      = float(np.max(magnitude))
    peak_dbfs = 20 * math.log10(peak / 32768) if peak > 0 else -999.0
    crest     = peak / rms if rms > 0 else 0.0
    return {
        "rms":          round(rms, 4),
        "dbfs":         round(dbfs, 4),
        "peak_dbfs":    round(peak_dbfs, 4),
        "crest_factor": round(crest, 4),
    }

# ── background IQ sampler for sweep console metrics ────────────────────────
class SweepIQSampler:
    _null = {"rms": None, "dbfs": None, "peak_dbfs": None, "crest_factor": None}

    def __init__(self, uri):
        self._uri    = uri
        self._latest = dict(self._null)
        self._lock   = threading.Lock()
        self._stop   = threading.Event()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name='SweepIQ'
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=3)

    def latest(self):
        with self._lock:
            return dict(self._latest)

    def _run(self):
        try:
            ctx   = iio.Context(self._uri)
            rxdev = ctx.find_device("cf-ad9361-lpc")
            if rxdev is None:
                return
            for ch in rxdev.channels:
                ch.enabled = ch.id in ("voltage0", "voltage1")
            buf = iio.Buffer(rxdev, 4096, False)
            while not self._stop.is_set():
                try:
                    buf.refill()
                    raw     = np.frombuffer(buf.read(), dtype=np.int16)
                    metrics = analyze_iq_sweep(raw.copy())
                    with self._lock:
                        self._latest = metrics
                except Exception:
                    pass
        except Exception:
            pass

# ── Stream A: sweep ────────────────────────────────────────────────────────
def run_sweep(uri, freq_list, dwell_ms, settle_ms, anomaly_atten,
              clock, log, quiet, stop_event, iq_count_fn, sweep_iq):

    dwell_s       = dwell_ms  / 1000.0
    settle_s      = settle_ms / 1000.0
    remain_s      = max(0.0, dwell_s - settle_s)
    seq           = 0
    sweep_num     = 0
    anomalies     = 0
    errors        = 0
    consec_errors = 0
    MAX_CONSEC_ERRORS = 10

    while not stop_event.is_set():
        sweep_num += 1
        temp_c     = iio_read_temp(uri)

        for idx, freq_hz in enumerate(freq_list):
            if stop_event.is_set():
                break

            set_wall_ns, set_mono_ns = clock.now()
            confirmed_hz = iio_set_freq(uri, freq_hz, timeout_s=5.0)

            if confirmed_hz is None:
                errors        += 1
                consec_errors += 1
                log.write({
                    "type":     "set_error",
                    "seq":      seq,
                    "wall_ns":  set_wall_ns,
                    "wall_iso": clock.format_wall_ns(set_wall_ns),
                    "mono_ns":  set_mono_ns,
                    "freq_hz":  freq_hz,
                    "error":    "iio_attr returned no confirmation",
                })
                if consec_errors >= MAX_CONSEC_ERRORS:
                    log.write({
                        "type":    "sweep_abort",
                        "reason":  f"{MAX_CONSEC_ERRORS} consecutive set errors",
                        "freq_hz": freq_hz,
                    })
                    stop_event.set()
                    break
                time.sleep(0.5)
                continue

            consec_errors = 0
            switch_rx_port(uri, freq_hz)

            if settle_s > 0:
                time.sleep(settle_s)

            rssi_atten      = iio_read_rssi_atten(uri)
            hardwaregain_db = iio_read_hardwaregain(uri)
            iq              = sweep_iq.latest()

            if remain_s > 0:
                time.sleep(remain_s)

            meas_wall_ns, meas_mono_ns = clock.now()
            seq += 1

            is_anomaly = (
                rssi_atten is not None
                and rssi_atten < anomaly_atten
            )
            if is_anomaly:
                anomalies += 1

            agc_delta = (
                round(RX_GAIN_BASELINE - hardwaregain_db, 3)
                if hardwaregain_db is not None else None
            )

            record = {
                "rx_port":         "RX"  if freq_hz < RX_CROSSOVER_HZ else "RX2",
                "seq":             seq,
                "sweep":           sweep_num,
                "freq_idx":        idx,
                "wall_ns":         meas_wall_ns,
                "wall_iso":        clock.format_wall_ns(meas_wall_ns),
                "mono_ns":         meas_mono_ns,
                "freq_hz":         freq_hz,
                "confirmed_hz":    confirmed_hz,
                "freq_match":      confirmed_hz == freq_hz,
                "rssi_atten_db":   rssi_atten,
                "hardwaregain_db": hardwaregain_db,
                "agc_delta_db":    agc_delta,
                "temp_c":          temp_c,
                "anomaly":         is_anomaly,
                "iq_frames":       iq_count_fn(),
                "rms":             iq["rms"],
                "dbfs":            iq["dbfs"],
                "peak_dbfs":       iq["peak_dbfs"],
                "crest_factor":    iq["crest_factor"],
            }
            log.write(record)

            if not quiet:
                rssi_str = f"{rssi_atten:6.2f}" if rssi_atten is not None else "  N/A"
                rms_str  = f"{iq['rms']:.2f}"          if iq["rms"]          is not None else "N/A"
                dbfs_str = f"{iq['dbfs']:.2f}"         if iq["dbfs"]         is not None else "N/A"
                peak_str = f"{iq['peak_dbfs']:.2f}"    if iq["peak_dbfs"]    is not None else "N/A"
                cf_str   = f"{iq['crest_factor']:.2f}" if iq["crest_factor"] is not None else "N/A"
                freq_mhz  = freq_hz / 1e6
                flag      = "*** ANOMALY ***" if is_anomaly else ""
                match_str = "" if confirmed_hz == freq_hz else f" FREQ_LAG:{confirmed_hz/1e6:.3f}"

                if rssi_atten is not None:
                    bar_len = max(0, min(30, int((127.0 - rssi_atten) / 127.0 * 30)))
                else:
                    bar_len = 0
                bar = chr(0x2588) * bar_len

                meas_wall_str = clock.format_wall_ns(meas_wall_ns)
                ts = meas_wall_str[11:32]
                print(
                    f"\r  {ts}  {freq_mhz:10.3f} MHz"
                    f"  ATTEN={rssi_str} dB"
                    f"  RMS={rms_str}"
                    f"  dBFS={dbfs_str}"
                    f"  PEAK={peak_str}"
                    f"  CF={cf_str}"
                    f"  IQ={iq_count_fn():>9}"
                    f"  A={anomalies:>4}"
                    f"  {bar:<30}"
                    f"  {flag}{match_str}   ",
                    end='', flush=True
                )

        if not stop_event.is_set():
            sw_wall, sw_mono = clock.now()
            log.write({
                "type":      "sweep_pass_end",
                "sweep":     sweep_num,
                "wall_ns":   sw_wall,
                "wall_iso":  clock.format_wall_ns(sw_wall),
                "mono_ns":   sw_mono,
                "records":   seq,
                "anomalies": anomalies,
                "errors":    errors,
                "temp_c":    temp_c,
            })

    end_wall, end_mono = clock.now()
    log.write({
        "type":      "sweep_summary",
        "wall_ns":   end_wall,
        "wall_iso":  clock.format_wall_ns(end_wall),
        "mono_ns":   end_mono,
        "sweeps":    sweep_num,
        "records":   seq,
        "anomalies": anomalies,
        "errors":    errors,
        "elapsed_s": round(end_mono / 1e9, 3),
    })

# ── Stream B: IQ sampler ───────────────────────────────────────────────────
class IQSampler:
    def __init__(self, uri, clock, log, buffer_frames=IQ_BUFFER_FRAMES):
        self.uri           = uri
        self.clock         = clock
        self.log           = log
        self.buffer_frames = buffer_frames
        self._frame_count  = 0
        self._lock         = threading.Lock()
        self._stop         = threading.Event()
        self._proc         = None
        self._thread       = threading.Thread(
            target=self._run, daemon=True, name='IQSampler'
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        self._thread.join(timeout=5)

    @property
    def frame_count(self):
        with self._lock:
            return self._frame_count

    def _run(self):
        cmd = [
            "iio_readdev", "-u", self.uri,
            "-b", str(self.buffer_frames),
            "cf-ad9361-lpc", "voltage0", "voltage1"
        ]
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            self.log.write({
                "type":   "iq_stream_unavailable",
                "reason": "iio_readdev not found on PATH",
            })
            return
        except Exception as e:
            self.log.write({"type": "iq_stream_error", "reason": str(e)})
            return

        bytes_per_frame  = IQ_SAMPLE_BYTES
        bytes_per_buffer = self.buffer_frames * bytes_per_frame
        seq              = 0

        while not self._stop.is_set():
            raw = self._proc.stdout.read(bytes_per_buffer)
            if not raw:
                break
            if len(raw) < bytes_per_frame:
                continue
            n_samples  = len(raw) // bytes_per_frame
            iq         = struct.unpack_from(f'{n_samples * 2}h', raw, 0)
            rms        = (sum(v * v for v in iq) / len(iq)) ** 0.5
            power_dbfs = 20 * math.log10(rms / 32767.0) if rms > 0 else -999.0

            wall_ns, mono_ns = self.clock.now()
            seq += 1

            with self._lock:
                self._frame_count += n_samples

            self.log.write({
                "seq":        seq,
                "wall_ns":    wall_ns,
                "wall_iso":   self.clock.format_wall_ns(wall_ns),
                "mono_ns":    mono_ns,
                "n_samples":  n_samples,
                "rms":        round(rms, 3),
                "power_dbfs": round(power_dbfs, 3),
            })

# ── main ───────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="PlutoSDR IIO Forensic Sweep Logger v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('--uri',           default=DEFAULT_URI)
    ap.add_argument('--start',         default=str(DEFAULT_START_HZ), metavar='HZ')
    ap.add_argument('--stop',          default=str(DEFAULT_STOP_HZ),  metavar='HZ')
    ap.add_argument('--step',          default=str(DEFAULT_STEP_HZ),  metavar='HZ')
    ap.add_argument('--freqs',         nargs='+', metavar='HZ',
                    help='Explicit frequency list (overrides --start/stop/step)')
    ap.add_argument('--dwell-ms',      type=int,   default=DEFAULT_DWELL_MS,  metavar='MS')
    ap.add_argument('--settle-ms',     type=int,   default=DEFAULT_SETTLE_MS, metavar='MS')
    ap.add_argument('--anomaly-atten', type=float, default=DEFAULT_ANOMALY_ATTEN, metavar='DB')
    ap.add_argument('--out',           default='.', metavar='DIR')
    ap.add_argument('--quiet',         action='store_true')
    ap.add_argument('--no-iq',         action='store_true')
    args = ap.parse_args()

    if args.settle_ms >= args.dwell_ms and args.dwell_ms > 0:
        args.settle_ms = args.dwell_ms // 2

    print("Querying NTP status...", flush=True)
    ntp_info = get_ntp_info()
    print_ntp_banner(ntp_info)

    clock = ClockAnchor()

    print(f"Probing PlutoSDR at {args.uri}...", end=' ', flush=True)
    pluto_info = probe_pluto(args.uri)
    configure_pluto_rx(args.uri)
    if not pluto_info['firmware']:
        print("\nERROR: Could not reach PlutoSDR.")
        sys.exit(1)
    print(f"done.  FW: {pluto_info['firmware']}  SN: {pluto_info['serial']}")

    iq_available = False if args.no_iq else check_iio_readdev()
    if not iq_available:
        print("[INFO] iio_readdev not found — Stream B disabled.")

    freq_list = build_freq_list(args)
    n_freqs   = len(freq_list)

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    forensic_header = {
        "type":                      "forensic_session_header",
        "ntp_source":                ntp_info["ntp_source"],
        "ntp_last_sync":             ntp_info["ntp_last_sync_utc"],
        "ntp_offset_s":              ntp_info["ntp_offset_s"],
        "session_wall_utc":          clock.session_wall_utc,
        "session_wall_ns":           clock.session_wall_ns,
        "session_wall_ns_remainder": clock.session_wall_ns_remainder,
        "session_mono_epoch_ns":     clock.session_mono_ns,
        "instrument":                "ADALM-PLUTO (PlutoSDR)",
        "pluto_uri":                 args.uri,
        "pluto_firmware":            pluto_info["firmware"],
        "pluto_model":               pluto_info["model"],
        "pluto_serial":              pluto_info["serial"],
        "sweep_start_hz":            freq_list[0],
        "sweep_stop_hz":             freq_list[-1],
        "sweep_step_hz":             int(float(args.step)) if not args.freqs else None,
        "sweep_n_freqs":             n_freqs,
        "dwell_ms":                  args.dwell_ms,
        "settle_ms":                 args.settle_ms,
        "anomaly_atten_threshold":   args.anomaly_atten,
        "anomaly_condition":         "rssi_atten_db < anomaly_atten_threshold",
        "iq_stream_available":       iq_available,
        "sweep_log":                 f"sweep_{STAMP}.jsonl.gz",
        "iq_log":                    f"iq_{STAMP}.jsonl.gz",
        "session_file":              f"session_{STAMP}.json",
    }

    session_path   = os.path.join(out_dir, f"session_{STAMP}.json")
    sweep_log_path = os.path.join(out_dir, f"sweep_{STAMP}.jsonl.gz")
    iq_log_path    = os.path.join(out_dir, f"iq_{STAMP}.jsonl.gz")

    with open(session_path, 'w') as f:
        json.dump(forensic_header, f, indent=2)

    sweep_log = GzipLog(sweep_log_path, forensic_header)
    iq_log    = GzipLog(iq_log_path,    forensic_header)

    if iq_available:
        iq_sampler = IQSampler(args.uri, clock, iq_log, IQ_BUFFER_FRAMES)
        iq_sampler.start()
    else:
        iq_sampler = None

    sweep_period_s = n_freqs * max(args.dwell_ms, 1) / 1000.0

    print(f"\n{'='*68}")
    print(f"  PLUTOSDR FORENSIC SWEEP LOGGER  v2")
    print(f"{'='*68}")
    print(f"  Session start   : {clock.session_wall_utc}")
    print(f"  Pluto URI       : {args.uri}")
    print(f"  Firmware        : {pluto_info['firmware']}")
    print(f"  Sweep           : {freq_list[0]/1e6:.3f} – {freq_list[-1]/1e6:.3f} MHz")
    print(f"  Steps           : {n_freqs:,}")
    print(f"  Step size       : {int(float(args.step))/1e6:.3f} MHz")
    print(f"  Dwell           : {args.dwell_ms} ms")
    print(f"  Anomaly thresh  : rssi_atten_db < {args.anomaly_atten} dB")
    print(f"  IQ stream       : {'ENABLED' if iq_available else 'DISABLED'}")
    print(f"  Sweep log       : sweep_{STAMP}.jsonl.gz")
    print(f"  Out dir         : {out_dir}")
    print(f"{'─'*68}")
    print(f"  Ctrl+C to stop")
    print(f"{'='*68}\n")

    sweep_iq = SweepIQSampler(args.uri)
    sweep_iq.start()

    stop_event   = threading.Event()
    sweep_thread = threading.Thread(
        target = run_sweep,
        args   = (args.uri, freq_list, args.dwell_ms, args.settle_ms,
                  args.anomaly_atten, clock, sweep_log,
                  args.quiet, stop_event,
                  lambda: iq_sampler.frame_count if iq_sampler else 0,
                  sweep_iq),
        daemon = True,
        name   = 'SweepStream',
    )
    sweep_thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        sweep_iq.stop()

        if iq_sampler is not None:
            iq_sampler.stop()

        sweep_thread.join(timeout=10)

        wall_ns, mono_ns = clock.now()
        end_rec = {
            "type":      "session_end",
            "wall_ns":   wall_ns,
            "wall_iso":  clock.format_wall_ns(wall_ns),
            "mono_ns":   mono_ns,
            "iq_frames": iq_sampler.frame_count if iq_sampler else 0,
        }
        sweep_log.write(end_rec)
        iq_log.write(end_rec)
        sweep_log.close()
        iq_log.close()

        print(f"\n\nSession complete.")
        print(f"  Session start : {clock.session_wall_utc}")
        print(f"  Session end   : {clock.format_wall_ns(wall_ns)}")
        print(f"  Duration      : {mono_ns/1e9:.3f} s")
        print(f"  IQ frames     : {iq_sampler.frame_count if iq_sampler else 'N/A'}")
        print(f"  Sweep log     : {sweep_log_path}")
        print(f"  IQ log        : {iq_log_path}")
        print(f"  Session meta  : {session_path}")


if __name__ == '__main__':
    main()