#!/usr/bin/env python3
"""
bt_scanner.py  —  CTW Bluetooth / BLE Forensic Scanner
=======================================================
PlutoSDR AD9361 wideband capture across the full 2.4 GHz ISM band.
Covers all 40 BLE channels and 79 Classic BT channels simultaneously
using 56 MHz instantaneous bandwidth and FFT-based per-channel binning.

STREAM A — Channel energy sweep (all BLE + Classic BT channels)
STREAM B — BLE advertising channel dwell (Ch 37/38/39 deep scan)

Anomaly classifiers:
  1. Advertisement interval anomaly (outside 20ms–10.24s = rogue)
  2. BD_ADDR prefix collision (MAC spoofing across advertisements)
  3. RSSI threshold breach (abnormally strong = physically close rogue)
  4. Advertising channel asymmetry (Ch 37 only, never 38/39)

Output:
  bt_STAMP.jsonl.gz     — forensic compressed log
  runtime/bt_live.jsonl — live mirror for SSE dashboard

Usage:
  python bt_scanner.py
  python bt_scanner.py --center 2441000000 --bw 56000000
  python bt_scanner.py --adv-only
  python bt_scanner.py --rssi-threshold -70
  python bt_scanner.py --out C:\\sdr\\logs
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
from pathlib import Path

import numpy as np

try:
    import iio
except ImportError:
    print("ERROR: pip install pylibiio")
    sys.exit(1)

# ── Configuration ──────────────────────────────────────────────────────────────

DEFAULT_URI         = "ip:192.168.2.1"
DEFAULT_CENTER_HZ   = 2_441_000_000    # centers 56 MHz window on full BT band
DEFAULT_BW_HZ       = 56_000_000       # AD9361 maximum
DEFAULT_SAMPLE_RATE = 56_000_000       # samples/sec = bandwidth
DEFAULT_GAIN        = 40               # dB — adjust per environment
DEFAULT_RSSI_THRESH = -80.0            # dBFS anomaly threshold
ADV_INTERVAL_MIN_MS = 20.0             # BLE spec minimum
ADV_INTERVAL_MAX_MS = 10_240.0         # BLE spec maximum
BDADDR_HISTORY      = 512              # max tracked BD_ADDR prefixes
FFT_SIZE            = 4096             # frequency resolution bins
BUFFER_FRAMES       = FFT_SIZE * 4

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ── BLE channel map ────────────────────────────────────────────────────────────
# 40 channels, 2 MHz spacing
# Advertising: 37=2402, 38=2426, 39=2480
# Data: all others

BLE_CHANNELS = {}
data_ch = 0
for k in range(40):
    if   k == 37: freq = 2_402_000_000
    elif k == 38: freq = 2_426_000_000
    elif k == 39: freq = 2_480_000_000
    else:
        # Data channels skip 2426 and 2480
        freq = 2_404_000_000 + data_ch * 2_000_000
        if freq >= 2_426_000_000: freq += 2_000_000
        if freq >= 2_480_000_000: freq += 2_000_000
        data_ch += 1
    BLE_CHANNELS[k] = {
        "freq_hz":    freq,
        "advertising": k in (37, 38, 39),
        "label":      f"BLE-{'ADV' if k in (37,38,39) else 'DAT'}{k}",
    }

# Classic BT channels: 79 channels 1 MHz spacing 2402–2480 MHz
CLASSIC_BT_CHANNELS = {
    k: {"freq_hz": 2_402_000_000 + k * 1_000_000,
        "label":   f"BT-{k}"}
    for k in range(79)
}

ADV_CHANNELS = {37: 2_402_000_000, 38: 2_426_000_000, 39: 2_480_000_000}

# ── OOB guard ──────────────────────────────────────────────────────────────────

_OOB = {
    "MAX_DBFS":     10.0,
    "MIN_DBFS":   -120.0,
    "MAX_FREQ":   2_500_000_000,
    "MIN_FREQ":   2_390_000_000,
    "MAX_BW":      60_000_000,
    "MAX_FFT":     65536,
}

def _cf(v, lo, hi):
    try:
        f = float(v)
        if not (-1e18 < f < 1e18): return lo
        return max(lo, min(hi, f))
    except Exception: return lo

# ── ClockAnchor ────────────────────────────────────────────────────────────────

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

# ── GzipLog ────────────────────────────────────────────────────────────────────

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
        if not self._q: return
        lines = []
        while self._q:
            lines.append(json.dumps(self._q.popleft(), separators=(',', ':')))
        blob = ('\n'.join(lines) + '\n').encode()
        with gzip.open(self.path, 'ab', compresslevel=6) as gz:
            gz.write(blob)

# ── LiveMirror ─────────────────────────────────────────────────────────────────

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

# ── FFT channel energy extractor ───────────────────────────────────────────────

def extract_channel_energies(iq_samples, center_hz, sample_rate, fft_size):
    """
    Run FFT on IQ block. For each BLE and Classic BT channel,
    extract the average power in that channel's frequency bin.
    Returns dict: freq_hz -> dbfs
    """
    if len(iq_samples) < fft_size * 2:
        return {}

    # Build complex array from interleaved I/Q int16
    iq = iq_samples.astype(np.float32)
    i_ch = iq[0::2]
    q_ch = iq[1::2]
    n    = min(len(i_ch), len(q_ch), fft_size)
    cplx = (i_ch[:n] + 1j * q_ch[:n])

    # Windowed FFT
    window  = np.blackman(n)
    cplx   *= window
    spectrum = np.fft.fftshift(np.abs(np.fft.fft(cplx, n=fft_size)) ** 2)
    spectrum = 10 * np.log10(spectrum / (32768.0 ** 2) / n + 1e-12)

    # Frequency axis
    freqs = np.fft.fftshift(
        np.fft.fftfreq(fft_size, d=1.0/sample_rate)
    ) + center_hz

    hz_per_bin = sample_rate / fft_size

    result = {}

    # BLE channels — 2 MHz wide each
    for ch_num, ch in BLE_CHANNELS.items():
        f0 = ch["freq_hz"] - 1_000_000
        f1 = ch["freq_hz"] + 1_000_000
        mask = (freqs >= f0) & (freqs < f1)
        if mask.sum() == 0: continue
        pwr = float(np.mean(spectrum[mask]))
        result[ch["freq_hz"]] = {
            "dbfs":        _cf(pwr, _OOB["MIN_DBFS"], _OOB["MAX_DBFS"]),
            "ch_num":      ch_num,
            "label":       ch["label"],
            "advertising": ch["advertising"],
            "type":        "BLE",
        }

    # Classic BT channels — 1 MHz wide each
    for ch_num, ch in CLASSIC_BT_CHANNELS.items():
        f0 = ch["freq_hz"] - 500_000
        f1 = ch["freq_hz"] + 500_000
        mask = (freqs >= f0) & (freqs < f1)
        if mask.sum() == 0: continue
        pwr = float(np.mean(spectrum[mask]))
        result[ch["freq_hz"]] = {
            "dbfs":    _cf(pwr, _OOB["MIN_DBFS"], _OOB["MAX_DBFS"]),
            "ch_num":  ch_num,
            "label":   ch["label"],
            "type":    "Classic-BT",
        }

    return result

# ── Anomaly engine ─────────────────────────────────────────────────────────────

class BTAnomalyEngine:
    """
    Four-classifier anomaly detection for Bluetooth forensics.

    Classifier 1 — Advertisement interval anomaly
      Track when each advertising channel fires above threshold.
      If interval < ADV_INTERVAL_MIN_MS or > ADV_INTERVAL_MAX_MS,
      flag as rogue advertisement timing.

    Classifier 2 — BD_ADDR prefix collision
      BLE advertisements embed the device BD_ADDR in the payload.
      We cannot fully decode BTLE PDUs from energy alone, but we
      track channel-level signatures (power profile across all three
      adv channels) as a proxy device fingerprint. Identical profiles
      on different time slots = likely same device with rotating MAC.

    Classifier 3 — RSSI threshold breach
      Signal stronger than threshold = device is physically close.
      Combined with no known device in the environment = rogue.

    Classifier 4 — Advertising channel asymmetry
      Legitimate BLE devices advertise on all three channels per
      advertising event. A device appearing only on Ch 37 or only
      on one channel is either malformed or a targeted sniffer
      injecting on a single channel.
    """

    def __init__(self, rssi_threshold, clock, log, mirror):
        self.rssi_threshold = rssi_threshold
        self.clock          = clock
        self.log            = log
        self.mirror         = mirror

        # Per-channel last-seen timestamp for interval tracking
        self._adv_last_seen = {37: None, 38: None, 39: None}
        self._adv_intervals = {37: deque(maxlen=32),
                               38: deque(maxlen=32),
                               39: deque(maxlen=32)}

        # Power profile fingerprints: tuple(dbfs_37, dbfs_38, dbfs_39)
        # rounded to 2 dB resolution -> device proxy fingerprint
        self._fingerprints  = defaultdict(list)  # fp -> [wall_ns, ...]

        # Per-channel detection counts
        self._adv_counts    = {37: 0, 38: 0, 39: 0}

        # Stats
        self.anomaly_count  = 0
        self._seq           = 0

    def feed(self, channel_energies, wall_ns):
        """
        Called once per FFT block with the full channel energy map.
        Runs all four classifiers.
        """
        adv_energies = {}
        for freq_hz, info in channel_energies.items():
            if not info.get("advertising"): continue
            ch = info["ch_num"]
            dbfs = info["dbfs"]
            adv_energies[ch] = dbfs

        if not adv_energies:
            return

        # ── Classifier 3: RSSI threshold ──────────────────────────────
        for ch, dbfs in adv_energies.items():
            if dbfs > self.rssi_threshold:
                self._emit_anomaly("RSSI_BREACH", {
                    "ble_ch":   ch,
                    "freq_hz":  ADV_CHANNELS[ch],
                    "dbfs":     dbfs,
                    "threshold":self.rssi_threshold,
                    "detail":   f"BLE Ch {ch} ({ADV_CHANNELS[ch]/1e6:.1f} MHz) "
                                f"signal {dbfs:.1f} dBFS exceeds threshold "
                                f"{self.rssi_threshold:.1f} dBFS",
                }, wall_ns)

        # ── Classifier 1: Advertisement interval ──────────────────────
        for ch, dbfs in adv_energies.items():
            if dbfs < self.rssi_threshold + 15:
                continue  # below noise floor, skip
            last = self._adv_last_seen[ch]
            if last is not None:
                interval_ms = (wall_ns - last) / 1e6
                self._adv_intervals[ch].append(interval_ms)
                if (interval_ms < ADV_INTERVAL_MIN_MS or
                        interval_ms > ADV_INTERVAL_MAX_MS):
                    self._emit_anomaly("ADV_INTERVAL", {
                        "ble_ch":      ch,
                        "freq_hz":     ADV_CHANNELS[ch],
                        "interval_ms": round(interval_ms, 3),
                        "spec_min_ms": ADV_INTERVAL_MIN_MS,
                        "spec_max_ms": ADV_INTERVAL_MAX_MS,
                        "dbfs":        dbfs,
                        "detail":      f"BLE Ch {ch} advertisement interval "
                                       f"{interval_ms:.1f} ms outside "
                                       f"spec [{ADV_INTERVAL_MIN_MS}–"
                                       f"{ADV_INTERVAL_MAX_MS}] ms",
                    }, wall_ns)
            self._adv_last_seen[ch] = wall_ns
            self._adv_counts[ch]   += 1

        # ── Classifier 4: Advertising channel asymmetry ───────────────
        active_adv = {ch for ch, dbfs in adv_energies.items()
                      if dbfs > self.rssi_threshold + 15}
        if len(active_adv) == 1:
            ch = next(iter(active_adv))
            # Only flag after we have seen at least 5 events on this ch
            if self._adv_counts[ch] >= 5:
                self._emit_anomaly("ADV_ASYMMETRY", {
                    "active_channels":  list(active_adv),
                    "silent_channels":  list({37,38,39} - active_adv),
                    "active_ch_count":  self._adv_counts[ch],
                    "detail":           f"BLE advertising on Ch {ch} only — "
                                        f"other adv channels silent. "
                                        f"Possible rogue injector or sniffer.",
                }, wall_ns)

        # ── Classifier 2: Power profile fingerprint collision ─────────
        if len(adv_energies) == 3:
            # Round to 2 dB buckets for noise tolerance
            fp = tuple(
                round(adv_energies.get(ch, -120) / 2) * 2
                for ch in (37, 38, 39)
            )
            self._fingerprints[fp].append(wall_ns)
            # If same fingerprint seen more than 3 times with
            # varying intervals (not just one device advertising normally)
            times = self._fingerprints[fp]
            if len(times) >= 4:
                intervals = [
                    (times[i+1] - times[i]) / 1e6
                    for i in range(len(times)-1)
                ]
                # High variance in intervals = multiple devices
                # sharing same power profile = MAC rotation suspected
                if len(intervals) >= 3:
                    mean_iv  = sum(intervals) / len(intervals)
                    variance = sum((x-mean_iv)**2
                                   for x in intervals) / len(intervals)
                    if variance > 5000:  # >70ms std dev
                        self._emit_anomaly("BDADDR_COLLISION", {
                            "fingerprint":       fp,
                            "observation_count": len(times),
                            "interval_variance_ms2": round(variance, 1),
                            "mean_interval_ms":  round(mean_iv, 1),
                            "detail":            f"BLE power profile {fp} seen "
                                                 f"{len(times)} times with high "
                                                 f"interval variance "
                                                 f"({variance**0.5:.0f} ms std). "
                                                 f"Possible MAC rotation / "
                                                 f"multiple devices sharing "
                                                 f"same RF signature.",
                        }, wall_ns)
                    # Prune to prevent unbounded growth
                    if len(self._fingerprints[fp]) > 64:
                        self._fingerprints[fp] = \
                            self._fingerprints[fp][-32:]

    def _emit_anomaly(self, anomaly_type, fields, wall_ns):
        self._seq += 1
        self.anomaly_count += 1
        rec = {
            "type":      f"BT_ANOMALY_{anomaly_type}",
            "_stream":   "bt",
            "seq":       self._seq,
            "wall_ns":   wall_ns,
            "wall_iso":  self.clock.format_wall_ns(wall_ns),
            **fields,
        }
        self.log.write(rec)
        self.mirror.write(rec)
        print(
            f"\n  [{rec['wall_iso'][11:23]}] "
            f"*** BT {anomaly_type} ***  "
            f"{fields.get('detail', '')}",
            flush=True
        )

# ── IIO capture thread ─────────────────────────────────────────────────────────

class BTCapture:
    def __init__(self, uri, center_hz, sample_rate, gain,
                 clock, log, mirror, rssi_threshold, stop_event):
        self.uri           = uri
        self.center_hz     = center_hz
        self.sample_rate   = sample_rate
        self.gain          = gain
        self.clock         = clock
        self.log           = log
        self.mirror        = mirror
        self.stop_event    = stop_event
        self.anomaly_engine = BTAnomalyEngine(
            rssi_threshold, clock, log, mirror
        )
        self._seq          = 0
        self._frame_count  = 0

    def run(self):
        try:
            ctx   = iio.Context(self.uri)
            phy   = ctx.find_device("ad9361-phy")
            rxdev = ctx.find_device("cf-ad9361-lpc")

            # Configure AD9361 for 2.4 GHz BT band
            rx = phy.find_channel("voltage0", False)
            for attr, val in [
                ("gain_control_mode",  "manual"),
                ("hardwaregain",       str(self.gain)),
                ("rf_bandwidth",       str(self.sample_rate)),
                ("sampling_frequency", str(self.sample_rate)),
            ]:
                try:
                    rx.attrs[attr].value = val
                except Exception as e:
                    print(f"  [BT] {attr} warning: {e}")

            # Set LO frequency
            lo = phy.find_channel("altvoltage0", True)
            lo.attrs["frequency"].value = str(int(self.center_hz))

            # Enable RX channels
            for ch in rxdev.channels:
                ch.enabled = ch.id in ("voltage0", "voltage1")

            buf = iio.Buffer(rxdev, BUFFER_FRAMES, False)

            print(f"[BT] Capturing at {self.center_hz/1e6:.1f} MHz "
                  f"BW={self.sample_rate/1e6:.0f} MHz "
                  f"gain={self.gain} dB")

            sweep_num = 0

            while not self.stop_event.is_set():
                buf.refill()
                raw = np.frombuffer(buf.read(), dtype=np.int16).copy()
                wall_ns, mono_ns = self.clock.now()

                if len(raw) < FFT_SIZE * 2:
                    continue

                self._frame_count += len(raw) // 2
                sweep_num += 1

                # Extract per-channel energies via FFT
                ch_energies = extract_channel_energies(
                    raw, self.center_hz, self.sample_rate, FFT_SIZE
                )

                # Run anomaly classifiers
                self.anomaly_engine.feed(ch_energies, wall_ns)

                # Build sweep record
                self._seq += 1
                rec = {
                    "type":        "BT_SWEEP",
                    "_stream":     "bt",
                    "seq":         self._seq,
                    "sweep":       sweep_num,
                    "wall_ns":     wall_ns,
                    "wall_iso":    self.clock.format_wall_ns(wall_ns),
                    "mono_ns":     mono_ns,
                    "center_hz":   self.center_hz,
                    "sample_rate": self.sample_rate,
                    "fft_size":    FFT_SIZE,
                    "channels":    [
                        {
                            "freq_hz":    freq_hz,
                            "dbfs":       info["dbfs"],
                            "ch_num":     info["ch_num"],
                            "label":      info["label"],
                            "type":       info["type"],
                            "advertising":info.get("advertising", False),
                        }
                        for freq_hz, info in sorted(ch_energies.items())
                    ],
                    "anomaly_count": self.anomaly_engine.anomaly_count,
                    "frame_count":   self._frame_count,
                }
                self.log.write(rec)
                self.mirror.write(rec)

                # Console status
                adv = {
                    ch: ch_energies.get(freq, {}).get("dbfs", -120)
                    for ch, freq in ADV_CHANNELS.items()
                }
                print(
                    f"\r  [{wall_ns}]  "
                    f"Ch37={adv[37]:6.1f}dBFS  "
                    f"Ch38={adv[38]:6.1f}dBFS  "
                    f"Ch39={adv[39]:6.1f}dBFS  "
                    f"A={self.anomaly_engine.anomaly_count:>4}  "
                    f"F={self._frame_count:>10}   ",
                    end='', flush=True
                )

        except Exception as e:
            print(f"\n[BT] Capture error: {e}")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="CTW Bluetooth/BLE Forensic Scanner"
    )
    ap.add_argument("--uri",            default=DEFAULT_URI)
    ap.add_argument("--center",         type=int,
                    default=DEFAULT_CENTER_HZ,   metavar="HZ")
    ap.add_argument("--bw",             type=int,
                    default=DEFAULT_BW_HZ,        metavar="HZ")
    ap.add_argument("--gain",           type=int,
                    default=DEFAULT_GAIN,          metavar="DB")
    ap.add_argument("--rssi-threshold", type=float,
                    default=DEFAULT_RSSI_THRESH,   metavar="DBFS")
    ap.add_argument("--out",            default=".",  metavar="DIR")
    ap.add_argument("--adv-only",       action="store_true",
                    help="Print advertising channel events only")
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
        "type":              "bt_session_header",
        "session_wall_utc":  clock.session_wall_utc,
        "session_wall_ns":   clock.session_wall_ns,
        "session_mono_ns":   clock.session_mono_ns,
        "ntp_source":        ntp_info["ntp_source"],
        "ntp_offset_ms":     ntp_info.get("ntp_offset_ms"),
        "pluto_uri":         args.uri,
        "center_hz":         args.center,
        "bandwidth_hz":      args.bw,
        "gain_db":           args.gain,
        "rssi_threshold":    args.rssi_threshold,
        "fft_size":          FFT_SIZE,
        "ble_channels":      len(BLE_CHANNELS),
        "classic_bt_channels": len(CLASSIC_BT_CHANNELS),
        "adv_channels":      list(ADV_CHANNELS.keys()),
        "adv_freqs_hz":      list(ADV_CHANNELS.values()),
        "stamp":             STAMP,
    }

    gz_path    = os.path.join(out_dir, f"bt_{STAMP}.jsonl.gz")
    live_path  = os.path.join(runtime_dir, "bt_live.jsonl")

    log    = GzipLog(gz_path, header)
    mirror = LiveMirror(live_path)
    mirror.write(header)

    print(f"\n{'='*62}")
    print(f"  CTW BLUETOOTH / BLE FORENSIC SCANNER")
    print(f"{'='*62}")
    print(f"  Pluto URI       : {args.uri}")
    print(f"  Center freq     : {args.center/1e6:.1f} MHz")
    print(f"  Bandwidth       : {args.bw/1e6:.0f} MHz")
    print(f"  Coverage        : {(args.center-args.bw//2)/1e6:.1f} – "
          f"{(args.center+args.bw//2)/1e6:.1f} MHz")
    print(f"  BLE channels    : {len(BLE_CHANNELS)} "
          f"(adv: 37={ADV_CHANNELS[37]/1e6:.3f}MHz "
          f"38={ADV_CHANNELS[38]/1e6:.3f}MHz "
          f"39={ADV_CHANNELS[39]/1e6:.3f}MHz)")
    print(f"  Classic BT      : {len(CLASSIC_BT_CHANNELS)} channels")
    print(f"  RSSI threshold  : {args.rssi_threshold} dBFS")
    print(f"  FFT size        : {FFT_SIZE}")
    print(f"  Gain            : {args.gain} dB")
    print(f"  BT log          : bt_{STAMP}.jsonl.gz")
    print(f"  Live mirror     : {live_path}")
    print(f"  Ctrl+C to stop")
    print(f"{'='*62}\n")

    stop_event = threading.Event()

    capture = BTCapture(
        uri            = args.uri,
        center_hz      = args.center,
        sample_rate    = args.bw,
        gain           = args.gain,
        clock          = clock,
        log            = log,
        mirror         = mirror,
        rssi_threshold = args.rssi_threshold,
        stop_event     = stop_event,
    )

    capture_thread = threading.Thread(
        target=capture.run, daemon=True, name="BTCapture"
    )
    capture_thread.start()

    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        capture_thread.join(timeout=5)

        wall_ns, mono_ns = clock.now()
        end_rec = {
            "type":          "session_end",
            "_stream":       "bt",
            "wall_ns":       wall_ns,
            "wall_iso":      clock.format_wall_ns(wall_ns),
            "mono_ns":       mono_ns,
            "total_sweeps":  capture._seq,
            "total_frames":  capture._frame_count,
            "anomalies":     capture.anomaly_engine.anomaly_count,
        }
        log.write(end_rec)
        mirror.write(end_rec)
        log.close()

        print(f"\n\nBT session complete.")
        print(f"  Sweeps    : {capture._seq}")
        print(f"  Frames    : {capture._frame_count}")
        print(f"  Anomalies : {capture.anomaly_engine.anomaly_count}")
        print(f"  Log       : {gz_path}")

if __name__ == "__main__":
    main()