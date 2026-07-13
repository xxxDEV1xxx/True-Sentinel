#!/usr/bin/env python3
"""
fs5000_dual.py  —  Bosean FS-5000 Dual-Stream Forensic Logger
==============================================================
STREAM A — Serial (USB/CH340)  → serial_STAMP.jsonl.gz
STREAM B — Audio (headphone jack → USB adapter) → audio_STAMP.jsonl.gz

Usage:
  python fs5000_dual.py                          # auto-detect everything
  python fs5000_dual.py --port COM4
  python fs5000_dual.py --list-audio             # show all input devices
  python fs5000_dual.py --audio-device 1         # force MME USB device
  python fs5000_dual.py --threshold 0.03         # more sensitive
  python fs5000_dual.py --out C:\\path\\to\\logs

pip install pyaudio pyserial
"""

import argparse
import datetime
import gzip
import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
# ── dependency check ───────────────────────────────────────────────────────
try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("ERROR: pip install pyserial")
    sys.exit(1)

try:
    import pyaudio
except ImportError:
    print("ERROR: pip install pyaudio")
    sys.exit(1)

# ── constants ──────────────────────────────────────────────────────────────
CH340_VID               = 0x1A86
CH340_PID               = 0x7523
BAUD                    = 115200
DEFAULT_SPIKE_THRESHOLD = 0.01
DANGEROUS_THRESHOLD     = 0.20
DEFAULT_THRESHOLD       = 0.05
DEFAULT_REFRACTORY      = 0.003      # 3 ms
CHUNK_FRAMES            = 256
PREFERRED_RATES         = [48000, 44100]

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

_LIVE_RE = re.compile(
    rb'DR:(?P<dr>[\d.]+)uSv/h;'
    rb'D:(?P<dose>[\d. ]+)uSv;'
    rb'(?:CPS:(?P<cps>[\d]+);)?'
    rb'CPM:(?P<cpm>[\d]+)'
)

APIS_TO_NAME: dict = {}

def _populate_api_names(pa: pyaudio.PyAudio):
    global APIS_TO_NAME
    for i in range(pa.get_host_api_count()):
        APIS_TO_NAME[i] = pa.get_host_api_info_by_index(i)['name']

# ── packet framing ─────────────────────────────────────────────────────────
def _cs(data: bytes) -> int:
    return sum(data) % 256

def make_packet(payload: bytes) -> bytes:
    hdr  = bytes([0xAA, len(payload) + 3])
    body = hdr + payload
    return body + bytes([_cs(body)]) + bytes([0x55])

# ── NTP query ──────────────────────────────────────────────────────────────
from ntp_web import get_ntp_info, print_web_time_banner
# ── clock anchor ───────────────────────────────────────────────────────────
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
        whole_s = self._wall_epoch // 1_000_000_000
        self.session_wall_ns_remainder = self._wall_epoch - whole_s * 1_000_000_000

    def now(self) -> tuple:
        mono_now = time.perf_counter_ns()
        delta    = mono_now - self._mono_epoch
        return self._wall_epoch + delta, delta

    def format_wall_ns(self, wall_ns: int) -> str:
        whole_s = wall_ns // 1_000_000_000
        frac_ns = wall_ns  % 1_000_000_000
        base    = datetime.datetime.fromtimestamp(
            whole_s, tz=datetime.timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%S')
        return f"{base}.{frac_ns:09d}Z"

# ── gzip log ───────────────────────────────────────────────────────────────
class GzipLog:
    def __init__(self, path: str, header: dict):
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

    def write(self, obj: dict):
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

# ── serial port discovery ──────────────────────────────────────────────────
def find_serial_port(forced=None) -> str:
    """
    If forced is given, verify it exists first.
    Otherwise auto-detect CH340. Either way print all available
    ports so the user can see what's actually there.
    """
    available = list(serial.tools.list_ports.comports())

    print("\nAvailable serial ports:")
    if not available:
        print("  (none detected)")
    for p in available:
        marker = " ← CH340 FS-5000" if (p.vid == CH340_VID and
                                          p.pid == CH340_PID) else ""
        print(f"  {p.device:<10} {p.description}{marker}")
    print()

    if forced:
        # Check if forced port is in the available list
        names = [p.device.upper() for p in available]
        if forced.upper() not in names:
            print(f"WARNING: {forced} not found in available ports.")
            print(f"  Plug in the FS-5000 USB cable and check Device Manager.")
            print(f"  Available ports listed above.")
            print(f"\n  Waiting for {forced} to appear (Ctrl+C to abort)...")
            # Wait up to 30 seconds for the port to appear
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                current = [p.device.upper()
                           for p in serial.tools.list_ports.comports()]
                if forced.upper() in current:
                    print(f"  {forced} detected.")
                    break
                time.sleep(1)
                sys.stdout.write('.')
                sys.stdout.flush()
            else:
                print(f"\nERROR: {forced} never appeared.")
                print("  Check: Device Manager → Ports (COM & LPT)")
                print("  Install CH340 driver if missing:")
                print("  https://www.wch-ic.com/downloads/CH341SER_EXE.html")
                sys.exit(1)
        return forced

    # Auto-detect CH340
    for p in available:
        if p.vid == CH340_VID and p.pid == CH340_PID:
            print(f"[AUTO] FS-5000 detected on {p.device}")
            return p.device

    print("ERROR: CH340 not detected automatically.")
    print("  Use --port COMx to specify the port manually.")
    sys.exit(1)

# ── audio device discovery ─────────────────────────────────────────────────
def list_audio_devices(pa: pyaudio.PyAudio):
    print("\nAvailable audio INPUT devices:")
    print(f"  {'Idx':<5} {'API':<24} {'Name':<42} {'Ch':<4} {'Rate'}")
    print(f"  {'-'*5} {'-'*24} {'-'*42} {'-'*4} {'-'*8}")
    for i in range(pa.get_device_count()):
        info = pa.get_device_info_by_index(i)
        if info['maxInputChannels'] < 1:
            continue
        api = APIS_TO_NAME.get(info['hostApi'], str(info['hostApi']))
        print(f"  {i:<5} {api:<24} {info['name'][:41]:<42} "
              f"{int(info['maxInputChannels']):<4} "
              f"{int(info['defaultSampleRate'])}")
    print()

def _try_open_stream(pa, dev_index, rate, chunk, callback):
    """Try to open a PyAudio stream. Returns stream or None."""
    try:
        s = pa.open(
            format             = pyaudio.paFloat32,
            channels           = 1,
            rate               = rate,
            input              = True,
            input_device_index = dev_index,
            frames_per_buffer  = chunk,
            stream_callback    = callback,
        )
        return s
    except Exception:
        return None

def find_audio_device_and_open(pa: pyaudio.PyAudio,
                               forced_index,
                               chunk: int,
                               callback) -> tuple:
    """
    Returns (stream, device_index, sample_rate, api_name).

    Searches by device name, not index — survives USB replug.
    Cascade order (WDM-KS first — only API that opened on this machine):
      1. Forced index if given — try all preferred rates
      2. WDM-KS   + name contains 'usb'
      3. WASAPI   + name contains 'usb'
      4. MME      + name contains 'usb'
      5. DirectSound + name contains 'usb'
      6. Any API  + name contains 'usb'
      7. System default input
    """

    api_index_by_name = {}
    for i in range(pa.get_host_api_count()):
        name = pa.get_host_api_info_by_index(i)['name'].lower()
        api_index_by_name[name] = i

    def usb_devices_for_api(api_name_lower):
        api_idx = api_index_by_name.get(api_name_lower)
        if api_idx is None:
            return []
        out = []
        for i in range(pa.get_device_count()):
            info = pa.get_device_info_by_index(i)
            if (info['maxInputChannels'] >= 1
                    and info['hostApi'] == api_idx
                    and 'usb' in info['name'].lower()):
                out.append(i)
        return out

    attempts = []

    # ── Stage 1: forced index ──────────────────────────────────────────
    if forced_index is not None:
        info = pa.get_device_info_by_index(forced_index)
        for rate in PREFERRED_RATES:
            print(f"  Trying forced [{forced_index}] "
                  f"{info['name'][:30]} @ {rate} Hz ...", end=' ')
            s = _try_open_stream(pa, forced_index, rate, chunk, callback)
            if s:
                print("OK")
                api = APIS_TO_NAME.get(info['hostApi'], '?')
                return s, forced_index, rate, api
            print("failed")
            attempts.append(f"forced [{forced_index}] @ {rate}")

    # ── Stages 2-5: named API order, USB devices by name ──────────────
    api_priority = [
        'windows wdm-ks',       # opened successfully in testing
        'windows wasapi',
        'mme',
        'windows directsound',
    ]

    for api_name_lower in api_priority:
        api_display = APIS_TO_NAME.get(
            api_index_by_name.get(api_name_lower, -1),
            api_name_lower
        )
        for dev in usb_devices_for_api(api_name_lower):
            info = pa.get_device_info_by_index(dev)
            for rate in PREFERRED_RATES:
                print(f"  Trying [{api_display}] [{dev}] "
                      f"{info['name'][:28]} @ {rate} Hz ...", end=' ')
                s = _try_open_stream(pa, dev, rate, chunk, callback)
                if s:
                    print("OK")
                    return s, dev, rate, api_display
                print("failed")
                attempts.append(f"[{api_display}] [{dev}] @ {rate}")

    # ── Stage 6: any API, any USB device ──────────────────────────────
    seen = set()
    for i in range(pa.get_device_count()):
        info = pa.get_device_info_by_index(i)
        if (info['maxInputChannels'] >= 1
                and 'usb' in info['name'].lower()
                and i not in seen):
            seen.add(i)
            api_display = APIS_TO_NAME.get(info['hostApi'], '?')
            for rate in PREFERRED_RATES:
                print(f"  Trying [{api_display}] [{i}] "
                      f"{info['name'][:28]} @ {rate} Hz ...", end=' ')
                s = _try_open_stream(pa, i, rate, chunk, callback)
                if s:
                    print("OK")
                    return s, i, rate, api_display
                print("failed")
                attempts.append(f"[{api_display}] [{i}] @ {rate}")

    # ── Stage 7: system default ────────────────────────────────────────
    try:
        def_idx  = pa.get_default_input_device_info()['index']
        def_info = pa.get_device_info_by_index(def_idx)
        for rate in PREFERRED_RATES:
            print(f"  Trying [default] [{def_idx}] "
                  f"{def_info['name'][:28]} @ {rate} Hz ...", end=' ')
            s = _try_open_stream(pa, def_idx, rate, CHUNK_FRAMES, callback)
            if s:
                api = APIS_TO_NAME.get(def_info['hostApi'], '?')
                print("OK  (system default fallback)")
                return s, def_idx, rate, api
            print("failed")
            attempts.append(f"[default] [{def_idx}] @ {rate}")
    except Exception:
        pass

    # ── All failed ─────────────────────────────────────────────────────
    print("\nERROR: Could not open any audio input stream.")
    print("Attempted:")
    for a in attempts:
        print(f"  {a}")
    print()
    print("Fix options:")
    print("  1. Run --list-audio and pass the correct index with --audio-device N")
    print("  2. Windows Sound → Recording → USB Device → Properties → Advanced")
    print("     Set: 1 channel, 16 bit, 48000 Hz")
    print("     Uncheck 'Allow exclusive control'")
    print("  3. Unplug/replug the USB audio adapter")
    sys.exit(1)

# ── pulse detector ─────────────────────────────────────────────────────────
class PulseDetector:
    def __init__(self, clock: ClockAnchor, log: GzipLog,
                 sample_rate: int, threshold: float,
                 refractory_s: float, on_pulse=None):
        self.clock         = clock
        self.log           = log
        self.sample_rate   = sample_rate
        self.threshold     = threshold
        self.refractory_ns = int(refractory_s * 1e9)
        self.on_pulse      = on_pulse
        self._seq             = 0
        self._last_trigger_ns = 0
        self._in_pulse        = False
        self._stream_start_ns = None
        self._total_samples   = 0
        self._ns_per_sample   = int(1_000_000_000 / sample_rate)

    def feed_chunk(self, samples, num_frames: int):
        chunk_arrival_ns = time.perf_counter_ns()
        if self._stream_start_ns is None:
            self._stream_start_ns = (chunk_arrival_ns
                                     - num_frames * self._ns_per_sample)
        chunk_start_idx      = self._total_samples
        self._total_samples += num_frames

        for i, s in enumerate(samples):
            amp = abs(s)
            if not self._in_pulse:
                if amp >= self.threshold:
                    sample_idx     = chunk_start_idx + i
                    sample_mono_ns = (
                        self._stream_start_ns
                        - self.clock.session_mono_ns
                        + sample_idx * self._ns_per_sample
                    )
                    if sample_mono_ns - self._last_trigger_ns < self.refractory_ns:
                        self._in_pulse = True
                        continue
                    wall_ns = self.clock.session_wall_ns + sample_mono_ns
                    self._last_trigger_ns = sample_mono_ns
                    self._in_pulse = True
                    self._seq += 1
                    self.log.write({
                        "seq":       self._seq,
                        "wall_ns":   wall_ns,
                        "wall_iso":  self.clock.format_wall_ns(wall_ns),
                        "mono_ns":   sample_mono_ns,
                        "amplitude": round(float(amp), 6),
                    })
                    if self.on_pulse:
                        self.on_pulse(wall_ns, amp)
            else:
                if amp < self.threshold:
                    self._in_pulse = False

    @property
    def pulse_count(self) -> int:
        return self._seq

# ── serial stream ──────────────────────────────────────────────────────────
def run_serial(port_name, clock, log, spike_threshold,
               quiet, stop_event, audio_pulse_count_fn):
    buf      = bytearray()
    last_dr  = None
    last_cpm = None
    seq      = 0
    try:
        with serial.Serial(port_name, BAUD, timeout=0.05) as port:
            port.reset_input_buffer()
            port.write(make_packet(bytes([0x0e, 0x00])))
            time.sleep(0.5)
            port.reset_input_buffer()
            port.write(make_packet(bytes([0x0e, 0x01])))
            time.sleep(0.3)
            ack = port.read(port.in_waiting or 1)
            if ack:
                if ack[0] == 0xAA and len(ack) > 1:
                    skip = 2 + ack[1]
                    if len(ack) > skip:
                        buf.extend(ack[skip:])
                else:
                    buf.extend(ack)

            while not stop_event.is_set():
                chunk = port.read(4096)
                if not chunk:
                    continue
                buf.extend(chunk)
                matches = list(_LIVE_RE.finditer(buf))
                if not matches:
                    if len(buf) > 512:
                        buf = buf[-512:]
                    continue
                for m in matches:
                    try:
                        dr   = float(m.group('dr'))
                        cpm  = int(m.group('cpm'))
                        cps_raw = m.group('cps')
                        cps  = int(cps_raw) if cps_raw is not None else (cpm // 60)
                        dose = float(m.group('dose').strip())
                    except (ValueError, AttributeError):
                        continue
                    wall_ns, mono_ns = clock.now()
                    seq += 1
                    log.write({
                        "seq":     seq,
                        "wall_ns": wall_ns,
                        "wall_iso": clock.format_wall_ns(wall_ns),
                        "mono_ns": mono_ns,
                        "dr":      dr,
                        "cpm":     cpm,
                        "cps":     cps,
                        "dose":    dose,
                    })
                    if not quiet and (dr != last_dr or cpm != last_cpm):
                        last_dr  = dr
                        last_cpm = cpm
                        aud = audio_pulse_count_fn()
                        if dr >= DANGEROUS_THRESHOLD:
                            flag = '!!! DANGEROUS !!!'
                        elif dr >= spike_threshold:
                            flag = '*** SPIKE ***'
                        else:
                            flag = ''
                        bar = chr(0x2588) * min(30, int(dr * 100))
                        ts  = datetime.datetime.now(
                            tz=datetime.timezone.utc).strftime('%H:%M:%S')
                        print(
                            f"\r  {ts}  {dr:7.4f} uSv/h  "
                            f"CPS={cps:>4}  CPM={cpm:>5}  "
                            f"AUD={aud:>7}  {bar:<30}  {flag}   ",
                            end='', flush=True
                        )
                buf = buf[max(0, matches[-1].end() - 512):]
    except Exception as e:
        if not stop_event.is_set():
            print(f"\n[serial] error: {type(e).__name__}: {e}")
    finally:
        try:
            with serial.Serial(port_name, BAUD, timeout=2) as p:
                p.write(make_packet(bytes([0x0e, 0x00])))
                time.sleep(0.2)
        except Exception:
            pass

# ── main ───────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="FS-5000 Dual-Stream Forensic Logger")
    ap.add_argument('--port',            help='Serial port e.g. COM4')
    ap.add_argument('--out',             default='.', metavar='DIR')
    ap.add_argument('--audio-device',    type=int, default=None, metavar='N')
    ap.add_argument('--list-audio',      action='store_true')
    ap.add_argument('--threshold',       type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument('--refractory',      type=float, default=DEFAULT_REFRACTORY)
    ap.add_argument('--spike-threshold', type=float,
                    default=DEFAULT_SPIKE_THRESHOLD)
    ap.add_argument('--quiet',           action='store_true')
    args = ap.parse_args()

    pa = pyaudio.PyAudio()
    _populate_api_names(pa)

    if args.list_audio:
        list_audio_devices(pa)
        pa.terminate()
        return

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)

    # NTP + clock anchor
    print("Querying NTP status...", end=' ', flush=True)
    ntp_info = get_ntp_info()
    print(f"done.  Source: {ntp_info['ntp_source']}")
    clock = ClockAnchor()

    # Serial port — with wait loop built in
    port_name = find_serial_port(args.port)

    # Audio — build callback shell first, detector assigned after
    detector_holder = [None]

    def audio_callback(in_data, frame_count, time_info, status):
        import struct as _s
        det = detector_holder[0]
        if det is not None:
            samples = _s.unpack_from(f'{frame_count}f', in_data)
            det.feed_chunk(samples, frame_count)
        return (None, pyaudio.paContinue)

    print("\nOpening audio stream (trying all available options):")
    stream, dev_index, sample_rate, api_name = find_audio_device_and_open(
        pa, args.audio_device, CHUNK_FRAMES, audio_callback
    )

    dev_name = pa.get_device_info_by_index(dev_index)['name']

    # Build forensic header
    forensic_header = {
        "type":                      "forensic_session_header",
        "record":                    0,
        "ntp_source":                ntp_info["ntp_source"],
        "ntp_last_sync":             ntp_info["ntp_last_sync_utc"],
        "ntp_offset_s":              ntp_info["ntp_offset_s"],
        "ntp_query_method":          ntp_info["ntp_query_method"],
        "ntp_error":                 ntp_info.get("ntp_error"),
        "ntp_raw":                   ntp_info.get("ntp_raw_output", ""),
        "session_wall_utc":          clock.session_wall_utc,
        "session_wall_ns":           clock.session_wall_ns,
        "session_wall_ns_remainder": clock.session_wall_ns_remainder,
        "session_mono_epoch_ns":     clock.session_mono_ns,
        "timing_note": (
            "wall_ns = session_wall_ns + mono_ns. "
            "mono_ns from perf_counter_ns — monotonic, never jumps. "
            "session_wall_ns from time_ns at session start, "
            "NTP-disciplined."
        ),
        "instrument":                "Bosean FS-5000",
        "serial_port":               port_name,
        "spike_threshold_usvh":      args.spike_threshold,
        "dangerous_threshold_usvh":  DANGEROUS_THRESHOLD,
        "audio_device_index":        dev_index,
        "audio_device_name":         dev_name,
        "audio_api":                 api_name,
        "sample_rate_hz":            sample_rate,
        "resolution_us":             round(1_000_000 / sample_rate, 3),
        "resolution_ns":             round(1_000_000_000 / sample_rate, 1),
        "audio_threshold":           args.threshold,
        "refractory_s":              args.refractory,
        "serial_log":                f"serial_{STAMP}.jsonl.gz",
        "audio_log":                 f"audio_{STAMP}.jsonl.gz",
        "session_file":              f"session_{STAMP}.json",
    }

    # Write human-readable companion
    session_path = os.path.join(out_dir, f"session_{STAMP}.json")
    with open(session_path, 'w') as f:
        json.dump(forensic_header, f, indent=2)

    serial_log_path = os.path.join(out_dir, f"serial_{STAMP}.jsonl.gz")
    audio_log_path  = os.path.join(out_dir, f"audio_{STAMP}.jsonl.gz")
    serial_log = GzipLog(serial_log_path, forensic_header)
    audio_log  = GzipLog(audio_log_path,  forensic_header)

    detector = PulseDetector(
        clock        = clock,
        log          = audio_log,
        sample_rate  = sample_rate,
        threshold    = args.threshold,
        refractory_s = args.refractory,
    )
    detector_holder[0] = detector

    stop_event    = threading.Event()
    serial_thread = threading.Thread(
        target = run_serial,
        args   = (port_name, clock, serial_log,
                  args.spike_threshold, args.quiet,
                  stop_event, lambda: detector.pulse_count),
        daemon = True,
        name   = 'SerialStream',
    )

    print(f"\n{'='*62}")
    print(f"  FS-5000 DUAL-STREAM FORENSIC LOGGER")
    print(f"{'='*62}")
    print(f"  NTP source      : {ntp_info['ntp_source']}")
    print(f"  NTP last sync   : {ntp_info['ntp_last_sync_utc']}")
    print(f"  NTP offset      : {ntp_info['ntp_offset_s']} s")
    print(f"  Session start   : {clock.session_wall_utc}")
    print(f"  Session wall ns : {clock.session_wall_ns}")
    print(f"  Sub-second ns   : {clock.session_wall_ns_remainder} ns")
    print(f"{'─'*62}")
    print(f"  Serial port     : {port_name}")
    print(f"  Audio device    : [{dev_index}] {dev_name}")
    print(f"  Audio API       : {api_name}")
    print(f"  Sample rate     : {sample_rate} Hz  "
          f"(~{forensic_header['resolution_ns']:.0f} ns / sample)")
    print(f"  Threshold       : {args.threshold}  "
          f"refractory {args.refractory*1000:.1f} ms")
    print(f"{'─'*62}")
    print(f"  Serial log      : serial_{STAMP}.jsonl.gz")
    print(f"  Audio log       : audio_{STAMP}.jsonl.gz")
    print(f"  Session meta    : session_{STAMP}.json")
    print(f"  Out dir         : {out_dir}")
    print(f"{'─'*62}")
    print(f"  AUD = running audio pulse total (vs serial CPS for correlation)")
    print(f"  Ctrl+C to stop")
    print(f"{'='*62}\n")

    stream.start_stream()
    serial_thread.start()

    try:
        while stream.is_active():
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()

        # Stop audio stream safely
        try:
            stream.stop_stream()
        except Exception:
            pass
        try:
            stream.close()
        except Exception:
            pass
        try:
            pa.terminate()
        except Exception:
            pass

        serial_thread.join(timeout=3)

        wall_ns, mono_ns = clock.now()
        end_rec = {
            "type":         "session_end",
            "wall_ns":      wall_ns,
            "wall_iso":     clock.format_wall_ns(wall_ns),
            "mono_ns":      mono_ns,
            "audio_pulses": detector.pulse_count,
        }
        serial_log.write(end_rec)
        audio_log.write(end_rec)
        serial_log.close()
        audio_log.close()

        print(f"\n\nSession complete.")
        print(f"  Session start   : {clock.session_wall_utc}")
        print(f"  Session end     : {clock.format_wall_ns(wall_ns)}")
        print(f"  Duration        : {mono_ns/1e9:.3f} s")
        print(f"  Audio pulses    : {detector.pulse_count}")
        print(f"  Serial log      : {serial_log_path}")
        print(f"  Audio log       : {audio_log_path}")
        print(f"  Session meta    : {session_path}")

if __name__ == '__main__':
    main()