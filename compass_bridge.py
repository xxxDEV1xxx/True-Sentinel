#!/usr/bin/env python3
"""
compass_bridge.py  —  CTW Compass Sensor Bridge
================================================
Reads AK09916 magnetometer from Galaxy S7 (herolte).
Streams heading + raw XYZ over TCP for collection by
gnss_compass.py on the PC via ADB forward.

Run on phone:
  python compass_bridge.py

On PC:
  adb forward tcp:5556 tcp:5556
  python gnss_compass.py --compass-port localhost:5556
"""

import json
import math
import socket
import struct
import threading
import time
import os

# ── Magnetic declination for Perris CA ────────────────────────────────────
# +11.5 degrees East as of 2026
# Update at: https://www.ngdc.noaa.gov/geomag/calculators/magcalc.shtml
DECLINATION_DEG = 11.5

# ── Sensor paths — SM-G930U (herolte) ─────────────────────────────────────
# Try multiple paths — varies by Android version and kernel
SENSOR_PATHS = [
    # IIO subsystem (most reliable on herolte)
    "/sys/bus/iio/devices/iio:device0",
    "/sys/bus/iio/devices/iio:device1",
    "/sys/bus/iio/devices/iio:device2",
    # I2C direct
    "/sys/bus/i2c/devices/5-000c",
    "/sys/bus/i2c/devices/1-000c",
    # Input event (fallback)
    None,
]

PORT = 5556


def find_ak09916_iio():
    """Find the AK09916 IIO device node."""
    import glob
    for base in glob.glob("/sys/bus/iio/devices/iio:device*"):
        name_file = os.path.join(base, "name")
        try:
            with open(name_file) as f:
                name = f.read().strip()
            if "ak09" in name.lower() or "magn" in name.lower():
                return base
        except Exception:
            continue
    return None


def read_iio_magn(iio_path):
    """Read raw XYZ from IIO sysfs node."""
    vals = {}
    for axis in ('x', 'y', 'z'):
        try:
            p = os.path.join(iio_path, f"in_magn_{axis}_raw")
            with open(p) as f:
                vals[axis] = int(f.read().strip())
        except Exception:
            vals[axis] = 0
    # Read scale if available
    scale = 1.0
    try:
        with open(os.path.join(iio_path, "in_magn_scale")) as f:
            scale = float(f.read().strip())
    except Exception:
        pass
    return vals['x'] * scale, vals['y'] * scale, vals['z'] * scale


def read_event_magn(event_fd):
    """
    Read from /dev/input/eventX.
    Linux input event: struct input_event = 24 bytes
    type=3 (EV_ABS), code=0/1/2 (ABS_X/Y/Z)
    """
    EVENT_SIZE = 24
    x = y = z = 0
    try:
        data = os.read(event_fd, EVENT_SIZE * 10)
        for i in range(0, len(data) - EVENT_SIZE + 1, EVENT_SIZE):
            _, _, type_, code, value = struct.unpack_from('llHHi', data, i)
            if type_ == 3:   # EV_ABS
                if code == 0: x = value
                if code == 1: y = value
                if code == 2: z = value
    except Exception:
        pass
    return float(x), float(y), float(z)


def compass_heading(x, y, declination=DECLINATION_DEG):
    """Convert XY magnetometer to true north heading."""
    heading = math.degrees(math.atan2(y, x))
    heading -= declination   # subtract East declination
    if heading < 0:    heading += 360
    if heading >= 360: heading -= 360
    return round(heading, 2)


def find_input_event():
    """Find magnetometer input event device."""
    try:
        with open("/proc/bus/input/devices") as f:
            content = f.read()
        blocks = content.split('\n\n')
        for block in blocks:
            if 'ak09' in block.lower() or 'compass' in block.lower():
                for line in block.split('\n'):
                    if line.startswith('H: Handlers='):
                        for tok in line.split():
                            if tok.startswith('event'):
                                return f"/dev/input/{tok}"
    except Exception:
        pass
    return None


class CompassReader:
    def __init__(self):
        self._iio_path   = None
        self._event_fd   = None
        self._mode       = None
        self._x = self._y = self._z = 0.0
        self._heading    = 0.0
        self._lock       = threading.Lock()
        self._stop       = threading.Event()
        self._thread     = threading.Thread(
            target=self._run, daemon=True, name="Compass"
        )

    def open(self):
        # Try IIO first
        self._iio_path = find_ak09916_iio()
        if self._iio_path:
            self._mode = "iio"
            print(f"[Compass] IIO: {self._iio_path}")
            self._thread.start()
            return True

        # Try input event
        ev_path = find_input_event()
        if ev_path:
            try:
                self._event_fd = os.open(ev_path, os.O_RDONLY | os.O_NONBLOCK)
                self._mode = "event"
                print(f"[Compass] Input event: {ev_path}")
                self._thread.start()
                return True
            except Exception as e:
                print(f"[Compass] Event open failed: {e}")

        print("[Compass] No sensor path found.")
        print("  Try: find /sys -name '*ak09*' 2>/dev/null")
        print("  Try: cat /proc/bus/input/devices | grep -i ak09")
        return False

    def _run(self):
        while not self._stop.is_set():
            try:
                if self._mode == "iio":
                    x, y, z = read_iio_magn(self._iio_path)
                elif self._mode == "event" and self._event_fd is not None:
                    x, y, z = read_event_magn(self._event_fd)
                else:
                    time.sleep(0.5)
                    continue

                heading = compass_heading(x, y)
                with self._lock:
                    self._x, self._y, self._z = x, y, z
                    self._heading = heading

            except Exception as e:
                print(f"[Compass] Read error: {e}")
                time.sleep(1)
                continue

            time.sleep(0.1)  # 10 Hz

    def read(self):
        with self._lock:
            return {
                "heading_deg":   self._heading,
                "x_gauss":       round(self._x, 6),
                "y_gauss":       round(self._y, 6),
                "z_gauss":       round(self._z, 6),
                "declination":   DECLINATION_DEG,
                "mode":          self._mode,
                "ts_ns":         time.time_ns(),
            }

    def stop(self):
        self._stop.set()
        if self._event_fd is not None:
            try: os.close(self._event_fd)
            except Exception: pass


def serve(compass: CompassReader):
    """Stream compass readings over TCP."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(4)
    print(f"[Compass] Streaming on port {PORT}")
    print(f"[Compass] PC: adb forward tcp:{PORT} tcp:{PORT}")

    while True:
        try:
            conn, addr = srv.accept()
            print(f"[Compass] Client connected: {addr}")
            threading.Thread(
                target=_handle_client,
                args=(conn, compass),
                daemon=True
            ).start()
        except Exception as e:
            print(f"[Compass] Accept error: {e}")
            break


def _handle_client(conn, compass):
    try:
        while True:
            reading = compass.read()
            line = json.dumps(reading, separators=(',', ':')) + '\n'
            conn.sendall(line.encode('utf-8'))
            time.sleep(0.1)
    except Exception:
        pass
    finally:
        conn.close()


if __name__ == "__main__":
    compass = CompassReader()
    if not compass.open():
        print("No compass sensor accessible.")
        print("Ensure running as root or with sensor permissions.")
        raise SystemExit(1)

    try:
        serve(compass)
    except KeyboardInterrupt:
        compass.stop()
        print("\nStopped.")
