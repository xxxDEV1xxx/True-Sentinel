#!/usr/bin/env python3
"""
mmwave_sensor.py  —  CTW mmWave Forensic Sensor Framework
==========================================================
Pluggable sensor architecture for 50–90 GHz detection.

Adding a new sensor:
  1. Subclass MMWaveSensor
  2. Implement open(), read_sample(), close()
  3. Register in SENSOR_REGISTRY at bottom of file
  4. Pass --sensor <name> on command line

Built-in drivers:
  schottky_serial   — V-band Schottky detector via Arduino ADC serial
  schottky_audio    — V-band Schottky detector via USB audio input
  bgt60_spi         — Infineon BGT60TR13C via SPI (RPi/Arduino)
  bgt60_serial      — BGT60 via Arduino bridge serial
  lnb_rtlsdr        — Ka/Ku LNB downconverter + RTL-SDR
  geiger_proxy      — FS-5000 GM tube audio channel (existing hardware)
  dummy             — Synthetic test signal (no hardware required)

All sensors output MMWaveSample objects and feed the same:
  - GzipLog  → mmwave_STAMP.jsonl.gz
  - LiveMirror → runtime/mmwave_live.jsonl
  - AnomalyEngine → PRESENCE / BURST / CORR events
  - ClockAnchor → same wall_ns epoch as all other CTW pipeline scripts

Usage:
  python mmwave_sensor.py --sensor dummy
  python mmwave_sensor.py --sensor schottky_audio --audio-device 1
  python mmwave_sensor.py --sensor schottky_serial --port COM5
  python mmwave_sensor.py --sensor bgt60_serial --port COM6
  python mmwave_sensor.py --sensor lnb_rtlsdr --lnb-lo 9750
  python mmwave_sensor.py --sensor geiger_proxy --audio-device 2
  python mmwave_sensor.py --list-sensors
  python mmwave_sensor.py --list-audio
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
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

# ══════════════════════════════════════════════════════════════════════════════
# SAMPLE DATACLASS — universal output from every sensor driver
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MMWaveSample:
    """
    Universal sample container.
    Every sensor driver must populate at minimum:
      wall_ns, mono_ns, power_raw, power_dbm (or None)

    Optional fields are populated when the sensor supports them.
    Fields left as None are omitted from the JSON record.
    """
    # Mandatory — timing
    wall_ns:       int     = 0
    mono_ns:       int     = 0
    wall_iso:      str     = ""

    # Mandatory — power
    power_raw:     float   = 0.0   # raw ADC count, voltage, or IQ magnitude
    power_dbm:     Optional[float] = None  # calibrated dBm if available

    # Optional — frequency information
    freq_hz:       Optional[float] = None  # center frequency if known
    freq_lo_hz:    Optional[float] = None  # LO frequency for downconverter
    freq_if_hz:    Optional[float] = None  # IF frequency for downconverter

    # Optional — IQ data (for sensors that produce baseband)
    i_sample:      Optional[float] = None
    q_sample:      Optional[float] = None
    amplitude:     Optional[float] = None  # sqrt(I²+Q²)
    phase_deg:     Optional[float] = None  # atan2(Q,I) in degrees

    # Optional — sensor-specific metadata
    sensor_name:   str     = ""
    sensor_temp_c: Optional[float] = None
    adc_counts:    Optional[int]   = None
    voltage_v:     Optional[float] = None
    presence:      Optional[bool]  = None  # for radar-type sensors
    motion:        Optional[bool]  = None
    range_m:       Optional[float] = None  # detected target range

    # Optional — quality indicators
    noise_floor:   Optional[float] = None
    snr_db:        Optional[float] = None
    saturated:     bool = False
    valid:         bool = True

    # Extra fields for sensor-specific data
    extra:         Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dict, omitting None values."""
        d = {
            "wall_ns":    self.wall_ns,
            "wall_iso":   self.wall_iso,
            "mono_ns":    self.mono_ns,
            "power_raw":  round(self.power_raw, 6),
            "sensor":     self.sensor_name,
            "valid":      self.valid,
            "saturated":  self.saturated,
        }
        for f in ("power_dbm", "freq_hz", "freq_lo_hz", "freq_if_hz",
                  "i_sample", "q_sample", "amplitude", "phase_deg",
                  "sensor_temp_c", "adc_counts", "voltage_v",
                  "presence", "motion", "range_m",
                  "noise_floor", "snr_db"):
            v = getattr(self, f)
            if v is not None:
                d[f] = round(v, 6) if isinstance(v, float) else v
        if self.extra:
            d.update(self.extra)
        return d

# ══════════════════════════════════════════════════════════════════════════════
# SENSOR BASE CLASS — implement this to add any new hardware
# ══════════════════════════════════════════════════════════════════════════════

class MMWaveSensor(ABC):
    """
    Base class for all mmWave sensor drivers.

    To add a new sensor:
      1. Subclass this
      2. Set self.name, self.description, self.freq_range_ghz
      3. Implement open(), read_sample(), close()
      4. Register in SENSOR_REGISTRY at bottom of file

    The framework handles all logging, anomaly detection,
    ClockAnchor timing, and live mirror output automatically.
    Your driver only needs to return MMWaveSample objects.
    """

    def __init__(self, args, clock):
        self.args        = args
        self.clock       = clock
        self.name        = "base"
        self.description = "Base sensor"
        self.freq_range_ghz = (0.0, 0.0)  # (low, high) GHz
        self._running    = False

    @abstractmethod
    def open(self) -> bool:
        """
        Initialize hardware connection.
        Return True on success, False on failure.
        Print a descriptive error on failure.
        """

    @abstractmethod
    def read_sample(self) -> Optional[MMWaveSample]:
        """
        Read one sample from the sensor.
        Return MMWaveSample or None if no data available yet.
        Must not block for more than ~100ms.
        Called continuously while running.
        """

    @abstractmethod
    def close(self):
        """Release hardware resources cleanly."""

    def capabilities(self) -> dict:
        """Return dict describing what this sensor can measure."""
        return {
            "name":           self.name,
            "description":    self.description,
            "freq_range_ghz": self.freq_range_ghz,
            "has_iq":         False,
            "has_range":      False,
            "has_presence":   False,
            "calibrated_dbm": False,
        }

# ══════════════════════════════════════════════════════════════════════════════
# DRIVER 1 — Schottky detector via Arduino serial
# ══════════════════════════════════════════════════════════════════════════════

class SchottkySerialSensor(MMWaveSensor):
    """
    V-band (50–75 GHz) Schottky zero-bias detector
    connected to Arduino Nano ADC, output via serial.

    Arduino sketch (upload separately):
      void setup() { Serial.begin(115200); analogReadResolution(12); }
      void loop()  {
        int v = analogRead(A0);
        Serial.println(v);
        delayMicroseconds(500);
      }

    Hardware:
      Schottky detector DC output → Arduino A0 (0–3.3V)
      Arduino USB → COM port

    Calibration:
      power_dbm requires a calibration table specific to your
      detector model. Default uses Pasternack PE8000 curve.
      Override by setting --cal-slope and --cal-intercept.
    """

    # Default calibration: Pasternack PE8000 approximate
    # voltage_mV = 10^((power_dbm + 50) / 20) * 0.1
    # Inverted: power_dbm = 20 * log10(voltage_mV / 0.1) - 50
    CAL_SLOPE     = 20.0   # dB per decade of voltage
    CAL_INTERCEPT = -50.0  # dBm at 0.1 mV

    def __init__(self, args, clock):
        super().__init__(args, clock)
        self.name           = "schottky_serial"
        self.description    = "V-band Schottky detector via Arduino serial ADC"
        self.freq_range_ghz = (50.0, 75.0)
        self._ser           = None
        self._adc_ref_v     = 3.3
        self._adc_bits      = 12
        self._cal_slope     = getattr(args, 'cal_slope',     self.CAL_SLOPE)
        self._cal_intercept = getattr(args, 'cal_intercept', self.CAL_INTERCEPT)
        self._freq_hz       = getattr(args, 'freq_hz',       60e9)

    def open(self) -> bool:
        try:
            import serial
            port = getattr(self.args, 'port', 'COM5')
            self._ser = serial.Serial(port, 115200, timeout=0.2)
            self._ser.reset_input_buffer()
            time.sleep(0.5)
            print(f"[mmwave] Schottky serial opened on {port}")
            return True
        except Exception as e:
            print(f"[mmwave] Schottky serial open failed: {e}")
            print(f"  Check: pip install pyserial")
            print(f"  Check: --port COM5 (or your Arduino port)")
            return False

    def read_sample(self) -> Optional[MMWaveSample]:
        if not self._ser:
            return None
        try:
            line = self._ser.readline().decode('ascii', errors='ignore').strip()
            if not line:
                return None
            adc_raw = int(line)
        except (ValueError, Exception):
            return None

        wall_ns, mono_ns = self.clock.now()
        voltage_v  = adc_raw * self._adc_ref_v / (2**self._adc_bits - 1)
        voltage_mv = voltage_v * 1000.0

        # Calibration curve: dBm from voltage
        if voltage_mv > 0.001:
            power_dbm = (self._cal_slope *
                         math.log10(voltage_mv / 0.1) +
                         self._cal_intercept)
        else:
            power_dbm = -80.0

        saturated = adc_raw >= (2**self._adc_bits - 10)

        s = MMWaveSample(
            wall_ns   = wall_ns,
            mono_ns   = mono_ns,
            wall_iso  = self.clock.format_wall_ns(wall_ns),
            power_raw = float(adc_raw),
            power_dbm = round(power_dbm, 2),
            voltage_v = round(voltage_v, 6),
            adc_counts= adc_raw,
            freq_hz   = self._freq_hz,
            sensor_name = self.name,
            saturated = saturated,
            valid     = not saturated,
        )
        return s

    def close(self):
        if self._ser:
            try: self._ser.close()
            except Exception: pass
            self._ser = None

    def capabilities(self) -> dict:
        c = super().capabilities()
        c.update({"calibrated_dbm": True, "has_voltage": True})
        return c

# ══════════════════════════════════════════════════════════════════════════════
# DRIVER 2 — Schottky detector via USB audio input
# ══════════════════════════════════════════════════════════════════════════════

class SchottkyAudioSensor(MMWaveSensor):
    """
    V-band Schottky detector output connected to USB audio adapter
    line input. The DC-coupled voltage appears as audio amplitude.

    Most USB audio adapters are AC-coupled (block DC).
    Use: Behringer UCA202, or a DC-coupled interface.
    Alternatively: use a low-pass filter + modulate the detector
    output at 1 kHz to get through AC coupling.

    Hardware:
      Schottky DC output → 1kHz modulator → USB audio in
      OR
      Schottky DC output → DC-coupled audio interface

    This reuses the same PulseDetector architecture as fs5000_dual.py.
    """

    CHUNK_FRAMES  = 256
    PREFERRED_RATES = [48000, 44100]

    def __init__(self, args, clock):
        super().__init__(args, clock)
        self.name           = "schottky_audio"
        self.description    = "V-band Schottky detector via USB audio ADC"
        self.freq_range_ghz = (50.0, 75.0)
        self._pa            = None
        self._stream        = None
        self._sample_rate   = None
        self._dev_index     = getattr(args, 'audio_device', None)
        self._freq_hz       = getattr(args, 'freq_hz', 60e9)
        self._threshold     = getattr(args, 'threshold', 0.05)
        self._latest        = None
        self._lock          = threading.Lock()

    def open(self) -> bool:
        try:
            import pyaudio
            self._pa = pyaudio.PyAudio()
        except ImportError:
            print("[mmwave] pyaudio not installed: pip install pyaudio")
            return False

        def callback(in_data, frame_count, time_info, status):
            import struct
            samples = struct.unpack_from(f'{frame_count}f', in_data)
            amplitude = max(abs(s) for s in samples)
            wall_ns, mono_ns = self.clock.now()
            s = MMWaveSample(
                wall_ns    = wall_ns,
                mono_ns    = mono_ns,
                wall_iso   = self.clock.format_wall_ns(wall_ns),
                power_raw  = amplitude,
                amplitude  = amplitude,
                freq_hz    = self._freq_hz,
                sensor_name= self.name,
                presence   = amplitude > self._threshold,
                valid      = True,
            )
            with self._lock:
                self._latest = s
            import pyaudio
            return (None, pyaudio.paContinue)

        # Try to open audio device
        import pyaudio
        dev    = self._dev_index
        opened = False
        for rate in self.PREFERRED_RATES:
            try:
                self._stream = self._pa.open(
                    format             = pyaudio.paFloat32,
                    channels           = 1,
                    rate               = rate,
                    input              = True,
                    input_device_index = dev,
                    frames_per_buffer  = self.CHUNK_FRAMES,
                    stream_callback    = callback,
                )
                self._sample_rate = rate
                opened = True
                break
            except Exception:
                continue

        if not opened:
            print("[mmwave] Could not open audio input.")
            print("  Run with --list-audio to see available devices.")
            return False

        dev_name = self._pa.get_device_info_by_index(
            dev if dev is not None else
            self._pa.get_default_input_device_info()['index']
        )['name']
        print(f"[mmwave] Audio opened: [{dev}] {dev_name} @ {self._sample_rate} Hz")
        self._stream.start_stream()
        return True

    def read_sample(self) -> Optional[MMWaveSample]:
        time.sleep(0.005)
        with self._lock:
            s = self._latest
            self._latest = None
        return s

    def close(self):
        try:
            if self._stream: self._stream.stop_stream(); self._stream.close()
            if self._pa:     self._pa.terminate()
        except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
# DRIVER 3 — Infineon BGT60TR13C via Arduino bridge serial
# ══════════════════════════════════════════════════════════════════════════════

class BGT60SerialSensor(MMWaveSensor):
    """
    Infineon BGT60TR13C 60 GHz radar chip via Arduino bridge.

    The BGT60TR13C is a 57–64 GHz FMCW radar chip available
    on breakout boards (~$150). It outputs I/Q baseband via SPI.
    An Arduino reads the SPI and streams JSON lines over serial.

    Arduino bridge sketch (upload separately to Arduino):
      Reads BGT60 SPI at configured chirp rate
      Outputs JSON: {"i":1234,"q":5678,"pres":1,"range":0.45}

    Hardware:
      BGT60TR13C breakout → Arduino SPI (pins 10,11,12,13)
      Arduino USB → COM port

    Python SDK alternative:
      If running on Raspberry Pi with direct SPI access,
      use the bgt60_spi driver instead.
    """

    def __init__(self, args, clock):
        super().__init__(args, clock)
        self.name           = "bgt60_serial"
        self.description    = "Infineon BGT60TR13C 60GHz radar via Arduino bridge"
        self.freq_range_ghz = (57.0, 64.0)
        self._ser           = None
        self._freq_hz       = 60.5e9  # BGT60 default center

    def open(self) -> bool:
        try:
            import serial
            port = getattr(self.args, 'port', 'COM6')
            self._ser = serial.Serial(port, 115200, timeout=0.2)
            self._ser.reset_input_buffer()
            time.sleep(1.0)
            print(f"[mmwave] BGT60 serial bridge opened on {port}")
            print(f"  Freq range: {self.freq_range_ghz[0]}–"
                  f"{self.freq_range_ghz[1]} GHz")
            return True
        except Exception as e:
            print(f"[mmwave] BGT60 serial open failed: {e}")
            return False

    def read_sample(self) -> Optional[MMWaveSample]:
        if not self._ser: return None
        try:
            line = self._ser.readline().decode('ascii', errors='ignore').strip()
            if not line: return None
            obj = json.loads(line)
        except Exception:
            return None

        wall_ns, mono_ns = self.clock.now()

        i_val    = float(obj.get('i', 0))
        q_val    = float(obj.get('q', 0))
        amp      = math.sqrt(i_val**2 + q_val**2)
        phase    = math.degrees(math.atan2(q_val, i_val)) if amp > 0 else 0.0
        presence = bool(obj.get('pres', 0))
        range_m  = float(obj.get('range', 0)) if 'range' in obj else None
        temp_c   = float(obj.get('temp', 0)) if 'temp' in obj else None

        # Approximate dBm from IQ amplitude (sensor-specific scaling)
        power_dbm = 20 * math.log10(amp / 32768.0) if amp > 0 else -80.0

        return MMWaveSample(
            wall_ns    = wall_ns,
            mono_ns    = mono_ns,
            wall_iso   = self.clock.format_wall_ns(wall_ns),
            power_raw  = amp,
            power_dbm  = round(power_dbm, 2),
            i_sample   = round(i_val, 4),
            q_sample   = round(q_val, 4),
            amplitude  = round(amp, 4),
            phase_deg  = round(phase, 2),
            freq_hz    = self._freq_hz,
            presence   = presence,
            range_m    = range_m,
            sensor_temp_c = temp_c,
            sensor_name= self.name,
            valid      = True,
            extra      = {k: v for k, v in obj.items()
                          if k not in ('i','q','pres','range','temp')},
        )

    def close(self):
        if self._ser:
            try: self._ser.close()
            except Exception: pass

    def capabilities(self) -> dict:
        c = super().capabilities()
        c.update({
            "has_iq":      True,
            "has_range":   True,
            "has_presence":True,
        })
        return c

# ══════════════════════════════════════════════════════════════════════════════
# DRIVER 4 — Infineon BGT60TR13C direct SPI (Raspberry Pi)
# ══════════════════════════════════════════════════════════════════════════════

class BGT60SPISensor(MMWaveSensor):
    """
    Infineon BGT60TR13C direct SPI on Raspberry Pi.
    Requires: pip install ifxradarsdk  (Infineon Python SDK)
    or:       pip install RPi.GPIO spidev

    If ifxradarsdk is not available, falls back to raw SPI
    register reads with manual frame parsing.
    """

    def __init__(self, args, clock):
        super().__init__(args, clock)
        self.name           = "bgt60_spi"
        self.description    = "Infineon BGT60TR13C direct SPI (Raspberry Pi)"
        self.freq_range_ghz = (57.0, 64.0)
        self._device        = None
        self._use_sdk       = False
        self._frame_queue   = deque(maxlen=32)

    def open(self) -> bool:
        # Try Infineon SDK first
        try:
            import ifxradarsdk
            from ifxradarsdk.fmcw import DeviceFmcw
            self._device  = DeviceFmcw()
            self._use_sdk = True
            print("[mmwave] BGT60 opened via Infineon ifxradarsdk")
            return True
        except ImportError:
            pass
        except Exception as e:
            print(f"[mmwave] ifxradarsdk open failed: {e}")

        # Fallback: raw spidev
        try:
            import spidev
            self._spi = spidev.SpiDev()
            self._spi.open(0, 0)   # bus 0, device 0
            self._spi.max_speed_hz = 50_000_000
            self._spi.mode = 0
            print("[mmwave] BGT60 opened via raw spidev")
            return True
        except Exception as e:
            print(f"[mmwave] spidev open failed: {e}")
            print("  Ensure SPI enabled: raspi-config → Interfaces → SPI")
            return False

    def read_sample(self) -> Optional[MMWaveSample]:
        wall_ns, mono_ns = self.clock.now()

        if self._use_sdk:
            try:
                import numpy as np
                frame = self._device.get_next_frame()
                # frame shape: (num_rx, num_chirps, num_samples)
                # Use first RX, first chirp
                chirp = frame[0][0]
                i_ch  = chirp.real
                q_ch  = chirp.imag
                amp   = float(np.mean(np.abs(chirp)))
                presence = amp > 50.0  # tune threshold per environment
                return MMWaveSample(
                    wall_ns    = wall_ns,
                    mono_ns    = mono_ns,
                    wall_iso   = self.clock.format_wall_ns(wall_ns),
                    power_raw  = amp,
                    power_dbm  = round(20*math.log10(amp/32768+1e-9), 2),
                    amplitude  = round(amp, 4),
                    freq_hz    = 60.5e9,
                    presence   = presence,
                    sensor_name= self.name,
                    valid      = True,
                )
            except Exception as e:
                print(f"[mmwave] BGT60 SDK read error: {e}")
                return None
        else:
            # Raw SPI — read ADC output registers
            # BGT60TR13C register map: 0x00=status, 0x01/0x02=I/Q ADC
            try:
                resp = self._spi.xfer2([0x00, 0x00, 0x00, 0x00])
                raw  = (resp[1] << 8) | resp[2]
                amp  = float(raw)
                return MMWaveSample(
                    wall_ns    = wall_ns,
                    mono_ns    = mono_ns,
                    wall_iso   = self.clock.format_wall_ns(wall_ns),
                    power_raw  = amp,
                    adc_counts = raw,
                    freq_hz    = 60.5e9,
                    sensor_name= self.name,
                    valid      = True,
                )
            except Exception:
                return None

    def close(self):
        try:
            if self._use_sdk and self._device:
                self._device.close()
            elif hasattr(self, '_spi'):
                self._spi.close()
        except Exception: pass

    def capabilities(self) -> dict:
        c = super().capabilities()
        c.update({"has_iq": True, "has_range": True, "has_presence": True})
        return c

# ══════════════════════════════════════════════════════════════════════════════
# DRIVER 5 — Ka/Ku LNB downconverter + RTL-SDR
# ══════════════════════════════════════════════════════════════════════════════

class LNBRTLSDRSensor(MMWaveSensor):
    """
    Satellite LNB (Low-Noise Block downconverter) feeding RTL-SDR.

    Ku-band LNB:  10.7–12.75 GHz input, 950–2150 MHz IF output
    Ka-band LNB:  18.3–20.2 GHz input, 950–2150 MHz IF output

    The LNB shifts the received frequency down by the LO frequency:
      IF = RF - LO
      RF = IF + LO

    So if LO = 9750 MHz and RTL-SDR tunes to 1000 MHz:
      You are receiving 9750 + 1000 = 10750 MHz = 10.75 GHz

    This covers:
      E-band subharmonics (1/6 of 71 GHz = ~11.8 GHz in Ku range)
      Ka-band satellite downlinks at 20 GHz
      1/3 subharmonic of 60 GHz = 20 GHz (in Ka range)
      Point-to-point microwave links at 11–12 GHz

    Hardware:
      LNB → coax → Bias-T (to inject 12–18V LNB supply) → RTL-SDR
      OR
      LNB → powered splitter/injector → RTL-SDR

    Requires: pip install pyrtlsdr
    """

    def __init__(self, args, clock):
        super().__init__(args, clock)
        self.name           = "lnb_rtlsdr"
        self.description    = "Ka/Ku LNB downconverter + RTL-SDR"
        self.freq_range_ghz = (10.7, 20.2)   # depends on LNB type
        self._sdr           = None
        self._lo_hz         = getattr(args, 'lnb_lo', 9750) * 1e6
        self._if_hz         = getattr(args, 'rtl_freq', 1000) * 1e6
        self._sample_rate   = 2_400_000
        self._gain          = getattr(args, 'rtl_gain', 40)
        self._latest        = None
        self._lock          = threading.Lock()
        self._thread        = None
        self._stop          = threading.Event()

    @property
    def rf_freq_hz(self):
        return self._lo_hz + self._if_hz

    def open(self) -> bool:
        try:
            from rtlsdr import RtlSdr
            self._sdr = RtlSdr()
            self._sdr.sample_rate = self._sample_rate
            self._sdr.center_freq = self._if_hz
            self._sdr.gain        = self._gain
            print(f"[mmwave] RTL-SDR opened")
            print(f"  LO:       {self._lo_hz/1e6:.1f} MHz")
            print(f"  IF:       {self._if_hz/1e6:.1f} MHz")
            print(f"  RF:       {self.rf_freq_hz/1e9:.4f} GHz")
            # Update freq range based on LNB LO
            lo_ghz = self._lo_hz / 1e9
            self.freq_range_ghz = (lo_ghz + 0.95, lo_ghz + 2.15)
            self._thread = threading.Thread(
                target=self._capture_loop, daemon=True, name="LNB-RTL"
            )
            self._thread.start()
            return True
        except ImportError:
            print("[mmwave] pyrtlsdr not installed: pip install pyrtlsdr")
            return False
        except Exception as e:
            print(f"[mmwave] RTL-SDR open failed: {e}")
            return False

    def _capture_loop(self):
        import numpy as np
        FFT_SIZE = 1024
        while not self._stop.is_set():
            try:
                samples = self._sdr.read_samples(FFT_SIZE)
                spec    = np.fft.fftshift(np.abs(np.fft.fft(samples))**2)
                power   = float(np.mean(spec))
                dbfs    = 10 * math.log10(power / (32767**2) + 1e-12)
                wall_ns, mono_ns = self.clock.now()
                s = MMWaveSample(
                    wall_ns    = wall_ns,
                    mono_ns    = mono_ns,
                    wall_iso   = self.clock.format_wall_ns(wall_ns),
                    power_raw  = power,
                    power_dbm  = round(dbfs, 2),
                    freq_hz    = self.rf_freq_hz,
                    freq_lo_hz = self._lo_hz,
                    freq_if_hz = self._if_hz,
                    sensor_name= self.name,
                    valid      = True,
                )
                with self._lock:
                    self._latest = s
            except Exception as e:
                time.sleep(0.1)

    def read_sample(self) -> Optional[MMWaveSample]:
        time.sleep(0.02)
        with self._lock:
            s = self._latest
            self._latest = None
        return s

    def close(self):
        self._stop.set()
        if self._thread: self._thread.join(timeout=3)
        try:
            if self._sdr: self._sdr.close()
        except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
# DRIVER 6 — FS-5000 GM tube audio (Geiger as mmWave proxy)
# ══════════════════════════════════════════════════════════════════════════════

class GeigerProxySensor(MMWaveSensor):
    """
    Bosean FS-5000 Geiger-Müller tube audio channel as broadband
    mmWave EM aperture — the same approach used in your existing
    dual-aperture architecture.

    This driver plugs the GM tube audio pulse stream into the
    mmwave_sensor.py framework so it shares the same session
    header, anomaly engine, and ClockAnchor epoch.

    Pulse rate above baseline = EM energy in band.
    Temporal correlation with SDR events = direction inference.

    Hardware:
      FS-5000 headphone jack → USB audio adapter → PC
    """

    CHUNK       = 256
    RATES       = [48000, 44100]
    REFRACTORY  = int(3e6)  # 3ms in ns

    def __init__(self, args, clock):
        super().__init__(args, clock)
        self.name           = "geiger_proxy"
        self.description    = "FS-5000 GM tube audio channel (broadband EM aperture)"
        self.freq_range_ghz = (0.0, 100.0)   # broadband, no frequency resolution
        self._pa            = None
        self._stream        = None
        self._threshold     = getattr(args, 'threshold', 0.05)
        self._dev_index     = getattr(args, 'audio_device', None)
        self._last_pulse_ns = 0
        self._pulse_count   = 0
        self._latest        = None
        self._baseline_rate = None
        self._rate_window   = deque(maxlen=60)  # 60-second sliding window
        self._lock          = threading.Lock()

    def open(self) -> bool:
        try:
            import pyaudio
            self._pa = pyaudio.PyAudio()
        except ImportError:
            print("[mmwave] pyaudio not installed: pip install pyaudio")
            return False

        def callback(in_data, frame_count, time_info, status):
            import struct
            samples = struct.unpack_from(f'{frame_count}f', in_data)
            wall_ns, mono_ns = self.clock.now()
            for amp in (abs(s) for s in samples):
                if amp >= self._threshold:
                    if (wall_ns - self._last_pulse_ns) >= self.REFRACTORY:
                        self._last_pulse_ns = wall_ns
                        self._pulse_count  += 1
                        self._rate_window.append(wall_ns)
                        # Pulse rate in last second
                        cutoff   = wall_ns - int(1e9)
                        rate_1s  = sum(1 for t in self._rate_window if t >= cutoff)
                        baseline = self._baseline_rate or 1.0
                        excess   = rate_1s / baseline if baseline > 0 else rate_1s
                        s = MMWaveSample(
                            wall_ns    = wall_ns,
                            mono_ns    = mono_ns,
                            wall_iso   = self.clock.format_wall_ns(wall_ns),
                            power_raw  = amp,
                            amplitude  = amp,
                            sensor_name= self.name,
                            presence   = excess > 2.0,
                            valid      = True,
                            extra      = {
                                "pulse_count":   self._pulse_count,
                                "rate_1s":       rate_1s,
                                "baseline_rate": round(baseline, 3),
                                "excess_factor": round(excess, 3),
                            },
                        )
                        import pyaudio
                        with self._lock:
                            self._latest = s
            import pyaudio
            return (None, pyaudio.paContinue)

        import pyaudio
        for rate in self.RATES:
            try:
                self._stream = self._pa.open(
                    format             = pyaudio.paFloat32,
                    channels           = 1,
                    rate               = rate,
                    input              = True,
                    input_device_index = self._dev_index,
                    frames_per_buffer  = self.CHUNK,
                    stream_callback    = callback,
                )
                break
            except Exception:
                continue

        if not self._stream:
            print("[mmwave] Geiger proxy audio open failed.")
            return False

        self._stream.start_stream()
        print(f"[mmwave] Geiger proxy audio opened")
        print(f"  Establishing 30s baseline pulse rate...")
        # Collect baseline for 30 seconds
        threading.Thread(target=self._calibrate_baseline,
                         daemon=True).start()
        return True

    def _calibrate_baseline(self):
        time.sleep(30)
        if self._rate_window:
            window_ns = int(30e9)
            now_ns = time.time_ns()
            recent = [t for t in self._rate_window
                      if now_ns - t <= window_ns]
            self._baseline_rate = len(recent) / 30.0
            print(f"[mmwave] Geiger baseline: {self._baseline_rate:.2f} pulses/sec")

    def read_sample(self) -> Optional[MMWaveSample]:
        time.sleep(0.01)
        with self._lock:
            s = self._latest
            self._latest = None
        return s

    def close(self):
        try:
            if self._stream: self._stream.stop_stream(); self._stream.close()
            if self._pa:     self._pa.terminate()
        except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
# DRIVER 7 — Dummy / synthetic test signal
# ══════════════════════════════════════════════════════════════════════════════

class DummySensor(MMWaveSensor):
    """
    Synthetic test signal. No hardware required.
    Generates a simulated 60 GHz presence event every 5 seconds
    with Gaussian noise baseline.
    Use to test the pipeline without any hardware connected.
    """

    def __init__(self, args, clock):
        super().__init__(args, clock)
        self.name           = "dummy"
        self.description    = "Synthetic test signal (no hardware)"
        self.freq_range_ghz = (57.0, 64.0)
        self._seq           = 0
        self._start_ns      = None

    def open(self) -> bool:
        self._start_ns = time.time_ns()
        print("[mmwave] Dummy sensor started — synthetic 60 GHz test signal")
        print("  Event pattern: baseline noise + burst every 5 seconds")
        return True

    def read_sample(self) -> Optional[MMWaveSample]:
        time.sleep(0.05)   # 20 Hz sample rate
        wall_ns, mono_ns = self.clock.now()
        self._seq += 1

        # Noise baseline
        import random
        elapsed_s  = (wall_ns - self._start_ns) / 1e9
        base_power = 0.008 + random.gauss(0, 0.002)

        # Synthetic event every 5 seconds, 500ms duration
        event_phase = elapsed_s % 5.0
        in_event    = 0.0 <= event_phase <= 0.5
        if in_event:
            power = base_power + 0.15 + random.gauss(0, 0.01)
        else:
            power = max(0.001, base_power)

        dbm = 20 * math.log10(power + 1e-9) - 20.0

        return MMWaveSample(
            wall_ns    = wall_ns,
            mono_ns    = mono_ns,
            wall_iso   = self.clock.format_wall_ns(wall_ns),
            power_raw  = round(power, 6),
            power_dbm  = round(dbm, 2),
            freq_hz    = 60.5e9,
            presence   = in_event,
            sensor_name= self.name,
            valid      = True,
            extra      = {
                "seq":       self._seq,
                "elapsed_s": round(elapsed_s, 3),
                "synthetic": True,
            },
        )

    def close(self):
        pass

# ══════════════════════════════════════════════════════════════════════════════
# SENSOR REGISTRY — register new drivers here
# ══════════════════════════════════════════════════════════════════════════════

SENSOR_REGISTRY: Dict[str, type] = {
    "schottky_serial": SchottkySerialSensor,
    "schottky_audio":  SchottkyAudioSensor,
    "bgt60_serial":    BGT60SerialSensor,
    "bgt60_spi":       BGT60SPISensor,
    "lnb_rtlsdr":      LNBRTLSDRSensor,
    "geiger_proxy":    GeigerProxySensor,
    "dummy":           DummySensor,
}

# ══════════════════════════════════════════════════════════════════════════════
# CLOCKANCHOR
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

# ══════════════════════════════════════════════════════════════════════════════
# GZIPLOG + LIVEMIRROR
# ══════════════════════════════════════════════════════════════════════════════

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
# ANOMALY ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class MMWaveAnomalyEngine:
    """
    Universal anomaly engine — works with any sensor driver output.
    Classifiers:
      PRESENCE       — power/presence above threshold
      BURST          — sudden power increase > burst_db above rolling mean
      PERSISTENCE    — signal present for > persist_s continuously
      RATE_SPIKE     — pulse rate above baseline (Geiger proxy)
      SATURATION     — sensor saturated (ADC clipped)
    """

    def __init__(self, clock, log, mirror,
                 threshold=0.05, burst_db=10.0, persist_s=5.0):
        self.clock      = clock
        self.log        = log
        self.mirror     = mirror
        self.threshold  = threshold
        self.burst_db   = burst_db
        self.persist_ns = int(persist_s * 1e9)

        self._history   = deque(maxlen=200)
        self._above_since_ns = None
        self._seq       = 0
        self.counts     = defaultdict(int)

    def feed(self, sample: MMWaveSample):
        if not sample.valid:
            return

        self._history.append(sample)

        anomalies = []

        # Rolling mean power from last 20 samples
        recent = list(self._history)[-20:]
        mean_power = sum(s.power_raw for s in recent) / len(recent) \
                     if recent else sample.power_raw

        # PRESENCE
        is_present = (
            (sample.presence is True) or
            (sample.power_raw > self.threshold) or
            (sample.power_dbm is not None and sample.power_dbm > -60)
        )

        # SATURATION
        if sample.saturated:
            anomalies.append(self._build(
                "SATURATION", sample,
                "Sensor ADC saturated — source may be extremely close "
                "or sensor gain too high.",
                "HIGH"
            ))

        # BURST — power spike above rolling mean
        if mean_power > 0:
            excess_db = 20 * math.log10(
                (sample.power_raw + 1e-12) / (mean_power + 1e-12)
            )
            if excess_db >= self.burst_db:
                anomalies.append(self._build(
                    "BURST", sample,
                    f"Power burst {excess_db:.1f} dB above rolling mean. "
                    f"Consistent with pulsed 60 GHz directed beam.",
                    "CRITICAL"
                ))

        # PERSISTENCE — continuous presence
        if is_present:
            if self._above_since_ns is None:
                self._above_since_ns = sample.wall_ns
            else:
                duration_ns = sample.wall_ns - self._above_since_ns
                if duration_ns >= self.persist_ns:
                    anomalies.append(self._build(
                        "PERSISTENCE", sample,
                        f"Continuous mmWave presence for "
                        f"{duration_ns/1e9:.1f}s. "
                        f"Parked/directed source indicated.",
                        "HIGH",
                        extra={"duration_s": round(duration_ns/1e9, 2)}
                    ))
        else:
            self._above_since_ns = None

        # PRESENCE event (single sample)
        if is_present and not sample.saturated:
            anomalies.append(self._build(
                "PRESENCE", sample,
                f"mmWave energy detected: power={sample.power_raw:.4f} "
                f"dbm={sample.power_dbm} "
                f"freq={sample.freq_hz/1e9:.3f}GHz "
                f"range={sample.range_m}m",
                "MEDIUM"
            ))

        # RATE_SPIKE (Geiger proxy)
        if sample.extra.get("excess_factor", 0) > 2.0:
            anomalies.append(self._build(
                "RATE_SPIKE", sample,
                f"GM tube pulse rate {sample.extra['rate_1s']}/s is "
                f"{sample.extra['excess_factor']:.1f}x baseline "
                f"({sample.extra.get('baseline_rate',0):.2f}/s). "
                f"Broadband EM energy increase detected.",
                "HIGH"
            ))

        for a in anomalies:
            self.log.write(a)
            self.mirror.write(a)
            sev = a.get("severity", "")
            if sev in ("CRITICAL", "HIGH"):
                tag = "!!! CRITICAL !!!" if sev == "CRITICAL" \
                      else "***   HIGH   ***"
                print(
                    f"\n  [{sample.wall_iso[11:23]}]  {tag}  "
                    f"MMWAVE_{a['event']}  "
                    f"{a.get('detail','')[:80]}",
                    flush=True
                )

    def _build(self, event, sample, detail, severity, extra=None):
        self._seq += 1
        self.counts[event] += 1
        rec = {
            "type":       f"MMWAVE_{event}",
            "_stream":    "mmwave",
            "seq":        self._seq,
            "severity":   severity,
            "event":      event,
            "wall_ns":    sample.wall_ns,
            "wall_iso":   sample.wall_iso,
            "sensor":     sample.sensor_name,
            "power_raw":  sample.power_raw,
            "power_dbm":  sample.power_dbm,
            "freq_ghz":   round(sample.freq_hz/1e9, 4)
                          if sample.freq_hz else None,
            "presence":   sample.presence,
            "range_m":    sample.range_m,
            "detail":     detail,
        }
        if extra:
            rec.update(extra)
        return rec

# ══════════════════════════════════════════════════════════════════════════════
# UTILITY — list audio devices
# ══════════════════════════════════════════════════════════════════════════════

def list_audio_devices():
    try:
        import pyaudio
        pa = pyaudio.PyAudio()
        print(f"\n  {'Idx':<5} {'Name':<44} {'Ch':<4} {'Rate'}")
        print(f"  {'-'*5} {'-'*44} {'-'*4} {'-'*8}")
        for i in range(pa.get_device_count()):
            info = pa.get_device_info_by_index(i)
            if info['maxInputChannels'] < 1: continue
            print(f"  {i:<5} {info['name'][:43]:<44} "
                  f"{int(info['maxInputChannels']):<4} "
                  f"{int(info['defaultSampleRate'])}")
        pa.terminate()
    except ImportError:
        print("pyaudio not installed: pip install pyaudio")

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

STAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def main():
    ap = argparse.ArgumentParser(
        description="CTW mmWave Forensic Sensor Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--sensor",        default="dummy",
                    choices=list(SENSOR_REGISTRY.keys()),
                    help="Sensor driver to use (default: dummy)")
    ap.add_argument("--list-sensors",  action="store_true",
                    help="List all available sensor drivers and exit")
    ap.add_argument("--list-audio",    action="store_true",
                    help="List audio input devices and exit")
    ap.add_argument("--out",           default=".", metavar="DIR")

    # Serial / SPI options
    ap.add_argument("--port",          default="COM5",
                    help="Serial port for serial-based sensors (default: COM5)")

    # Audio options
    ap.add_argument("--audio-device",  type=int, default=None, metavar="N",
                    help="Audio input device index (see --list-audio)")
    ap.add_argument("--threshold",     type=float, default=0.05,
                    help="Audio amplitude threshold (default: 0.05)")

    # Calibration
    ap.add_argument("--cal-slope",     type=float, default=20.0,
                    help="Schottky calibration slope dB/decade (default: 20)")
    ap.add_argument("--cal-intercept", type=float, default=-50.0,
                    help="Schottky calibration intercept dBm (default: -50)")
    ap.add_argument("--freq-hz",       type=float, default=60.5e9,
                    help="Sensor center frequency Hz (default: 60.5e9)")

    # LNB / RTL-SDR options
    ap.add_argument("--lnb-lo",        type=float, default=9750.0,
                    help="LNB local oscillator MHz (default: 9750)")
    ap.add_argument("--rtl-freq",      type=float, default=1000.0,
                    help="RTL-SDR IF center MHz (default: 1000)")
    ap.add_argument("--rtl-gain",      type=float, default=40.0,
                    help="RTL-SDR gain dB (default: 40)")

    # Anomaly engine options
    ap.add_argument("--burst-db",      type=float, default=10.0,
                    help="Burst detection threshold dB above mean (default: 10)")
    ap.add_argument("--persist-s",     type=float, default=5.0,
                    help="Persistence alarm threshold seconds (default: 5)")

    args = ap.parse_args()

    if args.list_sensors:
        print(f"\n  {'Name':<20} {'Freq Range':<22} Description")
        print(f"  {'-'*20} {'-'*22} {'-'*40}")
        for name, cls in SENSOR_REGISTRY.items():
            dummy_clock = type('C', (), {
                'now': lambda s: (0,0),
                'format_wall_ns': lambda s,x: '',
                'session_wall_ns': 0,
                'session_mono_ns': 0,
                'session_wall_utc': '',
            })()
            inst = cls(args, dummy_clock)
            lo, hi = inst.freq_range_ghz
            print(f"  {name:<20} {lo:.1f}–{hi:.1f} GHz{'':<10} "
                  f"{inst.description}")
        print()
        return

    if args.list_audio:
        list_audio_devices()
        return

    out_dir     = os.path.abspath(args.out)
    runtime_dir = os.path.join(out_dir, "runtime")
    os.makedirs(out_dir,     exist_ok=True)
    os.makedirs(runtime_dir, exist_ok=True)

    from ntp_web import get_ntp_info
    print("Querying web time reference...", flush=True)
    ntp_info = get_ntp_info()
    print(f"  Source : {ntp_info['ntp_source']}")
    print(f"  Offset : {ntp_info.get('ntp_offset_ms','?')} ms")

    clock  = ClockAnchor()

    # Instantiate selected sensor
    SensorClass = SENSOR_REGISTRY[args.sensor]
    sensor      = SensorClass(args, clock)
    caps        = sensor.capabilities()

    header = {
        "type":             "mmwave_session_header",
        "session_wall_utc": clock.session_wall_utc,
        "session_wall_ns":  clock.session_wall_ns,
        "session_mono_ns":  clock.session_mono_ns,
        "ntp_source":       ntp_info["ntp_source"],
        "ntp_offset_ms":    ntp_info.get("ntp_offset_ms"),
        "sensor":           args.sensor,
        "sensor_caps":      caps,
        "freq_range_ghz":   caps["freq_range_ghz"],
        "stamp":            STAMP,
        "args": {
            "port":          args.port,
            "audio_device":  args.audio_device,
            "threshold":     args.threshold,
            "freq_hz":       args.freq_hz,
            "lnb_lo_mhz":   args.lnb_lo,
            "burst_db":      args.burst_db,
            "persist_s":     args.persist_s,
        },
    }

    gz_path   = os.path.join(out_dir,     f"mmwave_{STAMP}.jsonl.gz")
    live_path = os.path.join(runtime_dir, "mmwave_live.jsonl")

    log    = GzipLog(gz_path, header)
    mirror = LiveMirror(live_path)
    mirror.write(header)

    engine = MMWaveAnomalyEngine(
        clock     = clock,
        log       = log,
        mirror    = mirror,
        threshold = args.threshold,
        burst_db  = args.burst_db,
        persist_s = args.persist_s,
    )

    print(f"\n{'='*68}")
    print(f"  CTW mmWave FORENSIC SENSOR FRAMEWORK")
    print(f"{'='*68}")
    print(f"  Sensor          : {args.sensor}")
    print(f"  Description     : {caps['description']}")
    print(f"  Freq range      : {caps['freq_range_ghz'][0]}–"
          f"{caps['freq_range_ghz'][1]} GHz")
    print(f"  Has IQ          : {caps.get('has_iq', False)}")
    print(f"  Has range       : {caps.get('has_range', False)}")
    print(f"  Has presence    : {caps.get('has_presence', False)}")
    print(f"  Burst threshold : {args.burst_db} dB above mean")
    print(f"  Persist alarm   : {args.persist_s} s")
    print(f"  Log             : mmwave_{STAMP}.jsonl.gz")
    print(f"  Live mirror     : {live_path}")
    print(f"  Ctrl+C to stop")
    print(f"{'='*68}\n")

    # Open sensor
    if not sensor.open():
        print("[mmwave] Sensor failed to open. Exiting.")
        sys.exit(1)

    sample_count = 0
    last_status  = time.time()

    try:
        while True:
            sample = sensor.read_sample()
            if sample is None:
                continue

            sample_count += 1

            # Write raw sample to log
            rec = {"type": "MMWAVE_SAMPLE", "_stream": "mmwave"}
            rec.update(sample.to_dict())
            log.write(rec)

            # Run anomaly engine
            engine.feed(sample)

            # Console heartbeat every 5 seconds
            now = time.time()
            if now - last_status >= 5.0:
                last_status = now
                pwr_str = (f"{sample.power_dbm:.1f} dBm"
                           if sample.power_dbm is not None
                           else f"{sample.power_raw:.5f}")
                freq_str = (f"{sample.freq_hz/1e9:.3f} GHz"
                            if sample.freq_hz else "?")
                pres_str = " PRESENT" if sample.presence else ""
                print(
                    f"\r  [{sample.wall_iso[11:23]}]  "
                    f"{freq_str}  {pwr_str}"
                    f"  n={sample_count}"
                    f"  A={sum(engine.counts.values())}"
                    f"{pres_str}   ",
                    end='', flush=True
                )

    except KeyboardInterrupt:
        pass
    finally:
        sensor.close()

        wall_ns, mono_ns = clock.now()
        end_rec = {
            "type":         "session_end",
            "_stream":      "mmwave",
            "wall_ns":      wall_ns,
            "wall_iso":     clock.format_wall_ns(wall_ns),
            "mono_ns":      mono_ns,
            "sample_count": sample_count,
            "anomalies":    dict(engine.counts),
            "total_anomalies": sum(engine.counts.values()),
        }
        log.write(end_rec)
        mirror.write(end_rec)
        log.close()

        print(f"\n\nmmWave session complete.")
        print(f"  Samples   : {sample_count}")
        for k, v in engine.counts.items():
            print(f"  {k:<20} : {v}")
        print(f"  Log       : {gz_path}")


if __name__ == "__main__":
    main()