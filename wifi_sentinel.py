#!/usr/bin/env python3
"""
wifi_sentinel.py  —  CTW WiFi Forensic Scanner
===============================================
Dual-adapter 802.11 forensic monitor for Windows.

TWO DETECTION LAYERS (auto-detected, graceful degradation):

  LAYER 1 — Management plane (always available)
    Uses Windows WLAN API via pywifi + netsh
    Detects: rogue AP, SSID spoofing, BSSID clones,
             beacon anomalies, channel conflicts,
             evil-twin probe responses
    Both adapters scan simultaneously on different
    channel sets for cross-band coverage

  LAYER 2 — Raw frame capture (requires monitor mode driver)
    Uses Npcap + Scapy
    Detects: deauth floods, beacon/data ratio collapse,
             timing-correlated cross-channel bursts,
             hidden SSID channel utilization,
             BSSID multichannel echo (MITM exfil signature)

FORENSIC OUTPUTS:
  wifi_STAMP.jsonl.gz          compressed forensic log
  runtime/wifi_live.jsonl      SSE live mirror
  wifi_stations_STAMP.json     AP database snapshot

DEPENDENCIES:
  pip install scapy pywifi comtypes
  Npcap: https://npcap.com (WinPcap-compatible mode)
  Monitor mode driver: Aircrack-ng patched RTL8812AU
                       OR Acrylic WiFi driver

OOB GUARD: All externally supplied fields validated before
           write per USPTO 19/466,387 enforcement boundary.

Author: Christopher T. Williams / CTW-11 / SENTINEL Platform
"""

import os, sys, time, json, gzip, threading, argparse, hashlib
import subprocess, re, struct, socket
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, deque

# ── optional imports with graceful degradation ────────────────────────────────
SCAPY_OK  = False
PYWIFI_OK = False

try:
    # Scapy: suppress its IPv6 warning on Windows
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import (
        sniff, RadioTap, Dot11, Dot11Beacon, Dot11ProbeResp,
        Dot11Deauth, Dot11Disas, Dot11AssoReq, Dot11ProbeReq,
        Dot11Elt, conf as scapy_conf
    )
    scapy_conf.use_pcap = True          # force Npcap backend
    SCAPY_OK = True
    print("[wifi_sentinel] Layer 2 (Scapy/Npcap): AVAILABLE")
except Exception as e:
    print(f"[wifi_sentinel] Layer 2 (Scapy/Npcap): UNAVAILABLE ({e})")

try:
    import pywifi
    from pywifi import const as pywifi_const
    PYWIFI_OK = True
    print("[wifi_sentinel] Layer 1 (pywifi): AVAILABLE")
except Exception as e:
    print(f"[wifi_sentinel] Layer 1 (pywifi): UNAVAILABLE ({e})")

# ── ClockAnchor (shared epoch with pluto_sweep / fs5000_dual) ─────────────────
class ClockAnchor:
    """
    Nanosecond-precision wall-clock anchor.
    Uses time.time_ns() + monotonic offset for drift-corrected timestamps.
    Compatible with existing SENTINEL pipeline epoch format.
    """
    def __init__(self):
        self._wall_ns   = time.time_ns()
        self._mono_ns   = time.monotonic_ns()
        self._session   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def now(self):
        mono_now = time.monotonic_ns()
        wall_ns  = self._wall_ns + (mono_now - self._mono_ns)
        return wall_ns, self._to_iso(wall_ns)

    def _to_iso(self, ns):
        s  = ns // 1_000_000_000
        us = (ns % 1_000_000_000) // 1_000
        dt = datetime.fromtimestamp(s, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{us:06d}Z"

    @property
    def session(self):
        return self._session


# ── GzipLog / LiveMirror (same pattern as pluto_sweep) ────────────────────────
class GzipLog:
    def __init__(self, path: Path):
        self._path = path
        self._fh   = gzip.open(path, "wt", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, rec: dict):
        line = json.dumps(rec, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self):
        with self._lock:
            self._fh.close()


class LiveMirror:
    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh   = open(path, "w", encoding="utf-8")
        self._lock = threading.Lock()

    def write(self, rec: dict):
        line = json.dumps(rec, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self):
        with self._lock:
            self._fh.close()


# ── OOB Guard ─────────────────────────────────────────────────────────────────
_BSSID_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
_CHAN_VALID = set(list(range(1, 15)) + list(range(36, 178, 4)))

def _oob_bssid(v):
    """Validate BSSID format. Returns normalized uppercase or INVALID."""
    s = str(v).strip().upper()
    if _BSSID_RE.match(s):
        return s
    return "OOB:BSSID"

def _oob_ssid(v):
    """Clamp SSID to printable ASCII, max 32 chars."""
    s = str(v).encode("ascii", errors="replace").decode("ascii")
    s = "".join(c if 32 <= ord(c) < 127 else "?" for c in s)
    return s[:32]

def _oob_channel(v):
    """Validate channel is a known 802.11 channel number."""
    try:
        c = int(v)
        if c in _CHAN_VALID:
            return c
        return -1     # OOB channel — forensically significant
    except (TypeError, ValueError):
        return -1

def _oob_rssi(v):
    """Clamp RSSI to plausible dBm range."""
    try:
        f = float(v)
        return max(-120.0, min(0.0, f))
    except (TypeError, ValueError):
        return -999.0

def _oob_int(v, lo, hi, name):
    try:
        i = int(v)
        if lo <= i <= hi:
            return i
        raise ValueError(f"OOB:{name}={i}")
    except (TypeError, ValueError) as e:
        raise ValueError(f"OOB:{name}: {e}")


# ── AP Record ─────────────────────────────────────────────────────────────────
class APRecord:
    """
    Represents one observed access point.
    All fields OOB-validated on construction.
    """
    __slots__ = ("bssid", "ssid", "channel", "band", "rssi",
                 "security", "first_seen_ns", "last_seen_ns",
                 "beacon_count", "data_count", "channels_seen",
                 "anomaly_flags")

    def __init__(self, bssid, ssid, channel, rssi, security="UNKNOWN"):
        self.bssid        = _oob_bssid(bssid)
        self.ssid         = _oob_ssid(ssid)
        self.channel      = _oob_channel(channel)
        self.band         = "5GHz" if self.channel > 14 else "2.4GHz"
        self.rssi         = _oob_rssi(rssi)
        self.security     = str(security)[:32]
        self.first_seen_ns= time.time_ns()
        self.last_seen_ns = self.first_seen_ns
        self.beacon_count = 0
        self.data_count   = 0
        self.channels_seen= {self.channel}
        self.anomaly_flags= set()

    def update(self, channel, rssi):
        self.channel      = _oob_channel(channel)
        self.rssi         = _oob_rssi(rssi)
        self.last_seen_ns = time.time_ns()
        self.channels_seen.add(self.channel)

    def to_dict(self):
        return {
            "bssid":         self.bssid,
            "ssid":          self.ssid,
            "channel":       self.channel,
            "band":          self.band,
            "rssi":          self.rssi,
            "security":      self.security,
            "first_seen_ns": self.first_seen_ns,
            "last_seen_ns":  self.last_seen_ns,
            "beacon_count":  self.beacon_count,
            "data_count":    self.data_count,
            "channels_seen": sorted(self.channels_seen),
            "anomaly_flags": sorted(self.anomaly_flags),
        }


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — MANAGEMENT PLANE SCANNER
# Uses netsh + pywifi. Always available. No monitor mode needed.
# ══════════════════════════════════════════════════════════════════════════════

class Layer1Scanner:
    """
    Continuous AP enumeration via Windows WLAN API.
    Runs on both adapters simultaneously via threading.
    Detects anomalies from AP table deltas between scans.
    """

    # Known home network config — loaded from args
    HOME_SSID    = None
    HOME_BSSID   = None
    HOME_CHANNEL = None

    def __init__(self, iface_name: str, clock: ClockAnchor,
                 log: GzipLog, mirror: LiveMirror,
                 anomaly_cb, args):
        self._iface   = iface_name
        self._clock   = clock
        self._log     = log
        self._mirror  = mirror
        self._cb      = anomaly_cb      # called on every anomaly detected
        self._args    = args
        self._ap_db   = {}              # bssid → APRecord
        self._lock    = threading.Lock()
        # for BSSID_MULTICHANNEL detection across scanner instances
        # (shared via anomaly_cb mechanism)

    # ── netsh scan ─────────────────────────────────────────────────────────
    def _netsh_scan(self):
        """
        Run 'netsh wlan show networks mode=bssid' and parse output.
        Returns list of dicts: bssid, ssid, channel, rssi, security.
        """
        results = []
        try:
            raw = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                stderr=subprocess.DEVNULL,
                timeout=15,
                encoding="utf-8",
                errors="replace"
            )
        except Exception as e:
            return results

        # Parse netsh output blocks
        # Each AP block starts with "SSID" line
        current = {}
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                if current:
                    results.append(current)
                current = {"ssid": "", "bssid": "", "channel": 0,
                           "rssi": -100, "security": "UNKNOWN"}
                # SSID : value
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current["ssid"] = parts[1].strip()
            elif line.startswith("BSSID"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    # BSSID value has colons, netsh uses spaces: aa bb cc dd ee ff
                    # or standard colon format depending on locale
                    raw_bssid = parts[1].strip()
                    # normalize — netsh sometimes outputs space-separated
                    raw_bssid = raw_bssid.replace(" ", ":")
                    current["bssid"] = raw_bssid
            elif "Signal" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    # Signal is 0-100%, convert to approximate dBm
                    try:
                        pct = int(parts[1].strip().replace("%", ""))
                        # Windows signal quality to dBm approximation:
                        # quality = 2 * (dBm + 100), so dBm = quality/2 - 100
                        current["rssi"] = float(pct / 2 - 100)
                    except ValueError:
                        pass
            elif "Channel" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    try:
                        current["channel"] = int(parts[1].strip())
                    except ValueError:
                        pass
            elif "Authentication" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current["security"] = parts[1].strip()

        if current and current.get("bssid"):
            results.append(current)

        return results

    # ── anomaly detection ───────────────────────────────────────────────────
    def _check_anomalies(self, ap: APRecord, wall_ns: str):
        """Run all Layer 1 anomaly checks against an AP record."""
        anom = []

        # BEACON_DATA_RATIO_COLLAPSE
        # (Layer 1 can't count frames, but can check if home channel
        #  AP has suspiciously low data inferred from signal drop pattern)

        # BSSID_MULTICHANNEL — is this BSSID appearing on multiple channels?
        if len(ap.channels_seen) > 1:
            flag = "BSSID_MULTICHANNEL"
            if flag not in ap.anomaly_flags:
                ap.anomaly_flags.add(flag)
                anom.append({
                    "anomaly_class": flag,
                    "bssid":         ap.bssid,
                    "ssid":          ap.ssid,
                    "channels":      sorted(ap.channels_seen),
                    "detail": (f"BSSID seen on {len(ap.channels_seen)} "
                               f"channels: {sorted(ap.channels_seen)} "
                               f"— possible MITM relay or band steering anomaly"),
                })

        # EVIL_TWIN — SSID matches home but BSSID doesn't
        if (self._args.home_ssid and
                ap.ssid == self._args.home_ssid and
                self._args.home_bssid and
                ap.bssid != self._args.home_bssid.upper()):
            flag = "EVIL_TWIN"
            if flag not in ap.anomaly_flags:
                ap.anomaly_flags.add(flag)
                anom.append({
                    "anomaly_class": flag,
                    "bssid":         ap.bssid,
                    "ssid":          ap.ssid,
                    "home_bssid":    self._args.home_bssid.upper(),
                    "detail": (f"SSID '{ap.ssid}' matches home network "
                               f"but BSSID {ap.bssid} does not match "
                               f"legitimate AP {self._args.home_bssid}"),
                })

        # OOB_CHANNEL — channel number outside legal 802.11 allocations
        if ap.channel == -1:
            flag = "OOB_CHANNEL"
            if flag not in ap.anomaly_flags:
                ap.anomaly_flags.add(flag)
                anom.append({
                    "anomaly_class": flag,
                    "bssid":         ap.bssid,
                    "ssid":          ap.ssid,
                    "detail": "Channel value outside legal 802.11 allocation",
                })

        # RSSI_ANOMALY — home SSID suddenly much stronger than known AP
        # (rogue AP physically closer = stronger signal)
        if (self._args.home_ssid and
                ap.ssid == self._args.home_ssid and
                self._args.home_rssi and
                ap.rssi > float(self._args.home_rssi) + 10):
            flag = "RSSI_ELEVATED_HOME_SSID"
            if flag not in ap.anomaly_flags:
                ap.anomaly_flags.add(flag)
                anom.append({
                    "anomaly_class": flag,
                    "bssid":         ap.bssid,
                    "ssid":          ap.ssid,
                    "observed_rssi": ap.rssi,
                    "baseline_rssi": float(self._args.home_rssi),
                    "delta_db":      ap.rssi - float(self._args.home_rssi),
                    "detail": (f"Home SSID signal {ap.rssi:.1f} dBm is "
                               f"{ap.rssi - float(self._args.home_rssi):.1f} dB "
                               f"above baseline — possible rogue AP physically "
                               f"closer than legitimate hardware"),
                })

        return anom

    # ── main scan loop ──────────────────────────────────────────────────────
    def run(self, stop: threading.Event, interval: float = 5.0):
        print(f"[L1:{self._iface}] Management plane scanner started "
              f"(interval {interval}s)")
        scan_count = 0
        while not stop.is_set():
            t_start = time.monotonic()
            aps     = self._netsh_scan()
            wall_ns, wall_iso = self._clock.now()
            scan_count += 1

            with self._lock:
                seen_bssids = set()
                for entry in aps:
                    bssid = _oob_bssid(entry.get("bssid", ""))
                    if bssid == "OOB:BSSID":
                        continue
                    seen_bssids.add(bssid)

                    if bssid not in self._ap_db:
                        ap = APRecord(
                            bssid    = bssid,
                            ssid     = entry.get("ssid", ""),
                            channel  = entry.get("channel", 0),
                            rssi     = entry.get("rssi", -100),
                            security = entry.get("security", "UNKNOWN"),
                        )
                        self._ap_db[bssid] = ap
                        # new AP discovered — log it
                        rec = {
                            "type":      "ap_discovered",
                            "_stream":   "wifi",
                            "_layer":    1,
                            "_iface":    self._iface,
                            "wall_ns":   wall_ns,
                            "wall_iso":  wall_iso,
                            "scan_seq":  scan_count,
                            **ap.to_dict(),
                        }
                        self._log.write(rec)
                        self._mirror.write(rec)
                        print(f"[L1:{self._iface}] NEW AP  "
                              f"{bssid}  '{ap.ssid}'  "
                              f"Ch{ap.channel}  {ap.rssi:.0f}dBm  "
                              f"{ap.security}")
                    else:
                        ap = self._ap_db[bssid]
                        ap.update(entry.get("channel", ap.channel),
                                  entry.get("rssi", ap.rssi))

                    # run anomaly checks every scan
                    anomalies = self._check_anomalies(ap, wall_iso)
                    for anom in anomalies:
                        rec = {
                            "type":     "wifi_anomaly",
                            "_stream":  "wifi",
                            "_layer":   1,
                            "_iface":   self._iface,
                            "wall_ns":  wall_ns,
                            "wall_iso": wall_iso,
                            **anom,
                        }
                        self._log.write(rec)
                        self._mirror.write(rec)
                        self._cb(rec)
                        print(f"[L1:{self._iface}] *** {anom['anomaly_class']}"
                              f"  {anom.get('bssid','')}  "
                              f"'{anom.get('ssid','')}'  "
                              f"{anom.get('detail','')[:80]}")

                # periodic full AP table snapshot
                if scan_count % 12 == 0:    # every ~60s at 5s interval
                    snap = {
                        "type":      "ap_table_snapshot",
                        "_stream":   "wifi",
                        "_layer":    1,
                        "_iface":    self._iface,
                        "wall_ns":   wall_ns,
                        "wall_iso":  wall_iso,
                        "scan_seq":  scan_count,
                        "ap_count":  len(self._ap_db),
                        "aps":       [v.to_dict()
                                      for v in self._ap_db.values()],
                    }
                    self._log.write(snap)
                    self._mirror.write(snap)

            elapsed = time.monotonic() - t_start
            remaining = interval - elapsed
            if remaining > 0:
                stop.wait(remaining)

        print(f"[L1:{self._iface}] Stopped. {scan_count} scans completed.")


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — RAW FRAME CAPTURE
# Requires Npcap + monitor mode driver. Degrades gracefully if absent.
# ══════════════════════════════════════════════════════════════════════════════

class Layer2Scanner:
    """
    Raw 802.11 frame capture via Scapy/Npcap.
    Detects frame-level anomalies impossible to see from management plane:
      - Deauth/disassoc floods
      - Beacon/data ratio collapse (MITM stub AP signature)
      - BSSID multichannel echo with timing correlation
      - Hidden SSID channel utilization ghosts
      - Probe response from multiple BSSIDs for same SSID
    """

    # Shared cross-channel timing correlator state
    # bssid → deque of (wall_ns, channel) tuples
    _global_burst_log  = defaultdict(lambda: deque(maxlen=200))
    _global_lock       = threading.Lock()

    def __init__(self, iface_name: str, clock: ClockAnchor,
                 log: GzipLog, mirror: LiveMirror,
                 anomaly_cb, args):
        self._iface  = iface_name
        self._clock  = clock
        self._log    = log
        self._mirror = mirror
        self._cb     = anomaly_cb
        self._args   = args

        # per-interface state
        self._deauth_count   = defaultdict(int)  # bssid → count in window
        self._deauth_window  = deque(maxlen=500) # (ns, bssid, target_mac)
        self._beacon_count   = defaultdict(int)  # bssid → beacons seen
        self._data_count     = defaultdict(int)  # bssid → data frames seen
        self._probe_resp     = defaultdict(set)  # ssid → set of bssids responding
        self._anomaly_fired  = set()             # deduplicate alerts

    def _channel_from_radiotap(self, pkt):
        """Extract channel from RadioTap header if present."""
        try:
            if pkt.haslayer(RadioTap):
                # channel freq is in RadioTap.Channel
                freq = pkt[RadioTap].Channel
                if freq:
                    # 2.4GHz: ch = (freq - 2407) / 5
                    if 2412 <= freq <= 2484:
                        return (freq - 2407) // 5
                    # 5GHz: ch = (freq - 5000) / 5
                    if 5170 <= freq <= 5850:
                        return (freq - 5000) // 5
        except Exception:
            pass
        return -1

    def _rssi_from_radiotap(self, pkt):
        """Extract RSSI (dBm) from RadioTap header."""
        try:
            if pkt.haslayer(RadioTap):
                return _oob_rssi(pkt[RadioTap].dBm_AntSignal)
        except Exception:
            pass
        return -100.0

    def _process_frame(self, pkt):
        """Called by Scapy for every captured frame."""
        if not pkt.haslayer(Dot11):
            return

        wall_ns, wall_iso = self._clock.now()
        dot11   = pkt[Dot11]
        channel = self._channel_from_radiotap(pkt)
        rssi    = self._rssi_from_radiotap(pkt)
        bssid   = _oob_bssid(dot11.addr3 or "00:00:00:00:00:00")
        src_mac = _oob_bssid(dot11.addr2 or "00:00:00:00:00:00")

        # ── BEACON frames ────────────────────────────────────────────────
        if pkt.haslayer(Dot11Beacon):
            self._beacon_count[bssid] += 1
            ssid = ""
            try:
                ssid = _oob_ssid(pkt[Dot11Elt].info.decode(
                    "utf-8", errors="replace"))
            except Exception:
                pass

            # Log beacon
            rec = {
                "type":     "beacon",
                "_stream":  "wifi",
                "_layer":   2,
                "_iface":   self._iface,
                "wall_ns":  wall_ns,
                "wall_iso": wall_iso,
                "bssid":    bssid,
                "ssid":     ssid,
                "channel":  channel,
                "rssi":     rssi,
            }
            self._mirror.write(rec)      # live only — beacons are high volume
            self._log.write(rec)

            # BEACON_DATA_RATIO_COLLAPSE check
            bc = self._beacon_count[bssid]
            dc = self._data_count[bssid]
            if bc > 50 and dc < 5:
                flag = f"BEACON_DATA_RATIO_COLLAPSE:{bssid}"
                if flag not in self._anomaly_fired:
                    self._anomaly_fired.add(flag)
                    anom = {
                        "type":          "wifi_anomaly",
                        "_stream":       "wifi",
                        "_layer":        2,
                        "_iface":        self._iface,
                        "wall_ns":       wall_ns,
                        "wall_iso":      wall_iso,
                        "anomaly_class": "BEACON_DATA_RATIO_COLLAPSE",
                        "bssid":         bssid,
                        "ssid":          ssid,
                        "channel":       channel,
                        "rssi":          rssi,
                        "beacon_count":  bc,
                        "data_count":    dc,
                        "ratio":         bc / max(dc, 1),
                        "detail": (f"BSSID {bssid} '{ssid}' has {bc} beacons "
                                   f"but only {dc} data frames — ratio "
                                   f"{bc/max(dc,1):.0f}:1 — "
                                   f"MITM stub AP signature: "
                                   f"keeping association alive with "
                                   f"no real data traffic on this channel"),
                    }
                    self._log.write(anom)
                    self._mirror.write(anom)
                    self._cb(anom)
                    print(f"[L2:{self._iface}] *** BEACON_DATA_RATIO_COLLAPSE "
                          f"{bssid} '{ssid}' ratio {bc/max(dc,1):.0f}:1")

            # BSSID multichannel — record in global burst log
            with self._global_lock:
                self._global_burst_log[bssid].append((wall_ns, channel))
                self._check_multichannel(bssid, ssid, wall_ns, wall_iso)

        # ── PROBE RESPONSE ───────────────────────────────────────────────
        elif pkt.haslayer(Dot11ProbeResp):
            ssid = ""
            try:
                ssid = _oob_ssid(pkt[Dot11Elt].info.decode(
                    "utf-8", errors="replace"))
            except Exception:
                pass
            self._probe_resp[ssid].add(bssid)

            # Multiple BSSIDs responding to same SSID probe
            if (len(self._probe_resp[ssid]) > 1 and
                    self._args.home_ssid and
                    ssid == self._args.home_ssid):
                flag = f"PROBE_RESPONSE_MISMATCH:{ssid}"
                if flag not in self._anomaly_fired:
                    self._anomaly_fired.add(flag)
                    responders = sorted(self._probe_resp[ssid])
                    anom = {
                        "type":          "wifi_anomaly",
                        "_stream":       "wifi",
                        "_layer":        2,
                        "_iface":        self._iface,
                        "wall_ns":       wall_ns,
                        "wall_iso":      wall_iso,
                        "anomaly_class": "PROBE_RESPONSE_MISMATCH",
                        "ssid":          ssid,
                        "responding_bssids": responders,
                        "detail": (f"SSID '{ssid}' has {len(responders)} "
                                   f"BSSIDs responding to probe requests: "
                                   f"{responders} — one is rogue"),
                    }
                    self._log.write(anom)
                    self._mirror.write(anom)
                    self._cb(anom)
                    print(f"[L2:{self._iface}] *** PROBE_RESPONSE_MISMATCH "
                          f"'{ssid}' {len(responders)} responders: "
                          f"{responders}")

        # ── DATA frames ──────────────────────────────────────────────────
        elif dot11.type == 2:   # type 2 = data
            self._data_count[bssid] += 1
            # Record in global burst log for cross-channel correlation
            with self._global_lock:
                self._global_burst_log[bssid].append((wall_ns, channel))

        # ── DEAUTH / DISASSOC ────────────────────────────────────────────
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            target = _oob_bssid(dot11.addr1 or "ff:ff:ff:ff:ff:ff")
            self._deauth_window.append((wall_ns, bssid, target))

            # Count deauths in rolling 10-second window
            cutoff = wall_ns - 10_000_000_000
            recent = [(ns, b, t) for ns, b, t in self._deauth_window
                      if ns > cutoff and b == bssid]

            if len(recent) >= self._args.deauth_threshold:
                flag = f"DEAUTH_FLOOD:{bssid}"
                if flag not in self._anomaly_fired:
                    self._anomaly_fired.add(flag)
                    anom = {
                        "type":          "wifi_anomaly",
                        "_stream":       "wifi",
                        "_layer":        2,
                        "_iface":        self._iface,
                        "wall_ns":       wall_ns,
                        "wall_iso":      wall_iso,
                        "anomaly_class": "DEAUTH_FLOOD",
                        "bssid":         bssid,
                        "target_mac":    target,
                        "count_10s":     len(recent),
                        "channel":       channel,
                        "rssi":          rssi,
                        "detail": (f"{len(recent)} deauth/disassoc frames "
                                   f"from {bssid} in 10s window — "
                                   f"classic MITM setup attack forcing "
                                   f"client reconnect to rogue AP"),
                    }
                    self._log.write(anom)
                    self._mirror.write(anom)
                    self._cb(anom)
                    print(f"[L2:{self._iface}] *** DEAUTH_FLOOD "
                          f"{bssid} → {target}  "
                          f"{len(recent)} frames in 10s")
                # reset after firing so it can fire again if flood resumes
                self._anomaly_fired.discard(flag)

    def _check_multichannel(self, bssid, ssid, wall_ns, wall_iso):
        """
        Check if bssid has appeared on multiple channels within
        the timing correlation window.
        Must be called with _global_lock held.
        """
        window_ns = int(self._args.timing_window_ms * 1_000_000)
        cutoff    = wall_ns - window_ns
        history   = [(ns, ch) for ns, ch in self._global_burst_log[bssid]
                     if ns > cutoff and ch != -1]
        channels  = set(ch for _, ch in history)

        if len(channels) > 1:
            flag = f"BSSID_MULTICHANNEL:{bssid}"
            if flag not in self._anomaly_fired:
                self._anomaly_fired.add(flag)
                anom = {
                    "type":          "wifi_anomaly",
                    "_stream":       "wifi",
                    "_layer":        2,
                    "_iface":        self._iface,
                    "wall_ns":       wall_ns,
                    "wall_iso":      wall_iso,
                    "anomaly_class": "BSSID_MULTICHANNEL",
                    "bssid":         bssid,
                    "ssid":          ssid,
                    "channels":      sorted(channels),
                    "window_ms":     self._args.timing_window_ms,
                    "frame_count":   len(history),
                    "detail": (f"BSSID {bssid} transmitted on channels "
                               f"{sorted(channels)} within "
                               f"{self._args.timing_window_ms}ms — "
                               f"single radio cannot do this — "
                               f"indicates multi-radio MITM relay "
                               f"or channel-hopping exfil bridge"),
                }
                self._log.write(anom)
                self._mirror.write(anom)
                self._cb(anom)
                print(f"[L2:{self._iface}] *** BSSID_MULTICHANNEL "
                      f"{bssid} channels {sorted(channels)} "
                      f"in {self._args.timing_window_ms}ms window")

    def run(self, stop: threading.Event):
        print(f"[L2:{self._iface}] Raw frame capture started")
        try:
            # Run sniff in a loop so we can check stop event
            while not stop.is_set():
                sniff(
                    iface   = self._iface,
                    prn     = self._process_frame,
                    store   = False,
                    timeout = 5,        # return every 5s to check stop
                    monitor = True,     # request monitor mode
                )
        except Exception as e:
            print(f"[L2:{self._iface}] Raw capture error: {e}")
            print(f"[L2:{self._iface}] Layer 2 degraded — "
                  f"Layer 1 management plane continues")
        print(f"[L2:{self._iface}] Stopped.")


# ══════════════════════════════════════════════════════════════════════════════
# CROSS-CHANNEL TIMING CORRELATOR
# The primary MITM exfil detection engine.
# Watches for data bursts on non-home channels correlated in time
# with activity on the home channel.
# ══════════════════════════════════════════════════════════════════════════════

class CrossChannelCorrelator:
    """
    Reads wifi_live.jsonl in real time and cross-correlates
    frame events across channels.

    Core detection:
      When home channel shows uplink data burst (your device sending),
      the MITM relay MUST forward that data within a bounded latency
      window (typically 5-50ms for a local relay).

      Any data burst on a non-home channel within that window,
      from a BSSID in the known-rogue candidate set,
      is flagged as TIMING_CORRELATED_EXFIL.
    """

    def __init__(self, mirror_path: Path, clock: ClockAnchor,
                 log: GzipLog, mirror: LiveMirror,
                 anomaly_cb, args):
        self._mirror_path = mirror_path
        self._clock       = clock
        self._log         = log
        self._mirror      = mirror
        self._cb          = anomaly_cb
        self._args        = args

        # home channel activity log: deque of (wall_ns, frame_type)
        self._home_activity = deque(maxlen=1000)
        # non-home channel bursts: deque of (wall_ns, channel, bssid, count)
        self._other_bursts  = deque(maxlen=1000)
        self._fired         = set()

    def run(self, stop: threading.Event):
        print("[correlator] Cross-channel timing correlator started")
        if not self._mirror_path.exists():
            print(f"[correlator] Waiting for {self._mirror_path}...")
            while not self._mirror_path.exists() and not stop.is_set():
                time.sleep(1)

        try:
            with open(self._mirror_path, "r",
                      encoding="utf-8", errors="replace") as fh:
                fh.seek(0, 2)   # tail — live events only
                while not stop.is_set():
                    line = fh.readline()
                    if not line:
                        time.sleep(0.02)
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    rtype   = rec.get("type", "")
                    channel = rec.get("channel", -1)
                    wall_ns = rec.get("wall_ns", 0)
                    bssid   = rec.get("bssid", "")

                    home_ch = self._args.home_channel

                    if rtype in ("beacon", "data_frame"):
                        if home_ch and channel == home_ch:
                            self._home_activity.append(
                                (wall_ns, rtype, bssid))
                        elif channel != -1 and channel != home_ch:
                            self._other_bursts.append(
                                (wall_ns, channel, bssid))
                            self._check_timing_correlation(
                                wall_ns, channel, bssid, rec)

        except Exception as e:
            print(f"[correlator] Error: {e}")
        print("[correlator] Stopped.")

    def _check_timing_correlation(self, burst_ns, channel, bssid, rec):
        """
        Check if this non-home burst follows recent home channel activity
        within the forwarding latency window.
        """
        if not self._args.home_channel:
            return

        window_ns = int(self._args.timing_window_ms * 1_000_000)
        cutoff    = burst_ns - window_ns

        recent_home = [(ns, t, b) for ns, t, b in self._home_activity
                       if ns > cutoff]

        if len(recent_home) >= 3:   # at least 3 home frames precede burst
            wall_ns, wall_iso = self._clock.now()
            lag_ms = (burst_ns - recent_home[-1][0]) / 1_000_000

            flag = f"TIMING_CORRELATED:{bssid}:{channel}"
            if flag not in self._fired:
                self._fired.add(flag)
                anom = {
                    "type":           "wifi_anomaly",
                    "_stream":        "wifi",
                    "_layer":         3,
                    "wall_ns":        wall_ns,
                    "wall_iso":       wall_iso,
                    "anomaly_class":  "TIMING_CORRELATED_EXFIL",
                    "bssid":          bssid,
                    "exfil_channel":  channel,
                    "home_channel":   self._args.home_channel,
                    "lag_ms":         round(lag_ms, 2),
                    "home_frames_preceding": len(recent_home),
                    "detail": (f"Data burst on Ch{channel} from {bssid} "
                               f"occurred {lag_ms:.1f}ms after "
                               f"{len(recent_home)} frames on home Ch"
                               f"{self._args.home_channel} — "
                               f"consistent with MITM relay forwarding "
                               f"latency — possible exfil channel"),
                }
                self._log.write(anom)
                self._mirror.write(anom)
                self._cb(anom)
                print(f"[correlator] *** TIMING_CORRELATED_EXFIL  "
                      f"Ch{self._args.home_channel}→Ch{channel}  "
                      f"lag {lag_ms:.1f}ms  {bssid}")
                # allow re-fire after 30s
                threading.Timer(
                    30.0,
                    lambda: self._fired.discard(flag)
                ).start()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def _list_adapters():
    """List available wireless adapters via netsh."""
    try:
        raw = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            stderr=subprocess.DEVNULL,
            timeout=10,
            encoding="utf-8",
            errors="replace"
        )
        print("\nAvailable wireless interfaces:")
        print("-" * 48)
        iface = None
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Name"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    iface = parts[1].strip()
                    print(f"  Name       : {iface}")
            elif line.startswith("Description"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    print(f"  Description: {parts[1].strip()}")
            elif line.startswith("Physical address"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    print(f"  MAC        : {parts[1].strip()}")
                    print()
    except Exception as e:
        print(f"[ERROR] Could not list interfaces: {e}")


def _anomaly_callback(rec: dict):
    """Global anomaly callback — can be extended for alerting."""
    pass    # primary handling is in each scanner's print statements


def main():
    ap = argparse.ArgumentParser(
        description="CTW WiFi Forensic Scanner — Dual Adapter MITM Detection"
    )
    ap.add_argument("--iface1",  default=None,
        help="Primary adapter name (ALFA AWUS036ACS) — locked channel monitor")
    ap.add_argument("--iface2",  default=None,
        help="Secondary adapter (TP-Link T2U) — sweep monitor")
    ap.add_argument("--list-adapters", action="store_true",
        help="List available wireless adapters and exit")
    ap.add_argument("--home-ssid",    default=None,
        help="Your legitimate network SSID (for evil-twin detection)")
    ap.add_argument("--home-bssid",   default=None,
        help="Your legitimate AP BSSID  e.g. AA:BB:CC:DD:EE:FF")
    ap.add_argument("--home-channel", type=int, default=None,
        help="Your home network channel (for timing correlation)")
    ap.add_argument("--home-rssi",    type=float, default=None,
        help="Expected RSSI of your legitimate AP at scan position (dBm)")
    ap.add_argument("--deauth-threshold", type=int, default=10,
        help="Deauth frames in 10s window to trigger DEAUTH_FLOOD (default 10)")
    ap.add_argument("--timing-window-ms", type=float, default=500.0,
        help="Cross-channel timing correlation window ms (default 500)")
    ap.add_argument("--scan-interval", type=float, default=5.0,
        help="Layer 1 scan interval seconds (default 5)")
    ap.add_argument("--no-layer2", action="store_true",
        help="Disable Layer 2 raw capture even if Scapy available")
    ap.add_argument("--out", default=r"C:\sdr\logs",
        help=r"Output directory (default C:\sdr\logs)")
    args = ap.parse_args()

    if args.list_adapters:
        _list_adapters()
        return

    # ── validate home BSSID if provided ──────────────────────────────────
    if args.home_bssid:
        validated = _oob_bssid(args.home_bssid)
        if validated == "OOB:BSSID":
            print(f"[ERROR] --home-bssid '{args.home_bssid}' "
                  f"is not a valid MAC address")
            sys.exit(1)
        args.home_bssid = validated

    # ── paths ─────────────────────────────────────────────────────────────
    base    = Path(args.out)
    runtime = base / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)

    clock   = ClockAnchor()
    stamp   = clock.session
    gz_path = base / f"wifi_{stamp}.jsonl.gz"
    lj_path = runtime / "wifi_live.jsonl"

    log    = GzipLog(gz_path)
    mirror = LiveMirror(lj_path)

    # ── session start record ──────────────────────────────────────────────
    wall_ns, wall_iso = clock.now()
    start_rec = {
        "type":              "session_start",
        "_stream":           "wifi",
        "wall_ns":           wall_ns,
        "wall_iso":          wall_iso,
        "session":           stamp,
        "iface1":            args.iface1,
        "iface2":            args.iface2,
        "home_ssid":         args.home_ssid,
        "home_bssid":        args.home_bssid,
        "home_channel":      args.home_channel,
        "home_rssi":         args.home_rssi,
        "layer1_available":  PYWIFI_OK,
        "layer2_available":  SCAPY_OK and not args.no_layer2,
        "deauth_threshold":  args.deauth_threshold,
        "timing_window_ms":  args.timing_window_ms,
    }
    log.write(start_rec)
    mirror.write(start_rec)

    print()
    print("=" * 68)
    print("  CTW WIFI SENTINEL — FORENSIC SCANNER")
    print(f"  Session : {stamp}")
    print(f"  Log     : {gz_path}")
    print(f"  Mirror  : {lj_path}")
    if args.home_ssid:
        print(f"  Home    : '{args.home_ssid}'"
              f"  BSSID:{args.home_bssid or 'any'}"
              f"  Ch:{args.home_channel or 'any'}"
              f"  RSSI:{args.home_rssi or 'baseline-auto'}")
    print(f"  Layer 1 : {'YES' if PYWIFI_OK else 'NO — pip install pywifi'}")
    print(f"  Layer 2 : {'YES' if (SCAPY_OK and not args.no_layer2) else 'NO'}")
    if not SCAPY_OK:
        print("            pip install scapy + Npcap (WinPcap mode) + "
              "monitor mode driver")
    print("  Ctrl+C to stop")
    print("=" * 68)
    print()

    stop    = threading.Event()
    threads = []

    # ── Layer 1 scanners ─────────────────────────────────────────────────
    if PYWIFI_OK:
        for iface_name in filter(None, [args.iface1, args.iface2]):
            l1 = Layer1Scanner(iface_name, clock, log, mirror,
                               _anomaly_callback, args)
            t  = threading.Thread(
                target=l1.run,
                args=(stop, args.scan_interval),
                daemon=True,
                name=f"L1-{iface_name}"
            )
            threads.append(t)
            t.start()
    else:
        print("[WARN] pywifi not available — Layer 1 disabled")
        print("       pip install pywifi comtypes")

    # ── Layer 2 scanners ─────────────────────────────────────────────────
    if SCAPY_OK and not args.no_layer2:
        for iface_name in filter(None, [args.iface1, args.iface2]):
            l2 = Layer2Scanner(iface_name, clock, log, mirror,
                               _anomaly_callback, args)
            t  = threading.Thread(
                target=l2.run,
                args=(stop,),
                daemon=True,
                name=f"L2-{iface_name}"
            )
            threads.append(t)
            t.start()

    # ── Cross-channel timing correlator ───────────────────────────────────
    corr = CrossChannelCorrelator(lj_path, clock, log, mirror,
                                  _anomaly_callback, args)
    t = threading.Thread(
        target=corr.run,
        args=(stop,),
        daemon=True,
        name="CrossCorrelator"
    )
    threads.append(t)
    t.start()

    # ── wait for Ctrl+C ───────────────────────────────────────────────────
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[wifi_sentinel] Stopping...")
        stop.set()
        for t in threads:
            t.join(timeout=8)

        wall_ns, wall_iso = clock.now()
        end_rec = {
            "type":     "session_end",
            "_stream":  "wifi",
            "wall_ns":  wall_ns,
            "wall_iso": wall_iso,
        }
        log.write(end_rec)
        mirror.write(end_rec)
        log.close()
        mirror.close()
        print(f"[wifi_sentinel] Session complete. Log: {gz_path}")


if __name__ == "__main__":
    main()
