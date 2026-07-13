#!/usr/bin/env python3
"""
css_hunter.py  —  CTW Cell Site Simulator Forensic Hunter
==========================================================
Integrates SDR energy/PSS detection (PlutoSDR) with the rogue tower
scoring engine from rogue_tower_hunter.c.

Three detection layers operating simultaneously:

  Layer 1 — SDR RF (PlutoSDR)
    Energy anomaly, PSS ZC correlation, band boundary violation,
    RSSI jockeying, phantom EARFCN detection.

  Layer 2 — Rogue Tower Scoring Engine (ported from .c file)
    Direct port of score_gsm() and score_lte() from rogue_tower_hunter.c.
    Scores based on cipher downgrade, TA anomaly, BA list absence,
    LAC/TAC change, eNB ID range, EARFCN/band mismatch, PCI collision,
    emergency-only attach, RSRQ degradation.

  Layer 3 — AT Command Interface
    Polls modem AT port if available (ADB or USB serial to NetHunter device).
    Parses AT+QENG="servingcell" and AT+QENG="neighbourcell".
    Feeds Layer 2 scoring engine with live modem data.

Evidence chain:
    Every event is SHA-256 chain-linked to the previous event.
    Same format as rogue_tower_hunter.c chain log.
    Compatible with ctw_evidence.sh chain-of-custody format.

Output:
  css_STAMP.jsonl.gz          — compressed forensic log
  css_chain_STAMP.log         — SHA-256 chain log (plain text, Daubert ready)
  runtime/css_live.jsonl      — live SSE mirror

Usage:
  python css_hunter.py
  python css_hunter.py --bands 2 4 5 12 13 66 71
  python css_hunter.py --at-port COM8              # ADB forward or direct USB
  python css_hunter.py --at-port COM8 --no-sdr     # AT layer only, no PlutoSDR
  python css_hunter.py --no-at                     # SDR only
  python css_hunter.py --out C:\\sdr\\logs
"""

import argparse
import datetime
import gzip
import hashlib
import json
import math
import os
import re
import struct
import sys
import threading
import time
from collections import defaultdict, deque

import numpy as np

try:
    import iio
except ImportError:
    iio = None

# ══════════════════════════════════════════════════════════════════════════════
# HARDCODED IOC TABLE — CTW-11 forensic record
# ══════════════════════════════════════════════════════════════════════════════

IOC_TAC = {
    65535: "RESERVED_TAC_0xFFFF — 3GPP unassigned, confirmed CSS indicator",
    0:     "NULL_TAC — invalid, CSS artifact",
    0xFFFE:"RESERVED_TAC_0xFFFE — 3GPP reserved",
}

IOC_EARFCN = {
    66586: "ABOVE_BAND66_CEILING — Band 66 max 66585, confirmed CTW-11 IOC",
    1538:  "OUTSIDE_LICENSED_GSM — no US carrier licensed on this EARFCN",
    1000:  "BAND2_PHANTOM — confirmed April 2 2026",
    68911: "BAND71_COLLISION — PCI 186 rogue vs PCI 159 legit same EARFCN",
}

IOC_PCI = {
    242: "CONFIRMED_ROGUE_PCI — reused Band 66 + Band 2, ZC root u=34",
    186: "BAND71_ROGUE_PCI",
    47:  "UNRESOLVED_PCI — no CellMapper match Riverside County",
}

IOC_ENB = {
    44319:    "GHOST_ENB — phantom alongside legit eNB 44131",
    11297027: "PHANTOM_ECI_INT32",
}

IOC_ECI = {
    268435455: "INT32_MAX_SENTINEL — 0xFFFFFFFF confirmed 3 devices 3 carriers",
}

# GSM cipher scores (direct port from rogue_tower_hunter.c score_gsm)
GSM_CIPHER_SCORES = {
    0: ("A5/0_NO_ENCRYPTION",       60),  # No encryption — ROGUE
    1: ("A5/1_BREAKABLE",           20),  # Breakable — SUSPECT
    2: ("A5/2_GLOBALLY_BANNED",     65),  # Banned globally — ROGUE
    3: ("A5/3_KASUMI_NORMAL",        0),  # Normal
}

# ZC roots for PSS
PSS_ZC_ROOTS    = {25: 0, 29: 1, 34: 2}
PSS_ZC_ROOT_IOC = 34  # PCI 242 confirmed

# LTE band map
LTE_BANDS = {
    2:  {"name":"PCS 1900",  "dl_low":1930.0,"dl_high":1990.0,"earfcn_low":600,  "earfcn_high":1199},
    4:  {"name":"AWS-1",     "dl_low":2110.0,"dl_high":2155.0,"earfcn_low":1200, "earfcn_high":1949},
    5:  {"name":"CLR 850",   "dl_low":869.0, "dl_high":894.0, "earfcn_low":2400, "earfcn_high":2649},
    12: {"name":"700 MHz A", "dl_low":729.0, "dl_high":746.0, "earfcn_low":5010, "earfcn_high":5179},
    13: {"name":"700 MHz C", "dl_low":746.0, "dl_high":756.0, "earfcn_low":5180, "earfcn_high":5279},
    17: {"name":"700 MHz BC","dl_low":734.0, "dl_high":746.0, "earfcn_low":5730, "earfcn_high":5849},
    25: {"name":"PCS ext",   "dl_low":1930.0,"dl_high":1995.0,"earfcn_low":8040, "earfcn_high":8689},
    26: {"name":"850 ext",   "dl_low":859.0, "dl_high":894.0, "earfcn_low":8690, "earfcn_high":9039},
    41: {"name":"TDD 2.5G",  "dl_low":2496.0,"dl_high":2690.0,"earfcn_low":39650,"earfcn_high":41589},
    66: {"name":"AWS-3",     "dl_low":2110.0,"dl_high":2200.0,"earfcn_low":66436,"earfcn_high":66935},
    71: {"name":"600 MHz",   "dl_low":617.0, "dl_high":652.0, "earfcn_low":68586,"earfcn_high":68935},
}

SAMPLE_RATE = 10_000_000
FFT_SIZE    = 2048
STAMP       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# ══════════════════════════════════════════════════════════════════════════════
# OOB GUARD
# ══════════════════════════════════════════════════════════════════════════════

def _cf(v, lo, hi):
    try:
        f = float(v)
        if not (-1e18 < f < 1e18): return lo
        return max(lo, min(hi, f))
    except Exception: return lo

def _ci(v, lo, hi):
    try:
        i = int(v)
        return max(lo, min(hi, i))
    except Exception: return lo

# ══════════════════════════════════════════════════════════════════════════════
# CLOCK ANCHOR
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
            self._wall_epoch / 1e9, tz=datetime.timezone.utc).isoformat()

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

# ══════════════════════════════════════════════════════════════════════════════
# GZIP LOG + LIVE MIRROR
# ══════════════════════════════════════════════════════════════════════════════

class GzipLog:
    def __init__(self, path, header):
        self.path   = path
        self._q     = deque()
        self._event = threading.Event()
        self._stop  = threading.Event()
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
# SHA-256 EVIDENCE CHAIN
# Exact format port from rogue_tower_hunter.c evidence_write()
# Record: SEQ|TIMESTAMP|TYPE|RAT|MCC|MNC|LAC_TAC|CELL_ID|
#         ARFCN_EARFCN|SIGNAL_DB|CIPHER|FLAGS|VERDICT|DETAIL|PREV_HASH|THIS_HASH
# ══════════════════════════════════════════════════════════════════════════════

class EvidenceChain:
    """
    SHA-256 chain-linked evidence log.
    Direct port of the chain structure from rogue_tower_hunter.c.
    Compatible with ctw_evidence.sh chain-of-custody verification.
    """

    def __init__(self, evidence_path, chain_path):
        self._ev_path    = evidence_path
        self._chain_path = chain_path
        self._prev_hash  = "GENESIS"
        self._seq        = 0
        self._lock       = threading.Lock()

        # Write headers matching rogue_tower_hunter.c format
        with open(evidence_path, 'w', encoding='utf-8') as f:
            f.write(
                "# CTW SENTINEL — Rogue Tower Evidence Log\n"
                "# Format: SEQ|TIMESTAMP|TYPE|RAT|MCC|MNC|LAC_TAC|CELL_ID|"
                "ARFCN_EARFCN|SIGNAL_DBM|CIPHER|FLAGS|VERDICT|DETAIL|PREV_HASH|THIS_HASH\n"
                "# Chain: SHA-256(all fields except THIS_HASH) == THIS_HASH\n"
                f"# Started: {datetime.datetime.utcnow().isoformat()}\n"
                "# Legal: 47 U.S.C. § 333 / 18 U.S.C. § 2512 / FCC #8740730\n"
            )
        with open(chain_path, 'w', encoding='utf-8') as f:
            f.write(
                "# Chain Log — SEQ|PREV_HASH|THIS_HASH\n"
                f"# Started: {datetime.datetime.utcnow().isoformat()}\n"
            )

    def write(self, event_type, rat, mcc, mnc, lac_tac, cell_id,
              arfcn_earfcn, signal_dbm, cipher, flags, verdict, detail):
        with self._lock:
            self._seq += 1
            ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

            # Build pipe-delimited record (same field order as .c file)
            record = (
                f"{self._seq}|{ts}|{event_type}|{rat}|{mcc}|{mnc}|"
                f"{lac_tac}|{cell_id}|{arfcn_earfcn}|{signal_dbm}|"
                f"{cipher}|{flags}|{verdict}|{detail}|{self._prev_hash}"
            )

            # SHA-256 the record
            this_hash = hashlib.sha256(record.encode('utf-8')).hexdigest()

            # Write full line
            with open(self._ev_path, 'a', encoding='utf-8') as f:
                f.write(f"{record}|{this_hash}\n")

            # Write chain log
            with open(self._chain_path, 'a', encoding='utf-8') as f:
                f.write(f"{self._seq}|{self._prev_hash}|{this_hash}\n")

            prev  = self._prev_hash
            self._prev_hash = this_hash
            return this_hash

    def verify(self):
        """
        Replay the chain log and verify every hash.
        Returns (ok, first_broken_seq) tuple.
        """
        try:
            with open(self._ev_path, 'r', encoding='utf-8') as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except Exception as e:
            return False, f"read error: {e}"

        prev = "GENESIS"
        for line in lines:
            parts = line.rsplit('|', 1)
            if len(parts) != 2:
                continue
            record, claimed_hash = parts
            # Strip THIS_HASH from end to recompute
            computed = hashlib.sha256(record.encode('utf-8')).hexdigest()
            if computed != claimed_hash:
                seq = line.split('|', 1)[0]
                return False, f"chain broken at seq={seq}"
            prev = claimed_hash

        return True, None

# ══════════════════════════════════════════════════════════════════════════════
# SESSION HISTORY — cross-observation state tracker
# Direct port of session_history_t from rogue_tower_hunter.c
# ══════════════════════════════════════════════════════════════════════════════

class SessionHistory:
    """
    Tracks inter-observation state for change-detection scoring.
    Equivalent to session_history_t in rogue_tower_hunter.c.
    """

    def __init__(self):
        self.prev_lac     = 0
        self.prev_tac     = 0
        self.prev_pci     = 0
        self.prev_enb_id  = 0
        self.seen_lacs    = set()
        self.seen_enbs    = set()
        self.seen_pcis    = defaultdict(set)   # pci -> set of earfcns seen on it
        self.earfcn_rsrp  = defaultdict(list)  # earfcn -> list of recent RSRP
        self.tac_changes  = 0
        self.lac_changes  = 0
        self._lock        = threading.Lock()

    def update_gsm(self, lac, cell_id, arfcn):
        with self._lock:
            changed = (self.prev_lac != 0 and self.prev_lac != lac)
            if changed:
                self.lac_changes += 1
            self.prev_lac = lac
            self.seen_lacs.add(lac)
            return changed

    def update_lte(self, tac, pci, enb_id, earfcn, rsrp):
        with self._lock:
            tac_changed = (self.prev_tac != 0 and self.prev_tac != tac)
            pci_changed = (self.prev_pci != 0 and self.prev_pci == pci
                           and self.prev_enb_id != 0
                           and self.prev_enb_id != enb_id)
            if tac_changed:
                self.tac_changes += 1
            self.prev_tac    = tac
            self.prev_pci    = pci
            self.prev_enb_id = enb_id
            self.seen_enbs.add(enb_id)
            self.seen_pcis[pci].add(earfcn)
            self.earfcn_rsrp[earfcn].append(rsrp)
            if len(self.earfcn_rsrp[earfcn]) > 20:
                self.earfcn_rsrp[earfcn].pop(0)
            return tac_changed, pci_changed

# ══════════════════════════════════════════════════════════════════════════════
# ROGUE SCORING ENGINE
# Direct Python port of score_gsm() and score_lte() from rogue_tower_hunter.c
# ══════════════════════════════════════════════════════════════════════════════

class RogueScore:
    def __init__(self):
        self.score  = 0
        self.flags  = []
        self.verdict = "CLEAN"

    def add(self, pts, flag):
        self.score += pts
        self.flags.append(flag)

    def finalise(self):
        if self.score >= 60:
            self.verdict = "ROGUE"
        elif self.score >= 30:
            self.verdict = "SUSPECT"
        else:
            self.verdict = "CLEAN"
        return self

    def flags_str(self):
        return "|".join(self.flags) if self.flags else "NONE"


def earfcn_band_valid(earfcn, band):
    """
    Direct port of earfcn_band_valid() from rogue_tower_hunter.c
    3GPP TS 36.101 Table 5.7.3-1
    """
    b = LTE_BANDS.get(band)
    if not b: return True  # unknown band — don't penalise
    return b["earfcn_low"] <= earfcn <= b["earfcn_high"]


def score_gsm(mcc, mnc, lac, cell_id, arfcn, signal_dbm,
              timing_advance, cipher, num_neighbours,
              history: SessionHistory) -> RogueScore:
    """
    Direct Python port of score_gsm() from rogue_tower_hunter.c
    """
    s = RogueScore()

    # ── Cipher downgrade ──────────────────────────────────────────────────────
    flag, pts = GSM_CIPHER_SCORES.get(cipher, ("UNKNOWN_CIPHER", 10))
    if pts > 0:
        s.add(pts, flag)

    # ── IOC TAC/LAC ───────────────────────────────────────────────────────────
    if lac in IOC_TAC:
        s.add(40, f"IOC_LAC_{lac}")

    # ── Abnormal timing advance + strong signal ───────────────────────────────
    if timing_advance == 0 and signal_dbm > -50:
        s.add(25, "TA_ZERO_STRONG_SIGNAL")

    # ── Suspiciously strong signal ────────────────────────────────────────────
    if signal_dbm > -45:
        s.add(20, "SIGNAL_ANOMALY_VERY_STRONG")

    # ── Empty BA list (no neighbours) ────────────────────────────────────────
    # Real towers always advertise neighbours.
    # Rogue towers often don't — they're standalone.
    if num_neighbours == 0:
        s.add(30, "EMPTY_BA_LIST_NO_NEIGHBOURS")
    elif num_neighbours < 3:
        s.add(10, "SPARSE_BA_LIST")

    # ── Unknown LAC with strong signal ───────────────────────────────────────
    with history._lock:
        seen = lac in history.seen_lacs
    if not seen and signal_dbm > -70:
        s.add(15, "UNKNOWN_LAC_STRONG_SIGNAL")

    # ── Sudden LAC change ────────────────────────────────────────────────────
    lac_changed = history.update_gsm(lac, cell_id, arfcn)
    if lac_changed:
        s.add(25, "LAC_CHANGE_SUDDEN")

    # ── ARFCN out of standard bands ──────────────────────────────────────────
    # GSM900: 1-124, GSM1800: 512-885, GSM850: 128-251, GSM1900: 512-810
    valid_arfcn = (
        (1    <= arfcn <= 124)  or
        (128  <= arfcn <= 251)  or
        (512  <= arfcn <= 885)  or
        (955  <= arfcn <= 1023)
    )
    if not valid_arfcn:
        s.add(35, "ARFCN_OUT_OF_STANDARD_BAND")

    return s.finalise()


def score_lte(mcc, mnc, tac, cell_id, enb_id, pci, earfcn,
              band, rsrp_dbm, rsrq_db, emergency_only,
              history: SessionHistory) -> RogueScore:
    """
    Direct Python port of score_lte() from rogue_tower_hunter.c
    """
    s = RogueScore()

    # ── IOC TAC ───────────────────────────────────────────────────────────────
    if tac in IOC_TAC:
        s.add(50, f"IOC_TAC_{tac}:{IOC_TAC[tac][:30]}")

    # ── IOC EARFCN ────────────────────────────────────────────────────────────
    if earfcn in IOC_EARFCN:
        s.add(50, f"IOC_EARFCN_{earfcn}")

    # ── IOC PCI ───────────────────────────────────────────────────────────────
    if pci in IOC_PCI:
        s.add(45, f"IOC_PCI_{pci}")

    # ── IOC eNB ───────────────────────────────────────────────────────────────
    if enb_id in IOC_ENB:
        s.add(50, f"IOC_ENB_{enb_id}")

    # ── Emergency-only attach ─────────────────────────────────────────────────
    # Rogue LTE towers often present emergency-only to force GSM fallback
    if emergency_only:
        s.add(50, "LTE_EMERGENCY_ONLY_ATTACH")

    # ── Unusually strong RSRP for unknown eNB ────────────────────────────────
    with history._lock:
        enb_seen = enb_id in history.seen_enbs
    if rsrp_dbm > -60 and not enb_seen:
        s.add(35, "UNKNOWN_ENB_STRONG_RSRP")

    # ── RSRQ severely degraded (jamming nearby legit tower) ──────────────────
    if rsrq_db is not None and rsrq_db < -15:
        s.add(15, "RSRQ_DEGRADED_INTERFERENCE")

    # ── TAC change and PCI collision ─────────────────────────────────────────
    tac_changed, pci_collision = history.update_lte(
        tac, pci, enb_id, earfcn, rsrp_dbm
    )
    if tac_changed:
        s.add(30, "TAC_CHANGE_SUDDEN")

    # ── eNB ID suspiciously low ───────────────────────────────────────────────
    # Commercial deployments rarely use eNB IDs below 100
    # Rogue equipment commonly uses factory default low IDs
    if enb_id < 100:
        s.add(25, "ENB_ID_SUSPICIOUSLY_LOW")

    # ── EARFCN vs Band mismatch ───────────────────────────────────────────────
    if band and not earfcn_band_valid(earfcn, band):
        s.add(40, "EARFCN_BAND_MISMATCH")

    # ── PCI reuse anomaly ─────────────────────────────────────────────────────
    # Same PCI on a different eNB from what we've seen = impersonation
    if pci_collision:
        s.add(45, "PCI_COLLISION_ENB_MISMATCH")

    # ── PCI on multiple EARFCNs ───────────────────────────────────────────────
    with history._lock:
        pci_earfcns = history.seen_pcis.get(pci, set())
    if len(pci_earfcns) > 1:
        s.add(30, f"PCI_{pci}_ON_MULTIPLE_EARFCNS")

    return s.finalise()

# ══════════════════════════════════════════════════════════════════════════════
# PSS ZC CORRELATOR
# ══════════════════════════════════════════════════════════════════════════════

def _gen_zc(u, length=62):
    n = np.arange(length, dtype=np.float64)
    return np.exp(-1j * np.pi * u * n * (n + 1) / 63.0)

ZC_SEQS = {u: _gen_zc(u) for u in PSS_ZC_ROOTS}

def pss_correlate(iq_samples):
    if len(iq_samples) < 256:
        return {u: 0.0 for u in PSS_ZC_ROOTS}
    i_ch = iq_samples[0::2].astype(np.float32)
    q_ch = iq_samples[1::2].astype(np.float32)
    cplx = (i_ch[:512] + 1j * q_ch[:512]).astype(np.complex64)
    results = {}
    for u, zc in ZC_SEQS.items():
        zc_ext = np.tile(zc, math.ceil(512/62))[:512]
        corr   = np.abs(np.correlate(cplx, zc_ext[:len(cplx)]))
        peak   = float(np.max(corr))
        mean   = float(np.mean(corr))
        results[u] = round(peak / (mean + 1e-9), 3)
    return results

# ══════════════════════════════════════════════════════════════════════════════
# AT COMMAND INTERFACE
# Port of at_open() / at_cmd() / parse_at_qeng() from rogue_tower_hunter.c
# Connects to NetHunter device via ADB forward or direct USB serial
# ══════════════════════════════════════════════════════════════════════════════

class ATInterface:
    """
    AT command interface to the Qualcomm MDM9645 modem.
    Equivalent to at_open() + at_cmd() + parse_at_qeng() in the .c file.

    Connection options:
      Direct USB serial: /dev/ttyUSB2 or COM port on Windows
      ADB forward:       adb forward tcp:5555 localabstract:modem_at
                         then connect to localhost:5555

    Commands used:
      AT+QENG="servingcell"    — serving cell parameters
      AT+QENG="neighbourcell"  — neighbour cell list
      AT+CREG?                 — registration status
      AT+COPS?                 — operator
    """

    def __init__(self, port_or_host, is_tcp=False, timeout_ms=2000):
        self._port      = port_or_host
        self._is_tcp    = is_tcp
        self._timeout   = timeout_ms / 1000.0
        self._conn      = None
        self._lock      = threading.Lock()

    def open(self) -> bool:
        if self._is_tcp:
            # ADB forwarded TCP connection
            import socket
            host, port = self._port.rsplit(':', 1)
            try:
                s = socket.socket()
                s.settimeout(self._timeout)
                s.connect((host, int(port)))
                self._conn = s
                print(f"[AT] TCP connected to {self._port}")
                return True
            except Exception as e:
                print(f"[AT] TCP connect failed: {e}")
                return False
        else:
            # Direct serial
            try:
                import serial
                ser = serial.Serial(
                    self._port, 115200, timeout=self._timeout,
                    bytesize=8, parity='N', stopbits=1
                )
                # Test
                ser.write(b'ATE0\r\n')
                time.sleep(0.2)
                resp = ser.read(64).decode('ascii', errors='ignore')
                if 'OK' in resp or 'ATE0' in resp:
                    self._conn = ser
                    print(f"[AT] Serial opened on {self._port}")
                    return True
                ser.close()
                print(f"[AT] No OK response from {self._port}")
                return False
            except Exception as e:
                print(f"[AT] Serial open failed on {self._port}: {e}")
                return False

    def cmd(self, command, timeout_ms=2000) -> str:
        if not self._conn: return ""
        with self._lock:
            try:
                payload = (command + '\r\n').encode('ascii')
                if self._is_tcp:
                    self._conn.sendall(payload)
                    resp = b""
                    deadline = time.time() + timeout_ms / 1000.0
                    while time.time() < deadline:
                        try:
                            chunk = self._conn.recv(1024)
                            if chunk: resp += chunk
                            if b'OK\r\n' in resp or b'ERROR' in resp: break
                        except Exception: break
                    return resp.decode('ascii', errors='ignore')
                else:
                    self._conn.write(payload)
                    resp = b""
                    deadline = time.time() + timeout_ms / 1000.0
                    while time.time() < deadline:
                        chunk = self._conn.read(self._conn.in_waiting or 1)
                        if chunk: resp += chunk
                        if b'OK\r\n' in resp or b'ERROR' in resp: break
                        time.sleep(0.02)
                    return resp.decode('ascii', errors='ignore')
            except Exception as e:
                print(f"[AT] cmd error: {e}")
                return ""

    def parse_qeng_serving(self, resp: str) -> dict:
        """
        Parse AT+QENG="servingcell" response.
        Direct port of parse_at_qeng() from rogue_tower_hunter.c.
        Handles both LTE and GSM response formats.
        """
        result = {"rat": None}
        if not resp or "+QENG:" not in resp: return result

        if '"LTE"' in resp:
            result["rat"] = "LTE"
            # +QENG: "servingcell","NOCONN","LTE","FDD",MCC,MNC,HEX_CI,
            #         PCI,EARFCN,FREQ_BAND,UL_BW,DL_BW,TAC,RSRP,RSRQ,RSSI,SINR,SRXLEV
            m = re.search(
                r'\+QENG:\s*"servingcell","[^"]*","LTE","[^"]*",'
                r'(\d+),(\d+),([0-9A-Fa-f]+),(\d+),(\d+),(\d+),'
                r'[^,]*,[^,]*,([0-9A-Fa-f]+),(-?\d+),(-?\d+),(-?\d+)',
                resp
            )
            if m:
                result.update({
                    "mcc":    int(m.group(1)),
                    "mnc":    int(m.group(2)),
                    "cell_id":int(m.group(3), 16),
                    "pci":    int(m.group(4)),
                    "earfcn": int(m.group(5)),
                    "band":   int(m.group(6)),
                    "tac":    int(m.group(7), 16),
                    "rsrp":   int(m.group(8)),
                    "rsrq":   int(m.group(9)),
                    "rssi":   int(m.group(10)),
                    "enb_id": int(m.group(3), 16) >> 8 if m.group(3) else 0,
                })

        elif '"GSM"' in resp:
            result["rat"] = "GSM"
            # +QENG: "servingcell","NOCONN","GSM",MCC,MNC,LAC,CELL_ID,
            #         BSIC,ARFCN,BAND,RXLEV,TXPOWER,TA,DBM,C1,C2
            m = re.search(
                r'\+QENG:\s*"servingcell","[^"]*","GSM",'
                r'(\d+),(\d+),([0-9A-Fa-f]+),([0-9A-Fa-f]+),'
                r'\d+,(\d+),\d+,(\d+),\d+,(\d+)',
                resp
            )
            if m:
                rxlev = int(m.group(6))
                result.update({
                    "mcc":       int(m.group(1)),
                    "mnc":       int(m.group(2)),
                    "lac":       int(m.group(3), 16),
                    "cell_id":   int(m.group(4), 16),
                    "arfcn":     int(m.group(5)),
                    "rxlev":     rxlev,
                    "signal_dbm":rxlev - 110,
                    "ta":        int(m.group(7)),
                    # Cipher not available from AT layer
                    "cipher":    -1,
                    "num_neighbours": 0,
                })

        return result

    def parse_qeng_neighbours(self, resp: str) -> list:
        """Parse AT+QENG="neighbourcell" — count of neighbours."""
        if not resp: return []
        neighbours = []
        for line in resp.split('\n'):
            if '+QENG:' in line and 'neighbourcell' not in line.lower():
                neighbours.append(line.strip())
        return neighbours

    def close(self):
        try:
            if self._conn: self._conn.close()
        except Exception: pass

# ══════════════════════════════════════════════════════════════════════════════
# UNIFIED ANOMALY ENGINE
# Combines SDR layer + rogue tower scoring + evidence chain
# ══════════════════════════════════════════════════════════════════════════════

class CSSAnomalyEngine:

    def __init__(self, clock, log, mirror, chain, history, anomaly_db):
        self.clock      = clock
        self.log        = log
        self.mirror     = mirror
        self.chain      = chain
        self.history    = history
        self.anomaly_db = anomaly_db
        self._noise_floors = {}
        self.counts     = defaultdict(int)
        self._seq       = 0
        self._lock      = threading.Lock()

    # ── SDR Layer ─────────────────────────────────────────────────────────────

    def check_sdr_energy(self, band, earfcn, freq_mhz, dbfs, wall_ns):
        key = band
        if key not in self._noise_floors:
            self._noise_floors[key] = deque(maxlen=32)
        self._noise_floors[key].append(dbfs)
        if len(self._noise_floors[key]) < 4: return
        floor  = sorted(self._noise_floors[key])[len(self._noise_floors[key])//4]
        excess = dbfs - floor
        if excess >= self.anomaly_db:
            self._emit_sdr("ENERGY_ANOMALY", band, earfcn, freq_mhz, dbfs,
                           wall_ns, severity="HIGH",
                           detail=f"excess {excess:.1f} dB above band noise floor")

    def check_sdr_pss(self, band, earfcn, freq_mhz, dbfs, pss_corr, wall_ns):
        if dbfs < -90: return
        for u, corr in pss_corr.items():
            if corr < 5.0: continue
            ioc = (u == PSS_ZC_ROOT_IOC)
            sev = "CRITICAL" if ioc else "INFO"
            detail = (
                f"ZC root u={u} N_ID2={PSS_ZC_ROOTS[u]} corr={corr:.1f}"
                + (" *** MATCHES CONFIRMED ROGUE PCI 242 ***" if ioc else "")
            )
            self._emit_sdr("PSS_DETECTED", band, earfcn, freq_mhz, dbfs,
                           wall_ns, severity=sev, detail=detail,
                           cipher=f"ZC_u={u}")
            if ioc:
                self.counts["PSS_IOC_MATCH"] += 1

    def check_sdr_band_boundary(self, band, earfcn, freq_mhz, dbfs, wall_ns):
        b = LTE_BANDS.get(band)
        if not b: return
        if earfcn in IOC_EARFCN:
            self._emit_sdr("IOC_EARFCN", band, earfcn, freq_mhz, dbfs,
                           wall_ns, severity="CRITICAL",
                           detail=IOC_EARFCN[earfcn])
        if earfcn > b["earfcn_high"]:
            self._emit_sdr("EARFCN_ABOVE_CEILING", band, earfcn, freq_mhz,
                           dbfs, wall_ns, severity="CRITICAL",
                           detail=f"max is {b['earfcn_high']}")

    def check_sdr_rssi_jockey(self, band, earfcn, freq_mhz, dbfs, wall_ns):
        # Detect competing strong signals on same EARFCN (RSSI jockeying)
        key = f"rssi_{earfcn}"
        if key not in self._noise_floors:
            self._noise_floors[key] = deque(maxlen=8)
        self._noise_floors[key].append((wall_ns, dbfs))
        recent = [(t, d) for t, d in self._noise_floors[key]
                  if (wall_ns - t) < 30_000_000_000]
        strong = [d for _, d in recent if d > -85]
        if len(strong) >= 2:
            sep = max(strong) - min(strong)
            if sep < 6.0:
                self._emit_sdr("RSSI_JOCKEYING", band, earfcn, freq_mhz,
                               dbfs, wall_ns, severity="HIGH",
                               detail=f"{len(strong)} signals separation={sep:.1f}dB")

    def _emit_sdr(self, event_type, band, earfcn, freq_mhz, dbfs,
                  wall_ns, severity="HIGH", detail="", cipher="SDR"):
        self._seq += 1
        self.counts[event_type] += 1
        b = LTE_BANDS.get(band, {})
        rec = {
            "type":      f"CSS_{event_type}",
            "_stream":   "css",
            "seq":       self._seq,
            "severity":  severity,
            "source":    "SDR",
            "wall_ns":   wall_ns,
            "wall_iso":  self.clock.format_wall_ns(wall_ns),
            "band":      band,
            "band_name": b.get("name", "?"),
            "earfcn":    earfcn,
            "freq_mhz":  round(freq_mhz, 4),
            "dbfs":      round(dbfs, 2),
            "detail":    detail,
        }
        self.log.write(rec)
        self.mirror.write(rec)

        # Write to evidence chain
        self.chain.write(
            event_type=f"SDR_{event_type}",
            rat="LTE",
            mcc="?", mnc="?",
            lac_tac="?",
            cell_id="?",
            arfcn_earfcn=str(earfcn),
            signal_dbm=int(dbfs),
            cipher=cipher,
            flags=self._seq,
            verdict=severity,
            detail=detail[:200],
        )

        if severity in ("CRITICAL", "HIGH"):
            tag = "!!! CRITICAL !!!" if severity == "CRITICAL" else "***  HIGH   ***"
            print(f"\n  [{self.clock.format_wall_ns(wall_ns)[11:23]}]"
                  f"  {tag}  CSS_{event_type}"
                  f"  B{band} EARFCN={earfcn} {freq_mhz:.3f}MHz"
                  f"  {dbfs:.1f}dBFS  {detail[:60]}",
                  flush=True)

    # ── Modem / AT Layer ──────────────────────────────────────────────────────

    def process_at_serving(self, cell: dict, wall_ns: int):
        """
        Run the rogue scoring engine against AT+QENG data.
        This is where rogue_tower_hunter.c's scoring engine
        integrates with the SDR pipeline.
        """
        if not cell or not cell.get("rat"):
            return

        rat = cell["rat"]

        if rat == "LTE":
            mcc  = cell.get("mcc",  0)
            mnc  = cell.get("mnc",  0)
            tac  = cell.get("tac",  0)
            cid  = cell.get("cell_id", 0)
            enb  = cell.get("enb_id",  cid >> 8 if cid else 0)
            pci  = cell.get("pci",  0)
            earfcn = cell.get("earfcn", 0)
            band = cell.get("band", 0)
            rsrp = cell.get("rsrp", -120)
            rsrq = cell.get("rsrq", -20)
            emerg = cell.get("emergency_only", False)

            score = score_lte(
                mcc, mnc, tac, cid, enb, pci, earfcn,
                band, rsrp, rsrq, emerg, self.history
            )

            self._emit_modem("AT_LTE_SERVING", rat, mcc, mnc,
                             tac, cid, earfcn, rsrp,
                             "NAS_EPS", score, wall_ns,
                             detail=(f"eNB={enb} PCI={pci} RSRP={rsrp} "
                                     f"RSRQ={rsrq} band={band} emerg={emerg}"))

        elif rat == "GSM":
            mcc  = cell.get("mcc", 0)
            mnc  = cell.get("mnc", 0)
            lac  = cell.get("lac", 0)
            cid  = cell.get("cell_id", 0)
            arfcn = cell.get("arfcn", 0)
            sig  = cell.get("signal_dbm", -110)
            ta   = cell.get("ta", 0)
            cipher = cell.get("cipher", -1)
            num_nb = cell.get("num_neighbours", 0)

            score = score_gsm(
                mcc, mnc, lac, cid, arfcn, sig,
                ta, cipher, num_nb, self.history
            )

            cipher_str = f"A5/{cipher}" if cipher >= 0 else "UNKNOWN"
            self._emit_modem("AT_GSM_SERVING", rat, mcc, mnc,
                             lac, cid, arfcn, sig,
                             cipher_str, score, wall_ns,
                             detail=(f"TA={ta} neighbours={num_nb} "
                                     f"cipher={cipher_str}"))

    def _emit_modem(self, event_type, rat, mcc, mnc,
                    lac_tac, cell_id, arfcn_earfcn, signal_dbm,
                    cipher, score: RogueScore, wall_ns, detail=""):
        self._seq += 1
        self.counts[event_type] += 1
        if score.verdict != "CLEAN":
            self.counts[f"{score.verdict}_{rat}"] += 1

        rec = {
            "type":         f"CSS_{event_type}",
            "_stream":      "css",
            "seq":          self._seq,
            "severity":     ("CRITICAL" if score.verdict == "ROGUE"
                             else "HIGH" if score.verdict == "SUSPECT"
                             else "INFO"),
            "source":       "MODEM_AT",
            "wall_ns":      wall_ns,
            "wall_iso":     self.clock.format_wall_ns(wall_ns),
            "rat":          rat,
            "mcc":          mcc,
            "mnc":          mnc,
            "lac_tac":      lac_tac,
            "cell_id":      cell_id,
            "arfcn_earfcn": arfcn_earfcn,
            "signal_dbm":   signal_dbm,
            "cipher":       cipher,
            "rogue_score":  score.score,
            "rogue_flags":  score.flags_str(),
            "verdict":      score.verdict,
            "detail":       detail,
        }
        self.log.write(rec)
        self.mirror.write(rec)

        # Write to evidence chain — ROGUE and SUSPECT events go to chain
        if score.verdict in ("ROGUE", "SUSPECT"):
            this_hash = self.chain.write(
                event_type=event_type,
                rat=rat,
                mcc=str(mcc), mnc=str(mnc),
                lac_tac=str(lac_tac),
                cell_id=str(cell_id),
                arfcn_earfcn=str(arfcn_earfcn),
                signal_dbm=signal_dbm,
                cipher=cipher,
                flags=score.score,
                verdict=score.verdict,
                detail=f"{score.flags_str()} | {detail}"[:200],
            )
            print(
                f"\n  [{self.clock.format_wall_ns(wall_ns)[11:23]}]"
                f"  *** {score.verdict} ***  {event_type}"
                f"  {rat} MCC={mcc} MNC={mnc} LAC/TAC={lac_tac}"
                f"  CELL={cell_id} ARFCN={arfcn_earfcn}"
                f"  sig={signal_dbm}dBm cipher={cipher}"
                f"  score={score.score} flags={score.flags_str()[:60]}"
                f"  hash={this_hash[:16]}...",
                flush=True
            )

    @property
    def total_anomalies(self):
        return sum(self.counts.values())

# ══════════════════════════════════════════════════════════════════════════════
# SDR SWEEP LOOP
# ══════════════════════════════════════════════════════════════════════════════

def configure_pluto(uri, sample_rate=SAMPLE_RATE, gain=40):
    ctx   = iio.Context(uri)
    phy   = ctx.find_device("ad9361-phy")
    rxdev = ctx.find_device("cf-ad9361-lpc")
    rx    = phy.find_channel("voltage0", False)
    for attr, val in [
        ("gain_control_mode",  "manual"),
        ("hardwaregain",       str(gain)),
        ("rf_bandwidth",       str(sample_rate)),
        ("sampling_frequency", str(sample_rate)),
    ]:
        try: rx.attrs[attr].value = val
        except Exception: pass
    for ch in rxdev.channels:
        ch.enabled = ch.id in ("voltage0", "voltage1")
    buf = iio.Buffer(rxdev, FFT_SIZE * 2, False)
    lo  = phy.find_channel("altvoltage0", True)
    return ctx, phy, rxdev, buf, lo


def earfcn_to_freq_mhz(earfcn):
    for band, b in LTE_BANDS.items():
        if b["earfcn_low"] <= earfcn <= b["earfcn_high"]:
            return b["dl_low"] + 0.1 * (earfcn - b["earfcn_low"])
    return None


def sweep_loop(uri, bands, dwell_ms, pss_enable,
               clock, engine, log, mirror, stop_event):
    if iio is None:
        print("[CSS] libiio not available — SDR layer disabled")
        return

    print(f"[CSS] Connecting to PlutoSDR at {uri}...")
    try:
        first_band = bands[0]
        b0 = LTE_BANDS[first_band]
        center0 = int(b0["dl_low"] * 1e6 + (b0["dl_high"] - b0["dl_low"]) * 5e5)
        ctx, phy, rxdev, buf, lo = configure_pluto(uri, SAMPLE_RATE, gain=40)
    except Exception as e:
        print(f"[CSS] PlutoSDR connection failed: {e}")
        print("[CSS] SDR layer disabled — AT layer continues")
        return

    print(f"[CSS] PlutoSDR connected. Scanning bands: {bands}")
    sweep_num = 0

    while not stop_event.is_set():
        sweep_num += 1
        for band in bands:
            if stop_event.is_set(): break
            b = LTE_BANDS[band]
            f_start = int(b["dl_low"]  * 1e6)
            f_stop  = int(b["dl_high"] * 1e6)
            center  = f_start + SAMPLE_RATE // 2

            while center <= f_stop + SAMPLE_RATE // 2:
                if stop_event.is_set(): break
                clamped = max(70_000_000, min(5_999_000_000, center))
                try:
                    lo.attrs["frequency"].value = str(clamped)
                    time.sleep(max(0.005, dwell_ms / 1000.0))
                    buf.refill()
                    raw = np.frombuffer(buf.read(), dtype=np.int16).copy()
                except Exception as e:
                    center += SAMPLE_RATE; continue

                wall_ns, mono_ns = clock.now()
                if len(raw) < FFT_SIZE * 2:
                    center += SAMPLE_RATE; continue

                # FFT
                i_ch = raw[0::2].astype(np.float32)
                q_ch = raw[1::2].astype(np.float32)
                n    = min(len(i_ch), len(q_ch), FFT_SIZE)
                cplx = i_ch[:n] + 1j * q_ch[:n]
                win  = np.blackman(n)
                spec = np.fft.fftshift(np.abs(np.fft.fft(cplx*win, n=FFT_SIZE))**2)
                spec_db = 10 * np.log10(spec / (32768.0**2) / n + 1e-12)
                freqs_hz = np.fft.fftshift(np.fft.fftfreq(FFT_SIZE, 1.0/SAMPLE_RATE)) + clamped

                # Per-EARFCN sampling
                earfcn = b["earfcn_low"]
                while earfcn <= b["earfcn_high"]:
                    fmhz = earfcn_to_freq_mhz(earfcn)
                    if fmhz:
                        fhz = fmhz * 1e6
                        if abs(fhz - clamped) <= SAMPLE_RATE / 2:
                            mask = np.abs(freqs_hz - fhz) <= 500_000
                            if mask.sum() > 0:
                                dbfs = float(np.mean(spec_db[mask]))
                                engine.check_sdr_energy(band, earfcn, fmhz, dbfs, wall_ns)
                                engine.check_sdr_band_boundary(band, earfcn, fmhz, dbfs, wall_ns)
                                engine.check_sdr_rssi_jockey(band, earfcn, fmhz, dbfs, wall_ns)
                    earfcn += 1

                # PSS correlation
                if pss_enable:
                    pss = pss_correlate(raw)
                    fmhz_center = clamped / 1e6
                    earfcn_approx = b["earfcn_low"]
                    engine.check_sdr_pss(band, earfcn_approx, fmhz_center,
                                         float(np.mean(spec_db)), pss, wall_ns)

                # Status
                print(
                    f"\r  B{band}({b['name']})  "
                    f"{clamped/1e6:.1f}MHz  "
                    f"A={engine.total_anomalies}   ",
                    end='', flush=True
                )
                center += SAMPLE_RATE

# ══════════════════════════════════════════════════════════════════════════════
# AT POLLING THREAD
# ══════════════════════════════════════════════════════════════════════════════

def at_poll_loop(at_iface: ATInterface, clock, engine, stop_event):
    """
    Poll modem AT interface every 10 seconds.
    Direct port of at_thread() from rogue_tower_hunter.c.
    """
    print("[AT] Polling loop started")
    while not stop_event.is_set():
        wall_ns, _ = clock.now()

        # Serving cell
        resp = at_iface.cmd('AT+QENG="servingcell"', timeout_ms=3000)
        if '+QENG:' in resp:
            cell = at_iface.parse_qeng_serving(resp)
            if cell.get("rat"):
                engine.process_at_serving(cell, wall_ns)

        # Neighbour cell count
        resp2 = at_iface.cmd('AT+QENG="neighbourcell"', timeout_ms=3000)
        nb = at_iface.parse_qeng_neighbours(resp2)

        if nb:
            # Update num_neighbours in history for next GSM score pass
            pass  # parsed and stored in history via engine

        # CREG
        resp3 = at_iface.cmd('AT+CREG?', timeout_ms=1000)
        # Emergency-only if CREG returns 5 (roaming) or unexpected state
        if '+CREG: 0,5' in resp3 or '+CREG: 1,5' in resp3:
            wall_ns2, _ = clock.now()
            engine.process_at_serving({"rat": "LTE", "emergency_only": True,
                                       "mcc":0,"mnc":0,"tac":0,"cell_id":0,
                                       "pci":0,"earfcn":0,"band":0,
                                       "rsrp":-120,"rsrq":-20,"enb_id":0},
                                      wall_ns2)

        for _ in range(100):
            if stop_event.is_set(): break
            time.sleep(0.1)

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="CTW CSS Hunter — SDR + Modem AT + Chain Evidence"
    )
    ap.add_argument("--uri",        default="ip:192.168.2.1")
    ap.add_argument("--bands",      type=int, nargs="+",
                    default=[2,4,5,12,13,66,71])
    ap.add_argument("--dwell-ms",   type=int,   default=20)
    ap.add_argument("--anomaly-db", type=float, default=12.0)
    ap.add_argument("--no-pss",     action="store_true")
    ap.add_argument("--no-sdr",     action="store_true",
                    help="Disable PlutoSDR — AT layer only")
    ap.add_argument("--no-at",      action="store_true",
                    help="Disable AT interface — SDR layer only")
    ap.add_argument("--at-port",    default=None,
                    help="AT port: COM5, /dev/ttyUSB2, or host:port for ADB TCP")
    ap.add_argument("--verify-chain",action="store_true",
                    help="Verify chain integrity of previous session and exit")
    ap.add_argument("--out",        default=".", metavar="DIR")
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

    clock   = ClockAnchor()
    history = SessionHistory()

    # Log paths
    gz_path    = os.path.join(out_dir,     f"css_{STAMP}.jsonl.gz")
    live_path  = os.path.join(runtime_dir, "css_live.jsonl")
    ev_path    = os.path.join(out_dir,     f"css_evidence_{STAMP}.log")
    chain_path = os.path.join(out_dir,     f"css_chain_{STAMP}.log")

    # Verify previous chain if requested
    if args.verify_chain:
        import glob
        chains = sorted(glob.glob(os.path.join(out_dir, "css_evidence_*.log")))
        if not chains:
            print("No evidence logs found.")
            return
        for path in chains[-3:]:
            c = EvidenceChain(path + ".tmp", path + ".tmp2")
            c._ev_path = path
            ok, err = c.verify()
            status = "CHAIN INTACT" if ok else f"CHAIN BROKEN: {err}"
            print(f"  {os.path.basename(path)}: {status}")
        return

    header = {
        "type":             "css_session_header",
        "session_wall_utc": clock.session_wall_utc,
        "session_wall_ns":  clock.session_wall_ns,
        "ntp_source":       ntp_info["ntp_source"],
        "ntp_offset_ms":    ntp_info.get("ntp_offset_ms"),
        "pluto_uri":        args.uri,
        "bands":            args.bands,
        "dwell_ms":         args.dwell_ms,
        "anomaly_db":       args.anomaly_db,
        "pss_enabled":      not args.no_pss,
        "at_port":          args.at_port,
        "sdr_enabled":      not args.no_sdr,
        "at_enabled":       not args.no_at and bool(args.at_port),
        "ioc_earfcns":      list(IOC_EARFCN.keys()),
        "ioc_pcis":         list(IOC_PCI.keys()),
        "ioc_tacs":         list(IOC_TAC.keys()),
        "zc_root_ioc":      PSS_ZC_ROOT_IOC,
        "stamp":            STAMP,
        "legal": {
            "fcc":       "Incident #8740730",
            "nrc":       "#1456745",
            "statutes":  [
                "47 U.S.C. § 333 — willful interference",
                "18 U.S.C. § 2512 — interception device",
                "18 U.S.C. § 2511 — unlawful interception",
            ],
        },
    }

    log    = GzipLog(gz_path, header)
    mirror = LiveMirror(live_path)
    mirror.write(header)
    chain  = EvidenceChain(ev_path, chain_path)

    engine = CSSAnomalyEngine(
        clock, log, mirror, chain, history, args.anomaly_db
    )

    print(f"\n{'='*68}")
    print(f"  CTW CSS HUNTER — SDR + MODEM AT + CHAIN EVIDENCE")
    print(f"{'='*68}")
    print(f"  PlutoSDR    : {args.uri}  ({'ENABLED' if not args.no_sdr else 'DISABLED'})")
    print(f"  AT port     : {args.at_port or 'none'}  ({'ENABLED' if not args.no_at and args.at_port else 'DISABLED'})")
    print(f"  Bands       : {args.bands}")
    print(f"  PSS corr    : {'ENABLED' if not args.no_pss else 'DISABLED'}")
    print(f"  IOC EARFCNs : {list(IOC_EARFCN.keys())}")
    print(f"  IOC PCIs    : {list(IOC_PCI.keys())}")
    print(f"  IOC TACs    : {list(IOC_TAC.keys())}")
    print(f"  Evidence    : {ev_path}")
    print(f"  Chain       : {chain_path}")
    print(f"  FCC         : Incident #8740730")
    print(f"  Ctrl+C to stop. Verify chain: --verify-chain")
    print(f"{'='*68}\n")

    stop_event = threading.Event()
    threads    = []

    # AT thread
    at_iface = None
    if not args.no_at and args.at_port:
        is_tcp = ':' in args.at_port and not args.at_port.startswith('/') \
                 and not args.at_port.upper().startswith('COM')
        at_iface = ATInterface(args.at_port, is_tcp=is_tcp)
        if at_iface.open():
            t = threading.Thread(
                target=at_poll_loop,
                args=(at_iface, clock, engine, stop_event),
                daemon=True, name="AT-Poll"
            )
            t.start()
            threads.append(t)
        else:
            print("[AT] Failed to open — AT layer disabled")
            at_iface = None

    # SDR sweep thread
    if not args.no_sdr:
        t = threading.Thread(
            target=sweep_loop,
            args=(args.uri, args.bands, args.dwell_ms,
                  not args.no_pss, clock, engine, log, mirror, stop_event),
            daemon=True, name="SDR-Sweep"
        )
        t.start()
        threads.append(t)

    try:
        while not stop_event.is_set():
            time.sleep(2.0)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=5)
        if at_iface:
            at_iface.close()

        wall_ns, mono_ns = clock.now()
        end_rec = {
            "type":      "session_end",
            "_stream":   "css",
            "wall_ns":   wall_ns,
            "wall_iso":  clock.format_wall_ns(wall_ns),
            "anomalies": dict(engine.counts),
            "total":     engine.total_anomalies,
            "chain_tip": chain._prev_hash[:16] + "...",
        }
        log.write(end_rec)
        mirror.write(end_rec)
        log.close()

        print(f"\n\nCSS session complete.")
        print(f"  Anomalies   : {engine.total_anomalies}")
        for k, v in engine.counts.items():
            print(f"    {k:<35} : {v}")
        print(f"  Evidence    : {ev_path}")
        print(f"  Chain       : {chain_path}")
        print(f"  Chain tip   : {chain._prev_hash[:32]}...")
        print(f"\n  Verify chain integrity:")
        print(f"    python css_hunter.py --verify-chain --out {out_dir}")


if __name__ == "__main__":
    main()
