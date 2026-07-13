@echo off
setlocal enabledelayedexpansion

set BASE=C:\sdr\logs
set PYTHON=python

:: ══════════════════════════════════════════════════════════════════════════════
:: CTW SENTINEL — INTERACTIVE LAUNCH MENU WITH ARGUMENT PASSTHROUGH
:: ══════════════════════════════════════════════════════════════════════════════

:menu
cls
echo.
echo  ================================================================
echo   CTW SENTINEL FORENSIC PLATFORM -- LAUNCH MENU
echo   Advanced CT Research
echo  ================================================================
echo.
echo   INFRASTRUCTURE
echo   [1]  gz_watch.py        gzip live mirror watcher
echo   [2]  live_reader.py     JSONL cursor server          :8080
echo   [3]  rf_server.py       SSE broadcast server         :8000
echo   [4]  correlator.py      RF/Geiger correlation engine
echo.
echo   RF SWEEP
echo   [5]  pluto_sweep.py     PlutoSDR 386 MHz forensic sweep
echo   [6]  bt_scanner.py      Bluetooth/BLE forensic scanner
echo   [7]  css_hunter.py      CSS band scanner (active cells)
echo   [8]  css_idle_hunter.py CSS idle/gap scanner (camping)
echo.
echo   GNSS
echo   [9]  ublox_data.py      u-blox raw UBX capture
echo   [10] ublox_parser.py    UBX binary forensic parser
echo   [11] gnss_server.py     GNSS map server              :8001
echo.
echo   60GHz mmWave
echo   [12] hlk_ld6002b.py     60GHz sensor -- passive scan (default)
echo   [13] hlk_ld6002b.py     60GHz sensor -- empty room calibration
echo   [14] hlk_ld6002b.py     60GHz sensor -- human reference calibration
echo   [15] hlk_ld6002b.py     60GHz sensor -- full forensic scan + triangulate
echo.
echo   DASHBOARDS
echo   [16] Open sweep.html    http://localhost:8000/sweep.html
echo   [17] Open gnss_map.html http://localhost:8001/gnss_map.html
echo.
echo   PRESETS
echo   [A]  FULL               All infrastructure + sweep + GNSS + mmwave scan
echo   [B]  CORE + SWEEP       Infrastructure + 386MHz sweep
echo   [C]  CORE + CSS         Infrastructure + CSS hunters
echo   [D]  CORE + BT          Infrastructure + Bluetooth
echo   [E]  GNSS ONLY          GNSS stack only
echo   [F]  RF FULL            All RF scanners
echo   [G]  mmWave ONLY        60GHz sensor passive scan (no calibration)
echo   [S]  STOP ALL           Kill all CTW processes
echo   [Q]  QUIT               Exit
echo   [H]  HELP               Display command options
echo.
echo  ================================================================
echo   ARGUMENT PASSTHROUGH:
echo     Append args after a menu number using comma separator
echo     Example:  1 4 5, 12,--port COM5 --phase scan 16,
echo     Comma after number = end of that entry's args
echo     Numbers without comma take default args
echo  ================================================================
echo.
set /p RAW_INPUT="  Enter selections: "
:: ══════════════════════════════════════════════════════════════════════════════
:: CTW SENTINEL -- HELP SYSTEM
:: Trigger: user types H or HELP or ?N (e.g. ?5 for entry 5 help)
:: ══════════════════════════════════════════════════════════════════════════════

:: Check for help trigger before anything else
set "HELP_INPUT=!RAW_INPUT!"

:: Bare H or HELP = show full reference
if /i "!HELP_INPUT!"=="H"    goto show_full_help
if /i "!HELP_INPUT!"=="HELP" goto show_full_help
if /i "!HELP_INPUT!"=="?"    goto show_full_help

:: ?N = show help for specific entry
for /l %%N in (1,1,17) do (
    if "!HELP_INPUT!"=="?%%N" goto show_help_%%N
)

:: Not a help command — fall through to normal parsing
goto end_help_check

:: ══════════════════════════════════════════════════════════════════════════════
:: FULL REFERENCE
:: ══════════════════════════════════════════════════════════════════════════════

:show_full_help
cls
echo.
echo  ================================================================
echo   CTW SENTINEL -- ARGUMENT REFERENCE
echo  ================================================================
echo.
echo   SYNTAX
echo     N                     run entry N with default args
echo     N,--arg val           run entry N with custom args
echo     N, M, O,--arg val P,  mix of defaults and custom
echo     Comma closes an entry's arg list
echo     ?N                    show help for entry N
echo     H or HELP or ?        show this screen
echo.
echo  ----------------------------------------------------------------
echo   [1]  gz_watch.py
echo        No arguments. Watches BASE dir for *.jsonl.gz files.
echo        Default: python gz_watch.py
echo.
echo   [2]  live_reader.py
echo        No arguments. Serves runtime/sweep_live.jsonl on :8080.
echo        Default: python live_reader.py
echo.
echo   [3]  rf_server.py
echo        No arguments. SSE broadcast on :8000.
echo        Default: python rf_server.py
echo.
echo   [4]  correlator.py
echo        --rf-live PATH     sweep_live.jsonl path
echo        --out DIR          output directory
echo        --window SECS      correlation window seconds (default 0.5)
echo        --spike USVH       Geiger spike threshold uSv/h (default 0.10)
echo        --serial-log PATH  fs5000 serial log path (auto-detect)
echo        --audio-log PATH   fs5000 audio log path (auto-detect)
echo        Default: --rf-live %BASE%\runtime\sweep_live.jsonl
echo                 --out %BASE%\runtime --window 0.5 --spike 0.10
echo.
echo   [5]  pluto_sweep.py
echo        --uri URI          PlutoSDR URI (default ip:192.168.2.1)
echo        --out DIR          output directory
echo        --start HZ         sweep start frequency Hz
echo        --stop HZ          sweep stop frequency Hz
echo        --step HZ          step size Hz
echo        --freqs HZ [HZ]    explicit frequency list (overrides start/stop)
echo        --dwell-ms MS      dwell time per step
echo        --settle-ms MS     settle time per step
echo        --anomaly-atten DB anomaly threshold dB (default 40)
echo        --no-iq            disable IQ stream (saves RAM)
echo        --quiet            suppress console output
echo        Default: --out %BASE% --start 385900000
echo                 --stop 386100000 --step 10000 --no-iq
echo.
echo   [6]  bt_scanner.py
echo        --uri URI          PlutoSDR URI
echo        --center HZ        center frequency (default 2441000000)
echo        --bw HZ            bandwidth (default 56000000)
echo        --gain DB          receiver gain (default 40)
echo        --rssi-threshold   dBFS anomaly threshold (default -75)
echo        --out DIR          output directory
echo        --adv-only         advertising channels only
echo        Default: --out %BASE% --rssi-threshold -75
echo.
echo   [7]  css_hunter.py      CSS band scanner (active cells + modem AT)
echo        --uri URI          PlutoSDR URI (default ip:192.168.2.1)
echo        --bands N [N]      LTE band numbers (default 2 4 5 12 13 66 71)
echo        --dwell-ms MS      dwell per window ms (default 20)
echo        --anomaly-db DB    dB above noise to flag (default 12)
echo        --no-pss           disable PSS ZC correlation
echo        --no-sdr           AT layer only, no PlutoSDR
echo        --no-at            SDR layer only, no modem AT
echo        --at-port X        modem AT port (COM8, /dev/ttyUSB2, host:port)
echo        --target-earfcn N  force scan specific EARFCNs
echo        --verify-chain     verify SHA-256 chain of previous session
echo        --out DIR          output directory
echo        Default: --out %BASE% --bands 2 4 5 12 13 66 71 --dwell-ms 20
echo.
echo   [8]  css_idle_hunter.py
echo        --uri URI          PlutoSDR URI
echo        --sensitivity DB   dB above gap noise to flag (default 10)
echo        --dwell-ms MS      settle time per window (default 15)
echo        --persist-min N    detections in 120s to flag (default 3)
echo        --out DIR          output directory
echo        Default: --out %BASE% --sensitivity 10 --persist-min 3
echo.
echo   [9]  ublox_data.py
echo        --port COMx        serial port (hardcoded in script, edit there)
echo        No CLI args -- edit COM_PORT at top of ublox_data.py
echo.
echo   [10] ublox_parser.py
echo        --ubx-dir DIR      directory containing *.ubx files
echo        --ubx-file PATH    exact .ubx file (overrides --ubx-dir)
echo        --out DIR          output for .jsonl.gz
echo        Default: --ubx-dir %BASE%\UBLOX --out %BASE%\UBLOX
echo.
echo   [11] gnss_server.py
echo        No arguments. SSE on :8001, serves gnss_map.html.
echo        Default: python gnss_server.py
echo.
echo   [12] hlk_ld6002b.py  (passive scan -- NO calibration required)
echo        --port COMx        serial port (REQUIRED)
echo        --out DIR          output directory
echo        --verbose          print unknown frames
echo        --raw-dump         hex dump all bytes
echo        --list-ports       show available COM ports
echo        NOTE: runs --phase scan but falls back to raw if no cal file
echo        Default: --phase scan --out %BASE%
echo        Example: 12,--port COM5
echo.
echo   [13] hlk_ld6002b.py  (empty room calibration)
echo        --port COMx        serial port (REQUIRED)
echo        --out DIR          output directory
echo        --room-x CM        room width east-west cm (default 400)
echo        --room-y CM        room depth north-south cm (default 400)
echo        --room-z CM        ceiling height cm (default 250)
echo        --mount-x CM       module X from SW corner cm (default 200)
echo        --mount-y CM       module Y from SW corner cm (default 200)
echo        Run 5 minutes minimum with room completely empty.
echo        Ctrl+C in the window when done -- cal saves automatically.
echo        Example: 13,--port COM5 --room-x 350 --room-y 450 --room-z 270
echo.
echo   [14] hlk_ld6002b.py  (human reference calibration)
echo        Same args as [13].
echo        Walk slowly along each wall at 1m distance.
echo        Cover NORTH EAST SOUTH WEST then Ctrl+C.
echo        Must run AFTER [13] empty room cal.
echo        Example: 14,--port COM5 --room-x 350 --room-y 450 --room-z 270
echo.
echo   [15] hlk_ld6002b.py  (full forensic scan + triangulation)
echo        Same args as [13].
echo        Uses saved calibration from [13]+[14] if present.
echo        Falls back to raw passive scan if no calibration file found.
echo        Emits ANOMALY and TRIANGULATION records to mmwave_live.jsonl.
echo        Example: 15,--port COM5 --room-x 350 --room-y 450
echo                    --room-z 270 --mount-x 175 --mount-y 225
echo.
echo   [16] Opens http://localhost:8000/sweep.html in browser.
echo        No arguments.
echo.
echo   [17] Opens http://localhost:8001/gnss_map.html in browser.
echo        No arguments.
echo.
echo  ----------------------------------------------------------------
echo   COMMON EXAMPLES
echo.
echo   Core + 386MHz sweep + browser:
echo     1 2 3 4 5, 16,
echo.
echo   Core + CSS active bands + CSS idle + browser:
echo     1 2 3 4 7,--bands 2 4 66 71 8, 16,
echo.
echo   Core + sweep + 60GHz passive scan on COM5:
echo     1 2 3 4 5, 12,--port COM5 16,
echo.
echo   60GHz empty room calibration only:
echo     13,--port COM5 --room-x 400 --room-y 380 --room-z 260
echo.
echo   60GHz full forensic with room geometry:
echo     1 2 3 4 5, 15,--port COM5 --room-x 400 --room-y 380
echo       --room-z 260 --mount-x 200 --mount-y 190 16,
echo.
echo   GNSS only:
echo     9 10 11 17,
echo.
echo  ================================================================
pause
goto menu

:: ══════════════════════════════════════════════════════════════════════════════
:: PER-ENTRY HELP  (?N)
:: ══════════════════════════════════════════════════════════════════════════════

:show_help_1
cls
echo  [1] gz_watch.py
echo  ----------------------------------------------------------------
echo  Purpose : Watches BASE directory for growing *.jsonl.gz files.
echo            Mirrors new records into runtime/sweep_live.jsonl
echo            for live dashboard consumption.
echo  Args    : None
echo  Default : python gz_watch.py
echo  Notes   : Must be running before any sweep logger writes data.
echo            Restart it if sweep_live.jsonl stops updating.
pause & goto menu

:show_help_2
cls
echo  [2] live_reader.py
echo  ----------------------------------------------------------------
echo  Purpose : HTTP server on :8080 serving runtime/sweep_live.jsonl.
echo            Supports HTTP Range requests for cursor-based polling.
echo            Used by sweep.html poll transport.
echo  Args    : None
echo  Default : python live_reader.py
echo  Notes   : Must be running for the POLL source in sweep.html.
echo            SSE source uses rf_server.py instead.
pause & goto menu

:show_help_3
cls
echo  [3] rf_server.py
echo  ----------------------------------------------------------------
echo  Purpose : SSE broadcast server on :8000.
echo            Tails sweep_live.jsonl and corr_live.jsonl.
echo            Broadcasts all records to connected dashboards.
echo            Also serves sweep.html as a static file.
echo  Args    : None
echo  Default : python rf_server.py
echo  Notes   : Primary data feed for sweep.html SSE mode.
pause & goto menu

:show_help_4
cls
echo  [4] correlator.py
echo  ----------------------------------------------------------------
echo  Purpose : Real-time RF/Geiger correlation engine.
echo            Cross-references PlutoSDR anomalies with FS-5000
echo            Geiger pulse events on shared ClockAnchor epoch.
echo            Classifies events as CORR / EM_ONLY / RF_ONLY.
echo.
echo  Args:
echo    --rf-live PATH     Path to sweep_live.jsonl
echo                       Default: %BASE%\runtime\sweep_live.jsonl
echo    --serial-log PATH  fs5000 serial_*.jsonl.gz (auto-detect)
echo    --audio-log PATH   fs5000 audio_*.jsonl.gz  (auto-detect)
echo    --out DIR          Output for corr_live.jsonl
echo                       Default: %BASE%\runtime
echo    --window SECS      Correlation window seconds
echo                       Default: 0.5
echo    --spike USVH       DR threshold for Geiger spike
echo                       Default: 0.10 uSv/h
echo.
echo  Example:
echo    4,--window 1.0 --spike 0.05
pause & goto menu

:show_help_5
cls
echo  [5] pluto_sweep.py
echo  ----------------------------------------------------------------
echo  Purpose : PlutoSDR IIO forensic sweep logger.
echo            Sweeps configured frequency range, logs RSSI/IQ data,
echo            detects anomalies, writes to sweep_*.jsonl.gz.
echo.
echo  Args:
echo    --uri URI          PlutoSDR IP URI
echo                       Default: ip:192.168.2.1
echo    --out DIR          Log output directory
echo                       Default: %BASE%
echo    --start HZ         Sweep start Hz
echo                       Default: 385900000
echo    --stop HZ          Sweep stop Hz
echo                       Default: 386100000
echo    --step HZ          Step size Hz
echo                       Default: 10000
echo    --freqs HZ [HZ]    Explicit frequency list
echo                       Overrides --start/--stop/--step
echo    --dwell-ms MS      Dwell time per step ms
echo                       Default: 0
echo    --settle-ms MS     Settle time per step ms
echo                       Default: 0
echo    --anomaly-atten DB Anomaly threshold dBm
echo                       Default: 40.0
echo    --no-iq            Disable IQ stream (saves RAM)
echo    --quiet            Suppress sweep console output
echo.
echo  Examples:
echo    5,--freqs 386000000 386020000
echo    5,--start 70000000 --stop 6000000000 --step 1000000 --no-iq
echo    5,--start 385800000 --stop 386200000 --step 5000
pause & goto menu

:show_help_6
cls
echo  [6] bt_scanner.py
echo  ----------------------------------------------------------------
echo  Purpose : Bluetooth and BLE forensic scanner.
echo            Wideband FFT capture across full 2.4GHz ISM band.
echo            Monitors all 40 BLE channels and 79 Classic BT channels.
echo            Detects: advertisement interval anomalies,
echo                     BD_ADDR collisions, RSSI breaches,
echo                     advertising channel asymmetry.
echo.
echo  Args:
echo    --uri URI          PlutoSDR URI
echo                       Default: ip:192.168.2.1
echo    --center HZ        Center frequency Hz
echo                       Default: 2441000000
echo    --bw HZ            Bandwidth Hz
echo                       Default: 56000000
echo    --gain DB          Receiver gain dB
echo                       Default: 40
echo    --rssi-threshold   dBFS above noise to flag
echo                       Default: -75
echo    --out DIR          Output directory
echo    --adv-only         Only report advertising channel events
echo.
echo  NOTE: Shares PlutoSDR with [5]. Run on second PlutoSDR
echo        (--uri ip:192.168.3.1) for simultaneous operation.
echo.
echo  Example:
echo    6,--rssi-threshold -65 --gain 45
pause & goto menu

:show_help_7
cls
echo  [7] css_hunter.py
echo  ----------------------------------------------------------------
echo  Purpose : Cell Site Simulator active band scanner.
echo            Two detection layers running simultaneously:
echo.
echo            LAYER 1 -- SDR RF (PlutoSDR)
echo              Energy anomaly above band noise floor
echo              PSS Zadoff-Chu correlation (ZC root u=34 = PCI 242 IOC)
echo              Band boundary violations (EARFCN above/below legal range)
echo              RSSI jockeying (competing signals on same EARFCN)
echo              Phantom EARFCN detection (no CellMapper match)
echo.
echo            LAYER 2 -- Rogue Tower Scoring Engine (from rogue_tower_hunter.c)
echo              GSM cipher downgrade scoring:
echo                A5/0 no encryption    +60  ROGUE
echo                A5/2 globally banned  +65  ROGUE
echo                A5/1 breakable        +20  SUSPECT
echo              Timing advance anomaly (TA=0 + strong signal)
echo              Empty BA list (no neighbours = standalone rogue)
echo              LAC/TAC change detection
echo              eNB ID below 100 (factory default = rogue equipment)
echo              EARFCN vs band mismatch
echo              PCI collision across eNBs
echo              Emergency-only attach
echo              RSRQ degradation (jammer interference)
echo              PCI on multiple EARFCNs
echo.
echo            IOC table from CTW-11 field evidence:
echo              TAC 65535 / TAC 0      -- 3GPP reserved, confirmed CSS
echo              EARFCN 66586           -- above Band 66 ceiling
echo              EARFCN 1538            -- outside US licensed allocations
echo              EARFCN 1000            -- Band 2 phantom
echo              EARFCN 68911           -- Band 71 PCI collision
echo              PCI 242                -- confirmed rogue, ZC root u=34
echo              PCI 186                -- Band 71 rogue
echo              eNB 44319              -- ghost alongside eNB 44131
echo              ECI 268435455          -- INT32_MAX sentinel
echo.
echo            Evidence chain:
echo              Every ROGUE/SUSPECT event is SHA-256 chain-linked.
echo              Chain log is Daubert-compatible and tamper-evident.
echo              Verify with --verify-chain after session.
echo.
echo  Args:
echo    --uri URI          PlutoSDR URI
echo                       Default: ip:192.168.2.1
echo    --bands N [N]      LTE band numbers to scan
echo                       Default: 2 4 5 12 13 66 71
echo                       Available: 2 4 5 12 13 17 25 26 41 66 71
echo    --dwell-ms MS      Dwell per frequency window ms
echo                       Default: 20
echo    --anomaly-db DB    dB above noise floor to flag
echo                       Default: 12
echo    --no-pss           Disable PSS ZC correlation (faster sweep)
echo    --no-sdr           Disable PlutoSDR -- run AT modem layer only
echo                       Use when PlutoSDR is occupied by pluto_sweep
echo    --no-at            Disable modem AT -- run SDR layer only
echo    --at-port X        Modem AT interface
echo                       Direct serial:  COM8  or  /dev/ttyUSB2
echo                       ADB forwarded:  localhost:5555
echo                       Setup ADB:      adb forward tcp:5555
echo                                           localabstract:modem_at
echo                       NetHunter:      run rogue_tower_hunter on phone,
echo                                       connect via ADB TCP from PC
echo    --target-earfcn N  Force scan specific EARFCNs only
echo                       Overrides --bands for targeted IOC monitoring
echo    --verify-chain     Replay and verify SHA-256 chain of previous
echo                       session evidence logs -- exits after verify
echo    --out DIR          Output directory
echo                       Default: %BASE%
echo.
echo  Output files per session:
echo    css_STAMP.jsonl.gz         compressed forensic log (all events)
echo    css_evidence_STAMP.log     SHA-256 chain evidence (ROGUE/SUSPECT)
echo    css_chain_STAMP.log        chain verification log (SEQ+hashes)
echo    runtime/css_live.jsonl     live SSE mirror for dashboard
echo.
echo  Verdict thresholds (from rogue_tower_hunter.c):
echo    score >= 60  =  ROGUE    (written to evidence chain)
echo    score >= 30  =  SUSPECT  (written to evidence chain)
echo    score  < 30  =  CLEAN    (logged only)
echo.
echo  Examples:
echo    SDR + modem AT on COM8:
echo      7,--bands 2 4 5 12 13 66 71 --at-port COM8
echo.
echo    SDR only (PlutoSDR on second unit, AT unavailable):
echo      7,--no-at --bands 66 2 71 --dwell-ms 50
echo.
echo    AT only (PlutoSDR busy with sweep, phone on COM8):
echo      7,--no-sdr --at-port COM8
echo.
echo    Targeted IOC EARFCNs:
echo      7,--target-earfcn 66586 1538 1000 --at-port COM8
echo.
echo    Verify previous session chain:
echo      7,--verify-chain
echo.
echo    Full session with ADB-forwarded NetHunter:
echo      7,--bands 2 4 5 12 13 66 71 --at-port localhost:5555
echo         --dwell-ms 30 --anomaly-db 10 --out C:\sdr\logs
echo.
echo  Chain verification (standalone):
echo    python css_hunter.py --verify-chain --out C:\sdr\logs
echo    Full session with ADB-forwarded NetHunter:
echo      7,--bands 2 4 5 12 13 66 71 --at-port localhost:5555
echo         --dwell-ms 30 --anomaly-db 10 --out C:\sdr\logs
echo.
echo  Chain verification (standalone):
echo    python css_hunter.py --verify-chain --out C:\sdr\logs
echo.
echo  ADB BRIDGE SETUP (Mode 2 -- PC + phone simultaneously):
echo  ----------------------------------------------------------------
echo    Step 1. Connect SM-G930U via USB, enable ADB in NetHunter
echo    Step 2. In NetHunter Kali terminal or adb shell:
echo              socat TCP-LISTEN:5555,reuseaddr,fork
echo                    FILE:/dev/ttyUSB2,raw,echo=0,b115200
echo            If socat not installed:
echo              while true; do nc -l -p 5555 ^< /dev/smd7 ^> /dev/smd7; done
echo    Step 3. On PC (separate cmd window):
echo              adb forward tcp:5555 tcp:5555
echo    Step 4. Launch entry 7 with at-port:
echo              7,--at-port localhost:5555
echo              7,--at-port localhost:5555 --bands 2 4 5 12 13 66 71
echo    Step 5. Optionally run rogue_tower_hunter on phone simultaneously:
echo              adb shell /data/local/tmp/rogue_tower_hunter
echo            Pull evidence after session:
echo              adb pull /sdcard/tower_evidence/ C:\sdr\logs\tower_evidence\
echo            Verify chain on PC:
echo              python css_hunter.py --verify-chain
echo                     --out C:\sdr\logs\tower_evidence
echo.
echo  NOTE: /dev/ttyUSB2 is the Qualcomm AT port on SM-G930U (herolte).
echo        If unavailable try /dev/smd7 or /dev/smd11.
echo        Check: adb shell ls /dev/tty* /dev/smd*
pause & goto menu

:show_help_8
cls
echo  [8] css_idle_hunter.py
echo  ----------------------------------------------------------------
echo  Purpose : CSS idle/camping layer scanner.
echo            Scans BETWEEN licensed bands in inter-allocation gaps.
echo            Detects CSS parked before device attachment.
echo            Gap regions include:
echo              GAP_PCS_AWS_CRITICAL  1990-2110 MHz
echo              GAP_AWS3_TDD          2200-2496 MHz
echo              GAP_600_700           652-699 MHz
echo              CTW11_386MHZ_IOC      385.92-386.08 MHz (your signal)
echo              CTW11_386_2ND_HARMONIC 772 MHz
echo              CTW11_386_3RD_HARMONIC 1158 MHz
echo              + 16 other gap regions
echo            Classifiers: SIGNAL_IN_GAP, PSS_IN_GAP,
echo                         SMOOTH_PILOT_NO_RB, PERSISTENT_GAP_SIGNAL,
echo                         CTW11_386MHZ_ACTIVE, CTW11_386_HARMONIC.
echo.
echo  Args:
echo    --uri URI          PlutoSDR URI
echo    --sensitivity DB   dB above gap noise to flag
echo                       Default: 10
echo    --dwell-ms MS      Settle per window ms
echo                       Default: 15
echo    --persist-min N    Min detections in 120s for persistence flag
echo                       Default: 3
echo    --out DIR          Output directory
echo.
echo  Example:
echo    8,--sensitivity 8 --persist-min 5
pause & goto menu

:show_help_9
cls
echo  [9] ublox_data.py
echo  ----------------------------------------------------------------
echo  Purpose : u-blox 7 GNSS raw binary capture.
echo            Configures GNSS receiver and logs UBX + NMEA.
echo            Enables: jamming detection, spoofing flags,
echo                     pseudorange capture, satellite status.
echo            Output: C:\GNSS_Evidence\ublox7_STAMP.ubx
echo                    C:\GNSS_Evidence\ublox7_STAMP.nmea
echo.
echo  Args    : None (COM port hardcoded in script)
echo  Edit    : Open ublox_data.py and change COM_PORT at top.
echo            Default COM_PORT = COM7
echo.
echo  NOTE: u-blox must be connected before launching.
echo        Check Device Manager for correct COM port.
pause & goto menu

:show_help_10
cls
echo  [10] ublox_parser.py
echo  ----------------------------------------------------------------
echo  Purpose : Parses u-blox binary UBX files into forensic JSONL.
echo            Tails the latest .ubx file in --ubx-dir.
echo            Extracts: NAV-PVT (position/fix), NAV-SAT (satellites),
echo                      NAV-STATUS (spoofing flags), NAV-CLOCK,
echo                      MON-HW (jamming), RXM-RAW (pseudoranges).
echo            Writes to runtime/gnss_live.jsonl for GNSS map.
echo            Uses same ClockAnchor epoch as pluto_sweep.py.
echo.
echo  Args:
echo    --ubx-dir DIR      Directory containing *.ubx files
echo                       Default: %BASE%\UBLOX
echo    --ubx-file PATH    Exact .ubx file (overrides --ubx-dir)
echo    --out DIR          Output for gnss_*.jsonl.gz
echo                       Default: %BASE%\UBLOX
echo.
echo  Example:
echo    10,--ubx-dir C:\GNSS_Evidence --out %BASE%\UBLOX
pause & goto menu

:show_help_11
cls
echo  [11] gnss_server.py
echo  ----------------------------------------------------------------
echo  Purpose : GNSS forensic map server on :8001.
echo            Tails runtime/gnss_live.jsonl via SSE.
echo            Serves gnss_map.html -- Leaflet map with:
echo              Live fix markers colored by fix type
echo              Spoof detection alerts (red markers + sidebar)
echo              Sky view constellation panel
echo              Satellite table with CNR/elevation/azimuth
echo              Pseudorange panel (toggleable checkbox)
echo              Track line, follow mode, tile layer switcher.
echo  Args    : None
echo  Default : python gnss_server.py
echo  Browse  : http://localhost:8001/gnss_map.html
pause & goto menu

:show_help_12
cls
echo  [12] hlk_ld6002b.py  -- PASSIVE SCAN (no calibration required)
echo  ----------------------------------------------------------------
echo  Purpose : 60GHz HLK-LD6002B forensic sensor, passive detection mode.
echo            Detects any 60GHz energy present regardless of calibration.
echo            If calibration file exists uses it for classification.
echo            If no calibration file, reports raw presence/coordinate data.
echo            This is the DEFAULT operational mode -- run this first.
echo.
echo  Args:
echo    --port COMx        Serial port  *** REQUIRED ***
echo    --out DIR          Output directory
echo                       Default: %BASE%
echo    --verbose          Print unknown frame types to console
echo    --raw-dump         Hex dump all received bytes (debug)
echo    --list-ports       Show available COM ports and exit
echo.
echo  The sensor reports per frame:
echo    Presence state: NONE / MOTION / MICRO_MOTION / STATIC_PRESENCE
echo    X/Y/Z coordinates cm (ceiling-mount frame)
echo    Velocity cm/s
echo    Motion intensity 0-100
echo    Target count
echo.
echo  Forensic note:
echo    Any presence reading with no person physically in room
echo    = external 60GHz source confirmed.
echo    Velocity ~0 + fixed coordinates = stationary emitter.
echo.
echo  Find your COM port first:
echo    12,--list-ports
echo.
echo  Then run:
echo    12,--port COM5
echo    12,--port COM5 --out C:\sdr\logs
pause & goto menu

:show_help_13
cls
echo  [13] hlk_ld6002b.py  -- EMPTY ROOM CALIBRATION
echo  ----------------------------------------------------------------
echo  Purpose : Establish null-space baseline for 60GHz sensor.
echo            Records what the sensor sees with NOTHING in the room.
echo            This baseline is subtracted during forensic scan to
echo            reveal signals that should not be present.
echo.
echo  Args:
echo    --port COMx        Serial port  *** REQUIRED ***
echo    --out DIR          Output directory (cal saved to runtime/)
echo    --room-x CM        Room width east-west in cm
echo                       Default: 400 (4 meters)
echo    --room-y CM        Room depth north-south in cm
echo                       Default: 400 (4 meters)
echo    --room-z CM        Ceiling height in cm
echo                       Default: 250 (2.5 meters)
echo    --mount-x CM       Module X position from SW corner cm
echo                       Default: 200 (centered)
echo    --mount-y CM       Module Y position from SW corner cm
echo                       Default: 200 (centered)
echo.
echo  PROCEDURE:
echo    1. Remove all people from the room
echo    2. Turn off fans, AC, anything that moves
echo    3. Launch this entry
echo    4. Run for minimum 5 minutes
echo    5. Ctrl+C in the CTW-mmwave-cal window
echo    6. Calibration saves automatically to:
echo         %BASE%\runtime\ld6002b_cal.json
echo.
echo  Example:
echo    13,--port COM5 --room-x 365 --room-y 420 --room-z 265
echo       --mount-x 180 --mount-y 210
pause & goto menu

:show_help_14
cls
echo  [14] hlk_ld6002b.py  -- HUMAN REFERENCE CALIBRATION
echo  ----------------------------------------------------------------
echo  Purpose : Record what a real human looks like per wall direction.
echo            Used to distinguish genuine human presence from an
echo            external 60GHz source during forensic scan.
echo            MUST be run after empty room calibration [13].
echo.
echo  Same args as [13].
echo.
echo  PROCEDURE:
echo    1. Run [13] empty room cal first
echo    2. Enter the room alone
echo    3. Launch this entry
echo    4. Walk slowly along the NORTH wall at 1m from wall
echo       Stay there 30 seconds
echo    5. Walk slowly along the EAST wall at 1m from wall
echo       Stay there 30 seconds
echo    6. Repeat for SOUTH and WEST walls
echo    7. Ctrl+C in the CTW-mmwave-cal window
echo    8. Human reference saves automatically
echo.
echo  After both [13] and [14] complete, entry [15] has a full
echo  null-space reference and can distinguish:
echo    Human body  vs  External 60GHz source
echo    Per-wall direction with coordinate triangulation
echo.
echo  Example:
echo    14,--port COM5 --room-x 365 --room-y 420 --room-z 265
pause & goto menu

:show_help_15
cls
echo  [15] hlk_ld6002b.py  -- FULL FORENSIC SCAN + TRIANGULATION
echo  ----------------------------------------------------------------
echo  Purpose : Full operational forensic mode.
echo            Subtracts empty baseline from live readings.
echo            Classifies any excess as external 60GHz source.
echo            Triangulates source location from multi-wall detections.
echo            Emits to runtime/mmwave_live.jsonl for dashboard.
echo.
echo  Same args as [13].
echo.
echo  ANOMALY CLASSES EMITTED:
echo    STATIC_EMITTER      velocity ~0, fixed coordinates
echo                        = CW or low-rate pulsed 60GHz beam
echo    SLOW_MODULATED      vel 5-30 cm/s
echo                        = FMCW sweep or AM modulated beam
echo    FAST_MODULATED      vel >30 cm/s
echo                        = Doppler-shifted or hopping emitter
echo    TRIANGULATION       source location estimated from 2+ walls
echo.
echo  CLASSIFICATION LOGIC:
echo    Reading vs empty baseline:
echo      Within baseline = BASELINE (normal)
echo    Reading vs human reference:
echo      Matches human  = HUMAN_CONSISTENT (person present)
echo      Neither match  = EXTERNAL_SOURCE (anomaly)
echo    Falls back to raw passive if no cal file found.
echo.
echo  TRIANGULATION:
echo    When 2+ walls show simultaneous anomalous readings,
echo    estimates source X/Y in room coordinates.
echo    Opposite walls (N+S or E+W) give highest confidence.
echo.
echo  Example:
echo    15,--port COM5 --room-x 365 --room-y 420 --room-z 265
echo       --mount-x 180 --mount-y 210 --out C:\sdr\logs
echo.
echo  Recommended full session:
echo    1 2 3 4 5, 15,--port COM5 --room-x 365 --room-y 420
echo      --room-z 265 --mount-x 180 --mount-y 210 16,
pause & goto menu

:show_help_16
cls
echo  [16] sweep.html dashboard
echo  ----------------------------------------------------------------
echo  Purpose : Opens RF forensic monitor in default browser.
echo            URL: http://localhost:8000/sweep.html
echo            Requires [3] rf_server.py to be running.
echo.
echo  PANELS:
echo    Spectrum     dBFS / PEAK / CF overlay across frequency range
echo    Waterfall    dBFS power history (ImageData pixel renderer)
echo    Time series  CF (yellow) / ATTEN (blue) / RMS (green)
echo    Correlation  CORR/EM_ONLY/RF_ONLY events + DR baseline
echo    Sidebar      Current measurement, session stats, anomaly log,
echo                 frequency table
echo.
echo  SOURCE SELECTOR:
echo    SSE    rf_server.py :8000/sse  (primary, auto-detected)
echo    POLL   live_reader.py :8080    (fallback)
echo    DEMO   synthetic data          (no hardware required)
echo.
echo  No args. Opens browser window automatically.
pause & goto menu

:show_help_17
cls
echo  [17] gnss_map.html
echo  ----------------------------------------------------------------
echo  Purpose : Opens GNSS forensic map in default browser.
echo            URL: http://localhost:8001/gnss_map.html
echo            Requires [11] gnss_server.py to be running.
echo.
echo  FEATURES:
echo    Live Leaflet map -- fix markers colored by fix type
echo      Green  = 3D fix (good)
echo      Orange = 2D fix (degraded)
echo      Red    = spoofing indicated
echo    Spoof alert panel -- CRITICAL banner + sidebar entry
echo    Sky view -- satellite constellation canvas
echo    Satellite table -- CNR / elevation / azimuth / usage
echo    Pseudorange panel -- toggleable checkbox per satellite
echo    Tile switcher -- Street / Satellite / Topo / Dark
echo    Track line -- full session path
echo    Follow mode -- auto-pan to latest fix
echo.
echo  No args. Opens browser window automatically.
pause & goto menu

:end_help_check
:: ── Resume normal parsing flow ────────────────────────────────────────────────
if /i "!RAW_INPUT!"=="Q" exit /b 0
if /i "!RAW_INPUT!"=="S" goto do_stop_all

:: ── Apply presets ─────────────────────────────────────────────────────────────
if /i "!RAW_INPUT!"=="A" set RAW_INPUT=1 2 3 4 5 12,--port COM5 --phase scan 16,
if /i "!RAW_INPUT!"=="B" set RAW_INPUT=1 2 3 4 5 16,
if /i "!RAW_INPUT!"=="C" set RAW_INPUT=1 2 3 4 7 8 16,
if /i "!RAW_INPUT!"=="D" set RAW_INPUT=1 2 3 4 6 16,
if /i "!RAW_INPUT!"=="E" set RAW_INPUT=9 10 11 17,
if /i "!RAW_INPUT!"=="F" set RAW_INPUT=1 2 3 4 5 6 7 8 16,
if /i "!RAW_INPUT!"=="G" set RAW_INPUT=12,--port COM5 --phase scan

:: ── Parse input into per-entry argument slots ─────────────────────────────────
:: Strategy: walk the raw input character by character building tokens.
:: A token is either a number (possibly with trailing args before the next
:: comma) or a bare number with no args.
::
:: We replace commas with a sentinel §, then split on spaces while tracking
:: which number we are assigning args to.

:: Normalise: ensure every comma is surrounded by spaces
set "NORMALISED=!RAW_INPUT!"
set "NORMALISED=!NORMALISED:,= § !"

:: Reset all run flags and arg slots
for /l %%N in (1,1,17) do (
    set "RUN_%%N=0"
    set "ARGS_%%N="
)

:: Walk tokens. A token that is a digit string = start of new entry.
:: A token that is § = closes current entry's arg list.
:: Anything else = appended to current entry's args.

set "CURRENT_NUM="
set "COLLECTING=0"

for %%T in (!NORMALISED!) do (
    set "TOK=%%T"

    :: Check if token is the sentinel
    if "!TOK!"=="§" (
        set "CURRENT_NUM="
        set "COLLECTING=0"
    ) else (
        :: Check if token is a number 1-17
        set "IS_NUM=0"
        for /l %%N in (1,1,17) do (
            if "!TOK!"=="%%N" set "IS_NUM=1"
        )

        if "!IS_NUM!"=="1" (
            :: Start a new entry
            set "CURRENT_NUM=!TOK!"
            set "RUN_!TOK!=1"
            set "COLLECTING=1"
        ) else (
            :: Append to current entry's args if we have one
            if defined CURRENT_NUM (
                if "!COLLECTING!"=="1" (
                    if "!ARGS_!CURRENT_NUM!!!"=="" (
                        set "ARGS_!CURRENT_NUM!=!TOK!"
                    ) else (
                        set "ARGS_!CURRENT_NUM!=!ARGS_!CURRENT_NUM!! !TOK!"
                    )
                )
            )
        )
    )
)

:: ── Confirm ───────────────────────────────────────────────────────────────────
cls
echo.
echo  ================================================================
echo   CTW SENTINEL -- LAUNCHING
echo  ================================================================
echo.
for /l %%N in (1,1,17) do (
    if "!RUN_%%N!"=="1" (
        if "!ARGS_%%N!"=="" (
            echo   [%%N]  ^(default args^)
        ) else (
            echo   [%%N]  !ARGS_%%N!
        )
    )
)
echo.
set /p CONFIRM="  Proceed? [Y/N]: "
if /i "!CONFIRM!" NEQ "Y" goto menu

:: ══════════════════════════════════════════════════════════════════════════════
:: PRE-FLIGHT
:: ══════════════════════════════════════════════════════════════════════════════

echo.
echo [CTW] Clearing previous session...
taskkill /FI "WINDOWTITLE eq CTW-gz_watch"    /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-live_reader" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-rf_server"   /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-sweep"       /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-correlator"  /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-ublox_data"  /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-ublox"       /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-gnss"        /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-bt"          /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-css"         /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-css-idle"    /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-mmwave"      /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-mmwave-cal"  /T /F >nul 2>&1
timeout /t 1 /nobreak >nul
echo [  OK] Cleared.

if not exist "%BASE%\runtime"              mkdir "%BASE%\runtime"
if not exist "%BASE%\runtime\process_logs" mkdir "%BASE%\runtime\process_logs"
if not exist "%BASE%\UBLOX"               mkdir "%BASE%\UBLOX"

:: Write stop.bat
(
echo @echo off
echo echo Stopping CTW pipeline...
echo taskkill /FI "WINDOWTITLE eq CTW-gz_watch"    /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-live_reader" /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-rf_server"   /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-sweep"       /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-correlator"  /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-ublox_data"  /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-ublox"       /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-gnss"        /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-bt"          /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-css"         /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-css-idle"    /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-mmwave"      /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-mmwave-cal"  /T /F ^>nul 2^>^&1
echo timeout /t 1 /nobreak ^>nul
echo echo Done.
echo pause
) > "%BASE%\stop.bat"
echo [  OK] stop.bat written.

:: Port checks — only for selected servers
if "!RUN_2!"=="1" (
    %PYTHON% -c "import socket,sys;s=socket.socket();s.settimeout(1);r=s.connect_ex(('127.0.0.1',8080));s.close();sys.exit(0 if r==0 else 1)" >nul 2>&1
    if not errorlevel 1 ( echo [ ERR] Port 8080 in use. Run stop.bat. & pause & goto menu )
)
if "!RUN_3!"=="1" (
    %PYTHON% -c "import socket,sys;s=socket.socket();s.settimeout(1);r=s.connect_ex(('127.0.0.1',8000));s.close();sys.exit(0 if r==0 else 1)" >nul 2>&1
    if not errorlevel 1 ( echo [ ERR] Port 8000 in use. Run stop.bat. & pause & goto menu )
)
if "!RUN_11!"=="1" (
    %PYTHON% -c "import socket,sys;s=socket.socket();s.settimeout(1);r=s.connect_ex(('127.0.0.1',8001));s.close();sys.exit(0 if r==0 else 1)" >nul 2>&1
    if not errorlevel 1 ( echo [ ERR] Port 8001 in use. Run stop.bat. & pause & goto menu )
)
echo [  OK] Ports clear.

:: ══════════════════════════════════════════════════════════════════════════════
:: LAUNCH SELECTED ENTRIES
:: ══════════════════════════════════════════════════════════════════════════════

:: ── [1] gz_watch.py ──────────────────────────────────────────────────────────
if "!RUN_1!"=="1" (
    echo [CTW] [1] gz_watch.py !ARGS_1!
    start "CTW-gz_watch" cmd /k "title CTW-gz_watch && %PYTHON% %BASE%\gz_watch.py !ARGS_1!"
    timeout /t 2 /nobreak >nul
    echo [  OK] gz_watch.
)

:: ── [2] live_reader.py ───────────────────────────────────────────────────────
if "!RUN_2!"=="1" (
    echo [CTW] [2] live_reader.py !ARGS_2!
    start "CTW-live_reader" cmd /k "title CTW-live_reader && %PYTHON% %BASE%\live_reader.py !ARGS_2!"
    echo [CTW] Waiting :8080...
    set WAIT=0
    :wait_8080
    timeout /t 1 /nobreak >nul
    set /a WAIT+=1
    if !WAIT! geq 20 ( echo [ ERR] live_reader timeout. & pause & goto menu )
    %PYTHON% -c "import socket,sys;s=socket.socket();s.settimeout(1);r=s.connect_ex(('127.0.0.1',8080));s.close();sys.exit(0 if r==0 else 1)" >nul 2>&1
    if errorlevel 1 goto wait_8080
    echo [  OK] live_reader :8080.
)

:: ── [3] rf_server.py ─────────────────────────────────────────────────────────
if "!RUN_3!"=="1" (
    echo [CTW] [3] rf_server.py !ARGS_3!
    start "CTW-rf_server" cmd /k "title CTW-rf_server && %PYTHON% %BASE%\rf_server.py !ARGS_3!"
    echo [CTW] Waiting :8000...
    set WAIT=0
    :wait_8000
    timeout /t 1 /nobreak >nul
    set /a WAIT+=1
    if !WAIT! geq 20 ( echo [ ERR] rf_server timeout. & pause & goto menu )
    %PYTHON% -c "import socket,sys;s=socket.socket();s.settimeout(1);r=s.connect_ex(('127.0.0.1',8000));s.close();sys.exit(0 if r==0 else 1)" >nul 2>&1
    if errorlevel 1 goto wait_8000
    echo [  OK] rf_server :8000.
)

:: ── [4] correlator.py ────────────────────────────────────────────────────────
if "!RUN_4!"=="1" (
    set "_A4=--rf-live %BASE%\runtime\sweep_live.jsonl --out %BASE%\runtime --window 0.5 --spike 0.10"
    if not "!ARGS_4!"=="" set "_A4=!ARGS_4!"
    echo [CTW] [4] correlator.py !_A4!
    start "CTW-correlator" cmd /k "title CTW-correlator && %PYTHON% %BASE%\correlator.py !_A4!"
    timeout /t 1 /nobreak >nul
    echo [  OK] correlator.
)

:: ── [5] pluto_sweep.py ───────────────────────────────────────────────────────
if "!RUN_5!"=="1" (
    set "_A5=--out %BASE% --start 385900000 --stop 386100000 --step 10000 --no-iq"
    if not "!ARGS_5!"=="" set "_A5=!ARGS_5!"
    echo [CTW] [5] pluto_sweep.py !_A5!
    start "CTW-sweep" cmd /k "title CTW-sweep && %PYTHON% %BASE%\pluto_sweep.py !_A5!"
    timeout /t 1 /nobreak >nul
    echo [  OK] pluto_sweep.
)

:: ── [6] bt_scanner.py ────────────────────────────────────────────────────────
if "!RUN_6!"=="1" (
    if exist "%BASE%\bt_scanner.py" (
        set "_A6=--out %BASE% --rssi-threshold -75"
        if not "!ARGS_6!"=="" set "_A6=!ARGS_6!"
        echo [CTW] [6] bt_scanner.py !_A6!
        start "CTW-bt" cmd /k "title CTW-bt && %PYTHON% %BASE%\bt_scanner.py !_A6!"
        timeout /t 2 /nobreak >nul
        echo [  OK] bt_scanner.
    ) else ( echo [WARN] bt_scanner.py not found. )
)

:: ── [7] css_hunter.py ────────────────────────────────────────────────────────
if "!RUN_7!"=="1" (
    if exist "%BASE%\css_hunter.py" (
        set "_A7=--out %BASE% --bands 2 4 5 12 13 66 71 --dwell-ms 20"
        if not "!ARGS_7!"=="" set "_A7=!ARGS_7!"
        echo [CTW] [7] css_hunter.py !_A7!
        start "CTW-css" cmd /k "title CTW-css && %PYTHON% %BASE%\css_hunter.py !_A7!"
        timeout /t 2 /nobreak >nul
        echo [  OK] css_hunter.
    ) else ( echo [WARN] css_hunter.py not found. )
)

:: ── [8] css_idle_hunter.py ───────────────────────────────────────────────────
if "!RUN_8!"=="1" (
    if exist "%BASE%\css_idle_hunter.py" (
        set "_A8=--out %BASE% --sensitivity 10 --persist-min 3"
        if not "!ARGS_8!"=="" set "_A8=!ARGS_8!"
        echo [CTW] [8] css_idle_hunter.py !_A8!
        start "CTW-css-idle" cmd /k "title CTW-css-idle && %PYTHON% %BASE%\css_idle_hunter.py !_A8!"
        timeout /t 2 /nobreak >nul
        echo [  OK] css_idle_hunter.
    ) else ( echo [WARN] css_idle_hunter.py not found. )
)

:: ── [9] ublox_data.py ────────────────────────────────────────────────────────
if "!RUN_9!"=="1" (
    if exist "%BASE%\ublox_data.py" (
        echo [CTW] [9] ublox_data.py !ARGS_9!
        start "CTW-ublox_data" cmd /k "title CTW-ublox_data && %PYTHON% %BASE%\ublox_data.py !ARGS_9!"
        echo [CTW] Waiting 5s for UBX file...
        timeout /t 5 /nobreak >nul
        echo [  OK] ublox_data.
    ) else ( echo [WARN] ublox_data.py not found. )
)

:: ── [10] ublox_parser.py ─────────────────────────────────────────────────────
if "!RUN_10!"=="1" (
    if exist "%BASE%\ublox_parser.py" (
        set "_A10=--ubx-dir %BASE%\UBLOX --out %BASE%\UBLOX"
        if not "!ARGS_10!"=="" set "_A10=!ARGS_10!"
        echo [CTW] [10] ublox_parser.py !_A10!
        start "CTW-ublox" cmd /k "title CTW-ublox && %PYTHON% %BASE%\ublox_parser.py !_A10!"
        timeout /t 2 /nobreak >nul
        echo [  OK] ublox_parser.
    ) else ( echo [WARN] ublox_parser.py not found. )
)

:: ── [11] gnss_server.py ──────────────────────────────────────────────────────
if "!RUN_11!"=="1" (
    if exist "%BASE%\gnss_server.py" (
        echo [CTW] [11] gnss_server.py !ARGS_11!
        start "CTW-gnss" cmd /k "title CTW-gnss && %PYTHON% %BASE%\gnss_server.py !ARGS_11!"
        echo [CTW] Waiting :8001...
        set WAIT=0
        :wait_8001
        timeout /t 1 /nobreak >nul
        set /a WAIT+=1
        if !WAIT! geq 20 ( echo [WARN] gnss_server timeout. & goto skip_gnss )
        %PYTHON% -c "import socket,sys;s=socket.socket();s.settimeout(1);r=s.connect_ex(('127.0.0.1',8001));s.close();sys.exit(0 if r==0 else 1)" >nul 2>&1
        if errorlevel 1 goto wait_8001
        echo [  OK] gnss_server :8001.
    ) else ( echo [WARN] gnss_server.py not found. )
)
:skip_gnss

:: ── [12] hlk_ld6002b.py -- passive scan (default, no calibration required) ──
if "!RUN_12!"=="1" (
    if exist "%BASE%\hlk_ld6002b.py" (
        :: Default: passive scan mode. Falls back to raw output if no cal file.
        :: Operator passes --port at minimum. Room args optional.
        set "_A12=--phase scan --out %BASE%"
        if not "!ARGS_12!"=="" set "_A12=!ARGS_12!"
        echo [CTW] [12] hlk_ld6002b.py (passive scan) !_A12!
        start "CTW-mmwave" cmd /k "title CTW-mmwave && %PYTHON% %BASE%\hlk_ld6002b.py !_A12!"
        timeout /t 2 /nobreak >nul
        echo [  OK] hlk_ld6002b passive scan.
    ) else ( echo [WARN] hlk_ld6002b.py not found. )
)

:: ── [13] hlk_ld6002b.py -- empty room calibration ───────────────────────────
if "!RUN_13!"=="1" (
    if exist "%BASE%\hlk_ld6002b.py" (
        set "_A13=--phase empty --out %BASE%"
        if not "!ARGS_13!"=="" set "_A13=!ARGS_13!"
        echo [CTW] [13] hlk_ld6002b.py (empty room cal) !_A13!
        echo [WARN] Room must be completely empty during this phase.
        echo [WARN] Run for 5 minutes minimum then Ctrl+C in the window.
        start "CTW-mmwave-cal" cmd /k "title CTW-mmwave-cal (EMPTY ROOM) && %PYTHON% %BASE%\hlk_ld6002b.py !_A13!"
        timeout /t 2 /nobreak >nul
        echo [  OK] hlk_ld6002b empty room cal started.
    ) else ( echo [WARN] hlk_ld6002b.py not found. )
)

:: ── [14] hlk_ld6002b.py -- human reference calibration ──────────────────────
if "!RUN_14!"=="1" (
    if exist "%BASE%\hlk_ld6002b.py" (
        set "_A14=--phase human --out %BASE%"
        if not "!ARGS_14!"=="" set "_A14=!ARGS_14!"
        echo [CTW] [14] hlk_ld6002b.py (human reference cal) !_A14!
        echo [WARN] Walk slowly along each wall at 1m distance.
        echo [WARN] Cover NORTH EAST SOUTH WEST then Ctrl+C.
        start "CTW-mmwave-cal" cmd /k "title CTW-mmwave-cal (HUMAN REF) && %PYTHON% %BASE%\hlk_ld6002b.py !_A14!"
        timeout /t 2 /nobreak >nul
        echo [  OK] hlk_ld6002b human ref cal started.
    ) else ( echo [WARN] hlk_ld6002b.py not found. )
)

:: ── [15] hlk_ld6002b.py -- full forensic scan + triangulation ────────────────
if "!RUN_15!"=="1" (
    if exist "%BASE%\hlk_ld6002b.py" (
        set "_A15=--phase scan --out %BASE%"
        if not "!ARGS_15!"=="" set "_A15=!ARGS_15!"
        echo [CTW] [15] hlk_ld6002b.py (forensic scan + triangulate) !_A15!
        start "CTW-mmwave" cmd /k "title CTW-mmwave && %PYTHON% %BASE%\hlk_ld6002b.py !_A15!"
        timeout /t 2 /nobreak >nul
        echo [  OK] hlk_ld6002b forensic scan.
    ) else ( echo [WARN] hlk_ld6002b.py not found. )
)

:: ── [16] sweep.html dashboard ────────────────────────────────────────────────
if "!RUN_16!"=="1" (
    echo [CTW] [16] Opening sweep.html...
    timeout /t 2 /nobreak >nul
    start "" "http://localhost:8000/sweep.html"
    echo [  OK] sweep.html opened.
)

:: ── [17] gnss_map.html ───────────────────────────────────────────────────────
if "!RUN_17!"=="1" (
    echo [CTW] [17] Opening gnss_map.html...
    timeout /t 1 /nobreak >nul
    start "" "http://localhost:8001/gnss_map.html"
    echo [  OK] gnss_map.html opened.
)

:: ══════════════════════════════════════════════════════════════════════════════
:: STATUS
:: ══════════════════════════════════════════════════════════════════════════════

echo.
echo  ================================================================
echo   CTW SENTINEL -- ACTIVE
echo.
echo   WIN   TITLE              ENTRY   DEFAULT PURPOSE
echo   ---   -----              -----   ---------------
if "!RUN_1!"=="1"  echo   *     CTW-gz_watch       [1]     gzip mirror watcher
if "!RUN_2!"=="1"  echo   *     CTW-live_reader    [2]     JSONL cursor :8080
if "!RUN_3!"=="1"  echo   *     CTW-rf_server      [3]     SSE broadcast :8000
if "!RUN_4!"=="1"  echo   *     CTW-correlator     [4]     RF/Geiger correlator
if "!RUN_5!"=="1"  echo   *     CTW-sweep          [5]     PlutoSDR 386MHz sweep
if "!RUN_6!"=="1"  echo   *     CTW-bt             [6]     BT/BLE scanner
if "!RUN_7!"=="1"  echo   *     CTW-css            [7]     CSS band scanner
if "!RUN_8!"=="1"  echo   *     CTW-css-idle       [8]     CSS idle/gap scanner
if "!RUN_9!"=="1"  echo   *     CTW-ublox_data     [9]     u-blox UBX capture
if "!RUN_10!"=="1" echo   *     CTW-ublox          [10]    UBX parser
if "!RUN_11!"=="1" echo   *     CTW-gnss           [11]    GNSS map :8001
if "!RUN_12!"=="1" echo   *     CTW-mmwave         [12]    60GHz passive scan
if "!RUN_13!"=="1" echo   *     CTW-mmwave-cal     [13]    60GHz empty room cal
if "!RUN_14!"=="1" echo   *     CTW-mmwave-cal     [14]    60GHz human ref cal
if "!RUN_15!"=="1" echo   *     CTW-mmwave         [15]    60GHz forensic scan
if "!RUN_16!"=="1" echo   *     browser            [16]    sweep.html
if "!RUN_17!"=="1" echo   *     browser            [17]    gnss_map.html
echo.
echo   RF   : http://localhost:8000/sweep.html
echo   GNSS : http://localhost:8001/gnss_map.html
echo.
echo   Run stop.bat to kill all.
echo  ================================================================
echo.

set /p NEXT="  [M] Menu  [S] Stop all  [Q] Quit: "
if /i "!NEXT!"=="M" goto menu
if /i "!NEXT!"=="S" goto do_stop_all
exit /b 0

:: ══════════════════════════════════════════════════════════════════════════════
:: STOP ALL
:: ══════════════════════════════════════════════════════════════════════════════

:do_stop_all
echo.
echo [CTW] Stopping all CTW processes...
taskkill /FI "WINDOWTITLE eq CTW-gz_watch"    /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-live_reader" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-rf_server"   /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-sweep"       /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-correlator"  /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-ublox_data"  /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-ublox"       /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-gnss"        /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-bt"          /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-css"         /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-css-idle"    /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-mmwave"      /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-mmwave-cal"  /T /F >nul 2>&1
timeout /t 1 /nobreak >nul
echo [  OK] All stopped.
echo.
set /p BACK="  [M] Menu  [Q] Quit: "
if /i "!BACK!"=="M" goto menu
exit /b 0
