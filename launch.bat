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
echo   [18] gnss_anomaly_report.py  GNSS forensic anomaly detection report
echo.
echo   POST-SESSION
echo   [19] geiger_sdr_correlator.py  Post-session Geiger/SDR correlation
echo.
echo   BROADCAST / AoA
echo   [20] broadcast_monitor.py      Licensed AM/FM carrier power monitor
echo   [21] broadcast_map_server.py   AoA bearing map server       :8002
echo   [22] Open broadcast_map.html   http://localhost:8002/
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
:: HELP SYSTEM
:: ══════════════════════════════════════════════════════════════════════════════

set "HELP_INPUT=!RAW_INPUT!"

if /i "!HELP_INPUT!"=="H"    goto show_full_help
if /i "!HELP_INPUT!"=="HELP" goto show_full_help
if /i "!HELP_INPUT!"=="?"    goto show_full_help

for /l %%N in (1,1,22) do (
    if "!HELP_INPUT!"=="?%%N" goto show_help_%%N
)

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
echo.
echo   [2]  live_reader.py
echo        No arguments. Serves runtime/sweep_live.jsonl on :8080.
echo.
echo   [3]  rf_server.py
echo        No arguments. SSE broadcast on :8000.
echo.
echo   [4]  correlator.py
echo        --rf-live PATH     sweep_live.jsonl path
echo        --out DIR          output directory
echo        --window SECS      correlation window seconds (default 0.5)
echo        --spike USVH       Geiger spike threshold uSv/h (default 0.10)
echo        --serial-log PATH  fs5000 serial log path (auto-detect)
echo        --audio-log PATH   fs5000 audio log path (auto-detect)
echo.
echo   [5]  pluto_sweep.py
echo        --uri URI          PlutoSDR URI (default ip:192.168.2.1)
echo        --out DIR          output directory
echo        --start HZ / --stop HZ / --step HZ
echo        --freqs HZ [HZ]    explicit frequency list
echo        --dwell-ms MS      dwell time per step
echo        --settle-ms MS     settle time per step
echo        --anomaly-atten DB anomaly threshold dB (default 40)
echo        --no-iq            disable IQ stream
echo        --quiet            suppress console output
echo.
echo   [6]  bt_scanner.py
echo        --uri URI / --center HZ / --bw HZ / --gain DB
echo        --rssi-threshold   dBFS anomaly threshold (default -75)
echo        --out DIR / --adv-only
echo.
echo   [7]  css_hunter.py
echo        --uri URI / --bands N [N] / --dwell-ms MS / --anomaly-db DB
echo        --no-pss / --no-sdr / --no-at / --at-port X
echo        --target-earfcn N / --verify-chain / --out DIR
echo.
echo   [8]  css_idle_hunter.py
echo        --uri URI / --sensitivity DB / --dwell-ms MS
echo        --persist-min N / --out DIR
echo.
echo   [9]  ublox_data.py      No CLI args -- edit COM_PORT in script.
echo.
echo   [10] ublox_parser.py
echo        --ubx-dir DIR / --ubx-file PATH / --out DIR
echo        --compass-port HOST:PORT   heading from compass_bridge.py
echo.
echo   [11] gnss_server.py     No arguments. SSE :8001 + gnss_map.html.
echo.
echo   [12] hlk_ld6002b.py (passive scan)
echo        --port COMx (REQUIRED) / --out DIR / --verbose / --raw-dump
echo        --list-ports
echo        Example: 12,--port COM5
echo.
echo   [13] hlk_ld6002b.py (empty room calibration)
echo        --port COMx / --out DIR
echo        --room-x CM / --room-y CM / --room-z CM
echo        --mount-x CM / --mount-y CM
echo.
echo   [14] hlk_ld6002b.py (human reference calibration)
echo        Same args as [13]. Run AFTER [13].
echo.
echo   [15] hlk_ld6002b.py (full forensic scan + triangulation)
echo        Same args as [13].
echo.
echo   [16] Opens http://localhost:8000/sweep.html
echo   [17] Opens http://localhost:8001/gnss_map.html
echo.
echo   [18] gnss_anomaly_report.py
echo        --log PATH / --all-logs / --ground-truth LAT,LON / --out DIR
echo        Example: 18,--ground-truth 33.800509,-117.220352
echo.
echo   [19] geiger_sdr_correlator.py
echo        --sdr-log FILE / --serial-log FILE / --audio-log FILE
echo        --all-sessions / --baseline-dr USVH
echo        --window SEC / --lag-max SEC / --out DIR
echo        Example: 19,--baseline-dr 0.02
echo.
echo   [20] broadcast_monitor.py
echo        --lat LAT (required) / --lon LON (required)
echo        --radius-km KM / --bands AM FM / --dwell-ms MS
echo        --anomaly-db DB / --gain DB
echo        --use-cache PATH / --no-fcc
echo        NOTE: Power level only. No content captured or stored.
echo        Example: 20,--lat 33.800509 --lon -117.220352
echo.
echo   [21] broadcast_map_server.py
echo        No arguments. Serves broadcast_map.html + SSE on :8002.
echo        Tails runtime/broadcast_live.jsonl + runtime/gnss_live.jsonl.
echo        Accepts POST /aoa for manual AoA bearing entries.
echo.
echo   [22] Opens http://localhost:8002/ (broadcast AoA map)
echo.
echo  ----------------------------------------------------------------
echo   COMMON EXAMPLES
echo.
echo   Core + 386MHz sweep + browser:
echo     1 2 3 4 5, 16,
echo.
echo   Broadcast AoA session:
echo     1 2 3 4 5, 9 10 11 20,--lat 33.800509 --lon -117.220352 21 22,
echo.
echo   Core + CSS active + idle + browser:
echo     1 2 3 4 7,--bands 2 4 66 71 8, 16,
echo.
echo   GNSS only:
echo     9 10 11 17,
echo.
echo  ================================================================
pause
goto menu

:: ══════════════════════════════════════════════════════════════════════════════
:: PER-ENTRY HELP (?N)
:: ══════════════════════════════════════════════════════════════════════════════

:show_help_1
cls
echo  [1] gz_watch.py
echo  ----------------------------------------------------------------
echo  Watches BASE directory for growing *.jsonl.gz files.
echo  Mirrors new records into runtime/sweep_live.jsonl.
echo  Must be running before any sweep logger writes data.
echo  Args: None
pause & goto menu

:show_help_2
cls
echo  [2] live_reader.py
echo  ----------------------------------------------------------------
echo  HTTP server :8080 serving runtime/sweep_live.jsonl.
echo  Supports HTTP Range requests for cursor-based polling.
echo  Used by sweep.html POLL transport.
echo  Args: None
pause & goto menu

:show_help_3
cls
echo  [3] rf_server.py
echo  ----------------------------------------------------------------
echo  SSE broadcast server :8000.
echo  Tails sweep_live.jsonl and corr_live.jsonl.
echo  Also serves sweep.html as a static file.
echo  Args: None
pause & goto menu

:show_help_4
cls
echo  [4] correlator.py
echo  ----------------------------------------------------------------
echo    --rf-live PATH     Default: %BASE%\runtime\sweep_live.jsonl
echo    --out DIR          Default: %BASE%\runtime
echo    --window SECS      Default: 0.5
echo    --spike USVH       Default: 0.10
echo    --serial-log PATH  fs5000 serial log (auto-detect)
echo    --audio-log PATH   fs5000 audio log (auto-detect)
echo  Example: 4,--window 1.0 --spike 0.05
pause & goto menu

:show_help_5
cls
echo  [5] pluto_sweep.py
echo  ----------------------------------------------------------------
echo    --uri URI          Default: ip:192.168.2.1
echo    --out DIR          Default: %BASE%
echo    --start HZ         Default: 385900000
echo    --stop HZ          Default: 386100000
echo    --step HZ          Default: 10000
echo    --freqs HZ [HZ]    Explicit list, overrides start/stop/step
echo    --dwell-ms MS      Default: 0
echo    --settle-ms MS     Default: 0
echo    --anomaly-atten DB Default: 40.0
echo    --no-iq            Disable IQ stream (saves RAM)
echo    --quiet            Suppress console output
echo  Examples:
echo    5,--freqs 386000000 386020000
echo    5,--start 70000000 --stop 6000000000 --step 1000000 --no-iq
pause & goto menu

:show_help_6
cls
echo  [6] bt_scanner.py
echo  ----------------------------------------------------------------
echo    --uri URI          Default: ip:192.168.2.1
echo    --center HZ        Default: 2441000000
echo    --bw HZ            Default: 56000000
echo    --gain DB          Default: 40
echo    --rssi-threshold   Default: -75
echo    --out DIR
echo    --adv-only         Advertising channels only
echo  NOTE: Shares PlutoSDR with [5]. Use second unit for simultaneous.
echo  Example: 6,--rssi-threshold -65 --gain 45
pause & goto menu

:show_help_7
cls
echo  [7] css_hunter.py
echo  ----------------------------------------------------------------
echo    --uri URI          Default: ip:192.168.2.1
echo    --bands N [N]      Default: 2 4 5 12 13 66 71
echo    --dwell-ms MS      Default: 20
echo    --anomaly-db DB    Default: 12
echo    --no-pss           Disable PSS ZC correlation
echo    --no-sdr           AT layer only
echo    --no-at            SDR layer only
echo    --at-port X        COM8 / /dev/ttyUSB2 / localhost:5555
echo    --target-earfcn N  Force specific EARFCNs
echo    --verify-chain     Verify SHA-256 chain of previous session
echo    --out DIR
echo  IOC table: TAC 65535/0, EARFCN 66586/1538/1000/68911, PCI 242/186
echo  Examples:
echo    7,--bands 2 4 5 12 13 66 71 --at-port COM8
echo    7,--no-sdr --at-port COM8
echo    7,--target-earfcn 66586 1538 1000 --at-port COM8
echo    7,--verify-chain
pause & goto menu

:show_help_8
cls
echo  [8] css_idle_hunter.py
echo  ----------------------------------------------------------------
echo    --uri URI
echo    --sensitivity DB   Default: 10
echo    --dwell-ms MS      Default: 15
echo    --persist-min N    Default: 3
echo    --out DIR
echo  Gap regions include 386 MHz IOC, harmonics, PCS/AWS gaps.
echo  Example: 8,--sensitivity 8 --persist-min 5
pause & goto menu

:show_help_9
cls
echo  [9] ublox_data.py
echo  ----------------------------------------------------------------
echo  u-blox 7 GNSS raw binary capture.
echo  Output: C:\GNSS_Evidence\ublox7_STAMP.ubx + .nmea
echo  Args: None -- edit COM_PORT at top of ublox_data.py (default COM7)
pause & goto menu

:show_help_10
cls
echo  [10] ublox_parser.py
echo  ----------------------------------------------------------------
echo    --ubx-dir DIR      Default: %BASE%\UBLOX
echo    --ubx-file PATH    Exact file (overrides --ubx-dir)
echo    --out DIR          Default: %BASE%\UBLOX
echo    --compass-port HOST:PORT   heading from compass_bridge.py
echo  Example: 10,--compass-port localhost:5556
pause & goto menu

:show_help_11
cls
echo  [11] gnss_server.py
echo  ----------------------------------------------------------------
echo  GNSS forensic map server :8001.
echo  Tails runtime/gnss_live.jsonl via SSE.
echo  Serves gnss_map.html -- live fixes, spoof alerts, sky view,
echo  satellite table, pseudorange panel, tile switcher.
echo  Args: None
echo  Browse: http://localhost:8001/gnss_map.html
pause & goto menu

:show_help_12
cls
echo  [12] hlk_ld6002b.py -- PASSIVE SCAN
echo  ----------------------------------------------------------------
echo    --port COMx   *** REQUIRED ***
echo    --out DIR     Default: %BASE%
echo    --verbose     Print unknown frame types
echo    --raw-dump    Hex dump all bytes
echo    --list-ports  Show available COM ports
echo  Example: 12,--port COM5
pause & goto menu

:show_help_13
cls
echo  [13] hlk_ld6002b.py -- EMPTY ROOM CALIBRATION
echo  ----------------------------------------------------------------
echo    --port COMx   *** REQUIRED ***
echo    --room-x CM   Default: 400
echo    --room-y CM   Default: 400
echo    --room-z CM   Default: 250
echo    --mount-x CM  Default: 200
echo    --mount-y CM  Default: 200
echo  Remove all people. Run 5 min minimum. Ctrl+C to save.
echo  Example: 13,--port COM5 --room-x 365 --room-y 420 --room-z 265
pause & goto menu

:show_help_14
cls
echo  [14] hlk_ld6002b.py -- HUMAN REFERENCE CALIBRATION
echo  ----------------------------------------------------------------
echo  Same args as [13]. Must run AFTER [13].
echo  Walk N/E/S/W walls at 1m. 30s per wall. Ctrl+C to save.
echo  Example: 14,--port COM5 --room-x 365 --room-y 420 --room-z 265
pause & goto menu

:show_help_15
cls
echo  [15] hlk_ld6002b.py -- FULL FORENSIC SCAN + TRIANGULATION
echo  ----------------------------------------------------------------
echo  Same args as [13].
echo  Classifies: STATIC_EMITTER / SLOW_MODULATED / FAST_MODULATED
echo  Triangulates when 2+ walls show simultaneous anomaly.
echo  Falls back to raw passive scan if no cal file found.
echo  Example: 15,--port COM5 --room-x 365 --room-y 420 --room-z 265
echo           --mount-x 180 --mount-y 210
pause & goto menu

:show_help_16
cls
echo  [16] sweep.html dashboard
echo  ----------------------------------------------------------------
echo  Opens http://localhost:8000/sweep.html
echo  Requires [3] rf_server.py running.
echo  Panels: Spectrum / Waterfall / Time series / Correlation / Sidebar
echo  Sources: SSE (primary) / POLL / DEMO
pause & goto menu

:show_help_17
cls
echo  [17] gnss_map.html
echo  ----------------------------------------------------------------
echo  Opens http://localhost:8001/gnss_map.html
echo  Requires [11] gnss_server.py running.
echo  Features: Live fixes / Spoof alerts / Sky view / Sat table /
echo            Pseudorange / Tile switcher / Track / Follow mode
pause & goto menu

:show_help_18
cls
echo  [18] gnss_anomaly_report.py
echo  ----------------------------------------------------------------
echo    --log PATH              Specific gnss_*.jsonl.gz to analyze
echo    --all-logs              Process all logs in output directory
echo    --ground-truth LAT,LON  Static receiver position
echo    --out DIR               Default: %BASE%
echo  Example: 18,--ground-truth 33.800509,-117.220352
pause & goto menu

:show_help_19
cls
echo  [19] geiger_sdr_correlator.py
echo  ----------------------------------------------------------------
echo    --sdr-log FILE [FILE]     sweep_*.jsonl.gz file(s)
echo    --serial-log FILE [FILE]  serial_*.jsonl.gz file(s)
echo    --audio-log FILE [FILE]   audio_*.jsonl.gz file(s)
echo    --all-sessions            Process all matched sessions
echo    --baseline-dr USVH        Known baseline dose rate
echo    --window SEC              Default: 30
echo    --lag-max SEC             Default: 0.5
echo    --out DIR                 Default: %BASE%
echo  Examples:
echo    19,--baseline-dr 0.02
echo    19,--all-sessions --baseline-dr 0.02
pause & goto menu

:show_help_20
cls
echo  [20] broadcast_monitor.py
echo  ----------------------------------------------------------------
echo    --lat LAT         Observer latitude  *** REQUIRED ***
echo    --lon LON         Observer longitude *** REQUIRED ***
echo    --radius-km KM    Station search radius (default 150)
echo    --bands AM FM     Bands to monitor (default: FM AM)
echo    --dwell-ms MS     Dwell per window ms (default 200)
echo    --anomaly-db DB   Deviation to flag dB (default 8)
echo    --gain DB         SDR gain (default 40)
echo    --use-cache PATH  Load station DB from cache file
echo    --no-fcc          Skip FCC fetch (cache required)
echo  NOTE: Power level ONLY. No content captured or stored.
echo  Anomaly classes: CARRIER_ABSENT / CARRIER_SUPPRESSED /
echo    CARRIER_ELEVATED / CARRIER_DRIFT / CARRIER_SPURIOUS /
echo    INTERMODULATION
echo  Outputs:
echo    broadcast_monitor_STAMP.jsonl.gz  -- compressed forensic log
echo    runtime/broadcast_live.jsonl      -- live SSE mirror
echo    broadcast_stations_STAMP.json     -- FCC station cache
echo  Examples:
echo    20,--lat 33.800509 --lon -117.220352
echo    20,--lat 33.800509 --lon -117.220352 --bands FM --radius-km 100
pause & goto menu

:show_help_21
cls
echo  [21] broadcast_map_server.py
echo  ----------------------------------------------------------------
echo  AoA bearing map server :8002.
echo  No arguments required.
echo  SSE feeds:
echo    /events/broadcast  tails runtime/broadcast_live.jsonl
echo    /events/gnss       tails runtime/gnss_live.jsonl
echo  POST /aoa  -- log manual AoA bearing measurement
echo    Body: { freq_mhz, heading_deg, power_dbfs, callsign }
echo    OOB-guarded. Written to aoa_log_STAMP.jsonl + broadcast_live.
echo  Serves broadcast_map.html on /
echo  Browse: http://localhost:8002/
echo  Run [20] first to populate broadcast_live.jsonl with stations.
echo  Run [9][10] for live GNSS observer position.
pause & goto menu

:show_help_22
cls
echo  [22] broadcast_map.html
echo  ----------------------------------------------------------------
echo  Opens http://localhost:8002/
echo  Requires [21] broadcast_map_server.py running.
echo  Features:
echo    Licensed AM/FM station markers at FCC geocoordinates
echo    Dashed bearing lines: observer -> licensed tower
echo    AoA Entry panel: freq / compass heading / dBFS / callsign
echo    AoA ray drawn on map colored by delta:
echo      Green  ^< 10 deg  -- Normal
echo      Yellow 10-30 deg  -- Investigate
echo      Red    ^> 30 deg  -- ANOMALY (signal not from licensed coords)
echo    Anomaly table: callsign / freq / licensed bearing /
echo                   measured AoA / delta / power / timestamp
echo    Live GNSS observer position (blue dot, auto-updates)
echo    Tile switcher: Street / Satellite / Dark
pause & goto menu

:end_help_check

:: ══════════════════════════════════════════════════════════════════════════════
:: CONTROL FLOW
:: ══════════════════════════════════════════════════════════════════════════════

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
set "NORMALISED=!RAW_INPUT!"
set "NORMALISED=!NORMALISED:,= § !"

for /l %%N in (1,1,22) do (
    set "RUN_%%N=0"
    set "ARGS_%%N="
)

set "CURRENT_NUM="
set "COLLECTING=0"

for %%T in (!NORMALISED!) do (
    set "TOK=%%T"
    if "!TOK!"=="§" (
        set "CURRENT_NUM="
        set "COLLECTING=0"
    ) else (
        set "IS_NUM=0"
        for /l %%N in (1,1,22) do (
            if "!TOK!"=="%%N" set "IS_NUM=1"
        )
        if "!IS_NUM!"=="1" (
            set "CURRENT_NUM=!TOK!"
            set "RUN_!TOK!=1"
            set "COLLECTING=1"
        ) else (
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
for /l %%N in (1,1,22) do (
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
taskkill /FI "WINDOWTITLE eq CTW-bcast"       /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-bcast-map"   /T /F >nul 2>&1
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
echo taskkill /FI "WINDOWTITLE eq CTW-bcast"       /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-bcast-map"   /T /F ^>nul 2^>^&1
echo timeout /t 1 /nobreak ^>nul
echo echo Done.
echo pause
) > "%BASE%\stop.bat"
echo [  OK] stop.bat written.

:: Port checks
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
if "!RUN_21!"=="1" (
    %PYTHON% -c "import socket,sys;s=socket.socket();s.settimeout(1);r=s.connect_ex(('127.0.0.1',8002));s.close();sys.exit(0 if r==0 else 1)" >nul 2>&1
    if not errorlevel 1 ( echo [ ERR] Port 8002 in use. Run stop.bat. & pause & goto menu )
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

:: ── [12] hlk_ld6002b.py -- passive scan ──────────────────────────────────────
if "!RUN_12!"=="1" (
    if exist "%BASE%\hlk_ld6002b.py" (
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

:: ── [16] sweep.html ──────────────────────────────────────────────────────────
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

:: ── [18] gnss_anomaly_report.py ──────────────────────────────────────────────
if "!RUN_18!"=="1" (
    if exist "%BASE%\gnss_anomaly_report.py" (
        set "_A18=--out %BASE%"
        if not "!ARGS_18!"=="" set "_A18=!ARGS_18!"
        echo [CTW] [18] gnss_anomaly_report.py !_A18!
        start "CTW-gnss-report" cmd /k "title CTW-gnss-report && %PYTHON% %BASE%\gnss_anomaly_report.py !_A18!"
        timeout /t 1 /nobreak >nul
        echo [  OK] gnss_anomaly_report.
    ) else ( echo [WARN] gnss_anomaly_report.py not found. )
)

:: ── [19] geiger_sdr_correlator.py ────────────────────────────────────────────
if "!RUN_19!"=="1" (
    if exist "%BASE%\geiger_sdr_correlator.py" (
        set "_A19=--out %BASE%"
        if not "!ARGS_19!"=="" set "_A19=!ARGS_19!"
        echo [CTW] [19] geiger_sdr_correlator.py !_A19!
        start "CTW-geiger-corr" cmd /k "title CTW-geiger-corr && %PYTHON% %BASE%\geiger_sdr_correlator.py !_A19!"
        timeout /t 1 /nobreak >nul
        echo [  OK] geiger_sdr_correlator.
    ) else ( echo [WARN] geiger_sdr_correlator.py not found. )
)

:: ── [20] broadcast_monitor.py ────────────────────────────────────────────────
if "!RUN_20!"=="1" (
    if exist "%BASE%\broadcast_monitor.py" (
        set "_A20=--out %BASE%"
        if not "!ARGS_20!"=="" set "_A20=!ARGS_20!"
        echo [CTW] [20] broadcast_monitor.py !_A20!
        start "CTW-bcast" cmd /k "title CTW-bcast && %PYTHON% %BASE%\broadcast_monitor.py !_A20!"
        timeout /t 2 /nobreak >nul
        echo [  OK] broadcast_monitor.
    ) else ( echo [WARN] broadcast_monitor.py not found. )
)

:: ── [21] broadcast_map_server.py ─────────────────────────────────────────────
if "!RUN_21!"=="1" (
    if exist "%BASE%\broadcast_map_server.py" (
        echo [CTW] [21] broadcast_map_server.py !ARGS_21!
        start "CTW-bcast-map" cmd /k "title CTW-bcast-map && %PYTHON% %BASE%\broadcast_map_server.py !ARGS_21!"
        echo [CTW] Waiting :8002...
        set WAIT=0
        :wait_8002
        timeout /t 1 /nobreak >nul
        set /a WAIT+=1
        if !WAIT! geq 20 ( echo [WARN] broadcast_map_server timeout. & goto skip_bcast_map )
        %PYTHON% -c "import socket,sys;s=socket.socket();s.settimeout(1);r=s.connect_ex(('127.0.0.1',8002));s.close();sys.exit(0 if r==0 else 1)" >nul 2>&1
        if errorlevel 1 goto wait_8002
        echo [  OK] broadcast_map_server :8002.
    ) else ( echo [WARN] broadcast_map_server.py not found. )
)
:skip_bcast_map

:: ── [22] broadcast_map.html ──────────────────────────────────────────────────
if "!RUN_22!"=="1" (
    echo [CTW] [22] Opening broadcast_map.html...
    timeout /t 1 /nobreak >nul
    start "" "http://localhost:8002/"
    echo [  OK] broadcast_map.html opened.
)

:: ══════════════════════════════════════════════════════════════════════════════
:: STATUS BOARD
:: ══════════════════════════════════════════════════════════════════════════════

echo.
echo  ================================================================
echo   CTW SENTINEL -- ACTIVE
echo.
echo   WIN   TITLE              ENTRY   PURPOSE
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
if "!RUN_18!"=="1" echo   *     CTW-gnss-report    [18]    GNSS anomaly report
if "!RUN_19!"=="1" echo   *     CTW-geiger-corr    [19]    Geiger/SDR correlator
if "!RUN_20!"=="1" echo   *     CTW-bcast          [20]    Broadcast monitor
if "!RUN_21!"=="1" echo   *     CTW-bcast-map      [21]    AoA map :8002
if "!RUN_22!"=="1" echo   *     browser            [22]    broadcast_map.html
echo.
echo   RF      : http://localhost:8000/sweep.html
echo   GNSS    : http://localhost:8001/gnss_map.html
echo   BCAST   : http://localhost:8002/
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
taskkill /FI "WINDOWTITLE eq CTW-bcast"       /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-bcast-map"   /T /F >nul 2>&1
timeout /t 1 /nobreak >nul
echo [  OK] All stopped.
echo.
set /p BACK="  [M] Menu  [Q] Quit: "
if /i "!BACK!"=="M" goto menu
exit /b 0
