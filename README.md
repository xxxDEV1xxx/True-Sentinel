# True-Sentinel

MINIMAL COMPONENTS
ADALM-PLUTO Rev.C (Z7010-AD9361 fw v0.38)   ✓ confirmed working
Bosean FS-5000                                ✓ confirmed working
u-blox 7 GNSS (COM7)                         ✓ confirmed working
Windows PC                            ✓ confirmed working
Python 3.14                                  ✓ confirmed working
timeapi.io 

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
echo   [7]  css_hunter.py
echo        --uri URI          PlutoSDR URI
echo        --bands N [N]      LTE band numbers (default 2 4 5 12 13 66 71)
echo        --dwell-ms MS      dwell per window (default 20)
echo        --anomaly-db DB    dB above noise to flag (default 12)
echo        --no-pss           disable PSS ZC correlation
echo        --target-earfcn N  force scan specific EARFCNs
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

use launch.bat in cmd. 
Menu with help options appears.
required 
