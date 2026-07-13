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
echo   Advanced CTW Research  ^|  USPTO 19/466,387
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