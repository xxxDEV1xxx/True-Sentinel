@echo off
:: CTW RF Forensic Monitor — Windows Launcher
:: run.bat — no PowerShell execution policy needed
:: Place in same directory as all .py files and sweep.html

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set RUNTIME_DIR=%SCRIPT_DIR%runtime
set LOG_DIR=%RUNTIME_DIR%\process_logs
set PID_DIR=%RUNTIME_DIR%\pids

:: ── Create dirs ──────────────────────────────────────────────────────────────
if not exist "%RUNTIME_DIR%"  mkdir "%RUNTIME_DIR%"
if not exist "%LOG_DIR%"      mkdir "%LOG_DIR%"
if not exist "%PID_DIR%"      mkdir "%PID_DIR%"
:: ── Write stop.bat immediately so it always exists ───────────────────────────
(
echo @echo off
echo echo Stopping CTW RF Monitor pipeline...
echo taskkill /FI "WINDOWTITLE eq CTW-gz_watch"    /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-live_reader" /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-rf_server"   /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-correlator"  /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-pluto_sweep" /T /F ^>nul 2^>^&1
echo taskkill /FI "WINDOWTITLE eq CTW-fs5000"      /T /F ^>nul 2^>^&1
echo timeout /t 1 /nobreak ^>nul
echo echo Done.
echo pause
) > "%SCRIPT_DIR%stop.bat"
echo [  OK] stop.bat ready.
:: ── Parse args ───────────────────────────────────────────────────────────────
set DEMO_MODE=0
set NO_BROWSER=0
set PLUTO_URI=ip:192.168.2.1
set OUT_DIR=%SCRIPT_DIR%
set SWEEP_ARGS=
set FREQS=
set SPIKE=0.10
set WINDOW=0.5

:parse
if "%~1"=="" goto endparse
if /i "%~1"=="--demo"       ( set DEMO_MODE=1  & shift & goto parse )
if /i "%~1"=="--no-browser" ( set NO_BROWSER=1 & shift & goto parse )
if /i "%~1"=="--uri"        ( set PLUTO_URI=%~2      & shift & shift & goto parse )
if /i "%~1"=="--out"        ( set OUT_DIR=%~2         & shift & shift & goto parse )
if /i "%~1"=="--spike"      ( set SPIKE=%~2           & shift & shift & goto parse )
if /i "%~1"=="--window"     ( set WINDOW=%~2          & shift & shift & goto parse )
if /i "%~1"=="--start"      ( set SWEEP_ARGS=%SWEEP_ARGS% --start %~2  & shift & shift & goto parse )
if /i "%~1"=="--stop"       ( set SWEEP_ARGS=%SWEEP_ARGS% --stop %~2   & shift & shift & goto parse )
if /i "%~1"=="--step"       ( set SWEEP_ARGS=%SWEEP_ARGS% --step %~2   & shift & shift & goto parse )
if /i "%~1"=="--dwell-ms"   ( set SWEEP_ARGS=%SWEEP_ARGS% --dwell-ms %~2 & shift & shift & goto parse )
if /i "%~1"=="--freqs"      (
    shift
    :freqs_loop
    if "%~1"=="" goto endparse
    if "%~1:~0,2%"=="--" goto endparse
    set SWEEP_ARGS=%SWEEP_ARGS% %~1
    shift
    goto freqs_loop
)
if /i "%~1"=="--quiet"      ( set SWEEP_ARGS=%SWEEP_ARGS% --quiet & shift & goto parse )
if /i "%~1"=="--no-iq"      ( set SWEEP_ARGS=%SWEEP_ARGS% --no-iq & shift & goto parse )
shift
goto parse
:endparse

:: ── Locate Python ─────────────────────────────────────────────────────────────
set PYTHON=
for %%P in (python python3 py) do (
    if "!PYTHON!"=="" (
        %%P --version >nul 2>&1 && set PYTHON=%%P
    )
)
if "!PYTHON!"=="" (
    echo [ ERR] Python 3 not found. Install from python.org
    pause
    exit /b 1
)

:: ── Banner ────────────────────────────────────────────────────────────────────
echo.
echo  ========================================================================
echo   CTW RF Forensic Monitor -- Full Pipeline  ^(Windows^)
echo   Advanced CTW Research  ^|  USPTO 19/466,387
echo  ========================================================================
echo   Script dir  : %SCRIPT_DIR%
echo   Runtime dir : %RUNTIME_DIR%
echo   Output dir  : %OUT_DIR%
echo   Demo mode   : %DEMO_MODE%
echo   Pluto URI   : %PLUTO_URI%
echo   Python      : !PYTHON!
echo  ========================================================================
echo.

:: ── Check scripts ─────────────────────────────────────────────────────────────
for %%F in (gz_watch.py live_reader.py rf_server.py correlator.py sweep.html) do (
    if not exist "%SCRIPT_DIR%%%F" (
        echo [ ERR] Missing: %SCRIPT_DIR%%%F
        pause & exit /b 1
    )
)
if %DEMO_MODE%==0 (
    if not exist "%SCRIPT_DIR%pluto_sweep.py" (
        echo [ ERR] Missing: %SCRIPT_DIR%pluto_sweep.py
        pause & exit /b 1
    )
)
echo [  OK] All scripts present.

:: ── Check ports ───────────────────────────────────────────────────────────────
echo [CTW] Checking ports...
!PYTHON! -c "import socket,sys; s=socket.socket(); s.settimeout(1); r=s.connect_ex(('127.0.0.1',8000)); s.close(); sys.exit(0 if r==0 else 1)" >nul 2>&1
if not errorlevel 1 (
    echo [ ERR] Port 8000 is already in use. Run stop.bat first.
    pause & exit /b 1
)
!PYTHON! -c "import socket,sys; s=socket.socket(); s.settimeout(1); r=s.connect_ex(('127.0.0.1',8080)); s.close(); sys.exit(0 if r==0 else 1)" >nul 2>&1
if not errorlevel 1 (
    echo [ ERR] Port 8080 is already in use. Run stop.bat first.
    pause & exit /b 1
)
echo [  OK] Ports 8000 and 8080 are free.

:: ── Check Pluto ───────────────────────────────────────────────────────────────
if %DEMO_MODE%==0 (
    echo [CTW] Probing PlutoSDR at %PLUTO_URI%...
    iio_attr -u %PLUTO_URI% -C 2>&1 | findstr /i "fw_version" >nul
    if errorlevel 1 (
        echo [ ERR] Cannot reach PlutoSDR at %PLUTO_URI%
        echo        Check USB/Ethernet connection or run with --demo
        pause & exit /b 1
    )
    echo [  OK] PlutoSDR reachable.
)

:: ── Install dependencies ──────────────────────────────────────────────────────
echo [CTW] Checking Python dependencies...
!PYTHON! -c "import watchdog" >nul 2>&1 || !PYTHON! -m pip install --quiet watchdog
!PYTHON! -c "import numpy"    >nul 2>&1 || !PYTHON! -m pip install --quiet numpy
!PYTHON! -c "import iio"      >nul 2>&1 || !PYTHON! -m pip install --quiet iio
echo [  OK] Dependencies checked.

:: ── 1. gz_watch.py ───────────────────────────────────────────────────────────
echo [CTW] Starting gz_watch.py...
start "CTW-gz_watch"    /MIN cmd /c "!PYTHON! "%SCRIPT_DIR%gz_watch.py"    >> "%LOG_DIR%\gz_watch.log"    2>&1"
timeout /t 1 /nobreak >nul
echo [  OK] gz_watch started.

:: ── 2. live_reader.py ────────────────────────────────────────────────────────
echo [CTW] Starting live_reader.py...
start "CTW-live_reader" /MIN cmd /c "!PYTHON! "%SCRIPT_DIR%live_reader.py" >> "%LOG_DIR%\live_reader.log" 2>&1"

echo [CTW] Waiting for live_reader on :8080...
:wait_8080
timeout /t 1 /nobreak >nul
!PYTHON! -c "import socket,sys; s=socket.socket(); s.settimeout(1); r=s.connect_ex(('127.0.0.1',8080)); s.close(); sys.exit(r)" >nul 2>&1
if errorlevel 1 goto wait_8080
echo [  OK] live_reader listening on :8080.

:: ── 3. rf_server.py ──────────────────────────────────────────────────────────
echo [CTW] Starting rf_server.py...
start "CTW-rf_server"   /MIN cmd /c "!PYTHON! "%SCRIPT_DIR%rf_server.py"   >> "%LOG_DIR%\rf_server.log"   2>&1"

echo [CTW] Waiting for rf_server on :8000...
:wait_8000
timeout /t 1 /nobreak >nul
!PYTHON! -c "import socket,sys; s=socket.socket(); s.settimeout(1); r=s.connect_ex(('127.0.0.1',8000)); s.close(); sys.exit(r)" >nul 2>&1
if errorlevel 1 goto wait_8000
echo [  OK] rf_server listening on :8000.

:: ── 3b. correlator.py ────────────────────────────────────────────────────────
echo [CTW] Starting correlator.py...
start "CTW-correlator"  /MIN cmd /c "!PYTHON! "%SCRIPT_DIR%correlator.py" --rf-live "%RUNTIME_DIR%\sweep_live.jsonl" --out "%RUNTIME_DIR%" --window %WINDOW% --spike %SPIKE% >> "%LOG_DIR%\correlator.log" 2>&1"
timeout /t 1 /nobreak >nul
echo [  OK] correlator started.

:: ── 4. pluto_sweep.py ────────────────────────────────────────────────────────
if %DEMO_MODE%==0 (
    echo [CTW] Starting pluto_sweep.py...
    start "CTW-pluto_sweep" /MIN cmd /c "!PYTHON! "!SCRIPT_DIR!pluto_sweep.py" --uri !PLUTO_URI! --out "!OUT_DIR!" !SWEEP_ARGS! >> "!LOG_DIR!\pluto_sweep.log" 2>&1"
    timeout /t 1 /nobreak >nul
    echo [  OK] pluto_sweep started.
) else (
    echo [WARN] Demo mode -- pluto_sweep.py not started.
)

:: ── 5. fs5000_dual.py ────────────────────────────────────────────────────────
if exist "%SCRIPT_DIR%fs5000_dual.py" (
    if %DEMO_MODE%==0 (
        echo [CTW] Starting fs5000_dual.py...
        start "CTW-fs5000" /MIN cmd /c "!PYTHON! "%SCRIPT_DIR%fs5000_dual.py" --out "%OUT_DIR%" >> "%LOG_DIR%\fs5000.log" 2>&1"
        timeout /t 1 /nobreak >nul
        echo [  OK] fs5000_dual started.
    )
)

:: ── 6. Browser ───────────────────────────────────────────────────────────────
if %NO_BROWSER%==0 (
    echo [CTW] Opening dashboard...
    timeout /t 2 /nobreak >nul
    start "" "http://localhost:8000"
)

:: ── Status ───────────────────────────────────────────────────────────────────
echo.
echo  ========================================================================
echo   Pipeline running.
echo.
echo   Dashboard    --^>  http://localhost:8000
echo   SSE stream   --^>  http://localhost:8000/sse
echo   Poll stream  --^>  http://localhost:8080/sweep
echo   Corr log     --^>  %RUNTIME_DIR%\corr_live.jsonl
echo   Process logs --^>  %LOG_DIR%\
echo.
echo   Each process runs in a minimised window titled CTW-^<name^>.
echo   Close this window or press Ctrl+C to stop the monitor.
echo   To stop all CTW processes run:  stop.bat
echo  ========================================================================
echo.

:: ── Write stop.bat on the fly ────────────────────────────────────────────────
(
echo @echo off
echo echo Stopping CTW RF Monitor pipeline...
echo taskkill /FI "WINDOWTITLE eq CTW-gz_watch"    /T /F >nul 2>&1
echo taskkill /FI "WINDOWTITLE eq CTW-live_reader" /T /F >nul 2>&1
echo taskkill /FI "WINDOWTITLE eq CTW-rf_server"   /T /F >nul 2>&1
echo taskkill /FI "WINDOWTITLE eq CTW-correlator"  /T /F >nul 2>&1
echo taskkill /FI "WINDOWTITLE eq CTW-pluto_sweep" /T /F >nul 2>&1
echo taskkill /FI "WINDOWTITLE eq CTW-fs5000"      /T /F >nul 2>&1
echo echo Done.
echo pause
) > "%SCRIPT_DIR%stop.bat"

echo [  OK] stop.bat written to %SCRIPT_DIR%

:: ── Tail pluto_sweep log ──────────────────────────────────────────────────────
if %DEMO_MODE%==0 (
    echo [CTW] Tailing pluto_sweep output ^(close window to stop pipeline^):
    echo.
    :tail_loop
    if exist "%LOG_DIR%\pluto_sweep.log" (
        type "%LOG_DIR%\pluto_sweep.log"
        timeout /t 2 /nobreak >nul
        goto tail_loop
    )
    timeout /t 1 /nobreak >nul
    goto tail_loop
) else (
    echo [CTW] Demo mode -- press Ctrl+C or close this window to stop.
    :demo_wait
    timeout /t 5 /nobreak >nul
    goto demo_wait
)