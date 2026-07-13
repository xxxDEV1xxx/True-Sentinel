# =============================================================================
# CTW RF Forensic Monitor — Full Pipeline Launcher (Windows)
# run.ps1
# =============================================================================
# Starts:
#   1. gz_watch.py     — gzip live mirror watcher
#   2. live_reader.py  — JSONL cursor server  (:8080)
#   3. rf_server.py    — SSE broadcast server (:8000)
#   4. pluto_sweep.py  — PlutoSDR IIO sweep logger
#   5. sweep.html      — opens dashboard in default browser
#
# Usage:
#   .\run.ps1
#   .\run.ps1 -Demo
#   .\run.ps1 -Freqs 386000000,386020000
#   .\run.ps1 -Start 385800000 -Stop 386200000 -Step 10000
#   .\run.ps1 -NoBrowser
#   .\run.ps1 -Out "C:\sdr\logs"
#   .\run.ps1 -PlutoUri "ip:192.168.2.1"
# =============================================================================

[CmdletBinding()]
param(
    [switch]  $Demo,
    [switch]  $NoBrowser,
    [switch]  $Quiet,
    [switch]  $NoIq,
    [string]  $PlutoUri  = "ip:192.168.2.1",
    [string]  $Out       = "",
    [string]  $Python    = "",
    [long]    $Start     = 0,
    [long]    $Stop      = 0,
    [long]    $Step      = 0,
    [int]     $DwellMs   = -1,
    [int]     $SettleMs  = -1,
    [double]  $AnomalyAtten = -1,
    [long[]]  $Freqs     = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Colour helpers ────────────────────────────────────────────────────────────
function Write-Log  ($m) { Write-Host "[CTW] $m"      -ForegroundColor White }
function Write-Ok   ($m) { Write-Host "[  OK] $m"     -ForegroundColor Green }
function Write-Warn ($m) { Write-Host "[WARN] $m"     -ForegroundColor Yellow }
function Write-Err  ($m) { Write-Host "[ ERR] $m"     -ForegroundColor Red }
function Write-Sep  ()   { Write-Host ("─" * 72)       -ForegroundColor Cyan }

# ── Resolve paths ─────────────────────────────────────────────────────────────
$ScriptDir   = $PSScriptRoot
$RuntimeDir  = Join-Path $ScriptDir "runtime"
$LogDir      = Join-Path $RuntimeDir "process_logs"
$PidDir      = Join-Path $RuntimeDir "pids"
$OutDir      = if ($Out) { $Out } else { $ScriptDir }

foreach ($d in @($RuntimeDir, $LogDir, $PidDir, $OutDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

$PortSSE  = 8000
$PortPoll = 8080
$BrowserUrl = "http://localhost:$PortSSE"

# ── Locate Python ─────────────────────────────────────────────────────────────
function Find-Python {
    if ($Python) {
        if (Get-Command $Python -ErrorAction SilentlyContinue) { return $Python }
        throw "Specified Python '$Python' not found on PATH."
    }
    foreach ($candidate in @("python", "python3", "py")) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            $ver = & $candidate --version 2>&1
            if ($ver -match "Python 3") { return $candidate }
        }
    }
    throw "Python 3 not found. Install from python.org or set -Python <path>."
}

# ── Process registry ──────────────────────────────────────────────────────────
$Processes = [ordered]@{}   # name -> Process object

function Save-Pid ($name, $proc) {
    $Processes[$name] = $proc
    $proc.Id | Out-File -FilePath (Join-Path $PidDir "$name.pid") -Encoding ascii
}

# ── Port check ────────────────────────────────────────────────────────────────
function Test-PortFree ($port) {
    $conn = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
    $listeners = $conn.GetActiveTcpListeners()
    foreach ($ep in $listeners) {
        if ($ep.Port -eq $port) { return $false }
    }
    return $true
}

function Assert-PortsFree {
    $blocked = $false
    foreach ($port in @($PortSSE, $PortPoll)) {
        if (-not (Test-PortFree $port)) {
            Write-Err "Port $port is already in use. Stop the existing process first."
            $blocked = $true
        }
    }
    if ($blocked) { exit 1 }
}

# ── Dependency check ──────────────────────────────────────────────────────────
function Test-PythonPackage ($py, $pkg, $importName) {
    $result = & $py -c "import $importName" 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Assert-Dependencies ($py) {
    Write-Log "Checking Python dependencies…"
    $missing = @()

    $checks = @(
        @{ pkg="watchdog"; import="watchdog" },
        @{ pkg="numpy";    import="numpy"    },
        @{ pkg="iio";      import="iio"      }
    )

    foreach ($c in $checks) {
        if (-not (Test-PythonPackage $py $c.pkg $c.import)) {
            $missing += $c.pkg
        }
    }

    if ($missing.Count -gt 0) {
        Write-Warn "Missing packages: $($missing -join ', ')"
        Write-Warn "Attempting auto-install…"
        & $py -m pip install --quiet @missing
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Auto-install failed. Run:  pip install $($missing -join ' ')"
            exit 1
        }
        Write-Ok "Packages installed."
    } else {
        Write-Ok "All Python packages present."
    }
}

# ── Script presence check ─────────────────────────────────────────────────────
function Assert-Scripts {
    $required = @("gz_watch.py","live_reader.py","rf_server.py","sweep.html")
    if (-not $Demo) { $required += "pluto_sweep.py" }
    $missing = $false
    foreach ($f in $required) {
        $path = Join-Path $ScriptDir $f
        if (-not (Test-Path $path)) {
            Write-Err "Missing: $path"
            $missing = $true
        }
    }
    if ($missing) { exit 1 }
    Write-Ok "All scripts present."
}

# ── Pluto reachability ────────────────────────────────────────────────────────
function Assert-Pluto {
    if ($Demo) {
        Write-Warn "Demo mode — skipping Pluto check."
        return
    }
    Write-Log "Probing PlutoSDR at $PlutoUri…"
    try {
        $out = & iio_attr -u $PlutoUri -C 2>&1
        if ($out -match "fw_version") {
            $fw = ($out | Select-String "fw_version" | Select-Object -First 1) -replace ".*:","" | ForEach-Object { $_.Trim() }
            Write-Ok "PlutoSDR reachable — firmware: $fw"
        } else {
            throw "No fw_version in probe output."
        }
    } catch {
        Write-Err "Cannot reach PlutoSDR at $PlutoUri"
        Write-Err "Check USB/Ethernet or use -Demo"
        exit 1
    }
}

# ── Start a process ───────────────────────────────────────────────────────────
function Start-PipelineProcess ($name, [string[]]$argList) {
    $logFile = Join-Path $LogDir "$name.log"
    Write-Log "Starting $name…"
    Write-Log "  CMD: $($argList -join ' ')"

    # Redirect stdout+stderr to log file, no window
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $argList[0]
    $psi.Arguments              = ($argList[1..($argList.Length-1)] | ForEach-Object {
        if ($_ -match '\s') { "`"$_`"" } else { $_ }
    }) -join " "
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.WorkingDirectory       = $ScriptDir

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi

    # Async log writing via event handlers
    $logStream = [System.IO.StreamWriter]::new($logFile, $false, [System.Text.Encoding]::UTF8)
    $logStream.AutoFlush = $true

    $outAction = {
        if ($EventArgs.Data) {
            $Event.MessageData.WriteLine($EventArgs.Data)
        }
    }

    Register-ObjectEvent -InputObject $proc -EventName OutputDataReceived `
        -Action $outAction -MessageData $logStream | Out-Null
    Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived  `
        -Action $outAction -MessageData $logStream | Out-Null

    $proc.Start() | Out-Null
    $proc.BeginOutputReadLine()
    $proc.BeginErrorReadLine()

    Start-Sleep -Milliseconds 600

    if ($proc.HasExited) {
        Write-Err "$name exited immediately (code $($proc.ExitCode)). Check: $logFile"
        Get-Content $logFile -Tail 10 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        return $null
    }

    Save-Pid $name $proc
    Write-Ok "$name started (PID $($proc.Id)) → $logFile"
    return $proc
}

# ── Wait for TCP port ─────────────────────────────────────────────────────────
function Wait-Port ($name, $port, $timeoutSec = 12) {
    Write-Log "Waiting for $name on :$port…"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect("127.0.0.1", $port)
            $tcp.Close()
            Write-Ok "$name listening on :$port"
            return
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }
    Write-Err "$name did not open :$port within ${timeoutSec}s"
    throw "$name port timeout"
}

# ── Open browser ──────────────────────────────────────────────────────────────
function Open-Dashboard {
    if ($NoBrowser) { return }
    Write-Log "Opening dashboard: $BrowserUrl"
    Start-Sleep -Seconds 1
    Start-Process $BrowserUrl
}

# ── Shutdown ──────────────────────────────────────────────────────────────────
function Stop-Pipeline {
    Write-Sep
    Write-Log "Shutting down CTW RF Monitor pipeline…"

    # Reverse order
    $names = @($Processes.Keys) | Sort-Object -Descending

    foreach ($name in $names) {
        $proc = $Processes[$name]
        if ($proc -and -not $proc.HasExited) {
            Write-Log "Stopping $name (PID $($proc.Id))…"
            try {
                # Send Ctrl+C equivalent via taskkill (graceful)
                & taskkill /PID $proc.Id /T 2>&1 | Out-Null
                $proc.WaitForExit(3000) | Out-Null
                if (-not $proc.HasExited) {
                    $proc.Kill()
                    Write-Warn "  $name force-killed."
                } else {
                    Write-Ok "  $name stopped."
                }
            } catch {
                Write-Warn "  Could not stop $name`: $_"
            }
        }
        $pidFile = Join-Path $PidDir "$name.pid"
        if (Test-Path $pidFile) { Remove-Item $pidFile -Force }
    }

    Write-Sep
    Write-Log "Log files:"
    foreach ($name in @("gz_watch","live_reader","rf_server","pluto_sweep")) {
        $lf = Join-Path $LogDir "$name.log"
        if (Test-Path $lf) {
            $lines = (Get-Content $lf | Measure-Object -Line).Lines
            Write-Host "    ${name}: $lf  ($lines lines)" -ForegroundColor Cyan
        }
    }
    Write-Sep
    Write-Ok "Pipeline stopped."
}

# ── Tail a log file to console ────────────────────────────────────────────────
function Start-LogTail ($logFile) {
    # Runs in a background job so we can still catch Ctrl+C in the main thread
    $job = Start-Job -ScriptBlock {
        param($f)
        $reader = [System.IO.StreamReader]::new(
            $f,
            [System.Text.Encoding]::UTF8,
            $true,
            4096,
            $false
        )
        # Seek to end
        $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
        while ($true) {
            $line = $reader.ReadLine()
            if ($line) { Write-Output $line }
            else        { Start-Sleep -Milliseconds 80 }
        }
    } -ArgumentList $logFile
    return $job
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

Write-Sep
Write-Host @"
   ██████╗████████╗██╗    ██╗    ██████╗ ███████╗
  ██╔════╝╚══██╔══╝██║    ██║    ██╔══██╗██╔════╝
  ██║        ██║   ██║ █╗ ██║    ██████╔╝█████╗
  ██║        ██║   ██║███╗██║    ██╔══██╗██╔══╝
  ╚██████╗   ██║   ╚███╔███╔╝    ██║  ██║██║
   ╚═════╝   ╚═╝    ╚══╝╚══╝     ╚═╝  ╚═╝╚═╝
"@ -ForegroundColor Cyan
Write-Host "  CTW RF Forensic Monitor — Full Pipeline (Windows)" -ForegroundColor Cyan
Write-Host "  Advanced CTW Research  |  USPTO 19/466,387"        -ForegroundColor Blue
Write-Sep

Write-Log "Script dir : $ScriptDir"
Write-Log "Runtime dir: $RuntimeDir"
Write-Log "Output dir : $OutDir"
Write-Log "Demo mode  : $Demo"
Write-Log "Pluto URI  : $PlutoUri"

# ── Pre-flight ────────────────────────────────────────────────────────────────
$py = Find-Python
Write-Ok "Python: $py  ($( & $py --version 2>&1 ))"

Assert-Dependencies $py
Assert-Scripts
Assert-PortsFree
Assert-Pluto

# ── Build pluto_sweep args ────────────────────────────────────────────────────
$sweepArgs = @(
    (Join-Path $ScriptDir "pluto_sweep.py"),
    "--uri", $PlutoUri,
    "--out", $OutDir
)
if ($Freqs.Count -gt 0)   { $sweepArgs += "--freqs";         $sweepArgs += ($Freqs | ForEach-Object { "$_" }) }
if ($Start -gt 0)         { $sweepArgs += "--start";         $sweepArgs += "$Start"        }
if ($Stop  -gt 0)         { $sweepArgs += "--stop";          $sweepArgs += "$Stop"         }
if ($Step  -gt 0)         { $sweepArgs += "--step";          $sweepArgs += "$Step"         }
if ($DwellMs  -ge 0)      { $sweepArgs += "--dwell-ms";      $sweepArgs += "$DwellMs"      }
if ($SettleMs -ge 0)      { $sweepArgs += "--settle-ms";     $sweepArgs += "$SettleMs"     }
if ($AnomalyAtten -ge 0)  { $sweepArgs += "--anomaly-atten"; $sweepArgs += "$AnomalyAtten" }
if ($Quiet)               { $sweepArgs += "--quiet"  }
if ($NoIq)                { $sweepArgs += "--no-iq"  }

# ── Start pipeline ────────────────────────────────────────────────────────────
Write-Sep
Write-Log "Starting pipeline…"
Write-Sep

# 1. gz_watch.py
$p1 = Start-PipelineProcess "gz_watch" @($py, (Join-Path $ScriptDir "gz_watch.py"))
if (-not $p1) { exit 1 }

# 2. live_reader.py
$p2 = Start-PipelineProcess "live_reader" @($py, (Join-Path $ScriptDir "live_reader.py"))
if (-not $p2) { exit 1 }
Wait-Port "live_reader" $PortPoll 12

# 3. rf_server.py
$p3 = Start-PipelineProcess "rf_server" @($py, (Join-Path $ScriptDir "rf_server.py"))
if (-not $p3) { exit 1 }
Wait-Port "rf_server" $PortSSE 12

# 3b. correlator.py
$p3b = Start-PipelineProcess "correlator" @(
    $py,
    (Join-Path $ScriptDir "correlator.py"),
    "--rf-live", (Join-Path $RuntimeDir "sweep_live.jsonl"),
    "--out",     $RuntimeDir,
    "--window",  "0.5",
    "--spike",   "0.10"
)
if (-not $p3b) { exit 1 }


# 4. pluto_sweep.py
if (-not $Demo) {
    $p4 = Start-PipelineProcess "pluto_sweep" (@($py) + $sweepArgs)
    if (-not $p4) { exit 1 }
} else {
    Write-Warn "Demo mode — pluto_sweep.py not started. Dashboard uses synthetic data."
}

# 5. Browser
Open-Dashboard

# ── Status banner ─────────────────────────────────────────────────────────────
Write-Sep
Write-Host ""
Write-Host "  Pipeline running." -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard   ->  $BrowserUrl"                              -ForegroundColor White
Write-Host "  SSE server  ->  http://localhost:$PortSSE/sse"           -ForegroundColor White
Write-Host "  Poll server ->  http://localhost:${PortPoll}/sweep"       -ForegroundColor White
Write-Host "  Sweep logs  ->  $OutDir\sweep_*.jsonl.gz"                 -ForegroundColor White
Write-Host "  Live mirror ->  $RuntimeDir\sweep_live.jsonl"             -ForegroundColor White
Write-Host "  Process logs->  $LogDir\"                                 -ForegroundColor White
Write-Host ""
Write-Host "  Press Ctrl+C to stop all processes." -ForegroundColor Yellow
Write-Host ""
Write-Sep

# ── Live tail of pluto_sweep (or just wait in demo mode) ─────────────────────
try {
    if (-not $Demo) {
        $sweepLog = Join-Path $LogDir "pluto_sweep.log"
        Write-Log "Tailing pluto_sweep output (Ctrl+C to stop pipeline):"
        Write-Sep

        # Wait for log file to exist
        $w = 0
        while (-not (Test-Path $sweepLog) -and $w -lt 20) {
            Start-Sleep -Milliseconds 500; $w++
        }

        $tailJob = Start-LogTail $sweepLog

        while ($true) {
            $lines = Receive-Job $tailJob
            foreach ($line in $lines) {
                Write-Host $line
            }
            Start-Sleep -Milliseconds 80

            # Check if any critical process has died
            foreach ($name in @("gz_watch","live_reader","rf_server","correlator","pluto_sweep")) {
                if ($Processes.Contains($name) -and $Processes[$name].HasExited) {
                    $code = $Processes[$name].ExitCode
                    if ($code -ne 0) {
                        Write-Err "$name exited unexpectedly (code $code)"
                        Write-Err "Check log: $(Join-Path $LogDir "$name.log")"
                    }
                }
            }
        }
    } else {
        Write-Log "Demo mode — waiting (Ctrl+C to stop)…"
        while ($true) {
            Start-Sleep -Seconds 5
            foreach ($name in @("gz_watch","live_reader","rf_server")) {
                if ($Processes.Contains($name) -and $Processes[$name].HasExited) {
                    $code = $Processes[$name].ExitCode
                    Write-Err "$name exited unexpectedly (code $code). Check: $(Join-Path $LogDir "$name.log")"
                }
            }
        }
    }
} finally {
    Stop-Pipeline
}