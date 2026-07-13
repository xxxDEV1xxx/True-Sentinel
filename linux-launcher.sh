#!/usr/bin/env bash
# =============================================================================
# CTW RF Forensic Monitor — Full Pipeline Launcher
# =============================================================================
# Starts:
#   1. gz_watch.py     — gzip live mirror watcher
#   2. live_reader.py  — JSONL cursor server  (:8080)
#   3. rf_server.py    — SSE broadcast server (:8000)
#   4. pluto_sweep.py  — PlutoSDR IIO sweep logger
#   5. sweep.html      — opens dashboard in browser
#
# Usage:
#   ./run.sh                          # full pipeline, auto-detect Pluto
#   ./run.sh --demo                   # skip pluto_sweep, browser demo mode
#   ./run.sh --freqs 386000000 386020000   # pass args to pluto_sweep
#   ./run.sh --start 70000000 --stop 6000000000 --step 1000000
#   ./run.sh --no-browser             # headless, no browser launch
#   ./run.sh --out /tmp/sdr           # set output dir for logs
# =============================================================================

set -euo pipefail

# ── Colour output ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; WHT='\033[1;37m'; NC='\033[0m'

log()  { echo -e "${WHT}[CTW]${NC} $*"; }
ok()   { echo -e "${GRN}[  OK]${NC} $*"; }
warn() { echo -e "${YLW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ ERR]${NC} $*"; }
sep()  { echo -e "${CYN}$(printf '─%.0s' {1..72})${NC}"; }

# ── Defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="${SCRIPT_DIR}/runtime"
LOG_DIR="${RUNTIME_DIR}/process_logs"
PID_DIR="${RUNTIME_DIR}/pids"

PLUTO_URI="ip:192.168.2.1"
SWEEP_ARGS=()
OUT_DIR="${SCRIPT_DIR}"
DEMO_MODE=false
NO_BROWSER=false
BROWSER_URL="http://localhost:8000"

PORT_SSE=8000
PORT_POLL=8080

PYTHON="${PYTHON:-python3}"

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --demo)        DEMO_MODE=true;            shift ;;
    --no-browser)  NO_BROWSER=true;           shift ;;
    --uri)         PLUTO_URI="$2";            shift 2 ;;
    --out)         OUT_DIR="$2";              shift 2 ;;
    --freqs)
      shift
      SWEEP_ARGS+=("--freqs")
      while [[ $# -gt 0 && "$1" != --* ]]; do
        SWEEP_ARGS+=("$1"); shift
      done
      ;;
    --start|--stop|--step|--dwell-ms|--settle-ms|--anomaly-atten)
      SWEEP_ARGS+=("$1" "$2"); shift 2 ;;
    --quiet)       SWEEP_ARGS+=("--quiet");   shift ;;
    --no-iq)       SWEEP_ARGS+=("--no-iq");   shift ;;
    --help|-h)
      grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//'
      exit 0 ;;
    *)
      warn "Unknown arg: $1 (ignored)"; shift ;;
  esac
done

# ── Setup dirs ────────────────────────────────────────────────────────────────
mkdir -p "${RUNTIME_DIR}" "${LOG_DIR}" "${PID_DIR}" "${OUT_DIR}"

# ── PID tracking ──────────────────────────────────────────────────────────────
declare -A PIDS=()   # name → pid
declare -A LOGS=()   # name → logfile

pid_file() { echo "${PID_DIR}/$1.pid"; }

save_pid() {
  local name="$1" pid="$2"
  PIDS["$name"]="$pid"
  echo "$pid" > "$(pid_file "$name")"
}

# ── Port check ────────────────────────────────────────────────────────────────
port_free() {
  ! ss -tlnp 2>/dev/null | grep -q ":$1 " &&
  ! netstat -tlnp 2>/dev/null | grep -q ":$1 " || true
  # Fallback: attempt connect
  ! (echo >/dev/tcp/localhost/"$1") 2>/dev/null
}

check_ports() {
  local blocked=false
  for port in $PORT_SSE $PORT_POLL; do
    if ! port_free "$port"; then
      err "Port $port already in use. Stop the existing process or use --no-browser."
      blocked=true
    fi
  done
  $blocked && exit 1 || true
}

# ── Python check ──────────────────────────────────────────────────────────────
check_python() {
  if ! command -v "${PYTHON}" &>/dev/null; then
    err "Python not found. Set PYTHON= env var or install python3."
    exit 1
  fi
  ok "Python: $(${PYTHON} --version 2>&1)"
}

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
  log "Checking Python dependencies…"
  local missing=()

  check_pkg() {
    local pkg="$1" import="$2"
    if ! "${PYTHON}" -c "import ${import}" 2>/dev/null; then
      missing+=("$pkg")
    fi
  }

  check_pkg "watchdog"  "watchdog"
  check_pkg "numpy"     "numpy"
  check_pkg "iio"       "iio"

  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing packages: ${missing[*]}"
    warn "Install with:  pip install ${missing[*]}"
    warn "Attempting auto-install…"
    "${PYTHON}" -m pip install --quiet "${missing[@]}" || {
      err "Auto-install failed. Install manually and retry."
      exit 1
    }
    ok "Packages installed."
  else
    ok "All Python packages present."
  fi
}

# ── Script presence check ─────────────────────────────────────────────────────
check_scripts() {
  local missing=false
  for f in gz_watch.py live_reader.py rf_server.py sweep.html; do
    if [[ ! -f "${SCRIPT_DIR}/${f}" ]]; then
      err "Missing: ${SCRIPT_DIR}/${f}"
      missing=true
    fi
  done
  if [[ "$DEMO_MODE" == false && ! -f "${SCRIPT_DIR}/pluto_sweep.py" ]]; then
    err "Missing: ${SCRIPT_DIR}/pluto_sweep.py"
    missing=true
  fi
  $missing && exit 1 || ok "All scripts present."
}

# ── Pluto reachability ────────────────────────────────────────────────────────
check_pluto() {
  if [[ "$DEMO_MODE" == true ]]; then
    warn "Demo mode — skipping Pluto check."
    return 0
  fi

  log "Probing PlutoSDR at ${PLUTO_URI}…"
  local out
  out=$(timeout 4 iio_attr -u "${PLUTO_URI}" -C 2>&1 || true)

  if echo "$out" | grep -qi "fw_version"; then
    local fw
    fw=$(echo "$out" | grep -i fw_version | head -1 | cut -d: -f2 | xargs)
    ok "PlutoSDR reachable — firmware: ${fw}"
  else
    err "Cannot reach PlutoSDR at ${PLUTO_URI}"
    err "Check USB/Ethernet connection or use --demo"
    echo
    echo "  Pluto probe output:"
    echo "$out" | head -8 | sed 's/^/    /'
    exit 1
  fi
}

# ── Start a process ───────────────────────────────────────────────────────────
start_process() {
  local name="$1"; shift
  local logfile="${LOG_DIR}/${name}.log"
  LOGS["$name"]="$logfile"

  log "Starting ${name}…"

  # Clear old log
  > "$logfile"

  "$@" >> "$logfile" 2>&1 &
  local pid=$!
  save_pid "$name" "$pid"

  # Brief existence check
  sleep 0.4
  if ! kill -0 "$pid" 2>/dev/null; then
    err "${name} exited immediately. Check log: ${logfile}"
    tail -10 "$logfile" | sed 's/^/    /'
    return 1
  fi

  ok "${name} started (PID ${pid}) → ${logfile}"
  return 0
}

# ── Wait for HTTP port to open ────────────────────────────────────────────────
wait_port() {
  local name="$1" port="$2" timeout_s="${3:-10}"
  local elapsed=0

  log "Waiting for ${name} on :${port}…"
  while ! (echo >/dev/tcp/localhost/"$port") 2>/dev/null; do
    sleep 0.3
    elapsed=$(echo "$elapsed + 0.3" | bc 2>/dev/null || echo $((elapsed + 1)))
    local elapsed_int=${elapsed%.*}
    if [[ "${elapsed_int:-0}" -ge "$timeout_s" ]]; then
      err "${name} did not open :${port} within ${timeout_s}s"
      return 1
    fi
  done
  ok "${name} listening on :${port}"
}

# ── Open browser ──────────────────────────────────────────────────────────────
open_browser() {
  if [[ "$NO_BROWSER" == true ]]; then return; fi

  log "Opening dashboard in browser…"
  sleep 1.0

  if command -v xdg-open &>/dev/null; then
    xdg-open "$BROWSER_URL" &
  elif command -v open &>/dev/null; then
    open "$BROWSER_URL" &
  elif command -v sensible-browser &>/dev/null; then
    sensible-browser "$BROWSER_URL" &
  elif command -v google-chrome &>/dev/null; then
    google-chrome "$BROWSER_URL" &
  elif command -v firefox &>/dev/null; then
    firefox "$BROWSER_URL" &
  else
    warn "No browser found. Open manually: ${BROWSER_URL}"
  fi
}

# ── Shutdown ──────────────────────────────────────────────────────────────────
shutdown() {
  echo
  sep
  log "Shutting down CTW RF Monitor pipeline…"

  # Kill in reverse start order
  for name in pluto_sweep correlator gz_watch live_reader rf_server; do
    local pf
    pf="$(pid_file "$name")"
    if [[ -f "$pf" ]]; then
      local pid
      pid=$(cat "$pf")
      if kill -0 "$pid" 2>/dev/null; then
        log "Stopping ${name} (PID ${pid})…"
        kill -TERM "$pid" 2>/dev/null || true
        # Wait up to 3s for clean exit
        local w=0
        while kill -0 "$pid" 2>/dev/null && [[ $w -lt 30 ]]; do
          sleep 0.1; w=$((w+1))
        done
        if kill -0 "$pid" 2>/dev/null; then
          warn "  ${name} did not exit — sending KILL"
          kill -KILL "$pid" 2>/dev/null || true
        else
          ok "  ${name} stopped."
        fi
      fi
      rm -f "$pf"
    fi
  done

  sep
  log "Log files:"
  for name in gz_watch live_reader rf_server pluto_sweep; do
    local lf="${LOG_DIR}/${name}.log"
    if [[ -f "$lf" ]]; then
      local lines
      lines=$(wc -l < "$lf" 2>/dev/null || echo 0)
      echo "    ${name}: ${lf}  (${lines} lines)"
    fi
  done
  sep
  ok "Pipeline stopped."
}

trap shutdown EXIT INT TERM

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

sep
echo -e "${WHT}"
echo "   ██████╗████████╗██╗    ██╗    ██████╗ ███████╗"
echo "  ██╔════╝╚══██╔══╝██║    ██║    ██╔══██╗██╔════╝"
echo "  ██║        ██║   ██║ █╗ ██║    ██████╔╝█████╗  "
echo "  ██║        ██║   ██║███╗██║    ██╔══██╗██╔══╝  "
echo "  ╚██████╗   ██║   ╚███╔███╔╝    ██║  ██║██║     "
echo "   ╚═════╝   ╚═╝    ╚══╝╚══╝     ╚═╝  ╚═╝╚═╝     "
echo -e "${CYN}  CTW RF Forensic Monitor — Full Pipeline${NC}"
echo -e "${BLU}  Advanced CTW Research  |  USPTO 19/466,387${NC}"
sep
echo
log "Script dir : ${SCRIPT_DIR}"
log "Runtime dir: ${RUNTIME_DIR}"
log "Output dir : ${OUT_DIR}"
log "Demo mode  : ${DEMO_MODE}"
log "Pluto URI  : ${PLUTO_URI}"
if [[ ${#SWEEP_ARGS[@]} -gt 0 ]]; then
  log "Sweep args : ${SWEEP_ARGS[*]}"
fi
echo

# ── Pre-flight ────────────────────────────────────────────────────────────────
check_python
check_deps
check_scripts
check_ports
check_pluto

sep
log "Starting pipeline…"
sep

# ── 1. gz_watch.py ────────────────────────────────────────────────────────────
start_process "gz_watch" \
  "${PYTHON}" "${SCRIPT_DIR}/gz_watch.py" || exit 1

# ── 2. live_reader.py ─────────────────────────────────────────────────────────
start_process "live_reader" \
  "${PYTHON}" "${SCRIPT_DIR}/live_reader.py" || exit 1
wait_port "live_reader" "$PORT_POLL" 10

# ── 3. rf_server.py ───────────────────────────────────────────────────────────
start_process "rf_server" \
  "${PYTHON}" "${SCRIPT_DIR}/rf_server.py" || exit 1
wait_port "rf_server" "$PORT_SSE" 10

# 3b. correlator.py
start_process "correlator" \
  "${PYTHON}" "${SCRIPT_DIR}/correlator.py" \
    --rf-live "${RUNTIME_DIR}/sweep_live.jsonl" \
    --out     "${RUNTIME_DIR}" \
    --window  "0.5" \
    --spike   "0.10"

# ── 4. pluto_sweep.py ─────────────────────────────────────────────────────────
if [[ "$DEMO_MODE" == false ]]; then
  start_process "pluto_sweep" \
    "${PYTHON}" "${SCRIPT_DIR}/pluto_sweep.py" \
      --uri "${PLUTO_URI}" \
      --out "${OUT_DIR}" \
      "${SWEEP_ARGS[@]}" || exit 1
else
  warn "Demo mode — pluto_sweep.py not started. Dashboard will use synthetic data."
fi

# ── 5. Browser ────────────────────────────────────────────────────────────────
open_browser

# ── Status banner ─────────────────────────────────────────────────────────────
sep
echo
echo -e "  ${GRN}Pipeline running.${NC}"
echo
echo -e "  Dashboard   →  ${WHT}${BROWSER_URL}${NC}"
echo -e "  SSE server  →  ${WHT}http://localhost:${PORT_SSE}/sse${NC}"
echo -e "  Poll server →  ${WHT}http://localhost:${PORT_POLL}/sweep${NC}"
echo -e "  Sweep logs  →  ${WHT}${OUT_DIR}/sweep_*.jsonl.gz${NC}"
echo -e "  Live mirror →  ${WHT}${RUNTIME_DIR}/sweep_live.jsonl${NC}"
echo -e "  Process logs→  ${WHT}${LOG_DIR}/${NC}"
echo
echo -e "  ${YLW}Press Ctrl+C to stop all processes.${NC}"
echo
sep

# ── Live tail of pluto_sweep console output ───────────────────────────────────
if [[ "$DEMO_MODE" == false && -f "${LOG_DIR}/pluto_sweep.log" ]]; then
  echo
  log "Tailing pluto_sweep output (Ctrl+C to stop pipeline):"
  sep
  tail -f "${LOG_DIR}/pluto_sweep.log"
else
  # Just wait for Ctrl+C in demo mode
  while true; do sleep 5; done
fi