#ntp configure first
python -c "
import ctypes, datetime, time, urllib.request, json, ssl

# Fetch true UTC
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('https://timeapi.io/api/time/current/zone?timeZone=UTC', headers={'User-Agent':'CTW/1.0'})
r = urllib.request.urlopen(req, timeout=5, context=ctx)
obj = json.loads(r.read())
true_utc = datetime.datetime.fromisoformat(obj['dateTime'].replace('Z','+00:00'))
print(f'True UTC from timeapi.io: {true_utc}')

class ST(ctypes.Structure):
    _fields_ = [('wYear',ctypes.c_uint16),('wMonth',ctypes.c_uint16),
                ('wDayOfWeek',ctypes.c_uint16),('wDay',ctypes.c_uint16),
                ('wHour',ctypes.c_uint16),('wMinute',ctypes.c_uint16),
                ('wSecond',ctypes.c_uint16),('wMilliseconds',ctypes.c_uint16)]

st = ST(true_utc.year, true_utc.month, true_utc.weekday(),
        true_utc.day, true_utc.hour, true_utc.minute,
        true_utc.second, true_utc.microsecond // 1000)

ok = ctypes.windll.kernel32.SetSystemTime(ctypes.byref(st))
print('Clock set OK.' if ok else 'FAILED - run as Administrator.')
"


#kill running ports if any 
taskkill /F /IM python.exe
taskkill /FI "WINDOWTITLE eq CTW-live_reader" /T /F
taskkill /FI "WINDOWTITLE eq CTW-gz_watch" /T /F
taskkill /FI "WINDOWTITLE eq CTW-rf_server" /T /F
taskkill /FI "WINDOWTITLE eq CTW-correlator" /T /F
taskkill /FI "WINDOWTITLE eq CTW-pluto_sweep" /T /F
taskkill /FI "WINDOWTITLE eq CTW-fs5000" /T /F
netstat -ano | findstr :8080
taskkill /PID 1234 /T /F
chmod +x run.sh
stop.bat
#test
Window 1:
python C:\sdr\logs\gz_watch.py
Window 2:
python C:\sdr\logs\live_reader.py
Window 3:
python C:\sdr\logs\rf_server.py
Window 4:
python C:\sdr\logs\pluto_sweep.py --out C:\sdr\logs --start 385900000 --stop 386100000 --step 10000 --no-iq

Also add "CTW-ublox" and "CTW-gnss" to the stop.bat block and the health-check loop.
Run order is: ublox_data.py first to create the .ubx file, then ublox_parser.py to tail it, then gnss_server.py to serve the map. The parser auto-detects the latest .ubx in C:\sdr\logs\UBLOX\ so no manual file selection is needed.


Then open http://localhost:8000/sweep.html and hit CONNECT. Once we confirm data is flowing we fix the bat properly.




python C:\sdr\logs\pluto_sweep.py --out C:\sdr\logs --start 385900000 --stop 386100000 --step 10000
python C:\sdr\logs\pluto_sweep.py --out C:\sdr\logs --freqs 386000000 386020000
win-launch.bat --freqs 386000000 386020000


# Full sweep — auto-detects Pluto on default IP
./run.sh

# Your confirmed forensic target — 386 MHz with 10 kHz channel spacing
./run.sh --freqs 386000000 386020000

# Narrow band, explicit step size
./run.sh --start 385800000 --stop 386200000 --step 10000

# Full band sweep
./run.sh --start 70000000 --stop 6000000000 --step 1000000

# Headless / no browser (server context)
./run.sh --freqs 386000000 386020000 --no-browser

# Demo mode — no Pluto required, browser auto-uses synthetic data
./run.sh --demo

# Custom output dir
./run.sh --freqs 386000000 386020000 --out /mnt/sdr/logs

# Override Python interpreter
PYTHON=python3.11 ./run.sh --demo



What a meaningful CORR event looks like in practice
json{
  "type":         "CORR",
  "source":       "geiger_led",
  "event_wall_ns": 1715123456789012345,
  "event_wall_iso":"2025-05-08T14:30:56.789012345Z",
  "dr":           0.4200,
  "cpm":          252,
  "cps":          4,
  "audio_pulses_1s": 6,
  "audio_burst":  true,
  "rf_freq_hz":   386010000,
  "rf_dbfs":      -68.4,
  "rf_cf":        118.3,
  "rf_atten":     83.1,
  "rf_dt_ms":     +47.2,
  "rf_count":     3,
  "all_rf_freqs": [386010000, 386000000, 386020000]
}