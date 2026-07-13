# fix_pluto.py  — run once then delete
import sys

with open(r'C:\sdr\logs\pluto_sweep.py', 'r', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()

# Find print_ntp_banner start and ClockAnchor start
banner_start = None
clock_start  = None

for i, line in enumerate(lines):
    if 'def print_ntp_banner' in line and banner_start is None:
        banner_start = i
    if 'class ClockAnchor' in line and clock_start is None:
        clock_start = i

if banner_start is None or clock_start is None:
    print(f"Could not locate: banner={banner_start} clock={clock_start}")
    sys.exit(1)

print(f"Deleting lines {banner_start+1} to {clock_start} (print_ntp_banner)")

REPLACEMENT = '''from ntp_web import get_ntp_info, print_web_time_banner

def print_ntp_banner(ntp_info: dict):
    """Wrapper — delegates to ntp_web, ASCII-safe for Windows cp1252."""
    print("\\n" + "="*68)
    print("  CTW WEB TIME REFERENCE")
    print("="*68)
    print(f"  Source          : {ntp_info.get('ntp_source','?')}")
    print(f"  Web UTC         : {ntp_info.get('ntp_last_sync_utc','?')}")
    print(f"  System UTC      : {ntp_info.get('ntp_utc_at_query','?')}")
    offset_s = ntp_info.get('ntp_offset_s')
    if offset_s is not None:
        sign = '+' if offset_s >= 0 else ''
        print(f"  System offset   : {sign}{offset_s:.6f} s  ({sign}{offset_s*1000:.3f} ms)")
        direction = 'AHEAD' if offset_s > 0 else 'BEHIND'
        print(f"  Offset note     : system clock is {direction} web reference by {abs(offset_s*1000):.1f} ms")
    else:
        print("  System offset   : unknown")
    err = ntp_info.get('ntp_error')
    if err:
        print(f"  ERROR           : {err}")
    print("="*68 + "\\n")

'''

# Also add UTF-8 stdout fix at the very top if not already there
utf8_fix = (
    'import sys as _sys, io as _io\n'
    '_sys.stdout = _io.TextIOWrapper(_sys.stdout.buffer, encoding="utf-8", errors="replace")\n'
    '_sys.stderr = _io.TextIOWrapper(_sys.stderr.buffer, encoding="utf-8", errors="replace")\n'
)

# Find the shebang / first import line
insert_utf8_at = 0
for i, line in enumerate(lines):
    if line.startswith('#!/'):
        insert_utf8_at = i + 1
        break
    if line.startswith('import') or line.startswith('from'):
        insert_utf8_at = i
        break

# Check if utf8 fix already present
already_has_utf8 = any('TextIOWrapper' in l for l in lines[:20])

new_lines = []

# Insert UTF-8 fix at top
for i, line in enumerate(lines):
    if i == insert_utf8_at and not already_has_utf8:
        new_lines.append(utf8_fix)
    # Skip the old print_ntp_banner block
    if banner_start <= i < clock_start:
        if i == banner_start:
            new_lines.append(REPLACEMENT)
        continue
    new_lines.append(line)

with open(r'C:\sdr\logs\pluto_sweep.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Done. pluto_sweep.py patched.")
print(f"  - UTF-8 stdout fix inserted at line {insert_utf8_at+1}")
print(f"  - print_ntp_banner replaced (lines {banner_start+1}-{clock_start})")
print(f"  - from ntp_web import added")