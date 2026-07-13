@echo off
taskkill /FI "WINDOWTITLE eq CTW-bt" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-css" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CTW-css-idle" /T /F >nul 2>&1
echo Stopping CTW RF Monitor pipeline...
echo Done.
pause
