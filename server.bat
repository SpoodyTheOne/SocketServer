@echo off
setlocal
setlocal enabledelayedexpansion
for /f "usebackq tokens=2 delims=:" %%a in (`ipconfig ^| findstr /r "[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*"`) do (
  set _temp=%%a
  rem remove leading space
  set _ipaddress=!_temp:~1!
  echo ip: !_ipaddress!
  title !_ipaddress!
  goto start
  )
endlocal

:start
python server.py
pause