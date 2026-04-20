@echo off
cd /d "%~dp0"
echo Starting VAPT...
py -3 app.py
if errorlevel 1 python app.py
pause
