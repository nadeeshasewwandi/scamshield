@echo off
cd /d "%~dp0"
set "ROOT=%~dp0"
set "VENV_ACTIVATE=%ROOT%.venv\Scripts\Activate.ps1"
start "Backend" powershell -NoExit -Command "Set-Location '%ROOT%backend'; & '%VENV_ACTIVATE%'; python app.py"
start "Frontend" powershell -NoExit -Command "Set-Location '%ROOT%frontend'; npm run dev -- --host 127.0.0.1 --port 5173"
echo Backend: http://127.0.0.1:8000
echo Frontend: http://127.0.0.1:5173
pause
