$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $root 'backend'
$frontend = Join-Path $root 'frontend'
$venvActivate = Join-Path $root '.venv\Scripts\Activate.ps1'

Write-Host "Starting backend..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit -Command Set-Location '$backend'; & '$venvActivate'; python app.py" -WindowStyle Normal

Start-Sleep -Seconds 3

Write-Host "Starting frontend..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit -Command Set-Location '$frontend'; npm run dev -- --host 127.0.0.1 --port 5173" -WindowStyle Normal

Write-Host "Both services started." -ForegroundColor Green
Write-Host "Backend: http://127.0.0.1:8000" -ForegroundColor Yellow
Write-Host "Frontend: http://127.0.0.1:5173" -ForegroundColor Yellow
