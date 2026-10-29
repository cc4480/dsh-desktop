# One-time setup on Windows (PowerShell 5.1 or 7): virtual environment, dependencies, demo data.
#   powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) { $python = @("py", "-3") } else { $python = @("python") }
$ver = & $python[0] $python[1..($python.Length)] -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$ver -lt [version]"3.11") { throw "Python 3.11 or newer is required (found $ver). Install it from python.org." }

if (-not (Test-Path .venv)) { & $python[0] $python[1..($python.Length)] -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

& .\.venv\Scripts\python.exe -m nids lab
& .\.venv\Scripts\python.exe -m nids train data\lab\baseline
Write-Host "`nDone. Next:"
Write-Host "  .\.venv\Scripts\python.exe -m nids add-user alice --role approver"
Write-Host "  .\.venv\Scripts\python.exe -m streamlit run dashboard\app.py"
