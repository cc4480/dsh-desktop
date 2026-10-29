# The whole demo in one command (Windows): lab data -> models + profile -> pipeline -> evaluation -> dashboard.
#   $env:NIDS_DASHBOARD_PASSWORD = "change-me-please"; .\scripts\demo.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$py = if (Test-Path .\.venv\Scripts\python.exe) { ".\.venv\Scripts\python.exe" } else { "python" }
function Run { & $py @args; if ($LASTEXITCODE -ne 0) { throw "failed: python $args" } }

Run -m nids lab
Run -m nids train data\lab\baseline
Run -m nids run data\lab\demo --fresh @args
Run -m nids evaluate data\lab\demo
if (-not (Test-Path config\users.yaml) -and -not $env:NIDS_DASHBOARD_PASSWORD) {
  throw "add a login first (python -m nids add-user <name> --role approver) or set NIDS_DASHBOARD_PASSWORD"
}
Run -m streamlit run dashboard\app.py
