# Build and run the isolated Docker lab on Windows (Docker Desktop, Linux containers / WSL 2 backend).
#   lab\run_lab.ps1 baseline [SECONDS]   benign only, default 1200 s -> data\lab-docker\baseline
#   lab\run_lab.ps1 attack               benign + scripted attacks   -> data\lab-docker\attack
param([Parameter(Mandatory)][ValidateSet("baseline", "attack")][string]$Mode, [int]$Seconds = 1200)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$root = (Resolve-Path "..").Path
if (-not $env:LAB_OUT) { $env:LAB_OUT = Join-Path $root "data\lab-docker\$Mode" }
if (Test-Path $env:LAB_OUT) { Remove-Item -Recurse -Force $env:LAB_OUT }
New-Item -ItemType Directory -Force $env:LAB_OUT | Out-Null

function Cleanup { docker compose --profile attack down --remove-orphans 2>&1 | Out-Null }
try {
  Cleanup
  docker compose --profile attack build
  if ($LASTEXITCODE -ne 0) { throw "docker build failed" }
  if ($Mode -eq "baseline") {
    docker compose up -d target sensor recorder client
    Write-Host "capturing benign baseline for $Seconds s ..."
    Start-Sleep -Seconds $Seconds
  } else {
    docker compose --profile attack up -d
    Write-Host "attack scenario running (about 20 min) ..."
    docker wait (docker compose ps -aq attacker) (docker compose ps -aq implant) | Out-Null
    Start-Sleep -Seconds 15   # let the tail of the scenario reach the sensor
  }
  docker compose stop -t 60 sensor recorder client   # SIGTERM: Zeek flushes open connections
  Write-Host "logs in $($env:LAB_OUT):"; Get-ChildItem $env:LAB_OUT
} finally { Cleanup }
