param(
  [string]$BaseUrl = "http://127.0.0.1:8000/v1",
  [string]$ApiKey = "changeme",
  [string]$ModelName = "qwen2.5:7b-instruct",
  [string]$PythonExe = "",
  [switch]$StartAegis,
  [switch]$OpenDashboard
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Get-PythonCommand {
  param(
    [string]$RepoRoot,
    [string]$PreferredPythonExe
  )

  if (-not [string]::IsNullOrWhiteSpace($PreferredPythonExe)) {
    if (-not (Test-Path $PreferredPythonExe)) {
      throw "Specified Python executable was not found: $PreferredPythonExe"
    }
    return "& '$PreferredPythonExe'"
  }

  $venvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
  if (Test-Path $venvPython) {
    return "& '$venvPython'"
  }
  if (Get-Command py -ErrorAction SilentlyContinue) {
    return "py -3"
  }
  if (Get-Command python -ErrorAction SilentlyContinue) {
    return "python"
  }

  throw "Python was not found. Install Python 3 or pass -PythonExe with a full path."
}

$pythonCmd = Get-PythonCommand -RepoRoot $root -PreferredPythonExe $PythonExe
Write-Host "[krimo] python: $pythonCmd"

$env:AEGIS_BASE_URL = $BaseUrl
$env:AEGIS_API_KEY = $ApiKey
$env:AGENT_MODEL_NAME = $ModelName
$env:PYTHONPATH = (Join-Path $root "src") + [IO.Path]::PathSeparator + (Join-Path $root "krimo_ai\src")

if ($StartAegis) {
  $dashboardFlag = ""
  if ($OpenDashboard) {
    $dashboardFlag = " -OpenDashboard"
  }
  $aegisCmd = @(
    "Set-Location '$root'"
    "& '$($PSScriptRoot)\..\scripts\start_aegis.ps1' -ApiKey '$ApiKey' -Model '$ModelName' -PythonExe '$PythonExe'$dashboardFlag"
  ) -join "; "
  Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $aegisCmd | Out-Null
  Start-Sleep -Seconds 3
}

try {
  $dashboardUrl = ($BaseUrl -replace "/v1/?$", "") + "/v1/dashboard"
  Invoke-WebRequest -UseBasicParsing -Method Get -Uri $dashboardUrl -TimeoutSec 3 | Out-Null
} catch {
  throw "Aegis is not reachable at $BaseUrl. Start it with: python -m uvicorn --app-dir src aegis.api.main:app --port 8000  or run .\scripts\start_aegis.ps1"
}

Invoke-Expression "$pythonCmd .\krimo_ai\run.py"
