param(
    [int]$AegisPort = 8000,
    [int]$OpenClawPort = 18789,
    [string]$AegisApiKey = "changeme",
    [string]$OpenClawCommand = "openclaw",
    [string]$OpenClawConfigPath = "",
    [string]$OpenClawStateDir = "",
    [string]$PythonExe = "",
    [switch]$OpenDashboard
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pluginPath = Join-Path $repoRoot "integrations\openclaw-aegis-guard"
$aegisUrl = "http://127.0.0.1:$AegisPort/v1"

function Get-PythonLaunchCommand {
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
if ([string]::IsNullOrWhiteSpace($OpenClawConfigPath)) {
    $OpenClawConfigPath = Join-Path $repoRoot ".openclaw\openclaw.aegis.json"
}
if ([string]::IsNullOrWhiteSpace($OpenClawStateDir)) {
    $OpenClawStateDir = Join-Path $repoRoot ".openclaw\state"
}

Write-Host "[stack] repo root: $repoRoot"
Write-Host "[stack] plugin path: $pluginPath"
Write-Host "[stack] openclaw config: $OpenClawConfigPath"
Write-Host "[stack] openclaw state: $OpenClawStateDir"

if (-not (Test-Path $pluginPath)) {
    throw "Plugin path not found: $pluginPath"
}
if (-not (Test-Path (Split-Path -Parent $OpenClawConfigPath))) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OpenClawConfigPath) | Out-Null
}
if (-not (Test-Path $OpenClawStateDir)) {
    New-Item -ItemType Directory -Force -Path $OpenClawStateDir | Out-Null
}
if (-not (Test-Path $OpenClawConfigPath)) {
    @"
{
  "gateway": {
    "mode": "local",
    "port": $OpenClawPort,
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": "aegis-openclaw-local-token"
    }
  },
  "agents": {
    "defaults": {
      "workspace": "$($repoRoot -replace '\\','\\\\')\\.openclaw\\\\workspace"
    }
  },
  "plugins": {
    "enabled": true,
    "load": { "paths": [] },
    "entries": {}
  }
}
"@ | Out-File -FilePath $OpenClawConfigPath -Encoding utf8
}

$env:OPENCLAW_CONFIG_PATH = $OpenClawConfigPath
$env:OPENCLAW_STATE_DIR = $OpenClawStateDir
$pythonLaunch = Get-PythonLaunchCommand -RepoRoot $repoRoot -PreferredPythonExe $PythonExe

$cfg = Get-Content $OpenClawConfigPath -Raw | ConvertFrom-Json
if (-not $cfg.agents) { $cfg | Add-Member -NotePropertyName agents -NotePropertyValue (@{}) }
if (-not $cfg.agents.defaults) { $cfg.agents | Add-Member -NotePropertyName defaults -NotePropertyValue (@{}) }
if (-not $cfg.agents.defaults.compaction) { $cfg.agents.defaults | Add-Member -NotePropertyName compaction -NotePropertyValue (@{}) }
$cfg.agents.defaults.compaction.mode = "safeguard"
$cfg.agents.defaults.compaction.memoryFlush = @{
    enabled = $false
}
$cfg | ConvertTo-Json -Depth 100 | Out-File -FilePath $OpenClawConfigPath -Encoding utf8

try {
    & $OpenClawCommand plugins install -l $pluginPath | Out-Host
} catch {
    Write-Host "[stack] plugin install returned non-zero (possibly already installed), continuing..."
}

& $OpenClawCommand plugins enable aegis-guard | Out-Host
& $OpenClawCommand config set "plugins.entries.aegis-guard.enabled" true | Out-Host
& $OpenClawCommand config set "plugins.entries.aegis-guard.config.aegisUrl" $aegisUrl | Out-Host
& $OpenClawCommand config set "plugins.entries.aegis-guard.config.apiKeyEnv" "AEGIS_API_KEY" | Out-Host
& $OpenClawCommand config set "plugins.entries.aegis-guard.config.environment" "dev" | Out-Host
& $OpenClawCommand config set "plugins.entries.aegis-guard.config.observeLlmIo" true | Out-Host
& $OpenClawCommand config set "plugins.entries.aegis-guard.config.guardOutboundMessages" true | Out-Host
& $OpenClawCommand config set "plugins.entries.aegis-guard.config.enforceInputGate" true | Out-Host

$aegisCmd = "Set-Location '$repoRoot'; `$env:AEGIS_API_KEY='$AegisApiKey'; $pythonLaunch -m uvicorn --app-dir src aegis.api.main:app --port $AegisPort"
$gatewayCmd = "Set-Location '$repoRoot'; `$env:AEGIS_API_KEY='$AegisApiKey'; `$env:AEGIS_BASE_URL='$aegisUrl'; `$env:OPENCLAW_CONFIG_PATH='$OpenClawConfigPath'; `$env:OPENCLAW_STATE_DIR='$OpenClawStateDir'; $OpenClawCommand gateway --port $OpenClawPort --verbose"

Start-Process powershell -ArgumentList "-NoExit", "-Command", $aegisCmd | Out-Null
Start-Process powershell -ArgumentList "-NoExit", "-Command", $gatewayCmd | Out-Null

Write-Host "[stack] started Aegis API on :$AegisPort"
Write-Host "[stack] python launcher: $pythonLaunch"
Write-Host "[stack] started OpenClaw gateway on :$OpenClawPort"
Write-Host "[stack] dashboard: http://127.0.0.1:$AegisPort/v1/dashboard"

if ($OpenDashboard) {
    Start-Process "http://127.0.0.1:$AegisPort/v1/dashboard" | Out-Null
}
