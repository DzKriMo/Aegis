param(
    [int]$AegisPort = 8000,
    [int]$OpenClawPort = 18790,
    [int]$LlamaCppPort = 8081,
    [string]$ModelPath = "",
    [string]$Alias = "qwen2.5-3b-instruct-q4_k_m",
    [string]$AegisApiKey = "changeme",
    [string]$OpenClawCommand = "openclaw.cmd",
    [string]$OpenClawConfigPath = "",
    [string]$OpenClawStateDir = "",
    [string]$PythonExe = "",
    [switch]$OpenDashboard
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pluginPath = Join-Path $repoRoot "integrations\openclaw-aegis-guard"
$aegisUrl = "http://127.0.0.1:$AegisPort/v1"
$llamaServer = Join-Path $repoRoot "llama.cpp\llama-server.exe"

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

    if (Get-Command py -ErrorAction SilentlyContinue) { return "py -3" }
    if (Get-Command python -ErrorAction SilentlyContinue) { return "python" }
    throw "Python was not found. Install Python 3 or pass -PythonExe."
}

if ([string]::IsNullOrWhiteSpace($ModelPath)) {
    $ModelPath = Join-Path $repoRoot "models\qwen2.5-3b-instruct-q4_k_m.gguf"
}
if (-not (Test-Path $ModelPath)) {
    throw "GGUF model not found: $ModelPath"
}
if (-not (Test-Path $llamaServer)) {
    throw "llama-server.exe not found: $llamaServer"
}

if ([string]::IsNullOrWhiteSpace($OpenClawConfigPath)) {
    $OpenClawConfigPath = Join-Path $repoRoot ".openclaw\openclaw.llamacpp.json"
}
if ([string]::IsNullOrWhiteSpace($OpenClawStateDir)) {
    $OpenClawStateDir = Join-Path $repoRoot ".openclaw\state"
}

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
    "auth": { "mode": "none" }
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

$cfg = Get-Content $OpenClawConfigPath -Raw | ConvertFrom-Json
if (-not $cfg.gateway) { $cfg | Add-Member -NotePropertyName gateway -NotePropertyValue (@{}) }
if (-not $cfg.agents) { $cfg | Add-Member -NotePropertyName agents -NotePropertyValue (@{}) }
if (-not $cfg.agents.defaults) { $cfg.agents | Add-Member -NotePropertyName defaults -NotePropertyValue (@{}) }
if (-not $cfg.plugins) { $cfg | Add-Member -NotePropertyName plugins -NotePropertyValue (@{}) }
if (-not $cfg.plugins.load) { $cfg.plugins | Add-Member -NotePropertyName load -NotePropertyValue (@{}) }
if (-not $cfg.plugins.entries) { $cfg.plugins | Add-Member -NotePropertyName entries -NotePropertyValue (@{}) }
if (-not ($cfg.agents.defaults.PSObject.Properties.Name -contains "model")) {
    $cfg.agents.defaults | Add-Member -NotePropertyName model -NotePropertyValue (@{})
}
if (-not ($cfg.agents.defaults.PSObject.Properties.Name -contains "models")) {
    $cfg.agents.defaults | Add-Member -NotePropertyName models -NotePropertyValue (@{})
}
if (-not ($cfg.PSObject.Properties.Name -contains "models")) {
    $cfg | Add-Member -NotePropertyName models -NotePropertyValue (@{})
}
if (-not ($cfg.plugins.entries.PSObject.Properties.Name -contains "aegis-guard")) {
    $cfg.plugins.entries | Add-Member -NotePropertyName "aegis-guard" -NotePropertyValue (@{})
}

$cfg.gateway.mode = "local"
$cfg.gateway.bind = "loopback"
$cfg.gateway.port = $OpenClawPort
$cfg.gateway.auth = @{ mode = "none" }

$providerModelId = "llamacpp/$Alias"
$cfg.agents.defaults.model = @{ primary = $providerModelId }
$cfg.agents.defaults.models = @{
    $providerModelId = @{
        params = @{
            maxTokens = 256
            timeoutMs = 240000
            temperature = 0.2
        }
    }
}
if (-not $cfg.agents.defaults.workspace) {
    $cfg.agents.defaults.workspace = "$($repoRoot -replace '\\','\\\\')\\.openclaw\\\\workspace"
}
if (-not $cfg.agents.defaults.compaction) {
    $cfg.agents.defaults | Add-Member -NotePropertyName compaction -NotePropertyValue (@{})
}
$cfg.agents.defaults.compaction.mode = "safeguard"
$cfg.agents.defaults.compaction.memoryFlush = @{ enabled = $false }

$cfg.plugins.enabled = $true
$cfg.plugins.load.paths = @($pluginPath)
$cfg.plugins.entries."aegis-guard" = @{
    enabled = $true
    config = @{
        aegisUrl = $aegisUrl
        apiKeyEnv = "AEGIS_API_KEY"
        environment = "dev"
        observeLlmIo = $true
        guardOutboundMessages = $true
        enforceInputGate = $true
    }
}

$cfg.models = @{
    mode = "merge"
    providers = @{
        llamacpp = @{
            baseUrl = "http://127.0.0.1:$LlamaCppPort/v1"
            apiKey = "local-free"
            api = "openai-completions"
            models = @(
                @{
                    id = $Alias
                    name = "llama.cpp: $Alias"
                    reasoning = $false
                    input = @("text")
                    cost = @{
                        input = 0
                        output = 0
                        cacheRead = 0
                        cacheWrite = 0
                    }
                    contextWindow = 32768
                    maxTokens = 2048
                }
            )
        }
    }
}

$cfg | ConvertTo-Json -Depth 100 | Out-File -FilePath $OpenClawConfigPath -Encoding utf8

$env:OPENCLAW_CONFIG_PATH = $OpenClawConfigPath
$env:OPENCLAW_STATE_DIR = $OpenClawStateDir
$pythonLaunch = Get-PythonLaunchCommand -RepoRoot $repoRoot -PreferredPythonExe $PythonExe

try {
    & $OpenClawCommand plugins install -l $pluginPath | Out-Host
} catch {
    Write-Host "[llamacpp-stack] plugin install returned non-zero (possibly already installed), continuing..."
}

& $OpenClawCommand plugins enable aegis-guard | Out-Host

$llamaCmd = "Set-Location '$repoRoot'; & '$llamaServer' --model '$ModelPath' --alias '$Alias' --host 127.0.0.1 --port $LlamaCppPort --ctx-size 32768"
$aegisCmd = "Set-Location '$repoRoot'; `$env:AEGIS_API_KEY='$AegisApiKey'; `$env:AEGIS_LLM_ENABLED='true'; `$env:AEGIS_MODEL_ENABLED='true'; `$env:AEGIS_LLM_TIMEOUT='45'; `$env:AEGIS_MODEL_TIMEOUT='90'; `$env:AEGIS_LLM_ENDPOINT='http://127.0.0.1:$LlamaCppPort/v1/chat/completions'; `$env:AEGIS_MODEL_ENDPOINT='http://127.0.0.1:$LlamaCppPort/v1/chat/completions'; `$env:AEGIS_LLM_MODEL='$Alias'; `$env:AEGIS_MODEL_NAME='$Alias'; $pythonLaunch -m uvicorn --app-dir src aegis.api.main:app --port $AegisPort"
$gatewayCmd = "Set-Location '$repoRoot'; `$env:AEGIS_API_KEY='$AegisApiKey'; `$env:AEGIS_BASE_URL='$aegisUrl'; `$env:OPENCLAW_CONFIG_PATH='$OpenClawConfigPath'; `$env:OPENCLAW_STATE_DIR='$OpenClawStateDir'; $OpenClawCommand gateway run --port $OpenClawPort --auth none --verbose"

Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $llamaCmd | Out-Null
Start-Sleep -Seconds 5
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $aegisCmd | Out-Null
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $gatewayCmd | Out-Null

Write-Host "[llamacpp-stack] llama.cpp server: http://127.0.0.1:$LlamaCppPort/v1"
Write-Host "[llamacpp-stack] model alias: $Alias"
Write-Host "[llamacpp-stack] gguf: $ModelPath"
Write-Host "[llamacpp-stack] started Aegis API on :$AegisPort"
Write-Host "[llamacpp-stack] started OpenClaw gateway on :$OpenClawPort"
Write-Host "[llamacpp-stack] dashboard: http://127.0.0.1:$AegisPort/v1/dashboard"

if ($OpenDashboard) {
    Start-Process "http://127.0.0.1:$AegisPort/v1/dashboard" | Out-Null
}
