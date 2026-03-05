param(
    [int]$AegisPort = 8000,
    [int]$OpenClawPort = 18790,
    [int]$LlamaPort = 8080,
    [int]$LlamaCtxSize = 16384,
    [string]$AegisApiKey = "changeme",
    [string]$OpenClawCommand = "openclaw.cmd",
    [string]$OpenClawConfigPath = "",
    [string]$OpenClawStateDir = "",
    [string]$LlamaServerExe = "",
    [string]$LlamaModelPath = "",
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
if ([string]::IsNullOrWhiteSpace($LlamaServerExe)) {
    $LlamaServerExe = Join-Path $repoRoot "llama.cpp\llama-server.exe"
}
if ([string]::IsNullOrWhiteSpace($LlamaModelPath)) {
    $LlamaModelPath = Join-Path $repoRoot "models\qwen2.5-3b-instruct-q4_k_m.gguf"
}

if (-not (Test-Path $pluginPath)) {
    throw "Plugin path not found: $pluginPath"
}
if (-not (Test-Path $LlamaServerExe)) {
    throw "llama-server executable not found at: $LlamaServerExe"
}
if (-not (Test-Path $LlamaModelPath)) {
    throw "Local GGUF model not found at: $LlamaModelPath"
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
      "mode": "none"
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

$cfg = Get-Content $OpenClawConfigPath -Raw | ConvertFrom-Json
if (-not $cfg.gateway) { $cfg | Add-Member -NotePropertyName gateway -NotePropertyValue (@{}) }
if (-not $cfg.agents) { $cfg | Add-Member -NotePropertyName agents -NotePropertyValue (@{}) }
if (-not $cfg.agents.defaults) { $cfg.agents | Add-Member -NotePropertyName defaults -NotePropertyValue (@{}) }
if (-not $cfg.plugins) { $cfg | Add-Member -NotePropertyName plugins -NotePropertyValue (@{}) }
if (-not $cfg.plugins.load) { $cfg.plugins | Add-Member -NotePropertyName load -NotePropertyValue (@{}) }
if (-not $cfg.plugins.entries) { $cfg.plugins | Add-Member -NotePropertyName entries -NotePropertyValue (@{}) }

$cfg.gateway.mode = "local"
$cfg.gateway.bind = "loopback"
$cfg.gateway.port = $OpenClawPort
$cfg.gateway.auth = @{ mode = "none" }

$cfg.agents.defaults.model = @{ primary = "local/qwen2.5-3b-instruct" }
$cfg.agents.defaults.models = @{
    "local/qwen2.5-3b-instruct" = @{
        params = @{
            maxTokens = 256
            timeoutMs = 180000
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
$cfg.agents.defaults.compaction.memoryFlush = @{
    enabled = $false
}

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
        local = @{
            baseUrl = "http://127.0.0.1:$LlamaPort/v1"
            apiKey = "local-free"
            api = "openai-completions"
            models = @(
                @{
                    id = "qwen2.5-3b-instruct"
                    name = "Qwen2.5 3B Instruct (Local llama.cpp)"
                    reasoning = $false
                    input = @("text")
                    cost = @{
                        input = 0
                        output = 0
                        cacheRead = 0
                        cacheWrite = 0
                    }
                    contextWindow = $LlamaCtxSize
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
    Write-Host "[free-stack] plugin install returned non-zero (possibly already installed), continuing..."
}

& $OpenClawCommand plugins enable aegis-guard | Out-Host

$llamaWorkDir = Split-Path -Parent $LlamaServerExe
$llamaCmd = "Set-Location '$llamaWorkDir'; & '$LlamaServerExe' -m '$LlamaModelPath' --port $LlamaPort --host 127.0.0.1 --ctx-size $LlamaCtxSize --n-gpu-layers 35"
$aegisCmd = "Set-Location '$repoRoot'; `$env:AEGIS_API_KEY='$AegisApiKey'; $pythonLaunch -m uvicorn --app-dir src aegis.api.main:app --port $AegisPort"
$gatewayCmd = "Set-Location '$repoRoot'; `$env:AEGIS_API_KEY='$AegisApiKey'; `$env:AEGIS_BASE_URL='$aegisUrl'; `$env:OPENCLAW_CONFIG_PATH='$OpenClawConfigPath'; `$env:OPENCLAW_STATE_DIR='$OpenClawStateDir'; $OpenClawCommand gateway run --port $OpenClawPort --auth none --verbose"

Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $llamaCmd | Out-Null
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $aegisCmd | Out-Null
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $gatewayCmd | Out-Null

Start-Sleep -Seconds 6
$llamaReady = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $resp = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$LlamaPort/v1/models" -TimeoutSec 3
        if ($resp.StatusCode -eq 200) {
            $llamaReady = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

Write-Host "[free-stack] started llama.cpp on :$LlamaPort"
Write-Host "[free-stack] llama ctx-size: $LlamaCtxSize"
Write-Host "[free-stack] started Aegis API on :$AegisPort"
Write-Host "[free-stack] python launcher: $pythonLaunch"
Write-Host "[free-stack] started OpenClaw gateway on :$OpenClawPort"
Write-Host "[free-stack] dashboard: http://127.0.0.1:$AegisPort/v1/dashboard"
Write-Host "[free-stack] openclaw status: openclaw.cmd --profile aegis health --json"
if ($llamaReady) {
    Write-Host "[free-stack] llama endpoint ready: http://127.0.0.1:$LlamaPort/v1/models"
} else {
    Write-Host "[free-stack] llama endpoint not ready yet, check the llama.cpp window logs."
}

if ($OpenDashboard) {
    Start-Process "http://127.0.0.1:$AegisPort/v1/dashboard" | Out-Null
}
