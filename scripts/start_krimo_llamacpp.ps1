[CmdletBinding()]
param(
    [int]$AegisPort = 8000,
    [int]$LlamaCppPort = 8081,
    [string]$ModelPath = "",
    [string]$Alias = "qwen2.5-3b-instruct-q4_k_m",
    [string]$AegisApiKey = "changeme",
    [string]$PythonExe = "",
    [switch]$OpenDashboard,
    [switch]$StartKrimo
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$llamaServer = Join-Path $repoRoot "llama.cpp\llama-server.exe"
$aegisUrl = "http://127.0.0.1:$AegisPort/v1"
$chatEndpoint = "http://127.0.0.1:$LlamaCppPort/v1/chat/completions"

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

$pythonLaunch = Get-PythonLaunchCommand -RepoRoot $repoRoot -PreferredPythonExe $PythonExe

$llamaCmd = "Set-Location '$repoRoot'; & '$llamaServer' --model '$ModelPath' --alias '$Alias' --host 127.0.0.1 --port $LlamaCppPort --ctx-size 32768"
$aegisCmd = "Set-Location '$repoRoot'; `$env:AEGIS_API_KEY='$AegisApiKey'; `$env:AEGIS_LLM_ENABLED='true'; `$env:AEGIS_MODEL_ENABLED='true'; `$env:AEGIS_LLM_TIMEOUT='45'; `$env:AEGIS_MODEL_TIMEOUT='90'; `$env:AEGIS_LLM_ENDPOINT='$chatEndpoint'; `$env:AEGIS_MODEL_ENDPOINT='$chatEndpoint'; `$env:AEGIS_LLM_MODEL='$Alias'; `$env:AEGIS_MODEL_NAME='$Alias'; `$env:AGENT_MODEL_ENDPOINT='$chatEndpoint'; `$env:AGENT_MODEL_NAME='$Alias'; $pythonLaunch -m uvicorn --app-dir src aegis.api.main:app --port $AegisPort"
$krimoCmd = "Set-Location '$repoRoot'; `$env:AEGIS_BASE_URL='$aegisUrl'; `$env:AEGIS_API_KEY='$AegisApiKey'; `$env:AGENT_MODEL_ENDPOINT='$chatEndpoint'; `$env:AGENT_MODEL_NAME='$Alias'; `$env:PYTHONPATH='src'; $pythonLaunch .\examples\real_guarded_agent.py"

Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $llamaCmd | Out-Null
Start-Sleep -Seconds 5
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $aegisCmd | Out-Null

if ($StartKrimo) {
    Start-Sleep -Seconds 2
    Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $krimoCmd | Out-Null
}

Write-Host "[krimo-llamacpp] llama.cpp server: http://127.0.0.1:$LlamaCppPort/v1"
Write-Host "[krimo-llamacpp] model alias: $Alias"
Write-Host "[krimo-llamacpp] gguf: $ModelPath"
Write-Host "[krimo-llamacpp] Aegis dashboard: http://127.0.0.1:$AegisPort/v1/dashboard"
Write-Host "[krimo-llamacpp] To start KriMo later:"
Write-Host "  `$env:AEGIS_BASE_URL='$aegisUrl'"
Write-Host "  `$env:AEGIS_API_KEY='$AegisApiKey'"
Write-Host "  `$env:AGENT_MODEL_ENDPOINT='$chatEndpoint'"
Write-Host "  `$env:AGENT_MODEL_NAME='$Alias'"
Write-Host "  `$env:PYTHONPATH='src'"
Write-Host "  python .\examples\real_guarded_agent.py"

if ($OpenDashboard) {
    Start-Process "http://127.0.0.1:$AegisPort/v1/dashboard" | Out-Null
}
