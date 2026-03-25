param(
    [int]$Port = 8000,
    [string]$ApiKey = "changeme",
    [string]$OllamaBaseUrl = "http://127.0.0.1:11434",
    [string]$Model = "qwen2.5:7b-instruct",
    [string]$PythonExe = "",
    [switch]$OpenDashboard,
    [switch]$Reload
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot

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

try {
    $ollama = Invoke-RestMethod -Method Get -Uri "$OllamaBaseUrl/api/tags" -TimeoutSec 5
} catch {
    throw "Ollama is not reachable at $OllamaBaseUrl. Start Ollama first."
}

$models = @($ollama.models | ForEach-Object { $_.name })
if ($models.Count -gt 0 -and ($models -notcontains $Model)) {
    Write-Host "[aegis] warning: model '$Model' was not found in Ollama tags." -ForegroundColor Yellow
    Write-Host "[aegis] available models: $($models -join ', ')" -ForegroundColor Yellow
}

$pythonCmd = Get-PythonCommand -RepoRoot $repoRoot -PreferredPythonExe $PythonExe
$reloadFlag = ""
if ($Reload) {
    $reloadFlag = " --reload"
}

$runCmd = @(
    "Set-Location '$repoRoot'"
    "`$env:AEGIS_API_KEY='$ApiKey'"
    "`$env:AEGIS_OLLAMA_BASE_URL='$OllamaBaseUrl'"
    "`$env:AEGIS_LLM_ENABLED='true'"
    "`$env:AEGIS_MODEL_ENABLED='true'"
    "`$env:AEGIS_LLM_ENDPOINT='$OllamaBaseUrl/v1/chat/completions'"
    "`$env:AEGIS_MODEL_ENDPOINT='$OllamaBaseUrl/v1/chat/completions'"
    "`$env:AEGIS_LLM_MODEL='$Model'"
    "`$env:AEGIS_MODEL_NAME='$Model'"
    "$pythonCmd -m uvicorn --app-dir src aegis.api.main:app --port $Port$reloadFlag"
) -join "; "

Write-Host "[aegis] repo: $repoRoot"
Write-Host "[aegis] ollama: $OllamaBaseUrl"
Write-Host "[aegis] model: $Model"
Write-Host "[aegis] port: $Port"
Write-Host "[aegis] dashboard: http://127.0.0.1:$Port/v1/dashboard"

Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $runCmd | Out-Null

if ($OpenDashboard) {
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:$Port/v1/dashboard" | Out-Null
}
