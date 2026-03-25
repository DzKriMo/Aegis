param(
    [string]$ProjectRoot = "$PSScriptRoot\..",
    [string]$VenvPath = "$PSScriptRoot\..\.venv",
    [string]$OllamaBaseUrl = "http://127.0.0.1:11434",
    [string]$OllamaModel = "qwen2.5:7b-instruct",
    [string]$PythonExe = "C:\Users\krimo\AppData\Local\Python\pythoncore-3.14-64\python.exe",
    [int]$ApiPort = 8000
)

$ErrorActionPreference = "Stop"

Set-Location $ProjectRoot

# Activate venv if present
$activate = Join-Path $VenvPath "Scripts\Activate.ps1"
if (Test-Path $activate) {
    . $activate
} else {
    Write-Host "Venv not found. Using PythonExe directly." -ForegroundColor Yellow
}

if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

try {
    $null = Invoke-RestMethod -Method Get -Uri "$OllamaBaseUrl/api/tags" -TimeoutSec 5
} catch {
    throw "Ollama is not reachable at '$OllamaBaseUrl'."
}

# Start Aegis API (includes dashboard endpoint) in a new window
Start-Process powershell -WorkingDirectory $ProjectRoot -ArgumentList @(
    "-NoExit",
    "-Command",
    "`$env:PYTHONPATH='src'; `$env:AEGIS_OLLAMA_BASE_URL='$OllamaBaseUrl'; `$env:AEGIS_LLM_ENABLED='true'; `$env:AEGIS_MODEL_ENABLED='true'; `$env:AEGIS_LLM_ENDPOINT='$OllamaBaseUrl/v1/chat/completions'; `$env:AEGIS_MODEL_ENDPOINT='$OllamaBaseUrl/v1/chat/completions'; `$env:AEGIS_LLM_MODEL='$OllamaModel'; `$env:AEGIS_MODEL_NAME='$OllamaModel'; & `"$PythonExe`" -m uvicorn aegis.api.main:app --port $ApiPort --reload"
)

Write-Host "Using Ollama: $OllamaBaseUrl" -ForegroundColor Green
Write-Host "Active model: $OllamaModel" -ForegroundColor Green
Write-Host "Dashboard URL: http://127.0.0.1:$ApiPort/v1/dashboard" -ForegroundColor Green
