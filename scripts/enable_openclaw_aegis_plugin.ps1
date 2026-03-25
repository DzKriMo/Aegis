[CmdletBinding()]
param(
    [string]$ConfigPath = "$HOME\.openclaw\openclaw.json",
    [string]$AegisUrl = "http://127.0.0.1:8000/v1",
    [string]$ApiKeyEnv = "AEGIS_API_KEY",
    [string]$Environment = "dev"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pluginPath = Join-Path $repoRoot "integrations\openclaw-aegis-guard"
$ConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)

if (-not (Test-Path $ConfigPath)) {
    throw "OpenClaw config not found: $ConfigPath"
}

if (-not (Test-Path $pluginPath)) {
    throw "Plugin path not found: $pluginPath"
}

$backupPath = "$ConfigPath.bak"
Copy-Item -Path $ConfigPath -Destination $backupPath -Force

$cfg = Get-Content -Raw $ConfigPath | ConvertFrom-Json

if (-not $cfg.plugins) {
    $cfg | Add-Member -NotePropertyName "plugins" -NotePropertyValue ([pscustomobject]@{})
}
if (-not $cfg.plugins.load) {
    $cfg.plugins | Add-Member -NotePropertyName "load" -NotePropertyValue ([pscustomobject]@{})
}
if (-not ($cfg.plugins.load.PSObject.Properties.Name -contains "paths")) {
    $cfg.plugins.load | Add-Member -NotePropertyName "paths" -NotePropertyValue @()
}
if (-not $cfg.plugins.entries) {
    $cfg.plugins | Add-Member -NotePropertyName "entries" -NotePropertyValue ([pscustomobject]@{})
}
if (-not ($cfg.plugins.entries.PSObject.Properties.Name -contains "aegis-guard")) {
    $cfg.plugins.entries | Add-Member -NotePropertyName "aegis-guard" -NotePropertyValue ([pscustomobject]@{})
}

$paths = @($cfg.plugins.load.paths | ForEach-Object { [string]$_ })
if ($paths -notcontains $pluginPath) {
    $cfg.plugins.load.paths = @($paths + $pluginPath)
} else {
    $cfg.plugins.load.paths = @($paths)
}

$cfg.plugins.entries."aegis-guard" = [pscustomobject]@{
    enabled = $true
    config = [pscustomobject]@{
        aegisUrl = $AegisUrl
        apiKeyEnv = $ApiKeyEnv
        environment = $Environment
        observeLlmIo = $true
        guardOutboundMessages = $true
        enforceInputGate = $true
    }
}

$cfg | ConvertTo-Json -Depth 100 | Set-Content -Path $ConfigPath -Encoding UTF8

Write-Host "[aegis-openclaw] updated config: $ConfigPath"
Write-Host "[aegis-openclaw] backup written: $backupPath"
Write-Host "[aegis-openclaw] plugin path: $pluginPath"
Write-Host "[aegis-openclaw] restart OpenClaw to load the plugin."
