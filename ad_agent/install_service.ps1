#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Tryzens AD Agent as a Windows service using NSSM.
.NOTES
    Run once from the ad_agent folder:
    powershell -ExecutionPolicy Bypass -File install_service.ps1
#>

param(
    [string]$AgentPath   = $PSScriptRoot,
    [string]$ServiceName = "TryzensADAgent",
    [string]$NssmDir     = "C:\tools"
)

$NssmExe = "$NssmDir\nssm.exe"
$PythonExe = (Get-Command python.exe -ErrorAction Stop).Source

# ── Download NSSM if missing ─────────────────────────────────────────────────
if (-not (Test-Path $NssmExe)) {
    Write-Host "Downloading NSSM..."
    New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
    $zip = "$env:TEMP\nssm.zip"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath "$env:TEMP\nssm_extracted" -Force
    Copy-Item "$env:TEMP\nssm_extracted\nssm-2.24\win64\nssm.exe" -Destination $NssmExe -Force
    Write-Host "NSSM installed at $NssmExe"
}

# ── Remove existing service if present ──────────────────────────────────────
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Removing existing service..."
    & $NssmExe stop $ServiceName
    & $NssmExe remove $ServiceName confirm
}

# ── Create logs folder ───────────────────────────────────────────────────────
$logsDir = "$AgentPath\logs"
New-Item -ItemType Directory -Force -Path $logsDir | Out-Null

# ── Install service ──────────────────────────────────────────────────────────
Write-Host "Installing service $ServiceName..."
& $NssmExe install $ServiceName $PythonExe "$AgentPath\app.py"
& $NssmExe set $ServiceName AppDirectory      $AgentPath
& $NssmExe set $ServiceName DisplayName       "Tryzens AD Agent"
& $NssmExe set $ServiceName Description       "On-premises AD API for Tryzens User Management App"
& $NssmExe set $ServiceName Start             SERVICE_AUTO_START
& $NssmExe set $ServiceName AppStdout         "$logsDir\stdout.log"
& $NssmExe set $ServiceName AppStderr         "$logsDir\stderr.log"
& $NssmExe set $ServiceName AppRotateFiles    1
& $NssmExe set $ServiceName AppRotateOnline   1
& $NssmExe set $ServiceName AppRotateBytes    5242880   # 5 MB

# ── Add Windows Firewall rule ────────────────────────────────────────────────
$port = (Get-Content "$AgentPath\.env" -ErrorAction SilentlyContinue |
         Select-String "AGENT_PORT=(\d+)").Matches.Groups[1].Value
if (-not $port) { $port = "5001" }

$ruleName = "Tryzens AD Agent port $port"
Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName $ruleName `
    -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null
Write-Host "Firewall rule added for port $port"

# ── Start service ────────────────────────────────────────────────────────────
& $NssmExe start $ServiceName
Write-Host ""
Write-Host "Done. Service '$ServiceName' is running."
Write-Host "Health check: http://localhost:$port/health"
