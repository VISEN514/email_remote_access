# Installs the watcher/broker as an auto-starting Windows service using NSSM,
# running as the INTERACTIVE OWNING USER (not LocalSystem -- see PLAN.md
# credential storage section for why). Run elevated after:
#   1. python -m venv .venv ; .venv\Scripts\pip install -r requirements.txt
#   2. config.yaml filled in, secrets/token.json exists (ran authorize_gmail.py)
#   3. nssm.exe on PATH
#
# NOTE: this installs the watcher/broker only. TightVNC's own Windows
# service is installed separately by TightVNC's own installer, runs as
# LocalSystem, and is NOT wrapped by NSSM -- its restart-on-failure is
# configured via the Service Control Manager's own recovery actions
# (Services MMC -> TightVNC Server -> Recovery tab), not by this script.

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonExe = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$MainScript = Join-Path $ProjectRoot "src\main.py"
$ServiceName = "EmailRemoteAccessWatcher"

if (-not (Test-Path $PythonExe)) {
    throw "Virtualenv python not found at $PythonExe. Run: python -m venv .venv; .venv\Scripts\pip install -r requirements.txt"
}

nssm install $ServiceName $PythonExe $MainScript
nssm set $ServiceName AppDirectory $ProjectRoot
nssm set $ServiceName Start SERVICE_AUTO_START
nssm set $ServiceName AppStdout (Join-Path $ProjectRoot "state\service.log")
nssm set $ServiceName AppStderr (Join-Path $ProjectRoot "state\service.log")
nssm set $ServiceName AppExit Default Restart

Write-Host "Service '$ServiceName' installed."
Write-Host "Run 'nssm edit $ServiceName' to set the interactive account to run as, per PLAN.md."
Write-Host "Start it with: nssm start $ServiceName"
