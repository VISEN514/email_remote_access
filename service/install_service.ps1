# Installs the watcher/broker as an auto-starting Windows service using NSSM,
# running as the INTERACTIVE OWNING USER (not LocalSystem -- see PLAN.md
# credential storage section for why). Run elevated after:
#   1. python -m venv .venv ; .venv\Scripts\pip install -r requirements.txt
#   2. config.yaml filled in, secrets/token.json exists (ran authorize_gmail.py)
#
# Uses the NSSM binary bundled at service/bin/nssm.exe -- falls back to PATH
# if that's not present, so this still works if nssm is installed globally.
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
$BundledNssm = Join-Path $PSScriptRoot "bin\nssm.exe"

if (-not (Test-Path $PythonExe)) {
    throw "Virtualenv python not found at $PythonExe. Run: python -m venv .venv; .venv\Scripts\pip install -r requirements.txt"
}

$Nssm = if (Test-Path $BundledNssm) { $BundledNssm } else { "nssm" }

& $Nssm install $ServiceName $PythonExe $MainScript
& $Nssm set $ServiceName AppDirectory $ProjectRoot
& $Nssm set $ServiceName Start SERVICE_AUTO_START
& $Nssm set $ServiceName AppStdout (Join-Path $ProjectRoot "state\service.log")
& $Nssm set $ServiceName AppStderr (Join-Path $ProjectRoot "state\service.log")
& $Nssm set $ServiceName AppExit Default Restart

Write-Host "Service '$ServiceName' installed (using $Nssm)."
Write-Host "Run '$Nssm edit $ServiceName' to set the interactive account to run as, per PLAN.md."
Write-Host "Start it with: $Nssm start $ServiceName"
