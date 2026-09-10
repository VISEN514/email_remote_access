# Registers the daily phrase-rotation popup in Task Scheduler (PLAN.md
# section 4): fixed 6am start (configurable below), "run as soon as
# possible after a missed start" enabled, "run only when user is logged
# on" -- same trust boundary as scripts/reset_phrase.py. Run this ONCE by
# hand, as the owning user (not elevated/SYSTEM).

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonExe = (Get-Command python).Source
$ScriptPath = Join-Path $ProjectRoot "src\popup_app.py"
$TaskName = "EmailRemoteAccess-DailyPhrasePopup"
$StartTime = "06:00"

$action = New-ScheduledTaskAction -Execute $PythonExe -Argument "`"$ScriptPath`"" -WorkingDirectory $ProjectRoot
$trigger = New-ScheduledTaskTrigger -Daily -At $StartTime
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force

Write-Host "Registered '$TaskName': daily at $StartTime, catch-up on missed start, runs only when logged on."
Write-Host "To re-run manually anytime: python `"$ScriptPath`""
