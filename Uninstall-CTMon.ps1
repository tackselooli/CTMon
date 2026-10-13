<#
.SYNOPSIS
    Uninstall-CTMon - Remove CTMon scheduled task, background instance and files.

.DESCRIPTION
    Stops any running CTMon instance, removes the Windows Scheduled Task (if
    registered) and deletes the installation directory and state files.

.PARAMETER InstallDir
    Installation directory to remove. Default: $HOME\CTMon

.PARAMETER KeepConfig
    Keep ~/.config/ctmon (config, seen-history, logs) - only remove program files.

.EXAMPLE
    .\Uninstall-CTMon.ps1
    Full uninstall.

.EXAMPLE
    .\Uninstall-CTMon.ps1 -KeepConfig
    Remove the program but keep your config and history.
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [switch]$KeepConfig
)

$ErrorActionPreference = 'Continue'

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $HOME 'CTMon'
}

$stateDir = Join-Path $HOME '.config/ctmon'
$mainScript = Join-Path $InstallDir 'CTMon.ps1'

Write-Host ''
Write-Host ' CTMon uninstaller' -ForegroundColor Yellow
Write-Host ' =================' -ForegroundColor Yellow

# 1) stop running instance
if (Test-Path $mainScript) {
    Write-Host '[..] stopping running instances'
    & $mainScript -Stop
} else {
    Write-Host '[..] no installation found at install dir'
}

# 2) remove scheduled task
if ((($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows) -and (Get-Command Unregister-ScheduledTask -ErrorAction SilentlyContinue)) {
    try {
        if (Get-ScheduledTask -TaskName 'CTMon' -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName 'CTMon' -Confirm:$false
            Write-Host '[ok] scheduled task removed' -ForegroundColor Green
        } else {
            Write-Host '[..] no scheduled task registered'
        }
    } catch {
        Write-Host ("[warn] could not remove scheduled task: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
} elseif (-not (($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows)) {
    Write-Host '[..] linux/macOS: remember to disable the systemd unit (systemctl --user disable --now ctmon) or remove the crontab line'
}

# 3) remove program files (NOTE: .env inside contains secrets - it is removed with it)
if (Test-Path $InstallDir) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host ("[ok] removed {0} (including .env if present - secrets are gone)" -f $InstallDir) -ForegroundColor Green
}

# 4) remove state (config, seen-history, match history, dashboard, logs)
if (-not $KeepConfig) {
    if (Test-Path $stateDir) {
        Remove-Item -LiteralPath $stateDir -Recurse -Force
        Write-Host ("[ok] removed {0} (config, history, dashboard files, logs)" -f $stateDir) -ForegroundColor Green
    }
} else {
    Write-Host ("[..] kept state directory: {0}" -f $stateDir) -ForegroundColor DarkGray
}

Write-Host ''
Write-Host ' CTMon uninstalled.' -ForegroundColor Green
Write-Host ''
