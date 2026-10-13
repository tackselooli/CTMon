<#
.SYNOPSIS
    Install-CTMon - Install CTMon (Certificate Transparency monitor) on this machine.

.DESCRIPTION
    Copies the project files to an installation directory, creates the default
    configuration, and optionally:
      - registers the Windows Scheduled Task for 24/7 operation (survives reboots), or
      - prints the systemd / cron setup for Linux/macOS.

    Default install directory: "$HOME\CTMon" (Windows)  |  "$HOME/CTMon" (Linux/macOS)
    Default config location  : "$HOME\.config\ctmon\config.json"

.PARAMETER InstallDir
    Where to install. Default: $HOME\CTMon

.PARAMETER WithTask
    Also register the 24/7 scheduled task (Windows) or print systemd/cron setup (Linux).

.PARAMETER NoConfig
    Do not create/overwrite the default config file.

.EXAMPLE
    .\Install-CTMon.ps1
    Install to $HOME\CTMon and create the default config.

.EXAMPLE
    .\Install-CTMon.ps1 -WithTask
    Install AND set up 24/7 persistence (Scheduled Task / systemd instructions).
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [switch]$WithTask,
    [switch]$NoConfig
)

$ErrorActionPreference = 'Stop'

$sourceDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $HOME 'CTMon'
}

$isWindowsPS = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows

Write-Host ''
Write-Host ' CTMon installer' -ForegroundColor Green
Write-Host " ===============" -ForegroundColor Green
Write-Host (" source : {0}" -f $sourceDir)
Write-Host (" target : {0}" -f $InstallDir)
Write-Host ''

# ---- 1) copy project files ----
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Host "[ok] created install directory" -ForegroundColor Green
}

$filesToCopy = @('CTMon.ps1', 'config.sample.json', 'targets.sample.txt', 'README.md', '.env.example', 'LICENSE', '.gitignore')
foreach ($f in $filesToCopy) {
    $src = Join-Path $sourceDir $f
    if (Test-Path $src) {
        Copy-Item -LiteralPath $src -Destination (Join-Path $InstallDir $f) -Force
        Write-Host ("[ok] installed {0}" -f $f) -ForegroundColor Green
    }
}
$linuxDir = Join-Path $sourceDir 'linux'
if (Test-Path $linuxDir) {
    $dstLinux = Join-Path $InstallDir 'linux'
    if (-not (Test-Path $dstLinux)) { New-Item -ItemType Directory -Path $dstLinux -Force | Out-Null }
    Copy-Item -Path (Join-Path $linuxDir '*') -Destination $dstLinux -Force
    Write-Host '[ok] installed linux/ service templates' -ForegroundColor Green
}

# ---- 2) default config ----
if (-not $NoConfig) {
    $stateDir = Join-Path $HOME '.config/ctmon'
    $cfgPath  = Join-Path $stateDir 'config.json'
    if (-not (Test-Path $cfgPath)) {
        if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
        $sample = Join-Path $InstallDir 'config.sample.json'
        if (Test-Path $sample) {
            Copy-Item -LiteralPath $sample -Destination $cfgPath -Force
            Write-Host ("[ok] config created: {0}" -f $cfgPath) -ForegroundColor Green
        }
    } else {
        Write-Host ("[ok] config already exists: {0}" -f $cfgPath) -ForegroundColor DarkGray
    }
}

# ---- 2b) secrets template hint ----
Write-Host ''
Write-Host '[..] secrets: copy .env.example to .env and add your Telegram bot token' -ForegroundColor Cyan
Write-Host ("     (or run: {0} -Setup  -  the wizard writes .env for you)" -f (Join-Path $InstallDir 'CTMon.ps1'))

# ---- 3) sanity check: run built-in self tests ----
Write-Host ''
Write-Host ' running built-in self tests...' -ForegroundColor Cyan
$mainScript = Join-Path $InstallDir 'CTMon.ps1'
try {
    & $mainScript -SelfTest
} catch {
    Write-Host "[warn] self test could not run: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---- 4) optional 24/7 persistence ----
if ($WithTask) {
    Write-Host ''
    & $mainScript -InstallTask
}

# ---- done ----
Write-Host ''
Write-Host ' installation complete!' -ForegroundColor Green
Write-Host ''
Write-Host ' next steps:' -ForegroundColor Yellow
Write-Host ("   1. {0} -Setup        # telegram bot token (.env) / chat id / targets" -f $mainScript)
Write-Host ("   2. {0} -TestAlert    # verify telegram delivery" -f $mainScript)
Write-Host ("   3. {0} -Target example.com          # run in foreground" -f $mainScript)
Write-Host ("   4. {0} -Background                  # or run detached 24/7" -f $mainScript)
Write-Host ("   5. {0} -ServeBg                     # dark-mode dashboard: http://127.0.0.1:8080/" -f $mainScript)
if ($isWindowsPS) {
    Write-Host ("   6. {0} -InstallTask                 # survive reboots" -f $mainScript)
} else {
    Write-Host '   6. see linux/ folder for systemd + cron templates   # survive reboots'
}
Write-Host ''
