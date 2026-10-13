<#
.SYNOPSIS
    CTMon - Monitor Bug Bounty Targets in Real Time Using Certificate Transparency logs.

.DESCRIPTION
    CTMon is a native-PowerShell remake of the "crtmon" tool (coffinxp) described in the
    InfoSec Write-ups article "Monitor Bug Bounty Targets in Real Time Using Certificate
    Transparency Logs". It watches the public Certificate Transparency feed in real time,
    extracts newly issued subdomains, matches them against your target list (and optional
    keywords), and sends instant notifications. It can also poll the crt.sh database as an
    alternative / fallback data source.

    Features (v2 - dashboard edition):
      - Real-time CT feed via WebSocket (certstream) with automatic reconnect + backoff
      - Optional crt.sh polling mode (lighter, ~1-5 min delay, survives blocked WSS)
      - HTML dark-mode DASHBOARD: built-in live web server (-Serve / -ServeBg) or a
        self-contained static snapshot file - no dependencies, no CDN, no admin rights
      - Secrets in a .env file (TELEGRAM_BOT_TOKEN etc.) instead of config.json
      - DNS enrichment: new subdomains are resolved to IPs (Sublert-style) with caching
      - Telegram bot notifications (grouped "target [N]" alerts, 4096-char safe chunks)
        plus optional Discord webhook and generic JSON webhook channels
      - Multiple targets: single domain, targets file, stdin pipeline, or config file
      - Keyword surveillance (alert when a brand keyword appears in ANY new certificate)
      - Built-in suspicious/phishing keyword heuristics (optional, inspired by
        chris408/certstream-suspicious)
      - Persistent match history with -Export (csv/json), -Summary and -Prune
      - v2.2 NET BYPASS: when crt.sh is unreachable (VPN off / ISP block) it
        automatically retries via proxy, then via DNS-over-HTTPS + curl --resolve,
        then fails over to the Cert Spotter CT API - every detour shows up in the
        dashboard event log
      - v2.2 risk scoring per match (wildcard / keyword / suspicious terms /
        unresolved DNS / deep subdomain) with severity badges everywhere
      - v2.2 slack + ntfy notification channels, Prometheus /api/metrics endpoint,
        and a weekly "top new assets" digest
      - Session + persistent seen-history so restarts never re-alert old subdomains
      - Daily rotating log files, live stats, session summary, periodic heartbeat
      - Reliable lifecycle: idempotent starts, stale-PID detection, health checks, automatic dashboard port fallback
      - One-command startup: -Background -ServeBg starts the monitor and dashboard
      - Diagnostics: -Doctor checks runtime, config, targets, state directory and dashboard health
      - 24/7 helpers: -Background, -Stop, -Status, -InstallTask / -UninstallTask
      - Works on Windows PowerShell 5.1+ and PowerShell 7+ (Windows/Linux/macOS)

.PARAMETER Target
    What to monitor. Accepts:
      - a single domain            : -Target example.com
      - several comma-separated    : -Target example.com,foo.dev
      - a PowerShell array         : -Target (Get-Content targets.txt)
      - a path to a targets file   : -Target C:\scopes\targets.txt   (one domain per line)
      - native stdin marker        : -Target -   (from cmd/bash:  cat targets.txt | pwsh -File CTMon.ps1 -Target -)
    If omitted, targets are read from the "targets" array in the config file.

.PARAMETER ConfigPath
    Path to the JSON configuration file. Default: ~/.config/ctmon/config.json

.PARAMETER Notify
    Notification channel: 'telegram', 'discord', 'webhook' or 'none'.
    Default is taken from config ('telegram'). Discord needs discord_webhook_url,
    webhook needs webhook_url (both can live in .env).

.PARAMETER Source
    Data source: 'certstream' (real-time WebSocket) or 'crtsh' (HTTP polling). Default from config.

.PARAMETER Setup
    Interactive first-run wizard: asks for Telegram bot token, chat id and targets.
    Secrets are stored in a .env file by default (recommended) or config.json.

.PARAMETER TestAlert
    Send a test message through the configured notification channel and exit.

.PARAMETER Background
    Start CTMon as a detached, hidden background process (PowerShell equivalent of
    "nohup crtmon ... &"). All other arguments are passed through to the child process.

.PARAMETER Stop
    Stop any running CTMon background instance(s) (monitor AND dashboard server) and exit.

.PARAMETER Status
    Show whether CTMon is running, its PID, live statistics, last log lines,
    dashboard server state and whether the scheduled task is installed.

.PARAMETER Serve
    Run the built-in HTTP dashboard server in the foreground (Ctrl+C to stop).
    Serves the dark-mode dashboard at http://127.0.0.1:<port>/ plus /api/data
    and /api/health endpoints. Works with or without a monitor instance running.

.PARAMETER ServeBg
    Start the dashboard server as a detached background process. Repeated calls reuse a healthy server.
    If the configured/default port is busy, CTMon tries the next 20 ports automatically.

.PARAMETER Doctor
    Run offline diagnostics for config, targets, writable state directory, PID files and dashboard health.

.PARAMETER Port
    TCP port for the dashboard server. Default: env DASHBOARD_PORT, config
    dashboard_port, or 8080. If implicit and busy, CTMon tries the next 20 ports.

.PARAMETER Bind
    IP address the dashboard server binds to. Default: 127.0.0.1 (localhost only -
    change consciously, the feed contains recon data).

.PARAMETER Dashboard
    Refresh the static dashboard files (dashboard.html + dashboard-data.json in
    ~/.config/ctmon) and open dashboard.html in the default browser. The static
    page shows the latest snapshot; use -ServeBg for the live view.

.PARAMETER Export
    Export the match history to CSV or JSON and exit. See -Format, -Days, -OutFile.

.PARAMETER Summary
    Print a match-history report (per-target, per-hour, DNS ratio) and exit.

.PARAMETER Prune
    Housekeeping: trim match history and delete old log files. See -Days.

.PARAMETER Digest
    Build and send the weekly digest (per-target recap of new assets from the match
    history) right now through the configured channel. Combine with -Days N and
    -Notify <channel>. With notify = none it prints to the console instead.

.PARAMETER WindowMinutes
    Polling sources (crtsh / certspotter) only report certificates issued within this
    many minutes (default: crtsh_window_minutes config = 1440 = last 24 h). Override for
    a one-time BACKFILL, e.g. -WindowMinutes 43200 reports everything from the last 30 days
    so you can verify matching works. The seen-history then keeps those from re-alerting.

.PARAMETER Format
    Export format for -Export: 'csv' or 'json'. Default: csv.

.PARAMETER Days
    -Export: export the last N days (default 30). -Summary: report window (default 7).
    -Prune: retention window (default 90).

.PARAMETER OutFile
    Destination file for -Export. Default: .\ctmon-matches-<timestamp>.<ext>

.PARAMETER InstallTask
    Register a Scheduled Task (Windows, runs at logon, hidden, no time limit) so CTMon
    survives reboots - the equivalent of the article's "@reboot" cron job.
    On Linux/macOS it prints a ready-to-use systemd unit + crontab line instead.

.PARAMETER UninstallTask
    Remove the CTMon scheduled task (Windows) and exit.

.PARAMETER Version
    Print the CTMon version and exit.

.PARAMETER SelfTest
    Run the built-in self-test suite (parsing, matching, escaping, chunking, config,
    seen-store, .env loader, DNS cache, dashboard builders, payloads, export) and exit.
    Exit code 0 = all tests passed.

.PARAMETER MaxRuntimeSeconds
    Developer/testing helper: automatically stop the monitor or server after N seconds (0 = run forever).

.PARAMETER DryRun
    Detect matches and print them to console/log, but do NOT send notifications.

.EXAMPLE
    ./CTMon.ps1 -Target example.com
    Monitor one domain using config defaults, alerts to Telegram.

.EXAMPLE
    ./CTMon.ps1 -Target targets.txt -Source crtsh
    Monitor every domain listed in targets.txt using the crt.sh polling source.

.EXAMPLE
    Get-Content targets.txt | pwsh -NoProfile -File ./CTMon.ps1 -Target -
    Same as "cat targets.txt | crtmon -target -" from the original article.
    (Native stdin redirection is required; PowerShell-to-script pipelines cannot
    deliver input to advanced scripts - use -Target (Get-Content targets.txt) instead.)

.EXAMPLE
    ./CTMon.ps1 -Target (Get-Content targets.txt)
    PowerShell-native way to feed a whole list file.

.EXAMPLE
    ./CTMon.ps1 -Setup
    First-run wizard (writes .env with your Telegram bot token + chat id).

.EXAMPLE
    ./CTMon.ps1 -Target example.com -Background -ServeBg
    Start monitoring and the dark-mode dashboard together, both detached.

.EXAMPLE
    ./CTMon.ps1 -Target example.com -Background
    ./CTMon.ps1 -ServeBg
    Start the monitor and dashboard separately:
    open http://127.0.0.1:8080/ in your browser.

.EXAMPLE
    ./CTMon.ps1 -Status
    ./CTMon.ps1 -Stop
    Check on / stop the background instances.

.EXAMPLE
    ./CTMon.ps1 -Export -Format csv -Days 30
    ./CTMon.ps1 -Summary
    Export / report the match history.

.NOTES
    Project    : CTMon 2.2.0
    Inspired by: coffinxp/crtmon, trickest/ctFESS, d-Rickyy-b/certstream-monitoring,
                 chris408/certstream-suspicious, jonaslejon/ct-monitor (DNS resolve),
                 yassineaboukir/Sublert (working-subdomain checks),
                 ProtonMail/ct-monitor (history persistence), Calidog certstream feed
    Disclaimer : For educational and authorized security research only. Always ensure you
                 have proper authorization before conducting security assessments.
#>
[CmdletBinding()]
param(
    [string[]]$Target,
    [string]$ConfigPath,
    [ValidateSet('telegram', 'discord', 'slack', 'ntfy', 'webhook', 'none')]
    [string]$Notify,
    [ValidateSet('certstream', 'crtsh', 'certspotter')]
    [string]$Source,
    [switch]$Setup,
    [switch]$TestAlert,
    [switch]$Background,
    [switch]$Stop,
    [switch]$Status,
    [switch]$Doctor,
    [switch]$Serve,
    [switch]$ServeBg,
    [switch]$Dashboard,
    [switch]$Export,
    [switch]$Summary,
    [switch]$Digest,
    [int]$WindowMinutes = 0,
    [switch]$Prune,
    [ValidateSet('csv', 'json')]
    [string]$Format = 'csv',
    [int]$Days = 0,
    [string]$OutFile,
    [int]$Port = 0,
    [string]$Bind = '127.0.0.1',
    [switch]$AutoPortFallback,
    [switch]$InstallTask,
    [switch]$UninstallTask,
    [switch]$Version,
    [switch]$Help,
    [switch]$SelfTest,
    [int]$MaxRuntimeSeconds = 0,
    [switch]$DryRun
)

# ============================================================================
#  CTMon - Certificate Transparency monitor for bug bounty hunters
#  Compatible with Windows PowerShell 5.1 and PowerShell 7+ (no PS7-only syntax)
# ============================================================================

$Script:CTMonVersion = '2.2.3'
$Script:ScriptPath   = $PSCommandPath
$Script:IsWindowsPS  = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows

# ---- Paths (mirrors crtmon's ~/.config/crtmon/provider.yaml convention) ----
$Script:StateDir      = Join-Path $HOME '.config/ctmon'
$Script:DefaultConfigPath = Join-Path $Script:StateDir 'config.json'
$Script:PidPath       = Join-Path $Script:StateDir 'ctmon.pid'
$Script:ServePidPath  = Join-Path $Script:StateDir 'ctmon-serve.pid'
$Script:StatePath     = Join-Path $Script:StateDir 'state.json'
$Script:SeenPath      = Join-Path $Script:StateDir 'seen.json'
$Script:MatchesPath   = Join-Path $Script:StateDir 'matches.jsonl'
$Script:DnsCachePath  = Join-Path $Script:StateDir 'dns-cache.json'
$Script:DashDataPath  = Join-Path $Script:StateDir 'dashboard-data.json'
$Script:DashHtmlPath  = Join-Path $Script:StateDir 'dashboard.html'
$Script:LogDir        = Join-Path $Script:StateDir 'logs'

# ---- Emoji via code points (encoding-proof on Windows PowerShell 5.1) ----
function Use-Emoji {
    param([int]$CodePoint)
    return [char]::ConvertFromUtf32($CodePoint)
}
$Script:EmojiRocket   = Use-Emoji 0x1F680   # rocket
$Script:EmojiSat      = Use-Emoji 0x1F6F0   # satellite
$Script:EmojiNew      = Use-Emoji 0x1F195   # NEW
$Script:EmojiGreen    = Use-Emoji 0x2705    # check mark
$Script:EmojiWarn     = Use-Emoji 0x26A0    # warning
$Script:EmojiStat     = Use-Emoji 0x1F4CA   # bar chart
$Script:EmojiGlobe    = Use-Emoji 0x1F310   # globe (dns)

# ============================================================================
#  LOGGING
# ============================================================================
$Script:LogFile  = $null
$Script:LogLevel = 'INFO'   # DEBUG | INFO | WARN | ERROR
$Script:NoColor  = $false
$Script:CtCertspotterToken = ''   # resolved from env/config in main
$Script:MetricsEnabled = $true    # GET /api/metrics on the dashboard server
$Script:DigestLastUtc = $null     # last weekly-digest send (ISO)
$Script:CtRuntimeConfig = $null   # config reference for dashboard net info

function Write-CtLog {
    <# Central logger: colored console output + optional rotating-file output.
       Also feeds the dashboard event buffer when one is active. #>
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('DEBUG', 'INFO', 'OK', 'WARN', 'ERROR', 'MATCH')][string]$Level = 'INFO'
    )

    $order = @{ 'DEBUG' = 0; 'INFO' = 1; 'OK' = 2; 'WARN' = 3; 'ERROR' = 4; 'MATCH' = 1 }
    if (($order[$Level] -lt $order[$Script:LogLevel]) -and ($Level -ne 'MATCH')) { return }

    $ts = (Get-Date).ToString('HH:mm:ss')

    if (-not $Script:NoColor) {
        switch ($Level) {
            'DEBUG' { $color = 'DarkGray' }
            'INFO'  { $color = 'Cyan' }
            'OK'    { $color = 'Green' }
            'WARN'  { $color = 'Yellow' }
            'ERROR' { $color = 'Red' }
            default { $color = 'Magenta' }
        }
        Write-Host $ts -ForegroundColor DarkGray -NoNewline
        Write-Host " $Level" -ForegroundColor $color -NoNewline
        Write-Host " $Message"
    }
    else {
        Write-Host "$ts $Level $Message"
    }

    # Mirror to rotating daily log file
    if ($Script:LogFile) {
        try {
            $logParent = Split-Path $Script:LogFile -Parent
            if (-not (Test-Path $logParent)) {
                New-Item -ItemType Directory -Path $logParent -Force | Out-Null
            }
            $stamp = (Get-Date).ToString('yyyy-MM-dd ') + $ts
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::AppendAllText($Script:LogFile, "$stamp $Level $Message$([Environment]::NewLine)", $utf8)
        } catch { }
    }

    # Feed the dashboard event buffer (WARN/ERROR/OK/MATCH are dashboard-worthy)
    if ($null -ne $Script:DashEvents) {
        if (($Level -eq 'WARN') -or ($Level -eq 'ERROR') -or ($Level -eq 'MATCH') -or ($Level -eq 'OK')) {
            Add-CtDashEvent -Level $Level -Message $Message
        }
    }
}

function Show-CtBanner {
    <# CRTMON-style ASCII banner (v2.2): three-tone block letters, feature tagline,
       plain-ASCII fallback for consoles that cannot render the block glyphs. #>
    $glyphs = @{
        'C' = @('░█▀▀░', '░█░░░', '░▀▀▀░')
        'T' = @('░▀█▀░', '░░█░░', '░░▀░░')
        'M' = @('░█▄█░', '░█░█░', '░▀░▀░')
        'O' = @('░█▀█░', '░█░█░', '░▀▀▀░')
        'N' = @('░█▀█░', '░█░█░', '░▀░▀░')
    }
    $okUnicode = $false
    try {
        # Verify the console can round-trip the block glyph we need
        $probe = [string][char]0x2591
        if ($probe.Length -eq 1) { $okUnicode = $true }
    } catch { $okUnicode = $false }

    if ($okUnicode) {
        $letters = @('C', 'T', 'M', 'O', 'N')
        $rowColors = @('Cyan', 'Green', 'DarkGreen')
        for ($r = 0; $r -lt 3; $r++) {
            $row = ''
            foreach ($l in $letters) { $row += $glyphs[$l][$r] }
            Write-Host $row -ForegroundColor $rowColors[$r]
        }
    }
    else {
        Write-Host '======== CTMON ========' -ForegroundColor Green
    }
    Write-Host " monitor your targets, hunt fresh assets in real time!" -ForegroundColor Green
    Write-Host " ── v$Script:CTMonVersion ── certstream · crt.sh · certspotter ── bypass: proxy · doh ──" -ForegroundColor Cyan
    Write-Host " alerts: telegram · discord · slack · ntfy · webhook  |  dashboard: -ServeBg" -ForegroundColor DarkGray
    Write-Host ''
}


# ============================================================================
#  CONFIGURATION (JSON - zero external dependencies, unlike the YAML original)
# ============================================================================
function New-CtDefaultConfig {
    <# Default configuration object. Keys mirror crtmon's provider.yaml where sensible.
       v2.2 adds: net bypass (proxy/DoH), certspotter token, slack/ntfy channels,
       Prometheus metrics and the weekly digest. #>
    return [pscustomobject]@{
        telegram_bot_token    = ''
        telegram_chat_id      = ''
        targets               = @()
        keywords              = @()
        notify                = 'telegram'
        source                = 'certstream'
        certstream_urls       = @('wss://certstream.calidog.io/', 'wss://certstream.cert.ee/')
        telegram_api_base     = 'https://api.telegram.org'
        discord_webhook_url   = ''
        webhook_url           = ''
        slack_webhook_url     = ''
        ntfy_topic            = ''
        ntfy_server           = 'https://ntfy.sh'
        include_wildcards     = $true
        exclude_regex         = @()
        flush_interval_seconds = 10
        batch_max_domains     = 10
        remember_seen         = $true
        seen_max_entries      = 50000
        enrich_dns            = $true
        dns_timeout_ms        = 2500
        matches_history_max   = 20000
        dashboard_enabled     = $true
        dashboard_port        = 8080
        dashboard_bind        = '127.0.0.1'
        crtsh_base_url        = 'https://crt.sh'
        crtsh_interval_seconds = 300
        crtsh_window_minutes  = 1440
        certstream_silent_timeout_seconds = 90
        certstream_fallback_minutes = 10  # auto-switch to crt.sh polling after N min with no feed data (0 = off)
        heartbeat_hours       = 6
        # ---- v2.2: network bypass ----
        net_proxy             = ''          # or env HTTPS_PROXY / ALL_PROXY (http/https/socks5)
        net_bypass            = $true       # master switch for the failover chain
        doh_enabled           = $true       # DNS-over-HTTPS fallback (defeats DNS blocking)
        doh_provider          = 'cloudflare' # cloudflare | google | auto
        certspotter_token     = ''          # optional; env CERTSPOTTER_TOKEN wins
        # ---- v2.2: metrics + digest ----
        metrics_enabled       = $true       # expose GET /api/metrics (Prometheus)
        digest_enabled        = $true       # weekly "top new assets" recap
        digest_weekday        = 'Monday'
        digest_hour           = 9           # local hour (0-23)
        digest_days           = 7           # digest window
        log_to_file           = $true
        log_level             = 'INFO'
        stats_summary         = $true
    }
}

function Save-CtConfig {
    param([Parameter(Mandatory = $true)][pscustomobject]$Config, [Parameter(Mandatory = $true)][string]$Path)

    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $json = $Config | ConvertTo-Json -Depth 6
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8)
}

function Get-CtConfig {
    <# Load config; create a default one on first run (like crtmon's first-run provider.yaml). #>
    param([string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { $Path = $Script:DefaultConfigPath }

    if (-not (Test-Path $Path)) {
        $def = New-CtDefaultConfig
        Save-CtConfig -Config $def -Path $Path
        Write-CtLog "created default configuration file: $Path" -Level INFO
        Write-CtLog "edit it (or run with -Setup) to add your Telegram bot token, chat id and targets" -Level INFO
        return $def
    }

    try {
        $raw  = [System.IO.File]::ReadAllText($Path)
        $json = $raw | ConvertFrom-Json
    } catch {
        Write-CtLog "configuration file is not valid JSON: $Path ($($_.Exception.Message))" -Level ERROR
        throw
    }

    # Merge any missing keys from defaults (forward compatible)
    $def = New-CtDefaultConfig
    $out = $def
    foreach ($p in $json.PSObject.Properties) {
        if ($null -ne $p.Value) {
            $out | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value -Force
        }
    }
    return $out
}

# ============================================================================
#  .ENV SECRETS FILE  (TELEGRAM_BOT_TOKEN etc. - keeps secrets out of config.json)
#  Resolution order: process environment > script-dir .env > state-dir .env > config.json
# ============================================================================
function Get-CtEnvLocations {
    <# Candidate .env file locations, highest priority first.
       Returns a plain array (callers wrap with @() as needed). #>
    $list = @()
    try {
        $scriptDir = Split-Path $Script:ScriptPath -Parent
        if ($scriptDir) { $list += (Join-Path $scriptDir '.env') }
    } catch { }
    $list += (Join-Path $Script:StateDir '.env')
    return $list
}

function Read-CtEnvFile {
    <# Minimal .env parser: KEY=VALUE, # comments, blank lines, optional 'export ',
       optional single/double quotes, CRLF-safe. Returns a hashtable. #>
    param([string]$Path)

    $result = @{}
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return $result }
    try {
        $lines = [System.IO.File]::ReadAllLines($Path)
        foreach ($line in $lines) {
            $l = $line.Trim()
            if ($l -eq '' -or $l.StartsWith('#')) { continue }
            if ($l.StartsWith('export ')) { $l = $l.Substring(7).TrimStart() }
            $idx = $l.IndexOf('=')
            if ($idx -lt 1) { continue }
            $key = $l.Substring(0, $idx).Trim()
            $val = $l.Substring($idx + 1).Trim()
            if ($val.Length -ge 2 -and ((($val.StartsWith('"')) -and ($val.EndsWith('"'))) -or (($val.StartsWith("'")) -and ($val.EndsWith("'"))))) {
                $val = $val.Substring(1, $val.Length - 2)
            }
            if ($key) { $result[$key] = $val }
        }
    } catch {
        Write-CtLog "could not read .env file ${Path}: $($_.Exception.Message)" -Level WARN
    }
    return $result
}

function Resolve-CtSecret {
    <# Resolve one secret (e.g. TELEGRAM_BOT_TOKEN) from process env, .env files, or the
       config fallback. Returns @{ Value; Source } so the UI can show where it came from.
       $Paths is overridable for the self-test suite. #>
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [string]$CurrentValue = '',
        [string[]]$Paths = @()
    )

    # 1) process environment (highest priority)
    $v = $null
    try { $v = [Environment]::GetEnvironmentVariable($Key) } catch { }
    if (-not [string]::IsNullOrWhiteSpace("$v")) { return @{ Value = "$v"; Source = 'environment' } }

    # 2) .env files
    $candidates = $Paths
    if (-not $candidates -or $candidates.Count -eq 0) { $candidates = @(Get-CtEnvLocations) }
    foreach ($p in $candidates) {
        if ($p -and (Test-Path $p)) {
            $map = Read-CtEnvFile -Path $p
            if ($map.ContainsKey($Key) -and (-not [string]::IsNullOrWhiteSpace($map[$Key]))) {
                return @{ Value = $map[$Key]; Source = $p }
            }
        }
    }

    # 3) config.json value (legacy location)
    if (-not [string]::IsNullOrWhiteSpace("$CurrentValue")) { return @{ Value = "$CurrentValue"; Source = 'config' } }

    return @{ Value = ''; Source = 'none' }
}

function Save-CtEnvFile {
    <# Write/update a .env file. Preserves the values of keys not touched by $Values.
       The file is regenerated with a friendly header (comments elsewhere are not kept). #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Values,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $knownOrder = @('TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID', 'DISCORD_WEBHOOK_URL', 'GENERIC_WEBHOOK_URL', 'SLACK_WEBHOOK_URL', 'NTFY_TOPIC', 'NTFY_SERVER', 'CERTSPOTTER_TOKEN', 'HTTPS_PROXY', 'DASHBOARD_PORT')
    $comments = @{
        'TELEGRAM_BOT_TOKEN'   = '# Telegram bot token from @BotFather (e.g. 123456789:AAE_...)'
        'TELEGRAM_CHAT_ID'     = '# Numeric chat id (send /start to your bot, then check .../getUpdates)'
        'DISCORD_WEBHOOK_URL'  = '# Optional: Discord webhook url (used when notify = "discord")'
        'GENERIC_WEBHOOK_URL'  = '# Optional: generic JSON webhook url (used when notify = "webhook")'
        'SLACK_WEBHOOK_URL'    = '# Optional: Slack incoming webhook url (used when notify = "slack")'
        'NTFY_TOPIC'           = '# Optional: ntfy topic (used when notify = "ntfy", e.g. my-ctmon-alerts)'
        'NTFY_SERVER'          = '# Optional: ntfy server (default https://ntfy.sh; self-hosted allowed)'
        'CERTSPOTTER_TOKEN'    = '# Optional: certspotter.com api token (free tier works without one)'
        'HTTPS_PROXY'          = '# Optional: proxy for crt.sh/certspotter/DoH (http:// or socks5://)'
        'DASHBOARD_PORT'       = '# Optional: dashboard server port (same as -Port)'
    }
    $extraKeys = @()
    foreach ($k in $Values.Keys) { if ($knownOrder -notcontains $k) { $extraKeys += $k } }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('# CTMon secrets - loaded automatically. Resolution order:')
    [void]$sb.Append([Environment]::NewLine)
    [void]$sb.Append('#   process environment > .env (next to CTMon.ps1) > ~/.config/ctmon/.env > config.json')
    [void]$sb.Append([Environment]::NewLine)
    [void]$sb.Append([Environment]::NewLine)

    $existing = @{}
    if (Test-Path $Path) {
        $existing = Read-CtEnvFile -Path $Path
    }

    foreach ($k in $knownOrder) {
        $val = $null
        if ($Values.ContainsKey($k)) { $val = $Values[$k] }
        elseif ($existing.ContainsKey($k)) { $val = $existing[$k] }
        else { $val = '' }
        [void]$sb.Append($comments[$k]).Append([Environment]::NewLine)
        [void]$sb.Append($k).Append('=').Append($val).Append([Environment]::NewLine)
        [void]$sb.Append([Environment]::NewLine)
    }
    foreach ($k in $extraKeys) {
        [void]$sb.Append($k).Append('=').Append($Values[$k]).Append([Environment]::NewLine)
    }

    $dir = Split-Path $Path -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), $utf8)
}

function Invoke-CtSetup {
    <# Interactive first-run wizard (equivalent of crtmon prompting for the Discord webhook).
       v2: secrets go into a .env file by default so tokens stay out of config backups. #>
    param([string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { $Path = $Script:DefaultConfigPath }
    Show-CtBanner

    if (Test-Path $Path) {
        try { $cfg = Get-CtConfig -Path $Path } catch { $cfg = New-CtDefaultConfig }
        Write-CtLog "editing existing configuration: $Path" -Level INFO
    } else {
        $cfg = New-CtDefaultConfig
        Write-CtLog "creating new configuration: $Path" -Level INFO
    }

    Write-Host ''
    Write-Host '== Telegram bot setup ==' -ForegroundColor Yellow
    Write-Host ' 1) In Telegram, open @BotFather  ->  /newbot  ->  copy the HTTP API token'
    Write-Host ' 2) Send any message to your new bot (press START), then get your numeric chat id'
    Write-Host '    from:  https://api.telegram.org/bot<TOKEN>/getUpdates   ("chat":{"id":123456789})'
    Write-Host ''
    Write-Host ' Where should the token be stored?' -ForegroundColor Yellow
    Write-Host '   1) .env file (recommended - keeps secrets out of config backups)'
    Write-Host '   2) config.json (legacy)'
    $storeChoice = Read-Host 'Choice [1]'
    $useEnv = $true
    if ("$storeChoice".Trim() -eq '2') { $useEnv = $false }

    $tok = Read-Host 'Telegram bot token (blank = keep current)'
    $cid = Read-Host 'Telegram chat id (blank = keep current)'

    $envPath = $null
    if ($useEnv) {
        # prefer the project dir; fall back to the state dir when not writable
        $envPath = @(Get-CtEnvLocations)[0]
        $envParent = Split-Path $envPath -Parent
        try {
            if (-not (Test-Path $envParent)) { New-Item -ItemType Directory -Path $envParent -Force | Out-Null }
            $probe = Join-Path $envParent ('.ctmon-write-probe-{0}' -f (Get-Random))
            [System.IO.File]::WriteAllText($probe, 'x')
            Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        } catch {
            $envPath = Join-Path $Script:StateDir '.env'
            Write-CtLog "script directory not writable - .env will be created at $envPath" -Level WARN
        }
    }

    $envValues = @{}
    if (-not [string]::IsNullOrWhiteSpace($tok)) {
        if ($useEnv) { $envValues['TELEGRAM_BOT_TOKEN'] = $tok.Trim() }
        else { $cfg.telegram_bot_token = $tok.Trim() }
    }
    if (-not [string]::IsNullOrWhiteSpace($cid)) {
        if ($useEnv) { $envValues['TELEGRAM_CHAT_ID'] = $cid.Trim() }
        else { $cfg.telegram_chat_id = $cid.Trim() }
    }
    if ($useEnv -and $envValues.Count -gt 0 -and $envPath) {
        Save-CtEnvFile -Values $envValues -Path $envPath
        Write-CtLog "secrets saved to: $envPath" -Level OK
    }

    Write-Host ''
    Write-Host '== Targets ==' -ForegroundColor Yellow
    Write-Host ' Enter domains to monitor, separated by commas  (e.g. example.com,vercel.app)'
    $t = Read-Host 'Targets (blank = keep current)'
    if (-not [string]::IsNullOrWhiteSpace($t)) {
        $cfg.targets = @($t -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    }

    $kw = Read-Host 'Brand keywords to also watch in ALL new certificates (blank = none)'
    if (-not [string]::IsNullOrWhiteSpace($kw)) {
        $cfg.keywords = @($kw -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    }

    Save-CtConfig -Config $cfg -Path $Path
    Write-CtLog "configuration saved: $Path" -Level OK
    Write-CtLog "tip: run 'CTMon.ps1 -TestAlert' to verify Telegram delivery" -Level INFO
    Write-CtLog "tip: run 'CTMon.ps1 -ServeBg' and open http://127.0.0.1:8080/ for the dashboard" -Level INFO
}

# ============================================================================
#  TARGETS (single domain | file | stdin '-' | comma list) - like crtmon -target
# ============================================================================
function ConvertTo-CtNormalDomain {
    <# Normalize a user/feed domain: lowercase, strip scheme, wildcard, trailing dot, path. #>
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $d = $Value.Trim().ToLowerInvariant()

    # strip scheme
    $d = $d -replace '^[a-z][a-z0-9+.\-]*://', ''
    # strip userinfo, path, port
    $idx = $d.IndexOf('/')
    if ($idx -ge 0) { $d = $d.Substring(0, $idx) }
    $idx = $d.IndexOf('?')
    if ($idx -ge 0) { $d = $d.Substring(0, $idx) }
    $idx = $d.IndexOf('@')
    if ($idx -ge 0) { $d = $d.Substring($idx + 1) }
    $idx = $d.IndexOf(':')
    if ($idx -ge 0) { $d = $d.Substring(0, $idx) }
    # strip leading wildcard (crtmon-style "*.target" display entries)
    if ($d.StartsWith('*.')) { $d = $d.Substring(2) }
    elseif ($d.StartsWith('*')) { $d = $d.Substring(1) }
    # strip trailing dot (FQDN form)
    $d = $d.TrimEnd('.')

    if ($d -eq '') { return $null }
    # keep it conservative: letters/digits/hyphen/dot/underscore only
    if ($d -notmatch '^[a-z0-9._\-]+$') { return $null }
    # must contain at least one dot to be a domain (allow punycode/xn--)
    if ($d.IndexOf('.') -lt 0) { return $null }
    return $d
}

function Get-CtTempDir {
    <# Cross-platform temp directory (PS 5.1 / PS 7 / Windows / Linux / macOS). #>
    if ($env:TEMP)  { return $env:TEMP }
    if ($env:TMPDIR) { return $env:TMPDIR }
    if ($Script:IsWindowsPS) { return Join-Path $env:SystemRoot 'Temp' }
    return '/tmp'
}

function Resolve-CtTargets {
    <# Resolve the -Target argument (or config) into a clean, de-duplicated target list.
       $TargetValue may be: a single string ('domain', 'a.com,b.com', 'file.txt', '-')
       or a string array (-Target (Get-Content targets.txt) / comma list bound as array). #>
    param([object]$TargetValue, [object]$ConfigTargets)

    $found = @()
    $rawItems = @()
    if ($TargetValue) {
        if ($TargetValue -is [System.Array]) {
            $rawItems = @($TargetValue | ForEach-Object { "$_" })
        } else {
            $rawItems = @("$TargetValue")
        }
    }

    if ($rawItems.Count -gt 0) {
        $first = $rawItems[0].Trim()

        if (($rawItems.Count -eq 1) -and ($first -eq '-')) {
            # native stdin mode: cat targets.txt | pwsh -File CTMon.ps1 -Target -
            # (PowerShell-to-PowerShell pipelines cannot deliver data to advanced
            #  scripts - that misuse is detected and reported in the main dispatch)
            $lines = @()
            if ([Console]::IsInputRedirected) {
                Write-CtLog 'using targets from stdin' -Level INFO
                $lines = @(([Console]::In.ReadToEnd()) -split "`n")
                $lines = @($lines | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") })
            }
            if ($lines.Count -eq 0) {
                Write-CtLog "stdin mode requested ('-Target -') but no input was received." -Level ERROR
                Write-CtLog 'native stdin and PowerShell-to-script pipelines cannot deliver data to advanced scripts.' -Level ERROR
                Write-CtLog 'use one of these instead:' -Level ERROR
                Write-Host  '   cat targets.txt | pwsh -NoProfile -File ./CTMon.ps1 -Target -' -ForegroundColor Gray
                Write-Host  '   ./CTMon.ps1 -Target (Get-Content targets.txt)' -ForegroundColor Gray
                Write-Host  '   ./CTMon.ps1 -Target targets.txt' -ForegroundColor Gray
                return ,@()
            }
            $found = @($lines | ForEach-Object { ConvertTo-CtNormalDomain "$_" } | Where-Object { $_ })
        }
        elseif ($rawItems.Count -gt 1) {
            # array of values: -Target (Get-Content targets.txt) or -Target a.com,b.com
            Write-CtLog "using targets from cli array count=$($rawItems.Count)" -Level INFO
            $found = @($rawItems | ForEach-Object { $_ -split ',' } | ForEach-Object { ConvertTo-CtNormalDomain "$_" } | Where-Object { $_ })
        }
        else {
            # single string: file path or comma-separated domain list
            $isFile = $false
            if ($first -match '[\\/]') {
                $isFile = Test-Path -LiteralPath $first -PathType Leaf
            } elseif ($first -match '\.(txt|list|cfg|conf|csv)$') {
                $isFile = Test-Path -LiteralPath $first -PathType Leaf
            }
            if ($isFile) {
                Write-CtLog "using targets from file: $first" -Level INFO
                $lines = [System.IO.File]::ReadAllLines($first)
                $found = @($lines | ForEach-Object {
                    $l = $_.Trim()
                    if ($l -and -not $l.StartsWith('#')) { ConvertTo-CtNormalDomain $l } else { $null }
                } | Where-Object { $_ })
            }
            else {
                $found = @($first -split ',' | ForEach-Object { ConvertTo-CtNormalDomain "$_" } | Where-Object { $_ })
                Write-CtLog "using targets from cli flag count=$($found.Count)" -Level INFO
            }
        }
    }

    if ($found.Count -eq 0 -and $ConfigTargets) {
        $found = @($ConfigTargets | ForEach-Object { ConvertTo-CtNormalDomain "$_" } | Where-Object { $_ })
        if ($found.Count -gt 0) { Write-CtLog "loaded configuration targets=$($found.Count)" -Level INFO }
    }

    # de-duplicate, case-insensitive
    $seen = @{}
    $uniq = @()
    foreach ($d in $found) { if (-not $seen.ContainsKey($d)) { $seen[$d] = $true; $uniq += $d } }
    return ,$uniq
}

# ============================================================================
#  MATCHING ENGINE (suffix targets + keyword watch + exclude regex)
# ============================================================================
function Test-CtMatch {
    <#
        Decide whether a domain from the feed matches the user scope.
        Returns $null (no match) or [pscustomobject]@{ Target; Keyword }
          - Target  = matched target domain (suffix match), or $null
          - Keyword = matched keyword (watch list), or $null
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [AllowEmptyCollection()][string[]]$Targets,
        [AllowEmptyCollection()][string[]]$Keywords,
        [AllowEmptyCollection()][string[]]$ExcludeRegex,
        [bool]$IncludeWildcards = $true
    )

    $d = $Domain.ToLowerInvariant()

    # Wildcard SAN entries like "*.foo.example.com"
    if ($d.StartsWith('*.')) {
        if (-not $IncludeWildcards) { return $null }
        $bare = ConvertTo-CtNormalDomain $d
        if (-not $bare) { return $null }
        $d = $bare
    }

    # user exclusion regexes win over everything (invalid regex -> rule skipped)
    if ($ExcludeRegex) {
        foreach ($rx in $ExcludeRegex) {
            if ($rx) {
                try { if ($d -match $rx) { return $null } } catch { }
            }
        }
    }

    # 1) suffix match against targets (example.com matches www.example.com, a.b.example.com)
    if ($Targets) {
        foreach ($t in $Targets) {
            if ($d -eq $t -or $d.EndsWith(".$t")) {
                return [pscustomobject]@{ Target = $t; Keyword = $null }
            }
        }
    }

    # 2) keyword watch: brand keyword anywhere in a new certificate domain (ctFESS-style)
    if ($Keywords) {
        foreach ($k in $Keywords) {
            if ($k -and $d.Contains($k)) {
                return [pscustomobject]@{ Target = $null; Keyword = $k }
            }
        }
    }

    return $null
}

# ============================================================================
#  SEEN STORE (in-session de-dup + optional persistent history)
# ============================================================================
function New-CtSeenStore {
    param([bool]$Persist = $true, [string]$Path = $Script:SeenPath, [int]$MaxEntries = 50000)
    $store = [pscustomobject]@{
        Persist    = $Persist
        Path       = $Path
        MaxEntries = [Math]::Max(1000, $MaxEntries)
        Set        = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Dirty      = $false
    }
    if ($Persist -and $Path -and (Test-Path $Path)) {
        try {
            $raw = [System.IO.File]::ReadAllText($Path)
            $arr = $raw | ConvertFrom-Json
            if ($arr) {
                foreach ($e in @($arr)) { $null = $store.Set.Add("$e") }
                Write-CtLog "loaded seen-history entries=$($store.Set.Count)" -Level DEBUG
            }
        } catch {
            Write-CtLog "could not load seen-history file (starting fresh): $($_.Exception.Message)" -Level WARN
        }
    }
    return $store
}

function Test-CtSeen {
    <# Returns $true if the domain was already seen; otherwise records it and returns $false. #>
    param([Parameter(Mandatory = $true)][object]$Store, [Parameter(Mandatory = $true)][string]$Key)

    if ($Store.Set.Contains($Key)) { return $true }
    $null = $Store.Set.Add($Key)
    $Store.Dirty = $true

    # cap growth (keep the most recent half when over limit)
    if ($Store.Set.Count -gt $Store.MaxEntries) {
        $keep = [Math]::Floor($Store.MaxEntries / 2)
        $all = [System.Linq.Enumerable]::ToList($Store.Set)
        $keepArr = $all.GetRange($all.Count - $keep, $keep)
        $Store.Set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($e in $keepArr) { $null = $Store.Set.Add($e) }
    }
    return $false
}

function Save-CtSeen {
    param([Parameter(Mandatory = $true)][object]$Store)
    if (-not ($Store.Persist -and $Store.Dirty -and $Store.Path)) { return }
    try {
        $dir = Split-Path $Store.Path -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $arr = [System.Linq.Enumerable]::ToArray($Store.Set)
        $json = $arr | ConvertTo-Json -Depth 3 -Compress
        if ($arr.Count -le 1) { if ($arr.Count -eq 0) { $json = '[]' } else { $json = '["' + $arr[0] + '"]' } }
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Store.Path, $json, $utf8)
        $Store.Dirty = $false
    } catch {
        Write-CtLog "could not save seen-history: $($_.Exception.Message)" -Level WARN
    }
}

# ============================================================================
#  SMALL HELPERS (HTML escape, message chunking)
# ============================================================================
function ConvertTo-CtHtmlSafe {
    <# Minimal Telegram-HTML escaping ( &, <, > ). #>
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;')
}

function Split-CtChunk {
    <# Split a string into chunks of at most $Size characters, on line boundaries when possible. #>
    param([string]$Text, [int]$Size = 3800)

    $chunks = @()
    if ([string]::IsNullOrEmpty($Text)) { return ,$chunks }
    $rest = $Text
    while ($rest.Length -gt $Size) {
        $cut = $rest.LastIndexOf("`n", $Size)
        if ($cut -le 0) { $cut = $Size }
        $chunks += $rest.Substring(0, $cut)
        $rest = $rest.Substring($cut).TrimStart("`n")
    }
    if ($rest.Length -gt 0) { $chunks += $rest }
    return ,$chunks
}


# ============================================================================
#  NOTIFIERS (Telegram primary - like the article; optional Discord + webhook)
# ============================================================================
function Send-CtTelegram {
    <#
        Send one message via the Telegram Bot API (sendMessage).
        Body is built as UTF-8 bytes so both PS 5.1 and PS 7 send Unicode correctly.
        Returns $true on success.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$ChatId,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$ApiBase = 'https://api.telegram.org'
    )

    if ([string]::IsNullOrWhiteSpace($Token) -or [string]::IsNullOrWhiteSpace($ChatId)) {
        Write-CtLog 'telegram credentials missing; notification skipped' -Level WARN
        return $false
    }

    $uri = "$ApiBase/bot$Token/sendMessage".Trim()
    $payload = @{
        chat_id                  = $ChatId
        text                     = $Text
        parse_mode               = 'HTML'
        disable_web_page_preview = $true
    }
    $json = $payload | ConvertTo-Json -Depth 4 -Compress
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)

    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 30
        if ($resp.ok) { return $true }
        Write-CtLog "telegram api returned ok=$($resp.ok)" -Level WARN
        return $false
    } catch {
        $em = $_.Exception.Message
        # Telegram rate limiting: honor retry_after and retry once
        $respBody = $null
        try {
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $respBody = $_.ErrorDetails.Message                     # PowerShell 7+
            } elseif ($_.Exception.Response) {
                $rs = $_.Exception.Response.GetResponseStream()          # Windows PowerShell 5.1
                if ($rs) { $respBody = (New-Object System.IO.StreamReader($rs)).ReadToEnd() }
            }
        } catch { }

        if ($respBody -match '"retry_after"\s*:\s*(\d+)') {
            $wait = [int]$Matches[1] + 1
            Write-CtLog "telegram rate limit hit; retrying in $wait s" -Level WARN
            Start-Sleep -Seconds $wait
            try {
                $null = Invoke-RestMethod -Uri $uri -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 30
                return $true
            } catch { $em = $_.Exception.Message }
        }
        Write-CtLog "telegram send failed: $em" -Level ERROR
        return $false
    }
}

function Send-CtTelegramChunked {
    <# Send possibly-long text as several <=4096 char messages. #>
    param(
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)][string]$ChatId,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$ApiBase = 'https://api.telegram.org'
    )
    $chunks = Split-CtChunk -Text $Text -Size 3800
    $ok = $true
    foreach ($c in $chunks) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        $r = Send-CtTelegram -Token $Token -ChatId $ChatId -Text $c -ApiBase $ApiBase
        if (-not $r) { $ok = $false }
        Start-Sleep -Milliseconds 350   # be gentle with Telegram rate limits
    }
    return $ok
}

function New-CtDiscordPayload {
    <# Build a crtmon-style Discord embed payload (grouped alerts "target [N]").
       Returns a hashtable ready for ConvertTo-Json. #>
    param(
        [Parameter(Mandatory = $true)][string]$Title,
        [AllowEmptyCollection()][string[]]$Domains,
        [string]$Footer = ''
    )

    $shown = @()
    $i = 0
    foreach ($d in $Domains) {
        if ($i -ge 10) { break }
        $shown += $d
        $i++
    }
    $more = $Domains.Count - $shown.Count
    $desc = ''
    if ($Domains.Count -eq 1) {
        $desc = 'NEW SUBDOMAIN: ' + $Domains[0]
    } else {
        $desc = ($shown | ForEach-Object { '`' + $_ + '`' }) -join "`n"
        if ($more -gt 0) { $desc += "`n... and $more more" }
    }

    $embed = @{
        title       = "$Title [$($Domains.Count)]"
        description = $desc
        color       = 3447003    # teal-ish
    }
    if ($Footer) { $embed.footer = @{ text = $Footer } }

    return @{ username = 'CTMon'; embeds = @($embed) }
}

function Send-CtDiscord {
    <# POST an embed payload to a Discord webhook. Returns $true on success. #>
    param(
        [Parameter(Mandatory = $true)][string]$WebhookUrl,
        [Parameter(Mandatory = $true)][object]$Payload
    )

    if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
        Write-CtLog 'discord webhook url missing; notification skipped' -Level WARN
        return $false
    }
    $json = $Payload | ConvertTo-Json -Depth 6 -Compress
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    try {
        $null = Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 30
        return $true
    } catch {
        Write-CtLog "discord send failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function New-CtWebhookPayload {
    <# Build a generic JSON webhook payload (works with Slack-compatible bridges,
       n8n, ntfy, custom listeners...). #>
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Target = '',
        [int]$Count = 0,
        [AllowEmptyCollection()][string[]]$Domains = @(),
        [string]$Source = ''
    )
    return @{
        text  = $Text
        ctmon = @{
            target   = $Target
            count    = $Count
            domains  = @($Domains)
            source   = $Source
            ts_utc   = (Get-Date).ToUniversalTime().ToString('o')
            version  = $Script:CTMonVersion
        }
    }
}

function Send-CtWebhook {
    <# POST a generic JSON payload to a webhook url. Returns $true on success. #>
    param(
        [Parameter(Mandatory = $true)][string]$WebhookUrl,
        [Parameter(Mandatory = $true)][object]$Payload
    )

    if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
        Write-CtLog 'webhook url missing; notification skipped' -Level WARN
        return $false
    }
    $json = $Payload | ConvertTo-Json -Depth 6 -Compress
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    try {
        $null = Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 30
        return $true
    } catch {
        Write-CtLog "webhook send failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

# ============================================================================
#  NTFY + SLACK CHANNELS (v2.2) - join Telegram / Discord / generic webhook
# ============================================================================

function ConvertTo-CtPlainText {
    <# Strip HTML tags and decode the entities CTMon itself emits, so the same
       alert text works on plain-text channels (ntfy, Slack, webhook). #>
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = $Text
    $t = $t -replace '<br\s*/?>', "`n"
    $t = $t -replace '<[^>]+>', ''
    $t = $t.Replace('&amp;', '&').Replace('&lt;', '<').Replace('&gt;', '>').Replace('&quot;', '"').Replace('&#39;', "'")
    return $t
}

function New-CtSlackPayload {
    <# Build a Slack incoming-webhook payload. Pure function (unit-tested). #>
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Footer = ''
    )
    $body = $Text
    if ($Footer) { $body = "$body`n$Footer" }
    return @{
        text       = $body
        username   = 'CTMon'
        icon_emoji = ':satellite:'
    }
}

function Send-CtSlack {
    <# POST a payload to a Slack incoming webhook. Returns $true on success. #>
    param(
        [Parameter(Mandatory = $true)][string]$WebhookUrl,
        [Parameter(Mandatory = $true)][object]$Payload
    )
    if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
        Write-CtLog 'slack webhook url missing; notification skipped' -Level WARN
        return $false
    }
    $json = $Payload | ConvertTo-Json -Depth 6 -Compress
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    try {
        $null = Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -TimeoutSec 30
        return $true
    } catch {
        Write-CtLog "slack send failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Send-CtNtfy {
    <# Push a message to an ntfy topic (ntfy.sh or a self-hosted server).
       Optional access token via NTFY_TOKEN. Returns $true on success. #>
    param(
        [Parameter(Mandatory = $true)][string]$Topic,
        [Parameter(Mandatory = $true)][string]$Text,
        [string]$Title = 'CTMon',
        [string]$Server = 'https://ntfy.sh',
        [string]$Token = '',
        [string]$Priority = 'default',
        [string]$Tags = 'satellite'
    )

    if ([string]::IsNullOrWhiteSpace($Topic)) {
        Write-CtLog 'ntfy topic missing; notification skipped' -Level WARN
        return $false
    }
    $server = 'https://ntfy.sh'
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $server = $Server.TrimEnd('/') }

    $uri = "$server/$Topic"
    $headers = @{
        'Title'    = $Title
        'Priority' = $Priority
        'Tags'     = $Tags
    }
    if (-not [string]::IsNullOrWhiteSpace($Token)) { $headers['Authorization'] = "Bearer $Token" }

    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
    try {
        $null = Invoke-RestMethod -Uri $uri -Method Post -Body $bytes -Headers $headers -ContentType 'text/plain; charset=utf-8' -TimeoutSec 30
        return $true
    } catch {
        Write-CtLog "ntfy send failed: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Send-CtNotifyDispatch {
    <# Send one pre-built text message through the configured channel. Used by
       -TestAlert and the weekly digest (grouped alerts keep their own richer
       formatting inside Send-CtFlush). #>
    param(
        [Parameter(Mandatory = $true)][object]$Config,
        [Parameter(Mandatory = $true)][string]$NotifyMode,
        [Parameter(Mandatory = $true)][string]$HtmlText,
        [string]$Title = 'CTMon'
    )

    $plain = ConvertTo-CtPlainText -Text $HtmlText

    switch ($NotifyMode) {
        'discord' {
            $payload = New-CtDiscordPayload -Title $Title -Domains @($plain) -Footer "CTMon v$Script:CTMonVersion"
            return (Send-CtDiscord -WebhookUrl "$($Config.discord_webhook_url)" -Payload $payload)
        }
        'slack' {
            $payload = New-CtSlackPayload -Text $plain -Footer "CTMon v$Script:CTMonVersion"
            return (Send-CtSlack -WebhookUrl "$($Config.slack_webhook_url)" -Payload $payload)
        }
        'ntfy' {
            $token = ''
            try { $token = [Environment]::GetEnvironmentVariable('NTFY_TOKEN') } catch { }
            return (Send-CtNtfy -Topic "$($Config.ntfy_topic)" -Text $plain -Title $Title -Server "$($Config.ntfy_server)" -Token $token)
        }
        'webhook' {
            $payload = New-CtWebhookPayload -Text $plain -Target $Title -Count 0 -Domains @() -Source 'dispatch'
            return (Send-CtWebhook -WebhookUrl "$($Config.webhook_url)" -Payload $payload)
        }
        'telegram' {
            return (Send-CtTelegramChunked -Token $Config.telegram_bot_token -ChatId $Config.telegram_chat_id -Text $HtmlText -ApiBase $Config.telegram_api_base)
        }
        default { return $false }
    }
}


# ============================================================================
#  ALERT BUFFER (grouped alerts like crtmon's Discord embeds "vercelApp [10]")
# ============================================================================
$Script:AlertBuffer = @{}
$Script:NotificationsEnabled = $false   # set in main: channel configured AND not dry-run
$Script:NotifyMode = 'telegram'

function Add-CtAlert {
    param(
        [Parameter(Mandatory = $true)][string]$Group,
        [Parameter(Mandatory = $true)][string]$Domain,
        [string]$Dns = '',
        [string]$Severity = 'low',
        [int]$Score = 0,
        [string]$Keyword = '',
        [string[]]$Reasons = @()
    )
    if (-not $Script:AlertBuffer.ContainsKey($Group)) { $Script:AlertBuffer[$Group] = New-Object System.Collections.Generic.List[object] }
    $Script:AlertBuffer[$Group].Add([pscustomobject]@{
        D = $Domain; Dns = $Dns; Severity = $Severity; Score = $Score
        Keyword = $Keyword; Reasons = @($Reasons)
    })
}

function Get-CtBufferedCount {
    $n = 0
    foreach ($k in @($Script:AlertBuffer.Keys)) { $n += $Script:AlertBuffer[$k].Count }
    return $n
}

function Send-CtFlush {
    <# Flush buffered matches to the configured notification channel(s).
       v2.2: severity-aware alerts + slack / ntfy channels. #>
    param(
        [object]$Config,
        [int]$BatchMax = 10,
        [string]$NotifyMode = 'telegram'
    )

    foreach ($group in @($Script:AlertBuffer.Keys)) {
        $list = $Script:AlertBuffer[$group]
        if (-not $list -or $list.Count -eq 0) { continue }

        $domNames = @($list | ForEach-Object { "$($_.D)" })
        $dnsFirst = ''
        foreach ($it in $list) { if ($it.Dns) { $dnsFirst = $it.Dns; break } }

        # ---- severity of this batch (worst wins) ----
        $worstSev = 'low'
        $worstScore = 0
        $worstReasons = @()
        foreach ($it in $list) {
            if ((Get-CtSeverityWeight -Level "$($it.Severity)") -gt (Get-CtSeverityWeight -Level $worstSev)) {
                $worstSev = "$($it.Severity)"
                $worstScore = [int]$it.Score
                $worstReasons = @($it.Reasons)
            }
        }
        $sevUpper = $worstSev.ToUpperInvariant()
        $riskLine = ''
        if ($worstSev -ne 'low' -and $worstSev -ne '') {
            $reasonTxt = ($worstReasons | Select-Object -First 3) -join ', '
            if ($reasonTxt) { $riskLine = "risk: <b>$sevUpper</b> ($worstScore) - $reasonTxt" }
            else { $riskLine = "risk: <b>$sevUpper</b> ($worstScore)" }
        }

        # ---------- Telegram (HTML) ----------
        $tgText = ''
        if ($list.Count -eq 1) {
            $tgText = "$($Script:EmojiNew) <b>NEW SUBDOMAIN</b>: <code>$(ConvertTo-CtHtmlSafe $domNames[0])</code>"
            if ($dnsFirst) { $tgText += "`n$($Script:EmojiGlobe) dns: <code>$(ConvertTo-CtHtmlSafe $dnsFirst)</code>" }
            if ($riskLine) { $tgText += "`n$($Script:EmojiWarn) $riskLine" }
        } else {
            $shown = @()
            $i = 0
            foreach ($dn in $domNames) {
                if ($i -ge $BatchMax) { break }
                $shown += "<code>$(ConvertTo-CtHtmlSafe $dn)</code>"
                $i++
            }
            $more = $list.Count - $shown.Count
            $body = ($shown -join "`n")
            if ($more -gt 0) { $body += "`n<i>... and $more more</i>" }
            $tgText = "$($Script:EmojiSat) <b>$group</b> [$($list.Count)]`n$body"
            if ($riskLine) { $tgText += "`n$($Script:EmojiWarn) $riskLine" }
        }

        # ---------- plain text (slack / ntfy / webhook) ----------
        $plainText = ConvertTo-CtPlainText -Text $tgText

        # ---------- Discord ----------
        $discordColor = 3447003
        if ($worstSev -eq 'critical' -or $worstSev -eq 'high') { $discordColor = 15548997 }
        elseif ($worstSev -eq 'medium') { $discordColor = 16098851 }
        $discordPayload = New-CtDiscordPayload -Title $group -Domains $domNames -Footer "CTMon v$Script:CTMonVersion | $group"
        try { $discordPayload.embeds[0].color = $discordColor } catch { }

        # ---------- slack ----------
        $slackPayload = New-CtSlackPayload -Text $plainText -Footer "CTMon v$Script:CTMonVersion"

        # ---------- generic webhook ----------
        $hookPayload = New-CtWebhookPayload -Text $plainText -Target $group -Count $list.Count -Domains $domNames -Source $Script:Stats.source
        try { $hookPayload.ctmon.severity = $worstSev; $hookPayload.ctmon.score = $worstScore } catch { }

        if ($Script:DryRun) {
            Write-CtLog "[dry-run] would send $NotifyMode alert for $group ($($list.Count) domain(s))" -Level INFO
        } elseif (-not $Script:NotificationsEnabled) {
            # console-only mode (no channel configured) - just count them
            $Script:Stats.notifications += 0
        } else {
            $ok = $false
            if ($NotifyMode -eq 'discord') {
                $ok = Send-CtDiscord -WebhookUrl "$($Config.discord_webhook_url)" -Payload $discordPayload
            } elseif ($NotifyMode -eq 'slack') {
                $ok = Send-CtSlack -WebhookUrl "$($Config.slack_webhook_url)" -Payload $slackPayload
            } elseif ($NotifyMode -eq 'ntfy') {
                $ntfyToken = ''
                try { $ntfyToken = [Environment]::GetEnvironmentVariable('NTFY_TOKEN') } catch { }
                $ntfyPriority = 'default'
                if ($worstSev -eq 'critical' -or $worstSev -eq 'high') { $ntfyPriority = 'high' }
                $ok = Send-CtNtfy -Topic "$($Config.ntfy_topic)" -Text $plainText -Title "CTMon: $group [$($list.Count)]" -Server "$($Config.ntfy_server)" -Token $ntfyToken -Priority $ntfyPriority
            } elseif ($NotifyMode -eq 'webhook') {
                $ok = Send-CtWebhook -WebhookUrl "$($Config.webhook_url)" -Payload $hookPayload
            } else {
                $ok = Send-CtTelegramChunked -Token $Config.telegram_bot_token -ChatId $Config.telegram_chat_id -Text $tgText -ApiBase $Config.telegram_api_base
            }
            if ($ok) {
                $Script:Stats.notifications += $list.Count
                Write-CtLog "$NotifyMode alert sent target=$group count=$($list.Count) risk=$worstSev" -Level OK
            }
        }
        $Script:AlertBuffer.Remove($group) | Out-Null
    }
}

# ============================================================================
#  STATS / STATE (session summary + -Status support + heartbeat data)
# ============================================================================
$Script:Stats = @{
    started        = (Get-Date)
    certs_seen     = 0
    domains_seen   = 0
    matched        = 0
    matched_today  = 0
    matched_day    = (Get-Date).ToString('yyyy-MM-dd')
    notifications  = 0
    reconnects     = 0
    bypass_count   = 0
    last_poll_utc    = ''
    last_poll_source = ''
    last_poll_entries = 0
    per_target     = @{}
    source         = 'certstream'
    pid            = $PID
    version        = $Script:CTMonVersion
    targets        = @()
}

function Add-CtStat {
    param([string]$Target)
    $Script:Stats.matched++
    $today = (Get-Date).ToString('yyyy-MM-dd')
    if ($Script:Stats.matched_day -ne $today) {
        $Script:Stats.matched_day = $today
        $Script:Stats.matched_today = 0
    }
    $Script:Stats.matched_today++
    if ($Target) {
        if (-not $Script:Stats.per_target.ContainsKey($Target)) { $Script:Stats.per_target[$Target] = 0 }
        $Script:Stats.per_target[$Target]++
    }
}

function Save-CtState {
    try {
        $dir = Split-Path $Script:StatePath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $obj = [pscustomobject]@{
            version       = $Script:CTMonVersion
            pid           = $PID
            started_utc   = $Script:Stats.started.ToUniversalTime().ToString('o')
            updated_utc   = (Get-Date).ToUniversalTime().ToString('o')
            source        = $Script:Stats.source
            certs_seen    = $Script:Stats.certs_seen
            domains_seen  = $Script:Stats.domains_seen
            matched       = $Script:Stats.matched
            matched_today = $Script:Stats.matched_today
            matched_day   = $Script:Stats.matched_day
            notifications = $Script:Stats.notifications
            reconnects    = $Script:Stats.reconnects
            bypass_count  = $Script:Stats.bypass_count
            digest_last_utc = "$Script:DigestLastUtc"
            last_poll_utc    = "$($Script:Stats.last_poll_utc)"
            last_poll_source = "$($Script:Stats.last_poll_source)"
            last_poll_entries = [int]$Script:Stats.last_poll_entries
            monitor_targets = @($Script:Stats.targets | ForEach-Object { "$_" })
            per_target    = $Script:Stats.per_target
        }
        $json = $obj | ConvertTo-Json -Depth 5
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Script:StatePath, $json, $utf8)
    } catch { }
}

function Get-CtUptimeText {
    param([datetime]$Start)
    $sp = (Get-Date) - $Start
    $totalHours = $sp.Hours + ($sp.Days * 24)
    return ('{0:00}h {1:00}m {2:00}s' -f $totalHours, $sp.Minutes, $sp.Seconds)
}

function Show-CtSessionSummary {
    <# End-of-session report (console) drawn as a unicode box with an ASCII fallback. #>
    param([bool]$ToTelegram = $false, [object]$Config = $null)
    if (-not $Script:Stats.stats_summary_enabled) { return }
    $up = Get-CtUptimeText -Start $Script:Stats.started

    $rows = @(
        @('uptime', $up),
        @('certificates', "$($Script:Stats.certs_seen)"),
        @('domains parsed', "$($Script:Stats.domains_seen)"),
        @('matched', "$($Script:Stats.matched) (today: $($Script:Stats.matched_today))"),
        @('notifications', "$($Script:Stats.notifications)"),
        @('bypass used', "$($Script:Stats.bypass_count)"),
        @('reconnects', "$($Script:Stats.reconnects)")
    )
    foreach ($k in $Script:Stats.per_target.Keys) {
        $rows += , @("  target: $k", "$($Script:Stats.per_target[$k])")
    }
    if ($Script:LogFile -and (Test-Path $Script:LogFile)) {
        $rows += , @('log file', "$($Script:LogFile)")
    }

    $w = 20
    foreach ($r in $rows) {
        $len = $r[0].Length + $r[1].Length + 3
        if ($len -gt $w) { $w = $len }
    }

    $okUnicode = $false
    try {
        $probe = [string][char]0x2550
        if ($probe.Length -eq 1) { $okUnicode = $true }
    } catch { $okUnicode = $false }

    Write-Host ''
    if ($okUnicode) {
        $tl = [char]0x256D; $tr = [char]0x256E; $bl = [char]0x2570; $br = [char]0x256F
        $hz = [char]0x2500; $vt = [char]0x2502
        Write-Host " $tl$([string]$hz * ($w + 2))$tr" -ForegroundColor Yellow
        $title = ' session summary'
        $titlePad = [string]' ' * [Math]::Max(0, $w + 1 - $title.Length)
        Write-Host " $vt$title$titlePad$vt" -ForegroundColor Yellow
        Write-Host " $vt$([string]$hz * ($w + 2))$vt" -ForegroundColor Yellow
        foreach ($r in $rows) {
            $pad = [string]' ' * [Math]::Max(1, $w - ($r[0].Length + $r[1].Length + 3))
            Write-Host " $vt $($r[0]) : $($r[1])$pad$vt" -ForegroundColor Gray
        }
        Write-Host " $bl$([string]$hz * ($w + 2))$br" -ForegroundColor Yellow
    }
    else {
        Write-Host " +$('-' * ($w + 2))+" -ForegroundColor Yellow
        Write-Host " | $($Script:EmojiStat) session summary" -ForegroundColor Yellow
        foreach ($r in $rows) { Write-Host " | $($r[0]) : $($r[1])" -ForegroundColor Gray }
        Write-Host " +$('-' * ($w + 2))+" -ForegroundColor Yellow
    }
    Write-Host ''

    if ($ToTelegram -and $Config -and (-not $Script:DryRun)) {
        $lines = @(
            "$($Script:EmojiStat) <b>CTMon session summary</b>",
            "uptime: $up",
            "certificates: $($Script:Stats.certs_seen) | domains: $($Script:Stats.domains_seen) | matched: $($Script:Stats.matched) | sent: $($Script:Stats.notifications) | bypass: $($Script:Stats.bypass_count)"
        )
        $null = Send-CtTelegramChunked -Token $Config.telegram_bot_token -ChatId $Config.telegram_chat_id -Text ($lines -join "`n") -ApiBase $Config.telegram_api_base
    }
}

# ============================================================================
#  DNS ENRICHMENT  (Sublert / ct-monitor inspired: resolve new subdomains to IPs)
# ============================================================================
function New-CtDnsCache {
    param([string]$Path = $Script:DnsCachePath)
    $cache = @{
        Path           = $Path
        Map            = @{}
        Dirty          = $false
        PositiveHours  = 168    # resolved entries live for 7 days
        NegativeHours  = 24     # unresolved entries retry after 1 day
        MaxEntries     = 5000
        DohEnabled     = $false        # v2.2: set by the monitor when doh_enabled = true
        DohProvider    = 'cloudflare'  # cloudflare | google | auto
        Proxy          = $null         # effective proxy for DoH lookups
    }
    if ($Path -and (Test-Path $Path)) {
        try {
            $raw = [System.IO.File]::ReadAllText($Path)
            $obj = $raw | ConvertFrom-Json
            if ($obj) {
                foreach ($p in $obj.PSObject.Properties) {
                    $v = $p.Value
                    $ts = $null
                    try { $ts = [datetime]::Parse("$($v.ts)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { $ts = (Get-Date) }
                    $cache.Map[$p.Name] = @{ ok = [bool]$v.ok; ip = "$($v.ip)"; ts = $ts.ToLocalTime() }
                }
                Write-CtLog "loaded dns cache entries=$($cache.Map.Count)" -Level DEBUG
            }
        } catch {
            Write-CtLog "could not load dns cache (starting fresh): $($_.Exception.Message)" -Level WARN
        }
    }
    return $cache
}

function Save-CtDnsCache {
    param([Parameter(Mandatory = $true)][hashtable]$Cache)
    if (-not ($Cache.Dirty -and $Cache.Path)) { return }
    try {
        # cap growth: drop the oldest half when over the limit
        if ($Cache.Map.Count -gt $Cache.MaxEntries) {
            $sorted = @($Cache.Map.Keys) | Sort-Object { $Cache.Map[$_].ts }
            $keep = [Math]::Floor($Cache.MaxEntries / 2)
            $newMap = @{}
            $start = [Math]::Max(0, $sorted.Count - $keep)
            for ($i = $start; $i -lt $sorted.Count; $i++) { $newMap[$sorted[$i]] = $Cache.Map[$sorted[$i]] }
            $Cache.Map = $newMap
        }
        $out = @{}
        foreach ($k in $Cache.Map.Keys) {
            $e = $Cache.Map[$k]
            $out[$k] = @{ ok = [bool]$e.ok; ip = "$($e.ip)"; ts = ([datetime]$e.ts).ToUniversalTime().ToString('o') }
        }
        $json = ConvertTo-Json -InputObject $out -Depth 5 -Compress
        if (($out.Count -eq 0)) { $json = '{}' }
        $dir = Split-Path $Cache.Path -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Cache.Path, $json, $utf8)
        $Cache.Dirty = $false
    } catch {
        Write-CtLog "could not save dns cache: $($_.Exception.Message)" -Level WARN
    }
}

function Resolve-CtHostCached {
    <# Resolve a domain to (up to 3) IP addresses using the system resolver, with a
       persistent cache and short timeout so slow lookups never stall the pipeline.
       v2.2: when the system resolver fails and DoH is enabled, a DNS-over-HTTPS
       lookup (queried by IP, so it cannot be poisoned) provides the fallback.
       Returns '' when the name does not resolve (or on timeout). #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][hashtable]$Cache,
        [int]$TimeoutMs = 2500
    )

    $key = $Domain.Trim().ToLowerInvariant()
    if ($key -eq '' -or (-not $key.Contains('.'))) { return '' }

    if ($Cache.Map.ContainsKey($key)) {
        $e = $Cache.Map[$key]
        $ageH = 0
        try { $ageH = ((Get-Date) - ([datetime]$e.ts)).TotalHours } catch { $ageH = 999999 }
        if ($e.ok -and $ageH -lt $Cache.PositiveHours) { return "$($e.ip)" }
        if ((-not $e.ok) -and $ageH -lt $Cache.NegativeHours) { return '' }
    }

    $ips = ''
    try {
        $task = [System.Net.Dns]::GetHostAddressesAsync($key)
        if ($task.Wait($TimeoutMs)) {
            try {
                $addrs = @($task.Result | ForEach-Object { $_.ToString() })
                $v4 = @($addrs | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
                $pick = @()
                if ($v4.Count -gt 0) { $pick += $v4[0] }
                foreach ($a in $addrs) {
                    if ($pick.Count -ge 3) { break }
                    if ($pick -notcontains $a) { $pick += $a }
                }
                $ips = ($pick -join ', ')
            } catch { $ips = '' }
        }
    } catch { $ips = '' }

    # ---- v2.2 DoH fallback (system resolver failed or was poisoned) ----
    if (-not $ips -and $Cache.DohEnabled) {
        try {
            $dohIp = Resolve-CtDoh -Name $key -Provider $Cache.DohProvider -Proxy $Cache.Proxy -TimeoutSec 6
            if ($dohIp) {
                $ips = $dohIp
                Write-CtLog "dns resolved via doh domain=$key ip=$dohIp (system resolver failed)" -Level DEBUG
            }
        } catch { }
    }

    $ok = ($ips -ne '')
    $Cache.Map[$key] = @{ ok = $ok; ip = $ips; ts = (Get-Date) }
    $Cache.Dirty = $true
    return $ips
}

# ============================================================================
#  MATCH HISTORY (jsonl - powers -Export / -Summary / offline dashboard)
# ============================================================================
function Add-CtMatchRecord {
    <# Append one match to the persistent match history (one JSON object per line).
       v2.2: carries risk severity/score/reasons for the dashboard and digests. #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Group,
        [string]$Keyword = '',
        [string]$Source = '',
        [string]$Dns = '',
        [bool]$AlertEnabled = $false,
        [int]$MaxRecords = 20000,
        [string]$Severity = 'low',
        [int]$Score = 0,
        [string[]]$Reasons = @()
    )
    try {
        $dir = Split-Path $Script:MatchesPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        # cap history size occasionally (cheap line count check)
        if ((Test-Path $Script:MatchesPath) -and ((Get-Item -LiteralPath $Script:MatchesPath -ErrorAction SilentlyContinue).Length -gt ($MaxRecords * 220))) {
            $lines = [System.IO.File]::ReadAllLines($Script:MatchesPath)
            $keep = $MaxRecords
            if ($lines.Count -gt $keep) {
                $kept = $lines[($lines.Count - $keep)..($lines.Count - 1)]
                $utf8b = New-Object System.Text.UTF8Encoding($false)
                [System.IO.File]::WriteAllText($Script:MatchesPath, (($kept -join [Environment]::NewLine) + [Environment]::NewLine), $utf8b)
            }
        }

        $rec = [ordered]@{
            ts_utc   = (Get-Date).ToUniversalTime().ToString('o')
            domain   = $Domain
            group    = $Group
            keyword  = $Keyword
            source   = $Source
            dns      = $Dns
            alert    = [int]$AlertEnabled
            severity = "$Severity"
            score    = $Score
            reasons  = (@($Reasons) -join '; ')
        }
        $line = ConvertTo-Json -InputObject $rec -Depth 3 -Compress
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::AppendAllText($Script:MatchesPath, $line + [Environment]::NewLine, $utf8)
    } catch {
        Write-CtLog "could not append match record: $($_.Exception.Message)" -Level WARN
    }
}

function Get-CtMatchRecords {
    <# Read the match history, newest first. -Days filters by age (0 = everything).
       Returns a plain array (callers wrap with @() as needed). #>
    param([int]$Days = 0)

    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path $Script:MatchesPath)) { return $out.ToArray() }
    $cutoff = $null
    if ($Days -gt 0) { $cutoff = (Get-Date).ToUniversalTime().AddDays(-1 * $Days) }
    try {
        $lines = [System.IO.File]::ReadAllLines($Script:MatchesPath)
        for ($i = $lines.Count - 1; $i -ge 0; $i--) {
            $l = $lines[$i]
            if ([string]::IsNullOrWhiteSpace($l)) { continue }
            try {
                $r = $l | ConvertFrom-Json
                # normalize: ConvertFrom-Json types ISO timestamps as [datetime]; keep ISO 'o' strings
                $tsNorm = "$($r.ts_utc)"
                if ($r.ts_utc -is [datetime]) { $tsNorm = ([datetime]$r.ts_utc).ToUniversalTime().ToString('o') }
                $sevNorm = "$($r.severity)"
                if ([string]::IsNullOrWhiteSpace($sevNorm)) { $sevNorm = 'low' }
                $scoreNorm = 0
                try { if ($null -ne $r.score) { $scoreNorm = [int]$r.score } } catch { $scoreNorm = 0 }
                $norm = [pscustomobject]@{
                    ts_utc   = $tsNorm
                    domain   = "$($r.domain)"
                    group    = "$($r.group)"
                    keyword  = "$($r.keyword)"
                    source   = "$($r.source)"
                    dns      = "$($r.dns)"
                    alert    = $r.alert
                    severity = $sevNorm
                    score    = $scoreNorm
                    reasons  = "$($r.reasons)"
                }
                if ($cutoff) {
                    $ts = $null
                    try { $ts = [datetime]::Parse($tsNorm, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { }
                    if ($ts -and $ts -lt $cutoff) { continue }
                }
                $out.Add($norm)
            } catch { }
        }
    } catch {
        Write-CtLog "could not read match history: $($_.Exception.Message)" -Level WARN
    }
    return $out.ToArray()
}

# ============================================================================
#  PROMETHEUS METRICS (v2.2) - GET /api/metrics on the dashboard server
# ============================================================================

function New-CtPrometheusMetrics {
    <# Pure builder: render a flat metrics hashtable in Prometheus text exposition
       format (version 0.0.4). Expected keys: version, certs_seen, domains_seen,
       matched, matched_today, notifications, reconnects, bypass_count,
       uptime_seconds, buffered, per_target (hashtable). Unit-tested. #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Metrics,
        [Parameter(Mandatory = $true)][string]$Version
    )

    function Get-Mx([string]$Key) {
        $v = 0
        try { if ($null -ne $Metrics[$Key]) { $v = [int]$Metrics[$Key] } } catch { $v = 0 }
        return $v
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $nl = "`n"

    $lines.Add('# HELP ctmon_build_info CTMon build information.')
    $lines.Add('# TYPE ctmon_build_info gauge')
    $lines.Add("ctmon_build_info{version=`"$Version`"} 1")

    $lines.Add('# HELP ctmon_certs_seen_total Certificates observed (session or last persisted state).')
    $lines.Add('# TYPE ctmon_certs_seen_total counter')
    $lines.Add("ctmon_certs_seen_total $(Get-Mx 'certs_seen')")

    $lines.Add('# HELP ctmon_domains_seen_total Domains parsed from certificates.')
    $lines.Add('# TYPE ctmon_domains_seen_total counter')
    $lines.Add("ctmon_domains_seen_total $(Get-Mx 'domains_seen')")

    $lines.Add('# HELP ctmon_matches_total Matched new assets.')
    $lines.Add('# TYPE ctmon_matches_total counter')
    $lines.Add("ctmon_matches_total $(Get-Mx 'matched')")

    $lines.Add('# HELP ctmon_matches_today_total Matched new assets today (UTC day).')
    $lines.Add('# TYPE ctmon_matches_today_total counter')
    $lines.Add("ctmon_matches_today_total $(Get-Mx 'matched_today')")

    $lines.Add('# HELP ctmon_notifications_total Notifications sent.')
    $lines.Add('# TYPE ctmon_notifications_total counter')
    $lines.Add("ctmon_notifications_total $(Get-Mx 'notifications')")

    $lines.Add('# HELP ctmon_reconnects_total Feed reconnects.')
    $lines.Add('# TYPE ctmon_reconnects_total counter')
    $lines.Add("ctmon_reconnects_total $(Get-Mx 'reconnects')")

    $lines.Add('# HELP ctmon_bypass_total Network bypass engagements (proxy / DoH / alt source).')
    $lines.Add('# TYPE ctmon_bypass_total counter')
    $lines.Add("ctmon_bypass_total $(Get-Mx 'bypass_count')")

    $lines.Add('# HELP ctmon_uptime_seconds Monitor uptime in seconds.')
    $lines.Add('# TYPE ctmon_uptime_seconds gauge')
    $lines.Add("ctmon_uptime_seconds $(Get-Mx 'uptime_seconds')")

    $lines.Add('# HELP ctmon_alert_buffered Buffered matches waiting for the next flush.')
    $lines.Add('# TYPE ctmon_alert_buffered gauge')
    $lines.Add("ctmon_alert_buffered $(Get-Mx 'buffered')")

    if ($Metrics['per_target'] -and $Metrics['per_target'] -is [hashtable]) {
        $lines.Add('# HELP ctmon_target_matches_total Matches per configured target/keyword group.')
        $lines.Add('# TYPE ctmon_target_matches_total counter')
        foreach ($k in $Metrics['per_target'].Keys) {
            $label = "$k".Replace('\', '\\').Replace('"', '\"').Replace("`n", ' ')
            $val = 0
            try { $val = [int]$Metrics['per_target'][$k] } catch { $val = 0 }
            $lines.Add("ctmon_target_matches_total{target=`"$label`"} $val")
        }
    }

    return (($lines.ToArray() -join $nl) + $nl)
}

# ============================================================================
#  WEEKLY DIGEST (v2.2) - "top new assets" recap pushed through the notifier
# ============================================================================

function New-CtDigestMessage {
    <# Pure builder: summarize match records into a per-target digest text.
       Returns @{ Text = string; GroupCount = int; Total = int }. #>
    param(
        [AllowEmptyCollection()][object[]]$Records,
        [int]$Days = 7,
        [int]$TopPerTarget = 8,
        [int]$MaxChars = 3500
    )

    $total = @($Records).Count
    if ($total -eq 0) {
        return @{ Text = "CTMon digest (last $Days day(s)): no new assets."; GroupCount = 0; Total = 0 }
    }

    $byGroup = @{}
    foreach ($r in $Records) {
        $g = "$($r.group)"
        if (-not $g) { $g = 'unknown' }
        if (-not $byGroup.ContainsKey($g)) {
            $byGroup[$g] = New-Object System.Collections.Generic.List[object]
        }
        $null = $byGroup[$g].Add($r)
    }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append("CTMon digest - last $Days day(s): $total new asset(s) across $($byGroup.Count) target group(s)")

    foreach ($g in ($byGroup.Keys | Sort-Object)) {
        $list = $byGroup[$g]
        $null = $sb.Append("`n`n")
        $null = $sb.Append("$g [$($list.Count)]")
        $shown = 0
        foreach ($r in $list) {
            if ($shown -ge $TopPerTarget) { break }
            $dom = "$($r.domain)"
            $sev = "$($r.severity)"
            if ($sev -and $sev -ne '') { $dom = "$dom ($sev)" }
            $null = $sb.Append("`n  $dom")
            $shown++
        }
        $rest = $list.Count - $shown
        if ($rest -gt 0) { $null = $sb.Append("`n  ... and $rest more") }
        if ($sb.Length -gt $MaxChars) { break }
    }
    if ($sb.Length -gt $MaxChars) {
        $trimmed = $sb.ToString(0, $MaxChars)
        $idx = $trimmed.LastIndexOf("`n")
        if ($idx -gt 0) { $trimmed = $trimmed.Substring(0, $idx) }
        $trimmed += "`n... (truncated)"
        return @{ Text = $trimmed; GroupCount = $byGroup.Count; Total = $total }
    }
    return @{ Text = $sb.ToString(); GroupCount = $byGroup.Count; Total = $total }
}

function Test-CtDigestDue {
    <# Pure scheduling rule: due on the configured weekday at/after the configured
       local hour, with at least $MinGapDays between sends. #>
    param(
        [Parameter(Mandatory = $true)][datetime]$Now,
        [object]$LastSentUtc = $null,
        [string]$Weekday = 'Monday',
        [int]$Hour = 9,
        [int]$MinGapDays = 6
    )

    if ([string]::IsNullOrWhiteSpace($Weekday) -or $Weekday -eq 'none') { return $false }
    if ($Hour -lt 0 -or $Hour -gt 23) { $Hour = 9 }

    if ($null -ne $LastSentUtc -and "$LastSentUtc" -ne '') {
        try {
            $last = [datetime]::Parse("$LastSentUtc", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            if (($Now.ToUniversalTime() - $last).TotalDays -lt $MinGapDays) { return $false }
        } catch { }
    }

    try { $target = [Enum]::Parse([System.DayOfWeek], $Weekday, $true) } catch { return $false }
    return ($Now.DayOfWeek -eq $target -and $Now.Hour -ge $Hour)
}

function Invoke-CtDigestSend {
    <# Build the digest from match history and push it through the configured
       notifier. With -PrintOnly it just prints to the console. #>
    param(
        [Parameter(Mandatory = $true)][object]$Config,
        [Parameter(Mandatory = $true)][string]$NotifyMode,
        [int]$Days = 7,
        [switch]$PrintOnly
    )

    $recs = @(Get-CtMatchRecords -Days $Days)
    $digest = New-CtDigestMessage -Records $recs -Days $Days

    if ($PrintOnly) {
        Write-Host ''
        Write-Host $digest.Text -ForegroundColor Gray
        Write-Host ''
        Write-CtLog "digest preview: $($digest.Total) asset(s) across $($digest.GroupCount) group(s)" -Level INFO
        return $true
    }

    if ($digest.Total -eq 0) {
        Write-CtLog "digest skipped: no matches in the last $Days day(s)" -Level INFO
        return $true   # nothing to send counts as done; do not retry all day
    }

    if ($Script:DryRun) {
        Write-CtLog "[dry-run] would send $NotifyMode digest ($($digest.Total) asset(s), $($digest.GroupCount) group(s))" -Level INFO
        return $false
    }

    $encoded = [System.Net.WebUtility]::HtmlEncode($digest.Text)
    $htmlText = "<pre>$encoded</pre>"
    $ok = Send-CtNotifyDispatch -Config $Config -NotifyMode $NotifyMode -HtmlText $htmlText -Title 'CTMon weekly digest'
    if ($ok) {
        Write-CtLog "digest sent via $NotifyMode ($($digest.Total) asset(s))" -Level OK
    }
    return $ok
}


# ============================================================================
#  DASHBOARD BUFFERS (in-memory feed for the html dashboard; monitor process only)
# ============================================================================
$Script:Dash = $null        # set up by Initialize-CtDashboard
$Script:DashEvents = $null  # separate on purpose: Write-CtLog checks this early

function Initialize-CtDashboard {
    $Script:DashEvents = New-Object System.Collections.Generic.List[object]   # newest first, cap 60
    $Script:Dash = @{
        Matches   = New-Object System.Collections.Generic.List[object]        # newest first, cap 120
        LastWrite = [datetime]::MinValue
    }
}

function Add-CtDashEvent {
    param([string]$Level, [string]$Message)
    if ($null -eq $Script:DashEvents) { return }
    try {
        $Script:DashEvents.Insert(0, [pscustomobject]@{
            ts_utc  = (Get-Date).ToUniversalTime().ToString('o')
            level   = $Level
            message = $Message
        })
        while ($Script:DashEvents.Count -gt 60) { $Script:DashEvents.RemoveAt($Script:DashEvents.Count - 1) }
    } catch { }
}

function Add-CtDashMatch {
    param(
        [string]$Domain, [string]$Group, [string]$Source,
        [string]$Dns = '', [string]$Keyword = '',
        [string]$Severity = 'low', [int]$Score = 0
    )
    if ($null -eq $Script:Dash) { return }
    try {
        $Script:Dash.Matches.Insert(0, [pscustomobject]@{
            ts_utc   = (Get-Date).ToUniversalTime().ToString('o')
            domain   = $Domain
            group    = $Group
            source   = $Source
            dns      = $Dns
            keyword  = $Keyword
            severity = "$Severity"
            score    = $Score
        })
        while ($Script:Dash.Matches.Count -gt 120) { $Script:Dash.Matches.RemoveAt($Script:Dash.Matches.Count - 1) }
    } catch { }
}


# ============================================================================
#  CERTSTREAM CLIENT (real-time CT feed over WebSocket, auto-reconnect)
#  Uses System.Net.WebSockets.ClientWebSocket - built into .NET, no modules needed.
# ============================================================================
function Connect-CtCertstream {
    <# Open a WebSocket to a certstream server. v2.2.3: honors the effective proxy
       (HTTPS_PROXY / net_proxy) so the real-time feed can pass through censorship
       and firewalled networks. Returns the ClientWebSocket or throws. #>
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [object]$Proxy = $null
    )

    # Windows PowerShell 5.1 needs TLS 1.2 enabled explicitly for wss/https
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch { }
    }

    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    try { $ws.Options.KeepAliveInterval = [TimeSpan]::FromSeconds(30) } catch { }

    if ($Proxy -and -not [string]::IsNullOrWhiteSpace("$($Proxy.Url)")) {
        try {
            $scheme = ''
            try { $scheme = ([Uri]$Proxy.Url).Scheme.ToLowerInvariant() } catch { }
            if ($scheme.StartsWith('socks')) {
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $ws.Options.Proxy = New-Object System.Net.WebProxy("$($Proxy.Url)")
                    Write-CtLog "certstream websocket via socks proxy $($Proxy.Url) (source: $($Proxy.Source))" -Level INFO
                } else {
                    Write-CtLog 'socks proxy needs PowerShell 7+ for the websocket feed; trying direct connection' -Level WARN
                }
            }
            else {
                $ws.Options.Proxy = New-Object System.Net.WebProxy("$($Proxy.Url)", $true)
                Write-CtLog "certstream websocket via proxy $($Proxy.Url) (source: $($Proxy.Source))" -Level INFO
            }
        } catch {
            Write-CtLog "could not apply proxy to websocket: $($_.Exception.Message); trying direct" -Level WARN
        }
    }

    $uri = [Uri]$Url
    $cts = New-Object System.Threading.CancellationTokenSource([TimeSpan]::FromSeconds(30))
    $task = $ws.ConnectAsync($uri, $cts.Token)
    $null = $task.GetAwaiter().GetResult()

    if ($ws.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
        try { $ws.Dispose() } catch { }
        throw "handshake failed (state=$($ws.State))"
    }
    return $ws
}

function Receive-CtCertstreamMessage {
    <# Receive one complete (possibly fragmented) WebSocket message as a string. #>
    param(
        [Parameter(Mandatory = $true)][System.Net.WebSockets.ClientWebSocket]$Ws,
        [Parameter(Mandatory = $true)][System.Threading.CancellationToken]$Token
    )

    $buffer = New-Object byte[] 32768
    $seg    = New-Object 'ArraySegment[byte]' -ArgumentList @(,$buffer)
    $ms     = New-Object System.IO.MemoryStream

    try {
        do {
            $rcv = $Ws.ReceiveAsync($seg, $Token)
            $result = $rcv.GetAwaiter().GetResult()

            if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                return $null
            }
            if ($result.Count -gt 0) {
                $ms.Write($buffer, 0, $result.Count)
            }
            if ($ms.Length -gt 32MB) { throw 'message too large' }
        } while (-not $result.EndOfMessage)

        if ($ms.Length -eq 0) { return $null }
        return [System.Text.Encoding]::UTF8.GetString($ms.ToArray())
    } finally {
        $ms.Dispose()
    }
}

function Read-CtCertDomains {
    <# Extract the domain list from one certstream JSON message.
       Robust across certstream feed variants: anything carrying leaf_cert data is
       processed; heartbeats and other control messages are ignored. #>
    param([Parameter(Mandatory = $true)][string]$Json)

    if ([string]::IsNullOrWhiteSpace($Json)) { return $null }
    try { $msg = $Json | ConvertFrom-Json } catch { return $null }
    if (-not $msg) { return $null }

    # ignore known control message types quickly
    if ($msg.message_type -eq 'heartbeat') { return $null }

    $leaf = $null
    if ($msg.data -and $msg.data.leaf_cert) { $leaf = $msg.data.leaf_cert }
    if (-not $leaf) { return $null }

    $domains = @()
    $all = $leaf.all_domains
    if ($all) { $domains = @($all) }
    elseif ($leaf.subject) { $domains = @("$($leaf.subject)") }

    if ($domains.Count -eq 0) { return $null }
    return $domains
}

# ============================================================================
#  CRT.SH POLLER (alternative / fallback source; near-real-time)
# ============================================================================
function Get-CrtshEntries {
    <# Query crt.sh JSON API for a target's recently issued certificates.
       Uses the central Invoke-CtHttpGet (proxy-aware). Throws on failure so the
       v2.2 bypass chain (Invoke-CtCrtshChain) can engage fallback paths. #>
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [string]$BaseUrl = 'https://crt.sh',
        [int]$TimeoutSec = 180,
        [object]$Proxy = $null
    )

    # q=%.target  ->  '%' must be URL-encoded as %25
    $uri = "$BaseUrl/?q=%25.$Target&output=json&exclude=expired"
    try {
        $resp = Invoke-CtHttpGet -Uri $uri -Proxy $Proxy -TimeoutSec $TimeoutSec -Accept 'application/json'
        if ($null -eq $resp) { return @() }
        if ($resp -is [array]) { return @($resp) }
        return @($resp)
    } catch {
        $code = ''
        try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { }
        if ($code -eq 503) { throw "crt.sh is overloaded (HTTP 503)" }
        throw $_.Exception.Message
    }
}

function Read-CrtshDomains {
    <# Convert crt.sh entries into (domain, cert_id, not_before) tuples, filtered by time window. #>
    param(
        [AllowEmptyCollection()][object[]]$Entries,
        [int]$WindowMinutes = 1440
    )

    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Entries -or $Entries.Count -eq 0) { return $out }

    $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-1 * [Math]::Max(1, $WindowMinutes))

    foreach ($e in $Entries) {
        if (-not $e) { continue }
        $id = "$($e.id)"
        $nbStr = "$($e.not_before)"

        # filter by not_before window (avoid flooding on first run)
        $within = $false
        try {
            if ($nbStr) {
                $nb = [datetime]::Parse($nbStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                if ($nb -ge $cutoff) { $within = $true }
            }
        } catch { $within = $false }

        # entries without a parsable date still count (better to alert than to miss)
        if (-not $within -and $nbStr -and $nbStr -ne '') { continue }

        $names = @()
        if ($e.name_value) { $names += @("$($e.name_value)" -split "`n") }
        if ($e.common_name) { $names += @("$($e.common_name)") }

        $uniq = @{}
        foreach ($n in $names) {
            $d = ConvertTo-CtNormalDomain $n
            if ($d -and -not $uniq.ContainsKey($d)) { $uniq[$d] = $true }
        }
        foreach ($d in $uniq.Keys) {
            $out.Add([pscustomobject]@{ Domain = $d; CertId = $id })
        }
    }
    return $out
}

# ============================================================================
#  NETWORK BYPASS ENGINE (v2.2) - proxy + DNS-over-HTTPS + alt-source failover
#  Keeps crt.sh / certstream reachable when the VPN is off or the ISP blocks
#  CT sites:  direct -> proxy -> DoH-resolved curl -> certspotter fallback.
# ============================================================================

function Get-CtEffectiveProxy {
    <# Resolve the effective HTTP(S)/SOCKS proxy. Priority: process env
       (HTTPS_PROXY > ALL_PROXY > HTTP_PROXY) > config net_proxy. Returns
       @{ Url; Source } or $null when no proxy is configured. #>
    param([object]$Config = $null)

    $envKeys = @('HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'HTTP_PROXY', 'http_proxy')
    foreach ($k in $envKeys) {
        $v = $null
        try { $v = [Environment]::GetEnvironmentVariable($k) } catch { }
        if (-not [string]::IsNullOrWhiteSpace("$v")) { return @{ Url = "$v".Trim(); Source = "env:$k" } }
    }
    if ($Config -and -not [string]::IsNullOrWhiteSpace("$($Config.net_proxy)")) {
        return @{ Url = "$($Config.net_proxy)".Trim(); Source = 'config' }
    }
    return $null
}

function Test-CtCurlAvailable {
    <# True when a real curl binary is callable (curl.exe on Windows - NOT the
       PowerShell curl alias - or curl on Linux/macOS). #>
    try {
        $c = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
        if ($c) { return $true }
    } catch { }
    if (-not $Script:IsWindowsPS) {
        try {
            $c = Get-Command 'curl' -ErrorAction SilentlyContinue
            if ($c) { return $true }
        } catch { }
    }
    return $false
}

function Test-CtCertstreamFallbackDue {
    <# Pure helper: true when the real-time feed produced no data for $Minutes. #>
    param(
        [Parameter(Mandatory = $true)][datetime]$Now,
        [Parameter(Mandatory = $true)][datetime]$LastDataUtc,
        [int]$Minutes = 0
    )
    if ($Minutes -le 0) { return $false }
    try { return (($Now - $LastDataUtc).TotalMinutes -ge $Minutes) } catch { return $false }
}

function Get-CtHttpErrorBody {
    <# Best-effort extraction of an HTTP error response body from an
       Invoke-RestMethod/WebRequest exception. Returns '' when unavailable. #>
    param([Parameter(Mandatory = $true)][object]$ErrorRecord)
    try {
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            return ([string]$ErrorRecord.ErrorDetails.Message).Trim()
        }
    } catch { }
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($resp) {
            $rs = $resp.GetResponseStream()
            if ($rs) {
                $sr = New-Object System.IO.StreamReader($rs)
                return $sr.ReadToEnd().Trim()
            }
        }
    } catch { }
    return ''
}

function Get-CtCertspotterHint {
    <# Pure helper: turn a certspotter failure (status text + optional response body)
       into an actionable message. Unit-tested by -SelfTest. #>
    param([string]$StatusText = '', [string]$Body = '')

    $msg = "$StatusText".Trim()
    if (-not $msg) { $msg = 'request failed' }
    try {
        if ($Body -match '"message"\s*:\s*"([^"]+)"') { $msg = $Matches[1] }
        elseif ($Body -match '"code"\s*:\s*"([^"]+)"') { $msg = "$($Matches[1]) (certspotter)" }
    } catch { }
    if ($msg -match 'not_allowed_by_plan|not beneath an eTLD') {
        $msg += ' - this is a shared/platform domain that the certspotter free plan refuses; monitor a normal registered domain, or use the real-time feed instead: CTMon.ps1 -Target <domain> (certstream)'
    }
    return $msg
}

function Invoke-CtCurlGet {
    <# Fetch a URL with the real curl binary. Used for SOCKS proxies on Windows
       PowerShell 5.1 and for --resolve DNS-bypass requests. Returns the raw body. #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$ProxyUrl = '',
        [int]$TimeoutSec = 60,
        [string]$ResolveIp = ''
    )

    $exe = $null
    try { $exe = (Get-Command 'curl.exe' -ErrorAction SilentlyContinue).Source } catch { }
    if (-not $exe -and -not $Script:IsWindowsPS) {
        try { $exe = (Get-Command 'curl' -ErrorAction SilentlyContinue).Source } catch { }
    }
    if (-not $exe) { throw 'curl executable not found (needed for socks proxy / dns-bypass requests)' }

    $argList = @('-sS', '-f', '--max-time', "$TimeoutSec", '-A', "CTMon/$Script:CTMonVersion", '-L')
    if ($ProxyUrl) { $argList += @('--proxy', $ProxyUrl) }
    if ($ResolveIp) {
        $hostName = ([Uri]$Uri).Host
        $port = ([Uri]$Uri).Port
        if ($port -le 0) { if ($Uri.StartsWith('https')) { $port = 443 } else { $port = 80 } }
        $argList += @('--resolve', "${hostName}:${port}:${ResolveIp}")
    }
    $argList += $Uri

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = ($argList -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    try { $proc.WaitForExit($TimeoutSec * 1000 + 5000) | Out-Null } catch { }
    if ($proc.ExitCode -ne 0) {
        $reason = $stderr.Trim()
        if (-not $reason) { $reason = "curl exit code $($proc.ExitCode)" }
        if ($proc.ExitCode -eq 22) { $reason = "target returned an HTTP error status ($reason)" }
        throw $reason
    }
    return $stdout
}

function Invoke-CtHttpGet {
    <# Central HTTP GET used by every network feature. Applies the effective proxy
       (http/https via Invoke-RestMethod, socks* via curl when needed). Returns the
       parsed JSON (or raw text with -AsText). Throws on failure. #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [object]$Proxy = $null,
        [int]$TimeoutSec = 60,
        [string]$Accept = 'application/json',
        [switch]$AsText
    )

    if ($PSVersionTable.PSVersion.Major -lt 6) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch { }
    }

    $useCurl = $false
    $curlProxy = ''
    if ($Proxy -and -not [string]::IsNullOrWhiteSpace("$($Proxy.Url)")) {
        $scheme = ''
        try { $scheme = ([Uri]$Proxy.Url).Scheme.ToLowerInvariant() } catch { }
        if ($scheme -eq 'http' -or $scheme -eq 'https') {
            $curlProxy = $Proxy.Url
        }
        elseif ($scheme.StartsWith('socks')) {
            # socks4/5: PS7's HttpClient usually copes; Windows PowerShell 5.1 needs curl.exe
            if ($PSVersionTable.PSVersion.Major -ge 6 -and -not (Test-CtCurlAvailable)) {
                $curlProxy = $Proxy.Url   # let PS7 try natively
            }
            else {
                $useCurl = $true
                $curlProxy = $Proxy.Url
            }
        }
        else {
            throw "unsupported proxy scheme '$scheme' in $($Proxy.Url)"
        }
    }

    if ($useCurl) {
        $body = Invoke-CtCurlGet -Uri $Uri -ProxyUrl $curlProxy -TimeoutSec $TimeoutSec
        if ($AsText) { return $body }
        try { return ($body | ConvertFrom-Json) } catch { throw "curl returned non-JSON response ($($_.Exception.Message))" }
    }

    $invokeParams = @{
        Uri        = $Uri
        Method     = 'Get'
        TimeoutSec = $TimeoutSec
        Headers    = @{ 'User-Agent' = "CTMon/$Script:CTMonVersion (CT-log monitor)"; 'Accept' = $Accept }
    }
    if ($curlProxy) { $invokeParams['Proxy'] = $curlProxy }

    $resp = Invoke-RestMethod @invokeParams
    return $resp
}

function Get-CtDohIpFromResponse {
    <# Pure helper: extract the first A-record IP from a DoH JSON response. #>
    param([object]$Response)
    if ($null -eq $Response) { return '' }
    try {
        $answers = $Response.Answer
        if (-not $answers) { return '' }
        foreach ($a in @($answers)) {
            if ("$($a.type)" -eq '1' -and "$($a.data)" -match '^\d{1,3}(\.\d{1,3}){3}$') {
                return "$($a.data)"
            }
        }
    } catch { }
    return ''
}

function Resolve-CtDoh {
    <# DNS-over-HTTPS A-record lookup that never touches the local resolver
       (defeats DNS poisoning / ISP hijacking of CT sites). Providers are queried
       by IP so the lookup itself cannot be poisoned. Returns '' on failure. #>
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Provider = 'cloudflare',
        [int]$TimeoutSec = 8,
        [object]$Proxy = $null
    )

    $name = $Name.Trim().ToLowerInvariant()
    if (-not $name) { return '' }

    $enc = [Uri]::EscapeDataString($name)
    $epCloudflare = @{ Uri = "https://1.1.1.1/dns-query?name=$enc&type=A"; Accept = 'application/dns-json' }
    $epGoogle     = @{ Uri = "https://8.8.8.8/resolve?name=$enc&type=A"; Accept = 'application/dns-json' }
    $epQuad9      = @{ Uri = "https://9.9.9.9:5053/dns-query?name=$enc&type=A"; Accept = 'application/dns-json' }
    $epAdguard    = @{ Uri = "https://94.140.14.14/resolve?name=$enc&type=A"; Accept = 'application/dns-json' }

    $endpoints = @()
    if ($Provider -eq 'google')      { $endpoints += $epGoogle }
    elseif ($Provider -eq 'quad9')   { $endpoints += $epQuad9 }
    elseif ($Provider -eq 'adguard') { $endpoints += $epAdguard }
    elseif ($Provider -eq 'auto')    { $endpoints += @($epCloudflare, $epGoogle, $epQuad9, $epAdguard) }
    else                             { $endpoints += $epCloudflare }

    foreach ($ep in $endpoints) {
        try {
            $resp = Invoke-CtHttpGet -Uri $ep.Uri -Proxy $Proxy -TimeoutSec $TimeoutSec -Accept $ep.Accept
            $ip = Get-CtDohIpFromResponse -Response $resp
            if ($ip) { return $ip }
        } catch { }
    }
    return ''
}

# ============================================================================
#  CERTSPOTTER SOURCE (v2.2) - alternative CT log API (crt.sh failover)
#  Free tier works without a token (rate limited); CERTSPOTTER_TOKEN raises it.
# ============================================================================

function Get-CertspotterEntries {
    <# Query the Cert Spotter v1 issuances API for a domain (subdomains included). #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [object]$Proxy = $null,
        [int]$TimeoutSec = 60
    )

    $uri = "https://api.certspotter.com/v1/issuances?domain=$([Uri]::EscapeDataString($Domain))&include_subdomains=true&expand=dns_names"
    $token = ''
    try { $token = [Environment]::GetEnvironmentVariable('CERTSPOTTER_TOKEN') } catch { }
    if ([string]::IsNullOrWhiteSpace($token) -and $Script:CtCertspotterToken) { $token = $Script:CtCertspotterToken }

    $resp = Invoke-CtHttpGet -Uri $uri -Proxy $Proxy -TimeoutSec $TimeoutSec -Accept 'application/json'
    if ($null -eq $resp) { return @() }
    return @($resp)
}

function Read-CertspotterDomains {
    <# Convert Cert Spotter issuances into (domain, cert_id) tuples with the same
       time-window filter used for crt.sh entries. #>
    param(
        [AllowEmptyCollection()][object[]]$Entries,
        [int]$WindowMinutes = 1440
    )

    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Entries -or $Entries.Count -eq 0) { return $out }

    $cutoff = (Get-Date).ToUniversalTime().AddMinutes(-1 * [Math]::Max(1, $WindowMinutes))

    foreach ($e in $Entries) {
        if (-not $e) { continue }
        $id = "$($e.id)"
        $nbStr = "$($e.not_before)"

        $within = $true
        if ($nbStr -and $nbStr -ne '') {
            $within = $false
            try {
                $nb = [datetime]::Parse($nbStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                if ($nb -ge $cutoff) { $within = $true }
            } catch { $within = $true }
        }
        if (-not $within) { continue }

        $names = @()
        if ($e.dns_names) { foreach ($dnCs in @($e.dns_names)) { $names += @("$dnCs") } }
        if ($e.common_name -and "$($e.common_name)" -ne '') { $names += @("$($e.common_name)") }

        $uniq = @{}
        foreach ($n in $names) {
            $d = ConvertTo-CtNormalDomain $n
            if ($d -and -not $uniq.ContainsKey($d)) { $uniq[$d] = $true }
        }
        foreach ($d in $uniq.Keys) {
            $out.Add([pscustomobject]@{ Domain = $d; CertId = $id })
        }
    }
    return $out
}

function Invoke-CtCrtshChain {
    <# The v2.2 bypass chain for one polling round:
         1) crt.sh via the effective proxy (direct when none configured)
         2) crt.sh via curl + DoH-resolved IP (defeats DNS blocking)
         3) Cert Spotter as an alternative CT source
       Returns @{ Entries; Source; Bypass } - Bypass is '' on the happy path or a
       short tag (e.g. 'proxy', 'doh:1.2.3.4', 'alt-source') describing the detour.
       Throws only when every path failed. #>
    param(
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][hashtable]$Runtime
    )

    $errors = @()
    $proxy = Get-CtEffectiveProxy -Config $Runtime.Config
    $bypassUsed = ''

    if ($proxy) { $bypassUsed = 'proxy' }

    # ---- path 1: crt.sh (direct or via proxy) with one patient retry on overload ----
    $crtshAttempt = 0
    while ($true) {
        $crtshAttempt++
        try {
            $e = Get-CrtshEntries -Target $Target -BaseUrl $Runtime.CrtshBaseUrl -Proxy $proxy -TimeoutSec $Runtime.CrtshTimeoutSec
            if ($crtshAttempt -gt 1) { Write-CtLog "crt.sh recovered on retry $crtshAttempt for ${Target}" -Level OK }
            return @{ Entries = $e; Source = 'crtsh'; Bypass = $bypassUsed }
        } catch {
            $errTxt = "$($_.Exception.Message)"
            if (($errTxt -match '50[23]') -and ($crtshAttempt -eq 1)) {
                Write-CtLog "crt.sh is overloaded (502/503); waiting 20 s, then retrying once before falling back" -Level WARN
                Start-Sleep -Seconds 20
                continue
            }
            $errors += "crtsh: $errTxt"
            Write-CtLog "bypass path 1 failed (direct/proxy): $errTxt" -Level DEBUG
            break
        }
    }

    if (-not $Runtime.NetBypass) { throw ($errors -join ' | ') }

    # ---- path 2: DoH + curl --resolve (DNS poisoning / ISP block bypass) ----
    $dohIp = ''
    if ($Runtime.DohEnabled) {
        $dohIp = Resolve-CtDoh -Name 'crt.sh' -Provider $Runtime.DohProvider -Proxy $proxy
    }
    if ($dohIp -and (Test-CtCurlAvailable)) {
        try {
            $raw = Invoke-CtCurlGet -Uri "$($Runtime.CrtshBaseUrl)/?q=%25.$Target&output=json&exclude=expired" -ProxyUrl "$($proxy.Url)" -TimeoutSec $Runtime.CrtshTimeoutSec -ResolveIp $dohIp
            $e = $raw | ConvertFrom-Json
            if ($null -eq $e) { $e = @() }
            return @{ Entries = @($e); Source = 'crtsh'; Bypass = "doh:$dohIp" }
        } catch {
            $errors += "crtsh+doh: $($_.Exception.Message)"
            Write-CtLog "bypass path 2 failed (doh+curl): $($_.Exception.Message)" -Level DEBUG
        }
    }
    else {
        Write-CtLog 'bypass path 2 skipped: doh disabled or no A record via doh or curl.exe unavailable' -Level DEBUG
    }

    # ---- path 3: Cert Spotter alternative source ----
    try {
        $e = Get-CertspotterEntries -Domain $Target -Proxy $proxy
        return @{ Entries = $e; Source = 'certspotter'; Bypass = 'alt-source' }
    } catch {
        $csBody = Get-CtHttpErrorBody -ErrorRecord $_
        $csMsg = Get-CtCertspotterHint -StatusText "$($_.Exception.Message)" -Body $csBody
        if ($csMsg -match '429') { $csMsg += ' (rate limited - set CERTSPOTTER_TOKEN in .env for a higher limit)' }
        $errors += "certspotter: $csMsg"
        Write-CtLog "bypass path 3 failed (certspotter): $csMsg" -Level DEBUG
    }

    throw ($errors -join ' | ')
}


# ============================================================================
#  RISK SCORING (v2.2) - severity per match: low / medium / high / critical
#  Signals: wildcard SAN, brand keyword, suspicious terms, unresolved DNS,
#  deep subdomain nesting. Powers badges in alerts, feed and dashboard.
# ============================================================================

$Script:CtSuspiciousTerms = @(
    'login', 'signin', 'sign-in', 'verify', 'secure', 'security', 'account',
    'update', 'billing', 'payment', 'invoice', 'confirm', 'alert', 'support',
    'webmail', 'mailbox', 'auth', 'sso', 'passport', 'wallet', 'recover',
    'unlock', 'reset', 'office', 'outlook', 'microsoft', 'apple', 'icloud',
    'paypal', 'netflix', 'amazon', 'facebook', 'instagram', 'telegram',
    'bank', 'banca', 'client', 'customer', 'portal', 'admin', 'vpn',
    'dev', 'test', 'stage', 'staging', 'uat', 'beta', 'backup', 'old'
)

function Get-CtRiskScore {
    <# Pure scoring function - no I/O. Returns
       @{ Score = int; Level = 'low|medium|high|critical'; Reasons = string[] }
       so it can be unit-tested by -SelfTest. #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [string]$Dns = '',
        [string]$Keyword = ''
    )

    $score = 0
    $reasons = @()

    $isWildcard = $Domain.StartsWith('*.')
    $clean = ConvertTo-CtNormalDomain $Domain
    if (-not $clean) { $clean = $Domain.ToLowerInvariant() }

    if ($isWildcard) {
        $score += 2
        $reasons += 'wildcard SAN entry'
    }

    if (-not [string]::IsNullOrWhiteSpace($Keyword)) {
        $score += 4
        $reasons += "brand keyword '$Keyword'"
    }

    $lower = $clean.ToLowerInvariant()
    foreach ($t in $Script:CtSuspiciousTerms) {
        if ($lower.Contains($t)) {
            $score += 3
            $reasons += "suspicious term '$t'"
            break   # one hit is enough signal, avoid reason spam
        }
    }

    if ([string]::IsNullOrWhiteSpace($Dns)) {
        $score += 2
        $reasons += 'no DNS record (parked / not yet live)'
    }

    $labels = ($clean -split '\.')
    if ($labels.Count -ge 4) {
        $score += 1
        $reasons += "deep subdomain ($($labels.Count) labels)"
    }

    $level = 'low'
    if ($score -ge 7)      { $level = 'critical' }
    elseif ($score -ge 4)  { $level = 'high' }
    elseif ($score -ge 2)  { $level = 'medium' }

    return [pscustomobject]@{ Score = $score; Level = $level; Reasons = @($reasons) }
}

function Get-CtSeverityColor {
    <# Map a severity level to a console color. #>
    param([string]$Level)
    switch ($Level) {
        'critical' { return 'Red' }
        'high'     { return 'Red' }
        'medium'   { return 'Yellow' }
        default    { return 'DarkGray' }
    }
}

function Get-CtSeverityWeight {
    <# Numeric weight used for sorting / max computations. #>
    param([string]$Level)
    switch ($Level) {
        'critical' { return 4 }
        'high'     { return 3 }
        'medium'   { return 2 }
        'low'      { return 1 }
        default    { return 0 }
    }
}


# ============================================================================
#  SHARED MATCH PIPELINE (v2: dns enrichment + history + dashboard feed)
# ============================================================================
function Invoke-CtMatchPipeline {
    <# Handle one candidate domain: de-dup, match, enrich, risk-score, record, buffer, dashboard. #>
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][hashtable]$Runtime,
        [Parameter(Mandatory = $true)][object]$Match   # result of Test-CtMatch
    )

    $group = $Match.Target
    if (-not $group) { $group = "keyword: $($Match.Keyword)" }

    # DNS enrichment (Sublert-style working-subdomain check, cached)
    $dnsInfo = ''
    if ($Runtime.EnrichDns) {
        $dnsInfo = Resolve-CtHostCached -Domain $Domain -Cache $Runtime.DnsCache -TimeoutMs $Runtime.DnsTimeoutMs
    }

    # v2.2 risk scoring (wildcard / keyword / suspicious terms / unresolved / depth)
    $risk = Get-CtRiskScore -Domain $Domain -Dns $dnsInfo -Keyword "$($Match.Keyword)"

    Add-CtAlert -Group $group -Domain $Domain -Dns $dnsInfo -Severity $risk.Level -Score $risk.Score -Keyword "$($Match.Keyword)" -Reasons $risk.Reasons
    Add-CtStat -Target $group
    Add-CtMatchRecord -Domain $Domain -Group $group -Keyword "$($Match.Keyword)" -Source $Runtime.SourceName -Dns $dnsInfo -AlertEnabled $Script:NotificationsEnabled -MaxRecords $Runtime.MatchesMax -Severity $risk.Level -Score $risk.Score -Reasons $risk.Reasons
    Add-CtDashMatch -Domain $Domain -Group $group -Source $Runtime.SourceName -Dns $dnsInfo -Keyword "$($Match.Keyword)" -Severity $risk.Level -Score $risk.Score
    Write-CtDashboardData   # throttled internally (>= 5s between writes)
    Write-CtLog "new subdomain domain=$Domain target=$group risk=$($risk.Level)/$($risk.Score)$(if ($dnsInfo) { " dns=$dnsInfo" })" -Level MATCH
}

# ============================================================================
#  MONITOR LOOPS
# ============================================================================
function Invoke-CtMonitorCertstream {
    <#
        Main real-time loop: connect -> receive -> match -> buffer -> flush.
        Handles reconnection with exponential backoff and rotates through certstream_urls.
    #>
    param([Parameter(Mandatory = $true)][hashtable]$Runtime)

    $cfg          = $Runtime.Config
    $targets      = $Runtime.Targets
    $keywords     = $Runtime.Keywords
    $exclude      = $Runtime.ExcludeRegex
    $seenStore    = $Runtime.SeenStore
    $urls         = $Runtime.CertstreamUrls
    $wsProxy      = Get-CtEffectiveProxy -Config $cfg
    $lastDataUtc  = (Get-Date)   # for the auto-fallback timer
    $flushSeconds = $Runtime.FlushIntervalSeconds
    $batchMax     = $Runtime.BatchMaxDomains

    $urlIndex    = 0
    $backoff     = 1
    $lastFlush   = (Get-Date)
    $lastSave    = (Get-Date)
    $lastBeat    = (Get-Date)
    $deadline    = $null
    $recvCts     = $null
    $silentCount = 0
    $silentMs    = 90000
    if ($Runtime.SilentTimeoutSeconds -gt 0) { $silentMs = [int]($Runtime.SilentTimeoutSeconds * 1000) }
    if ($Script:MaxRuntimeSeconds -gt 0) { $deadline = (Get-Date).AddSeconds($Script:MaxRuntimeSeconds) }

    while ($true) {
        # v2.2.3: if the feed has been dead for too long, switch to crt.sh polling
        if (($Runtime.CertstreamFallbackMinutes -gt 0) -and
            (Test-CtCertstreamFallbackDue -Now (Get-Date) -LastDataUtc $lastDataUtc -Minutes $Runtime.CertstreamFallbackMinutes)) {
            Write-CtLog "no certstream data for $([int]$Runtime.CertstreamFallbackMinutes) minute(s) - auto-switching to crt.sh polling mode (restart CTMon to retry the real-time feed)" -Level WARN
            Add-CtDashEvent -Level 'WARN' -Message 'certstream unreachable - auto-switched to crt.sh polling mode'
            Send-CtFlush -Config $cfg -BatchMax $batchMax -NotifyMode $Runtime.NotifyMode
            Save-CtSeen -Store $seenStore
            Save-CtDnsCache -Cache $Runtime.DnsCache
            Save-CtState
            Invoke-CtMonitorCrtsh -Runtime $Runtime
            return
        }

        $url = $urls[$urlIndex % $urls.Count]
        Write-CtLog "connecting to certstream url=$url" -Level INFO

        $ws = $null
        try {
            $ws = Connect-CtCertstream -Url $url -Proxy $wsProxy
            $backoff = 1
            $Script:Stats.source = 'certstream'
            $Runtime.SourceName = 'certstream'
            Write-CtLog 'certstream server is ready' -Level OK
            Write-CtLog "starting ctmon targets=$($targets.Count) notify=$($Runtime.NotifyMode) source=certstream" -Level INFO

            while ($true) {
                # deadline check on every iteration (heartbeats loop back here)
                if ($deadline -and (Get-Date) -ge $deadline) {
                    Write-CtLog "max runtime reached ($($Script:MaxRuntimeSeconds)s); stopping" -Level INFO
                    Send-CtFlush -Config $cfg -BatchMax $batchMax -NotifyMode $Runtime.NotifyMode
                    Save-CtSeen -Store $seenStore
                    Save-CtDnsCache -Cache $Runtime.DnsCache
                    Save-CtState
                    Write-CtDashboardData -Force
                    return
                }

                # (re)arm the receive watchdog: silent-feed timeout + max-runtime deadline
                try { if ($recvCts) { $recvCts.Dispose() } } catch { }
                $recvCts = New-Object System.Threading.CancellationTokenSource
                $recvCts.CancelAfter($silentMs)
                if ($deadline) {
                    $remainMs = [int][Math]::Floor((($deadline) - (Get-Date)).TotalMilliseconds)
                    if ($remainMs -lt 0) { $remainMs = 0 }
                    if ($remainMs -lt $silentMs) { $recvCts.CancelAfter($remainMs) }
                }
                $ct = $recvCts.Token

                $raw = Receive-CtCertstreamMessage -Ws $ws -Token $ct
                if ($null -eq $raw) {
                    Write-CtLog 'certstream closed the connection' -Level WARN
                    break
                }
                $silentCount = 0
                $lastDataUtc = (Get-Date)

                $domains = Read-CtCertDomains -Json $raw
                if ($null -eq $domains) { continue }   # heartbeat / other message types

                $Script:Stats.certs_seen++
                $Script:Stats.domains_seen += $domains.Count

                foreach ($dom in $domains) {
                    $clean = ConvertTo-CtNormalDomain $dom
                    if (-not $clean) { continue }
                    if (Test-CtSeen -Store $seenStore -Key $clean) { continue }

                    $m = Test-CtMatch -Domain $clean -Targets $targets -Keywords $keywords -ExcludeRegex $exclude -IncludeWildcards $Runtime.IncludeWildcards
                    if ($null -eq $m) { continue }

                    Invoke-CtMatchPipeline -Domain $clean -Runtime $Runtime -Match $m
                }

                # periodic flush (time-based, like the original's instant alerts but batched)
                if (((Get-Date) - $lastFlush).TotalSeconds -ge $flushSeconds -or (Get-CtBufferedCount) -ge ($batchMax * 2)) {
                    Send-CtFlush -Config $cfg -BatchMax $batchMax -NotifyMode $Runtime.NotifyMode
                    $lastFlush = (Get-Date)
                }

                # periodic persistence
                if (((Get-Date) - $lastSave).TotalSeconds -ge 60) {
                    Save-CtSeen -Store $seenStore
                    Save-CtDnsCache -Cache $Runtime.DnsCache
                    Save-CtState
                    Write-CtDashboardData -Force
                    $lastSave = (Get-Date)

                    # weekly digest check (v2.2; the rule itself is cheap date math)
                    if ($Runtime.DigestEnabled -and -not $Script:DryRun) {
                        try {
                            if (Test-CtDigestDue -Now (Get-Date) -LastSentUtc $Script:DigestLastUtc -Weekday $Runtime.DigestWeekday -Hour $Runtime.DigestHour) {
                                Write-CtLog 'weekly digest due - sending' -Level INFO
                                $digestOk = Invoke-CtDigestSend -Config $cfg -NotifyMode $Runtime.NotifyMode -Days $Runtime.DigestDays
                                if ($digestOk) {
                                    $Script:DigestLastUtc = (Get-Date).ToUniversalTime().ToString('o')
                                    Save-CtState
                                }
                            }
                        } catch { }
                    }
                }

                # heartbeat (proves 24/7 instance is alive)
                if ($Runtime.HeartbeatHours -gt 0 -and ((Get-Date) - $lastBeat).TotalHours -ge $Runtime.HeartbeatHours) {
                    $up = Get-CtUptimeText -Start $Script:Stats.started
                    if ($Runtime.NotifyMode -eq 'telegram' -and -not $Script:DryRun) {
                        $null = Send-CtTelegram -Token $cfg.telegram_bot_token -ChatId $cfg.telegram_chat_id -ApiBase $cfg.telegram_api_base -Text "$($Script:EmojiGreen) <b>CTMon heartbeat</b>`nuptime: $up | certs: $($Script:Stats.certs_seen) | matched: $($Script:Stats.matched) | sent: $($Script:Stats.notifications)"
                    }
                    Write-CtLog "heartbeat uptime=$up matched=$($Script:Stats.matched)" -Level INFO
                    $lastBeat = (Get-Date)
                }
            }
        } catch [System.OperationCanceledException] {
            if ($deadline -and (Get-Date) -ge $deadline) {
                Write-CtLog "max runtime reached ($($Script:MaxRuntimeSeconds)s); stopping" -Level INFO
                Send-CtFlush -Config $cfg -BatchMax $batchMax -NotifyMode $Runtime.NotifyMode
                Save-CtSeen -Store $seenStore
                Save-CtDnsCache -Cache $Runtime.DnsCache
                Save-CtState
                Write-CtDashboardData -Force
                return
            }
            $silentCount++
            Write-CtLog "no data received from feed in $($Runtime.SilentTimeoutSeconds)s (feed stalled?)" -Level WARN
            if ($silentCount -eq 3) {
                Write-CtLog 'all certstream feeds appear silent. options:' -Level WARN
                Write-CtLog '  1) run a local certstream server in docker (like the original crtmon):' -Level WARN
                Write-CtLog '     docker run -d --name certstream -p 8888:8888 ghcr.io/tinker-security/certstream-server-go:latest' -Level WARN
                Write-CtLog '     then add "ws://127.0.0.1:8888/" to certstream_urls in the config' -Level WARN
                Write-CtLog '  2) switch to crt.sh polling mode:  CTMon.ps1 -Source crtsh' -Level WARN
            }
        } catch {
            Write-CtLog "certstream error: $($_.Exception.Message)" -Level ERROR
        } finally {
            if ($recvCts) { try { $recvCts.Dispose() } catch { } ; $recvCts = $null }
            if ($ws) {
                try { $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'bye', [System.Threading.CancellationToken]::None).GetAwaiter().GetResult() | Out-Null } catch { }
                try { $ws.Dispose() } catch { }
            }
        }

        # flush whatever we have before sleeping
        Send-CtFlush -Config $cfg -BatchMax $batchMax -NotifyMode $Runtime.NotifyMode
        Save-CtSeen -Store $seenStore
        Save-CtDnsCache -Cache $Runtime.DnsCache
        Save-CtState
        Write-CtDashboardData -Force

        $urlIndex++
        $Script:Stats.reconnects++
        $wait = [Math]::Min($backoff, 120)
        Write-CtLog "reconnecting in $wait s (attempt $($Script:Stats.reconnects))" -Level WARN
        $backoff = $backoff * 2

        # sleep in small slices so Ctrl+C stays responsive and deadline still applies
        $sleepEnd = (Get-Date).AddSeconds($wait)
        while ((Get-Date) -lt $sleepEnd) {
            if ($deadline -and (Get-Date) -ge $deadline) { return }
            Start-Sleep -Milliseconds 250
        }
    }
}

function Invoke-CtMonitorCrtsh {
    <# Polling loop over crt.sh - the resilient fallback when WSS is blocked/unstable.
       v2.2: every round goes through the bypass chain (proxy -> DoH+curl ->
       certspotter). Bypass engagements are logged and shown in the dashboard. #>
    param([Parameter(Mandatory = $true)][hashtable]$Runtime)

    $cfg       = $Runtime.Config
    $targets   = $Runtime.Targets
    $keywords  = $Runtime.Keywords
    $exclude   = $Runtime.ExcludeRegex
    $seenStore = $Runtime.SeenStore
    $interval  = $Runtime.CrtshIntervalSeconds
    $window    = $Runtime.CrtshWindowMinutes
    $batchMax  = $Runtime.BatchMaxDomains

    $certIds  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $lastFlush = (Get-Date)
    $lastSave  = (Get-Date)
    $lastBeat  = (Get-Date)
    $lastDigestCheck = (Get-Date)
    $deadline  = $null
    if ($Script:MaxRuntimeSeconds -gt 0) { $deadline = (Get-Date).AddSeconds($Script:MaxRuntimeSeconds) }

    $startSource = $Runtime.PollSource
    if ([string]::IsNullOrWhiteSpace($startSource)) { $startSource = 'crtsh' }
    $Script:Stats.source = $startSource
    $Runtime.SourceName = $startSource
    Write-CtLog "starting ctmon targets=$($targets.Count) notify=$($Runtime.NotifyMode) source=$startSource interval=${interval}s window=${window}m" -Level INFO
    if ($Runtime.NetBypass) { Write-CtLog 'net bypass enabled: proxy -> doh -> certspotter failover when crt.sh is unreachable' -Level INFO }

    while ($true) {
        foreach ($t in $targets) {
            if ($deadline -and (Get-Date) -ge $deadline) {
                Write-CtLog "max runtime reached ($($Script:MaxRuntimeSeconds)s); stopping" -Level INFO
                Send-CtFlush -Config $cfg -BatchMax $batchMax -NotifyMode $Runtime.NotifyMode
                Save-CtSeen -Store $seenStore
                Save-CtDnsCache -Cache $Runtime.DnsCache
                Save-CtState
                Write-CtDashboardData -Force
                return
            }

            # ---- fetch through the v2.2 bypass chain ----
            $entries = @()
            $fetchSource = $startSource
            $pollSource = $startSource
            if ($pollSource -eq 'certspotter') {
                try {
                    $proxy = Get-CtEffectiveProxy -Config $cfg
                    $entries = Get-CertspotterEntries -Domain $t -Proxy $proxy -TimeoutSec $Runtime.CrtshTimeoutSec
                } catch {
                    Write-CtLog "certspotter query failed for ${t}: $($_.Exception.Message)" -Level WARN
                    $entries = @()
                }
            }
            else {
                try {
                    $fetched = Invoke-CtCrtshChain -Target $t -Runtime $Runtime
                    $entries = $fetched.Entries
                    $fetchSource = $fetched.Source
                    if ($fetched.Bypass) {
                        $Script:Stats.bypass_count++
                        Write-CtLog "bypass engaged target=$t via $($fetched.Bypass) (primary path failed)" -Level WARN
                        Write-CtLog "continuing with source=$fetchSource for this round" -Level INFO
                    }
                } catch {
                    $allMsg = "$($_.Exception.Message)"
                    Write-CtLog "all sources failed for ${t}: $allMsg" -Level WARN
                    if ($allMsg -match 'not_allowed_by_plan|not beneath an eTLD') {
                        Write-CtLog "hint: '${t}' is a shared/platform domain - polling APIs refuse it. use the real-time feed:  CTMon.ps1 -Target ${t}  (certstream)" -Level WARN
                    } elseif ($allMsg -match '50[23]') {
                        Write-CtLog "hint: crt.sh is overloaded for this heavy query; CTMon retries next cycle - or switch to the real-time feed:  CTMon.ps1 -Target ${t}  (certstream)" -Level WARN
                    }
                    $entries = @()
                }
            }
            $Runtime.SourceName = $fetchSource
            $Script:Stats.source = $fetchSource
            $Script:Stats.certs_seen += $entries.Count
            $Script:Stats.last_poll_utc = (Get-Date).ToUniversalTime().ToString('o')
            $Script:Stats.last_poll_source = $fetchSource
            $Script:Stats.last_poll_entries = $entries.Count

            if ($fetchSource -eq 'certspotter') {
                $rows = Read-CertspotterDomains -Entries $entries -WindowMinutes $window
            } else {
                $rows = Read-CrtshDomains -Entries $entries -WindowMinutes $window
            }
            if ($entries.Count -gt 0 -and $rows.Count -eq 0) {
                Write-CtLog "target=${t}: $($entries.Count) cert(s) via $fetchSource, none issued within the last $window min window - feed stays quiet until a new certificate appears" -Level INFO
            }
            foreach ($row in $rows) {
                if ($row.CertId) { $null = $certIds.Add($row.CertId) }
                if (Test-CtSeen -Store $seenStore -Key $row.Domain) { continue }

                $m = Test-CtMatch -Domain $row.Domain -Targets $targets -Keywords $keywords -ExcludeRegex $exclude -IncludeWildcards $Runtime.IncludeWildcards
                if ($null -eq $m) { continue }

                Invoke-CtMatchPipeline -Domain $row.Domain -Runtime $Runtime -Match $m
            }

            # weekly digest check (cheap; the rule itself is date math)
            if ($Runtime.DigestEnabled -and ((Get-Date) - $lastDigestCheck).TotalMinutes -ge 15) {
                $lastDigestCheck = (Get-Date)
                try {
                    if (-not $Script:DryRun -and (Test-CtDigestDue -Now (Get-Date) -LastSentUtc $Script:DigestLastUtc -Weekday $Runtime.DigestWeekday -Hour $Runtime.DigestHour)) {
                        Write-CtLog 'weekly digest due - sending' -Level INFO
                        $digestOk = Invoke-CtDigestSend -Config $cfg -NotifyMode $Runtime.NotifyMode -Days $Runtime.DigestDays
                        if ($digestOk) {
                            $Script:DigestLastUtc = (Get-Date).ToUniversalTime().ToString('o')
                            Save-CtState
                        }
                    }
                } catch {
                    Write-CtLog "digest check failed: $($_.Exception.Message)" -Level DEBUG
                }
            }

            # be polite to the CT source: small delay between targets
            Start-Sleep -Seconds 2
        }

        if (((Get-Date) - $lastFlush).TotalSeconds -ge $Runtime.FlushIntervalSeconds) {
            Send-CtFlush -Config $cfg -BatchMax $batchMax -NotifyMode $Runtime.NotifyMode
            $lastFlush = (Get-Date)
        }
        if (((Get-Date) - $lastSave).TotalSeconds -ge 60) {
            Save-CtSeen -Store $seenStore
            Save-CtDnsCache -Cache $Runtime.DnsCache
            Save-CtState
            Write-CtDashboardData -Force
            $lastSave = (Get-Date)
        }
        if ($Runtime.HeartbeatHours -gt 0 -and ((Get-Date) - $lastBeat).TotalHours -ge $Runtime.HeartbeatHours) {
            $up = Get-CtUptimeText -Start $Script:Stats.started
            if ($Runtime.NotifyMode -eq 'telegram' -and -not $Script:DryRun) {
                $null = Send-CtTelegram -Token $cfg.telegram_bot_token -ChatId $cfg.telegram_chat_id -ApiBase $cfg.telegram_api_base -Text "$($Script:EmojiGreen) <b>CTMon heartbeat</b>`nuptime: $up | polls: $($Script:Stats.certs_seen) | matched: $($Script:Stats.matched) | sent: $($Script:Stats.notifications) | bypass: $($Script:Stats.bypass_count)"
            }
            Write-CtLog "heartbeat uptime=$up matched=$($Script:Stats.matched) bypass=$($Script:Stats.bypass_count)" -Level INFO
            $lastBeat = (Get-Date)
        }

        Write-CtLog "next poll in $interval s" -Level DEBUG
        $sleepEnd = (Get-Date).AddSeconds($interval)
        while ((Get-Date) -lt $sleepEnd) {
            if ($deadline -and (Get-Date) -ge $deadline) { return }
            Start-Sleep -Milliseconds 500
        }
    }
}


# ============================================================================
#  24/7 PERSISTENCE  (the PowerShell equivalent of "nohup ... &" + "@reboot cron")
# ============================================================================
function Get-CtPwshExecutable {
    <# Path of the PowerShell executable currently running this script. #>
    return (Get-Process -Id $PID).Path
}

function Test-CtTcpPortAvailable {
    <# Test whether the requested local bind address/port can be bound right now. #>
    param([int]$Port, [string]$Bind = '127.0.0.1')
    if ($Port -lt 1 -or $Port -gt 65535) { return $false }
    if ($Bind -eq 'localhost') { $Bind = '127.0.0.1' }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Bind, [ref]$ip)) { return $false }
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener($ip, $Port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($listener) { try { $listener.Stop() } catch { } }
    }
}

function Test-CtDashboardHealth {
    <# Validate that the endpoint is CTMon's own dashboard, not just any open TCP port. #>
    param(
        [int]$Port,
        [string]$Bind = '127.0.0.1',
        [int]$ExpectedPid = 0,
        [int]$TimeoutMs = 700,
        [switch]$PassThru
    )
    if ($Port -lt 1 -or $Port -gt 65535) { return $false }
    $hostAddress = $Bind
    if ([string]::IsNullOrWhiteSpace($hostAddress) -or $hostAddress -eq '0.0.0.0') { $hostAddress = '127.0.0.1' }
    if ($hostAddress -eq '::' -or $hostAddress -eq '[::]') { $hostAddress = '::1' }
    if ($hostAddress -eq 'localhost') { $hostAddress = '127.0.0.1' }
    if ($hostAddress.Contains(':') -and -not $hostAddress.StartsWith('[')) { $hostAddress = '[' + $hostAddress + ']' }
    $request = $null
    $response = $null
    $reader = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create("http://${hostAddress}:$Port/api/health")
        $request.Method = 'GET'
        $request.Timeout = $TimeoutMs
        $request.ReadWriteTimeout = $TimeoutMs
        $request.Proxy = $null
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $body = $reader.ReadToEnd()
        $health = $body | ConvertFrom-Json
        # Accept older CTMon versions too, so an upgrade does not mistake the old
        # server for an unrelated process and spawn another dashboard on the next port.
        if ($health.status -ne 'ok' -or [string]::IsNullOrWhiteSpace("$($health.ctmon_version)")) { return $false }
        if ($ExpectedPid -gt 0 -and [int]$health.server_pid -ne $ExpectedPid) { return $false }
        if ($PassThru) { return $health }
        return $true
    } catch {
        return $false
    } finally {
        if ($reader) { try { $reader.Dispose() } catch { } }
        if ($response) { try { $response.Close() } catch { } }
    }
}

function Get-CtDashboardUrl {
    param([int]$Port, [string]$Bind = '127.0.0.1')
    $hostAddress = $Bind
    if ([string]::IsNullOrWhiteSpace($hostAddress) -or $hostAddress -eq '0.0.0.0') { $hostAddress = '127.0.0.1' }
    if ($hostAddress -eq '::' -or $hostAddress -eq '[::]') { $hostAddress = '::1' }
    if ($hostAddress -eq 'localhost') { $hostAddress = '127.0.0.1' }
    if ($hostAddress.Contains(':') -and -not $hostAddress.StartsWith('[')) { $hostAddress = '[' + $hostAddress + ']' }
    return "http://${hostAddress}:$Port/"
}

function Get-CtAvailableServePort {
    <# Return preferred port if free, else optionally scan the next 20 ports. Zero means failure. #>
    param([int]$PreferredPort, [string]$Bind = '127.0.0.1', [switch]$AllowFallback)
    if ($PreferredPort -lt 1 -or $PreferredPort -gt 65535) { return 0 }
    if (Test-CtTcpPortAvailable -Port $PreferredPort -Bind $Bind) { return $PreferredPort }
    if (-not $AllowFallback) { return 0 }
    $lastPort = [Math]::Min(65535, $PreferredPort + 20)
    for ($candidate = $PreferredPort + 1; $candidate -le $lastPort; $candidate++) {
        if (Test-CtTcpPortAvailable -Port $candidate -Bind $Bind) { return $candidate }
    }
    return 0
}

function Start-CtBackground {
    param(
        [string]$TargetValue,
        [string]$Path,
        [string]$NotifyMode,
        [string]$SourceMode,
        [switch]$DryRun,
        [switch]$ServeMode,
        [int]$ServePort = 0,
        [string]$ServeBind = '127.0.0.1',
        [switch]$PortExplicit
    )

    $dir = $Script:StateDir
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (-not (Test-Path $Script:LogDir)) { New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null }

    # Prevent duplicate instances and clean up dead PID files before launching anything.
    if ($ServeMode) {
        $existingServe = Test-CtPidAlive -Path $Script:ServePidPath
        if ($existingServe -and $existingServe.Port -gt 0 -and (Test-CtDashboardHealth -Port $existingServe.Port -Bind $existingServe.Bind -ExpectedPid $existingServe.Pid)) {
            if ($PortExplicit -and $ServePort -gt 0 -and $ServePort -ne $existingServe.Port) {
                Write-CtLog "dashboard is already healthy on port $($existingServe.Port); stop it with -Stop before moving it to port $ServePort" -Level WARN
                return $false
            }
            Write-CtLog "dashboard already running and healthy (pid=$($existingServe.Pid), port=$($existingServe.Port)); not starting a duplicate" -Level OK
            Write-CtLog ("dashboard: {0}" -f (Get-CtDashboardUrl -Port $existingServe.Port -Bind $existingServe.Bind)) -Level INFO
            return $true
        }
        if ($existingServe) {
            Write-CtLog "dashboard PID record is stale or unhealthy (pid=$($existingServe.Pid)); replacing it" -Level WARN
            Remove-Item -LiteralPath $Script:ServePidPath -Force -ErrorAction SilentlyContinue
        } elseif (Test-Path $Script:ServePidPath) {
            Write-CtLog 'removing stale dashboard PID file' -Level WARN
            Remove-Item -LiteralPath $Script:ServePidPath -Force -ErrorAction SilentlyContinue
        }

        if ($ServePort -le 0) { $ServePort = Get-CtDashboardPort -Path $Path }
        # A competing -ServeBg may have bound the port milliseconds before writing its PID
        # file. Probe CTMon's health endpoint before treating an occupied port as a conflict.
        $orphanHealth = Test-CtDashboardHealth -Port $ServePort -Bind $ServeBind -PassThru
        if ($orphanHealth) {
            $repairPid = 0
            if ([int]::TryParse("$($orphanHealth.server_pid)", [ref]$repairPid) -and $repairPid -gt 0) {
                try {
                    $repairUtf8 = New-Object System.Text.UTF8Encoding($false)
                    [System.IO.File]::WriteAllText($Script:ServePidPath, ("{0}:{1}:{2}" -f $repairPid, $ServePort, $ServeBind), $repairUtf8)
                } catch { }
                Write-CtLog "dashboard already healthy on port $ServePort (pid=$repairPid); repaired PID record and skipped duplicate start" -Level OK
                Write-CtLog ("dashboard: {0}" -f (Get-CtDashboardUrl -Port $ServePort -Bind $ServeBind)) -Level INFO
                return $true
            }
        }
        $preferredPort = $ServePort
        $chosenPort = Get-CtAvailableServePort -PreferredPort $ServePort -Bind $ServeBind -AllowFallback:(-not $PortExplicit)
        if ($chosenPort -le 0) {
            if ($PortExplicit) {
                Write-CtLog "dashboard port $ServePort is unavailable on bind address $ServeBind; choose another with -Port" -Level ERROR
            } else {
                Write-CtLog "no available dashboard port found from $preferredPort through $([Math]::Min(65535, $preferredPort + 20)) on $ServeBind" -Level ERROR
            }
            return $false
        }
        $ServePort = $chosenPort
        if ($ServePort -ne $preferredPort) {
            Write-CtLog "configured dashboard port $preferredPort is busy; automatically selected port $ServePort" -Level WARN
        }
    } else {
        $existingMonitor = Test-CtPidAlive -Path $Script:PidPath
        if ($existingMonitor) {
            Write-CtLog "monitor already running (pid=$($existingMonitor.Pid)); not starting a duplicate. Use -Stop before changing targets/source" -Level WARN
            return $true
        }
        if (Test-Path $Script:PidPath) {
            Write-CtLog 'removing stale monitor PID file' -Level WARN
            Remove-Item -LiteralPath $Script:PidPath -Force -ErrorAction SilentlyContinue
        }
    }

    $psExe  = Get-CtPwshExecutable
    $stamp  = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $kind   = 'bg'
    if ($ServeMode) { $kind = 'serve' }
    $logOut = Join-Path $Script:LogDir "ctmon-$kind-$stamp.out.log"
    $logErr = Join-Path $Script:LogDir "ctmon-$kind-$stamp.err.log"

    # single command-line string with quoted paths (works for PS 5.1 and PS 7)
    $argString = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Script:ScriptPath + '"'
    if ($ServeMode) {
        $argString += ' -Serve'
        if ($ServePort -gt 0) { $argString += " -Port $ServePort" }
        if (-not [string]::IsNullOrWhiteSpace($ServeBind)) { $argString += ' -Bind "' + $ServeBind + '"' }
        if (-not $PortExplicit) { $argString += ' -AutoPortFallback' }
    }
    if ($TargetValue) { $argString += ' -Target "' + $TargetValue + '"' }
    if ($Path -and ($Path -ne $Script:DefaultConfigPath)) { $argString += ' -ConfigPath "' + $Path + '"' }
    if ($NotifyMode)  { $argString += ' -Notify '  + $NotifyMode }
    if ($SourceMode)  { $argString += ' -Source '  + $SourceMode }
    if ($DryRun)      { $argString += ' -DryRun' }

    if ($Script:IsWindowsPS) {
        $proc = Start-Process -FilePath $psExe -ArgumentList $argString -WindowStyle Hidden -PassThru -RedirectStandardOutput $logOut -RedirectStandardError $logErr
    } else {
        $proc = Start-Process -FilePath $psExe -ArgumentList $argString -PassThru -RedirectStandardOutput $logOut -RedirectStandardError $logErr
    }

    if ($proc) {
        if (-not $ServeMode) {
            # The monitor child also publishes its own PID once initialized. This early
            # record lets -Status/-Stop find it immediately after Start-Process returns.
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($Script:PidPath, "$($proc.Id)", $utf8)
            Start-Sleep -Milliseconds 250
            $aliveProc = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
            if (-not $aliveProc) {
                Remove-Item -LiteralPath $Script:PidPath -Force -ErrorAction SilentlyContinue
                Write-CtLog "monitor process $($proc.Id) exited during startup; inspect stderr: $logErr" -Level ERROR
                return $false
            }
            Write-CtLog "background monitor started pid=$($proc.Id)" -Level OK
            Write-CtLog "stdout log: $logOut" -Level INFO
            Write-CtLog "stderr log: $logErr" -Level INFO
            Write-CtLog 'stop it anytime with:  CTMon.ps1 -Stop' -Level INFO
            return $true
        } else {
            # The server child writes its PID record only after successfully binding the
            # socket. Wait for the health endpoint so a bind failure is never reported OK.
            $ready = $false
            for ($attempt = 0; $attempt -lt 16; $attempt++) {
                Start-Sleep -Milliseconds 300
                $aliveProc = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
                if (-not $aliveProc) { break }
                if (Test-CtDashboardHealth -Port $ServePort -Bind $ServeBind -ExpectedPid $proc.Id -TimeoutMs 600) {
                    $ready = $true
                    break
                }
                $childServeInfo = Test-CtPidAlive -Path $Script:ServePidPath
                if ($childServeInfo -and $childServeInfo.Pid -eq $proc.Id -and $childServeInfo.Port -gt 0 -and (Test-CtDashboardHealth -Port $childServeInfo.Port -Bind $childServeInfo.Bind -ExpectedPid $proc.Id -TimeoutMs 600)) {
                    $ServePort = $childServeInfo.Port
                    $ServeBind = $childServeInfo.Bind
                    $ready = $true
                    break
                }
            }
            if (-not $ready) {
                $aliveProc = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
                if (-not $aliveProc) {
                    Write-CtLog "dashboard server exited during startup (port $ServePort); inspect stderr: $logErr" -Level ERROR
                    $ownedPid = Test-CtPidAlive -Path $Script:ServePidPath
                    if ($ownedPid -and $ownedPid.Pid -eq $proc.Id) { Remove-Item -LiteralPath $Script:ServePidPath -Force -ErrorAction SilentlyContinue }
                    return $false
                }
                Write-CtLog "dashboard process $($proc.Id) is still starting but health was not confirmed; inspect logs: $logOut and $logErr" -Level WARN
                Write-CtLog "stdout log: $logOut" -Level INFO
                Write-CtLog "stderr log: $logErr" -Level INFO
                return $false
            } else {
                Write-CtLog "dashboard server started and healthy pid=$($proc.Id) port=$ServePort" -Level OK
                Write-CtLog (("dashboard: {0} (stop with: CTMon.ps1 -Stop)" -f (Get-CtDashboardUrl -Port $ServePort -Bind $ServeBind))) -Level OK
            }
            Write-CtLog "stdout log: $logOut" -Level INFO
            Write-CtLog "stderr log: $logErr" -Level INFO
            return $true
        }
    } else {
        Write-CtLog 'failed to start background process' -Level ERROR
        return $false
    }
}

function Stop-CtRunning {
    $stopped = 0

    # 1) pid files (preferred) - monitor first, then dashboard server
    foreach ($pair in @(,@('monitor', $Script:PidPath)) + @(,@('dashboard', $Script:ServePidPath))) {
        $label = $pair[0]
        $pidFile = $pair[1]
        if (Test-Path $pidFile) {
            $pidText = ([System.IO.File]::ReadAllText($pidFile)).Trim()
            # Dashboard PID files may carry "pid:port" or "pid:port:bind".
            $colon = $pidText.IndexOf(':')
            if ($colon -gt 0) { $pidText = $pidText.Substring(0, $colon) }
            $targetPid = 0
            if ([int]::TryParse($pidText, [ref]$targetPid)) {
                if ($targetPid -eq $PID) {
                    Write-CtLog "$label pid file points at this very process; nothing to stop" -Level WARN
                } else {
                    try {
                        $p = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
                        if ($p) {
                            Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
                            Write-CtLog "stopped $label instance pid=$targetPid" -Level OK
                            $stopped++
                        } else {
                            Write-CtLog "$label pid file found but process $targetPid is not running (stale entry)" -Level WARN
                        }
                    } catch {
                        Write-CtLog "could not stop process $targetPid`: $($_.Exception.Message)" -Level ERROR
                    }
                }
            }
            Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
        }
    }

    # 2) sweep for orphaned monitor/dashboard instances by command line (Windows only)
    if ($Script:IsWindowsPS) {
        try {
            $procs = Get-CimInstance -ClassName Win32_Process -Filter "Name LIKE 'powershell%' OR Name LIKE 'pwsh%'" -ErrorAction SilentlyContinue |
                Where-Object {
                    ($_.CommandLine -like '*CTMon.ps1*') -and
                    ($_.ProcessId -ne $PID) -and
                    ($_.CommandLine -notmatch '\-(Stop|Status|SelfTest|Setup|TestAlert|Doctor|InstallTask|UninstallTask|Version|Help|Export|Summary|Prune|Dashboard)\b')
                }
            foreach ($pr in $procs) {
                try {
                    Stop-Process -Id $pr.ProcessId -Force -ErrorAction SilentlyContinue
                    Write-CtLog "stopped orphaned instance pid=$($pr.ProcessId)" -Level OK
                    $stopped++
                } catch { }
            }
        } catch { }
    }

    if ($stopped -eq 0) {
        Write-CtLog 'no running CTMon instances found' -Level INFO
    }
}

function Test-CtPidAlive {
    <# Check a pid file (legacy "pid", "pid:port", or "pid:port:bind" format). #>
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $pidText = ([System.IO.File]::ReadAllText($Path)).Trim()
    $port = 0
    $bind = '127.0.0.1'
    $firstColon = $pidText.IndexOf(':')
    if ($firstColon -gt 0) {
        $secondColon = $pidText.IndexOf(':', $firstColon + 1)
        $pidPart = $pidText.Substring(0, $firstColon)
        if ($secondColon -gt $firstColon) {
            $portPart = $pidText.Substring($firstColon + 1, $secondColon - $firstColon - 1)
            $bindPart = $pidText.Substring($secondColon + 1)
            if (-not [string]::IsNullOrWhiteSpace($bindPart)) { $bind = $bindPart }
        } else {
            $pidPart = $pidText.Substring(0, $firstColon)
            $portPart = $pidText.Substring($firstColon + 1)
        }
        $parsedPort = 0
        if ([int]::TryParse($portPart, [ref]$parsedPort)) { $port = $parsedPort }
        $pidText = $pidPart
    }
    $targetPid = 0
    if ([int]::TryParse($pidText, [ref]$targetPid)) {
        $p = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
        if ($p) { return @{ Pid = $targetPid; StartTime = $p.StartTime; Port = $port; Bind = $bind } }
    }
    return $null
}

function Get-CtServePort {
    <# Port of a RUNNING dashboard server (from its pid file), or 0. #>
    $info = Test-CtPidAlive -Path $Script:ServePidPath
    if ($info -and $info.Port -gt 0) { return [int]$info.Port }
    return 0
}

function Show-CtStatus {
    Show-CtBanner

    # process state (monitor)
    $monitor = Test-CtPidAlive -Path $Script:PidPath
    if ($monitor) {
        $up = ''
        try { $up = Get-CtUptimeText -Start ([datetime]$monitor.StartTime) } catch { $up = 'unknown' }
        Write-Host " status          : $($Script:EmojiGreen) MONITOR RUNNING (pid $($monitor.Pid), uptime $up)" -ForegroundColor Green
    } else {
        Write-Host ' status          : monitor NOT running (use -Background or -InstallTask)' -ForegroundColor Yellow
    }

    # dashboard server state
    $serve = Test-CtPidAlive -Path $Script:ServePidPath
    if ($serve -and $serve.Port -gt 0 -and (Test-CtDashboardHealth -Port $serve.Port -Bind $serve.Bind -ExpectedPid $serve.Pid)) {
        $up = ''
        try { $up = Get-CtUptimeText -Start ([datetime]$serve.StartTime) } catch { $up = 'unknown' }
        Write-Host " dashboard       : $($Script:EmojiGreen) SERVER HEALTHY (pid $($serve.Pid), uptime $up)" -ForegroundColor Green
        Write-Host (" dashboard url   : {0}" -f (Get-CtDashboardUrl -Port $serve.Port -Bind $serve.Bind)) -ForegroundColor Gray
        Write-Host (" dashboard health: {0}api/health" -f ((Get-CtDashboardUrl -Port $serve.Port -Bind $serve.Bind))) -ForegroundColor Gray
    } elseif ($serve) {
        Write-Host " dashboard       : UNHEALTHY (PID $($serve.Pid) exists, but /api/health did not confirm CTMon)" -ForegroundColor Yellow
        if ($serve.Port -gt 0) { Write-Host (" dashboard probe : {0}api/health" -f (Get-CtDashboardUrl -Port $serve.Port -Bind $serve.Bind)) -ForegroundColor Gray }
        Write-Host ' dashboard fix   : .\CTMon.ps1 -Stop; then .\CTMon.ps1 -ServeBg' -ForegroundColor Gray
    } else {
        if (Test-Path $Script:ServePidPath) {
            Write-Host ' dashboard       : server not running (stale PID file detected)' -ForegroundColor Yellow
        } else {
            Write-Host ' dashboard       : server not running (use -ServeBg; static file: dashboard.html)' -ForegroundColor Gray
        }
        if (Test-Path $Script:DashHtmlPath) {
            Write-Host " dashboard file  : $Script:DashHtmlPath" -ForegroundColor Gray
        }
    }

    # persisted stats
    if (Test-Path $Script:StatePath) {
        try {
            $st = [System.IO.File]::ReadAllText($Script:StatePath) | ConvertFrom-Json
            $byShown = 0
            try { $byShown = [int]$st.bypass_count } catch { $byShown = 0 }
            Write-Host (" last state      : certs={0} domains={1} matched={2} (today: {3}) sent={4} reconnects={5} bypass={6}" -f $st.certs_seen, $st.domains_seen, $st.matched, $st.matched_today, $st.notifications, $st.reconnects, $byShown) -ForegroundColor Gray
            Write-Host (" state updated   : {0}" -f $st.updated_utc) -ForegroundColor Gray
            try {
                $mtStatus = @($st.monitor_targets | ForEach-Object { "$_" }) | Where-Object { $_ }
                if ($mtStatus.Count -gt 0) { Write-Host (" monitor targets : {0}" -f ($mtStatus -join ', ')) -ForegroundColor Gray }
            } catch { }
        } catch { }
    }

    # config + secrets summary
    try {
        $cfg = Get-CtConfig
        $tg = 'not configured'
        $sec = Resolve-CtSecret -Key 'TELEGRAM_BOT_TOKEN' -CurrentValue "$($cfg.telegram_bot_token)"
        $sec2 = Resolve-CtSecret -Key 'TELEGRAM_CHAT_ID' -CurrentValue "$($cfg.telegram_chat_id)"
        if ($sec.Value -and $sec2.Value) { $tg = "configured (source: $($sec.Source))" }
        Write-Host (" telegram        : {0}" -f $tg) -ForegroundColor Gray
        Write-Host (" targets         : {0}" -f (($cfg.targets | ForEach-Object { "$_" }) -join ', ')) -ForegroundColor Gray
        Write-Host (" keywords        : {0}" -f (($cfg.keywords | ForEach-Object { "$_" }) -join ', ')) -ForegroundColor Gray
        $proxyNow = Get-CtEffectiveProxy -Config $cfg
        if ($proxyNow) { Write-Host (" proxy           : {0} (source: {1})" -f $proxyNow.Url, $proxyNow.Source) -ForegroundColor Gray }
        if ($cfg.doh_enabled) { Write-Host (" doh fallback    : enabled ({0})" -f $cfg.doh_provider) -ForegroundColor Gray }
        if ($cfg.digest_enabled) { Write-Host (" weekly digest   : {0} around {1}:00 ({2} day window)" -f $cfg.digest_weekday, $cfg.digest_hour, $cfg.digest_days) -ForegroundColor Gray }
        Write-Host (" config file     : {0}" -f $Script:DefaultConfigPath) -ForegroundColor Gray
        $envFiles = @(Get-CtEnvLocations) | Where-Object { Test-Path $_ }
        if ($envFiles.Count -gt 0) {
            Write-Host (" .env files      : {0}" -f ($envFiles -join ', ')) -ForegroundColor Gray
        }
    } catch { }

    # log tail
    if (Test-Path $Script:LogDir) {
        $latest = Get-ChildItem -LiteralPath $Script:LogDir -Filter 'ctmon-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) {
            Write-Host (" latest log      : {0}" -f $latest.FullName) -ForegroundColor Gray
            $tail = Get-Content -LiteralPath $latest.FullName -Tail 5 -ErrorAction SilentlyContinue
            foreach ($l in $tail) { Write-Host "   $l" -ForegroundColor DarkGray }
        }
    }

    # scheduled task (Windows)
    if ($Script:IsWindowsPS) {
        try {
            $task = Get-ScheduledTask -TaskName 'CTMon' -ErrorAction SilentlyContinue
            if ($task) { Write-Host " scheduled task  : installed ($($task.State))" -ForegroundColor Gray }
            else { Write-Host ' scheduled task  : not installed' -ForegroundColor Gray }
        } catch { }
    }
}


function Invoke-CtDoctor {
    <# Offline diagnostics. Does not print or persist secret values. #>
    $script:DoctorWarnings = 0
    $script:DoctorFailures = 0
    Write-Host ''
    Write-Host 'CTMon Doctor - local diagnostics' -ForegroundColor Cyan
    Write-Host ('PowerShell: {0} | OS: {1}' -f $PSVersionTable.PSVersion, [Environment]::OSVersion.Platform) -ForegroundColor Gray

    function Write-CtDoctorResult {
        param([ValidateSet('OK','WARN','FAIL')][string]$State, [string]$Name, [string]$Details = '')
        $color = 'Green'; $mark = '[OK]'
        if ($State -eq 'WARN') { $color = 'Yellow'; $mark = '[WARN]'; $script:DoctorWarnings++ }
        elseif ($State -eq 'FAIL') { $color = 'Red'; $mark = '[FAIL]'; $script:DoctorFailures++ }
        $line = "$mark $Name"
        if ($Details) { $line += " - $Details" }
        Write-Host $line -ForegroundColor $color
    }

    # Runtime / config
    Write-CtDoctorResult -State 'OK' -Name 'PowerShell runtime detected'
    $cfg = $null
    try {
        $cfg = Get-CtConfig -Path $ConfigPath
        $cfgPathDisplay = $Script:DefaultConfigPath
        if ($ConfigPath) { $cfgPathDisplay = $ConfigPath }
        Write-CtDoctorResult -State 'OK' -Name 'Configuration parses' -Details $cfgPathDisplay
    } catch {
        Write-CtDoctorResult -State 'FAIL' -Name 'Configuration parses' -Details $_.Exception.Message
    }

    if ($cfg) {
        $resolvedTargets = @()
        try {
    $resolvedTargets = Resolve-CtTargets -TargetValue $Target -ConfigTargets $cfg.targets
} catch {
    $resolvedTargets = @()
}
        if ($resolvedTargets.Count -gt 0) {
            Write-CtDoctorResult -State 'OK' -Name 'Targets configured' -Details ("{0} target(s): {1}" -f $resolvedTargets.Count, ($resolvedTargets -join ', '))
        } else {
            Write-CtDoctorResult -State 'WARN' -Name 'Targets configured' -Details 'none found; use -Target or add targets to config.json'
        }
        $proxyInfoDoc = Get-CtEffectiveProxy -Config $cfg
        if ($proxyInfoDoc) {
            Write-CtDoctorResult -State 'OK' -Name 'Network proxy configured' -Details "$($proxyInfoDoc.Url) (source: $($proxyInfoDoc.Source))"
        } else {
            Write-CtDoctorResult -State 'OK' -Name 'Network proxy' -Details 'none (direct); set HTTPS_PROXY env or net_proxy config to route around blocks'
        }
        if ($cfg.doh_enabled) {
            Write-CtDoctorResult -State 'OK' -Name 'DNS-over-HTTPS fallback' -Details "provider: $($cfg.doh_provider)"
        } else {
            Write-CtDoctorResult -State 'WARN' -Name 'DNS-over-HTTPS fallback' -Details 'disabled (doh_enabled = false)'
        }
        if ($cfg.net_bypass) {
            Write-CtDoctorResult -State 'OK' -Name 'crt.sh bypass chain' -Details 'armed: proxy -> doh+curl -> certspotter'
        } else {
            Write-CtDoctorResult -State 'WARN' -Name 'crt.sh bypass chain' -Details 'disabled (net_bypass = false)'
        }
        $notifyMode = 'telegram'
        if ($Notify) { $notifyMode = $Notify } elseif ($cfg.notify) { $notifyMode = "$($cfg.notify)" }
        if ($notifyMode -eq 'telegram') {
            $tok = Resolve-CtSecret -Key 'TELEGRAM_BOT_TOKEN' -CurrentValue "$($cfg.telegram_bot_token)"
            $chat = Resolve-CtSecret -Key 'TELEGRAM_CHAT_ID' -CurrentValue "$($cfg.telegram_chat_id)"
            if ($tok.Value -and $chat.Value) { Write-CtDoctorResult -State 'OK' -Name 'Telegram credentials present' }
            else { Write-CtDoctorResult -State 'WARN' -Name 'Telegram credentials present' -Details 'set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env or config.json' }
        } elseif ($notifyMode -eq 'discord') {
            $hook = Resolve-CtSecret -Key 'DISCORD_WEBHOOK_URL' -CurrentValue "$($cfg.discord_webhook_url)"
            if ($hook.Value) { Write-CtDoctorResult -State 'OK' -Name 'Discord webhook configured' } else { Write-CtDoctorResult -State 'WARN' -Name 'Discord webhook configured' -Details 'set DISCORD_WEBHOOK_URL' }
        } elseif ($notifyMode -eq 'webhook') {
            $hook = Resolve-CtSecret -Key 'GENERIC_WEBHOOK_URL' -CurrentValue "$($cfg.webhook_url)"
            if ($hook.Value) { Write-CtDoctorResult -State 'OK' -Name 'Generic webhook configured' } else { Write-CtDoctorResult -State 'WARN' -Name 'Generic webhook configured' -Details 'set GENERIC_WEBHOOK_URL' }
        } elseif ($notifyMode -eq 'slack') {
            $hook = Resolve-CtSecret -Key 'SLACK_WEBHOOK_URL' -CurrentValue "$($cfg.slack_webhook_url)"
            if ($hook.Value) { Write-CtDoctorResult -State 'OK' -Name 'Slack webhook configured' } else { Write-CtDoctorResult -State 'WARN' -Name 'Slack webhook configured' -Details 'set SLACK_WEBHOOK_URL' }
        } elseif ($notifyMode -eq 'ntfy') {
            $topic = Resolve-CtSecret -Key 'NTFY_TOPIC' -CurrentValue "$($cfg.ntfy_topic)"
            if ($topic.Value) { Write-CtDoctorResult -State 'OK' -Name 'ntfy topic configured' -Details "server: $($cfg.ntfy_server)" } else { Write-CtDoctorResult -State 'WARN' -Name 'ntfy topic configured' -Details 'set NTFY_TOPIC' }
        } else {
            Write-CtDoctorResult -State 'OK' -Name 'Notifications disabled by configuration'
        }
    }

    # Writable state directory
    try {
        if (-not (Test-Path $Script:StateDir)) { New-Item -ItemType Directory -Path $Script:StateDir -Force | Out-Null }
        $probe = Join-Path $Script:StateDir ('.ctmon-doctor-' + [guid]::NewGuid().ToString('N') + '.tmp')
        [System.IO.File]::WriteAllText($probe, 'ok')
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        Write-CtDoctorResult -State 'OK' -Name 'State directory writable' -Details $Script:StateDir
    } catch {
        Write-CtDoctorResult -State 'FAIL' -Name 'State directory writable' -Details $_.Exception.Message
    }

    # PID file / server health
    $monitor = Test-CtPidAlive -Path $Script:PidPath
    if ($monitor) { Write-CtDoctorResult -State 'OK' -Name 'Monitor PID file points to a live process' -Details "pid=$($monitor.Pid)" }
    elseif (Test-Path $Script:PidPath) { Write-CtDoctorResult -State 'WARN' -Name 'Monitor PID file' -Details 'stale; run -Stop to clean up' }
    else { Write-CtDoctorResult -State 'WARN' -Name 'Monitor process' -Details 'not running' }

    $serve = Test-CtPidAlive -Path $Script:ServePidPath
    if ($serve -and $serve.Port -gt 0 -and (Test-CtDashboardHealth -Port $serve.Port -Bind $serve.Bind -ExpectedPid $serve.Pid)) {
        Write-CtDoctorResult -State 'OK' -Name 'Dashboard health endpoint' -Details "healthy at http://127.0.0.1:$($serve.Port)/api/health"
    } elseif ($serve) {
        Write-CtDoctorResult -State 'FAIL' -Name 'Dashboard health endpoint' -Details "PID $($serve.Pid) exists but port $($serve.Port) is not a healthy CTMon dashboard"
    } elseif (Test-Path $Script:ServePidPath) {
        Write-CtDoctorResult -State 'WARN' -Name 'Dashboard PID file' -Details 'stale; run -Stop to clean up'
    } else {
        $basePort = Get-CtDashboardPort -Path $ConfigPath
        if (Test-CtTcpPortAvailable -Port $basePort -Bind '127.0.0.1') {
            Write-CtDoctorResult -State 'WARN' -Name 'Dashboard server' -Details "not running; configured port $basePort is available"
        } else {
            Write-CtDoctorResult -State 'WARN' -Name 'Dashboard server' -Details "not managed by this PID file; port $basePort is occupied (CTMon will try another port automatically)"
        }
    }

    Write-Host ''
    if ($script:DoctorFailures -gt 0) {
        Write-Host ("Doctor finished: {0} failure(s), {1} warning(s)." -f $script:DoctorFailures, $script:DoctorWarnings) -ForegroundColor Red
        return $false
    }
    Write-Host ("Doctor finished: no hard failures, {0} warning(s)." -f $script:DoctorWarnings) -ForegroundColor Green
    return $true
}

function Install-CtScheduledTask {
    param([string]$TargetValue, [string]$Path)

    if (-not $Script:IsWindowsPS) {
        # ---- Linux / macOS: print systemd + cron equivalents ----
        Write-CtLog 'Linux/macOS detected - here is your 24/7 setup (copy/paste):' -Level INFO
        Write-Host ''
        Write-Host '== Option A: systemd user service (recommended) ==' -ForegroundColor Yellow
        Write-Host " 1) mkdir -p ~/.config/systemd/user" -ForegroundColor Gray
        Write-Host " 2) Save the following as ~/.config/systemd/user/ctmon.service:" -ForegroundColor Gray
        $exeSafe = Get-CtPwshExecutable
        Write-Host ''
        Write-Host '   [Unit]' -ForegroundColor White
        Write-Host '   Description=CTMon - Certificate Transparency monitor' -ForegroundColor White
        Write-Host '   After=network-online.target' -ForegroundColor White
        Write-Host ''
        Write-Host '   [Service]' -ForegroundColor White
        Write-Host "   ExecStart=`"$exeSafe`" -NoProfile -File `"$Script:ScriptPath`"" -ForegroundColor White
        Write-Host '   Restart=always' -ForegroundColor White
        Write-Host '   RestartSec=10' -ForegroundColor White
        Write-Host ''
        Write-Host " 3) systemctl --user daemon-reload && systemctl --user enable --now ctmon" -ForegroundColor Gray
        Write-Host ''
        Write-Host '   Optional dashboard service: copy ctmon.service, change the description,' -ForegroundColor Gray
        Write-Host "   and use `"$exeSafe`" -NoProfile -File `"$Script:ScriptPath`" -Serve as ExecStart." -ForegroundColor Gray
        Write-Host ''
        Write-Host '== Option B: cron @reboot (same as the article) ==' -ForegroundColor Yellow
        Write-Host " echo `"@reboot sleep 30; $($Script:ScriptPath) >> $Script:LogDir/ctmon-cron.log 2>&1 &`" | crontab -" -ForegroundColor Gray
        Write-Host ''
        return
    }

    # ---- Windows: real Scheduled Task ----
    $psExe = Get-CtPwshExecutable
    $actionArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script:ScriptPath`""
    if ($TargetValue) { $actionArgs += " -Target `"$TargetValue`"" }
    if ($Path -and ($Path -ne $Script:DefaultConfigPath)) { $actionArgs += " -ConfigPath `"$Path`"" }
    $action = New-ScheduledTaskAction -Execute $psExe -Argument $actionArgs
    $logonUser = "$env:USERDOMAIN\$env:USERNAME"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $logonUser
    $settings = New-ScheduledTaskSettingsSet `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew

    try {
        if (Get-ScheduledTask -TaskName 'CTMon' -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName 'CTMon' -Confirm:$false
            Write-CtLog 'removed existing CTMon task' -Level INFO
        }
        Register-ScheduledTask -TaskName 'CTMon' -Action $action -Trigger $trigger -Settings $settings -Description 'CTMon - Certificate Transparency monitor (bug bounty recon)' | Out-Null
        Write-CtLog "scheduled task 'CTMon' installed - runs hidden at every logon, no time limit" -Level OK
        Write-CtLog "targets are read from: $Script:DefaultConfigPath (edit 'targets' there)" -Level INFO
        try {
            Start-ScheduledTask -TaskName 'CTMon'
            Write-CtLog 'task started now' -Level OK
        } catch {
            Write-CtLog "task installed but could not start immediately: $($_.Exception.Message)" -Level WARN
        }
        Write-CtLog 'remove it anytime with:  CTMon.ps1 -UninstallTask' -Level INFO
        Write-CtLog 'run the dashboard next to it with:  CTMon.ps1 -ServeBg' -Level INFO
    } catch {
        Write-CtLog "could not register scheduled task: $($_.Exception.Message)" -Level ERROR
        Write-CtLog 'try running PowerShell as Administrator, or use -Background instead' -Level WARN
    }
}

function Uninstall-CtScheduledTask {
    if (-not $Script:IsWindowsPS) {
        Write-CtLog 'on Linux/macOS remove the cron line (crontab -e) or disable the systemd unit:' -Level INFO
        Write-Host '  systemctl --user disable --now ctmon' -ForegroundColor Gray
        return
    }
    try {
        if (Get-ScheduledTask -TaskName 'CTMon' -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName 'CTMon' -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName 'CTMon' -Confirm:$false
            Write-CtLog "scheduled task 'CTMon' removed" -Level OK
        } else {
            Write-CtLog "scheduled task 'CTMon' is not installed" -Level INFO
        }
    } catch {
        Write-CtLog "could not remove task: $($_.Exception.Message)" -Level ERROR
    }
}

# ============================================================================
#  BUILT-IN SELF TEST SUITE (-SelfTest)
# ============================================================================
function Invoke-CtSelfTest {
    Show-CtBanner
    $script:pass = 0
    $script:fail = 0
    $Script:NoColor = $false

    function Assert {
        param([string]$Name, [bool]$Condition, [string]$Extra = '')
        if ($Condition) { Write-CtLog "PASS  $Name" -Level OK; $script:pass++ }
        else { Write-CtLog "FAIL  $Name $Extra" -Level ERROR; $script:fail++ }
    }

    # --- domain normalization ---
    $n1 = ConvertTo-CtNormalDomain 'HTTPS://Sub.Example.COM./path?x=1'
    Assert 'normalize: scheme/path/case' ($n1 -eq 'sub.example.com') "got '$n1'"
    $n2 = ConvertTo-CtNormalDomain '*.Sub.Example.com'
    Assert 'normalize: wildcard strip' ($n2 -eq 'sub.example.com') "got '$n2'"
    $n3 = ConvertTo-CtNormalDomain 'localhost'
    Assert 'normalize: reject no-dot' ($null -eq $n3) "got '$n3'"
    $n4 = ConvertTo-CtNormalDomain 'bad domain!@#'
    Assert 'normalize: reject invalid chars' ($null -eq $n4) "got '$n4'"
    $n5 = ConvertTo-CtNormalDomain 'xn--bcher-kva.example.com'
    Assert 'normalize: punycode kept' ($n5 -eq 'xn--bcher-kva.example.com') "got '$n5'"

    # --- target resolution (comma list) ---
    $t = Resolve-CtTargets -TargetValue 'Example.com, foo.dev ,, example.com'
    Assert 'targets: comma + dedupe' ($t.Count -eq 2 -and $t[0] -eq 'example.com' -and $t[1] -eq 'foo.dev') "got $($t -join '|')"
    $t2 = Resolve-CtTargets -TargetValue @('Example.com', 'B.foo.dev', '')
    Assert 'targets: array resolution' ($t2.Count -eq 2 -and $t2[0] -eq 'example.com' -and $t2[1] -eq 'b.foo.dev') "got $($t2 -join '|')"

    # --- matching ---
    $m1 = Test-CtMatch -Domain 'a.b.example.com' -Targets @('example.com') -Keywords @()
    Assert 'match: suffix hit' ($null -ne $m1 -and $m1.Target -eq 'example.com')
    $m2 = Test-CtMatch -Domain 'notexample.com' -Targets @('example.com') -Keywords @()
    Assert 'match: suffix no false positive' ($null -eq $m2)
    $m3 = Test-CtMatch -Domain 'paypal-login-evil.xyz' -Targets @() -Keywords @('paypal')
    Assert 'match: keyword watch' ($null -ne $m3 -and $m3.Keyword -eq 'paypal')
    $m4 = Test-CtMatch -Domain 'x.example.com' -Targets @('example.com') -ExcludeRegex @('^x\.')
    Assert 'match: exclude regex' ($null -eq $m4)
    $m5 = Test-CtMatch -Domain '*.wild.example.com' -Targets @('example.com') -IncludeWildcards $true
    Assert 'match: wildcard included' ($null -ne $m5)
    $m6 = Test-CtMatch -Domain '*.wild.example.com' -Targets @('example.com') -IncludeWildcards $false
    Assert 'match: wildcard excluded' ($null -eq $m6)

    # --- seen store ---
    $tmpSeen = Join-Path (Get-CtTempDir) ("ctmon-test-seen-{0}.json" -f (Get-Random))
    $s = New-CtSeenStore -Persist $true -Path $tmpSeen -MaxEntries 1000
    $r1 = Test-CtSeen -Store $s -Key 'fresh.example.com'
    $r2 = Test-CtSeen -Store $s -Key 'fresh.example.com'
    Assert 'seen: first-add=false second=true' ((-not $r1) -and $r2)
    Save-CtSeen -Store $s
    Assert 'seen: file written' (Test-Path $tmpSeen)
    $s2 = New-CtSeenStore -Persist $true -Path $tmpSeen -MaxEntries 1000
    Assert 'seen: persisted reload' ($s2.Set.Contains('fresh.example.com'))
    Remove-Item -LiteralPath $tmpSeen -Force -ErrorAction SilentlyContinue

    # --- HTML escape ---
    $esc = ConvertTo-CtHtmlSafe '<a&b>'
    Assert 'escape: html entities' ($esc -eq '&lt;a&amp;b&gt;') "got '$esc'"

    # --- chunking ---
    $long = (1..500 | ForEach-Object { "subdomain-number-$_.example-long-target-name.com" }) -join "`n"
    $chunks = Split-CtChunk -Text $long -Size 3800
    $allOk = $true
    foreach ($c in $chunks) { if ($c.Length -gt 3800) { $allOk = $false } }
    Assert 'chunk: <=3800 chars each' ($chunks.Count -ge 2 -and $allOk) "count=$($chunks.Count)"

    # --- config round-trip ---
    $tmpCfg = Join-Path (Get-CtTempDir) ("ctmon-test-cfg-{0}.json" -f (Get-Random))
    $c = New-CtDefaultConfig
    $c.targets = @('example.com')
    $c.telegram_bot_token = '123:ABC'
    Save-CtConfig -Config $c -Path $tmpCfg
    $c2 = Get-CtConfig -Path $tmpCfg
    Assert 'config: round-trip' ($c2.targets[0] -eq 'example.com' -and $c2.telegram_bot_token -eq '123:ABC')
    Assert 'config: defaults merged' ($c2.flush_interval_seconds -eq 10)
    Assert 'config: v2 keys present' (($null -ne $c2.enrich_dns) -and ($null -ne $c2.dashboard_port) -and ($null -ne $c2.matches_history_max))
    Remove-Item -LiteralPath $tmpCfg -Force -ErrorAction SilentlyContinue

    # --- certstream message parse ---
    $sample = '{"message_type":"certificate_update","data":{"update_type":"Insertion","leaf_cert":{"subject":"CN=foo.example.com","all_domains":["foo.example.com","*.bar.example.com"]}}}'
    $doms = Read-CtCertDomains -Json $sample
    Assert 'certstream: parse update' ($null -ne $doms -and $doms.Count -eq 2)
    $hb = Read-CtCertDomains -Json '{"message_type":"heartbeat"}'
    Assert 'certstream: heartbeat ignored' ($null -eq $hb)
    $bad = Read-CtCertDomains -Json 'not json at all {'
    Assert 'certstream: bad json ignored' ($null -eq $bad)

    # --- crt.sh url encode ---
    $uri = "https://crt.sh/?q=%25.$('example.com')&output=json&exclude=expired"
    Assert 'crtsh: percent encoded' ($uri -eq 'https://crt.sh/?q=%25.example.com&output=json&exclude=expired')

    # --- crt.sh entries parse ---
    $entries = @(
        [pscustomobject]@{ id = '1'; name_value = "a.example.com`nb.example.com"; common_name = 'a.example.com'; not_before = (Get-Date).ToUniversalTime().AddMinutes(-5).ToString('yyyy-MM-ddTHH:mm:ss') },
        [pscustomobject]@{ id = '2'; name_value = 'old.example.com'; common_name = ''; not_before = '2020-01-01T00:00:00' }
    )
    $rows = Read-CrtshDomains -Entries $entries -WindowMinutes 1440
    $rowDomains = @($rows | ForEach-Object { $_.Domain })
    Assert 'crtsh: window filter + multi-name' (($rowDomains -contains 'a.example.com') -and ($rowDomains -contains 'b.example.com') -and (-not ($rowDomains -contains 'old.example.com'))) "got: $($rowDomains -join ',')"

    # --- telegram payload build ---
    $chunks2 = Split-CtChunk -Text (('x' * 9000)) -Size 3800
    Assert 'chunk: long single-line split' ($chunks2.Count -eq 3)

    # ================= v2.0 tests =================

    # --- .env file parsing ---
    $tmpEnv = Join-Path (Get-CtTempDir) ("ctmon-test-env-{0}" -f (Get-Random))
    $envContent = "# comment line`r`nTELEGRAM_BOT_TOKEN=123:ABC-DEF`r`n`r`n# quoted value`r`nTELEGRAM_CHAT_ID=`"42 42`"`r`nexport DISCORD_WEBHOOK_URL='https://example.test/hook'`r`nGENERIC_WEBHOOK_URL=`r`n"
    [System.IO.File]::WriteAllText($tmpEnv, $envContent, (New-Object System.Text.UTF8Encoding($false)))
    $envMap = Read-CtEnvFile -Path $tmpEnv
    Assert 'env: parse basic key' ($envMap['TELEGRAM_BOT_TOKEN'] -eq '123:ABC-DEF') "got '$($envMap['TELEGRAM_BOT_TOKEN'])'"
    Assert 'env: quotes stripped' ($envMap['TELEGRAM_CHAT_ID'] -eq '42 42') "got '$($envMap['TELEGRAM_CHAT_ID'])'"
    Assert 'env: export prefix tolerated' ($envMap['DISCORD_WEBHOOK_URL'] -eq 'https://example.test/hook') "got '$($envMap['DISCORD_WEBHOOK_URL'])'"
    Assert 'env: empty value ok' ($envMap.ContainsKey('GENERIC_WEBHOOK_URL') -and $envMap['GENERIC_WEBHOOK_URL'] -eq '')
    Remove-Item -LiteralPath $tmpEnv -Force -ErrorAction SilentlyContinue

    # --- secret resolution order (process env > .env > config fallback) ---
    $tmpEnv2 = Join-Path (Get-CtTempDir) ("ctmon-test-env2-{0}" -f (Get-Random))
    [System.IO.File]::WriteAllText($tmpEnv2, "TELEGRAM_BOT_TOKEN=from-file`r`n", (New-Object System.Text.UTF8Encoding($false)))
    $rFile = Resolve-CtSecret -Key 'TELEGRAM_BOT_TOKEN' -CurrentValue 'from-config' -Paths @($tmpEnv2)
    Assert 'secret: .env beats config' ($rFile.Value -eq 'from-file' -and $rFile.Source -eq $tmpEnv2) "got '$($rFile.Value)'/$($rFile.Source)"
    $oldT = [Environment]::GetEnvironmentVariable('CTMON_SELFTEST_SECRET')
    [Environment]::SetEnvironmentVariable('CTMON_SELFTEST_SECRET', 'from-process', 'Process')
    $rProc = Resolve-CtSecret -Key 'CTMON_SELFTEST_SECRET' -CurrentValue 'from-config' -Paths @($tmpEnv2)
    Assert 'secret: process env beats .env' ($rProc.Value -eq 'from-process' -and $rProc.Source -eq 'environment')
    [Environment]::SetEnvironmentVariable('CTMON_SELFTEST_SECRET', $null, 'Process')
    $rCfg = Resolve-CtSecret -Key 'CTMON_UNSET_KEY_XYZ' -CurrentValue 'from-config' -Paths @($tmpEnv2)
    Assert 'secret: config fallback' ($rCfg.Value -eq 'from-config' -and $rCfg.Source -eq 'config')
    Remove-Item -LiteralPath $tmpEnv2 -Force -ErrorAction SilentlyContinue

    # --- default .env locations (script dir + state dir) end-to-end ---
    $oldScriptPath = $Script:ScriptPath
    $oldStateDir   = $Script:StateDir
    $tmpScriptDir  = Join-Path (Get-CtTempDir) ("ctmon-test-scriptdir-{0}" -f (Get-Random))
    $tmpStateDirT  = Join-Path (Get-CtTempDir) ("ctmon-test-statedir-{0}" -f (Get-Random))
    New-Item -ItemType Directory -Path $tmpScriptDir -Force | Out-Null
    New-Item -ItemType Directory -Path $tmpStateDirT -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $tmpScriptDir '.env'), "TELEGRAM_CHAT_ID=123456`r`n", (New-Object System.Text.UTF8Encoding($false)))
    $Script:ScriptPath = Join-Path $tmpScriptDir 'CTMon.ps1'
    $Script:StateDir   = $tmpStateDirT
    $locs = @(Get-CtEnvLocations)
    $firstOk = ($locs.Count -gt 0) -and ("$($locs[0])".EndsWith('.env')) -and (-not ("$($locs[0])".Contains([char]10)))
    Assert 'env-loc: two candidate paths' (($locs.Count -eq 2) -and $firstOk) "count=$($locs.Count) first='$($locs[0])'"
    $rDefault = Resolve-CtSecret -Key 'TELEGRAM_CHAT_ID' -CurrentValue ''
    Assert 'secret: default .env locations found' (($rDefault.Value -eq '123456') -and ($rDefault.Source -eq (Join-Path $tmpScriptDir '.env'))) "got '$($rDefault.Value)'/$($rDefault.Source)"
    $Script:ScriptPath = $oldScriptPath
    $Script:StateDir   = $oldStateDir
    Remove-Item -LiteralPath $tmpScriptDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpStateDirT -Recurse -Force -ErrorAction SilentlyContinue

    # --- .env writer (update keeps untouched keys) ---
    $tmpEnv3 = Join-Path (Get-CtTempDir) ("ctmon-test-env3-{0}" -f (Get-Random))
    Save-CtEnvFile -Values @{ TELEGRAM_BOT_TOKEN = 'tok-1' } -Path $tmpEnv3
    Save-CtEnvFile -Values @{ TELEGRAM_CHAT_ID = 'chat-1' } -Path $tmpEnv3
    $envMap3 = Read-CtEnvFile -Path $tmpEnv3
    Assert 'env-write: new key added' ($envMap3['TELEGRAM_CHAT_ID'] -eq 'chat-1')
    Assert 'env-write: existing key kept' ($envMap3['TELEGRAM_BOT_TOKEN'] -eq 'tok-1')
    Remove-Item -LiteralPath $tmpEnv3 -Force -ErrorAction SilentlyContinue

    # --- dns cache round-trip ---
    $tmpDns = Join-Path (Get-CtTempDir) ("ctmon-test-dns-{0}.json" -f (Get-Random))
    $dc = New-CtDnsCache -Path $tmpDns
    $dc.Map['a.example.com'] = @{ ok = $true; ip = '1.2.3.4, 5.6.7.8'; ts = (Get-Date) }
    $dc.Map['b.example.com'] = @{ ok = $false; ip = ''; ts = (Get-Date) }
    $dc.Dirty = $true
    Save-CtDnsCache -Cache $dc
    $dc2 = New-CtDnsCache -Path $tmpDns
    Assert 'dns-cache: persisted reload' (($dc2.Map.ContainsKey('a.example.com')) -and ($dc2.Map['a.example.com'].ip -like '1.2.3.4*'))
    Remove-Item -LiteralPath $tmpDns -Force -ErrorAction SilentlyContinue

    # --- discord payload ---
    $dp = New-CtDiscordPayload -Title 'example.com' -Domains @('a.example.com', 'b.example.com') -Footer 'CTMon test'
    $dpOk = ($dp.username -eq 'CTMon') -and ($dp.embeds.Count -eq 1) -and ($dp.embeds[0].title -eq 'example.com [2]') -and ($dp.embeds[0].description -like '*a.example.com*')
    Assert 'discord: embed payload' $dpOk "title='$($dp.embeds[0].title)'"

    # --- generic webhook payload ---
    $wp = New-CtWebhookPayload -Text 'hello' -Target 'example.com' -Count 2 -Domains @('a.example.com') -Source 'certstream'
    $wpOk = ($wp.text -eq 'hello') -and ($wp.ctmon.target -eq 'example.com') -and ($wp.ctmon.domains.Count -eq 1) -and ($wp.ctmon.version -eq $Script:CTMonVersion)
    Assert 'webhook: payload structure' $wpOk

    # --- match history round-trip ---
    $oldMatchesPath = $Script:MatchesPath
    $testHistoryPath = Join-Path (Get-CtTempDir) ("ctmon-test-matches-{0}.jsonl" -f (Get-Random))
    $Script:MatchesPath = $testHistoryPath
    Add-CtMatchRecord -Domain 'old.example.com' -Group 'example.com' -Source 'certstream' -Dns '' -AlertEnabled $false
    Start-Sleep -Milliseconds 20
    Add-CtMatchRecord -Domain 'new.example.com' -Group 'example.com' -Source 'crtsh' -Dns '9.9.9.9' -AlertEnabled $true
    $recs = Get-CtMatchRecords
    Assert 'history: jsonl round-trip count' ($recs.Count -eq 2) "count=$($recs.Count)"
    Assert 'history: newest first' ($recs[0].domain -eq 'new.example.com') "got '$($recs[0].domain)'"
    Assert 'history: dns field kept' ($recs[0].dns -eq '9.9.9.9')
    $recs7 = Get-CtMatchRecords -Days 1
    Assert 'history: days filter keeps fresh' ($recs7.Count -eq 2)
    $recs0 = Get-CtMatchRecords -Days 0
    Assert 'history: days 0 = all' ($recs0.Count -eq 2)
    Remove-Item -LiteralPath $testHistoryPath -Force -ErrorAction SilentlyContinue
    $Script:MatchesPath = $oldMatchesPath

    # --- export (csv + json) ---
    $testExportHistoryPath = Join-Path (Get-CtTempDir) ("ctmon-test-export-{0}.jsonl" -f (Get-Random))
    $Script:MatchesPath = $testExportHistoryPath
    Add-CtMatchRecord -Domain 'x.example.com' -Group 'example.com' -Source 'certstream' -Dns '1.1.1.1' -AlertEnabled $true
    $tmpCsv = Join-Path (Get-CtTempDir) ("ctmon-test-export-{0}.csv" -f (Get-Random))
    $nCsv = Invoke-CtExport -Format 'csv' -Days 30 -OutFile $tmpCsv
    Assert 'export: csv file + rows' (($nCsv -eq 1) -and (Test-Path $tmpCsv) -and ((Get-Item -LiteralPath $tmpCsv).Length -gt 20))
    $tmpJson = Join-Path (Get-CtTempDir) ("ctmon-test-export-{0}.json" -f (Get-Random))
    $nJson = Invoke-CtExport -Format 'json' -Days 30 -OutFile $tmpJson
    $jsonOk = $false
    try { $parsed = [System.IO.File]::ReadAllText($tmpJson) | ConvertFrom-Json; $jsonOk = (@($parsed).Count -eq 1) } catch { }
    Assert 'export: json file parses' (($nJson -eq 1) -and $jsonOk)
    Remove-Item -LiteralPath $testExportHistoryPath -Force -ErrorAction SilentlyContinue
    $Script:MatchesPath = $oldMatchesPath
    Remove-Item -LiteralPath $tmpCsv -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue

    # --- dashboard snapshot + html ---
    Initialize-CtDashboard
    Add-CtDashMatch -Domain 'dash.example.com' -Group 'example.com' -Source 'certstream' -Dns '2.2.2.2'
    Add-CtDashEvent -Level 'MATCH' -Message 'test event'
    $snap = New-CtDashboardSnapshot -StatusText 'live'
    $snapOk = ($null -ne $snap) -and ("$($snap.ctmon_version)" -eq $Script:CTMonVersion) -and ($snap.status -eq 'live') -and ($null -ne $snap.stats)
    Assert 'dashboard: snapshot structure' $snapOk
    $tmpSnap = Join-Path (Get-CtTempDir) ("ctmon-test-snap-{0}.json" -f (Get-Random))
    $jsonOk2 = $false
    try {
        $jsonStr = ConvertTo-Json -InputObject $snap -Depth 6 -Compress
        $null = $jsonStr | ConvertFrom-Json
        [System.IO.File]::WriteAllText($tmpSnap, $jsonStr, (New-Object System.Text.UTF8Encoding($false)))
        $jsonOk2 = $true
    } catch { }
    Assert 'dashboard: snapshot serializes' $jsonOk2
    Remove-Item -LiteralPath $tmpSnap -Force -ErrorAction SilentlyContinue

    $tmpHtml = Join-Path (Get-CtTempDir) ("ctmon-test-dash-{0}.html" -f (Get-Random))
    Write-CtDashboardHtml -OutPath $tmpHtml -Snapshot $snap
    $htmlTxt = ''
    try { $htmlTxt = [System.IO.File]::ReadAllText($tmpHtml) } catch { }
    $htmlOk = (($htmlTxt.Length -gt 3000) -and (-not $htmlTxt.Contains('__CTMON_SNAPSHOT__')) -and ($htmlTxt.Contains('id="snapshot"')) -and ($htmlTxt.Contains('CTMon dashboard')))
    Assert 'dashboard: html rendered (no placeholders left)' $htmlOk "len=$($htmlTxt.Length)"
    Remove-Item -LiteralPath $tmpHtml -Force -ErrorAction SilentlyContinue

    # --- http request line parsing ---
    $parsedReq = Get-CtHttpRequestPath -RequestLine 'GET /api/data?x=1 HTTP/1.1'
    Assert 'serve: request line parse' ($parsedReq -eq '/api/data') "got '$parsedReq'"
    $parsedMethod = Get-CtHttpRequestMethod -RequestLine 'HEAD /api/health HTTP/1.1'
    Assert 'serve: request method parse' ($parsedMethod -eq 'HEAD') "got '$parsedMethod'"
    $urlV4 = Get-CtDashboardUrl -Port 8080 -Bind '127.0.0.1'
    Assert 'serve: dashboard URL builder' ($urlV4 -eq 'http://127.0.0.1:8080/') "got '$urlV4'"
    $testPortListener = $null
    try {
        $testPortListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $testPortListener.Start()
        $busyTestPort = [int]$testPortListener.LocalEndpoint.Port
        Assert 'serve: busy port is detected' (-not (Test-CtTcpPortAvailable -Port $busyTestPort -Bind '127.0.0.1'))
        $fallbackTestPort = Get-CtAvailableServePort -PreferredPort $busyTestPort -Bind '127.0.0.1' -AllowFallback
        Assert 'serve: fallback chooses another port' (($fallbackTestPort -gt 0) -and ($fallbackTestPort -ne $busyTestPort)) "got $fallbackTestPort (busy $busyTestPort)"
    } catch {
        Assert 'serve: local port diagnostics' $false $_.Exception.Message
    } finally {
        if ($testPortListener) { try { $testPortListener.Stop() } catch { } }
    }

    # --- PID file format: include dashboard port/bind and keep IPv6 bind text intact ---
    $tmpPidPath = Join-Path (Get-CtTempDir) ("ctmon-test-pid-{0}.txt" -f (Get-Random))
    [System.IO.File]::WriteAllText($tmpPidPath, ("{0}:8123:127.0.0.1" -f $PID))
    $pidInfo = Test-CtPidAlive -Path $tmpPidPath
    Assert 'pid: dashboard PID/port/bind parsing' (($null -ne $pidInfo) -and ($pidInfo.Pid -eq $PID) -and ($pidInfo.Port -eq 8123) -and ($pidInfo.Bind -eq '127.0.0.1'))
    Remove-Item -LiteralPath $tmpPidPath -Force -ErrorAction SilentlyContinue

    # ================= v2.2 tests =================

    # --- risk scoring ---
    $rLow = Get-CtRiskScore -Domain 'api.example.com' -Dns '1.2.3.4'
    Assert 'risk: plain resolved subdomain is low' ($rLow.Level -eq 'low' -and $rLow.Score -eq 0) "got $($rLow.Level)/$($rLow.Score)"
    $rMed = Get-CtRiskScore -Domain 'api.example.com' -Dns ''
    Assert 'risk: unresolved dns is medium' ($rMed.Level -eq 'medium') "got $($rMed.Level)/$($rMed.Score)"
    $rHigh = Get-CtRiskScore -Domain 'secure-login.paypal-verify.com' -Dns '1.1.1.1' -Keyword 'paypal'
    Assert 'risk: keyword + suspicious terms is high+' ($rHigh.Score -ge 7 -and ($rHigh.Level -eq 'high' -or $rHigh.Level -eq 'critical')) "got $($rHigh.Level)/$($rHigh.Score)"
    $rWild = Get-CtRiskScore -Domain '*.dev.example.com' -Dns ''
    Assert 'risk: wildcard + suspicious + unresolved' ($rWild.Score -ge 5) "got $($rWild.Level)/$($rWild.Score)"
    Assert 'risk: reasons populated' ($rHigh.Reasons.Count -ge 2)
    Assert 'risk: severity weights ordered' ((Get-CtSeverityWeight -Level 'critical') -gt (Get-CtSeverityWeight -Level 'high') -and (Get-CtSeverityWeight -Level 'high') -gt (Get-CtSeverityWeight -Level 'medium'))

    # --- plain-text conversion (ntfy / slack) ---
    $plain = ConvertTo-CtPlainText -Text '<b>NEW</b>: <code>a.example.com</code> &amp; <i>more</i>'
    Assert 'notify: html stripped to plain text' ($plain -eq 'NEW: a.example.com & more') "got '$plain'"

    # --- slack payload ---
    $slk = New-CtSlackPayload -Text 'hello slack' -Footer 'CTMon v2.2.0'
    Assert 'notify: slack payload structure' (($slk.text -like '*hello slack*CTMon*') -and $slk.username -eq 'CTMon')

    # --- prometheus metrics ---
    $mx = @{ certs_seen = 10; domains_seen = 20; matched = 3; matched_today = 2; notifications = 1; reconnects = 0; bypass_count = 4; uptime_seconds = 60; buffered = 0; per_target = @{ 'example.com' = 3 } }
    $pm = New-CtPrometheusMetrics -Metrics $mx -Version $Script:CTMonVersion
    Assert 'metrics: build info line' ($pm.Contains('ctmon_build_info{version="' + $Script:CTMonVersion + '"} 1'))
    Assert 'metrics: counters present' ($pm.Contains('ctmon_matches_total 3') -and $pm.Contains('ctmon_bypass_total 4'))
    Assert 'metrics: per-target label line' ($pm.Contains('ctmon_target_matches_total{target="example.com"} 3'))
    Assert 'metrics: escaped label stays valid' ((New-CtPrometheusMetrics -Metrics @{ per_target = @{ 'weird"target' = 1 } } -Version 'test').Contains('target="weird\"target"'))

    # --- digest builder + schedule rule ---
    $digRecs = @(
        [pscustomobject]@{ domain = 'a.example.com'; group = 'example.com'; severity = 'high' },
        [pscustomobject]@{ domain = 'b.example.com'; group = 'example.com'; severity = 'low' },
        [pscustomobject]@{ domain = 'x.foo.dev'; group = 'foo.dev'; severity = 'medium' }
    )
    $dig = New-CtDigestMessage -Records $digRecs -Days 7
    Assert 'digest: groups + totals' ($dig.GroupCount -eq 2 -and $dig.Total -eq 3 -and $dig.Text.Contains('example.com [2]')) "groups=$($dig.GroupCount)"
    $dueMonday = Get-Date '2024-01-08T10:30:00'
    $dueOk = Test-CtDigestDue -Now $dueMonday -LastSentUtc $null -Weekday 'Monday' -Hour 9
    Assert 'digest: due on target weekday after hour' $dueOk
    $dueNotYet = Test-CtDigestDue -Now (Get-Date '2024-01-08T08:30:00') -LastSentUtc $null -Weekday 'Monday' -Hour 9
    Assert 'digest: not due before hour' (-not $dueNotYet)
    $dueWrongDay = Test-CtDigestDue -Now (Get-Date '2024-01-09T10:30:00') -LastSentUtc $null -Weekday 'Monday' -Hour 9
    Assert 'digest: not due on other days' (-not $dueWrongDay)
    $dueGap = Test-CtDigestDue -Now $dueMonday -LastSentUtc '2024-01-05T09:00:00Z' -Weekday 'Monday' -Hour 9
    Assert 'digest: min gap respected' (-not $dueGap)
    $dueNever = Test-CtDigestDue -Now $dueMonday -LastSentUtc $null -Weekday 'none' -Hour 9
    Assert 'digest: weekday none disables' (-not $dueNever)
    Assert 'fallback: disabled at 0 minutes' (-not (Test-CtCertstreamFallbackDue -Now (Get-Date '2024-01-08T10:00:00') -LastDataUtc (Get-Date '2024-01-01T10:00:00') -Minutes 0))
    Assert 'fallback: due after threshold' ((Test-CtCertstreamFallbackDue -Now (Get-Date '2024-01-08T10:11:00') -LastDataUtc (Get-Date '2024-01-08T10:00:00') -Minutes 10))
    Assert 'fallback: not due before threshold' (-not (Test-CtCertstreamFallbackDue -Now (Get-Date '2024-01-08T10:09:00') -LastDataUtc (Get-Date '2024-01-08T10:00:00') -Minutes 10))

    # --- proxy resolution ---
    $oldProxy = [Environment]::GetEnvironmentVariable('HTTPS_PROXY', 'Process')
    try {
        [Environment]::SetEnvironmentVariable('HTTPS_PROXY', 'socks5://127.0.0.1:1080', 'Process')
        $px = Get-CtEffectiveProxy -Config $null
        Assert 'proxy: env var wins' (($null -ne $px) -and $px.Url -eq 'socks5://127.0.0.1:1080' -and $px.Source -eq 'env:HTTPS_PROXY') "got $($px.Url)/$($px.Source)"
        [Environment]::SetEnvironmentVariable('HTTPS_PROXY', $null, 'Process')
        $cfgPx = New-CtDefaultConfig
        $cfgPx.net_proxy = 'http://127.0.0.1:8080'
        $px2 = Get-CtEffectiveProxy -Config $cfgPx
        Assert 'proxy: config fallback' (($null -ne $px2) -and $px2.Url -eq 'http://127.0.0.1:8080' -and $px2.Source -eq 'config') "got $($px2.Url)/$($px2.Source)"
    } finally {
        if ($null -ne $oldProxy) { [Environment]::SetEnvironmentVariable('HTTPS_PROXY', $oldProxy, 'Process') }
        else { [Environment]::SetEnvironmentVariable('HTTPS_PROXY', $null, 'Process') }
    }

    # --- doh response parsing ---
    $dohResp = [pscustomobject]@{ Answer = @(
        [pscustomobject]@{ type = 28; data = '2606:4700::1' },
        [pscustomobject]@{ type = 1; data = '104.16.132.229' }
    ) }
    Assert 'doh: a-record extraction' ((Get-CtDohIpFromResponse -Response $dohResp) -eq '104.16.132.229') "got '$(Get-CtDohIpFromResponse -Response $dohResp)'"
    Assert 'doh: empty on no answer' ((Get-CtDohIpFromResponse -Response $null) -eq '')

    # --- certspotter parsing ---
    $csEntries = @(
        [pscustomobject]@{ id = '77'; not_before = (Get-Date).ToUniversalTime().AddMinutes(-5).ToString('yyyy-MM-ddTHH:mm:ss'); dns_names = @('fresh.example.com', '*.wild.example.com') },
        [pscustomobject]@{ id = '78'; not_before = '2020-01-01T00:00:00'; dns_names = @('stale.example.com') }
    )
    $csRows = Read-CertspotterDomains -Entries $csEntries -WindowMinutes 1440
    $csDomains = @($csRows | ForEach-Object { $_.Domain })
    Assert 'certspotter: fresh kept, stale dropped' (($csDomains -contains 'fresh.example.com') -and (-not ($csDomains -contains 'stale.example.com'))) "got: $($csDomains -join ',')"
    $hintMsg = Get-CtCertspotterHint -StatusText '403 (Forbidden).' -Body '{"code":"not_allowed_by_plan","message":"Cannot search vercel.app because it is not beneath an eTLD available for public registration"}'
    Assert 'certspotter: plan-block hint surfaces api message' ($hintMsg.Contains('not beneath an eTLD') -and $hintMsg.Contains('certstream')) "got '$hintMsg'"
    $hintPlain = Get-CtCertspotterHint -StatusText '429 (Too Many Requests).' -Body ''
    Assert 'certspotter: plain status passthrough' ($hintPlain.StartsWith('429')) "got '$hintPlain'"
    $hintCode = Get-CtCertspotterHint -StatusText '403 (Forbidden).' -Body '{"code":"not_allowed_by_plan"}'
    Assert 'certspotter: code-only body tagged' ($hintCode.Contains('not_allowed_by_plan (certspotter)')) "got '$hintCode'"

    # --- match record severity round-trip ---
    $oldMatchesPath2 = $Script:MatchesPath
    $sevHistoryPath = Join-Path (Get-CtTempDir) ("ctmon-test-sev-{0}.jsonl" -f (Get-Random))
    $Script:MatchesPath = $sevHistoryPath
    Add-CtMatchRecord -Domain 'risk.example.com' -Group 'example.com' -Source 'certstream' -Dns '' -AlertEnabled $false -Severity 'high' -Score 6 -Reasons @('brand keyword x', 'no DNS record (parked / not yet live)')
    $sevRecs = Get-CtMatchRecords
    Assert 'history: severity round-trip' ($sevRecs.Count -eq 1 -and $sevRecs[0].severity -eq 'high' -and ([int]$sevRecs[0].score) -eq 6 -and "$($sevRecs[0].reasons)".Contains('no DNS record')) "got sev='$($sevRecs[0].severity)' score='$($sevRecs[0].score)' reasons='$($sevRecs[0].reasons)'"
    Remove-Item -LiteralPath $sevHistoryPath -Force -ErrorAction SilentlyContinue
    $Script:MatchesPath = $oldMatchesPath2

    # --- snapshot: risk aggregation + net info + new default config keys ---
    Initialize-CtDashboard
    Add-CtDashMatch -Domain 'risk-a.example.com' -Group 'example.com' -Source 'certstream' -Dns '' -Severity 'high' -Score 5
    Add-CtDashMatch -Domain 'risk-b.example.com' -Group 'example.com' -Source 'certstream' -Dns '9.9.9.9' -Severity 'low' -Score 0
    $snapRisk = New-CtDashboardSnapshot -StatusText 'live'
    $riskRow = $null
    foreach ($rrow in @($snapRisk.risk)) { if ($rrow.group -eq 'example.com') { $riskRow = $rrow; break } }
    Assert 'snapshot: risk aggregation per group' (($null -ne $riskRow) -and ($riskRow.count -eq 2) -and ($riskRow.unresolved -eq 1) -and ($riskRow.max_severity -eq 'high')) "got count=$($riskRow.count) unres=$($riskRow.unresolved) max=$($riskRow.max_severity)"
    Assert 'snapshot: net info present' ($null -ne $snapRisk.net -and $null -ne $snapRisk.net.doh)
    $cfg22 = New-CtDefaultConfig
    Assert 'config: v2.2 keys present' (($null -ne $cfg22.net_proxy) -and ($null -ne $cfg22.doh_enabled) -and ($null -ne $cfg22.digest_weekday) -and ($null -ne $cfg22.metrics_enabled) -and ($null -ne $cfg22.ntfy_topic) -and ($null -ne $cfg22.slack_webhook_url))
    Initialize-CtDashboard


    Write-Host ''
    if ($script:fail -gt 0) {
        Write-CtLog "self-test complete: $script:pass passed, $script:fail failed" -Level ERROR
        exit 1
    } else {
        Write-CtLog "self-test complete: $script:pass passed, $script:fail failed" -Level OK
        exit 0
    }
}

# ============================================================================
#  HELP (crtmon-style usage screen)
# ============================================================================
function Get-CtTargetArgString {
    <# Flatten the -Target array into a single safe command-line string for
       background relaunch / scheduled task registration.
       '-' (stdin) cannot be persisted: fall back to config targets. #>
    param([object]$Target)
    if (-not $Target) { return $null }
    $joined = (@($Target) | ForEach-Object { "$_" }) -join ','
    if ($joined.Trim() -eq '-') {
        Write-CtLog "stdin mode ('-Target -') cannot be used here; the persisted run will use config targets" -Level WARN
        return $null
    }
    return $joined
}

function Show-CtUsage {
    Show-CtBanner
    Write-Host ' usage:' -ForegroundColor Yellow
    Write-Host '   ./CTMon.ps1 -Target example.com'
    Write-Host '   ./CTMon.ps1 -Target example.com,foo.dev -Notify telegram -Source certstream'
    Write-Host '   ./CTMon.ps1 -Target targets.txt'
    Write-Host '   ./CTMon.ps1 -Target (Get-Content targets.txt)'
    Write-Host '   cat targets.txt | pwsh -NoProfile -File ./CTMon.ps1 -Target -'
    Write-Host '   ./CTMon.ps1 -Target example.com -Background        # nohup equivalent'
    Write-Host '   ./CTMon.ps1 -Target example.com -Background -ServeBg # monitor + dashboard'
    Write-Host '   ./CTMon.ps1 -ServeBg                               # dark-mode dashboard (http://127.0.0.1:8080)'
    Write-Host '   ./CTMon.ps1 -Stop                                  # kill monitor + dashboard'
    Write-Host '   ./CTMon.ps1 -Status                                # is it running? stats? dashboard?'
    Write-Host '   ./CTMon.ps1 -InstallTask                           # survive reboots (@reboot equivalent)'
    Write-Host '   ./CTMon.ps1 -Setup                                 # telegram token (.env) / chat id / targets wizard'
    Write-Host '   ./CTMon.ps1 -TestAlert                             # send a test notification'
    Write-Host '   ./CTMon.ps1 -Export -Format csv -Days 30           # export match history'
    Write-Host '   ./CTMon.ps1 -Summary                               # match history report'
    Write-Host '   ./CTMon.ps1 -Prune -Days 90                        # housekeeping'
    Write-Host '   ./CTMon.ps1 -Digest                                # weekly digest now (-Days N window)'
    Write-Host '   ./CTMon.ps1 -SelfTest                              # run the built-in test suite'
    Write-Host ''
    Write-Host ' options:' -ForegroundColor Yellow
    Write-Host '   -Target            target domain, comma list, PowerShell array, targets file path, or - for stdin'
    Write-Host '   -ConfigPath        path to configuration file (default: ~/.config/ctmon/config.json)'
    Write-Host '   -Notify            notification channel: telegram, discord, slack, ntfy, webhook, none'
    Write-Host '   -Source            data source: certstream (real-time), crtsh (polling), certspotter (alt API)'
    Write-Host '   -Digest            build + send the weekly digest now (-Days N, -Notify channel)'
    Write-Host '   -WindowMinutes N   cert window override for crt.sh/certspotter (43200 = 30 day backfill)'
    Write-Host '   -Setup             interactive first-run wizard (secrets -> .env)'
    Write-Host '   -TestAlert         send a test notification and exit'
    Write-Host '   -Background        run monitor detached/hidden in background'
    Write-Host '   -Stop              stop monitor AND dashboard server'
    Write-Host '   -Status            show running state + stats + dashboard'
    Write-Host '   -Serve             run the dashboard web server in the foreground'
    Write-Host '   -ServeBg           run the dashboard web server detached'
    Write-Host '   -Port / -Bind      dashboard port (default 8080/env) and bind address (default 127.0.0.1)'
    Write-Host '   -Dashboard         refresh + open the static dashboard file in the browser'
    Write-Host '   -Export            export match history (with -Format csv|json, -Days N, -OutFile path)'
    Write-Host '   -Summary           print a match-history report (-Days N, default 7)'
    Write-Host '   -Prune             trim history + delete old logs (-Days N, default 90)'
    Write-Host '   -InstallTask       register scheduled task (Windows) / print systemd+cron (Linux)'
    Write-Host '   -UninstallTask     remove the scheduled task'
    Write-Host '   -DryRun            detect matches but do not send notifications'
    Write-Host '   -SelfTest          run built-in self-tests'
    Write-Host '   -Doctor            run local diagnostics'
    Write-Host '   -Version           show version'
    Write-Host '   -h, -Help          show this help message'
    Write-Host ''
    Write-Host ' secrets (.env file next to CTMon.ps1 or in ~/.config/ctmon):' -ForegroundColor Yellow
    Write-Host '   TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, DISCORD_WEBHOOK_URL, GENERIC_WEBHOOK_URL, DASHBOARD_PORT'
    Write-Host '   SLACK_WEBHOOK_URL, NTFY_TOPIC, NTFY_SERVER, NTFY_TOKEN, CERTSPOTTER_TOKEN, HTTPS_PROXY'
    Write-Host '   proxy: HTTPS_PROXY / ALL_PROXY (http/https/socks5) - or net_proxy in config.json'
    Write-Host '   resolution order: process environment > .env > config.json'
    Write-Host ''
    Write-Host ' configuration:' -ForegroundColor Yellow
    Write-Host "   config file location: $Script:DefaultConfigPath"
    Write-Host '   supports multiple targets, keyword watch, seen-history, heartbeat, dns enrichment'
    Write-Host ''
}


# ============================================================================
#  DASHBOARD DATA (snapshot builder + throttled writer; monitor process side)
# ============================================================================
function Get-CtDashboardPort {
    <# Resolve the dashboard port: env DASHBOARD_PORT > selected config dashboard_port > 8080. #>
    param([string]$Path)
    $p = 0
    try { if ($env:DASHBOARD_PORT) { $p = [int]$env:DASHBOARD_PORT } } catch { $p = 0 }
    if ($p -gt 0 -and $p -lt 65536) { return $p }
    $configToRead = $Script:DefaultConfigPath
    if (-not [string]::IsNullOrWhiteSpace($Path)) { $configToRead = $Path }
    try {
        if (Test-Path $configToRead) {
            $cfg = Get-CtConfig -Path $configToRead
            if ($cfg.dashboard_port) {
                $p = [int]$cfg.dashboard_port
                if ($p -gt 0 -and $p -lt 65536) { return $p }
            }
        }
    } catch { }
    return 8080
}

function New-CtHourlyBuckets {
    <# Build 24 empty UTC hour buckets (oldest first). Returns hashtable keyed 'yyyy-MM-ddTHH:00'. #>
    $h = @{}
    $startHour = [datetime]::new((Get-Date).ToUniversalTime().Year, (Get-Date).ToUniversalTime().Month, (Get-Date).ToUniversalTime().Day, (Get-Date).ToUniversalTime().Hour, 0, 0, [System.DateTimeKind]::Utc)
    for ($i = 23; $i -ge 0; $i--) {
        $k = $startHour.AddHours(-1 * $i).ToString('yyyy-MM-ddTHH:00', [System.Globalization.CultureInfo]::InvariantCulture)
        $h[$k] = 0
    }
    return $h
}

function New-CtDashboardSnapshot {
    <# Build the dashboard data object.
       Monitor mode  : live buffers + live stats (StatusText 'live').
       History mode  : rebuilt from state.json + matches.jsonl (StatusText 'offline').
       v2.2 additions: risk aggregates per target group, net/bypass info, severity stats. #>
    param([string]$StatusText = 'live', [switch]$FromHistory)

    $perTarget = @{}
    $matchesList = New-Object System.Collections.Generic.List[object]
    $eventsList = New-Object System.Collections.Generic.List[object]
    $statsOut = @{
        certs_seen = 0; domains_seen = 0; matched = 0; matched_today = 0
        notifications = 0; reconnects = 0; bypass_count = 0
        last_poll_utc = ''; last_poll_source = ''; last_poll_entries = 0
    }
    $uptimeSeconds = 0
    $uptimeText = '-'
    $source = ''
    $historyTotal = 0
    $stateUpdated = ''
    $targetsOut = @()

    if (-not $FromHistory -and $null -ne $Script:Dash) {
        # ---- live monitor mode ----
        foreach ($m in $Script:Dash.Matches) { $matchesList.Add($m) }
        if ($null -ne $Script:DashEvents) { foreach ($e in $Script:DashEvents) { $eventsList.Add($e) } }
        $statsOut.certs_seen = $Script:Stats.certs_seen
        $statsOut.domains_seen = $Script:Stats.domains_seen
        $statsOut.matched = $Script:Stats.matched
        $statsOut.matched_today = $Script:Stats.matched_today
        $statsOut.notifications = $Script:Stats.notifications
        $statsOut.reconnects = $Script:Stats.reconnects
        $statsOut.bypass_count = $Script:Stats.bypass_count
        $statsOut.last_poll_utc = "$($Script:Stats.last_poll_utc)"
        $statsOut.last_poll_source = "$($Script:Stats.last_poll_source)"
        $statsOut.last_poll_entries = [int]$Script:Stats.last_poll_entries
        $perTarget = $Script:Stats.per_target
        $source = "$($Script:Stats.source)"
        $uptimeSeconds = [int]((Get-Date) - $Script:Stats.started).TotalSeconds
        $uptimeText = Get-CtUptimeText -Start $Script:Stats.started
        if ($Script:Stats.targets) { $targetsOut = @($Script:Stats.targets | ForEach-Object { "$_" }) }
    }
    else {
        # ---- history/offline mode (rebuild from disk) ----
        $StatusText = 'offline'
        try {
            if (Test-Path $Script:DefaultConfigPath) {
                $cfgSnap = Get-CtConfig -Path $Script:DefaultConfigPath
                if ($cfgSnap.targets) { $targetsOut = @($cfgSnap.targets | ForEach-Object { "$_" }) }
            }
        } catch { }
        if (Test-Path $Script:StatePath) {
            try {
                $st = [System.IO.File]::ReadAllText($Script:StatePath) | ConvertFrom-Json
                $statsOut.certs_seen = [int]$st.certs_seen
                $statsOut.domains_seen = [int]$st.domains_seen
                $statsOut.matched = [int]$st.matched
                $statsOut.matched_today = [int]$st.matched_today
                $statsOut.notifications = [int]$st.notifications
                $statsOut.reconnects = [int]$st.reconnects
                try { $statsOut.bypass_count = [int]$st.bypass_count } catch { $statsOut.bypass_count = 0 }
                try { $statsOut.last_poll_utc = "$($st.last_poll_utc)" } catch { }
                try { $statsOut.last_poll_source = "$($st.last_poll_source)" } catch { }
                try { $statsOut.last_poll_entries = [int]$st.last_poll_entries } catch { }
                $source = "$($st.source)"
                $stateUpdated = "$($st.updated_utc)"
                if ($st.per_target) {
                    foreach ($p in $st.per_target.PSObject.Properties) { $perTarget[$p.Name] = [int]$p.Value }
                }
                try {
                    $sUtc = [datetime]::Parse("$($st.started_utc)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                    $uptimeSeconds = [int]((Get-Date).ToUniversalTime() - $sUtc).TotalSeconds
                    if ($uptimeSeconds -lt 0) { $uptimeSeconds = 0 }
                    $uptimeText = '{0}h {1:00}m' -f [int][Math]::Floor($uptimeSeconds / 3600), [int](($uptimeSeconds % 3600) / 60)
                } catch { }
            } catch { }
        }
        $recs = Get-CtMatchRecords -Days 0
        $historyTotal = $recs.Count
        $shown = 0
        foreach ($r in $recs) {
            if ($shown -ge 120) { break }
            $matchesList.Add([pscustomobject]@{
                ts_utc = "$($r.ts_utc)"; domain = "$($r.domain)"; group = "$($r.group)"
                source = "$($r.source)"; dns = "$($r.dns)"; keyword = "$($r.keyword)"
                severity = "$($r.severity)"; score = [int]$r.score
            })
            $shown++
        }
    }

    # ---- hourly buckets from the (displayed) match timestamps ----
    $hourly = New-CtHourlyBuckets
    foreach ($m in $matchesList) {
        try {
            $ts = [datetime]::Parse("$($m.ts_utc)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            $k = $ts.ToString('yyyy-MM-ddTHH:00', [System.Globalization.CultureInfo]::InvariantCulture)
            if ($hourly.ContainsKey($k)) { $hourly[$k]++ }
        } catch { }
    }

    # ---- v2.2: risk aggregates per group (feed + recent history window) ----
    $riskAgg = @{}
    foreach ($m in $matchesList) {
        $g = "$($m.group)"
        if (-not $g) { continue }
        if (-not $riskAgg.ContainsKey($g)) {
            $riskAgg[$g] = @{ group = $g; count = 0; unresolved = 0; wildcard = 0; keyword = 0; suspicious = 0; score_sum = 0; max_severity = 'low' }
        }
        $a = $riskAgg[$g]
        $a.count++
        $sev = "$($m.severity)".ToLowerInvariant()
        if ($sev -eq '' -or $sev -eq 'low') { $sev = 'low' }
        try { $a.score_sum += [int]$m.score } catch { }
        if ((Get-CtSeverityWeight -Level $sev) -gt (Get-CtSeverityWeight -Level $a.max_severity)) { $a.max_severity = $sev }
        $dom = "$($m.domain)"
        if (-not $m.dns) { $a.unresolved++ }
        if ($dom.StartsWith('*.')) { $a.wildcard++ }
        if ("$($m.keyword)") { $a.keyword++ }
        foreach ($term in $Script:CtSuspiciousTerms) {
            if ($dom.ToLowerInvariant().Contains($term)) { $a.suspicious++; break }
        }
    }
    $riskOut = @()
    foreach ($g in $riskAgg.Keys) {
        $a = $riskAgg[$g]
        $avg = 0
        if ($a.count -gt 0) { $avg = [Math]::Round($a.score_sum / $a.count, 1) }
        $riskOut += [pscustomobject]@{
            group        = $a.group
            count        = $a.count
            unresolved   = $a.unresolved
            wildcard     = $a.wildcard
            keyword      = $a.keyword
            suspicious   = $a.suspicious
            avg_score    = $avg
            max_severity = $a.max_severity
        }
    }
    $riskOut = @($riskOut | Sort-Object -Property @{ Expression = { Get-CtSeverityWeight -Level $_.max_severity } }, @{ Expression = { $_.count } } -Descending)

    # ---- v2.2: network / bypass info for the header pill ----
    $netOut = @{ proxy = ''; proxy_source = ''; doh = $false }
    try {
        $proxyInfo = Get-CtEffectiveProxy -Config $Script:CtRuntimeConfig
        if ($proxyInfo) {
            $netOut.proxy = "$($proxyInfo.Url)"
            $netOut.proxy_source = "$($proxyInfo.Source)"
        }
        if ($null -ne $Script:CtRuntimeConfig) { $netOut.doh = [bool]$Script:CtRuntimeConfig.doh_enabled }
    } catch { }

    return [pscustomobject]@{
        ctmon_version    = $Script:CTMonVersion
        generated_utc    = (Get-Date).ToUniversalTime().ToString('o')
        status           = $StatusText
        pid              = $PID
        uptime_seconds   = $uptimeSeconds
        uptime_text      = $uptimeText
        source           = $source
        history_total    = $historyTotal
        state_updated_utc = $stateUpdated
        targets          = $targetsOut
        stats            = $statsOut
        per_target       = $perTarget
        hourly           = $hourly
        risk             = $riskOut
        net              = $netOut
        matches          = $matchesList.ToArray()
        events           = $eventsList.ToArray()
    }
}

function Write-CtDashboardData {
    <# Write dashboard-data.json (atomic) + regenerate dashboard.html. Throttled to
       at most one write per 5 seconds unless -Force. Never fatal. #>
    param([switch]$Force)

    if ($null -eq $Script:Dash) { return }
    try {
        $now = (Get-Date)
        if (-not $Force) {
            if (($now - $Script:Dash.LastWrite).TotalSeconds -lt 5) { return }
        }
        $Script:Dash.LastWrite = $now

        $dir = $Script:StateDir
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        $snap = New-CtDashboardSnapshot -StatusText 'live'
        $json = ConvertTo-Json -InputObject $snap -Depth 6 -Compress
        $utf8 = New-Object System.Text.UTF8Encoding($false)

        # atomic-ish write: tmp file then replace
        $tmp = "$($Script:DashDataPath).tmp"
        [System.IO.File]::WriteAllText($tmp, $json, $utf8)
        try {
            if (Test-Path $Script:DashDataPath) { [System.IO.File]::Replace($tmp, $Script:DashDataPath, $null) }
            else { [System.IO.File]::Move($tmp, $Script:DashDataPath) }
        } catch {
            try { [System.IO.File]::Copy($tmp, $Script:DashDataPath, $true); Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch { }
        }

        Write-CtDashboardHtml -OutPath $Script:DashHtmlPath -Snapshot $snap
    } catch { }
}

# ============================================================================
#  DASHBOARD HTML (self-contained dark-mode page, no CDN / no external assets)
# ============================================================================
function Write-CtDashboardHtml {
    <# Render the dashboard template with an embedded JSON snapshot.
       The page fetches api/data every 5 s when served over HTTP; under file://
       it falls back to the embedded snapshot. #>
    param(
        [string]$OutPath = '',
        [object]$Snapshot = $null
    )
    try {
        if ([string]::IsNullOrEmpty($OutPath)) { $OutPath = $Script:DashHtmlPath }
        if ($null -eq $Snapshot) { $Snapshot = New-CtDashboardSnapshot -StatusText 'live' }
        $snapJson = ConvertTo-Json -InputObject $Snapshot -Depth 6 -Compress
        if ($null -eq $snapJson) { $snapJson = '{}' }
        # make the JSON safe to embed inside <script type="application/json">
        $snapJson = $snapJson.Replace('<', '\u003c')

        $dir = Split-Path $OutPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        $html = $Script:CtDashboardTemplate
        $html = $html.Replace('__CTMON_VERSION__', "$Script:CTMonVersion")
        $html = $html.Replace('__CTMON_GENERATED__', (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC'))
        $html = $html.Replace('__CTMON_SNAPSHOT__', $snapJson)

        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($OutPath, $html, $utf8)
    } catch {
        Write-CtLog "could not write dashboard html: $($_.Exception.Message)" -Level WARN
    }
}

$Script:CtDashboardTemplate = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTMon dashboard</title>
<style>
  :root {
    --bg: #0b0f14; --panel: #11161d; --panel2: #151c25; --border: #1e2733;
    --text: #e6edf3; --dim: #8b98a5; --accent: #22d3ee; --green: #34d399;
    --amber: #fbbf24; --red: #f87171; --purple: #a78bfa; --mono: ui-monospace, 'Cascadia Mono', 'JetBrains Mono', Consolas, monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font: 14px/1.45 -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; min-height: 100vh; }
  a { color: var(--accent); text-decoration: none; }
  header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;
           padding: 14px 22px; border-bottom: 1px solid var(--border); background: linear-gradient(180deg, #10161e, #0b0f14); }
  .brand { display: flex; align-items: center; gap: 10px; font-size: 19px; font-weight: 700; letter-spacing: .4px; }
  .logo { color: var(--accent); font-size: 21px; }
  .ver { color: var(--dim); font-size: 12px; font-weight: 400; }
  .head-right { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .pill { display: inline-flex; align-items: center; gap: 7px; padding: 4px 12px; border-radius: 999px;
          font-size: 12px; font-weight: 600; border: 1px solid var(--border); background: var(--panel); }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--dim); }
  .pill.live .dot { background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse 1.6s infinite; }
  .pill.live { color: var(--green); border-color: rgba(52,211,153,.4); }
  .pill.offline { color: var(--amber); border-color: rgba(251,191,36,.4); }
  .pill.offline .dot { background: var(--amber); }
  .pill.snapshot { color: var(--accent); border-color: rgba(34,211,238,.4); }
  .pill.snapshot .dot { background: var(--accent); }
  .pill.net { color: var(--dim); cursor: default; }
  .pill.net.on { color: var(--accent); border-color: rgba(34,211,238,.4); }
  @keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: .35 } }
  .dim { color: var(--dim); font-size: 12px; }
  button { background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 8px;
           padding: 5px 12px; font-size: 12px; cursor: pointer; }
  button:hover { border-color: var(--accent); color: var(--accent); }
  button.paused { color: var(--amber); border-color: rgba(251,191,36,.5); }
  button.kwon { color: var(--green); border-color: rgba(52,211,153,.5); }
  main { padding: 18px 22px 30px; max-width: 1500px; margin: 0 auto; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 18px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 13px 16px; }
  .card .k { color: var(--dim); font-size: 11px; text-transform: uppercase; letter-spacing: .8px; }
  .card .v { font-size: 24px; font-weight: 700; margin-top: 4px; font-variant-numeric: tabular-nums; }
  .card .v.accent { color: var(--accent); } .card .v.green { color: var(--green); }
  .card .v.amber { color: var(--amber); } .card .v.purple { color: var(--purple); }
  .card .v.red { color: var(--red); }
  .grid { display: grid; grid-template-columns: 1fr 360px; gap: 14px; }
  @media (max-width: 980px) { .grid { grid-template-columns: 1fr; } }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; margin-bottom: 14px; }
  .panel h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .9px; color: var(--dim); margin-bottom: 10px; font-weight: 600; }
  .panel-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; }
  .panel-head h2 { margin-bottom: 0; }
  .panel-tools { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  input[type=text] { background: var(--panel2); border: 1px solid var(--border); color: var(--text); border-radius: 8px;
                     padding: 6px 10px; font-size: 12px; width: 180px; outline: none; }
  input[type=text]:focus { border-color: var(--accent); }
  select { background: var(--panel2); border: 1px solid var(--border); color: var(--text); border-radius: 8px;
           padding: 5px 8px; font-size: 12px; outline: none; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .7px; color: var(--dim);
       padding: 6px 8px; border-bottom: 1px solid var(--border); position: sticky; top: 0; background: var(--panel);
       cursor: pointer; user-select: none; white-space: nowrap; }
  th:hover { color: var(--accent); }
  th .arrow { font-size: 9px; margin-left: 3px; color: var(--accent); }
  td { padding: 7px 8px; border-bottom: 1px solid rgba(30,39,51,.55); font-size: 13px; vertical-align: top; }
  td.dom { font-family: var(--mono); font-size: 12.5px; color: var(--accent); word-break: break-all; }
  td.dom mark { background: rgba(251,191,36,.28); color: #fde68a; border-radius: 3px; padding: 0 2px; }
  td.grp { font-family: var(--mono); font-size: 12px; color: var(--purple); white-space: nowrap; }
  td.src { font-size: 11px; color: var(--dim); white-space: nowrap; }
  td.dns { font-family: var(--mono); font-size: 11.5px; color: var(--green); white-space: nowrap; }
  td.dns.none { color: var(--dim); }
  td.tm { color: var(--dim); font-size: 11.5px; white-space: nowrap; }
  .feed-wrap { overflow: auto; max-height: 560px; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 10.5px; border: 1px solid var(--border); color: var(--dim); white-space: nowrap; }
  .badge.new { color: var(--green); border-color: rgba(52,211,153,.45); }
  .badge.kw { color: var(--purple); border-color: rgba(167,139,250,.5); }
  .sev { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 10.5px; font-weight: 700; border: 1px solid var(--border); white-space: nowrap; }
  .sev.sev-low { color: var(--dim); border-color: var(--border); }
  .sev.sev-medium { color: var(--amber); border-color: rgba(251,191,36,.5); }
  .sev.sev-high { color: #fca5a5; border-color: rgba(248,113,113,.55); }
  .sev.sev-critical { color: #fff; background: rgba(248,113,113,.22); border-color: var(--red); }
  .empty { color: var(--dim); font-size: 12.5px; padding: 18px 8px; text-align: center; }
  .chart { display: flex; align-items: flex-end; gap: 3px; height: 90px; }
  .bar { flex: 1; background: linear-gradient(180deg, var(--accent), rgba(34,211,238,.25)); border-radius: 3px 3px 0 0; min-height: 2px; position: relative; }
  .bar .tip { display: none; position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%);
              background: var(--panel2); border: 1px solid var(--border); padding: 2px 7px; border-radius: 6px;
              font-size: 10.5px; white-space: nowrap; z-index: 5; }
  .bar:hover .tip { display: block; }
  .chart-x { display: flex; justify-content: space-between; color: var(--dim); font-size: 10px; margin-top: 5px; }
  .spark-wrap { display: inline-flex; align-items: flex-end; gap: 6px; }
  .trow { margin: 7px 0; }
  .trow .lbl { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 3px; gap: 8px; }
  .trow .lbl .n { color: var(--dim); }
  .trow .track { background: var(--panel2); border-radius: 4px; height: 7px; overflow: hidden; }
  .trow .fill { height: 100%; background: linear-gradient(90deg, var(--purple), var(--accent)); border-radius: 4px; }
  ul.events { list-style: none; max-height: 240px; overflow: auto; }
  ul.events li { font-size: 11.5px; padding: 4px 0; border-bottom: 1px solid rgba(30,39,51,.5); color: var(--dim); }
  ul.events li .lv { font-weight: 700; margin-right: 6px; }
  .lv.MATCH { color: var(--green); } .lv.OK { color: var(--green); } .lv.WARN { color: var(--amber); }
  .lv.ERROR { color: var(--red); } .lv.INFO { color: var(--accent); }
  .radar-box { display: flex; flex-direction: column; align-items: center; gap: 8px; }
  .radar-legend { display: flex; flex-wrap: wrap; gap: 8px 12px; justify-content: center; font-size: 11px; color: var(--dim); }
  .radar-legend b { color: var(--text); font-weight: 600; }
  .radar-note { font-size: 11px; color: var(--dim); text-align: center; }
  footer { text-align: center; color: var(--dim); font-size: 11.5px; padding: 8px 20px 26px; }
  footer code { font-family: var(--mono); color: var(--accent); }
</style>
</head>
<body>
<header>
  <div class="brand"><span class="logo">&#9618;</span> CTMon <span class="ver" id="ver"></span></div>
  <div class="head-right">
    <span class="pill snapshot" id="pill"><span class="dot"></span><span id="pillText">loading&#8230;</span></span>
    <span class="pill net" id="netPill" title="network bypass status">net: -</span>
    <span class="spark-wrap" id="sparkWrap" title="matches / hour trend (24h)"></span>
    <span class="dim" id="uptime"></span>
    <span class="dim" id="srcInfo"></span>
    <button id="pauseBtn" title="pause auto-refresh">&#9208; pause</button>
  </div>
</header>
<main>
  <section class="cards">
    <div class="card"><div class="k">certificates seen</div><div class="v" id="cCerts">&#8211;</div></div>
    <div class="card"><div class="k">domains parsed</div><div class="v" id="cDomains">&#8211;</div></div>
    <div class="card"><div class="k">matches (session)</div><div class="v accent" id="cMatched">&#8211;</div></div>
    <div class="card"><div class="k">matches today</div><div class="v green" id="cToday">&#8211;</div></div>
    <div class="card"><div class="k">high risk</div><div class="v red" id="cRisk">&#8211;</div></div>
    <div class="card"><div class="k">notifications</div><div class="v purple" id="cNotif">&#8211;</div></div>
    <div class="card"><div class="k">reconnects</div><div class="v amber" id="cReconn">&#8211;</div></div>
    <div class="card"><div class="k">bypass used</div><div class="v accent" id="cBypass">&#8211;</div></div>
  </section>
  <section class="grid">
    <div class="panel">
      <div class="panel-head">
        <h2>live match feed</h2>
        <div class="panel-tools">
          <input type="text" id="q" placeholder="filter domains / targets&#8230;" spellcheck="false">
          <button id="kwBtn" title="highlight brand keywords in domains">&#10003; kw</button>
          <button id="csvBtn" title="download the current (filtered) feed as CSV">&#8595; csv</button>
        </div>
      </div>
      <div class="feed-wrap">
        <table>
          <thead><tr>
            <th data-key="ts">time<span class="arrow"></span></th>
            <th data-key="domain">new subdomain<span class="arrow"></span></th>
            <th data-key="group">target<span class="arrow"></span></th>
            <th data-key="source">src<span class="arrow"></span></th>
            <th data-key="dns">dns<span class="arrow"></span></th>
            <th data-key="severity">risk<span class="arrow"></span></th>
            <th>alert</th>
          </tr></thead>
          <tbody id="feedBody"></tbody>
        </table>
        <div class="empty" id="feedEmpty">no matches yet &#8212; the feed fills up as new certificates appear</div>
      </div>
    </div>
    <div class="side">
      <div class="panel">
        <h2>matches / hour (24h)</h2>
        <div class="chart" id="chart"></div>
        <div class="chart-x"><span id="chartStart">-24h</span><span id="chartEnd">now</span></div>
      </div>
      <div class="panel">
        <div class="panel-head">
          <h2>threat radar</h2>
          <select id="radarTarget" title="pick a target group"><option value="">(all)</option></select>
        </div>
        <div class="radar-box">
          <svg id="radar" width="300" height="220" viewBox="0 0 300 220" role="img" aria-label="risk radar"></svg>
          <div class="radar-legend" id="radarLegend"></div>
          <div class="radar-note">wildcard &#183; unresolved &#183; keyword &#183; suspicious &#183; volume</div>
        </div>
      </div>
      <div class="panel">
        <h2>per target</h2>
        <div id="perTarget"><div class="empty">nothing yet</div></div>
      </div>
      <div class="panel">
        <h2>events</h2>
        <ul class="events" id="events"><li>no events yet</li></ul>
      </div>
    </div>
  </section>
</main>
<footer>
  CTMon <span id="ver2"></span> &#183; generated <span id="gen"></span> &#183;
  <span id="modeHint">live mode: auto-refresh 5s &#183; run <code>CTMon.ps1 -ServeBg</code> for the live view</span>
</footer>
<script id="snapshot" type="application/json">__CTMON_SNAPSHOT__</script>
<script>
(function () {
  'use strict';
  var snapEl = document.getElementById('snapshot');
  var embedded = null;
  try { embedded = JSON.parse(snapEl.textContent); } catch (e) { embedded = null; }

  var data = (embedded && typeof embedded === 'object' && embedded.ctmon_version) ? embedded
             : { status: 'offline', stats: {}, matches: [], events: [], per_target: {}, hourly: {}, risk: [] };
  var live = false;        // true once a fetch() succeeds (http serving)
  var paused = false;
  var kwHighlight = false;
  var sortKey = 'ts';
  var sortDir = -1;        // newest first by default; click toggles / a-z on first click per column

  function arr(x) { return Array.isArray(x) ? x : (x ? [x] : []); }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function asObj(x) { return (x && typeof x === 'object' && !Array.isArray(x)) ? x : {}; }

  function fmtTime(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return esc(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  function setPill(mode, text) {
    var pill = document.getElementById('pill');
    pill.className = 'pill ' + mode;
    document.getElementById('pillText').textContent = text;
  }

  function sevClass(level) {
    var l = String(level || 'low').toLowerCase();
    if (l !== 'low' && l !== 'medium' && l !== 'high' && l !== 'critical') l = 'low';
    return 'sev sev-' + l;
  }
  function sevWeight(level) {
    switch (String(level || '').toLowerCase()) {
      case 'critical': return 4;
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 0;
    }
  }

  function highlightKw(domain, kw) {
    if (!kwHighlight || !kw) return esc(domain);
    var idx = String(domain).toLowerCase().indexOf(String(kw).toLowerCase());
    if (idx < 0) return esc(domain);
    return esc(domain.slice(0, idx)) + '<mark>' + esc(domain.slice(idx, idx + kw.length)) + '</mark>' + esc(domain.slice(idx + kw.length));
  }

  // ---------- sparkline (matches/hour, last 24h) ----------
  function renderSpark() {
    var wrap = document.getElementById('sparkWrap');
    wrap.innerHTML = '';
    var hourly = asObj(data.hourly);
    var keys = Object.keys(hourly).sort();
    if (!keys.length) { wrap.style.display = 'none'; return; }
    wrap.style.display = 'inline-flex';
    var vals = keys.map(function (k) { return hourly[k]; });
    var max = 1;
    for (var i = 0; i < vals.length; i++) if (vals[i] > max) max = vals[i];
    var w = 90, h = 22, step = w / (vals.length - 1 || 1);
    var pts = [];
    for (var j = 0; j < vals.length; j++) {
      var x = (j * step).toFixed(1);
      var y = (h - 2 - (vals[j] / max) * (h - 4)).toFixed(1);
      pts.push(x + ',' + y);
    }
    var svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">'
      + '<polyline points="' + pts.join(' ') + '" fill="none" stroke="#22d3ee" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" opacity=".9"/>'
      + '</svg>';
    wrap.innerHTML = svg;
  }

  // ---------- threat radar ----------
  function renderRadar() {
    var svg = document.getElementById('radar');
    var sel = document.getElementById('radarTarget');
    var legend = document.getElementById('radarLegend');
    var riskAll = arr(data.risk);
    // keep dropdown options in sync
    var groups = riskAll.map(function (r) { return r.group; });
    var currentSel = sel.value;
    var wantOpts = [''].concat(groups);
    var optSig = wantOpts.join('|');
    if (sel.getAttribute('data-sig') !== optSig) {
      sel.innerHTML = '';
      var optAll = document.createElement('option');
      optAll.value = ''; optAll.textContent = '(all groups)';
      sel.appendChild(optAll);
      for (var gi = 0; gi < groups.length; gi++) {
        var o = document.createElement('option');
        o.value = groups[gi]; o.textContent = groups[gi];
        sel.appendChild(o);
      }
      sel.setAttribute('data-sig', optSig);
    }
    sel.value = currentSel;
    if (sel.value !== currentSel && sel.options.length) sel.selectedIndex = 0;
    var pick = sel.value;

    var groupsUse = pick ? riskAll.filter(function (r) { return r.group === pick; }) : riskAll;
    if (!groupsUse.length) {
      svg.innerHTML = '<text x="150" y="112" text-anchor="middle" fill="#8b98a5" font-size="12">no risk data yet</text>';
      legend.innerHTML = '';
      return;
    }

    // aggregate selected groups (all) or single group
    var agg = { count: 0, unresolved: 0, wildcard: 0, keyword: 0, suspicious: 0, score: 0 };
    var maxCount = 1;
    for (var i = 0; i < groupsUse.length; i++) {
      var r = groupsUse[i];
      agg.count += (r.count || 0);
      agg.unresolved += (r.unresolved || 0);
      agg.wildcard += (r.wildcard || 0);
      agg.keyword += (r.keyword || 0);
      agg.suspicious += (r.suspicious || 0);
      agg.score += ((r.avg_score || 0) * (r.count || 0));
      if ((r.count || 0) > maxCount) maxCount = r.count;
    }
    var avgScore = agg.count ? (agg.score / agg.count) : 0;

    var axes = [
      { label: 'volume',     v: Math.min(1, agg.count / Math.max(6, maxCount)) },
      { label: 'wildcard',   v: agg.count ? Math.min(1, agg.wildcard / agg.count) : 0 },
      { label: 'unresolved', v: agg.count ? Math.min(1, agg.unresolved / agg.count) : 0 },
      { label: 'keyword',    v: agg.count ? Math.min(1, agg.keyword / agg.count) : 0 },
      { label: 'suspicious', v: agg.count ? Math.min(1, agg.suspicious / agg.count) : 0 }
    ];
    // severity as a 6th axis derived from average score (10 = critical zone)
    var sevV = Math.min(1, avgScore / 10);

    var cx = 150, cy = 112, R = 82;
    var n = 6;
    function pt(i, frac) {
      var ang = -Math.PI / 2 + (i * 2 * Math.PI / n);
      return [cx + Math.cos(ang) * R * frac, cy + Math.sin(ang) * R * frac];
    }
    var out = [];
    // grid rings
    for (var ring = 1; ring <= 4; ring++) {
      var ringPts = [];
      for (var a = 0; a < n; a++) { var p = pt(a, ring / 4); ringPts.push(p[0].toFixed(1) + ',' + p[1].toFixed(1)); }
      out.push('<polygon points="' + ringPts.join(' ') + '" fill="none" stroke="#1e2733" stroke-width="1"/>');
    }
    // spokes + labels
    var vals = [axes[0].v, axes[1].v, axes[2].v, axes[3].v, axes[4].v, sevV];
    var labels = ['vol', 'wild', 'unres', 'kw', 'sus', 'sev'];
    for (var s = 0; s < n; s++) {
      var p2 = pt(s, 1);
      out.push('<line x1="' + cx + '" y1="' + cy + '" x2="' + p2[0].toFixed(1) + '" y2="' + p2[1].toFixed(1) + '" stroke="#1e2733" stroke-width="1"/>');
      var pl = pt(s, 1.18);
      var anchor = 'middle';
      if (pl[0] > cx + 4) anchor = 'start'; else if (pl[0] < cx - 4) anchor = 'end';
      out.push('<text x="' + pl[0].toFixed(1) + '" y="' + (pl[1] + 3).toFixed(1) + '" text-anchor="' + anchor + '" fill="#8b98a5" font-size="10">' + labels[s] + '</text>');
    }
    // data polygon
    var dataPts = [];
    for (var d = 0; d < n; d++) {
      var frac = Math.max(0.04, Math.min(1, vals[d]));
      var p3 = pt(d, frac);
      dataPts.push(p3[0].toFixed(1) + ',' + p3[1].toFixed(1));
      out.push('<circle cx="' + p3[0].toFixed(1) + '" cy="' + p3[1].toFixed(1) + '" r="2.5" fill="#22d3ee"/>');
    }
    var color = avgScore >= 7 ? '#f87171' : (avgScore >= 4 ? '#fbbf24' : '#22d3ee');
    out.push('<polygon points="' + dataPts.join(' ') + '" fill="' + color + '22" stroke="' + color + '" stroke-width="1.6"/>');
    svg.innerHTML = out.join('');

    var legendBits = [];
    if (pick) legendBits.push('<b>' + esc(pick) + '</b>');
    legendBits.push('avg score <b>' + avgScore.toFixed(1) + '</b>');
    legendBits.push('assets <b>' + agg.count + '</b>');
    if (agg.wildcard) legendBits.push('wildcard <b>' + agg.wildcard + '</b>');
    if (agg.unresolved) legendBits.push('unresolved <b>' + agg.unresolved + '</b>');
    if (agg.keyword) legendBits.push('kw <b>' + agg.keyword + '</b>');
    legend.innerHTML = legendBits.join(' &#183; ');
  }

  // ---------- feed ----------
  function renderFeed() {
    var q = document.getElementById('q').value.toLowerCase();
    var body = document.getElementById('feedBody');
    body.innerHTML = '';
    var rows = arr(data.matches);
    var filtered = [];
    for (var i = 0; i < rows.length; i++) {
      var m = rows[i];
      var hay = String(m.domain || '') + ' ' + String(m.group || '') + ' ' + String(m.source || '') + ' ' + String(m.keyword || '');
      if (q && hay.toLowerCase().indexOf(q) < 0) continue;
      filtered.push(m);
    }
    // sorting
    filtered.sort(function (a, b) {
      var va, vb;
      switch (sortKey) {
        case 'ts': va = new Date(a.ts_utc || 0).getTime() || 0; vb = new Date(b.ts_utc || 0).getTime() || 0; break;
        case 'domain': va = String(a.domain || '').toLowerCase(); vb = String(b.domain || '').toLowerCase(); break;
        case 'group': va = String(a.group || '').toLowerCase(); vb = String(b.group || '').toLowerCase(); break;
        case 'source': va = String(a.source || '').toLowerCase(); vb = String(b.source || '').toLowerCase(); break;
        case 'dns': va = a.dns ? 1 : 0; vb = b.dns ? 1 : 0; break;
        case 'severity': va = sevWeight(a.severity); vb = sevWeight(b.severity); break;
        default: va = 0; vb = 0;
      }
      if (va < vb) return -1 * sortDir;
      if (va > vb) return 1 * sortDir;
      return 0;
    });

    // header arrows
    var ths = document.querySelectorAll('th[data-key]');
    for (var t = 0; t < ths.length; t++) {
      var arrow = ths[t].querySelector('.arrow');
      if (arrow) arrow.textContent = (ths[t].getAttribute('data-key') === sortKey) ? (sortDir === 1 ? '▲' : '▼') : '';
    }

    var shownRows = 0;
    for (var r = 0; r < filtered.length && shownRows < 100; r++) {
      var mm = filtered[r];
      var dnsTxt = mm.dns ? esc(mm.dns) : 'unresolved';
      var dnsCls = mm.dns ? 'dns' : 'dns none';
      var alertBit = mm.keyword ? '<span class="badge kw">kw</span>' : '<span class="badge new">new</span>';
      var sev = mm.severity ? String(mm.severity).toLowerCase() : 'low';
      var sevTxt = mm.severity ? mm.severity + (mm.score ? ' ' + mm.score : '') : 'low';
      var tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="tm">' + fmtTime(mm.ts_utc) + '</td>' +
        '<td class="dom">' + highlightKw(mm.domain, mm.keyword) + '</td>' +
        '<td class="grp">' + esc(mm.group) + '</td>' +
        '<td class="src">' + esc(mm.source) + '</td>' +
        '<td class="' + dnsCls + '">' + dnsTxt + '</td>' +
        '<td><span class="' + sevClass(sev) + '">' + esc(sevTxt) + '</span></td>' +
        '<td>' + alertBit + '</td>';
      body.appendChild(tr);
      shownRows++;
    }
    document.getElementById('feedEmpty').style.display = (shownRows === 0) ? 'block' : 'none';
  }

  // ---------- csv export ----------
  function downloadCsv() {
    var q = document.getElementById('q').value.toLowerCase();
    var rows = arr(data.matches).filter(function (m) {
      if (!q) return true;
      var hay = String(m.domain || '') + ' ' + String(m.group || '');
      return hay.toLowerCase().indexOf(q) >= 0;
    });
    function csvField(v) { return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; }
    var lines = ['ts_utc,domain,target,source,dns,risk,score,keyword'];
    for (var i = 0; i < rows.length; i++) {
      var m = rows[i];
      lines.push([csvField(m.ts_utc), csvField(m.domain), csvField(m.group), csvField(m.source),
                  csvField(m.dns), csvField(m.severity || 'low'), csvField(m.score || 0), csvField(m.keyword)].join(','));
    }
    var blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'ctmon-matches-' + new Date().toISOString().slice(0, 10) + '.csv';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 300);
  }

  function render() {
    var st = asObj(data.stats);
    var ver = data.ctmon_version || '';
    document.getElementById('ver').textContent = 'v' + ver;
    document.getElementById('ver2').textContent = 'v' + ver;
    document.getElementById('cCerts').textContent = st.certs_seen != null ? st.certs_seen : '–';
    document.getElementById('cDomains').textContent = st.domains_seen != null ? st.domains_seen : '–';
    document.getElementById('cMatched').textContent = st.matched != null ? st.matched : '–';
    document.getElementById('cToday').textContent = st.matched_today != null ? st.matched_today : '–';
    document.getElementById('cNotif').textContent = st.notifications != null ? st.notifications : '–';
    document.getElementById('cReconn').textContent = st.reconnects != null ? st.reconnects : '–';
    document.getElementById('cBypass').textContent = st.bypass_count != null ? st.bypass_count : '–';

    // high-risk counter from the visible feed + risk data
    var riskHigh = 0;
    var rowsAll = arr(data.matches);
    for (var i = 0; i < rowsAll.length; i++) {
      var sv = String(rowsAll[i].severity || '').toLowerCase();
      if (sv === 'high' || sv === 'critical') riskHigh++;
    }
    document.getElementById('cRisk').textContent = riskHigh;

    // net / bypass pill
    var net = asObj(data.net);
    var netPill = document.getElementById('netPill');
    var netBits = [];
    if (net.proxy) netBits.push('proxy: ' + String(net.proxy).replace(/^(\w+:\/\/)[^@]*@/, '$1***@'));
    if (net.doh) netBits.push('doh: on');
    var bypasses = st.bypass_count || 0;
    if (bypasses > 0) netBits.push('bypassed ×' + bypasses);
    if (netBits.length) {
      netPill.className = 'pill net on';
      netPill.textContent = netBits.join(' · ');
    } else {
      netPill.className = 'pill net';
      netPill.textContent = 'net: direct';
    }

    document.getElementById('uptime').textContent = data.uptime_text ? ('up ' + data.uptime_text) : '';
    var srcBits = [];
    if (data.source) srcBits.push('source: ' + data.source);
    var lp = st.last_poll_utc ? new Date(st.last_poll_utc) : null;
    if (lp && !isNaN(lp.getTime())) {
        var lpTxt = 'last poll ' + lp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        if (st.last_poll_source) lpTxt += ' via ' + st.last_poll_source;
        if (st.last_poll_entries != null) lpTxt += ' (' + st.last_poll_entries + ' certs)';
        srcBits.push(lpTxt);
    }
    srcBits.push('targets: ' + arr(data.targets).length);
    document.getElementById('srcInfo').textContent = srcBits.join(' · ');

    if (live) {
      if (data.status === 'live') setPill('live', 'LIVE');
      else setPill('offline', 'MONITOR OFFLINE');
      document.getElementById('modeHint').innerHTML = 'live dashboard · auto-refresh 5s · <code>api/data</code> · <code>api/metrics</code>';
    } else {
      setPill('snapshot', 'SNAPSHOT');
      document.getElementById('modeHint').innerHTML = 'static snapshot · run <code>CTMon.ps1 -ServeBg</code> for the live view';
    }
    document.getElementById('gen').textContent = data.generated_utc ? String(data.generated_utc).replace('T', ' ').replace('Z', ' UTC') : '–';

    renderFeed();
    renderSpark();

    // ---- hourly chart ----
    var chart = document.getElementById('chart');
    chart.innerHTML = '';
    var hourly = asObj(data.hourly);
    var keys = Object.keys(hourly).sort();
    var max = 1;
    for (var j = 0; j < keys.length; j++) if (hourly[keys[j]] > max) max = hourly[keys[j]];
    for (var k = 0; k < keys.length; k++) {
      var v = hourly[keys[k]];
      var bar = document.createElement('div');
      bar.className = 'bar';
      bar.style.height = Math.max(2, Math.round(v / max * 100)) + '%';
      bar.innerHTML = '<span class="tip">' + esc(keys[k].slice(5, 13)) + ' — ' + v + '</span>';
      chart.appendChild(bar);
    }
    document.getElementById('chartEnd').textContent = 'now UTC';
    document.getElementById('chartStart').textContent = (keys.length ? keys[0].slice(5, 13) : '-24h');

    renderRadar();

    // ---- per target ----
    var pt = asObj(data.per_target);
    var ptKeys = Object.keys(pt).sort(function (a, b) { return pt[b] - pt[a]; });
    var ptEl = document.getElementById('perTarget');
    ptEl.innerHTML = '';
    if (!ptKeys.length) { ptEl.innerHTML = '<div class="empty">nothing yet</div>'; }
    var ptMax = 1;
    for (var p1 = 0; p1 < ptKeys.length; p1++) if (pt[ptKeys[p1]] > ptMax) ptMax = pt[ptKeys[p1]];
    for (var p = 0; p < ptKeys.length && p < 8; p++) {
      var name = ptKeys[p];
      var cnt = pt[name];
      var row = document.createElement('div');
      row.className = 'trow';
      row.innerHTML = '<div class="lbl"><span>' + esc(name) + '</span><span class="n">' + cnt + '</span></div>' +
        '<div class="track"><div class="fill" style="width:' + Math.round(cnt / ptMax * 100) + '%"></div></div>';
      ptEl.appendChild(row);
    }

    // ---- events ----
    var ev = document.getElementById('events');
    ev.innerHTML = '';
    var evs = arr(data.events);
    if (!evs.length) { ev.innerHTML = '<li>no events yet</li>'; }
    for (var e = 0; e < evs.length && e < 30; e++) {
      var item = evs[e];
      var li = document.createElement('li');
      li.innerHTML = '<span class="lv ' + esc(item.level) + '">' + esc(item.level) + '</span>' +
                     esc(item.message) + ' <span style="opacity:.6">· ' + fmtTime(item.ts_utc) + '</span>';
      ev.appendChild(li);
    }
  }

  function tick() {
    if (paused) return;
    fetch('api/data', { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('http ' + r.status); return r.json(); })
      .then(function (j) { live = true; data = j; render(); })
      .catch(function () { if (live) { live = false; render(); } });
  }

  document.getElementById('pauseBtn').addEventListener('click', function () {
    paused = !paused;
    this.textContent = paused ? '\u25B6 resume' : '\u23F8 pause';
    this.className = paused ? 'paused' : '';
  });
  document.getElementById('kwBtn').addEventListener('click', function () {
    kwHighlight = !kwHighlight;
    this.className = kwHighlight ? 'kwon' : '';
    render();
  });
  document.getElementById('csvBtn').addEventListener('click', downloadCsv);
  document.getElementById('q').addEventListener('input', renderFeed);
  document.getElementById('radarTarget').addEventListener('change', renderRadar);
  var thList = document.querySelectorAll('th[data-key]');
  for (var ti = 0; ti < thList.length; ti++) {
    thList[ti].addEventListener('click', function () {
      var key = this.getAttribute('data-key');
      if (sortKey === key) { sortDir = sortDir * -1; } else { sortKey = key; sortDir = 1; }
      renderFeed();
    });
  }

  render();
  tick();
  setInterval(tick, 5000);
})();
</script>
</body>
</html>
'@


# ============================================================================
#  EXPORT / SUMMARY / PRUNE (match history utilities)
# ============================================================================
function Invoke-CtExport {
    <# Export match history to CSV or JSON. Returns the number of exported records. #>
    param(
        [ValidateSet('csv', 'json')][string]$Format = 'csv',
        [int]$Days = 30,
        [string]$OutFile = ''
    )

    $recs = @(Get-CtMatchRecords -Days $Days)
    if ([string]::IsNullOrWhiteSpace($OutFile)) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $OutFile = Join-Path (Get-Location) ("ctmon-matches-{0}.{1}" -f $stamp, $Format)
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)

    if ($Format -eq 'json') {
        $json = ConvertTo-Json -InputObject $recs -Depth 5
        if (@($recs).Count -eq 0) { $json = '[]' }
        [System.IO.File]::WriteAllText($OutFile, $json, $utf8)
    }
    else {
        function ConvertTo-CtCsvField([string]$v) {
            if ($null -eq $v) { $v = '' }
            return '"' + ($v -replace '"', '""') + '"'
        }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('ts_utc,ts_local,domain,group,keyword,source,dns,alert_sent').Append([Environment]::NewLine)
        foreach ($r in $recs) {
            $tsLocal = ''
            try {
                $ts = [datetime]::Parse("$($r.ts_utc)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                $tsLocal = $ts.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
            } catch { }
            $line = (ConvertTo-CtCsvField "$($r.ts_utc)") + ',' +
                    (ConvertTo-CtCsvField $tsLocal) + ',' +
                    (ConvertTo-CtCsvField "$($r.domain)") + ',' +
                    (ConvertTo-CtCsvField "$($r.group)") + ',' +
                    (ConvertTo-CtCsvField "$($r.keyword)") + ',' +
                    (ConvertTo-CtCsvField "$($r.source)") + ',' +
                    (ConvertTo-CtCsvField "$($r.dns)") + ',' +
                    (ConvertTo-CtCsvField "$($r.alert)")
            [void]$sb.Append($line).Append([Environment]::NewLine)
        }
        [System.IO.File]::WriteAllText($OutFile, $sb.ToString(), $utf8)
    }

    Write-CtLog "exported $($recs.Count) record(s) to: $OutFile" -Level OK
    return $recs.Count
}

function Show-CtSummaryReport {
    <# Console report over the match history (what -Summary prints). #>
    param([int]$Days = 7)

    $recs = @(Get-CtMatchRecords -Days $Days)
    Write-Host ''
    Write-Host " $($Script:EmojiStat) match history - last $Days day(s)" -ForegroundColor Yellow
    if ($recs.Count -eq 0) {
        Write-Host ' no matches recorded in this window' -ForegroundColor Gray
        Write-Host ''
        return
    }

    Write-Host (" total matches   : {0}" -f $recs.Count) -ForegroundColor Gray

    # per group
    $byGroup = @{}
    $bySource = @{}
    $resolved = 0
    foreach ($r in $recs) {
        $g = "$($r.group)"
        if (-not $byGroup.ContainsKey($g)) { $byGroup[$g] = 0 }
        $byGroup[$g]++
        $src = "$($r.source)"
        if (-not $bySource.ContainsKey($src)) { $bySource[$src] = 0 }
        $bySource[$src]++
        if ("$($r.dns)" -ne '') { $resolved++ }
    }
    Write-Host ' per target      :' -ForegroundColor Gray
    $top = $byGroup.Keys | Sort-Object { $byGroup[$_]* -1 } | Select-Object -First 15
    foreach ($g in $top) { Write-Host ("   {0,-40} {1}" -f $g, $byGroup[$g]) -ForegroundColor Gray }

    Write-Host ' per source      :' -ForegroundColor Gray
    foreach ($s in $bySource.Keys) { Write-Host ("   {0,-40} {1}" -f $s, $bySource[$s]) -ForegroundColor Gray }

    $pct = [int][Math]::Round(100.0 * $resolved / $recs.Count)
    Write-Host (" dns resolved    : {0}/{1} ({2}%)" -f $resolved, $recs.Count, $pct) -ForegroundColor Gray
    Write-Host (" first match     : {0}" -f $recs[$recs.Count - 1].ts_utc) -ForegroundColor Gray
    Write-Host (" last match      : {0}" -f $recs[0].ts_utc) -ForegroundColor Gray

    # per day counts
    $byDay = @{}
    foreach ($r in $recs) {
        try {
            $ts = [datetime]::Parse("$($r.ts_utc)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            $d = $ts.ToLocalTime().ToString('yyyy-MM-dd')
            if (-not $byDay.ContainsKey($d)) { $byDay[$d] = 0 }
            $byDay[$d]++
        } catch { }
    }
    Write-Host ' per day         :' -ForegroundColor Gray
    foreach ($d in ($byDay.Keys | Sort-Object)) { Write-Host ("   {0}  {1}" -f $d, ('#' * [Math]::Min(60, $byDay[$d])) + " $($byDay[$d])") -ForegroundColor Gray }
    Write-Host ''
}

function Invoke-CtPrune {
    <# Housekeeping: trim match history + dns cache, delete old logs. #>
    param([int]$Days = 90)

    $freed = 0
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-1 * [Math]::Max(1, $Days))

    # 1) match history
    if (Test-Path $Script:MatchesPath) {
        $keep = New-Object System.Collections.Generic.List[string]
        try {
            $lines = [System.IO.File]::ReadAllLines($Script:MatchesPath)
            foreach ($l in $lines) {
                $in = $false
                if (-not [string]::IsNullOrWhiteSpace($l)) {
                    try {
                        $r = $l | ConvertFrom-Json
                        $ts = [datetime]::Parse("$($r.ts_utc)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                        if ($ts -ge $cutoff) { $in = $true }
                    } catch { $in = $true }   # keep unparsable lines (safe side)
                }
                if ($in) { $keep.Add($l) }
            }
            if ($keep.Count -lt $lines.Count) {
                $freed += $lines.Count - $keep.Count
                $utf8 = New-Object System.Text.UTF8Encoding($false)
                $content = ''
                if ($keep.Count -gt 0) { $content = (($keep.ToArray() -join [Environment]::NewLine) + [Environment]::NewLine) }
                [System.IO.File]::WriteAllText($Script:MatchesPath, $content, $utf8)
            }
        } catch {
            Write-CtLog "could not prune match history: $($_.Exception.Message)" -Level WARN
        }
    }

    # 2) old log files
    if (Test-Path $Script:LogDir) {
        try {
            $oldLogs = Get-ChildItem -LiteralPath $Script:LogDir -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-1 * $Days) }
            foreach ($f in $oldLogs) { $freed++; Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
        } catch { }
    }

    # 3) stale dns cache entries
    if (Test-Path $Script:DnsCachePath) {
        try {
            $cache = New-CtDnsCache -Path $Script:DnsCachePath
            $before = $cache.Map.Count
            foreach ($k in @($cache.Map.Keys)) {
                $e = $cache.Map[$k]
                if ((($cache.PositiveHours -lt $Days * 24) -and $e.ok) -or (-not $e.ok)) {
                    # keep resolved entries up to their own TTL; negatives are dropped
                }
                try {
                    if (((Get-Date) - ([datetime]$e.ts)).TotalDays -gt $Days) { $cache.Map.Remove($k) }
                } catch { }
            }
            if ($cache.Map.Count -lt $before) {
                $freed += $before - $cache.Map.Count
                $cache.Dirty = $true
                Save-CtDnsCache -Cache $cache
            }
        } catch { }
    }

    Write-CtLog "prune complete (retention: $Days day(s)) - removed $freed item(s)" -Level OK
}

# ============================================================================
#  STATIC DASHBOARD LAUNCHER (-Dashboard)
# ============================================================================
function Invoke-CtDashboardOpen {
    <# Rebuild the static dashboard from history/state and open it in the browser. #>
    $snap = New-CtDashboardSnapshot -StatusText 'live' -FromHistory
    Write-CtDashboardHtml -OutPath $Script:DashHtmlPath -Snapshot $snap

    # also refresh the json so a later -Serve picks up consistent data
    try {
        $json = ConvertTo-Json -InputObject $snap -Depth 6 -Compress
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Script:DashDataPath, $json, $utf8)
    } catch { }

    Write-CtLog "dashboard written: $Script:DashHtmlPath" -Level OK
    if ($snap.status -eq 'offline' -or (-not $snap.status)) {
        Write-CtLog 'monitor is not running - the page shows persisted history (start with -Background, live view with -ServeBg)' -Level INFO
    }
    try {
        if ($Script:IsWindowsPS) {
            Start-Process -FilePath $Script:DashHtmlPath | Out-Null
            Write-CtLog 'opened in your default browser' -Level OK
        } else {
            try {
                Start-Process -FilePath 'xdg-open' -ArgumentList "`"$Script:DashHtmlPath`"" -ErrorAction Stop | Out-Null
                Write-CtLog 'opened in your browser' -Level OK
            } catch {
                Write-CtLog "could not auto-open a browser - open the file manually: $Script:DashHtmlPath" -Level WARN
            }
        }
    } catch {
        Write-CtLog "could not auto-open a browser - open the file manually: $Script:DashHtmlPath" -Level WARN
    }
}


# ============================================================================
#  BUILT-IN DASHBOARD SERVER (raw TcpListener HTTP - no admin rights needed,
#  works identically on PS 5.1 / PS 7 / Windows / Linux / macOS)
# ============================================================================
function Get-CtHttpRequestPath {
    <# Extract the URL path (no query string) from an HTTP request line, e.g.
       'GET /api/data?x=1 HTTP/1.1'  ->  '/api/data'  (served by -SelfTest too) #>
    param([string]$RequestLine)

    if ([string]::IsNullOrWhiteSpace($RequestLine)) { return '/' }
    $parts = @("$RequestLine".Trim() -split '\s+')
    $target = '/'
    if ($parts.Count -ge 2) { $target = $parts[1] } elseif ($parts.Count -ge 1) { $target = $parts[0] }
    $q = $target.IndexOf('?')
    if ($q -ge 0) { $target = $target.Substring(0, $q) }
    $h = $target.IndexOf('#')
    if ($h -ge 0) { $target = $target.Substring(0, $h) }
    if ($target -eq '') { $target = '/' }
    return $target
}

function Get-CtHttpRequestMethod {
    <# Extract the HTTP method from a request line. #>
    param([string]$RequestLine)
    if ([string]::IsNullOrWhiteSpace($RequestLine)) { return 'GET' }
    $parts = @("$RequestLine".Trim() -split '\s+')
    if ($parts.Count -ge 1) { return $parts[0].ToUpperInvariant() }
    return 'GET'
}

function Test-CtMonitorAlive {
    <# Is a monitor instance currently running (pid file + live process)? #>
    $info = Test-CtPidAlive -Path $Script:PidPath
    return ($null -ne $info)
}

function Send-CtHttpResponse {
    <# Write one complete HTTP/1.1 response and return. #>
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [int]$Status = 200,
        [string]$StatusText = 'OK',
        [string]$ContentType = 'text/html; charset=utf-8',
        [byte[]]$Body = @(),
        [switch]$AllowCors
    )

    $hdr = "HTTP/1.1 $Status $StatusText`r`n"
    $hdr += "Content-Type: $ContentType`r`n"
    $hdr += "Content-Length: $($Body.Length)`r`n"
    $hdr += "Connection: close`r`n"
    $hdr += "Cache-Control: no-store`r`n"
    if ($AllowCors) { $hdr += "Access-Control-Allow-Origin: *`r`n" }
    $hdr += "X-Content-Type-Options: nosniff`r`n"
    $hdr += "`r`n"
    $hdrBytes = [System.Text.Encoding]::ASCII.GetBytes($hdr)
    $Stream.Write($hdrBytes, 0, $hdrBytes.Length)
    if ($Body.Length -gt 0) { $Stream.Write($Body, 0, $Body.Length) }
}

function Read-CtDashboardDataFile {
    <# Read dashboard-data.json; create a fresh offline snapshot if the file does not
       exist yet (first dashboard run without a monitor). #>
    if (-not (Test-Path $Script:DashDataPath)) {
        try {
            $snap = New-CtDashboardSnapshot -StatusText 'offline' -FromHistory
            $json = ConvertTo-Json -InputObject $snap -Depth 6 -Compress
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            if (-not (Test-Path $Script:StateDir)) { New-Item -ItemType Directory -Path $Script:StateDir -Force | Out-Null }
            [System.IO.File]::WriteAllText($Script:DashDataPath, $json, $utf8)
        } catch { return $null }
    }
    try { return [System.IO.File]::ReadAllText($Script:DashDataPath) } catch { return $null }
}

function Invoke-CtHandleHttpClient {
    <# Parse one HTTP request and route it. Returns 1 when a request was handled. #>
    param(
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpClient]$Client
    )

    $handled = 0
    try {
        $stream = $Client.GetStream()
        try {
            $stream.ReadTimeout = 5000
            $buf = New-Object byte[] 16384
            $reqText = ''
            try {
                while ($true) {
                    $n = $stream.Read($buf, 0, $buf.Length)
                    if ($n -le 0) { break }
                    $reqText += [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
                    if (($reqText.IndexOf("`r`n`r`n") -ge 0) -or ($reqText.Length -gt 32768)) { break }
                }
            } catch { }

            if ($reqText.Length -gt 0) {
                $handled = 1
                $lines = @($reqText -split "`r`n")
                $firstLine = $lines[0]
                $method = Get-CtHttpRequestMethod -RequestLine $firstLine
                $path   = Get-CtHttpRequestPath -RequestLine $firstLine
                $utf8   = New-Object System.Text.UTF8Encoding($false)

                Write-CtLog "dashboard request $method $path" -Level DEBUG

                if ($method -ne 'GET') {
                    $bodyBytes = $utf8.GetBytes('method not allowed')
                    Send-CtHttpResponse -Stream $stream -Status 405 -StatusText 'Method Not Allowed' -ContentType 'text/plain; charset=utf-8' -Body $bodyBytes -AllowCors
                    return $handled
                }

                switch -Regex ($path) {
                    '^/$' {
                        # ---- dashboard page ----
                        if (-not (Test-Path $Script:DashHtmlPath)) {
                            $snap = New-CtDashboardSnapshot -StatusText 'offline' -FromHistory
                            Write-CtDashboardHtml -OutPath $Script:DashHtmlPath -Snapshot $snap
                        }
                        try {
                            $html = [System.IO.File]::ReadAllBytes($Script:DashHtmlPath)
                            Send-CtHttpResponse -Stream $stream -Status 200 -StatusText 'OK' -ContentType 'text/html; charset=utf-8' -Body $html
                        } catch {
                            $bodyBytes = $utf8.GetBytes('dashboard unavailable')
                            Send-CtHttpResponse -Stream $stream -Status 500 -StatusText 'Internal Server Error' -ContentType 'text/plain; charset=utf-8' -Body $bodyBytes
                        }
                    }
                    '^/api/data$|^/dashboard-data\.json$' {
                        # ---- live data endpoint ----
                        $json = Read-CtDashboardDataFile
                        if ($null -eq $json) {
                            $json = '{"status":"offline","stats":{},"matches":[],"events":[],"per_target":{},"hourly":{}}'
                        }
                        if (-not (Test-CtMonitorAlive)) {
                            # monitor is gone: flip status so the UI does not claim LIVE on stale data
                            $json = $json -replace '"status"\s*:\s*"live"', '"status":"offline"'
                        }
                        $bodyBytes = $utf8.GetBytes($json)
                        Send-CtHttpResponse -Stream $stream -Status 200 -StatusText 'OK' -ContentType 'application/json; charset=utf-8' -Body $bodyBytes -AllowCors
                    }
                    '^/api/health$' {
                        # ---- health endpoint ----
                        $alive = $false
                        if (Test-CtMonitorAlive) { $alive = $true }
                        $health = @{
                            status          = 'ok'
                            ctmon_version   = $Script:CTMonVersion
                            monitor_running = $alive
                            server_pid      = $PID
                            server_uptime_s = [int]((Get-Date) - $Script:Stats.started).TotalSeconds
                            ts_utc          = (Get-Date).ToUniversalTime().ToString('o')
                        }
                        $bodyBytes = $utf8.GetBytes((ConvertTo-Json -InputObject $health -Depth 3 -Compress))
                        Send-CtHttpResponse -Stream $stream -Status 200 -StatusText 'OK' -ContentType 'application/json; charset=utf-8' -Body $bodyBytes -AllowCors
                    }
                    '^/api/metrics$' {
                        # ---- v2.2 Prometheus metrics (from the live snapshot) ----
                        $metricsOk = $false
                        $metricsText = ''
                        try {
                            if (-not $Script:MetricsEnabled) { throw 'metrics disabled by config' }
                            $snapJsonM = Read-CtDashboardDataFile
                            $snapM = $snapJsonM | ConvertFrom-Json
                            $stM = $snapM.stats
                            $ptM = @{}
                            try {
                                if ($snapM.per_target) {
                                    foreach ($pM in $snapM.per_target.PSObject.Properties) { $ptM[$pM.Name] = [int]$pM.Value }
                                }
                            } catch { }
                            $byM = 0
                            try { $byM = [int]$snapM.stats.bypass_count } catch { $byM = 0 }
                            $mx = @{
                                certs_seen     = [int]$stM.certs_seen
                                domains_seen   = [int]$stM.domains_seen
                                matched        = [int]$stM.matched
                                matched_today  = [int]$stM.matched_today
                                notifications  = [int]$stM.notifications
                                reconnects     = [int]$stM.reconnects
                                bypass_count   = $byM
                                uptime_seconds = [int]$snapM.uptime_seconds
                                buffered       = 0
                                per_target     = $ptM
                            }
                            $metricsText = New-CtPrometheusMetrics -Metrics $mx -Version $Script:CTMonVersion
                            $metricsOk = $true
                        } catch {
                            $metricsText = '# metrics unavailable: ' + $_.Exception.Message
                        }
                        if ($metricsOk) {
                            $bodyBytes = $utf8.GetBytes($metricsText)
                            Send-CtHttpResponse -Stream $stream -Status 200 -StatusText 'OK' -ContentType 'text/plain; version=0.0.4; charset=utf-8' -Body $bodyBytes
                        } else {
                            $bodyBytes = $utf8.GetBytes($metricsText)
                            Send-CtHttpResponse -Stream $stream -Status 503 -StatusText 'Service Unavailable' -ContentType 'text/plain; charset=utf-8' -Body $bodyBytes
                        }
                    }
                    '^/favicon\.ico$' {
                        Send-CtHttpResponse -Stream $stream -Status 204 -StatusText 'No Content' -ContentType 'image/x-icon' -Body @()
                    }
                    default {
                        $bodyBytes = $utf8.GetBytes('not found')
                        Send-CtHttpResponse -Stream $stream -Status 404 -StatusText 'Not Found' -ContentType 'text/plain; charset=utf-8' -Body $bodyBytes
                    }
                }
            }
        } finally {
            try { $stream.Dispose() } catch { }
        }
    } catch {
        Write-CtLog "dashboard request error: $($_.Exception.Message)" -Level DEBUG
    } finally {
        try { $Client.Dispose() } catch { }
    }
    return $handled
}

function Invoke-CtDashboardServer {
    <# Blocking dashboard web server loop (Ctrl+C / deadline to stop). #>
    param(
        [int]$Port = 8080,
        [string]$Bind = '127.0.0.1'
    )

    if ($Bind -eq 'localhost') { $Bind = '127.0.0.1' }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Bind, [ref]$ip)) {
        Write-CtLog "invalid bind address '$Bind' - use an IP like 127.0.0.1" -Level ERROR
        return $false
    }

    $deadline = $null
    if ($Script:MaxRuntimeSeconds -gt 0) { $deadline = (Get-Date).AddSeconds($Script:MaxRuntimeSeconds) }

    $listener = $null
    $served = 0
    $boundSuccessfully = $false
    try {
        # make sure both dashboard files exist before the first request
        $null = Read-CtDashboardDataFile
        if (-not (Test-Path $Script:DashHtmlPath)) {
            $snap = New-CtDashboardSnapshot -StatusText 'offline' -FromHistory
            Write-CtDashboardHtml -OutPath $Script:DashHtmlPath -Snapshot $snap
        }

        $listener = New-Object System.Net.Sockets.TcpListener($ip, $Port)
        $listener.Start()
        $boundSuccessfully = $true
        # Publish only after the socket is successfully bound; a failed startup must not
        # leave a PID record that looks like a running dashboard.
        try {
            $pidDir = Split-Path $Script:ServePidPath -Parent
            if (-not (Test-Path $pidDir)) { New-Item -ItemType Directory -Path $pidDir -Force | Out-Null }
            $pidUtf8 = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText($Script:ServePidPath, ("{0}:{1}:{2}" -f $PID, $Port, $Bind), $pidUtf8)
        } catch {
            Write-CtLog "could not write dashboard PID file: $($_.Exception.Message)" -Level WARN
        }
        $Script:Stats.source = 'dashboard' 

        $proto = 'http'
        Write-CtLog "dashboard serving at ${proto}://${Bind}:${Port}/  (Ctrl+C to stop)" -Level OK
        Write-CtLog 'routes:  /  (dark dashboard)   /api/data  (live json)   /api/health   /api/metrics (prometheus)' -Level INFO
        if ($Bind -ne '127.0.0.1' -and $Bind -ne '::1') {
            Write-CtLog "WARNING: bound to $Bind (not localhost) - the dashboard exposes your recon feed to the network" -Level WARN
        }

        while ($true) {
            if ($deadline -and (Get-Date) -ge $deadline) {
                Write-CtLog "max runtime reached ($($Script:MaxRuntimeSeconds)s); stopping dashboard server" -Level INFO
                return $true
            }
            if ($listener.Pending()) {
                try {
                    $client = $listener.AcceptTcpClient()
                    $served += Invoke-CtHandleHttpClient -Client $client
                } catch {
                    Write-CtLog "accept error: $($_.Exception.Message)" -Level DEBUG
                    Start-Sleep -Milliseconds 200
                }
            }
            else {
                Start-Sleep -Milliseconds 120
            }
        }
    }
    catch [System.Net.Sockets.SocketException] {
        # Even after a successful preflight, another process can win the bind race.
        # For implicit/default ports, retry once on the next free port instead of
        # making -ServeBg report a false success followed by a dead server.
        $allowFallback = (($Port -le 0) -or $AutoPortFallback)
        if (-not $boundSuccessfully -and $allowFallback) {
            $nextPort = Get-CtAvailableServePort -PreferredPort ($Port + 1) -Bind $Bind -AllowFallback
            if ($nextPort -gt 0) {
                if ($listener) { try { $listener.Stop() } catch { } }
                Write-CtLog "dashboard port $Port became unavailable during bind; retrying on port $nextPort" -Level WARN
                return (Invoke-CtDashboardServer -Port $nextPort -Bind $Bind)
            }
        }
        Write-CtLog "could not start dashboard server on ${Bind}:${Port} ($($_.Exception.Message))" -Level ERROR
        Write-CtLog 'port already in use? try:  CTMon.ps1 -ServeBg -Port 8081' -Level WARN
        return $false
    }
    finally {
        if ($listener) { try { $listener.Stop() } catch { } }
    }
}


# ============================================================================
#  MAIN DISPATCH
# ============================================================================

# NOTE: advanced scripts (CmdletBinding) cannot receive PowerShell-to-PowerShell
# pipeline objects (Get-Content targets.txt | ./CTMon.ps1 would silently DROP them).
# Detect that misuse loudly and point the user at the supported patterns instead.
$boundErrors = @($Error | Where-Object { "$($_.FullyQualifiedErrorId)" -like 'InputObjectNotBound*' })
if ($boundErrors.Count -gt 0) {
    Write-Host '' -ForegroundColor Red
    Write-CtLog 'you piped objects directly into CTMon.ps1, but advanced PowerShell scripts cannot receive pipeline objects - your input was NOT delivered.' -Level ERROR
    Write-CtLog 'use one of these supported patterns instead:' -Level ERROR
    Write-Host  '   ./CTMon.ps1 -Target (Get-Content targets.txt)                    # PowerShell array' -ForegroundColor Gray
    Write-Host  '   ./CTMon.ps1 -Target targets.txt                                  # file path' -ForegroundColor Gray
    Write-Host  '   cat targets.txt | pwsh -NoProfile -File ./CTMon.ps1 -Target -    # native stdin' -ForegroundColor Gray
    exit 1
}

$Script:PipelineInput = @()   # reserved; stdin mode reads [Console]::In only

# show version
if ($Version) {
    Write-Host "CTMon v$Script:CTMonVersion"
    exit 0
}

# show help (also support -h/-help style like crtmon)
$targetSingle = $null
if ($Target) {
    $tArr = @($Target)
    if ($tArr.Count -eq 1) { $targetSingle = "$($tArr[0])".Trim() }
}
if ($Help -or ($targetSingle -eq '-h') -or ($targetSingle -eq '-help')) {
    Show-CtUsage
    exit 0
}

# Guard incompatible action flags. The intentional -Background -ServeBg pair is
# supported below as a combined monitor + dashboard startup.
$ctActions = @(
    @{ N = '-SelfTest';      S = [bool]$SelfTest }
    @{ N = '-Stop';          S = [bool]$Stop }
    @{ N = '-Status';        S = [bool]$Status }
    @{ N = '-Doctor';        S = [bool]$Doctor }
    @{ N = '-Export';        S = [bool]$Export }
    @{ N = '-Summary';       S = [bool]$Summary }
    @{ N = '-Digest';        S = [bool]$Digest }
    @{ N = '-Prune';         S = [bool]$Prune }
    @{ N = '-ServeBg';       S = [bool]$ServeBg }
    @{ N = '-Dashboard';     S = [bool]$Dashboard }
    @{ N = '-UninstallTask'; S = [bool]$UninstallTask }
    @{ N = '-InstallTask';   S = [bool]$InstallTask }
    @{ N = '-Setup';         S = [bool]$Setup }
    @{ N = '-TestAlert';     S = [bool]$TestAlert }
    @{ N = '-Serve';         S = [bool]$Serve }
    @{ N = '-Background';    S = [bool]$Background }
)
$ctActive = @($ctActions | Where-Object { $_.S })
if ($ctActive.Count -gt 1 -and -not ($ctActive.Count -eq 2 -and $Background -and $ServeBg)) {
    $ctNames = @($ctActive | ForEach-Object { $_.N })
    Write-Host ''
    Write-CtLog "you combined several action flags: $($ctNames -join ' ')" -Level WARN
    Write-CtLog "only $($ctNames[0]) will run - the others are IGNORED. run each mode as a separate command, e.g.:" -Level WARN
    Write-Host  '   ./CTMon.ps1 -Target example.com -Background   # 1) start the monitor (detached)' -ForegroundColor Gray
    Write-Host  '   ./CTMon.ps1 -ServeBg                          # 2) start the dashboard server' -ForegroundColor Gray
    Write-Host  '   ./CTMon.ps1 -Status                           # 3) check what is running' -ForegroundColor Gray
    Write-Host  '   ./CTMon.ps1 -Doctor                           # diagnose local setup' -ForegroundColor Gray
    Write-Host  ''
}

# run self tests
if ($SelfTest) {
    Invoke-CtSelfTest
}

# stop running instances (monitor AND dashboard server)
if ($Stop) {
    Stop-CtRunning
    exit 0
}

# show status
if ($Status) {
    Show-CtStatus
    exit 0
}

if ($Doctor) {
    $doctorOk = Invoke-CtDoctor
    if ($doctorOk) { exit 0 } else { exit 1 }
}

# export match history
if ($Export) {
    $exportDays = 30
    if ($Days -gt 0) { $exportDays = $Days }
    $n = Invoke-CtExport -Format $Format -Days $exportDays -OutFile $OutFile
    if ($n -gt 0) { exit 0 } else { exit 0 }
}

# match-history summary report
if ($Summary) {
    $summaryDays = 7
    if ($Days -gt 0) { $summaryDays = $Days }
    Show-CtSummaryReport -Days $summaryDays
    exit 0
}

# housekeeping
if ($Prune) {
    $pruneDays = 90
    if ($Days -gt 0) { $pruneDays = $Days }
    Invoke-CtPrune -Days $pruneDays
    exit 0
}

# weekly digest on demand (v2.2)
if ($Digest) {
    $ErrorActionPreference = 'Stop'
    try {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            } catch { }
        }
        $cfgDigest = Get-CtConfig -Path $ConfigPath
        $digestNotify = 'telegram'
        if ($Notify) { $digestNotify = $Notify } elseif ($cfgDigest.notify) { $digestNotify = "$($cfgDigest.notify)" }
        $digestDays = 7
        if ($Days -gt 0) { $digestDays = $Days }

        # resolve channel secrets exactly like the monitor does
        $secTokDg  = Resolve-CtSecret -Key 'TELEGRAM_BOT_TOKEN'  -CurrentValue "$($cfgDigest.telegram_bot_token)"
        $secChatDg = Resolve-CtSecret -Key 'TELEGRAM_CHAT_ID'    -CurrentValue "$($cfgDigest.telegram_chat_id)"
        $secSlkDg  = Resolve-CtSecret -Key 'SLACK_WEBHOOK_URL'   -CurrentValue "$($cfgDigest.slack_webhook_url)"
        $secNtfDg  = Resolve-CtSecret -Key 'NTFY_TOPIC'          -CurrentValue "$($cfgDigest.ntfy_topic)"
        $secNtfSDg = Resolve-CtSecret -Key 'NTFY_SERVER'         -CurrentValue "$($cfgDigest.ntfy_server)"
        $secHkDg   = Resolve-CtSecret -Key 'GENERIC_WEBHOOK_URL' -CurrentValue "$($cfgDigest.webhook_url)"
        $cfgDigest.telegram_bot_token = $secTokDg.Value
        $cfgDigest.telegram_chat_id   = $secChatDg.Value
        $cfgDigest.slack_webhook_url  = $secSlkDg.Value
        $cfgDigest.ntfy_topic         = $secNtfDg.Value
        $cfgDigest.ntfy_server        = $secNtfSDg.Value
        $cfgDigest.webhook_url        = $secHkDg.Value

        if ($digestNotify -eq 'none') {
            Write-CtLog 'notify = none - printing the digest to the console instead' -Level WARN
            $null = Invoke-CtDigestSend -Config $cfgDigest -NotifyMode 'none' -Days $digestDays -PrintOnly
        } else {
            $okDg = Invoke-CtDigestSend -Config $cfgDigest -NotifyMode $digestNotify -Days $digestDays
            if ($okDg) { exit 0 } else { exit 1 }
        }
        exit 0
    } catch {
        Write-CtLog "digest failed: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# start the dashboard server detached
if ($ServeBg) {
    # Supported combined mode: one command starts the monitor first, then the dashboard.
    # This is intentionally the sole exception to the multiple-action guard above.
    $monitorOk = $true
    if ($Background) {
        $targetValue = Get-CtTargetArgString -Target $Target
        $monitorOk = Start-CtBackground -TargetValue $targetValue -Path $ConfigPath -NotifyMode $Notify -SourceMode $Source -DryRun:$DryRun
    }
    $servePort = 0
    if ($Port -gt 0) { $servePort = $Port } else { $servePort = Get-CtDashboardPort -Path $ConfigPath }
    $serverOk = Start-CtBackground -ServeMode -ServePort $servePort -ServeBind $Bind -PortExplicit:($Port -gt 0) -Path $ConfigPath
    if ($monitorOk -and $serverOk) { exit 0 } else { exit 1 }
}

# refresh + open the static dashboard file
if ($Dashboard) {
    Invoke-CtDashboardOpen
    exit 0
}

# uninstall task
if ($UninstallTask) {
    Uninstall-CtScheduledTask
    exit 0
}

# install task (needs config to exist so the child has targets)
if ($InstallTask) {
    Install-CtScheduledTask -TargetValue (Get-CtTargetArgString -Target $Target) -Path $ConfigPath
    exit 0
}

# interactive setup wizard
if ($Setup) {
    Invoke-CtSetup -Path $ConfigPath
    exit 0
}

# test alert (honors notify mode; secrets resolved exactly like the monitor does)
if ($TestAlert) {
    $ErrorActionPreference = 'Stop'
    try {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            } catch { }
        }
        $cfg = Get-CtConfig -Path $ConfigPath
        $secTok  = Resolve-CtSecret -Key 'TELEGRAM_BOT_TOKEN'  -CurrentValue "$($cfg.telegram_bot_token)"
        $secChat = Resolve-CtSecret -Key 'TELEGRAM_CHAT_ID'    -CurrentValue "$($cfg.telegram_chat_id)"
        $secDisc = Resolve-CtSecret -Key 'DISCORD_WEBHOOK_URL' -CurrentValue "$($cfg.discord_webhook_url)"
        $secHook = Resolve-CtSecret -Key 'GENERIC_WEBHOOK_URL' -CurrentValue "$($cfg.webhook_url)"
        $secSlack    = Resolve-CtSecret -Key 'SLACK_WEBHOOK_URL' -CurrentValue "$($cfg.slack_webhook_url)"
        $secNtfy     = Resolve-CtSecret -Key 'NTFY_TOPIC'        -CurrentValue "$($cfg.ntfy_topic)"
        $secNtfySrv  = Resolve-CtSecret -Key 'NTFY_SERVER'       -CurrentValue "$($cfg.ntfy_server)"
        $cfg.telegram_bot_token  = $secTok.Value
        $cfg.telegram_chat_id    = $secChat.Value
        $cfg.discord_webhook_url = $secDisc.Value
        $cfg.webhook_url         = $secHook.Value
        $cfg.slack_webhook_url   = $secSlack.Value
        $cfg.ntfy_topic          = $secNtfy.Value
        $cfg.ntfy_server         = $secNtfySrv.Value

        $testMode = 'telegram'
        if ($Notify) { $testMode = $Notify }
        elseif ($cfg.notify) { $testMode = "$($cfg.notify)" }

        $text = "$($Script:EmojiRocket) <b>CTMon</b> test message`nIf you can read this, your $testMode notifications are working!"

        if ($testMode -eq 'telegram') {
            if ([string]::IsNullOrWhiteSpace($cfg.telegram_bot_token) -or [string]::IsNullOrWhiteSpace($cfg.telegram_chat_id)) {
                Write-CtLog 'telegram bot token / chat id are not configured yet - run: CTMon.ps1 -Setup (or edit .env)' -Level ERROR
                exit 1
            }
            Write-CtLog "sending test message to telegram chat $($cfg.telegram_chat_id) (token source: $($secTok.Source))..." -Level INFO
            $ok = Send-CtTelegram -Token $cfg.telegram_bot_token -ChatId $cfg.telegram_chat_id -Text $text -ApiBase $cfg.telegram_api_base
        }
        elseif ($testMode -eq 'discord') {
            if ([string]::IsNullOrWhiteSpace($cfg.discord_webhook_url)) {
                Write-CtLog 'discord webhook url is not configured yet - set DISCORD_WEBHOOK_URL in .env' -Level ERROR
                exit 1
            }
            Write-CtLog "sending test message to discord webhook (source: $($secDisc.Source))..." -Level INFO
            $payload = New-CtDiscordPayload -Title 'CTMon test message' -Domains @('If you can read this, your Discord notifications are working!') -Footer "CTMon v$Script:CTMonVersion"
            $ok = Send-CtDiscord -WebhookUrl $cfg.discord_webhook_url -Payload $payload
        }
        elseif ($testMode -eq 'webhook') {
            if ([string]::IsNullOrWhiteSpace($cfg.webhook_url)) {
                Write-CtLog 'generic webhook url is not configured yet - set GENERIC_WEBHOOK_URL in .env' -Level ERROR
                exit 1
            }
            Write-CtLog "sending test message to webhook (source: $($secHook.Source))..." -Level INFO
            $payload = New-CtWebhookPayload -Text $text -Target 'test' -Count 0 -Domains @() -Source 'testalert'
            $ok = Send-CtWebhook -WebhookUrl $cfg.webhook_url -Payload $payload
        }
        elseif ($testMode -eq 'slack') {
            if ([string]::IsNullOrWhiteSpace("$($cfg.slack_webhook_url)")) {
                Write-CtLog 'slack webhook url is not configured yet - set SLACK_WEBHOOK_URL in .env' -Level ERROR
                exit 1
            }
            Write-CtLog "sending test message to slack webhook (source: $($secSlack.Source))..." -Level INFO
            $payload = New-CtSlackPayload -Text $text -Footer "CTMon v$Script:CTMonVersion"
            $ok = Send-CtSlack -WebhookUrl $cfg.slack_webhook_url -Payload $payload
        }
        elseif ($testMode -eq 'ntfy') {
            if ([string]::IsNullOrWhiteSpace("$($cfg.ntfy_topic)")) {
                Write-CtLog 'ntfy topic is not configured yet - set NTFY_TOPIC in .env' -Level ERROR
                exit 1
            }
            Write-CtLog "sending test message to ntfy topic $($cfg.ntfy_topic) (server: $($cfg.ntfy_server))..." -Level INFO
            $ntfyToken = ''
            try { $ntfyToken = [Environment]::GetEnvironmentVariable('NTFY_TOKEN') } catch { }
            $ok = Send-CtNtfy -Topic "$($cfg.ntfy_topic)" -Text (ConvertTo-CtPlainText -Text $text) -Title 'CTMon test message' -Server "$($cfg.ntfy_server)" -Token $ntfyToken
        }
        else {
            Write-CtLog 'notify is set to "none" - set "notify": "telegram" (or discord/slack/ntfy/webhook) in the config first' -Level ERROR
            exit 1
        }

        if ($ok) { Write-CtLog 'test message delivered' -Level OK; exit 0 }
        else { Write-CtLog 'test message FAILED - check credentials/network' -Level ERROR; exit 1 }
    } catch {
        Write-CtLog "test alert failed: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# --------------------------------------------------------------------------
#  Monitor / server mode (foreground or -Background child)
# --------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# global flags used by the notification engine
$Script:DryRun = $DryRun.IsPresent

try {
    # friendlier console title
    try { $host.UI.RawUI.WindowTitle = 'CTMon - Certificate Transparency monitor' } catch { }

    # UTF-8 console output (best effort - never fatal)
    try {
        if ($Script:IsWindowsPS) { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 }
    } catch { }

    # Windows PowerShell 5.1: make sure TLS 1.2 is available for https/wss
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        } catch { }
    }

    # load config (creates default on first run, like crtmon's provider.yaml)
    $cfg = Get-CtConfig -Path $ConfigPath

    # apply runtime overrides / defaults
    $notifyMode = 'telegram'
    if ($Notify) { $notifyMode = $Notify }
    elseif ($cfg.notify) { $notifyMode = "$($cfg.notify)" }
    $sourceMode = 'certstream'
    if ($Source) { $sourceMode = $Source }
    elseif ($cfg.source) { $sourceMode = "$($cfg.source)" }

    # logging
    $Script:LogLevel = 'INFO'
    if ($cfg.log_level) { $Script:LogLevel = "$($cfg.log_level)".ToUpperInvariant() }
    if ($cfg.log_to_file) {
        if (-not (Test-Path $Script:LogDir)) { New-Item -ItemType Directory -Path $Script:LogDir -Force | Out-Null }
        $Script:LogFile = Join-Path $Script:LogDir ("ctmon-{0}.log" -f (Get-Date).ToString('yyyyMMdd'))
    }

    # ---------------- dashboard server mode ----------------
    if ($Serve) {
        Show-CtBanner
        Initialize-CtDashboard
        $servePort = 0
        if ($Port -gt 0) { $servePort = $Port } else { $servePort = Get-CtDashboardPort -Path $ConfigPath }
        $bindSafe = '127.0.0.1'
        if (-not [string]::IsNullOrWhiteSpace($Bind)) { $bindSafe = $Bind.Trim() }
        $preferredPort = $servePort
        $chosenPort = Get-CtAvailableServePort -PreferredPort $servePort -Bind $bindSafe -AllowFallback:(($Port -le 0) -or $AutoPortFallback)
        if ($chosenPort -le 0) {
            Write-CtLog "dashboard port $servePort is unavailable on bind address $bindSafe; choose another with -Port" -Level ERROR
            exit 1
        }
        $servePort = $chosenPort
        if ($servePort -ne $preferredPort) {
            Write-CtLog "configured dashboard port $preferredPort is busy; automatically selected port $servePort" -Level WARN
        }

        Write-CtLog "dashboard server starting pid=$PID" -Level INFO
        try {
            $ok = Invoke-CtDashboardServer -Port $servePort -Bind $bindSafe
            if ($ok) { exit 0 } else { exit 1 }
        } finally {
            try {
                if (Test-Path $Script:ServePidPath) {
                    $txt = ([System.IO.File]::ReadAllText($Script:ServePidPath)).Trim()
                    $colon = $txt.IndexOf(':')
                    $pidPart = $txt
                    if ($colon -gt 0) { $pidPart = $txt.Substring(0, $colon) }
                    $parsedPid = 0
                    if ([int]::TryParse($pidPart, [ref]$parsedPid) -and ($parsedPid -eq $PID)) {
                        Remove-Item -LiteralPath $Script:ServePidPath -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch { }
        }
    }

    Show-CtBanner

    # background mode: relaunch detached
    if ($Background) {
        $startOk = Start-CtBackground -TargetValue (Get-CtTargetArgString -Target $Target) -Path $ConfigPath -NotifyMode $notifyMode -SourceMode $sourceMode -DryRun:$DryRun
        if ($startOk) { exit 0 } else { exit 1 }
    }

    # resolve secrets from process env / .env files / config (priority order)
    $secTok  = Resolve-CtSecret -Key 'TELEGRAM_BOT_TOKEN'  -CurrentValue "$($cfg.telegram_bot_token)"
    $secChat = Resolve-CtSecret -Key 'TELEGRAM_CHAT_ID'    -CurrentValue "$($cfg.telegram_chat_id)"
    $secDisc = Resolve-CtSecret -Key 'DISCORD_WEBHOOK_URL' -CurrentValue "$($cfg.discord_webhook_url)"
    $secHook = Resolve-CtSecret -Key 'GENERIC_WEBHOOK_URL' -CurrentValue "$($cfg.webhook_url)"
    $secSlack    = Resolve-CtSecret -Key 'SLACK_WEBHOOK_URL' -CurrentValue "$($cfg.slack_webhook_url)"
    $secNtfy     = Resolve-CtSecret -Key 'NTFY_TOPIC'        -CurrentValue "$($cfg.ntfy_topic)"
    $secNtfySrv  = Resolve-CtSecret -Key 'NTFY_SERVER'       -CurrentValue "$($cfg.ntfy_server)"
    $secCspToken = Resolve-CtSecret -Key 'CERTSPOTTER_TOKEN' -CurrentValue "$($cfg.certspotter_token)"
    $cfg.telegram_bot_token  = $secTok.Value
    $cfg.telegram_chat_id    = $secChat.Value
    $cfg.discord_webhook_url = $secDisc.Value
    $cfg.webhook_url         = $secHook.Value
    $cfg.slack_webhook_url   = $secSlack.Value
    $cfg.ntfy_topic          = $secNtfy.Value
    $cfg.ntfy_server         = $secNtfySrv.Value
    $cfg.certspotter_token   = $secCspToken.Value
    $Script:CtCertspotterToken = $secCspToken.Value
    if ($secTok.Source -ne 'none')  { Write-CtLog "telegram bot token source: $($secTok.Source)" -Level DEBUG }
    if ($secDisc.Source -ne 'none') { Write-CtLog "discord webhook url source: $($secDisc.Source)" -Level DEBUG }
    if ($secHook.Source -ne 'none') { Write-CtLog "generic webhook url source: $($secHook.Source)" -Level DEBUG }
    if ($secSlack.Source -ne 'none') { Write-CtLog "slack webhook url source: $($secSlack.Source)" -Level DEBUG }
    if ($secNtfy.Source -ne 'none') { Write-CtLog "ntfy topic source: $($secNtfy.Source)" -Level DEBUG }

    # resolve targets
    $targets = Resolve-CtTargets -TargetValue $Target -ConfigTargets $cfg.targets
    if ($targets.Count -eq 0) {
        Write-CtLog "no targets configured. please add target domains to $Script:DefaultConfigPath or use -Target flag or stdin" -Level ERROR
        exit 1
    }
    for ($i = 0; $i -lt $targets.Count; $i++) {
        Write-CtLog "$($i + 1). $($targets[$i])" -Level INFO
    }

    # keyword watch list
    $keywords = @()
    if ($cfg.keywords) { $keywords = @($cfg.keywords | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ }) }
    if ($keywords.Count -gt 0) { Write-CtLog "keyword watch active: $($keywords -join ', ')" -Level INFO }

    $exclude = @()
    if ($cfg.exclude_regex) { $exclude = @($cfg.exclude_regex | ForEach-Object { "$_" } | Where-Object { $_ }) }

    # notification readiness (per channel)
    $channelReady = $false
    if ($notifyMode -eq 'telegram') {
        if ([string]::IsNullOrWhiteSpace("$($cfg.telegram_bot_token)") -or [string]::IsNullOrWhiteSpace("$($cfg.telegram_chat_id)")) {
            Write-CtLog 'no telegram bot token / chat id configured (check .env / config.json); telegram notifications disabled' -Level WARN
            $notifyMode = 'none'
        } else {
            $channelReady = $true
            Write-CtLog 'telegram notifications enabled' -Level OK
        }
    } elseif ($notifyMode -eq 'discord') {
        if ([string]::IsNullOrWhiteSpace("$($cfg.discord_webhook_url)")) {
            Write-CtLog 'no discord webhook url configured (DISCORD_WEBHOOK_URL in .env, or discord_webhook_url in config); discord notifications disabled' -Level WARN
            $notifyMode = 'none'
        } else {
            $channelReady = $true
            Write-CtLog 'discord notifications enabled' -Level OK
        }
    } elseif ($notifyMode -eq 'webhook') {
        if ([string]::IsNullOrWhiteSpace("$($cfg.webhook_url)")) {
            Write-CtLog 'no generic webhook url configured (GENERIC_WEBHOOK_URL in .env, or webhook_url in config); webhook notifications disabled' -Level WARN
            $notifyMode = 'none'
        } else {
            $channelReady = $true
            Write-CtLog 'generic webhook notifications enabled' -Level OK
        }
    } elseif ($notifyMode -eq 'slack') {
        if ([string]::IsNullOrWhiteSpace("$($cfg.slack_webhook_url)")) {
            Write-CtLog 'no slack webhook url configured (SLACK_WEBHOOK_URL in .env, or slack_webhook_url in config); slack notifications disabled' -Level WARN
            $notifyMode = 'none'
        } else {
            $channelReady = $true
            Write-CtLog 'slack notifications enabled' -Level OK
        }
    } elseif ($notifyMode -eq 'ntfy') {
        if ([string]::IsNullOrWhiteSpace("$($cfg.ntfy_topic)")) {
            Write-CtLog 'no ntfy topic configured (NTFY_TOPIC in .env, or ntfy_topic in config); ntfy notifications disabled' -Level WARN
            $notifyMode = 'none'
        } else {
            $channelReady = $true
            Write-CtLog "ntfy notifications enabled (topic: $($cfg.ntfy_topic))" -Level OK
        }
    } else {
        Write-CtLog 'notifications disabled (console output only)' -Level WARN
    }
    $Script:NotifyMode = $notifyMode
    $Script:NotificationsEnabled = $channelReady -and (-not $Script:DryRun)

    # seen store
    $rememberSeen = $true
    if ($null -ne $cfg.remember_seen) { $rememberSeen = [bool]$cfg.remember_seen }
    $seenMax = 50000
    if ($cfg.seen_max_entries) { try { $seenMax = [int]$cfg.seen_max_entries } catch { } }
    $seenStore = New-CtSeenStore -Persist $rememberSeen -Path $Script:SeenPath -MaxEntries $seenMax

    # dns enrichment settings + cache
    $enrichDns = $true
    if ($null -ne $cfg.enrich_dns) { try { $enrichDns = [bool]$cfg.enrich_dns } catch { } }
    $dnsTimeout = 2500
    try { if ($cfg.dns_timeout_ms) { $dnsTimeout = [Math]::Max(500, [int]$cfg.dns_timeout_ms) } } catch { }
    $matchesMax = 20000
    try { if ($cfg.matches_history_max) { $matchesMax = [Math]::Max(100, [int]$cfg.matches_history_max) } } catch { }
    $dnsCache = New-CtDnsCache -Path $Script:DnsCachePath
    if ($dohEnabled) {
        $dnsCache.DohEnabled = $true
        $dnsCache.DohProvider = $dohProvider
        $dnsCache.Proxy = $proxyInfo
    }
    if ($enrichDns) { Write-CtLog "dns enrichment enabled (timeout ${dnsTimeout} ms)" -Level INFO } else { Write-CtLog 'dns enrichment disabled' -Level INFO }

    # runtime bundle for the loops
    $flushSeconds = 10
    try { if ($cfg.flush_interval_seconds) { $flushSeconds = [Math]::Max(2, [int]$cfg.flush_interval_seconds) } } catch { }
    $batchMax = 10
    try { if ($cfg.batch_max_domains) { $batchMax = [Math]::Max(1, [int]$cfg.batch_max_domains) } } catch { }
    $heartbeatHours = 6
    try { if ($null -ne $cfg.heartbeat_hours) { $heartbeatHours = [Math]::Max(0, [double]$cfg.heartbeat_hours) } } catch { }
    $crtshInterval = 300
    try { if ($cfg.crtsh_interval_seconds) { $crtshInterval = [Math]::Max(30, [int]$cfg.crtsh_interval_seconds) } } catch { }
    $crtshWindow = 1440
    try { if ($cfg.crtsh_window_minutes) { $crtshWindow = [Math]::Max(5, [int]$cfg.crtsh_window_minutes) } } catch { }
    if ($WindowMinutes -gt 0) {
        $crtshWindow = [Math]::Max(5, $WindowMinutes)
        Write-CtLog "cli override: cert window = $crtshWindow minute(s) (backfill mode)" -Level INFO
    }

    $urls = @('wss://certstream.calidog.io/', 'wss://certstream.cert.ee/')
    if ($cfg.certstream_urls -and @($cfg.certstream_urls).Count -gt 0) { $urls = @($cfg.certstream_urls | ForEach-Object { "$_" }) }
    $crtshBase = 'https://crt.sh'
    if ($cfg.crtsh_base_url) { $crtshBase = "$($cfg.crtsh_base_url)".TrimEnd('/') }
    $silentTimeout = 90
    try { if ($null -ne $cfg.certstream_silent_timeout_seconds) { $silentTimeout = [Math]::Max(15, [int]$cfg.certstream_silent_timeout_seconds) } } catch { }

    # ---- v2.2: network bypass + metrics + digest settings ----
    $netBypass = $true
    try { if ($null -ne $cfg.net_bypass) { $netBypass = [bool]$cfg.net_bypass } } catch { }
    $dohEnabled = $true
    try { if ($null -ne $cfg.doh_enabled) { $dohEnabled = [bool]$cfg.doh_enabled } } catch { }
    $dohProvider = 'cloudflare'
    try { if ($cfg.doh_provider) { $dohProvider = "$($cfg.doh_provider)".ToLowerInvariant() } } catch { }
    $crtshTimeoutSec = 180
    $digestEnabled = $true
    try { if ($null -ne $cfg.digest_enabled) { $digestEnabled = [bool]$cfg.digest_enabled } } catch { }
    $digestWeekday = 'Monday'
    try { if ($cfg.digest_weekday) { $digestWeekday = "$($cfg.digest_weekday)" } } catch { }
    $digestHour = 9
    try { if ($null -ne $cfg.digest_hour) { $digestHour = [Math]::Max(0, [Math]::Min(23, [int]$cfg.digest_hour)) } } catch { }
    $digestDays = 7
    try { if ($null -ne $cfg.digest_days) { $digestDays = [Math]::Max(1, [int]$cfg.digest_days) } } catch { }
    $metricsEnabled = $true
    try { if ($null -ne $cfg.metrics_enabled) { $metricsEnabled = [bool]$cfg.metrics_enabled } } catch { }
    $Script:MetricsEnabled = $metricsEnabled
    $csFallbackMinutes = 10
    try { if ($null -ne $cfg.certstream_fallback_minutes) { $csFallbackMinutes = [Math]::Max(0, [int]$cfg.certstream_fallback_minutes) } } catch { }
    $proxyInfo = Get-CtEffectiveProxy -Config $cfg
    if ($proxyInfo) { Write-CtLog "network proxy active: $($proxyInfo.Url) (source: $($proxyInfo.Source))" -Level INFO }
    if ($netBypass) { Write-CtLog "net bypass armed (doh: $dohProvider, alt source: certspotter) - crt.sh outages will fail over automatically" -Level INFO }

    $runtime = @{
        Config                 = $cfg
        Targets                = $targets
        Keywords               = $keywords
        ExcludeRegex           = $exclude
        SeenStore              = $seenStore
        NotifyMode             = $notifyMode
        IncludeWildcards       = $true
        FlushIntervalSeconds   = $flushSeconds
        BatchMaxDomains        = $batchMax
        HeartbeatHours         = $heartbeatHours
        CrtshIntervalSeconds   = $crtshInterval
        CrtshWindowMinutes     = $crtshWindow
        CrtshBaseUrl           = $crtshBase
        CertstreamUrls         = $urls
        SilentTimeoutSeconds   = $silentTimeout
        CertstreamFallbackMinutes = $csFallbackMinutes
        EnrichDns              = $enrichDns
        DnsTimeoutMs           = $dnsTimeout
        DnsCache               = $dnsCache
        MatchesMax             = $matchesMax
        SourceName             = 'certstream'
        PollSource             = 'crtsh'
        CrtshTimeoutSec        = $crtshTimeoutSec
        NetBypass              = $netBypass
        DohEnabled             = $dohEnabled
        DohProvider            = $dohProvider
        DigestEnabled          = $digestEnabled
        DigestWeekday          = $digestWeekday
        DigestHour             = $digestHour
        DigestDays             = $digestDays
    }
    if ($null -ne $cfg.include_wildcards) { $runtime.IncludeWildcards = [bool]$cfg.include_wildcards }
    if ($sourceMode -eq 'crtsh' -or $sourceMode -eq 'certspotter') { $runtime.PollSource = $sourceMode }

    $Script:Stats.stats_summary_enabled = [bool]$cfg.stats_summary
    $Script:Stats.targets = $targets
    $Script:CtRuntimeConfig = $cfg
    if ($Script:DryRun) { Write-CtLog 'DRY RUN mode: matches will be logged but NOT sent to any channel' -Level WARN }

    # restore "matched today" counter from the persisted state (same-day restarts)
    try {
        if (Test-Path $Script:StatePath) {
            $stPrev = [System.IO.File]::ReadAllText($Script:StatePath) | ConvertFrom-Json
            if ("$($stPrev.matched_day)" -eq (Get-Date).ToString('yyyy-MM-dd')) {
                $Script:Stats.matched_today = [int]$stPrev.matched_today
                $Script:Stats.matched_day   = "$($stPrev.matched_day)"
            }
            if ($stPrev.digest_last_utc) { $Script:DigestLastUtc = "$($stPrev.digest_last_utc)" }
        }
    } catch { }

    # dashboard buffers + first paint
    $dashboardEnabled = $true
    if ($null -ne $cfg.dashboard_enabled) { try { $dashboardEnabled = [bool]$cfg.dashboard_enabled } catch { } }
    if ($dashboardEnabled) {
        Initialize-CtDashboard
        Write-CtDashboardData -Force
        Write-CtLog "dashboard data: $Script:DashDataPath" -Level INFO
    }

    # publish our pid so -Status / -Stop can see us (also covers scheduled-task runs)
    try {
        $dir = Split-Path $Script:PidPath -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Script:PidPath, "$PID", $utf8)
    } catch { }

    # save initial state (so -Status works immediately)
    Save-CtState

    # ---- run ----
    try {
        switch ($sourceMode) {
            'crtsh'       { Invoke-CtMonitorCrtsh -Runtime $runtime }
            'certspotter' { Invoke-CtMonitorCrtsh -Runtime $runtime }
            default       { Invoke-CtMonitorCertstream -Runtime $runtime }
        }
    } finally {
        # Ctrl+C / deadline / crash - always flush + summarize
        Send-CtFlush -Config $cfg -BatchMax $batchMax -NotifyMode $notifyMode
        Save-CtSeen -Store $seenStore
        Save-CtDnsCache -Cache $dnsCache
        Save-CtState
        Write-CtDashboardData -Force
        Show-CtSessionSummary -ToTelegram ($channelReady -and ($notifyMode -eq 'telegram') -and $Script:Stats.matched -gt 0) -Config $cfg
        # remove our pid file only if it is still ours (do not clobber a newer instance)
        try {
            if (Test-Path $Script:PidPath) {
                $txt = ([System.IO.File]::ReadAllText($Script:PidPath)).Trim()
                $parsedPid = 0
                if ([int]::TryParse($txt, [ref]$parsedPid) -and ($parsedPid -eq $PID)) {
                    Remove-Item -LiteralPath $Script:PidPath -Force -ErrorAction SilentlyContinue
                }
            }
        } catch { }
    }

    exit 0
} catch {
    Write-CtLog "fatal: $($_.Exception.Message)" -Level ERROR
    if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) {
        Write-CtLog "at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())" -Level DEBUG
    }
    exit 1
}
