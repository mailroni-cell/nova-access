<#
NOVA-Share SERVICE (PC) · S-187 round A · 2026-11-01 · updated S-191 round C (encryption) 2026-11-01
Signed: Claude Sonnet 5.5 · project "SUPER NOVA" · thread "המשך" (milestone 5, step 5.8)

What (Roni approved 2026-11-01, "אשר"; no guest sharing):
  A background service for the Windows PC that holds the NOVA "My library" shares, so the TV can manage them
  after ONE install (no window has to stay open, nothing else is touched on the PC).
  * Setup  : (run by NOVA-Share-Setup.cmd, as administrator) copies this script to C:\ProgramData\NOVA-Share (SYSTEM + Administrators only),
             creates the standard user "nova" (random strong password kept encrypted for this machine only), opens the firewall
             (Private network, local subnet only, UDP 47800 / TCP 47801), adopts shares made by the old NOVA-Share window,
             registers a scheduled task that starts at boot as SYSTEM, then shows a 6-digit pairing code (valid 5 minutes).
  * Run    : the service itself. Answers the TV's search (UDP "NOVA-FIND" -> "NOVA-HERE|name|47801|svc") and JSON lines on TCP 47801.
             Commands: hello, pair, status, drives, dirs, share-add, share-temp, share-remove, share-pause, share-resume,
             remove-all, health, health-fix, unpair, uninstall. Everything except hello/pair needs the token the TV got when it paired.
  * Uninstall : removes the shares, the user, the firewall rules, the scheduled task and C:\ProgramData\NOVA-Share (no trace is left).
  Shares are READ ONLY. Temporary shares close by themselves.
  Round C (S-191, protocol v2): after pairing, every request and answer is AES-256-GCM encrypted with a key made from the pairing
  token (the token itself is never sent again). Only hello / pair are plain. An old TV that does not know v2 keeps working in plain
  text until the first time a TV used v2 with that token; from then on that token is refused in plain text ("enc-required").
  The encryption switches itself on only after a self test (known-answer vectors) passes; otherwise hello says enc=0 and all
  stays as before. Setup keeps the existing pairings and the existing "nova" password, so an update does not break a working TV.
S-219 (2026-11-02, Claude, thread "להמשיך את SUPER NOVA אחרי בנייה 286"): command "thumbs". When the TV finds that taking a
  frame from a video is slow on this PC's share, it asks the service for ready pictures instead. The service uses the Windows
  thumbnail maker (the same pictures Explorer shows, no download), keeps them in C:\ProgramData\NOVA-Share\thumbs (removed on
  Uninstall, at most 4000 files) and sends them back as small JPEGs. Read only: nothing is written next to the movies.
Targets Windows PowerShell 5.1 (powershell.exe). Event log (no secrets): C:\ProgramData\NOVA-Share\events.log
#>
[CmdletBinding()]
param([ValidateSet('Setup', 'Run', 'Uninstall', 'SelfTest')][string]$Action = 'Setup')
$ErrorActionPreference = 'Stop'

$script:Version = '1.2.0-s219'
$script:TaskName = 'NOVA-Share'
$script:UserName = 'nova'
$script:UdpPort = 47800
$script:TcpPort = 47801
$pdDir = $env:ProgramData
if (-not $pdDir) { $pdDir = 'C:\ProgramData' }
$script:Root = $pdDir.TrimEnd('\') + '\NOVA-Share'
$script:CfgPath = $script:Root + '\config.json'
$script:PairPath = $script:Root + '\pair.json'
$script:LogPath = $script:Root + '\events.log'
$script:ServiceCopy = $script:Root + '\nova_share_service.ps1'
$script:ThumbDir = $script:Root + '\thumbs'
$script:ThumbOk = $null              # S-219: $null = not loaded yet, $true / $false after the first try
$script:Fails = @{}
$script:AclJobs = @{}
$script:Cfg = $null
$script:CodeExpires = [int64]0
$script:EncOk = $null                 # round C: $null = not tested yet, $true / $false after the self test
$script:SeenNonces = @{}              # round C: request nonces seen lately (replay protection)
$script:ReqAad = [System.Text.Encoding]::UTF8.GetBytes('nova-req-v2')
$script:ResAadPrefix = [System.Text.Encoding]::UTF8.GetBytes('nova-res-v2')
$script:BlockedNames = @('AppData', '$Recycle.Bin', 'System Volume Information', 'Recovery', 'Windows.old', '$WinREAgent', 'Config.Msi')

# ── small helpers ───────────────────────────────────────────────────────────
function Get-Now { return [int64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

function Write-Event([string]$text) {
    try {
        if (-not (Test-Path -LiteralPath $script:Root)) { return }
        if ((Test-Path -LiteralPath $script:LogPath) -and ((Get-Item -LiteralPath $script:LogPath).Length -gt 262144)) {
            Move-Item -LiteralPath $script:LogPath -Destination ($script:LogPath + '.old') -Force
        }
        $line = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  ' + $text + "`r`n"
        [System.IO.File]::AppendAllText($script:LogPath, $line, (New-Object System.Text.UTF8Encoding($false)))
    } catch { }
}

function Read-JsonFile([string]$path) {
    try {
        if (-not (Test-Path -LiteralPath $path)) { return $null }
        $t = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
        if (-not $t.Trim()) { return $null }
        return (ConvertFrom-Json -InputObject $t)
    } catch { return $null }
}

function Write-JsonFile([string]$path, $obj) {
    $json = ConvertTo-Json -InputObject $obj -Depth 8
    $tmp = $path + '.tmp'
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $path -Force
}

function Get-Config {
    $c = Read-JsonFile $script:CfgPath
    if (-not $c) { $c = [pscustomobject]@{ version = 1; userSid = ''; userSecret = ''; tokens = @(); shares = @() } }
    foreach ($k in @('userSid', 'userSecret')) { if (-not $c.PSObject.Properties[$k]) { Add-Member -InputObject $c -NotePropertyName $k -NotePropertyValue '' } }
    foreach ($k in @('tokens', 'shares')) { if (-not $c.PSObject.Properties[$k]) { Add-Member -InputObject $c -NotePropertyName $k -NotePropertyValue @() } }
    $c.tokens = @($c.tokens | Where-Object { $_ })
    $c.shares = @($c.shares | Where-Object { $_ })
    return $c
}

function Save-Config($c) { Write-JsonFile $script:CfgPath $c }

function Protect-Text([string]$t) {
    Add-Type -AssemblyName System.Security
    $b = [System.Text.Encoding]::UTF8.GetBytes($t)
    return [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect($b, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine))
}

function Unprotect-Text([string]$s) {
    Add-Type -AssemblyName System.Security
    $b = [System.Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($s), $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [System.Text.Encoding]::UTF8.GetString($b)
}

function Get-RandomBytes([int]$n) {
    $b = New-Object byte[] $n
    $r = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $r.GetBytes($b)
    $r.Dispose()
    return , $b
}

function New-RandomHex([int]$bytes) {
    $b = Get-RandomBytes $bytes
    return ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant()
}

function New-RandomDigits([int]$n) {
    $out = ''
    while ($out.Length -lt $n) {
        $b = Get-RandomBytes 16
        foreach ($x in $b) { if (($x -lt 250) -and ($out.Length -lt $n)) { $out += [string]($x % 10) } }   # 250 = 25 x 10: no bias
    }
    return $out
}

function New-NovaPassword {
    # 14 characters, no look-alikes (0/O, 1/l/I), always upper + lower + digit so Windows accepts it.
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
    do {
        $out = ''
        while ($out.Length -lt 14) {
            $b = Get-RandomBytes 32
            foreach ($x in $b) { if (($x -lt 224) -and ($out.Length -lt 14)) { $out += $chars[$x % $chars.Length] } }   # 224 = 4 x 56: no bias
        }
    } until (($out -cmatch '[A-Z]') -and ($out -cmatch '[a-z]') -and ($out -match '[2-9]'))
    return $out
}

function Get-Sha256Hex([string]$t) {
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($t)))).Replace('-', '').ToLowerInvariant() }
    finally { $h.Dispose() }
}

function Test-SameText([string]$a, [string]$b) {
    if (($null -eq $a) -or ($null -eq $b)) { return $false }
    if ($a.Length -ne $b.Length) { return $false }
    $d = 0
    for ($i = 0; $i -lt $a.Length; $i++) { $d = $d -bor ([int][char]$a[$i] -bxor [int][char]$b[$i]) }
    return ($d -eq 0)
}

function Test-LanIp($ip) {
    try {
        $b = $ip.GetAddressBytes()
        if ($b.Length -ne 4) { return $false }
        return (($b[0] -eq 10) -or (($b[0] -eq 192) -and ($b[1] -eq 168)) -or (($b[0] -eq 172) -and ($b[1] -ge 16) -and ($b[1] -le 31)))
    } catch { return $false }
}

function Test-AllowedIp($ip) {
    try { if ([System.Net.IPAddress]::IsLoopback($ip)) { return $true } } catch { }
    return (Test-LanIp $ip)
}

function Get-LanAddress {
    try {
        $c = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
        if ($c) { return [string](@($c.IPv4Address)[0].IPAddress) }
    } catch { }
    try {
        $a = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1
        if ($a) { return [string]$a.IPAddress }
    } catch { }
    return [string]$env:COMPUTERNAME
}

# ── brute-force protection (per IP: 10 failures in a minute = blocked for 5 minutes) ──
function Test-IpBlocked([string]$ip) {
    $f = $script:Fails[$ip]
    if (-not $f) { return $false }
    return ((Get-Now) -lt $f.until)
}

function Add-IpFail([string]$ip) {
    $now = Get-Now
    $f = $script:Fails[$ip]
    if ((-not $f) -or (($now - $f.t0) -gt 60)) { $f = @{ n = 0; t0 = $now; until = [int64]0 } }
    $f.n = $f.n + 1
    if ($f.n -ge 10) {
        $f.until = $now + 300; $f.n = 0; $f.t0 = $now
        Write-Event ('blocked ' + $ip + ' for 5 minutes (too many failures)')
    }
    $script:Fails[$ip] = $f
}

# ── pairing code (shown on the PC, 6 digits, 5 minutes, 5 wrong tries) ─────
function New-PairCode {
    $code = New-RandomDigits 6
    $exp = (Get-Now) + 300
    Write-JsonFile $script:PairPath ([pscustomobject]@{ code = $code; expires = $exp; fails = 0 })
    $script:CodeExpires = $exp
    return $code
}

function Test-PairCode([string]$code) {
    if ($code -notmatch '^\d{6}$') { return $false }
    $pj = Read-JsonFile $script:PairPath
    if (-not $pj) { return $false }
    if ([int64]$pj.expires -lt (Get-Now)) { return $false }
    if ([int]$pj.fails -ge 5) { return $false }
    if (Test-SameText ([string]$pj.code) $code) {
        Remove-Item -LiteralPath $script:PairPath -Force -ErrorAction SilentlyContinue
        return $true
    }
    $pj.fails = [int]$pj.fails + 1
    try { Write-JsonFile $script:PairPath $pj } catch { }
    return $false
}

# ── paths: what may be listed / shared ──────────────────────────────────────
function Test-PathBlocked([string]$full, [string[]]$roots, [string]$sysDrive, [bool]$forShare) {
    $p = $full.TrimEnd('\')
    $sys = $sysDrive.TrimEnd('\')
    foreach ($r0 in $roots) {
        $r = ([string]$r0).TrimEnd('\')
        if ($r -and (($p -ieq $r) -or $p.StartsWith($r + '\', [System.StringComparison]::OrdinalIgnoreCase))) { return $true }
    }
    $seg = $p.Split('\')
    for ($i = 1; $i -lt $seg.Length; $i++) { if ($script:BlockedNames -contains $seg[$i]) { return $true } }
    if ($forShare) {
        if ($p -ieq $sys) { return $true }                                                     # the whole system drive
        if (($seg.Length -ge 2) -and ($seg[0] -ieq $sys) -and ($seg[1] -ieq 'Users') -and ($seg.Length -le 3)) { return $true }   # C:\Users and a profile folder itself
    }
    return $false
}

function Get-BlockedRoots {
    $roots = @()
    foreach ($v in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) { if ($v) { $roots += [string]$v } }
    return , $roots
}

function Get-SystemDrive { $s = $env:SystemDrive; if (-not $s) { $s = 'C:' }; return $s }

function Resolve-NovaPath([string]$path) {
    $r = @{ ok = $false; full = ''; error = 'bad-path' }
    if ([string]::IsNullOrWhiteSpace($path) -or ($path.Length -gt 240)) { return $r }
    if ($path -notmatch '^[A-Za-z]:\\') { return $r }
    if (($path -match '[\*\?<>\|"]') -or ($path.Substring(2) -match ':')) { return $r }
    if ($path -match '(^|\\)\.\.?(\\|$)') { return $r }
    try { $full = [System.IO.Path]::GetFullPath($path) } catch { return $r }
    $full = $full.TrimEnd('\')
    if ($full.Length -eq 2) { $full = $full + '\' }   # "D:" -> "D:\"
    $r.ok = $true; $r.full = $full; $r.error = ''
    return $r
}

function Test-DirSharable([string]$path) {
    $r = Resolve-NovaPath $path
    if (-not $r.ok) { return $r }
    $full = [string]$r.full
    if (Test-PathBlocked $full (Get-BlockedRoots) (Get-SystemDrive) $true) { $r.ok = $false; $r.error = 'blocked'; return $r }
    if (-not (Test-Path -LiteralPath $full -PathType Container)) { $r.ok = $false; $r.error = 'not-found'; return $r }
    try {
        $di = New-Object System.IO.DirectoryInfo($full)
        if (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $r.ok = $false; $r.error = 'blocked'; return $r }
        $drv = New-Object System.IO.DriveInfo($full.Substring(0, 1))
        if (([string]$drv.DriveType -ne 'Fixed') -and ([string]$drv.DriveType -ne 'Removable')) { $r.ok = $false; $r.error = 'drive-type'; return $r }
    } catch { $r.ok = $false; $r.error = 'not-found' }
    return $r
}

function Get-ShareBase([string]$path) {
    $leaf = ''
    try { $leaf = $path.TrimEnd('\').Split('\')[-1] } catch { }
    $clean = ($leaf -replace '[^A-Za-z0-9_\-]', '') -replace '^(?i)NOVA-?', ''   # "NOVA-Test" -> NOVA-Test, not NOVA-NOVA-Test
    if (-not $clean) { $clean = 'Movies' }
    $base = 'NOVA-' + $clean
    if ($base.Length -gt 30) { $base = $base.Substring(0, 30) }
    return $base
}

function New-ShareName([string]$path) {
    $base = Get-ShareBase $path
    $name = $base
    $i = 1
    while ($true) {
        $inCfg = (@($script:Cfg.shares | Where-Object { $_.name -ieq $name }).Count -gt 0)
        $inSmb = $false
        try { $inSmb = [bool](Get-SmbShare -Name $name -ErrorAction SilentlyContinue) } catch { }
        if ((-not $inCfg) -and (-not $inSmb)) { return $name }
        $i++
        $name = $base + [string]$i
        if ($name.Length -gt 30) { $name = $base.Substring(0, 30 - ([string]$i).Length) + [string]$i }
    }
}

# ── shares ──────────────────────────────────────────────────────────────────
function Enable-ShareRecord($rec) {
    $ex = $null
    try { $ex = Get-SmbShare -Name $rec.name -ErrorAction SilentlyContinue } catch { }
    if (-not $ex) {
        New-SmbShare -Name $rec.name -Path $rec.path -ReadAccess ($env:COMPUTERNAME + '\' + $script:UserName) -Description 'NOVA TV (read only)' | Out-Null
    }
}

function Disable-ShareRecord([string]$name) {
    if ($name -notlike 'NOVA-*') { return }
    try { if (Get-SmbShare -Name $name -ErrorAction SilentlyContinue) { Remove-SmbShare -Name $name -Force } }
    catch { Write-Event ('remove share failed ' + $name + ': ' + $_.Exception.Message) }
}

function Get-IcaclsPathArg([string]$p) {
    if ($p.EndsWith('\')) { return ('"' + $p + '\"') }   # "D:\\" (a single trailing backslash would swallow the quote)
    return ('"' + $p + '"')
}

# The disk permission (read for "nova") can take minutes on a big folder, so icacls runs in the background and the share is
# "preparing" until it ends. icacls also adds the permission to existing files and folders by itself (inheritance).
function Start-AclJob([string]$name, [string]$path, [string]$mode) {
    if (-not $script:Cfg.userSid) { return }
    $sid = [string]$script:Cfg.userSid
    if ($mode -eq 'grant') { $spec = '/grant *' + $sid + ':(OI)(CI)RX /Q' } else { $spec = '/remove:g *' + $sid + ' /Q' }
    $argLine = (Get-IcaclsPathArg $path) + ' ' + $spec
    try {
        $p = Start-Process -FilePath ($env:SystemRoot + '\System32\icacls.exe') -ArgumentList $argLine -WindowStyle Hidden -PassThru
        if ($mode -eq 'grant') { $script:AclJobs[$name] = $p }
    } catch { Write-Event ('icacls failed: ' + $_.Exception.Message) }
}

function Update-AclJobs {
    foreach ($n in @($script:AclJobs.Keys)) {
        $p = $script:AclJobs[$n]
        $done = $true
        try { $done = $p.HasExited } catch { }
        if ($done) {
            $script:AclJobs.Remove($n)
            $rec = @($script:Cfg.shares | Where-Object { $_.name -eq $n })[0]
            if ($rec -and ($rec.state -eq 'preparing')) { $rec.state = 'active'; Save-Config $script:Cfg; Write-Event ('share ready ' + $n) }
        }
    }
}

function Find-Share([string]$name) {
    if ($name -notmatch '^NOVA-[A-Za-z0-9_\-]{1,30}$') { return $null }
    return @($script:Cfg.shares | Where-Object { $_.name -ieq $name })[0]
}

function Remove-ShareRecord($rec) {
    Disable-ShareRecord $rec.name
    $script:Cfg.shares = @($script:Cfg.shares | Where-Object { $_.name -ne $rec.name })
    $still = @($script:Cfg.shares | Where-Object { $_.path -ieq $rec.path }).Count
    if ($still -eq 0) { Start-AclJob $rec.name $rec.path 'remove' }
    Save-Config $script:Cfg
}

function ConvertTo-ShareItem($rec, [string]$ip) {
    $now = Get-Now
    $rem = 0
    $temp = $false
    if ([int64]$rec.expires -gt 0) { $temp = $true; $rem = [int][Math]::Max(0, ([int64]$rec.expires - $now)) }
    return @{ name = [string]$rec.name; path = [string]$rec.path; address = ($ip + '/' + [string]$rec.name); state = [string]$rec.state; temp = $temp; remaining = $rem }
}

function Add-ShareFromPath([string]$full, [int]$minutes) {
    $now = Get-Now
    $exp = [int64]0
    if ($minutes -gt 0) { $exp = $now + ([int64]$minutes * 60) }
    $rec = @($script:Cfg.shares | Where-Object { $_.path -ieq $full })[0]
    if ($rec) {
        if (($minutes -gt 0) -and ($rec.state -ne 'paused') -and ([int64]$rec.expires -eq 0)) { return @{ ok = $false; error = 'already-shared' } }
        $rec.expires = $exp
        if ($rec.state -eq 'paused') { $rec.state = 'active' }
        Enable-ShareRecord $rec
    } else {
        if (@($script:Cfg.shares).Count -ge 30) { return @{ ok = $false; error = 'too-many' } }
        $name = New-ShareName $full
        $rec = [pscustomobject]@{ name = $name; path = $full; state = 'preparing'; expires = $exp; created = $now }
        Enable-ShareRecord $rec
        $script:Cfg.shares = @($script:Cfg.shares) + $rec
        Start-AclJob $name $full 'grant'
    }
    Save-Config $script:Cfg
    Write-Event ('share ' + $rec.name + ' = ' + $full + ' (minutes ' + $minutes + ')')
    return @{ ok = $true; share = (ConvertTo-ShareItem $rec (Get-LanAddress)) }
}

# ── firewall / health ───────────────────────────────────────────────────────
function Initialize-FirewallRules {
    foreach ($r in @(@('NOVA-Share-UDP', 'UDP', 47800), @('NOVA-Share-TCP', 'TCP', 47801))) {
        if (Get-NetFirewallRule -Name $r[0] -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $r[0] }
        New-NetFirewallRule -Name $r[0] -DisplayName ('NOVA-Share (' + $r[1] + ')') -Direction Inbound -Action Allow `
            -Protocol $r[1] -LocalPort $r[2] -Profile Private, Domain -RemoteAddress LocalSubnet | Out-Null
    }
    $rule = Get-NetFirewallRule -Name 'FPS-SMB-In-TCP' -ErrorAction SilentlyContinue
    if ($rule) { Enable-NetFirewallRule -Name 'FPS-SMB-In-TCP' }
    else { Get-NetFirewallRule -Group '@FirewallAPI.dll,-28502' | Where-Object { $_.Direction -eq 'Inbound' -and "$($_.Profile)" -notmatch 'Public|Any' } | Enable-NetFirewallRule }
}

function Get-Health {
    $items = @()
    $svc = $null
    try { $svc = Get-Service -Name LanmanServer } catch { }
    $items += @{ id = 'smb'; ok = [bool]($svc -and ($svc.Status -eq 'Running')); fix = $true }
    $u = $null
    try { $u = Get-LocalUser -Name $script:UserName -ErrorAction SilentlyContinue } catch { }
    $items += @{ id = 'user'; ok = [bool]($u -and $u.Enabled); fix = [bool]$u }
    $miss = 0
    foreach ($rec in @($script:Cfg.shares | Where-Object { $_.state -ne 'paused' })) {
        $ex = $null
        try { $ex = Get-SmbShare -Name $rec.name -ErrorAction SilentlyContinue } catch { }
        if (-not $ex) { $miss++ }
    }
    $items += @{ id = 'shares'; ok = ($miss -eq 0); fix = $true; missing = $miss }
    $fwOk = $true
    foreach ($n in @('NOVA-Share-UDP', 'NOVA-Share-TCP')) {
        $fr = $null
        try { $fr = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue } catch { }
        if ((-not $fr) -or ([string]$fr.Enabled -ne 'True')) { $fwOk = $false }
    }
    $items += @{ id = 'firewall'; ok = $fwOk; fix = $true }
    $pub = 0
    try { $pub = @(Get-NetConnectionProfile | Where-Object { [string]$_.NetworkCategory -eq 'Public' }).Count } catch { }
    $items += @{ id = 'network'; ok = ($pub -eq 0); fix = $true; publicCount = $pub }
    return , $items
}

function Invoke-HealthFix {
    try { Set-Service -Name LanmanServer -StartupType Automatic; if ((Get-Service -Name LanmanServer).Status -ne 'Running') { Start-Service -Name LanmanServer } } catch { Write-Event ('fix smb: ' + $_.Exception.Message) }
    try { if (Get-LocalUser -Name $script:UserName -ErrorAction SilentlyContinue) { Enable-LocalUser -Name $script:UserName } } catch { Write-Event ('fix user: ' + $_.Exception.Message) }
    foreach ($rec in @($script:Cfg.shares | Where-Object { $_.state -ne 'paused' })) { try { Enable-ShareRecord $rec } catch { Write-Event ('fix share ' + $rec.name + ': ' + $_.Exception.Message) } }
    try { Initialize-FirewallRules } catch { Write-Event ('fix firewall: ' + $_.Exception.Message) }
    try {
        foreach ($p in @(Get-NetConnectionProfile | Where-Object { [string]$_.NetworkCategory -eq 'Public' })) {
            Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory Private
            Write-Event ('network set to Private: ' + $p.Name)
        }
    } catch { Write-Event ('fix network: ' + $_.Exception.Message) }
}

# ── encryption, protocol v2 (round C) ───────────────────────────────────────
# AES-256-GCM through the Windows CNG (bcrypt.dll); Windows PowerShell 5.1 has no managed AES-GCM.
$script:GcmSource = @'
using System;
using System.Runtime.InteropServices;
public static class NovaGcm {
    [StructLayout(LayoutKind.Sequential)]
    struct AuthInfo {
        public int cbSize; public int dwInfoVersion;
        public IntPtr pbNonce; public int cbNonce;
        public IntPtr pbAuthData; public int cbAuthData;
        public IntPtr pbTag; public int cbTag;
        public IntPtr pbMacContext; public int cbMacContext;
        public int cbAAD; public long cbData; public int dwFlags;
    }
    [DllImport("bcrypt.dll")] static extern uint BCryptOpenAlgorithmProvider(out IntPtr phAlg, [MarshalAs(UnmanagedType.LPWStr)] string alg, [MarshalAs(UnmanagedType.LPWStr)] string impl, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptCloseAlgorithmProvider(IntPtr hAlg, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptSetProperty(IntPtr hObj, [MarshalAs(UnmanagedType.LPWStr)] string prop, byte[] input, int cb, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr hKey, IntPtr obj, int cbObj, byte[] secret, int cbSecret, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll")] static extern uint BCryptEncrypt(IntPtr hKey, byte[] input, int cbInput, ref AuthInfo info, byte[] iv, int cbIv, byte[] output, int cbOutput, out int cbResult, uint flags);
    [DllImport("bcrypt.dll")] static extern uint BCryptDecrypt(IntPtr hKey, byte[] input, int cbInput, ref AuthInfo info, byte[] iv, int cbIv, byte[] output, int cbOutput, out int cbResult, uint flags);

    static void OpenAlg(byte[] key, out IntPtr alg, out IntPtr hKey) {
        alg = IntPtr.Zero; hKey = IntPtr.Zero;
        uint st = BCryptOpenAlgorithmProvider(out alg, "AES", null, 0);
        if (st != 0) throw new InvalidOperationException("BCryptOpenAlgorithmProvider 0x" + st.ToString("x"));
        byte[] mode = System.Text.Encoding.Unicode.GetBytes("ChainingModeGCM\0");
        st = BCryptSetProperty(alg, "ChainingMode", mode, mode.Length, 0);
        if (st != 0) { BCryptCloseAlgorithmProvider(alg, 0); throw new InvalidOperationException("BCryptSetProperty 0x" + st.ToString("x")); }
        st = BCryptGenerateSymmetricKey(alg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
        if (st != 0) { BCryptCloseAlgorithmProvider(alg, 0); throw new InvalidOperationException("BCryptGenerateSymmetricKey 0x" + st.ToString("x")); }
    }

    // cipher text followed by the 16-byte tag
    public static byte[] Seal(byte[] key, byte[] nonce, byte[] plain, byte[] aad) {
        IntPtr alg, hKey;
        OpenAlg(key, out alg, out hKey);
        byte[] tag = new byte[16];
        GCHandle hN = GCHandle.Alloc(nonce, GCHandleType.Pinned);
        GCHandle hA = GCHandle.Alloc(aad, GCHandleType.Pinned);
        GCHandle hT = GCHandle.Alloc(tag, GCHandleType.Pinned);
        try {
            AuthInfo info = new AuthInfo();
            info.cbSize = Marshal.SizeOf(typeof(AuthInfo)); info.dwInfoVersion = 1;
            info.pbNonce = hN.AddrOfPinnedObject(); info.cbNonce = nonce.Length;
            info.pbAuthData = hA.AddrOfPinnedObject(); info.cbAuthData = aad.Length;
            info.pbTag = hT.AddrOfPinnedObject(); info.cbTag = 16;
            byte[] ct = new byte[plain.Length];
            int n;
            uint st = BCryptEncrypt(hKey, plain, plain.Length, ref info, null, 0, ct, ct.Length, out n, 0);
            if (st != 0) throw new InvalidOperationException("BCryptEncrypt 0x" + st.ToString("x"));
            byte[] r = new byte[ct.Length + 16];
            Buffer.BlockCopy(ct, 0, r, 0, ct.Length);
            Buffer.BlockCopy(tag, 0, r, ct.Length, 16);
            return r;
        } finally { hN.Free(); hA.Free(); hT.Free(); BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(alg, 0); }
    }

    // the plain text, or null when the tag does not match
    public static byte[] Open(byte[] key, byte[] nonce, byte[] cipherAndTag, byte[] aad) {
        if (cipherAndTag.Length < 16) return null;
        IntPtr alg, hKey;
        OpenAlg(key, out alg, out hKey);
        int len = cipherAndTag.Length - 16;
        byte[] ct = new byte[len];
        byte[] tag = new byte[16];
        Buffer.BlockCopy(cipherAndTag, 0, ct, 0, len);
        Buffer.BlockCopy(cipherAndTag, len, tag, 0, 16);
        GCHandle hN = GCHandle.Alloc(nonce, GCHandleType.Pinned);
        GCHandle hA = GCHandle.Alloc(aad, GCHandleType.Pinned);
        GCHandle hT = GCHandle.Alloc(tag, GCHandleType.Pinned);
        try {
            AuthInfo info = new AuthInfo();
            info.cbSize = Marshal.SizeOf(typeof(AuthInfo)); info.dwInfoVersion = 1;
            info.pbNonce = hN.AddrOfPinnedObject(); info.cbNonce = nonce.Length;
            info.pbAuthData = hA.AddrOfPinnedObject(); info.cbAuthData = aad.Length;
            info.pbTag = hT.AddrOfPinnedObject(); info.cbTag = 16;
            byte[] plain = new byte[len];
            int n;
            uint st = BCryptDecrypt(hKey, ct, len, ref info, null, 0, plain, len, out n, 0);
            if (st == 0xC000A002) return null;
            if (st != 0) throw new InvalidOperationException("BCryptDecrypt 0x" + st.ToString("x"));
            return plain;
        } finally { hN.Free(); hA.Free(); hT.Free(); BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(alg, 0); }
    }
}
'@

function ConvertTo-HexString([byte[]]$b) { return ([BitConverter]::ToString($b)).Replace('-', '').ToLowerInvariant() }
function ConvertFrom-HexString([string]$h) {
    $b = New-Object byte[] ([int]($h.Length / 2))
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($h.Substring(2 * $i, 2), 16) }
    return , $b
}

# the AES key of one pairing: HMAC-SHA256(key = the stored token hash, message = "nova-share-v2 key"); the TV computes the same from the token
function Get-EncKey([string]$hashHex) {
    $m = [System.Security.Cryptography.HMACSHA256]::new([byte[]](ConvertFrom-HexString $hashHex.ToLowerInvariant()))
    try { return , ($m.ComputeHash([System.Text.Encoding]::UTF8.GetBytes('nova-share-v2 key'))) } finally { $m.Dispose() }
}

# true only when the CNG code compiled AND reproduced two known answers (NIST GCM test case 16, and a request made by the TV code)
function Test-GcmReady {
    if ($null -ne $script:EncOk) { return [bool]$script:EncOk }
    $script:EncOk = $false
    try {
        if (-not ('NovaGcm' -as [type])) { Add-Type -TypeDefinition $script:GcmSource -Language CSharp }
        $k = [byte[]](ConvertFrom-HexString 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308')
        $iv = [byte[]](ConvertFrom-HexString 'cafebabefacedbaddecaf888')
        $p = [byte[]](ConvertFrom-HexString 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
        $a = [byte[]](ConvertFrom-HexString 'feedfacedeadbeeffeedfacedeadbeefabaddad2')
        $want = '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b'
        $ct = [NovaGcm]::Seal($k, $iv, $p, $a)
        if ((ConvertTo-HexString $ct) -ne $want) { throw 'known answer 1 (seal) differs' }
        $back = [NovaGcm]::Open($k, $iv, $ct, $a)
        if (($null -eq $back) -or ((ConvertTo-HexString $back) -ne (ConvertTo-HexString $p))) { throw 'known answer 1 (open) differs' }
        $bad = [byte[]]$ct.Clone(); $bad[3] = $bad[3] -bxor 1
        if ($null -ne [NovaGcm]::Open($k, $iv, $bad, $a)) { throw 'a damaged message was accepted' }
        $key = [byte[]](Get-EncKey (Get-Sha256Hex ('0123456789abcdef' * 4)))
        $n2 = [Convert]::FromBase64String('AQIDBAUGBwgJCgsM')
        $c2 = [Convert]::FromBase64String('jPp97vuBHA2rTS9/PeCLs62Wl192hlPt2W21xgq0xiAUesT3WPM4YeiYOlkc4zQ=')
        $o2 = [NovaGcm]::Open($key, $n2, $c2, $script:ReqAad)
        if (($null -eq $o2) -or ([System.Text.Encoding]::UTF8.GetString($o2) -ne '{"cmd":"status","t":1700000000}')) { throw 'known answer 2 (TV request) differs' }
        $script:EncOk = $true
    } catch { Write-Event ('encryption not available: ' + $_.Exception.Message) }
    return [bool]$script:EncOk
}

function Test-RecEnc($rec) {
    $pr = $rec.PSObject.Properties['enc']
    return (($null -ne $pr) -and ($pr.Value -eq $true))
}
function Set-RecEnc($rec) {
    if ($rec.PSObject.Properties['enc']) { $rec.enc = $true } else { Add-Member -InputObject $rec -NotePropertyName 'enc' -NotePropertyValue $true }
    Save-Config $script:Cfg
}

# a request must be fresh (clock within 10 minutes) and never seen before (nonce kept 22 minutes): no replay
function Test-FreshRequest([string]$nonceText, [int64]$t) {
    $now = Get-Now
    foreach ($k in @($script:SeenNonces.Keys)) { if ([int64]$script:SeenNonces[$k] -lt ($now - 1300)) { $script:SeenNonces.Remove($k) } }
    if ([math]::Abs($now - $t) -gt 600) { return 'time' }
    if ($script:SeenNonces.ContainsKey($nonceText)) { return 'replay' }
    if ($script:SeenNonces.Count -gt 5000) { return 'busy' }
    $script:SeenNonces[$nonceText] = $now
    return 'ok'
}

# envelope {"v":2,"n":...,"c":...} -> @{ rec; req; key; nonce }, or $null when no pairing's key opens it
function Open-RequestEnvelope($env) {
    try {
        $n = [Convert]::FromBase64String([string]$env.n)
        $c = [Convert]::FromBase64String([string]$env.c)
    } catch { return $null }
    if (($n.Length -ne 12) -or ($c.Length -lt 17) -or ($c.Length -gt 6000)) { return $null }
    foreach ($t in @($script:Cfg.tokens)) {
        $h = ([string]$t.hash).ToLowerInvariant()
        if ($h -notmatch '^[0-9a-f]{64}$') { continue }
        $key = [byte[]](Get-EncKey $h)
        $plain = [NovaGcm]::Open($key, $n, $c, $script:ReqAad)
        if ($null -ne $plain) {
            $req = $null
            try { $req = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString($plain)) } catch { }
            if (-not $req) { return $null }
            return @{ rec = $t; req = $req; key = $key; nonce = $n; nonceText = [string]$env.n }
        }
    }
    return $null
}

# the whole encrypted exchange: @{ resp = <answer>; key = <key or $null for a plain answer>; nonce = <request nonce> }
function Invoke-EncryptedRequest($env, [string]$ip) {
    if (-not (Test-GcmReady)) { return @{ resp = @{ ok = $false; error = 'no-enc' }; key = $null; nonce = $null } }
    $ctx = Open-RequestEnvelope $env
    if (-not $ctx) { Add-IpFail $ip; return @{ resp = @{ ok = $false; error = 'auth' }; key = $null; nonce = $null } }
    $inner = $ctx.req
    $t = [int64]0
    try { $t = [int64]$inner.t } catch { }
    $fresh = Test-FreshRequest $ctx.nonceText $t
    if ($fresh -eq 'time') { return @{ resp = @{ ok = $false; error = 'time'; now = (Get-Now) }; key = $ctx.key; nonce = $ctx.nonce } }
    if ($fresh -ne 'ok') { Add-IpFail $ip; return @{ resp = @{ ok = $false; error = $fresh }; key = $ctx.key; nonce = $ctx.nonce } }
    if (-not (Test-RecEnc $ctx.rec)) { Set-RecEnc $ctx.rec; Write-Event ("TV '" + [string]$ctx.rec.tv + "' now uses encryption") }
    $resp = $null
    try { $resp = Invoke-NovaCommand $inner $ip $ctx.rec }
    catch { Write-Event ('command error ' + [string]$inner.cmd + ': ' + $_.Exception.Message); $resp = @{ ok = $false; error = 'internal' } }
    if ($resp -is [array]) { $resp = $resp[$resp.Count - 1] }
    return @{ resp = $resp; key = $ctx.key; nonce = $ctx.nonce }
}

# the answer as one encrypted line, bound to the request it answers
function New-EncryptedLine([byte[]]$key, [byte[]]$reqNonce, $resp) {
    $plain = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $resp -Depth 6 -Compress))
    $aad = [byte[]]($script:ResAadPrefix + $reqNonce)
    $nonce = [byte[]](Get-RandomBytes 12)
    $ct = [NovaGcm]::Seal($key, $nonce, $plain, $aad)
    return (ConvertTo-Json -InputObject @{ v = 2; n = [Convert]::ToBase64String($nonce); c = [Convert]::ToBase64String($ct) } -Compress)
}

# ── the commands the TV can send ────────────────────────────────────────────
# ── S-219: pictures for the TV library (Windows thumbnail maker) ──────────────
function Initialize-NovaThumb {
    if ($null -ne $script:ThumbOk) { return $script:ThumbOk }
    try {
        if (-not ('NovaThumb' -as [type])) {
            Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @'
using System;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
public static class NovaThumb {
    [ComImport, Guid("bcc18b79-ba16-442f-80c4-8a59c30c463b"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItemImageFactory { [PreserveSig] int GetImage(Size2 size, int flags, out IntPtr phbm); }
    [StructLayout(LayoutKind.Sequential)] private struct Size2 { public int cx; public int cy; }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    private static extern void SHCreateItemFromParsingName(string path, IntPtr pbc, [MarshalAs(UnmanagedType.LPStruct)] Guid riid,
        [MarshalAs(UnmanagedType.Interface)] out IShellItemImageFactory ppv);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr h);
    public static byte[] Make(string path, int width) {
        IShellItemImageFactory f;
        SHCreateItemFromParsingName(path, IntPtr.Zero, typeof(IShellItemImageFactory).GUID, out f);
        IntPtr hb = IntPtr.Zero;
        int hr;
        try { hr = f.GetImage(new Size2 { cx = width, cy = width }, 0x8 | 0x1, out hb); }   // THUMBNAILONLY | BIGGERSIZEOK
        finally { Marshal.ReleaseComObject(f); }
        if (hr != 0 || hb == IntPtr.Zero) return null;
        try {
            using (Bitmap src = Image.FromHbitmap(hb)) {
                if (src.Width < 16 || src.Height < 16) return null;
                int h = Math.Max(1, (int)((long)src.Height * width / src.Width));
                using (Bitmap dst = new Bitmap(width, h))
                using (Graphics g = Graphics.FromImage(dst))
                using (MemoryStream ms = new MemoryStream()) {
                    g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                    g.DrawImage(src, 0, 0, width, h);
                    ImageCodecInfo jpg = null;
                    foreach (ImageCodecInfo c in ImageCodecInfo.GetImageEncoders()) if (c.MimeType == "image/jpeg") jpg = c;
                    EncoderParameters ep = new EncoderParameters(1);
                    ep.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 80L);
                    dst.Save(ms, jpg, ep);
                    return ms.ToArray();
                }
            }
        } finally { DeleteObject(hb); }
    }
}
'@
        }
        if (-not (Test-Path -LiteralPath $script:ThumbDir)) { New-Item -ItemType Directory -Path $script:ThumbDir -Force | Out-Null }
        $script:ThumbOk = $true
    } catch { Write-Event ('thumbs not available: ' + $_.Exception.Message); $script:ThumbOk = $false }
    return $script:ThumbOk
}

function Get-NovaThumbs($req) {
    $rec = Find-Share ([string]$req.share)
    if (-not $rec) { return @{ ok = $false; error = 'not-found' } }
    if (-not (Initialize-NovaThumb)) { return @{ ok = $false; error = 'no-thumbs' } }
    $base = [System.IO.Path]::GetFullPath([string]$rec.path).TrimEnd('\')
    $w = 320
    try { $w = [Math]::Max(160, [Math]::Min(480, [int]$req.w)) } catch { }
    $videoExt = @('.mkv', '.mp4', '.m4v', '.avi', '.mov', '.wmv', '.ts', '.m2ts', '.mpg', '.mpeg', '.webm', '.flv', '.3gp', '.vob')
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $out = @()
    foreach ($rel in @($req.files | Select-Object -First 8)) {
        $relText = [string]$rel
        if ($sw.ElapsedMilliseconds -gt 6000) { $out += @{ p = $relText; later = $true }; continue }   # the rest in the next request
        $item = @{ p = $relText; miss = $true }
        try {
            $full = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($base, $relText.Replace('/', '\').TrimStart('\')))
            $inside = $full.StartsWith($base + '\', [System.StringComparison]::OrdinalIgnoreCase)
            $ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant()
            if ($inside -and ($videoExt -contains $ext) -and (Test-Path -LiteralPath $full -PathType Leaf)) {
                $fi = New-Object System.IO.FileInfo($full)
                $key = (Get-Sha256Hex ($full.ToLowerInvariant() + '|' + $fi.Length + '|' + $fi.LastWriteTimeUtc.Ticks + '|' + $w)).Substring(0, 32)
                $cache = $script:ThumbDir + '\' + $key + '.jpg'
                $bytes = $null
                if (Test-Path -LiteralPath $cache) { $bytes = [System.IO.File]::ReadAllBytes($cache) }
                else {
                    try { $bytes = [NovaThumb]::Make($full, $w) } catch { $bytes = $null }
                    if ($bytes) { [System.IO.File]::WriteAllBytes($cache, $bytes) }
                }
                if ($bytes) { $item = @{ p = $relText; img = [Convert]::ToBase64String($bytes) } }
            }
        } catch { }
        $out += $item
    }
    try {   # keep the picture folder small
        $all = @(Get-ChildItem -LiteralPath $script:ThumbDir -Filter '*.jpg' -File)
        if ($all.Count -gt 4000) { $all | Sort-Object LastWriteTimeUtc | Select-Object -First 500 | Remove-Item -Force -ErrorAction SilentlyContinue }
    } catch { }
    return @{ ok = $true; items = $out }
}

function Invoke-NovaCommand($req, [string]$ip, $encRec = $null) {
    $cmd = [string]$req.cmd

    if ($cmd -eq 'hello') {
        $pairing = $false
        $pj = Read-JsonFile $script:PairPath
        if ($pj -and ([int64]$pj.expires -gt (Get-Now))) { $pairing = $true }
        $encFlag = 0
        if (Test-GcmReady) { $encFlag = 1 }
        return @{ ok = $true; computer = [string]$env:COMPUTERNAME; version = $script:Version; paired = (@($script:Cfg.tokens).Count -gt 0); pairing = $pairing; enc = $encFlag; thumbs = 1 }
    }

    if ($cmd -eq 'pair') {
        $code = ([string]$req.code) -replace '\s', ''
        if (-not (Test-PairCode $code)) { Add-IpFail $ip; Write-Event ('pairing refused from ' + $ip); return @{ ok = $false; error = 'bad-code' } }
        $tv = (([string]$req.tv) -replace '[^\p{L}\p{N} ._-]', '').Trim()
        if ($tv.Length -gt 30) { $tv = $tv.Substring(0, 30) }
        if (-not $tv) { $tv = 'TV' }
        $token = New-RandomHex 32
        $rec = [pscustomobject]@{ id = (New-RandomHex 4); hash = (Get-Sha256Hex $token); tv = $tv; created = (Get-Now) }
        $all = @($script:Cfg.tokens) + $rec
        if ($all.Count -gt 10) { $all = $all[($all.Count - 10)..($all.Count - 1)] }
        $script:Cfg.tokens = @($all)
        Save-Config $script:Cfg
        Write-Event ("paired TV '" + $tv + "' from " + $ip)
        return @{ ok = $true; token = $token; computer = [string]$env:COMPUTERNAME; host = (Get-LanAddress); user = $script:UserName; password = (Unprotect-Text ([string]$script:Cfg.userSecret)) }
    }

    # everything else needs a token (or, in v2, the key of a pairing: $encRec is the pairing whose key opened the request)
    $tr = $null
    if ($encRec) { $tr = $encRec }
    else {
        $token = [string]$req.token
        if ($token.Length -ge 32) {
            $h = Get-Sha256Hex $token
            foreach ($t in @($script:Cfg.tokens)) { if (Test-SameText ([string]$t.hash) $h) { $tr = $t } }
        }
        if (-not $tr) { Add-IpFail $ip; return @{ ok = $false; error = 'auth' } }
        # this pairing already used encryption: its token is never accepted in plain text again (no downgrade)
        if (Test-RecEnc $tr) { Write-Event ('plain request refused (enc-required) from ' + $ip); return @{ ok = $false; error = 'enc-required' } }
    }

    switch ($cmd) {
        'status' {
            $lan = Get-LanAddress
            $items = @()
            foreach ($rec in @($script:Cfg.shares)) { $items += (ConvertTo-ShareItem $rec $lan) }
            $pub = 0
            try { $pub = @(Get-NetConnectionProfile | Where-Object { [string]$_.NetworkCategory -eq 'Public' }).Count } catch { }
            return @{ ok = $true; computer = [string]$env:COMPUTERNAME; ip = $lan; version = $script:Version; shares = $items; tvs = @($script:Cfg.tokens).Count; publicNetwork = ($pub -gt 0); now = (Get-Now) }
        }
        'drives' {
            $sys = (Get-SystemDrive).TrimEnd('\')
            $list = @()
            foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
                try {
                    if ((([string]$d.DriveType -eq 'Fixed') -or ([string]$d.DriveType -eq 'Removable')) -and $d.IsReady) {
                        $list += @{ letter = $d.Name.Substring(0, 1); label = [string]$d.VolumeLabel; total = [int64]$d.TotalSize; free = [int64]$d.AvailableFreeSpace; system = ($d.Name.TrimEnd('\') -ieq $sys); type = [string]$d.DriveType }
                    }
                } catch { }
            }
            return @{ ok = $true; drives = $list }
        }
        'dirs' {
            $r = Resolve-NovaPath ([string]$req.path)
            if (-not $r.ok) { return @{ ok = $false; error = $r.error } }
            $full = [string]$r.full
            $roots = Get-BlockedRoots
            $sys = Get-SystemDrive
            if (Test-PathBlocked $full $roots $sys $false) { return @{ ok = $false; error = 'blocked' } }
            if (-not (Test-Path -LiteralPath $full -PathType Container)) { return @{ ok = $false; error = 'not-found' } }
            $out = @()
            $trunc = $false
            try {
                $di = New-Object System.IO.DirectoryInfo($full)
                foreach ($c in ($di.GetDirectories() | Sort-Object Name)) {
                    $a = $c.Attributes
                    if (($a -band [System.IO.FileAttributes]::Hidden) -ne 0) { continue }
                    if (($a -band [System.IO.FileAttributes]::System) -ne 0) { continue }
                    if (($a -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    if (Test-PathBlocked $c.FullName $roots $sys $false) { continue }
                    if ($out.Count -ge 300) { $trunc = $true; break }
                    $out += @{ name = [string]$c.Name; path = [string]$c.FullName }
                }
            } catch { return @{ ok = $false; error = 'no-access' } }
            $parent = $null
            if ($full.TrimEnd('\').Length -gt 2) { $parent = $full.TrimEnd('\').Substring(0, $full.TrimEnd('\').LastIndexOf('\')); if ($parent.Length -eq 2) { $parent = $parent + '\' } }
            return @{ ok = $true; path = $full; parent = $parent; dirs = $out; truncated = $trunc }
        }
        'share-add' {
            $chk = Test-DirSharable ([string]$req.path)
            if (-not $chk.ok) { return @{ ok = $false; error = $chk.error } }
            return (Add-ShareFromPath ([string]$chk.full) 0)
        }
        'share-temp' {
            $chk = Test-DirSharable ([string]$req.path)
            if (-not $chk.ok) { return @{ ok = $false; error = $chk.error } }
            $m = 0
            try { $m = [int]$req.minutes } catch { }
            if (($m -lt 1) -or ($m -gt 1440)) { return @{ ok = $false; error = 'bad-minutes' } }
            return (Add-ShareFromPath ([string]$chk.full) $m)
        }
        'share-remove' {
            $rec = Find-Share ([string]$req.name)
            if (-not $rec) { return @{ ok = $false; error = 'not-found' } }
            Remove-ShareRecord $rec
            Write-Event ('share removed ' + $rec.name)
            return @{ ok = $true }
        }
        'share-pause' {
            $rec = Find-Share ([string]$req.name)
            if (-not $rec) { return @{ ok = $false; error = 'not-found' } }
            Disable-ShareRecord $rec.name
            $rec.state = 'paused'
            Save-Config $script:Cfg
            Write-Event ('share paused ' + $rec.name)
            return @{ ok = $true; share = (ConvertTo-ShareItem $rec (Get-LanAddress)) }
        }
        'share-resume' {
            $rec = Find-Share ([string]$req.name)
            if (-not $rec) { return @{ ok = $false; error = 'not-found' } }
            Enable-ShareRecord $rec
            $rec.state = 'active'
            Save-Config $script:Cfg
            Write-Event ('share resumed ' + $rec.name)
            return @{ ok = $true; share = (ConvertTo-ShareItem $rec (Get-LanAddress)) }
        }
        'remove-all' {
            foreach ($rec in @($script:Cfg.shares)) { Remove-ShareRecord $rec }
            Write-Event 'all shares removed'
            return @{ ok = $true }
        }
        'health' { return @{ ok = $true; items = (Get-Health) } }
        'thumbs' { return (Get-NovaThumbs $req) }
        'health-fix' {
            Invoke-HealthFix
            Write-Event 'health fix run'
            return @{ ok = $true; items = (Get-Health) }
        }
        'unpair' {
            $script:Cfg.tokens = @($script:Cfg.tokens | Where-Object { $_.id -ne $tr.id })
            Save-Config $script:Cfg
            Write-Event ("TV '" + $tr.tv + "' unpaired")
            return @{ ok = $true }
        }
        'uninstall' { Write-Event 'uninstall requested by a TV'; return @{ ok = $true; after = 'uninstall' } }
        default { return @{ ok = $false; error = 'unknown-command' } }
    }
}

# ── the server loop ─────────────────────────────────────────────────────────
function Read-RequestLine($stream) {
    $buf = New-Object 'System.Collections.Generic.List[byte]'
    while ($buf.Count -lt 8192) {
        $b = $stream.ReadByte()
        if ($b -lt 0) { break }
        if ($b -eq 10) { break }
        $buf.Add([byte]$b)
    }
    return [System.Text.Encoding]::UTF8.GetString($buf.ToArray()).Trim()
}

function Invoke-ClientRequest($client) {
    $ip = ''
    try {
        $addr = $client.Client.RemoteEndPoint.Address
        $ip = $addr.ToString()
        if (-not (Test-AllowedIp $addr)) { return }
        if (Test-IpBlocked $ip) { return }
        $client.ReceiveTimeout = 3000
        $client.SendTimeout = 5000
        $stream = $client.GetStream()
        $line = Read-RequestLine $stream
        $resp = $null
        $encKey = $null
        $encNonce = $null
        if ($line.StartsWith('NOVA-PAIR ')) {
            $resp = @{ ok = $false; error = 'use-new-wizard' }   # the old NOVA 272 pairing needs a window on the PC; the service uses a code instead
        } else {
            $req = $null
            try { $req = ConvertFrom-Json -InputObject $line } catch { }
            if ($req -and ([string]$req.v -eq '2') -and $req.n -and $req.c) {
                $r2 = Invoke-EncryptedRequest $req $ip
                $resp = $r2.resp; $encKey = $r2.key; $encNonce = $r2.nonce
            }
            elseif ((-not $req) -or (-not $req.cmd)) { Add-IpFail $ip; $resp = @{ ok = $false; error = 'bad-request' } }
            else {
                try { $resp = Invoke-NovaCommand $req $ip }
                catch { Write-Event ('command error ' + [string]$req.cmd + ': ' + $_.Exception.Message); $resp = @{ ok = $false; error = 'internal' } }
            }
        }
        if ($resp -is [array]) { $resp = $resp[$resp.Count - 1] }
        $after = ''
        if ($resp.ContainsKey('after')) { $after = [string]$resp['after']; $resp.Remove('after') }
        $text = ''
        if ($encKey) { $text = New-EncryptedLine ([byte[]]$encKey) ([byte[]]$encNonce) $resp } else { $text = ConvertTo-Json -InputObject $resp -Depth 6 -Compress }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        if ($after -eq 'uninstall') { try { $client.Close() } catch { }; Invoke-Uninstall $false }
    } catch { Write-Event ('client ' + $ip + ': ' + $_.Exception.Message) }
    finally { try { $client.Close() } catch { } }
}

function Invoke-Housekeeping {
    $now = Get-Now
    foreach ($rec in @($script:Cfg.shares)) {
        if (([int64]$rec.expires -gt 0) -and ([int64]$rec.expires -le $now)) {
            Write-Event ('temporary share closed: ' + $rec.name)
            Remove-ShareRecord $rec
        }
    }
    Update-AclJobs
}

function Invoke-Reconcile {
    $now = Get-Now
    foreach ($rec in @($script:Cfg.shares)) {
        try {
            if (([int64]$rec.expires -gt 0) -and ([int64]$rec.expires -le $now)) { Remove-ShareRecord $rec; continue }
            if ($rec.state -eq 'paused') { Disable-ShareRecord $rec.name; continue }
            Enable-ShareRecord $rec
            if (($rec.state -eq 'preparing') -and (-not $script:AclJobs.ContainsKey($rec.name))) { Start-AclJob $rec.name $rec.path 'grant' }
        } catch { Write-Event ('reconcile ' + $rec.name + ': ' + $_.Exception.Message) }
    }
}

function Start-ServiceLoop {
    $script:Cfg = Get-Config
    if (-not $script:Cfg.userSid) { Write-Event 'not installed (no user) - exiting'; return }
    Write-Event ('service start v' + $script:Version)
    if (Test-GcmReady) { Write-Event 'encryption (AES-GCM) ready' } else { Write-Event 'encryption NOT available - plain text only (see the line above)' }
    try { Invoke-Reconcile } catch { Write-Event ('reconcile: ' + $_.Exception.Message) }
    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket, [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
    $udp.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $script:UdpPort)))
    $tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $script:TcpPort)
    $tcp.Start()
    $lastHk = [int64]0
    while ($true) {
        $worked = $false
        try {
            while ($udp.Available -gt 0) {
                $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $data = $udp.Receive([ref]$ep)
                $worked = $true
                if ((Test-LanIp $ep.Address) -and ([System.Text.Encoding]::UTF8.GetString($data).Trim() -eq 'NOVA-FIND')) {
                    $name = ([string]$env:COMPUTERNAME) -replace '[^A-Za-z0-9_\-]', ''
                    $reply = [System.Text.Encoding]::UTF8.GetBytes('NOVA-HERE|' + $name + '|' + $script:TcpPort + '|svc')
                    [void]$udp.Send($reply, $reply.Length, $ep)
                }
            }
            while ($tcp.Pending()) { $worked = $true; Invoke-ClientRequest ($tcp.AcceptTcpClient()) }
            if (((Get-Now) - $lastHk) -ge 10) { $lastHk = Get-Now; Invoke-Housekeeping }
        } catch { Write-Event ('loop: ' + $_.Exception.Message) }
        if (-not $worked) { Start-Sleep -Milliseconds 150 }
    }
}

# ── uninstall (from the PC window or from a TV): no trace is left ───────────
function Invoke-Uninstall([bool]$local) {
    Write-Event 'uninstall start'
    if ($local) { try { Stop-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue } catch { } ; Start-Sleep -Milliseconds 800 }
    $script:Cfg = Get-Config
    foreach ($rec in @($script:Cfg.shares)) {
        Disable-ShareRecord $rec.name
        Start-AclJob $rec.name $rec.path 'remove'
    }
    try { foreach ($s in @(Get-SmbShare | Where-Object { ($_.Name -like 'NOVA-*') -and (-not $_.Special) })) { Remove-SmbShare -Name $s.Name -Force } } catch { }
    try { if (Get-LocalUser -Name $script:UserName -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $script:UserName } } catch { Write-Event ('remove user: ' + $_.Exception.Message) }
    try { Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' -Name $script:UserName -ErrorAction SilentlyContinue } catch { }
    foreach ($n in @('NOVA-Share-UDP', 'NOVA-Share-TCP')) { try { Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue } catch { } }
    # delete the folder a few seconds from now (this script lives in it), then drop the task
    try { Start-Process -FilePath 'cmd.exe' -ArgumentList ('/c ping -n 6 127.0.0.1 >nul & rmdir /s /q "' + $script:Root + '"') -WindowStyle Hidden } catch { }
    try { Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    if (-not $local) { exit 0 }
}

# ── setup (run by NOVA-Share-Setup.cmd, as administrator) ───────────────────
function Test-ServiceAlive {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.ReceiveTimeout = 2500
        $c.SendTimeout = 2500
        $c.Connect('127.0.0.1', $script:TcpPort)
        $s = $c.GetStream()
        $b = [System.Text.Encoding]::UTF8.GetBytes('{"cmd":"hello"}' + "`n")
        $s.Write($b, 0, $b.Length)
        $s.Flush()
        $line = Read-RequestLine $s
        $c.Close()
        return ($line -match '"ok"\s*:\s*true')
    } catch { return $false }
}

function Install-NovaService {
    try { Stop-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue } catch { }
    Start-Sleep -Milliseconds 800
    if (-not (Test-Path -LiteralPath $script:Root)) { New-Item -ItemType Directory -Path $script:Root -Force | Out-Null }
    # only SYSTEM and Administrators may touch this folder (a SYSTEM task runs the script in it)
    & ($env:SystemRoot + '\System32\icacls.exe') $script:Root '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '/Q' | Out-Null
    if ($PSCommandPath -and ($PSCommandPath -ine $script:ServiceCopy)) { Copy-Item -LiteralPath $PSCommandPath -Destination $script:ServiceCopy -Force }

    Set-Service -Name LanmanServer -StartupType Automatic
    if ((Get-Service -Name LanmanServer).Status -ne 'Running') { Start-Service -Name LanmanServer }

    $u = Get-LocalUser -Name $script:UserName -ErrorAction SilentlyContinue
    # an update keeps the same password (the TVs already hold it); a new one is made only on a fresh install
    $pw = ''
    if ($u) { try { $oldCfg = Get-Config; if ($oldCfg.userSecret) { $pw = Unprotect-Text ([string]$oldCfg.userSecret) } } catch { $pw = '' } }
    if (-not $pw) { $pw = New-NovaPassword }
    $sec = ConvertTo-SecureString $pw -AsPlainText -Force
    if ($u) {
        Set-LocalUser -Name $script:UserName -Password $sec -PasswordNeverExpires $true -UserMayChangePassword $false
        Enable-LocalUser -Name $script:UserName
    } else {
        New-LocalUser -Name $script:UserName -Password $sec -FullName 'NOVA TV' -Description 'NOVA - read only from the TV' `
            -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires | Out-Null
    }
    try { Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $script:UserName -ErrorAction Stop } catch { }
    try {
        $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
        if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
        New-ItemProperty -Path $k -Name $script:UserName -Value 0 -PropertyType DWord -Force | Out-Null
    } catch { }
    $sid = [string](Get-LocalUser -Name $script:UserName).SID.Value

    $cfg = Get-Config
    $sidChanged = ($cfg.userSid -and ([string]$cfg.userSid -ne $sid))
    $cfg.userSid = $sid
    $cfg.userSecret = Protect-Text $pw
    # shares made earlier by the old NOVA-Share window become managed by the service
    $known = @{}
    foreach ($s in @($cfg.shares)) { $known[([string]$s.name).ToLower()] = $true }
    foreach ($s in @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { ($_.Name -like 'NOVA-*') -and (-not $_.Special) })) {
        if (-not $known.ContainsKey(([string]$s.Name).ToLower())) {
            $cfg.shares = @($cfg.shares) + [pscustomobject]@{ name = [string]$s.Name; path = [string]$s.Path; state = 'active'; expires = 0; created = (Get-Now) }
        }
    }
    if ($sidChanged) { foreach ($s in @($cfg.shares)) { if ($s.state -ne 'paused') { $s.state = 'preparing' } } }
    Save-Config $cfg
    $script:Cfg = $cfg

    Initialize-FirewallRules
    foreach ($p in @(Get-NetConnectionProfile | Where-Object { [string]$_.NetworkCategory -eq 'Public' })) {
        $ans = [System.Windows.Forms.MessageBox]::Show(
            "הרשת '$($p.Name)' מוגדרת ב-Windows כ'ציבורית', ובה Windows חוסם שיתוף.`r`nלהפוך אותה ל'פרטית' (רשת הבית)?",
            'NOVA-Share', 'YesNo', 'Question')
        if ($ans -eq 'Yes') { Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory Private }
    }

    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $script:ServiceCopy + '" -Action Run')
    $trg = New-ScheduledTaskTrigger -AtStartup
    $pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $script:TaskName -Action $act -Trigger $trg -Principal $pri -Settings $set -Description 'NOVA-Share service (S-187)' -Force | Out-Null
    Start-ScheduledTask -TaskName $script:TaskName
    Write-Event ('installed v' + $script:Version)
    for ($i = 0; $i -lt 12; $i++) { if (Test-ServiceAlive) { return $true }; Start-Sleep -Milliseconds 700 }
    return $false
}

function Get-LocalStatusText {
    $cfg = Get-Config
    $alive = Test-ServiceAlive
    $lines = @()
    $lines += 'המחשב: ' + $env:COMPUTERNAME + '  (' + (Get-LanAddress) + ')'
    if ($alive) { $lines += 'השירות: פועל' } else { $lines += 'השירות: לא עונה (נסה להפעיל מחדש את המחשב או להריץ את ההתקנה שוב)' }
    $lines += 'טלוויזיות מחוברות: ' + @($cfg.tokens).Count
    $lines += 'שיתופים: ' + @($cfg.shares).Count
    foreach ($s in @($cfg.shares)) {
        $extra = ''
        if ([int64]$s.expires -gt 0) { $extra = ' · זמני' }
        if ($s.state -eq 'paused') { $extra += ' · מושהה' }
        if ($s.state -eq 'preparing') { $extra += ' · מכין הרשאות' }
        $lines += '   ' + $s.name + '  ' + $s.path + $extra
    }
    return ($lines -join "`r`n")
}

function Show-SetupForm([bool]$aliveAtStart) {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'NOVA-Share · שירות במחשב'
    $form.ClientSize = New-Object System.Drawing.Size(540, 440)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.RightToLeft = 'Yes'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 10.5)

    $add = {
        param($ctl, $x, $y, $w, $h)
        $ctl.Location = New-Object System.Drawing.Point($x, $y)
        $ctl.Size = New-Object System.Drawing.Size($w, $h)
        $form.Controls.Add($ctl)
        return $ctl
    }
    $title = & $add (New-Object System.Windows.Forms.Label) 16 14 508 34
    $title.Font = New-Object System.Drawing.Font('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
    if ($aliveAtStart) { $title.Text = 'NOVA-Share הותקן ופועל ברקע' } else { $title.Text = 'NOVA-Share הותקן, אבל השירות עוד לא עונה' }

    $info = & $add (New-Object System.Windows.Forms.Label) 16 54 508 78
    $info.Text = "עכשיו בטלוויזיה: הספרייה שלי ← מחשב או NAS ← הקלד את הקוד שלמטה.`r`nאחרי החיבור הראשון אפשר לסגור את החלון הזה. השירות ממשיך לפעול ברקע, וכל השאר (בחירת תיקיות, שיתוף זמני) נעשה מהטלוויזיה."

    $lblCode = & $add (New-Object System.Windows.Forms.Label) 16 140 508 76
    $lblCode.Font = New-Object System.Drawing.Font('Consolas', 44, [System.Drawing.FontStyle]::Bold)
    $lblCode.TextAlign = 'MiddleCenter'
    $lblCode.RightToLeft = 'No'

    $lblTimer = & $add (New-Object System.Windows.Forms.Label) 16 220 508 28
    $lblTimer.TextAlign = 'MiddleCenter'
    $lblTimer.ForeColor = [System.Drawing.Color]::DimGray

    $setCode = {
        $c = New-PairCode
        $lblCode.Text = $c.Substring(0, 3) + ' ' + $c.Substring(3)
    }
    & $setCode

    $btnNew = & $add (New-Object System.Windows.Forms.Button) 16 262 250 40
    $btnNew.Text = 'קוד חדש'
    $btnNew.Add_Click({ & $setCode })

    $btnStatus = & $add (New-Object System.Windows.Forms.Button) 274 262 250 40
    $btnStatus.Text = 'מצב השירות'
    $btnStatus.Add_Click({ [void][System.Windows.Forms.MessageBox]::Show((Get-LocalStatusText), 'NOVA-Share · מצב') })

    $btnRemove = & $add (New-Object System.Windows.Forms.Button) 16 314 250 40
    $btnRemove.Text = 'הסר את השירות מהמחשב'
    $btnRemove.Add_Click({
        $ans = [System.Windows.Forms.MessageBox]::Show("להסיר את NOVA-Share מהמחשב? השיתופים, המשתמש nova, כללי חומת האש והשירות יימחקו. הסרטים עצמם לא יימחקו, והטלוויזיה תפסיק לראות אותם.", 'NOVA-Share', 'YesNo', 'Warning')
        if ($ans -eq 'Yes') {
            try { Invoke-Uninstall $true; [void][System.Windows.Forms.MessageBox]::Show('הוסר. לא נשאר זכר במחשב.', 'NOVA-Share'); $form.Close() }
            catch { [void][System.Windows.Forms.MessageBox]::Show('ההסרה נכשלה: ' + $_.Exception.Message, 'NOVA-Share') }
        }
    })

    $btnClose = & $add (New-Object System.Windows.Forms.Button) 274 314 250 40
    $btnClose.Text = 'סגור'
    $btnClose.Add_Click({ $form.Close() })

    $foot = & $add (New-Object System.Windows.Forms.Label) 16 368 508 60
    $foot.ForeColor = [System.Drawing.Color]::DimGray
    $foot.Text = "הקוד תקף 5 דקות ומשמש רק לחיבור טלוויזיה. השיתופים הם לקריאה בלבד. להסרה מלאה: הכפתור 'הסר את השירות' (או מהטלוויזיה)."

    $tm = New-Object System.Windows.Forms.Timer
    $tm.Interval = 1000
    $tm.Add_Tick({
        $left = $script:CodeExpires - (Get-Now)
        if ($left -gt 0) { $lblTimer.Text = ('הקוד תקף עוד {0}:{1:00}' -f [int][Math]::Floor($left / 60), [int]($left % 60)) }
        else { $lblTimer.Text = 'הקוד פג תוקף. לחץ "קוד חדש".' }
    })
    $tm.Start()
    $form.Add_FormClosed({ $tm.Stop() })
    [void]$form.ShowDialog()
}

function Invoke-Setup {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        try {
            Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', ('"{0}"' -f $PSCommandPath), '-Action', 'Setup')
        } catch { [void][System.Windows.Forms.MessageBox]::Show('כדי להתקין צריך לאשר את חלון ההרשאות של Windows (כן). נסה שוב.', 'NOVA-Share') }
        return
    }
    # before anything on the PC changes, this new script tests itself (including the encryption known answers)
    try {
        $pf = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-Action', 'SelfTest') -WindowStyle Hidden -Wait -PassThru
        if ($pf.ExitCode -ne 0) {
            $go = [System.Windows.Forms.MessageBox]::Show("הבדיקה העצמית של הגרסה החדשה נכשלה, והשירות הקיים לא שונה.`r`nלהמשיך בכל זאת?", 'NOVA-Share', 'YesNo', 'Warning')
            if ($go -ne 'Yes') { return }
        }
    } catch { }
    try {
        $alive = Install-NovaService
        Show-SetupForm $alive
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show("ההתקנה נכשלה:`r`n" + $_.Exception.Message, 'NOVA-Share')
        exit 1
    }
}

# ── self test (pure logic only; runs on any PowerShell, changes nothing) ─────
function Invoke-SelfTest {
    $script:SelfFail = 0
    function Check([string]$n, $got, $exp) {
        if ($got -ceq $exp) { Write-Host ('ok    ' + $n) } else { Write-Host ('FAIL  ' + $n + '  got=[' + $got + ']  expected=[' + $exp + ']'); $script:SelfFail++ }
    }
    $roots = @('C:\Windows', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData')
    $b = { param($p, $share) Test-PathBlocked $p $roots 'C:' $share }
    Check 'block Windows\System32 (share)' (& $b 'C:\Windows\System32' $true) $true
    Check 'block Windows (list)' (& $b 'C:\Windows' $false) $true
    Check 'block ProgramData (case)' (& $b 'c:\programdata\x' $true) $true
    Check 'Windowsfoo is not Windows' (& $b 'C:\Windowsfoo' $true) $false
    Check 'system root: share blocked' (& $b 'C:\' $true) $true
    Check 'system root: list allowed' (& $b 'C:\' $false) $false
    Check 'C:\Users share blocked' (& $b 'C:\Users' $true) $true
    Check 'C:\Users list allowed' (& $b 'C:\Users' $false) $false
    Check 'profile root share blocked' (& $b 'C:\Users\Roni' $true) $true
    Check 'profile root list allowed' (& $b 'C:\Users\Roni' $false) $false
    Check 'profile Videos share allowed' (& $b 'C:\Users\Roni\Videos' $true) $false
    Check 'AppData blocked' (& $b 'C:\Users\Roni\AppData\Local' $false) $true
    Check 'D:\Movies allowed' (& $b 'D:\Movies' $true) $false
    Check 'D:\ root allowed' (& $b 'D:\' $true) $false
    Check 'Recycle bin blocked' (& $b 'D:\Movies\$Recycle.Bin' $false) $true
    Check 'path empty' (Resolve-NovaPath '').ok $false
    Check 'path no slash' (Resolve-NovaPath 'D:').ok $false
    Check 'path dotdot' (Resolve-NovaPath 'D:\a\..\b').ok $false
    Check 'path pipe' (Resolve-NovaPath 'D:\a|b').ok $false
    Check 'path unc' (Resolve-NovaPath '\\server\share').ok $false
    Check 'path ads' (Resolve-NovaPath 'D:\a:b').ok $false
    Check 'name Movies' (Get-ShareBase 'D:\Movies') 'NOVA-Movies'
    Check 'name hebrew' (Get-ShareBase 'D:\סרטים') 'NOVA-Movies'
    Check 'name NOVA-Test' (Get-ShareBase 'D:\NOVA-Test') 'NOVA-Test'
    Check 'name drive root' (Get-ShareBase 'D:\') 'NOVA-D'
    Check 'name long' ((Get-ShareBase 'D:\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA').Length) 30
    Check 'sha256 abc' (Get-Sha256Hex 'abc') 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    Check 'same text' (Test-SameText 'abc' 'abc') $true
    Check 'different text' (Test-SameText 'abc' 'abd') $false
    Check 'digits' ((New-RandomDigits 6) -match '^\d{6}$') $true
    Check 'hex length' ((New-RandomHex 32).Length) 64
    $okPw = $true
    for ($i = 0; $i -lt 50; $i++) { $p = New-NovaPassword; if (($p.Length -ne 14) -or ($p -cnotmatch '[A-Z]') -or ($p -cnotmatch '[a-z]') -or ($p -notmatch '[2-9]') -or ($p -cmatch '[0O1lI]')) { $okPw = $false } }
    Check 'password rules' $okPw $true
    Check 'lan 192.168' (Test-LanIp ([System.Net.IPAddress]::Parse('192.168.1.20'))) $true
    Check 'lan 172.16' (Test-LanIp ([System.Net.IPAddress]::Parse('172.16.5.5'))) $true
    Check 'lan 172.32 no' (Test-LanIp ([System.Net.IPAddress]::Parse('172.32.5.5'))) $false
    Check 'lan public no' (Test-LanIp ([System.Net.IPAddress]::Parse('8.8.8.8'))) $false
    Check 'loopback ok' (Test-AllowedIp ([System.Net.IPAddress]::Parse('127.0.0.1'))) $true

    # files: pairing code + config round trip in a temp folder
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('nova_selftest_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $script:Root = $tmp
    $script:PairPath = Join-Path $tmp 'pair.json'
    $script:CfgPath = Join-Path $tmp 'config.json'
    $c = New-PairCode
    Check 'code is 6 digits' ($c -match '^\d{6}$') $true
    $wrong = if ($c -eq '000000') { '111111' } else { '000000' }
    for ($i = 0; $i -lt 5; $i++) { [void](Test-PairCode $wrong) }
    Check 'locked after 5 wrong tries' (Test-PairCode $c) $false
    $c2 = New-PairCode
    Check 'new code works once' (Test-PairCode $c2) $true
    Check 'code is one-time' (Test-PairCode $c2) $false
    $c3 = New-PairCode
    $pj = Read-JsonFile $script:PairPath
    $pj.expires = (Get-Now) - 1
    Write-JsonFile $script:PairPath $pj
    Check 'expired code refused' (Test-PairCode $c3) $false
    $cfg = Get-Config
    Check 'empty config shares' (@($cfg.shares).Count) 0
    $cfg.shares = @($cfg.shares) + [pscustomobject]@{ name = 'NOVA-Movies'; path = 'D:\Movies'; state = 'active'; expires = 0; created = 1 }
    $cfg.tokens = @($cfg.tokens) + [pscustomobject]@{ id = 'a1'; hash = 'x'; tv = 'Salon'; created = 1 }
    Save-Config $cfg
    $back = Get-Config
    Check 'config round trip shares' (@($back.shares).Count) 1
    Check 'config round trip token' (@($back.tokens)[0].tv) 'Salon'
    Check 'share name validation' ($null -eq (Find-Share 'C:\x')) $true
    $script:Cfg = $back
    Check 'find share' ((Find-Share 'NOVA-Movies').path) 'D:\Movies'
    $item = ConvertTo-ShareItem (Find-Share 'NOVA-Movies') '192.168.1.5'
    Check 'share item address' $item.address '192.168.1.5/NOVA-Movies'
    Check 'share item not temp' $item.temp $false
    # protocol: hello needs no token, others do
    $h = Invoke-NovaCommand ([pscustomobject]@{ cmd = 'hello' }) '192.168.1.9'
    Check 'hello ok' $h.ok $true
    Check 'hello paired' $h.paired $true
    $a = Invoke-NovaCommand ([pscustomobject]@{ cmd = 'status' }) '192.168.1.9'
    Check 'status without token refused' $a.error 'auth'
    $a2 = Invoke-NovaCommand ([pscustomobject]@{ cmd = 'status'; token = 'short' }) '192.168.1.9'
    Check 'short token refused' $a2.error 'auth'
    for ($i = 0; $i -lt 10; $i++) { Add-IpFail '192.168.1.77' }
    Check 'ip blocked after 10 failures' (Test-IpBlocked '192.168.1.77') $true

    # round C: encryption (the vectors come from an independent implementation; the TV's Kotlin code does the same maths)
    Check 'encryption self test passes' (Test-GcmReady) $true
    $encTok = '0123456789abcdef' * 4
    $encRec = [pscustomobject]@{ id = 'e1'; hash = (Get-Sha256Hex $encTok); tv = 'EncTV'; created = 1 }
    $script:Cfg.tokens = @($script:Cfg.tokens) + $encRec
    Check 'key from token' (ConvertTo-HexString ([byte[]](Get-EncKey (Get-Sha256Hex $encTok)))) 'c572b2e811008722ca1971822daabbfff5df852e9101bf3b07f403cfa6af9533'
    $vEnv = [pscustomobject]@{ v = 2; n = 'AQIDBAUGBwgJCgsM'; c = 'jPp97vuBHA2rTS9/PeCLs62Wl192hlPt2W21xgq0xiAUesT3WPM4YeiYOlkc4zQ=' }
    $ctx = Open-RequestEnvelope $vEnv
    Check 'TV request opens' ($null -ne $ctx) $true
    Check 'TV request belongs to its pairing' ([string]$ctx.rec.id) 'e1'
    Check 'TV request text' ([string]$ctx.req.cmd) 'status'
    $vBad = [pscustomobject]@{ v = 2; n = 'AQIDBAUGBwgJCgsM'; c = 'kPp97vuBHA2rTS9/PeCLs62Wl192hlPt2W21xgq0xiAUesT3WPM4YeiYOlkc4zQ=' }
    Check 'damaged request refused' ($null -eq (Open-RequestEnvelope $vBad)) $true
    Check 'old request time refused' (Test-FreshRequest 'n-old' 1700000000) 'time'
    Check 'fresh request ok' (Test-FreshRequest 'n-new' (Get-Now)) 'ok'
    Check 'replayed request refused' (Test-FreshRequest 'n-new' (Get-Now)) 'replay'
    # a whole v2 exchange: build a request like the TV, let the service answer, open the answer like the TV
    $kb = [byte[]](Get-EncKey (Get-Sha256Hex $encTok))
    $rn = [byte[]](Get-RandomBytes 12)
    $rq = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @{ cmd = 'zzz'; t = (Get-Now) } -Compress))
    $rc = [NovaGcm]::Seal($kb, $rn, $rq, $script:ReqAad)
    $env2 = [pscustomobject]@{ v = 2; n = [Convert]::ToBase64String($rn); c = [Convert]::ToBase64String($rc) }
    $ex = Invoke-EncryptedRequest $env2 '192.168.1.9'
    Check 'v2 answer is encrypted' ($null -ne $ex.key) $true
    Check 'v2 command reached the service' ([string]$ex.resp.error) 'unknown-command'
    $line = New-EncryptedLine ([byte[]]$ex.key) ([byte[]]$ex.nonce) $ex.resp
    $o = ConvertFrom-Json -InputObject $line
    $ao = [NovaGcm]::Open($kb, [Convert]::FromBase64String([string]$o.n), [Convert]::FromBase64String([string]$o.c), [byte[]]($script:ResAadPrefix + $rn))
    Check 'v2 answer opens with the token key' ([string](ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString($ao))).error) 'unknown-command'
    Check 'pairing is marked as encrypted' (Test-RecEnc $encRec) $true
    $pl = Invoke-NovaCommand ([pscustomobject]@{ cmd = 'status'; token = $encTok }) '192.168.1.9'
    Check 'plain token refused after encryption' ([string]$pl.error) 'enc-required'
    Check 'hello offers encryption' ((Invoke-NovaCommand ([pscustomobject]@{ cmd = 'hello' }) '192.168.1.9').enc) 1
    Check 'other ip not blocked' (Test-IpBlocked '192.168.1.78') $false
    Remove-Item -LiteralPath $tmp -Recurse -Force
    if ($script:SelfFail -eq 0) { Write-Host 'SELFTEST PASSED' } else { Write-Host ('SELFTEST FAILED: ' + $script:SelfFail); exit 1 }
}

switch ($Action) {
    'Setup' { Invoke-Setup }
    'Run' { Start-ServiceLoop }
    'Uninstall' { Add-Type -AssemblyName System.Windows.Forms; Invoke-Uninstall $true }
    'SelfTest' { Invoke-SelfTest }
}
