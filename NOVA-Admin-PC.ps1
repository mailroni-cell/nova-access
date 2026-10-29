﻿# ─────────────────────────────────────────────────────────────────────────────
# SUPER NOVA Admin (PC) · S-154 · 2026-10-29
# Signed: Claude Opus 5.5 · project "SUPER NOVA" · thread "קרא MD והמשך"
# What: Roni: the PC admin window always has everything the phone NOVA-Admin app has (CLAUDE.md rule S-154).
#       Rewritten from S-018..S-098 to the phone's model (admin/AdminModel.kt, AdminData.kt, NovaCrypto.kt,
#       NovaRemote.kt, InstallLog.kt, CrashWatch.kt):
#       - admin.enc in nova-access is the one list (read-merge-write, newest "mod" wins, nothing of the phone is lost),
#         then codes.json exactly like the phone (sealed entry "d" + end date "x").
#       - 4-digit codes (S-109), invite text word for word like the phone (S-149e).
#       - live status from each user's server, devices from the TVs' own presence (ntfy.sh, S-140/S-147),
#         install journey kept on this PC (access\installs.json, S-151), crash logs (S-137).
#       - per user: WhatsApp / mail / copy invite, screen message (S-093), remote restart (S-137), rename (S-055),
#         change login + new code (S-088), end date (S-077), admin code (S-098), show-details code (S-057),
#         shared-code notice (S-146), install reminder (S-151), switch off / on / delete.
#       - updates itself: version.json "adminPc" in nova-access (NOVA-Admin-PC.ps1).
#       Secrets: GitHub key and sync password stay DPAPI-encrypted on this PC (access\github.key, access\sync.key).
#       Server passwords live only inside the sealed entries and are opened in memory only; never logged.
# Start: double-click C:\Projects\Streamer\NOVA-Admin.cmd (also makes a desktop shortcut "NOVA Admin").
# ─────────────────────────────────────────────────────────────────────────────
$PcVersion = 1
$ErrorActionPreference = 'Stop'
$root      = 'C:\Projects\Streamer\access'
$keyFile   = Join-Path $root 'github.key'
$syncFile  = Join-Path $root 'sync.key'
$cacheFile = Join-Path $root 'cache.dat'
$instFile  = Join-Path $root 'installs.json'
$crashFile = Join-Path $root 'crashes.json'
$errFile   = Join-Path $root 'admin_error.txt'
$Repo      = 'mailroni-cell/nova-access'
$DefaultLink = 'https://github.com/mailroni-cell/nova-access/raw/main/NOVA.apk'
$Salt      = 'bba7c8a8ffec56841421c28c'   # same as NovaRemote.kt (TV + phone)
$utf8      = New-Object Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $root | Out-Null

try {
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Net.Http, Microsoft.VisualBasic
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── small helpers ────────────────────────────────────────────────────────────
function Now-S { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }
function Now-Ms { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }
function Day($s) { [DateTimeOffset]::FromUnixTimeSeconds([int64]$s).ToLocalTime().ToString('dd/MM/yyyy') }
function When($s) {
    $d = [DateTimeOffset]::FromUnixTimeSeconds([int64]$s).ToLocalTime()
    $p = if ($d.ToString('dd/MM') -eq (Get-Date).ToString('dd/MM')) { 'היום' } else { $d.ToString('dd/MM') }
    return $p + ' ' + $d.ToString('HH:mm')
}
function Has($o, $n) { return ($null -ne $o -and $null -ne $o.PSObject.Properties[$n]) }
function Prop($o, $n, $def) { if ((Has $o $n) -and $null -ne $o.$n) { return $o.$n }; return $def }
function Set-P($o, $n, $v) { if (Has $o $n) { $o.$n = $v } else { $o | Add-Member -NotePropertyName $n -NotePropertyValue $v } }
function Read-Text($p) { if (Test-Path $p) { return [IO.File]::ReadAllText($p, $utf8) }; return $null }
function Write-Text($p, $t) { [IO.File]::WriteAllText($p, $t, $utf8) }
function Protect($t) { if (-not $t) { return '' }; return (ConvertTo-SecureString $t -AsPlainText -Force | ConvertFrom-SecureString) }
function Unprotect($t) {
    if (-not $t) { return '' }
    $s = ConvertTo-SecureString $t.Trim()
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
}
function Get-Key { if (Test-Path $keyFile) { return (Unprotect (Get-Content $keyFile -Raw)) }; return $null }
function Get-Sync { if (Test-Path $syncFile) { return (Unprotect (Get-Content $syncFile -Raw)) }; return $null }
function Hex($bytes) { return -join ($bytes | ForEach-Object { $_.ToString('x2') }) }
function Sha($s) { return Hex ([Security.Cryptography.SHA256]::Create().ComputeHash($utf8.GetBytes($s))) }
function Js($s) { return ($s | ConvertTo-Json -Compress) }

# ── crypto: byte for byte like NovaCrypto.kt ─────────────────────────────────
function Normalize($c) { return (($c.ToUpper()) -replace '[^A-Z0-9]', '') }
function IdOf($code) { return Sha ('id:' + $code) }
function Pbkdf2($pw, [byte[]]$salt, $iter) {
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($utf8.GetBytes($pw), $salt, $iter, [Security.Cryptography.HashAlgorithmName]::SHA256)
    return $kdf.GetBytes(64)
}
$script:keyCache = @{}
function CodeKey($code) {
    if (-not $script:keyCache.ContainsKey($code)) { $script:keyCache[$code] = Pbkdf2 $code $utf8.GetBytes('nova-access-v1') 20000 }
    return $script:keyCache[$code]
}
function Seal($k, $text) {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $pb = $utf8.GetBytes($text); $iv = New-Object byte[] 16; $rng.GetBytes($iv)
    $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = [byte[]]$k[0..31]; $aes.IV = $iv
    $ivct = [byte[]]($iv + $aes.CreateEncryptor().TransformFinalBlock($pb, 0, $pb.Length))
    $tag = (New-Object Security.Cryptography.HMACSHA256(, [byte[]]$k[32..63])).ComputeHash($ivct)
    return [Convert]::ToBase64String([byte[]]($ivct + $tag))
}
function Open-Box($k, $b64) {
    try {
        $all = [Convert]::FromBase64String(($b64 -replace '\s', ''))
        $body = [byte[]]$all[0..($all.Length - 33)]; $tag = [byte[]]$all[($all.Length - 32)..($all.Length - 1)]
        $mine = (New-Object Security.Cryptography.HMACSHA256(, [byte[]]$k[32..63])).ComputeHash($body)
        if ([Convert]::ToBase64String($mine) -ne [Convert]::ToBase64String($tag)) { return $null }
        $aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = [byte[]]$k[0..31]; $aes.IV = [byte[]]$body[0..15]
        return $utf8.GetString($aes.CreateDecryptor().TransformFinalBlock($body, 16, $body.Length - 16))
    } catch { return $null }
}
function New-Code($taken) {
    $rng = New-Object Random
    for ($i = 0; $i -lt 200; $i++) { $c = [string]($rng.Next(1000, 10000)); if ($taken -notcontains (IdOf $c)) { return $c } }
    throw 'אין קוד פנוי. נסה שוב.'
}
function Pretty($code) { return (($code -split '(.{4})' | Where-Object { $_ }) -join '-') }
# S-057: 6-digit "show details" code (HMAC of the 10-minute window), like NovaCrypto.revealCode
function Reveal-Code($pretty) {
    $win = [int64][Math]::Floor((Now-S) / 600)
    $h = (New-Object Security.Cryptography.HMACSHA256(, $utf8.GetBytes('nova-reveal-v1:' + (Normalize $pretty)))).ComputeHash($utf8.GetBytes([string]$win))
    $o = $h[$h.Length - 1] -band 0x0f
    $bin = (([int64]($h[$o] -band 0x7f)) -shl 24) -bor (([int64]$h[$o + 1]) -shl 16) -bor (([int64]$h[$o + 2]) -shl 8) -bor ([int64]$h[$o + 3])
    return ($bin % 1000000).ToString('000000')
}
function Open-Entry($u) {
    $t = Open-Box (CodeKey (Normalize $u.pretty)) $u.d
    if (-not $t) { return $null }
    return ($t | ConvertFrom-Json)
}
# S-106: change fields of the newest sealed entry and seal it again under the same code (other fields stay)
function Reseal($u, $set) {
    $o = Open-Entry $u
    if (-not $o) { throw "לא הצלחתי לפתוח את הפרטים של $($u.name)." }
    foreach ($k in $set.Keys) { Set-P $o $k ([string]$set[$k]) }
    return Seal (CodeKey (Normalize $u.pretty)) ($o | ConvertTo-Json -Compress)
}

# ── ntfy.sh (NovaRemote.kt) ──────────────────────────────────────────────────
function H24($s) { return (Sha $s).Substring(0, 24) }
function Cmd-Topic($code) { return 'nova-c' + (H24 "cmd|$Salt|$code") }
function Code-Tag($code) { return (H24 "tag|$Salt|$code").Substring(0, 12) }
$PresenceTopic = 'nova-p' + (H24 "presence|$Salt")
$CrashTopic    = 'nova-x' + (H24 "crash|$Salt")
function Ntfy-Post($topic, $body) {
    try { Invoke-WebRequest -UseBasicParsing -Method Post -Uri ('https://ntfy.sh/' + $topic) -Body $utf8.GetBytes($body) -TimeoutSec 15 | Out-Null; return $true } catch { return $false }
}
function Ntfy-Parse($text) {
    $out = @()
    foreach ($line in ($text -split "`n")) {
        if (-not $line.Trim()) { continue }
        try { $o = $line | ConvertFrom-Json } catch { continue }
        if ($o.event -eq 'message') { $out += [pscustomobject]@{ at = [int64]$o.time; body = [string]$o.message } }
    }
    return $out
}

# ── GitHub (nova-access) ─────────────────────────────────────────────────────
function Gh-Headers { return @{ Authorization = "Bearer $(Get-Key)"; 'User-Agent' = 'NOVA-Admin-PC'; Accept = 'application/vnd.github+json' } }
function Gh-Get($path) {
    try {
        $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/contents/$path" -Headers (Gh-Headers)
        return [pscustomobject]@{ text = $utf8.GetString([Convert]::FromBase64String(($r.content -replace '\s', ''))); sha = $r.sha }
    } catch {
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { return $null }
        throw
    }
}
# false = someone else changed the file in between (409/422): read again and retry
function Gh-Put($path, $text, $sha, $msg) {
    $body = @{ message = $msg; content = [Convert]::ToBase64String($utf8.GetBytes($text)) }
    if ($sha) { $body.sha = $sha }
    try {
        Invoke-RestMethod -Method Put -Uri "https://api.github.com/repos/$Repo/contents/$path" -Headers (Gh-Headers) -Body $utf8.GetBytes(($body | ConvertTo-Json)) -ContentType 'application/json; charset=utf-8' | Out-Null
        return $true
    } catch {
        $c = 0; if ($_.Exception.Response) { $c = [int]$_.Exception.Response.StatusCode }
        if ($c -eq 409 -or $c -eq 422) { return $false }
        if ($c -eq 401 -or $c -eq 403) { throw 'מפתח GitHub לא תקין או בלי הרשאה' }
        throw
    }
}

# ── the shared list (admin.enc) ──────────────────────────────────────────────
function New-U($s) {
    return [pscustomobject]@{
        id = [string]$s.id; name = [string]$s.name; pretty = [string]$s.pretty; d = [string]$s.d; date = [string](Prop $s 'date' '')
        active = [bool](Prop $s 'active' $true); phone = [string](Prop $s 'phone' ''); mail = [string](Prop $s 'mail' '')
        mod = [int64](Prop $s 'mod' 0); del = [bool](Prop $s 'del' $false); x = [int64](Prop $s 'x' 0); adm = [bool](Prop $s 'adm' $false)
    }
}
function New-Cfg($s) { return [pscustomobject]@{ server = [string](Prop $s 'server' ''); link = [string](Prop $s 'link' $DefaultLink); dlcode = [string](Prop $s 'dlcode' '') } }
$script:users = @(); $script:cfg = New-Cfg $null; $script:salt = $null; $script:akey = $null; $script:akeyFor = $null
function Admin-Key([byte[]]$salt) {
    $pw = Get-Sync
    $tag = $pw + '|' + [Convert]::ToBase64String($salt)
    if ($script:akeyFor -ne $tag) { $script:akey = Pbkdf2 $pw $salt 100000; $script:akeyFor = $tag; $script:salt = $salt }
    return $script:akey
}
function Load-Remote {
    $f = Gh-Get 'admin.enc'
    if (-not $f) { return [pscustomobject]@{ users = @(); cfg = (New-Cfg $null); sha = $null } }
    $s = $f.text | ConvertFrom-Json
    $plain = Open-Box (Admin-Key ([Convert]::FromBase64String($s.salt))) $s.d
    if (-not $plain) { throw 'SYNC_PASSWORD' }
    $l = $plain | ConvertFrom-Json
    return [pscustomobject]@{ users = @(@($l.users) | Where-Object { $_ } | ForEach-Object { New-U $_ }); cfg = (New-Cfg $l.cfg); sha = $f.sha }
}
function List-Json($users, $cfg) {
    $u = @($users | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; pretty = $_.pretty; d = $_.d; date = $_.date; active = [bool]$_.active
        phone = $_.phone; mail = $_.mail; mod = [int64]$_.mod; del = [bool]$_.del; x = [int64]$_.x; adm = [bool]$_.adm } })
    return (ConvertTo-Json -InputObject ([ordered]@{ users = $u; cfg = [ordered]@{ server = $cfg.server; link = $cfg.link; dlcode = $cfg.dlcode } }) -Depth 6 -Compress)
}
function Save-Remote($users, $cfg, $sha) {
    if (-not $script:salt) { $b = New-Object byte[] 16; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); $script:salt = $b }
    $box = Seal (Admin-Key $script:salt) (List-Json $users $cfg)
    $file = ConvertTo-Json -InputObject ([ordered]@{ v = 1; salt = [Convert]::ToBase64String([byte[]]$script:salt); d = $box }) -Compress
    return (Gh-Put 'admin.enc' $file $sha 'NOVA admin (PC): update list')
}
# newest change of each user wins (the remote copy on a tie); deleted users stay as a mark
function Merge-Users($remote, $local) {
    $by = [ordered]@{}
    foreach ($u in @($remote) + @($local)) { if (-not $u) { continue }; if (-not $by.Contains($u.id) -or [int64]$u.mod -gt [int64]$by[$u.id].mod) { $by[$u.id] = $u } }
    return @($by.Values | Sort-Object -Property date -Descending | ForEach-Object { New-U $_ })
}
function Save-Cache { try { Write-Text $cacheFile (Protect (List-Json $script:users $script:cfg)) } catch { } }
function Load-Cache {
    try { $l = (Unprotect (Read-Text $cacheFile)) | ConvertFrom-Json; $script:users = @(@($l.users) | Where-Object { $_ } | ForEach-Object { New-U $_ }); $script:cfg = New-Cfg $l.cfg } catch { }
}
function Find($users, $id) { return ($users | Where-Object { $_.id -eq $id } | Select-Object -First 1) }
# read the newest admin.enc, apply $edit on top (it gets $L with .users / .cfg), write it back (retry if the phone wrote in between), then codes.json
function Change([scriptblock]$edit) {
    for ($i = 0; $i -lt 3; $i++) {
        $now = Load-Remote
        $L = [pscustomobject]@{ users = (Merge-Users $now.users $script:users); cfg = $now.cfg }
        & $edit $L
        if (Save-Remote $L.users $L.cfg $now.sha) {
            $script:users = @($L.users); $script:cfg = $L.cfg; Save-Cache
            Publish-Codes $L.users
            return
        }
    }
    throw 'הרשימה השתנתה בזמן השמירה. נסה שוב.'
}
function Publish-Codes($users) {
    for ($i = 0; $i -lt 3; $i++) {
        $f = Gh-Get 'codes.json'
        $codes = @(); if ($f) { try { $codes = @(($f.text | ConvertFrom-Json).codes | Where-Object { $_ }) } catch { } }
        $off = @($users | Where-Object { -not $_.active -or $_.del } | ForEach-Object { $_.id })
        $on = @{}; $users | Where-Object { $_.active -and -not $_.del } | ForEach-Object { $on[$_.id] = $_ }
        $kept = New-Object System.Collections.ArrayList
        foreach ($c in $codes) {
            if ($off -contains $c.id) { continue }
            $u = $on[[string]$c.id]
            if ($u) {
                Set-P $c 'd' $u.d
                if ($u.x -gt 0) { Set-P $c 'x' ([int64]$u.x) } elseif (Has $c 'x') { $c.PSObject.Properties.Remove('x') }
            }
            [void]$kept.Add($c)
        }
        $have = @($kept | ForEach-Object { $_.id })
        foreach ($u in $on.Values) {
            if ($have -contains $u.id) { continue }
            $e = [ordered]@{ id = $u.id; d = $u.d }; if ($u.x -gt 0) { $e.x = [int64]$u.x }
            [void]$kept.Add([pscustomobject]$e)
        }
        $text = '{"v":1,"codes":' + (ConvertTo-Json -InputObject @($kept) -Compress -Depth 4) + '}'
        if ($f -and $f.text.Trim() -eq $text) { return }
        $sha = $null; if ($f) { $sha = $f.sha }
        if (Gh-Put 'codes.json' $text $sha 'NOVA admin (PC): update codes') { return }
    }
    throw 'לא הצלחתי לעדכן את רשימת הקודים. נסה שוב.'
}

# ── install journey (InstallLog.kt), kept on this PC ─────────────────────────
$script:inst = @{}
try { $j = Read-Text $instFile; if ($j) { ($j | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $script:inst[$_.Name] = $_.Value } } } catch { }
function Inst($id) {
    if (-not $script:inst.ContainsKey($id)) { $script:inst[$id] = [pscustomobject]@{ i = 0; v = ''; f = 0; l = 0; d = [pscustomobject]@{} } }
    return $script:inst[$id]
}
function Save-Inst { try { Write-Text $instFile (ConvertTo-Json -InputObject $script:inst -Depth 6 -Compress) } catch { } }
function Invited($u, $via) { $i = Inst $u.id; $i.i = Now-S; $i.v = $via; Save-Inst }
function Inst-Seen($id, $reports) {
    if (-not $reports -or $reports.Count -eq 0) { return }
    $i = Inst $id
    foreach ($s in $reports) {
        $p = $null; if (Has $i.d $s.dev) { $p = $i.d.($s.dev) }
        if (-not $p -or [int64]$p.at -lt $s.at) {
            $m = $s.model; if (-not $m -and $p) { $m = $p.m }
            $v = $s.ver; if ($v -le 0 -and $p) { $v = [int]$p.ver }
            Set-P $i.d $s.dev ([pscustomobject]@{ tv = $s.tv; m = $m; ver = $v; at = $s.at })
        }
        if ([int64]$i.f -eq 0 -or $s.at -lt [int64]$i.f) { $i.f = $s.at }
        if ($s.at -gt [int64]$i.l) { $i.l = $s.at }
    }
}

# ── live state: server status, devices (presence), crash logs ────────────────
$script:live = @{}; $script:devices = @{}; $script:admins = @{}; $script:grants = @{}
$script:novaLatest = 0; $script:historyRead = $false
$script:crash = [pscustomobject]@{ since = ((Now-S) - 12 * 3600); read = 0; logs = @() }
try { $c = (Read-Text $crashFile) | ConvertFrom-Json; if ($c) { $script:crash = $c; $script:crash.logs = @($c.logs | Where-Object { $_ }) } } catch { }
function Save-Crash { try { Write-Text $crashFile (ConvertTo-Json -InputObject $script:crash -Depth 4 -Compress) } catch { } }
function Crash-Unread { return @($script:crash.logs | Where-Object { [int64]$_.t -gt [int64]$script:crash.read }).Count }
function Is-Admin($u) { return ($u.adm -or $script:admins[$u.id] -eq $true) }
function Shown-Users { return @(@($script:users | Where-Object { -not $_.del }) | Sort-Object -Property @{ Expression = { Is-Admin $_ }; Descending = $true }, @{ Expression = { $_.date }; Descending = $true }) }
function Expired($u) { return ($u.x -gt 0 -and (Now-S) -ge $u.x) }

$script:http = New-Object System.Net.Http.HttpClient
$script:http.Timeout = [TimeSpan]::FromSeconds(15)
$script:http.DefaultRequestHeaders.Add('User-Agent', 'NOVA-Admin-PC')
$script:jobs = New-Object System.Collections.ArrayList
function Fetch($url, [scriptblock]$done, $state) {
    try { [void]$script:jobs.Add(@{ t = $script:http.GetStringAsync($url); done = $done; state = $state }) } catch { }
}
function Check-Live {
    foreach ($u in @($script:users | Where-Object { $_.active -and -not $_.del })) {
        $g = $script:grants[$u.id + $u.d]
        if (-not $g) {
            $o = Open-Entry $u
            if (-not $o) { $script:live[$u.id] = @{ ok = $false; error = 'הקוד לא נפתח' }; continue }
            $g = @{ s = ([string]$o.s).TrimEnd('/'); u = [string]$o.u; p = [string]$o.p; a = ([string](Prop $o 'a' '') -eq '1') }
            $script:grants[$u.id + $u.d] = $g
        }
        $script:admins[$u.id] = $g.a
        $url = $g.s + '/player_api.php?username=' + [Uri]::EscapeDataString($g.u) + '&password=' + [Uri]::EscapeDataString($g.p)
        Fetch $url {
            param($text, $id)
            if ($null -eq $text) { $script:live[$id] = @{ ok = $false; error = 'אין חיבור לשרת' }; return }
            try { $info = ($text | ConvertFrom-Json).user_info } catch { $info = $null }
            if (-not $info) { $script:live[$id] = @{ ok = $false; error = 'השרת לא החזיר פרטים' }; return }
            if ([string]$info.auth -eq '0') { $script:live[$id] = @{ ok = $false; error = 'משתמש או סיסמה שגויים' }; return }
            $exp = $null; $n = 0L; if ([int64]::TryParse([string]$info.exp_date, [ref]$n)) { $exp = $n }
            $a = 0; [void][int]::TryParse([string]$info.active_cons, [ref]$a); $m = 0; [void][int]::TryParse([string]$info.max_connections, [ref]$m)
            $script:live[$id] = @{ ok = $true; status = [string]$info.status; active = $a; max = $m; exp = $exp }
        } $u.id
    }
}
function Check-Presence {
    $now = Now-S
    $since = if ($script:historyRead) { $now - 180 } else { $now - 12 * 3600 }
    if (-not $script:historyRead) {
        Fetch ("https://raw.githubusercontent.com/$Repo/main/version.json?t=$now") { param($text) if ($text) { try { $script:novaLatest = [int](($text | ConvertFrom-Json).versionCode) } catch { } } } $null
    }
    Fetch ("https://ntfy.sh/$PresenceTopic/json?poll=1&since=$since") {
        param($text)
        if ($null -eq $text) { return }
        $now = Now-S; $all = @{}; $fresh = @{}
        foreach ($m in (Ntfy-Parse $text)) {
            $f = $m.body -split '\|'
            if ($f.Count -lt 6 -or $f[0] -ne 'v1') { continue }
            $ver = 0; if ($f.Count -gt 6) { [void][int]::TryParse($f[6], [ref]$ver) }
            $s = [pscustomobject]@{ dev = $f[2]; tv = ($f[3] -eq 'tv'); playing = ($f[4] -eq 'p'); model = $f[5]; at = $m.at; ver = $ver }
            if (-not $all.ContainsKey($f[1])) { $all[$f[1]] = New-Object System.Collections.ArrayList }
            [void]$all[$f[1]].Add($s)
            if ($m.at -lt $now - 180) { continue }
            if (-not $fresh.ContainsKey($f[1])) { $fresh[$f[1]] = @{} }
            $p = $fresh[$f[1]][$s.dev]; if (-not $p -or $p.at -le $s.at) { $fresh[$f[1]][$s.dev] = $s }
        }
        $script:devices = @{}
        foreach ($u in $script:users) {
            $tag = Code-Tag (Normalize $u.pretty)
            if ($fresh.ContainsKey($tag)) { $script:devices[$u.id] = @($fresh[$tag].Values | Sort-Object -Property at -Descending) }
            if ($all.ContainsKey($tag)) { Inst-Seen $u.id @($all[$tag]) }
        }
        Save-Inst
        if ($script:users.Count) { $script:historyRead = $true }
    } $null
}
function Check-Crashes {
    Fetch ("https://ntfy.sh/$CrashTopic/json?poll=1&since=" + [int64]$script:crash.since) {
        param($text)
        if ($null -eq $text) { return }
        $old = @($script:crash.logs)
        $seen = @{}; foreach ($o in $old) { $seen[[string]$o.t + '|' + $o.x] = 1 }
        $new = @()
        foreach ($m in (Ntfy-Parse $text)) { if (-not $seen.ContainsKey([string]$m.at + '|' + $m.body)) { $new += [pscustomobject]@{ t = $m.at; x = $m.body } } }
        if ($new.Count -eq 0) { return }
        $script:crash.logs = @(($new + $old) | Sort-Object -Property t -Descending | Select-Object -First 30)
        $script:crash.since = ($new | Measure-Object -Property t -Maximum).Maximum
        Save-Crash
        try { $win.Title = 'SUPER NOVA · ניהול · ⚠ קריסה חדשה' } catch { }
    } $null
}

# ── texts like the phone ─────────────────────────────────────────────────────
function Invite-Text($u) {
    $link = if ($script:cfg.link) { $script:cfg.link } else { $DefaultLink }
    $dl = $script:cfg.dlcode; $code = Normalize $u.pretty
    $phoneLink = if ($dl) { "https://aftv.news/$dl" } else { $link }
    $tvTyped = if ($dl) { $dl } else { $link }
    return "SUPER NOVA  🎬`n`n" +
        "📱 בטלפון / טאבלט - לחץ והתקן:`n`n" +
        "$phoneLink`n`n" +
        "📺 בטלוויזיה - התקן את Downloader:`n`n" +
        "https://play.google.com/store/apps/details?id=com.esaba.downloader`n`n" +
        "פתח אותו, הקלד $tvTyped ולחץ Go.`n`n" +
        "🔑 הקוד שלך (בטלפון: העתק הדבק ): $code"
}
$SharedText = 'שים לב: הקוד שלך פתוח כרגע ביותר ממכשיר אחד. הקוד אישי ומיועד למכשיר אחד בלבד. אם זה לא אתה, פנה אלינו.'
$Green = '#5BD68A'; $Gold = '#F5C76B'; $Red = '#F06B6B'; $Orange = '#F5A35B'; $Muted = '#8A8A98'
function Status-Of($u) {
    $st = $script:live[$u.id]; $devs = @($script:devices[$u.id] | Where-Object { $_ })
    if (-not $u.active) { return @($Muted, 'כבוי') }
    if (Expired $u) { return @($Red, "פג תוקף ב-$(Day $u.x)") }
    if (-not $st) { return @($Muted, 'בודק...') }
    if (-not $st.ok) { return @($Red, $st.error) }
    if ($st.status -and $st.status -ne 'Active') { return @($Red, "בשרת: $($st.status)") }
    if ($devs | Where-Object { $_.playing }) { return @($Green, 'צופה עכשיו') }
    if ($devs.Count) { return @($Gold, 'NOVA פתוחה · לא צופה') }
    return @($Muted, 'פעיל · NOVA סגורה')
}
function Inst-MaxVer($i) { $m = 0; foreach ($p in $i.d.PSObject.Properties) { if ([int]$p.Value.ver -gt $m) { $m = [int]$p.Value.ver } }; return $m }
function Install-Tag($u) {
    $i = Inst $u.id
    if ([int64]$i.f -gt 0) { $v = Inst-MaxVer $i; $t = '✔ מותקן'; if ($v -gt 0) { $t += " · $($v - 1)" }; return @($Green, $t) }
    if ([int64]$i.i -gt 0) { return @($Orange, '⏳ הוזמן · טרם הותקן') }
    return @($Muted, 'טרם נשלחה הזמנה')
}
function Shared-Note($u) {
    $d = @($script:devices[$u.id] | Where-Object { $_ }); if ($d.Count -lt 2) { return $null }
    return "⚠ פתוח עכשיו ב-$($d.Count) מכשירים: " + (($d | ForEach-Object { $(if ($_.tv) { '📺 ' } else { '📱 ' }) + $(if ($_.model) { $_.model } else { 'מכשיר' }) + $(if ($_.playing) { ' (צופה)' } else { '' }) }) -join ' · ')
}
function Local-Digits($s) { $d = $s -replace '\D', ''; if ($d.StartsWith('972')) { $d = '0' + $d.Substring(3) }; return $d }
function Matches($u, $q) {
    $q = $q.Trim(); if (-not $q) { return $true }
    if ($u.name -like "*$q*") { return $true }
    $qd = Local-Digits $q
    return ($qd.Length -ge 3 -and (Local-Digits $u.phone).Contains($qd))
}
function Wa-Number($p) { $d = $p -replace '\D', ''; if ($d.StartsWith('0')) { $d = '972' + $d.Substring(1) }; return $d }

# ── window ───────────────────────────────────────────────────────────────────
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SUPER NOVA · ניהול" Width="1280" Height="820" MinWidth="1060" MinHeight="660" WindowStartupLocation="CenterScreen"
        FlowDirection="RightToLeft" Background="#0B0D12" FontFamily="Segoe UI" Foreground="#EDEDF2">
  <Window.Resources>
    <Style x:Key="Gold" TargetType="Button">
      <Setter Property="Foreground" Value="#111"/><Setter Property="FontSize" Value="14"/><Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Padding" Value="16,8"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Margin" Value="4"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="B" Background="#F5C76B" CornerRadius="10" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="B" Property="Opacity" Value="0.85"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter TargetName="B" Property="Opacity" Value="0.35"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Ghost" TargetType="Button">
      <Setter Property="Foreground" Value="#EDEDF2"/><Setter Property="FontSize" Value="14"/>
      <Setter Property="Padding" Value="12,9"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Margin" Value="4"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="B" Background="#151923" BorderBrush="#333A48" BorderThickness="1" CornerRadius="10" Padding="{TemplateBinding Padding}"><ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="B" Property="BorderBrush" Value="#F5C76B"/></Trigger>
          <Trigger Property="IsEnabled" Value="False"><Setter TargetName="B" Property="Opacity" Value="0.35"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Stat" TargetType="Border"><Setter Property="Background" Value="#151923"/><Setter Property="CornerRadius" Value="12"/><Setter Property="Padding" Value="8"/><Setter Property="Margin" Value="3"/></Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#151923"/><Setter Property="Foreground" Value="White"/><Setter Property="BorderBrush" Value="#333A48"/>
      <Setter Property="Padding" Value="10,7"/><Setter Property="FontSize" Value="15"/><Setter Property="CaretBrush" Value="#F5C76B"/>
    </Style>
    <Style TargetType="ListBoxItem">
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ListBoxItem">
        <Border x:Name="B" Background="#151923" CornerRadius="12" Padding="14,10" Margin="0,4" BorderThickness="2" BorderBrush="Transparent"><ContentPresenter/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="B" Property="Background" Value="#1B2030"/></Trigger>
          <Trigger Property="IsSelected" Value="True"><Setter TargetName="B" Property="BorderBrush" Value="#F5C76B"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
  </Window.Resources>
  <DockPanel>
    <Border DockPanel.Dock="Top" BorderBrush="#222" BorderThickness="0,0,0,1" Padding="18,10">
      <DockPanel>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock Text="★ SUPER NOVA · ניהול" FontSize="24" FontWeight="Bold" Foreground="#F5C76B"/>
          <TextBlock x:Name="SyncState" Text="מחשב" Foreground="#8A8A98" FontSize="13" Margin="14,8,0,0"/>
        </StackPanel>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
          <Button x:Name="BNew" Content="+ משתמש חדש" Style="{StaticResource Gold}"/>
          <Button x:Name="BAll" Content="✉ הודעה לכל המשתמשים" Style="{StaticResource Ghost}"/>
          <Button x:Name="BCrash" Content="יומני קריסה" Style="{StaticResource Ghost}"/>
          <Button x:Name="BRefresh" Content="⟳ רענן" Style="{StaticResource Ghost}"/>
          <Button x:Name="BSettings" Content="⚙ הגדרות" Style="{StaticResource Ghost}"/>
        </StackPanel>
      </DockPanel>
    </Border>
    <TextBlock x:Name="Status" DockPanel.Dock="Bottom" Foreground="#A8A8B8" FontSize="13" Margin="18,6" TextWrapping="Wrap"/>
    <Grid>
      <Grid.ColumnDefinitions><ColumnDefinition Width="470"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
      <Border BorderBrush="#222" BorderThickness="0,0,1,0" Padding="14">
        <DockPanel>
          <StackPanel DockPanel.Dock="Top">
            <UniformGrid Columns="4">
              <Border Style="{StaticResource Stat}"><StackPanel><TextBlock x:Name="NUsers" FontSize="24" FontWeight="Bold" Foreground="#F5C76B" HorizontalAlignment="Center"/><TextBlock Text="משתמשים" HorizontalAlignment="Center"/></StackPanel></Border>
              <Border Style="{StaticResource Stat}"><StackPanel><TextBlock x:Name="NWatch" FontSize="24" FontWeight="Bold" Foreground="#5BD68A" HorizontalAlignment="Center"/><TextBlock Text="צופים עכשיו" HorizontalAlignment="Center"/></StackPanel></Border>
              <Border Style="{StaticResource Stat}"><StackPanel><TextBlock x:Name="NEnd" FontSize="24" FontWeight="Bold" Foreground="#F06B6B" HorizontalAlignment="Center"/><TextBlock Text="נגמר השבוע" HorizontalAlignment="Center"/></StackPanel></Border>
              <Border Style="{StaticResource Stat}"><StackPanel><TextBlock x:Name="NOff" FontSize="24" FontWeight="Bold" Foreground="#8A8A98" HorizontalAlignment="Center"/><TextBlock Text="כבויים" HorizontalAlignment="Center"/></StackPanel></Border>
            </UniformGrid>
            <TextBlock x:Name="Load" FontWeight="Bold" Margin="4,8,4,0" Visibility="Collapsed"/>
            <TextBlock x:Name="SharedAll" FontWeight="Bold" Foreground="#F5A35B" Margin="4,4,4,0" Visibility="Collapsed"/>
            <Grid Margin="0,10,0,0">
              <TextBox x:Name="Search"/>
              <TextBlock x:Name="SearchHint" Text="🔍 חיפוש לפי שם או טלפון" Foreground="#8A8A98" Margin="12,8" IsHitTestVisible="False"/>
            </Grid>
            <TextBlock x:Name="Found" Foreground="#8A8A98" FontSize="12" Margin="6,4,0,0" Visibility="Collapsed"/>
          </StackPanel>
          <TextBlock x:Name="Empty" DockPanel.Dock="Top" Text="אין משתמשים עדיין. לחץ &quot;משתמש חדש&quot;." Foreground="#8A8A98" Margin="10,20" Visibility="Collapsed"/>
          <ListBox x:Name="List" Background="Transparent" BorderThickness="0" Margin="0,6,0,0" ScrollViewer.HorizontalScrollBarVisibility="Disabled" HorizontalContentAlignment="Stretch">
            <ListBox.ItemTemplate><DataTemplate>
              <DockPanel>
                <StackPanel DockPanel.Dock="Right" VerticalAlignment="Center" Margin="8,0,0,0">
                  <Border CornerRadius="8" Padding="8,3" Background="{Binding TagBg}"><TextBlock Text="{Binding Tag}" Foreground="{Binding TagFg}" FontSize="12" FontWeight="Bold"/></Border>
                  <TextBlock Text="{Binding Code}" Foreground="#F5C76B" FontFamily="Consolas" FontSize="13" HorizontalAlignment="Center" Margin="0,4,0,0" FlowDirection="LeftToRight"/>
                </StackPanel>
                <StackPanel>
                  <TextBlock Text="{Binding Name}" Foreground="{Binding NameFg}" FontSize="16" FontWeight="SemiBold"/>
                  <TextBlock Text="{Binding Sub}" Foreground="{Binding SubFg}" FontSize="13"/>
                  <TextBlock Text="{Binding Extra}" Foreground="{Binding ExtraFg}" FontSize="12" Visibility="{Binding ExtraVis}" TextWrapping="Wrap"/>
                </StackPanel>
              </DockPanel>
            </DataTemplate></ListBox.ItemTemplate>
          </ListBox>
        </DockPanel>
      </Border>
      <ScrollViewer Grid.Column="1" VerticalScrollBarVisibility="Auto">
        <StackPanel Margin="24,16">
          <TextBlock x:Name="Pick" Text="בחר משתמש מהרשימה" Foreground="#8A8A98" FontSize="16" Margin="0,30"/>
          <StackPanel x:Name="Card" Visibility="Collapsed">
            <DockPanel>
              <TextBlock x:Name="CCode" DockPanel.Dock="Right" FontSize="26" FontWeight="Bold" Foreground="#F5C76B" FontFamily="Consolas" FlowDirection="LeftToRight" VerticalAlignment="Center"/>
              <TextBlock x:Name="CName" FontSize="28" FontWeight="Bold"/>
            </DockPanel>
            <TextBlock x:Name="CStatus" FontSize="15" Margin="0,4,0,0"/>
            <TextBlock x:Name="CInfo" Foreground="#A8A8B8" FontSize="14" Margin="0,4,0,0" TextWrapping="Wrap"/>
            <TextBlock x:Name="CShared" Foreground="#F5A35B" FontWeight="Bold" Margin="0,6,0,0" TextWrapping="Wrap" Visibility="Collapsed"/>
            <Button x:Name="BShared" Content="שלח הודעה: הקוד בשימוש ביותר ממכשיר אחד" Style="{StaticResource Gold}" HorizontalAlignment="Left" Visibility="Collapsed"/>
            <Border Background="#121620" CornerRadius="14" Padding="16,12" Margin="0,12,0,0">
              <StackPanel>
                <TextBlock Text="מסע ההתקנה" Foreground="#F5C76B" FontWeight="Bold" Margin="0,0,0,6"/>
                <StackPanel x:Name="CSteps"/>
              </StackPanel>
            </Border>
            <Button x:Name="BRemind" Content="🔔 שלח תזכורת להתקנה" Style="{StaticResource Gold}" HorizontalAlignment="Left" Margin="4,10,4,0" Visibility="Collapsed"/>
            <UniformGrid x:Name="CButtons" Columns="3" Margin="0,12,0,0">
              <Button x:Name="BWhats" Content="שלח בוואטסאפ" Style="{StaticResource Ghost}"/>
              <Button x:Name="BMail" Content="שלח במייל" Style="{StaticResource Ghost}"/>
              <Button x:Name="BCopy" Content="העתק הודעה" Style="{StaticResource Ghost}"/>
              <Button x:Name="BMsg" Content="✉ הודעה למסך" Style="{StaticResource Ghost}"/>
              <Button x:Name="BRestart" Content="🔄 אתחול NOVA מרחוק" Style="{StaticResource Ghost}"/>
              <Button x:Name="BRename" Content="שנה שם תצוגה" Style="{StaticResource Ghost}"/>
              <Button x:Name="BLogin" Content="שנה משתמש וסיסמה" Style="{StaticResource Ghost}"/>
              <Button x:Name="BExpiry" Content="📅 תוקף החשבון" Style="{StaticResource Ghost}"/>
              <Button x:Name="BReveal" Content="קוד להצגת פרטים בטלוויזיה" Style="{StaticResource Ghost}"/>
              <Button x:Name="BNewCode" Content="קוד חדש" Style="{StaticResource Ghost}"/>
              <Button x:Name="BAdmin" Content="👑 הפוך לקוד מנהל שלי" Style="{StaticResource Ghost}"/>
              <Button x:Name="BOff" Content="כבה משתמש" Style="{StaticResource Ghost}" Foreground="#F06B6B"/>
              <Button x:Name="BOn" Content="הפעל מחדש" Style="{StaticResource Ghost}"/>
              <Button x:Name="BDel" Content="מחק משתמש כבוי" Style="{StaticResource Ghost}" Foreground="#F06B6B"/>
            </UniformGrid>
          </StackPanel>
        </StackPanel>
      </ScrollViewer>
    </Grid>
  </DockPanel>
</Window>
'@
$win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}
$xaml.SelectNodes('//*[@*[local-name()="Name"]]') | ForEach-Object { $n = $_.Attributes | Where-Object { $_.LocalName -eq 'Name' } | Select-Object -First 1; $ui[$n.Value] = $win.FindName($n.Value) }
$bc = New-Object Windows.Media.BrushConverter
function Brush($c) { return $bc.ConvertFromString($c) }
function Say($t) { $ui.Status.Text = $t }
function Pump { $win.Dispatcher.Invoke([Action]{}, 'Background') }

# ── small dialogs (like the phone's AlertDialogs) ───────────────────────────
function New-Dialog($title) {
    $d = New-Object Windows.Window
    $d.Title = $title; $d.Owner = $win; $d.WindowStartupLocation = 'CenterOwner'; $d.SizeToContent = 'WidthAndHeight'; $d.ResizeMode = 'NoResize'
    $d.FlowDirection = 'RightToLeft'; $d.Background = Brush '#121620'; $d.Foreground = Brush '#EDEDF2'; $d.FontFamily = 'Segoe UI'; $d.FontSize = 15
    $p = New-Object Windows.Controls.StackPanel; $p.Margin = (New-Object Windows.Thickness(22,22,22,22)); $p.MinWidth = 440; $p.MaxWidth = 620; $d.Content = $p
    $h = New-Object Windows.Controls.TextBlock; $h.Text = $title; $h.FontSize = 20; $h.FontWeight = [Windows.FontWeights]::Bold; $h.Foreground = Brush $Gold; $h.Margin = (New-Object Windows.Thickness(0,0,0,12)); $h.TextWrapping = 'Wrap'
    [void]$p.Children.Add($h)
    return @{ win = $d; panel = $p; result = $null }
}
function Add-Text($dlg, $t, $color) {
    $b = New-Object Windows.Controls.TextBlock; $b.Text = $t; $b.TextWrapping = 'Wrap'; $b.Margin = (New-Object Windows.Thickness(0,2,0,8))
    if ($color) { $b.Foreground = Brush $color } else { $b.Foreground = Brush '#A8A8B8' }
    [void]$dlg.panel.Children.Add($b); return $b
}
function Add-Box($dlg, $label, $value, $ltr, $multi) {
    if ($label) { [void](Add-Text $dlg $label $null) }
    $t = New-Object Windows.Controls.TextBox; $t.Text = $value; $t.Margin = (New-Object Windows.Thickness(0,0,0,10))
    $t.Style = $win.FindResource([Windows.Controls.TextBox])
    if ($ltr) { $t.FlowDirection = 'LeftToRight' }
    if ($multi) { $t.AcceptsReturn = $true; $t.TextWrapping = 'Wrap'; $t.MinHeight = 110; $t.VerticalScrollBarVisibility = 'Auto' }
    [void]$dlg.panel.Children.Add($t); return $t
}
function Add-Btn($dlg, $text, $gold, [scriptblock]$click, $color) {
    $b = New-Object Windows.Controls.Button; $b.Content = $text; $b.HorizontalAlignment = 'Stretch'
    $b.Style = $win.FindResource($(if ($gold) { 'Gold' } else { 'Ghost' }))
    if ($color) { $b.Foreground = Brush $color }
    $b.Tag = @{ dlg = $dlg; click = $click; v = $null }
    $b.Add_Click({ param($s, $e) $t = $s.Tag; & $t.click $t.dlg $t.v })
    [void]$dlg.panel.Children.Add($b); return $b
}
function Close-Dlg($dlg, $r) { $dlg.result = $r; $dlg.win.Close() }
function Ask($title, $label, $value, $ltr, $multi, $okText) {
    $d = New-Dialog $title
    $box = Add-Box $d $label $value $ltr $multi
    $d.box = $box
    [void](Add-Btn $d $(if ($okText) { $okText } else { 'שמור' }) $true { param($x) Close-Dlg $x $x.box.Text })
    [void](Add-Btn $d 'ביטול' $false { param($x) Close-Dlg $x $null })
    $d.win.Tag = $box
    $d.win.Add_ContentRendered({ param($s, $e) [void]$s.Tag.Focus() })
    [void]$d.win.ShowDialog(); return $d.result
}
function Confirm($title, $text) { return ([Windows.MessageBox]::Show($text, $title, 'YesNo') -eq 'Yes') }

# ── work: every change goes through admin.enc + codes.json ───────────────────
$script:busy = $false
function Work([scriptblock]$block, $okText) {
    if ($script:busy) { return }
    $script:busy = $true; Say 'מסנכרן...'; Pump
    try { & $block; if ($okText) { Say $okText } }
    catch { if ($_.Exception.Message -eq 'SYNC_PASSWORD') { Say 'סיסמת הסנכרון לא תואמת לזו שבטלפון. בדוק בהגדרות.' } else { Say ('משהו השתבש: ' + $_.Exception.Message) } }
    finally { $script:busy = $false; Refresh-UI }
}
function Ready { return ((Test-Path $keyFile) -and (Test-Path $syncFile)) }
function Load-All {
    if (-not (Ready)) { Say 'צריך מפתח GitHub וסיסמת סנכרון (אותה סיסמה כמו בטלפון). לחץ ⚙ הגדרות.'; return }
    Work {
        $r = Load-Remote
        $script:users = @(Merge-Users $r.users @()); $script:cfg = $r.cfg; Save-Cache
        $ui.SyncState.Text = 'מחשב · מסונכרן עם הטלפון ✔'
        Check-Live; Check-Presence; Check-Crashes
    } 'הכול מעודכן.'
}

# ── list + card ──────────────────────────────────────────────────────────────
$script:sel = $null
function Refresh-UI {
    $all = Shown-Users; $now = Now-S
    $ui.NUsers.Text = $all.Count
    $ui.NWatch.Text = @($all | Where-Object { @($script:devices[$_.id] | Where-Object { $_ -and $_.playing }).Count }).Count
    $ui.NEnd.Text = @($all | Where-Object { $l = $script:live[$_.id]; $l -and $l.exp -and $l.exp -ge $now -and $l.exp -le ($now + 7 * 86400) }).Count
    $ui.NOff.Text = @($all | Where-Object { -not $_.active }).Count
    $ls = @($all | Where-Object { $_.active } | ForEach-Object { $script:live[$_.id] } | Where-Object { $_ -and $_.ok })
    if ($ls.Count) {
        $on = ($ls | ForEach-Object { $_.active } | Measure-Object -Sum).Sum; $max = ($ls | ForEach-Object { $_.max } | Measure-Object -Sum).Sum
        $pct = 0; if ($max -gt 0) { $pct = [int][Math]::Floor($on * 100 / $max) }
        $t = "עומס על הספק עכשיו: $on $(if ($on -eq 1) { 'חיבור' } else { 'חיבורים' })"; if ($max -gt 0) { $t += " מתוך $max ($pct%)" }
        $ui.Load.Text = $t; $ui.Load.Foreground = Brush $(if ($pct -ge 90) { $Red } elseif ($pct -ge 60) { $Orange } else { $Green }); $ui.Load.Visibility = 'Visible'
    } else { $ui.Load.Visibility = 'Collapsed' }
    $sh = @($all | Where-Object { @($script:devices[$_.id] | Where-Object { $_ }).Count -gt 1 }).Count
    if ($sh) { $ui.SharedAll.Text = "⚠ $sh $(if ($sh -eq 1) { 'קוד פתוח' } else { 'קודים פתוחים' }) ביותר ממכשיר אחד כרגע"; $ui.SharedAll.Visibility = 'Visible' } else { $ui.SharedAll.Visibility = 'Collapsed' }
    $cu = Crash-Unread
    $ui.BCrash.Content = $(if ($cu -gt 0) { "⚠ יומני קריסה: $cu חדשים" } else { "יומני קריסה ($(@($script:crash.logs).Count))" })
    $ui.BCrash.Foreground = Brush $(if ($cu -gt 0) { $Orange } else { '#EDEDF2' })
    $q = $ui.Search.Text
    $shown = @($all | Where-Object { Matches $_ $q })
    $ui.Found.Text = "נמצאו $($shown.Count)"; $ui.Found.Visibility = $(if ($q.Trim()) { 'Visible' } else { 'Collapsed' })
    $ui.Empty.Visibility = $(if ($all.Count) { 'Collapsed' } else { 'Visible' })
    $rows = @($shown | ForEach-Object {
        $u = $_; $st = Status-Of $u; $tg = Install-Tag $u; $adm = Is-Admin $u
        $ex = @(); $exc = $Muted
        if ($adm) { $ex += 'קוד מנהל · נספר לבדיקות' }
        $l = $script:live[$u.id]; if ($l -and $l.exp) { $ex += "בתוקף עד $(Day $l.exp)" }
        if ($u.x -gt 0) { $ex += "NOVA עד $(Day $u.x)"; if (Expired $u) { $exc = $Red } }
        $sn = Shared-Note $u; if ($sn) { $ex += $sn; $exc = $Orange }
        $tagBg = $(if ($tg[0] -eq $Green) { '#1F3A2A' } elseif ($tg[0] -eq $Orange) { '#3A321F' } else { '#252830' })
        [pscustomobject]@{ Id = $u.id; Name = $(if ($adm) { "👑 $($u.name)" } else { $u.name }); NameFg = $(if ($adm) { $Gold } else { '#FFFFFF' })
            Sub = $st[1]; SubFg = $st[0]; Tag = $tg[1]; TagFg = $tg[0]; TagBg = $tagBg; Code = ($u.pretty -replace '-', '')
            Extra = ($ex -join "`n"); ExtraFg = $exc; ExtraVis = $(if ($ex.Count) { 'Visible' } else { 'Collapsed' }) }
    })
    $script:refreshing = $true
    $ui.List.ItemsSource = $rows
    if ($script:sel) { $ui.List.SelectedItem = ($rows | Where-Object { $_.Id -eq $script:sel } | Select-Object -First 1) }
    $script:refreshing = $false
    Show-Card
}
function Cur { if (-not $script:sel) { return $null }; return (Find $script:users $script:sel) }
function Step($done, $text) {
    $t = New-Object Windows.Controls.TextBlock; $t.Text = $(if ($done) { '✔ ' } else { '○ ' }) + $text; $t.FontSize = 14; $t.Margin = (New-Object Windows.Thickness(0,2,0,2))
    $t.Foreground = Brush $(if ($done) { $Green } else { $Muted }); [void]$ui.CSteps.Children.Add($t)
}
function Line($text, $color) { $t = New-Object Windows.Controls.TextBlock; $t.Text = $text; $t.FontSize = 13; $t.Margin = (New-Object Windows.Thickness(0,2,0,2)); $t.Foreground = Brush $color; [void]$ui.CSteps.Children.Add($t) }
function Show-Card {
    $u = Cur
    if (-not $u -or $u.del) { $ui.Card.Visibility = 'Collapsed'; $ui.Pick.Visibility = 'Visible'; return }
    $ui.Card.Visibility = 'Visible'; $ui.Pick.Visibility = 'Collapsed'
    $adm = Is-Admin $u
    $ui.CName.Text = $(if ($adm) { "👑 $($u.name)" } else { $u.name }); $ui.CCode.Text = ($u.pretty -replace '-', '')
    $st = Status-Of $u; $ui.CStatus.Text = $st[1]; $ui.CStatus.Foreground = Brush $st[0]
    $info = @(); if ($u.phone) { $info += "טלפון: $($u.phone)" }; if ($u.mail) { $info += "מייל: $($u.mail)" }
    if (-not $adm) { $info += $(if ($u.x -gt 0) { "תוקף החשבון: עד $(Day $u.x)" } else { 'תוקף החשבון: ללא הגבלה' }) }
    $devs = @($script:devices[$u.id] | Where-Object { $_ })
    if ($devs.Count -eq 1) { $info += "פתוח עכשיו ב: $($devs[0].model)$(if ($devs[0].playing) { ' · צופה' } else { '' })" }
    $ui.CInfo.Text = ($info -join ' · ')
    $sn = Shared-Note $u
    $ui.CShared.Text = $sn; $ui.CShared.Visibility = $(if ($sn) { 'Visible' } else { 'Collapsed' }); $ui.BShared.Visibility = $ui.CShared.Visibility
    $ui.CSteps.Children.Clear()
    $i = Inst $u.id
    Step $true "הקוד נוצר · $($u.date)"
    if ([int64]$i.i -gt 0) { Step $true ("הזמנה נשלחה" + $(if ($i.v) { " ב$($i.v)" } else { '' }) + " · $(When $i.i)") } else { Step $false 'הזמנה עוד לא נשלחה מהמחשב הזה' }
    if ([int64]$i.f -gt 0) { Step $true "NOVA הותקנה והקוד הופעל · $(When $i.f)" } else { Step $false 'NOVA עוד לא נפתחה עם הקוד' }
    foreach ($p in @($i.d.PSObject.Properties | Sort-Object -Property { [int64]$_.Value.at } -Descending)) {
        $d = $p.Value; $v = [int]$d.ver
        $vt = if ($v -le 0) { 'גרסה ישנה (לפני 223)' } else { "גרסה $($v - 1)" + $(if ($script:novaLatest -gt 0 -and $v -lt $script:novaLatest) { ' (ישנה)' } else { ' (מעודכנת)' }) }
        Line ("    " + $(if ($d.tv) { '📺' } else { '📱' }) + " " + $(if ($d.m) { $d.m } else { 'מכשיר' }) + " · $vt") $Muted
    }
    if ([int64]$i.l -gt 0) { Line "🕒 נראה לאחרונה: $(When $i.l)" '#FFFFFF' }
    $ui.BRemind.Visibility = $(if ([int64]$i.f -eq 0 -and [int64]$i.i -gt 0 -and (Now-S) - [int64]$i.i -gt 2 * 86400) { 'Visible' } else { 'Collapsed' })
    $ui.BAdmin.Content = $(if ($adm) { '👑 קוד מנהל: פעיל (לחץ להחזיר למשתמש רגיל)' } else { '👑 הפוך לקוד מנהל שלי' })
    $ui.BExpiry.Content = $(if ($u.x -gt 0) { "📅 תוקף החשבון: עד $(Day $u.x)" } else { '📅 תוקף החשבון: ללא הגבלה' })
    $ui.BExpiry.Visibility = $(if ($adm) { 'Collapsed' } else { 'Visible' })
    $ui.BOff.Visibility = $(if (-not $adm -and $u.active) { 'Visible' } else { 'Collapsed' })
    $ui.BOn.Visibility = $(if (-not $adm -and -not $u.active) { 'Visible' } else { 'Collapsed' })
    $ui.BDel.Visibility = $ui.BOn.Visibility
    foreach ($b in 'BWhats', 'BMail', 'BCopy', 'BMsg', 'BRestart', 'BRename', 'BLogin', 'BReveal', 'BNewCode', 'BAdmin', 'BOff', 'BOn', 'BDel', 'BShared', 'BRemind', 'BExpiry') { $ui[$b].IsEnabled = -not $script:busy }
}

# ── actions (AdminModel.kt) ──────────────────────────────────────────────────
function Send-Whats($u, $pre) {
    $p = $u.phone
    if (-not $p) { $p = Ask "מספר הטלפון של $($u.name)" 'אפשר להשאיר ריק' '' $true $false 'המשך'; if ($null -eq $p) { return }; $p = $p.Trim(); if ($p) { Set-Contact $u $p $null } }
    if (-not $pre) { Invited $u 'וואטסאפ' }
    Start-Process ('https://wa.me/' + (Wa-Number $p) + '?text=' + [Uri]::EscapeDataString($pre + (Invite-Text $u)))
    Say "וואטסאפ נפתח מול $($u.name). לחץ שלח."; Show-Card
}
function Send-Mail($u, $pre) {
    $m = $u.mail
    if (-not $m) { $m = Ask "המייל של $($u.name)" 'אפשר להשאיר ריק' '' $true $false 'המשך'; if ($null -eq $m) { return }; $m = $m.Trim(); if ($m) { Set-Contact $u $null $m } }
    if (-not $pre) { Invited $u 'מייל' }
    Start-Process ('mailto:' + $m + '?subject=' + [Uri]::EscapeDataString('NOVA - הקוד שלך') + '&body=' + [Uri]::EscapeDataString((($pre + (Invite-Text $u)) -replace "`n", "`r`n")))
    Say "מייל מוכן ל-$($u.name) נפתח. לחץ שלח."; Show-Card
}
function Set-Contact($u, $phone, $mail) {
    $id = $u.id
    Work { Change { param($L) $x = Find $L.users $id; if ($phone) { $x.phone = $phone }; if ($mail) { $x.mail = $mail }; $x.mod = Now-Ms } } $null
    $u2 = Cur; if ($u2) { $u.phone = $u2.phone; $u.mail = $u2.mail }
}
function Send-Message($targets, $text) {
    $t = $text.Trim(); if (-not $t) { Say 'ההודעה ריקה.'; return }
    $ids = @($targets | Where-Object { $_.active -and -not $_.del } | ForEach-Object { $_.id })
    $mi = [string](Now-Ms)
    $ok = $(if ($ids.Count -eq 1) { 'ההודעה נשלחה. היא תופיע על המסך שלו בתוך כ-3 דקות (רק בטלוויזיה שמחוברת בקוד הזה).' } else { "ההודעה נשלחה ל-$($ids.Count) משתמשים. היא תופיע על המסכים בתוך כ-3 דקות." })
    Work { Change { param($L) foreach ($x in $L.users) { if ($ids -contains $x.id) { $x.d = Reseal $x @{ m = $t; mi = $mi }; $x.mod = Now-Ms } } } } $ok
}
function New-User {
    $d = New-Dialog 'משתמש חדש'
    $d.n = Add-Box $d 'שם (כפי שיופיע בטלוויזיה)' '' $false $false
    $d.u = Add-Box $d 'שם משתמש (באנגלית)' '' $true $false
    [void](Add-Text $d 'סיסמה' $null)
    $pw = New-Object Windows.Controls.PasswordBox; $pw.FlowDirection = 'LeftToRight'; $pw.Margin = (New-Object Windows.Thickness(0,0,0,10)); $pw.Padding = (New-Object Windows.Thickness(10,7,10,7)); $pw.FontSize = 15
    $pw.Background = Brush '#151923'; $pw.Foreground = Brush '#FFFFFF'; $pw.BorderBrush = Brush '#333A48'; [void]$d.panel.Children.Add($pw); $d.p = $pw
    $d.s = Add-Box $d 'שרת' $script:cfg.server $true $false
    $d.ph = Add-Box $d 'טלפון לוואטסאפ (לא חובה)' '' $true $false
    $d.m = Add-Box $d 'מייל (לא חובה)' '' $true $false
    [void](Add-Btn $d 'צור קוד' $true { param($x) Close-Dlg $x 'ok' })
    [void](Add-Btn $d 'ביטול' $false { param($x) Close-Dlg $x $null })
    [void]$d.win.ShowDialog()
    if ($d.result -ne 'ok') { return }
    $name = $d.n.Text.Trim(); $user = $d.u.Text.Trim(); $pass = $d.p.Password; $server = $d.s.Text.Trim(); $phone = $d.ph.Text.Trim(); $mail = $d.m.Text.Trim()
    $d.p.Clear()
    if (-not $name -or -not $user -or -not $pass -or -not $server) { Say 'חסר פרט: שם, משתמש, סיסמה ושרת.'; return }
    if (($user + $pass) -match '[\u0590-\u05FF]') { Say 'משתמש או סיסמה הוקלדו בעברית. עבור לאנגלית (Alt+Shift) והקלד שוב.'; return }
    if ($server -notmatch '^http') { $server = 'http://' + $server }
    $script:newId = $null
    Work {
        Change {
            param($L)
            $code = New-Code @($L.users | ForEach-Object { $_.id })
            $plain = '{"n":' + (Js $name) + ',"s":' + (Js $server) + ',"u":' + (Js $user) + ',"p":' + (Js $pass) + '}'
            $nu = New-U ([pscustomobject]@{ id = (IdOf $code); name = $name; pretty = (Pretty $code); d = (Seal (CodeKey $code) $plain); date = (Get-Date -Format 'yyyy-MM-dd HH:mm')
                active = $true; phone = $phone; mail = $mail; mod = (Now-Ms); del = $false; x = 0; adm = $false })
            $L.users = @($nu) + @($L.users); $L.cfg.server = $server
            $script:newId = $nu.id
        }
        Check-Live
    } "הקוד של $name פורסם. הוא יעבוד בטלוויזיה בתוך כמה דקות."
    $pass = $null
    if ($script:newId) { $script:sel = $script:newId; Refresh-UI }
}
function Pick-Expiry($u) {
    $now = Now-S; $base = [Math]::Max($now, [int64]$u.x)
    $d = New-Dialog "תוקף החשבון של $($u.name)"
    [void](Add-Text $d $(if ($u.x -gt 0) { if ($u.x -gt $now) { "עכשיו: עד $(Day $u.x). הארכה נספרת מהתאריך הזה." } else { "פג ב-$(Day $u.x). נספר מהיום." } } else { 'עכשיו: ללא הגבלה.' }) $null)
    foreach ($o in @(@(1, 'חודש'), @(3, '3 חודשים'), @(6, 'חצי שנה'), @(12, 'שנה'))) {
        $t = [DateTimeOffset]::FromUnixTimeSeconds($base).AddMonths($o[0]).ToUnixTimeSeconds()
        $b = Add-Btn $d "$($o[1]) (עד $(Day $t))" $false { param($x, $v) Close-Dlg $x $v }
        $b.Tag.v = $t
    }
    $b = Add-Btn $d 'ללא הגבלה' $false { param($x) Close-Dlg $x 0 }
    if ($u.x -gt $now) { $b = Add-Btn $d 'סיים היום' $false { param($x) Close-Dlg $x (Now-S) } $Red }
    [void](Add-Btn $d 'ביטול' $false { param($x) Close-Dlg $x $null })
    [void]$d.win.ShowDialog()
    if ($null -eq $d.result) { return }
    $until = [int64]$d.result; $id = $u.id; $nm = $u.name
    Work { Change { param($L) $x = Find $L.users $id; $x.x = $until; $x.mod = Now-Ms } } $(if ($until -gt 0) { "$nm בתוקף עד $(Day $until)." } else { "ל-$nm אין תאריך סיום." })
}
function Show-Reveal($u) {
    $rc = Reveal-Code $u.pretty
    $msg = "SUPER NOVA: קוד להצגת פרטים בטלוויזיה: $rc`nבטלוויזיה: הגדרות > חשבון > הצג פרטים, ולהקיש את הקוד. הקוד בתוקף כ-10 דקות."
    $d = New-Dialog 'קוד להצגת פרטים'
    $c = Add-Text $d $rc $Gold; $c.FontSize = 40; $c.FontWeight = [Windows.FontWeights]::Bold; $c.FlowDirection = 'LeftToRight'; $c.HorizontalAlignment = 'Center'
    [void](Add-Text $d "בטלוויזיה של $($u.name): הגדרות > חשבון > הצג פרטים, ולהקיש את הקוד. בתוקף כ-10 דקות." $null)
    $d.msg = $msg; $d.phone = $u.phone; $d.name = $u.name
    if ($u.phone) { [void](Add-Btn $d 'שלח בוואטסאפ' $true { param($x) Start-Process ('https://wa.me/' + (Wa-Number $x.phone) + '?text=' + [Uri]::EscapeDataString($x.msg)) }) }
    [void](Add-Btn $d 'העתק הודעה' $false { param($x) [Windows.Clipboard]::SetText($x.msg); Say "הקוד ל-$($x.name) הועתק." })
    [void](Add-Btn $d 'סגור' $false { param($x) Close-Dlg $x $null })
    [void]$d.win.ShowDialog()
}
function Show-Crashes {
    $d = New-Dialog 'יומני קריסה מהטלוויזיות'
    if (@($script:crash.logs).Count -eq 0) { [void](Add-Text $d 'אין יומני קריסה.' $null) }
    else {
        $t = New-Object Windows.Controls.TextBox; $t.IsReadOnly = $true; $t.TextWrapping = 'Wrap'; $t.VerticalScrollBarVisibility = 'Auto'; $t.Height = 420; $t.Width = 580
        $t.FlowDirection = 'LeftToRight'; $t.FontFamily = 'Consolas'; $t.FontSize = 12; $t.Background = Brush '#0B0D12'; $t.Foreground = Brush '#DDDDDD'
        $t.Text = ((@($script:crash.logs) | ForEach-Object { (When $_.t) + "`r`n" + $_.x }) -join "`r`n`r`n──────────`r`n`r`n")
        [void]$d.panel.Children.Add($t); $d.t = $t
        [void](Add-Btn $d 'העתק הכול' $false { param($x) [Windows.Clipboard]::SetText($x.t.Text); Say 'היומנים הועתקו. אפשר להדביק ל-Claude.' })
        [void](Add-Btn $d 'נקה את כל היומנים' $false { param($x) $script:crash.logs = @(); Save-Crash; Close-Dlg $x $null } $Red)
    }
    [void](Add-Btn $d 'סגור' $false { param($x) Close-Dlg $x $null })
    $script:crash.read = [int64](@($script:crash.logs | ForEach-Object { [int64]$_.t }) + @(0) | Measure-Object -Maximum).Maximum; Save-Crash
    $win.Title = 'SUPER NOVA · ניהול'
    [void]$d.win.ShowDialog(); Refresh-UI
}
function Show-Settings {
    $d = New-Dialog 'הגדרות'
    $d.c = Add-Box $d 'מספר Downloader (קוד קצר מ-go.aftvnews.com)' $script:cfg.dlcode $true $false
    $d.l = Add-Box $d 'קישור ההורדה המלא (למקרה שאין מספר)' $(if ($script:cfg.link) { $script:cfg.link } else { $DefaultLink }) $true $false
    [void](Add-Text $d $(if (Test-Path $keyFile) { 'מפתח GitHub שמור במחשב (מוצפן). להחלפה: הדבק חדש.' } else { 'אין מפתח GitHub עדיין.' }) $null)
    $k = New-Object Windows.Controls.PasswordBox; $k.FlowDirection = 'LeftToRight'; $k.Margin = (New-Object Windows.Thickness(0,0,0,10)); $k.Padding = (New-Object Windows.Thickness(10,7,10,7)); $k.Background = Brush '#151923'; $k.Foreground = Brush '#FFFFFF'; [void]$d.panel.Children.Add($k); $d.k = $k
    [void](Add-Text $d $(if (Test-Path $syncFile) { 'סיסמת סנכרון שמורה (מוצפנת). להחלפה: הקלד חדשה.' } else { 'סיסמת סנכרון: אותה סיסמה כמו באפליקציה בטלפון (לפחות 10 תווים).' }) $null)
    $s = New-Object Windows.Controls.PasswordBox; $s.FlowDirection = 'LeftToRight'; $s.Margin = (New-Object Windows.Thickness(0,0,0,10)); $s.Padding = (New-Object Windows.Thickness(10,7,10,7)); $s.Background = Brush '#151923'; $s.Foreground = Brush '#FFFFFF'; [void]$d.panel.Children.Add($s); $d.s = $s
    [void](Add-Btn $d 'שמור' $true { param($x) Close-Dlg $x 'ok' })
    [void](Add-Btn $d 'פתח את דף יצירת המפתח' $false { param($x) Start-Process 'https://github.com/settings/personal-access-tokens/new' })
    [void](Add-Btn $d 'פתח את אתר המספרים' $false { param($x) [Windows.Clipboard]::SetText($x.l.Text); Start-Process 'https://go.aftvnews.com/'; Say 'קישור ההורדה הועתק. הדבק אותו באתר שנפתח.' })
    [void](Add-Text $d "איך יוצרים מפתח GitHub (פעם אחת):`n1. לחץ `"פתח את דף יצירת המפתח`".`n2. Token name: NOVA. Expiration: הכי ארוך שיש.`n3. Repository access: Only select repositories ובחר nova-access.`n4. Permissions: Contents = Read and write.`n5. לחץ Generate token, העתק, הדבק כאן ולחץ שמור.`n`nהמפתח והסיסמה נשמרים מוצפנים במחשב הזה בלבד." $null)
    [void](Add-Btn $d 'ביטול' $false { param($x) Close-Dlg $x $null })
    [void]$d.win.ShowDialog()
    if ($d.result -ne 'ok') { $d.k.Clear(); $d.s.Clear(); return }
    if ($d.k.Password) { Set-Content $keyFile (Protect $d.k.Password.Trim()) }
    if ($d.s.Password) {
        if ($d.s.Password.Length -lt 10) { Say 'סיסמת הסנכרון קצרה מדי: לפחות 10 תווים.'; $d.k.Clear(); $d.s.Clear(); return }
        Set-Content $syncFile (Protect $d.s.Password); $script:akeyFor = $null
    }
    $d.k.Clear(); $d.s.Clear()
    $dl = $d.c.Text.Trim(); $ln = $d.l.Text.Trim()
    if (-not (Ready)) { Say 'נשמר. עדיין חסר מפתח GitHub או סיסמת סנכרון.'; return }
    if ($dl -ne $script:cfg.dlcode -or ($ln -and $ln -ne $script:cfg.link)) {
        Work { Change { param($L) $L.cfg.dlcode = $dl; if ($ln) { $L.cfg.link = $ln } } } 'נשמר.'
    }
    Load-All
}

# ── events ───────────────────────────────────────────────────────────────────
$ui.List.Add_SelectionChanged({ if ($script:refreshing) { return }; $s = $ui.List.SelectedItem; if ($s) { $script:sel = $s.Id }; Show-Card })
$ui.Search.Add_TextChanged({ $ui.SearchHint.Visibility = $(if ($ui.Search.Text) { 'Collapsed' } else { 'Visible' }); Refresh-UI })
$ui.BNew.Add_Click({ if (Ready) { New-User } else { Show-Settings } })
$ui.BAll.Add_Click({ $t = Ask 'הודעה לכל המשתמשים' 'ההודעה תופיע על המסך של כל המשתמשים הפעילים.' '' $false $true 'שלח'; if ($t) { Send-Message (Shown-Users) $t } })
$ui.BCrash.Add_Click({ Show-Crashes })
$ui.BRefresh.Add_Click({ Load-All })
$ui.BSettings.Add_Click({ Show-Settings })
$ui.BWhats.Add_Click({ $u = Cur; if ($u) { Send-Whats $u '' } })
$ui.BMail.Add_Click({ $u = Cur; if ($u) { Send-Mail $u '' } })
$ui.BCopy.Add_Click({ $u = Cur; if ($u) { [Windows.Clipboard]::SetText((Invite-Text $u)); Invited $u 'העתקה'; Say "ההודעה ל-$($u.name) הועתקה."; Show-Card } })
$ui.BRemind.Add_Click({
    $u = Cur; if (-not $u) { return }
    Invited $u 'תזכורת'
    if ($u.phone) { Send-Whats $u 'תזכורת: ' } elseif ($u.mail) { Send-Mail $u 'תזכורת: ' } else { Send-Whats $u 'תזכורת: ' }
})
$ui.BShared.Add_Click({ $u = Cur; if ($u) { Send-Message @($u) $SharedText } })
$ui.BMsg.Add_Click({ $u = Cur; if (-not $u) { return }; $t = Ask "הודעה למסך של $($u.name)" 'ההודעה תופיע על המסך שלו (טלוויזיה, טלפון, טאבלט).' '' $false $true 'שלח'; if ($t) { Send-Message @($u) $t } })
$ui.BRestart.Add_Click({
    $u = Cur; if (-not $u) { return }
    if (-not (Confirm "להפעיל מחדש את NOVA אצל $($u.name)?" 'NOVA תיסגר ותיפתח מחדש תוך דקה, אם היא פתוחה עכשיו. אם היא סגורה - לא יקרה כלום.')) { return }
    if (Ntfy-Post (Cmd-Topic (Normalize $u.pretty)) 'restart') { Say "נשלח. NOVA של $($u.name) תופעל מחדש תוך דקה (אם היא פתוחה)." } else { Say 'השליחה נכשלה. כדאי לבדוק את האינטרנט ולנסות שוב.' }
})
$ui.BRename.Add_Click({
    $u = Cur; if (-not $u) { return }
    $n = Ask "שם התצוגה של $($u.name)" 'השם שיופיע בטלוויזיה. הטלוויזיה תתעדכן לבד בתוך רבע שעה, או מיד בפתיחה הבאה. המשתמש יראה הודעה קצרה.' $u.name $false $false 'שמור'
    if ($null -eq $n -or -not $n.Trim()) { return }
    $n = $n.Trim(); $id = $u.id
    Work { Change { param($L) $x = Find $L.users $id; $x.name = $n; $x.d = Reseal $x @{ n = $n }; $x.mod = Now-Ms } } "השם שונה ל-$n. בטלוויזיה הוא יתעדכן לבד בתוך רבע שעה (או מיד כשפותחים את האפליקציה), עם הודעה קצרה למשתמש."
})
$ui.BLogin.Add_Click({
    $u = Cur; if (-not $u) { return }
    $d = New-Dialog "משתמש וסיסמה של $($u.name)"
    $d.u = Add-Box $d 'משתמש חדש' '' $true $false
    $d.p = Add-Box $d 'סיסמה חדשה' '' $true $false
    [void](Add-Text $d 'אותו קוד ואותו שרת. הטלוויזיה תתעדכן לבד בתוך רבע שעה, או מיד בפתיחה הבאה.' $null)
    [void](Add-Btn $d 'שמור' $true { param($x) Close-Dlg $x 'ok' })
    [void](Add-Btn $d 'ביטול' $false { param($x) Close-Dlg $x $null })
    [void]$d.win.ShowDialog()
    if ($d.result -ne 'ok') { return }
    $nu = $d.u.Text.Trim(); $np = $d.p.Text; $d.p.Clear()
    if (-not $nu -or -not $np) { Say 'חסר משתמש או סיסמה.'; return }
    if (($nu + $np) -match '[\u0590-\u05FF]') { Say 'משתמש או סיסמה הוקלדו בעברית. עבור לאנגלית (Alt+Shift) והקלד שוב.'; return }
    $id = $u.id; $nm = $u.name
    Work { Change { param($L) $x = Find $L.users $id; $x.d = Reseal $x @{ n = $x.name; u = $nu; p = $np }; $x.mod = Now-Ms }; $script:grants.Clear(); Check-Live } "פרטי ההתחברות של $nm שונו. הטלוויזיה תתעדכן לבד בתוך רבע שעה, או מיד בפתיחה הבאה."
    $np = $null
})
$ui.BExpiry.Add_Click({ $u = Cur; if ($u) { Pick-Expiry $u } })
$ui.BReveal.Add_Click({ $u = Cur; if ($u) { Show-Reveal $u } })
$ui.BNewCode.Add_Click({
    $u = Cur; if (-not $u) { return }
    if (-not (Confirm "קוד חדש ל-$($u.name)?" 'הקוד הישן יפסיק לעבוד. אחרי זה שלח לו את ההודעה עם הקוד החדש.')) { return }
    $id = $u.id; $nm = $u.name; $script:newId = $null
    Work {
        Change {
            param($L)
            $x = Find $L.users $id
            $o = Open-Box (CodeKey (Normalize $x.pretty)) $x.d
            if (-not $o) { throw "לא הצלחתי לפתוח את הפרטים של $nm." }
            $code = New-Code @($L.users | ForEach-Object { $_.id })
            $n = New-U $x; $n.id = IdOf $code; $n.pretty = Pretty $code; $n.d = Seal (CodeKey $code) $o; $n.date = Get-Date -Format 'yyyy-MM-dd HH:mm'; $n.mod = Now-Ms
            $x.del = $true; $x.active = $false; $x.mod = Now-Ms
            $L.users = @($n) + @($L.users); $script:newId = $n.id
        }
        Check-Live
    } "ל-$nm יש קוד חדש. הקוד הישן הפסיק לעבוד; שלח לו את ההודעה החדשה."
    if ($script:newId) { $script:sel = $script:newId; Refresh-UI }
})
$ui.BAdmin.Add_Click({
    $u = Cur; if (-not $u) { return }
    $on = -not (Is-Admin $u); $id = $u.id; $nm = $u.name
    Work {
        Change { param($L) $x = Find $L.users $id; $x.d = Reseal $x @{ n = $x.name; a = $(if ($on) { '1' } else { '0' }) }; $x.adm = $on; if ($on) { $x.x = 0 }; $x.active = ($x.active -or $on); $x.mod = Now-Ms }
        $script:admins[$id] = $on; $script:grants.Clear()
    } $(if ($on) { "👑 $nm הוא עכשיו קוד מנהל: בלי תאריך סיום ובלי הודעות קוד משותף. הטלוויזיה תתעדכן בתוך רבע שעה." } else { "$nm חזר להיות משתמש רגיל." })
})
$ui.BOff.Add_Click({
    $u = Cur; if (-not $u) { return }
    if (-not (Confirm "לכבות את $($u.name)?" 'הטלוויזיה שלו תפסיק לעבוד.')) { return }
    $id = $u.id; $nm = $u.name
    Work { Change { param($L) $x = Find $L.users $id; $x.active = $false; $x.mod = Now-Ms }; $script:live.Remove($id) } "$nm כובה. הטלוויזיה שלו תיכבה בפתיחה הבאה."
})
$ui.BOn.Add_Click({
    $u = Cur; if (-not $u) { return }
    $id = $u.id; $nm = $u.name
    Work { Change { param($L) $x = Find $L.users $id; $x.active = $true; $x.mod = Now-Ms }; Check-Live } "$nm הופעל מחדש."
})
$ui.BDel.Add_Click({
    $u = Cur; if (-not $u) { return }
    if (-not (Confirm "למחוק את $($u.name) לגמרי?" 'המשתמש יימחק גם מהרשימה בטלפון.')) { return }
    $id = $u.id; $nm = $u.name
    Work { Change { param($L) $x = Find $L.users $id; $x.del = $true; $x.active = $false; $x.mod = Now-Ms } } "$nm נמחק מהרשימה."
    $script:sel = $null; Refresh-UI
})

# ── timers: finished network calls, presence + crashes every minute, server status every 5 minutes ──
$tick = New-Object Windows.Threading.DispatcherTimer; $tick.Interval = [TimeSpan]::FromMilliseconds(300)
$tick.Add_Tick({
    $doneAny = $false
    foreach ($j in @($script:jobs)) {
        if (-not $j.t.IsCompleted) { continue }
        $script:jobs.Remove($j); $doneAny = $true
        $text = $null; if ($j.t.Status -eq 'RanToCompletion') { $text = $j.t.Result }
        try { & $j.done $text $j.state } catch { }
    }
    if ($doneAny -and -not $script:busy) { Refresh-UI }
})
$tick.Start()
$minute = New-Object Windows.Threading.DispatcherTimer; $minute.Interval = [TimeSpan]::FromSeconds(60)
$script:minutes = 0
$minute.Add_Tick({
    if (-not (Ready) -or $script:busy) { return }
    $script:minutes++
    Check-Presence; Check-Crashes
    if ($script:minutes % 5 -eq 0) { Check-Live }
})
$minute.Start()

# ── updates itself from nova-access (version.json "adminPc") ─────────────────
function Check-SelfUpdate {
    Fetch ("https://raw.githubusercontent.com/$Repo/main/version.json?t=" + (Now-S)) {
        param($text)
        if (-not $text) { return }
        try { $a = ($text | ConvertFrom-Json).adminPc } catch { return }
        if (-not $a -or [int]$a.version -le $PcVersion -or -not $a.url) { return }
        try {
            $bytes = $script:http.GetByteArrayAsync([string]$a.url).GetAwaiter().GetResult()
            $body = $utf8.GetString($bytes)
            if ($body -notmatch 'SUPER NOVA Admin \(PC\)' -or $body -notmatch '\$PcVersion = (\d+)' -or [int]$Matches[1] -ne [int]$a.version) { return }
            $me = $PSCommandPath; if (-not $me) { $me = 'C:\Projects\Streamer\tools\nova_admin.ps1' }
            Copy-Item $me ($me + '.bak') -Force
            [IO.File]::WriteAllBytes($me, $bytes)
            Say "עודכן לגרסה $($a.version). נפתח מחדש..."
            Start-Process powershell -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', "`"$me`"")
            $win.Close()
        } catch { }
    } $null
}

$win.Add_ContentRendered({
    Load-Cache; Refresh-UI
    if (Ready) { Load-All } else { Show-Settings }
    Check-SelfUpdate
})

# desktop shortcut, once
$lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'NOVA Admin.lnk'
if (-not (Test-Path $lnk)) {
    try {
        $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
        $sc.TargetPath = 'C:\Projects\Streamer\NOVA-Admin.cmd'; $sc.WorkingDirectory = 'C:\Projects\Streamer'
        $sc.IconLocation = 'C:\Windows\System32\imageres.dll,73'; $sc.WindowStyle = 7; $sc.Save()
    } catch { }
}

$win.ShowDialog() | Out-Null
} catch {
    [IO.File]::WriteAllText($errFile, ((Get-Date -Format s) + "`n" + $_.Exception.ToString() + "`n" + $_.InvocationInfo.PositionMessage), $utf8)
    try { [Windows.MessageBox]::Show("NOVA Admin נתקל בשגיאה. הפרטים נשמרו ב-access\admin_error.txt`n`n" + $_.Exception.Message, 'NOVA') | Out-Null } catch { }
}
