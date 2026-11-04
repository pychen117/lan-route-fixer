#Requires -Version 5.1
<#
.SYNOPSIS
    Keep LAN hosts from the SSH config off the VPN tunnel (aTrust / EasyConnect).

.DESCRIPTION
    Sangfor aTrust and EasyConnect split the private IPv4 space (10/8,
    172.16/12, 192.168/16) into many long-prefix routes on their tunnel
    adapter, each with metric 0. Windows picks the longest prefix first, so
    a host such as 192.168.4.94 stops answering on the local Wi-Fi even though
    it is one metre away.

    This script adds an explicit /32 host route for every SSH host that lives
    in a physical adapter's subnet. The /32 is longer than any tunnel prefix,
    so it always wins, and it points at the physical adapter's on-link
    gateway (0.0.0.0).

    Windows has no `ip rule`, so the route is re-applied by a watch loop (or
    the optional scheduled task) whenever aTrust rewrites the table.

    Actions:
      status     show the SSH hosts, the chosen physical adapter and the
                 route that currently wins (read-only, no admin needed)
      apply      create the /32 routes (needs an elevated PowerShell)
      remove     delete the /32 routes this tool owns
      watch      re-apply every -WatchInterval seconds until Ctrl+C
      install    register a scheduled task that runs "watch" at logon
      uninstall  remove the scheduled task

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\windows\pin-lan.ps1 -Action status

.EXAMPLE
    # One-click wrapper (self-elevates through UAC):
    .\tools\windows\fix-lan.cmd

.EXAMPLE
    # Elevated PowerShell:
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\tools\windows\pin-lan.ps1 -Action apply

.NOTES
    ASCII-only on purpose: Windows PowerShell 5.1 reads .ps1 files in the
    system ANSI code page unless they carry a BOM.
#>
[CmdletBinding()]
param(
    [ValidateSet('status', 'apply', 'remove', 'watch', 'install', 'uninstall')]
    [string]$Action = 'status',

    [string]$SshConfig = (Join-Path $env:USERPROFILE '.ssh\config'),

    # Force one adapter (name or ifIndex) instead of automatic selection.
    [string]$Adapter = '',

    [int]$WatchInterval = 10,

    [string]$TaskName = 'LanRouteFixer',

    [switch]$AsJson
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-IPv4Number([string]$Address) {
    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return $null }
    $bytes = $parsed.GetAddressBytes()
    if ($bytes.Length -ne 4) { return $null }
    # Plain [long] arithmetic: Windows PowerShell 5.1's -shl rejects [uint64].
    return ([long]$bytes[0] * 16777216) + ([long]$bytes[1] * 65536) + ([long]$bytes[2] * 256) + [long]$bytes[3]
}

function Get-PrefixInfo([string]$Prefix) {
    $parts = $Prefix -split '/'
    if ($parts.Count -ne 2) { return $null }
    $number = Get-IPv4Number $parts[0]
    if ($null -eq $number) { return $null }
    $length = 0
    if (-not [int]::TryParse($parts[1], [ref]$length)) { return $null }
    if ($length -lt 0 -or $length -gt 32) { return $null }
    $mask = [long]0
    if ($length -ge 32) {
        $mask = [long]4294967295
    }
    elseif ($length -gt 0) {
        $mask = [long](4294967295 - ([math]::Pow(2, 32 - $length) - 1))
    }
    return [pscustomobject]@{ Address = $parts[0]; Length = $length; Mask = $mask; Network = $number }
}

function Test-InPrefix([string]$Address, [string]$Prefix) {
    $info = Get-PrefixInfo $Prefix
    if ($null -eq $info) { return $false }
    $number = Get-IPv4Number $Address
    if ($null -eq $number) { return $false }
    return (($number -band $info.Mask) -eq ($info.Network -band $info.Mask))
}

# Tunnels and other virtual adapters that must never own a LAN host route.
$script:TunnelPattern = '(?i)tunnel|atrust|sangfor|easyconnect|tailscale|wintun|wireguard|openvpn|forticlient|anyconnect|globalprotect|vpn|loopback|virtual|hyper-v|vethernet|wi-fi direct|bluetooth'

function Test-PhysicalAdapter($adapter) {
    if ($null -eq $adapter) { return $false }
    if ($adapter.Status -ne 'Up') { return $false }
    if ($adapter.MediaType -notin @('Native 802.11', '802.3')) { return $false }
    if ($adapter.InterfaceDescription -match $script:TunnelPattern) { return $false }
    if ($adapter.Name -match $script:TunnelPattern) { return $false }
    return $true
}

function Get-PhysicalAdapters {
    $candidates = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { Test-PhysicalAdapter $_ })
    $result = @()
    foreach ($adapter in $candidates) {
        $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '0.0.0.0' })
        if ($addresses.Count -eq 0) { continue }
        $result += [pscustomobject]@{
            Name        = $adapter.Name
            ifIndex     = [int]$adapter.ifIndex
            Description = $adapter.InterfaceDescription
            Addresses   = $addresses
            Metric      = (Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue).InterfaceMetric
        }
    }
    return @($result | Sort-Object { if ($null -eq $_.Metric) { 9999 } else { [int]$_.Metric } })
}

function Get-CoveringAdapters([string]$Address, $adapters) {
    if ($null -eq (Get-IPv4Number $Address)) { return @() }
    $hits = @()
    foreach ($adapter in $adapters) {
        foreach ($ip in $adapter.Addresses) {
            $prefix = "$($ip.IPAddress)/$($ip.PrefixLength)"
            if (Test-InPrefix $Address $prefix) {
                $hits += [pscustomobject]@{ Adapter = $adapter; Prefix = $prefix; Address = $ip.IPAddress }
                break
            }
        }
    }
    return $hits
}

function Get-AdapterByKey([string]$Key, $adapters) {
    if (-not $Key) { return $null }
    $number = 0
    foreach ($adapter in $adapters) {
        if ($adapter.Name -eq $Key) { return $adapter }
        if ([int]::TryParse($Key, [ref]$number) -and $adapter.ifIndex -eq $number) { return $adapter }
    }
    # Allow matching the *current* adapter of an already pinned host too.
    $known = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -eq $Key -or [string]$_.ifIndex -eq $Key
    }
    if ($known) { return $known | Select-Object -First 1 }
    return $null
}

# ---------------------------------------------------------------------------
# SSH config parsing (Host / HostName / Port / User / Include)
# ---------------------------------------------------------------------------

function Strip-SshComment([string]$Line) {
    $inQuote = $null
    for ($i = 0; $i -lt $Line.Length; $i++) {
        $ch = $Line[$i]
        if ($ch -eq '"' -or $ch -eq "'") {
            if ($null -eq $inQuote) { $inQuote = $ch }
            elseif ($inQuote -eq $ch) { $inQuote = $null }
            continue
        }
        if ($ch -eq '#' -and $null -eq $inQuote) {
            # OpenSSH treats '#' as a comment start at the beginning of a
            # token, i.e. after whitespace or at column 0.
            if ($i -eq 0 -or $Line[$i - 1] -eq ' ' -or $Line[$i - 1] -eq "`t") {
                return $Line.Substring(0, $i)
            }
        }
    }
    return $Line
}

function Expand-SshInclude([string]$Pattern, [string]$BaseDir) {
    if ([string]::IsNullOrWhiteSpace($Pattern)) { return @() }
    $pattern = $Pattern.Trim('"').Trim("'")
    if ($pattern.StartsWith('~')) {
        $pattern = Join-Path $env:USERPROFILE $pattern.Substring(2)
    }
    elseif (-not [System.IO.Path]::IsPathRooted($pattern)) {
        $pattern = Join-Path $BaseDir $pattern
    }
    return @(Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
}

function Read-SshConfigFile([string]$Path, [int]$Depth, [System.Collections.Generic.List[string]]$Seen) {
    $blocks = @()
    if ($Depth -gt 4) { return $blocks }
    if (-not (Test-Path -LiteralPath $Path)) { return $blocks }
    try {
        $full = (Resolve-Path -LiteralPath $Path).Path
    } catch { return $blocks }
    if ($Seen.Contains($full)) { return $blocks }
    $Seen.Add($full)

    $current = $null
    $lines = @(Get-Content -LiteralPath $full -ErrorAction Stop)
    $lineNumber = 0
    foreach ($raw in $lines) {
        $lineNumber++
        $line = (Strip-SshComment $raw).Trim()
        if (-not $line) { continue }
        $match = [regex]::Match($line, '^(\S+)(?:\s+|=\s*)(.*)$')
        if (-not $match.Success) { continue }
        $key = $match.Groups[1].Value
        $value = $match.Groups[2].Value.Trim()

        if ($key -eq 'Host') {
            $names = @($value -split '\s+' | Where-Object { $_ })
            $current = [pscustomobject]@{
                Names      = $names
                HostName   = ''
                Port       = 22
                User       = ''
                Source     = $full
                Line       = $lineNumber
            }
            $blocks += $current
            continue
        }
        if ($key -eq 'Match') {
            # A Match block changes the meaning of every following Host line;
            # stop attributing options rather than pretending we understand it.
            $current = $null
            continue
        }
        if ($key -eq 'Include') {
            foreach ($pattern in ($value -split '\s+')) {
                foreach ($include in (Expand-SshInclude $pattern (Split-Path -Parent $full))) {
                    $blocks += Read-SshConfigFile $include ($Depth + 1) $Seen
                }
            }
            continue
        }
        if ($null -eq $current) { continue }
        switch ($key.ToLowerInvariant()) {
            'hostname' { if (-not $current.HostName) { $current.HostName = $value } }
            'port' { $port = 0; if ([int]::TryParse($value, [ref]$port)) { $current.Port = $port } }
            'user' { if (-not $current.User) { $current.User = $value } }
        }
    }
    return $blocks
}

function Read-SshHosts([string]$Path) {
    $seen = New-Object 'System.Collections.Generic.List[string]'
    $blocks = @(Read-SshConfigFile $Path 0 $seen)
    $hosts = New-Object 'System.Collections.Generic.List[object]'
    foreach ($block in $blocks) {
        if ($block.Names.Count -eq 1 -and $block.Names[0] -eq '*') { continue }
        foreach ($name in $block.Names) {
            if (-not $name) { continue }
            if ($name.Contains('*') -or $name.Contains('?')) { continue }
            if ($name.StartsWith('!')) { continue }
            $address = $block.HostName
            if (-not $address) { $address = $name }
            if ($address.StartsWith('%')) { continue }
            $hosts.Add([pscustomobject]@{
                Name    = $name
                Address = $address
                Port    = $block.Port
                User    = $block.User
                Source  = $block.Source
                Line    = $block.Line
            })
        }
    }
    return $hosts.ToArray()
}

# ---------------------------------------------------------------------------
# route inspection
# ---------------------------------------------------------------------------

function Get-RouteTable {
    return @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
}

function Get-BestRouteFor([string]$Address, $routes) {
    $number = Get-IPv4Number $Address
    if ($null -eq $number) { return $null }
    $best = $null
    foreach ($route in $routes) {
        $info = Get-PrefixInfo $route.DestinationPrefix
        if ($null -eq $info) { continue }
        if (($number -band $info.Mask) -ne ($info.Network -band $info.Mask)) { continue }
        $metric = 0
        if ($null -ne $route.RouteMetric) { $metric = [int]$route.RouteMetric }
        if ($null -eq $best) {
            $best = [pscustomobject]@{ Route = $route; Length = $info.Length; Metric = $metric }
        }
        elseif ($info.Length -gt $best.Length) {
            $best = [pscustomobject]@{ Route = $route; Length = $info.Length; Metric = $metric }
        }
        elseif ($info.Length -eq $best.Length -and $metric -lt $best.Metric) {
            $best = [pscustomobject]@{ Route = $route; Length = $info.Length; Metric = $metric }
        }
    }
    return $best
}

function Get-OwnedRoute([string]$Address, $routes) {
    foreach ($route in $routes) {
        if ($route.DestinationPrefix -ne "$Address/32") { continue }
        $nextHop = [string]$route.NextHop
        if ($nextHop -eq '0.0.0.0' -or $nextHop -eq '::' -or -not $nextHop) { return $route }
    }
    return $null
}

function Get-RouteDescription($best, $adapterNames) {
    if ($null -eq $best) { return 'no route' }
    $route = $best.Route
    $name = $adapterNames[[int]$route.InterfaceIndex]
    if (-not $name) { $name = "if$($route.InterfaceIndex)" }
    $nextHop = [string]$route.NextHop
    return "$name $($route.DestinationPrefix) -> $nextHop (metric $($best.Metric))"
}

function Get-AdapterNameMap {
    $map = @{}
    foreach ($adapter in (Get-NetAdapter -ErrorAction SilentlyContinue)) {
        $map[[int]$adapter.ifIndex] = $adapter.Name
    }
    return $map
}

# ---------------------------------------------------------------------------
# planning
# ---------------------------------------------------------------------------

function Get-Plan([string]$ConfigPath, [string]$ForcedAdapter) {
    $adapters = @(Get-PhysicalAdapters)
    $hosts = @(Read-SshHosts $ConfigPath)
    $routes = @(Get-RouteTable)
    $names = Get-AdapterNameMap
    $forced = Get-AdapterByKey $ForcedAdapter $adapters
    $entries = @()

    foreach ($sshHost in $hosts) {
        $entry = [pscustomobject]@{
            Host        = $sshHost.Name
            Address     = $sshHost.Address
            Port        = $sshHost.Port
            IsAddress   = $false
            Physical    = $null
            Prefix      = ''
            Owned       = $null
            Best        = $null
            Action      = 'skip'
            Note        = ''
        }
        if ($null -eq (Get-IPv4Number $sshHost.Address)) {
            $entry.Note = 'not an IPv4 address (hostname or IPv6); not pinned'
            $entries += $entry
            continue
        }
        $entry.IsAddress = $true

        if ($forced) {
            $entry.Physical = $forced
            $entry.Prefix = ''
        }
        else {
            $covering = @(Get-CoveringAdapters $sshHost.Address $adapters)
            if ($covering.Count -gt 0) {
                $entry.Physical = $covering[0].Adapter
                $entry.Prefix = $covering[0].Prefix
            }
        }

        $entry.Owned = Get-OwnedRoute $sshHost.Address $routes
        $entry.Best = Get-BestRouteFor $sshHost.Address $routes

        if ($null -eq $entry.Physical) {
            $entry.Action = 'skip'
            if ($null -eq $entry.Best) {
                $entry.Note = 'outside every physical subnet; no route found'
            }
            else {
                $entry.Note = "outside every physical subnet; currently via $(Get-RouteDescription $entry.Best $names)"
            }
        }
        elseif ($entry.Owned -and $entry.Owned.InterfaceIndex -eq $entry.Physical.ifIndex) {
            $entry.Action = 'pinned'
            $entry.Note = "host route on $($entry.Physical.Name)"
        }
        elseif ($null -ne $entry.Best -and $entry.Best.Route.InterfaceIndex -eq $entry.Physical.ifIndex -and $entry.Best.Length -eq 32) {
            $entry.Action = 'pinned'
            $entry.Note = "host route on $($entry.Physical.Name)"
        }
        else {
            $entry.Action = 'pin'
            if ($null -eq $entry.Best) {
                $entry.Note = "no route at all; pin to $($entry.Physical.Name)"
            }
            else {
                $entry.Note = "currently via $(Get-RouteDescription $entry.Best $names)"
            }
        }
        $entries += $entry
    }
    return [pscustomobject]@{
        Adapters = $adapters
        Hosts    = $hosts
        Routes   = $routes
        Entries  = $entries
        Names    = $names
        Forced   = $forced
        Config   = $ConfigPath
    }
}

function Format-Plan($plan) {
    $configState = if (Test-Path -LiteralPath $plan.Config) { $plan.Config } else { "$($plan.Config) (missing)" }
    Write-Host "SSH config : $configState"
    if ($plan.Adapters.Count -eq 0) {
        Write-Host 'Physical   : none (is the Wi-Fi or Ethernet adapter up?)' -ForegroundColor Yellow
    }
    else {
        $items = @()
        foreach ($adapter in $plan.Adapters) {
            $addr = @($adapter.Addresses | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" }) -join ', '
            $items += "$($adapter.Name) [if $($adapter.ifIndex)] $addr"
        }
        Write-Host "Physical   : $($items -join '; ')"
    }
    $tunnels = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and ($_.InterfaceDescription -match $script:TunnelPattern -or $_.Name -match $script:TunnelPattern)
    } | ForEach-Object { $_.Name })
    if ($tunnels.Count -gt 0) {
        Write-Host "Tunnels    : $($tunnels -join ', ')"
    }
    Write-Host ''

    $header = '{0,-16} {1,-16} {2,-5} {3,-14} {4,-8} {5}' -f 'HOST', 'ADDRESS', 'PORT', 'ADAPTER', 'STATE', 'DETAIL'
    Write-Host $header -ForegroundColor Cyan
    foreach ($entry in $plan.Entries) {
        $adapterText = '-'
        if ($entry.Physical) { $adapterText = "$($entry.Physical.Name) [$($entry.Physical.ifIndex)]" }
        $color = 'Gray'
        if ($entry.Action -eq 'pin') { $color = 'Yellow' }
        elseif ($entry.Action -eq 'pinned') { $color = 'Green' }
        $stateText = $entry.Action
        if ($entry.Action -eq 'skip') { $stateText = 'skip' }
        Write-Host ('{0,-16} {1,-16} {2,-5} {3,-14} {4,-8} {5}' -f `
            $entry.Host, $entry.Address, $entry.Port, $adapterText, $stateText, $entry.Note) -ForegroundColor $color
    }

    $pinners = @($plan.Entries | Where-Object { $_.Action -eq 'pin' })
    $pinned = @($plan.Entries | Where-Object { $_.Action -eq 'pinned' })
    $skipped = @($plan.Entries | Where-Object { $_.Action -eq 'skip' })
    Write-Host ''
    Write-Host ("Summary    : {0} pinned, {1} to pin, {2} skipped" -f $pinned.Count, $pinners.Count, $skipped.Count)
    if ($pinners.Count -gt 0) {
        if (Test-Elevated) {
            Write-Host 'Next       : run -Action apply to create the /32 host routes' -ForegroundColor Yellow
        }
        else {
            Write-Host 'Next       : open an elevated PowerShell and run -Action apply' -ForegroundColor Yellow
            Write-Host '             (Windows refuses route writes to a normal user)' -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# mutation
# ---------------------------------------------------------------------------

function Invoke-Apply($plan, [switch]$Quiet) {
    if (-not (Test-Elevated)) {
        throw 'Applying routes needs an elevated PowerShell (Run as Administrator).'
    }
    $targets = @($plan.Entries | Where-Object { $_.Action -eq 'pin' })
    if ($targets.Count -eq 0) {
        if (-not $Quiet) { Write-Host 'Nothing to pin: every LAN SSH host already has its host route.' -ForegroundColor Green }
        return 0
    }
    $changed = 0
    foreach ($entry in $targets) {
        $existing = Get-OwnedRoute $entry.Address $plan.Routes
        try {
            if ($existing -and $existing.InterfaceIndex -eq $entry.Physical.ifIndex) {
                Set-NetRoute -DestinationPrefix "$($entry.Address)/32" -InterfaceIndex $entry.Physical.ifIndex -RouteMetric 0 -ErrorAction Stop | Out-Null
                $changed++
                if (-not $Quiet) { Write-Host "  ok   $($entry.Host) $($entry.Address)/32 -> $($entry.Physical.Name) (metric refreshed)" -ForegroundColor Green }
                continue
            }
            if ($existing) {
                Remove-NetRoute -DestinationPrefix "$($entry.Address)/32" -InterfaceIndex $existing.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            }
            New-NetRoute -DestinationPrefix "$($entry.Address)/32" -InterfaceIndex $entry.Physical.ifIndex -NextHop '0.0.0.0' -RouteMetric 0 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
            $changed++
            if (-not $Quiet) { Write-Host "  ok   $($entry.Host) $($entry.Address)/32 -> $($entry.Physical.Name)" -ForegroundColor Green }
        }
        catch {
            Write-Host "  FAIL $($entry.Host) $($entry.Address): $($_.Exception.Message)" -ForegroundColor Red
            throw
        }
    }
    return $changed
}

function Invoke-Remove($plan, [switch]$Quiet) {
    if (-not (Test-Elevated)) {
        throw 'Removing routes needs an elevated PowerShell (Run as Administrator).'
    }
    $changed = 0
    foreach ($entry in $plan.Entries) {
        $owned = Get-OwnedRoute $entry.Address $plan.Routes
        if ($null -eq $owned) { continue }
        if ([string]$owned.NextHop -ne '0.0.0.0' -and [string]$owned.NextHop -ne '::') { continue }
        Remove-NetRoute -DestinationPrefix "$($entry.Address)/32" -InterfaceIndex $owned.InterfaceIndex -Confirm:$false -ErrorAction Stop | Out-Null
        $changed++
        if (-not $Quiet) { Write-Host "  removed $($entry.Host) $($entry.Address)/32 from if $($owned.InterfaceIndex)" }
    }
    if (-not $Quiet) { Write-Host "Removed $changed host route(s)." }
    return $changed
}

# ---------------------------------------------------------------------------
# scheduled task
# ---------------------------------------------------------------------------

function Get-ScheduledTaskState {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) { return $null }
    return $task
}

function Install-ScheduledTask {
    if (-not (Test-Elevated)) {
        throw 'Registering a scheduled task needs an elevated PowerShell (Run as Administrator).'
    }
    $scriptPath = (Resolve-Path -LiteralPath $PSCommandPath).Path
    $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Action watch -WatchInterval {1} -SshConfig "{2}"' -f `
            $scriptPath, $WatchInterval, $SshConfig
    )
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Registered scheduled task '$TaskName' (runs at logon, highest privileges)." -ForegroundColor Green
    Write-Host "Check it with: Get-ScheduledTask -TaskName '$TaskName' | Format-List" -ForegroundColor DarkGray
}

function Uninstall-ScheduledTask {
    if (-not (Test-Elevated)) {
        throw 'Removing a scheduled task needs an elevated PowerShell (Run as Administrator).'
    }
    $task = Get-ScheduledTaskState
    if ($null -eq $task) {
        Write-Host "Scheduled task '$TaskName' is not registered." -ForegroundColor Yellow
        return
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

function Write-PlanJson($plan) {
    $items = @($plan.Entries | ForEach-Object {
        [pscustomobject]@{
            host     = $_.Host
            address  = $_.Address
            port     = $_.Port
            action   = $_.Action
            adapter  = if ($_.Physical) { $_.Physical.Name } else { $null }
            ifIndex  = if ($_.Physical) { $_.Physical.ifIndex } else { $null }
            note     = $_.Note
        }
    })
    [pscustomobject]@{
        sshConfig  = $plan.Config
        physical   = @($plan.Adapters | ForEach-Object { [pscustomobject]@{ name = $_.Name; ifIndex = $_.ifIndex } })
        hosts      = $items
    } | ConvertTo-Json -Depth 4
}

try {
    switch ($Action) {
        'status' {
            $plan = Get-Plan $SshConfig $Adapter
            if ($AsJson) { Write-PlanJson $plan } else { Format-Plan $plan }
            exit 0
        }
        'apply' {
            $plan = Get-Plan $SshConfig $Adapter
            $changed = Invoke-Apply $plan
            Write-Host "Pinned $changed host route(s)." -ForegroundColor Green
            exit 0
        }
        'remove' {
            $plan = Get-Plan $SshConfig $Adapter
            Invoke-Remove $plan | Out-Null
            exit 0
        }
        'watch' {
            if (-not (Test-Elevated)) {
                throw 'watch needs an elevated PowerShell (Run as Administrator), because it re-applies routes.'
            }
            Write-Host "Watching every $WatchInterval s; Ctrl+C to stop. Config: $SshConfig" -ForegroundColor Cyan
            $lastState = ''
            while ($true) {
                $plan = Get-Plan $SshConfig $Adapter
                $state = ($plan.Entries | ForEach-Object { "$($_.Host)=$($_.Action)" }) -join ' '
                try {
                    $changed = Invoke-Apply $plan -Quiet
                    if ($changed -gt 0 -or $state -ne $lastState) {
                        $stamp = Get-Date -Format 'HH:mm:ss'
                        $pinners = @($plan.Entries | Where-Object { $_.Action -eq 'pin' } | ForEach-Object { $_.Host })
                        if ($changed -gt 0) {
                            Write-Host "[$stamp] repaired $changed route(s): $($pinners -join ', ')" -ForegroundColor Yellow
                        }
                        else {
                            Write-Host "[$stamp] all pinned" -ForegroundColor DarkGray
                        }
                        $lastState = $state
                    }
                }
                catch {
                    Write-Host "[$((Get-Date -Format 'HH:mm:ss'))] apply failed: $($_.Exception.Message)" -ForegroundColor Red
                }
                Start-Sleep -Seconds ([math]::Max(1, $WatchInterval))
            }
        }
        'install' {
            Install-ScheduledTask
            exit 0
        }
        'uninstall' {
            Uninstall-ScheduledTask
            exit 0
        }
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    if ($env:LANRF_DEBUG) {
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    }
    exit 1
}