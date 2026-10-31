# UC-07 port scan (T1046): rapid TCP connect-scan of SOC01.
# Fires 60 SYNs near-simultaneously to exceed the Suricata threshold
# (flags:S, count 20 / 5s). Replaces nmap (installer needs UAC elevation).
$target = "10.10.10.5"
$ports = 1..60
$sockets = @()
foreach ($p in $ports) {
    $s = New-Object System.Net.Sockets.Socket(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Tcp)
    $s.Blocking = $false
    [void]$s.BeginConnect($target, $p, $null, $s)
    $sockets += $s
}
Start-Sleep -Milliseconds 1500
foreach ($s in $sockets) { try { $s.Close() } catch {} }
Write-Output "Scan complete: $($sockets.Count) SYN attempts sent to ${target}"
