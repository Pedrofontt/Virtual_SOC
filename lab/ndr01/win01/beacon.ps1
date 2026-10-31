# UC-08 beaconing (T1571): beacons to SOC01:4444 every 10s.
# Runs ~70s to exceed the Suricata threshold (count 5 / 60s).
for ($i=0; $i -lt 7; $i++) {
  Test-NetConnection -ComputerName 10.10.10.5 -Port 4444 -WarningAction SilentlyContinue | Out-Null
  Start-Sleep -Seconds 10
}
