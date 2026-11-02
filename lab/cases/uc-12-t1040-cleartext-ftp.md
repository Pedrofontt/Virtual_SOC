# UC-12 — T1040 Network Sniffing (cleartext FTP credentials)

Status: PASS

## Hypothesis
Cleartext FTP credentials (USER/PASS) transmitted over the wire are detectable at the
passive NDR sensor.

## Detection logic
- Source: Suricata `eve.json` → Wazuh agent 003 → rule 100046.
- Suricata `7000007`: `alert ftp any any -> any any (msg:"LAB NDR - cleartext FTP creds";
  flow:established,to_server; content:"USER "; nocase; content:"PASS "; nocase; ...)`
- Wazuh `100046` (level 10, T1040): child of 86601 on `alert.signature_id ^7000007$`.

## Trigger
FTP server on SOC01 (`mini_ftpd.py`, a minimal RFC-959 server replacing pyftpdlib 2.2.0,
which is incompatible with Python 3.12's removed `asynchat`/`asyncore`):
```bash
sudo python3 /usr/local/bin/mini_ftpd.py   # binds 0.0.0.0:21
```
From WIN01:
```powershell
$cmds = @"
open 10.10.10.5
ftpuser
Ftppass123
quit
"@
$cmds | Out-File -Encoding ascii C:\lab\ftp.txt
ftp -s:C:\lab\ftp.txt
```

## Expected vs observed
Expected: `100046` (level 10), src WIN01 → SOC01:21.
Observed: `100046` fired — src `10.10.10.20` → dst `10.10.10.5:21`,
`signature_id 7000007`, timestamp `2026-11-02T01:54:03Z`. Suricata stats confirmed
`ftp_flow: 1, ftp_tx: 5` (app-layer parse succeeded).

## Benign control / False positives
- Benign: no FTP session (background traffic) → silent by construction (rule only matches
  cleartext `USER ` + `PASS ` on the FTP channel).

## Cleanup
Stop `mini_ftpd.py` after the test (Task 14 close-out).
