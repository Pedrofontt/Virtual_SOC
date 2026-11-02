# UC-11 — T1110 Brute Force (SMB)

Status: PASS (with lab controls)

## Hypothesis
A burst of failed SMB logon attempts against WIN01 is detectable at the passive NDR sensor
by counting SYN connections to port 445.

## Detection logic
- Source: Suricata `eve.json` → Wazuh agent 003 → rule 100045.
- Suricata `7000006`: `alert tcp any any -> any 445 (msg:"LAB NDR - SMB brute force"; flags:S;
  threshold:type threshold, track by_src, count 10, seconds 30; ...)`
- Wazuh `100045` (level 12, T1110): child of 86601 on `alert.signature_id ^7000006$`.
- Note: attack source is SOC01 (impacket), target WIN01:445 (not the reverse).

## Trigger
From SOC01 (impacket, single process, 12 concurrent logon attempts):
```python
from impacket.smbconnection import SMBConnection
import threading
def attempt():
    try:
        c = SMBConnection('10.10.10.20', '10.10.10.20', timeout=10)
        c.login('nosuchuser', 'wrongpass'); c.close()
    except Exception:
        pass
[threading.Thread(target=attempt).start() for _ in range(12)]
```

## Expected vs observed
Expected: `100045` (level 12) once 10 SYNs to 445 within 30 s, src SOC01.
Observed: `100045` fired — src `10.10.10.5` → dst `10.10.10.20:445`,
`signature_id 7000006`, timestamp `2026-11-02T01:42:38Z`.

## Benign control / False positives
- Benign: single successful logon (`labadmin`/`labadmin123` → `LOGIN SUCCESS`) → 1 SYN,
  below threshold → silent (latest `100045` timestamp unchanged).
- FP risk: legitimate bursts of >10 SMB connections in 30 s would trip it; none in the
  isolated lab.

## Lab controls (all logged)
1. **Opened 445** — WIN01 firewalls SMB inbound by default (filtered, `connect_ex=11`).
   Opened with `Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True`.
2. **Non-existent user** (`nosuchuser`) — used to avoid re-locking a real account (see #3).
3. **Concurrent connections** — Windows' SMB auth rate-limiter (~2 s per failed logon) makes
   sequential attempts too slow to reach 10 SYNs/30 s, so 12 attempts were fired concurrently.
4. **Recovered a labadmin lockout** — the first (sequential) run locked `labadmin` via 9
   `STATUS_LOGON_FAILURE` + lockout. Recovered by restoring WIN01 to the `pre-uc06` snapshot
   (then re-opening 445). This is realistic T1110 impact and is documented here deliberately.

## Cleanup
445 left open (documented lab change). No real accounts remain locked.
