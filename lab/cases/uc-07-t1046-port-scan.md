# UC-07 — T1046 Network Service Scanning (TCP port scan)

Status: PASS

## Hypothesis
A rapid burst of TCP SYN probes from WIN01 against SOC01 is detectable by counting SYN
packets at the passive NDR sensor, without host-based detection.

## Detection logic
- Source: Suricata `eve.json` → Wazuh agent 003 → rule 100041.
- Suricata `7000002`: `alert tcp any any -> any any (msg:"LAB NDR - TCP port scan"; flags:S;
  threshold:type threshold, track by_src, count 20, seconds 5; ...)`
- Wazuh `100041` (level 10, T1046): child of 86601 on `alert.signature_id ^7000002$`.

## Trigger
From WIN01:
```powershell
powershell -ExecutionPolicy Bypass -File C:\lab\port-scan.ps1   # 60 SYNs across SOC01 ports
```

## Expected vs observed
Expected: `100041` (level 10) once 20+ SYNs are seen from WIN01 within 5 s.
Observed: `100041` fired (agent 003, src WIN01 → SOC01).

## Benign control / False positives
- Benign: single `Test-NetConnection` to an open port (1514) → silent (1 SYN, below threshold).
- FP risk: NAT provisioning bursts of many SYNs in a short window could trip the 20/5s
  threshold — the lab is fully isolated at test time, so no FP observed.

## Cleanup
None (transient traffic only).
