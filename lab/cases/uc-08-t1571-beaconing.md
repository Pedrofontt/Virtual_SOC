# UC-08 — T1571 Non-Standard Port (beaconing)

Status: PASS

## Hypothesis
Repeated periodic SYNs to a non-standard port (4444) from WIN01 are detectable as beaconing
at the passive NDR sensor.

## Detection logic
- Source: Suricata `eve.json` → Wazuh agent 003 → rule 100042.
- Suricata `7000003`: `alert tcp any any -> any 4444 (msg:"LAB NDR - beaconing non-standard port";
  flags:S; threshold:type threshold, track by_src, count 5, seconds 60; ...)`
- Wazuh `100042` (level 12, T1571): child of 86601 on `alert.signature_id ^7000003$`.

## Trigger
From WIN01:
```powershell
powershell -ExecutionPolicy Bypass -File C:\lab\beacon.ps1   # periodic SYNs to SOC01:4444
```

## Expected vs observed
Expected: `100042` (level 12) after 5 SYNs to 4444 within 60 s.
Observed: `100042` fired (agent 003, src WIN01 → SOC01:4444).

## Benign control / False positives
- Benign: a single non-blocking `BeginConnect` socket to 4444 then `Close()` after ~300 ms
  → exactly 1 SYN (`alerted:false`).
- **DEVIATION:** the plan's `Test-NetConnection -Port 4444` to a *closed* port retransmits
  SYN ~5× (`pkts_toserver:5`), which trips the count-5/60s threshold on the benign control.
  Replaced with the single-SYN socket approach (see lessons-learned).

## Cleanup
None (transient traffic only).
