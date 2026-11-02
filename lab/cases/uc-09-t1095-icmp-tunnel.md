# UC-09 — T1095 Non-Application Layer Protocol (ICMP tunneling)

Status: PASS

## Hypothesis
Oversized ICMP echo payloads from WIN01 are detectable as ICMP tunneling at the passive
NDR sensor.

## Detection logic
- Source: Suricata `eve.json` → Wazuh agent 003 → rule 100043.
- Suricata `7000004`: `alert icmp any any -> any any (msg:"LAB NDR - ICMP tunneling"; itype:8;
  dsize:>1000; ...)` (ICMP echo request with payload > 1000 bytes).
- Wazuh `100043` (level 12, T1095): child of 86601 on `alert.signature_id ^7000004$`.

## Trigger
From WIN01:
```powershell
ping -n 3 -l 1200 10.10.10.5   # 3 ICMP echoes, 1200-byte payload
```

## Expected vs observed
Expected: `100043` (level 12), src WIN01 → SOC01, proto ICMP.
Observed: `100043` fired — src `10.10.10.20` → dst `10.10.10.5`, `ICMP`,
`signature_id 7000004`, timestamp `2026-11-01T05:01:55Z`.

## Benign control / False positives
- Benign: `ping -n 3 10.10.10.5` (default 32-byte payload) → silent.
- FP risk: `dsize` triggers on payload size only; normal ping stays well under 1000 bytes.
  Keep `ping -l` under the MTU to avoid fragmentation confusing the size check.

## Cleanup
None (transient traffic only).
