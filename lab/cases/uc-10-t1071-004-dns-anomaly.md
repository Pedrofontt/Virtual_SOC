# UC-10 — T1071.004 Application Layer Protocol: DNS (anomalous query)

Status: PASS

## Hypothesis
Abnormally long DNS query names from WIN01 are detectable at the passive NDR sensor on
query length alone (no DNS server response required).

## Detection logic
- Source: Suricata `eve.json` → Wazuh agent 003 → rule 100044.
- Suricata `7000005`: `alert dns any any -> any 53 (msg:"LAB NDR - DNS anomaly"; dns.query;
  pcre:"/^.{40,}$/"; ...)` (DNS query name ≥ 40 chars).
- Wazuh `100044` (level 12, T1071.004): child of 86601 on `alert.signature_id ^7000005$`.

## Trigger
From WIN01:
```powershell
powershell -ExecutionPolicy Bypass -File C:\lab\dns-exfil.ps1   # long random-label queries -> SOC01:53
```
The queries are sent to `10.10.10.5:53`; they time out (no DNS server) but the query packet
hits the wire and is parsed by Suricata's DNS app-layer parser.

## Expected vs observed
Expected: `100044` (level 12), src WIN01 → SOC01, proto UDP.
Observed: `100044` fired — src `10.10.10.20` → dst `10.10.10.5`, `UDP`,
`signature_id 7000005`, timestamp `2026-11-01T05:09:59Z`.

## Benign control / False positives
- Benign: `nslookup corp.lab 10.10.10.5` (short name) → silent.
- FP risk: CDN/certificate-transparency lookups can legitimately exceed 40 chars — in this
  isolated lab (DC01 off, no real DNS traffic) there is no such noise.

## Cleanup
None (transient traffic only).
