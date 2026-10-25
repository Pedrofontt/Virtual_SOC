# UC-04 — T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting

Status: PASS

## Hypothesis
Requesting a service ticket for a service account with a registered SPN (`MSSQLSvc`) — Kerberoasting —
is detectable from Samba KDC authorization audit telemetry by matching the requested service name.

## Detection logic
- Source: DC01 `/var/log/samba/audit.json` (json decoder), KDC Authorization events. Field
  `KDC Authorization.serviceDescription` carries the requested SPN
  (e.g. `MSSQLSvc/dc01.corp.lab:1433@CORP.LAB`).
- Rule `100033` (level 12, T1558.003): `field name="KDC Authorization.serviceDescription"` pcre2 `MSSQLSvc`.

## Trigger
From SOC01 (impacket 0.13.1, patched for Samba 4.19):
```bash
GetUserSPNs.py CORP/attacker:'Attacker!lab123' -dc-ip 10.10.10.10 -request
```
Lab controls: SOC01 clock synced with DC01 (clock skew otherwise aborts the TGS request with
`KRB_AP_ERR_SKEW`); impacket kerberosv5 checksum patch applied; `svc-sql` given a weak SPN password.

## Expected vs observed
Expected: one 100033 alert naming the MSSQLSvc SPN.
Observed: `100033` fired at `2026-10-24T04:01:52.284+0000` — "Kerberoasting - TGS-REQ for
MSSQLSvc/dc01.corp.lab:1433@CORP.LAB by attacker", level 12, agent `dc01`.

## Benign control
Normal TGS-REQ for non-MSSQLSvc SPNs (host, cifs, etc.) do not match 100033.

## False positives / tuning
- Broad SPN match (`MSSQLSvc`) would also flag a legitimate client requesting the SQL service
  ticket. For the isolated lab this is acceptable; production tuning would add `by <account>`
  constraints or a frequency rule.

## Cleanup
Intentionally **not** cleaned up — lab kept attack-ready for study. `svc-sql`/weak SPN and
`attacker` credentials remain as the documented lab config.

## Troubleshooting notes
- Kerberoasting required impacket's AP-REQ authenticator checksum patch (Samba 4.19 KU 6 RC4
  cksumtype -138) — see `soc01.md`.
- SOC01/DC01 clock skew must be zeroed before `-request` (else `KRB_AP_ERR_SKEW`).
