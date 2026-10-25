# UC-03 — T1110 Brute Force: domain logon burst

Status: PASS

## Hypothesis
A password-guessing attack against a domain account (3 failed SMB logons then a success, from a
domain-joined endpoint) is detectable from Samba JSON auth audit telemetry with three custom rules:
failed logon, burst correlation, and successful logon.

## Detection logic
- Source: DC01 `/var/log/samba/audit.json` (localfile `log_format=json`, decoder `json`), agent `002`.
  Fields preserved verbatim: `Authentication.status`, `.clientAccount`, `.clientDomain`,
  `.remoteAddress`, `.mappedAccount`, `.serviceDescription`, etc.
- Rules in `lab/soc01/local_rules.xml`:
  - `100029` (level 8, T1110): `Authentication.status` == `NT_STATUS_WRONG_PASSWORD`.
  - `100030` (level 12, T1110): burst — `if_matched_sid 100029`, `frequency 3 / timeframe 60`,
    `same_field Authentication.mappedAccount`.
  - `100031` (level 3): `Authentication.status` == `NT_STATUS_OK`.

## Trigger
From WIN01 (`10.10.10.20`), three wrong-password `net use` attempts then one correct logon:
```powershell
net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass   # x3
net use \\10.10.10.10\IPC$ /user:CORP\attacker 'Attacker!lab123'
net use * /delete /y
```
(Post-join caveat: see "Troubleshooting" — Windows negative-caches the failed credential per server
name, so the three attempts must target the DC under three different names.)

## Expected vs observed
Expected: 100029 per failed logon, 100030 on the 3rd failure within 60s, 100031 on the success.
Observed (2026-10-24):
- 100029 fired for `attacker@CORP` from `ipv4:10.10.10.20:*`.
- 100030 fired at `2026-10-24T23:19:25.133+0000` — "3+ failed logons in 60s for attacker", level 12.
- 100031 fired for the correct-password logon (`attacker@CORP`).
- Bonus: post-join, the computer account `DESKTOP-I4QI720$` authenticates via NETLOGON +
  Kerberos `ENC-TS Pre-authentication` (rule 100031) — endpoint identity confirmed as a domain member.

## Benign control
A single failed logon (or a success without 3 failures) does not fire 100030. `samba-tool user show`
(read-only) produced no auth alerts.

## False positives / tuning
- `same_field` cannot use `Authentication.remoteAddress` (it is `ipv4:IP:<srcport>` and the port
  changes per connection) nor `Authentication.clientAccount` (Kerberos decodes it as
  `attacker@CORP`, NTLM as `attacker`). Use the normalized `Authentication.mappedAccount`.
- A legitimate account lockout (many wrong passwords) would also fire — acceptable signal.

## Cleanup
Intentionally **not** cleaned up — the lab is left attack-ready for study. `attacker` remains in
"Domain Admins" (the UC-03b privileged-group-change state) so the simulation can be re-run.

## Troubleshooting notes
- Windows negative-caches a failed credential per server name, so repeated identical `net use`
  sends only one auth attempt. Fix: target the DC under `\\dc01`, `\\dc01.corp.lab`, `\\10.10.10.10`
  (three distinct SMB sessions).
- Post-join, `\\dc01`/`\\dc01.corp.lab` auth via Kerberos KDC, `\\10.10.10.10` via SMB2/NTLM —
  this is what forces the `mappedAccount` correlation field.
