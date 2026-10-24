# WIN01 runbook

Build: Windows 11 Enterprise Evaluation, 2 vCPU, 4 GB RAM, 64 GB VDI, EFI + TPM 2.0 + Secure Boot.
NIC: int-corp 10.10.10.20 (static) + NAT (temporary — detach in Task 5).

Local credentials: in `lab/runbook/.local-credentials.md` (gitignored) — user `labadmin`.

Fit tweaks applied:
- Memory Integrity off (registry: `HypervisorEnforcedCodeIntegrity` Enabled = 0)
- Transparency effects off
- Animation effects off

Tools: Sysinternals (Sysmon) extracted to `C:\lab\tools`.

## Detection stack (Task 5)

- Sysmon 15.22 installed with `lab/win01/sysmon-config.xml` (schema 4.90): EID 1 (all process create) + EID 10 (lsass access only).
- Wazuh agent 4.14.8 (MSI, `WAZUH_MANAGER=10.10.10.5`, name `win01`); service name is `WazuhSvc` (not `Wazuh`). Enrolled as agent 001, status active.
- `ossec.conf` additions applied: Sysmon eventchannel localfile + syscheck on `C:\lab\critical` (check_all, realtime yes).
- Telemetry verified: Sysmon EID 1/5/10 events reach SOC01 archives; detections fire as Wazuh 4.14 rules 92000+ (92021, 92031, 92066 observed). NOTE: Wazuh 4.14 no longer uses the plan's "Sysmon - Event 1" / rule 61601 naming — that check is obsolete.
- FIM config corrected in Task 6: syscheck `<directories>` merged into the DEFAULT `<syscheck>` block (a second block is silently ignored on Windows) and switched to `realtime="yes"` (per-directory frequency unsupported on Windows — warning 6701). FIM verified end-to-end: rules 554/550/553 fire for add/modify/delete (see `lab/cases/uc-00-fim.md`).

## Domain join (Task 9)

- Joined `corp.lab` as `DESKTOP-I4QI720`. Procedure:
  ```powershell
  netsh interface ip set dns name="Ethernet" static 10.10.10.10
  nslookup dc01.corp.lab                      # -> 10.10.10.10
  Add-Computer -DomainName corp.lab -Credential CORP\Administrator -Restart
  ```
  (`CORP\Administrator` password: `DomAdmin!lab123`.) Rebooted; logon screen shows `CORP`.
- Verified on the SIEM: computer account `DESKTOP-I4QI720$` emits NETLOGON `ServerAuthenticate` +
  Kerberos `ENC-TS Pre-authentication` from 10.10.10.20 (rule 100031).
- Snapshots: `pre-domain-join`, `win01-joined`.

### Re-running the UC-03 logon burst post-join (gotcha)

Post-join, repeated `net use \\10.10.10.10\IPC$ /user:CORP\attacker wrongpass` sends only ONE auth
attempt: Windows negative-caches the failed credential per server name (attempts 2+ return a cached
"System error 1326" without re-authenticating). Force 3 fresh 4625s by targeting the DC under three
different names:
```powershell
net use \\dc01\IPC$          /user:CORP\attacker wrongpass   # Kerberos -> 4625
net use \\dc01.corp.lab\IPC$ /user:CORP\attacker wrongpass   # Kerberos -> 4625
net use \\10.10.10.10\IPC$   /user:CORP\attacker wrongpass   # NTLM     -> 4625
net use \\10.10.10.10\IPC$   /user:CORP\attacker 'Attacker!lab123'
net use * /delete /y
```
Each name = a separate SMB session (`\\dc01`/`\\dc01.corp.lab` go Kerberos, `\\10.10.10.10` goes NTLM).

## Lab controls log

| Date | Control | Reason | Restored? |
|---|---|---|---|
| 2026-10-16 | Defender real-time protection disabled for UC-01 window (GUI toggle — Set-MpPreference is AMSI-blocked) | MiniDump would be killed before Sysmon records it | yes (pre-uc01 snapshot revert) |
| 2026-10-16 | Tamper Protection: already OFF on this image, no action needed | — | n/a |
| 2026-10-16 | LSA Protection disabled: `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f` + reboot | Win11 24H2+ ships RunAsPPL=2; comsvcs MiniDump fails silently with it on | yes (pre-uc01 snapshot revert) |
| 2026-10-18 | UC-02: no defense controls changed (benign base64 payload `Write-Output hello` only; detection source = Sysmon EID 1) | — | n/a |
| 2026-10-24 | WIN01 DNS pointed at DC01 (10.10.10.10) + joined `corp.lab` | Task 9 UC-03 re-verify from a domain member | n/a (permanent lab change) |
