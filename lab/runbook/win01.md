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
- `ossec.conf` additions applied: Sysmon eventchannel localfile + syscheck on `C:\lab\critical` (check_all, realtime off).
- Telemetry verified: Sysmon EID 1/5/10 events reach SOC01 archives; detections fire as Wazuh 4.14 rules 92000+ (92021, 92031, 92066 observed). NOTE: Wazuh 4.14 no longer uses the plan's "Sysmon - Event 1" / rule 61601 naming — that check is obsolete.
- FIM config corrected in Task 6: syscheck `<directories>` merged into the DEFAULT `<syscheck>` block (a second block is silently ignored on Windows) and switched to `realtime="yes"` (per-directory frequency unsupported on Windows — warning 6701). FIM verified end-to-end: rules 554/550/553 fire for add/modify/delete (see `lab/cases/uc-00-fim.md`).

## Lab controls log

| Date | Control | Reason | Restored? |
|---|---|---|---|
|  | Defender real-time protection disabled for UC-01 window | MiniDump would be killed before Sysmon records it | fill in during Task 7 |
