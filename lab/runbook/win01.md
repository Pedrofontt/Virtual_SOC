# WIN01 runbook

Build: Windows 11 Enterprise Evaluation, 2 vCPU, 4 GB RAM, 64 GB VDI, EFI + TPM 2.0 + Secure Boot.
NIC: int-corp 10.10.10.20 (static) + NAT (temporary — detach in Task 5).

Local credentials: in `lab/runbook/.local-credentials.md` (gitignored) — user `labadmin`.

Fit tweaks applied:
- Memory Integrity off (registry: `HypervisorEnforcedCodeIntegrity` Enabled = 0)
- Transparency effects off
- Animation effects off

Tools: Sysinternals (Sysmon) extracted to `C:\lab\tools`.

## Lab controls log

| Date | Control | Reason | Restored? |
|---|---|---|---|
|  | Defender real-time protection disabled for UC-01 window | MiniDump would be killed before Sysmon records it | fill in during Task 7 |
