# Virtual SOC Lab — Project Memory

## What this is
A free, isolated, reproducible virtual SOC lab on a personal Windows PC (Ryzen 5 4600G, 16 GB RAM, 241 GB free SSD). Goal: real, reproducible alerts + documented detection pipeline for a cybersecurity portfolio. Success = alerts, not installed software.

## Hard constraints (never violate)
- Hypervisor: VirtualBox 7.1.x (Windows host). No bridged adapters, no inbound port forwards, lab never touches the home LAN.
- Running guests must never exceed 11 GB RAM total; host keeps 5 GB. Milestone power-on = S1 only: SOC01 (3 vCPU/5 GB/50 GB) + WIN01 (2 vCPU/4 GB/40 GB).
- Wazuh pinned to 4.14.x stable on Ubuntu 24.04 LTS (5.0 is RC — not used). Indexer heap Xms1g/Xmx1g. Indices 7d; archives 30d/5 GB.
- WIN01 = Windows 11 Enterprise Evaluation (Win10 Eval ISOs are decommissioned). Guest type "Windows 11" for EFI/TPM 2.0/Secure Boot.
- No real malware. No secrets in git (Wazuh admin password lives only in SOC01 + local runbook placeholders). Dumps (*.dmp) and pcaps never committed.
- NAT adapters are provisioning-only; detached after each guest's pre-isolation checklist.

## Locked decisions (from the design spec)
- Networks: `vboxnet0` host-only 10.10.30.0/24 (LAB-MGMT: host .1, SOC01 .10, SOAR01 .20 later); `int-corp` internal 10.10.10.0/24 (LAB-CORP: SOC01 .5, DC01 .10, WIN01 .20, NDR01 .40). Static IPs, no DHCP.
- SOAR = n8n (single container, SQLite, 2 GB VM) — Shuffle rejected: 3–4 GB idle breaks the ceiling.
- NDR = Suricata on NDR01 (1 GB). Passive promiscuous first; on gate G2 failure, inline bridge model (AF_PACKET on br0). Plain "router between zones" rejected: on-link traffic bypasses it.
- Milestone 1 use cases: UC-00 FIM warm-up (rule 550) then UC-01 T1003.001 LSASS access via Sysmon EID 10 (custom rule 100010, level 12, parent 61610 — verify parent id during implementation).
- Power-on sets S1–S4 in spec §6; S5 (Shuffle/mail/Velociraptor) not supported on 16 GB.

## Key files
- Design spec: `docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md`
- Implementation plan: `docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md` (8 tasks; Task 1 = repo scaffolding, Task 8 = milestone wrap-up)
- Session state: `docs/superpowers/session.md` — always update before ending a session
- User brief (Spanish): `docs/initial_info.md`; DFD: `docs/DFD.PNG` (model cannot read images — ask user for Mermaid/text if needed)

## Workflow
- Superpowers skills in use: brainstorming (done), writing-plans (done), next: executing-plans or subagent-driven-development. GUI-only steps (VirtualBox wizard, Windows installer) require the user at the keyboard.
- Plan per phase only: do NOT write phase 2–4 implementation plans until Milestone 1 passes. Divergences during implementation go to `lab/cases/exercise-log.md` + spec amendments.
- Commit after each task with a conventional one-line message. Only commit the design doc + plan + lab files; never secrets.
