# Virtual SOC Lab — Project Memory

## What this is
A free, isolated, reproducible virtual SOC lab on a personal Windows PC (Ryzen 5 4600G, 16 GB RAM, 241 GB free SSD). Goal: real, reproducible alerts + documented detection pipeline for a cybersecurity portfolio. Success = alerts, not installed software.

## Hard constraints (never violate)
- Hypervisor: VirtualBox 7.2.20 (installed; 7.1.x spec updated to 7.2.x in practice). No bridged adapters, no inbound port forwards, lab never touches the home LAN.
- **Host hypervisor stack MUST stay OFF** (verified blocker): Memory Integrity OFF + `bcdedit hypervisorlaunchtype Off`. If someone re-enables Hyper-V/WSL2, host-only networking dies with VERR_INTNET_FLT_IF_NOT_FOUND. Re-enable procedure is in lab/runbook/soc01.md.
- Host-only adapter is named "VirtualBox Host-Only Ethernet Adapter #2" (rename happened during driver repair) at 10.10.30.1/24. SOC01 NIC1 attaches to "#2".
- Secrets NEVER in git: lab/runbook/.local-credentials.md is gitignored and holds all lab passwords.
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

## Operational facts (learned during execution)
- SOC01 remote access from host: `plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10 "<cmd>"` where <PW> comes ONLY from lab/runbook/.local-credentials.md (PuTTY at C:\Program Files\PuTTY\plink.exe; Windows ssh.exe is too old for Ubuntu 24.04 KEX). sudo needs `echo <PW> | sudo -S`. JSON via plink: base64-encode and pipe `echo <b64> | base64 -d | curl ... -d @-` (quoting dies otherwise).
- SOC01: Ubuntu 24.04.5 minimal, 3 vCPU/5 GB/48 GB root (LV was 24 GB - extended), Wazuh 4.14.8 all-in-one. Indexer heap 1g/1g. Snapshot `base-soc01` exists. VM files at C:\lab-vms\SOC01\soc01.vdi, VM registered under C:\Users\pedro\VirtualBox VMs\SOC01.
- Cluster health shows YELLOW permanently: .opendistro-ism-config keeps a replica shard, admin can't modify it (security_exception; no ISM settings endpoint in 4.14). Accepted and documented; G1 interprets healthy = yellow with only that shard unassigned.
- Wazuh install pitfalls (fixed): Ubuntu LVM default = half disk (lvextend +100%FREE + resize2fs); failed install rollbacks leave stale dirs (/var/lib|etc|log/wazuh-indexer, /etc/filebeat, /usr/share/filebeat/module) that must be purged before retry.
- First boot after power-on: wazuh-indexer takes ~90 s to become active; run G1 checks only after it's active.
- User frequently misses UAC prompts launched from this shell - always tell them to watch the taskbar/click Yes before launching elevated commands.

## Workflow
- Superpowers skills in use: brainstorming (done), writing-plans (done), executing-plans (in progress, Task 4/8). GUI-only steps (Windows installer) require the user at the keyboard. ADHD output mode is ON for this project.
- Plan per phase only: do NOT write phase 2–4 implementation plans until Milestone 1 passes. Divergences during implementation go to `lab/cases/exercise-log.md` + spec amendments.
- Commit after each task with a conventional one-line message. Only commit the design doc + plan + lab files; never secrets.
