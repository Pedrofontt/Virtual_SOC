# Session state — resume here

Last updated: 2026-10-14 (session 2, end of day). User will compact context and resume tomorrow.
Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — EXECUTION, Task 4 of 8

Planning is long done (spec + plan committed). Implementation is underway: **Tasks 1–3 complete, Task 4 blocked on the user's ISO download.**

| Task | State |
|---|---|
| 1. Repo scaffolding (lab/README, networks, evidence policy) | DONE (commit 5eca3c3) |
| 2. Host prep + SOC01 base VM (VirtualBox, ISOs, networks, Ubuntu) | DONE (c7a6282, cde697d, f732d23) |
| 3. Wazuh all-in-one install + tuning + G1 baseline | DONE (f7096dc) |
| 4. WIN01 Windows 11 Eval install + fit tweaks | BLOCKED: user must download the Win11 Eval ISO via browser (eval center form is JS-driven; headless download failed). Save to C:\iso\ |
| 5. Sysmon config + Wazuh agent enrollment + telemetry | pending |
| 6. UC-00 FIM use case + evidence | pending |
| 7. UC-01 T1003.001 rule + simulation + evidence | pending |
| 8. Milestone 1 wrap-up + final G1 | pending |

## The big lesson of today (critical context for tomorrow)

VirtualBox host-only networking failed with `VERR_INTNET_FLT_IF_NOT_FOUND` for hours. Root cause was **not** VirtualBox: the Windows Hyper-V/VBS stack (Memory Integrity ON + Hyper-V hypervisor running) blocks VirtualBox's NDIS filter. Fixed by:
1. Memory Integrity OFF (Settings → Windows Security → Core isolation)
2. `bcdedit /set hypervisorlaunchtype off` (elevated)
3. Reboot
4. Clean elevated reinstall of VirtualBox 7.2.20 (the original winget install with --disable-interactivity skipped driver registration — never install VirtualBox that way)

Do NOT re-enable Hyper-V/WSL2/Docker Desktop on this host while the lab is in use (it breaks host-only networking again). Re-enable procedure is documented in lab/runbook/soc01.md.

## Operational quick reference

- **SOC01 SSH from host** (works from this shell):
  `plink -batch -hostkey SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo -pw <PW> socadmin@10.10.30.10 "<cmd>"`
  where <PW> is in lab/runbook/.local-credentials.md (gitignored, local only)
  (plink at C:\Program Files\PuTTY\plink.exe; Windows ssh.exe too old for Ubuntu 24.04)
- sudo over plink: `echo <PW> | sudo -S <cmd>`; JSON payloads: base64 + `base64 -d | curl ... -d @-` (direct quoting breaks)
- **Credentials:** lab/runbook/.local-credentials.md (GITIGNORED — never commit; .gitignore rule `**/.local-credentials.md` added)
- **Wazuh dashboard:** https://10.10.30.10 from host browser (self-signed cert warning is normal), admin login. API: https://127.0.0.1:55000 on SOC01, indexer API :9200.
- **Networks:** host-only adapter named "VirtualBox Host-Only Ethernet Adapter **#2**" = 10.10.30.1 (host). int-corp internal = 10.10.10.0/24. SOC01: 10.10.30.10 + 10.10.10.5. WIN01 will be 10.10.10.20.
- **Snapshots:** SOC01 has `base-soc01` (post-Wazuh, no agents, NAT detached). WIN01 will get `base-phase1` after Task 5.
- **SOC01 state right now:** running headless; all 4 services active; NAT NIC detached (nic3 none). First-boot note: indexer takes ~90 s to go active.
- **Cluster health:** permanently YELLOW — single unassigned replica on .opendistro-ism-config (admin can't modify; documented). G1 gate = yellow with only that shard unassigned. G1 baseline was: heap.percent 60, free 366 MB.
- **VMs:** SOC01 disk C:\lab-vms\SOC01\soc01.vdi; VM dir C:\Users\pedro\VirtualBox VMs\SOC01. ISOs in C:\iso\ (Ubuntu 24.04.5, VirtualBox installer + ExtPack 7.2.20, putty.msi; Win11 Eval ISO goes here next).
- **Host tweaks live:** Memory Integrity OFF, hypervisorlaunchtype OFF, PuTTY installed. C:\iso\ also holds one-off fix scripts (fixdrv*.ps1, bcdchk.ps1) — leftovers, harmless.

## Next session — first steps

1. User: download Windows 11 Enterprise Evaluation ISO from https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise (browser form) → save to C:\iso\ → say "iso ready"
2. Me: create WIN01 via VBoxManage — ostype Windows11_64 (gives EFI+TPM2.0+Secure Boot), 4096 MB, 2 CPU, 40 GB VDI at C:\lab-vms\WIN01\, NIC1=int-corp, NIC2=NAT, ISO attached, then snapshot nothing yet
3. User: walk Win11 installer (Enterprise Eval; if MS account forced: Shift+F10 → `oobe\bypassnro`; else "Domain join instead" → local user `labadmin`; password goes ONLY into .local-credentials.md)
4. Me: static IP 10.10.10.20 on int-corp adapter (user does GUI Settings) — plan Task 4 Steps 5-8 (Guest Additions, Memory Integrity off via registry, effects off, Sysinternals download)
5. Then Tasks 5-8 straight through the plan (docs/superpowers/plans/2026-10-12-phase0-1-detection-core.md)

## Notes carried over

- Exercise-log.md, case docs, evidence exports happen in Tasks 6-8 (files don't exist yet).
- User prefers I drive everything scriptable; GUI steps (Windows installer, some Settings screens) are theirs.
- ADHD output mode is ON for this project (user enabled it explicitly).
- User's originals docs/DFD.PNG + docs/initial_info.md remain untracked on purpose.
