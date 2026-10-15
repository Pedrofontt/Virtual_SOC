# Session state — resume here

Last updated: 2026-10-14 (session 3, end of day). User will compact context and resume tomorrow.
Resume by reading this file, then continue with "Next session — first steps" below.

## Where we are — Task 4 of 8, Windows install ~90% done

Tasks 1–3 complete. Task 4 (WIN01) is mid-install: the Windows 11 Enterprise Eval VM is created, configured,
and Windows is installing. The user got past the account screen (local account `labadmin`) and privacy screen;
it was installing updates when they logged off. Next session: confirm desktop, finish Task 4 fit-tweaks.

| Task | State |
|---|---|
| 1. Repo scaffolding | DONE |
| 2. Host prep + SOC01 base VM | DONE |
| 3. Wazuh all-in-one install + tuning + G1 baseline | DONE |
| 4. WIN01 Windows 11 Eval install + fit tweaks | IN PROGRESS (install nearly done) |
| 5. Sysmon + Wazuh agent enrollment + telemetry | pending |
| 6. UC-00 FIM use case + evidence | pending |
| 7. UC-01 T1003.001 rule + simulation + evidence | pending |
| 8. Milestone 1 wrap-up + final G1 | pending |

## The big lesson of today — WIN01 boot + Secure Boot

WIN01 would not boot the ISO ("The VM failed to boot") for a long time. Root cause chain (all fixed):

1. `--secureboot` is NOT a VBoxManage flag in 7.2. My first `modifyvm` aborted entirely on it.
2. Secure Boot is `modifynvram <vm> secureboot --enable`, which REQUIRES a PK enrolled first.
3. I wrongly used `inituefivarstore` → wiped boot entries → "missing OS".
4. Deleting the `.nvram` file fixed boot entries (firmware then found and loaded `cdboot.efi`),
   but left `SecureBootEnable=1` with NO PK/KEK/db → `cdboot.efi` loaded/unloaded 4× then "Boot failure"
   (bootmgr.efi rejected).

**The correct WIN01 Secure Boot sequence (documented in lab/runbook/setup.md):**
```
VBoxManage modifynvram WIN01 enrollorclpk
VBoxManage modifynvram WIN01 enrollmssignatures
VBoxManage modifynvram WIN01 secureboot --enable
```
Never use `inituefivarstore`. DVD must be on the IDE controller. Disk must be 64 GB (Win11 min), not 40 GB.

Win11 Eval local account (no MS account): on "Let's set things up for your work or school" →
"Sign-in options" → "Domain join instead" → local user. (`oobe\bypassnro` was flaky.)

## Current lab state

- **SOC01**: SUSPENDED (savestate) — I suspended it to free 5 GB so WIN01 could boot. Not running.
  `VBoxManage startvm SOC01` resumes it (indexer ~90 s to go active after resume). Snapshot `base-soc01` exists.
  Wazuh admin password + ssh password in `lab/runbook/.local-credentials.md` (gitignored).
- **WIN01**: Windows 11 Eval installing. Config: 4 GB / 2 vCPU / 64 GB VDI, EFI + Secure Boot + TPM 2.0,
  chipset ICH9, NIC1 = int-corp, NIC2 = NAT, DVD (Win11 ISO) on IDE still attached. Local account `labadmin`
  (password NOT yet recorded — get it from user, store in .local-credentials.md).
  VM disk `C:\lab-vms\WIN01\win01.vdi`, registered at `C:\Users\pedro\VirtualBox VMs\WIN01`.
- **RAM budget**: 16 GB host. SOC01 (5 GB) + WIN01 (4 GB) = 9 GB when both run. Free RAM is tight
  (~3.8 GB free with Brave + SOC01 running) — suspend SOC01 whenever WIN01 work needs the headroom.

## New files / commits this session

- `lab/runbook/setup.md` — NEW rebuild-from-scratch reference (host prereqs + SOC01 + WIN01), committed `73bdaf8`.
- `AGENTS.md` — added "Lab setup recording" rule: after ANY build/install/tuning change, append commands to
  setup.md automatically. (AGENTS.md is local-only/gitignored; setup.md is tracked.)
- `.local-credentials.md` — still gitignored; WIN01 `labadmin` password needs to be added.

## Next session — first steps

1. Ask user: is WIN01 at the desktop? If not, finish the Windows install (it was on the update/finalize step).
2. Get the `labadmin` password from the user → store in `lab/runbook/.local-credentials.md`.
3. Finish Task 4 fit-tweaks (per plan Task 4 steps): set static IP 10.10.10.20 on the int-corp NIC,
   install Guest Additions, note/adjust any Memory Integrity or fit settings in-guest.
4. Append the exact WIN01 completion commands to `lab/runbook/setup.md` (auto-record rule).
5. Resume SOC01 (`VBoxManage startvm SOC01`), then start Task 5 (Sysmon + Wazuh agent enrollment).

## Notes carried over

- Remote control: plink from host to SOC01 (`plink -batch -hostkey SHA256:... -pw <PW> socadmin@10.10.30.10`),
  `<PW>` from .local-credentials.md. sudo = `echo <PW> | sudo -S`.
- User is at the keyboard for GUI steps; I drive everything scriptable.
- ADHD output mode is ON for this project.
- user's originals `docs/DFD.PNG` + `docs/initial_info.md` remain untracked on purpose.
