# WIN01 — the Windows endpoint, explained step by step

> Companion to the terse `win01.md` runbook and the command-only `setup.md` §2.
> This doc teaches the *what* and *why* behind each step, so you can read it like a lesson.

## 1. What this box is

**WIN01 is the lab's Windows workstation** — the "victim/attacker endpoint" where most of the
simulated attacks happen. It runs Windows 11 Enterprise (evaluation).

Think of it as an ordinary employee laptop on the corporate network:

- It's **domain-joined** to `corp.lab` (its computer account is `DESKTOP-I4QI720`).
- Real users (and the lab's simulated attacker) log into it and run commands.
- It ships its **Sysmon** (system monitoring) events up to SOC01 for detection.

It exists so we can simulate Windows-native attacks (LSASS dumping, PowerShell obfuscation, network
logons) and watch SOC01 catch them.

| Box | Role |
|---|---|
| **WIN01** (`10.10.10.20`) | Windows 11 endpoint — runs the attack simulations, sends Sysmon logs |
| **DC01** (`10.10.10.10`) | Domain controller — WIN01 joined its domain |
| **SOC01** (`10.10.10.5`) | SIEM — collects WIN01's Sysmon events and raises alerts |

## 2. The big idea: why Windows needs extra logging

Windows has its own event log, but it's **not granular enough** for real detection. That's why we
add **Sysmon** (Sysinternals System Monitor) — a Microsoft-provided driver + service that logs
*very* detailed process/network/file activity:

- **EID 1** — every process creation (who ran what, with what command line).
- **EID 10** — process access (who opened a handle to `lsass.exe`, the classic credential-dump signal).

Sysmon is the difference between "a service started" and "`rundll32.exe` accessed `lsass.exe` with
dump rights" — the latter is a concrete attack signature.

## 3. Step 0 — Create the VM

Windows 11 needs a few extras VirtualBox Linux guests don't:

- **EFI** boot (not legacy BIOS).
- **TPM 2.0** (Trusted Platform Module) — Windows 11 refuses to install without it.
- **Secure Boot** keys — see `setup.md` §2.2 (install fails without these).

```powershell
VBoxManage createvm --name WIN01 --ostype Windows11_64 --register
VBoxManage modifyvm WIN01 --memory 4096 --cpus 2 --vram 128
VBoxManage modifyvm WIN01 --firmware efi --tpm-type 2.0
VBoxManage modifyvm WIN01 --nic1 intnet --intnet1 int-corp --nic2 nat
VBoxManage createmedium disk --filename C:\lab-vms\WIN01\win01.vdi --size 65536
VBoxManage storagectl WIN01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach WIN01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\WIN01\win01.vdi
VBoxManage storageattach WIN01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\Win11_24H2_Eval.iso
VBoxManage startvm WIN01
```

## 4. Step 1 — Install Windows 11

Install Windows 11 Enterprise (evaluation), create the local user `labadmin`, then:

- **Static IP** `10.10.10.20` on the `int-corp` NIC (this box is a lab fixture; its address must be
  stable).
- **Guest Additions** (better display/mouse/clipboard).
- **Fit tweaks** (Memory Integrity off, transparency/animation off) — the box is RAM-constrained.

## 5. Step 2 — Install Sysmon + the Wazuh agent

Two pieces of "telemetry plumbing":

**Sysmon** (with a config that logs EID 1 = all process create + EID 10 = lsass access only):

```powershell
Sysmon64.exe -accepteula -i C:\lab\win01\sysmon-config.xml
```

**Wazuh agent** (ships Sysmon events up to SOC01):

```powershell
msiexec.exe /i wazuh-agent-4.14.8-1.msi /qn WAZUH_MANAGER="10.10.10.5" WAZUH_AGENT_NAME="win01"
```

The agent service is named `WazuhSvc` (not `Wazuh`) — a small gotcha when checking it's running.

Then we add `ossec.conf` entries so the agent reads the Sysmon event channel and does **FIM**
(file integrity monitoring) on `C:\lab\critical`:

```xml
<localfile><location>Microsoft-Windows-Sysmon/Operational</location> ...</localfile>
<syscheck><directories realtime="yes">C:\lab\critical</directories></syscheck>
```

## 6. Step 3 — Isolate and snapshot

Detach NAT, snapshot:

```powershell
VBoxManage controlvm WIN01 acpipowerbutton
VBoxManage modifyvm WIN01 --nic2 none
VBoxManage snapshot WIN01 take base-phase1
```

## 7. Step 4 — Join the domain (Task 9)

This makes WIN01 a real member of `corp.lab`, so its logons go through DC01 (Kerberos/NTLM):

```powershell
netsh interface ip set dns name="Ethernet" static 10.10.10.10   # point DNS at the DC
nslookup dc01.corp.lab                                           # -> 10.10.10.10 (proves DNS works)
Add-Computer -DomainName corp.lab -Credential CORP\Administrator -Restart
```

(`CORP\Administrator` password is in `.local-credentials.md`.) After the reboot, the login screen
shows `CORP` — WIN01 is domain-joined, and its computer account `DESKTOP-I4QI720$` now authenticates
to DC01 via Kerberos (visible on SOC01 as rule 100031).

## 8. How WIN01's events flow to SOC01 (recap)

```
[attack runs on WIN01]
        |
        v
Sysmon logs EID 1/10  (also Windows Security log 4624/4625 for logons)
        |
        v
Wazuh agent (WazuhSvc) reads those channels + does FIM
        |
        v  :1514 (encrypted, authenticated)
SOC01 manager -> rules -> alerts
```

Two things worth remembering:

- **Sysmon vs Windows Security log** — Sysmon is *process/access* telemetry; the Windows Security
  log is *account/logon* telemetry. Different sources, both useful. Our identity detections (failed
  logons) actually come from **DC01's** logs, not WIN01's — WIN01 triggers the logon, DC01 records it.
- **Agent is push-pull** — the agent runs as a service, reconnects automatically, and buffers events
  while disconnected.

## 9. The detections WIN01 powers

| Rule | Detects | Source |
|---|---|---|
| 100010 | LSASS access by rundll32 (Mimikatz-style dump) | Sysmon EID 10 |
| 100020 | PowerShell `-enc` encoded command | Sysmon EID 1 |
| 100029/100030/100031 | failed / burst / successful logons | DC01 (triggered from WIN01) |

## 10. Gotchas we hit (the interesting lessons)

- **Win11 24H2+ ships LSA Protection ON by default (`RunAsPPL=2`).** The classic `rundll32 comsvcs
  MiniDump` LSASS dump then fails *silently* (empty dump dir, no error). To run UC-01, we disable it:
  `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f` + reboot.
- **Defender's AMSI blocks disabling Defender via PowerShell.** `Set-MpPreference
  -DisableRealtimeMonitoring` is flagged as malicious before it runs. Disable via the GUI instead.
- **Windows FIM: no second `<syscheck>` block.** On Windows, a *second* `<syscheck>` block is silently
  ignored — you must merge new directories into the default block. And per-directory `frequency` is
  unsupported (warning 6701); use `realtime="yes"`.
- **Wazuh 4.14 renamed its Sysmon rule groups.** The old "Sysmon - Event 1" / rule 61601 naming is
  gone; 4.14 uses per-event-id rule groups like `sysmon_event_10`. Don't trust older tutorials.
- **Sysmon log needs admin to read.** `Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational`
  throws UnauthorizedAccessException from a non-elevated session — verify in the elevated shell or
  just trust the Wazuh alert as evidence.

## 11. How to test it yourself

1. Confirm the agent is connected (on SOC01):
   ```bash
   sudo /var/ossec/bin/agent_control -l          # agent 001 win01 active
   ```
2. On WIN01, generate a failed logon (watch SOC01 for rule 100029):
   ```cmd
   net use \\dc01.corp.lab\IPC$ /user:CORP\attacker wrongpass
   net use * /delete /y
   ```
3. On WIN01, run a benign encoded PowerShell (watch SOC01 for rule 100020):
   ```powershell
   powershell -enc WwBTAHkAcwB0AGUAbQAuAEkAbwAuAEYAaQBsAGUALgBXAHIAaQB0AGUATABpAG4AZQA9ACIAaABlAGwAbABvACIA
   ```
