# Lab setup — rebuild from scratch

Single reference for every command that puts a lab VM into its current state.
Secrets are NOT stored here — passwords live only in `lab/runbook/.local-credentials.md` (gitignored).

---

## 0. Host prerequisites (one-time, required)

Run before any VM networking works:

1. Memory Integrity (Core Isolation) OFF
2. `bcdedit /set hypervisorlaunchtype off` (elevated) + reboot
3. VirtualBox 7.2.20 + Extension Pack installed ELEVATED (winget non-interactive skips driver registration — do not use)
4. Host-only network `VirtualBox Host-Only Ethernet Adapter #2` at 10.10.30.1/24, DHCP disabled
5. PuTTY (plink) installed at `C:\Program Files\PuTTY\plink.exe` (Windows ssh.exe is too old for Ubuntu 24.04 KEX)

---

## 1. SOC01 — Wazuh all-in-one SIEM (Ubuntu 24.04.5)

### 1.1 Create VM + disk (host)
```powershell
VBoxManage createvm --name SOC01 --ostype Ubuntu_64 --register
VBoxManage modifyvm SOC01 --memory 5120 --cpus 3 --vram 16
VBoxManage modifyvm SOC01 --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter #2" `
  --nic2 intnet --intnet2 int-corp --nic3 nat
VBoxManage createmedium disk --filename C:\lab-vms\SOC01\soc01.vdi --size 51200
VBoxManage storagectl SOC01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach SOC01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\SOC01\soc01.vdi
VBoxManage storageattach SOC01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\ubuntu-24.04.5-live-server-amd64.iso
VBoxManage startvm SOC01
```

### 1.2 Install Ubuntu (interactive)
- Ubuntu Server 24.04.5 minimal, user `socadmin`, enable OpenSSH (password auth).

### 1.3 Static IPs (netplan) + base tools
```bash
# /etc/netplan/*.yaml
# enp0s3: 10.10.30.10/24  (host-only LAB-MGMT)
# enp0s8: 10.10.10.5/24   (int-corp LAB-CORP)
# enp0s9: dhcp            (NAT, provisioning-only)
sudo netplan apply
sudo apt update && sudo apt install -y curl jq tmux htop net-tools iputils-ping
```

### 1.4 Wazuh 4.14.8 all-in-one
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh --generate-config-files
sudo bash wazuh-install.sh --wazuh-indexer node-1
sudo bash wazuh-install.sh --start-cluster
sudo bash wazuh-install.sh --wazuh-server wazuh-1
sudo bash wazuh-install.sh --wazuh-dashboard dashboard
tar -xvf wazuh-install-files.tar   # -> wazuh-passwords.txt (admin password)
```
**Pitfalls (fixed during original build):**
- Ubuntu LVM gives `/` only half the disk → `sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv && sudo resize2fs /dev/ubuntu-vg/ubuntu-lv`
- Failed-install rollback leaves stale dirs → purge before retry: `/var/lib|etc|log/wazuh-indexer`, `/etc/filebeat`, `/var/lib/filebeat`, `/usr/share/filebeat/module`

### 1.5 Tuning
```bash
# indexer heap 1g/1g in /etc/wazuh-indexer/jvm.options
# ISM policies via :9200 API: lab_retention (7d) + lab_archives_retention (30d)
# /var/ossec/etc/ossec.conf: logall_json=yes in first <global> block only
```

### 1.6 Isolate + snapshot
```powershell
VBoxManage controlvm SOC01 acpipowerbutton   # graceful shutdown
VBoxManage modifyvm SOC01 --nic3 none        # detach NAT
VBoxManage snapshot SOC01 take base-soc01    # rollback point (no agents)
```

---

## 2. WIN01 — Windows 11 Enterprise Eval endpoint

### 2.1 Create VM + disk (host)
```powershell
VBoxManage createvm --name WIN01 --ostype Windows11_64 --register
VBoxManage modifyvm WIN01 --memory 4096 --cpus 2 --vram 128 --firmware efi --tpm-type 2.0 --chipset ich9
VBoxManage modifyvm WIN01 --nic1 intnet --intnet1 int-corp --nic2 nat
VBoxManage createmedium disk --filename C:\lab-vms\WIN01\win01.vdi --size 65536   # 64 GB (Win11 min)
VBoxManage storagectl WIN01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach WIN01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\WIN01\win01.vdi
VBoxManage storagectl WIN01 --name IDE --add ide --bootable on
VBoxManage storageattach WIN01 --storagectl IDE --port 0 --device 0 --type dvddrive --medium C:\iso\<win11-eval>.iso
VBoxManage modifyvm WIN01 --boot1 dvd --boot2 disk
```

### 2.2 Secure Boot keys (CRITICAL — install fails without these)
```powershell
VBoxManage modifynvram WIN01 enrollorclpk
VBoxManage modifynvram WIN01 enrollmssignatures
VBoxManage modifynvram WIN01 secureboot --enable
```
**Why:** deleting/regenerating the NVRAM leaves `SecureBootEnable=1` but no PK/KEK/db →
firmware loads `cdboot.efi` but rejects `bootmgr.efi` → "The VM failed to boot".
Do NOT use `inituefivarstore` (it wipes boot entries).

### 2.3 Install Windows 11 Eval (interactive)
- Language → Install now → "I don't have a product key" → Windows 11 Enterprise (Evaluation)
- Custom install → select 64 GB disk
- At the account screen, do NOT sign in with a Microsoft account. Reliable local-account path:
  on "Let's set things up for your work or school" → **Sign-in options** → **Domain join instead** → local user `labadmin`.
  (`oobe\bypassnro` also works but was flaky — the domain-join path is deterministic.)

### 2.4 Guest Additions + static IP + fit tweaks + Sysinternals
```powershell
# Guest Additions (host menu): Devices -> Insert Guest Additions CD image ->
#   in VM run VBoxWindowsAdditions-amd64.exe -> reboot.
# Enable shared clipboard (runtime; persists only this boot):
VBoxManage controlvm WIN01 clipboard mode bidirectional
VBoxManage controlvm WIN01 draganddrop bidirectional
```
In WIN01 (admin PowerShell):
```powershell
# static IP on the int-corp adapter (usually "Ethernet"; NAT is "Ethernet 2")
netsh interface ip set address name="Ethernet" static 10.10.10.20 255.255.255.0
# Memory Integrity off (fit tweak; verify via Settings > Privacy > Device security)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
# transparency off: Settings > Personalization > Colors > "Transparency effects" = Off
# animations off: Settings > Accessibility > Visual effects > "Animation effects" = Off
# Sysinternals (Sysmon):
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path "C:\lab\tools" | Out-Null
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\lab\tools" -Force
```

### 2.5 Sysmon + Wazuh agent (Task 5)
```powershell
# Sysmon 15.22 with repo config (schema 4.90): EID 1 all + EID 10 lsass only
& C:\lab\tools\Sysmon64.exe -accepteula -i C:\lab\sysmon-config.xml
# Wazuh agent 4.14.8 (while NAT is still attached)
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.8-1.msi" -OutFile "$env:TEMP\wazuh-agent-4.14.8-1.msi"
msiexec /i "$env:TEMP\wazuh-agent-4.14.8-1.msi" /qn WAZUH_MANAGER="10.10.10.5" WAZUH_REGISTRATION_SERVER="10.10.10.5" WAZUH_AGENT_NAME="win01"
# Append before </ossec_config> in C:\Program Files (x86)\ossec-agent\ossec.conf:
#   <localfile><location>Microsoft-Windows-Sysmon/Operational</location><log_format>eventchannel</log_format></localfile>
#   <syscheck><directories check_all="yes" realtime="yes">C:\lab\critical</directories></syscheck>  # NOTE: must be merged into the existing block, see 2.5b
Start-Service WazuhSvc   # service name is WazuhSvc, not Wazuh
```

### 2.5b FIM config correction (Task 6) — CRITICAL for Windows + 4.14.8
The 2.5 snippet above is WRONG for Windows in two ways (verified empirically):
- A second `<syscheck>` block is silently IGNORED. The `<directories>` line must be merged INTO the existing default `<syscheck>` block (after `<frequency>43200</frequency>`).
- Per-directory `frequency` is ignored on Windows agents (log warning 6701, global 43200 wins).
- Use realtime instead: `<directories check_all="yes" realtime="yes">C:\lab\critical</directories>` (realtime alerts instantly; supported on Windows).
Final repo artifact: `lab/win01/ossec.conf.additions.xml`.

### 2.5c Wazuh 4.14.8 FIM decoder fix (Task 6) — REQUIRED or FIM alerts never fire
Wazuh 4.14.8 ships rules 550/553/554 whose `decoded_as` names (syscheck_new_entry,
syscheck_integrity_changed, syscheck_deleted, + 6 registry variants) exist nowhere in the
shipped decoder files. analysisd's FIM alert path therefore never matches a rule: events are
stored in fim_entry but zero alerts. Fix on SOC01: append decoder stubs to
`/var/ossec/etc/decoders/local_decoder.xml` (prematch intentionally impossible - they only
exist so getDecoderfromlist() finds them):

```xml
<decoder name="syscheck_new_entry"><parent>wazuh</parent><prematch>^__fim_lab_never_match_new$</prematch></decoder>
<decoder name="syscheck_integrity_changed"><parent>wazuh</parent><prematch>^__fim_lab_never_match_mod$</prematch></decoder>
<decoder name="syscheck_deleted"><parent>wazuh</parent><prematch>^__fim_lab_never_match_del$</prematch></decoder>
<decoder name="syscheck_registry_key_added"><parent>wazuh</parent><prematch>^__fim_lab_never_match_rka$</prematch></decoder>
<decoder name="syscheck_registry_key_modified"><parent>wazuh</parent><prematch>^__fim_lab_never_match_rkm$</prematch></decoder>
<decoder name="syscheck_registry_key_deleted"><parent>wazuh</parent><prematch>^__fim_lab_never_match_rkd$</prematch></decoder>
<decoder name="syscheck_registry_value_added"><parent>wazuh</parent><prematch>^__fim_lab_never_match_rva$</prematch></decoder>
<decoder name="syscheck_registry_value_modified"><parent>wazuh</parent><prematch>^__fim_lab_never_match_rvm$</prematch></decoder>
<decoder name="syscheck_registry_value_deleted"><parent>wazuh</parent><prematch>^__fim_lab_never_match_rvd$</prematch></decoder>
```
Then `sudo /var/ossec/bin/wazuh-control restart`.

### 2.6 Isolate + snapshot
```powershell
VBoxManage controlvm WIN01 acpipowerbutton   # can take 10+ min on fresh install (Windows updates at shutdown)
VBoxManage modifyvm WIN01 --nic2 none        # detach NAT (needs VM off)
VBoxManage modifyvm WIN01 --clipboard-mode bidirectional --draganddrop-mode bidirectional
VBoxManage snapshot WIN01 take base-phase1   # sysmon + wazuh agent enrolled, no tests run
```

### 2.7 UC-01 custom rule 100010 deploy (Task 7)
Rule source of truth: `lab/soc01/local_rules.xml`. Deploy from host (byte-for-byte copy):
```powershell
# host:
& "C:\Program Files\PuTTY\pscp.exe" -batch -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw <PW> lab\soc01\local_rules.xml socadmin@10.10.30.10:/tmp/local_rules.xml
# SOC01:
install -o root -g wazuh -m 640 /tmp/local_rules.xml /var/ossec/etc/rules/local_rules.xml
systemctl restart wazuh-manager && systemctl is-active wazuh-manager
grep -iE "error|invalid" /var/ossec/logs/ossec.log | tail -5   # expect nothing new
```
IMPORTANT (4.14): the rule must use `<if_group>sysmon_event_10</if_group>` — Wazuh 4.14 has
NO `61610` parent rule; the group is added by the built-in `windows_eventchannel` decoder (not
an XML file, not greppable). `wazuh-logtest` cannot exercise this decoder chain — verify with
real events only.

### 2.8 UC-01 lab controls on WIN01 (test window only, all reverted by snapshot)
```powershell
# Defender real-time protection: Windows Security GUI -> Virus & threat protection ->
#   Manage settings -> Real-time protection Off.
#   (Set-MpPreference -DisableRealtimeMonitoring is AMSI-blocked: "This script contains
#   malicious content". Tamper Protection was already Off on this image.)
# LSA Protection off (Win11 24H2+ ships RunAsPPL=2; comsvcs MiniDump fails silently with it on):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 0 /f
Restart-Computer
# Simulation (admin PowerShell):
$lsassPid = (Get-Process lsass).Id
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $lsassPid C:\lab\dumps\lsass_lab.dmp full
# Expect: 2 rule-100010 alerts per run (probe open 0x1410 + dump open 0x1fffff).
# Snapshot around test: VBoxManage snapshot WIN01 take pre-uc01  (before)  / restore (after).
```

