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

---

## 3. DC01 — Samba Active Directory DC (Ubuntu 24.04.5)

Domain controller for `corp.lab` / NetBIOS `CORP`. 2 vCPU / 4 GB RAM, plain ext4 (no LVM).
Host key `SHA256:bt437mjTsTehLfEyzu+dinU7WnM4KDq1bhfeY6kxfK4`; ssh NAT port-forward `127.0.0.1:2222`.

### 3.1 Create VM + disk (host)
```powershell
VBoxManage createvm --name DC01 --ostype Ubuntu_64 --register
VBoxManage modifyvm DC01 --memory 4096 --cpus 2 --vram 16
VBoxManage modifyvm DC01 --nic1 intnet --intnet1 int-corp --nic2 nat
VBoxManage createmedium disk --filename C:\lab-vms\DC01\dc01.vdi --size 40960
VBoxManage storagectl DC01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach DC01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\DC01\dc01.vdi
VBoxManage storageattach DC01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\ubuntu-24.04.5-live-server-amd64.iso
VBoxManage startvm DC01
```

### 3.2 Install Ubuntu (interactive)
Ubuntu Server 24.04.5 minimal, user `dcadmin`, enable OpenSSH (password auth). Full disk, no LVM.

### 3.3 Static IP + free port 53
```bash
# netplan: enp0s3 -> 10.10.10.10/24, nameservers [127.0.0.1]  (the DC is its own DNS)
sudo netplan apply
sudo systemctl disable --now systemd-resolved   # systemd-resolved holds port 53; Samba DNS needs it
```

### 3.4 Provision Samba AD DC (the "create a domain" step)
```bash
sudo apt update && sudo apt install -y samba
sudo samba-tool domain provision --use-rfc2307 --server-role=dc \
  --dns-backend=SAMBA_INTERNAL --realm=corp.lab --domain=CORP --adminpass='<ADMINPW>'
sudo systemctl unmask samba-ad-dc && sudo systemctl enable --now samba-ad-dc
sudo systemctl mask smbd nmbd winbind     # AD DC runs as the 'samba' binary; these are not used
```

### 3.5 smb.conf additions (enable auth JSON + KDC debug to syslog)
Append to `[global]` in `/etc/samba/smb.conf` (see `lab/dc01/smb.conf.additions.txt`):
```
log level = 1 auth_json_audit:3 kdc:10
logging = syslog
log file = /var/log/samba/log.samba
dns forwarder = 192.168.100.1
```
Then `sudo systemctl restart samba-ad-dc`.

### 3.6 Accounts + SPN + no-pre-auth flag
```bash
sudo samba-tool user create attacker 'Attacker!lab123'
sudo samba-tool user create svc-sql  'SvcSQL!lab123'
sudo samba-tool user create victim   'Victim!lab123'
sudo samba-tool spn add MSSQLSvc/dc01.corp.lab:1433 svc-sql     # kerberoast target (weak SPN account)
sudo samba-tool user setexpiry victim --noexpiry                # no password expiry
# AS-REP roast target: add UF_DONT_REQUIRE_PREAUTH (0x400000) to victim's UAC (0x200 normal -> 4194816)
sudo ldbmodify -H /var/lib/samba/private/sam.ldb --controls=relax:0 <<'EOF'
dn: CN=victim,CN=Users,DC=corp,DC=lab
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
EOF
```

### 3.7 Audit routing (rsyslog splits JSON vs text)
Install `lab/dc01/rsyslog-samba-audit.conf` -> `/etc/rsyslog.d/30-samba-audit.conf`, then:
```bash
sudo chown syslog:adm /var/log/samba/log.samba && sudo chmod 664 /var/log/samba/log.samba
# /etc/logrotate.d/samba: "create 640 root adm" -> "create 644 syslog adm"  (rsyslog must be able to re-create it)
sudo rsyslogd -N1        # MUST validate; a bad filter makes rsyslog silently skip the file
sudo systemctl restart rsyslog
```

### 3.8 Wazuh agent
```bash
# .deb is downloaded on the host and relayed host -> SOC01 -> DC01 (DC01 has no internet after isolation)
sudo WAZUH_MANAGER='10.10.10.5' WAZUH_AGENT_NAME='dc01' dpkg -i ./wazuh-agent_4.14.8-1_amd64.deb
sudo systemctl daemon-reload && sudo systemctl enable --now wazuh-agent
```
Append `lab/dc01/ossec.conf.additions.xml` before `</ossec_config>` in `/var/ossec/etc/ossec.conf`, then:
```bash
sudo systemctl restart wazuh-agent
```

### 3.9 Isolate + snapshot
```powershell
VBoxManage controlvm DC01 acpipowerbutton   # graceful shutdown
VBoxManage modifyvm DC01 --nic2 none        # detach NAT
VBoxManage snapshot DC01 take base-phase2   # provisioned AD DC, isolated, pre-agent
```

---

## 4. NDR01 — Suricata network sensor (Ubuntu 24.04.5)

Passive NDR sensor sniffing int-corp via VirtualBox promiscuous "allow-all" NIC. 1 vCPU /
1 GB RAM (2 GB only during install — must drop back) / 15 GB disk. Static `10.10.10.40/24`.
Host key `SHA256:RcRl+dhZx3qks9o3j6HxnS32ZU6QGcfWIGCI1ylXHxA`; ssh NAT port-forward `127.0.0.1:2223`.

### 4.1 Create VM + disk (host)
```powershell
VBoxManage createvm --name NDR01 --ostype Ubuntu_64 --register
VBoxManage modifyvm NDR01 --memory 2048 --cpus 1 --vram 16   # 2 GB for install; drop to 1024 in 4.6
VBoxManage modifyvm NDR01 --nic1 intnet --intnet1 int-corp --nicpromisc1 allow-all \
  --nic2 nat --natpf2 "ssh,tcp,127.0.0.1,2223,,22"
VBoxManage createmedium disk --filename C:\lab-vms\NDR01\ndr01.vdi --size 15360
VBoxManage storagectl NDR01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach NDR01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\NDR01\ndr01.vdi
VBoxManage storageattach NDR01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\ubuntu-24.04.5-live-server-amd64.iso
VBoxManage startvm NDR01
```
`--nicpromisc1 allow-all` is the whole point: without it the passive sensor sees only its own traffic.

### 4.2 Install Ubuntu (interactive)
Ubuntu Server 24.04.5 minimal, user `ndradmin`, enable OpenSSH (password auth). Full disk.

### 4.3 Static IP + clocksource (persist)
```bash
# netplan enp0s3 -> 10.10.10.40/24 on int-corp
sudo netplan apply
# persist a stable clocksource (tsc mis-calibrates after savestate restore):
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 clocksource=acpi_pm"/' /etc/default/grub
sudo update-grub
```

### 4.4 Suricata 8.0.8 + config + local rules
```bash
sudo add-apt-repository -y ppa:oisf/suricata-stable && sudo apt update
sudo apt install -y suricata jq
# apply repo additions (HOME_NET, af-packet enp0s3, custom-only ruleset, eve.json types):
#   lab/ndr01/suricata.yaml.additions.txt  ->  /etc/suricata/suricata.yaml
#   lab/ndr01/local.rules                   ->  /etc/suricata/rules/local.rules   (sids 7000001-7000007)
sudo suricata -T -c /etc/suricata/suricata.yaml   # config test before restart
sudo systemctl enable --now suricata
```

### 4.5 Wazuh agent (003)
```bash
sudo WAZUH_MANAGER='10.10.10.5' WAZUH_AGENT_NAME='ndr01' dpkg -i ./wazuh-agent_4.14.8-1_amd64.deb
# append before </ossec_config> in /var/ossec/etc/ossec.conf:
#   <localfile><location>/var/log/suricata/eve.json</location><log_format>json</log_format></localfile>
sudo systemctl restart wazuh-agent
```

### 4.6 Isolate + drop RAM + snapshot
```powershell
VBoxManage controlvm NDR01 acpipowerbutton
VBoxManage modifyvm NDR01 --memory 1024        # drop the install-time 2 GB back to 1 GB
VBoxManage modifyvm NDR01 --nic2 none          # detach NAT (removes the 2223 forward)
VBoxManage snapshot NDR01 take base-phase3
VBoxManage startvm NDR01 --type headless
```

