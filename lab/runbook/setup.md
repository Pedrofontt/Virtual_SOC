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
- At the MS account screen: Shift+F10 → `oobe\bypassnro` → reboot → "I don't have internet" → limited setup → local user `labadmin`

### 2.4 (pending) Guest Additions + Sysmon + Wazuh agent — record here as done
