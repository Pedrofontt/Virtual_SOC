# SOC01 runbook

Build: Ubuntu Server 24.04 minimal, 3 vCPU, 5 GB RAM, 50 GB VDI.
VM created via VBoxManage (not the GUI wizard): registered at C:\lab-vms\SOC01\soc01.vdi.
NICs: host-only "VirtualBox Host-Only Ethernet Adapter #2" 10.10.30.10, int-corp 10.10.10.5, NAT (temporary).
Boot order: dvd first.

## Host-level prerequisites (REQUIRED, verified 2026-10-13)

VirtualBox host-only networking fails with VERR_INTNET_FLT_IF_NOT_FOUND while the Windows hypervisor stack is active.
Required host state:
1. Memory Integrity (Core Isolation) OFF
2. bcdedit hypervisorlaunchtype = Off
3. VirtualBox 7.2.20 installed ELEVATED (winget non-interactive install skips driver registration - do not use)
4. VBoxNetAdp and VBoxNetLwf services present and running

To undo for WSL2/Docker Desktop use: bcdedit /set hypervisorlaunchtype auto + Memory Integrity ON + reboot.

Local credentials (DO NOT COMMIT):
- socadmin password: <fill in locally>
- wazuh admin password: set during Task 3

## OOM runbook (S1-tune)

If the indexer OOMs or the API times out during testing:
1. SOC01: sudo systemctl stop wazuh-dashboard   # frees 0.8-1 GB guest RAM
2. Host browser https://10.10.30.10 will error - expected, not a crash
3. Verify headless: curl -ks https://127.0.0.1:9200/_cluster/health?pretty
4. After the test: sudo systemctl start wazuh-dashboard
5. If still OOMing: power off WIN01, raise SOC01 to 6 GB (S1-tune), re-run

## Build log (2026-10-13)

- Ubuntu 24.04.5 minimal installed (3 vCPU / 5 GB / 50 GB), socadmin account, OpenSSH enabled
- Static IPs via netplan: enp0s3 10.10.30.10/24, enp0s8 10.10.10.5/24, enp0s9 DHCP (NAT)
- Tools installed: curl jq tmux htop net-tools iputils-ping
- Remote admin: plink from host: plink -batch -pw <pw> socadmin@10.10.30.10 (host key SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo)
- Verified: guest reaches 10.10.30.1 and archive.ubuntu.com (HTTP 200)

## Wazuh install log (2026-10-13/14)

- Wazuh 4.14.8 all-in-one installed (indexer, manager, filebeat, dashboard) after two failed attempts:
  1. Dashboard unpack failed: Ubuntu LVM gave / only 24 GB of the 48 GB VG. Fixed: lvextend +100%FREE + resize2fs -> / is 48 GB
  2. Indexer/filebeat start failures: stale dirs from attempt-1 rollback. Fixed: purged /var/lib|etc|log/wazuh-indexer, /etc/filebeat, /var/lib/filebeat, /usr/share/filebeat/module before reinstalling
- Wazuh admin password: NOT stored here (local notes only)
- Tuning applied: indexer heap Xms1g/Xmx1g; ISM policies lab_retention (7d) and lab_archives_retention (30d); logall_json=yes in /var/ossec/etc/ossec.conf (first <global> block only - the second <global> is the active-response section)
- Cluster health: yellow. Cause: .opendistro-ism-config keeps replica 1 and admin cannot modify it (security_exception, and the ISM plugin exposes no settings endpoint in 4.14). Single unassigned replica of a tiny system index - no functional impact, all data indices green. G1 gate interpretation: healthy = yellow with only this shard unassigned
- G1 baseline (no agents): heap.percent 60, free 366 MB
- NAT detached (NIC 3 disabled). Snapshot taken: base-soc01
- First-boot note: wazuh-indexer takes ~90 s to reach active after boot; wait before running G1 checks

## Build deviations from the plan (log only, not a problem)

- VM created with VBoxManage commands instead of the GUI wizard (same parameters).
- Host-only adapter ended up named "VirtualBox Host-Only Ethernet Adapter #2" after a driver re-registration;
  NIC1 points at "#2". All host-only references in the lab mean this adapter.
- Ubuntu point release used: 24.04.5 (newest noble ISO at build time).
- Host hypervisor stack disabled for VirtualBox (see "Host-level prerequisites" above).
