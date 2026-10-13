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

## Build deviations from the plan (log only, not a problem)

- VM created with VBoxManage commands instead of the GUI wizard (same parameters).
- Host-only adapter ended up named "VirtualBox Host-Only Ethernet Adapter #2" after a driver re-registration;
  NIC1 points at "#2". All host-only references in the lab mean this adapter.
- Ubuntu point release used: 24.04.5 (newest noble ISO at build time).
- Host hypervisor stack disabled for VirtualBox (see "Host-level prerequisites" above).
