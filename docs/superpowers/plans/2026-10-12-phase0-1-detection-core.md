# Phase 0–1 Detection Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the phase-0 host and the phase-1 detection core (SOC01 Wazuh all-in-one + WIN01 endpoint), then prove two reproducible detections: UC-00 (FIM) and UC-01 (T1003.001 LSASS access).

**Architecture:** VirtualBox 7.1.x on the Windows host with two lab networks (`vboxnet0` host-only 10.10.30.0/24 for LAB-MGMT, `int-corp` internal 10.10.10.0/24 for LAB-CORP). SOC01 runs Ubuntu Server 24.04 LTS with the Wazuh 4.14.x all-in-one stack. WIN01 runs Windows 11 Enterprise Evaluation with Sysmon + the Wazuh agent. Detection flow: Sysmon/FIM events -> Wazuh agent -> SOC01 manager -> indexer -> dashboard/API.

**Tech Stack:** VirtualBox 7.1.x, Ubuntu Server 24.04 LTS, Wazuh 4.14.x (stable; 5.0 is RC and out of scope), Sysmon (latest Sysinternals), Windows 11 Enterprise Evaluation, PowerShell 5.1 (host), bash (guests).

## Global Constraints

These come from `docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md` and apply to every task.

- Simultaneous VM RAM ceiling: **11 GB**; host must keep **5 GB** free. Milestone power-on is **S1 only**: SOC01 + WIN01 (9 GB total).
- SOC01: **3 vCPU / 5 GB RAM / 50 GB** dynamic VDI. WIN01: **2 vCPU / 4 GB RAM / 40 GB** dynamic VDI.
- Wazuh pinned to the **4.14.x stable line** on **Ubuntu 24.04 LTS**. Indexer heap **Xms1g/Xmx1g**. Indices delete after **7 days**; alert archives **30 days or 5 GB**.
- **No bridged adapters. No inbound port forwards.** NAT adapters exist only for package installs and are detached after the per-guest pre-isolation checklist passes.
- WIN01 must be created with guest type "Windows 11" (EFI + virtual TPM 2.0 + Secure Boot), Memory Integrity disabled, transparency/effects disabled.
- No real malware. UC-01 uses a living-off-the-land simulation. Defender real-time protection disable/re-enable is a documented lab control. Snapshot before the test, revert after.
- UC-01 custom rule: **level 12**, group `credential_access`, MITRE `T1003.001`. UC-01 pass conditions: Sysmon EID 10 visible in Wazuh, rule fires on **two** separate executions, benign control does not fire, exercise log documents expected vs observed.
- Gate G1 must pass before UC-01: indexer health `green`, `heap.percent < 75`, guest headroom >= 300 MB.
- **No secrets in git.** The Wazuh admin password lives only inside SOC01 and in the local runbook (`lab/runbook/soc01.md`), which must never be committed with the password filled in.
- All IPs static: host 10.10.30.1; SOC01 10.10.30.10 (mgmt) + 10.10.10.5 (corp); WIN01 10.10.10.20.

---

## File Structure

- Create: `lab/README.md` — lab overview, power-on matrix, portfolio limits (spec §11)
- Create: `lab/network/networks.md` — network/IP/NIC reference (spec §4)
- Create: `lab/runbook/soc01.md` — SOC01 build + OOM runbook + credentials template (password blank)
- Create: `lab/runbook/win01.md` — WIN01 build notes + lab controls log
- Create: `lab/win01/sysmon-config.xml` — minimal Sysmon config (EID 1 all, EID 10 lsass only)
- Create: `lab/win01/ossec.conf.additions.xml` — agent config snippet (Sysmon channel + syscheck)
- Create: `lab/soc01/local_rules.xml` — UC-01 custom rule (deployed to SOC01 in Task 7)
- Create: `lab/cases/uc-00-fim.md` — use case doc: hypothesis, steps, expected vs observed
- Create: `lab/cases/uc-01-t1003-lsass.md` — use case doc: same structure + rule logic + FP discussion
- Create: `lab/cases/exercise-log.md` — running log of every simulated exercise
- Create: `lab/evidence/README.md` + `lab/evidence/.gitignore` — what evidence to export; ignore `*.dmp`, `*.pcap`
- Modify: `docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md` — no changes needed unless a verified fact (rule id, API output) contradicts it; log divergences in the exercise log instead

---

### Task 1: Repository scaffolding

**Files:**
- Create: `lab/README.md`
- Create: `lab/network/networks.md`
- Create: `lab/evidence/README.md`
- Create: `lab/evidence/.gitignore`

**Interfaces:**
- Consumes: nothing (spec values only)
- Produces: `lab/network/networks.md` (the IP/NIC table every later task references), `lab/README.md` (power-on matrix), `lab/evidence/.gitignore` (prevents committing dumps later)

- [ ] **Step 1: Create `lab/evidence/.gitignore`**

```
*.dmp
*.pcap
*.pcapng
```

- [ ] **Step 2: Create `lab/network/networks.md`**

```markdown
# Lab networks

Two VirtualBox networks. No bridged adapters. No DHCP on lab networks. All IPs static.

## vboxnet0 — host-only, LAB-MGMT, 10.10.30.0/24

| Node | Address | Role |
|---|---|---|
| Host (Windows) | 10.10.30.1 | Analyst browser |
| SOC01 nic0 | 10.10.30.10 | Wazuh dashboard :443, API :55000 |
| SOAR01 nic0 (phase 4) | 10.10.30.20 | n8n :5678 |

## int-corp — internal, LAB-CORP, 10.10.10.0/24

| Node | Address | Role |
|---|---|---|
| SOC01 nic1 | 10.10.10.5 | Agent events :1514, enrollment :1515 |
| WIN01 | 10.10.10.20 | Endpoint (Sysmon + Wazuh agent) |
| DC01 (phase 2) | 10.10.10.10 | Samba AD DC + DNS, domain corp.lab |
| NDR01 (phase 3) | 10.10.10.40 | Suricata sensor; bridge model on gate G2 failure |
| SRV01 (phase 5) | 10.10.10.30 | Reserved, not built |

## Guest NICs

- SOC01: host-only + int-corp + NAT (NAT detached after Task 3 checklist)
- WIN01: int-corp + NAT (NAT detached after Task 5 checklist)
- NAT adapters are for package installs only. When detached, the lab has no Internet path.
```

- [ ] **Step 3: Create `lab/evidence/README.md`**

```markdown
# Evidence

Export artifacts here after each exercise. Commit only what is small and non-sensitive.

Required per use case:
- Screenshot of the source event (Event Viewer / Wazuh Discover)
- Screenshot or JSON export of the Wazuh alert
- Benign control result (screenshot or log line)
- Exercise log entry in ../cases/exercise-log.md

Never commit: memory dumps (*.dmp), packet captures (*.pcap), credentials, the Wazuh admin password.
```

- [ ] **Step 4: Create `lab/README.md`**

```markdown
# Virtual SOC Lab

Free, isolated, reproducible SOC lab on a 16 GB host. Design: docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md

## Power-on matrix (from the spec)

| ID | Guests on | Guest RAM | Used for |
|---|---|---|---|
| S1 | SOC01 + WIN01 | 9 GB | Milestone 1 detections (this plan) |
| S1-tune | SOC01 (6 GB) + WIN01 | 10 GB | Indexer OOM troubleshooting only |
| S2 | SOC01 + WIN01 + DC01 | 11 GB | Phase 2 identity |
| S3 | SOC01 + WIN01 + NDR01 | 10 GB | Phase 3 NDR |
| S4 | SOC01 + WIN01 + SOAR01 | 11 GB | Phase 4 automation |

Rules: never exceed 11 GB of running guests. Boot SOC01 first, wait for the API, then others. Shut down in reverse.

## Portfolio limits

- 16 GB forces phased power-on; this is not a 24/7 SOC
- Samba AD is not Windows Server AD
- Wazuh + Sysmon is not a commercial EDR
- Suricata here is a single-segment IDS, not a full NDR platform
- Free-tool coverage is not commercial-product parity

## Current state

Phase 0–1 in progress. See runbook/ and cases/.
```

- [ ] **Step 5: Verify content matches the spec**

Read back `lab/README.md` and `lab/network/networks.md`. Check every IP and RAM figure against spec sections 4, 5, 6. Any mismatch means the spec or this plan changed without the other.

- [ ] **Step 6: Commit**

```powershell
git add lab/
git commit -m "docs: add lab scaffolding, network reference, evidence policy"
```

---

### Task 2: Host prep and SOC01 base VM

**Files:**
- Create: `lab/runbook/soc01.md` (build log, credentials template — password field left empty)

**Interfaces:**
- Consumes: `lab/network/networks.md` (IPs, NIC plan)
- Produces: a running SOC01 base guest at 10.10.30.10 + 10.10.10.5 with temporary NAT Internet; `lab/runbook/soc01.md` with the install steps recorded

- [ ] **Step 1: Install VirtualBox 7.1.x + Extension Pack**

Download from https://www.virtualbox.org/wiki/Downloads. Install VirtualBox, then the Extension Pack (double-click). Expected: `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe` exists.

- [ ] **Step 2: Create the host-only network**

Run in PowerShell (as the user, no admin needed):

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif create
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter" --ip 10.10.30.1 --netmask 255.255.255.0
```

Expected: second command prints nothing on success. Verify with:

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" list hostonlyifs
```

Expected: one interface, `IPAddress: 10.10.30.1`, `NetworkMask: 255.255.255.0`, DHCP likely enabled by default. Disable DHCP if shown:

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" dhcpserver modify --ifname "VirtualBox Host-Only Ethernet Adapter" --disable
```

- [ ] **Step 3: Download Ubuntu Server 24.04 LTS ISO**

From https://releases.ubuntu.com/noble/ grab the newest `ubuntu-24.04.*-live-server-amd64.iso`. Save to `C:\iso\`. Expected: file present, roughly 2.5–3 GB.

- [ ] **Step 4: Create the SOC01 VM (GUI wizard)**

VirtualBox Manager -> New:
- Name: `SOC01`, Type: `Linux`, Version: `Ubuntu (64-bit)`
- ISO: the Ubuntu Server ISO from Step 3
- Hardware: 5120 MB RAM, 3 CPUs
- Virtual Hard Disk: 50 GB, VDI (dynamically allocated)
- Finish, then open Settings -> Network:
  - Adapter 1: Host-only Adapter, name "VirtualBox Host-Only Ethernet Adapter", Promiscuous: Deny
  - Adapter 2: Internal Network, Name: `int-corp`, Promiscuous: Deny
  - Adapter 3: NAT
- System -> Processor: confirm 3 CPUs; System -> Acceleration: default (nested paging on)

- [ ] **Step 5: Install Ubuntu Server (minimal)**

Start SOC01. Installer choices:
- Language: English
- Installation type: **Ubuntu Server (minimized)**
- Network: leave DHCP for now (installer needs Internet via NAT later; static IPs come from netplan next)
- Storage: use entire disk, default LVM layout
- Profile: name `socadmin`, hostname `soc01`, password of your choice (record it in `lab/runbook/soc01.md` under a local-only section)
- OpenSSH server: **Install**
- Skip snaps (no featured snaps needed)

Reboot when done. Expected: login prompt.

- [ ] **Step 6: Set static IPs via netplan**

Log in as `socadmin`. Identify the three NICs:

```bash
ip -br link show
```

Expected: three interfaces, typically `enp0s3` (host-only), `enp0s8` (int-corp), `enp0s9` (NAT). Edit netplan:

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

Replace with (adjust interface names to what `ip -br link show` reported):

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [10.10.30.10/24]
    enp0s8:
      dhcp4: false
      addresses: [10.10.10.5/24]
    enp0s9:
      dhcp4: true
```

Apply:

```bash
sudo netplan apply
ip -br addr show
```

Expected: `10.10.30.10/24` on the host-only NIC, `10.10.10.5/24` on the int-corp NIC, DHCP address on the NAT NIC.

- [ ] **Step 7: Verify host connectivity and Internet**

From the Windows host:

```powershell
ping 10.10.30.10
```

Expected: replies, TTL 64.

From SOC01:

```bash
ping -c 2 10.10.30.1
curl -sI https://archive.ubuntu.com | head -n 1
```

Expected: host replies; curl prints `HTTP/1.1 200` (or 3xx). If curl fails, the NAT adapter is not carrying traffic — check Adapter 3 attachment in VirtualBox.

- [ ] **Step 8: Install SOC tooling while online (pre-isolation checklist part 1)**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl jq tmux htop net-tools
```

Expected: each package installs without error.

- [ ] **Step 9: Record the build in the runbook**

Write `lab/runbook/soc01.md`:

```markdown
# SOC01 runbook

Build: Ubuntu Server 24.04 minimal, 3 vCPU, 5 GB RAM, 50 GB VDI.
NICs: host-only 10.10.30.10, int-corp 10.10.10.5, NAT (temporary).

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
```

The `<fill in locally>` markers are intentional: the password must never be committed.

- [ ] **Step 10: Commit**

```powershell
git add lab/runbook/soc01.md
git commit -m "docs: SOC01 base build runbook and OOM procedure"
```

---

### Task 3: Wazuh all-in-one install and tuning

**Files:**
- Modify: `lab/runbook/soc01.md` (append install notes; password stays local)

**Interfaces:**
- Consumes: SOC01 base guest with Internet (Task 2)
- Produces: working Wazuh 4.14.x stack: manager :1514/:1515, indexer :9200, dashboard https://10.10.30.10, API :55000. Gate G1 runnable

- [ ] **Step 1: Run the official all-in-one installer**

On SOC01:

```bash
cd ~
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

If the URL 404s, check the current 4.14.x directory listing at https://packages.wazuh.com/ and use the newest 4.14 patch path. Do not use a 5.0 release candidate.

Expected: the script prints `Installation finished` and an admin password like `Admin password: <random>`. Save the password immediately to `lab/runbook/soc01.md` (local only). The install files stay at `~/wazuh-install-files.tar` on SOC01.

- [ ] **Step 2: Verify the stack is up**

```bash
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard
curl -ks https://127.0.0.1:9200/_cluster/health?pretty -u admin:<PASS>
```

Expected: three `active` lines; JSON with `"status" : "green"`. Replace `<PASS>` with the admin password (never echo it into git).

- [ ] **Step 3: Pin the indexer heap at 1 GB**

```bash
grep -E "^-Xm[sx]" /etc/wazuh-indexer/jvm.options
```

Expected: `-Xms1g` and `-Xmx1g` (the 4.14 assistant falls back to 1 GB regardless of RAM; confirm both lines equal `1g`). If they differ, edit the file so both are `1g`, then:

```bash
sudo systemctl restart wazuh-indexer
```

- [ ] **Step 4: Set 7-day index retention via ISM policy**

```bash
curl -ks -X PUT "https://127.0.0.1:9200/_plugins/_ism/policies/lab_retention" \
  -H 'Content-Type: application/json' -u admin:<PASS> -d '
{
  "policy": {
    "description": "Lab: delete indices after 7 days",
    "default_state": "hot",
    "states": [
      {"name": "hot", "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "7d"}}]},
      {"name": "delete", "actions": [{"delete": {}}]}
    ]
  }
}'
```

Expected: JSON with `"acknowledged": true`.

- [ ] **Step 5: Enable alert archives with the 30-day/5 GB cap**

Edit the manager config:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Inside `<global>`, set `<logall_json>yes</logall_json>`, save, then:

```bash
sudo systemctl restart wazuh-manager
curl -ks -X PUT "https://127.0.0.1:9200/_plugins/_ism/policies/lab_archives_retention" \
  -H 'Content-Type: application/json' -u admin:<PASS> -d '
{
  "policy": {
    "description": "Lab archives: delete after 30 days",
    "default_state": "hot",
    "states": [
      {"name": "hot", "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "30d"}}]},
      {"name": "delete", "actions": [{"delete": {}}]}
    ]
  }
}'
```

Expected: `"acknowledged": true`, and after a few minutes the `wazuh-archives-*` index appears:

```bash
curl -ks "https://127.0.0.1:9200/_cat/indices?v" -u admin:<PASS> | grep wazuh
```

The 5 GB archive cap is enforced by the 30-day cap at this EPS; record actual archive growth in `soc01.md` after the first exercise.

- [ ] **Step 6: Verify the dashboard from the host**

From the Windows host browser, open `https://10.10.30.10` (accept the self-signed certificate warning). Expected: Wazuh login page. Log in with `admin` / the saved password. Expected: dashboard loads with agent count 0.

- [ ] **Step 7: Run gate G1 baseline (spec section 12)**

On SOC01:

```bash
curl -ks https://127.0.0.1:9200/_cluster/health?pretty -u admin:<PASS> | jq .status
curl -ks "https://127.0.0.1:9200/_cat/nodes?v&h=name,heap.percent,ram.percent" -u admin:<PASS>
free -m
```

Expected: `green`; `heap.percent` under 75; `free -m` shows >= 300 MB available. Log the numbers in `lab/cases/exercise-log.md` under "G1 baseline".

- [ ] **Step 8: Detach SOC01 NAT**

VirtualBox Manager -> SOC01 -> Settings -> Network -> Adapter 3 -> uncheck "Enable Network Adapter". SOC01 keeps its two lab NICs. Verify it still answers:

```powershell
ping 10.10.30.10
```

Expected: replies.

- [ ] **Step 9: Snapshot SOC01 (powered off)**

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" snapshot SOC01 take base-soc01 --description "wazuh all-in-one tuned, no agents"
```

Expected: `Snapshot taken. UUID: ...`

- [ ] **Step 10: Commit**

```powershell
git add lab/runbook/soc01.md
git commit -m "docs: SOC01 Wazuh all-in-one install and tuning notes"
```

---

### Task 4: WIN01 base VM with Windows 11 Evaluation

**Files:**
- Create: `lab/runbook/win01.md` (build notes + lab controls log)

**Interfaces:**
- Consumes: none beyond the network reference
- Produces: WIN01 guest at 10.10.10.20, Windows 11 Enterprise Evaluation installed, EFI/TPM/Secure Boot confirmed, Memory Integrity off, Sysinternals downloaded, NAT still attached (for Task 5)

- [ ] **Step 1: Download the Windows 11 Enterprise Evaluation ISO**

From https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise (free, 90-day evaluation). Save to `C:\iso\`. Expected: ISO file present (~6 GB).

- [ ] **Step 2: Create the WIN01 VM (GUI wizard)**

VirtualBox Manager -> New:
- Name: `WIN01`, Type: `Microsoft Windows`, Version: `Windows 11 (64-bit)`
- ISO: the Windows 11 Evaluation ISO
- Hardware: 4096 MB RAM, 2 CPUs
- Virtual Hard Disk: 40 GB, VDI (dynamically allocated)

The Windows 11 guest type defaults the VM to EFI, virtual TPM 2.0, and Secure Boot support. Verify in Settings:
- System -> Motherboard: "Enable EFI" checked, "Enable Secure Boot" checked, TPM = 2.0
- Network: Adapter 1 = Internal Network `int-corp`; Adapter 2 = NAT

- [ ] **Step 3: Install Windows 11**

Start WIN01. Installer choices:
- Edition: Windows 11 Enterprise Evaluation
- If OOBE demands a Microsoft account: press Shift+F10 at the network page, run `oobe\bypassnro`, let it reboot, then choose "I don't have internet" -> "Continue with limited setup". If that option is absent (Enterprise builds sometimes skip it), choose "Set up for work or school" -> "Domain join instead" and create a local user
- Local user: `labadmin` with a lab-only password (record in `lab/runbook/win01.md` local section)

Expected: desktop appears.

- [ ] **Step 4: Install Guest Additions**

Devices -> Insert Guest Additions CD image, run the installer inside WIN01, reboot. Expected: mouse integration and shared clipboard work; window resizes.

- [ ] **Step 5: Set the static IP**

In WIN01, Settings -> Network & internet -> Advanced network settings -> the `int-corp` adapter:
- IPv4: 10.10.10.20 / 255.255.255.0, gateway empty, DNS empty
Verify:

```powershell
ping 10.10.10.5
```

Expected: replies (SOC01 must be running; that is S1). If SOC01 is off, start it first.

- [ ] **Step 6: Apply the 4 GB fit tweaks**

In an admin PowerShell:

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
```

Then Settings -> Personalization: disable transparency effects and animations. Expected: `reg add` prints `The operation completed successfully.` Memory Integrity shows "Off" after the next reboot. Reboot WIN01.

- [ ] **Step 7: Download Sysinternals and extract Sysmon (pre-isolation checklist part 2)**

In WIN01 (NAT still attached):

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\lab\tools\"
```

Expected: `C:\lab\tools\Sysmon64.exe` exists. Keep the whole suite unpacked locally (Procmon, Autoruns) for later investigation demos.

- [ ] **Step 8: Verify the Sysmon event channel exists**

Start -> Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> Sysmon -> Operational. Expected: channel exists, possibly empty until Sysmon is installed in Task 5. Also confirm the channel via PowerShell:

```powershell
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
```

Expected: output shows the log name and record count.

- [ ] **Step 9: Record the build and lab controls**

Write `lab/runbook/win01.md`:

```markdown
# WIN01 runbook

Build: Windows 11 Enterprise Evaluation, 2 vCPU, 4 GB RAM, 40 GB VDI.
NIC: int-corp 10.10.10.20 + NAT (temporary).

Local credentials (DO NOT COMMIT):
- labadmin password: <fill in locally>

Fit tweaks applied: Memory Integrity off (DeviceGuard registry), transparency/effects off.

## Lab controls log

| Date | Control | Reason | Restored? |
|---|---|---|---|
|  | Defender real-time protection disabled for UC-01 window | MiniDump would be killed before Sysmon records it | fill in during Task 7 |
```

- [ ] **Step 10: Commit**

```powershell
git add lab/runbook/win01.md
git commit -m "docs: WIN01 Windows 11 eval build notes and lab controls log"
```

---

### Task 5: Sysmon config and Wazuh agent enrollment

**Files:**
- Create: `lab/win01/sysmon-config.xml`
- Create: `lab/win01/ossec.conf.additions.xml`
- Modify: `lab/runbook/win01.md` (record agent install)

**Interfaces:**
- Consumes: WIN01 (Task 4), SOC01 manager on 10.10.10.5:1515/1514 (Task 3)
- Produces: Sysmon installed with EID 1 + EID 10 (lsass); Wazuh agent enrolled as `win01`, status active; Sysmon EID 1 events flowing into SOC01's `alerts.json`

- [ ] **Step 1: Write the Sysmon config in the repo**

Create `lab/win01/sysmon-config.xml`:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"/>
    <ProcessAccess onmatch="include">
      <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
    </ProcessAccess>
  </EventFiltering>
</Sysmon>
```

This logs every process creation (EID 1) and every process-access to lsass.exe only (EID 10) — enough for UC-01 and its benign control, with minimal noise.

- [ ] **Step 2: Install Sysmon with this config**

On WIN01, check the binary's schema version first:

```powershell
& C:\lab\tools\Sysmon64.exe -?
```

Expected: version banner, e.g. `Sysmon v15.x - System activity monitor`. If the binary requires a newer schemaversion than `4.90`, update the `schemaversion` attribute in `lab/win01/sysmon-config.xml` to match the binary's reported schema, then recreate the file on WIN01 with the same content (type it into Notepad at `C:\lab\sysmon-config.xml`, matching exactly).

Install (admin PowerShell):

```powershell
& C:\lab\tools\Sysmon64.exe -accepteula -i C:\lab\sysmon-config.xml
```

Expected: `Sysmon started.` Verify:

```powershell
Get-Service Sysmon64
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" | Select-Object RecordCount
```

Expected: service `Running`; the event log shows a record count that grows when any process starts.

- [ ] **Step 3: Write the agent config additions in the repo**

Create `lab/win01/ossec.conf.additions.xml`:

```xml
<!-- Append inside <ossec_config> of C:\Program Files (x86)\ossec-agent\ossec.conf -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<syscheck>
  <directories check_all="yes" realtime="no">C:\lab\critical</directories>
</syscheck>
```

The Sysmon channel feeds Wazuh. The syscheck block watches `C:\lab\critical` for UC-00 (FIM). `realtime="no"` keeps resource use low; a scheduled scan is enough for a demo.

- [ ] **Step 4: Download and install the Wazuh agent MSI (pre-isolation checklist part 3)**

On WIN01, while NAT is attached, download the agent matching the manager version. From https://packages.wazuh.com/4.x/windows/ pick the newest 4.14.x MSI (pattern `wazuh-agent-4.14.*-1.msi`). Install with the manager addresses baked in (admin PowerShell):

```powershell
msiexec /i "$env:TEMP\wazuh-agent-4.14.x-1.msi" /qn WAZUH_MANAGER="10.10.10.5" WAZUH_REGISTRATION_SERVER="10.10.10.5" WAZUH_AGENT_NAME="win01"
```

Expected: exit code 0. Then apply the additions from Step 3 to `C:\Program Files (x86)\ossec-agent\ossec.conf` (edit with Notepad as admin: paste the two blocks before the closing `</ossec_config>`), and restart the agent:

```powershell
Restart-Service Wazuh
```

- [ ] **Step 5: Verify enrollment**

On SOC01:

```bash
curl -ks -u admin:<PASS> "https://127.0.0.1:55000/agents?pretty" | jq '.data.affected_items[] | {name, status}'
```

Expected: one item, `name: "win01"`, `status: "active"`. If `status: "never_connected"`, check WIN01's `C:\Program Files (x86)\ossec-agent\ossec.log` for registration errors and that WIN01 pings 10.10.10.5.

- [ ] **Step 6: Verify Sysmon telemetry flows**

On WIN01, generate a process (e.g., open Notepad). On SOC01:

```bash
sudo tail -n 20 /var/ossec/logs/alerts/alerts.json | grep -o "sysmon" | head -1
```

Expected: at least one line contains `sysmon` within a minute or two. More precisely, confirm an EID 1 arrived:

```bash
sudo grep -c "Sysmon - Event 1" /var/ossec/logs/alerts/alerts.json
```

Expected: count >= 1. Note: the stock rule for Sysmon EID 1 (rule 61601) fires an alert per process; alert volume will be high by design. That is acceptable for the lab.

- [ ] **Step 7: Detach WIN01 NAT**

VirtualBox Manager -> WIN01 -> Settings -> Network -> Adapter 2 -> uncheck "Enable Network Adapter". Verify agent connectivity survives (it uses int-corp):

```bash
curl -ks -u admin:<PASS> "https://127.0.0.1:55000/agents?pretty" | jq '.data.affected_items[].status'
```

Expected: `active`.

- [ ] **Step 8: Snapshot both guests (powered off)**

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" snapshot WIN01 take base-phase1 --description "sysmon + wazuh agent enrolled, no tests run"
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" snapshot SOC01 take base-phase1 --description "stack tuned, win01 enrolled"
```

Expected: two `Snapshot taken` lines.

- [ ] **Step 9: Commit**

```powershell
git add lab/win01/ lab/runbook/win01.md
git commit -m "feat: Sysmon lab config and Wazuh agent enrollment for WIN01"
```

---

### Task 6: UC-00 — File Integrity Monitoring warm-up

**Files:**
- Create: `lab/cases/uc-00-fim.md`
- Modify: `lab/cases/exercise-log.md` (create with the first entries)

**Interfaces:**
- Consumes: syscheck config on WIN01 (Task 5), SOC01 running (S1)
- Produces: proven end-to-end pipeline (host change -> agent -> manager -> alert), the first portfolio use case doc

- [ ] **Step 1: Power on in S1 order**

Start SOC01. Wait for the API to answer:

```bash
curl -ks -u admin:<PASS> https://127.0.0.1:55000/healthcheck
```

Expected: JSON health report. Then start WIN01 and log in.

- [ ] **Step 2: Create the monitored file**

On WIN01 (admin PowerShell):

```powershell
New-Item -ItemType Directory -Path C:\lab\critical -Force | Out-Null
Set-Content -Path C:\lab\critical\secret.txt -Value "lab-secret-v1"
```

Expected: file exists. Wazuh's first scan (within minutes) reports the add as rule 554 (`File added to the system`).

- [ ] **Step 3: Run the modification test**

```powershell
Set-Content -Path C:\lab\critical\secret.txt -Value "lab-secret-v2"
```

Expected: on SOC01, within the syscheck frequency window:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json
```

Watch for an alert whose decoded path is `C:\lab\critical\secret.txt` with rule 550 (`Integrity checksum changed`). Expected fields in the JSON: `"syscheck": {"path": "C:\\lab\\critical\\secret.txt", "event": "modified"}`.

- [ ] **Step 4: Verify in the dashboard**

Host browser -> Wazuh dashboard -> Discover -> search `rule.id:550 and agent.name:win01`. Expected: the modification alert with a timestamp and the file path. Screenshot it to `lab/evidence/uc-00-alert.png`.

- [ ] **Step 5: Run the benign control**

Read the file without changing it:

```powershell
Get-Content C:\lab\critical\secret.txt
```

Expected: no new rule-550 alert for that minute in `alerts.json`; only the earlier modification remains. Record the negative result in the exercise log.

- [ ] **Step 6: Cleanup**

Restore the file content:

```powershell
Set-Content -Path C:\lab\critical\secret.txt -Value "lab-secret-v1"
```

Expected: a second rule-550 alert (which is itself evidence of FIM working). Note it in the log.

- [ ] **Step 7: Write the use case doc**

Create `lab/cases/uc-00-fim.md`:

```markdown
# UC-00 — File Integrity Monitoring warm-up

Status: PASS (fill after running)

## Hypothesis
A change to a monitored lab file is visible in Wazuh without any third guest.

## Prerequisites
- S1 powered on: SOC01 + WIN01
- Wazuh agent syscheck watching C:\lab\critical (lab/win01/ossec.conf.additions.xml)

## Test procedure
1. Create C:\lab\critical\secret.txt with content lab-secret-v1
2. Edit the file to lab-secret-v2

## Expected
- Rule 554 on file add
- Rule 550 on modification, fields: agent.name=win01, syscheck.path=C:\lab\critical\secret.txt, syscheck.event=modified

## Observed
(fill: alert ids, timestamps, JSON excerpt)

## Benign control
Read-only access: Get-Content. Result: no alert (expected).

## Cleanup
File content restored; restore produces its own 550 as verification.
```

- [ ] **Step 8: Update the exercise log**

Create `lab/cases/exercise-log.md`:

```markdown
# Exercise log

| Date | Exercise | Expected | Observed | Cleanup done |
|---|---|---|---|---|
| fill | UC-00 FIM modify | rule 550 on secret.txt | fill | yes/no |
| fill | UC-00 benign read | no alert | fill | n/a |
```

- [ ] **Step 9: Commit**

```powershell
git add lab/cases/
git commit -m "docs: UC-00 FIM use case doc and exercise log"
```

---

### Task 7: UC-01 — T1003.001 LSASS credential access

**Files:**
- Create: `lab/soc01/local_rules.xml`
- Create: `lab/cases/uc-01-t1003-lsass.md`
- Modify: `lab/cases/exercise-log.md`, `lab/runbook/win01.md` (lab controls log row)

**Interfaces:**
- Consumes: Sysmon EID 10 lsass events flowing (Task 5), S1 power-on (Task 6), snapshot `base-phase1`
- Produces: custom Wazuh rule 100010 firing on the simulation, UC-01 pass per spec §8, portfolio centerpiece doc

- [ ] **Step 1: Confirm the parent Sysmon rule id on SOC01**

```bash
grep -n "Process accessed" /var/ossec/ruleset/rules/0915-sysmon_rules.xml | head -3
```

Expected: a rule block for Sysmon Event 10. Open the file around that line and note its `<rule id="...">`. In Wazuh 4.14 this is expected to be `61610`. If the id differs, substitute it for `61610` in the rule below.

- [ ] **Step 2: Write the custom rule in the repo**

Create `lab/soc01/local_rules.xml`:

```xml
<group name="lab,">
  <rule id="100010" level="12">
    <if_sid>61610</if_sid>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe$</field>
    <field name="win.eventdata.sourceImage" type="pcre2">(?i)rundll32\.exe$</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">(?i)^0x(1010|1410|1438|1fffff)$</field>
    <description>LAB: LSASS access by rundll32 (T1003.001 simulation) - target $(win.eventdata.targetImage) source $(win.eventdata.sourceImage)</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>credential_access,lab,sysmon_process_access,</group>
  </rule>
</group>
```

The three field constraints together (dump-class access mask + rundll32 source + lsass target) keep the false-positive surface to backup/AV tools, which is exactly what the FP discussion in the case doc covers.

- [ ] **Step 3: Deploy the rule on SOC01**

Create the same file on SOC01 (type it into an editor, matching the repo copy byte-for-byte):

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Replace the file content with the rule above (keeping the XML header line the stock file starts with: `<!-- Local rules -->`), then:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Expected: `active`.

- [ ] **Step 4: Confirm the rule file loaded without errors**

```bash
sudo grep -iE "error|invalid" /var/ossec/logs/ossec.log | tail -5
sudo grep -c "100010" /var/ossec/etc/rules/local_rules.xml
```

Expected: no new error lines after the restart; the second command prints `1` (the rule id appears once in the deployed file). Full chain verification happens with the real event in Step 8, which exercises decode -> parent rule 61610 -> child rule 100010.

- [ ] **Step 5: Snapshot WIN01 (powered off) for the exercise**

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" snapshot WIN01 take pre-uc01 --description "clean state before T1003.001 test"
```

Expected: `Snapshot taken. UUID: ...`

- [ ] **Step 6: Run the simulation**

On WIN01, admin PowerShell, in this exact order:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
New-Item -ItemType Directory -Path C:\lab\dumps -Force | Out-Null
$lsassPid = (Get-Process lsass).Id
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $lsassPid C:\lab\dumps\lsass_lab.dmp full
Start-Sleep 8
Set-MpPreference -DisableRealtimeMonitoring $false
```

Expected: no console output from rundll32; `C:\lab\dumps\lsass_lab.dmp` exists and is large (tens of MB). Record the Defender disable/re-enable in `lab/runbook/win01.md` lab controls log.

- [ ] **Step 7: Verify the source event**

```powershell
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=10} |
  Where-Object { $_.Message -like "*lsass*" } | Select-Object -First 2 TimeCreated, Message
```

Expected: an EID 10 with `TargetImage: C:\Windows\System32\lsass.exe`, `SourceImage: ...\rundll32.exe`, `GrantedAccess: 0x1fffff` (or one of the other masks). Screenshot to `lab/evidence/uc-01-sysmon-eid10.png`.

- [ ] **Step 8: Verify the Wazuh alert**

On SOC01:

```bash
sudo grep "100010" /var/ossec/logs/alerts/alerts.json | tail -1
```

Expected: an alert with `"rule":{"id":"100010","level":12,...}`, MITRE `T1003.001`, and the `win.eventdata` fields present. Also check the dashboard: Discover -> `rule.id:100010`. Screenshot to `lab/evidence/uc-01-alert.png`.

- [ ] **Step 9: Reproducibility — second run**

Repeat the three command lines of Step 6 (Defender toggle + MiniDump). Expected: a second rule-100010 alert, distinct timestamp. If the rule fires only once, investigate the grantedAccess value of the second run (it can differ by run); if so, extend the mask list in `local_rules.xml`, redeploy, and re-test.

- [ ] **Step 10: Benign control**

Start Notepad, close it. Expected: Sysmon EID 1 events arrive (rule 61601) but no rule 100010 appears for that minute. Record the negative in the exercise log.

- [ ] **Step 11: Cleanup and revert**

```powershell
Remove-Item C:\lab\dumps -Recurse -Force
Get-MpPreference | Select-Object DisableRealtimeMonitoring
```

Expected: dump directory gone; `DisableRealtimeMonitoring` shows `False` (restored). Then power off WIN01 and revert:

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" snapshot WIN01 restore pre-uc01
```

Expected: progress bar, guest back to pre-test state. Delete the dump evidence note in the exercise log if the revert removed it from the guest — the screenshot stays in `lab/evidence/`.

- [ ] **Step 12: Write the case doc**

Create `lab/cases/uc-01-t1003-lsass.md`:

```markdown
# UC-01 — T1003.001 OS Credential Dumping: LSASS Memory

Status: PASS (fill after running)

## Hypothesis
A local admin living-off-the-land LSASS dump is detectable from Sysmon process-access
telemetry, without malware and without a domain.

## Detection logic
- Source: Sysmon Event ID 10 (ProcessAccess), rule 61610 parent
- Custom rule 100010: targetImage lsass.exe + sourceImage rundll32.exe + grantedAccess
  in {0x1010, 0x1410, 0x1438, 0x1fffff}
- Level 12, group credential_access, MITRE T1003.001

## Prerequisites
- S1 powered on; Sysmon EID 10 logging lsass only (lab/win01/sysmon-config.xml)
- Lab control: Defender real-time protection disabled for the test window only
  (see lab/runbook/win01.md lab controls log)

## Test procedure
1. Snapshot pre-uc01
2. Defender off
3. rundll32.exe comsvcs.dll, MiniDump <lsass pid> C:\lab\dumps\lsass_lab.dmp full
4. Defender on

## Expected vs observed
(fill: source event fields, alert id 100010 fields, timestamps, run 1 and run 2)

## Benign control
Notepad start/stop: no rule 100010 (expected).

## False positives
Backup agents and AV touching LSASS appear as different sourceImage values; the rule
constrains sourceImage to rundll32.exe, so those do not match. Widening the rule is
discussed here only as future work, never done silently.

## Cleanup
Dump deleted; Defender re-enabled; WIN01 reverted to pre-uc01 snapshot.
```

- [ ] **Step 13: Commit**

```powershell
git add lab/soc01/local_rules.xml lab/cases/ lab/runbook/win01.md
git commit -m "feat: UC-01 T1003.001 detection rule and case doc"
```

---

### Task 8: Milestone 1 wrap-up

**Files:**
- Modify: `lab/README.md` (current state section)
- Modify: `lab/cases/exercise-log.md` (final entries)
- Modify: `lab/evidence/README.md` if evidence layout changed

**Interfaces:**
- Consumes: UC-00 and UC-01 both passing (Tasks 6–7)
- Produces: milestone 1 declared complete per spec §8 pass conditions

- [ ] **Step 1: Final gate G1 run**

With S1 powered on, repeat the three G1 checks from Task 3 Step 7 and log them. Expected: still `green`, `heap.percent` < 75, >= 300 MB headroom after both use cases.

- [ ] **Step 2: Verify both use case pass conditions against the spec**

UC-00: alert 550 with path/agent/timestamp, benign read silent, cleanup done.
UC-01 (spec §8): (1) EID 10 on WIN01, (2) same event searchable in Wazuh with targetImage/grantedAccess/sourceImage, (3) rule fired on two runs, (4) benign control silent, (5) exercise log has expected vs observed + timestamps + Defender lab control.

- [ ] **Step 3: Export evidence**

Confirm `lab/evidence/` holds at least: `uc-00-alert.png`, `uc-01-sysmon-eid10.png`, `uc-01-alert.png`. Export alert JSONs from SOC01:

```bash
sudo grep "100010\|550" /var/ossec/logs/alerts/alerts.json | tail -20 > /tmp/milestone1-alerts.jsonl
```

Then copy `/tmp/milestone1-alerts.jsonl` content into `lab/evidence/milestone1-alerts.jsonl` via clipboard (host-side), stripping nothing. Expected: file committed with real alert content, no secrets (alerts contain lab hostnames only).

- [ ] **Step 4: Finalize the exercise log**

Add the final two rows for UC-01 (run 1, run 2, benign) with observed alert ids and timestamps. Mark UC-00 and UC-01 statuses PASS in their docs. Do not claim anything that the log does not show.

- [ ] **Step 5: Update lab README current state**

Replace the "Current state" section of `lab/README.md` with:

```markdown
## Current state

Milestone 1 COMPLETE: SOC01 + WIN01 (S1) detect UC-00 FIM and UC-01 T1003.001.
Evidence in evidence/, use cases in cases/. Next: Phase 2 identity (DC01, S2).
```

- [ ] **Step 6: Commit**

```powershell
git add lab/
git commit -m "docs: milestone 1 wrap-up, evidence, exercise log final"
```

---

## Self-review notes

- Spec §2/§5/§6 constraints -> Global Constraints section + Task 2 (5 GB/3 vCPU/50 GB) + Task 4 (4 GB/2 vCPU/40 GB) + every power-on instruction uses S1 only.
- Spec §7 Phase 0 -> Task 2 Steps 1-7 (host-only net, int-corp, isolation). Phase 1 -> Tasks 3-8.
- Spec §8 UC-00 -> Task 6; UC-01 -> Task 7 (rule 100010 level 12, MITRE, pass conditions); benign controls in Tasks 6-7.
- Spec §12 G1 -> Task 3 Step 7 and Task 8 Step 1. G2 is Phase 3, out of scope for this plan.
- Spec §10 security rules -> no secrets committed (runbook placeholders), Defender control logged, dump deleted, snapshots before/after, NAT detached after checklists.
- Divergence risk noted in-plan: parent rule id 61610 must be confirmed (Task 7 Step 1); Sysmon schemaversion must match the downloaded binary (Task 5 Step 2).
