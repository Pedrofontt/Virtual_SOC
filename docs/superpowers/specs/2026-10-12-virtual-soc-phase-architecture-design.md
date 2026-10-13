# Virtual SOC Lab — Phase Architecture Design

Status: design, pending review
Date: 2026-10-12
Source brief: `docs/initial_info.md`
Source diagram: `docs/DFD.PNG` (logical zones kept; physical layout reduced for 16 GB)
Implementation scope of the first plan: Phase 0 and Phase 1 only

## 1. Purpose

Build a free, isolated, reproducible virtual SOC on a personal Windows PC. Success is not "tools installed". Success is a documented detection pipeline: simulated activity, source event, SIEM alert, evidence, and a repeatable procedure.

This design locks the resource model, what may be powered on together, the automation layer, and the first portfolio use case. Later phases are specified so they do not get redesigned, but they are not the first implementation plan.

## 2. Locked constraints

| Item | Value |
|---|---|
| Host CPU | AMD Ryzen 5 4600G, 6 cores / 12 threads |
| Host RAM | 16 GB |
| Free SSD | 241 GB |
| Cost | Zero. No paid licenses, no cloud exposure |
| Hypervisor | VirtualBox |
| Isolation | No bridged adapters. No inbound port forwards. Lab must not sit on the home LAN |

The CPU is not the bottleneck. SOC guests are bursty. RAM is the bottleneck. Disk growth from the Wazuh indexer is the second risk.

### Memory budget

| Consumer | Reservation |
|---|---|
| Windows host + VirtualBox + one browser | 5 GB, do not dip below this |
| All running guests combined | 11 GB ceiling |

If Task Manager shows the host committing near 16 GB, power off a guest. Do not "push through" swap. Swapping on this SSD makes alert timestamps lag and breaks the reproducibility criterion.

## 3. Decisions

| Decision | Choice | Why |
|---|---|---|
| Hypervisor | VirtualBox | Lightest zero-cost option. No account. Docker inside a Linux guest does not need nested virtualization |
| Analyst console | The Windows host, not a VM | The DFD admin laptop would burn 3–4 GB for no detection value |
| SIEM | Wazuh all-in-one single node on SOC01 | One guest instead of manager + indexer + dashboard VMs |
| Endpoint | Windows 11 Enterprise Evaluation + Wazuh agent + Sysmon | Windows 10 Eval ISOs were decommissioned after its Oct 2025 end of support. The Evaluation Center now offers Windows 11 only. VirtualBox 7 provides virtual TPM 2.0, EFI, and Secure Boot, which Windows 11 requires. 4 GB RAM + 2 vCPU is the Windows 11 minimum |
| Identity | Samba AD DC on DC01, domain `corp.lab` | Free. Phase 2 only. Not required for milestone 1 |
| SOAR | n8n on SOAR01, SQLite, single container | Shuffle's compose stack idles at 3–4 GB and breaks the 11 GB ceiling. n8n idles under 1 GB |
| NDR | Suricata on NDR01, not Security Onion | Security Onion wants 8–12 GB. Suricata is the sensor. Wazuh is the SIEM |
| EDR claim boundary | Wazuh agent + Sysmon only | Do not call this a commercial EDR. Velociraptor is deferred |
| Email (MAIL01) | Deferred, not in the success path | Proxmox Mail Gateway does not fit the first four phases |
| SRV01 | Deferred | No web server is required to prove detection |
| First use case | MITRE ATT&CK T1003.001 via Sysmon Event ID 10 | Highest-signal, single-host, no domain, no SOAR |
| Internet | NAT adapter attached only to install packages, then detached | Keeps the lab isolated after build |

### Rejected

- **Shuffle as the phase-4 SOAR.** Default stack is about 15 containers plus its own OpenSearch. Measured lab idle is 3–4 GB. SOC01 (5) + WIN01 (4) + Shuffle (4) = 13 GB, which forces host swap. Shuffle may be retried only if RAM is upgraded to 32 GB, or as a solo demo with WIN01 powered off. A solo demo cannot show detect-and-respond on the endpoint, so it fails the pipeline goal.
- **Security Onion as the NDR guest.** It is a distro, not a sensor, and it does not fit beside Wazuh.
- **Hyper-V.** Requires Windows Pro and complicates a Linux Docker guest. Rejected for "lightest and easiest".
- **A separate LAB-SEC L2 network in the first build.** Logical zone stays in the documentation. Physical path is two VirtualBox networks. Fewer NICs, fewer failure modes.

## 4. Logical zones vs physical networks

The DFD zones remain the language of the portfolio. They are not four virtual switches.

| Logical zone | What it means here | Physical attachment |
|---|---|---|
| LAB-CORP | Simulated company: identity, endpoint, later a server | Internal network `int-corp` |
| LAB-SEC | SIEM, sensor, automation | SOC01 and SOAR01 are reached on the host-only net. NDR01 sits on `int-corp` so it can see corp traffic, and ships events to SOC01 |
| LAB-MGMT | Analyst access to dashboards | Host-only `vboxnet0`. The analyst is the host |
| LAB-EDGE | Mail and Internet | Not built. NAT NIC exists only as a disconnected provisioning interface |

### Addressing

No VirtualBox DHCP on lab networks. Static addresses keep alert identities stable.

`vboxnet0` host-only, LAB-MGMT, `10.10.30.0/24`

| Node | Address | Role |
|---|---|---|
| Host | 10.10.30.1 | Analyst browser |
| SOC01 nic0 | 10.10.30.10 | Wazuh dashboard :443, API :55000 |
| SOAR01 nic0 | 10.10.30.20 | n8n :5678, phase 4 |

`int-corp` internal, LAB-CORP, `10.10.10.0/24`

| Node | Address | Role |
|---|---|---|
| SOC01 nic1 | 10.10.10.5 | Agent events :1514, enrollment :1515 |
| DC01 | 10.10.10.10 | Samba AD + DNS, phase 2. Domain `corp.lab`, NetBIOS `CORP` |
| WIN01 | 10.10.10.20 | Endpoint |
| SRV01 | 10.10.10.30 | Reserved, not built |
| NDR01 nic0 | 10.10.10.40 | Suricata, promiscuous mode Allow All, phase 3 |

Phase 1 agents use `10.10.10.5` directly. DNS is not a phase-1 dependency.

### Guest NICs

- SOC01: host-only + `int-corp` + NAT (detached after install)
- WIN01: `int-corp` + NAT (detached after install)
- DC01: `int-corp` + NAT (detached after install)
- NDR01: `int-corp` only, promiscuous Allow All. Install packages by temporary NAT, then remove that NIC or leave it disconnected
- SOAR01: host-only + temporary NAT

Promiscuous mode is set on NDR01's `int-corp` adapter to Allow All. Verification gate for phase 3: `tcpdump` on NDR01 must see a WIN01-to-SOC01 flow before Suricata rules are trusted. If that capture fails, fallback is inline: WIN01 default gateway becomes NDR01, NDR01 forwards to SOC01. Do not start with the inline design.

## 5. Guest matrix

Disks are VirtualBox dynamic VDI. Allocated size is a cap, not immediate use. Keep one snapshot per guest. Delete it after the milestone evidence is exported. Do not keep a snapshot of a running Wazuh indexer; snapshot SOC01 powered off.

| Guest | OS | vCPU | RAM | Disk cap | Phase |
|---|---|---|---|---|---|
| SOC01 | Ubuntu Server 24.04 LTS, Wazuh 4.14.x all-in-one | 3 | 5 GB | 50 GB | 1 |
| WIN01 | Windows 11 Enterprise Evaluation, Wazuh agent, Sysmon | 2 | 4 GB | 40 GB | 1 |
| DC01 | Ubuntu Server 24.04 LTS, Samba AD DC | 1 | 2 GB | 20 GB | 2 |
| NDR01 | Ubuntu Server 24.04 LTS, Suricata + Wazuh agent | 1 | 1 GB | 15 GB | 3 |
| SOAR01 | Ubuntu Server 24.04 LTS, Docker Engine, n8n | 1 | 2 GB | 20 GB | 4 |

Allocated disk cap for these five guests: 145 GB. Expected steady use is far lower. Leave the rest of the 241 GB for the host, one snapshot set, and exported evidence. No MAIL01 disk is reserved in the success path.

vCPU totals stay at or under 6 while a scenario is running. The host keeps the rest of the 12 threads. SOC01 gets 3 vCPU because the official quickstart recommends 4 for a single-host deployment and CPU is not the bottleneck here. Extra vCPU does not fix an indexer that is RAM-bound, so do not go to 4.

### SOC01 memory tuning (required, not optional)

On a 5 GB guest the indexer heap is capped:

- OpenSearch heap: `-Xms1g -Xmx1g`, verified in `/etc/wazuh-indexer/jvm.options`. The 4.14 install assistant is known to fall back to a 1 GB heap regardless of host RAM; confirm `Xms` and `Xmx` are equal at `1g` after install. 1 GB heap carries a handful of agents, which is this lab
- Single-node, zero replicas
- Index lifecycle: delete indices older than 7 days
- Alert archive: 30 days or 5 GB, whichever comes first
- If the indexer OOMs during phase-1 tuning, stop `wazuh-dashboard` inside the guest for the ingestion test. That frees about 1 GB inside SOC01. The host browser does not free guest RAM

Do not raise SOC01 to 6 GB while WIN01 and a third guest are on. 6 GB is allowed only for a phase-1 solo tuning window: SOC01 6 GB + WIN01 4 GB = 10 GB, third guests off.

## 6. Power-on scenarios

These are the only legal simultaneous sets. Anything else is out of policy until RAM changes.

| ID | Purpose | Guests on | Guest RAM | Fits 11 GB |
|---|---|---|---|---|
| S0 | Install or snapshot maintenance | one guest | ≤ 6 GB | Yes |
| S1 | Detect on the endpoint. Milestone 1 | SOC01 + WIN01 | 9 GB | Yes |
| S1-tune | Indexer needs more heap | SOC01 at 6 GB + WIN01 | 10 GB | Yes. No third guest |
| S2 | Identity correlation | SOC01 + WIN01 + DC01 | 11 GB | Yes, at the ceiling. Close extra host apps |
| S3 | Network detection | SOC01 + WIN01 + NDR01 | 10 GB | Yes. DC01 off |
| S4 | Detect and automated response | SOC01 + WIN01 + SOAR01 | 11 GB | Yes, at the ceiling. DC01 and NDR01 off |
| S5 | Shuffle, mail, Velociraptor, or SRV01 | not a supported set on 16 GB | — | No |

S4 is the minimum set that can simulate, detect, and respond without crashing the host. S1 is the minimum set that can simulate and detect. Milestone 1 uses S1 only.

Boot order: SOC01 first, wait until the API answers, then the other guests in that scenario. Shut down in reverse. Before every attack test, snapshot WIN01 powered on only if a revert is required mid-test; otherwise snapshot WIN01 powered off before the exercise and revert after evidence is copied out.

## 7. Phases

### Phase 0 — Host prep

VirtualBox installed. `vboxnet0` created at `10.10.30.0/24`. Internal network `int-corp` named and DHCP disabled. Host firewall does not need inbound rules; the analyst connects outbound to `10.10.30.10`. No guest is exposed to the home LAN.

Exit gate: host-only ping from the host to a temporary Linux guest on `10.10.30.10`, then that guest is removed or reused as SOC01.

### Phase 1 — Detection core (first implementation)

Build SOC01 and WIN01. Install Wazuh all-in-one. WIN01 must be created with VirtualBox guest type "Windows 11" so the wizard defaults to EFI, virtual TPM 2.0, and Secure Boot support, which the installer requires. After install, apply the 4 GB RAM fit tweaks: disable Memory Integrity / Core Isolation and transparency and animation effects. Install the Wazuh agent and the latest Sysmon on WIN01. Sysmon config must log Event ID 1 and Event ID 10, including access to `lsass.exe`. SwiftOnSecurity `sysmonconfig.xml` (or a documented subset of it) is the baseline config. Collect `Microsoft-Windows-Sysmon/Operational` and Security logs.

Detach NAT on both guests after install. Snapshot both powered off as `base-phase1`.

Exit gate: UC-00 and UC-01 pass. That is portfolio milestone 1.

### Phase 2 — Identity

Add DC01. Provision `corp.lab`. Join WIN01. Correlate endpoint activity with authentication events.

Exit gate: three failed logons then a success produce a Wazuh alert with both the endpoint and the domain identity in the evidence. A privileged group change produces a separate alert.

Power-on: S2. If the host swaps, drop WIN01 to a console session and close the host browser while DC provisioning runs. Do not add NDR01 or SOAR01.

### Phase 3 — NDR

Add NDR01. Suricata in IDS mode, not inline, unless the promiscuous-mode gate fails. A Wazuh agent on NDR01 forwards `eve.json`. No packet capture retention. A 1 GB pcap ring is allowed only while collecting evidence for one test, then deleted.

Exit gate: a lab-only HTTP User-Agent `lab-ndr-test` from WIN01 to SOC01 produces a custom Suricata alert (`sid` in the local range) visible in Wazuh. No public exploit traffic. No ET rule that requires a real attack tool.

Power-on: S3.

### Phase 4 — Automation

Add SOAR01. Docker Engine, not Docker Desktop. n8n in a single container, SQLite backend, queue mode off.

Required container settings:

- `EXECUTIONS_DATA_PRUNE=true`
- `EXECUTIONS_DATA_MAX_AGE=168`
- metrics off
- no extra workers

Wazuh sends the UC-01 alert JSON to `http://10.10.30.20:5678/webhook/...` over the host-only network. The playbook must:

1. Record the alert id, rule id, agent name, and timestamp
2. Enrich from a local test list or from fields already in the alert. No mandatory Internet lookup
3. Write an incident record to a local file or n8n data store
4. Take one safe action: tag the alert or send a local notification
5. Append an audit line with the action and the result

Destructive active response (disable account, isolate host, delete files) is out of scope until a separate design says otherwise. Human approval is required before any action that changes the endpoint.

VirusTotal or similar enrichment is a documented exception, not the default. It requires a lab API key that is not committed, a temporary NAT attach, and a note in the exercise log. Prefer the local enrichment path so the isolation rule stays intact.

Power-on: S4.

### Phase 5 — Explicitly not scheduled

MAIL01 (Proxmox Mail Gateway), SRV01, Velociraptor, and Shuffle. Each would replace another guest, not join S1–S4. They need their own design note before any install.

## 8. Milestone 1 use cases

Both run in S1. UC-00 exists so a broken Sysmon rule does not look like a broken pipeline.

### UC-00 — File integrity warm-up

| Field | Value |
|---|---|
| Hypothesis | A change to a monitored lab file is visible in Wazuh without any third guest |
| Prerequisite | Wazuh FIM watching `C:\lab\critical\secret.txt` |
| Test | Edit the file once |
| Expected source | Syscheck event on WIN01 |
| Expected alert | FIM modified alert in Wazuh with path, agent, and timestamp |
| Benign control | Read the file. Must not alert |
| Cleanup | Restore the file contents |

This use case is a pipeline test, not the portfolio centerpiece.

### UC-01 — T1003.001 LSASS access

| Field | Value |
|---|---|
| Hypothesis | A local admin living-off-the-land dump of LSASS is detectable from Sysmon process-access telemetry without malware and without a domain |
| Technique | T1003.001 OS Credential Dumping: LSASS Memory |
| Source | Sysmon Event ID 10 |
| Trigger | `rundll32.exe` calling `comsvcs.dll` MiniDump against the `lsass.exe` PID, inside WIN01 only |
| Lab control | Snapshot WIN01 first. Disable Defender real-time protection for the test window only, then re-enable it. Defender often kills this technique before Sysmon records it. The disablement is a lab control, documented in the exercise log, not a recommendation |
| Expected source fields | `targetImage` ends with `\lsass.exe`; `sourceImage` ends with `\rundll32.exe`; `grantedAccess` is a dump-class mask (`0x1010`, `0x1410`, `0x1438`, or `0x1fffff`); call trace references `comsvcs.dll` when present |
| Rule | Custom Wazuh rule if the stock rule does not match this exact chain. Level 12. Groups include `credential_access`. MITRE ID `T1003.001` |
| Expected alert | One alert per execution, with agent name, rule id, source image, target image, granted access, and timestamp |
| Benign control | A normal process start (Sysmon Event ID 1 for `notepad.exe`) must not match this rule |
| False positives to document | Backup agents and AV opening LSASS with different source images. Exclusion is by `sourceImage`, never by dropping all Event ID 10 |
| Cleanup | Delete the dump file, re-enable Defender, revert WIN01 to the pre-test snapshot |

Pass condition, all required:

1. WIN01 shows the Sysmon Event ID 10
2. The same event is searchable in Wazuh with the fields above
3. The rule fires on a second execution, not only the first
4. The benign control does not fire that rule
5. The exercise log records expected vs observed, timestamps, and the Defender lab control

### Next detections, not milestone 1

| ID | Phase | Technique | Why it waits |
|---|---|---|---|
| UC-02 | 1, after UC-01 | T1059.001 encoded PowerShell, Sysmon Event ID 1 plus PowerShell 4104 | Second rule on the same two guests. Do not block milestone 1 on it |
| UC-03 | 2 | Failed logons then a success, plus privileged group change | Needs DC01 and S2 |

## 9. Data flow

Phase 1:

1. Sysmon writes Event ID 10 on WIN01
2. Wazuh agent forwards it to SOC01 `10.10.10.5:1514`
3. Wazuh manager decodes it and runs the local ruleset
4. The indexer stores the alert
5. The analyst reads it from the host browser at `https://10.10.30.10`

Phase 4 adds one hop: Wazuh integration posts the alert JSON to n8n on `10.10.30.20`. n8n does not receive a copy of the raw Security log. It receives the alert.

Phase 3 adds a parallel source: Suricata writes `eve.json`, the NDR01 Wazuh agent forwards it, Wazuh alerts on the decoded Suricata event. NDR events are not required to reach n8n in the first automation demo.

## 10. Security rules for the lab

- Isolated from the home LAN and from any production system
- No intentionally vulnerable service exposed to the Internet
- Lab-only accounts and passwords. Never reuse a real credential
- No real malware. UC-01 is a living-off-the-land simulation in a snapshot-backed guest
- SOAR actions in this design cannot disable accounts, isolate hosts, or delete files
- Secrets, API keys, and tokens stay out of the git repo
- NAT is a provisioning exception. The exercise log notes when it was attached and when it was detached

## 11. Portfolio boundary

Document these limits next to the architecture so a recruiter is not misled:

- 16 GB forces phased power-on. This is not a 24/7 SOC
- Samba AD is not Windows Server AD
- Wazuh plus Sysmon is not a commercial EDR
- n8n is the automation layer because Shuffle does not fit. The integration pattern (alert JSON in, enrichment, case record, safe action, audit) is the skill being shown
- Suricata here is a single-segment IDS, not a full NDR platform
- Free-tool coverage is not commercial-product parity

## 12. Acceptance for this design

This design is accepted when the reviewer agrees with all of the following:

1. VirtualBox, two networks, five-guest maximum, 11 GB simultaneous ceiling
2. Milestone 1 is S1 only: SOC01 + WIN01, UC-00 then UC-01
3. n8n replaces Shuffle unless RAM changes
4. MAIL01, SRV01, Velociraptor, Security Onion, and a separate analyst VM are out of the first four phases
5. The first implementation plan covers Phase 0 and Phase 1 only

## 13. Out of scope for the first implementation plan

Phase 2–5 build steps, custom Suricata rule files, the n8n workflow JSON, Samba provisioning, and any host hardening beyond "no bridged NIC". Those get their own plan after milestone 1 passes.

## 14. Versions verified against official sources, October 2026

| Component | Verified state | Consequence for this design |
|---|---|---|
| Windows 10 Eval | Decommissioned from the Evaluation Center after Oct 14 2025 end of support. Only Windows 11 Eval remains, or Visual Studio subscriptions | WIN01 is Windows 11 Enterprise Evaluation, not Windows 10 |
| Windows 11 in VirtualBox | Requires UEFI, virtual TPM 2.0, Secure Boot support, 4 GB RAM, 2 vCPU. VirtualBox 7.x provides all of these | WIN01 profile locked at 4 GB / 2 vCPU with the guest type set to Windows 11 |
| Wazuh | Stable line 4.14.x as of Oct 2026; 5.0 still release candidate. Ubuntu 24.04 in the supported list (26.04 not listed) | Pin Wazuh 4.14.x on Ubuntu 24.04 LTS. Do not use the 5.0 RC in milestone 1 |
| Wazuh sizing | All-in-one minimum 4 GB / 2 cores; quickstart recommends 4 vCPU / 8 GB for 1–25 agents. Fresh install uses about 17 GB disk before agents | SOC01 5 GB / 3 vCPU / 50 GB is below the quickstart recommendation but above the minimum; acceptable for 1–3 agents at low EPS |
| n8n | Idle about 100 MB; example sizing 320 MB–2 GB; production guidance (Postgres, heavy workflows) suggests 4 GB | SOAR01 at 2 GB with SQLite and a single webhook workflow fits. Do not add Postgres or AI nodes |
| Suricata | Stable 8.0.x and maintained 7.0.x lines; Ubuntu PPA available. January 2026 security releases affect both lines | NDR01 uses the Ubuntu PPA and keeps the package updated; 1 GB RAM is enough for a lab ruleset in IDS mode |
| VirtualBox | 7.x is required for Windows 11 guests | Use latest 7.1.x |
