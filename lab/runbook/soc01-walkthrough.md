# SOC01 — the SIEM, explained step by step

> Companion to the terse `soc01.md` runbook and the command-only `setup.md` §1.
> This doc teaches the *what* and *why* behind each step, so you can read it like a lesson.

## 1. What this box is

**SOC01 is the lab's brain — the security operations center in a VM.** It runs **Wazuh**, an
open-source **SIEM** (Security Information and Event Management) platform.

Think of it as the building's security desk:

- Every other machine (DC01, WIN01) runs a small **agent** that reports back to SOC01.
- SOC01 **collects** all those log events, **analyzes** them against detection rules, and **raises
  alerts** when something matches an attack pattern.
- You view those alerts in a web dashboard.

That's the SIEM model in one line: **agents ship logs → manager correlates → dashboard displays.**

| Box | Role |
|---|---|
| **SOC01** (`10.10.10.5`) | Wazuh SIEM — collects logs from all agents, runs detection rules, shows the dashboard |
| **DC01** (`10.10.10.10`) | Domain controller — sends its auth/Kerberos logs to SOC01 |
| **WIN01** (`10.10.10.20`) | Windows workstation — sends its Sysmon/security logs to SOC01 |

## 2. The big idea: what a SIEM is for

A single computer's log file tells you very little. The power of a SIEM comes from **correlation**:
when DC01's Kerberos log says "3 failed logons in 60 seconds for the same account" — that's only
visible when you *collect and count across events*. SOC01 does three jobs:

1. **Collect** — agents push logs up (or the manager pulls them).
2. **Detect** — rules match event fields against attack patterns (e.g. "wrong password ×3").
3. **Alert** — matched rules become alerts in the dashboard, ranked by severity (level 3 = info,
   level 12 = critical).

The detection rules are where *you* do the interesting work — everything else is plumbing.

## 3. Step 0 — Create the VM

Standard VirtualBox Ubuntu guest. Three NICs at first:

- **Host-only** adapter → `10.10.30.10` (the *management* network — how you reach SOC01 from your
  Windows host for SSH).
- `int-corp` → `10.10.10.5` (the *lab* network — where SOC01 talks to DC01/WIN01).
- `nat` → temporary internet during provisioning only (detached before snapshot).

```powershell
VBoxManage createvm --name SOC01 --ostype Ubuntu_64 --register
VBoxManage modifyvm SOC01 --memory 5120 --cpus 3 --vram 16
VBoxManage modifyvm SOC01 --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter #2"
VBoxManage modifyvm SOC01 --nic2 intnet --intnet2 int-corp --nic3 nat
VBoxManage createmedium disk --filename C:\lab-vms\SOC01\soc01.vdi --size 51200
VBoxManage storagectl SOC01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach SOC01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\SOC01\soc01.vdi
VBoxManage storageattach SOC01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\ubuntu-24.04.5-live-server-amd64.iso
VBoxManage startvm SOC01
```

**Important host prerequisite (see `setup.md` §0):** VirtualBox's host-only networking fails with
`VERR_INTNET_FLT_IF_NOT_FOUND` while the Windows hypervisor stack (Hyper-V / WSL2 / Docker) is active.
You must disable Memory Integrity and `bcdedit /set hypervisorlaunchtype off` first.

## 4. Step 1 — Install Ubuntu

Ubuntu Server 24.04.5, user `socadmin`, OpenSSH enabled. Then static IPs:

```bash
sudo netplan apply   # enp0s3 -> 10.10.30.10 (host-only/mgmt), enp0s8 -> 10.10.10.5 (int-corp)
sudo apt install -y curl jq tmux htop net-tools iputils-ping
```

Why two static IPs? SOC01 lives in **two networks** on purpose: the host-only network so *you* can
SSH into it from your Windows host, and `int-corp` so it can reach the lab machines it monitors.

## 5. Step 2 — Install Wazuh (the big one)

Wazuh 4.14.x ships as a single "all-in-one" installer that lays down **four components**:

| Component | What it is | Port |
|---|---|---|
| **wazuh-indexer** | The database (OpenSearch) that stores events & alerts | 9200 |
| **wazuh-manager** | The brain — runs detection rules, ingests agent logs | 1514/1515 |
| **wazuh-dashboard** | The web UI you view alerts in | 443 |
| **filebeat** | Pipes manager alerts into the indexer | — |

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh --generate-config-files
sudo bash wazuh-install.sh --wazuh-indexer node-1    # then --start-cluster
sudo bash wazuh-install.sh --wazuh-server wazuh-1
sudo bash wazuh-install.sh --wazuh-dashboard dashboard
```

The installer prints a set of admin passwords at the end — **save them**, they're not recoverable.

The `generate-config-files` step produces a `config.yml` used by the later steps; this is why the
install is run in phases, not one command.

## 6. Step 3 — Tuning (why the lab doesn't OOM)

An all-in-one SIEM on 5 GB of guest RAM is tight. We tune two things:

```bash
# indexer heap -> 1 GB (the default is larger and exhausts RAM)
# in /etc/wazuh-indexer/jvm.options:  -Xms1g  -Xmx1g

# log every alert to JSON (needed for direct indexer queries later)
# in /var/ossec/etc/ossec.conf (first <global> block):  <logall_json>yes</logall_json>
```

Also two ISM retention policies keep the indexer from growing forever:
`lab_retention` (alerts kept 7 days) and `lab_archives_retention` (30 days).

**OOM note (from `soc01.md`):** if the indexer is starved during a test, `systemctl stop
wazuh-dashboard` frees ~1 GB instantly. That's expected, not a crash.

## 7. Step 4 — Isolate and snapshot

Detach the NAT adapter (seal the lab) and snapshot:

```powershell
VBoxManage controlvm SOC01 acpipowerbutton
VBoxManage modifyvm SOC01 --nic3 none
VBoxManage snapshot SOC01 take base-soc01
```

Note: the indexer takes ~90 s to reach `active` after every boot — wait before checking health.

## 8. How events flow through SOC01 (recap)

```
[DC01/WIN01] --agent--> :1514 --> wazuh-manager (analysisd runs rules)
                                    |
                                    v
                              alerts.json (local file, every alert)
                                    |
                                    v  (filebeat)
                              wazuh-indexer (OpenSearch, searchable)
                                    |
                                    v
                              wazuh-dashboard (you)
```

Two ideas worth remembering:

- **`alerts.json` vs the indexer** — the manager writes every alert to a local `alerts.json` file
  *and* ships it to the indexer. Low-level events (below `log_alert_level`) stay in `archives.json`
  and never reach the indexer. So when debugging, check `alerts.json` first — it's the ground truth.
- **Alert rotation** — Wazuh rotates `alerts.json` daily (to `ossec-alerts-<day>.json.gz`), so
  yesterday's alerts aren't in `alerts.json` anymore. Use `zgrep` for older days.

## 9. The agents (how SOC01 sees the lab)

Each monitored box enrolls with the manager and gets an **agent ID**:

| Agent ID | Host | Sends |
|---|---|---|
| 000 | SOC01 | its own syslog (sudo, etc.) |
| 001 | WIN01 | Sysmon EID 1/10, Windows FIM |
| 002 | DC01 | Samba auth JSON + Kerberos KDC text + AD-database FIM |

Enrollment on the agent side looks like:
```bash
sudo WAZUH_MANAGER='10.10.10.5' WAZUH_AGENT_NAME='dc01' dpkg -i wazuh-agent_4.14.8-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

## 10. The detection rules (where you add value)

SOC01's rules live in `/var/ossec/etc/rules/`. We add our custom rules to `local_rules.xml`
(see `lab/soc01/local_rules.xml`). A rule is an XML block matching event fields to a severity:

| Rule | Detects | Technique |
|---|---|---|
| 100010 | LSASS access by rundll32 | T1003.001 |
| 100020 | PowerShell `-enc` encoded command | T1059.001 |
| 100029 | failed domain logon | T1110 |
| 100030 | 3+ failed logons / 60s | T1110 |
| 100031 | successful domain logon | (situational) |
| 100032 | AD database modified (FIM) | T1565.001 |
| 100033 | Kerberoasting (TGS-REQ `MSSQLSvc`) | T1558.003 |
| 100034 | AS-REP roasting (pre-auth-less AS-REQ) | T1558.004 |

**Rule XML gotcha (the big one):** `if_sid`, `if_group`, `if_matched_sid`, and `same_field` are
**child elements**, not `<rule>` attributes. Getting this wrong silently breaks the rule:

```xml
<!-- CORRECT -->
<rule id="100030" level="12" frequency="3" timeframe="60">
  <if_matched_sid>100029</if_matched_sid>
  <same_field>Authentication.mappedAccount</same_field>
  ...
</rule>
```

## 11. Gotchas we hit (the interesting lessons)

- **Clock skew (recurring):** no NTP, so after any VM savestate/shutdown, SOC01's `date` drifts —
  and it stops collecting (or mis-timestamps) events. Always check `date` on every VM first after a
  resume.
- **The indexer returns `yellow` cluster health forever:** a single unassigned replica of a tiny
  system index (`.opendistro-ism-config`) that the admin account can't modify. Harmless — all *data*
  indices are green. Treat `yellow` as healthy here.
- **`wazuh-logtest` can't test some decoder chains:** modern Windows eventchannel decoding runs inside
  `analysisd` with agent context, so rules keyed on those groups never match in `logtest`. Verify with
  real events and a clean manager restart instead.
- **Dashboard save error 1113:** a raw `"` character inside a rule's regex breaks the dashboard's XML
  upload. Use PCRE2 hex escapes (`\x22`/`\x27`) instead of literal quotes.
- **Every `sudo` on SOC01 becomes an alert** (rule 5402) that records the *command text* — so grepping
  `alerts.json` for a rule id can "self-match" your own grep command. Prefer `jq` filters.

## 12. How to test it yourself

1. Confirm the manager is healthy:
   ```bash
   sudo /var/ossec/bin/wazuh-control status          # all daemons "running"
   sudo curl -ks https://127.0.0.1:9200/_cluster/health?pretty
   ```
2. Confirm agents are connected:
   ```bash
   sudo /var/ossec/bin/agent_control -l              # agents 000/001/002 active
   ```
3. Open the dashboard in your host browser: `https://10.10.30.10`, log in with the admin password,
   and check **Threat Hunting** (or Security Events) for the latest alerts.
