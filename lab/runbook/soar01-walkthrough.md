# SOAR01 — the automation box, explained step by step

> Companion to the terse `soar01.md` runbook and the command-only `setup.md` §5.
> This doc teaches the *what* and *why* so you can read it like a lesson.

## 1. What this box is

**SOAR01 is the lab's hands.** Where SOC01 (the SIEM) *detects* and NDR01 *watches the wire*,
SOAR01 **acts on a detection automatically**. It runs **n8n**, an open-source workflow engine, in a
Docker container. When Wazuh raises a specific alert, n8n takes over: it enriches the alert with
threat intelligence and writes the results — no human in the loop.

This is the difference between *detection* and *response*:

- A SIEM alert that nobody acts on is just a log line.
- A **SOAR** (Security Orchestration, Automation and Response) playbook turns that alert into
  repeatable, automated steps: enrich → decide → record/notify.

| Box | Role |
|---|---|
| **SOAR01** (`10.10.30.20`) | n8n automation — receives alert, enriches with VirusTotal, writes incident |
| **SOC01** (`10.10.10.5`) | SIEM — evaluates rules and triggers the integration |
| **WIN01** (`10.10.10.20`) | Endpoint — Sysmon EID 22 produces the DNS telemetry |

## 2. The big idea: a push bridge, not polling

Wazuh doesn't wait for n8n to ask "any new alerts?". Instead, Wazuh **pushes** the alert to n8n the
moment rule 100047 fires. The mechanism is a Wazuh **integration** (`integratord`):

1. A rule matches → Wazuh writes an alert.
2. `integratord` sees the alert matches the integration's `rule_id` (100047) and runs the integration.
3. The integration POSTs the **full alert JSON** to `http://10.10.30.20:5678/webhook/soar`.
4. n8n's Webhook node wakes the workflow.

Two design points worth remembering:

- The integration is **scoped to a rule id**, not "all alerts". That's the triage filter — only the
  high-value detection reaches automation.
- The whole alert is forwarded, so n8n has everything (rule, agent, Sysmon `queryName`, timestamp).

## 3. Step 0 — create the VM

A small Ubuntu guest on the **host-only** management network (so the host can SSH to it directly), plus
a temporary NAT adapter for install-time internet and, later, the VirusTotal call.

```powershell
VBoxManage createvm --name SOAR01 --ostype Ubuntu_64 --register
VBoxManage modifyvm SOAR01 --memory 2048 --cpus 1 --vram 16
VBoxManage modifyvm SOAR01 --nic1 hostonly --hostonlyadapter1 "VirtualBox Host-Only Ethernet Adapter #2" `
  --nic2 nat --natpf2 "ssh,tcp,127.0.0.1,2224,,22"
VBoxManage createmedium disk --filename C:\lab-vms\SOAR01\soar01.vdi --size 20480
VBoxManage storagectl SOAR01 --name SATA --add sata --controller IntelAhci --bootable on
VBoxManage storageattach SOAR01 --storagectl SATA --port 0 --device 0 --type hdd --medium C:\lab-vms\SOAR01\soar01.vdi
VBoxManage storageattach SOAR01 --storagectl SATA --port 1 --device 0 --type dvddrive --medium C:\iso\ubuntu-24.04.5-live-server-amd64.iso
VBoxManage startvm SOAR01
```

- Host-only = management plane (the host reaches `10.10.30.20` directly; no hop needed).
- NAT = internet for Docker/n8n image pulls and the VirusTotal API. It is a **demo-only exception** and
  is detached before the snapshot.

## 4. Step 1 — install Ubuntu

Ubuntu Server 24.04.5 minimal, user `soaradmin`, OpenSSH enabled. Full disk (no LVM).

## 5. Step 2 — static IP + a stable clock

```bash
# netplan: enp0s3 -> 10.10.30.20/24  (host-only management)
sudo netplan apply
```

No NTP in the lab. Linux guests freeze their clock while the host sleeps, so after any resume:

```bash
date -u                       # compare with the host
sudo timedatectl set-ntp off
sudo timedatectl set-time 'YYYY-MM-DD HH:MM:SS'
sudo docker restart n8n       # timestamps in new executions stay sane
```

## 6. Step 3 — Docker Engine

n8n runs as a container so it is reproducible and isolated. Install Docker Engine 29.x from Docker's
apt repo, then confirm:

```bash
docker --version
```

## 7. Step 4 — the n8n container

```bash
sudo mkdir -p /srv/soar/{incidents,notifications} /srv/n8n
sudo chmod -R 777 /srv/soar          # the container writes here as its own user

sudo docker run -d --name n8n --restart unless-stopped \
  -p 5678:5678 \
  -v /srv/soar:/srv/soar \
  -v /srv/n8n:/home/node/.n8n \
  -e EXECUTIONS_DATA_PRUNE=true -e EXECUTIONS_DATA_MAX_AGE=168 \
  -e N8N_METRICS=false -e N8N_SECURE_COOKIE=false \
  -e NODE_FUNCTION_ALLOW_BUILTIN=fs \
  n8nio/n8n:latest
```

Why each piece:

- **`-p 5678:5678`** — the web UI and the webhook both listen here.
- **`/srv/soar`** — the *output* directory: incidents, notifications, audit. Bind-mounted so the files
  live on the VM (inspectable, persistent across container rebuilds).
- **`/srv/n8n`** — n8n's own data (SQLite DB, credentials). Mounting it preserves workflows/credentials.
- **`NODE_FUNCTION_ALLOW_BUILTIN=fs`** — lets Code nodes `require('fs')` so they can write the files.
  (The 1.x `N8N_CODE_ENABLE_BUILTIN_MODULES` variable is ignored in 2.x — a real gotcha.)
- **SQLite, queue off** — this is a single-node, low-volume lab; the default embedded DB is enough.

## 8. Step 5 — the workflow (7 nodes)

The workflow is exported in `lab/soar01/workflow.json` and documented in `lab/soar01/workflow.md`.
The node chain:

1. **Webhook** (`POST /soar`) — the trigger; Wazuh POSTs the alert here.
2. **extract** (Code) — pulls `domain` out of the alert. The alert is under `json.body`, and the Sysmon
   field is `data.win.eventdata.queryName`.
3. **vt-lookup** (HTTP Request) — `GET https://www.virustotal.com/api/v3/domains/{{ $json.domain }}`
   with a Header-Auth credential (`x-apikey`). Adds `last_analysis_stats` + `reputation`.
4. **build-incident** (Code) — merges alert + VT verdict into an `incident`, a `notification`, and an
   `audit` object (severity derives from the VT malicious count).
5. **write-incident** (Code + fs) — writes `/srv/soar/incidents/<alert-id>.json`.
6. **write-notification** (Code + fs) — writes `/srv/soar/notifications/latest.json`.
7. **write-audit** (Code + fs) — appends a line to `/srv/soar/audit.log`.

The "safe action" is intentionally **non-destructive**: notify + record only. No blocking, no host
isolation. For a learning lab that's the right default — you see the automation without breaking the VM.

## 9. Step 6 — the Wazuh → n8n bridge (SOC01)

On SOC01, an integration block in `/var/ossec/etc/ossec.conf`:

```xml
<integration>
  <name>custom-forward-to-n8n</name>
  <hook_url>http://10.10.30.20:5678/webhook/soar</hook_url>
  <rule_id>100047</rule_id>
  <api_key>lab</api_key>
</integration>
```

and the script `custom-forward-to-n8n` in `/var/ossec/integrations/`. In Wazuh 4.14 the script receives
`$1` = alert-JSON file path, `$2` = api_key, `$3` = hook_url; custom integrations **must** be named
`custom-*`. Restart `wazuh-manager` and confirm in `ossec.log`:
`Enabling integration for: 'custom-forward-to-n8n'`.

## 10. Step 7 — isolate + snapshot

```powershell
VBoxManage controlvm SOAR01 acpipowerbutton
VBoxManage modifyvm SOAR01 --nic2 none        # detach NAT (VT is demo-only)
VBoxManage snapshot SOAR01 take base-phase4
VBoxManage startvm SOAR01 --type headless
```

After detaching NAT, SOAR01 has **no internet**. That's deliberate: the automation still runs, but the
VirusTotal call needs NAT re-attached temporarily for a live demo.

## 11. How a detection flows (recap)

```
WIN01 Sysmon EID 22 (DnsQuery malware.wicar.org)
        |
        v  Wazuh agent 001
SOC01 manager -> rule 100047 (level 12, T1071.004)
        |
        v  integratord (rule_id 100047)
custom-forward-to-n8n --> POST http://10.10.30.20:5678/webhook/soar
        |
        v
n8n: webhook -> extract -> VT lookup -> build-incident -> write files
        |
        v
/srv/soar/incidents/<id>.json + notifications/latest.json + audit.log
```

Key idea: **Wazuh decides *that* it matters; n8n decides *what to do about it*.** The alert is the
contract between them — a single JSON document.

## 12. How to test it yourself

1. Confirm the webhook is live (from SOAR01): `curl -s http://localhost:5678/webhook/soar` should say
   "This webhook is not registered for GET requests" (i.e. it *is* registered for POST).
2. On WIN01 (elevated): disable Defender RT, flush, then
   `Resolve-DnsName -Type A malware.wicar.org` (timeout expected).
3. On SOC01: rule **100047** should appear; `/var/ossec/logs/integrations.log` should show
   `custom-forward-to-n8n: {"message":"Workflow was started"}HTTP:200`.
4. On SOAR01: check `/srv/soar/incidents/`, `notifications/latest.json`, `audit.log`.
5. Benign control: `Resolve-DnsName -Type TXT example.com` → event but **no** 100047 alert.

## 13. Gotchas we hit (the interesting lessons)

- **Publish, not just "active".** In n8n 2.x, flipping `active=1` in the DB does *not* register the
  webhook; publishing is an async pipeline. Use the UI Publish. A restart re-registers published flows.
- **Leading `=` on expressions.** Without it n8n sends `{{ }}` literally → VirusTotal 404.
- **Webhook body nesting.** The alert is at `json.body.data.win.eventdata...`.
- **`fs` needs the env var.** `NODE_FUNCTION_ALLOW_BUILTIN=fs`.
- **VT 404 kills the run.** Unknown domains error the HTTP node before the write steps — choose a
  domain VirusTotal knows.
- **Windows DNS cache is sticky.** The exact malicious name can be served from a negative cache that
  `ipconfig /flushdns` won't clear (and `dnscache` is protected) — reboot WIN01.
- **Defender can block the exact bad domain at the DNS layer** after a signature update, so Sysmon never
  logs it — disable RT (Tamper off) for the demo.

## 14. Snapshots

- `base-phase4` — Docker + n8n + published workflow, NAT detached, no demo runs.
