# Virtual SOC Lab — Phase 4 SOAR Design

Status: design, approved
Date: 2026-11-14
Source: `docs/superpowers/specs/2026-10-12-virtual-soc-phase-architecture-design.md` §7 (Phase 4), §4-5 (guests/networks)
Precedes: implementation plan (writing-plans)

## 1. Purpose

Add a SOAR layer (SOAR01 running n8n) that turns a high-fidelity Wazuh alert into an *incident*: receive the alert, enrich it against a third-party source (VirusTotal), persist an incident record, take one safe non-destructive action, and append an audit line. The portfolio story becomes "detect → enrich → respond", not just "detect".

The enrichment source is **real VirusTotal** (domain reputation), chosen over a local mock for credibility. The trigger is a **malicious-domain DNS lookup** detected on the endpoint (Sysmon EID 22), not the NDR sensor, so the S4 power budget (11 GB) is preserved with NDR01 off.

## 2. Locked constraints (inherited)

| Item | Value |
|---|---|
| Host RAM ceiling (all guests) | 11 GB |
| SOAR01 profile | Ubuntu Server 24.04 LTS, 1 vCPU / 2 GB / 20 GB, static `10.10.30.20` on host-only `vboxnet0`, temp NAT |
| Power-on | S4: SOC01 (5) + WIN01 (4) + SOAR01 (2) = 11 GB (DC01 + NDR01 off) |
| SOAR tool | n8n on Docker Engine (not Docker Desktop), single container, SQLite backend, queue mode off |
| n8n settings | `EXECUTIONS_DATA_PRUNE=true`, `EXECUTIONS_DATA_MAX_AGE=168`, metrics off, no extra workers |
| Isolation | No bridged NICs, no inbound forwards. NAT attached to SOAR01 **only during the VT demo**, then detached (logged) |
| Enrichment | VirusTotal public API (free tier); key gitignored. Local enrichment preferred by default — VT is the documented exception |
| Safe action | Non-destructive only (local analyst notification). Destructive response out of scope; human approval required for anything that changes the endpoint |

## 3. Architecture & components

### 3.1 SOAR01 guest

- Ubuntu Server 24.04 LTS; 1 vCPU / 2 GB / 20 GB disk.
- NIC0 host-only `vboxnet0`, static `10.10.30.20/24` (n8n on `:5678`).
- Temp NAT for package install, then detached; re-attached only for the VT demo (§7).
- Docker Engine + `n8nio/n8n` single container, SQLite backend, queue mode off.
- Bind mount a host directory → container volume: `/srv/soar` on SOAR01 holds `incidents/`, `notifications/`, `audit.log`.
- GRUB `clocksource=acpi_pm` persisted (same fast-clock fix as NDR01/DC01).

### 3.2 n8n workflow (the playbook)

One workflow, triggered by a Webhook node:

1. **Webhook** — `POST http://10.10.30.20:5678/webhook/soar` receives the Wazuh alert JSON.
2. **Parse** — extract `alert.id`, `rule.id`, `agent.name`, `timestamp`, and the queried `domain`.
3. **Enrich** — `HTTP Request` → `GET https://www.virustotal.com/api/v3/domains/{domain}` with header `x-apikey`.
4. **Verdict** — reduce VT's `data.attributes.last_analysis_stats` to `{malicious, suspicious, harmless, undetected}` + `reputation` + permalink.
5. **Incident record** — write `/srv/soar/incidents/<alert-id>.json`: raw alert + `enrichment.vt` block + verdict + timestamp.
6. **Safe action** — write `/srv/soar/notifications/latest.json`: human-readable "analyst paged" notice (domain, verdict, alert id).
7. **Audit** — append one line to `/srv/soar/audit.log`: timestamp, alert id, domain, action, result.

### 3.3 Detection (the only new one)

- **WIN01 Sysmon**: add Event ID **22** (DNS query) to `sysmon-config.xml` (currently EID 1 + 10).
- **Wazuh rule `100047`** (SOC01 `local_rules.xml`): level 12, IOC-based — matches the specific malicious domain in the Sysmon DNS query name; group `dns,lab`; MITRE T1071.004. Emits the queried domain in the alert so n8n can read it.
- Benign control: a query to any *other* domain (e.g. `corp.lab`) is silent — the rule is IOC-specific.

### 3.4 Wazuh → n8n bridge (push)

- Wazuh `<integration>` block on SOC01 triggers **only on rule `100047`** (the triage filter), running a small script (`/var/ossec/integrations/forward-to-n8n`).
- The script reads the alert JSON from stdin and POSTs it to `http://10.10.30.20:5678/webhook/soar`.
- This mirrors real-SIEM "push" (Splunk webhook action, Sentinel automation rule); the trigger condition is explicit — no other of the ~8,000 rules is forwarded.

## 4. Detection & enrichment details

| Field | Value |
|---|---|
| Detection source | Sysmon EID 22 (DNS query) on WIN01 |
| Wazuh rule | `100047`, level 12, group `dns,lab`, MITRE T1071.004 |
| Enrichment key (queried) | the DNS domain from the alert (`win.eventdata.queryName`, exact field confirmed at build) |
| Enrichment source | VirusTotal `GET /api/v3/domains/{domain}` |
| Returned | `last_analysis_stats` (malicious/suspicious/harmless/undetected), `reputation`, permalink |
| Demo domain | chosen + verified against VT **immediately before the demo** (must show `malicious > 0`) |

Notes:
- The detection is IOC-based (a blocklist hit). Enrichment is the *independent* confirmation that quantifies "how malicious" — this cleanly separates detection from enrichment.
- The "attack" is a single DNS lookup (e.g. `Resolve-DnsName <malicious-domain>` on WIN01) — no malware, no exploit, fully reversible.

## 5. Data flow

```
WIN01: Resolve-DnsName <malicious-domain>
  → Sysmon EID 22 (queryName) → Wazuh agent → SOC01
  → rule 100047 fires (level 12, T1071.004), alert carries domain + src_ip + agent
  → Wazuh integration (trigger: rule 100047) POSTs alert JSON → n8n webhook
  → n8n: extract domain → VirusTotal → verdict
  → /srv/soar/incidents/<id>.json  (incident record)
  → /srv/soar/notifications/latest.json  (safe action)
  → /srv/soar/audit.log  (audit)
```

## 6. The demo (how enrichment is shown to have worked)

1. **Wazuh dashboard** — the raw alert (the "before").
2. **n8n execution log** — the workflow run, showing the VT HTTP node's JSON response (the "during").
3. **`/srv/soar/incidents/<id>.json`** — raw alert + `enrichment.vt` verdict (the "after").
4. **`/srv/soar/notifications/latest.json` + `/srv/soar/audit.log`** — the response + audit trail.

Evidence is exported via `pscp` from SOAR01 to `lab/evidence/phase4-*` and committed.

## 7. Isolation & secrets

- NAT on SOAR01: attach → run demo (VT call) → detach. Recorded in the exercise log.
- VT API key: stored in gitignored `lab/runbook/.local-credentials.md`, injected as an n8n credential/env var — never committed, never in the workflow JSON export.
- VT is the documented exception; the default enrichment path in the architecture remains local.

## 8. Risks & error handling

- **VT reputations change.** Mitigation: verify the chosen domain against VT right before the demo; keep a fallback domain. If `malicious == 0` at demo time, the flow still works — the verdict is just weaker.
- **NAT/internet flakiness.** Mitigation: confirm SOAR01 can reach `virustotal.com` immediately after attaching NAT, before running the attack.
- **Sysmon EID 22 field name.** Confirm `win.eventdata.queryName` in the decoded Wazuh event at build; if the decoder names it differently, adjust rule + n8n extraction (both key on the same field).
- **n8n webhook reachability.** SOC01 → SOAR01 is host-only (10.10.30.10 → 10.10.30.20), no firewall between; verify with a manual `curl` before trusting the integration.
- **Clock drift (known gotcha).** After any SOC01/SOAR01 savestate, check `date` first; re-sync before the demo so alert timestamps align.
- **Wazuh integration self-match.** The forwarder runs on SOC01; keep it keyed strictly to rule 100047 so it never echoes its own noise.

## 9. Acceptance — Phase 4 done when ALL

1. SOAR01 built: n8n reachable at `http://10.10.30.20:5678`, container running with the pinned settings.
2. Rule `100047` + Sysmon EID 22 deployed; benign control (query to another domain) does **not** fire.
3. Attack fires: the malicious-domain DNS lookup produces alert `100047` in Wazuh.
4. The Wazuh integration automatically forwards the alert; an n8n execution is triggered without manual intervention.
5. The workflow completes end-to-end: VT verdict obtained, incident JSON written, notification written, audit line appended.
6. Evidence exported to `lab/evidence/phase4-*` and committed.
7. Lab stays isolated: NAT attached only for the demo, then detached; VT key never committed.
8. Docs updated + committed: `soar01-walkthrough.md`, `soar01.md`, `setup.md` §5, `lessons-learned.md`, `progress.md`, one use-case doc (`uc-13-…`).
