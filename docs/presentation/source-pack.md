# Virtual SOC Lab — Source Pack for a 15–20 Minute Technical Talk

This document is the single source of truth for generating presentation content (slides,
script, audio overview). Every fact below is taken from the project repository and its
recorded evidence. **Do not invent numbers, tool names, or results.** If a claim is not in
this document, omit it or mark it as "not covered".

Presentation contract (already decided):

- **Audience:** technical peers / security community
- **Length:** 15–20 minutes including a live demo and Q&A buffer
- **Language:** English
- **Structure:** cold-open incident narrative (payoff first, then rewind)
- **Demo:** live but pre-warmed, with a pre-recorded fallback clip

---

## 1. One-paragraph abstract

The Virtual SOC Lab is a free, isolated blue-team lab built on a single 16 GB Windows host
with VirtualBox. It emulates a small company: a Windows endpoint with Sysmon, a Samba
Active Directory domain, a Suricata network sensor, a Wazuh SIEM, and an n8n SOAR platform.
Its purpose is not to show installed tools but to prove a loop: a documented simulated
attack produces a reproducible alert with evidence, a benign look-alike stays silent, and —
for one case — the alert is automatically enriched and turned into an incident record with
no human in the loop. All fourteen use-case notes, the rebuild runbook, and the evidence
exports are in the repository so another person can reproduce the results.

---

## 2. The cold open (start here, 45 seconds)

Open with the payoff, not the architecture. Read or show this:

> At 20:12 UTC on 15 November, a DNS lookup left a Windows endpoint in the lab.
> Wazuh raised rule 100047 four seconds later. Nobody was watching the SIEM. The alert
> was forwarded to the SOAR platform, enriched against VirusTotal — 17 security vendors
> flagged the domain as malicious, reputation minus 60 — and an incident record, an
> analyst notification, and an audit line were written automatically. Total elapsed time
> from alert to enriched incident: about 4.5 seconds.

Then the line that frames the whole talk:

> "Most home labs stop when the dashboard loads. This one starts there. The question is:
> can an attack become an alert with evidence — and can a benign twin stay silent?"

Visual for this beat: the notification JSON and the audit line, or the DFD with the UC-13
path highlighted.

---

## 3. The problem: labs that are museums of tools

Cyber labs often measure success by whether software is installed and dashboards render.
That is a museum, not a SOC. The lab defines success as observable behavior instead. A use
case is complete only when all seven criteria hold:

1. A documented, authorised, simulated attack runs inside the isolated lab.
2. The activity produces the expected telemetry in its source (Sysmon, Windows Security,
   Samba audit, Suricata).
3. The events reach the SIEM with useful fields and correct timestamps.
4. A rule fires reproducibly — same input, same alert.
5. The alert contains enough evidence to investigate (who, what, where, when).
6. A benign control — similar but legitimate activity — stays silent.
7. Another person can repeat the exercise from the repository.

Soundbite: **"Detection is a claim. Reproducibility is the proof."**

---

## 4. What was built

Five virtual machines on one host, each with a clear job:

| VM | Role | Operating system / tooling | RAM |
|---|---|---|---|
| SOC01 | SIEM: manager, indexer, dashboard | Ubuntu 24.04.5, Wazuh 4.14.8 | 5 GB |
| WIN01 | Endpoint | Windows 11 Enterprise Evaluation, Sysmon 15.22 (schema 4.90), Wazuh agent 4.14.8 | 4 GB |
| DC01 | Identity | Ubuntu 24.04.5, Samba AD DC, domain `corp.lab`, DNS | 2 GB |
| NDR01 | Network detection | Ubuntu 24.04.5, Suricata 8.0.8 | 1 GB |
| SOAR01 | Automation | Ubuntu 24.04.5, Docker Engine 29.x, n8n 2.47.7 | 2 GB |

Everything is free software or free evaluation software. No paid licences, no real malware.

The lab follows four build phases plus host preparation, and each phase adds one capability:

- **Phase 0 — Host prep:** VirtualBox 7.2.20, isolated networks, no bridged adapters.
- **Phase 1 — Detection core:** Wazuh + Sysmon; file integrity, LSASS access, PowerShell.
- **Phase 2 — Identity:** Samba AD; logon failures, privileged group change, Kerberos abuse.
- **Phase 3 — NDR:** Suricata; scans, beaconing, tunnels, DNS anomalies, brute force, FTP.
- **Phase 4 — Automation:** n8n + VirusTotal; alert-to-incident enrichment.

Phase 5 (email gateway, extra servers, Velociraptor) is deliberately **not scheduled**.

---

## 5. Architecture and constraints

Two isolated networks plus host-only management; no bridged adapters anywhere:

| Network | Subnet | Members |
|---|---|---|
| LAB-MGMT (host-only) | `10.10.30.0/24` | Host `10.10.30.1`, SOC01 `10.10.30.10`, SOAR01 `10.10.30.20` |
| LAB-CORP (internal) | `10.10.10.0/24` | SOC01 `10.10.10.5`, WIN01 `10.10.10.20`, DC01 `10.10.10.10`, NDR01 `10.10.10.40` |

Ports: Wazuh dashboard 443, Wazuh API 55000, agent events 1514, enrolment 1515, n8n 5678.

NAT adapters are used only for package installation and are detached afterwards, so the
finished lab has no Internet path. The one exception is the UC-13 demo, which temporarily
re-attaches SOAR01's NAT adapter to call VirusTotal.

Because the host has 16 GB of RAM, not all VMs run at once. Four power-on scenarios are
documented, and the rule is never to exceed 11 GB of running guests:

| Scenario | Guests | RAM | Used for |
|---|---|---|---|
| S1 | SOC01 + WIN01 | 9 GB | Phase 1 |
| S2 | SOC01 + WIN01 + DC01 | 11 GB | Phase 2 |
| S3 | SOC01 + WIN01 + NDR01 | 10 GB | Phase 3 |
| S4 | SOC01 + WIN01 + SOAR01 | 11 GB | Phase 4 |

Boot SOC01 first and wait for the API; shut down in reverse. Each phase has a VirtualBox
snapshot used as a clean rollback point.

---

## 6. The detection portfolio

Fourteen case notes cover fifteen exercises (UC-03 includes a sub-exercise, UC-03b).
Sixteen custom Wazuh rules (`100010`–`100047`) plus built-in file-integrity rules.

| Use case | Technique | Telemetry | Rule | Level | Scenario |
|---|---|---|---|---|---|
| UC-00 File integrity | — | Wazuh FIM | 550 / 553 / 554 (built-in) | — | S1 |
| UC-01 LSASS access | T1003.001 | Sysmon EID 10 | 100010 | 12 | S1 |
| UC-02 PowerShell `-enc` | T1059.001 | Sysmon EID 1 / 4104 | 100020 | 12 | S1 |
| UC-03 Failed logons / burst / success | T1110, T1078 | Windows Security, Samba audit | 100029 / 100030 / 100031 | 3–12 | S2 |
| UC-03b Privileged group change | T1565.001 | FIM on `sam.ldb.d` | 100032 | 12 | S2 |
| UC-04 Kerberoasting | T1558.003 | Samba KDC audit | 100033 | 12 | S2 |
| UC-05 AS-REP roasting | T1558.004 | Samba KDC audit | 100034 | 12 | S2 |
| UC-06 NDR marker | — | Suricata `eve.json` | 100040 | 8 | S3 |
| UC-07 Port scan | T1046 | Suricata | 100041 | 10 | S3 |
| UC-08 Beaconing | T1571 | Suricata | 100042 | 12 | S3 |
| UC-09 ICMP tunnel | T1095 | Suricata | 100043 | 12 | S3 |
| UC-10 DNS anomaly | T1071.004 | Suricata | 100044 | 12 | S3 |
| UC-11 SMB brute force | T1110 | Suricata | 100045 | 12 | S3 |
| UC-12 Cleartext FTP | T1040 | Suricata | 100046 | 10 | S3 |
| UC-13 DNS → VirusTotal → SOAR | T1071.004 | Sysmon EID 22 → Wazuh → n8n | 100047 | 12 | S4 |

Why this matters: the portfolio shows host, identity, network, and automation layers, not a
single trick repeated four times.

---

## 7. The UC-13 pipeline, node by node

This is the climax of the talk. It is the only case that crosses four systems.

**Step 1 — Telemetry.** Sysmon Event ID 22 (DnsQuery) on WIN01 records the queried name.
The Wazuh agent forwards it to SOC01.

**Step 2 — Detection.** Wazuh custom rule `100047` (level 12, ATT&CK T1071.004) in
`lab/soc01/local_rules.xml`:

- It fires only for the Sysmon event group (`sysmon_event_22`).
- It matches the field `win.eventdata.queryName` with PCRE2 `(?i)malware\.wicar\.org`.
- The match is an **unanchored substring**, so it also catches any
  `*.malware.wicar.org` subdomain.
- The rule group is `dns,lab,soar,`.

**Step 3 — Bridge.** Wazuh's integratord runs the integration `custom-forward-to-n8n`,
scoped to `rule_id 100047`, and POSTs the full alert JSON to
`http://10.10.30.20:5678/webhook/soar` over the host-only network. The integration log
confirms `{"message":"Workflow was started"}HTTP:200`.

**Step 4 — SOAR.** n8n runs a seven-node workflow:

1. **Webhook** — POST entry point at path `soar`.
2. **extract** — unwraps the alert (the Webhook node nests it under `json.body`) into
   alert id, rule id, agent, timestamp, domain.
3. **vt-lookup** — HTTP GET to
   `https://www.virustotal.com/api/v3/domains/{domain}` with a Header-Auth credential
   named `x-apikey`; the API key never appears in the exported workflow.
4. **build-incident** — builds the incident, notification, and audit objects from the
   VirusTotal verdict (malicious, suspicious, harmless, undetected, reputation).
5. **write-incident** — writes `/srv/soar/incidents/<alert-id>.json`.
6. **write-notification** — writes `/srv/soar/notifications/latest.json`.
7. **write-audit** — appends one line to `/srv/soar/audit.log`.

The workflow performs no destructive action. It enriches, notifies, and audits; any action
that changes an endpoint requires human approval by design.

**Step 5 — Result.** An analyst-readable incident, a high-severity notification, and an
audit trail — automatically, in about 4.5 seconds from the alert timestamp.

---

## 8. Evidence: what actually happened

The demo ran end to end twice, plus a benign control:

| Run | Wazuh alert ID | Alert time (UTC) | VirusTotal verdict (malicious / suspicious / harmless / undetected) | Reputation |
|---|---|---|---|---|
| 1 | 1794768910.1065381 | 2026-11-15T18:55:10Z | 17 / 1 / 41 / 33 | −60 |
| 2 | 1794773538.1555595 | 2026-11-15T20:12:18Z | 17 / 1 / 41 / 33 | −60 |

Run 2 notification (verbatim):

```json
{"severity":"high","message":"Analyst paged: DNS query to known-malicious domain malware.wicar.org (rule 100047) on win01. VT: 17 vendors malicious.","alert_id":"1794773538.1555595","timestamp":"2026-11-15T20:12:22.521Z"}
```

Run 2 audit line (verbatim):

```json
{"timestamp":"2026-11-15T20:12:22.521Z","alert_id":"1794773538.1555595","domain":"malware.wicar.org","action":"notify_analyst","result":"success"}
```

**Benign control:** a DNS query to `example.com` produced a Sysmon EID 22 event but **zero**
rule-100047 alerts, while background DNS continued to flow. This is the false-positive
check, and it passed.

Evidence files in the repository: `lab/evidence/phase4-alerts.json`,
`lab/evidence/phase4-incident.json`, plus alert screenshots for UC-01…UC-12 and phase 2/3
captures. Every run, expected versus observed, is recorded in
`lab/cases/exercise-log.md`.

---

## 9. Detection engineering: logic and tuning

The talk should show that rules are reasoned about, not copied.

**Rule shape.** A good lab rule answers: which log source, which field, which condition,
which severity, and which benign behavior must not match. UC-13 uses Sysmon EID 22, the
`queryName` field, a case-insensitive substring, level 12, and a benign control of ordinary
DNS.

**True positive versus false positive.** For UC-13 the true-positive shape is a `queryName`
containing `malware.wicar.org`; the deliberate lab lookup raised exactly one alert per run.
Background DNS (`go.microsoft.com`, `ecs.office.com`, `example.com`) never matched.

**Threshold tuning.** UC-03 uses a frequency rule (three failed logons in 60 seconds)
instead of alerting on every failure. UC-05 (AS-REP) initially produced duplicates and a
normal-Kerberos false positive; the rule was tuned rather than accepted.

**Substring versus anchored matching.** The unanchored substring intentionally catches
subdomains. If look-alikes became a problem, the rule would be anchored:
`(?i)(^|\.)malware\.wicar\.org$`.

**Honest gap.** VirusTotal returns 404 for unknown domains, and the HTTP node currently
stops the workflow instead of degrading gracefully. It is documented as a tuning gap, with
the fix described: never-error plus a missing-verdict path. In production the rule would be
driven by a threat-intel feed, with allowlists and deduplication, not a hard-coded indicator.

---

## 10. Lessons that make the talk credible

These are real problems encountered and fixed. Use two or three, not all eight.

1. **n8n 2.x "active" is not enough — you must Publish.** Setting the database flag did not
   register the webhook; the 2.x publish pipeline does, and a container restart re-registers
   already-published flows.
2. **Expressions need a leading `=`.** Without it, the VirusTotal URL was sent literally as
   `{{ $json.domain }}` and returned 404.
3. **The Webhook node nests the POST body under `json.body`.** The extract step handles it
   with `const body = a.body ?? a`.
4. **`require('fs')` is blocked in Code nodes.** The 2.x fix is the container variable
   `NODE_FUNCTION_ALLOW_BUILTIN=fs`; the older 1.x variable is ignored.
5. **VirusTotal 404 on unknown domains stops the workflow.** A fabricated subdomain fired
   the rule and the integration returned 200, but no files were written because the HTTP
   node errored first.
6. **The exact domain sticks in the Windows DNS negative cache.** `ipconfig /flushdns` does
   not clear it and `dnscache` is a protected service; only a reboot clears it.
7. **Defender eventually blocks the exact malicious domain at the DNS layer.** After a
   signature update, a fresh subdomain still logged and fired the rule, but the exact name
   produced no Sysmon event. Real-time protection is disabled only for the demo window.
8. **Sysmon EID 22 logs real wire queries only.** A name answered from cache or hosts emits
   no event, so a fresh subdomain distinguishes "pipeline broken" from "query suppressed".

Also worth one slide: Wazuh 4.14.8 shipped file-integrity rules referencing decoders that
did not exist, and the fix was documented stubs. That shows the lab deals with real product
behavior, not idealized tutorials.

---

## 11. Limitations and honest scope

Say these out loud; they increase credibility.

- Activity is **simulated and benign**; no real malware is required. UC-13 uses a known
  test domain (WICAR) and only asks VirusTotal for reputation.
- **Samba AD is not Windows Server AD**; some Microsoft-specific behavior differs.
- **Wazuh + Sysmon is not a commercial EDR.**
- **Suricata is a single-segment IDS**, not a full NDR platform.
- The **16 GB host forces phased power-on**; this is not a 24/7 SOC.
- **Free-tool coverage is not commercial-product parity.**
- The SOAR performs enrichment and notification only; destructive response is out of scope
  and requires human approval.
- Phase 5 (email gateway, extra servers, Velociraptor) is **not scheduled**.

---

## 12. Safety and responsible use

- All traffic stays on host-only/internal VirtualBox networks; no bridged adapters.
- Only test accounts and test assets; credentials are lab-only and gitignored.
- Automated response is limited to lab assets, logged, and audited.
- The lab is never exposed to the Internet; NAT is attached only for installs and the
  temporary VirusTotal demo.
- Only test systems you own or are authorised to test.

---

## 13. Suggested slide-by-slide outline (cold-open narrative, 15–20 minutes)

| Time | Slide | Content |
|---|---|---|
| 0:00–0:45 | **Cold open** | The 20:12 UTC incident: rule 100047, VirusTotal 17/1/41/33, reputation −60, incident + notification + audit in ~4.5 s. The framing question. |
| 0:45–2:30 | **The problem** | Tool museums versus behavior. The seven success criteria. "Detection is a claim; reproducibility is the proof." |
| 2:30–5:00 | **Architecture** | DFD: five VMs, two isolated networks, ports. The 16 GB constraint and the S1–S4 power-on matrix. No bridged NICs; NAT detached. |
| 5:00–6:30 | **The portfolio** | Coverage table: host, identity, network, automation. 15 exercises, 16 rules, ATT&CK mapping. |
| 6:30–9:00 | **Incident chain, part 1** | Sysmon EID 22 → Wazuh rule 100047. Show the rule logic and explain the unanchored substring and severity. |
| 9:00–11:00 | **Incident chain, part 2** | integratord → n8n seven-node workflow → VirusTotal → incident/notification/audit. Show the real notification JSON. |
| 11:00–14:00 | **Live demo** | Pre-warmed S4; DNS query on WIN01; watch the alert and the three files appear. Fallback clip if anything stalls. |
| 14:00–16:00 | **Credibility** | Two or three lessons (Publish, leading `=`, DNS negative cache/Defender). Tuning: threshold rule, anchored versus substring, the graceful-404 gap. |
| 16:00–17:30 | **Honest scope** | Limitations: simulated, Samba, no EDR equivalence, single-segment IDS, phased power-on, not 24/7. |
| 17:30–18:30 | **Reproducibility / close** | One repository: setup runbook, 14 case notes, evidence exports, exercise log. Another person can rebuild and verify. Call to action / repo link. |
| 18:30–20:00 | **Q&A buffer** | Spare slides: DFD, rule XML, workflow JSON, evidence files. |

Soundbites to reuse:

- "Most labs stop when the dashboard loads. This one starts there."
- "Every alert has a benign twin that must stay silent."
- "Four and a half seconds from alert to enriched incident — with an audit trail."
- "The lab is not a 24/7 SOC; it is a reproducible proof."

---

## 14. Live demo plan (pre-warmed, with fallback)

The demo is the same UC-13 chain shown on slides, but live. It is reliable only if rehearsed.

**Before the talk (pre-warm):**

1. Power on SOAR01, attach NAT: `VBoxManage modifyvm SOAR01 --nic2 nat`.
2. Power on S4: SOC01, then WIN01, then SOAR01. Wait for the WIN01 agent to be `Active`.
3. Confirm the n8n workflow is published and the webhook is registered.
4. On WIN01: disable Defender real-time protection for the demo window; confirm the DNS
   cache is clean.
5. Rehearse the query once, then **reboot WIN01** so the exact domain is not left in the
   negative cache. The live run should be the first query after that reboot.
6. Keep a pre-recorded clip of a successful run ready.

**Live sequence (about 3 minutes):**

1. Show the clean state: no incident file for the upcoming alert.
2. On WIN01, elevated: `ipconfig /flushdns`, then `Resolve-DnsName -Type A malware.wicar.org`
   (a timeout is expected).
3. Switch to Wazuh Discover, filter `rule.id:100047`, show the alert and its fields.
4. Show `/var/ossec/logs/integrations.log` with `HTTP:200`.
5. On SOAR01, show the new incident JSON, `notifications/latest.json`, and the audit line.
6. Run the benign control: `Resolve-DnsName -Type TXT example.com`; show that no 100047
   alert appears.

**If anything fails:** play the recorded clip, narrate the same evidence, and move on. Known
risks: VM boot time, DNS negative cache, Defender blocking the exact name, VirusTotal 404,
and a detached NAT adapter.

---

## 15. Anticipated Q&A

**Why n8n and not Shuffle?**
Shuffle was evaluated early and remains on the not-built list. n8n was chosen for this lab
because it runs as a single container, has native webhook and HTTP nodes, and supports code
nodes that can write local files — enough for a transparent, auditable enrichment workflow.

**Why Wazuh?**
It provides manager, indexer, and dashboard in one free stack, with an agent that collects
Windows event channels (including Sysmon) and a rule engine that supports custom PCRE2
matching and integrations.

**Is this an EDR?**
No. Wazuh + Sysmon gives strong host telemetry and detection, but it is not a commercial
endpoint detection and response product, and the talk should say so.

**How do you avoid false positives?**
Every exercise defines a benign control. Thresholds replace per-event alerts where
appropriate. Rules are tuned when they misfire (for example, the UC-05 duplicate and
normal-Kerberos false positive). UC-13 uses an indicator substring, so only the deliberate
query matches.

**Do you use real malware?**
No. The exercises are benign simulations. UC-13 resolves a known malicious test domain
(WICAR) and only queries VirusTotal for reputation; the workflow performs no destructive
action.

**How reproducible is it?**
The repository contains a rebuild-from-scratch runbook with every command, per-VM
snapshots, 14 case notes with expected results, and exported evidence including an exercise
log of expected versus observed. The README's replication checklist walks through build
order and tests.

**What would you change for production?**
Drive detections from threat-intelligence feeds with allowlists and deduplication; make the
VirusTotal step degrade gracefully on 404; add rate limiting and analyst assignment; use a
high-availability indexer; and require explicit approval workflows for any response action.

**Why only 16 GB?**
The host is a personal PC. The lab is designed around that constraint with phased power-on
scenarios; it is a deliberate design decision, not an accident.

**How long did it take?**
Answer in phases, not a single number: host prep, detection core, identity, NDR, and
automation were built one phase at a time, each with its own plan and acceptance checks.

**What is next?**
Phase 5 is explicitly not scheduled (email gateway, extra server, Velociraptor). The next
valuable step is production-style hardening: threat-intel-driven rules, deduplication, and
graceful failure paths.

---

## 16. Fact sheet (for accuracy checks)

- Host: Windows, VirtualBox 7.2.20 + Extension Pack, 16 GB RAM, 512 GB disk, no bridged NICs.
- Hypervisor tuning: Memory Integrity off; `bcdedit /set hypervisorlaunchtype off`.
- SOC01: Ubuntu 24.04.5, Wazuh 4.14.8 all-in-one, 5 GB RAM, 3 vCPU.
- WIN01: Windows 11 Enterprise Evaluation, Sysmon 15.22 (schema 4.90), Wazuh agent 4.14.8,
  4 GB RAM, 2 vCPU.
- DC01: Ubuntu 24.04.5, Samba AD DC, domain `corp.lab`, NetBIOS `CORP`, 2 GB RAM, 1 vCPU.
- NDR01: Ubuntu 24.04.5, Suricata 8.0.8, single-segment passive IDS, 1 GB RAM, 1 vCPU.
- SOAR01: Ubuntu 24.04.5, Docker Engine 29.x, n8n 2.47.7, 2 GB RAM, 1 vCPU.
- Addresses: SOC01 `10.10.10.5` / `10.10.30.10`; WIN01 `10.10.10.20`; DC01 `10.10.10.10`;
  NDR01 `10.10.10.40`; SOAR01 `10.10.30.20`; host `10.10.30.1`.
- Ports: 443 (dashboard), 55000 (API), 1514/1515 (agent), 5678 (n8n).
- Custom rules: 100010, 100020, 100029, 100030, 100031, 100032, 100033, 100034, and
  100040–100047 (16 total). Built-in FIM rules: 550, 553, 554.
- UC-13 rule: 100047, level 12, T1071.004, group `dns,lab,soar,`, `if_group
  sysmon_event_22`, field `win.eventdata.queryName`, PCRE2 `(?i)malware\.wicar\.org`.
- Integration: `custom-forward-to-n8n`, scoped to rule 100047, POSTs to
  `http://10.10.30.20:5678/webhook/soar`.
- n8n workflow: 7 nodes; outputs to `/srv/soar/incidents/<alert-id>.json`,
  `/srv/soar/notifications/latest.json`, `/srv/soar/audit.log`.
- UC-13 run 1: alert `1794768910.1065381`, 2026-11-15T18:55:10Z.
- UC-13 run 2: alert `1794773538.1555595`, 2026-11-15T20:12:18Z; notification and audit at
  2026-11-15T20:12:22.521Z.
- VirusTotal verdict for both runs: malicious 17, suspicious 1, harmless 41, undetected 33,
  reputation −60.
- Benign control: `example.com` emitted a Sysmon EID 22 event and zero rule-100047 alerts.
- Evidence: 12 alert screenshots (UC-01…UC-12), phase 2/3 capture JSON, phase 4 alert and
  incident JSON, and `lab/cases/exercise-log.md`.
- Repository entry points: `README.md`; `lab/runbook/setup.md`; `lab/runbook/replicate.md`;
  `lab/cases/`; `lab/evidence/`; `docs/DFD.PNG`.

---

## 17. Glossary

- **SIEM** — Security Information and Event Management (here: Wazuh).
- **EDR** — Endpoint Detection and Response.
- **NDR** — Network Detection and Response (here: a Suricata IDS, not a full platform).
- **SOAR** — Security Orchestration, Automation, and Response (here: n8n).
- **FIM** — File Integrity Monitoring.
- **IOC** — Indicator of Compromise.
- **ATT&CK** — MITRE Adversarial Tactics, Techniques, and Common Knowledge.
- **Sysmon EID 22** — Sysmon event ID 22, DNS query.
- **Integratord** — Wazuh's component that posts alerts to external systems.
- **PCRE2** — Perl-compatible regular expressions, version 2.

---

## 18. Where to verify every claim

- Rebuild commands: `lab/runbook/setup.md`
- Replication and test matrix: `lab/runbook/replicate.md`
- Architecture and diagrams: `docs/DFD.PNG`, `docs/superpowers/specs/`
- Per-phase plans: `docs/superpowers/plans/`
- Use cases and tuning: `lab/cases/`
- Evidence exports: `lab/evidence/`
- SOAR workflow: `lab/soar01/workflow.json`, `lab/soar01/workflow.md`
- Rule source: `lab/soc01/local_rules.xml`
- Networks: `lab/network/networks.md`

---

*End of source pack. Use only the facts above when generating slides, scripts, or audio.*
