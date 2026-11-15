# UC-13 — T1071.004 Application Layer Protocol: DNS (SOAR auto-enrichment)

Status: PASS

## Hypothesis
A DNS query from WIN01 to a known-malicious domain is detected by Wazuh rule 100047 (from Sysmon
EID 22), automatically forwarded to n8n, enriched with VirusTotal, and turned into an incident +
notification + audit record — no human step in the loop.

## Detection logic
- Source: Sysmon Event ID 22 (DnsQuery) on WIN01 → Wazuh agent 001 → SOC01 manager.
- Custom rule `100047` (level 12, T1071.004) in `lab/soc01/local_rules.xml`:
  - `<if_group>sysmon_event_22</if_group>` (group added by the built-in `windows_eventchannel` decoder).
  - `<field name="win.eventdata.queryName" type="pcre2">(?i)malware\.wicar\.org</field>`
    (substring match — also matches any `*.malware.wicar.org` subdomain).
  - description embeds the queried name; group `dns,lab,soar,`.
- Bridge: Wazuh **integratord** runs integration `custom-forward-to-n8n` (scoped to `rule_id 100047`),
  POSTing the full alert JSON to `http://10.10.30.20:5678/webhook/soar`.
- SOAR: n8n workflow (7 nodes) → VirusTotal `GET /api/v3/domains/{domain}` → writes
  `/srv/soar/incidents/<alert-id>.json`, `/srv/soar/notifications/latest.json`, `/srv/soar/audit.log`.

## Prerequisites
- S4 powered on: SOC01 + WIN01 + SOAR01; DC01 + NDR01 OFF.
- Agent 001 active; rule 100047 live; integration `custom-forward-to-n8n` enabled (check ossec.log:
  `Enabling integration for: 'custom-forward-to-n8n'`).
- SOAR01 NAT attached for the VT call (detached after the demo). n8n workflow **published**
  (id `uw47iA9RnDEEyCrS`), webhook `POST /soar` registered.
- WIN01: **Defender real-time protection OFF** (Tamper Protection off), and WIN01 **freshly rebooted**
  (see Troubleshooting — the exact domain otherwise sticks in the DNS negative cache / gets blocked).

## Test procedure
1. Confirm the DNS cache is clean: `Get-DnsClientCache -Name malware.wicar.org` → "No objects found".
2. WIN01, elevated PowerShell:
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
   ipconfig /flushdns
   Resolve-DnsName -Type A malware.wicar.org      # timeout is expected
   ```
3. Confirm Sysmon logged the query (`QueryStatus: 1460`) and Wazuh raised rule 100047.
4. Confirm the integration POST in `/var/ossec/logs/integrations.log`
   (`custom-forward-to-n8n: {"message":"Workflow was started"}HTTP:200`).
5. Confirm n8n wrote the three artifacts under `/srv/soar` on SOAR01.
6. Benign control: `Resolve-DnsName -Type TXT example.com` → Sysmon event but **no** 100047 alert.

## Expected vs observed
Expected: rule 100047 (level 12) → integration HTTP 200 → n8n writes incident, notification, audit.

Observed (two successful runs):

| Run | Wazuh alert id | Alert ts (UTC) | VT verdict (malicious/suspicious/harmless/undetected) | Reputation |
|---|---|---|---|---|
| 1 | 1794768910.1065381 | 2026-11-15T18:55:10Z | 17 / 1 / 41 / 33 | -60 |
| 2 | 1794773538.1555595 | 2026-11-15T20:12:18Z | 17 / 1 / 41 / 33 | -60 |

`integrations.log`:
```
2026-11-15T20:12:22Z custom-forward-to-n8n: {"message":"Workflow was started"}HTTP:200
```

`notifications/latest.json` (run 2):
```json
{"severity":"high","message":"Analyst paged: DNS query to known-malicious domain malware.wicar.org (rule 100047) on win01. VT: 17 vendors malicious.","alert_id":"1794773538.1555595","timestamp":"2026-11-15T20:12:22.521Z"}
```

`audit.log` (run 2):
```json
{"timestamp":"2026-11-15T20:12:22.521Z","alert_id":"1794773538.1555595","domain":"malware.wicar.org","action":"notify_analyst","result":"success"}
```

Incident JSON contains the full Wazuh alert (rule 100047, Sysmon EID 22, `queryName`, `queryStatus 1460`,
image `powershell.exe`, user `labadmin`) plus `enrichment` (VT verdict + permalink).
Evidence: `lab/evidence/phase4-alerts.json`, `lab/evidence/phase4-incident.json`.

## Benign control
`Resolve-DnsName -Type TXT example.com` produced a Sysmon EID 22 event (status 1460) but **zero**
rule-100047 alerts — the pipeline stayed live (background DNS continued to flow).

## False positives
The rule is an IOC substring match, so in the isolated lab it has zero false positives by construction
(only the deliberate query matches). In production, `malware.wicar.org` is a known malware-test domain;
a real deployment would drive this rule from a threat-intel feed and maintain allowlists.

## Cleanup
- SOAR01 NAT detached (`--nic2 none`) and snapshot `base-phase4` taken (2026-11-15).
- VT key never committed: lives only in the n8n Header-Auth credential + gitignored
  `lab/runbook/.local-credentials.md`; the exported `workflow.json` excludes it.
- WIN01: re-enable Defender after demos (`Set-MpPreference -DisableRealtimeMonitoring $false`).
- Rule 100047 intentionally left deployed (part of the detection baseline).

## Troubleshooting notes
- **VT 404 stops the workflow.** A unique subdomain (e.g. `zzq7x1.malware.wicar.org`) is cache-proof and
  fires the rule, but VirusTotal has no record → HTTP 404 → the HTTP node errors and the run ends before
  writing files. Use a domain VT actually knows (malicious > 0).
- **Exact domain sticks in the Windows DNS negative cache.** `ipconfig /flushdns` does not clear it and
  `dnscache` is a protected service (`Restart-Service dnscache` → "Cannot open ... service"). A **WIN01
  reboot** clears it.
- **Defender blocks the exact malicious domain at the DNS layer** once its signatures know it (a fresh
  subdomain still logs; the exact name does not, even with the cache flushed). Disable real-time
  protection (Tamper off) for the demo.
- **Typos matter:** `malware.wicar.org==` → Sysmon status 9560 (invalid name char, but still matches the
  substring regex); `malware.wicar.com` → no rule match.
- **n8n 2.x specifics:** activation is *Publish* (DB `active=1` alone does not register the webhook);
  expression fields need a leading `=`; the alert is nested under `json.body` in the webhook node;
  `require('fs')` needs `NODE_FUNCTION_ALLOW_BUILTIN=fs`.
