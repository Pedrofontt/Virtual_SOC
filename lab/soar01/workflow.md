# SOAR01 n8n workflow — VirusTotal domain enrichment (UC-13)

Workflow that receives a Wazuh rule-100047 alert (Sysmon EID 22 DNS query) via webhook,
enriches the queried domain with VirusTotal, and writes incident / notification / audit
files under the bind-mounted `/srv/soar`.

Import: `lab/soar01/workflow.json` (n8n → Workflows → Import from File).
Webhook production URL: `http://10.10.30.20:5678/webhook/soar`.

## Nodes (7, in order)

| # | Node | Type | Purpose |
|---|------|------|---------|
| 1 | Webhook | Webhook (POST, path `soar`, auth **None**) | entry point; Wazuh integration POSTs alert JSON here |
| 2 | extract | Code (JS) | unwrap `json.body` → `{ alert_id, rule_id, agent, timestamp, domain, raw }` |
| 3 | vt-lookup | HTTP Request (GET) | `https://www.virustotal.com/api/v3/domains/{{ $json.domain }}`, Header Auth `x-apikey` |
| 4 | build-incident | Code (JS) | build incident + notification + audit objects from VT verdict |
| 5 | write-incident | Code (JS, fs) | `writeFileSync('/srv/soar/incidents/<alert_id>.json', ...)` |
| 6 | write-notification | Code (JS, fs) | `writeFileSync('/srv/soar/notifications/latest.json', ...)` |
| 7 | write-audit | Code (JS, fs) | `appendFileSync('/srv/soar/audit.log', <audit> + '\n')` |

## Code snippets

**extract**
```js
const a = $input.first().json;
const body = a.body ?? a;
return {
  alert_id: body.id,
  rule_id: body.rule?.id,
  agent: body.agent?.name,
  timestamp: body.timestamp,
  domain: body.data?.win?.eventdata?.queryName || null,
  raw: body
};
```

**build-incident**
```js
const prev = $('extract').first().json;
const vt = $('vt-lookup').first().json;
const s = vt.data?.attributes?.last_analysis_stats || {};
const verdict = { malicious: s.malicious ?? 0, suspicious: s.suspicious ?? 0, harmless: s.harmless ?? 0, undetected: s.undetected ?? 0 };
const reputation = vt.data?.attributes?.reputation ?? 0;
const domain = vt.data?.id ?? prev.domain;
const incident = {
  incident_id: prev.alert_id,
  created_at: new Date().toISOString(),
  alert: prev.raw,
  enrichment: { source: 'virustotal', domain, verdict, reputation, permalink: `https://www.virustotal.com/gui/domain/${domain}` }
};
return {
  alert_id: prev.alert_id,
  domain,
  incident,
  notification: {
    severity: 'high',
    message: `Analyst paged: DNS query to known-malicious domain ${domain} (rule ${prev.rule_id}) on ${prev.agent}. VT: ${verdict.malicious} vendors malicious.`,
    alert_id: prev.alert_id,
    timestamp: incident.created_at
  },
  audit: { timestamp: incident.created_at, alert_id: prev.alert_id, domain, action: 'notify_analyst', result: 'success' }
};
```

**write-incident**
```js
const { writeFileSync } = require('fs');
const d = $input.first().json;
writeFileSync(`/srv/soar/incidents/${d.alert_id}.json`, JSON.stringify(d.incident, null, 2));
return d;
```

**write-notification**
```js
const { writeFileSync } = require('fs');
const d = $input.first().json;
writeFileSync('/srv/soar/notifications/latest.json', JSON.stringify(d.notification, null, 2));
return d;
```

**write-audit**
```js
const { appendFileSync } = require('fs');
const d = $input.first().json;
appendFileSync('/srv/soar/audit.log', JSON.stringify(d.audit) + '\n');
return d;
```

## Key gotchas (n8n 2.47.7) — required to make this work

1. **`fs` in Code nodes is blocked by default.** The task-runner sandbox rejects
   `require('fs')` with `Module 'fs' is disallowed`. The container must run with
   `NODE_FUNCTION_ALLOW_BUILTIN=fs` (NOT the older `N8N_CODE_ENABLE_BUILTIN_MODULES`).
2. **Expressions need a leading `=`.** A node parameter is treated as a literal string
   unless it starts with `=`. So the VT URL must be stored as
   `=https://www.virustotal.com/api/v3/domains/{{ $json.domain }}` (with `=` prefix).
   Without it, `{{ $json.domain }}` is sent literally and VT returns 404.
3. **Webhook wraps the body.** The Webhook node outputs `{ headers, query, params, body,
   webhookUrl, executionMode }`; the alert is under `json.body`, not top-level. The
   `extract` node therefore reads `a.body.data.win.eventdata.queryName` (with `a.body ?? a`
   fallback for robustness).
4. **Activation = "Publish".** In n8n 2.x there is no separate "Active" toggle; clicking
   **Publish** activates the webhook. It is a persisted/async publication (outbox), so a
   publish + container restart re-registers the webhook automatically.
5. **Credential = Header Auth** named `x-apikey` (value = VirusTotal API key). Attached to
   the `vt-lookup` HTTP Request node. The key never appears in `workflow.json`.

## Smoke test

```bash
curl -s -X POST http://127.0.0.1:5678/webhook/soar -H 'Content-Type: application/json' \
  -d '{"id":"manual-test","rule":{"id":"100047"},"agent":{"name":"win01"},"timestamp":"2026-11-14T00:00:00Z","data":{"win":{"eventdata":{"queryName":"google.com"}}}}'
sleep 4
ls -la /srv/soar/incidents /srv/soar/notifications; cat /srv/soar/audit.log
```

Expected: `incidents/manual-test.json` (with a VT verdict for google.com),
`notifications/latest.json`, and one appended `audit.log` line.
