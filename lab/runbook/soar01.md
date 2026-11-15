# SOAR01 runbook

Build: Ubuntu Server 24.04.5 minimal, 1 vCPU, 2 GB RAM, 20 GB VDI.
NIC1 host-only static `10.10.30.20/24` (VirtualBox Host-Only Adapter #2); NIC2 NAT temporary
(install + VirusTotal demos only, ssh forward `127.0.0.1:2224`) — **detached before the snapshot**.
Host key `SHA256:L0z4KGt1aq87MtiZCTB+7+JAlCl3dFOrveJK/YsKK/E`. Reach from the host directly:
`ssh soaradmin@10.10.30.20`.

Local credentials (DO NOT COMMIT — see `lab/runbook/.local-credentials.md`): `soaradmin`.
VT API key lives only in that file + the n8n Header-Auth credential.

## Provision (Docker Engine + n8n)

- Docker Engine 29.1.3 (official apt repo). Single container, **SQLite**, queue off.
- Container `n8n`: image `n8nio/n8n:latest` (**v2.47.7** in this build), port `5678:5678`,
  `--restart unless-stopped`.
- Bind mounts: `/srv/soar:/srv/soar` (world-writable; SOAR output) and
  `/srv/n8n:/home/node/.n8n` (n8n data persistence).
- Env: `EXECUTIONS_DATA_PRUNE=true`, `EXECUTIONS_DATA_MAX_AGE=168`, `N8N_METRICS=false`,
  `N8N_SECURE_COOKIE=false`, **`NODE_FUNCTION_ALLOW_BUILTIN=fs`**.
- Config artifacts: `lab/soar01/workflow.json` (importable) + `lab/soar01/workflow.md` (build notes).
- Snapshot `base-phase4` taken after isolation (NAT detached).

## SOAR pipeline

```
Sysmon EID 22 (WIN01) -> Wazuh rule 100047 (SOC01) -> integratord custom-forward-to-n8n
   -> POST http://10.10.30.20:5678/webhook/soar -> n8n workflow
   -> VirusTotal /api/v3/domains/{domain} -> /srv/soar/{incidents,notifications,audit.log}
```

Workflow (7 nodes): **Webhook** `POST /soar` → **extract** (domain) → **vt-lookup** (VirusTotal,
Header Auth `x-apikey`) → **build-incident** → **write-incident** → **write-notification** →
**write-audit** (Code + `fs`).

Outputs on SOAR01:
- `/srv/soar/incidents/<alert-id>.json` — full alert + VT enrichment.
- `/srv/soar/notifications/latest.json` — analyst page (overwritten each run).
- `/srv/soar/audit.log` — append-only audit line.

## Gotchas

- **n8n 2.x activation = Publish.** A DB `active=1` alone does not register the webhook; publishing is
  async via the publication outbox. Container restart re-registers published webhooks.
- **Expression fields need a leading `=`** — `=https://www.virustotal.com/api/v3/domains/{{ $json.domain }}`.
- **Webhook body is nested under `json.body`** in the trigger node output.
- **`require('fs')` needs `NODE_FUNCTION_ALLOW_BUILTIN=fs`** (the 1.x `N8N_CODE_ENABLE_BUILTIN_MODULES`
  is ignored in 2.x).
- **VT 404 on unknown domains stops the workflow** (HTTP node errors on non-2xx). Use a domain VT knows.
- **NAT is demo-only.** Detached in the snapshot; re-attach temporarily to let the VT call reach the
  internet, then detach again.
- **Clock:** no NTP — check `date -u` after any host sleep; if it drifted, fix and restart the container.
- **Owner login:** `soaradmin@corp.lab` (password in `.local-credentials.md`); the REST login endpoint
  may reject it — use the UI.

## Snapshot layout

- `base-phase4` — Docker + n8n + published workflow, NAT detached, no demo runs.
