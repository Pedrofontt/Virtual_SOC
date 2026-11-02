# UC-06 — NDR marker (exit gate)

Status: PASS

## Hypothesis
A deliberately-marked HTTP request from WIN01 to SOC01 is visible to the passive NDR
sensor and fires the custom marker rule, proving the whole NDR pipeline (Suricata →
Wazuh agent 003 → SOC01 manager → custom rule) end to end.

## Detection logic
- Source: Suricata `eve.json` `alert` event → Wazuh agent 003 → manager rule 86601 chain.
- Suricata `7000001`: `alert http any any -> any any (msg:"LAB NDR marker - lab-ndr-test UA";
  flow:established,to_server; http.user_agent; content:"lab-ndr-test"; nocase; ...)`
- Wazuh `100040` (level 8): child of 86601, keyed on
  `<field name="alert.signature_id" type="pcre2">^7000001$</field>`.

## Trigger
From WIN01:
```powershell
Invoke-WebRequest -Uri http://10.10.10.5 -Headers @{User-Agent='lab-ndr-test'}
```

## Expected vs observed
Expected: `100040` (level 8) for the `lab-ndr-test` UA, agent 003.
Observed: `100040` fired (dashboard + `alerts.json` + `eve.json` signature_id 7000001).

## Benign control / False positives
- Benign: default PowerShell `Invoke-WebRequest` UA → silent (no `lab-ndr-test`).
- FP risk: none — the marker string is unique to this exercise.

## Cleanup
None. Marker is a one-shot gate; no state retained.
