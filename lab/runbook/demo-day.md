# Demo day — UC-13 (DNS → Wazuh → n8n → VirusTotal)

Everything is pre-configured. Start three VMs, run one DNS lookup, watch the chain.

**State when stored:** SOC01, WIN01, SOAR01 powered off. SOAR01 has its NAT adapter
**attached** (`nic2=nat`) — required for the VirusTotal call. Snapshots `demo-ready` exist
on all three.

---

## 1. Start (in this order)

```powershell
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vb startvm SOC01  --type headless    # wait for dashboard/API (~60-90 s)
& $vb startvm WIN01  --type headless
& $vb startvm SOAR01 --type headless
```

Wait until:

- Wazuh dashboard: `https://10.10.30.10` returns 302/200
- Wazuh API: `https://10.10.30.10:55000` returns 401
- n8n: `http://10.10.30.20:5678` returns 200
- Agent 001 (win01) is `Active`:

```powershell
& "C:\Program Files\PuTTY\plink.exe" -batch `
  -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 `
  socadmin@10.10.30.10 "echo socadmin123 | sudo -S /var/ossec/bin/agent_control -l"
```

## 2. Pre-flight (30 seconds)

- Rule 100047 deployed and integratord running (already verified at store time):
  ```bash
  sudo /var/ossec/bin/wazuh-control status | grep integratord
  sudo grep -c 100047 /var/ossec/etc/rules/local_rules.xml   # => 1
  ```
- n8n workflow published (webhook answers POST).
- WIN01 DNS cache is clean after the clean shutdown (no need to restart `dnscache`).

## 3. Run the demo

WIN01 (PowerShell; elevation not required):

```powershell
ipconfig /flushdns
Resolve-DnsName -Type A malware.wicar.org     # timeout is expected
```

Then show:

1. Wazuh **Discover** — filter `rule.id:100047`; open the alert (Sysmon EID 22,
   `queryName: malware.wicar.org`, agent `win01`).
2. SOC01 — integration POST:
   ```bash
   sudo tail -2 /var/ossec/logs/integrations.log   # ... HTTP:200
   ```
3. SOAR01 — outputs:
   ```bash
   ls -lt /srv/soar/incidents | head
   cat /srv/soar/notifications/latest.json
   tail -2 /srv/soar/audit.log
   ```

## 4. Benign control

```powershell
Resolve-DnsName -Type TXT example.com
```

A Sysmon EID 22 event appears; **no** rule-100047 alert.

## 5. Shut down

```powershell
& $vb guestcontrol WIN01 run --exe C:\Windows\System32\shutdown.exe `
  --username labadmin --password labadmin123 -- /s /f /t 0
& $vb controlvm SOC01  acpipowerbutton
& $vb controlvm SOAR01 acpipowerbutton
```

Leave SOAR01 `nic2=nat` attached for the next demo. Detach it for normal isolation:
`& $vb modifyvm SOAR01 --nic2 none` (VM must be off).

---

## If something fails

| Symptom | Fix |
|---|---|
| No Sysmon EID 22 for the exact domain | Defender may now block it: disable real-time protection **interactively** in WIN01 (Tamper is off), then reboot WIN01. |
| Query returns instantly and no event | Cached/blocked name: reboot WIN01 (a clean shutdown clears the cache). |
| Integration log shows non-200 | Is SOAR01 up and NAT attached? Is the n8n container running? `docker ps` |
| Webhook not registered | `docker restart n8n` re-registers published workflows. |
| VirusTotal 404 and no files | Unknown domain: the HTTP node errors before writing. Use a VT-known domain. |
| Duplicate incident/audit lines | Known dedup gap: Wazuh forwarded the same alert twice. Cosmetic. |
| SOC01 will not boot (initramfs stall) | Restore `demo-ready` (VM off): `VBoxManage snapshot SOC01 restore demo-ready`. |

## Notes

- Defender real-time can stay **ON**; the chain was verified with it on (2026-11-16).
- SOC01 was restored from `base-phase1-fixed` and its rules + integration were re-applied
  from this repository; `demo-ready` snapshot captures that fixed state.
- SOC01 currently runs with 2 vCPUs and `paravirtprovider=none` (boot stability). This does
  not affect the demo.
