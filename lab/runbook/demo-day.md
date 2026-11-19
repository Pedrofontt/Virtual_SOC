# Demo day — UC-13 (DNS → Wazuh → n8n → VirusTotal)

Start three VMs, run one DNS lookup, watch the chain. Everything is pre-configured.

**Stored state:** all three VMs off, SOAR01 NAT **attached** (needed for VirusTotal),
`demo-ready` snapshot on each VM.

Tags: **[HOST]** = host PowerShell · **[BROWSER]** = host browser · **[WIN01]** = the VM
window (or the `win` helper below).

---

## 1. One-time setup — [HOST]

Open PowerShell on the host and paste this once per session:

```powershell
$vb   = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$plink = "C:\Program Files\PuTTY\plink.exe"

function soc($cmd)  { & $plink -batch -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123  socadmin@10.10.30.10  "echo socadmin123 | sudo -S $cmd" }
function soar($cmd) { & $plink -batch -hostkey "SHA256:L0z4KGt1aq87MtiZCTB+7+JAlCl3dFOrveJK/YsKK/E" -pw soaradmin123 soaradmin@10.10.30.20  $cmd }
function win($ps)   { & $vb guestcontrol WIN01 run --exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" --username labadmin --password labadmin123 -- -NoProfile -Command $ps }
function win-reboot   { & $vb guestcontrol WIN01 run --exe C:\Windows\System32\shutdown.exe --username labadmin --password labadmin123 -- /r /f /t 0 }
function win-shutdown { & $vb guestcontrol WIN01 run --exe C:\Windows\System32\shutdown.exe --username labadmin --password labadmin123 -- /s /f /t 0 }
```

## 2. Start the VMs — [HOST]

```powershell
& $vb startvm SOC01  --type headless
& $vb startvm WIN01  --type separate     # separate = visible window; headless to hide
& $vb startvm SOAR01 --type headless
```

Wait until all three answer:

```powershell
curl.exe -k -s -o NUL -w "%{http_code}`n" https://10.10.30.10          # 302
curl.exe -k -s -o NUL -w "%{http_code}`n" https://10.10.30.10:55000    # 401
curl.exe -s  -o NUL -w "%{http_code}`n" http://10.10.30.20:5678        # 200
soc "/var/ossec/bin/agent_control -l"                                  # 001 win01 Active
```

## 3. Reset WIN01 after a practice run — [HOST]

A failed lookup of `malware.wicar.org` sticks in the DNS cache; `ipconfig /flushdns` does
**not** clear it. Reboot is the fix — then **don't query again** until the demo:

```powershell
win-reboot
```

Wait ~60 s and confirm the cache is empty (expect `0`):

```powershell
win "(Get-DnsClientCache -Name malware.wicar.org -ErrorAction SilentlyContinue | Measure-Object).Count"
```

## 4. Run the demo — [WIN01]

In the WIN01 window (no elevation needed):

```powershell
ipconfig /flushdns
Resolve-DnsName -Type A malware.wicar.org     # timeout is expected
```

## 5. Show the chain

1. **Wazuh Discover** — [BROWSER] `https://10.10.30.10`: filter `rule.id:100047`, range
   **Last 15 minutes**. Alert: agent `win01`, `queryName: malware.wicar.org`, level 12,
   T1071.004.
2. **Integration** — [HOST]:
   ```powershell
   soc "tail -2 /var/ossec/logs/integrations.log"      # ... HTTP:200
   ```
3. **SOAR outputs** — [HOST]:
   ```powershell
   soar "ls -lt /srv/soar/incidents | head -3; cat /srv/soar/notifications/latest.json; tail -1 /srv/soar/audit.log"
   ```

## 6. Benign control — [WIN01]

```powershell
Resolve-DnsName -Type TXT example.com      # Sysmon event, no 100047 alert
```

## 7. Stop — [HOST]

```powershell
win-shutdown
& $vb controlvm SOC01  acpipowerbutton
& $vb controlvm SOAR01 acpipowerbutton
```

Leave SOAR01 `nic2=nat` attached. Detach for isolation (VM off): `& $vb modifyvm SOAR01 --nic2 none`.

---

## If something fails

| Symptom | Fix |
|---|---|
| No Sysmon EID 22 | Defender may block the name: disable real-time in WIN01, reboot. |
| Query instant, no event | Cache not clean: `win-reboot`, retry once. |
| Integration not 200 | SOAR01 up? NAT attached? `soar "docker ps"` |
| Webhook not registered | `soar "docker restart n8n"` |
| VirusTotal 404 | Unknown domain; use `malware.wicar.org`. |
| Duplicate audit lines | Known dedup gap, cosmetic. |
| SOC01 won't boot | `& $vb snapshot SOC01 restore demo-ready` (VM off). |

## Notes

- Defender real-time can stay **ON** (verified 2026-11-16).
- Never run the demo query twice on the same boot — use step 3.
- SOC01 runs 2 vCPU + `paravirtprovider=none` for boot stability; unrelated to the demo.
