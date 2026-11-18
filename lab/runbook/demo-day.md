# Demo day — UC-13 (DNS → Wazuh → n8n → VirusTotal)

Everything is pre-configured. Start three VMs, run one DNS lookup, watch the chain.

**State when stored:** SOC01, WIN01, SOAR01 powered off. SOAR01 has its NAT adapter
**attached** (`nic2=nat`) — required for the VirusTotal call. Snapshots `demo-ready` exist
on all three.

## Where each command runs

| Tag | Meaning |
|---|---|
| **[HOST]** | Windows PowerShell on the physical host |
| **[BROWSER]** | Browser on the host |
| **[SOC01]** | Shell inside SOC01 — run from the host with `plink` (or SSH into the VM) |
| **[SOAR01]** | Shell inside SOAR01 — run from the host with `plink` (or SSH into the VM) |
| **[WIN01]** | PowerShell inside WIN01 — either the VM window (GUI) or `guestcontrol` from the host |

`plink` commands are typed on the host but execute on the VM. Use `curl.exe` (not `curl`) on
the host: in PowerShell 5.1 `curl` is an alias for `Invoke-WebRequest`, which does not accept
`-k`. `NUL` discards the body; `%{http_code}` prints only the status.

---

## 1. Start the VMs — [HOST]

```powershell
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vb startvm SOC01  --type headless    # wait for dashboard/API (~60-90 s)
& $vb startvm WIN01  --type separate    # separate = visible VM window (use headless to hide)
& $vb startvm SOAR01 --type headless
```

`--type headless` = no window (access via SSH/`guestcontrol`). `--type separate` = normal VM
window. Use `separate` for WIN01 if you want to type the demo command on screen.

### Readiness checks — [HOST]

```powershell
curl.exe -k -s -o NUL -w "%{http_code}`n" https://10.10.30.10          # 302 = dashboard up
curl.exe -k -s -o NUL -w "%{http_code}`n" https://10.10.30.10:55000    # 401 = API up
curl.exe -s  -o NUL -w "%{http_code}`n" http://10.10.30.20:5678        # 200 = n8n up
```

Agent 001 must be `Active` — **[HOST]** (executes on SOC01):

```powershell
& "C:\Program Files\PuTTY\plink.exe" -batch `
  -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 `
  socadmin@10.10.30.10 "echo socadmin123 | sudo -S /var/ossec/bin/agent_control -l"
```

Expect `ID: 001, Name: win01 ... Active`. If not, wait 30 s and retry.

## 2. Pre-flight (30 seconds)

- Rule 100047 and integratord — **[HOST]** (executes on SOC01):

  ```powershell
  & "C:\Program Files\PuTTY\plink.exe" -batch `
    -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 `
    socadmin@10.10.30.10 "echo socadmin123 | sudo -S sh -c 'grep -c 100047 /var/ossec/etc/rules/local_rules.xml; /var/ossec/bin/wazuh-control status | grep integratord'"
  ```

  Expect `1`, then `wazuh-integratord is running...`.

- n8n container — **[HOST]** (executes on SOAR01):

  ```powershell
  & "C:\Program Files\PuTTY\plink.exe" -batch `
    -hostkey "SHA256:L0z4KGt1aq87MtiZCTB+7+JAlCl3dFOrveJK/YsKK/E" -pw soaradmin123 `
    soaradmin@10.10.30.20 "docker ps --format '{{.Names}} {{.Status}}'"
  ```

- WIN01 DNS cache is clean (expect `0`) — **[WIN01]** via `guestcontrol` from **[HOST]**:

  ```powershell
  & $vb guestcontrol WIN01 run --exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    --username labadmin --password labadmin123 -- -NoProfile -Command `
    "(Get-DnsClientCache -Name malware.wicar.org -ErrorAction SilentlyContinue | Measure-Object).Count"
  ```

- Open the Wazuh dashboard — **[BROWSER]**: `https://10.10.30.10`.

## 3. Run the demo — [WIN01]

In the WIN01 window (PowerShell; elevation not required):

```powershell
ipconfig /flushdns
Resolve-DnsName -Type A malware.wicar.org     # timeout is expected
```

Headless alternative — run from **[HOST]** via `guestcontrol`:

```powershell
& $vb guestcontrol WIN01 run --exe "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
  --username labadmin --password labadmin123 -- -NoProfile -Command `
  "ipconfig /flushdns | Out-Null; try { Resolve-DnsName -Type A malware.wicar.org -ErrorAction Stop } catch { 'query-error: ' + `$_.Exception.Message }"
```

Then show:

1. **Discover** — **[BROWSER]**: filter `rule.id:100047`, range **Last 15 minutes**; open the
   alert (Sysmon EID 22, `queryName: malware.wicar.org`, agent `win01`, level 12, T1071.004).
2. Integration POST — **[HOST]** (executes on SOC01):

   ```powershell
   & "C:\Program Files\PuTTY\plink.exe" -batch `
     -hostkey "SHA256:h9rirGAifvJjmZK2Ppdc177c72FOewK6EDwjKUKAyoo" -pw socadmin123 `
     socadmin@10.10.30.10 "echo socadmin123 | sudo -S tail -2 /var/ossec/logs/integrations.log"
   ```

   Expect `... HTTP:200`.

3. SOAR outputs — **[HOST]** (executes on SOAR01):

   ```powershell
   & "C:\Program Files\PuTTY\plink.exe" -batch `
     -hostkey "SHA256:L0z4KGt1aq87MtiZCTB+7+JAlCl3dFOrveJK/YsKK/E" -pw soaradmin123 `
     soaradmin@10.10.30.20 "ls -lt /srv/soar/incidents | head -3; cat /srv/soar/notifications/latest.json; tail -1 /srv/soar/audit.log"
   ```

## 4. Benign control — [WIN01]

```powershell
Resolve-DnsName -Type TXT example.com
```

A Sysmon EID 22 event appears; **no** rule-100047 alert.

## 5. Shut down — [HOST]

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

| Symptom | Fix (where) |
|---|---|
| No Sysmon EID 22 for the exact domain | **[WIN01]** Defender may now block it: disable real-time protection interactively (Tamper is off), then reboot WIN01. |
| Query returns instantly and no event | **[WIN01]** Cached/blocked name: reboot WIN01 (a clean shutdown clears the cache). |
| Integration log shows non-200 | **[HOST]** Check SOAR01 is up, NAT attached, container running (`docker ps` on SOAR01). |
| Webhook not registered | **[SOAR01]** `docker restart n8n` re-registers published workflows. |
| VirusTotal 404 and no files | VirusTotal did not know the domain: the HTTP node errors before writing. Use a VT-known domain. |
| Duplicate incident/audit lines | Known dedup gap: Wazuh forwarded the same alert twice. Cosmetic. |
| SOC01 will not boot (initramfs stall) | **[HOST]** Restore `demo-ready` (VM off): `VBoxManage snapshot SOC01 restore demo-ready`. |

## Notes

- Defender real-time can stay **ON**; the chain was verified with it on (2026-11-16).
- SOC01 was restored from `base-phase1-fixed` and its rules + integration were re-applied
  from this repository; `demo-ready` snapshot captures that fixed state.
- SOC01 currently runs with 2 vCPUs and `paravirtprovider=none` (boot stability). This does
  not affect the demo.
