# D001: PowerShell encoded command or download and execute

| | |
|---|---|
| **Rule** | [`sigma/powershell_encoded_or_download_cradle.yml`](sigma/powershell_encoded_or_download_cradle.yml) |
| **Based on** | Hunt [H001](../hunts/H001-powershell-process-creation.md) |
| **Status / level** | experimental / medium |
| **Results** | [`reports/evaluation.md`](../reports/evaluation.md) |

## What it detects

PowerShell (`powershell.exe` or `pwsh.exe`) started with either:

1. an **encoded command** (`-EncodedCommand` or a short form like `-enc`), or
2. a **download and execute** command: it downloads something
   (`DownloadString`, `Invoke-WebRequest`, ...) **and** runs it with `IEX`.

Both hide what PowerShell really runs: the code is either encoded, or
downloaded and never saved to disk.

## The logic

```text
PowerShell
AND (encoded-command flag  OR  (download AND IEX))
```

| Part | What the rule checks |
|---|---|
| PowerShell | The path ends with `\powershell.exe` or `\pwsh.exe`, **or** the original file name is `PowerShell.EXE` / `pwsh.dll` |
| Encoded flag | The command line contains `' -e '`, `' -ec '`, `' -en '`, `' -enc '` or `' -enco'` |
| Download | `DownloadString`, `DownloadData`, `Invoke-WebRequest` or `Invoke-RestMethod` |
| Run it | `IEX` or `Invoke-Expression` |

Why it's built this way (each point fixes something from the hunt):

- **Spaces around the flag** (`' -enc '`), so `q4-encryption-audit.txt`
  doesn't match (`thl-evt-0008`).
- **Ignores case.** Sigma does this by default, so `-eNc` matches
  (`thl-evt-0012`).
- **Short forms.** Microsoft's docs list `-e` and `-ec` for `-EncodedCommand`.
  `' -enco'` (no space at the end) covers everything from `-enco` up to
  `-EncodedCommand`.
- **`windash`** also catches the flag written with `/` or a Unicode dash, like
  `/enc`.
- **Original file name** catches renamed PowerShell, if the data has it.
- **Download and `IEX` must both be there**, so a plain download doesn't alert.
- **Left out:** `-NoProfile` and hidden windows. The hunt showed both are
  common in normal automation.

## Fields it needs

| Sigma field | ECS field | In our data? |
|---|---|---|
| `Image` | `process.executable` | Yes |
| `OriginalFileName` | `process.pe.original_file_name` | **No** |
| `CommandLine` | `process.command_line` | Yes |

With Windows Security event 4688, the command line is only logged if
command-line logging is turned on.

## ATT&CK mapping

| Technique | Tactic | Why |
|---|---|---|
| T1059.001 PowerShell | Execution | It only matches PowerShell |
| T1027.010 Command Obfuscation | Stealth | The encoded-command part |
| T1105 Ingress Tool Transfer | Command and Control | The download part |

In ATT&CK v20, T1027.010 moved from "Defense Evasion" to **Stealth**.
`sigma check` rejected the old tag.

## Elastic version (EQL)

```bash
.venv/bin/sigma check detections/sigma/powershell_encoded_or_download_cradle.yml
.venv/bin/sigma convert -t eql -p ecs_windows detections/sigma/powershell_encoded_or_download_cradle.yml
```

`sigma check`: 0 errors, 0 issues. The converted query:

```eql
any where ((process.executable.caseless like~ ("*\\powershell.exe", "*\\pwsh.exe")) or (process.pe.original_file_name like~ ("PowerShell.EXE", "pwsh.dll"))) and ((process.command_line like~ ("* -e *", "* /e *", "* –e *", "* —e *", "* ―e *") or process.command_line like~ ("* -ec *", "* /ec *", "* –ec *", "* —ec *", "* ―ec *") or process.command_line like~ ("* -en *", "* /en *", "* –en *", "* —en *", "* ―en *") or process.command_line like~ ("* -enc *", "* /enc *", "* –enc *", "* —enc *", "* ―enc *") or process.command_line like~ ("* -enco*", "* /enco*", "* –enco*", "* —enco*", "* ―enco*")) or ((process.command_line like~ ("*DownloadString*", "*DownloadData*", "*Invoke-WebRequest*", "*Invoke-RestMethod*")) and (process.command_line like~ ("*IEX*", "*Invoke-Expression*"))))
```

- **Why EQL and not Lucene?** sigma-cli's Lucene version matches the command
  line case-sensitively, so it would miss `-eNc` again. EQL's `like~` ignores
  case.
- Use it as an **EQL rule** in Elastic Security, on your process-event index.
- `process.executable.caseless` must exist in your index (Elastic Defend has
  it; plain ECS doesn't).
- **Not run on a real cluster.**

## Expected false positives

- **Management and deployment tools** that use `-EncodedCommand`, like
  `thl-evt-0011`. If they get noisy, add a narrow exclusion (that program's
  path + that service account), never "ignore all encoded commands".
- Admins or developers testing encoded commands.
- Installers that download and run a setup script.

## Known gaps

- **Renamed PowerShell without the original file name** is missed
  (`thl-evt-0016` in our data).
- **Obfuscation:** aliases like `iwr ... | iex`, split-up strings, or Base64
  decoded inside the script (`FromBase64String`).
- **A tab or quotes** around the flag instead of spaces.
- **`-EncodedArguments`** (Windows PowerShell 5.1).
- **PowerShell inside another program** that doesn't start `powershell.exe`.

## Testing and results (Milestone 4)

Sigma can't run on JSON files by itself, so:

1. [`detection.py`](../src/threathunt_lab/detection.py) does the same checks
   in Python. A test fails if its patterns ever differ from the Sigma file.
2. `python -m threathunt_lab evaluate` runs it on each event (it never sees
   the labels), then compares with the labels.
3. The results are in [`reports/evaluation.md`](../reports/evaluation.md). A
   test reruns the evaluation and fails if the report is out of date.

Extra tests cover things the dataset doesn't have: `-e`, `-ec`, `/enc`, a
Unicode dash, `Invoke-WebRequest | Invoke-Expression`, a download without
`IEX`, `-ExecutionPolicy` (starts with `-e` but isn't the flag), a renamed
binary **with** an original file name, and missing or broken fields.

**What the results show:**
- **No false positives.** The lookalikes from the hunt didn't alert.
- **One miss: `thl-evt-0016`**, the renamed binary, as expected. A test shows
  the rule catches it when the original file name is there.
- **`thl-evt-0011` alerted**, which is correct for this rule. But it's a
  legitimate tool (a "benign true positive"), so it would need a check with
  its owners.
- **The results are optimistic.** The rule was built from the hunt on these
  same 16 events. New events the rule has never seen would be a fairer test.
