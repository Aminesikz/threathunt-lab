# D001: PowerShell encoded command or download and execute

| | |
|---|---|
| **Rule** | [`sigma/powershell_encoded_or_download_cradle.yml`](sigma/powershell_encoded_or_download_cradle.yml) |
| **Based on** | Hunt [H001](../hunts/H001-powershell-process-creation.md) |
| **Status / level** | experimental / medium |
| **Formats** | Sigma (source), Elastic EQL (converted with sigma-cli) |

## What it detects

PowerShell (`powershell.exe` or `pwsh.exe`) started with either:

1. an **encoded command**: `-EncodedCommand` or one of its short forms, or
2. a **download and execute** command line: something that downloads content
   (`DownloadString`, `Invoke-WebRequest`, ...) **and** runs it with `IEX` /
   `Invoke-Expression`.

This is the detection objective in the labels file
(`powershell-hidden-or-remote-code`). Both behaviours hide what PowerShell
really runs: either the code is encoded, or it is downloaded and never written
to disk.

## Why

The hunt found these behaviours in every event that still needed follow-up
(H001 §7). It also showed what does **not** work well on its own, so those
things are left out of the rule:

- `-NoProfile` and hidden windows: common in normal automation (H001 Q4).
- PowerShell ISE: an editor. The hunt saw no use of it with these flags.

## Logic

```text
PowerShell image
AND (encoded-command flag  OR  (download AND invoke-expression))
```

| Part | Sigma | Why |
|---|---|---|
| PowerShell image | `Image\|endswith` `\powershell.exe`, `\pwsh.exe`, or `OriginalFileName` `PowerShell.EXE`, `pwsh.dll` | `OriginalFileName` comes from the file itself, so it still works when the binary is renamed (if the data has it) |
| Encoded flag | `CommandLine\|windash\|contains` `' -e '`, `' -ec '`, `' -en '`, `' -enc '`, `' -enco'` | See below |
| Download | `CommandLine\|contains` `DownloadString`, `DownloadData`, `Invoke-WebRequest`, `Invoke-RestMethod` | Common ways to fetch a script into memory |
| Invoke | `CommandLine\|contains` `IEX`, `Invoke-Expression` | Runs the downloaded text. Requiring both parts keeps the rule narrow |

How the encoded flag is matched, and the hunt problem each choice fixes:

- **Spaces around the flag** (`' -enc '`). The flag has to be a separate word,
  so `q4-encryption-audit.txt` doesn't match. That was a false match in H001 Q4.
- **Case doesn't matter.** Sigma matches case-insensitively by default, and
  PowerShell's parameters are case-insensitive too, so `-eNc` matches. The KQL
  query in H001 Q4 missed it.
- **Short forms.** Microsoft's `pwsh` documentation lists `-EncodedCommand | -e
  | -ec`. `-en` and `-enc` are shorter forms commonly seen in attacks.
  `' -enco'` (no trailing space) covers `-enco`, `-encod`, ... up to
  `-EncodedCommand`.
- **`windash`.** Also matches the flag written with `/` or a Unicode dash (for
  example `/enc` or `–enc`). Microsoft's `powershell.exe` page notes that
  from `cmd.exe` you can use either a hyphen or a forward slash.

## Required fields

The `ecs_windows` pipeline in sigma-cli maps the Sigma field names to ECS:

| Sigma field | ECS field | In our dataset? |
|---|---|---|
| `Image` | `process.executable` | Yes |
| `OriginalFileName` | `process.pe.original_file_name` | **No** |
| `CommandLine` | `process.command_line` | Yes |

The rule needs `process.command_line`. On Windows Security event 4688, the
command line is only logged when the "Include command line in process creation
events" policy is turned on.

## ATT&CK mapping

| Technique | Tactic | Why it's mapped |
|---|---|---|
| T1059.001 PowerShell | Execution | The rule only matches PowerShell |
| T1027.010 Command Obfuscation | Stealth | The encoded-command branch |
| T1105 Ingress Tool Transfer | Command and Control | The download branch |

ATT&CK v20 split the old Defense Evasion tactic, and T1027.010 is now under
**Stealth**. `sigma check` flagged the old `attack.defense-evasion` tag as
invalid. Not mapped, even though H001 mentions them: T1204.002 (the rule
doesn't look at the Office parent) and T1036.003 (the rule doesn't detect the
renaming itself).

## Elastic version (EQL)

Converted with:

```bash
.venv/bin/sigma check detections/sigma/powershell_encoded_or_download_cradle.yml
.venv/bin/sigma convert -t eql -p ecs_windows detections/sigma/powershell_encoded_or_download_cradle.yml
```

`sigma check` result: 0 errors, 0 issues. Converted query:

```eql
any where ((process.executable.caseless like~ ("*\\powershell.exe", "*\\pwsh.exe")) or (process.pe.original_file_name like~ ("PowerShell.EXE", "pwsh.dll"))) and ((process.command_line like~ ("* -e *", "* /e *", "* –e *", "* —e *", "* ―e *") or process.command_line like~ ("* -ec *", "* /ec *", "* –ec *", "* —ec *", "* ―ec *") or process.command_line like~ ("* -en *", "* /en *", "* –en *", "* —en *", "* ―en *") or process.command_line like~ ("* -enc *", "* /enc *", "* –enc *", "* —enc *", "* ―enc *") or process.command_line like~ ("* -enco*", "* /enco*", "* –enco*", "* —enco*", "* ―enco*")) or ((process.command_line like~ ("*DownloadString*", "*DownloadData*", "*Invoke-WebRequest*", "*Invoke-RestMethod*")) and (process.command_line like~ ("*IEX*", "*Invoke-Expression*"))))
```

Notes:

- **Why EQL and not Lucene.** sigma-cli can also produce a Lucene query, but in
  the Lucene output `process.command_line` is matched without any
  case-insensitive option, so `-eNc` would be missed again. EQL's `like~`
  ignores case.
- **Use it as an EQL rule** in Elastic Security, with the index pattern of your
  process events (for example `logs-endpoint.events.process-*`).
- **`process.executable.caseless`** must exist in your mapping. It isn't a
  base ECS field. Check your index before using the rule.
- **Not run on a cluster.** The query was produced by sigma-cli but has not
  been run in Elastic.

## Expected false positives

- Management or deployment tools that pass scripts with `-EncodedCommand`. In
  our data this is `thl-evt-0011` (deployagent.exe), labelled as an expected
  alert. If it gets noisy, add a narrow exclusion (that parent path + that
  service account), not "ignore encoded commands".
- Admins or developers testing encoded commands.
- Installers that download and run a setup script.

## Known gaps

- **Renamed PowerShell without `OriginalFileName`.** Without PE metadata, a
  renamed binary is missed. In our data this is `thl-evt-0016`, which is
  expected to be missed.
- **Obfuscation.** Aliases like `iwr ... | iex` written differently, string
  concatenation, `&(gcm i*x)`, or Base64 decoded inside `-Command`
  (`FromBase64String`) aren't covered.
- **Unusual spacing.** A flag followed by a tab or wrapped in quotes doesn't
  match `' -enc '`.
- **`-EncodedArguments`** (Windows PowerShell 5.1) isn't covered.
- **PowerShell inside other programs.** Code run through PowerShell's .NET
  library by a different `.exe` doesn't start `powershell.exe` at all.

## How it will be tested (Milestone 4)

Sigma is a rule format, not a program. It can't run on our JSON files by
itself. Milestone 4 will:

1. Add a short Python function that applies the same logic to each event.
2. Add a test that fails if that function's patterns ever differ from the
   Sigma file, so the two can't drift apart.
3. Run it over the events only, then compare with the labels to count true and
   false positives and negatives.
