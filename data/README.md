# Data

| File | What's in it |
|---|---|
| `synthetic/process_creation_events.json` | 16 synthetic Windows process-start events |
| `synthetic/process_creation_labels.json` | The expected result for each event (kept separate) |

The format is described in [`docs/event_schema.md`](../docs/event_schema.md).

## Where the data comes from

- Every event was **created manually for this project**. Nothing was produced
  by running the commands, and no malware or real environment was used.
- Host names, user names, file paths and the `ExampleCorp` tool are made up.
- The only IP address, `198.51.100.23`, is from a range reserved for
  documentation (RFC 5737). `intranet.example.com` is a reserved example domain.
- The encoded PowerShell commands only decode to harmless `Write-Output '...'`
  text. You can safely decode them in Python with
  `base64.b64decode(value).decode("utf-16-le")`.
- There are no passwords, secrets or real personal data.

## Scenarios

| Scenario | Classification | Expected | What it tests |
|---|---|---|---|
| S01–S03, S07 | benign | no_alert | Normal non-PowerShell activity |
| S04, S05, S14 | benign | no_alert | Normal PowerShell, VS Code terminal, ISE |
| S06, S15 | benign | no_alert | Scheduled scripts (S15 has a hidden window) |
| S08 | benign | no_alert | `-enc` only inside a file name |
| S09, S10, S13 | suspicious_looking | alert | Encoded command from Office, download and run, PowerShell 7 |
| S11 | benign | alert | Real tool using `-EncodedCommand` (a known innocent alert) |
| S12 | suspicious_looking | alert | Mixed case `-eNc` |
| S16 | suspicious_looking | alert | Renamed PowerShell (a known gap) |

Each event's full reason is in the labels file.

## Limitations

- **Tiny and hand-picked.** It says nothing about how common this activity is
  in real networks, and results on it don't show real-world performance.
- `suspicious_looking` describes how a test was designed, not a confirmed
  attack.
- Each event stands alone: no process trees, network events or PowerShell
  script logs.

## Safety

Treat every field as untrusted text. Never paste a command line into a shell
or PowerShell.
