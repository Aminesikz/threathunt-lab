# Data

## `synthetic/`

| File | Contents |
|---|---|
| `process_creation_events.json` | 16 synthetic Windows process-creation events (ECS-style field names). |
| `process_creation_labels.json` | Evaluation labels for those events, stored separately. |

The schema is described in [`docs/event_schema.md`](../docs/event_schema.md).

### Provenance

- Every record was **created manually for this project**. No record was
  produced by running the commands it describes, and no malware, sandbox, or
  real environment was used.
- Host names, user names, the `ExampleCorp` deployment agent and file paths are
  fictional.
- The only IP address (`198.51.100.23`) comes from the RFC 5737 documentation
  range. `intranet.example.com` uses a reserved example domain.
- The encoded PowerShell commands are UTF-16LE Base64 encodings of harmless
  `Write-Output '...'` strings, such as
  `Write-Output 'ThreatHunt Lab synthetic event - inert'`. You can decode them
  safely, for example in Python:
  `base64.b64decode(value).decode("utf-16-le")`.
- There are no credentials, secrets or real personal data.

### Scenario summary

| Scenario | Classification | Expected outcome | Purpose |
|---|---|---|---|
| S01–S03, S07 | benign | no_alert | Routine non-PowerShell activity |
| S04, S05, S14 | benign | no_alert | Ordinary interactive PowerShell / ISE / editor terminal |
| S06, S15 | benign | no_alert | Scheduled on-disk scripts (S15 uses a hidden window) |
| S08 | benign | no_alert | `-enc` appears only as a substring of a file name |
| S09, S10, S13 | suspicious_looking | alert | Encoded command from Office; download-and-execute pattern; PowerShell 7 |
| S11 | benign | alert | Legitimate tool using `-EncodedCommand` (known benign trigger) |
| S12 | suspicious_looking | alert | Upper case and abbreviated `-eNc` parameter |
| S16 | suspicious_looking | alert | Renamed PowerShell binary (known detection gap) |

The full rationale for each event is in `process_creation_labels.json`.

### Limitations

- The dataset is **tiny and hand-picked**. Its benign/suspicious ratio says
  nothing about how often this activity happens in real environments. Any
  metrics calculated on it will not reflect production detection performance.
- `suspicious_looking` describes how a scenario was designed. It does not mean
  the activity is confirmed malicious.
- Each event is a standalone process start. There are no process trees, network
  events, or script-block logs to correlate with.
- Command lines are realistic in shape but simplified.

### Safety

Treat every field as untrusted, inert text. Do not copy command lines into a
shell or PowerShell session.
