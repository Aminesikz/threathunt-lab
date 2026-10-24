# Event schema

The dataset has two files:

1. **Events**: process-start events, shaped like real telemetry. The PowerShell
   data is Windows, the PHP2Shell data (`php_web_events.json`) is Linux.
   Both use the same fields and rules.
2. **Labels**: the expected answers for testing, kept in a separate file.

The rules below are checked by [`validation.py`](../src/threathunt_lab/validation.py).

## Events

**File:** `data/synthetic/process_creation_events.json`, a JSON list of events.

Events are nested JSON, the way Elasticsearch stores them. A field like
`process.parent.name` means `{"process": {"parent": {"name": ...}}}`.

Field names follow [ECS](https://www.elastic.co/guide/en/ecs/current/index.html)
(Elastic Common Schema), but the schema hasn't been checked against a specific
ECS version, so it isn't claimed to be fully ECS-compliant.

### Required fields

| Field | Type | Notes |
|---|---|---|
| `@timestamp` | text | UTC time with a `Z`, e.g. `2026-01-15T08:00:00.000Z` |
| `event.id` | text | Must be unique in the file |
| `event.category` | list of text | Must include `process` |
| `event.type` | list of text | Must include `start` |
| `event.action` | text | `start` in this dataset |
| `host.name` | text | Computer name |
| `user.name` | text | Account that started the process |
| `process.name` | text | File name, e.g. `powershell.exe` (case kept as logged) |
| `process.executable` | text | Full path to the program |
| `process.command_line` | text | Full command line. **Only ever read as text, never run** |
| `process.parent.name` | text | Program that started this process |
| `process.parent.command_line` | text | The parent's command line |

### Rules

- Every required field must be there, with the right type.
- Text can't be empty or only spaces. Lists can't be empty.
- `event.id` must be unique.
- Timestamps must be UTC with a `Z` (not `+00:00`), with up to 6 decimal
  places, and a real date and time (no 30 February, no hour 24).
- Events can't contain `label`, `labels` or `evaluation` keys. Answers belong
  in the labels file.
- Extra fields are allowed, because real events have many more fields.

### Example

```json
{
  "@timestamp": "2026-01-15T08:01:12.000Z",
  "event": {"id": "thl-evt-0001", "category": ["process"], "type": ["start"], "action": "start"},
  "host": {"name": "WKS-FIN-01"},
  "user": {"name": "user.fin01"},
  "process": {
    "name": "notepad.exe",
    "executable": "C:\\Windows\\System32\\notepad.exe",
    "command_line": "\"C:\\Windows\\System32\\notepad.exe\" C:\\Users\\user.fin01\\Documents\\notes.txt",
    "parent": {"name": "explorer.exe", "command_line": "C:\\Windows\\Explorer.EXE"}
  }
}
```

### Fields left out

Real process events usually also have `process.pid`, `process.entity_id`,
`process.pe.original_file_name`, `process.hash.*` and more. They're left out
to keep the data small. Because `process.pe.original_file_name` is missing, a
renamed PowerShell can't be recognised (scenario S16).

### Extra fields in the Linux data

| Field | Notes |
|---|---|
| `host.os.type` | `linux` |
| `process.parent.executable` | The parent's full path. Detection D002 needs it. Left out of `php-evt-0013` on purpose (scenario P13) |

## Labels

**File:** `data/synthetic/process_creation_labels.json`

These are project fields, not ECS. They describe what a test expects, **not**
whether something is really malicious.

```json
{
  "schema_version": "1",
  "detection_objective": {"id": "powershell-hidden-or-remote-code", "description": "..."},
  "labels": [
    {
      "event_id": "thl-evt-0009",
      "scenario_id": "S09-office-spawns-encoded-powershell",
      "classification": "suspicious_looking",
      "expected_outcome": "alert",
      "rationale": "..."
    }
  ]
}
```

| Field | Allowed values | Meaning |
|---|---|---|
| `event_id` | an `event.id` from the events file | Which event this label is for |
| `scenario_id` | any text | Name of the test scenario |
| `classification` | `benign`, `suspicious_looking` | What the activity is. There's no `malicious` on purpose |
| `expected_outcome` | `alert`, `no_alert` | Whether the detection **should** alert, given its objective |
| `rationale` | any text | Why the scenario exists |

### Rules

- Every event has exactly one label, and every label points to a real event.
- `classification` and `expected_outcome` are separate. For example, S11 is
  `benign` but `alert`: a real deployment tool doing exactly what the detection
  looks for.

## Why the labels are in a separate file

- The detection can be given only the events, so it can't see the answers.
- The events stay shaped like real telemetry.
- All the test assumptions are in one place.
