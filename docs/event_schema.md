# Event Schema

This document describes the two record types used by ThreatHunt Lab:

1. **Event documents**: production-style Windows process-creation telemetry.
2. **Evaluation labels**: test metadata stored in a separate file.

The validator in `src/threathunt_lab/validation.py` enforces the rules below.
Field definitions live in `src/threathunt_lab/schema.py`.

## ECS alignment statement

Event field names were chosen to match
[Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
field names. The schema has **not** been validated against any specific ECS
release, so it is not claimed to be ECS-compliant. In particular, the documents
omit `ecs.version` on purpose, since no version has been verified.

## 1. Event documents

**File:** `data/synthetic/process_creation_events.json`

**Format:** a JSON array of objects. Each object is a nested JSON document, the
form Elasticsearch stores and returns. Fields are referred to by dotted path
(`process.parent.name` means `{"process": {"parent": {"name": ...}}}`).

### Required fields

| Field | JSON type | ECS? | Notes |
|---|---|---|---|
| `@timestamp` | string | ECS | UTC, ISO 8601, explicit `Z` suffix. See [Timestamps](#timestamps). |
| `event.id` | string | ECS | Stable identifier. **Must be unique within the dataset** (a project rule; ECS itself does not guarantee uniqueness). |
| `event.category` | array of strings | ECS | Must include `process`. ECS allows arrays for this field. |
| `event.type` | array of strings | ECS | Must include `start` (process creation). Not listed in the project spec, but added because it is the usual way to select process-start events in ECS data. |
| `event.action` | string | ECS | Source-specific action name. This dataset uses `start`; other data sources use different values. |
| `host.name` | string | ECS | Host where the process started. |
| `user.name` | string | ECS | Account that started the process. |
| `process.name` | string | ECS | Image file name, e.g. `powershell.exe`. Case is preserved as logged. |
| `process.executable` | string | ECS | Full path to the executable. |
| `process.command_line` | string | ECS | Full command line as logged. **Untrusted, inert text; never executed.** |
| `process.parent.name` | string | ECS | Parent process image name. |
| `process.parent.command_line` | string | ECS | Parent process command line. |

Every event field is an ECS field name. The event documents contain **no custom
project fields**.

### Validation rules

- Every required field must be present.
- String fields must be non-empty, and must not consist only of whitespace.
- Array fields must be non-empty arrays of non-empty strings.
- `event.id` values must be unique across the file.
- Events must not contain the top-level keys `evaluation`, `label` or `labels`.
  Evaluation metadata belongs in the labels file, never in telemetry.
- Extra fields are allowed and ignored. Real ECS documents carry many more
  fields than this project requires.

### Timestamps

Accepted format: `YYYY-MM-DDTHH:MM:SS[.ffffff]Z`

- Must be UTC, with a literal `Z`. Offsets such as `+00:00` are rejected so that
  the dataset uses one consistent form.
- Fractional seconds are optional, with 1 to 6 digits. The sample data uses
  milliseconds (`.000`).
- The value must be a real calendar date and time. Hour `24` is rejected.
- Only ASCII digits are accepted.

Chronological ordering is **not** a validation rule, because real telemetry can
arrive out of order. The sample dataset happens to be ordered, and a test checks
that property for the sample file only.

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

### Common ECS fields deliberately not included (yet)

The following fields are common in real process telemetry but are left out to
keep the dataset small: `process.pid`, `process.entity_id`, `process.args`,
`process.parent.executable`, `process.pe.original_file_name`, `process.hash.*`,
`user.domain`, `host.os.*`, `event.kind`, `agent.*`, `ecs.version`.

Because `process.pe.original_file_name` is missing, a renamed PowerShell binary
cannot be recognised from these fields. Scenario `S16` exists to make that
limitation visible.

## 2. Evaluation labels

**File:** `data/synthetic/process_creation_labels.json`

All label fields are **custom project fields**, not ECS. They describe what a
test scenario expects. They are *not* evidence about whether activity is
malicious.

### Document structure

```json
{
  "schema_version": "1",
  "detection_objective": {
    "id": "powershell-hidden-or-remote-code",
    "description": "..."
  },
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

| Field | Type | Allowed values | Meaning |
|---|---|---|---|
| `schema_version` | string | — | Version of this labels format. |
| `detection_objective.id` | string | — | Identifier of the objective that `expected_outcome` refers to. |
| `detection_objective.description` | string | — | Plain-language statement of that objective. |
| `labels[].event_id` | string | must match an `event.id` | Links the label to exactly one event. |
| `labels[].scenario_id` | string | — | Human-readable test scenario identifier. |
| `labels[].classification` | string | `benign`, `suspicious_looking` | How the scenario was *designed*. There is intentionally no `malicious` value. |
| `labels[].expected_outcome` | string | `alert`, `no_alert` | What a detection meeting the stated objective should do for this event. |
| `labels[].rationale` | string | — | Why the scenario exists and why the outcome is expected. |

### Rules

- Every event has exactly one label, and every label refers to an existing event.
- `classification` and `expected_outcome` are independent. For example, scenario
  `S11` is `benign` but `alert`: a legitimate management tool whose behaviour
  falls inside the detection objective. This is a known benign trigger.
  Scenario `S16` is `suspicious_looking` and `alert`, but a name-based detection
  is expected to miss it.
- `expected_outcome` only makes sense relative to `detection_objective`. The
  current objective is **provisional** and will be revisited when the detection
  is designed in Milestone 3. Labels may change at that point.

## Why labels are stored in a separate file

- A detection under test can be given only the events file, so it cannot "see"
  the answer.
- Event documents stay shaped like real telemetry, so the same documents could
  later be indexed into Elasticsearch without being stripped first.
- Evaluation assumptions are reviewed in one place.
