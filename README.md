# ThreatHunt Lab

A reproducible, Python-based lab for threat hunting and detection engineering on
synthetic Windows security telemetry.

The project follows the detection engineering lifecycle:

**Hunting hypothesis → Telemetry → Investigation → Detection → Testing → Evaluation → Documentation**

The first use case is investigating potentially suspicious **PowerShell
process-creation** events. The project does not need an Elastic cluster.
Telemetry uses ECS-style field names so that hunting queries and detections
written later carry over to Elastic Security.

> **Status:** Milestone 2 (first threat hunt) is complete and awaiting review.
> The project has no detection rules yet. They come in Milestone 3.

## Repository layout

```text
.
├── README.md
├── pyproject.toml             # Packaging and pytest configuration
├── src/threathunt_lab/
│   ├── schema.py              # Required fields, label vocabulary, dotted-path lookup
│   ├── validation.py          # Event and label validation (returns all issues)
│   ├── loader.py              # Defensive JSON loading and dataset assembly
│   ├── hunt.py                # Hunt H001: steps Q1–Q7, stacking, Base64 decoding
│   └── __main__.py            # `python -m threathunt_lab {validate,hunt}`
├── data/
│   ├── README.md              # Provenance, scenarios, limitations
│   └── synthetic/
│       ├── process_creation_events.json   # Telemetry only
│       └── process_creation_labels.json   # Evaluation metadata only
├── docs/
│   └── event_schema.md        # Field reference and ECS alignment notes
├── hunts/
│   └── H001-powershell-process-creation.md   # Hypothesis, queries, findings
└── tests/                     # pytest suite
```

Directories for detections and reports will be added in the milestones that
need them.

## Setup

Requires Python 3.11 or newer. Development has used Python 3.14 on macOS
(Apple Silicon). There are no runtime dependencies. `pytest` is the only
development dependency.

```bash
python3 -m venv .venv                       # skip if .venv already exists
.venv/bin/python -m pip install -e ".[dev]"
```

## Usage

Validate the bundled synthetic dataset from the repository root:

```bash
.venv/bin/python -m threathunt_lab validate
```

Expected output:

```text
Validation passed
  events:            16 (data/synthetic/process_creation_events.json)
  labels:            16 (data/synthetic/process_creation_labels.json)
  objective:         powershell-hidden-or-remote-code
  classifications:   {'benign': 11, 'suspicious_looking': 5}
  expected outcomes: {'alert': 6, 'no_alert': 10}
```

To validate other files, pass
`--events path/to/events.json --labels path/to/labels.json`. On failure the
command exits with status `1` and lists every issue, for example:

```text
events[0] (thl-evt-0001) field '@timestamp': timestamp '2026-01-15 08:00' must be ISO 8601 UTC with a 'Z' suffix, e.g. 2026-01-15T08:00:00.000Z
```

Run threat hunt H001 (PowerShell process creation) over the events. It reads
the events file only, never the labels:

```bash
.venv/bin/python -m threathunt_lab hunt               # all steps, Q1–Q7
.venv/bin/python -m threathunt_lab hunt --step Q4     # one step (repeatable)
```

The write-up, with the Elastic queries, observed output and conclusions, is
[`hunts/H001-powershell-process-creation.md`](hunts/H001-powershell-process-creation.md).

From Python:

```python
from threathunt_lab.loader import load_dataset

dataset = load_dataset()  # default paths, relative to the repository root
for event in dataset.events:
    label = dataset.label_for(event)
```

## Testing

```bash
.venv/bin/python -m pytest
```

The pytest configuration adds `src/` to the import path, so the tests run even
if the editable install is not working (see Troubleshooting).

## Design decisions

- **Labels are kept apart from telemetry.** Events and evaluation labels live in
  two files, joined by `event.id`. A detection under test can be given only
  the events, so it cannot see the expected answer. The validator rejects
  events that embed `evaluation`/`label`/`labels` keys. See
  [`docs/event_schema.md`](docs/event_schema.md).
- **Nested ECS-style documents.** Events are stored the way Elasticsearch stores
  them, and fields are addressed by dotted path (`process.parent.name`).
- **Validation collects every issue.** Validators return a list of issues
  instead of stopping at the first one, so one run shows everything wrong
  with a file. The loader raises a single `DatasetValidationError` that
  contains them all.
- **Input is untrusted.** The loader caps file size and requires UTF-8. It
  rejects duplicate JSON keys, which Python's `json` would otherwise resolve
  silently, and it rejects `NaN`/`Infinity`. Command lines are only ever
  treated as text.
- **No `malicious` label.** Synthetic scenarios are classified `benign` or
  `suspicious_looking`. `expected_outcome` is defined relative to a stated
  detection objective. It is not a verdict on intent.
- **Hunting never sees the labels.** The `hunt` command loads events with
  `load_events()`, not `load_dataset()`, and a test runs it with no labels
  file present. A hunter has no answer key.
- **Documented results are checked against real runs.** Tests re-run the hunt
  and fail if any output quoted in the hunt write-up has changed.
- **Standard library only.** No third-party runtime dependencies so far.

## Milestones

- [x] **Milestone 1: Project foundation and synthetic data**
  - [x] Python project structure, `pyproject.toml`, pytest configuration
  - [x] Documented event schema (`docs/event_schema.md`)
  - [x] Synthetic dataset with benign and suspicious-looking events
  - [x] Evaluation labels stored separately from telemetry
  - [x] Loading and validation: required fields, types, UTC timestamps, unique IDs, label coverage
  - [x] Automated tests
  - [x] README and `.gitignore`
- [x] **Milestone 2: First threat hunt** (awaiting review)
  - [x] Specific hunting hypothesis about PowerShell process creation
  - [x] Relevant telemetry, data sources and fields explained
  - [x] Elastic KQL and ES|QL queries (in the write-up) plus an equivalent local `hunt` command
  - [x] Documented investigation workflow (Q1–Q7) with observed output
  - [x] Findings, benign explanations, limitations and conclusions
  - [x] Hand-off notes for Milestone 3
- [ ] Milestone 3: Detection engineering
- [ ] Milestone 4: Automated detection testing
- [ ] Milestone 5: Portfolio release

## Limitations

- The dataset has 16 hand-written synthetic events. It does not represent how
  common this activity is in real environments, and it cannot measure
  production detection performance.
- Field names follow ECS, but the schema has not been validated against a
  specific ECS release.
- The labels' detection objective is provisional and may be refined in
  Milestone 3.
- Fields such as `process.pe.original_file_name` are not modelled, so some
  evasions (for example, a renamed binary) cannot be represented fully.
- The Elastic queries in the hunt write-up have been checked against Elastic's
  documentation but **not run on a cluster**. The local `hunt` command is the
  executed reference.

## Troubleshooting

**`No module named threathunt_lab` after `pip install -e .` on macOS.**
Recent Python versions (3.13 and later) skip `.pth` files that carry the
macOS `hidden` file flag at start-up. This is a security hardening. If the project sits in an
iCloud-synced folder (such as `~/Documents` with "Desktop & Documents Folders"
turned on), macOS can mark files inside `.venv` as hidden, so the editable
install's `.pth` file is ignored. To check, run:

```bash
ls -lO .venv/lib/python3*/site-packages/*.pth   # "hidden" in the flags column confirms it
```

Workarounds:

- Run commands with `PYTHONPATH=src`, for example
  `PYTHONPATH=src .venv/bin/python -m threathunt_lab validate`.
- Better: keep the project in a folder that is not synced by iCloud, then
  recreate `.venv`.

The test suite is not affected, because pytest adds `src/` to the path itself.

## Safety

All telemetry is synthetic and inert. Never execute command lines taken from
event data. See [`data/README.md`](data/README.md) for dataset provenance.
