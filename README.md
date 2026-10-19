# ThreatHunt Lab

A small Python lab for practising threat hunting and detection engineering on
synthetic Windows process-creation events.

The use case is suspicious **PowerShell** activity. It follows these steps:
hypothesis → hunt → detection → testing → evaluation. Events use ECS
(Elastic Common Schema) field names, so the queries and rules carry over to
Elastic Security, but you don't need an Elastic cluster to run anything here.

## What's in the repo

```text
src/threathunt_lab/   Python code: loading, validation, the hunt
data/synthetic/       16 synthetic events + their labels (kept in separate files)
docs/                 Event schema
hunts/                H001: the PowerShell threat hunt write-up
detections/           D001: the Sigma rule and its write-up
tests/                pytest tests
```

## Setup

Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

## Usage

Check that the dataset is valid:

```bash
.venv/bin/python -m threathunt_lab validate
```

Run the threat hunt (steps Q1–Q7, or one step with `--step Q4`):

```bash
.venv/bin/python -m threathunt_lab hunt
```

Check the Sigma rule and convert it to an Elastic EQL query:

```bash
.venv/bin/sigma check detections/sigma/powershell_encoded_or_download_cradle.yml
.venv/bin/sigma convert -t eql -p ecs_windows detections/sigma/powershell_encoded_or_download_cradle.yml
```

Run the tests:

```bash
.venv/bin/python -m pytest
```

## Milestones

- [x] 1. Project setup, synthetic data, loading and validation
- [x] 2. Threat hunt H001 ([write-up](hunts/H001-powershell-process-creation.md))
- [x] 3. Detection D001 ([write-up](detections/D001-powershell-encoded-or-download.md))
- [ ] 4. Automated detection testing (true/false positives, precision, recall)
- [ ] 5. Final clean-up

## Notes

- **Labels are separate from events.** The hunt and the detection only see the
  events, never the expected answers.
- **No `malicious` label.** Events are `benign` or `suspicious_looking`, which
  describes how a test scenario was designed, not proof of an attack.
- **Limits.** 16 hand-made events can't show how common this activity is in real
  networks. The Elastic queries have been checked against Elastic's docs and
  sigma-cli, but haven't been run on a real cluster.

## Safety

All data is synthetic and inert. Never run command lines taken from the events.
See [`data/README.md`](data/README.md).
