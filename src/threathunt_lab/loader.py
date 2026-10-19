"""Load and validate the dataset files.

The files are treated as untrusted: size limit, UTF-8 only, no duplicate JSON
keys (json would silently keep the last one) and no NaN/Infinity.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from threathunt_lab.schema import get_field
from threathunt_lab.validation import (
    ValidationIssue,
    validate_events,
    validate_label_coverage,
    validate_labels,
)

MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB: far above the sample dataset size.

DEFAULT_EVENTS_PATH = Path("data/synthetic/process_creation_events.json")
DEFAULT_LABELS_PATH = Path("data/synthetic/process_creation_labels.json")


class DatasetError(Exception):
    """A dataset file could not be read or parsed."""


class DatasetValidationError(DatasetError):
    """A dataset file was parsed but failed schema validation."""

    def __init__(self, source: Path, issues: list[ValidationIssue]) -> None:
        self.source = source
        self.issues = issues
        details = "\n".join(f"  - {issue}" for issue in issues)
        super().__init__(f"{source}: {len(issues)} validation issue(s):\n{details}")


@dataclass(frozen=True)
class Dataset:
    """Validated events plus their separately stored evaluation labels."""

    events: list[dict[str, Any]]
    labels_by_event_id: dict[str, dict[str, Any]]
    detection_objective: dict[str, str]

    def label_for(self, event: dict[str, Any]) -> dict[str, Any]:
        """Return the evaluation label for an event."""
        return self.labels_by_event_id[get_field(event, "event.id")]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name!r} is not allowed")


def read_json(path: Path) -> Any:
    """Read a JSON file defensively and return the parsed value."""
    path = Path(path)
    if not path.is_file():
        raise DatasetError(f"{path}: file not found")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise DatasetError(f"{path}: file is {size} bytes; limit is {MAX_FILE_BYTES}")

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DatasetError(f"{path}: file is not valid UTF-8: {exc}") from exc

    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise DatasetError(
            f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except ValueError as exc:
        raise DatasetError(f"{path}: {exc}") from exc


def load_events(path: Path) -> list[dict[str, Any]]:
    """Load and validate process-creation events."""
    records = read_json(path)
    issues = validate_events(records)
    if issues:
        raise DatasetValidationError(Path(path), issues)
    return records


def load_labels(path: Path) -> dict[str, Any]:
    """Load and validate the evaluation labels document."""
    document = read_json(path)
    issues = validate_labels(document)
    if issues:
        raise DatasetValidationError(Path(path), issues)
    return document


def load_dataset(
    events_path: Path = DEFAULT_EVENTS_PATH,
    labels_path: Path = DEFAULT_LABELS_PATH,
) -> Dataset:
    """Load events and labels, and check that they correspond one-to-one."""
    events = load_events(events_path)
    labels_document = load_labels(labels_path)
    labels = labels_document["labels"]

    issues = validate_label_coverage(events, labels)
    if issues:
        raise DatasetValidationError(Path(labels_path), issues)

    return Dataset(
        events=events,
        labels_by_event_id={label["event_id"]: label for label in labels},
        detection_objective=labels_document["detection_objective"],
    )
