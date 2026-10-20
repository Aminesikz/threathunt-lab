"""Load and validate the dataset files.

The files are treated as untrusted: size limit, UTF-8 only, no duplicate JSON
keys (json would silently keep the last one) and no NaN/Infinity.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from threathunt_lab.schema import get_field
from threathunt_lab.validation import validate_events, validate_label_coverage, validate_labels

MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB, far more than the sample data needs

DEFAULT_EVENTS_PATH = Path("data/synthetic/process_creation_events.json")
DEFAULT_LABELS_PATH = Path("data/synthetic/process_creation_labels.json")


class DatasetError(Exception):
    """A file couldn't be read or parsed."""


class DatasetValidationError(DatasetError):
    """A file was read but has validation issues."""

    def __init__(self, source, issues) -> None:
        self.issues = issues
        details = "\n".join(f"  - {issue}" for issue in issues)
        super().__init__(f"{source}: {len(issues)} validation issue(s):\n{details}")


@dataclass
class Dataset:
    events: list[dict]
    labels_by_event_id: dict[str, dict]
    detection_objective: dict

    def label_for(self, event: dict) -> dict:
        return self.labels_by_event_id[get_field(event, "event.id")]


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def reject_constant(name):
    raise ValueError(f"non-standard JSON constant {name!r} is not allowed")


def read_json(path: Path):
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
        return json.loads(text, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant)
    except json.JSONDecodeError as exc:
        raise DatasetError(f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    except ValueError as exc:  # from reject_duplicate_keys or reject_constant
        raise DatasetError(f"{path}: {exc}") from exc


def load_events(path: Path) -> list[dict]:
    events = read_json(path)
    issues = validate_events(events)
    if issues:
        raise DatasetValidationError(path, issues)
    return events


def load_labels(path: Path) -> dict:
    document = read_json(path)
    issues = validate_labels(document)
    if issues:
        raise DatasetValidationError(path, issues)
    return document


def load_dataset(events_path: Path = DEFAULT_EVENTS_PATH, labels_path: Path = DEFAULT_LABELS_PATH) -> Dataset:
    """Load the events and the labels, and check they match one to one."""
    events = load_events(events_path)
    document = load_labels(labels_path)
    labels = document["labels"]

    issues = validate_label_coverage(events, labels)
    if issues:
        raise DatasetValidationError(labels_path, issues)

    return Dataset(
        events=events,
        labels_by_event_id={label["event_id"]: label for label in labels},
        detection_objective=document["detection_objective"],
    )
