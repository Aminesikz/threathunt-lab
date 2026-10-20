"""Validation of events and labels.

Each function returns a list of issues instead of stopping at the first
problem, so one run shows everything that's wrong with a file.
"""

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

from threathunt_lab.schema import (
    FORBIDDEN_EVENT_KEYS,
    LABEL_CLASSIFICATIONS,
    LABEL_EXPECTED_OUTCOMES,
    MISSING,
    REQUIRED_EVENT_FIELDS,
    REQUIRED_LABEL_FIELDS,
    get_field,
)

# UTC with a "Z" at the end, optional fractions of a second. [0-9] instead of
# \d because \d also matches non-ASCII digits. Hour 24 isn't allowed.
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z"
)


@dataclass
class ValidationIssue:
    location: str  # e.g. "events[3] (thl-evt-0004)"
    message: str
    field: str | None = None

    def __str__(self) -> str:
        where = f"{self.location} field '{self.field}'" if self.field else self.location
        return f"{where}: {self.message}"


def parse_utc_timestamp(value: str) -> datetime:
    """Parse a timestamp like 2026-01-15T08:00:00.000Z, or raise ValueError."""
    if not TIMESTAMP_PATTERN.fullmatch(value):
        raise ValueError(
            f"timestamp {value!r} must be ISO 8601 UTC with a 'Z' suffix, "
            "e.g. 2026-01-15T08:00:00.000Z"
        )
    try:
        return datetime.fromisoformat(value)  # also catches dates like 30 February
    except ValueError as exc:
        raise ValueError(f"timestamp {value!r} is not a valid date/time: {exc}") from exc


def type_error(value, expected: str) -> str | None:
    """Return a message if the value has the wrong type, otherwise None."""
    if expected == "string":
        if not isinstance(value, str):
            return f"must be a string, got {type(value).__name__}"
        if not value.strip():
            return "must not be empty"
    if expected == "string_list":
        if not isinstance(value, list) or not value:
            return "must be a non-empty list of strings"
        if not all(isinstance(item, str) and item.strip() for item in value):
            return "must contain only non-empty strings"
    return None


def duplicates(ids: list[str]) -> list[tuple[str, int]]:
    """Return (id, count) for every id that appears more than once."""
    return [(id_, count) for id_, count in sorted(Counter(ids).items()) if count > 1]


# --- Events -----------------------------------------------------------------


def validate_event(record, index: int) -> list[ValidationIssue]:
    location = f"events[{index}]"
    if not isinstance(record, dict):
        return [ValidationIssue(location, f"must be a JSON object, got {type(record).__name__}")]
    event_id = get_field(record, "event.id")
    if isinstance(event_id, str) and event_id:
        location += f" ({event_id})"

    issues = []
    for key in sorted(FORBIDDEN_EVENT_KEYS & record.keys()):
        issues.append(ValidationIssue(
            location, "evaluation metadata must be stored in the labels file, not in the event", key
        ))

    for field, expected in REQUIRED_EVENT_FIELDS.items():
        value = get_field(record, field)
        if value is MISSING:
            issues.append(ValidationIssue(location, "required field is missing", field))
            continue
        error = type_error(value, expected)
        if error:
            issues.append(ValidationIssue(location, error, field))
            continue

        # The type is right, so now check the content.
        if field == "@timestamp":
            try:
                parse_utc_timestamp(value)
            except ValueError as exc:
                issues.append(ValidationIssue(location, str(exc), field))
        if field == "event.category" and "process" not in value:
            issues.append(ValidationIssue(location, "must include 'process'", field))
        if field == "event.type" and "start" not in value:
            issues.append(ValidationIssue(location, "must include 'start'", field))
    return issues


def validate_events(records) -> list[ValidationIssue]:
    if not isinstance(records, list):
        return [ValidationIssue(
            "events file", f"top level must be a JSON array, got {type(records).__name__}"
        )]
    if not records:
        return [ValidationIssue("events file", "contains no events")]

    issues = []
    ids = []
    for index, record in enumerate(records):
        issues += validate_event(record, index)
        event_id = get_field(record, "event.id")
        if isinstance(event_id, str) and event_id:
            ids.append(event_id)

    for event_id, count in duplicates(ids):
        issues.append(ValidationIssue(
            "events file", f"event ID {event_id!r} appears {count} times; IDs must be unique", "event.id"
        ))
    return issues


# --- Labels -----------------------------------------------------------------


def validate_label(label, index: int) -> list[ValidationIssue]:
    location = f"labels[{index}]"
    if not isinstance(label, dict):
        return [ValidationIssue(location, f"must be a JSON object, got {type(label).__name__}")]
    if isinstance(label.get("event_id"), str):
        location += f" ({label['event_id']})"

    issues = []
    for field in REQUIRED_LABEL_FIELDS:
        if field not in label:
            issues.append(ValidationIssue(location, "required field is missing", field))
            continue
        error = type_error(label[field], "string")
        if error:
            issues.append(ValidationIssue(location, error, field))

    allowed_values = {
        "classification": LABEL_CLASSIFICATIONS,
        "expected_outcome": LABEL_EXPECTED_OUTCOMES,
    }
    for field, allowed in allowed_values.items():
        value = label.get(field)
        if isinstance(value, str) and value.strip() and value not in allowed:
            issues.append(ValidationIssue(location, f"{value!r} is not one of {sorted(allowed)}", field))
    return issues


def check_string(document: dict, key: str, field_name: str) -> list[ValidationIssue]:
    """Check that document[key] exists and is non-empty text."""
    if key not in document:
        return [ValidationIssue("labels file", "required field is missing", field_name)]
    error = type_error(document[key], "string")
    return [ValidationIssue("labels file", error, field_name)] if error else []


def validate_labels(document) -> list[ValidationIssue]:
    if not isinstance(document, dict):
        return [ValidationIssue(
            "labels file", f"top level must be a JSON object, got {type(document).__name__}"
        )]

    issues = check_string(document, "schema_version", "schema_version")

    objective = document.get("detection_objective")
    if isinstance(objective, dict):
        issues += check_string(objective, "id", "detection_objective.id")
        issues += check_string(objective, "description", "detection_objective.description")
    else:
        issues.append(ValidationIssue(
            "labels file", "must be an object with 'id' and 'description'", "detection_objective"
        ))

    labels = document.get("labels")
    if not isinstance(labels, list) or not labels:
        issues.append(ValidationIssue("labels file", "must be a non-empty array", "labels"))
        return issues

    ids = []
    for index, label in enumerate(labels):
        issues += validate_label(label, index)
        if isinstance(label, dict) and isinstance(label.get("event_id"), str):
            ids.append(label["event_id"])

    for event_id, count in duplicates(ids):
        issues.append(ValidationIssue(
            "labels file", f"event ID {event_id!r} has {count} labels; expected exactly one", "event_id"
        ))
    return issues


def validate_label_coverage(events: list[dict], labels: list[dict]) -> list[ValidationIssue]:
    """Every event needs exactly one label, and every label needs an event."""
    event_ids = {get_field(event, "event.id") for event in events}
    label_ids = {label["event_id"] for label in labels}

    issues = []
    for event_id in sorted(event_ids - label_ids):
        issues.append(ValidationIssue("labels file", f"no label for event ID {event_id!r}", "event_id"))
    for event_id in sorted(label_ids - event_ids):
        issues.append(ValidationIssue("labels file", f"label refers to unknown event ID {event_id!r}", "event_id"))
    return issues
