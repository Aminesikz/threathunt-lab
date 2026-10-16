"""Explicit validation of event records and evaluation labels.

Validators never raise on bad data. They return a list of
:class:`ValidationIssue` so that every problem in a file is reported at once,
which is more useful than fixing one error per run. Raising is left to the
loader (see ``loader.py``).

Event content is treated as untrusted, inert text: values are type-checked and
compared, never executed or interpreted.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from threathunt_lab.schema import (
    FORBIDDEN_EVENT_KEYS,
    LABEL_CLASSIFICATIONS,
    LABEL_EXPECTED_OUTCOMES,
    MISSING,
    REQUIRED_EVENT_CATEGORY,
    REQUIRED_EVENT_FIELDS,
    REQUIRED_EVENT_TYPE,
    REQUIRED_LABEL_FIELDS,
    get_field,
)

# UTC only, explicit "Z" suffix, optional fractional seconds (up to microseconds).
# [0-9] is used instead of \d, which would also match non-ASCII digits.
# Hours are limited to 00-23: newer Python versions accept "24:00:00" as the
# next day's midnight, but that form is ambiguous and rejected here.
_TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z"
)


@dataclass(frozen=True)
class ValidationIssue:
    """A single problem found in a dataset file."""

    location: str
    message: str
    field: str | None = None

    def __str__(self) -> str:
        where = f"{self.location} field '{self.field}'" if self.field else self.location
        return f"{where}: {self.message}"


def parse_utc_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 UTC timestamp such as ``2026-01-15T08:00:00.000Z``.

    Raises ValueError with a readable message if the value is malformed, is
    not explicitly UTC, or is not a real calendar date/time.
    """
    if not _TIMESTAMP_PATTERN.fullmatch(value):
        raise ValueError(
            f"timestamp {value!r} must be ISO 8601 UTC with a 'Z' suffix, "
            "e.g. 2026-01-15T08:00:00.000Z"
        )
    try:
        # Python 3.11+ parses the "Z" suffix as UTC.
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"timestamp {value!r} is not a valid date/time: {exc}") from exc


def _describe_event(index: int, record: Any) -> str:
    event_id = get_field(record, "event.id") if isinstance(record, dict) else MISSING
    if isinstance(event_id, str) and event_id:
        return f"events[{index}] ({event_id})"
    return f"events[{index}]"


def _check_type(value: Any, expected: str) -> str | None:
    """Return an error message if ``value`` does not match ``expected``."""
    if expected == "string":
        if not isinstance(value, str):
            return f"must be a string, got {type(value).__name__}"
        if not value.strip():
            return "must not be empty"
        return None
    if expected == "string_list":
        if not isinstance(value, list) or not value:
            return "must be a non-empty list of strings"
        if not all(isinstance(item, str) and item.strip() for item in value):
            return "must contain only non-empty strings"
        return None
    raise ValueError(f"unknown expected type {expected!r}")  # programming error


def validate_event(record: Any, index: int) -> list[ValidationIssue]:
    """Validate a single process-creation event record."""
    location = _describe_event(index, record)
    if not isinstance(record, dict):
        return [ValidationIssue(location, f"must be a JSON object, got {type(record).__name__}")]

    issues: list[ValidationIssue] = []

    for key in sorted(FORBIDDEN_EVENT_KEYS & record.keys()):
        issues.append(
            ValidationIssue(
                location,
                "evaluation metadata must be stored in the labels file, not in the event",
                field=key,
            )
        )

    # Fields that are present and correctly typed; only these get content checks,
    # so each broken field produces a single, specific issue.
    well_typed: set[str] = set()
    for field, expected in REQUIRED_EVENT_FIELDS.items():
        value = get_field(record, field)
        if value is MISSING:
            issues.append(ValidationIssue(location, "required field is missing", field))
        elif type_error := _check_type(value, expected):
            issues.append(ValidationIssue(location, type_error, field))
        else:
            well_typed.add(field)

    if "@timestamp" in well_typed:
        try:
            parse_utc_timestamp(record["@timestamp"])
        except ValueError as exc:
            issues.append(ValidationIssue(location, str(exc), "@timestamp"))

    required_values = {
        "event.category": REQUIRED_EVENT_CATEGORY,
        "event.type": REQUIRED_EVENT_TYPE,
    }
    for field, required in required_values.items():
        if field in well_typed and required not in get_field(record, field):
            issues.append(ValidationIssue(location, f"must include {required!r}", field))

    return issues


def validate_events(records: Any) -> list[ValidationIssue]:
    """Validate a list of event records, including event ID uniqueness."""
    if not isinstance(records, list):
        return [
            ValidationIssue(
                "events file", f"top level must be a JSON array, got {type(records).__name__}"
            )
        ]
    if not records:
        return [ValidationIssue("events file", "contains no events")]

    issues: list[ValidationIssue] = []
    for index, record in enumerate(records):
        issues.extend(validate_event(record, index))

    ids = [
        event_id
        for record in records
        if isinstance(record, dict)
        and isinstance(event_id := get_field(record, "event.id"), str)
        and event_id
    ]
    for event_id, count in sorted(Counter(ids).items()):
        if count > 1:
            issues.append(
                ValidationIssue(
                    "events file",
                    f"event ID {event_id!r} appears {count} times; IDs must be unique",
                    "event.id",
                )
            )
    return issues


def validate_label(label: Any, index: int) -> list[ValidationIssue]:
    """Validate a single evaluation label."""
    location = f"labels[{index}]"
    if isinstance(label, dict) and isinstance(label.get("event_id"), str):
        location = f"labels[{index}] ({label['event_id']})"
    if not isinstance(label, dict):
        return [ValidationIssue(location, f"must be a JSON object, got {type(label).__name__}")]

    issues: list[ValidationIssue] = []
    for field in REQUIRED_LABEL_FIELDS:
        if field not in label:
            issues.append(ValidationIssue(location, "required field is missing", field))
            continue
        type_error = _check_type(label[field], "string")
        if type_error:
            issues.append(ValidationIssue(location, type_error, field))

    allowed_values = {
        "classification": LABEL_CLASSIFICATIONS,
        "expected_outcome": LABEL_EXPECTED_OUTCOMES,
    }
    for field, allowed in allowed_values.items():
        value = label.get(field)
        if isinstance(value, str) and value.strip() and value not in allowed:
            issues.append(
                ValidationIssue(
                    location, f"{value!r} is not one of {sorted(allowed)}", field
                )
            )
    return issues


def validate_labels(document: Any) -> list[ValidationIssue]:
    """Validate the structure of the evaluation labels document."""
    if not isinstance(document, dict):
        return [
            ValidationIssue(
                "labels file", f"top level must be a JSON object, got {type(document).__name__}"
            )
        ]

    issues: list[ValidationIssue] = []

    version = document.get("schema_version", MISSING)
    if version is MISSING:
        issues.append(ValidationIssue("labels file", "required field is missing", "schema_version"))
    elif type_error := _check_type(version, "string"):
        issues.append(ValidationIssue("labels file", type_error, "schema_version"))

    objective = document.get("detection_objective", MISSING)
    if not isinstance(objective, dict):
        issues.append(
            ValidationIssue(
                "labels file", "must be an object with 'id' and 'description'", "detection_objective"
            )
        )
    else:
        for key in ("id", "description"):
            value = objective.get(key, MISSING)
            field = f"detection_objective.{key}"
            if value is MISSING:
                issues.append(ValidationIssue("labels file", "required field is missing", field))
            elif type_error := _check_type(value, "string"):
                issues.append(ValidationIssue("labels file", type_error, field))

    labels = document.get("labels", MISSING)
    if not isinstance(labels, list) or not labels:
        issues.append(ValidationIssue("labels file", "must be a non-empty array", "labels"))
        return issues

    for index, label in enumerate(labels):
        issues.extend(validate_label(label, index))

    ids = [
        label["event_id"]
        for label in labels
        if isinstance(label, dict) and isinstance(label.get("event_id"), str)
    ]
    for event_id, count in sorted(Counter(ids).items()):
        if count > 1:
            issues.append(
                ValidationIssue(
                    "labels file",
                    f"event ID {event_id!r} has {count} labels; expected exactly one",
                    "event_id",
                )
            )
    return issues


def validate_label_coverage(
    events: list[dict[str, Any]], labels: list[dict[str, Any]]
) -> list[ValidationIssue]:
    """Check that every event has a label and every label refers to an event.

    Assumes both inputs have already passed structural validation.
    """
    event_ids = {get_field(event, "event.id") for event in events}
    label_ids = {label["event_id"] for label in labels}

    issues = [
        ValidationIssue("labels file", f"no label for event ID {event_id!r}", "event_id")
        for event_id in sorted(event_ids - label_ids)
    ]
    issues.extend(
        ValidationIssue(
            "labels file", f"label refers to unknown event ID {event_id!r}", "event_id"
        )
        for event_id in sorted(label_ids - event_ids)
    )
    return issues
