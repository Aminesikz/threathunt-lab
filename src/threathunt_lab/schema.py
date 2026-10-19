"""Field definitions for events and labels. See docs/event_schema.md.

Events are nested JSON, and fields are looked up by dotted path, e.g.
get_field(event, "process.parent.name").
"""

from __future__ import annotations

from typing import Any, Final

# Sentinel distinguishing "field absent" from "field present with value None".
MISSING: Final = object()

# Required event fields and their expected JSON type.
# "string": a non-empty string.
# "string_list": a non-empty list of non-empty strings (ECS allows arrays for
#                event.category and event.type).
REQUIRED_EVENT_FIELDS: Final[dict[str, str]] = {
    "@timestamp": "string",
    "event.id": "string",
    "event.category": "string_list",
    "event.type": "string_list",
    "event.action": "string",
    "host.name": "string",
    "user.name": "string",
    "process.name": "string",
    "process.executable": "string",
    "process.command_line": "string",
    "process.parent.name": "string",
    "process.parent.command_line": "string",
}

# This dataset contains process-creation events only.
REQUIRED_EVENT_CATEGORY: Final = "process"
REQUIRED_EVENT_TYPE: Final = "start"

# Top-level keys that would indicate evaluation metadata has leaked into the
# production-style telemetry. Labels belong in the separate labels file.
FORBIDDEN_EVENT_KEYS: Final[frozenset[str]] = frozenset(
    {"evaluation", "label", "labels"}
)

# Evaluation label vocabulary (custom project fields, not ECS).
# "suspicious_looking" deliberately avoids implying confirmed malicious activity.
LABEL_CLASSIFICATIONS: Final[frozenset[str]] = frozenset(
    {"benign", "suspicious_looking"}
)
LABEL_EXPECTED_OUTCOMES: Final[frozenset[str]] = frozenset({"alert", "no_alert"})
REQUIRED_LABEL_FIELDS: Final[tuple[str, ...]] = (
    "event_id",
    "scenario_id",
    "classification",
    "expected_outcome",
    "rationale",
)


def get_field(document: dict[str, Any], dotted_path: str) -> Any:
    """Return the value at ``dotted_path`` in a nested document, or MISSING.

    ``@timestamp`` is a literal top-level key, not a nested path.
    """
    if dotted_path == "@timestamp":
        return document.get("@timestamp", MISSING)

    current: Any = document
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return MISSING
        current = current[part]
    return current
