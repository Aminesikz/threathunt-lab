"""Field definitions for events and labels. See docs/event_schema.md."""

# Returned by get_field() when a field isn't there. A special object, not None,
# so "missing" and "present but null" can be told apart.
MISSING = object()

# Required event fields and their type:
#   "string"      = non-empty text
#   "string_list" = non-empty list of non-empty text (ECS allows lists here)
REQUIRED_EVENT_FIELDS = {
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

# Labels belong in the labels file. These keys inside an event are rejected.
FORBIDDEN_EVENT_KEYS = {"evaluation", "label", "labels"}

# Label values. There's deliberately no "malicious".
LABEL_CLASSIFICATIONS = {"benign", "suspicious_looking"}
LABEL_EXPECTED_OUTCOMES = {"alert", "no_alert"}
REQUIRED_LABEL_FIELDS = ["event_id", "scenario_id", "classification", "expected_outcome", "rationale"]


def get_field(document, dotted_path: str):
    """Look up a field like "process.parent.name" in a nested event, or return MISSING."""
    if dotted_path == "@timestamp":  # a normal key that happens to have no dots
        return document.get("@timestamp", MISSING) if isinstance(document, dict) else MISSING

    current = document
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return MISSING
        current = current[part]
    return current
