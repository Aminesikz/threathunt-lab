"""Tests for loading and validating the dataset (Milestone 1)."""

import pytest

from threathunt_lab.__main__ import main
from threathunt_lab.loader import DatasetError, DatasetValidationError, load_dataset, read_json
from threathunt_lab.schema import REQUIRED_EVENT_FIELDS
from threathunt_lab.validation import (
    parse_utc_timestamp,
    validate_event,
    validate_events,
    validate_labels,
)


def delete_field(event, dotted_path):
    """Delete a field such as "process.parent.name" from a nested event."""
    *parents, last = dotted_path.split(".")
    for part in parents:
        event = event[part]
    del event[last]


# --- Events -------------------------------------------------------------------


def test_valid_event_has_no_issues(make_event):
    assert validate_event(make_event(), 0) == []


@pytest.mark.parametrize("field", sorted(REQUIRED_EVENT_FIELDS))
def test_missing_required_field_is_reported(make_event, field):
    event = make_event()
    delete_field(event, field)
    issues = validate_event(event, 0)
    assert [(i.field, i.message) for i in issues] == [(field, "required field is missing")]


def test_wrong_field_types_are_reported(make_event):
    event = make_event()
    event["process"]["name"] = 42
    event["user"]["name"] = "   "
    event["event"]["category"] = "process"  # must be a list
    messages = {i.field: i.message for i in validate_event(event, 0)}
    assert messages == {
        "process.name": "must be a string, got int",
        "user.name": "must not be empty",
        "event.category": "must be a non-empty list of strings",
    }


def test_labels_inside_an_event_are_rejected(make_event):
    # Evaluation metadata belongs in the labels file, never in the telemetry.
    event = make_event()
    event["label"] = {"expected_outcome": "alert"}
    issues = validate_event(event, 0)
    assert [i.field for i in issues] == ["label"]


@pytest.mark.parametrize(
    "value",
    [
        "2026-01-15T08:00:00",  # no timezone
        "2026-01-15T08:00:00+00:00",  # UTC, but no "Z"
        "2026-02-30T08:00:00Z",  # 30 February does not exist
        "2026-01-15T24:00:00Z",  # hour 24
    ],
)
def test_invalid_timestamps_are_rejected(value):
    with pytest.raises(ValueError, match="timestamp"):
        parse_utc_timestamp(value)


def test_valid_timestamp_parses_as_utc():
    assert parse_utc_timestamp("2026-01-15T08:30:05.250Z").isoformat() == "2026-01-15T08:30:05.250000+00:00"


def test_duplicate_event_ids_are_reported(make_event):
    issues = validate_events([make_event("evt-a"), make_event("evt-b"), make_event("evt-a")])
    assert len(issues) == 1
    assert "'evt-a' appears 2 times" in issues[0].message


def test_all_issues_are_reported_not_just_the_first(make_event):
    first = make_event("evt-a")
    del first["user"]
    second = make_event("evt-b")
    second["@timestamp"] = "yesterday"
    issues = validate_events([first, second])
    assert {i.field for i in issues} == {"user.name", "@timestamp"}


# --- Labels ---------------------------------------------------------------------


def test_malicious_is_not_an_allowed_classification(make_labels):
    # Synthetic events are "suspicious_looking" at most, never confirmed malicious.
    document = make_labels("evt-a")
    document["labels"][0]["classification"] = "malicious"
    assert [i.field for i in validate_labels(document)] == ["classification"]


def test_events_and_labels_must_match_one_to_one(write_json, make_event, make_labels):
    events_path = write_json("events.json", [make_event("evt-a"), make_event("evt-b")])
    labels_path = write_json("labels.json", make_labels("evt-a"))
    with pytest.raises(DatasetValidationError, match="no label for event ID 'evt-b'"):
        load_dataset(events_path, labels_path)


# --- Reading JSON files safely ------------------------------------------------------


def test_missing_file_gives_clear_error(tmp_path):
    with pytest.raises(DatasetError, match="file not found"):
        read_json(tmp_path / "nope.json")


@pytest.mark.parametrize(
    ("content", "expected_error"),
    [
        ('[\n  {"event": }\n]', "invalid JSON at line 2"),
        ('{"id": "a", "id": "b"}', "duplicate JSON key 'id'"),
        ('{"value": NaN}', "non-standard JSON constant"),
    ],
)
def test_bad_json_is_rejected(tmp_path, content, expected_error):
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(DatasetError, match=expected_error):
        read_json(path)


# --- The shipped sample dataset and the validate command ----------------------------


def test_sample_dataset_loads(events_path, labels_path):
    dataset = load_dataset(events_path, labels_path)
    assert len(dataset.events) == 16
    assert len(dataset.labels_by_event_id) == 16


def test_sample_events_contain_no_label_words(events_path):
    raw_text = events_path.read_text(encoding="utf-8")
    for word in ("expected_outcome", "classification", "scenario_id"):
        assert word not in raw_text


def test_validate_command_passes_on_sample_data(capsys):
    assert main(["validate"]) == 0
    assert "Validation passed" in capsys.readouterr().out


def test_validate_command_fails_with_readable_error(write_json, make_event, labels_path, capsys):
    event = make_event()
    event["@timestamp"] = "2026-01-15 08:00"
    events_path = write_json("events.json", [event])
    assert main(["validate", "--events", str(events_path), "--labels", str(labels_path)]) == 1
    assert "field '@timestamp'" in capsys.readouterr().err
