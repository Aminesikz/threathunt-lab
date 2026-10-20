"""Shared test fixtures. pytest gives these to any test that names them as a parameter."""

import copy
import json
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "synthetic"

VALID_EVENT = {
    "@timestamp": "2026-01-15T08:00:00.000Z",
    "event": {"id": "evt-a", "category": ["process"], "type": ["start"], "action": "start"},
    "host": {"name": "TEST-HOST"},
    "user": {"name": "test.user"},
    "process": {
        "name": "notepad.exe",
        "executable": "C:\\Windows\\System32\\notepad.exe",
        "command_line": "notepad.exe",
        "parent": {"name": "explorer.exe", "command_line": "C:\\Windows\\Explorer.EXE"},
    },
}


@pytest.fixture
def events_path():
    return DATA_DIR / "process_creation_events.json"


@pytest.fixture
def labels_path():
    return DATA_DIR / "process_creation_labels.json"


@pytest.fixture
def make_event():
    """Return a function that builds a fresh, valid event to modify in a test."""

    def make(event_id="evt-a"):
        event = copy.deepcopy(VALID_EVENT)  # deep copy, so tests can't affect each other
        event["event"]["id"] = event_id
        return event

    return make


@pytest.fixture
def make_labels():
    """Return a function that builds a valid labels document for the given event IDs."""

    def make(*event_ids):
        return {
            "schema_version": "1",
            "detection_objective": {"id": "test-objective", "description": "Test objective."},
            "labels": [
                {
                    "event_id": event_id,
                    "scenario_id": "T01-test",
                    "classification": "benign",
                    "expected_outcome": "no_alert",
                    "rationale": "Test fixture.",
                }
                for event_id in event_ids
            ],
        }

    return make


@pytest.fixture
def write_json(tmp_path):
    """Return a function that saves a value as a JSON file in a temporary folder."""

    def write(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    return write
