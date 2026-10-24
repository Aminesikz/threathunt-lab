"""Tests for evaluating the detections against the labels (Milestones 4 and 8)."""

import json
from pathlib import Path

import pytest

from threathunt_lab.__main__ import main
from threathunt_lab.evaluate import evaluate, outcome, ratio
from threathunt_lab.loader import load_dataset

REPORTS = Path(__file__).resolve().parents[1] / "reports"


@pytest.mark.parametrize(
    ("expected_alert", "alerted", "result"),
    [(True, True, "TP"), (False, True, "FP"), (False, False, "TN"), (True, False, "FN")],
)
def test_outcome(expected_alert, alerted, result):
    assert outcome(expected_alert, alerted) == result


def test_ratio_handles_division_by_zero():
    assert ratio(5, 6) == 0.833
    assert ratio(0, 0) is None


def test_evaluate_counts_a_small_dataset(write_json, make_event, make_labels):
    # Four events, one of each result: TP, FP, TN, FN.
    events = [make_event(event_id) for event_id in ("tp", "fp", "tn", "fn")]
    for event in events[:2]:  # these two will alert
        event["process"]["executable"] = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        event["process"]["command_line"] = "powershell.exe -enc AAAA"
    labels = make_labels("tp", "fp", "tn", "fn")
    for label in labels["labels"]:
        label["expected_outcome"] = "alert" if label["event_id"] in ("tp", "fn") else "no_alert"

    dataset = load_dataset(write_json("events.json", events), write_json("labels.json", labels))
    report = evaluate(dataset)

    assert report["counts"] == {"TP": 1, "FP": 1, "TN": 1, "FN": 1}
    assert report["precision"] == 0.5
    assert report["recall"] == 0.5
    assert {row["event_id"]: row["result"] for row in report["results"]} == {
        "tp": "TP", "fp": "FP", "tn": "TN", "fn": "FN",
    }


@pytest.mark.parametrize("detection_id", ["D001", "D002"])
def test_evaluate_command_writes_both_reports(tmp_path, capsys, detection_id):
    assert main(["evaluate", "--detection", detection_id, "--out", str(tmp_path)]) == 0
    report = json.loads((tmp_path / f"{detection_id}-evaluation.json").read_text(encoding="utf-8"))
    assert report["detection"] == detection_id
    assert sum(report["counts"].values()) == report["events"]
    markdown = (tmp_path / f"{detection_id}-evaluation.md").read_text(encoding="utf-8")
    assert f"# Evaluation: detection {detection_id}" in markdown
    assert "precision" in capsys.readouterr().out


def test_d002_only_misses_the_event_without_a_parent_path(tmp_path):
    assert main(["evaluate", "--detection", "D002", "--out", str(tmp_path)]) == 0
    report = json.loads((tmp_path / "D002-evaluation.json").read_text(encoding="utf-8"))
    wrong = {row["event_id"]: row["result"] for row in report["results"] if row["result"] in ("FP", "FN")}
    assert wrong == {"php-evt-0013": "FN"}


def test_evaluate_command_rejects_malformed_events(write_json, make_event, labels_path, tmp_path, capsys):
    event = make_event()
    event["@timestamp"] = "not a time"
    events_path = write_json("events.json", [event])
    assert main(["evaluate", "--events", str(events_path), "--labels", str(labels_path), "--out", str(tmp_path)]) == 1
    assert "Evaluation FAILED" in capsys.readouterr().err
    assert not (tmp_path / "D001-evaluation.json").exists()


@pytest.mark.parametrize("detection_id", ["D001", "D002"])
def test_committed_reports_match_a_fresh_run(tmp_path, detection_id):
    # The reports in reports/ must be real output: rerun and compare.
    assert main(["evaluate", "--detection", detection_id, "--out", str(tmp_path)]) == 0
    for name in (f"{detection_id}-evaluation.json", f"{detection_id}-evaluation.md"):
        fresh = (tmp_path / name).read_text(encoding="utf-8")
        committed = (REPORTS / name).read_text(encoding="utf-8")
        assert fresh == committed, f"reports/{name} is out of date: run evaluate --detection {detection_id}"
