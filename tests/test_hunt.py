"""Tests for hunt H001 (Milestone 2)."""

from __future__ import annotations

import base64
import json
import re
import shutil
from pathlib import Path

import pytest

from threathunt_lab.__main__ import main
from threathunt_lab.hunt import (
    KQL_NAMES,
    KQL_PATTERNS,
    decode_powershell_base64,
    features,
    is_powershell,
    print_table,
    q1_baseline,
    q5_beyond_process_name,
    run_hunt,
    stack,
)

HUNT_DOC = Path(__file__).resolve().parents[1] / "hunts" / "H001-powershell-process-creation.md"


def make_process(make_event, event_id, name, command_line="", executable=None):
    event = make_event(event_id)
    event["process"]["name"] = name
    event["process"]["command_line"] = command_line or name
    event["process"]["executable"] = executable or f"C:\\Windows\\System32\\{name}"
    return event


# --- Helpers ---------------------------------------------------------------------


def test_stack_counts_rarest_first(make_event):
    events = [
        make_process(make_event, "e1", "powershell.exe"),
        make_process(make_event, "e2", "powershell.exe"),
        make_process(make_event, "e3", "cmd.exe"),
        make_process(make_event, "e4", "b.exe"),
    ]
    # Ties (count 1) are sorted by value, so the order is always the same.
    assert stack(events, "process.name") == [
        (("b.exe",), 1),
        (("cmd.exe",), 1),
        (("powershell.exe",), 2),
    ]


def test_stack_shows_missing_fields(make_event):
    event = make_event()
    del event["process"]["parent"]
    assert stack([event], "process.parent.name") == [(("<missing>",), 1)]


def test_decode_returns_the_script():
    blob = base64.b64encode("Write-Output 'hi'".encode("utf-16-le")).decode()
    assert decode_powershell_base64(blob) == "Write-Output 'hi'"


@pytest.mark.parametrize(
    "blob",
    [
        "not base64!!",  # not Base64 characters
        "QQ!!BCAA==",  # Base64 with junk inside: must be rejected, not skipped
        base64.b64encode(b"abc").decode(),  # 3 bytes can't be UTF-16 (2 bytes per character)
        base64.b64encode(b"\x00\xd8").decode(),  # valid Base64, invalid UTF-16
    ],
)
def test_decode_returns_none_for_bad_input(blob):
    assert decode_powershell_base64(blob) is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [("powershell.exe", True), ("POWERSHELL.EXE", True), ("pwsh.exe", True), ("svcupdate.exe", False)],
)
def test_is_powershell_ignores_case(make_event, name, expected):
    assert is_powershell(make_process(make_event, "e1", name)) is expected


def test_features_ignore_case(make_event):
    event = make_process(make_event, "e1", "powershell.exe", "POWERSHELL.EXE -NoP -W Hidden -eNc AAAA")
    assert features(event) == ["encoded_command", "hidden_window", "no_profile"]


def test_features_are_plain_substrings(make_event):
    # The known weakness discussed in the write-up: "-enc" inside a file name.
    event = make_process(make_event, "e1", "powershell.exe", "powershell.exe Get-Content q4-encryption.txt")
    assert features(event) == ["encoded_command"]


def test_print_table_escapes_terminal_control_codes(capsys):
    print_table("t", ["value"], [["\x1b[31mred"]])
    output = capsys.readouterr().out
    assert "\x1b" not in output
    assert "\\x1b[31mred" in output


# --- Steps -------------------------------------------------------------------------


def test_q1_sorts_timestamps_as_times_not_text(make_event, capsys):
    # As text, "...00.5Z" sorts before "...00Z", although it is later.
    early, late = make_event("early"), make_event("late")
    early["@timestamp"] = "2026-01-15T08:00:00Z"
    late["@timestamp"] = "2026-01-15T08:00:00.5Z"
    q1_baseline([late, early])
    output = capsys.readouterr().out
    assert "first @timestamp       2026-01-15T08:00:00Z" in output
    assert "last @timestamp        2026-01-15T08:00:00.5Z" in output


def test_q5_finds_powershell_arguments_on_a_renamed_binary(make_event, capsys):
    events = [
        make_process(make_event, "normal", "powershell.exe", "powershell.exe -enc AAAA"),
        make_process(make_event, "renamed", "svcupdate.exe", "svcupdate.exe -enc AAAA", "C:\\Users\\Public\\svcupdate.exe"),
    ]
    q5_beyond_process_name(events)
    output = capsys.readouterr().out
    assert "renamed" in output
    assert "normal " not in output


# --- The hunt command ---------------------------------------------------------------


def test_hunt_runs_without_the_labels_file(events_path, tmp_path, monkeypatch, capsys):
    # Run from an empty folder holding only the events, so no labels file
    # exists. The hunt must still work, because it never reads the labels.
    events_copy = shutil.copy(events_path, tmp_path / "events.json")
    monkeypatch.chdir(tmp_path)
    assert main(["hunt", "--events", str(events_copy)]) == 0
    assert "== Q7 Host timelines ==" in capsys.readouterr().out


def test_hunt_can_run_one_step(capsys):
    assert main(["hunt", "--step", "Q4"]) == 0
    output = capsys.readouterr().out
    assert "== Q4 Command-line features ==" in output
    assert "== Q3" not in output


def test_hunt_rejects_invalid_events(write_json, make_event, capsys):
    event = make_event()
    del event["process"]["command_line"]
    assert main(["hunt", "--events", str(write_json("events.json", [event]))]) == 1
    assert "process.command_line" in capsys.readouterr().err


# --- The write-up matches reality -----------------------------------------------------


def test_write_up_quotes_real_hunt_output(events_path, capsys):
    # Every ```text block in the write-up is quoted hunt output. Re-run the hunt
    # and check each block appears exactly, so quoted results are never invented.
    run_hunt(json.loads(events_path.read_text(encoding="utf-8")))
    output = capsys.readouterr().out
    blocks = re.findall(r"```text\n(.*?)\n```", HUNT_DOC.read_text(encoding="utf-8"), re.DOTALL)
    assert blocks
    for block in blocks:
        assert block in output, f"not produced by the hunt:\n{block}"


def test_q4_kql_comparison_uses_the_query_in_the_write_up():
    doc = HUNT_DOC.read_text(encoding="utf-8")
    for name in KQL_NAMES:
        assert f'"{name}"' in doc
    for pattern in KQL_PATTERNS:
        assert f"*{pattern}*" in doc
