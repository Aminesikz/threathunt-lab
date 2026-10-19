"""Tests for the Sigma rule in detections/ (Milestone 3)."""

from __future__ import annotations

import re
from pathlib import Path

from sigma.backends.elasticsearch import EqlBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch.windows import ecs_windows

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
