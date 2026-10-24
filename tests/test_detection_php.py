"""Tests for detection D002: a PHP web server starts a shell or tool (Milestone 7)."""

import re
from pathlib import Path

import pytest
import yaml
from sigma.backends.elasticsearch import EqlBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

from threathunt_lab.detection_php import (
    CHILD_ENDSWITH,
    MAIL_COMMAND,
    PARENT_CONTAINS,
    PARENT_ENDSWITH,
    detect,
)

DETECTIONS = Path(__file__).resolve().parents[1] / "detections"
RULE = DETECTIONS / "sigma" / "php_web_server_starts_shell.yml"
PIPELINE = DETECTIONS / "pipelines" / "ecs_linux.yml"
DOC = DETECTIONS / "D002-php-web-server-starts-shell.md"


def load_rule():
    return SigmaCollection.from_yaml(RULE.read_text(encoding="utf-8"))


def test_rule_is_valid_sigma():
    assert load_rule().rules[0].title == "PHP Web Server Starts a Shell or Tool"


def test_doc_shows_the_real_eql_conversion():
    pipeline = ProcessingPipeline.from_yaml(PIPELINE.read_text(encoding="utf-8"))
    converted = EqlBackend(pipeline).convert(load_rule())[0]
    assert "process.parent.executable" in converted  # the pipeline mapped the fields
    documented = re.search(r"```eql\n(.*?)\n```", DOC.read_text(encoding="utf-8"), re.DOTALL).group(1)
    assert documented == converted


def test_python_copy_matches_the_sigma_rule():
    detection = yaml.safe_load(RULE.read_text(encoding="utf-8"))["detection"]
    assert detection["selection_parent"] == [
        {"ParentImage|endswith": PARENT_ENDSWITH},
        {"ParentImage|contains": PARENT_CONTAINS},
    ]
    assert detection["selection_child"] == {"Image|endswith": CHILD_ENDSWITH}
    assert detection["filter_mail"] == {"CommandLine": MAIL_COMMAND}
    assert detection["condition"] == "selection_parent and selection_child and not filter_mail"


def web_event(make_event, parent, child, command_line="sh -c id"):
    event = make_event()
    event["process"]["parent"]["executable"] = parent
    event["process"]["executable"] = child
    event["process"]["command_line"] = command_line
    return event


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        ("/usr/sbin/php-fpm8.3", "/usr/bin/dash"),  # version in the name
        ("/usr/sbin/php-fpm", "/usr/bin/bash"),
        ("/usr/sbin/apache2", "/usr/bin/sh"),  # mod_php
        ("/usr/sbin/httpd", "/usr/bin/curl"),  # Red Hat's name for Apache
        ("/usr/bin/php-cgi8.2", "/usr/bin/wget"),
        ("/usr/local/bin/frankenphp", "/usr/bin/id"),
        ("/usr/local/lsws/lsphp83/bin/lsphp", "/usr/bin/whoami"),
        ("/USR/SBIN/PHP-FPM8.3", "/USR/BIN/DASH"),  # Sigma ignores case
    ],
)
def test_detects_web_server_starting_a_shell_or_tool(make_event, parent, child):
    assert detect(web_event(make_event, parent, child))


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        ("/usr/bin/php8.3", "/usr/bin/dash"),  # PHP command line, not a web server
        ("/usr/sbin/cron", "/usr/bin/dash"),
        ("/usr/sbin/php-fpm8.3", "/usr/bin/convert"),  # not a shell or tool on the list
        ("/usr/sbin/php-fpm8.3", "/usr/bin/identify"),  # ends with "id" but not "/id"
        ("/usr/sbin/apache2", "/usr/bin/rotatelogs"),
    ],
)
def test_ignores_other_parents_and_children(make_event, parent, child):
    assert not detect(web_event(make_event, parent, child))


def test_mail_exclusion_is_exact(make_event):
    mail = web_event(make_event, "/usr/sbin/php-fpm8.4", "/usr/bin/dash", "sh -c /usr/sbin/sendmail -t -i")
    assert not detect(mail)
    mail["process"]["command_line"] += "; curl -s http://192.0.2.1/m"
    assert detect(mail)


@pytest.mark.parametrize(
    "broken",
    [
        lambda e: e["process"]["parent"].pop("executable"),  # like php-evt-0013
        lambda e: e["process"].pop("executable"),
        lambda e: e.pop("process"),
        lambda e: e["process"].update(executable=None),
    ],
)
def test_missing_or_broken_fields_do_not_crash(make_event, broken):
    event = web_event(make_event, "/usr/sbin/php-fpm8.3", "/usr/bin/dash")
    broken(event)
    assert detect(event) is False
