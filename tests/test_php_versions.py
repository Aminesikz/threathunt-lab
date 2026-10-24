"""Tests for the PHP2Shell version check (Milestone 6)."""

import pytest

from threathunt_lab.__main__ import main
from threathunt_lab.loader import DatasetError
from threathunt_lab.php_versions import check_inventory, check_version, load_inventory


@pytest.mark.parametrize(
    ("version", "status"),
    [
        ("8.5.11", "VULNERABLE"),
        ("8.5.12", "patched"),
        ("8.4.26", "VULNERABLE"),
        ("8.4.27", "patched"),
        ("8.3.36", "patched"),
        ("8.2.9", "VULNERABLE"),  # 9 < 35 as numbers, not as text
        ("8.2.100", "patched"),
        ("8.1.33", "no upstream fix"),
        ("7.4.33", "no upstream fix"),
        ("8.6.0", "unknown branch"),
    ],
)
def test_check_version(version, status):
    assert check_version(version) == status


@pytest.mark.parametrize("version", ["8.3", "8.3.30-1+deb13u1", "v8.3.30", ""])
def test_check_version_rejects_other_formats(version):
    with pytest.raises(ValueError):
        check_version(version)


def server(host, version, sapi="php-fpm", internet_facing=True):
    return {"host": host, "php_version": version, "sapi": sapi, "internet_facing": internet_facing}


def test_most_urgent_servers_come_first():
    results = check_inventory([
        server("patched", "8.4.27"),
        server("internal", "8.3.30", internet_facing=False),
        server("fpm", "8.3.30"),
        server("mod-php", "8.3.30", sapi="apache2-mod_php"),
        server("old", "8.0.30"),
    ])
    assert [s["host"] for s in results] == ["old", "mod-php", "fpm", "internal", "patched"]


def test_load_inventory_reports_every_issue(write_json):
    path = write_json("inventory.json", [
        server("ok", "8.3.30"),
        {"host": "no-version", "sapi": "php-fpm", "internet_facing": True},
        server("bad-version", "8.3"),
        server("bad-flag", "8.3.30", internet_facing="yes"),
        "not an object",
    ])
    with pytest.raises(DatasetError) as error:
        load_inventory(path)
    message = str(error.value)
    assert "4 issue(s)" in message
    assert "server 1: 'php_version'" in message
    assert "server 2: php_version '8.3'" in message
    assert "server 3: 'internet_facing'" in message
    assert "server 4: expected an object" in message


def test_php_versions_command_on_sample_inventory(capsys):
    assert main(["php-versions"]) == 0
    output = capsys.readouterr().out
    assert "web-shop-01    8.3.30       apache2-mod_php  yes              VULNERABLE" in output
    assert output.index("web-legacy-01") < output.index("web-shop-01")


def test_php_versions_command_rejects_bad_inventory(write_json, capsys):
    path = write_json("inventory.json", {"host": "not a list"})
    assert main(["php-versions", "--inventory", str(path)]) == 1
    assert "Version check FAILED" in capsys.readouterr().err
