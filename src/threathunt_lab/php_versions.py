"""Check a list of servers for PHP versions affected by PHP2Shell.

Only the version number is checked. Linux distributions can fix PHP without
changing it, so "VULNERABLE" means "check this host".
"""

import re

from threathunt_lab.hunt import print_table
from threathunt_lab.loader import DatasetError, read_json

# First fixed release in each branch.
FIXED_RELEASES = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
REQUIRED_FIELDS = {"host": str, "php_version": str, "sapi": str, "internet_facing": bool}

# Most urgent first.
STATUS_ORDER = ["no upstream fix", "VULNERABLE", "unknown branch", "patched"]


def check_version(version: str) -> str:
    match = VERSION.fullmatch(version)
    if not match:
        raise ValueError(f"not a PHP version: {version!r}")
    major, minor, patch = (int(part) for part in match.groups())

    if (major, minor) in FIXED_RELEASES:
        return "patched" if patch >= FIXED_RELEASES[(major, minor)] else "VULNERABLE"
    if (major, minor) < (8, 2):
        return "no upstream fix"  # PHP no longer updates 8.1 and older
    return "unknown branch"


def load_inventory(path) -> list[dict]:
    servers = read_json(path)
    if not isinstance(servers, list):
        raise DatasetError(f"{path}: expected a JSON list of servers")

    issues = []
    for index, server in enumerate(servers):
        if not isinstance(server, dict):
            issues.append(f"server {index}: expected an object")
            continue
        for field, field_type in REQUIRED_FIELDS.items():
            if not isinstance(server.get(field), field_type):
                issues.append(f"server {index}: {field!r} missing or not {field_type.__name__}")
        if isinstance(server.get("php_version"), str) and not VERSION.fullmatch(server["php_version"]):
            issues.append(f"server {index}: php_version {server['php_version']!r} is not like 8.3.30")
    if issues:
        raise DatasetError(f"{path}: {len(issues)} issue(s):\n" + "\n".join(f"  - {issue}" for issue in issues))
    return servers


def check_inventory(servers: list[dict]) -> list[dict]:
    """Add a status to each server. Sort by status, then internet-facing, then mod_php."""
    results = [{**server, "status": check_version(server["php_version"])} for server in servers]
    return sorted(
        results,
        key=lambda s: (
            STATUS_ORDER.index(s["status"]),
            not s["internet_facing"],
            "mod_php" not in s["sapi"],
            s["host"],
        ),
    )


def print_results(results: list[dict]) -> None:
    rows = [
        [s["host"], s["php_version"], s["sapi"], "yes" if s["internet_facing"] else "no", s["status"]]
        for s in results
    ]
    print_table("PHP2Shell version check", ["host", "php_version", "sapi", "internet_facing", "status"], rows)
