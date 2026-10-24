"""Hunt H001: suspicious PowerShell process creation.

Each step (Q1 to Q7) prints tables for the analyst to read. The analyst, not
the code, decides what looks suspicious (see hunts/H001-...md).

The hunt only gets the events, never the labels. Command lines are only read
as text, never run.
"""

import base64
import binascii
import re
from collections import Counter
from pathlib import PureWindowsPath

from threathunt_lab.schema import get_field
from threathunt_lab.validation import parse_utc_timestamp

POWERSHELL_NAMES = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}

# Words to look for in command lines (ignoring case), like a KQL search for
# *-enc*. Deliberately broad, so some harmless commands match too.
FEATURES = {
    "encoded_command": ["-enc"],
    "hidden_window": ["hidden"],
    "no_profile": ["-nop"],
    "policy_bypass": ["bypass"],
    "download": [
        "downloadstring",
        "downloadfile",
        "net.webclient",
        "invoke-webrequest",
        "start-bitstransfer",
    ],
    "invoke_expression": ["iex", "invoke-expression"],
}

# The values in the simple KQL query in step Q4. KQL is case-sensitive, so Q4
# copies that to show what the query would miss.
KQL_NAMES = ["powershell.exe", "pwsh.exe", "POWERSHELL.EXE"]
KQL_PATTERNS = ["-enc", "-Enc", "-ENC", "-EncodedCommand"]

# 20 or more Base64 characters in a row, with optional '=' padding.
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


# --- Helpers ------------------------------------------------------------------


def text(event: dict, field: str) -> str:
    """Return a field's value as a string, or "<missing>" if it isn't there."""
    value = get_field(event, field)
    return value if isinstance(value, str) else "<missing>"


def is_powershell(event: dict) -> bool:
    """True if the process name is PowerShell, in any letter case."""
    return text(event, "process.name").lower() in POWERSHELL_NAMES


def features(event: dict) -> list[str]:
    """Return the names of the FEATURES found in the event's command line."""
    command_line = text(event, "process.command_line").lower()
    return [
        name
        for name, needles in FEATURES.items()
        if any(needle in command_line for needle in needles)
    ]


def features_text(event: dict) -> str:
    return ", ".join(features(event)) or "-"


def count_rarest_first(values) -> list[tuple]:
    """Count each value, rarest first ("stacking"). Ties are sorted by value."""
    counts = Counter(values)
    return sorted(counts.items(), key=lambda item: (item[1], item[0]))


def stack(events: list[dict], *fields: str) -> list[tuple]:
    """Stack events by one or more fields, rarest combination first."""
    # A tuple, not a list: Counter keys must be hashable.
    return count_rarest_first(tuple(text(e, field) for field in fields) for e in events)


def decode_powershell_base64(blob: str) -> str | None:
    """Decode a PowerShell -EncodedCommand value to text, or return None.

    PowerShell encodes the script as UTF-16LE text, then Base64. This reverses
    that. It only produces text; it never runs it.
    """
    try:
        # validate=True rejects characters that aren't Base64. Without it,
        # b64decode silently skips them and may decode something different.
        return base64.b64decode(blob, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None


def safe(value: str) -> str:
    """Escape invisible characters (e.g. terminal escape codes) before printing."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in value
    )


def print_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    rows = [[safe(cell) for cell in row] for row in rows]
    widths = [
        max([len(column)] + [len(row[i]) for row in rows])
        for i, column in enumerate(columns)
    ]

    def line(cells):
        return "  ".join(cell.ljust(width) for cell, width in zip(cells, widths)).rstrip()

    print()
    print(f"-- {title}")
    print(line(columns))
    print(line(["-" * width for width in widths]))
    for row in rows:
        print(line(row))
    if not rows:
        print("(no results)")


def print_stack(title: str, events: list[dict], *fields: str) -> None:
    rows = [[*values, str(count)] for values, count in stack(events, *fields)]
    print_table(title, [*fields, "count"], rows)


def fields_row(event: dict, *fields: str) -> list[str]:
    return [text(event, field) for field in fields]


def count_distinct(events: list[dict], field: str) -> str:
    return str(len({text(e, field) for e in events}))


# --- Steps --------------------------------------------------------------------


def q1_baseline(events: list[dict]) -> None:
    # Sort by parsed time, not by text: as text, "...:00.5Z" comes before
    # "...:00Z" even though it is later.
    by_time = sorted(events, key=lambda e: parse_utc_timestamp(e["@timestamp"]))
    print_table(
        "Dataset summary",
        ["metric", "value"],
        [
            ["events", str(len(events))],
            ["first @timestamp", by_time[0]["@timestamp"]],
            ["last @timestamp", by_time[-1]["@timestamp"]],
            ["distinct host.name", count_distinct(events, "host.name")],
            ["distinct user.name", count_distinct(events, "user.name")],
            ["distinct process.name", count_distinct(events, "process.name")],
        ],
    )
    print_stack("Events per host (rarest first)", events, "host.name")
    print_stack("Process names (rarest first)", events, "process.name")


def q2_powershell_starts(events: list[dict]) -> None:
    powershell = [e for e in events if is_powershell(e)]
    exact_case = [e for e in events if text(e, "process.name") in POWERSHELL_NAMES]
    print_table(
        "Exact-case vs case-insensitive name match",
        ["match", "events"],
        [
            ["exact case, lower-case names only (like KQL on a keyword field)", str(len(exact_case))],
            ["case-insensitive", str(len(powershell))],
        ],
    )
    columns = ["@timestamp", "event.id", "host.name", "user.name", "process.name"]
    print_table("PowerShell process starts", columns, [fields_row(e, *columns) for e in powershell])


def q3_parent_stacking(events: list[dict]) -> None:
    powershell = [e for e in events if is_powershell(e)]
    print_stack("PowerShell parents (rarest first)", powershell, "process.parent.name")
    columns = ["event.id", "process.parent.name", "process.parent.command_line"]
    print_table(
        "Parent command lines of PowerShell starts",
        columns,
        [fields_row(e, *columns) for e in powershell],
    )


def q4_command_line_features(events: list[dict]) -> None:
    powershell = [e for e in events if is_powershell(e)]

    rows = []
    for name, needles in FEATURES.items():
        matched = [text(e, "event.id") for e in powershell if name in features(e)]
        rows.append([name, " | ".join(needles), str(len(matched)), ", ".join(matched) or "-"])
    print_table(
        "Feature counts across PowerShell starts",
        ["feature", "searched for", "events", "event.id values"],
        rows,
    )

    print_table(
        "Features per PowerShell start",
        ["event.id", "host.name", "process.parent.name", "features"],
        [fields_row(e, "event.id", "host.name", "process.parent.name") + [features_text(e)] for e in powershell],
    )

    print_table(
        "Command lines for manual review",
        ["event.id", "process.command_line"],
        [fields_row(e, "event.id", "process.command_line") for e in powershell],
    )

    # Same search, done the case-sensitive KQL way vs ignoring case.
    rows = []
    for e in events:
        kql_match = text(e, "process.name") in KQL_NAMES and any(
            pattern in text(e, "process.command_line") for pattern in KQL_PATTERNS
        )
        any_case_match = is_powershell(e) and "encoded_command" in features(e)
        if kql_match or any_case_match:
            rows.append([text(e, "event.id"), "yes" if kql_match else "NO", "yes" if any_case_match else "NO"])
    print_table(
        "Encoded-command search: case-sensitive KQL query vs case-insensitive",
        ["event.id", "KQL match", "case-insensitive match"],
        rows,
    )


def q5_beyond_process_name(events: list[dict]) -> None:
    print_table(
        "Non-PowerShell processes with PowerShell-style arguments",
        ["event.id", "host.name", "process.name", "process.executable", "features"],
        [
            fields_row(e, "event.id", "host.name", "process.name", "process.executable") + [features_text(e)]
            for e in events
            if not is_powershell(e) and features(e)
        ],
    )
    # Lower-cased because Windows paths are not case-sensitive.
    directories = [str(PureWindowsPath(text(e, "process.executable")).parent).lower() for e in events]
    print_table(
        "Executable directories, all events (rarest first)",
        ["directory", "count"],
        [[directory, str(count)] for directory, count in count_rarest_first(directories)],
    )


def q6_decode_encoded_commands(events: list[dict]) -> None:
    rows = []
    for e in events:
        for blob in BASE64_RUN.findall(text(e, "process.command_line")):
            decoded = decode_powershell_base64(blob)
            if decoded is None:
                decoded = "<not decodable as UTF-16LE Base64>"
            rows.append([text(e, "event.id"), text(e, "process.name"), str(len(blob)), decoded])
    print_table(
        "Decoded Base64 candidates (text only, never executed)",
        ["event.id", "process.name", "blob length", "decoded text"],
        rows,
    )


def q7_host_timeline(events: list[dict]) -> None:
    for host in sorted({text(e, "host.name") for e in events}):
        host_events = [e for e in events if text(e, "host.name") == host]
        host_events.sort(key=lambda e: parse_utc_timestamp(e["@timestamp"]))
        print_table(
            f"Timeline for {host}",
            ["@timestamp", "event.id", "user.name", "parent -> process", "features"],
            [
                fields_row(e, "@timestamp", "event.id", "user.name")
                + [f"{text(e, 'process.parent.name')} -> {text(e, 'process.name')}", features_text(e)]
                for e in host_events
            ],
        )


STEPS = {
    "Q1": ("Baseline: know the data", q1_baseline),
    "Q2": ("PowerShell process starts", q2_powershell_starts),
    "Q3": ("Parent process stacking", q3_parent_stacking),
    "Q4": ("Command-line features", q4_command_line_features),
    "Q5": ("Beyond the process name", q5_beyond_process_name),
    "Q6": ("Decode encoded commands", q6_decode_encoded_commands),
    "Q7": ("Host timelines", q7_host_timeline),
}


def run_hunt(events: list[dict], step_ids: list[str] | None = None, steps: dict = STEPS) -> None:
    """Print the chosen steps (all of them by default), in order."""
    selected = [step_id for step_id in steps if step_ids is None or step_id in step_ids]
    for number, step_id in enumerate(selected):
        if number > 0:
            print("\n")
        title, step = steps[step_id]
        print(f"== {step_id} {title} ==")
        step(events)
