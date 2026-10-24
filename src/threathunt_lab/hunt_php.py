"""Hunt H002: a PHP web server starting a shell or tool on Linux (PHP2Shell).

Same idea as H001: the steps print tables, the analyst decides. The hunt only
gets the events, never the labels. Command lines are never run.
"""

import re

from threathunt_lab.hunt import fields_row, print_stack, print_table, q1_baseline, text
from threathunt_lab.validation import parse_utc_timestamp

# Parent names that mean "a web request is being handled". Matched as the
# start of the name, because PHP-FPM's name includes its version (php-fpm8.3).
WEB_PARENTS = ["php-fpm", "php-cgi", "apache2", "httpd", "frankenphp", "lsphp"]

# PHP's mail() runs exactly this. Anything else, even a longer command, is shown.
KNOWN_GOOD = ["sh -c /usr/sbin/sendmail -t -i"]

# Whole words, so "id" doesn't match "video".
FEATURES = {
    "discovery": re.compile(r"\b(id|uname|whoami|hostname)\b"),
    "download": re.compile(r"\b(wget|curl)\b"),
    "tmp_folder": re.compile(r"/tmp\b"),
    "ip_address": re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b"),
}


def is_web_child(event: dict) -> bool:
    return text(event, "process.parent.name").lower().startswith(tuple(WEB_PARENTS))


def features(event: dict) -> list[str]:
    command_line = text(event, "process.command_line")
    if command_line in KNOWN_GOOD:
        return ["known_good"]
    return [name for name, pattern in FEATURES.items() if pattern.search(command_line)]


def by_time(events: list[dict]) -> list[dict]:
    return sorted(events, key=lambda e: parse_utc_timestamp(e["@timestamp"]))


# --- Steps --------------------------------------------------------------------


def q2_web_server_children(events: list[dict]) -> None:
    children = [e for e in events if is_web_child(e)]
    print_stack(
        "Processes started by web servers (rarest first)",
        children,
        "host.name",
        "process.parent.name",
        "process.name",
    )
    columns = ["event.id", "user.name", "process.parent.executable", "process.executable"]
    print_table("Paths and users", columns, [fields_row(e, *columns) for e in children])
    print_table(
        "Started by PHP, but not by a web server",
        ["event.id", "host.name", "user.name", "process.parent.name", "process.name"],
        [
            fields_row(e, "event.id", "host.name", "user.name", "process.parent.name", "process.name")
            for e in events
            if text(e, "process.parent.name").lower().startswith("php") and not is_web_child(e)
        ],
    )


def q3_command_lines(events: list[dict]) -> None:
    children = by_time(e for e in events if is_web_child(e))
    print_table(
        "Command lines started by web servers",
        ["event.id", "host.name", "process.command_line", "features"],
        [fields_row(e, "event.id", "host.name", "process.command_line") + [", ".join(features(e)) or "-"] for e in children],
    )


def q4_host_timeline(events: list[dict]) -> None:
    hosts = sorted({text(e, "host.name") for e in events if is_web_child(e)})
    for host in hosts:
        print_table(
            f"Timeline for {host}",
            ["@timestamp", "event.id", "user.name", "parent -> process", "process.command_line"],
            [
                fields_row(e, "@timestamp", "event.id", "user.name")
                + [f"{text(e, 'process.parent.name')} -> {text(e, 'process.name')}", text(e, "process.command_line")]
                for e in by_time(e for e in events if text(e, "host.name") == host)
            ],
        )


STEPS = {
    "Q1": ("Baseline: know the data", q1_baseline),
    "Q2": ("What do web servers start?", q2_web_server_children),
    "Q3": ("What did they run?", q3_command_lines),
    "Q4": ("Host timelines", q4_host_timeline),
}
