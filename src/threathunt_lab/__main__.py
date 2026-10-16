"""Command-line entry point: ``python -m threathunt_lab {validate,hunt}``."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from threathunt_lab.hunt import STEPS, run_hunt
from threathunt_lab.loader import (
    DEFAULT_EVENTS_PATH,
    DEFAULT_LABELS_PATH,
    DatasetError,
    load_dataset,
    load_events,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m threathunt_lab")
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser(
        "validate", help="load the dataset and report schema validation results"
    )
    validate.add_argument("--events", type=Path, default=DEFAULT_EVENTS_PATH)
    validate.add_argument("--labels", type=Path, default=DEFAULT_LABELS_PATH)

    hunt = subcommands.add_parser(
        "hunt", help="run hunt H001 (PowerShell process creation) over the events"
    )
    hunt.add_argument("--events", type=Path, default=DEFAULT_EVENTS_PATH)
    hunt.add_argument(
        "--step",
        choices=list(STEPS),
        action="append",
        help="run only this step; repeat to run several (default: all steps)",
    )
    return parser


def run_validate(events_path: Path, labels_path: Path) -> int:
    try:
        dataset = load_dataset(events_path, labels_path)
    except DatasetError as exc:
        print(f"Validation FAILED\n{exc}", file=sys.stderr)
        return 1

    labels = dataset.labels_by_event_id.values()
    classifications = Counter(label["classification"] for label in labels)
    outcomes = Counter(label["expected_outcome"] for label in labels)
    print("Validation passed")
    print(f"  events:            {len(dataset.events)} ({events_path})")
    print(f"  labels:            {len(dataset.labels_by_event_id)} ({labels_path})")
    print(f"  objective:         {dataset.detection_objective['id']}")
    print(f"  classifications:   {dict(sorted(classifications.items()))}")
    print(f"  expected outcomes: {dict(sorted(outcomes.items()))}")
    return 0


def run_hunt_command(events_path: Path, step_ids: list[str] | None) -> int:
    # Events only: hunting must not see the evaluation labels.
    try:
        events = load_events(events_path)
    except DatasetError as exc:
        print(f"Hunt FAILED: could not load events\n{exc}", file=sys.stderr)
        return 1
    run_hunt(events, step_ids)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        return run_validate(args.events, args.labels)
    if args.command == "hunt":
        return run_hunt_command(args.events, args.step)
    return 2  # unreachable: argparse enforces a known subcommand


if __name__ == "__main__":
    sys.exit(main())
