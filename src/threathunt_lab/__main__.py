"""Command-line entry point: ``python -m threathunt_lab {validate,hunt,evaluate,php-versions}``."""

import argparse
import sys
from collections import Counter
from pathlib import Path

from threathunt_lab.evaluate import DETECTIONS, evaluate, write_reports
from threathunt_lab import hunt_php
from threathunt_lab.hunt import STEPS, run_hunt
from threathunt_lab.loader import (
    DEFAULT_EVENTS_PATH,
    DEFAULT_LABELS_PATH,
    PHP_EVENTS_PATH,
    DatasetError,
    load_dataset,
    load_events,
)
from threathunt_lab.php_versions import check_inventory, load_inventory, print_results

DEFAULT_INVENTORY_PATH = Path("data/synthetic/php_inventory.json")

# Each hunt: its steps and its default events file.
HUNTS = {
    "H001": (STEPS, DEFAULT_EVENTS_PATH),
    "H002": (hunt_php.STEPS, PHP_EVENTS_PATH),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m threathunt_lab")
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser(
        "validate", help="load the dataset and report schema validation results"
    )
    validate.add_argument("--events", type=Path, default=DEFAULT_EVENTS_PATH)
    validate.add_argument("--labels", type=Path, default=DEFAULT_LABELS_PATH)

    hunt = subcommands.add_parser("hunt", help="run a hunt over the events")
    hunt.add_argument("--hunt", choices=list(HUNTS), default="H001", help="H001 PowerShell (default), H002 PHP")
    hunt.add_argument("--events", type=Path, help="default: the hunt's own events file")
    hunt.add_argument(
        "--step",
        action="append",
        help="run only this step, e.g. Q2; repeat to run several (default: all steps)",
    )

    evaluate_cmd = subcommands.add_parser(
        "evaluate", help="run a detection and compare the results with the labels"
    )
    evaluate_cmd.add_argument("--detection", choices=list(DETECTIONS), default="D001")
    evaluate_cmd.add_argument("--events", type=Path, help="default: the detection's own events file")
    evaluate_cmd.add_argument("--labels", type=Path, help="default: the detection's own labels file")
    evaluate_cmd.add_argument("--out", type=Path, default=Path("reports"))

    php_versions = subcommands.add_parser(
        "php-versions", help="check a server list for PHP versions affected by PHP2Shell"
    )
    php_versions.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY_PATH)
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


def run_hunt_command(hunt_id: str, events_path: Path | None, step_ids: list[str] | None) -> int:
    steps, default_events = HUNTS[hunt_id]
    unknown = sorted(set(step_ids or []) - set(steps))
    if unknown:
        print(f"Unknown step(s) for {hunt_id}: {', '.join(unknown)}. Choose from {', '.join(steps)}", file=sys.stderr)
        return 2

    # Events only: hunting must not see the evaluation labels.
    try:
        events = load_events(events_path or default_events)
    except DatasetError as exc:
        print(f"Hunt FAILED: could not load events\n{exc}", file=sys.stderr)
        return 1
    run_hunt(events, step_ids, steps)
    return 0


def run_evaluate(detection_id: str, events_path: Path | None, labels_path: Path | None, out_dir: Path) -> int:
    defaults = DETECTIONS[detection_id]
    try:
        dataset = load_dataset(events_path or defaults["events"], labels_path or defaults["labels"])
    except DatasetError as exc:
        print(f"Evaluation FAILED: could not load the dataset\n{exc}", file=sys.stderr)
        return 1

    report = evaluate(dataset, detection_id)
    json_path, md_path = write_reports(report, out_dir)
    counts = report["counts"]
    print(f"Detection {detection_id} on {report['events']} events")
    print(f"  TP {counts['TP']}  FP {counts['FP']}  TN {counts['TN']}  FN {counts['FN']}")
    print(f"  precision {report['precision']}  recall {report['recall']}")
    print(f"  reports written to {json_path} and {md_path}")
    return 0


def run_php_versions(inventory_path: Path) -> int:
    try:
        servers = load_inventory(inventory_path)
    except DatasetError as exc:
        print(f"Version check FAILED\n{exc}", file=sys.stderr)
        return 1
    print_results(check_inventory(servers))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        return run_validate(args.events, args.labels)
    if args.command == "hunt":
        return run_hunt_command(args.hunt, args.events, args.step)
    if args.command == "evaluate":
        return run_evaluate(args.detection, args.events, args.labels, args.out)
    if args.command == "php-versions":
        return run_php_versions(args.inventory)
    return 2  # unreachable: argparse enforces a known subcommand


if __name__ == "__main__":
    sys.exit(main())
