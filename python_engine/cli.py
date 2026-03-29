from __future__ import annotations

import argparse
import json
from pathlib import Path

from dpi_engine import DPIEngine, RuleManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Python DPI Engine")
    parser.add_argument("--input", required=True, help="Input PCAP file")
    parser.add_argument("--output", required=True, help="Output filtered PCAP file")
    parser.add_argument(
        "--rules",
        required=False,
        help="Optional rules payload: either a JSON string or a JSON file path",
    )
    parser.add_argument("--json", action="store_true", help="Emit compact JSON output")
    return parser


def load_rules_from_arg(rules: RuleManager, rules_arg: str) -> None:
    # If it's a file path, load as file. Otherwise treat as JSON payload.
    rules_path = Path(rules_arg)
    if rules_path.exists():
        rules.load_from_file(rules_path)
        return

    try:
        payload = json.loads(rules_arg)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid --rules value. Expected JSON string or file path: {exc}") from exc

    if not isinstance(payload, dict):
        raise SystemExit("Invalid --rules value. JSON payload must be an object")
    rules.update_from_payload(payload)


def main() -> None:
    args = build_parser().parse_args()
    rules = RuleManager()

    if args.rules:
        load_rules_from_arg(rules, args.rules)

    engine = DPIEngine(rule_manager=rules)
    result = engine.process_file(args.input, args.output)

    payload = {
        "input_file": result.input_file,
        "output_file": result.output_file,
        "stats": result.stats,
        "total": result.stats.get("total_packets", 0),
        "forwarded": result.stats.get("forwarded_packets", 0),
        "dropped": result.stats.get("dropped_packets", 0),
        "drop_rate": (result.stats.get("drop_rate", 0) or 0) * 100,
        "top_apps": result.stats.get("app_counts", {}),
        "block_reasons": result.stats.get("block_reasons", {}),
    }

    if args.json:
        print(json.dumps(payload, separators=(",", ":")))
        return

    print("DPI processing complete")
    print(f"Input: {result.input_file}")
    print(f"Output: {result.output_file}")
    for key, value in result.stats.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
