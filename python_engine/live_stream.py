from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

from dpi_engine import DPIEngine, RuleManager
from dpi_engine.parser import parse_packet
from dpi_engine.types import AppType

try:
    from scapy.all import AsyncSniffer, wrpcap  # type: ignore
except Exception as exc:  # pragma: no cover
    print(json.dumps({"type": "error", "error": f"scapy import failed: {exc}"}), flush=True)
    raise


running = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live stream DPI capture")
    parser.add_argument("--interface", required=True, help="Network interface name")
    parser.add_argument("--output", required=True, help="Output PCAP file path")
    parser.add_argument("--rules", required=False, help="Rules JSON string or path")
    parser.add_argument("--interval", type=float, default=2.0, help="Stats emit interval in seconds")
    parser.add_argument("--json", action="store_true", help="Emit NDJSON status lines")
    return parser.parse_args()


def load_rules_from_arg(rules: RuleManager, rules_arg: str | None) -> None:
    if not rules_arg:
        return

    path = Path(rules_arg)
    if path.exists():
        rules.load_from_file(path)
        return

    payload = json.loads(rules_arg)
    if not isinstance(payload, dict):
        raise ValueError("Rules payload must be a JSON object")
    rules.update_from_payload(payload)


class LiveStats:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.total_packets = 0
        self.forwarded_packets = 0
        self.dropped_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.app_counts: dict[str, int] = {}
        self.block_reasons: dict[str, int] = {}

    def as_dict(self) -> dict:
        drop_rate = (self.dropped_packets / self.total_packets) if self.total_packets else 0.0
        uptime = time.time() - self.started_at
        return {
            "uptime_seconds": round(uptime, 2),
            "total_packets": self.total_packets,
            "forwarded_packets": self.forwarded_packets,
            "dropped_packets": self.dropped_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "drop_rate": drop_rate,
            "app_counts": self.app_counts,
            "block_reasons": self.block_reasons,
        }


def emit(payload: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, separators=(",", ":")), flush=True)
    else:
        print(payload, flush=True)


def install_signal_handlers() -> None:
    def stop_handler(signum, _frame):
        global running
        running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)



def main() -> None:
    args = parse_args()
    install_signal_handlers()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rules = RuleManager()
    try:
        load_rules_from_arg(rules, args.rules)
    except Exception as exc:
        emit({"type": "error", "error": f"Invalid rules payload: {exc}"}, args.json)
        sys.exit(2)

    engine = DPIEngine(rule_manager=rules)
    stats = LiveStats()

    emit(
        {
            "type": "started",
            "interface": args.interface,
            "output_file": str(output_path),
            "stats": stats.as_dict(),
        },
        args.json,
    )

    def on_packet(packet):
        nonlocal stats
        if not running:
            return

        raw = bytes(packet)
        parsed = parse_packet(int(time.time()), 0, raw)
        if parsed is None:
            return

        stats.total_packets += 1

        if parsed.has_tcp:
            stats.tcp_packets += 1
        elif parsed.has_udp:
            stats.udp_packets += 1

        tuple_key = parsed.tuple
        if tuple_key is None:
            stats.forwarded_packets += 1
            wrpcap(str(output_path), packet, append=True)
            return

        action, reason, app = engine._process_packet(tuple_key, parsed.payload, parsed.tcp_flags)
        app_name = app.value if isinstance(app, AppType) else str(app)
        stats.app_counts[app_name] = stats.app_counts.get(app_name, 0) + 1

        if action.value == "DROP":
            stats.dropped_packets += 1
            if reason:
                stats.block_reasons[reason] = stats.block_reasons.get(reason, 0) + 1
            return

        stats.forwarded_packets += 1
        wrpcap(str(output_path), packet, append=True)

    sniffer = AsyncSniffer(iface=args.interface, prn=on_packet, store=False)

    try:
        sniffer.start()
    except Exception as exc:
        emit({"type": "error", "error": f"Unable to start sniffer: {exc}"}, args.json)
        sys.exit(1)

    last_emit = time.time()

    try:
        while running:
            now = time.time()
            if now - last_emit >= max(0.5, args.interval):
                emit({"type": "tick", "stats": stats.as_dict(), "output_file": str(output_path)}, args.json)
                last_emit = now
            time.sleep(0.2)
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass

    emit({"type": "stopped", "stats": stats.as_dict(), "output_file": str(output_path)}, args.json)


if __name__ == "__main__":
    main()
