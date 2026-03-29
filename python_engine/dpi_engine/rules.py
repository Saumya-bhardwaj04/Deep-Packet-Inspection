from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .types import AppType


@dataclass
class RuleSet:
    blocked_ips: set[str] = field(default_factory=set)
    blocked_apps: set[AppType] = field(default_factory=set)
    blocked_domains: set[str] = field(default_factory=set)
    blocked_ports: set[int] = field(default_factory=set)


class RuleManager:
    def __init__(self) -> None:
        self.rules = RuleSet()

    def should_block(self, src_ip: str, dst_port: int, app: AppType, domain: str) -> Optional[str]:
        if src_ip in self.rules.blocked_ips:
            return f"IP:{src_ip}"
        if dst_port in self.rules.blocked_ports:
            return f"PORT:{dst_port}"
        if app in self.rules.blocked_apps:
            return f"APP:{app.value}"
        if domain:
            lower_domain = domain.lower()
            for pattern in self.rules.blocked_domains:
                if fnmatch.fnmatch(lower_domain, pattern.lower()):
                    return f"DOMAIN:{pattern}"
        return None

    def to_dict(self) -> dict:
        return {
            "blocked_ips": sorted(self.rules.blocked_ips),
            "blocked_apps": sorted([app.value for app in self.rules.blocked_apps]),
            "blocked_domains": sorted(self.rules.blocked_domains),
            "blocked_ports": sorted(self.rules.blocked_ports),
        }

    def load_from_file(self, file_path: str | Path) -> None:
        payload = json.loads(Path(file_path).read_text(encoding="utf-8"))
        self.update_from_payload(payload)

    def save_to_file(self, file_path: str | Path) -> None:
        Path(file_path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    def update_from_payload(self, payload: dict) -> None:
        blocked_apps: set[AppType] = set()
        for app_name in payload.get("blocked_apps", []):
            for app in AppType:
                if app.value.lower() == str(app_name).lower():
                    blocked_apps.add(app)
                    break

        self.rules = RuleSet(
            blocked_ips={str(x) for x in payload.get("blocked_ips", [])},
            blocked_apps=blocked_apps,
            blocked_domains={str(x) for x in payload.get("blocked_domains", [])},
            blocked_ports={int(x) for x in payload.get("blocked_ports", [])},
        )
