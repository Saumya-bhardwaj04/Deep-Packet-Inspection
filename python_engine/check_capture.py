from __future__ import annotations

import json
import platform
import sys


payload = {
    "ok": False,
    "platform": platform.system(),
    "python": sys.version.split()[0],
    "provider": None,
    "interfaces": [],
    "reason": None,
    "suggestion": None,
}

try:
    from scapy.all import conf, get_if_list  # type: ignore

    payload["provider"] = "libpcap" if bool(getattr(conf, "use_pcap", False)) else "native"

    try:
        payload["interfaces"] = get_if_list() or []
    except Exception as exc:
        payload["interfaces"] = []
        payload["reason"] = f"Unable to list interfaces: {exc}"

    # Production requirement: reliable capture needs pcap provider.
    if bool(getattr(conf, "use_pcap", False)) and payload["interfaces"]:
        payload["ok"] = True
    else:
        payload["ok"] = False
        if not payload["reason"]:
            payload["reason"] = "Packet capture backend unavailable"
        if payload["platform"] == "Windows":
            payload["suggestion"] = "Install Npcap (WinPcap API compatible mode) and restart the service"
        else:
            payload["suggestion"] = "Install libpcap/tcpdump dependencies and restart the service"

except Exception as exc:
    payload["ok"] = False
    payload["reason"] = f"Scapy check failed: {exc}"
    payload["suggestion"] = "Verify python dependencies are installed in the backend Python environment"

print(json.dumps(payload, separators=(",", ":")))
