from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AppType(str, Enum):
    UNKNOWN = "Unknown"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    QUIC = "QUIC"
    GOOGLE = "Google"
    FACEBOOK = "Facebook"
    YOUTUBE = "YouTube"
    TWITTER = "Twitter/X"
    INSTAGRAM = "Instagram"
    NETFLIX = "Netflix"
    AMAZON = "Amazon"
    MICROSOFT = "Microsoft"
    APPLE = "Apple"
    WHATSAPP = "WhatsApp"
    TELEGRAM = "Telegram"
    TIKTOK = "TikTok"
    SPOTIFY = "Spotify"
    ZOOM = "Zoom"
    DISCORD = "Discord"
    GITHUB = "GitHub"
    CLOUDFLARE = "Cloudflare"


class ConnectionState(str, Enum):
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    CLASSIFIED = "CLASSIFIED"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


class PacketAction(str, Enum):
    FORWARD = "FORWARD"
    DROP = "DROP"


@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> "FiveTuple":
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )


@dataclass
class ParsedPacket:
    ts_sec: int
    ts_usec: int
    data: bytes
    has_ip: bool = False
    has_tcp: bool = False
    has_udp: bool = False
    protocol: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    payload: bytes = b""

    @property
    def tuple(self) -> Optional[FiveTuple]:
        if not self.has_ip or (not self.has_tcp and not self.has_udp):
            return None
        return FiveTuple(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
        )


@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets_in: int = 0
    bytes_in: int = 0
    tcp_syn_seen: bool = False
    tcp_syn_ack_seen: bool = False
    tcp_fin_seen: bool = False


@dataclass
class DPIStats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    app_counts: dict[str, int] = field(default_factory=dict)
    block_reasons: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "forwarded_packets": self.forwarded_packets,
            "dropped_packets": self.dropped_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "drop_rate": (self.dropped_packets / self.total_packets) if self.total_packets else 0.0,
            "app_counts": self.app_counts,
            "block_reasons": self.block_reasons,
        }
