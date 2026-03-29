from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .apps import sni_to_app_type
from .extractors import extract_dns_query, extract_http_host, extract_tls_sni
from .parser import parse_packet
from .pcap import PcapReader, PcapWriter
from .rules import RuleManager
from .types import AppType, Connection, ConnectionState, DPIStats, FiveTuple, PacketAction


@dataclass
class ProcessResult:
    input_file: str
    output_file: str
    stats: dict


class DPIEngine:
    def __init__(self, rule_manager: RuleManager | None = None) -> None:
        self.rule_manager = rule_manager or RuleManager()
        self.connections: dict[FiveTuple, Connection] = {}

    def _get_connection(self, key: FiveTuple) -> Connection:
        conn = self.connections.get(key)
        if conn:
            return conn
        rev = key.reverse()
        conn = self.connections.get(rev)
        if conn:
            return conn
        conn = Connection(tuple=key)
        self.connections[key] = conn
        return conn

    def _classify_connection(self, conn: Connection, tuple_key: FiveTuple, payload: bytes) -> None:
        host = ""
        app = AppType.UNKNOWN

        if tuple_key.protocol == 6 and tuple_key.dst_port == 443:
            host = extract_tls_sni(payload) or ""
            app = sni_to_app_type(host) if host else AppType.HTTPS
        elif tuple_key.protocol == 6 and tuple_key.dst_port == 80:
            host = extract_http_host(payload) or ""
            app = sni_to_app_type(host) if host else AppType.HTTP
        elif tuple_key.dst_port == 53 or tuple_key.src_port == 53:
            host = extract_dns_query(payload) or ""
            app = AppType.DNS if host else AppType.UNKNOWN
        elif tuple_key.dst_port == 443:
            app = AppType.HTTPS
        elif tuple_key.dst_port == 80:
            app = AppType.HTTP

        if app != AppType.UNKNOWN or host:
            conn.state = ConnectionState.CLASSIFIED
            conn.app_type = app
            conn.sni = host

    def _process_packet(self, tuple_key: FiveTuple, payload: bytes, tcp_flags: int) -> tuple[PacketAction, str | None, AppType]:
        conn = self._get_connection(tuple_key)
        conn.packets_in += 1
        conn.bytes_in += len(payload)

        if tuple_key.protocol == 6:
            if tcp_flags & 0x02:
                if tcp_flags & 0x10:
                    conn.tcp_syn_ack_seen = True
                else:
                    conn.tcp_syn_seen = True
            if conn.tcp_syn_seen and conn.tcp_syn_ack_seen and (tcp_flags & 0x10):
                conn.state = ConnectionState.ESTABLISHED
            if tcp_flags & 0x01:
                conn.tcp_fin_seen = True
            if tcp_flags & 0x04:
                conn.state = ConnectionState.CLOSED
            if conn.tcp_fin_seen and (tcp_flags & 0x10):
                conn.state = ConnectionState.CLOSED

        if conn.state != ConnectionState.CLASSIFIED and payload:
            self._classify_connection(conn, tuple_key, payload)

        reason = self.rule_manager.should_block(
            src_ip=tuple_key.src_ip,
            dst_port=tuple_key.dst_port,
            app=conn.app_type,
            domain=conn.sni,
        )
        if reason:
            conn.state = ConnectionState.BLOCKED
            return PacketAction.DROP, reason, conn.app_type

        return PacketAction.FORWARD, None, conn.app_type

    def process_file(self, input_file: str | Path, output_file: str | Path) -> ProcessResult:
        input_file = str(input_file)
        output_file = str(output_file)
        stats = DPIStats()

        self.connections.clear()

        with PcapReader(input_file) as reader, PcapWriter(output_file) as writer:
            if not reader.global_header:
                raise RuntimeError("Failed to read PCAP global header")
            writer.write_global_header(reader.global_header.raw)

            for packet in reader.packets():
                parsed = parse_packet(packet.ts_sec, packet.ts_usec, packet.data)
                if parsed is None:
                    continue

                stats.total_packets += 1
                stats.total_bytes += len(packet.data)

                tuple_key = parsed.tuple
                if tuple_key is None:
                    stats.forwarded_packets += 1
                    writer.write_packet(packet.header_raw, packet.data)
                    continue

                if parsed.has_tcp:
                    stats.tcp_packets += 1
                elif parsed.has_udp:
                    stats.udp_packets += 1

                action, reason, app = self._process_packet(tuple_key, parsed.payload, parsed.tcp_flags)
                stats.app_counts[app.value] = stats.app_counts.get(app.value, 0) + 1

                if action == PacketAction.DROP:
                    stats.dropped_packets += 1
                    if reason:
                        stats.block_reasons[reason] = stats.block_reasons.get(reason, 0) + 1
                    continue

                stats.forwarded_packets += 1
                writer.write_packet(packet.header_raw, packet.data)

        return ProcessResult(input_file=input_file, output_file=output_file, stats=stats.as_dict())
