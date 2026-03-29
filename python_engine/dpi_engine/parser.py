from __future__ import annotations

import socket
import struct
from typing import Optional

from .types import ParsedPacket


def _ip_to_str(ip_raw: bytes) -> str:
    return socket.inet_ntoa(ip_raw)


def parse_packet(ts_sec: int, ts_usec: int, data: bytes) -> Optional[ParsedPacket]:
    pkt = ParsedPacket(ts_sec=ts_sec, ts_usec=ts_usec, data=data)
    if len(data) < 14:
        return None

    ether_type = struct.unpack("!H", data[12:14])[0]
    if ether_type != 0x0800:
        return pkt

    pkt.has_ip = True
    ip_off = 14
    if len(data) < ip_off + 20:
        return None

    version_ihl = data[ip_off]
    version = (version_ihl >> 4) & 0x0F
    if version != 4:
        return None

    ihl = version_ihl & 0x0F
    ip_header_len = ihl * 4
    if len(data) < ip_off + ip_header_len:
        return None

    pkt.protocol = data[ip_off + 9]
    pkt.src_ip = _ip_to_str(data[ip_off + 12 : ip_off + 16])
    pkt.dst_ip = _ip_to_str(data[ip_off + 16 : ip_off + 20])

    transport_off = ip_off + ip_header_len
    if pkt.protocol == 6:
        if len(data) < transport_off + 20:
            return None
        pkt.has_tcp = True
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", data[transport_off : transport_off + 4])
        pkt.tcp_flags = data[transport_off + 13]
        tcp_data_offset = (data[transport_off + 12] >> 4) & 0x0F
        tcp_len = tcp_data_offset * 4
        payload_off = transport_off + tcp_len
    elif pkt.protocol == 17:
        if len(data) < transport_off + 8:
            return None
        pkt.has_udp = True
        pkt.src_port, pkt.dst_port = struct.unpack("!HH", data[transport_off : transport_off + 4])
        payload_off = transport_off + 8
    else:
        payload_off = transport_off

    if payload_off < len(data):
        pkt.payload = data[payload_off:]
    return pkt
