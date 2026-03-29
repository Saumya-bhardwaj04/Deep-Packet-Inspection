from __future__ import annotations

from typing import Optional


def _u16_be(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], byteorder="big", signed=False)


def _u24_be(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 3], byteorder="big", signed=False)


def extract_tls_sni(payload: bytes) -> Optional[str]:
    if len(payload) < 9:
        return None
    if payload[0] != 0x16:
        return None
    version = _u16_be(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return None
    record_len = _u16_be(payload, 3)
    if record_len > len(payload) - 5:
        return None
    if payload[5] != 0x01:
        return None

    off = 5
    handshake_len = _u24_be(payload, off + 1)
    if handshake_len <= 0:
        return None
    off += 4

    # version + random
    if off + 34 > len(payload):
        return None
    off += 34

    if off >= len(payload):
        return None
    session_len = payload[off]
    off += 1 + session_len

    if off + 2 > len(payload):
        return None
    cs_len = _u16_be(payload, off)
    off += 2 + cs_len

    if off >= len(payload):
        return None
    comp_len = payload[off]
    off += 1 + comp_len

    if off + 2 > len(payload):
        return None
    exts_len = _u16_be(payload, off)
    off += 2
    exts_end = min(len(payload), off + exts_len)

    while off + 4 <= exts_end:
        ext_type = _u16_be(payload, off)
        ext_len = _u16_be(payload, off + 2)
        off += 4
        if off + ext_len > exts_end:
            break
        if ext_type == 0x0000 and ext_len >= 5:
            list_len = _u16_be(payload, off)
            if list_len < 3:
                return None
            name_type = payload[off + 2]
            name_len = _u16_be(payload, off + 3)
            if name_type != 0x00:
                return None
            if name_len > ext_len - 5:
                return None
            host_bytes = payload[off + 5 : off + 5 + name_len]
            try:
                return host_bytes.decode("utf-8", errors="ignore")
            except Exception:
                return None
        off += ext_len

    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    if len(payload) < 4:
        return None
    methods = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")
    if not any(payload.startswith(m) for m in methods):
        return None

    text = payload.decode("latin1", errors="ignore")
    for line in text.splitlines():
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            if ":" in host:
                host = host.split(":", 1)[0]
            return host
    return None


def extract_dns_query(payload: bytes) -> Optional[str]:
    if len(payload) < 12:
        return None
    if payload[2] & 0x80:
        return None
    qd_count = _u16_be(payload, 4)
    if qd_count == 0:
        return None

    off = 12
    labels: list[str] = []
    while off < len(payload):
        length = payload[off]
        if length == 0:
            break
        if length > 63 or off + 1 + length > len(payload):
            return None
        off += 1
        labels.append(payload[off : off + length].decode("ascii", errors="ignore"))
        off += length
    if not labels:
        return None
    return ".".join(labels)
