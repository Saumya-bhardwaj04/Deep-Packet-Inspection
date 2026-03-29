from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, BinaryIO


@dataclass
class PcapGlobalHeader:
    raw: bytes
    byteorder: str
    snaplen: int


@dataclass
class PcapPacket:
    header_raw: bytes
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int
    data: bytes


class PcapReader:
    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self._f: BinaryIO | None = None
        self.global_header: PcapGlobalHeader | None = None

    def __enter__(self) -> "PcapReader":
        self.open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def open(self) -> None:
        self._f = self.file_path.open("rb")
        raw = self._f.read(24)
        if len(raw) != 24:
            raise ValueError("Invalid PCAP: global header too short")
        magic = raw[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            byteorder = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            byteorder = ">"
        else:
            raise ValueError("Invalid PCAP: unsupported magic number")

        _, _, _, _, _, snaplen, _ = struct.unpack(f"{byteorder}IHHIIII", raw)
        self.global_header = PcapGlobalHeader(raw=raw, byteorder=byteorder, snaplen=snaplen)

    def close(self) -> None:
        if self._f:
            self._f.close()
            self._f = None

    def packets(self) -> Generator[PcapPacket, None, None]:
        if not self._f or not self.global_header:
            raise RuntimeError("Reader not opened")

        bo = self.global_header.byteorder
        while True:
            header_raw = self._f.read(16)
            if not header_raw:
                break
            if len(header_raw) != 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{bo}IIII", header_raw)
            data = self._f.read(incl_len)
            if len(data) != incl_len:
                break
            yield PcapPacket(
                header_raw=header_raw,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                incl_len=incl_len,
                orig_len=orig_len,
                data=data,
            )


class PcapWriter:
    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self._f: BinaryIO | None = None

    def __enter__(self) -> "PcapWriter":
        self._f = self.file_path.open("wb")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._f:
            self._f.close()
            self._f = None

    def write_global_header(self, raw: bytes) -> None:
        if not self._f:
            raise RuntimeError("Writer not opened")
        self._f.write(raw)

    def write_packet(self, header_raw: bytes, data: bytes) -> None:
        if not self._f:
            raise RuntimeError("Writer not opened")
        self._f.write(header_raw)
        self._f.write(data)
