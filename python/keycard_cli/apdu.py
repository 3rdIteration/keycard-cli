from __future__ import annotations

from dataclasses import dataclass


SW_OK = 0x9000


@dataclass(frozen=True)
class APDUResponse:
    data: bytes
    sw: int

    @property
    def ok(self) -> bool:
        return self.sw == SW_OK


def decode_hex_command(value: str) -> bytes:
    value = value.strip()
    if value.startswith("0x"):
        value = value[2:]
    if len(value) % 2 != 0:
        raise ValueError("hex command must contain an even number of characters")
    return bytes.fromhex(value)


def sw_to_hex(sw: int) -> str:
    return f"0x{sw:04x}"
