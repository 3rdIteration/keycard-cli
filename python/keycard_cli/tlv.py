"""BER-TLV encoding/decoding helpers, mirroring keycard-go/apdu/utils.go."""
from __future__ import annotations

from io import BytesIO
from typing import Optional


class TagNotFoundError(Exception):
    def __init__(self, tag: bytes) -> None:
        super().__init__(f"tag {tag.hex()} not found")
        self.tag = tag


def _read_byte(buf: BytesIO) -> Optional[int]:
    b = buf.read(1)
    if not b:
        return None
    return b[0]


def _parse_tag(buf: BytesIO) -> Optional[bytes]:
    b = _read_byte(buf)
    if b is None:
        return None
    tag = bytes([b])
    if (b & 0x1F) != 0x1F:
        return tag
    while True:
        b = _read_byte(buf)
        if b is None:
            return None
        tag += bytes([b])
        if (b & 0x80) != 0x80:
            return tag


def _parse_length(buf: BytesIO) -> int:
    b = _read_byte(buf)
    if b is None:
        raise ValueError("unexpected end of data while reading length")
    if b == 0x80:
        raise ValueError("unsupported indefinite length (0x80)")
    if b > 0x80:
        num_bytes = b - 0x80
        if num_bytes > 3:
            raise ValueError("length too big")
        raw = buf.read(num_bytes)
        return int.from_bytes(raw, "big")
    return b


def _find_tag(data: bytes, occurrence: int, tags: list[bytes]) -> bytes:
    if not tags:
        return data

    target = tags[0]
    buf = BytesIO(data)

    while True:
        tag = _parse_tag(buf)
        if tag is None:
            raise TagNotFoundError(target)

        length = _parse_length(buf)
        value = buf.read(length) if length else b""

        if tag == target:
            if len(tags) == 1:
                if occurrence > 0:
                    occurrence -= 1
                    continue
                return value
            return _find_tag(value, occurrence, tags[1:])


def find_tag(data: bytes, *tags: bytes) -> bytes:
    """Find a nested tag in BER-TLV data, raising TagNotFoundError if absent."""
    return _find_tag(data, 0, list(tags))


def find_tag_n(data: bytes, n: int, *tags: bytes) -> bytes:
    """Find the nth occurrence of a tag sequence in BER-TLV data."""
    return _find_tag(data, n, list(tags))


def try_find_tag(data: bytes, *tags: bytes) -> bytes:
    """Like find_tag but returns b'' instead of raising."""
    try:
        return find_tag(data, *tags)
    except (TagNotFoundError, ValueError):
        return b""


def write_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    if length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    raise ValueError(f"length {length} too large for TLV encoding")


def encode_tlv(tag: bytes, value: bytes) -> bytes:
    """Encode a simple TLV (tag + length + value)."""
    return tag + write_length(len(value)) + value
