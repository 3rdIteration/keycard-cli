from __future__ import annotations

from string import Template


def build_url(url_template: str, variables: dict[str, str]) -> str:
    return Template(url_template).substitute(variables)


def build_ndef_data_with_url(url_template: str, variables: dict[str, str]) -> tuple[str, bytes]:
    url = build_url(url_template, variables)
    payload = bytes([0x00]) + url.encode("utf-8")
    record = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
    payload_with_length = len(record).to_bytes(2, "big") + record
    return url, payload_with_length
