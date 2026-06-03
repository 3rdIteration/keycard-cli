"""Ethereum transaction encoding, hashing, and signing helpers.

Supports:
  - Legacy (pre-EIP-155) transactions.
  - EIP-155 replay-protected transactions (chain_id > 0).

Transaction dict keys (all values as int or hex str):
  nonce, gas_price, gas, to, value, data, chain_id (optional, default 0 = legacy)

Usage example::

    tx = {
        "nonce": 0,
        "gas_price": 20_000_000_000,
        "gas": 21000,
        "to": "0xrecipient...",
        "value": 1_000_000_000_000_000_000,
        "data": b"",
        "chain_id": 1,
    }
    tx_hash = hash_transaction(tx)
    # sign tx_hash with keycard, get Signature(r, s, v)
    signed_hex = encode_signed_transaction(tx, sig_r, sig_s, sig_v_raw, chain_id=1)
"""
from __future__ import annotations

from typing import Union

from Cryptodome.Hash import keccak as _keccak


# ── RLP encoding ─────────────────────────────────────────────────────────────

def _rlp_encode_bytes(data: bytes) -> bytes:
    if len(data) == 1 and data[0] < 0x80:
        return data
    length = len(data)
    if length <= 55:
        return bytes([0x80 + length]) + data
    len_bytes = _int_to_bytes(length)
    return bytes([0xB7 + len(len_bytes)]) + len_bytes + data


def _rlp_encode_list(items: list) -> bytes:
    encoded_items = b"".join(_rlp_encode(item) for item in items)
    length = len(encoded_items)
    if length <= 55:
        return bytes([0xC0 + length]) + encoded_items
    len_bytes = _int_to_bytes(length)
    return bytes([0xF7 + len(len_bytes)]) + len_bytes + encoded_items


def _rlp_encode(value) -> bytes:
    if isinstance(value, int):
        if value == 0:
            return _rlp_encode_bytes(b"")
        return _rlp_encode_bytes(_int_to_bytes(value))
    if isinstance(value, (bytes, bytearray)):
        return _rlp_encode_bytes(bytes(value))
    if isinstance(value, list):
        return _rlp_encode_list(value)
    raise TypeError(f"cannot RLP-encode {type(value)}")


def _int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


# ── Keccak-256 ────────────────────────────────────────────────────────────────

def _keccak256(data: bytes) -> bytes:
    d = _keccak.new(digest_bits=256)
    d.update(data)
    return d.digest()


# ── Parsing helpers ───────────────────────────────────────────────────────────

def _parse_int(v: Union[int, str, bytes, None]) -> int:
    if v is None:
        return 0
    if isinstance(v, int):
        return v
    if isinstance(v, (bytes, bytearray)):
        return int.from_bytes(v, "big") if v else 0
    s = str(v).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def _parse_bytes(v: Union[str, bytes, None]) -> bytes:
    if v is None:
        return b""
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    s = str(v).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return bytes.fromhex(s[2:]) if len(s) > 2 else b""
    return bytes.fromhex(s) if s else b""


def _parse_address(v: Union[str, bytes, None]) -> bytes:
    if v is None:
        return b""  # contract creation
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    s = str(v).strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return bytes.fromhex(s)


# ── Transaction hashing ───────────────────────────────────────────────────────

def hash_transaction(tx: dict) -> bytes:
    """Compute the hash of an unsigned Ethereum transaction.

    For EIP-155 transactions (chain_id > 0), the hash is:
      keccak256(RLP([nonce, gas_price, gas, to, value, data, chain_id, 0, 0]))

    For legacy transactions (chain_id == 0):
      keccak256(RLP([nonce, gas_price, gas, to, value, data]))

    Returns 32-byte hash ready for signing.
    """
    nonce = _parse_int(tx.get("nonce"))
    gas_price = _parse_int(tx.get("gas_price") or tx.get("gasPrice"))
    gas = _parse_int(tx.get("gas") or tx.get("gas_limit") or tx.get("gasLimit"))
    to = _parse_address(tx.get("to"))
    value = _parse_int(tx.get("value"))
    data = _parse_bytes(tx.get("data") or tx.get("input"))
    chain_id = _parse_int(tx.get("chain_id") or tx.get("chainId") or 0)

    fields: list = [nonce, gas_price, gas, to, value, data]
    if chain_id > 0:
        fields += [chain_id, 0, 0]

    rlp_encoded = _rlp_encode(fields)
    return _keccak256(rlp_encoded)


# ── Signed transaction encoding ───────────────────────────────────────────────

def encode_signed_transaction(tx: dict, sig_r: bytes, sig_s: bytes,
                               sig_v_raw: int, chain_id: int = 0) -> str:
    """Encode a signed Ethereum transaction as a hex string (with 0x prefix).

    Args:
        tx:         Transaction dict (same format as hash_transaction).
        sig_r:      32-byte big-endian r value of the signature.
        sig_s:      32-byte big-endian s value of the signature.
        sig_v_raw:  Recovery id (0 or 1) returned by the keycard.
        chain_id:   Chain ID for EIP-155 (0 for legacy).

    Returns:
        Hex-encoded signed transaction (starting with "0x").
    """
    nonce = _parse_int(tx.get("nonce"))
    gas_price = _parse_int(tx.get("gas_price") or tx.get("gasPrice"))
    gas = _parse_int(tx.get("gas") or tx.get("gas_limit") or tx.get("gasLimit"))
    to = _parse_address(tx.get("to"))
    value = _parse_int(tx.get("value"))
    data = _parse_bytes(tx.get("data") or tx.get("input"))

    if chain_id > 0:
        v = chain_id * 2 + 35 + sig_v_raw
    else:
        v = sig_v_raw + 27

    r_int = int.from_bytes(sig_r, "big")
    s_int = int.from_bytes(sig_s, "big")

    fields: list = [nonce, gas_price, gas, to, value, data, v, r_int, s_int]
    rlp_encoded = _rlp_encode(fields)
    return "0x" + rlp_encoded.hex()
