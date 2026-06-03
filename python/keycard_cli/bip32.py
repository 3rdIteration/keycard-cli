"""BIP32 extended public key (xpub) serialization.

Implements the BIP32 serialization format for extended public keys:
  version (4) | depth (1) | fingerprint (4) | child_index (4) | chain_code (32) | key (33)
followed by a 4-byte SHA256d checksum, Base58-encoded.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
"""
from __future__ import annotations

import hashlib
import struct

# BIP32 mainnet public key version bytes
XPUB_VERSION = 0x0488B21E

# Base58 alphabet
_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _base58_encode(data: bytes) -> str:
    # Count leading zero bytes
    count = 0
    for b in data:
        if b == 0:
            count += 1
        else:
            break

    n = int.from_bytes(data, "big")
    chars = []
    while n:
        n, rem = divmod(n, 58)
        chars.append(_BASE58_ALPHABET[rem])
    result = bytes(reversed(chars))
    return ("1" * count) + result.decode("ascii")


def _base58check_encode(payload: bytes) -> str:
    checksum = _sha256d(payload)[:4]
    return _base58_encode(payload + checksum)


def _compress_pubkey(uncompressed: bytes) -> bytes:
    """Compress an uncompressed secp256k1 public key (65 bytes → 33 bytes)."""
    if len(uncompressed) == 33:
        return uncompressed
    if len(uncompressed) != 65 or uncompressed[0] != 0x04:
        raise ValueError(f"expected 65-byte uncompressed public key, got {len(uncompressed)} bytes")
    y = uncompressed[64]
    prefix = bytes([0x03 if y & 1 else 0x02])
    return prefix + uncompressed[1:33]


def serialize_xpub(
    pub_key: bytes,
    chain_code: bytes,
    depth: int = 0,
    fingerprint: bytes = b"\x00\x00\x00\x00",
    child_index: int = 0,
    version: int = XPUB_VERSION,
) -> str:
    """Serialize an extended public key to BIP32 xpub string.

    Args:
        pub_key:     33-byte compressed (or 65-byte uncompressed) secp256k1 key.
        chain_code:  32-byte chain code from the card's ExportKey extended response.
        depth:       BIP32 depth (0 for a root/master-level export).
        fingerprint: 4-byte parent fingerprint (all zeros for root).
        child_index: BIP32 child index (0 for root).
        version:     4-byte version (default: mainnet xpub 0x0488B21E).

    Returns:
        Base58Check-encoded xpub string.
    """
    if len(chain_code) != 32:
        raise ValueError(f"chain_code must be 32 bytes, got {len(chain_code)}")

    compressed = _compress_pubkey(pub_key)
    if len(compressed) != 33:
        raise ValueError("failed to compress public key")

    payload = (
        struct.pack(">I", version)
        + bytes([depth])
        + fingerprint[:4]
        + struct.pack(">I", child_index)
        + chain_code
        + compressed
    )
    return _base58check_encode(payload)
