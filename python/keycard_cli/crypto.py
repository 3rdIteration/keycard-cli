from __future__ import annotations

from Cryptodome.Hash import keccak


def hash_ethereum_message(message: str) -> bytes:
    data = message.encode("utf-8")
    if message.startswith("0x"):
        try:
            data = bytes.fromhex(message[2:])
        except ValueError:
            pass

    wrapped = f"\x19Ethereum Signed Message:\n{len(data)}".encode("utf-8") + data
    digest = keccak.new(digest_bits=256)
    digest.update(wrapped)
    return digest.digest()
