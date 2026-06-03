from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Optional

from .bip32 import serialize_xpub
from .card import CardSession, connect_to_card
from .keycard_proto import (
    KeycardCommandSet,
    P2_PAIRING_ANY,
    P2_PAIRING_EPHEMERAL,
    P2_PAIRING_PERSISTENT,
    PairingInfo,
    Signature,
)

# Match pysatochip xpub version mappings.
_XPUB_HEADERS_MAINNET = {
    "standard": 0x0488B21E,  # xpub
    "p2wpkh-p2sh": 0x049D7CB2,  # ypub
    "p2wsh-p2sh": 0x0295B43F,  # Ypub
    "p2wpkh": 0x04B24746,  # zpub
    "p2wsh": 0x02AA7ED3,  # Zpub
}

_XPUB_HEADERS_TESTNET = {
    "standard": 0x043587CF,  # tpub
    "p2wpkh-p2sh": 0x044A5262,  # upub
    "p2wsh-p2sh": 0x024289EF,  # Upub
    "p2wpkh": 0x045F1CF6,  # vpub
    "p2wsh": 0x02575483,  # Vpub
}


def _compress_pub(pub_key: bytes) -> bytes:
    if len(pub_key) == 33:
        return pub_key
    if len(pub_key) != 65 or pub_key[0] != 0x04:
        raise ValueError("expected 65-byte uncompressed or 33-byte compressed pubkey")
    return bytes([0x03 if (pub_key[64] & 1) else 0x02]) + pub_key[1:33]


def _hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha).digest()


def _parse_bip32_path(path: str) -> list[int]:
    text = path.strip()
    if text in ("", "m"):
        return []
    if not text.startswith("m/"):
        raise ValueError(f"unsupported path format: {path}")
    parts = text[2:].split("/")
    result: list[int] = []
    for p in parts:
        hardened = p.endswith("'")
        if hardened:
            p = p[:-1]
        idx = int(p)
        if idx < 0 or idx >= 0x80000000:
            raise ValueError(f"invalid path index: {idx}")
        if hardened:
            idx |= 0x80000000
        result.append(idx)
    return result


def _encode_der_int(v: bytes) -> bytes:
    i = v.lstrip(b"\x00") or b"\x00"
    if i[0] & 0x80:
        i = b"\x00" + i
    return b"\x02" + bytes([len(i)]) + i


def _signature_to_der(sig: Signature) -> bytes:
    seq = _encode_der_int(sig.r) + _encode_der_int(sig.s)
    return b"\x30" + bytes([len(seq)]) + seq


def _signature_to_compact65(sig: Signature, compressed: bool = True) -> bytes:
    # Bitcoin-style compact header byte for recoverable signatures.
    # 27 + recid (+4 when compressed pubkey is used)
    header = 27 + (sig.v & 0x03) + (4 if compressed else 0)
    return bytes([header]) + sig.r + sig.s


@dataclass
class ECPubkeyCompat:
    """Small compatibility wrapper matching pysatochip ECPubkey accessors."""

    _raw_pub: bytes

    def get_public_key_bytes(self, compressed: bool = True) -> bytes:
        return _compress_pub(self._raw_pub) if compressed else self._raw_pub

    def get_public_key_hex(self, compressed: bool = True) -> str:
        return self.get_public_key_bytes(compressed=compressed).hex()


class KeycardCompatConnector:
    """pysatochip-like adapter for SeedSigner-side backend abstraction.

    The goal is API shape compatibility for common workflows:
    PIN verify, xpub export, and 32-byte digest signing.
    """

    def __init__(
        self,
        session: Optional[CardSession] = None,
        pairing_password: Optional[str] = None,
        pairing_key_hex: Optional[str] = None,
        pairing_index: Optional[int] = None,
    ) -> None:
        self.session = session or connect_to_card()
        self.kcs = KeycardCommandSet(self.session)
        self.pairing_password = pairing_password
        self._secure_open = False
        self._last_path: Optional[str] = None

        if pairing_key_hex is not None and pairing_index is not None:
            self.kcs.set_pairing_info(bytes.fromhex(pairing_key_hex), int(pairing_index))

        # Prime card app info and secure-channel ephemeral secret.
        self.kcs.select()

    def card_disconnect(self) -> None:
        self.session.disconnect()

    def card_select(self):
        info = self.kcs.select()
        return {
            "installed": info.installed,
            "initialized": info.initialized,
            "instance_uid": info.instance_uid.hex(),
            "version": info.version.hex(),
            "available_slots": info.available_slots.hex(),
            "key_uid": info.key_uid.hex(),
        }

    def set_pairing(self, pairing_key_hex: str, pairing_index: int) -> None:
        self.kcs.set_pairing_info(bytes.fromhex(pairing_key_hex), int(pairing_index))
        self._secure_open = False

    def get_pairing(self) -> Optional[tuple[str, int]]:
        if self.kcs.pairing_info is None:
            return None
        return self.kcs.pairing_info.key.hex(), self.kcs.pairing_info.index

    def pair(self, pairing_password: Optional[str] = None, pair_mode: str = "ephemeral") -> tuple[str, int]:
        password = pairing_password or self.pairing_password
        if not password:
            raise ValueError("pairing_password required for initial pairing")
        mode_map = {
            "ephemeral": P2_PAIRING_EPHEMERAL,
            "persistent": P2_PAIRING_PERSISTENT,
            "any": P2_PAIRING_ANY,
        }
        selected_mode = mode_map.get(pair_mode.lower())
        if selected_mode is None:
            raise ValueError("pair_mode must be one of: ephemeral, persistent, any")

        info: PairingInfo = self.kcs.pair(password, pair_mode=selected_mode)
        self._secure_open = False
        return info.key.hex(), info.index

    def _ensure_secure_channel(self) -> None:
        if self._secure_open:
            return
        if self.kcs.pairing_info is None:
            # Default to ephemeral pairing when no pairing is injected.
            self.pair()
        self.kcs.open_secure_channel()
        self._secure_open = True

    def card_verify_PIN(self, pin: str | None = None):
        if not pin:
            raise ValueError("PIN is required")
        self._ensure_secure_channel()
        self.kcs.verify_pin(pin)
        return ([], 0x90, 0x00)

    def card_get_status(self):
        self._ensure_secure_channel()
        app = self.kcs.get_status_application()
        path = self.kcs.get_status_key_path()
        status = {
            "pin_retry_count": app.pin_retry_count,
            "puk_retry_count": app.puk_retry_count,
            "key_initialized": app.key_initialized,
            "path": path.path,
        }
        return ([], 0x90, 0x00, status)

    def card_bip32_get_authentikey(self) -> ECPubkeyCompat:
        pub = self.kcs.identify()
        return ECPubkeyCompat(pub)

    def card_export_authentikey(self) -> ECPubkeyCompat:
        return self.card_bip32_get_authentikey()

    def card_bip32_get_extendedkey(self, path, sid=None, option_flags=0x40):
        _ = sid
        _ = option_flags
        self._ensure_secure_channel()
        path_str = path.decode("ascii") if isinstance(path, bytes) else str(path)
        key = self.kcs.export_key_extended(path_str)
        self._last_path = path_str
        return ECPubkeyCompat(key.pub_key), key.chain_code

    def card_bip32_get_xpub(self, path, xtype, is_mainnet, sid=None):
        _ = sid
        path_str = path.decode("ascii") if isinstance(path, bytes) else str(path)
        indices = _parse_bip32_path(path_str)
        depth = len(indices)

        child, child_chain = self.card_bip32_get_extendedkey(path_str)
        child_index = indices[-1] if indices else 0

        if depth == 0:
            fingerprint = b"\x00\x00\x00\x00"
        else:
            parent_parts: list[str] = []
            for i in indices[:-1]:
                base = str(i & 0x7FFFFFFF)
                if i & 0x80000000:
                    base += "'"
                parent_parts.append(base)
            parent_path = "m/" + "/".join(parent_parts)
            if parent_path == "m/":
                parent_path = "m"
            parent, _ = self.card_bip32_get_extendedkey(parent_path)
            fingerprint = _hash160(parent.get_public_key_bytes(compressed=True))[:4]

        header_map = _XPUB_HEADERS_MAINNET if is_mainnet else _XPUB_HEADERS_TESTNET
        version = header_map.get(xtype)
        if version is None:
            raise ValueError(f"unsupported xtype: {xtype}")

        return serialize_xpub(
            child.get_public_key_bytes(compressed=False),
            child_chain,
            depth=depth,
            fingerprint=fingerprint,
            child_index=child_index,
            version=version,
        )

    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse=None):
        _ = chalresponse  # 2FA challenge-response is handled at caller level.
        self._ensure_secure_channel()

        if isinstance(txhash, list):
            digest = bytes(txhash)
        elif isinstance(txhash, bytes):
            digest = txhash
        else:
            digest = bytes.fromhex(str(txhash))
        if len(digest) != 32:
            raise ValueError("txhash must be exactly 32 bytes")

        # keynbr 0xFF means BIP32 current/derived key in pysatochip conventions.
        if int(keynbr) == 0xFF and self._last_path:
            sig = self.kcs.sign_with_path(digest, self._last_path)
        else:
            sig = self.kcs.sign(digest)

        der = _signature_to_der(sig)
        return (list(der), 0x90, 0x00)

    def card_sign_transaction(self, keynbr, txhash, chalresponse=None):
        return self.card_sign_transaction_hash(keynbr, txhash, chalresponse)

    def card_sign_message(self, keynbr, pubkey, message, hmac=b"", altcoin=None):
        _ = pubkey
        _ = hmac
        _ = altcoin
        self._ensure_secure_channel()

        # This compatibility layer signs a 32-byte digest. Message formatting/hashing
        # should be handled by caller abstraction (for example SeedSigner).
        if isinstance(message, list):
            digest = bytes(message)
        elif isinstance(message, bytes):
            digest = message
        else:
            digest = str(message).encode("utf-8")
        if len(digest) != 32:
            raise ValueError("message must be a 32-byte digest in this adapter")

        if int(keynbr) == 0xFF and self._last_path:
            sig = self.kcs.sign_with_path(digest, self._last_path)
        else:
            sig = self.kcs.sign(digest)

        der = _signature_to_der(sig)
        compsig = _signature_to_compact65(sig)
        return (list(der), 0x90, 0x00, compsig)
