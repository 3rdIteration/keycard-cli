"""Full keycard protocol implementation, mirroring github.com/status-im/keycard-go.

Provides APDU builders, secure channel, pairing, and the full command set.
Requires:
  - pycryptodomex >= 3.22 (AES, SHA, HMAC, PBKDF2)
  - cryptography >= 41 (secp256k1 ECDH key exchange)
"""
from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Optional, Tuple

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, SHA512, HMAC
from Cryptodome.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicNumbers,
    SECP256K1,
    ECDH,
)

from .apdu import APDUResponse, SW_OK
from .card import CardSession
from .tlv import find_tag, find_tag_n, try_find_tag, encode_tlv, TagNotFoundError

# ── secp256k1 curve constants (for pure-Python point arithmetic) ──────────────
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _secp256k1_point_add(p1, p2):
    """Add two secp256k1 affine points.  None represents the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    p = _SECP256K1_P
    if x1 == x2:
        if y1 != y2:
            return None  # point at infinity
        # Point doubling
        m = (3 * x1 * x1 * pow(2 * y1, p - 2, p)) % p
    else:
        m = ((y2 - y1) * pow(x2 - x1, p - 2, p)) % p
    x3 = (m * m - x1 - x2) % p
    y3 = (m * (x1 - x3) - y1) % p
    return x3, y3


def _secp256k1_point_mul(k: int, point):
    """Scalar multiplication on secp256k1 using double-and-add."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _secp256k1_point_add(result, addend)
        addend = _secp256k1_point_add(addend, addend)
        k >>= 1
    return result

# ── AIDs ─────────────────────────────────────────────────────────────────────
KEYCARD_AID = bytes.fromhex("A000000804000101")
KEYCARD_INSTANCE_AID = bytes.fromhex("A00000080400010101")
CASH_INSTANCE_AID = bytes.fromhex("A00000080400010301")
ISD_AID = bytes.fromhex("A000000151000000")

# ── CLA / INS constants ───────────────────────────────────────────────────────
CLA_GP = 0x80
CLA_ISO = 0x00

INS_SELECT = 0xA4
INS_INIT = 0xFE
INS_OPEN_SECURE_CHANNEL = 0x10
INS_MUTUALLY_AUTHENTICATE = 0x11
INS_PAIR = 0x12
INS_UNPAIR = 0x13
INS_IDENTIFY = 0x14
INS_GET_STATUS = 0xF2
INS_GENERATE_KEY = 0xD4
INS_REMOVE_KEY = 0xD3
INS_VERIFY_PIN = 0x20
INS_CHANGE_PIN = 0x21
INS_UNBLOCK_PIN = 0x22
INS_DERIVE_KEY = 0xD1
INS_EXPORT_KEY = 0xC2
INS_SIGN = 0xC0
INS_SET_PINLESS_PATH = 0xC1
INS_LOAD_KEY = 0xD0
INS_GENERATE_MNEMONIC = 0xD2
INS_GET_DATA = 0xCA
INS_STORE_DATA = 0xE2

P1_PAIRING_FIRST_STEP = 0x00
P1_PAIRING_FINAL_STEP = 0x01
P1_GET_STATUS_APPLICATION = 0x00
P1_GET_STATUS_KEY_PATH = 0x01
P1_DERIVE_KEY_FROM_MASTER = 0x00
P1_DERIVE_KEY_FROM_PARENT = 0x40
P1_DERIVE_KEY_FROM_CURRENT = 0x80
P1_CHANGE_PIN_PIN = 0x00
P1_CHANGE_PIN_PUK = 0x01
P1_CHANGE_PIN_PAIRING_SECRET = 0x02
P1_SIGN_CURRENT_KEY = 0x00
P1_SIGN_DERIVE = 0x01
P1_SIGN_DERIVE_AND_MAKE_CURRENT = 0x02
P1_SIGN_PINLESS = 0x03
P1_EXPORT_KEY_CURRENT = 0x00
P1_EXPORT_KEY_DERIVE = 0x01
P1_EXPORT_KEY_DERIVE_AND_MAKE_CURRENT = 0x02
P2_EXPORT_KEY_PRIVATE_AND_PUBLIC = 0x00
P2_EXPORT_KEY_PUBLIC_ONLY = 0x01
P2_EXPORT_KEY_EXTENDED_PUBLIC = 0x02
P1_LOAD_KEY_SEED = 0x03

SW_NO_PAIRING_SLOTS = 0x6A84
SW_WRONG_PIN_MASK = 0x63C0

# ── TLV tags ──────────────────────────────────────────────────────────────────
TAG_APPLICATION_INFO_TEMPLATE = bytes([0xA4])
TAG_PRE_INIT = bytes([0x80])
TAG_APPLICATION_STATUS_TEMPLATE = bytes([0xA3])
TAG_INSTANCE_UID = bytes([0x8F])
TAG_SECURE_CHANNEL_PUB_KEY = bytes([0x80])
TAG_APP_VERSION = bytes([0x02])
TAG_KEY_UID = bytes([0x8E])
TAG_CAPABILITIES = bytes([0x8D])
TAG_PAIRING_INDEX = bytes([0x00])
TAG_SIGNATURE_TEMPLATE = bytes([0xA0])
TAG_RAW_SIGNATURE = bytes([0x80])
TAG_EXPORT_KEY_TEMPLATE = bytes([0xA1])
TAG_EXPORT_KEY_PUBLIC = bytes([0x80])
TAG_EXPORT_KEY_PRIVATE = bytes([0x81])
TAG_EXPORT_KEY_CHAIN_CODE = bytes([0x82])

PAIRING_TOKEN_SALT = "Keycard Pairing Password Salt"

# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_apdu(cla: int, ins: int, p1: int, p2: int,
                data: bytes = b"", le: Optional[int] = None) -> bytes:
    """Serialize a short (Lc ≤ 255) APDU command."""
    buf = bytes([cla, ins, p1, p2])
    if data:
        buf += bytes([len(data)]) + data
    if le is not None:
        buf += bytes([le])
    return buf


def _transmit(session: CardSession, cla: int, ins: int, p1: int, p2: int,
              data: bytes = b"", le: Optional[int] = None) -> APDUResponse:
    cmd = _build_apdu(cla, ins, p1, p2, data, le)
    return session.transmit(cmd)


def _check_ok(resp: APDUResponse) -> None:
    if resp.sw != SW_OK:
        raise RuntimeError(f"unexpected SW: 0x{resp.sw:04x}")


# ── Derivation path ───────────────────────────────────────────────────────────

HARDENED = 0x80000000

_STARTING_MASTER = 1
_STARTING_CURRENT = 2
_STARTING_PARENT = 3


def _decode_path(path_str: str) -> Tuple[int, list]:
    """Decode a BIP32 derivation path string.

    Returns (starting_point, [uint32, ...]) where starting_point is one of
    _STARTING_MASTER / _STARTING_CURRENT / _STARTING_PARENT.
    """
    s = path_str.strip()
    if not s:
        return _STARTING_CURRENT, []

    starting = _STARTING_CURRENT
    if s.startswith("m/"):
        starting = _STARTING_MASTER
        s = s[2:]
    elif s.startswith("../"):
        starting = _STARTING_PARENT
        s = s[3:]
    elif s.startswith("./"):
        starting = _STARTING_CURRENT
        s = s[2:]
    elif s == "m":
        return _STARTING_MASTER, []
    elif s == ".":
        return _STARTING_CURRENT, []
    elif s == "..":
        return _STARTING_PARENT, []

    segments = []
    for part in s.split("/"):
        if not part:
            continue
        hardened = False
        if part.endswith("'"):
            hardened = True
            part = part[:-1]
        idx = int(part)
        if idx >= HARDENED:
            raise ValueError(f"index {idx} exceeds max BIP32 value")
        if hardened:
            idx += HARDENED
        segments.append(idx)
    return starting, segments


def _encode_path(path_str: str) -> Tuple[int, bytes]:
    """Return (p1_start_bits, encoded_path_bytes)."""
    starting, segments = _decode_path(path_str)
    p1_bits = {
        _STARTING_MASTER: P1_DERIVE_KEY_FROM_MASTER,
        _STARTING_CURRENT: P1_DERIVE_KEY_FROM_CURRENT,
        _STARTING_PARENT: P1_DERIVE_KEY_FROM_PARENT,
    }[starting]
    encoded = b"".join(struct.pack(">I", seg) for seg in segments)
    return p1_bits, encoded


# ── Padding (ISO 7816-4) ──────────────────────────────────────────────────────

def _append_padding(data: bytes, block_size: int = 16) -> bytes:
    padding = block_size - (len(data) % block_size)
    return data + bytes([0x80]) + bytes(padding - 1)


def _remove_padding(data: bytes, block_size: int = 16) -> bytes:
    i = len(data) - 1
    while i > len(data) - block_size - 1:
        if data[i] == 0x80:
            return data[:i]
        i -= 1
    return data


# ── CBC-MAC ───────────────────────────────────────────────────────────────────

def _calculate_mac(meta: bytes, data: bytes, mac_key: bytes) -> bytes:
    """Calculate MAC for keycard secure channel.

    meta is exactly 16 bytes; data is the encrypted payload (already block-aligned).
    A 16-byte ISO 7816-4 padding block is appended before MAC computation.
    Returns the new 16-byte IV (last block of the CBC chain).
    """
    padded = _append_padding(data, 16)
    result = AES.new(mac_key, AES.MODE_CBC, iv=bytes(16)).encrypt(meta + padded)
    return result[-16:]


# ── ECDH on secp256k1 ─────────────────────────────────────────────────────────

def _generate_keypair() -> Tuple[bytes, bytes]:
    """Return (private_key_bytes_32, uncompressed_pub_key_bytes_65)."""
    key = ec.generate_private_key(SECP256K1())
    priv = key.private_numbers().private_value.to_bytes(32, "big")
    pub_numbers = key.public_key().public_numbers()
    x = pub_numbers.x.to_bytes(32, "big")
    y = pub_numbers.y.to_bytes(32, "big")
    pub = bytes([0x04]) + x + y
    return priv, pub


def _ecdh_shared_secret(priv_bytes: bytes, card_pub_bytes: bytes) -> bytes:
    """Compute ECDH shared secret (x-coordinate) given raw private and uncompressed public keys."""
    assert card_pub_bytes[0] == 0x04 and len(card_pub_bytes) == 65
    priv_int = int.from_bytes(priv_bytes, "big")
    x = int.from_bytes(card_pub_bytes[1:33], "big")
    y = int.from_bytes(card_pub_bytes[33:65], "big")

    priv_key = ec.derive_private_key(priv_int, SECP256K1())
    card_pub = EllipticCurvePublicNumbers(x, y, SECP256K1()).public_key()
    # ECDH returns the raw x-coordinate as bytes
    return priv_key.exchange(ECDH(), card_pub)


def _derive_session_keys(secret: bytes, pairing_key: bytes,
                         card_data: bytes) -> Tuple[bytes, bytes, bytes]:
    """Derive (enc_key, mac_key, iv) from the shared secret and pairing key."""
    salt = card_data[:32]
    iv = card_data[32:]
    h = SHA512.new()
    h.update(secret + pairing_key + salt)
    digest = h.digest()
    return digest[:32], digest[32:], iv


# ── ApplicationInfo ───────────────────────────────────────────────────────────

@dataclass
class ApplicationInfo:
    installed: bool = False
    initialized: bool = False
    instance_uid: bytes = b""
    secure_channel_pub_key: bytes = b""
    version: bytes = b""
    available_slots: bytes = b""
    key_uid: bytes = b""
    capabilities: int = 0

    CAP_SECURE_CHANNEL: int = field(default=1, init=False, repr=False)
    CAP_KEY_MANAGEMENT: int = field(default=2, init=False, repr=False)
    CAP_CREDENTIALS_MANAGEMENT: int = field(default=4, init=False, repr=False)
    CAP_NDEF: int = field(default=8, init=False, repr=False)
    CAP_FACTORY_RESET: int = field(default=16, init=False, repr=False)

    def has_secure_channel(self) -> bool:
        return bool(self.capabilities & 1)

    def has_key_management(self) -> bool:
        return bool(self.capabilities & 2)

    def has_credentials_management(self) -> bool:
        return bool(self.capabilities & 4)

    def has_ndef(self) -> bool:
        return bool(self.capabilities & 8)


def _parse_application_info(data: bytes) -> ApplicationInfo:
    info = ApplicationInfo(installed=True)
    if not data:
        return info

    # Pre-initialized (not yet init'd): tag 0x80
    if data[0] == 0x80:
        info.secure_channel_pub_key = data[2:]  # skip tag + length
        info.capabilities = 4  # credentials management
        if info.secure_channel_pub_key:
            info.capabilities |= 1  # + secure channel
        return info

    # Initialized: tag 0xA4 template
    if data[0] != 0xA4:
        raise ValueError(f"unexpected application info tag: 0x{data[0]:02x}")

    info.initialized = True
    tpl = try_find_tag(data, TAG_APPLICATION_INFO_TEMPLATE)
    info.instance_uid = try_find_tag(tpl, TAG_INSTANCE_UID)
    info.secure_channel_pub_key = try_find_tag(tpl, TAG_SECURE_CHANNEL_PUB_KEY)
    info.version = try_find_tag(tpl, TAG_APP_VERSION)
    try:
        info.available_slots = find_tag_n(tpl, 1, TAG_APP_VERSION)
    except (TagNotFoundError, ValueError):
        info.available_slots = b""
    info.key_uid = try_find_tag(tpl, TAG_KEY_UID)
    cap_bytes = try_find_tag(data, TAG_CAPABILITIES)
    info.capabilities = cap_bytes[0] if cap_bytes else 0x1F  # all capabilities
    return info


# ── ApplicationStatus ─────────────────────────────────────────────────────────

@dataclass
class ApplicationStatus:
    pin_retry_count: int = 0
    puk_retry_count: int = 0
    key_initialized: bool = False
    path: str = ""


def _parse_application_status(data: bytes) -> ApplicationStatus:
    status = ApplicationStatus()
    try:
        tpl = find_tag(data, TAG_APPLICATION_STATUS_TEMPLATE)
    except (TagNotFoundError, ValueError):
        # key path status
        status.path = _decode_path_bytes(data)
        return status

    pin = try_find_tag(tpl, bytes([0x02]))
    if pin:
        status.pin_retry_count = pin[0]
    try:
        puk2 = find_tag_n(tpl, 1, bytes([0x02]))
        status.puk_retry_count = puk2[0]
    except (TagNotFoundError, ValueError):
        pass
    key_init = try_find_tag(tpl, bytes([0x01]))
    status.key_initialized = key_init == bytes([0xFF])
    return status


def _decode_path_bytes(data: bytes) -> str:
    if not data:
        return ""
    segments = []
    for i in range(0, len(data), 4):
        val = struct.unpack(">I", data[i:i + 4])[0]
        if val >= HARDENED:
            segments.append(f"{val - HARDENED}'")
        else:
            segments.append(str(val))
    return "m/" + "/".join(segments) if segments else "m"


# ── ExportedKey ───────────────────────────────────────────────────────────────

@dataclass
class ExportedKey:
    pub_key: bytes = b""
    priv_key: bytes = b""
    chain_code: bytes = b""


def _parse_exported_key(data: bytes) -> ExportedKey:
    tpl = try_find_tag(data, TAG_EXPORT_KEY_TEMPLATE)
    if not tpl:
        raise ValueError("no exported key template in response")
    pub = try_find_tag(tpl, TAG_EXPORT_KEY_PUBLIC)
    priv = try_find_tag(tpl, TAG_EXPORT_KEY_PRIVATE)
    chain = try_find_tag(tpl, TAG_EXPORT_KEY_CHAIN_CODE)

    if not pub and priv:
        # Derive public key from private key using secp256k1 scalar multiplication
        priv_int = int.from_bytes(priv, "big")
        point = _secp256k1_point_mul(priv_int, (_SECP256K1_Gx, _SECP256K1_Gy))
        if point is None:
            raise ValueError("invalid private key: multiplication yielded point at infinity")
        x = point[0].to_bytes(32, "big")
        y = point[1].to_bytes(32, "big")
        pub = bytes([0x04]) + x + y

    return ExportedKey(pub_key=pub, priv_key=priv, chain_code=chain)


# ── Signature ─────────────────────────────────────────────────────────────────

@dataclass
class Signature:
    pub_key: bytes
    r: bytes
    s: bytes
    v: int


def _keccak256(data: bytes) -> bytes:
    from Cryptodome.Hash import keccak as _keccak
    d = _keccak.new(digest_bits=256)
    d.update(data)
    return d.digest()


def _ec_recover(message_hash: bytes, sig65: bytes) -> bytes:
    """Recover uncompressed public key from a 65-byte recoverable secp256k1 signature."""
    r = int.from_bytes(sig65[:32], "big")
    s = int.from_bytes(sig65[32:64], "big")
    v = sig65[64]

    p = _SECP256K1_P
    n = _SECP256K1_N
    G = (_SECP256K1_Gx, _SECP256K1_Gy)

    # Recover R from (r, v): x = r + floor(v/2) * n
    x = r + (v // 2) * n
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if (y % 2) != (v % 2):
        y = p - y
    R = (x, y)

    # Q = r^-1 * (s*R - hash*G)
    r_inv = pow(r, n - 2, n)  # modular inverse via Fermat (n is prime)
    hash_int = int.from_bytes(message_hash, "big")

    sR = _secp256k1_point_mul(s, R)
    hG = _secp256k1_point_mul(hash_int, G)
    hG_neg = (hG[0], (p - hG[1]) % p)
    Q = _secp256k1_point_mul(r_inv, _secp256k1_point_add(sR, hG_neg))

    if Q is None:
        raise ValueError("recovered point at infinity")
    qx = Q[0].to_bytes(32, "big")
    qy = Q[1].to_bytes(32, "big")
    return bytes([0x04]) + qx + qy


def _parse_signature(message_hash: bytes, data: bytes) -> Signature:
    # Try new format: tag 0x80 → raw 65-byte recoverable signature
    raw = try_find_tag(data, TAG_RAW_SIGNATURE)
    if raw and len(raw) == 65:
        try:
            pub = _ec_recover(message_hash, raw)
            return Signature(pub_key=pub, r=raw[:32], s=raw[32:64], v=raw[64])
        except Exception:
            pass

    # Legacy format: 0xA0 template with DER signature + public key
    tpl = try_find_tag(data, TAG_SIGNATURE_TEMPLATE)
    if not tpl:
        raise ValueError("no signature in response")

    pub = try_find_tag(tpl, bytes([0x80]))
    # Parse DER r, s
    r = try_find_tag(tpl, bytes([0x30]), bytes([0x02]))
    s = try_find_tag(tpl, bytes([0x30]))  # second 0x02 inside 0x30
    try:
        s = find_tag_n(tpl, 1, bytes([0x30]), bytes([0x02]))
    except (TagNotFoundError, ValueError):
        pass

    if len(r) > 32:
        r = r[len(r) - 32:]
    if len(s) > 32:
        s = s[len(s) - 32:]

    # Calculate v
    rs = r + s
    v = 0
    for i in range(4):
        try:
            recovered = _ec_recover(message_hash, rs + bytes([i]))
            if recovered == pub or (len(pub) == 33 and _compress_pub(recovered) == pub):
                v = i
                break
        except Exception:
            continue

    return Signature(pub_key=pub, r=r, s=s, v=v)


def _compress_pub(pub: bytes) -> bytes:
    if len(pub) == 33:
        return pub
    y = pub[64]
    prefix = bytes([3 if y & 1 else 2])
    return prefix + pub[1:33]


# ── PairingInfo ───────────────────────────────────────────────────────────────

@dataclass
class PairingInfo:
    key: bytes
    index: int


# ── SecureChannel ─────────────────────────────────────────────────────────────

class SecureChannel:
    """Keycard secure channel – mirrors keycard-go/secure_channel.go."""

    def __init__(self, session: CardSession) -> None:
        self._session = session
        self._open = False
        self._priv_key: bytes = b""
        self._pub_key: bytes = b""
        self._secret: bytes = b""
        self._enc_key: bytes = b""
        self._mac_key: bytes = b""
        self._iv: bytes = b""

    def generate_secret(self, card_pub_key: bytes) -> None:
        self._priv_key, self._pub_key = _generate_keypair()
        self._secret = _ecdh_shared_secret(self._priv_key, card_pub_key)

    def reset(self) -> None:
        self._open = False

    def init(self, iv: bytes, enc_key: bytes, mac_key: bytes) -> None:
        self._iv = iv
        self._enc_key = enc_key
        self._mac_key = mac_key
        self._open = True

    @property
    def secret(self) -> bytes:
        return self._secret

    @property
    def pub_key(self) -> bytes:
        return self._pub_key

    def send(self, cla: int, ins: int, p1: int, p2: int,
             data: bytes = b"", le: Optional[int] = None) -> APDUResponse:
        if self._open:
            enc_data = self._encrypt(data)
            meta = bytes([cla, ins, p1, p2, len(enc_data) + 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            self._update_iv(meta, enc_data)
            payload = self._iv + enc_data
            raw = _build_apdu(cla, ins, p1, p2, payload, le)
        else:
            raw = _build_apdu(cla, ins, p1, p2, data, le)

        resp = self._session.transmit(raw)

        if self._open:
            if resp.sw != SW_OK:
                raise RuntimeError(f"secure channel error: SW 0x{resp.sw:04x}")
            rmeta = bytes([len(resp.data)]) + bytes(15)
            rmac = resp.data[:16]
            rdata = resp.data[16:]
            plain = self._decrypt(rdata)
            self._update_iv(rmeta, rdata)
            if self._iv != rmac:
                raise RuntimeError("invalid response MAC in secure channel")
            # Parse the decrypted plain response
            sw = (plain[-2] << 8) | plain[-1]
            return APDUResponse(plain[:-2], sw)

        return resp

    def _encrypt(self, data: bytes) -> bytes:
        padded = _append_padding(data, 16)
        cipher = AES.new(self._enc_key, AES.MODE_CBC, iv=self._iv)
        return cipher.encrypt(padded)

    def _decrypt(self, data: bytes) -> bytes:
        cipher = AES.new(self._enc_key, AES.MODE_CBC, iv=self._iv)
        plain = cipher.decrypt(data)
        return _remove_padding(plain, 16)

    def _update_iv(self, meta: bytes, data: bytes) -> None:
        self._iv = _calculate_mac(meta, data, self._mac_key)

    def one_shot_encrypt(self, pin: str, puk: str, pairing_token: bytes) -> bytes:
        """Encrypt init secrets with card's public key for the INIT command."""
        plaintext = pin.encode() + puk.encode() + pairing_token
        plaintext = _append_padding(plaintext, 16)
        iv = os.urandom(16)
        cipher = AES.new(self._secret, AES.MODE_CBC, iv=iv)
        ciphertext = cipher.encrypt(plaintext)
        pub = self._pub_key
        return bytes([len(pub)]) + pub + iv + ciphertext


# ── CommandSet ────────────────────────────────────────────────────────────────

class WrongPINError(Exception):
    def __init__(self, remaining: int) -> None:
        super().__init__(f"wrong PIN ({remaining} attempts remaining)")
        self.remaining = remaining


class KeycardCommandSet:
    """High-level keycard command set, mirroring keycard-go CommandSet."""

    def __init__(self, session: CardSession) -> None:
        self._session = session
        self._sc = SecureChannel(session)
        self.application_info: Optional[ApplicationInfo] = None
        self.pairing_info: Optional[PairingInfo] = None

    def set_pairing_info(self, key: bytes, index: int) -> None:
        self.pairing_info = PairingInfo(key=key, index=index)

    # ── SELECT ────────────────────────────────────────────────────────────────

    def select(self) -> ApplicationInfo:
        resp = _transmit(self._session, CLA_ISO, INS_SELECT, 0x04, 0x00,
                         KEYCARD_INSTANCE_AID, le=0)
        _check_ok(resp)
        info = _parse_application_info(resp.data)
        self.application_info = info
        if info.has_secure_channel() and info.secure_channel_pub_key:
            self._sc.generate_secret(info.secure_channel_pub_key)
            self._sc.reset()
        return info

    # ── PAIR ──────────────────────────────────────────────────────────────────

    def pair(self, pairing_pass: str) -> PairingInfo:
        challenge = os.urandom(32)
        resp = _transmit(self._session, CLA_GP, INS_PAIR, P1_PAIRING_FIRST_STEP, 0, challenge)
        if resp.sw == SW_NO_PAIRING_SLOTS:
            raise RuntimeError("no available pairing slots")
        _check_ok(resp)

        card_cryptogram = resp.data[:32]
        card_challenge = resp.data[32:]
        secret_hash = _verify_cryptogram(challenge, pairing_pass, card_cryptogram)

        h = SHA256.new()
        h.update(secret_hash + card_challenge)
        resp2 = _transmit(self._session, CLA_GP, INS_PAIR, P1_PAIRING_FINAL_STEP, 0, h.digest())
        _check_ok(resp2)

        h2 = SHA256.new()
        h2.update(secret_hash + resp2.data[1:])
        pairing_key = h2.digest()
        pairing_index = resp2.data[0]
        self.pairing_info = PairingInfo(key=pairing_key, index=pairing_index)
        return self.pairing_info

    def unpair(self, index: int) -> None:
        resp = self._sc.send(CLA_GP, INS_UNPAIR, index, 0)
        _check_ok(resp)

    # ── OPEN SECURE CHANNEL ───────────────────────────────────────────────────

    def open_secure_channel(self) -> None:
        if self.pairing_info is None:
            raise RuntimeError("pairing info required before opening secure channel")
        resp = _transmit(self._session, CLA_GP, INS_OPEN_SECURE_CHANNEL,
                         self.pairing_info.index, 0, self._sc.pub_key)
        _check_ok(resp)
        enc_key, mac_key, iv = _derive_session_keys(
            self._sc.secret, self.pairing_info.key, resp.data)
        self._sc.init(iv, enc_key, mac_key)
        self._mutually_authenticate()

    def _mutually_authenticate(self) -> None:
        data = os.urandom(32)
        resp = self._sc.send(CLA_GP, INS_MUTUALLY_AUTHENTICATE, 0, 0, data)
        _check_ok(resp)

    # ── INIT ──────────────────────────────────────────────────────────────────

    def init(self, pin: str, puk: str, pairing_pass: str) -> None:
        """Initialize an uninitialized keycard with the given secrets."""
        # Derive pairing token from pairing_pass
        pairing_token = _derive_pairing_token(pairing_pass)
        encrypted = self._sc.one_shot_encrypt(pin, puk, pairing_token)
        resp = _transmit(self._session, CLA_GP, INS_INIT, 0, 0, encrypted)
        _check_ok(resp)

    # ── GET STATUS ────────────────────────────────────────────────────────────

    def get_status_application(self) -> ApplicationStatus:
        resp = self._sc.send(CLA_GP, INS_GET_STATUS, P1_GET_STATUS_APPLICATION, 0)
        _check_ok(resp)
        return _parse_application_status(resp.data)

    def get_status_key_path(self) -> ApplicationStatus:
        resp = self._sc.send(CLA_GP, INS_GET_STATUS, P1_GET_STATUS_KEY_PATH, 0)
        _check_ok(resp)
        return _parse_application_status(resp.data)

    # ── PIN MANAGEMENT ────────────────────────────────────────────────────────

    def verify_pin(self, pin: str) -> None:
        resp = self._sc.send(CLA_GP, INS_VERIFY_PIN, 0, 0, pin.encode())
        if (resp.sw & SW_WRONG_PIN_MASK) == SW_WRONG_PIN_MASK:
            remaining = resp.sw & 0x000F
            raise WrongPINError(remaining)
        _check_ok(resp)

    def change_pin(self, pin: str) -> None:
        resp = self._sc.send(CLA_GP, INS_CHANGE_PIN, P1_CHANGE_PIN_PIN, 0, pin.encode())
        _check_ok(resp)

    def change_puk(self, puk: str) -> None:
        resp = self._sc.send(CLA_GP, INS_CHANGE_PIN, P1_CHANGE_PIN_PUK, 0, puk.encode())
        _check_ok(resp)

    def change_pairing_secret(self, pairing_pass: str) -> None:
        pairing_token = _derive_pairing_token(pairing_pass)
        resp = self._sc.send(CLA_GP, INS_CHANGE_PIN, P1_CHANGE_PIN_PAIRING_SECRET, 0, pairing_token)
        _check_ok(resp)

    def unblock_pin(self, puk: str, new_pin: str) -> None:
        data = (puk + new_pin).encode()
        resp = self._sc.send(CLA_GP, INS_UNBLOCK_PIN, 0, 0, data)
        _check_ok(resp)

    # ── KEY MANAGEMENT ────────────────────────────────────────────────────────

    def generate_key(self) -> bytes:
        """Generate a new key on the card; returns key UID."""
        resp = self._sc.send(CLA_GP, INS_GENERATE_KEY, 0, 0)
        _check_ok(resp)
        return resp.data

    def remove_key(self) -> None:
        resp = self._sc.send(CLA_GP, INS_REMOVE_KEY, 0, 0)
        _check_ok(resp)

    def derive_key(self, path: str) -> None:
        p1_bits, encoded = _encode_path(path)
        resp = self._sc.send(CLA_GP, INS_DERIVE_KEY, p1_bits, 0, encoded)
        _check_ok(resp)

    def load_seed(self, seed: bytes) -> bytes:
        resp = self._sc.send(CLA_GP, INS_LOAD_KEY, P1_LOAD_KEY_SEED, 0, seed)
        _check_ok(resp)
        return resp.data

    def generate_mnemonic(self, checksum_size: int) -> list:
        """Generate mnemonic indexes (checksum_size ∈ {4,5,6,7,8})."""
        resp = self._sc.send(CLA_GP, INS_GENERATE_MNEMONIC, checksum_size, 0)
        _check_ok(resp)
        indexes = []
        for i in range(0, len(resp.data), 2):
            indexes.append(struct.unpack(">H", resp.data[i:i + 2])[0])
        return indexes

    # ── KEY EXPORT ────────────────────────────────────────────────────────────

    def export_key(self, path: str, make_current: bool = False,
                   only_public: bool = True) -> ExportedKey:
        p2 = P2_EXPORT_KEY_PUBLIC_ONLY if only_public else P2_EXPORT_KEY_PRIVATE_AND_PUBLIC
        p1_bits, encoded = _encode_path(path)
        if make_current:
            p1_bits |= P1_EXPORT_KEY_DERIVE_AND_MAKE_CURRENT
        elif encoded:
            p1_bits |= P1_EXPORT_KEY_DERIVE
        else:
            p1_bits = P1_EXPORT_KEY_CURRENT
        resp = self._sc.send(CLA_GP, INS_EXPORT_KEY, p1_bits, p2, encoded)
        _check_ok(resp)
        return _parse_exported_key(resp.data)

    def export_key_extended(self, path: str, make_current: bool = False) -> ExportedKey:
        """Export key with chain code (for xpub generation)."""
        p1_bits, encoded = _encode_path(path)
        if make_current:
            p1_bits |= P1_EXPORT_KEY_DERIVE_AND_MAKE_CURRENT
        elif encoded:
            p1_bits |= P1_EXPORT_KEY_DERIVE
        else:
            p1_bits = P1_EXPORT_KEY_CURRENT
        resp = self._sc.send(CLA_GP, INS_EXPORT_KEY, p1_bits,
                             P2_EXPORT_KEY_EXTENDED_PUBLIC, encoded)
        _check_ok(resp)
        return _parse_exported_key(resp.data)

    # ── SIGN ──────────────────────────────────────────────────────────────────

    def sign(self, data: bytes) -> Signature:
        if len(data) != 32:
            raise ValueError("data must be 32 bytes")
        resp = self._sc.send(CLA_GP, INS_SIGN, P1_SIGN_CURRENT_KEY, 1, data)
        _check_ok(resp)
        return _parse_signature(data, resp.data)

    def sign_with_path(self, data: bytes, path: str) -> Signature:
        if len(data) != 32:
            raise ValueError("data must be 32 bytes")
        _, encoded_path = _encode_path(path)
        resp = self._sc.send(CLA_GP, INS_SIGN, P1_SIGN_DERIVE, 1,
                             data + encoded_path)
        _check_ok(resp)
        return _parse_signature(data, resp.data)

    def sign_pinless(self, data: bytes) -> Signature:
        if len(data) != 32:
            raise ValueError("data must be 32 bytes")
        resp = self._sc.send(CLA_GP, INS_SIGN, P1_SIGN_PINLESS, 1, data)
        _check_ok(resp)
        return _parse_signature(data, resp.data)

    def set_pinless_path(self, path: str) -> None:
        p1_bits, encoded = _encode_path(path)
        resp = self._sc.send(CLA_GP, INS_SET_PINLESS_PATH, 0, 0, encoded)
        _check_ok(resp)

    # ── IDENTIFY ──────────────────────────────────────────────────────────────

    def identify(self) -> bytes:
        """Return card's uncompressed public key for identity verification."""
        challenge = os.urandom(32)
        resp = _transmit(self._session, CLA_GP, INS_IDENTIFY, 0, 0, challenge)
        _check_ok(resp)
        # Response: sig (64) + pub key; or sig template
        return _parse_identification(challenge, resp.data)


def _parse_identification(challenge: bytes, data: bytes) -> bytes:
    """Extract and verify the card identity public key from an IDENTIFY response."""
    # Expect TLV 0x80 = 64-byte raw signature, 0x81 = public key
    sig = try_find_tag(data, bytes([0x80]))
    pub = try_find_tag(data, bytes([0x81]))
    if not sig or not pub:
        raise ValueError("invalid IDENTIFY response")
    # Verify signature over challenge
    h = _keccak256(challenge)
    recovered = _ec_recover(h, sig + bytes([0]) if len(sig) == 64 else sig)
    if recovered != pub and _compress_pub(recovered) != pub:
        # Try v=1
        recovered = _ec_recover(h, sig[:64] + bytes([1]))
        if recovered != pub and _compress_pub(recovered) != pub:
            raise RuntimeError("identification failed: recovered key mismatch")
    return pub


# ── Cash CommandSet ───────────────────────────────────────────────────────────

@dataclass
class CashApplicationInfo:
    installed: bool = False
    pub_key: bytes = b""
    pub_data: bytes = b""
    version: bytes = b""


class CashCommandSet:
    def __init__(self, session: CardSession) -> None:
        self._session = session
        self.info: Optional[CashApplicationInfo] = None

    def select(self) -> CashApplicationInfo:
        resp = _transmit(self._session, CLA_ISO, INS_SELECT, 0x04, 0x00,
                         CASH_INSTANCE_AID, le=0)
        if resp.sw == 0x6A82:
            self.info = CashApplicationInfo(installed=False)
            return self.info
        _check_ok(resp)
        info = CashApplicationInfo(installed=True)
        # Parse cash response (simple TLV)
        info.pub_key = try_find_tag(resp.data, bytes([0x80]))
        info.pub_data = try_find_tag(resp.data, bytes([0x81]))
        info.version = try_find_tag(resp.data, bytes([0x02]))
        self.info = info
        return info

    def sign(self, data: bytes) -> Signature:
        if len(data) != 32:
            raise ValueError("data must be 32 bytes")
        resp = _transmit(self._session, CLA_GP, INS_SIGN, P1_SIGN_CURRENT_KEY, 1, data)
        _check_ok(resp)
        return _parse_signature(data, resp.data)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _derive_pairing_token(pairing_pass: str) -> bytes:
    import unicodedata
    normalized = unicodedata.normalize("NFKD", pairing_pass).encode("utf-8")
    salt = unicodedata.normalize("NFKD", PAIRING_TOKEN_SALT).encode("utf-8")
    return PBKDF2(normalized, salt, dkLen=32, count=50000, prf=lambda p, s: HMAC.new(p, s, SHA256).digest())


def _verify_cryptogram(challenge: bytes, pairing_pass: str, card_cryptogram: bytes) -> bytes:
    """Verify card cryptogram and return the secret hash."""
    secret_hash = _derive_pairing_token(pairing_pass)
    h = SHA256.new()
    h.update(secret_hash + challenge)
    expected = h.digest()
    if expected != card_cryptogram:
        raise RuntimeError("invalid card cryptogram")
    return secret_hash


def eth_address_from_pub(pub_key: bytes) -> str:
    """Derive an Ethereum address (checksummed) from an uncompressed public key."""
    # Remove 0x04 prefix if present
    if pub_key[0] == 0x04:
        pub_key = pub_key[1:]
    digest = _keccak256(pub_key)
    addr = digest[-20:]
    return _checksum_address(addr)


def _checksum_address(addr: bytes) -> str:
    hex_addr = addr.hex().lower()
    checksum_hash = _keccak256(hex_addr.encode()).hex()
    result = "0x"
    for i, c in enumerate(hex_addr):
        result += c.upper() if int(checksum_hash[i], 16) >= 8 else c
    return result
