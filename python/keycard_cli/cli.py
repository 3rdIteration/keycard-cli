from __future__ import annotations

import argparse
import json
import logging
import shlex
import sys
from typing import Callable

from .apdu import SW_OK, decode_hex_command, sw_to_hex
from .bip32 import serialize_xpub
from .card import CardSession, connect_to_card
from .crypto import hash_ethereum_message
from .eth_tx import encode_signed_transaction, hash_transaction
from .keycard_proto import (
    CashCommandSet,
    KeycardCommandSet,
    P2_PAIRING_ANY,
    P2_PAIRING_EPHEMERAL,
    P2_PAIRING_PERSISTENT,
    WrongPINError,
    eth_address_from_pub,
)

VERSION = "dev"

KEYCARD_INSTANCE_AID = bytes.fromhex("A00000080400010101")
CASH_INSTANCE_AID = bytes.fromhex("A00000080400010301")
ISD_AID = bytes.fromhex("A000000151000000")


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )


def _select_aid(session: CardSession, aid: bytes):
    command = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
    return session.transmit(command)


def _parse_hex(value: str) -> bytes:
    return decode_hex_command(value)


def _print_signature(sig) -> None:
    eth_sig = sig.r + sig.s + bytes([sig.v + 27])
    print(f"SIGNATURE R: {sig.r.hex()}")
    print(f"SIGNATURE S: {sig.s.hex()}")
    print(f"SIGNATURE V: {sig.v:x}")
    print(f"ETH SIGNATURE: 0x{eth_sig.hex()}")
    print(f"PUBLIC KEY: 0x{sig.pub_key.hex()}")
    print(f"ADDRESS: {eth_address_from_pub(sig.pub_key)}")
    print()


def cmd_version(_: argparse.Namespace) -> int:
    print(f"version {VERSION}")
    return 0


def cmd_info(_: argparse.Namespace) -> int:
    session = connect_to_card()
    try:
        keycard_resp = _select_aid(session, KEYCARD_INSTANCE_AID)
        cash_resp = _select_aid(session, CASH_INSTANCE_AID)

        print("Keycard Applet:")
        print(f"  Installed: {keycard_resp.ok}")
        print(f"  SW: {sw_to_hex(keycard_resp.sw)}")
        print(f"  Response: 0x{keycard_resp.data.hex()}")
        print("Cash Applet:")
        print(f"  Installed: {cash_resp.ok}")
        print(f"  SW: {sw_to_hex(cash_resp.sw)}")
        print(f"  Response: 0x{cash_resp.data.hex()}")
        return 0
    finally:
        session.disconnect()


def _not_implemented(name: str) -> Callable[[argparse.Namespace], int]:
    def _cmd(_: argparse.Namespace) -> int:
        raise NotImplementedError(
            f"'{name}' is not ported yet in the Python implementation"
        )

    return _cmd


class Shell:
    """Interactive shell mirroring all keycard-go shell commands."""

    def __init__(self, session: CardSession) -> None:
        self.session = session
        self._kcs = KeycardCommandSet(session)
        self._cash = CashCommandSet(session)
        self.commands: dict[str, Callable[[list[str]], None]] = {
            "echo": self._echo,
            "gp-send-apdu": self._gp_send_apdu,
            "gp-select": self._gp_select,
            "keycard-init": self._keycard_init,
            "keycard-select": self._keycard_select,
            "keycard-pair": self._keycard_pair,
            "keycard-unpair": self._keycard_unpair,
            "keycard-open-secure-channel": self._keycard_open_secure_channel,
            "keycard-get-status": self._keycard_get_status,
            "keycard-set-secrets": self._keycard_set_secrets,
            "keycard-set-pairing": self._keycard_set_pairing,
            "keycard-verify-pin": self._keycard_verify_pin,
            "keycard-change-pin": self._keycard_change_pin,
            "keycard-change-puk": self._keycard_change_puk,
            "keycard-unblock-pin": self._keycard_unblock_pin,
            "keycard-change-pairing-secret": self._keycard_change_pairing_secret,
            "keycard-generate-key": self._keycard_generate_key,
            "keycard-remove-key": self._keycard_remove_key,
            "keycard-derive-key": self._keycard_derive_key,
            "keycard-export-key-private": self._keycard_export_key_private,
            "keycard-export-key-public": self._keycard_export_key_public,
            "keycard-export-xpub": self._keycard_export_xpub,
            "keycard-sign": self._keycard_sign,
            "keycard-sign-with-path": self._keycard_sign_with_path,
            "keycard-sign-message": self._keycard_sign_message,
            "keycard-sign-pinless": self._keycard_sign_pinless,
            "keycard-sign-message-pinless": self._keycard_sign_message_pinless,
            "keycard-sign-tx": self._keycard_sign_tx,
            "keycard-set-pinless-path": self._keycard_set_pinless_path,
            "keycard-load-seed": self._keycard_load_seed,
            "keycard-generate-mnemonic": self._keycard_generate_mnemonic,
            "keycard-identify": self._keycard_identify,
            "cash-select": self._cash_select,
            "cash-sign": self._cash_sign,
        }
        # Per-session PIN/PUK/pairing password storage for convenience
        self._pin: str = ""
        self._puk: str = ""
        self._pairing_pass: str = ""

    def run(self) -> int:
        for line in sys.stdin:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            parts = shlex.split(text)
            command_name, args = parts[0], parts[1:]
            command = self.commands.get(command_name)
            if command is None:
                raise ValueError(f"command not found: {command_name}")
            command(args)
        return 0

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _require_args(self, args: list[str], *allowed_counts: int) -> None:
        if len(args) not in allowed_counts:
            counts = " | ".join(str(n) for n in allowed_counts)
            raise ValueError(
                f"wrong number of arguments: got {len(args)}, expected {counts}"
            )

    # ── Global platform ───────────────────────────────────────────────────────

    def _echo(self, args: list[str]) -> None:
        print("> " + " ".join(args))

    def _gp_send_apdu(self, args: list[str]) -> None:
        self._require_args(args, 1)
        response = self.session.transmit(decode_hex_command(args[0]))
        print(f"SW {sw_to_hex(response.sw)}")
        print(f"DATA 0x{response.data.hex()}")
        if response.sw != SW_OK:
            raise RuntimeError(f"unexpected response sw={sw_to_hex(response.sw)}")

    def _gp_select(self, args: list[str]) -> None:
        self._require_args(args, 0, 1)
        aid = ISD_AID if not args else decode_hex_command(args[0])
        response = _select_aid(self.session, aid)
        print(f"SW {sw_to_hex(response.sw)}")
        print(f"DATA 0x{response.data.hex()}")

    # ── Keycard commands ──────────────────────────────────────────────────────

    def _keycard_select(self, args: list[str]) -> None:
        self._require_args(args, 0)
        info = self._kcs.select()
        key_initialized = bool(info.key_uid)
        print(f"Installed: {info.installed}")
        print(f"Initialized: {info.initialized}")
        print(f"Key Initialized: {key_initialized}")
        print(f"InstanceUID: {info.instance_uid.hex()}")
        print(f"SecureChannelPublicKey: {info.secure_channel_pub_key.hex()}")
        print(f"Version: {info.version.hex()}")
        print(f"AvailableSlots: {info.available_slots.hex()}")
        print(f"KeyUID: {info.key_uid.hex()}")
        print("Capabilities:")
        print(f"  Secure channel: {info.has_secure_channel()}")
        print(f"  Key management: {info.has_key_management()}")
        print(f"  Credentials Management: {info.has_credentials_management()}")
        print(f"  NDEF: {info.has_ndef()}")
        print()

    def _keycard_init(self, args: list[str]) -> None:
        self._require_args(args, 0)
        if not self._pin:
            import secrets as _secrets
            import string
            self._pin = "".join(_secrets.choice(string.digits) for _ in range(6))
            self._puk = "".join(_secrets.choice(string.digits) for _ in range(12))
            chars = string.ascii_letters + string.digits
            self._pairing_pass = "".join(_secrets.choice(chars) for _ in range(20))
        self._kcs.init(self._pin, self._puk, self._pairing_pass)
        print(f"PIN: {self._pin}")
        print(f"PUK: {self._puk}")
        print(f"PAIRING PASSWORD: {self._pairing_pass}")
        print()

    def _keycard_set_secrets(self, args: list[str]) -> None:
        self._require_args(args, 3)
        self._pin, self._puk, self._pairing_pass = args[0], args[1], args[2]

    def _keycard_pair(self, args: list[str]) -> None:
        self._require_args(args, 0, 1)
        if not self._pairing_pass:
            raise ValueError("pairing password not set; use keycard-set-secrets first")

        pair_mode = P2_PAIRING_EPHEMERAL
        if len(args) == 1:
            mode = args[0].strip().lower()
            mode_map = {
                "ephemeral": P2_PAIRING_EPHEMERAL,
                "persistent": P2_PAIRING_PERSISTENT,
                "any": P2_PAIRING_ANY,
            }
            if mode not in mode_map:
                raise ValueError("pair mode must be one of: ephemeral, persistent, any")
            pair_mode = mode_map[mode]

        info = self._kcs.pair(self._pairing_pass, pair_mode=pair_mode)
        print(f"PAIRING KEY: {info.key.hex()}")
        print(f"PAIRING INDEX: {info.index}")
        print()

    def _keycard_unpair(self, args: list[str]) -> None:
        self._require_args(args, 1)
        self._kcs.unpair(int(args[0]))
        print("UNPAIRED")
        print()

    def _keycard_set_pairing(self, args: list[str]) -> None:
        self._require_args(args, 2)
        key = _parse_hex(args[0])
        index = int(args[1])
        self._kcs.set_pairing_info(key, index)

    def _keycard_open_secure_channel(self, args: list[str]) -> None:
        self._require_args(args, 0)
        self._kcs.open_secure_channel()

    def _keycard_get_status(self, args: list[str]) -> None:
        self._require_args(args, 0)
        app_status = self._kcs.get_status_application()
        key_status = self._kcs.get_status_key_path()
        print(f"STATUS - PIN RETRY COUNT: {app_status.pin_retry_count}")
        print(f"STATUS - PUK RETRY COUNT: {app_status.puk_retry_count}")
        print(f"STATUS - KEY INITIALIZED: {app_status.key_initialized}")
        print(f"STATUS - KEY PATH: {key_status.path}")
        print()

    def _keycard_verify_pin(self, args: list[str]) -> None:
        self._require_args(args, 1)
        self._kcs.verify_pin(args[0])

    def _keycard_change_pin(self, args: list[str]) -> None:
        self._require_args(args, 1)
        self._kcs.change_pin(args[0])

    def _keycard_change_puk(self, args: list[str]) -> None:
        self._require_args(args, 1)
        self._kcs.change_puk(args[0])

    def _keycard_unblock_pin(self, args: list[str]) -> None:
        self._require_args(args, 2)
        self._kcs.unblock_pin(args[0], args[1])

    def _keycard_change_pairing_secret(self, args: list[str]) -> None:
        self._require_args(args, 1)
        self._kcs.change_pairing_secret(args[0])

    def _keycard_generate_key(self, args: list[str]) -> None:
        self._require_args(args, 0)
        app_status = self._kcs.get_status_application()
        if app_status.key_initialized:
            raise RuntimeError(
                "key already generated; delete it before creating a new one"
            )
        key_uid = self._kcs.generate_key()
        print(f"KEY UID {key_uid.hex()}")
        print()

    def _keycard_remove_key(self, args: list[str]) -> None:
        self._require_args(args, 0)
        self._kcs.remove_key()
        print("KEY REMOVED")
        print()

    def _keycard_derive_key(self, args: list[str]) -> None:
        self._require_args(args, 1)
        self._kcs.derive_key(args[0])

    def _keycard_export_key_private(self, args: list[str]) -> None:
        self._require_args(args, 1)
        key = self._kcs.export_key(args[0], only_public=False)
        print(f"EXPORTED PRIVATE KEY\n{key.priv_key.hex()}")
        print(f"EXPORTED PUBLIC KEY\n{key.pub_key.hex()}")
        print()

    def _keycard_export_key_public(self, args: list[str]) -> None:
        self._require_args(args, 1)
        key = self._kcs.export_key(args[0], only_public=True)
        print(f"EXPORTED PUBLIC KEY\n{key.pub_key.hex()}")
        print()

    def _keycard_export_xpub(self, args: list[str]) -> None:
        """Export an extended public key (BIP32 xpub) for the given derivation path.

        Usage: keycard-export-xpub <path>
        Example: keycard-export-xpub m/44'/60'/0'
        """
        self._require_args(args, 1)
        key = self._kcs.export_key_extended(args[0])
        if not key.chain_code:
            raise RuntimeError(
                "card did not return a chain code; ensure the keycard firmware "
                "supports P2=0x02 (extended public key export)"
            )
        xpub = serialize_xpub(key.pub_key, key.chain_code)
        print(f"XPUB: {xpub}")
        print(f"PUBLIC KEY: 0x{key.pub_key.hex()}")
        print(f"CHAIN CODE: 0x{key.chain_code.hex()}")
        print()

    def _keycard_sign(self, args: list[str]) -> None:
        self._require_args(args, 1)
        data = _parse_hex(args[0])
        if len(data) != 32:
            raise ValueError("data must be exactly 32 bytes (64 hex chars)")
        sig = self._kcs.sign(data)
        _print_signature(sig)

    def _keycard_sign_with_path(self, args: list[str]) -> None:
        self._require_args(args, 2)
        data = _parse_hex(args[0])
        if len(data) != 32:
            raise ValueError("data must be exactly 32 bytes (64 hex chars)")
        sig = self._kcs.sign_with_path(data, args[1])
        _print_signature(sig)

    def _keycard_sign_message(self, args: list[str]) -> None:
        if not args:
            raise ValueError("keycard-sign-message requires at least 1 argument")
        message = " ".join(args)
        msg_hash = hash_ethereum_message(message)
        sig = self._kcs.sign(msg_hash)
        _print_signature(sig)

    def _keycard_sign_pinless(self, args: list[str]) -> None:
        self._require_args(args, 1)
        data = _parse_hex(args[0])
        if len(data) != 32:
            raise ValueError("data must be exactly 32 bytes (64 hex chars)")
        sig = self._kcs.sign_pinless(data)
        _print_signature(sig)

    def _keycard_sign_message_pinless(self, args: list[str]) -> None:
        if not args:
            raise ValueError("keycard-sign-message-pinless requires at least 1 argument")
        message = " ".join(args)
        msg_hash = hash_ethereum_message(message)
        sig = self._kcs.sign_pinless(msg_hash)
        _print_signature(sig)

    def _keycard_sign_tx(self, args: list[str]) -> None:
        """Sign an Ethereum transaction with the currently loaded key.

        Usage: keycard-sign-tx <json-tx>
        The argument is a JSON object with fields:
          nonce, gas_price (or gasPrice), gas (or gasLimit), to, value,
          data (optional), chain_id (or chainId, optional – 0 for legacy)

        Example:
          keycard-sign-tx '{"nonce":0,"gas_price":"0x4a817c800","gas":21000,"to":"0xabc...","value":"0xde0b6b3a7640000","chain_id":1}'

        Output:
          TX HASH: 0x...
          SIGNED TX: 0x...  (RLP-encoded, ready to broadcast)
        """
        self._require_args(args, 1)
        try:
            tx = json.loads(args[0])
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON transaction: {exc}") from exc

        chain_id = int(tx.get("chain_id") or tx.get("chainId") or 0)
        tx_hash = hash_transaction(tx)
        sig = self._kcs.sign(tx_hash)

        signed = encode_signed_transaction(tx, sig.r, sig.s, sig.v, chain_id)
        print(f"TX HASH: 0x{tx_hash.hex()}")
        print(f"SIGNATURE R: {sig.r.hex()}")
        print(f"SIGNATURE S: {sig.s.hex()}")
        print(f"SIGNATURE V: {sig.v}")
        print(f"SIGNED TX: {signed}")
        print()

    def _keycard_set_pinless_path(self, args: list[str]) -> None:
        self._require_args(args, 1)
        self._kcs.set_pinless_path(args[0])

    def _keycard_load_seed(self, args: list[str]) -> None:
        self._require_args(args, 1)
        seed = _parse_hex(args[0])
        key_uid = self._kcs.load_seed(seed)
        if key_uid:
            print(f"KEY UID {key_uid.hex()}")
        print()

    def _keycard_generate_mnemonic(self, args: list[str]) -> None:
        self._require_args(args, 1)
        checksum_size = int(args[0])
        indexes = self._kcs.generate_mnemonic(checksum_size)
        print(f"MNEMONIC INDEXES {indexes}")
        print()

    def _keycard_identify(self, args: list[str]) -> None:
        self._require_args(args, 0, 1)
        pub_key = self._kcs.identify()
        print(f"IDENTIFICATION PUBLIC KEY: 0x{pub_key.hex()}")
        if len(args) == 1:
            expected = _parse_hex(args[0])
            if pub_key != expected:
                raise RuntimeError("genuinity check failed: key mismatch")
        print()

    # ── Cash commands ─────────────────────────────────────────────────────────

    def _cash_select(self, args: list[str]) -> None:
        self._require_args(args, 0)
        info = self._cash.select()
        print(f"Installed: {info.installed}")
        if info.installed:
            print(f"PublicKey: {info.pub_key.hex()}")
            print(f"PublicData: {info.pub_data.hex()}")
            print(f"Version: {info.version.hex()}")
        print()

    def _cash_sign(self, args: list[str]) -> None:
        self._require_args(args, 1)
        data = _parse_hex(args[0])
        if len(data) != 32:
            raise ValueError("data must be exactly 32 bytes (64 hex chars)")
        sig = self._cash.sign(data)
        _print_signature(sig)


def cmd_shell(_: argparse.Namespace) -> int:
    session = connect_to_card()
    try:
        shell = Shell(session)
        return shell.run()
    finally:
        session.disconnect()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keycard")
    parser.add_argument(
        "-l",
        "--log-level",
        default="info",
        choices=["debug", "info", "warn", "error"],
        help='Log level, one of: "error", "warn", "info", "debug"',
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("version").set_defaults(func=cmd_version)
    subparsers.add_parser("info").set_defaults(func=cmd_info)
    subparsers.add_parser("install").set_defaults(func=_not_implemented("install"))
    subparsers.add_parser("delete").set_defaults(func=_not_implemented("delete"))
    subparsers.add_parser("init").set_defaults(func=_not_implemented("init"))
    subparsers.add_parser("shell").set_defaults(func=cmd_shell)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.log_level)
    try:
        return args.func(args)
    except Exception as exc:
        logging.error("application error: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
