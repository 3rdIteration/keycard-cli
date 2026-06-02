from __future__ import annotations

import argparse
import logging
import shlex
import sys
from typing import Callable

from .apdu import SW_OK, decode_hex_command, sw_to_hex
from .card import CardSession, connect_to_card

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
    def __init__(self, session: CardSession):
        self.session = session
        self.commands: dict[str, Callable[[list[str]], int]] = {
            "echo": self._echo,
            "gp-send-apdu": self._gp_send_apdu,
            "gp-select": self._gp_select,
            "keycard-select": self._keycard_select,
            "cash-select": self._cash_select,
        }

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

    def _echo(self, args: list[str]) -> int:
        print("> " + " ".join(args))
        return 0

    def _gp_send_apdu(self, args: list[str]) -> int:
        if len(args) != 1:
            raise ValueError("gp-send-apdu expects 1 argument")
        response = self.session.transmit(decode_hex_command(args[0]))
        print(f"SW {sw_to_hex(response.sw)}")
        print(f"DATA 0x{response.data.hex()}")
        if response.sw != SW_OK:
            raise RuntimeError(f"unexpected response sw={sw_to_hex(response.sw)}")
        return 0

    def _gp_select(self, args: list[str]) -> int:
        if len(args) > 1:
            raise ValueError("gp-select expects 0 or 1 arguments")
        aid = ISD_AID if not args else decode_hex_command(args[0])
        response = _select_aid(self.session, aid)
        print(f"SW {sw_to_hex(response.sw)}")
        print(f"DATA 0x{response.data.hex()}")
        return 0

    def _keycard_select(self, args: list[str]) -> int:
        if args:
            raise ValueError("keycard-select expects 0 arguments")
        response = _select_aid(self.session, KEYCARD_INSTANCE_AID)
        print(f"Installed: {response.ok}")
        print(f"SW: {sw_to_hex(response.sw)}")
        print(f"Response: 0x{response.data.hex()}")
        return 0

    def _cash_select(self, args: list[str]) -> int:
        if args:
            raise ValueError("cash-select expects 0 arguments")
        response = _select_aid(self.session, CASH_INSTANCE_AID)
        print(f"Installed: {response.ok}")
        print(f"SW: {sw_to_hex(response.sw)}")
        print(f"Response: 0x{response.data.hex()}")
        return 0


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
