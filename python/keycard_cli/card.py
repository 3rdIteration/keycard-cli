from __future__ import annotations

import time
from typing import Optional

from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException
from smartcard.System import readers

from .apdu import APDUResponse


class CardSession:
    def __init__(self, connection: CardConnection, reader_name: str) -> None:
        self._connection = connection
        self.reader_name = reader_name

    def transmit(self, command: bytes) -> APDUResponse:
        data, sw1, sw2 = self._connection.transmit(list(command))
        return APDUResponse(bytes(data), (sw1 << 8) | sw2)

    def disconnect(self) -> None:
        try:
            self._connection.disconnect()
        except Exception:
            pass


def connect_to_card(wait_seconds: Optional[int] = None) -> CardSession:
    all_readers = readers()
    if not all_readers:
        raise RuntimeError("no smartcard reader found")

    start = time.time()
    while True:
        for reader in all_readers:
            connection = reader.createConnection()
            try:
                connection.connect(CardConnection.T1_protocol)
                return CardSession(connection, str(reader))
            except CardConnectionException:
                continue

        if wait_seconds is not None and (time.time() - start) >= wait_seconds:
            raise TimeoutError("timed out waiting for card")

        time.sleep(0.5)
