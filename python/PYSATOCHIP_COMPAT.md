# pysatochip Compatibility Layer (Keycard Backend)

This folder now includes a lightweight compatibility adapter intended to make
Keycard usage as close as practical to `pysatochip` for SeedSigner-side
abstractions.

## Module

- `keycard_cli.pysatochip_compat`
- Main class: `KeycardCompatConnector`

Example import:

```python
from keycard_cli.pysatochip_compat import KeycardCompatConnector
```

## Intended Scope

This adapter focuses on the common Satochip-like operations typically used by
higher-level wallet software:

- PIN verification
- BIP32 extended key and xpub retrieval
- 32-byte digest signing (transaction hash style)
- Authentikey-style export

It is not a full protocol-level Satochip emulation.

## API Mapping

Implemented methods with pysatochip-like names:

- `card_select()`
- `card_verify_PIN(pin)`
- `card_get_status()`
- `card_bip32_get_authentikey()`
- `card_export_authentikey()`
- `card_bip32_get_extendedkey(path, sid=None, option_flags=0x40)`
- `card_bip32_get_xpub(path, xtype, is_mainnet, sid=None)`
- `card_sign_transaction_hash(keynbr, txhash, chalresponse=None)`
- `card_sign_transaction(keynbr, txhash, chalresponse=None)`
- `card_sign_message(keynbr, pubkey, message, hmac=b"", altcoin=None)`
- `card_disconnect()`

Additional helper methods for pairing lifecycle:

- `pair(pairing_password=None, pair_mode="ephemeral")` -> `(pairing_key_hex, pairing_index)`
- `set_pairing(pairing_key_hex, pairing_index)`
- `get_pairing()`

## Pairing Behavior (Important)

Keycard secure operations require pairing information:

- `pairing_key` (hex)
- `pairing_index` (slot id)

By default, this adapter uses ephemeral pairing (`pair_mode="ephemeral"`),
which returns pairing index `0xFF` and does not consume a persistent slot.

If the adapter does not have pairing info, it can attempt fresh pairing using a
pairing password. In default ephemeral mode this does not consume a slot.
Persistent mode (`pair_mode="persistent"`) consumes one card slot.

For mostly stateless devices, ephemeral mode is preferred. If you use persistent
pairing, persist pairing data externally and call `set_pairing(...)` on each
session before secure operations.

Recommended storage key:

- card `instance_uid` from `card_select()`

This allows one persisted pairing record per card.

## No-Persistence Mode (No MicroSD)

If the host does not provide persistent storage, this backend can still operate
using default ephemeral pairing.

In that mode, practical behavior is:

- Create a fresh ephemeral pairing for the session
- Perform secure operations (PIN verify, xpub/sign)
- Optional: unpair before exit

If power is lost or the app crashes, ephemeral pairing is automatically cleared
on deselect/reset by the card. Persistent slots are only at risk when
persistent pairing mode is used.

So for no-MicroSD operation with ephemeral default, slot exhaustion is avoided
in normal operation.

## What Happens When Pairing Slots Are Exhausted

Typical persistent capacity is 10 pairing slots on current Keycard applet
builds, but this is card/firmware dependent. Always treat the card-reported
value as the source of truth.

You can check remaining slots from `card_select()` output (`available_slots`),
which is reported in hex.

- New persistent pairing attempts fail.
- Existing saved pairing key/index can still work.
- Recovery requires unpairing old slots or clearing pairings on card.

Because of this, callers should avoid automatic persistent re-pairing on every
run.

## Signature Compatibility Notes

- `card_sign_transaction_hash(...)` returns `(response, sw1, sw2)` where
  `response` is DER signature bytes as a list.
- `card_sign_message(...)` returns `(response, sw1, sw2, compsig)` where
  `response` is DER signature bytes as a list, and `compsig` is 65-byte
  compact form.
- Message formatting/hashing policy should be handled by the caller layer
  (for example SeedSigner), which can pass a 32-byte digest.

## xpub Compatibility Notes

`card_bip32_get_xpub(...)` supports the same `xtype` values commonly used in
pysatochip:

- `standard`
- `p2wpkh-p2sh`
- `p2wsh-p2sh`
- `p2wpkh`
- `p2wsh`

It computes depth, parent fingerprint, and child index from the provided BIP32
path and uses the corresponding mainnet/testnet version bytes.
