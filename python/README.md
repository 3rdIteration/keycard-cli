# keycard-cli Python port

This directory contains the Python port of `keycard-cli` for interacting with Status Keycard applets through a smart card reader.

## What is included

- CLI entrypoint: `keycard.py`
- Python package: `keycard_cli/`
- Interactive shell with Keycard/Cash APDU workflows
- Ethereum helpers for message and transaction signing

## Requirements

- Python 3.10+ recommended
- A PC/SC-compatible smart card reader
- `pcscd` running on Linux

Python dependencies are in `requirements.txt`:

- `pyscard>=2.0.12`
- `pycryptodomex>=3.22.0`
- `cryptography>=41.0.0`

## Installation

From this folder:

```bash
cd /tmp/workspace/3rdIteration/keycard-cli/python
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick start

Run commands with:

```bash
python keycard.py <command>
```

Available top-level commands:

- `version` — print CLI version
- `info` — probe Keycard and Cash applet presence
- `shell` — run interactive command stream from stdin
- `install` — reserved, not ported yet
- `delete` — reserved, not ported yet
- `init` — reserved, not ported yet

Examples:

```bash
python keycard.py version
python keycard.py info
python keycard.py -l debug shell < ../_shell-commands-examples/card_init_example.sh
```

## Logging

Use `-l/--log-level`:

- `error`
- `warn`
- `info` (default)
- `debug`

Example:

```bash
python keycard.py -l debug info
```

## Shell command coverage

The Python shell implements the command set used by the Go shell, including:

- Global platform: `echo`, `gp-send-apdu`, `gp-select`
- Keycard: select/init/pairing, secure channel, PIN/PUK ops, key generation/removal/derivation/export, signing, mnemonic/seed, identify
- Cash: `cash-select`, `cash-sign`

Shell mode reads commands from standard input. Empty lines and `#` comments are ignored.

## Typical shell flow

Example sequence:

1. `keycard-select`
2. `keycard-set-secrets <pin> <puk> <pairing-password>` (or `keycard-init`)
3. `keycard-pair`
4. `keycard-open-secure-channel`
5. `keycard-verify-pin <pin>`
6. `keycard-sign <32-byte-hex>`

You can also use the command files under `../_shell-commands-examples/`.

## Limitations

- Top-level `install`, `delete`, and `init` commands are placeholders in the Python CLI and currently return a not-ported error.
- Hardware access depends on your local reader/driver setup (`pyscard` + PC/SC stack).

## Troubleshooting

- **No reader found**: verify your reader is connected and PC/SC is installed and running.
- **Card connection issues**: reinsert the card and retry.
- **Import errors**: ensure the virtual environment is active and `pip install -r requirements.txt` succeeded.

## Project layout

```text
python/
├── keycard.py                  # CLI launcher
├── requirements.txt            # Python dependencies
└── keycard_cli/
    ├── cli.py                  # Argument parsing + shell command handlers
    ├── card.py                 # Reader/card connection layer
    ├── keycard_proto.py        # Keycard protocol + crypto helpers
    ├── eth_tx.py               # Ethereum transaction encoding/signing helpers
    ├── crypto.py               # Ethereum message hash helper
    ├── apdu.py                 # APDU response/encoding utilities
    ├── bip32.py                # BIP32 xpub/public key utilities
    ├── ndef.py                 # NDEF support helpers
    └── tlv.py                  # TLV parsing helpers
```
