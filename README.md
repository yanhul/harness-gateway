# Harness Gateway

Human-authorized repair gateway for AIOS, try, android-ai-assistant, and RX50.

## Trust model

GitHub failure -> gateway creates immutable ticket -> Android SMS notification -> human approval -> repair worker -> verification -> persisted result.

The agent cannot authorize itself and cannot modify governance.

## Command protocol

- `SUA <ticket> <nonce>` — authorize one repair
- `BOQUA <ticket>` — reject one repair
- `RETRY <ticket>` — retry verification without changing code
- `STATUS` — current queue/status
- `STOP` — revoke pending repair authorizations

Commands must originate from the configured human phone identity, reference an unexpired one-time nonce, and match the exact repository/commit recorded in the ticket.

## Governance firewall

Before Act, persist SHA-256 digests for policy, evidence criteria, promotion criteria, terminal conditions, and trust roots. Any protected digest change blocks the repair.

## Transport

The Android device is the SMS transport; it must not hold GitHub write credentials. A control server/worker is the authority boundary.
