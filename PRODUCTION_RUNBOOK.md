# Production boundary runbook

This repository is the control-plane gateway only. It must not contain governance rules, evidence criteria, promotion criteria, terminal conditions, or GitHub write credentials.

## Required secrets

- `GITHUB_WEBHOOK_SECRET`
- `ANDROID_GATEWAY_TOKEN`
- `REPAIR_WORKER_TOKEN`
- `AUTHORIZED_PHONE`
- `GATEWAY_DB`

Never commit real values. The gateway must fail closed when an authentication secret required by an enabled endpoint is absent.

## Network boundary

- Bind to `127.0.0.1` by default.
- Put the service behind a TLS-terminating reverse proxy for remote webhook/SMS traffic.
- Do not expose the SQLite database or repair-worker endpoint directly to the public Internet.
- Keep the Android bridge as a transport adapter only; it receives no GitHub credentials.

## GitHub webhook

Configure a `workflow_run` webhook for the four allowlisted repositories. Deliver `X-Hub-Signature-256` and validate the event type/action before accepting a failure ticket. The trusted harness producer supplies the governance digest; the gateway only binds and transports that digest.

## Repair flow

`workflow_run completed/failure` -> ticket -> SMS -> human `SUA ticket nonce` -> gateway authorization -> repair worker -> independent governance/SHA check -> repair -> verify -> persist -> resume.

`SUA` is the only command that can authorize repair. `RETRY` is verify-only. `BOQUA` rejects. `STOP` revokes pending authorization.

## Current implementation gate

Before production deployment, the gateway must pass adversarial tests for token replay, token revocation after `STOP`, sender spoofing, webhook signature failure, unknown repository, SHA mismatch, governance mismatch, duplicate webhook delivery, oversized request bodies, and event-ledger tampering.

The Android application itself is a separate deployment artifact and is intentionally not represented as a GitHub credential holder.
