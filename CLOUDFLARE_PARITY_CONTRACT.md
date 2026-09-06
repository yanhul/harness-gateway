# Cloudflare Parity Contract

## Purpose

This document freezes the Python gateway semantics before the Cloudflare Worker/Durable Object implementation. Cloudflare is an implementation of these semantics, not a new policy authority.

## Governing invariants

1. Policy, evidence criteria, promotion criteria, terminal conditions, and trust roots are external governance and are not agent-editable.
2. Human repair authorization is exactly `SUA <ticket> <nonce>`.
3. The gateway derives the governance digest from the ticket. The human command does not supply it.
4. A repair authorization is bound to exactly `(ticket, repo, target_sha, governance_digest)`.
5. Human authorization nonce is ticket-bound, expiring, and single-use.
6. `STOP` revokes pending human authorization and must remain effective.
7. Repair-worker authorization is distinct from the human SMS nonce.
8. Worker lifecycle operations require an already-consumed repair authorization and exact binding.
9. Lifecycle transitions cannot skip states.
10. Audit events form a durable, verifiable hash chain.

## Canonical ticket lifecycle

```text
OBSERVED -> DIAGNOSED -> AWAITING_HUMAN
                         |-> REJECTED
                         |-> EXPIRED
                         |-> REVOKED
                         |-> BLOCKED
                         `-> AUTHORIZED -> ACTING -> VERIFYING -> PERSISTED -> RESUMED
```

Other transitions are rejected. `BLOCKED` is terminal for this lifecycle unless the canonical Python implementation explicitly adds a governed recovery path; Cloudflare must not invent one.

## Webhook contract

- Accept only the configured repository allowlist.
- Validate the GitHub workflow-run event shape and the exact target repository/SHA semantics used by the Python reference implementation.
- Verify `X-Hub-Signature-256` against the configured webhook secret using HMAC-SHA256 over the raw request body bytes before JSON parsing.
- Reject missing or invalid signatures.
- Do not authenticate a webhook from parsed JSON or an unsigned repository field.

## Human SMS contract

Input is exactly a supported command. For authorization:

```text
SUA <ticket> <nonce>
```

Sender identity is authenticated by the SMS bridge/gateway boundary. The gateway loads the ticket's stored governance digest and target binding. A user-provided governance digest is never required for normal `SUA` authorization. If an internal caller explicitly supplies a digest, a mismatch is rejected.

On successful `SUA`:
- ticket becomes `AUTHORIZED`;
- authorization records the exact ticket/repo/SHA/governance binding;
- the nonce is consumed atomically;
- replay is rejected.

`BOQUA <ticket>` rejects repair. `RETRY <ticket>` is verify-only and cannot authorize a new repair. `STATUS` is read-only. `STOP` revokes pending authorization.

## Repair-worker contract

A worker must authenticate separately from the human SMS bridge. A repair token may be issued only from `AUTHORIZED` and must carry the exact ticket/repo/SHA/governance binding.

Consumption is one-time. It must be an atomic conditional operation so concurrent consumers cannot both succeed.

Lifecycle endpoint accepts only:

```text
VERIFYING
PERSISTED
RESUMED
```

and only the legal next state is permitted. `ACTING -> PERSISTED`, for example, is rejected.

## Audit contract

Every state-changing effect appends an event containing at least:

- event sequence/order;
- ticket;
- event type;
- actor identity/type;
- canonical payload;
- creation time;
- previous event hash;
- current event hash.

The event hash is deterministic SHA-256 over a fixed canonical encoding of the previous hash, ticket, event type, actor, payload, and creation time. Empty/placeholder hashes are forbidden. Verification must detect any mutation or broken predecessor link.

## Persistence/concurrency contract

Cloudflare Durable Object serialization is the authoritative request serialization boundary for a gateway object. SQL mutations that enforce one-time use must additionally be conditional/transactionally safe. Schema initialization must be serialized with `blockConcurrencyWhile`.

The Python reference gateway's `RLock` is an in-process safety mechanism only; it is not a claim of cross-process SQLite safety.

## Parity tests required before promotion

Cloudflare must independently prove equivalent outcomes for:

- valid webhook -> ticket creation;
- spoofed/missing webhook signature -> rejection;
- unsupported repository -> rejection;
- valid `SUA ticket nonce` -> authorization;
- `SUA` without a user-supplied governance digest -> success when ticket/nonce are valid;
- wrong sender -> rejection;
- wrong nonce/ticket/expired nonce/replayed nonce -> rejection;
- governance mismatch -> rejection;
- exact SHA mismatch -> rejection;
- `STOP` -> pending authorization revoked;
- repair token replay -> rejection;
- concurrent repair-token consumption -> exactly one success;
- lifecycle without consumed worker authorization -> rejection;
- illegal lifecycle jump -> rejection;
- exact repo/SHA/governance lifecycle binding -> enforced;
- audit-chain mutation -> verification failure.

## Promotion gate

Passing unit/parity tests is not live-production proof. Production requires a separately authorized canary, real GitHub webhook delivery, and real Android/Google Messages end-to-end evidence. No implementation may mark itself production-ready merely because CI passes.
