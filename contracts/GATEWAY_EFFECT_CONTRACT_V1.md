# Gateway Effect Contract v1

## Purpose

`harness-gateway` is an external-effect boundary. AIOS owns policy, capability, authority and evidence decisions. The gateway does not mint, broaden, or replace authority; it binds an already-authorized effect to a human-approved target, an attempt, and a durable receipt.

## Canonical effect identity

An effect contract MUST contain these non-empty immutable fields:

- `effect_id` — stable identity of the effect.
- `action` — exact requested action.
- `capability_ref` — versioned capability resolved by AIOS.
- `authority_ref` — exact AIOS permit/authority reference.
- `evidence_ref` — evidence supporting the predecessor/decision.
- `lineage_ref` — lineage of the originating workload/run.
- `idempotency_key` — producer-owned replay identity.

The gateway persists the contract exactly as normalized strings and never rewrites these values.

## State machine

The ticket state machine is explicit:

`PENDING -> AUTHORIZED -> attempt -> {COMPLETED | UNKNOWN_REQUIRES_VERIFY | FAILED_REQUIRES_VERIFY | AUTHORIZED}`

`UNKNOWN_REQUIRES_VERIFY` and `FAILED_REQUIRES_VERIFY` are non-dispatching verification states. They MUST NOT be treated as `AUTHORIZED` implicitly.

Only an explicit human-authorized `authorize_retry()` transition may move either verification state back to `AUTHORIZED`. `retry_verify_only()` is verification-only and MUST NOT grant dispatch authority.

`REJECTED`, `COMPLETED`, and `EXPIRED` are terminal. Terminal states never create another attempt.

`OBSERVED` is a non-terminal receipt that returns the ticket to `AUTHORIZED` because it records an observation rather than an ambiguous outcome. `UNKNOWN` and `FAILED` always enter their explicit verification states.

## Target and attempt binding

A ticket binds an effect contract to `repository` and `target_sha`. Human authorization must match the exact target SHA. Every `begin_effect` creates a unique attempt identity `ticket_id:<monotonic-attempt-number>`.

Attempt allocation is serialized by a cross-process state lock and reloads durable state while holding that lock. The gateway therefore cannot allocate the same attempt number concurrently from two processes against one state file.

A receipt MUST match exactly:

- `ticket_id` to the ticket receiving it;
- `attempt_id` to the currently open attempt;
- `target_sha` to the ticket target;
- `effect_id` to the effect contract;
- `idempotency_key` to the effect contract;
- `evidence_ref` to the effect contract;
- `lineage_ref` to the effect contract.

No receipt field may substitute for or broaden the contract.

## Receipt states

Allowed receipt statuses are `OBSERVED`, `UNKNOWN`, `FAILED`, and `COMPLETED`.

- `OBSERVED` records an observation and leaves the ticket `AUTHORIZED`.
- `UNKNOWN` is an ambiguous external outcome and MUST enter `UNKNOWN_REQUIRES_VERIFY`; it MUST NOT become success or create an automatic dispatch.
- `FAILED` records failure and MUST enter `FAILED_REQUIRES_VERIFY`; it permits retry only after explicit verification/authorization.
- `COMPLETED` is terminal success for the exact effect/attempt only.

A terminal receipt cannot be overwritten by a later receipt. A completed effect cannot accept another attempt or replayed receipt.

## Idempotency and retry

The same ticket/effect/idempotency tuple may be retried only after the current attempt has produced an explicitly retryable state and a human has authorized the retry. Replaying `UNKNOWN` or `FAILED` directly into `begin_effect` is forbidden.

The retry authorization re-checks human identity, gateway revocation, expiry, and governance freshness. A changed governance digest or expired ticket fails closed.

A duplicate receipt for the same attempt is rejected after a receipt has been persisted. Reusing an idempotency key for a different effect or different contract fields is rejected.

The gateway MUST fail closed on idempotency conflicts; it MUST NOT silently treat a changed payload as the same operation.

## Governance freshness

Authorization, effect start, and explicit retry authorization require the persisted governance digest to equal the current gateway governance digest. A governance change invalidates the effect boundary until a new ticket is explicitly created and authorized.

## Durable ordering

State mutation and receipt persistence use atomic durable writes. The implementation must not report a transition as persisted before the durable state write succeeds.

## Negative invariants

1. Missing contract => no effect.
2. Wrong human identity => no authorization.
3. Wrong nonce => no authorization.
4. Wrong target SHA => no authorization/effect/receipt.
5. Governance drift => no authorization/effect/retry.
6. Cross-effect receipt => reject.
7. Cross-attempt receipt => reject.
8. Evidence or lineage mismatch => reject.
9. Idempotency mismatch/replay => reject.
10. `UNKNOWN` => `UNKNOWN_REQUIRES_VERIFY`, never `AUTHORIZED` implicitly.
11. `FAILED` => `FAILED_REQUIRES_VERIFY`, never direct dispatch.
12. `retry_verify_only()` => no authority transition.
13. `authorize_retry()` => required before dispatch after UNKNOWN/FAILED.
14. Concurrent `begin_effect()` => unique attempt IDs.
15. Terminal ticket => no new attempt.
16. Gateway never grants AIOS authority.

## Verification gate

Contract compliance requires:

`unit tests PASS` + `adversarial tests PASS` + `persistence/restart tests PASS` + `exact-head CI PASS`.

A green CI result from another commit is not evidence for this contract.
