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

## Target and attempt binding

A ticket binds an effect contract to `repository` and `target_sha`. Human authorization must match the exact target SHA. Every `begin_effect` creates a unique attempt identity `ticket_id:<monotonic-attempt-number>`.

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

- `OBSERVED` records an observation and leaves the ticket retryable/authorized.
- `UNKNOWN` is an ambiguous external outcome and MUST NOT become success or create an automatic dispatch.
- `FAILED` records failure and permits explicit verification/retry according to ticket policy.
- `COMPLETED` is terminal success for the exact effect/attempt only.

A terminal receipt cannot be overwritten by a later receipt. A completed effect cannot accept another attempt or replayed receipt.

## Idempotency

The same ticket/effect/idempotency tuple may be retried only when the existing attempt is explicitly in a retryable state. A duplicate receipt for the same attempt is rejected after a terminal receipt has been persisted. Reusing an idempotency key for a different effect or different contract fields is rejected.

The gateway MUST fail closed on idempotency conflicts; it MUST NOT silently treat a changed payload as the same operation.

## Governance freshness

Authorization and effect start require the persisted governance digest to equal the current gateway governance digest. A governance change invalidates the effect boundary until a new ticket is explicitly created and authorized.

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
10. `UNKNOWN` => never `COMPLETED` implicitly.
11. Terminal ticket => no new attempt.
12. Gateway never grants AIOS authority.

## Verification gate

Contract compliance requires:

`unit tests PASS` + `adversarial tests PASS` + `persistence/restart tests PASS` + `exact-head CI PASS`.

A green CI result from another commit is not evidence for this contract.