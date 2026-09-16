# Gateway Effect Contract v1

## Purpose

`harness-gateway` is an external-effect boundary. AIOS owns policy, capability, authority and evidence decisions. The gateway does not mint, broaden, or replace authority; it binds an already-authorized effect to a human-approved target, a durable attempt and immutable receipt history.

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

## Canonical state machine

Effect state is separate from attempt state:

`PENDING -> AUTHORIZED -> ATTEMPT_OPEN -> {COMPLETED | RECONCILING}`

`RECONCILING -> AUTHORIZED` is allowed only after authoritative `NO_EFFECT` reconciliation. That transition does **not** grant retry authority.

`AUTHORIZED -> ATTEMPT_OPEN` for an already-attempted effect requires a fresh explicit human `authorize_retry()` operation.

`RECONCILING -> COMPLETED` is allowed only after authoritative `EFFECTED` reconciliation.

`REJECTED`, `COMPLETED`, and `EXPIRED` are terminal. Terminal effects never create another attempt.

Receipt statuses `OBSERVED`, `UNKNOWN`, and `FAILED` all enter `RECONCILING`. An observation alone never grants dispatch authority.

## Attempt and fence binding

Every `begin_effect()` creates a unique attempt identity `ticket_id:<monotonic-fence>`. Each attempt has an immutable fence. The fence is a freshness token: a receipt from an obsolete attempt may be retained as historical evidence but MUST NOT mutate the current effect state.

Only one attempt may be open for an effect at a time. Attempt allocation is serialized by a cross-process state lock and reloads durable state while holding that lock.

A receipt MUST contain and match exactly:

- `ticket_id`;
- `attempt_id`;
- `attempt_fence`;
- `target_sha`;
- `effect_id`;
- `idempotency_key`;
- `evidence_ref`;
- `lineage_ref`;
- allowed receipt `status`.

No receipt field may substitute for or broaden the contract.

## Immutable receipts

Allowed receipt statuses are `OBSERVED`, `UNKNOWN`, `FAILED`, and `COMPLETED`.

Every accepted receipt is appended to `receipts[]`. `last_receipt` is only a compatibility/materialized field and is never the source of truth.

A duplicate receipt for the same attempt is rejected. A valid receipt from a stale fence is recorded with `stale=true` but cannot change the current effect state.

`UNKNOWN` means the external outcome is ambiguous. `FAILED` is also treated as ambiguous at this boundary unless a separately verified reconciliation proves `NO_EFFECT`. Neither status is permission to retry.

## Reconciliation and retry

`retry_verify_only()` performs verification checks and never changes retry authority.

`reconcile()` requires a human identity and non-empty verification reference:

- `NO_EFFECT` -> `AUTHORIZED`, with retry authority still false;
- `EFFECTED` -> `COMPLETED`;
- `UNRESOLVED` -> remains `RECONCILING`.

Only then can `authorize_retry()` grant the separate retry authorization required by `begin_effect()`.

## Idempotency

The producer's `idempotency_key` remains stable across retries. `attempt_id` and `attempt_fence` change per attempt. Reusing an idempotency key for a different effect or different contract fields is rejected.

The gateway MUST fail closed on idempotency conflicts; it MUST NOT silently treat a changed payload as the same operation.

## Governance freshness

Authorization, effect start, retry authorization, receipt acceptance, and reconciliation require the persisted governance digest to equal the current gateway governance digest. Governance drift fails closed.

## Durable ordering

Every mutation follows:

`LOCK -> RELOAD -> VALIDATE -> APPEND/UPDATE -> VERSION++ -> ATOMIC SAVE -> UNLOCK`

State mutation and receipt persistence use atomic durable writes. The implementation must not report a transition as persisted before the durable state write succeeds.

## Negative invariants

1. Missing contract => no effect.
2. Wrong human identity => no authorization/retry/reconciliation.
3. Wrong nonce => no authorization.
4. Wrong target SHA => no authorization/effect/receipt.
5. Governance drift => no authorization/effect/retry/reconciliation.
6. Cross-effect receipt => reject.
7. Unknown attempt/fence => reject.
8. Stale receipt => evidence only; never current-state mutation.
9. Evidence or lineage mismatch => reject.
10. Idempotency mismatch/replay => reject.
11. `UNKNOWN`/`FAILED`/`OBSERVED` => `RECONCILING`, never implicit dispatch.
12. `reconcile(NO_EFFECT)` => `AUTHORIZED` but not retry-authorized.
13. `authorize_retry()` => required before a subsequent attempt.
14. Concurrent `begin_effect()` => unique monotonic fences.
15. Concurrent receipt writes => at most one receipt per attempt.
16. Receipt history survives restart.
17. Terminal effect => no new attempt or receipt mutation.
18. Gateway never grants AIOS authority.

## Verification gate

Contract compliance requires:

`unit tests PASS` + `adversarial tests PASS` + `cross-process tests PASS` + `persistence/restart tests PASS` + `exact-head CI PASS`.

A green CI result from another commit is not evidence for this contract.
