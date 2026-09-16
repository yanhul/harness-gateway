# Canonical Effect Lifecycle Architecture v1

## Ownership

- **AIOS** owns policy, capability resolution, authority/permit, evidence and lineage.
- **Gateway** owns durable effect/attempt coordination at the external side-effect boundary.
- **Worker/provider** owns the external side effect and emits a bound receipt.
- **Reconciliation** determines the real-world outcome after an ambiguous attempt; it does not silently grant retry authority.

The gateway never mints or broadens AIOS authority.

## Canonical entities

### Effect

One logical side effect. Stable identity is `effect_id` plus the producer's `idempotency_key` and immutable contract fields.

### Attempt

One execution opportunity for an effect. Every attempt has a unique `attempt_id` and monotonically increasing `fence`. The attempt fence is the freshness token for the execution boundary.

### Receipt

Immutable evidence bound to exactly one effect and attempt. Receipts are append-only history; `last_receipt` is forbidden as the source of truth.

### Authorization

A separate permission to start an attempt. Initial authorization and retry authorization are distinct lifecycle events. A successful reconciliation to `NO_EFFECT` does not itself grant retry authority.

## Effect state machine

```text
PENDING
  | authorize
  v
AUTHORIZED --begin_effect--> ATTEMPT_OPEN
                               | COMPLETED receipt
                               v
                           COMPLETED

ATTEMPT_OPEN -- UNKNOWN/FAILED/OBSERVED --> RECONCILING
RECONCILING -- reconcile(EFFECTED) --> COMPLETED
RECONCILING -- reconcile(NO_EFFECT) --> AUTHORIZED
AUTHORIZED -- authorize_retry + begin_effect --> ATTEMPT_OPEN

PENDING -- reject --> REJECTED
PENDING/AUTHORIZED/RECONCILING -- expiry --> EXPIRED
```

Terminal states are `COMPLETED`, `REJECTED`, and `EXPIRED`. A terminal effect cannot create another attempt.

`UNKNOWN` is never equivalent to retry. It means the external outcome is unknown and requires reconciliation. A `FAILED` receipt is also treated as ambiguous at this boundary unless the receipt itself is a separately verified no-effect proof.

## Attempt state

Each attempt is independently recorded as `OPEN`, `COMPLETED`, `FAILED`, `UNKNOWN`, `OBSERVED`, or `STALE_RECEIPT_RECORDED`.

A stale receipt may be retained as immutable evidence, but it must not mutate the current effect state. A receipt from an obsolete fence cannot resurrect, complete, or re-authorize the current attempt.

## Concurrency and durability invariants

1. Every mutating operation reloads durable state while holding the cross-process state lock.
2. Every successful mutation increments the durable state version.
3. Attempt allocation is serialized and produces a unique monotonic fence and attempt ID.
4. Only one `ATTEMPT_OPEN` attempt may exist for an effect at a time.
5. Every receipt is append-only and immutable.
6. Receipt writes are serialized with attempt allocation and reconciliation.
7. A receipt is accepted only when its effect, idempotency key, evidence, lineage, target, attempt ID and fence bind to the stored contract/attempt.
8. A stale fence may be recorded as evidence but cannot change current effect state.
9. Retry requires both authoritative reconciliation to `NO_EFFECT` and a fresh explicit retry authorization.
10. Governance changes fail closed.
11. Restart must preserve state version, attempts, fences and receipt history.
12. No gateway operation grants AIOS authority.

## Mutation protocol

```text
LOCK
  -> RELOAD
  -> VALIDATE current state + bindings + transition
  -> APPEND immutable attempt/receipt/reconciliation event
  -> UPDATE materialized state
  -> INCREMENT version
  -> ATOMIC SAVE
UNLOCK
```

The JSON store remains the current stdlib-only persistence format. The lock plus reload-before-write protocol is mandatory for cross-process correctness; thread-only tests are not evidence of cross-process safety.

## Verification gate

The lifecycle is not considered implemented until tests cover:

- real multi-process attempt allocation;
- concurrent receipt persistence;
- stale-fence receipt rejection of state mutation;
- receipt history preservation across multiple attempts;
- restart durability;
- crash/ambiguity reconciliation;
- explicit retry authorization;
- terminal-state fencing;
- governance/identity/target/idempotency fail-closed behavior.
