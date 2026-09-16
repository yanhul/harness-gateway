# Harness Gateway

A fail-closed, human-authorized effect gateway for **AIOS, try, android-ai-assistant, and RX50**.

The repository now contains an executable state machine, not only a protocol document. The gateway is a **boundary component**, not a second AIOS control plane.

## Boundary

```text
AIOS CONTROL PLANE
  policy / authority / capability / evidence / lineage
                 |
                 v
        HARNESS GATEWAY
  human authorization / effect binding / receipt
                 |
        +--------+---------+
        |        |         |
       TRY      RX50    ANDROID
```

AIOS remains the authority owner. Repository adapters remain responsible for their domain evidence/workload semantics. The gateway prevents a repair effect from crossing the boundary without an explicit, bound authorization.

## Effect contract v3

`CREATE` persists the AIOS-supplied effect contract. The gateway requires these fields before `BEGIN_EFFECT` can cross the external boundary:

- `effect_id`
- `action`
- `capability_ref`
- `authority_ref`
- `evidence_ref`
- `lineage_ref`
- `idempotency_key`

The gateway never creates authority or capability records. It only binds them to the human-approved ticket, exact `target_sha`, generated `attempt_id`, and returned receipt. See `EFFECT_CONTRACT.md`.

## Fail-closed invariants

1. Exact human sender identity is required for authorization/rejection/stop/retry.
2. `SUA` consumes a one-time nonce; replay is rejected.
3. Ticket expiry is enforced.
4. Repository and exact target commit SHA are bound to the ticket.
5. Protected governance digests are snapshotted at ticket creation and rechecked before authorization/effect.
6. Effects require an `AUTHORIZED` ticket and the exact target SHA.
7. Each effect gets a monotonic `attempt_id` bound to the ticket.
8. Receipts bind `ticket_id`, `attempt_id`, `target_sha`, `effect_id`, `evidence_ref`, and `lineage_ref`.
9. `STOP` revokes all pending/authorized tickets.
10. State persistence is atomic (`fsync` + `os.replace`).
11. The gateway has no GitHub credentials and executes no shell/repository mutation.
12. A worker must independently enforce the target SHA and return a bound receipt.

## Commands

- `CREATE` — create an immutable repair ticket and governance snapshot.
- `SUA` — human authorization for exactly one ticket/nonce/target.
- `BOQUA` — reject a pending ticket.
- `BEGIN_EFFECT` — issue a bound attempt after authorization.
- `RECEIPT` — persist the worker's bound result.
- `RETRY` — verification-only retry; it does not authorize code changes.
- `STATUS` — inspect persisted state.
- `STOP` — revoke pending and authorized work.

The canonical machine-readable contract is `protocol.json` (v3).

## Transport

`gateway_cli.py` provides a JSONL transport for local or supervised deployment. SMS, Android, GitHub, CI, and repair-worker integrations belong outside the core state machine. They must not become authority owners.

## Verification

Run:

```bash
python -m unittest -v test_gateway.py
```

The tests cover sender/target mismatch, nonce replay, governance mutation, expiry, missing AIOS contract, cross-effect receipt replay, unauthorized effects, receipt binding, and emergency stop.
