# External Effect Contract

This repository implements the boundary, not the AIOS control plane.

## Ownership

| Field | Owner | Gateway role |
|---|---|---|
| `effect_id` | AIOS | bind and persist |
| `action` | AIOS/domain contract | bind and persist |
| `capability_ref` | AIOS capability registry | bind; never mint |
| `authority_ref` | AIOS authority/permit layer | require; never mint |
| `evidence_ref` | AIOS/domain evidence | require on effect contract and receipt |
| `lineage_ref` | AIOS/domain lineage | require on effect contract and receipt |
| `idempotency_key` | effect producer | bind and persist |
| `attempt_id` | gateway | allocate monotonically per ticket |
| `target_sha` | gateway ticket / worker contract | exact revision fence |
| `governance_digest` | protected governance snapshot | recheck before authorization/effect |
| `receipt.status` | worker/verifier | persist; never upgrade unknown to success |

## Boundary flow

```text
AIOS
  contract + capability + authority + evidence + lineage
                    |
                    v
             HUMAN-AUTH GATEWAY
       identity / nonce / expiry / target
                    |
                    v
                 ATTEMPT
                    |
                    v
             external worker
                    |
                    v
                RECEIPT
          evidence + lineage + status
                    |
                    v
                 AIOS
```

TRY, RX50, and Android remain domain execution/evidence substrates. They may
produce evidence and workload-specific semantics, but they must not become a
second authority owner.

## Absorbed patterns

The implementation selectively absorbs externally validated harness patterns:

- durable, fail-closed execution boundaries;
- portable contract/evidence state rather than provider-specific session state;
- policy/approval/evidence/receipt separation;
- validate-before-effect and atomic state persistence;
- explicit attempt identity and terminal settlement;
- adapters outside the governance core.

These patterns are adapted to the existing AIOS boundary instead of copying
another project's control plane.


## Protocol v5 — governed retry attempt

A retry is not a verification retry. `RETRY_EFFECT` accepts only an AIOS Ed25519-signed `AIOS_GATEWAY_RETRY_PERMIT_V1`. Gateway is configured with pinned AIOS public keys only (`AIOS_GATEWAY_RETRY_PUBLIC_KEYS`, JSON map of key ID to 32-byte public-key hex); it never receives the AIOS private key or an issuer HMAC secret.

The permit binds the effect, contract, AIOS authority permit, actor, ticket, target SHA, exact previous Gateway attempt and fence, exact previous Gateway receipt digest, signed provider operation-receipt digest, AIOS reconciliation-evidence digest, decision identity, next attempt number/ID/fence, nonce, and validity window. Gateway accepts only `reconciliation_outcome=PROVEN_NOT_SUBMITTED`. It verifies the signature and all local durable bindings, consumes the nonce/permit once, and atomically appends the next attempt with `fence=prior_fence+1`.

An exact replay of a consumed permit returns the same attempt with `execute_allowed=false`; a changed permit under the same ID, nonce reuse, stale receipt digest, stale fence, wrong target/effect/actor/authority, expired permit, or non-increasing fence is rejected. A crash after Gateway allocation but before AIOS mapping therefore cannot authorize a second provider execution.

Gateway does not decide whether non-submission is proven. It trusts only the signed AIOS permit. AIOS must verify the TRY operation receipt against its pinned provider key, and must not issue the permit for `UNKNOWN`, `COMPLETED`, or an ambiguous provider failure.
