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
