# GitHub webhook contract

Configure one `workflow_run` webhook for each of:

- `yanhul/AIOS`
- `yanhul/try`
- `yanhul/android-ai-assistant`
- `yanhul/RX50`

The webhook endpoint is `POST /github/webhook`.

## Authentication

GitHub must send `X-Hub-Signature-256`. The gateway verifies the signature over the exact request body with `GITHUB_WEBHOOK_SECRET`. Invalid or missing signatures are rejected before parsing.

## Accepted event

Only `workflow_run` failure-like conclusions are eligible: `failure`, `timed_out`, `cancelled`. The payload must contain a repository full name in the four-repo allowlist, workflow name, positive run id, exact 40-character `head_sha`, exact GitHub `html_url`, and a 64-character hexadecimal `governance_digest` supplied by the trusted harness producer.

The ticket idempotency key is:

`repo | workflow | run_id | head_sha`

Duplicate deliveries return the existing ticket and do not issue a second repair ticket.

## Trust boundary

The gateway creates the ticket and human-approval boundary. It does not receive GitHub write credentials and does not modify the target repository. A repair worker must separately validate the exact repo/SHA/governance digest before any write.
