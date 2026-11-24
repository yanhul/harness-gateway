import tempfile
import unittest
import hashlib
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pathlib import Path

from gateway import AuthorizationError, Gateway, GatewayError

GOV = {k: f"digest-{k}" for k in ("policy", "evidence_criteria", "promotion_criteria", "terminal_conditions", "trust_roots")}
CONTRACT = {
    "effect_id": "E1",
    "contract_id": "C1",
    "actor": "aios",
    "action": "repair",
    "capability_ref": "capability:repo-repair@1",
    "authority_ref": "aios:permit:P1",
    "evidence_ref": "evidence:failure:F1",
    "lineage_ref": "lineage:run:R1",
    "idempotency_key": "idem:E1",
}


class Clock:
    value = 1000.0
    def __call__(self):
        return self.value


def _retry_keypair():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = "ed25519:" + hashlib.sha256(public).hexdigest()[:32]
    return private, key_id, public.hex()


def _signed_retry_permit(private, key_id, *, prior_receipt_digest, **overrides):
    now = 1000.0
    body = {
        "type": "AIOS_GATEWAY_RETRY_PERMIT_V1", "permit_id": "GRP-" + "a" * 32,
        "key_id": key_id, "algorithm": "Ed25519", "effect_id": "E1", "contract_id": "C1",
        "authority_ref": "aios:permit:P1", "actor": "aios", "issuer": "operator:human",
        "retry_authorization_id": "RA-" + "d" * 32, "ticket_id": "T1", "target_sha": "abc123",
        "prior_gateway_attempt_id": "T1:1", "prior_fence": 1,
        "prior_gateway_receipt_digest": prior_receipt_digest,
        "operation_receipt_digest": "b" * 64, "reconciliation_evidence_digest": "c" * 64,
        "reconciliation_outcome": "PROVEN_NOT_SUBMITTED", "decision_id": "DEC-RETRY-1",
        "next_attempt_number": 2, "next_attempt_id": "T1:2", "next_fence": 2,
        "nonce": "nonce-retry-1", "issued_at": now, "expires_at": now + 300,
    }
    body.update(overrides)
    signature = private.sign(__import__("gateway").canonical_json(body).encode()).hex()
    return {**body, "signature": signature}


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.g = Gateway(Path(self.tmp.name) / "state.json", "+84999", GOV, self.clock)
        self.g.create_ticket("T1", "yanhul/try", "abc123", "N1", 60, CONTRACT)

    def tearDown(self):
        self.tmp.cleanup()

    def test_authorize_requires_exact_human_and_target(self):
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84000", "abc123")
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84999", "wrong")
        t = self.g.authorize("T1", "N1", "+84999", "abc123")
        self.assertEqual(t.state, "AUTHORIZED")

    def test_nonce_is_one_time(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84999", "abc123")

    def test_governance_change_fails_closed(self):
        self.g.governance["policy"] = "changed"
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84999", "abc123")

    def test_expiry_fails_closed(self):
        self.clock.value = 1060.0
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84999", "abc123")
        self.assertEqual(self.g.status()["tickets"]["T1"]["state"], "EXPIRED")

    def test_effect_requires_aios_contract_and_receipt_is_bound(self):
        g2 = Gateway(Path(self.tmp.name) / "no-contract.json", "+84999", GOV, self.clock)
        g2.create_ticket("T2", "yanhul/try", "abc123", "N2", 60)
        g2.authorize("T2", "N2", "+84999", "abc123")
        with self.assertRaises(AuthorizationError):
            g2.begin_effect("T2", "abc123")

        self.g.authorize("T1", "N1", "+84999", "abc123")
        effect = self.g.begin_effect("T1", "abc123")
        self.assertEqual(effect["attempt_id"], "T1:1")
        self.assertEqual(effect["authority_ref"], CONTRACT["authority_ref"])
        with self.assertRaises(GatewayError):
            self.g.record_receipt("T1", {"ticket_id": "T1", "attempt_id": "T1:9", "attempt_fence": 1, "target_sha": "abc123", "effect_id": "E1", "status": "COMPLETED", "evidence_ref": CONTRACT["evidence_ref"], "lineage_ref": CONTRACT["lineage_ref"]})
        t = self.g.record_receipt("T1", {"ticket_id": "T1", "attempt_id": "T1:1", "attempt_fence": 1, "target_sha": "abc123", "effect_id": "E1", "status": "COMPLETED", "evidence_ref": CONTRACT["evidence_ref"], "lineage_ref": CONTRACT["lineage_ref"]})
        self.assertEqual(t.state, "COMPLETED")

    def test_receipt_cannot_cross_effect(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        self.g.begin_effect("T1", "abc123")
        bad = {"ticket_id": "T1", "attempt_id": "T1:1", "attempt_fence": 1, "target_sha": "abc123", "effect_id": "OTHER", "status": "COMPLETED", "evidence_ref": CONTRACT["evidence_ref"], "lineage_ref": CONTRACT["lineage_ref"]}
        with self.assertRaises(GatewayError):
            self.g.record_receipt("T1", bad)


    def test_receipt_must_match_exact_attempt_fence(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        effect = self.g.begin_effect("T1", "abc123")
        receipt = {
            "ticket_id": "T1", "attempt_id": effect["attempt_id"],
            "attempt_fence": effect["fence"] + 1, "target_sha": "abc123",
            "effect_id": CONTRACT["effect_id"], "status": "COMPLETED",
            "evidence_ref": CONTRACT["evidence_ref"],
            "lineage_ref": CONTRACT["lineage_ref"],
        }
        with self.assertRaisesRegex(GatewayError, "attempt fence"):
            self.g.record_receipt("T1", receipt)
        receipt["attempt_fence"] = True
        with self.assertRaisesRegex(GatewayError, "fence is invalid"):
            self.g.record_receipt("T1", receipt)

    def test_stop_revokes_pending_and_authorized(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        self.g.stop("+84999")
        self.assertEqual(self.g.status()["revoked"], True)
        self.assertEqual(self.g.status()["tickets"]["T1"]["state"], "REJECTED")


    def test_attempt_and_receipt_history_survive_restart_with_hash_chained_events(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        effect = self.g.begin_effect("T1", "abc123")
        receipt = {
            "ticket_id": "T1", "attempt_id": effect["attempt_id"], "attempt_fence": effect["fence"],
            "target_sha": "abc123", "effect_id": CONTRACT["effect_id"],
            "status": "UNKNOWN", "evidence_ref": CONTRACT["evidence_ref"],
            "lineage_ref": CONTRACT["lineage_ref"],
        }
        self.g.record_receipt("T1", receipt)
        reopened = Gateway(self.g.path, "+84999", GOV, self.clock)
        status = reopened.status()
        ticket = status["tickets"]["T1"]
        self.assertEqual(len(ticket["attempt_history"]), 1)
        self.assertEqual(len(ticket["receipt_history"]), 1)
        self.assertEqual(ticket["attempt_history"][0]["status"], "UNKNOWN")
        self.assertEqual(ticket["attempt_history"][0]["fence"], 1)
        self.assertEqual([e["sequence"] for e in status["events"]], list(range(1, len(status["events"]) + 1)))
        self.assertEqual(status["version"], 3)

    def test_begin_effect_replay_returns_same_attempt_without_execution_authority(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        first = self.g.begin_effect("T1", "abc123")
        replay = self.g.begin_effect("T1", "abc123")
        self.assertEqual(first["attempt_id"], replay["attempt_id"])
        self.assertTrue(first["execute_allowed"])
        self.assertFalse(replay["execute_allowed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(self.g.status()["tickets"]["T1"]["attempts"], 1)

    def test_receipt_must_match_aios_evidence_and_lineage_refs(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        effect = self.g.begin_effect("T1", "abc123")
        receipt = {
            "ticket_id": "T1", "attempt_id": effect["attempt_id"], "attempt_fence": effect["fence"],
            "target_sha": "abc123", "effect_id": CONTRACT["effect_id"],
            "status": "COMPLETED", "evidence_ref": "evidence:forged",
            "lineage_ref": CONTRACT["lineage_ref"],
        }
        with self.assertRaisesRegex(GatewayError, "evidence binding"):
            self.g.record_receipt("T1", receipt)

    def test_unknown_receipt_can_only_be_reconciled_not_replayed(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        first = self.g.begin_effect("T1", "abc123")
        unknown = {
            "ticket_id": "T1", "attempt_id": first["attempt_id"], "attempt_fence": first["fence"],
            "target_sha": "abc123", "effect_id": CONTRACT["effect_id"],
            "status": "UNKNOWN", "evidence_ref": CONTRACT["evidence_ref"],
            "lineage_ref": CONTRACT["lineage_ref"],
        }
        self.g.record_receipt("T1", unknown)
        replay = self.g.begin_effect("T1", "abc123")
        self.assertEqual(replay["attempt_id"], first["attempt_id"])
        self.assertFalse(replay["execute_allowed"])
        settled = dict(unknown, status="COMPLETED")
        self.g.record_receipt("T1", settled)
        self.assertEqual(len(self.g.status()["tickets"]["T1"]["receipt_history"]), 2)
        self.g.record_receipt("T1", unknown)  # exact duplicate is idempotent
        final_ticket = self.g.status()["tickets"]["T1"]
        self.assertEqual(final_ticket["state"], "COMPLETED")
        self.assertEqual(len(final_ticket["receipt_history"]), 2)

    def test_concurrent_gateway_instances_reload_before_mutation(self):
        other = Gateway(self.g.path, "+84999", GOV, self.clock)
        self.g.authorize("T1", "N1", "+84999", "abc123")
        effect = other.begin_effect("T1", "abc123")
        self.assertEqual(effect["attempt_id"], "T1:1")
        self.assertEqual(len(self.g.status()["tickets"]["T1"]["attempt_history"]), 1)

    def test_event_chain_tampering_fails_closed(self):
        self.g.create_ticket("T2", "yanhul/try", "abc123", "N2", 60, CONTRACT)
        data = self.g.status()
        data["events"][0]["payload"]["target_sha"] = "tampered"
        self.g.path.write_text(__import__("json").dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(GatewayError, "event hash mismatch"):
            Gateway(self.g.path, "+84999", GOV, self.clock)


    def test_parallel_begin_effect_allocates_one_execution_attempt(self):
        from concurrent.futures import ThreadPoolExecutor
        self.g.authorize("T1", "N1", "+84999", "abc123")
        other = Gateway(self.g.path, "+84999", GOV, self.clock)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda gateway: gateway.begin_effect("T1", "abc123"), (self.g, other)))
        self.assertEqual({r["attempt_id"] for r in results}, {"T1:1"})
        self.assertEqual(sum(bool(r["execute_allowed"]) for r in results), 1)
        self.assertEqual(len(self.g.status()["tickets"]["T1"]["attempt_history"]), 1)

    def test_legacy_v2_attempt_without_history_fails_closed(self):
        legacy = {
            "version": 2, "revoked": False,
            "tickets": {"T1": {
                "ticket_id": "T1", "repository": "yanhul/try", "target_sha": "abc123",
                "nonce": "N1", "expires_at": 2000.0, "governance": GOV,
                "state": "AUTHORIZED", "approved_by": "+84999", "nonce_used": True,
                "attempts": 1, "last_receipt": None, "created_at": 1000.0,
                "effect_contract": CONTRACT,
            }},
        }
        self.g.path.write_text(__import__("json").dumps(legacy), encoding="utf-8")
        migrated = Gateway(self.g.path, "+84999", GOV, self.clock)
        with self.assertRaisesRegex(GatewayError, "legacy attempt count"):
            migrated.begin_effect("T1", "abc123")


    def test_cli_create_persists_the_aios_effect_contract(self):
        import json
        import subprocess
        import sys
        request = {
            "command": "CREATE", "ticket": "CLI-1", "repository": "yanhul/try",
            "target_sha": "abc123", "nonce": "CLI-N1", "ttl_seconds": 60,
            "effect_contract": CONTRACT,
        }
        completed = subprocess.run(
            [sys.executable, "gateway_cli.py", "--state", str(Path(self.tmp.name) / "cli.json"),
             "--human-identity", "+84999", "--governance", json.dumps(GOV)],
            input=json.dumps(request) + "\n", text=True, capture_output=True, check=True,
        )
        result = json.loads(completed.stdout.strip())
        self.assertTrue(result["ok"])
        self.assertEqual(result["ticket"]["effect_contract"], CONTRACT)


    def _unknown_prior(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        first = self.g.begin_effect("T1", "abc123")
        receipt = {
            "ticket_id": "T1", "attempt_id": first["attempt_id"], "attempt_fence": first["fence"],
            "target_sha": "abc123", "effect_id": "E1", "status": "UNKNOWN",
            "evidence_ref": CONTRACT["evidence_ref"], "lineage_ref": CONTRACT["lineage_ref"],
        }
        self.g.record_receipt("T1", receipt)
        digest = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        return first, digest

    def _retry_gateway(self):
        private, key_id, public = _retry_keypair()
        self.g = Gateway(self.g.path, "+84999", GOV, self.clock, {key_id: public})
        return private, key_id

    def test_retry_effect_requires_signed_aios_permit_and_proven_non_submission(self):
        self._unknown_prior()
        private, key_id = self._retry_gateway()
        with self.assertRaisesRegex(AuthorizationError, "schema mismatch"):
            self.g.retry_effect("T1", {})
        permit = _signed_retry_permit(private, key_id, prior_receipt_digest=self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"])
        result = self.g.retry_effect("T1", permit)
        self.assertEqual(result["attempt_id"], "T1:2")
        self.assertEqual(result["fence"], 2)
        self.assertTrue(result["execute_allowed"])
        self.assertFalse(result["replayed"])

    def test_retry_effect_exact_replay_is_non_executable_after_restart(self):
        self._unknown_prior()
        private, key_id = self._retry_gateway()
        permit = _signed_retry_permit(private, key_id, prior_receipt_digest=self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"])
        first = self.g.retry_effect("T1", permit)
        reopened = Gateway(self.g.path, "+84999", GOV, self.clock, self.g.retry_permit_public_keys)
        replay = reopened.retry_effect("T1", permit)
        self.assertEqual(first["attempt_id"], replay["attempt_id"])
        self.assertEqual(replay["fence"], first["fence"])
        self.assertTrue(replay["replayed"])
        self.assertFalse(replay["execute_allowed"])
        self.assertEqual(reopened.status()["tickets"]["T1"]["attempts"], 2)

    def test_retry_effect_rejects_tampered_signature_and_stale_receipt(self):
        self._unknown_prior()
        private, key_id = self._retry_gateway()
        digest = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        permit = _signed_retry_permit(private, key_id, prior_receipt_digest=digest)
        tampered = dict(permit, actor="agent:attacker")
        with self.assertRaisesRegex(AuthorizationError, "signature is invalid"):
            self.g.retry_effect("T1", tampered)
        stale = _signed_retry_permit(private, key_id, prior_receipt_digest="d" * 64)
        with self.assertRaisesRegex(AuthorizationError, "prior_gateway_receipt_digest"):
            self.g.retry_effect("T1", stale)

    def test_retry_effect_requires_pinned_signer_and_unexpired_permit(self):
        self._unknown_prior()
        private, key_id = self._retry_gateway()
        digest = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        permit = _signed_retry_permit(private, key_id, prior_receipt_digest=digest)
        unpinned = Gateway(self.g.path, "+84999", GOV, self.clock, {})
        with self.assertRaisesRegex(AuthorizationError, "signer is not pinned"):
            unpinned.retry_effect("T1", permit)
        expired = _signed_retry_permit(
            private, key_id, prior_receipt_digest=digest,
            permit_id="GRP-" + "9" * 32, nonce="expired-nonce",
            issued_at=100.0, expires_at=200.0,
        )
        with self.assertRaisesRegex(AuthorizationError, "expired or issued in the future"):
            self.g.retry_effect("T1", expired)

    def test_retry_effect_rejects_completed_prior_attempt_even_with_aios_signature(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        first = self.g.begin_effect("T1", "abc123")
        completed = {
            "ticket_id": "T1", "attempt_id": first["attempt_id"], "attempt_fence": first["fence"],
            "target_sha": "abc123", "effect_id": "E1", "status": "COMPLETED",
            "evidence_ref": CONTRACT["evidence_ref"], "lineage_ref": CONTRACT["lineage_ref"],
        }
        self.g.record_receipt("T1", completed)
        private, key_id, public = _retry_keypair()
        self.g = Gateway(self.g.path, "+84999", GOV, self.clock, {key_id: public})
        digest = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        permit = _signed_retry_permit(private, key_id, prior_receipt_digest=digest)
        with self.assertRaisesRegex(AuthorizationError, "retry requires a live authorized/failed ticket"):
            self.g.retry_effect("T1", permit)

    def test_retry_effect_rejects_unknown_without_proven_non_submission(self):
        self._unknown_prior()
        private, key_id = self._retry_gateway()
        digest = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        permit = _signed_retry_permit(private, key_id, prior_receipt_digest=digest,
                                      reconciliation_outcome="UNKNOWN")
        with self.assertRaisesRegex(AuthorizationError, "proven non-submission"):
            self.g.retry_effect("T1", permit)
        self.assertEqual(self.g.status()["tickets"]["T1"]["attempts"], 1)

    def test_retry_fence_increases_monotonically_for_next_permit(self):
        self._unknown_prior()
        private, key_id = self._retry_gateway()
        digest1 = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        permit1 = _signed_retry_permit(private, key_id, prior_receipt_digest=digest1)
        attempt2 = self.g.retry_effect("T1", permit1)
        receipt2 = {
            "ticket_id": "T1", "attempt_id": attempt2["attempt_id"], "attempt_fence": attempt2["fence"],
            "target_sha": "abc123", "effect_id": "E1", "status": "UNKNOWN",
            "evidence_ref": CONTRACT["evidence_ref"], "lineage_ref": CONTRACT["lineage_ref"],
        }
        self.g.record_receipt("T1", receipt2)
        digest2 = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        permit2 = _signed_retry_permit(
            private, key_id, prior_receipt_digest=digest2,
            permit_id="GRP-" + "e" * 32, prior_gateway_attempt_id="T1:2", prior_fence=2,
            next_attempt_number=3, next_attempt_id="T1:3", next_fence=3,
            nonce="nonce-retry-2", decision_id="DEC-RETRY-2",
        )
        attempt3 = self.g.retry_effect("T1", permit2)
        self.assertEqual(attempt3["attempt_id"], "T1:3")
        self.assertEqual(attempt3["fence"], 3)

    def test_retry_permit_nonce_cannot_be_reused_for_another_ticket(self):
        self._unknown_prior()
        private, key_id = self._retry_gateway()
        digest = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        permit = _signed_retry_permit(private, key_id, prior_receipt_digest=digest)
        first = self.g.retry_effect("T1", permit)
        receipt2 = {
            "ticket_id": "T1", "attempt_id": first["attempt_id"], "attempt_fence": first["fence"],
            "target_sha": "abc123", "effect_id": "E1", "status": "UNKNOWN",
            "evidence_ref": CONTRACT["evidence_ref"], "lineage_ref": CONTRACT["lineage_ref"],
        }
        self.g.record_receipt("T1", receipt2)
        digest2 = self.g.status()["tickets"]["T1"]["receipt_history"][-1]["digest"]
        reused_nonce = _signed_retry_permit(
            private, key_id, prior_receipt_digest=digest2,
            permit_id="GRP-" + "f" * 32, prior_gateway_attempt_id="T1:2", prior_fence=2,
            next_attempt_number=3, next_attempt_id="T1:3", next_fence=3,
            decision_id="DEC-RETRY-3",
        )
        with self.assertRaisesRegex(AuthorizationError, "nonce already consumed"):
            self.g.retry_effect("T1", reused_nonce)


if __name__ == "__main__":
    unittest.main()