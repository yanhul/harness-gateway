import tempfile
import unittest
from pathlib import Path

from gateway import AuthorizationError, Gateway, GatewayError

GOV = {k: f"digest-{k}" for k in ("policy", "evidence_criteria", "promotion_criteria", "terminal_conditions", "trust_roots")}
CONTRACT = {
    "effect_id": "E1",
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


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.g = Gateway(Path(self.tmp.name) / "state.json", "+84999", GOV, self.clock)
        self.g.create_ticket("T1", "yanhul/try", "abc123", "N1", 60, CONTRACT)

    def tearDown(self):
        self.tmp.cleanup()

    def _authorize_and_begin(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        return self.g.begin_effect("T1", "abc123")

    def _receipt(self, effect, **overrides):
        receipt = {
            "ticket_id": "T1",
            "attempt_id": effect["attempt_id"],
            "target_sha": "abc123",
            "effect_id": effect["effect_id"],
            "idempotency_key": effect["idempotency_key"],
            "status": "COMPLETED",
            "evidence_ref": effect["evidence_ref"],
            "lineage_ref": effect["lineage_ref"],
        }
        receipt.update(overrides)
        return receipt

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

    def test_effect_requires_aios_contract(self):
        g2 = Gateway(Path(self.tmp.name) / "no-contract.json", "+84999", GOV, self.clock)
        g2.create_ticket("T2", "yanhul/try", "abc123", "N2", 60)
        g2.authorize("T2", "N2", "+84999", "abc123")
        with self.assertRaises(AuthorizationError):
            g2.begin_effect("T2", "abc123")

    def test_cross_ticket_idempotency_key_is_rejected(self):
        other = dict(CONTRACT, effect_id="E2")
        with self.assertRaises(GatewayError):
            self.g.create_ticket("T2", "yanhul/try", "def456", "N2", 60, other)

    def test_receipt_requires_exact_contract_binding(self):
        effect = self._authorize_and_begin()
        for field in ("effect_id", "idempotency_key", "evidence_ref", "lineage_ref"):
            bad = self._receipt(effect, **{field: "forged"})
            with self.subTest(field=field):
                with self.assertRaises(GatewayError):
                    self.g.record_receipt("T1", bad)

    def test_receipt_cannot_cross_attempt_or_target(self):
        effect = self._authorize_and_begin()
        with self.assertRaises(GatewayError):
            self.g.record_receipt("T1", self._receipt(effect, attempt_id="T1:9"))
        with self.assertRaises(GatewayError):
            self.g.record_receipt("T1", self._receipt(effect, target_sha="wrong"))

    def test_unknown_is_not_success_and_can_be_retried(self):
        effect = self._authorize_and_begin()
        t = self.g.record_receipt("T1", self._receipt(effect, status="UNKNOWN"))
        self.assertEqual(t.state, "AUTHORIZED")
        self.assertEqual(t.last_receipt["status"], "UNKNOWN")
        retry = self.g.retry_verify_only("T1", "+84999")
        self.assertEqual(retry.state, "AUTHORIZED")

    def test_failed_is_retryable_but_completed_is_terminal(self):
        effect = self._authorize_and_begin()
        t = self.g.record_receipt("T1", self._receipt(effect, status="FAILED"))
        self.assertEqual(t.state, "FAILED")
        retry = self.g.retry_verify_only("T1", "+84999")
        self.assertEqual(retry.state, "FAILED")
        with self.assertRaises(AuthorizationError):
            self.g.begin_effect("T1", "abc123")

    def test_completed_receipt_is_terminal_and_replay_is_rejected(self):
        effect = self._authorize_and_begin()
        receipt = self._receipt(effect)
        t = self.g.record_receipt("T1", receipt)
        self.assertEqual(t.state, "COMPLETED")
        with self.assertRaises(GatewayError):
            self.g.record_receipt("T1", receipt)
        with self.assertRaises(AuthorizationError):
            self.g.begin_effect("T1", "abc123")

    def test_stop_revokes_pending_and_authorized(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        self.g.stop("+84999")
        self.assertEqual(self.g.status()["revoked"], True)
        self.assertEqual(self.g.status()["tickets"]["T1"]["state"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
