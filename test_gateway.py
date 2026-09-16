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
            self.g.record_receipt("T1", {"ticket_id": "T1", "attempt_id": "T1:9", "target_sha": "abc123", "effect_id": "E1", "status": "COMPLETED", "evidence_ref": "evidence:x", "lineage_ref": "lineage:x"})
        t = self.g.record_receipt("T1", {"ticket_id": "T1", "attempt_id": "T1:1", "target_sha": "abc123", "effect_id": "E1", "status": "COMPLETED", "evidence_ref": "evidence:x", "lineage_ref": "lineage:x"})
        self.assertEqual(t.state, "COMPLETED")

    def test_receipt_cannot_cross_effect(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        self.g.begin_effect("T1", "abc123")
        bad = {"ticket_id": "T1", "attempt_id": "T1:1", "target_sha": "abc123", "effect_id": "OTHER", "status": "COMPLETED", "evidence_ref": "evidence:x", "lineage_ref": "lineage:x"}
        with self.assertRaises(GatewayError):
            self.g.record_receipt("T1", bad)

    def test_stop_revokes_pending_and_authorized(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")
        self.g.stop("+84999")
        self.assertEqual(self.g.status()["revoked"], True)
        self.assertEqual(self.g.status()["tickets"]["T1"]["state"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
