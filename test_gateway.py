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


if __name__ == "__main__":
    unittest.main()