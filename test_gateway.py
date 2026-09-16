import multiprocessing
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


def begin_worker(path: str, queue):
    try:
        gateway = Gateway(path, "+84999", GOV)
        queue.put(("ok", gateway.begin_effect("T1", "abc123")))
    except Exception as exc:  # noqa: BLE001 - subprocess test boundary
        queue.put(("error", type(exc).__name__, str(exc)))


def receipt_worker(path: str, receipt: dict, queue):
    try:
        gateway = Gateway(path, "+84999", GOV)
        gateway.record_receipt("T1", receipt)
        queue.put(("ok", receipt["attempt_id"]))
    except Exception as exc:  # noqa: BLE001 - subprocess test boundary
        queue.put(("error", type(exc).__name__, str(exc)))


class Clock:
    value = 1000.0
    def __call__(self):
        return self.value


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.path = Path(self.tmp.name) / "state.json"
        self.g = Gateway(self.path, "+84999", GOV, self.clock)
        self.g.create_ticket("T1", "yanhul/try", "abc123", "N1", 60, CONTRACT)

    def tearDown(self):
        self.tmp.cleanup()

    def _authorize(self):
        self.g.authorize("T1", "N1", "+84999", "abc123")

    def _begin(self):
        return self.g.begin_effect("T1", "abc123")

    def _receipt(self, effect, status="COMPLETED", **overrides):
        receipt = {
            "ticket_id": "T1",
            "attempt_id": effect["attempt_id"],
            "attempt_fence": effect["attempt_fence"],
            "target_sha": "abc123",
            "effect_id": effect["effect_id"],
            "idempotency_key": effect["idempotency_key"],
            "status": status,
            "evidence_ref": effect["evidence_ref"],
            "lineage_ref": effect["lineage_ref"],
        }
        receipt.update(overrides)
        return receipt

    def _retry(self, effect):
        self.g.record_receipt("T1", self._receipt(effect, status="UNKNOWN"))
        self.g.retry_verify_only("T1", "+84999")
        self.g.reconcile("T1", effect["attempt_id"], "+84999", "NO_EFFECT", "verify:no-effect")
        self.g.authorize_retry("T1", "+84999")

    def test_authorize_requires_exact_human_and_target(self):
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84000", "abc123")
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84999", "wrong")
        self.assertEqual(self.g.authorize("T1", "N1", "+84999", "abc123").state, "AUTHORIZED")

    def test_nonce_is_one_time(self):
        self._authorize()
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84999", "abc123")

    def test_governance_change_fails_closed(self):
        self.g.governance["policy"] = "changed"
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84999", "abc123")

    def test_expiry_is_persisted(self):
        self.clock.value = 1060.0
        with self.assertRaises(AuthorizationError):
            self.g.authorize("T1", "N1", "+84999", "abc123")
        restarted = Gateway(self.path, "+84999", GOV, self.clock)
        self.assertEqual(restarted.status()["tickets"]["T1"]["state"], "EXPIRED")

    def test_effect_requires_aios_contract(self):
        path = Path(self.tmp.name) / "no-contract.json"
        g2 = Gateway(path, "+84999", GOV, self.clock)
        g2.create_ticket("T2", "yanhul/try", "abc123", "N2", 60)
        g2.authorize("T2", "N2", "+84999", "abc123")
        with self.assertRaises(AuthorizationError):
            g2.begin_effect("T2", "abc123")

    def test_cross_ticket_idempotency_key_is_rejected(self):
        with self.assertRaises(GatewayError):
            self.g.create_ticket("T2", "yanhul/try", "def456", "N2", 60, dict(CONTRACT, effect_id="E2"))

    def test_receipt_requires_exact_contract_binding_and_fence(self):
        self._authorize()
        effect = self._begin()
        for field in ("effect_id", "idempotency_key", "evidence_ref", "lineage_ref", "attempt_fence"):
            bad = self._receipt(effect, **{field: "forged"})
            with self.subTest(field=field):
                with self.assertRaises(GatewayError):
                    self.g.record_receipt("T1", bad)

    def test_unknown_never_becomes_dispatchable_without_reconciliation_and_retry_auth(self):
        self._authorize()
        effect = self._begin()
        self.g.record_receipt("T1", self._receipt(effect, status="UNKNOWN"))
        self.assertEqual(self.g.status()["tickets"]["T1"]["state"], "RECONCILING")
        with self.assertRaises(AuthorizationError):
            self.g.begin_effect("T1", "abc123")
        self.g.retry_verify_only("T1", "+84999")
        self.g.reconcile("T1", effect["attempt_id"], "+84999", "NO_EFFECT", "verify:no-effect")
        self.assertFalse(self.g.status()["tickets"]["T1"]["retry_authorized"])
        with self.assertRaises(AuthorizationError):
            self.g.begin_effect("T1", "abc123")
        self.g.authorize_retry("T1", "+84999")
        second = self._begin()
        self.assertEqual(second["attempt_id"], "T1:2")

    def test_failed_requires_reconciliation_before_retry(self):
        self._authorize()
        effect = self._begin()
        self.g.record_receipt("T1", self._receipt(effect, status="FAILED"))
        self.g.reconcile("T1", effect["attempt_id"], "+84999", "NO_EFFECT", "verify:failed-no-effect")
        with self.assertRaises(AuthorizationError):
            self.g.begin_effect("T1", "abc123")
        self.g.authorize_retry("T1", "+84999")
        self.assertEqual(self._begin()["attempt_id"], "T1:2")

    def test_reconcile_effected_is_terminal(self):
        self._authorize()
        effect = self._begin()
        self.g.record_receipt("T1", self._receipt(effect, status="UNKNOWN"))
        self.g.reconcile("T1", effect["attempt_id"], "+84999", "EFFECTED", "verify:effected")
        with self.assertRaises(AuthorizationError):
            self.g.authorize_retry("T1", "+84999")
        with self.assertRaises(GatewayError):
            self.g.record_receipt("T1", self._receipt(effect, status="COMPLETED"))

    def test_stale_worker_receipt_is_recorded_but_cannot_mutate_new_attempt(self):
        self._authorize()
        first = self._begin()
        self._retry(first)
        second = self._begin()
        stale = self._receipt(first, status="COMPLETED")
        self.g.record_receipt("T1", stale)
        status = self.g.status()["tickets"]["T1"]
        self.assertEqual(status["state"], "ATTEMPT_OPEN")
        self.assertEqual(status["attempt_records"][-1]["attempt_id"], second["attempt_id"])
        self.assertTrue(status["receipts"][-1]["stale"])

    def test_receipt_history_survives_restart(self):
        self._authorize()
        first = self._begin()
        self.g.record_receipt("T1", self._receipt(first, status="UNKNOWN"))
        self.g.reconcile("T1", first["attempt_id"], "+84999", "NO_EFFECT", "verify:no-effect")
        self.g.authorize_retry("T1", "+84999")
        second = self._begin()
        self.g.record_receipt("T1", self._receipt(second, status="UNKNOWN"))
        restarted = Gateway(self.path, "+84999", GOV, self.clock)
        status = restarted.status()["tickets"]["T1"]
        self.assertEqual([r["attempt_id"] for r in status["receipts"]], ["T1:1", "T1:2"])
        self.assertEqual(status["fence_counter"], 2)

    def test_terminal_cannot_start_new_attempt(self):
        self._authorize()
        effect = self._begin()
        self.g.record_receipt("T1", self._receipt(effect))
        with self.assertRaises(AuthorizationError):
            self.g.begin_effect("T1", "abc123")

    def test_cross_process_attempt_allocation_is_unique(self):
        self._authorize()
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        processes = [ctx.Process(target=begin_worker, args=(str(self.path), queue)) for _ in range(2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
        results = [queue.get(timeout=5) for _ in processes]
        for process in processes:
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(sorted(r[1]["attempt_id"] for r in results if r[0] == "ok"), ["T1:1", "T1:2"])
        self.assertFalse([r for r in results if r[0] == "error"], results)

    def test_cross_process_receipt_race_has_one_winner(self):
        self._authorize()
        effect = self._begin()
        receipt = self._receipt(effect)
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        processes = [ctx.Process(target=receipt_worker, args=(str(self.path), receipt, queue)) for _ in range(2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
        results = [queue.get(timeout=5) for _ in processes]
        successes = [r for r in results if r[0] == "ok"]
        failures = [r for r in results if r[0] == "error"]
        self.assertEqual(len(successes), 1, results)
        self.assertEqual(len(failures), 1, results)
        self.assertEqual(self.g.status()["tickets"]["T1"]["receipts"][0]["attempt_id"], "T1:1")

    def test_stop_revokes_active_lifecycle(self):
        self._authorize()
        self.g.stop("+84999")
        self.assertTrue(self.g.status()["revoked"])
        self.assertEqual(self.g.status()["tickets"]["T1"]["state"], "REJECTED")


if __name__ == "__main__":
    unittest.main()
