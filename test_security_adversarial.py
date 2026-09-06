import hashlib
import os
import tempfile
import unittest

from gateway import Ledger, digest


class SecurityAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        self.ledger = Ledger(self.tmp.name)
        os.environ["AUTHORIZED_PHONE"] = "+10000000000"

    def tearDown(self):
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def make_ticket(self):
        p = {
            "repo": "yanhul/try",
            "workflow": "CI",
            "run_id": 12345,
            "head_sha": "a" * 40,
            "conclusion": "failure",
            "run_url": "https://github.com/yanhul/try/actions/runs/12345",
            "governance_digest": "b" * 64,
        }
        row, nonce = self.ledger.create(p)
        self.ledger.command("+10000000000", f"SUA {row['ticket']} {nonce}", True, "b" * 64)
        auth = self.ledger.repair_token(row["ticket"], row["repo"], row["head_sha"], row["governance_digest"])
        return row, auth["authorization_token"]

    def test_stop_revokes_issued_token(self):
        row, token = self.make_ticket()
        result = self.ledger.command("+10000000000", "STOP", True)
        self.assertEqual(result["revoked"], 1)
        with self.assertRaises(PermissionError):
            self.ledger.consume_repair_token(token, row["ticket"], row["repo"], row["head_sha"], row["governance_digest"])

    def test_event_chain_detects_tamper(self):
        row, _ = self.make_ticket()
        self.assertTrue(self.ledger.verify_event_chain())
        self.ledger.db.execute("UPDATE events SET actor='tampered' WHERE ticket=?", (row["ticket"],))
        self.ledger.db.commit()
        self.assertFalse(self.ledger.verify_event_chain())

    def test_exact_run_url(self):
        p = {
            "repo": "yanhul/try", "workflow": "CI", "run_id": 12346,
            "head_sha": "a" * 40, "conclusion": "failure",
            "run_url": "https://github.com/yanhul/try/actions/runs/12346/evil",
            "governance_digest": "b" * 64,
        }
        with self.assertRaises(ValueError):
            self.ledger.create(p)


if __name__ == "__main__":
    unittest.main()
