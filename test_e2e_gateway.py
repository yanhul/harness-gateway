import hashlib
import hmac
import json
import os
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

from gateway import Handler, Ledger, normalize_workflow_run


class GatewayE2ETests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        self.ledger = Ledger(self.tmp.name)
        os.environ.update({
            "GITHUB_WEBHOOK_SECRET": "webhook-secret",
            "ANDROID_GATEWAY_TOKEN": "android-token",
            "REPAIR_WORKER_TOKEN": "worker-token",
            "AUTHORIZED_PHONE": "+10000000000",
        })
        Handler.ledger = self.ledger
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        try:
            os.unlink(self.tmp.name)
        except FileNotFoundError:
            pass

    def post(self, path, body, headers=None):
        raw = json.dumps(body, separators=(",", ":")).encode()
        conn = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        h = {"Content-Type": "application/json", "Content-Length": str(len(raw))}
        h.update(headers or {})
        conn.request("POST", path, raw, h)
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        return resp.status, data

    def test_webhook_sms_authorize_consume_replay(self):
        sha = "a" * 40
        gov = "b" * 64
        payload = {
            "action": "completed",
            "repository": {"full_name": "yanhul/try"},
            "workflow_run": {
                "id": 987654,
                "name": "CI",
                "head_sha": sha,
                "conclusion": "failure",
                "html_url": "https://github.com/yanhul/try/actions/runs/987654",
            },
            "governance_digest": gov,
            "failure": "test_failure",
        }
        # Capture the nonce only through the internal ticket-creation boundary;
        # the HTTP webhook response intentionally never exposes it.
        row, nonce = self.ledger.create(normalize_workflow_run(payload))
        raw = json.dumps(payload, separators=(",", ":")).encode()
        sig = "sha256=" + hmac.new(b"webhook-secret", raw, hashlib.sha256).hexdigest()
        status, created = self.post("/github/webhook", payload, {
            "X-GitHub-Event": "workflow_run",
            "X-Hub-Signature-256": sig,
        })
        self.assertEqual(status, 200)
        self.assertTrue(created["accepted"])
        self.assertFalse(created["new"])
        ticket = row["ticket"]

        status, authorized = self.post("/sms/command", {"text": f"SUA {ticket} {nonce}", "governance_digest": gov}, {
            "X-Gateway-Token": "android-token",
            "X-SMS-Sender": "+10000000000",
        })
        self.assertEqual(status, 200)
        self.assertEqual(authorized["status"], "AUTHORIZED")

        status, issued = self.post("/repair/authorize", {
            "ticket": ticket, "repo": "yanhul/try", "head_sha": sha,
            "governance_digest": gov,
        }, {"X-Repair-Worker-Token": "worker-token"})
        self.assertEqual(status, 200)
        token = issued["authorization_token"]

        status, consumed = self.post("/repair/authorize", {
            "ticket": ticket, "repo": "yanhul/try", "head_sha": sha,
            "governance_digest": gov, "authorization_token": token,
        }, {"X-Repair-Worker-Token": "worker-token"})
        self.assertEqual(status, 200)
        self.assertEqual(consumed["effect"], "repair")

        status, replay = self.post("/repair/authorize", {
            "ticket": ticket, "repo": "yanhul/try", "head_sha": sha,
            "governance_digest": gov, "authorization_token": token,
        }, {"X-Repair-Worker-Token": "worker-token"})
        self.assertEqual(status, 400)
        self.assertIn("replayed", replay["error"])


if __name__ == "__main__":
    unittest.main()
