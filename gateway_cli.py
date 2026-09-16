"""Minimal JSONL CLI transport for the gateway state machine.

It intentionally has no network, SMS, GitHub-token, or shell execution capability.
A deployment can put a trusted transport in front of this process.
"""
from __future__ import annotations

import argparse
import json
import sys

from gateway import Gateway, GatewayError


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--state", required=True)
    p.add_argument("--human-identity", required=True)
    p.add_argument("--governance", required=True, help="JSON object containing all protected governance digests")
    a = p.parse_args()
    gateway = Gateway(a.state, a.human_identity, json.loads(a.governance))

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            req = json.loads(line)
            cmd = req.get("command")
            if cmd == "CREATE":
                result = gateway.create_ticket(req["ticket"], req["repository"], req["target_sha"], req["nonce"], int(req["ttl_seconds"]))
                out = {"ok": True, "ticket": result.__dict__}
            elif cmd == "SUA":
                result = gateway.authorize(req["ticket"], req["nonce"], req["sender"], req["target_sha"])
                out = {"ok": True, "ticket": result.__dict__}
            elif cmd == "BOQUA":
                out = {"ok": True, "ticket": gateway.reject(req["ticket"], req["sender"]).__dict__}
            elif cmd == "RETRY":
                out = {"ok": True, "ticket": gateway.retry_verify_only(req["ticket"], req["sender"]).__dict__}
            elif cmd == "STOP":
                gateway.stop(req["sender"])
                out = {"ok": True}
            elif cmd == "BEGIN_EFFECT":
                out = {"ok": True, "effect": gateway.begin_effect(req["ticket"], req["target_sha"])}
            elif cmd == "RECEIPT":
                out = {"ok": True, "ticket": gateway.record_receipt(req["ticket"], req["receipt"]).__dict__}
            elif cmd == "STATUS":
                out = {"ok": True, "status": gateway.status()}
            else:
                raise GatewayError("unknown command")
        except (KeyError, ValueError, GatewayError, json.JSONDecodeError) as exc:
            out = {"ok": False, "error": str(exc)}
        print(json.dumps(out, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
