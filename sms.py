from __future__ import annotations
import json, os
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def send_ticket_sms(ticket: dict, nonce: str) -> None:
    """Send a repair ticket notification through the Android bridge.

    The bridge URL must be HTTPS. No GitHub or repair-worker credential is sent.
    """
    url = os.environ.get("SMS_BRIDGE_URL", "")
    token = os.environ.get("ANDROID_GATEWAY_TOKEN", "")
    if not url or not token:
        raise RuntimeError("SMS bridge is not configured")
    if urlparse(url).scheme != "https":
        raise RuntimeError("SMS bridge must use HTTPS")
    text = f"CI FAILURE {ticket['repo']} run={ticket['run_id']} sha={ticket['head_sha']} ticket={ticket['ticket']} nonce={nonce}. Reply: SUA {ticket['ticket']} {nonce}"
    body = json.dumps({"text": text}, separators=(",", ":")).encode()
    req = Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "X-Gateway-Token": token,
    })
    with urlopen(req, timeout=10) as resp:
        if not 200 <= resp.status < 300:
            raise RuntimeError(f"SMS bridge HTTP {resp.status}")
