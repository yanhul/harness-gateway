"""Fail-closed human authorization gateway.

This module is deliberately transport-agnostic. SMS, GitHub, and repair workers are
adapters around this state machine; none of them become the authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Mapping

TERMINAL = {"REJECTED", "COMPLETED", "FAILED", "EXPIRED"}
PROTECTED = ("policy", "evidence_criteria", "promotion_criteria", "terminal_conditions", "trust_roots")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_digest(values: Mapping[str, str]) -> str:
    payload = json.dumps(dict(sorted(values.items())), sort_keys=True, separators=(",", ":"))
    return sha256_text(payload)


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    repository: str
    target_sha: str
    nonce: str
    expires_at: float
    governance: dict[str, str]
    state: str = "PENDING"
    approved_by: str | None = None
    nonce_used: bool = False
    attempts: int = 0
    last_receipt: dict | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def governance_digest(self) -> str:
        return canonical_digest(self.governance)


class GatewayError(Exception):
    pass


class AuthorizationError(GatewayError):
    pass


class Gateway:
    """Persistent, fail-closed command/effect state machine.

    The gateway authorizes effects but does not itself grant GitHub credentials or
    decide what code to change. A worker must separately enforce the exact ticket
    and return a receipt tied to ticket_id/attempt_id/target_sha.
    """

    def __init__(self, path: str | Path, human_identity: str, governance: Mapping[str, str], now=time.time):
        if not human_identity:
            raise ValueError("human_identity required")
        missing = [k for k in PROTECTED if not governance.get(k)]
        if missing:
            raise ValueError(f"missing protected governance: {','.join(missing)}")
        self.path = Path(path)
        self.human_identity = human_identity
        self.governance = dict(governance)
        self._now = now
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {"version": 1, "tickets": {}, "revoked": False}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, sort_keys=True, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def create_ticket(self, ticket_id: str, repository: str, target_sha: str, nonce: str, ttl_seconds: int) -> Ticket:
        if not all((ticket_id, repository, target_sha, nonce)) or ttl_seconds <= 0:
            raise ValueError("ticket fields/ttl invalid")
        if ticket_id in self._data["tickets"]:
            raise GatewayError("ticket already exists")
        t = Ticket(ticket_id, repository, target_sha, nonce, self._now() + ttl_seconds, dict(self.governance))
        self._data["tickets"][ticket_id] = asdict(t)
        self._save()
        return t

    def _ticket(self, ticket_id: str) -> Ticket:
        raw = self._data["tickets"].get(ticket_id)
        if not raw:
            raise GatewayError("unknown ticket")
        return Ticket(**raw)

    def _check_governance(self, t: Ticket) -> None:
        if t.governance_digest != canonical_digest(self.governance):
            raise AuthorizationError("governance digest changed")

    def authorize(self, ticket_id: str, nonce: str, sender: str, target_sha: str) -> Ticket:
        t = self._ticket(ticket_id)
        if self._data.get("revoked"):
            raise AuthorizationError("gateway revoked")
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        if t.state != "PENDING":
            raise AuthorizationError(f"ticket not pending: {t.state}")
        if self._now() >= t.expires_at:
            self._transition(t.ticket_id, "EXPIRED")
            raise AuthorizationError("ticket expired")
        if t.nonce_used or nonce != t.nonce:
            raise AuthorizationError("invalid or replayed nonce")
        if target_sha != t.target_sha:
            raise AuthorizationError("target sha mismatch")
        self._check_governance(t)
        raw = self._data["tickets"][ticket_id]
        raw.update(state="AUTHORIZED", approved_by=sender, nonce_used=True)
        self._save()
        return self._ticket(ticket_id)

    def _transition(self, ticket_id: str, state: str) -> None:
        if state not in TERMINAL:
            raise ValueError("invalid terminal state")
        self._data["tickets"][ticket_id]["state"] = state
        self._save()

    def reject(self, ticket_id: str, sender: str) -> Ticket:
        t = self._ticket(ticket_id)
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        if t.state != "PENDING":
            raise AuthorizationError("ticket not pending")
        self._transition(ticket_id, "REJECTED")
        return self._ticket(ticket_id)

    def stop(self, sender: str) -> None:
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        self._data["revoked"] = True
        for raw in self._data["tickets"].values():
            if raw["state"] in {"PENDING", "AUTHORIZED"}:
                raw["state"] = "REJECTED"
        self._save()

    def retry_verify_only(self, ticket_id: str, sender: str) -> Ticket:
        t = self._ticket(ticket_id)
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        if t.state not in {"AUTHORIZED", "FAILED"}:
            raise AuthorizationError("retry requires authorized/failed ticket")
        self._check_governance(t)
        if self._now() >= t.expires_at:
            self._transition(ticket_id, "EXPIRED")
            raise AuthorizationError("ticket expired")
        return t

    def begin_effect(self, ticket_id: str, target_sha: str) -> dict:
        t = self._ticket(ticket_id)
        if t.state != "AUTHORIZED":
            raise AuthorizationError("effect requires authorized ticket")
        self._check_governance(t)
        if target_sha != t.target_sha:
            raise AuthorizationError("target sha mismatch")
        attempt_id = f"{ticket_id}:{t.attempts + 1}"
        self._data["tickets"][ticket_id]["attempts"] = t.attempts + 1
        self._save()
        return {"ticket_id": ticket_id, "attempt_id": attempt_id, "repository": t.repository, "target_sha": t.target_sha}

    def record_receipt(self, ticket_id: str, receipt: Mapping[str, object]) -> Ticket:
        t = self._ticket(ticket_id)
        required = ("ticket_id", "attempt_id", "target_sha", "status")
        if any(not receipt.get(k) for k in required):
            raise GatewayError("receipt missing required fields")
        if receipt["ticket_id"] != ticket_id or receipt["target_sha"] != t.target_sha:
            raise GatewayError("receipt binding mismatch")
        expected_attempt = f"{ticket_id}:{t.attempts}"
        if receipt["attempt_id"] != expected_attempt:
            raise GatewayError("receipt attempt mismatch")
        status = str(receipt["status"])
        if status not in {"OBSERVED", "UNKNOWN", "FAILED", "COMPLETED"}:
            raise GatewayError("invalid receipt status")
        raw = self._data["tickets"][ticket_id]
        raw["last_receipt"] = dict(receipt)
        raw["state"] = "COMPLETED" if status == "COMPLETED" else ("FAILED" if status == "FAILED" else "AUTHORIZED")
        self._save()
        return self._ticket(ticket_id)

    def status(self) -> dict:
        return json.loads(json.dumps(self._data, sort_keys=True))
