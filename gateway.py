"""Fail-closed human authorization and external-effect gateway.

AIOS owns policy/authority/capability decisions. This gateway only binds an
already-authorized effect to a human-approved target and a durable receipt.
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

TERMINAL = {"REJECTED", "COMPLETED", "EXPIRED"}
RETRY_REQUIRES_VERIFY = {"UNKNOWN_REQUIRES_VERIFY", "FAILED_REQUIRES_VERIFY"}
PROTECTED = ("policy", "evidence_criteria", "promotion_criteria", "terminal_conditions", "trust_roots")
CONTRACT_FIELDS = ("effect_id", "action", "capability_ref", "authority_ref", "evidence_ref", "lineage_ref", "idempotency_key")
RECEIPT_FIELDS = ("ticket_id", "attempt_id", "target_sha", "effect_id", "idempotency_key", "status", "evidence_ref", "lineage_ref")
RECEIPT_STATUSES = {"OBSERVED", "UNKNOWN", "FAILED", "COMPLETED"}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_digest(values: Mapping[str, str]) -> str:
    payload = json.dumps(dict(sorted(values.items())), sort_keys=True, separators=(",", ":"))
    return sha256_text(payload)


def _require_contract(contract: Mapping[str, object]) -> dict[str, str]:
    normalized = {key: str(contract.get(key, "")).strip() for key in CONTRACT_FIELDS}
    missing = [key for key, value in normalized.items() if not value]
    if missing:
        raise AuthorizationError("effect contract missing: " + ",".join(missing))
    return normalized


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
    effect_contract: dict[str, str] | None = None

    @property
    def governance_digest(self) -> str:
        return canonical_digest(self.governance)


class GatewayError(Exception):
    pass


class AuthorizationError(GatewayError):
    pass


class Gateway:
    """Persistent state machine at the external-effect boundary.

    It never grants authority and never executes repository mutations. The
    worker must enforce the returned contract/target and return a bound receipt.
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
            return {"version": 2, "tickets": {}, "revoked": False}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("tickets"), dict):
            raise GatewayError("invalid gateway state")
        return data

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

    def _lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    def _acquire_lock(self, timeout: float = 10.0, poll: float = 0.01):
        """Acquire a cross-process advisory lock; lock survives process crashes safely."""
        lock = self._lock_path()
        lock.parent.mkdir(parents=True, exist_ok=True)
        handle = open(lock, "a+b")
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    if handle.tell() == 0:
                        handle.write(b"0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return handle
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    handle.close()
                    raise GatewayError("state lock timeout")
                time.sleep(poll)

    def _release_lock(self, handle) -> None:
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()

    def create_ticket(self, ticket_id: str, repository: str, target_sha: str, nonce: str,
                      ttl_seconds: int, effect_contract: Mapping[str, object] | None = None) -> Ticket:
        if not all((ticket_id, repository, target_sha, nonce)) or ttl_seconds <= 0:
            raise ValueError("ticket fields/ttl invalid")
        if ticket_id in self._data["tickets"]:
            raise GatewayError("ticket already exists")
        contract = _require_contract(effect_contract) if effect_contract is not None else None
        if contract is not None:
            for raw in self._data["tickets"].values():
                existing = raw.get("effect_contract") or {}
                if existing.get("idempotency_key") == contract["idempotency_key"]:
                    raise GatewayError("idempotency key already bound to another ticket")
        t = Ticket(ticket_id, repository, target_sha, nonce, self._now() + ttl_seconds,
                   dict(self.governance), effect_contract=contract)
        self._data["tickets"][ticket_id] = asdict(t)
        self._save()
        return t

    def _ticket(self, ticket_id: str) -> Ticket:
        raw = self._data["tickets"].get(ticket_id)
        if not raw:
            raise GatewayError("unknown ticket")
        raw.setdefault("effect_contract", None)
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
            if raw["state"] in {"PENDING", "AUTHORIZED", *RETRY_REQUIRES_VERIFY}:
                raw["state"] = "REJECTED"
        self._save()

    def authorize_retry(self, ticket_id: str, sender: str) -> Ticket:
        """Explicit human VERIFY -> RETRY authorization after ambiguity/failure."""
        t = self._ticket(ticket_id)
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        if self._data.get("revoked"):
            raise AuthorizationError("gateway revoked")
        if t.state not in RETRY_REQUIRES_VERIFY:
            raise AuthorizationError(f"retry authorization requires verification state: {t.state}")
        if self._now() >= t.expires_at:
            self._transition(ticket_id, "EXPIRED")
            raise AuthorizationError("ticket expired")
        self._check_governance(t)
        raw = self._data["tickets"][ticket_id]
        raw["state"] = "AUTHORIZED"
        self._save()
        return self._ticket(ticket_id)

    def retry_verify_only(self, ticket_id: str, sender: str) -> Ticket:
        """Verification-only check; never grants retry authorization."""
        t = self._ticket(ticket_id)
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        if t.state not in {"AUTHORIZED", *RETRY_REQUIRES_VERIFY}:
            raise AuthorizationError("verification requires authorized/retry-pending ticket")
        self._check_governance(t)
        if self._now() >= t.expires_at:
            self._transition(ticket_id, "EXPIRED")
            raise AuthorizationError("ticket expired")
        return t

    def begin_effect(self, ticket_id: str, target_sha: str) -> dict[str, object]:
        """Atomically reload and allocate the next attempt under the state lock."""
        handle = self._acquire_lock()
        try:
            self._data = self._load()
            t = self._ticket(ticket_id)
            if t.state != "AUTHORIZED":
                raise AuthorizationError("effect requires authorized ticket")
            self._check_governance(t)
            if target_sha != t.target_sha:
                raise AuthorizationError("target sha mismatch")
            if t.effect_contract is None:
                raise AuthorizationError("effect requires AIOS contract binding")
            contract = _require_contract(t.effect_contract)
            attempt_id = f"{ticket_id}:{t.attempts + 1}"
            self._data["tickets"][ticket_id]["attempts"] = t.attempts + 1
            self._save()
            return {**contract, "ticket_id": ticket_id, "attempt_id": attempt_id,
                    "repository": t.repository, "target_sha": t.target_sha,
                    "governance_digest": t.governance_digest}
        finally:
            self._release_lock(handle)

    def record_receipt(self, ticket_id: str, receipt: Mapping[str, object]) -> Ticket:
        t = self._ticket(ticket_id)
        if t.state in TERMINAL:
            raise GatewayError("ticket is terminal")
        if any(not receipt.get(k) for k in RECEIPT_FIELDS):
            raise GatewayError("receipt missing required fields")
        if receipt["ticket_id"] != ticket_id or receipt["target_sha"] != t.target_sha:
            raise GatewayError("receipt binding mismatch")
        if not t.effect_contract:
            raise GatewayError("receipt requires AIOS contract binding")
        contract = _require_contract(t.effect_contract)
        expected_attempt = f"{ticket_id}:{t.attempts}"
        if receipt["attempt_id"] != expected_attempt:
            raise GatewayError("receipt attempt mismatch")
        for field in ("effect_id", "idempotency_key", "evidence_ref", "lineage_ref"):
            if receipt[field] != contract[field]:
                raise GatewayError(f"receipt {field} mismatch")
        status = str(receipt["status"])
        if status not in RECEIPT_STATUSES:
            raise GatewayError("invalid receipt status")
        if t.last_receipt is not None:
            previous = t.last_receipt
            if previous.get("attempt_id") == receipt["attempt_id"]:
                raise GatewayError("duplicate receipt for attempt")
        raw = self._data["tickets"][ticket_id]
        raw["last_receipt"] = dict(receipt)
        if status == "COMPLETED":
            raw["state"] = "COMPLETED"
        elif status == "FAILED":
            raw["state"] = "FAILED_REQUIRES_VERIFY"
        elif status == "UNKNOWN":
            raw["state"] = "UNKNOWN_REQUIRES_VERIFY"
        else:
            raw["state"] = "AUTHORIZED"
        self._save()
        return self._ticket(ticket_id)

    def status(self) -> dict:
        return json.loads(json.dumps(self._data, sort_keys=True))
