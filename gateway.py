"""Fail-closed human authorization and external-effect gateway."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Mapping

TERMINAL = {"REJECTED", "COMPLETED", "EXPIRED"}
CONTRACT_FIELDS = ("effect_id", "action", "capability_ref", "authority_ref", "evidence_ref", "lineage_ref", "idempotency_key")
RECEIPT_FIELDS = ("ticket_id", "attempt_id", "attempt_fence", "target_sha", "effect_id", "idempotency_key", "status", "evidence_ref", "lineage_ref")
RECEIPT_STATUSES = {"OBSERVED", "UNKNOWN", "FAILED", "COMPLETED"}
RECONCILE_OUTCOMES = {"NO_EFFECT", "EFFECTED", "UNRESOLVED"}
PROTECTED = ("policy", "evidence_criteria", "promotion_criteria", "terminal_conditions", "trust_roots")


class GatewayError(Exception):
    pass


class AuthorizationError(GatewayError):
    pass


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
    version: int = 0
    fence_counter: int = 0
    retry_authorized: bool = False
    attempt_records: list[dict] = field(default_factory=list)
    receipts: list[dict] = field(default_factory=list)

    @property
    def governance_digest(self) -> str:
        return canonical_digest(self.governance)


class Gateway:
    """Durable effect boundary: authorization binding, attempts, receipts and reconciliation."""

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
            return {"version": 3, "tickets": {}, "revoked": False}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("tickets"), dict):
            raise GatewayError("invalid gateway state")
        data.setdefault("version", 3)
        data.setdefault("revoked", False)
        for raw in data["tickets"].values():
            self._normalize(raw)
        return data

    @staticmethod
    def _normalize(raw: dict) -> None:
        raw.setdefault("version", 0)
        raw.setdefault("fence_counter", int(raw.get("attempts", 0)))
        raw.setdefault("retry_authorized", raw.get("state") == "AUTHORIZED")
        raw.setdefault("attempt_records", [])
        raw.setdefault("receipts", [])
        raw.setdefault("last_receipt", None)
        raw.setdefault("effect_contract", None)
        for attempt in raw["attempt_records"]:
            attempt.setdefault("state", "OPEN")

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

    def _acquire_lock(self, timeout: float = 10.0, poll: float = 0.01):
        lock_path = self.path.with_name(self.path.name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(lock_path, "a+b")
        if os.name == "nt" and os.path.getsize(lock_path) == 0:
            handle.write(b"0")
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                if os.name == "nt":
                    import msvcrt
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

    def _mutate(self, fn):
        handle = self._acquire_lock()
        try:
            self._data = self._load()
            before = copy.deepcopy(self._data)
            try:
                result = fn()
            except Exception:
                if self._data != before:
                    self._data["version"] = int(self._data.get("version", 0)) + 1
                    self._save()
                raise
            self._data["version"] = int(self._data.get("version", 0)) + 1
            self._save()
            return result
        finally:
            self._release_lock(handle)

    def _raw(self, ticket_id: str) -> dict:
        raw = self._data["tickets"].get(ticket_id)
        if not raw:
            raise GatewayError("unknown ticket")
        self._normalize(raw)
        return raw

    def _ticket(self, ticket_id: str) -> Ticket:
        return Ticket(**self._raw(ticket_id))

    def _check_governance(self, ticket: Ticket) -> None:
        if ticket.governance_digest != canonical_digest(self.governance):
            raise AuthorizationError("governance digest changed")

    def _expire(self, raw: dict) -> None:
        if raw["state"] not in TERMINAL and self._now() >= raw["expires_at"]:
            raw["state"] = "EXPIRED"
            raw["retry_authorized"] = False
            raise AuthorizationError("ticket expired")

    def create_ticket(self, ticket_id: str, repository: str, target_sha: str, nonce: str,
                      ttl_seconds: int, effect_contract: Mapping[str, object] | None = None) -> Ticket:
        def op():
            if not all((ticket_id, repository, target_sha, nonce)) or ttl_seconds <= 0:
                raise ValueError("ticket fields/ttl invalid")
            if ticket_id in self._data["tickets"]:
                raise GatewayError("ticket already exists")
            contract = _require_contract(effect_contract) if effect_contract is not None else None
            if contract is not None and any((r.get("effect_contract") or {}).get("idempotency_key") == contract["idempotency_key"] for r in self._data["tickets"].values()):
                raise GatewayError("idempotency key already bound to another ticket")
            ticket = Ticket(ticket_id, repository, target_sha, nonce, self._now() + ttl_seconds,
                            dict(self.governance), effect_contract=contract, version=1)
            self._data["tickets"][ticket_id] = asdict(ticket)
            return ticket
        return self._mutate(op)

    def authorize(self, ticket_id: str, nonce: str, sender: str, target_sha: str) -> Ticket:
        def op():
            ticket = self._ticket(ticket_id); raw = self._raw(ticket_id)
            if self._data.get("revoked"):
                raise AuthorizationError("gateway revoked")
            if sender != self.human_identity:
                raise AuthorizationError("sender identity mismatch")
            if ticket.state != "PENDING":
                raise AuthorizationError(f"ticket not pending: {ticket.state}")
            self._expire(raw)
            if ticket.nonce_used or nonce != ticket.nonce:
                raise AuthorizationError("invalid or replayed nonce")
            if target_sha != ticket.target_sha:
                raise AuthorizationError("target sha mismatch")
            self._check_governance(ticket)
            raw.update(state="AUTHORIZED", approved_by=sender, nonce_used=True, retry_authorized=True)
            raw["version"] += 1
            return self._ticket(ticket_id)
        return self._mutate(op)

    def reject(self, ticket_id: str, sender: str) -> Ticket:
        def op():
            raw = self._raw(ticket_id)
            if sender != self.human_identity or raw["state"] != "PENDING":
                raise AuthorizationError("ticket not pending or sender mismatch")
            raw.update(state="REJECTED", retry_authorized=False); raw["version"] += 1
            return self._ticket(ticket_id)
        return self._mutate(op)

    def stop(self, sender: str) -> None:
        def op():
            if sender != self.human_identity:
                raise AuthorizationError("sender identity mismatch")
            self._data["revoked"] = True
            for raw in self._data["tickets"].values():
                if raw["state"] not in TERMINAL:
                    raw.update(state="REJECTED", retry_authorized=False); raw["version"] += 1
        self._mutate(op)

    def begin_effect(self, ticket_id: str, target_sha: str) -> dict[str, object]:
        def op():
            raw = self._raw(ticket_id); ticket = self._ticket(ticket_id)
            if ticket.state != "AUTHORIZED":
                raise AuthorizationError("effect requires authorized ticket")
            self._check_governance(ticket); self._expire(raw)
            if target_sha != ticket.target_sha:
                raise AuthorizationError("target sha mismatch")
            if not ticket.effect_contract:
                raise AuthorizationError("effect requires AIOS contract binding")
            if not raw.get("retry_authorized"):
                raise AuthorizationError("attempt requires explicit retry authorization")
            fence = int(raw.get("fence_counter", 0)) + 1
            attempt_id = f"{ticket_id}:{fence}"
            raw["fence_counter"] = fence; raw["attempts"] = int(raw.get("attempts", 0)) + 1
            raw["attempt_records"].append({"attempt_id": attempt_id, "fence": fence, "state": "OPEN", "created_at": self._now()})
            raw.update(state="ATTEMPT_OPEN", retry_authorized=False); raw["version"] += 1
            return {**_require_contract(ticket.effect_contract), "ticket_id": ticket_id, "attempt_id": attempt_id,
                    "attempt_fence": fence, "repository": ticket.repository, "target_sha": ticket.target_sha,
                    "governance_digest": ticket.governance_digest}
        return self._mutate(op)

    def retry_verify_only(self, ticket_id: str, sender: str) -> Ticket:
        def op():
            ticket = self._ticket(ticket_id); raw = self._raw(ticket_id)
            if sender != self.human_identity or ticket.state != "RECONCILING":
                raise AuthorizationError("verification requires reconciling ticket and exact sender")
            self._check_governance(ticket); self._expire(raw)
            return self._ticket(ticket_id)
        return self._mutate(op)

    def reconcile(self, ticket_id: str, attempt_id: str, sender: str, outcome: str, verification_ref: str) -> Ticket:
        def op():
            raw = self._raw(ticket_id); ticket = self._ticket(ticket_id)
            if sender != self.human_identity:
                raise AuthorizationError("sender identity mismatch")
            if ticket.state not in {"ATTEMPT_OPEN", "RECONCILING"}:
                raise AuthorizationError("effect is not awaiting reconciliation")
            if outcome not in RECONCILE_OUTCOMES or not verification_ref:
                raise GatewayError("invalid reconciliation evidence")
            attempt = next((a for a in raw["attempt_records"] if a["attempt_id"] == attempt_id), None)
            if attempt is None or attempt.get("reconciliation") is not None:
                raise GatewayError("unknown or already reconciled attempt")
            self._check_governance(ticket)
            attempt["reconciliation"] = {"outcome": outcome, "verification_ref": verification_ref, "at": self._now()}
            if outcome == "NO_EFFECT":
                raw.update(state="AUTHORIZED", retry_authorized=False)
            elif outcome == "EFFECTED":
                raw.update(state="COMPLETED", retry_authorized=False)
            else:
                raw.update(state="RECONCILING", retry_authorized=False)
            raw["version"] += 1
            return self._ticket(ticket_id)
        return self._mutate(op)

    def authorize_retry(self, ticket_id: str, sender: str) -> Ticket:
        def op():
            raw = self._raw(ticket_id); ticket = self._ticket(ticket_id)
            if sender != self.human_identity or self._data.get("revoked"):
                raise AuthorizationError("retry authorization denied")
            if ticket.state != "AUTHORIZED" or not raw.get("attempts") or raw.get("retry_authorized"):
                raise AuthorizationError("retry requires NO_EFFECT reconciliation and fresh authorization")
            self._expire(raw); self._check_governance(ticket)
            raw["retry_authorized"] = True; raw["version"] += 1
            return self._ticket(ticket_id)
        return self._mutate(op)

    def record_receipt(self, ticket_id: str, receipt: Mapping[str, object]) -> Ticket:
        def op():
            raw = self._raw(ticket_id); ticket = self._ticket(ticket_id)
            if ticket.state in TERMINAL:
                raise GatewayError("ticket is terminal")
            if any(not receipt.get(k) for k in RECEIPT_FIELDS):
                raise GatewayError("receipt missing required fields")
            if receipt["ticket_id"] != ticket_id or receipt["target_sha"] != ticket.target_sha:
                raise GatewayError("receipt binding mismatch")
            contract = _require_contract(ticket.effect_contract or {})
            for name in ("effect_id", "idempotency_key", "evidence_ref", "lineage_ref"):
                if receipt[name] != contract[name]:
                    raise GatewayError(f"receipt {name} mismatch")
            status = str(receipt["status"])
            if status not in RECEIPT_STATUSES:
                raise GatewayError("invalid receipt status")
            attempt = next((a for a in raw["attempt_records"] if a["attempt_id"] == receipt["attempt_id"]), None)
            if attempt is None:
                raise GatewayError("receipt attempt mismatch")
            try:
                fence = int(receipt["attempt_fence"])
            except (TypeError, ValueError) as exc:
                raise GatewayError("invalid receipt fence") from exc
            if fence != int(attempt["fence"]):
                raise GatewayError("receipt fence mismatch")
            if any(all(r.get(k) == receipt.get(k) for k in RECEIPT_FIELDS) for r in raw["receipts"]):
                raise GatewayError("duplicate receipt")
            stale = fence < int(raw["fence_counter"]) or raw["state"] != "ATTEMPT_OPEN"
            bound = dict(receipt); bound.update(recorded_at=self._now(), stale=stale)
            raw["receipts"].append(bound); raw["last_receipt"] = bound
            if stale:
                attempt["state"] = "STALE_RECEIPT_RECORDED"
            elif status == "COMPLETED":
                attempt["state"] = "COMPLETED"; raw.update(state="COMPLETED", retry_authorized=False)
            else:
                attempt["state"] = status; raw.update(state="RECONCILING", retry_authorized=False)
            raw["version"] += 1
            return self._ticket(ticket_id)
        return self._mutate(op)

    def status(self) -> dict:
        handle = self._acquire_lock()
        try:
            self._data = self._load()
            return json.loads(json.dumps(self._data, sort_keys=True))
        finally:
            self._release_lock(handle)
