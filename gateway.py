"""Fail-closed human authorization and external-effect gateway.

AIOS owns policy/authority/capability decisions. This gateway only binds an
already-authorized effect to a human-approved target and a durable receipt.
The gateway persists immutable attempt/receipt history; it never executes work.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import os
import tempfile
import time
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Mapping

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # verification unavailable => all retry permits fail closed
    InvalidSignature = Ed25519PublicKey = None

TERMINAL = {"REJECTED", "COMPLETED", "FAILED", "EXPIRED"}
PROTECTED = ("policy", "evidence_criteria", "promotion_criteria", "terminal_conditions", "trust_roots")
CONTRACT_FIELDS = ("effect_id", "contract_id", "actor", "action", "capability_ref", "authority_ref", "evidence_ref", "lineage_ref", "idempotency_key")
RECEIPT_STATUSES = {"OBSERVED", "UNKNOWN", "FAILED", "COMPLETED"}
RETRY_PERMIT_TYPE = "AIOS_GATEWAY_RETRY_PERMIT_V1"
RETRY_PERMIT_FIELDS = (
    "type", "permit_id", "key_id", "algorithm", "effect_id", "contract_id", "authority_ref",
    "actor", "issuer", "retry_authorization_id", "ticket_id", "target_sha", "prior_gateway_attempt_id", "prior_fence",
    "prior_gateway_receipt_digest", "operation_receipt_digest", "reconciliation_evidence_digest",
    "reconciliation_outcome", "decision_id", "next_attempt_number", "next_attempt_id",
    "next_fence", "nonce", "issued_at", "expires_at",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_RETRY_PERMIT_ID = re.compile(r"^GRP-[0-9a-f]{32}$")
_MAX_RETRY_PERMIT_TTL = 900
_CLOCK_SKEW = 60


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def canonical_digest(values: Mapping[str, str]) -> str:
    return sha256_text(canonical_json(dict(sorted(values.items()))))


def _require_contract(contract: Mapping[str, object]) -> dict[str, str]:
    if not isinstance(contract, Mapping):
        raise AuthorizationError("effect contract is required")
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
    attempt_history: list[dict] = field(default_factory=list)
    receipt_history: list[dict] = field(default_factory=list)
    retry_permit_history: list[dict] = field(default_factory=list)

    @property
    def governance_digest(self) -> str:
        return canonical_digest(self.governance)


class GatewayError(Exception):
    pass


class AuthorizationError(GatewayError):
    pass


@contextmanager
def _process_lock(path: Path):
    """Serialize read/modify/write across threads and processes."""
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _THREAD_LOCK:
        with lock_path.open("a+b") as handle:
            if os.name == "nt":
                import msvcrt
                handle.seek(0, os.SEEK_END)
                if handle.tell() == 0:
                    handle.write(b"0")
                    handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


_THREAD_LOCK = threading.RLock()


def _serialized(method):
    def wrapped(self, *args, **kwargs):
        with _process_lock(self.path):
            self._data = self._load()
            return method(self, *args, **kwargs)
    wrapped.__name__ = method.__name__
    wrapped.__doc__ = method.__doc__
    return wrapped


class Gateway:
    """Persistent state machine at the external-effect boundary.

    Every mutation is serialized and committed atomically. An idempotent
    replay returns the original attempt with execute_allowed=False; it never
    silently allocates another attempt or replays an external effect.
    """

    def __init__(self, path: str | Path, human_identity: str, governance: Mapping[str, str], now=time.time,
                 retry_permit_public_keys: Mapping[str, str] | None = None):
        if not human_identity:
            raise ValueError("human_identity required")
        missing = [k for k in PROTECTED if not governance.get(k)]
        if missing:
            raise ValueError(f"missing protected governance: {','.join(missing)}")
        self.path = Path(path)
        self.human_identity = human_identity
        self.governance = dict(governance)
        if retry_permit_public_keys is None:
            raw_keys = os.environ.get("AIOS_GATEWAY_RETRY_PUBLIC_KEYS", "")
            try:
                retry_permit_public_keys = json.loads(raw_keys) if raw_keys else {}
            except ValueError as exc:
                raise GatewayError("AIOS gateway retry public-key configuration is invalid JSON") from exc
        if not isinstance(retry_permit_public_keys, Mapping):
            raise GatewayError("AIOS gateway retry public-key registry must be a mapping")
        self.retry_permit_public_keys = dict(retry_permit_public_keys)
        for key_id, public_key in self.retry_permit_public_keys.items():
            if (not isinstance(key_id, str) or not key_id.startswith("ed25519:")
                    or not isinstance(public_key, str) or not re.fullmatch(r"[0-9a-f]{64}", public_key)):
                raise GatewayError("AIOS gateway retry public-key entry is malformed")
        self._now = now
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {"version": 3, "tickets": {}, "revoked": False, "events": []}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("tickets"), dict):
            raise GatewayError("invalid gateway state")
        data.setdefault("events", [])
        if not isinstance(data["events"], list):
            raise GatewayError("invalid gateway event ledger")
        self._verify_event_chain(data["events"])
        # Read v2 snapshots without fabricating missing historical attempts.
        for raw in data["tickets"].values():
            if not isinstance(raw, dict):
                raise GatewayError("invalid gateway ticket")
            raw.setdefault("effect_contract", None)
            raw.setdefault("attempt_history", [])
            raw.setdefault("receipt_history", [])
            raw.setdefault("retry_permit_history", [])
        data["version"] = 3
        return data

    @staticmethod
    def _verify_event_chain(events: list[dict]) -> None:
        previous = "0" * 64
        for index, event in enumerate(events, start=1):
            if not isinstance(event, dict) or event.get("sequence") != index:
                raise GatewayError("gateway event sequence is corrupt")
            if event.get("previous_hash") != previous:
                raise GatewayError("gateway event chain predecessor mismatch")
            body = {k: v for k, v in event.items() if k != "event_hash"}
            digest = sha256_text(canonical_json(body))
            if event.get("event_hash") != digest:
                raise GatewayError("gateway event hash mismatch")
            previous = digest

    def _append_event(self, event_type: str, ticket_id: str | None, payload: Mapping[str, object]) -> None:
        events = self._data.setdefault("events", [])
        previous = events[-1]["event_hash"] if events else "0" * 64
        body = {
            "sequence": len(events) + 1,
            "event_type": event_type,
            "ticket_id": ticket_id,
            "timestamp": self._now(),
            "payload": dict(payload),
            "previous_hash": previous,
        }
        events.append({**body, "event_hash": sha256_text(canonical_json(body))})

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, sort_keys=True, separators=(",", ":"), allow_nan=False)
                f.write("\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            if os.name != "nt":
                dir_fd = os.open(str(self.path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    @_serialized
    def create_ticket(self, ticket_id: str, repository: str, target_sha: str, nonce: str,
                      ttl_seconds: int, effect_contract: Mapping[str, object] | None = None) -> Ticket:
        if not all((ticket_id, repository, target_sha, nonce)) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
            raise ValueError("ticket fields/ttl invalid")
        if ticket_id in self._data["tickets"]:
            raise GatewayError("ticket already exists")
        contract = _require_contract(effect_contract) if effect_contract is not None else None
        t = Ticket(ticket_id, repository, target_sha, nonce, self._now() + ttl_seconds,
                   dict(self.governance), effect_contract=contract)
        self._data["tickets"][ticket_id] = asdict(t)
        self._append_event("TICKET_CREATED", ticket_id, {
            "repository": repository, "target_sha": target_sha,
            "effect_id": contract["effect_id"] if contract else None,
            "idempotency_key": contract["idempotency_key"] if contract else None,
        })
        self._save()
        return self._ticket(ticket_id)

    def _ticket(self, ticket_id: str) -> Ticket:
        raw = self._data["tickets"].get(ticket_id)
        if not raw:
            raise GatewayError("unknown ticket")
        raw.setdefault("effect_contract", None)
        raw.setdefault("attempt_history", [])
        raw.setdefault("receipt_history", [])
        raw.setdefault("retry_permit_history", [])
        return Ticket(**raw)

    def _check_governance(self, t: Ticket) -> None:
        if t.governance_digest != canonical_digest(self.governance):
            raise AuthorizationError("governance digest changed")

    def _transition(self, ticket_id: str, state: str, event_type: str) -> None:
        if state not in TERMINAL:
            raise ValueError("invalid terminal state")
        self._data["tickets"][ticket_id]["state"] = state
        self._append_event(event_type, ticket_id, {"state": state})
        self._save()

    @_serialized
    def authorize(self, ticket_id: str, nonce: str, sender: str, target_sha: str) -> Ticket:
        t = self._ticket(ticket_id)
        if self._data.get("revoked"):
            raise AuthorizationError("gateway revoked")
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        if t.state != "PENDING":
            raise AuthorizationError(f"ticket not pending: {t.state}")
        if self._now() >= t.expires_at:
            self._transition(t.ticket_id, "EXPIRED", "TICKET_EXPIRED")
            raise AuthorizationError("ticket expired")
        if t.nonce_used or nonce != t.nonce:
            raise AuthorizationError("invalid or replayed nonce")
        if target_sha != t.target_sha:
            raise AuthorizationError("target sha mismatch")
        self._check_governance(t)
        raw = self._data["tickets"][ticket_id]
        raw.update(state="AUTHORIZED", approved_by=sender, nonce_used=True)
        self._append_event("TICKET_AUTHORIZED", ticket_id, {"sender": sender, "target_sha": target_sha})
        self._save()
        return self._ticket(ticket_id)

    @_serialized
    def reject(self, ticket_id: str, sender: str) -> Ticket:
        t = self._ticket(ticket_id)
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        if t.state != "PENDING":
            raise AuthorizationError("ticket not pending")
        self._transition(ticket_id, "REJECTED", "TICKET_REJECTED")
        return self._ticket(ticket_id)

    @_serialized
    def stop(self, sender: str) -> None:
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        self._data["revoked"] = True
        changed = []
        for ticket_id, raw in self._data["tickets"].items():
            if raw["state"] in {"PENDING", "AUTHORIZED"}:
                raw["state"] = "REJECTED"
                changed.append(ticket_id)
        self._append_event("GATEWAY_STOPPED", None, {"sender": sender, "revoked_tickets": sorted(changed)})
        self._save()

    @_serialized
    def retry_verify_only(self, ticket_id: str, sender: str) -> Ticket:
        t = self._ticket(ticket_id)
        if sender != self.human_identity:
            raise AuthorizationError("sender identity mismatch")
        if t.state not in {"AUTHORIZED", "FAILED"}:
            raise AuthorizationError("retry requires authorized/failed ticket")
        self._check_governance(t)
        if self._now() >= t.expires_at:
            self._transition(ticket_id, "EXPIRED", "TICKET_EXPIRED")
            raise AuthorizationError("ticket expired")
        # This operation authorizes verification only. It never allocates a
        # fresh attempt and never reopens a completed/unknown side effect.
        self._append_event("VERIFICATION_RETRY_REQUESTED", ticket_id, {"sender": sender})
        self._save()
        return self._ticket(ticket_id)

    @_serialized
    def begin_effect(self, ticket_id: str, target_sha: str) -> dict[str, object]:
        t = self._ticket(ticket_id)
        if t.state != "AUTHORIZED":
            raise AuthorizationError("effect requires authorized ticket")
        self._check_governance(t)
        if target_sha != t.target_sha:
            raise AuthorizationError("target sha mismatch")
        if t.effect_contract is None:
            raise AuthorizationError("effect requires AIOS contract binding")
        contract = _require_contract(t.effect_contract)
        raw = self._data["tickets"][ticket_id]
        history = raw["attempt_history"]
        # A ticket's effect contract and idempotency key are immutable. A
        # repeated BEGIN_EFFECT must return the same attempt and must not
        # authorize another provider execution.
        if history:
            existing = history[0]
            if existing.get("idempotency_key") != contract["idempotency_key"]:
                raise GatewayError("attempt idempotency binding mismatch")
            return {**contract, **existing, "ticket_id": ticket_id,
                    "repository": t.repository, "target_sha": t.target_sha,
                    "governance_digest": t.governance_digest,
                    "replayed": True, "execute_allowed": False}
        if t.attempts:
            raise GatewayError("legacy attempt count has no durable attempt history; reconciliation required")
        attempt_id = f"{ticket_id}:1"
        attempt = {
            "attempt_id": attempt_id,
            "attempt_number": 1,
            "fence": 1,
            "effect_id": contract["effect_id"],
            "idempotency_key": contract["idempotency_key"],
            "target_sha": t.target_sha,
            "status": "DISPATCHED",
            "started_at": self._now(),
        }
        raw["attempts"] = 1
        raw["attempt_history"] = [attempt]
        self._append_event("EFFECT_ATTEMPT_DISPATCHED", ticket_id, attempt)
        self._save()
        return {**contract, **attempt, "ticket_id": ticket_id,
                "repository": t.repository, "target_sha": t.target_sha,
                "governance_digest": t.governance_digest,
                "replayed": False, "execute_allowed": True}

    def _verify_retry_permit(self, permit: Mapping[str, object]) -> dict:
        if not isinstance(permit, Mapping) or set(permit) != set(RETRY_PERMIT_FIELDS) | {"signature"}:
            raise AuthorizationError("retry permit schema mismatch")
        record = dict(permit)
        if (record.get("type") != RETRY_PERMIT_TYPE or record.get("algorithm") != "Ed25519"
                or not isinstance(record.get("permit_id"), str) or not _RETRY_PERMIT_ID.fullmatch(record["permit_id"])
                or not isinstance(record.get("key_id"), str)
                or not isinstance(record.get("signature"), str) or not _HEX128.fullmatch(record["signature"])):
            raise AuthorizationError("retry permit identity/signature is malformed")
        public_hex = self.retry_permit_public_keys.get(record["key_id"])
        if public_hex is None:
            raise AuthorizationError("retry permit signer is not pinned by Gateway")
        if Ed25519PublicKey is None:
            raise AuthorizationError("Ed25519 verification unavailable; retry permit rejected")
        body = {key: record[key] for key in RETRY_PERMIT_FIELDS}
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
                bytes.fromhex(record["signature"]), canonical_json(body).encode("utf-8"))
        except (ValueError, InvalidSignature) as exc:
            raise AuthorizationError("retry permit signature is invalid") from exc
        for key in ("prior_gateway_receipt_digest", "operation_receipt_digest", "reconciliation_evidence_digest"):
            if not isinstance(record.get(key), str) or not _HEX64.fullmatch(record[key]):
                raise AuthorizationError(f"retry permit {key} is invalid")
        for key in ("effect_id", "contract_id", "authority_ref", "actor", "issuer", "retry_authorization_id",
                    "ticket_id", "target_sha", "prior_gateway_attempt_id", "decision_id", "next_attempt_id", "nonce"):
            if not isinstance(record.get(key), str) or not record[key].strip():
                raise AuthorizationError(f"retry permit {key} is missing")
        for key in ("prior_fence", "next_attempt_number", "next_fence"):
            value = record.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise AuthorizationError(f"retry permit {key} is invalid")
        for key in ("issued_at", "expires_at"):
            value = record.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise AuthorizationError("retry permit validity window is invalid")
        if (record["expires_at"] <= record["issued_at"]
                or record["expires_at"] - record["issued_at"] > _MAX_RETRY_PERMIT_TTL):
            raise AuthorizationError("retry permit validity window is invalid")
        now = self._now()
        if now > record["expires_at"] or record["issued_at"] > now + _CLOCK_SKEW:
            raise AuthorizationError("retry permit is expired or issued in the future")
        if not re.fullmatch(r"RA-[0-9a-f]{32}", record["retry_authorization_id"]):
            raise AuthorizationError("retry permit AIOS retry-authorization binding is malformed")
        if record.get("reconciliation_outcome") != "PROVEN_NOT_SUBMITTED":
            raise AuthorizationError("retry permit lacks proven non-submission reconciliation")
        return record

    @_serialized
    def retry_effect(self, ticket_id: str, permit: Mapping[str, object]) -> dict[str, object]:
        """Consume one AIOS-signed permit and allocate the next fenced attempt.

        An exact replay returns the already allocated attempt with execute_allowed=False.
        Gateway verifies the AIOS signature but never creates retry authority itself.
        """
        t = self._ticket(ticket_id)
        record = self._verify_retry_permit(permit)
        raw = self._data["tickets"][ticket_id]
        contract = _require_contract(t.effect_contract or {})
        digest = sha256_text(canonical_json(record))
        history = raw.setdefault("retry_permit_history", [])
        consumed = next((item for item in history if item.get("permit_id") == record["permit_id"]), None)
        if consumed is not None:
            if consumed.get("permit_digest") != digest:
                raise AuthorizationError("retry permit id replayed with different content")
            attempt = next((item for item in raw.get("attempt_history", [])
                            if item.get("attempt_id") == consumed.get("attempt_id")), None)
            if attempt is None:
                raise GatewayError("consumed retry permit has no durable attempt")
            return {**contract, **attempt, "ticket_id": ticket_id,
                    "repository": t.repository, "target_sha": t.target_sha,
                    "governance_digest": t.governance_digest,
                    "retry_permit_id": record["permit_id"], "replayed": True, "execute_allowed": False}

        if self._data.get("revoked") or t.state not in {"AUTHORIZED", "FAILED"}:
            raise AuthorizationError("retry requires a live authorized/failed ticket")
        self._check_governance(t)
        if self._now() >= t.expires_at:
            self._transition(ticket_id, "EXPIRED", "TICKET_EXPIRED")
            raise AuthorizationError("ticket expired")
        attempts = raw.get("attempt_history", [])
        receipts = raw.get("receipt_history", [])
        if not attempts or not receipts:
            raise AuthorizationError("retry requires a durable prior attempt and receipt")
        prior = attempts[-1]
        prior_receipt = next((item for item in reversed(receipts)
                              if item.get("receipt", {}).get("attempt_id") == prior.get("attempt_id")), None)
        if prior_receipt is None:
            raise AuthorizationError("retry prior attempt has no durable receipt")
        expected = {
            "effect_id": contract["effect_id"], "contract_id": contract["contract_id"],
            "authority_ref": contract["authority_ref"], "actor": contract["actor"],
            "ticket_id": ticket_id, "target_sha": t.target_sha,
            "prior_gateway_attempt_id": prior.get("attempt_id"),
            "prior_fence": prior.get("fence"),
            "prior_gateway_receipt_digest": prior_receipt.get("digest"),
            "next_attempt_number": int(raw.get("attempts", 0)) + 1,
            "next_attempt_id": f"{ticket_id}:{int(raw.get('attempts', 0)) + 1}",
            "next_fence": int(prior.get("fence", 0)) + 1,
        }
        for key, value in expected.items():
            if record.get(key) != value:
                raise AuthorizationError(f"retry permit {key} binding mismatch")
        if prior.get("status") not in {"UNKNOWN", "FAILED"}:
            raise AuthorizationError("retry prior attempt is not unresolved/rejected")
        nonce = record["nonce"]
        for other in self._data.get("consumed_retry_nonces", []):
            if other == nonce:
                raise AuthorizationError("retry permit nonce already consumed")
        attempt = {
            "attempt_id": record["next_attempt_id"],
            "attempt_number": record["next_attempt_number"],
            "fence": record["next_fence"],
            "effect_id": contract["effect_id"],
            "idempotency_key": contract["idempotency_key"],
            "target_sha": t.target_sha,
            "status": "DISPATCHED",
            "started_at": self._now(),
            "retry_permit_id": record["permit_id"],
            "prior_attempt_id": prior["attempt_id"],
            "prior_receipt_digest": prior_receipt["digest"],
        }
        raw["attempts"] = record["next_attempt_number"]
        raw["attempt_history"].append(attempt)
        history.append({"permit_id": record["permit_id"], "permit_digest": digest,
                        "nonce": nonce, "attempt_id": attempt["attempt_id"],
                        "consumed_at": self._now()})
        self._data.setdefault("consumed_retry_nonces", []).append(nonce)
        raw["state"] = "AUTHORIZED"
        self._append_event("RETRY_PERMIT_CONSUMED", ticket_id, {
            "permit_id": record["permit_id"], "permit_digest": digest,
            "operation_receipt_digest": record["operation_receipt_digest"],
            "reconciliation_evidence_digest": record["reconciliation_evidence_digest"],
            "attempt_id": attempt["attempt_id"], "fence": attempt["fence"],
        })
        self._append_event("EFFECT_ATTEMPT_DISPATCHED", ticket_id, attempt)
        self._save()
        return {**contract, **attempt, "ticket_id": ticket_id,
                "repository": t.repository, "target_sha": t.target_sha,
                "governance_digest": t.governance_digest,
                "retry_permit_id": record["permit_id"], "replayed": False, "execute_allowed": True}

    @_serialized
    def record_receipt(self, ticket_id: str, receipt: Mapping[str, object]) -> Ticket:
        t = self._ticket(ticket_id)
        required = ("ticket_id", "attempt_id", "attempt_fence", "target_sha", "effect_id", "status", "evidence_ref", "lineage_ref")
        if not isinstance(receipt, Mapping) or any(not receipt.get(k) for k in required):
            raise GatewayError("receipt missing required fields")
        if receipt["ticket_id"] != ticket_id or receipt["target_sha"] != t.target_sha:
            raise GatewayError("receipt binding mismatch")
        fence = receipt["attempt_fence"]
        if isinstance(fence, bool) or not isinstance(fence, int) or fence < 1:
            raise GatewayError("receipt attempt fence is invalid")
        if not t.effect_contract or receipt["effect_id"] != t.effect_contract["effect_id"]:
            raise GatewayError("receipt effect binding mismatch")
        if receipt["evidence_ref"] != t.effect_contract["evidence_ref"]:
            raise GatewayError("receipt evidence binding mismatch")
        if receipt["lineage_ref"] != t.effect_contract["lineage_ref"]:
            raise GatewayError("receipt lineage binding mismatch")
        raw = self._data["tickets"][ticket_id]
        attempts = raw.get("attempt_history", [])
        attempt = next((a for a in attempts if a.get("attempt_id") == receipt["attempt_id"]), None)
        if attempt is None:
            raise GatewayError("receipt attempt is not present in durable attempt history")
        if (attempt.get("effect_id") != receipt["effect_id"]
                or attempt.get("target_sha") != receipt["target_sha"]
                or attempt.get("fence") != fence):
            raise GatewayError("receipt does not match durable attempt fence")
        status = str(receipt["status"])
        if status not in RECEIPT_STATUSES:
            raise GatewayError("invalid receipt status")
        digest = sha256_text(canonical_json(dict(receipt)))
        receipts = raw.setdefault("receipt_history", [])
        for prior in receipts:
            if prior.get("digest") == digest:
                return self._ticket(ticket_id)
        previous_status = attempt.get("status")
        allowed = {
            "DISPATCHED": RECEIPT_STATUSES,
            "UNKNOWN": {"OBSERVED", "FAILED", "COMPLETED"},
            "OBSERVED": {"COMPLETED"},
        }
        if status not in allowed.get(previous_status, set()):
            raise GatewayError(f"receipt status regression or terminal replay: {previous_status} -> {status}")
        entry = {"receipt": dict(receipt), "digest": digest, "recorded_at": self._now()}
        receipts.append(entry)
        attempt["status"] = status
        attempt["last_receipt_digest"] = digest
        raw["last_receipt"] = dict(receipt)
        raw["state"] = "COMPLETED" if status == "COMPLETED" else ("FAILED" if status == "FAILED" else "AUTHORIZED")
        self._append_event("EFFECT_RECEIPT_RECORDED", ticket_id, {
            "attempt_id": receipt["attempt_id"], "receipt_digest": digest, "status": status,
        })
        self._save()
        return self._ticket(ticket_id)

    @_serialized
    def status(self) -> dict:
        return json.loads(json.dumps(self._data, sort_keys=True))