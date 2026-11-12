"""The decision flow.

    request ─▶ AUTHORIZE (funds held)
            ─▶ scan page + context (detector)   ┐ both must say allow;
            ─▶ compare with user intent (policy) ┘ either one unreachable = block (fail closed)
            ─▶ block  → VOID                      funds released
               review → keep the hold, wait for a human (auto-void on timeout)
               allow  → sign capture ticket → CAPTURE → record spend

Nothing in this file calls an LLM, and the agent has no way to reach `capture`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from decimal import Decimal
from typing import Any, Callable, Optional

from .audit import AuditLog
from .clients import ClientError
from .config import Settings
from .models import AgentPaymentRequest
from .tickets import issue_ticket

RANK = {"allow": 0, "review": 1, "block": 2}

AGENT_MESSAGES = {
    "CAPTURED": "Payment completed.",
    "BLOCKED": "Payment blocked by the firewall and the hold was released. Do not retry; ask the user.",
    "PENDING_REVIEW": "Payment is held and waiting for human approval. Do not retry; wait for the user.",
    "REJECTED": "A human reviewer rejected this payment. The hold was released.",
    "EXPIRED": "The review window ended and the hold was released.",
    "FAILED": "The payment could not be started. Nothing was charged.",
}


class GatewayError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class Gateway:
    def __init__(self, settings: Settings, paypal: Any, detector: Any, policy: Any,
                 audit: Optional[AuditLog] = None, clock: Callable[[], float] = time.time):
        self.s = settings
        self.paypal, self.detector, self.policy = paypal, detector, policy
        self.clock = clock
        self.audit = audit or AuditLog(settings.audit_file, clock)
        self._records: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- agent entry point --------
    def submit(self, req: AgentPaymentRequest) -> dict[str, Any]:
        fingerprint = hashlib.sha256(json.dumps(
            [req.intent_id, str(req.amount), req.currency.upper(), req.payee.id], sort_keys=True).encode()).hexdigest()
        with self._lock:
            existing = self._records.get(req.request_id)
            if existing:
                if existing["fingerprint"] != fingerprint:
                    raise GatewayError(409, "idempotency_mismatch", "request_id was already used for a different payment")
                self._expire_review_if_due(existing)
                return existing
            rec: dict[str, Any] = {
                "request_id": req.request_id, "fingerprint": fingerprint, "intent_id": req.intent_id,
                "amount": f"{req.amount:.2f}", "currency": req.currency.upper(), "payee": req.payee.model_dump(),
                "cart": json.loads(req.cart.model_dump_json()), "page_url": req.page_url,
                "page_hash": hashlib.sha256(req.page_html.encode()).hexdigest(),
                "status": "RECEIVED", "verdict": None, "reason_codes": [], "auth_id": None,
                "detector": None, "policy": None, "receipt": None, "review": None,
                "created_at": self.clock(), "decided_at": None, "errors": [],
            }
            self._records[req.request_id] = rec
            self.audit.append("received", req.request_id, {
                "intent_id": req.intent_id, "amount": rec["amount"], "currency": rec["currency"],
                "payee": req.payee.id, "page_url": req.page_url, "page_hash": rec["page_hash"]})

            # 1. hold the funds first. Nothing can be captured that was not held and checked.
            try:
                auth = self.paypal.authorize(req.amount, req.currency, req.payee.id, req.request_id,
                                             idempotency_key=req.request_id)
            except ClientError as exc:
                return self._finish(rec, "FAILED", "block", ["authorize_failed"], str(exc))
            rec["auth_id"] = auth["id"]
            self.audit.append("authorized", req.request_id, {"auth_id": auth["id"], "status": auth.get("status")})
            if auth.get("status") != "HELD":
                self._void(rec, "authorization not in HELD state")
                return self._finish(rec, "FAILED", "block", ["authorize_not_held"], f"status {auth.get('status')}")

            # 2. independent checks. Unreachable service = fail closed.
            detector = self._call("detector", rec, lambda: self.detector.scan(req.page_html, req.agent_context, req.page_url))
            policy = self._call("policy", rec, lambda: self.policy.evaluate(
                req.intent_id, self._policy_payload(req)))
            rec["detector"], rec["policy"] = detector, policy
            self.audit.append("checked", req.request_id, {
                "detector": None if detector is None else {k: detector.get(k) for k in ("risk", "level", "recommendation")},
                "policy": None if policy is None else {"verdict": policy.get("verdict"),
                                                       "failed": [c["name"] for c in policy.get("reasons", [])]}})

            verdict, codes = self._combine(detector, policy)
            rec["verdict"], rec["reason_codes"] = verdict, codes

            # 3. act on the verdict
            if verdict == "block":
                self._void(rec, "blocked: " + ",".join(codes))
                self._consume(rec, captured=False)
                return self._finish(rec, "BLOCKED", verdict, codes)
            if verdict == "review":
                rec["review"] = {"expires_at": self.clock() + self.s.review_ttl_seconds, "decision": None}
                return self._finish(rec, "PENDING_REVIEW", verdict, codes)
            return self._capture(rec, verdict, codes, approved_by=None)

    # ---------------------------------------------------------------- human review ------------
    def approve(self, request_id: str, reviewer: str, note: str) -> dict[str, Any]:
        with self._lock:
            rec = self._pending(request_id)
            rec["review"].update({"decision": "approved", "reviewer": reviewer, "note": note, "at": self.clock()})
            self.audit.append("review_approved", request_id, {"reviewer": reviewer, "note": note})
            return self._capture(rec, "review", rec["reason_codes"], approved_by=reviewer)

    def reject(self, request_id: str, reviewer: str, note: str) -> dict[str, Any]:
        with self._lock:
            rec = self._pending(request_id)
            rec["review"].update({"decision": "rejected", "reviewer": reviewer, "note": note, "at": self.clock()})
            self.audit.append("review_rejected", request_id, {"reviewer": reviewer, "note": note})
            self._void(rec, f"rejected by {reviewer}")
            self._consume(rec, captured=False)
            return self._finish(rec, "REJECTED", "block", rec["reason_codes"])

    def sweep(self) -> int:
        with self._lock:
            return sum(1 for r in list(self._records.values()) if self._expire_review_if_due(r))

    # ---------------------------------------------------------------- reads -------------------
    def get(self, request_id: str) -> dict[str, Any]:
        with self._lock:
            rec = self._records.get(request_id)
            if rec is None:
                raise GatewayError(404, "not_found", "unknown request")
            self._expire_review_if_due(rec)
            return rec

    def list(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        with self._lock:
            for r in list(self._records.values()):
                self._expire_review_if_due(r)
            items = [r for r in self._records.values() if status is None or r["status"] == status]
            return sorted(items, key=lambda r: r["created_at"], reverse=True)

    @staticmethod
    def agent_view(rec: dict[str, Any]) -> dict[str, Any]:
        """What the agent may see: fixed text and reason codes only. Never page excerpts or payee strings,
        because echoing attacker-controlled text back into the agent's context would re-inject it."""
        return {"request_id": rec["request_id"], "status": rec["status"], "decision": rec["verdict"],
                "reason_codes": rec["reason_codes"], "message": AGENT_MESSAGES.get(rec["status"], ""),
                "receipt": rec["receipt"]}

    # ---------------------------------------------------------------- internals ---------------
    def _policy_payload(self, req: AgentPaymentRequest) -> dict[str, Any]:
        return {"request_id": req.request_id, "amount": f"{req.amount:.2f}", "currency": req.currency,
                "payee": req.payee.model_dump(), "cart": json.loads(req.cart.model_dump_json()),
                "page_url": req.page_url}

    def _call(self, name: str, rec: dict[str, Any], fn: Callable[[], dict]) -> Optional[dict]:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001  any failure must fail closed, never open
            rec["errors"].append(f"{name}: {exc}")
            self.audit.append("check_error", rec["request_id"], {"service": name, "error": str(exc)[:200]})
            return None

    def _combine(self, detector: Optional[dict], policy: Optional[dict]) -> tuple[str, list[str]]:
        verdict, codes = "allow", []
        if detector is None:
            verdict, codes = "block", ["detector_unavailable"]
        else:
            rec = detector.get("recommendation", "block")
            if rec not in RANK:
                rec = "block"
            if rec != "allow":
                codes.append(f"injection_{detector.get('level', 'high')}")
            verdict = max(verdict, rec, key=RANK.__getitem__)
        if policy is None:
            verdict, codes = "block", codes + ["policy_unavailable"]
        else:
            pv = policy.get("verdict", "block")
            if pv not in RANK:
                pv = "block"
            codes += [c["name"] for c in policy.get("reasons", [])]
            verdict = max(verdict, pv, key=RANK.__getitem__)
        return verdict, codes

    def _capture(self, rec: dict[str, Any], verdict: str, codes: list[str], approved_by: Optional[str]) -> dict[str, Any]:
        amount, currency = Decimal(rec["amount"]), rec["currency"]
        ticket = issue_ticket(self.s.capture_secret, rec["auth_id"], amount, currency, ttl_seconds=60, now=self.clock())
        try:
            result = self.paypal.capture(rec["auth_id"], ticket)
        except ClientError as exc:
            self._void(rec, "capture failed")
            return self._finish(rec, "FAILED", "block", codes + ["capture_failed"], str(exc))
        self._consume(rec, captured=True)
        rec["receipt"] = self._receipt(rec, result, approved_by)
        return self._finish(rec, "CAPTURED", verdict, codes)

    def _receipt(self, rec: dict[str, Any], capture: dict[str, Any], approved_by: Optional[str]) -> dict[str, Any]:
        body = {"request_id": rec["request_id"], "auth_id": rec["auth_id"], "capture_id": capture.get("capture_id"),
                "amount": rec["amount"], "currency": rec["currency"], "payee": rec["payee"]["id"],
                "approved_by": approved_by or "firewall-auto", "ts": round(self.clock(), 3)}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        sig = hmac.new(self.s.receipt_secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        return {**body, "signature": sig}

    def _void(self, rec: dict[str, Any], reason: str) -> None:
        if not rec.get("auth_id"):
            return
        try:
            self.paypal.void(rec["auth_id"], reason)
            self.audit.append("voided", rec["request_id"], {"auth_id": rec["auth_id"], "reason": reason[:200]})
        except ClientError as exc:
            rec["errors"].append(f"void: {exc}")
            self.audit.append("void_error", rec["request_id"], {"error": str(exc)[:200]})

    def _consume(self, rec: dict[str, Any], captured: bool) -> None:
        try:
            self.policy.consume(rec["intent_id"], rec["request_id"], Decimal(rec["amount"]),
                                rec["payee"]["id"], captured)
        except Exception as exc:  # noqa: BLE001  bookkeeping failure must not undo a decision
            rec["errors"].append(f"consume: {exc}")

    def _pending(self, request_id: str) -> dict[str, Any]:
        rec = self.get(request_id)
        if rec["status"] != "PENDING_REVIEW":
            raise GatewayError(409, "not_pending", f"request is {rec['status']}, not PENDING_REVIEW")
        return rec

    def _expire_review_if_due(self, rec: dict[str, Any]) -> bool:
        if rec["status"] == "PENDING_REVIEW" and self.clock() >= rec["review"]["expires_at"]:
            self._void(rec, "review window expired")
            self._consume(rec, captured=False)
            self._finish(rec, "EXPIRED", "block", rec["reason_codes"])
            return True
        return False

    def _finish(self, rec: dict[str, Any], status: str, verdict: Optional[str], codes: list[str],
                error: Optional[str] = None) -> dict[str, Any]:
        rec["status"], rec["verdict"], rec["reason_codes"] = status, verdict, codes
        rec["decided_at"] = self.clock()
        if error:
            rec["errors"].append(error)
        self.audit.append("decision", rec["request_id"], {"status": status, "verdict": verdict, "reason_codes": codes})
        return rec
