from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Callable, Optional

from .config import Settings
from .providers import ProviderError
from .tickets import TicketError, verify_ticket


class ServiceError(Exception):
    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


@dataclass
class Authorization:
    id: str
    order_id: str
    provider_auth_id: Optional[str]
    amount: Decimal
    currency: str
    payee: str
    reference: str
    status: str  # PENDING_APPROVAL | HELD | CAPTURED | VOIDED | EXPIRED
    created_at: float
    expires_at: Optional[float] = None
    approval_url: Optional[str] = None
    capture_id: Optional[str] = None
    void_reason: Optional[str] = None

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "order_id": self.order_id,
            "amount": f"{self.amount:.2f}",
            "currency": self.currency,
            "payee": self.payee,
            "reference": self.reference,
            "status": self.status,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "approval_url": self.approval_url,
            "capture_id": self.capture_id,
            "void_reason": self.void_reason,
        }


class AuthService:
    def __init__(self, provider: Any, settings: Settings, clock: Callable[[], float] = time.time):
        self.provider = provider
        self.settings = settings
        self.clock = clock
        self._items: dict[str, Authorization] = {}
        self._idem: dict[str, str] = {}
        self._lock = threading.RLock()

    # -- helpers ---------------------------------------------------------------------------
    def _get(self, auth_id: str) -> Authorization:
        item = self._items.get(auth_id)
        if item is None:
            raise ServiceError(404, "not_found", "authorization not found")
        self._expire_if_due(item)
        return item

    def _expire_if_due(self, item: Authorization) -> bool:
        if item.status == "HELD" and item.expires_at is not None and self.clock() >= item.expires_at:
            try:
                self.provider.void(item.provider_auth_id, request_id=item.id + "-expire")
            except ProviderError:
                pass  # PayPal lets unused authorizations lapse on their own
            item.status = "EXPIRED"
            item.void_reason = "hold expired before capture"
            return True
        return False

    def _authorize(self, item: Authorization) -> None:
        try:
            item.provider_auth_id = self.provider.authorize_order(item.order_id, request_id=item.id + "-auth")
        except ProviderError as exc:
            raise ServiceError(502, "provider_error", str(exc)) from exc
        item.status = "HELD"
        item.expires_at = self.clock() + self.settings.hold_ttl_seconds

    # -- operations ------------------------------------------------------------------------
    def create(self, amount: Decimal, currency: str, payee: str, reference: str,
               idempotency_key: str, payee_email: Optional[str] = None) -> Authorization:
        currency = currency.upper()
        with self._lock:
            existing_id = self._idem.get(idempotency_key)
            if existing_id:
                existing = self._get(existing_id)
                if (existing.amount, existing.currency, existing.payee) != (amount, currency, payee):
                    raise ServiceError(409, "idempotency_mismatch",
                                       "idempotency key was already used with different parameters")
                return existing
            auth_id = "auth_" + uuid.uuid4().hex[:16]
            try:
                order = self.provider.create_order(amount, currency, reference, request_id=auth_id,
                                                   payee_email=payee_email)
            except ProviderError as exc:
                raise ServiceError(502, "provider_error", str(exc)) from exc
            item = Authorization(
                id=auth_id, order_id=order["order_id"], provider_auth_id=None, amount=amount,
                currency=currency, payee=payee, reference=reference, status="PENDING_APPROVAL",
                created_at=self.clock(), approval_url=order.get("approval_url"),
            )
            self._items[auth_id] = item
            self._idem[idempotency_key] = auth_id
            if order.get("approval_url") is None:
                self._authorize(item)  # already approved (mock) -> hold the funds now
            return item

    def confirm(self, auth_id: str) -> Authorization:
        """Called after the buyer approved the order at approval_url (live mode)."""
        with self._lock:
            item = self._get(auth_id)
            if item.status == "HELD":
                return item
            if item.status != "PENDING_APPROVAL":
                raise ServiceError(409, "bad_state", f"authorization is {item.status}")
            self._authorize(item)
            return item

    def get(self, auth_id: str) -> Authorization:
        with self._lock:
            return self._get(auth_id)

    def capture(self, auth_id: str, ticket: Optional[str]) -> Authorization:
        with self._lock:
            item = self._get(auth_id)
            try:
                verify_ticket(self.settings.capture_secret, ticket, item.id, item.amount,
                              item.currency, now=self.clock())
            except TicketError as exc:
                raise ServiceError(403, "invalid_capture_ticket", str(exc)) from exc
            if item.status == "CAPTURED":
                raise ServiceError(409, "already_captured", "authorization was already captured")
            if item.status != "HELD":
                raise ServiceError(409, "not_held", f"authorization is {item.status}, cannot capture")
            try:
                result = self.provider.capture(item.provider_auth_id, item.amount, item.currency,
                                               request_id=item.id + "-cap")
            except ProviderError as exc:
                raise ServiceError(502, "provider_error", str(exc)) from exc
            item.status = "CAPTURED"
            item.capture_id = result["capture_id"]
            return item

    def void(self, auth_id: str, reason: str) -> Authorization:
        with self._lock:
            item = self._get(auth_id)
            if item.status in ("VOIDED", "EXPIRED"):
                return item
            if item.status == "CAPTURED":
                raise ServiceError(409, "already_captured", "cannot void a captured authorization")
            if item.provider_auth_id:
                try:
                    self.provider.void(item.provider_auth_id, request_id=item.id + "-void")
                except ProviderError as exc:
                    raise ServiceError(502, "provider_error", str(exc)) from exc
            item.status = "VOIDED"
            item.void_reason = reason
            return item

    def sweep(self) -> int:
        """Void every hold whose time is up. Call from cron or the /v1/sweep endpoint."""
        with self._lock:
            return sum(1 for item in list(self._items.values()) if self._expire_if_due(item))
