"""Payment providers: an in-memory mock and a PayPal Orders v2 REST client.

Both expose the same four calls used by AuthService:
    create_order -> {"order_id", "approval_url"}   (approval_url None = already approved)
    authorize_order -> provider_auth_id
    capture / void
"""
from __future__ import annotations

import threading
import time
import uuid
from decimal import Decimal
from typing import Any, Optional

import httpx


class ProviderError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class MockProvider:
    """Deterministic stand-in for PayPal. Auto-approves, keeps balances of what was held."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.orders: dict[str, dict[str, Any]] = {}
        self.auths: dict[str, dict[str, Any]] = {}

    def create_order(self, amount: Decimal, currency: str, reference: str, request_id: str,
                     payee_email: Optional[str] = None) -> dict[str, Any]:
        order_id = "MOCK-ORDER-" + uuid.uuid4().hex[:12].upper()
        with self._lock:
            self.orders[order_id] = {"amount": amount, "currency": currency, "reference": reference}
        return {"order_id": order_id, "approval_url": None}

    def authorize_order(self, order_id: str, request_id: str) -> str:
        with self._lock:
            order = self.orders.get(order_id)
            if order is None:
                raise ProviderError("unknown order", 404)
            auth_id = "MOCK-AUTH-" + uuid.uuid4().hex[:12].upper()
            self.auths[auth_id] = {**order, "status": "CREATED"}
            return auth_id

    def capture(self, auth_id: str, amount: Decimal, currency: str, request_id: str) -> dict[str, Any]:
        with self._lock:
            auth = self.auths.get(auth_id)
            if auth is None:
                raise ProviderError("unknown authorization", 404)
            if auth["status"] != "CREATED":
                raise ProviderError(f"authorization is {auth['status']}", 422)
            auth["status"] = "CAPTURED"
            return {"capture_id": "MOCK-CAP-" + uuid.uuid4().hex[:12].upper(), "status": "COMPLETED"}

    def void(self, auth_id: str, request_id: str) -> None:
        with self._lock:
            auth = self.auths.get(auth_id)
            if auth is None:
                raise ProviderError("unknown authorization", 404)
            if auth["status"] == "CAPTURED":
                raise ProviderError("already captured", 422)
            auth["status"] = "VOIDED"


class PayPalLiveProvider:
    """PayPal REST (Orders v2 + Payments v2). Point base_url at the sandbox to test.

    Flow: create order (intent=AUTHORIZE) -> buyer approves at approval_url ->
    authorize order (funds held) -> later capture or void the authorization.
    """

    def __init__(self, client_id: str, client_secret: str, base_url: str,
                 return_url: str, cancel_url: str,
                 transport: Optional[httpx.BaseTransport] = None) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._return_url = return_url
        self._cancel_url = cancel_url
        self._http = httpx.Client(base_url=base_url, timeout=20, transport=transport)
        self._token: Optional[str] = None
        self._token_exp = 0.0
        self._lock = threading.Lock()

    def _access_token(self) -> str:
        with self._lock:
            if self._token and time.time() < self._token_exp - 30:
                return self._token
            resp = self._http.post(
                "/v1/oauth2/token",
                data={"grant_type": "client_credentials"},
                auth=(self._client_id, self._client_secret),
            )
            if resp.status_code != 200:
                raise ProviderError(f"PayPal auth failed: {resp.status_code}", 502)
            data = resp.json()
            self._token = data["access_token"]
            self._token_exp = time.time() + int(data.get("expires_in", 300))
            return self._token

    def _call(self, method: str, path: str, request_id: str, json_body: Optional[dict] = None) -> dict:
        headers = {
            "Authorization": f"Bearer {self._access_token()}",
            "Content-Type": "application/json",
            "PayPal-Request-Id": request_id,  # PayPal-side idempotency
        }
        resp = self._http.request(method, path, headers=headers, json=json_body)
        if resp.status_code >= 400:
            raise ProviderError(f"PayPal {method} {path} -> {resp.status_code}: {resp.text[:300]}", 502)
        return resp.json() if resp.content else {}

    def create_order(self, amount: Decimal, currency: str, reference: str, request_id: str,
                     payee_email: Optional[str] = None) -> dict[str, Any]:
        unit: dict[str, Any] = {
            "reference_id": reference[:127],
            "amount": {"currency_code": currency, "value": f"{amount:.2f}"},
        }
        if payee_email:
            unit["payee"] = {"email_address": payee_email}
        body = {
            "intent": "AUTHORIZE",
            "purchase_units": [unit],
            "payment_source": {
                "paypal": {
                    "experience_context": {
                        "return_url": self._return_url,
                        "cancel_url": self._cancel_url,
                        "user_action": "PAY_NOW",
                    }
                }
            },
        }
        data = self._call("POST", "/v2/checkout/orders", request_id, body)
        approval = next(
            (l["href"] for l in data.get("links", []) if l.get("rel") in ("payer-action", "approve")),
            None,
        )
        return {"order_id": data["id"], "approval_url": approval}

    def authorize_order(self, order_id: str, request_id: str) -> str:
        data = self._call("POST", f"/v2/checkout/orders/{order_id}/authorize", request_id, {})
        try:
            return data["purchase_units"][0]["payments"]["authorizations"][0]["id"]
        except (KeyError, IndexError) as exc:
            raise ProviderError("PayPal did not return an authorization id", 502) from exc

    def capture(self, auth_id: str, amount: Decimal, currency: str, request_id: str) -> dict[str, Any]:
        body = {"amount": {"currency_code": currency, "value": f"{amount:.2f}"}, "final_capture": True}
        data = self._call("POST", f"/v2/payments/authorizations/{auth_id}/capture", request_id, body)
        return {"capture_id": data.get("id", ""), "status": data.get("status", "")}

    def void(self, auth_id: str, request_id: str) -> None:
        self._call("POST", f"/v2/payments/authorizations/{auth_id}/void", request_id)
