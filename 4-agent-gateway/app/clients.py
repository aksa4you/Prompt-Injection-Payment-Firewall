"""HTTP clients for the three backing services. The orchestrator only depends on these small interfaces,
so tests swap in fakes and you can swap in gRPC/queues later."""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Optional

import httpx

from .config import Settings


class ClientError(Exception):
    """A backing service failed or was unreachable. The orchestrator fails closed on this."""

    def __init__(self, service: str, message: str, status_code: Optional[int] = None):
        super().__init__(f"{service}: {message}")
        self.service = service
        self.status_code = status_code


def _request(http: httpx.Client, service: str, method: str, path: str, **kw: Any) -> dict[str, Any]:
    try:
        resp = http.request(method, path, **kw)
    except httpx.HTTPError as exc:
        raise ClientError(service, f"unreachable ({exc.__class__.__name__})") from exc
    if resp.status_code >= 400:
        raise ClientError(service, f"HTTP {resp.status_code}: {resp.text[:200]}", resp.status_code)
    return resp.json() if resp.content else {}


class PayPalClient:
    def __init__(self, settings: Settings, transport: Optional[httpx.BaseTransport] = None):
        self._http = httpx.Client(base_url=settings.paypal_url, timeout=settings.http_timeout,
                                  headers={"X-Service-Token": settings.service_token}, transport=transport)

    def authorize(self, amount: Decimal, currency: str, payee: str, reference: str, idempotency_key: str) -> dict:
        return _request(self._http, "paypal", "POST", "/v1/authorizations", json={
            "amount": f"{amount:.2f}", "currency": currency, "payee": payee,
            "reference": reference, "idempotency_key": idempotency_key})

    def capture(self, auth_id: str, ticket: str) -> dict:
        return _request(self._http, "paypal", "POST", f"/v1/authorizations/{auth_id}/capture",
                        headers={"X-Capture-Ticket": ticket})

    def void(self, auth_id: str, reason: str) -> dict:
        return _request(self._http, "paypal", "POST", f"/v1/authorizations/{auth_id}/void", json={"reason": reason[:300]})

    def get(self, auth_id: str) -> dict:
        return _request(self._http, "paypal", "GET", f"/v1/authorizations/{auth_id}")


class DetectorClient:
    def __init__(self, settings: Settings, transport: Optional[httpx.BaseTransport] = None):
        headers = {"X-Service-Token": settings.detector_token} if settings.detector_token else {}
        self._http = httpx.Client(base_url=settings.detector_url, timeout=settings.http_timeout,
                                  headers=headers, transport=transport)

    def scan(self, html: str, context: str, url: str) -> dict:
        return _request(self._http, "detector", "POST", "/v1/scan",
                        json={"html": html, "context": context, "url": url})


class PolicyClient:
    def __init__(self, settings: Settings, transport: Optional[httpx.BaseTransport] = None):
        self._http = httpx.Client(base_url=settings.policy_url, timeout=settings.http_timeout,
                                  headers={"X-Service-Token": settings.service_token}, transport=transport)

    def evaluate(self, intent_id: str, request: dict[str, Any]) -> dict:
        return _request(self._http, "policy", "POST", "/v1/evaluate",
                        json={"intent_id": intent_id, "request": request})

    def consume(self, intent_id: str, request_id: str, amount: Decimal, payee_id: str, captured: bool) -> dict:
        return _request(self._http, "policy", "POST", f"/v1/intents/{intent_id}/consume", json={
            "request_id": request_id, "amount": f"{amount:.2f}", "payee_id": payee_id, "captured": captured})
