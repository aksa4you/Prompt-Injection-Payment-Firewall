import json
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.providers import PayPalLiveProvider
from app.tickets import issue_ticket

SETTINGS = Settings(service_token="svc", capture_secret="cap-secret", hold_ttl_seconds=100)
HEADERS = {"X-Service-Token": "svc"}


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def client(clock):
    return TestClient(create_app(SETTINGS, clock=clock))


def make(client, key="idem-key-0001", amount="30.00"):
    resp = client.post("/v1/authorizations", headers=HEADERS, json={
        "amount": amount, "currency": "USD", "payee": "bookshop", "reference": "order-1",
        "idempotency_key": key})
    assert resp.status_code == 201, resp.text
    return resp.json()


def ticket(auth, clock, secret="cap-secret", amount=None, ttl=60):
    return issue_ticket(secret, auth["id"], Decimal(amount or auth["amount"]), auth["currency"],
                        ttl_seconds=ttl, now=clock.t)


def test_authorize_holds_funds(client):
    auth = make(client)
    assert auth["status"] == "HELD"
    assert auth["amount"] == "30.00"


def test_requires_service_token(client):
    assert client.post("/v1/authorizations", json={}).status_code == 401
    assert client.get("/v1/authorizations/x", headers={"X-Service-Token": "nope"}).status_code == 401


def test_capture_needs_valid_ticket(client, clock):
    auth = make(client)
    url = f"/v1/authorizations/{auth['id']}/capture"
    assert client.post(url, headers=HEADERS).status_code == 403  # no ticket: the agent's situation
    bad = client.post(url, headers={**HEADERS, "X-Capture-Ticket": ticket(auth, clock, secret="guess")})
    assert bad.status_code == 403
    ok = client.post(url, headers={**HEADERS, "X-Capture-Ticket": ticket(auth, clock)})
    assert ok.status_code == 200
    assert ok.json()["status"] == "CAPTURED"


def test_ticket_is_bound_to_amount(client, clock):
    auth = make(client)
    url = f"/v1/authorizations/{auth['id']}/capture"
    wrong = ticket(auth, clock, amount="4999.00")
    resp = client.post(url, headers={**HEADERS, "X-Capture-Ticket": wrong})
    assert resp.status_code == 403
    assert client.get(f"/v1/authorizations/{auth['id']}", headers=HEADERS).json()["status"] == "HELD"


def test_ticket_is_bound_to_authorization(client, clock):
    a, b = make(client, key="idem-key-000a"), make(client, key="idem-key-000b")
    resp = client.post(f"/v1/authorizations/{b['id']}/capture",
                       headers={**HEADERS, "X-Capture-Ticket": ticket(a, clock)})
    assert resp.status_code == 403


def test_expired_ticket_rejected(client, clock):
    auth = make(client)
    t = ticket(auth, clock, ttl=10)
    clock.t += 11
    resp = client.post(f"/v1/authorizations/{auth['id']}/capture", headers={**HEADERS, "X-Capture-Ticket": t})
    assert resp.status_code == 403


def test_capture_twice_conflicts(client, clock):
    auth = make(client)
    url = f"/v1/authorizations/{auth['id']}/capture"
    h = {**HEADERS, "X-Capture-Ticket": ticket(auth, clock)}
    assert client.post(url, headers=h).status_code == 200
    assert client.post(url, headers=h).status_code == 409


def test_void_then_capture_fails(client, clock):
    auth = make(client)
    v = client.post(f"/v1/authorizations/{auth['id']}/void", headers=HEADERS, json={"reason": "injection"})
    assert v.json()["status"] == "VOIDED"
    resp = client.post(f"/v1/authorizations/{auth['id']}/capture",
                       headers={**HEADERS, "X-Capture-Ticket": ticket(auth, clock)})
    assert resp.status_code == 409


def test_void_is_idempotent_and_cannot_undo_capture(client, clock):
    auth = make(client)
    url = f"/v1/authorizations/{auth['id']}/void"
    assert client.post(url, headers=HEADERS).status_code == 200
    assert client.post(url, headers=HEADERS).status_code == 200
    auth2 = make(client, key="idem-key-0002")
    client.post(f"/v1/authorizations/{auth2['id']}/capture",
                headers={**HEADERS, "X-Capture-Ticket": ticket(auth2, clock)})
    assert client.post(f"/v1/authorizations/{auth2['id']}/void", headers=HEADERS).status_code == 409


def test_idempotency(client):
    first, second = make(client), make(client)
    assert first["id"] == second["id"]
    clash = client.post("/v1/authorizations", headers=HEADERS, json={
        "amount": "99.00", "currency": "USD", "payee": "bookshop", "reference": "order-1",
        "idempotency_key": "idem-key-0001"})
    assert clash.status_code == 409


def test_hold_expires_and_sweep_voids(client, clock):
    auth = make(client)
    clock.t += 101
    assert client.post("/v1/sweep", headers=HEADERS).json() == {"expired": 1}
    state = client.get(f"/v1/authorizations/{auth['id']}", headers=HEADERS).json()
    assert state["status"] == "EXPIRED"
    resp = client.post(f"/v1/authorizations/{auth['id']}/capture",
                       headers={**HEADERS, "X-Capture-Ticket": ticket(auth, clock, ttl=1000)})
    assert resp.status_code == 409


def test_validation(client):
    resp = client.post("/v1/authorizations", headers=HEADERS, json={
        "amount": "-5", "currency": "USD", "payee": "x", "reference": "r", "idempotency_key": "idem-key-0009"})
    assert resp.status_code == 422


# ---- live provider: verify the exact PayPal REST calls against a mocked transport -------------
def test_live_provider_request_shapes():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, dict(request.headers),
                     json.loads(request.content) if request.content and request.headers.get(
                         "content-type", "").startswith("application/json") else None))
        path = request.url.path
        if path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        if path == "/v2/checkout/orders":
            return httpx.Response(201, json={"id": "ORD1", "links": [
                {"rel": "self", "href": "x"}, {"rel": "payer-action", "href": "https://paypal/approve"}]})
        if path.endswith("/authorize"):
            return httpx.Response(201, json={"purchase_units": [
                {"payments": {"authorizations": [{"id": "AUTH1"}]}}]})
        if path.endswith("/capture"):
            return httpx.Response(201, json={"id": "CAP1", "status": "COMPLETED"})
        if path.endswith("/void"):
            return httpx.Response(204)
        return httpx.Response(404)

    provider = PayPalLiveProvider("id", "secret", "https://api-m.sandbox.paypal.com", "r", "c",
                                  transport=httpx.MockTransport(handler))
    order = provider.create_order(Decimal("30.00"), "USD", "ref", "req-1", payee_email="shop@example.com")
    assert order == {"order_id": "ORD1", "approval_url": "https://paypal/approve"}
    assert provider.authorize_order("ORD1", "req-2") == "AUTH1"
    assert provider.capture("AUTH1", Decimal("30.00"), "USD", "req-3")["capture_id"] == "CAP1"
    provider.void("AUTH1", "req-4")

    create = next(s for s in seen if s[1] == "/v2/checkout/orders")
    assert create[3]["intent"] == "AUTHORIZE"
    assert create[3]["purchase_units"][0]["amount"] == {"currency_code": "USD", "value": "30.00"}
    assert create[3]["purchase_units"][0]["payee"] == {"email_address": "shop@example.com"}
    assert create[2]["authorization"] == "Bearer tok"
    assert create[2]["paypal-request-id"] == "req-1"
    paths = [s[1] for s in seen]
    assert "/v2/checkout/orders/ORD1/authorize" in paths
    assert "/v2/payments/authorizations/AUTH1/capture" in paths
    assert "/v2/payments/authorizations/AUTH1/void" in paths
    assert paths.count("/v1/oauth2/token") == 1  # token cached
