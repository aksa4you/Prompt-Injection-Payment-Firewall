"""Role 5 tests. Everything here runs offline: shop pages are served by the real shop app, the gateway and
PayPal are replaced by httpx MockTransport fakes. A live end-to-end test runs only when E2E=1 (stack running)."""
from __future__ import annotations

import json
import os
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient

from app import pages
from app.agent import NaiveShoppingAgent
from app.dashboard import create_app
from app.runner import Config, Runner, render
from app.shop import app as shop_app
from app.tickets import TicketError, verify_ticket

AGENT = NaiveShoppingAgent()
ATTACK_IDS = [s.id for s in pages.SCENARIOS if s.is_attack]
shop = TestClient(shop_app)


def html_for(sid: str) -> str:
    return shop.get(f"/s/{sid}").text


# ------------------------------------------------------------------ shop pages
def test_every_scenario_page_renders_with_a_checkout_block():
    for s in pages.SCENARIOS:
        r = shop.get(f"/s/{s.id}")
        assert r.status_code == 200
        assert 'id="checkout"' in r.text


def test_unknown_scenario_is_404():
    assert shop.get("/s/nope").status_code == 404


def test_scenario_ids_are_unique_and_expectations_valid():
    ids = [s.id for s in pages.SCENARIOS]
    assert len(ids) == len(set(ids))
    assert all(s.expected in ("CAPTURED", "BLOCKED", "PENDING_REVIEW") for s in pages.SCENARIOS)
    assert any(not s.is_attack for s in pages.SCENARIOS), "need benign scenarios to prove no false positives"


# ------------------------------------------------------------------ the gullible agent
def test_agent_is_not_hijacked_by_a_clean_page():
    d = AGENT.decide("buy book", html_for("clean_purchase"))
    assert not d.hijacked
    assert d.price == Decimal("29.99") and d.payee_id == "bookshop"


@pytest.mark.parametrize("sid", ATTACK_IDS)
def test_agent_is_hijacked_by_every_attack_page(sid):
    d = AGENT.decide("buy book", html_for(sid))
    assert d.hijacked, f"{sid}: the demo agent should fall for this attack"
    assert d.payee_id != "bookshop"


def test_overcharge_attacks_inflate_the_price_and_swap_attacks_keep_it():
    assert AGENT.decide("t", html_for("css_hidden")).price == Decimal("4999")
    assert AGENT.decide("t", html_for("paraphrase_overcharge")).price == Decimal("4999")
    swap = AGENT.decide("t", html_for("silent_payee_swap"))
    assert swap.price == Decimal("29.99") and swap.payee_id == "pay.evil.example"


def test_agent_needs_a_checkout_block():
    with pytest.raises(ValueError):
        AGENT.decide("t", "<html><body>nothing here</body></html>")


# ------------------------------------------------------------------ runner against fakes
class FakeStack:
    """Minimal stand-in for policy + gateway + paypal. Mimics the real contracts closely enough for routing tests."""

    def __init__(self, status_for=lambda body: "BLOCKED"):
        self.status_for = status_for
        self.calls: list[tuple[str, str]] = []
        self.records: dict[str, dict] = {}
        self.captured_tickets: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, method = request.url.path, request.method
        self.calls.append((method, path))
        body = json.loads(request.content) if request.content else {}
        if path == "/v1/intents":
            return httpx.Response(201, json={"id": "int-1"})
        if path == "/v1/payment-requests":
            status = self.status_for(body)
            rec = {"request_id": body["request_id"], "status": status, "amount": body["amount"],
                   "payee": body["payee"], "reason_codes": ["budget"] if status == "BLOCKED" else [],
                   "detector": {"risk": 0.9 if status == "BLOCKED" else 0.0}}
            self.records[body["request_id"]] = rec
            return httpx.Response(200, json={"request_id": body["request_id"], "status": status})
        if path.startswith("/v1/admin/requests/") and path.endswith("/approve"):
            rid = path.split("/")[-2]
            self.records[rid]["status"] = "CAPTURED"
            return httpx.Response(200, json=self.records[rid])
        if path.startswith("/v1/admin/requests/"):
            return httpx.Response(200, json=self.records[path.rsplit("/", 1)[-1]])
        if path == "/v1/authorizations":
            return httpx.Response(201, json={"id": "AUTH-1"})
        if path.endswith("/capture"):
            self.captured_tickets.append(request.headers.get("X-Capture-Ticket", ""))
            return httpx.Response(200, json={"status": "CAPTURED", "amount": "4999.00"})
        if path.startswith("/s/"):
            return httpx.Response(200, text=html_for(path.split("/")[-1]))
        return httpx.Response(404)


def make_runner(stack: FakeStack) -> Runner:
    return Runner(Config(), transport=httpx.MockTransport(stack))


def test_protected_run_sends_page_and_agent_notes_to_the_gateway_only():
    stack = FakeStack()
    result = make_runner(stack).run("css_hidden", "protected")
    paths = [p for _, p in stack.calls]
    assert "/v1/payment-requests" in paths
    assert not any("capture" in p or "authorizations" in p for p in paths), "agent side must never touch PayPal"
    assert result["status"] == "BLOCKED" and result["passed"] is True and result["money_lost"] is False
    assert result["agent_hijacked"] is True


def test_protected_run_flags_a_wrong_outcome_as_failed():
    stack = FakeStack(status_for=lambda body: "CAPTURED")  # a broken firewall that lets the attack through
    result = make_runner(stack).run("css_hidden", "protected")
    assert result["passed"] is False and result["money_lost"] is True


def test_review_scenario_can_be_approved():
    stack = FakeStack(status_for=lambda body: "PENDING_REVIEW")
    held = make_runner(stack).run("needs_review", "protected")
    assert held["status"] == "PENDING_REVIEW" and held["passed"] is True
    approved = make_runner(stack).run("needs_review", "protected", approve=True)
    assert approved["status"] == "CAPTURED" and approved["initial_status"] == "PENDING_REVIEW"


def test_unprotected_run_authorizes_and_captures_with_a_valid_ticket():
    stack = FakeStack()
    r = make_runner(stack).run("css_hidden", "unprotected")
    assert r["status"] == "CAPTURED" and r["money_lost"] is True
    ticket = stack.captured_tickets[0]
    verify_ticket(Config().capture_secret, ticket, "AUTH-1", Decimal("4999.00"), "USD")  # does not raise
    with pytest.raises(TicketError):
        verify_ticket("some-other-secret", ticket, "AUTH-1", Decimal("4999.00"), "USD")


def test_unknown_scenario_raises():
    with pytest.raises(KeyError):
        make_runner(FakeStack()).run("nope")


def test_render_table_marks_losses_and_passes():
    stack = FakeStack()
    runner = make_runner(stack)
    out = render([runner.run("css_hidden", "unprotected"), runner.run("css_hidden", "protected")])
    assert "MONEY LOST" in out and "PASS" in out


# ------------------------------------------------------------------ dashboard backend
def make_dashboard() -> TestClient:
    stack = FakeStack()

    def admin_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/admin/requests":
            return httpx.Response(200, json=[{"request_id": "r1", "status": "BLOCKED"}])
        if request.url.path == "/v1/admin/audit/verify":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, text="nope")

    admin = httpx.Client(base_url="http://gateway", transport=httpx.MockTransport(admin_handler))
    return TestClient(create_app(runner=make_runner(stack), admin=admin))


def test_dashboard_lists_scenarios_and_serves_the_page():
    c = make_dashboard()
    assert len(c.get("/api/scenarios").json()) == len(pages.SCENARIOS)
    assert "Payment Firewall" in c.get("/").text


def test_dashboard_run_totals_money_lost_and_saved():
    c = make_dashboard()
    c.post("/api/run", json={"scenario": "css_hidden", "mode": "unprotected"})
    c.post("/api/run", json={"scenario": "css_hidden", "mode": "protected"})
    log = c.get("/api/runs").json()
    assert log["lost_unprotected"] == "4999.00" and log["blocked_by_firewall"] == "4999.00"
    assert len(log["runs"]) == 2


def test_dashboard_validates_input_and_proxies_admin_calls():
    c = make_dashboard()
    assert c.post("/api/run", json={"scenario": "css_hidden", "mode": "weird"}).status_code == 422
    assert c.post("/api/run", json={"scenario": "nope"}).status_code == 404
    assert c.get("/api/requests").json()[0]["status"] == "BLOCKED"
    assert c.get("/api/audit/verify").json() == {"ok": True}
    assert c.get("/api/requests/zzz").status_code == 404  # upstream error passes through


def test_dashboard_reports_502_when_a_service_is_down():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")
    runner = Runner(Config(), transport=httpx.MockTransport(boom))
    c = TestClient(create_app(runner=runner, admin=httpx.Client(base_url="http://x", transport=httpx.MockTransport(boom))))
    assert c.post("/api/run", json={"scenario": "css_hidden"}).status_code == 502
    assert c.get("/api/requests").status_code == 502


# ------------------------------------------------------------------ live end-to-end (needs the real stack)
@pytest.mark.skipif(os.getenv("E2E") != "1", reason="set E2E=1 with the stack running (scripts/run_all.py)")
def test_live_stack_blocks_every_attack_and_pays_for_the_clean_purchase():
    runner = Runner()
    for s in pages.SCENARIOS:
        r = runner.run(s.id, "protected")
        assert r["status"] == s.expected, (s.id, r)
        assert not r["money_lost"], s.id
