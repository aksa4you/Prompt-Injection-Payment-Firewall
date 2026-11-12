from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from app.engine import PolicyEngine
from app.main import create_app
from app.models import ConsumeIn, EvaluateIn, IntentIn, PolicyConfig


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def engine(clock):
    return PolicyEngine("secret", PolicyConfig(daily_cap=Decimal("500"), review_over=Decimal("250")), clock=clock)


def intent(engine, **kw):
    base = dict(user_id="u1", description="buy the Python Cookbook", max_amount="30.00", currency="USD",
                item_keywords=["python cookbook"], allowed_domains=["bookshop.example"])
    base.update(kw)
    return engine.create_intent(IntentIn(**base))


_n = [0]


def pay(intent_id, amount="29.99", payee="bookshop", domain="bookshop.example", items=None, total=None,
        currency="USD", page="https://www.bookshop.example/cart", request_id=None):
    _n[0] += 1
    items = items if items is not None else [{"name": "Python Cookbook, 3rd ed.", "price": amount, "qty": 1}]
    return EvaluateIn.model_validate({"intent_id": intent_id, "request": {
        "request_id": request_id or f"req-{_n[0]}", "amount": amount, "currency": currency,
        "payee": {"id": payee, "name": payee, "domain": domain},
        "cart": {"items": items, "total": total or amount, "currency": currency}, "page_url": page}})


def names(result, status):
    return {c["name"] for c in result["checks"] if c["status"] == status}


# ---- the headline scenario ------------------------------------------------------------------------
def test_legitimate_purchase_is_allowed(engine):
    i = intent(engine)
    r = engine.evaluate(pay(i["id"]))
    assert r["verdict"] == "allow", r["reasons"]


def test_hijacked_checkout_is_blocked(engine):
    """User wanted a $30 book. The injected page now asks for $4,999 to a new payee."""
    i = intent(engine, allowed_domains=[])  # no allowlist: payee is simply unknown
    r = engine.evaluate(pay(i["id"], amount="4999.00", payee="evil-llc", domain="pay.evil.example",
                            items=[{"name": "Premium Gold Plan", "price": "4999.00", "qty": 1}],
                            page="https://bookshop.example/cart"))
    assert r["verdict"] == "block"
    assert "budget" in names(r, "block")
    assert "payee" in names(r, "review")
    assert "item_match" in names(r, "review")
    assert r["intent_diff"]["user_asked"]["max_amount"] == "30.00"
    assert r["intent_diff"]["agent_wants"]["amount"] == "4999.00"


def test_hijack_with_user_allowlist_blocks_on_payee_and_merchant(engine):
    i = intent(engine, max_amount="5000")  # even a big budget cannot launder a stranger payee
    r = engine.evaluate(pay(i["id"], amount="4999.00", payee="evil-llc", domain="evil.example",
                            page="https://evil.example/pay"))
    assert {"payee", "merchant_domain"} <= names(r, "block")


# ---- intent lifecycle -------------------------------------------------------------------------------
def test_no_intent_no_payment(engine):
    r = engine.evaluate(pay("int_missing"))
    assert r["verdict"] == "block" and r["intent_diff"] is None


def test_intent_expires(engine, clock):
    i = intent(engine, ttl_seconds=60)
    clock.t += 61
    assert "intent_active" in names(engine.evaluate(pay(i["id"])), "block")


def test_single_use_intent_burns_after_capture(engine):
    i = intent(engine)
    first = engine.evaluate(pay(i["id"], request_id="req-r1"))
    assert first["verdict"] == "allow"
    engine.consume(i["id"], ConsumeIn(request_id="req-r1", amount="29.99", payee_id="bookshop"))
    assert "intent_active" in names(engine.evaluate(pay(i["id"], request_id="req-r2")), "block")


def test_voided_payment_does_not_burn_intent(engine):
    i = intent(engine)
    engine.consume(i["id"], ConsumeIn(request_id="req-r1", amount="29.99", payee_id="bookshop", captured=False))
    assert engine.evaluate(pay(i["id"], request_id="req-r2"))["verdict"] == "allow"


def test_tampered_intent_detected(engine):
    i = intent(engine)
    engine._intents[i["id"]]["record"]["max_amount"] = "99999.00"  # attacker edits the store
    r = engine.evaluate(pay(i["id"], amount="5000.00"))
    assert "intent_integrity" in names(r, "block")


# ---- individual checks ----------------------------------------------------------------------------------
def test_currency_mismatch(engine):
    i = intent(engine)
    r = engine.evaluate(pay(i["id"], currency="EUR"))
    assert "currency" in names(r, "block")


def test_small_overage_goes_to_review_big_overage_blocks(engine):
    i = intent(engine)  # budget 30.00, tolerance 10%
    assert engine.evaluate(pay(i["id"], amount="32.00"))["verdict"] == "review"
    assert engine.evaluate(pay(i["id"], amount="34.00"))["verdict"] == "block"


def test_cart_total_mismatch_blocks(engine):
    i = intent(engine)
    r = engine.evaluate(pay(i["id"], amount="29.99", total="9.99"))
    assert "cart_total" in names(r, "block")


def test_quantity_limit(engine):
    i = intent(engine, max_amount="100", max_quantity=1)
    items = [{"name": "Python Cookbook", "price": "10.00", "qty": 5}]
    r = engine.evaluate(pay(i["id"], amount="50.00", total="50.00", items=items))
    assert "quantity" in names(r, "block")


def test_wrong_item_goes_to_review(engine):
    i = intent(engine)
    r = engine.evaluate(pay(i["id"], items=[{"name": "Gold Subscription", "price": "29.99", "qty": 1}]))
    assert r["verdict"] == "review" and "item_match" in names(r, "review")


def test_extra_expensive_item_goes_to_review(engine):
    i = intent(engine, max_amount="200")
    items = [{"name": "Python Cookbook", "price": "20.00", "qty": 1}, {"name": "Warranty bundle", "price": "80.00", "qty": 1}]
    r = engine.evaluate(pay(i["id"], amount="100.00", total="100.00", items=items))
    assert "item_match" in names(r, "review")


def test_page_domain_must_match_payee_when_no_allowlist(engine):
    i = intent(engine, allowed_domains=[])
    engine._known_payees["u1"].add("bookshop")
    r = engine.evaluate(pay(i["id"], domain="other.example", page="https://bookshop.example/cart"))
    assert "merchant_domain" in names(r, "review")


def test_new_payee_reviewed_then_trusted_after_first_payment(engine):
    first = intent(engine, allowed_domains=[])
    assert engine.evaluate(pay(first["id"], request_id="req-aaa"))["verdict"] == "review"
    engine.consume(first["id"], ConsumeIn(request_id="req-aaa", amount="29.99", payee_id="bookshop"))
    second = intent(engine, allowed_domains=[])
    assert engine.evaluate(pay(second["id"], request_id="req-bbb"))["verdict"] == "allow"


def test_daily_cap(engine):
    for n in range(4):
        i = intent(engine, max_amount="150")
        engine.consume(i["id"], ConsumeIn(request_id=f"c{n}", amount="120.00", payee_id="bookshop"))
    i = intent(engine, max_amount="150")
    r = engine.evaluate(pay(i["id"], amount="120.00", total="120.00"))  # 480 spent + 120 > 500
    assert "daily_cap" in names(r, "block")


def test_high_value_needs_human(engine):
    i = intent(engine, max_amount="400", item_keywords=[])
    r = engine.evaluate(pay(i["id"], amount="300.00", total="300.00"))
    assert r["verdict"] == "review" and "high_value" in names(r, "review")


def test_velocity_review_then_block_and_idempotent_per_request(engine):
    i = intent(engine, single_use=False)
    verdicts = [engine.evaluate(pay(i["id"], request_id=f"vel-{n}"))["checks"] for n in range(11)]
    velocity = [next(c for c in cs if c["name"] == "velocity")["status"] for cs in verdicts]
    assert velocity[4] == "allow" and velocity[5] == "review" and velocity[10] == "block"
    # re-evaluating the same request id must not count twice
    j = intent(engine, single_use=False, user_id="u2")
    for _ in range(20):
        r = engine.evaluate(pay(j["id"], request_id="same"))
    assert next(c for c in r["checks"] if c["name"] == "velocity")["status"] == "allow"


def test_consume_is_idempotent(engine):
    i = intent(engine, single_use=False)
    for _ in range(3):
        engine.consume(i["id"], ConsumeIn(request_id="dup", amount="400.00", payee_id="bookshop"))
    assert sum(engine._spend.values()) == Decimal("400.00")


# ---- HTTP surface ------------------------------------------------------------------------------------------
def test_api_credentials_are_separated(clock):
    client = TestClient(create_app("user-key", "svc-token", PolicyEngine("s", clock=clock)))
    body = dict(user_id="u1", description="book", max_amount="30", currency="USD")
    assert client.post("/v1/intents", json=body).status_code == 401
    assert client.post("/v1/intents", json=body, headers={"X-Service-Token": "svc-token"}).status_code == 401  # gateway cannot mint intents
    made = client.post("/v1/intents", json=body, headers={"X-User-Key": "user-key"})
    assert made.status_code == 201
    iid = made.json()["id"]
    payload = {"intent_id": iid, "request": {
        "request_id": "http-1", "amount": "4999", "currency": "USD", "payee": {"id": "x"},
        "cart": {"items": [], "total": "4999", "currency": "USD"}}}
    assert client.post("/v1/evaluate", json=payload).status_code == 401
    assert client.post("/v1/evaluate", json=payload, headers={"X-User-Key": "user-key"}).status_code == 401
    ok = client.post("/v1/evaluate", json=payload, headers={"X-Service-Token": "svc-token"})
    assert ok.status_code == 200 and ok.json()["verdict"] == "block"
