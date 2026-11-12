from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from decimal import Decimal
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from .models import ConsumeIn, EvaluateIn, IntentIn, PolicyConfig

ALLOW, REVIEW, BLOCK = "allow", "review", "block"
RANK = {ALLOW: 0, REVIEW: 1, BLOCK: 2}
WORD = re.compile(r"[a-z0-9]+")


def _host(value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value if "//" in value else "//" + value)
    return (parsed.hostname or "").lower().rstrip(".")


def _domain_matches(host: str, allowed: str) -> bool:
    allowed = _host(allowed)
    return bool(host and allowed and (host == allowed or host.endswith("." + allowed)))


def _tokens(text: str) -> set[str]:
    return {t for t in WORD.findall(text.lower()) if len(t) > 1}


class PolicyEngine:
    def __init__(self, signing_secret: str = "dev-intent-secret", config: Optional[PolicyConfig] = None,
                 clock: Callable[[], float] = time.time):
        self.secret = signing_secret
        self.config = config or PolicyConfig()
        self.clock = clock
        self._lock = threading.RLock()
        self._intents: dict[str, dict[str, Any]] = {}
        self._spend: dict[tuple[str, str], Decimal] = defaultdict(Decimal)  # (user, day) -> captured spend
        self._known_payees: dict[str, set[str]] = defaultdict(set)  # user -> payees paid before
        self._evals: dict[str, deque] = defaultdict(deque)  # user -> timestamps of evaluations
        self._seen_requests: set[str] = set()
        self._consumed_requests: set[str] = set()

    # -- intents -----------------------------------------------------------------------------
    def _sign(self, record: dict[str, Any]) -> str:
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
        return hmac.new(self.secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    def create_intent(self, data: IntentIn) -> dict[str, Any]:
        now = self.clock()
        record = {
            "id": "int_" + uuid.uuid4().hex[:16],
            "user_id": data.user_id,
            "description": data.description,
            "max_amount": f"{data.max_amount:.2f}",
            "currency": data.currency.upper(),
            "item_keywords": [k.lower().strip() for k in data.item_keywords if k.strip()],
            "allowed_payees": [p.strip() for p in data.allowed_payees if p.strip()],
            "allowed_domains": [_host(d) for d in data.allowed_domains if _host(d)],
            "max_quantity": data.max_quantity,
            "single_use": data.single_use,
            "tolerance_pct": str(data.tolerance_pct),
            "created_at": now,
            "expires_at": now + data.ttl_seconds,
        }
        with self._lock:
            self._intents[record["id"]] = {"record": record, "signature": self._sign(record), "used": False}
        return {**record, "signature": self._intents[record["id"]]["signature"]}

    def get_intent(self, intent_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            entry = self._intents.get(intent_id)
            if not entry:
                return None
            return {**entry["record"], "signature": entry["signature"], "used": entry["used"]}

    # -- evaluation ----------------------------------------------------------------------------
    def evaluate(self, body: EvaluateIn) -> dict[str, Any]:
        req = body.request
        checks: list[dict[str, str]] = []

        def add(name: str, status: str, message: str) -> None:
            checks.append({"name": name, "status": status, "message": message})

        with self._lock:
            entry = self._intents.get(body.intent_id)
            if entry is None:
                add("intent_exists", BLOCK, "no such user intent: the agent cannot pay without one")
                return self._result(checks, None, req)
            record = entry["record"]
            now = self.clock()

            # 1. integrity + lifecycle of the intent ---------------------------------------------
            if not hmac.compare_digest(entry["signature"], self._sign(record)):
                add("intent_integrity", BLOCK, "stored intent failed its signature check")
                return self._result(checks, record, req)
            add("intent_integrity", ALLOW, "intent signature valid")
            if now >= record["expires_at"]:
                add("intent_active", BLOCK, "intent has expired")
            elif record["single_use"] and entry["used"]:
                add("intent_active", BLOCK, "intent was already used for a payment")
            else:
                add("intent_active", ALLOW, "intent is active")

            # 2. currency ---------------------------------------------------------------------------
            if req.currency.upper() != record["currency"] or req.cart.currency.upper() != record["currency"]:
                add("currency", BLOCK, f"user budgeted {record['currency']}, request is {req.currency.upper()}")
            else:
                add("currency", ALLOW, "currency matches")

            # 3. amount vs what the user said they would spend -----------------------------------------
            max_amount = Decimal(record["max_amount"])
            tol = Decimal(record["tolerance_pct"])
            if req.amount <= max_amount:
                add("budget", ALLOW, f"{req.amount} is within the user's {max_amount} budget")
            elif req.amount <= max_amount * (1 + tol):
                add("budget", REVIEW, f"{req.amount} slightly exceeds the {max_amount} budget (tax/shipping?)")
            else:
                ratio = (req.amount / max_amount).quantize(Decimal("0.1"))
                add("budget", BLOCK, f"{req.amount} is {ratio}x the user's {max_amount} budget")

            # 4. cart integrity ---------------------------------------------------------------------------
            items_sum = sum((i.price * i.qty for i in req.cart.items), Decimal("0"))
            if abs(req.cart.total - req.amount) > self.config.cart_tolerance:
                add("cart_total", BLOCK, f"charge {req.amount} does not equal cart total {req.cart.total}")
            elif items_sum > req.cart.total + self.config.cart_tolerance:
                add("cart_total", REVIEW, f"line items sum to {items_sum}, above cart total {req.cart.total}")
            else:
                add("cart_total", ALLOW, "charge equals cart total")

            qty = sum(i.qty for i in req.cart.items)
            if qty > record["max_quantity"]:
                add("quantity", BLOCK, f"{qty} units in cart, user allowed {record['max_quantity']}")
            else:
                add("quantity", ALLOW, "quantity within limit")

            # 5. is the cart what the user asked for? ---------------------------------------------------------
            keywords = record["item_keywords"]
            if keywords:
                wanted = set().union(*(_tokens(k) for k in keywords))
                hit = [i.name for i in req.cart.items if _tokens(i.name) & wanted]
                extra = [i for i in req.cart.items if not (_tokens(i.name) & wanted)]
                if not hit:
                    add("item_match", REVIEW, f"no cart item matches what the user asked for ({', '.join(keywords)})")
                elif extra and sum((i.price * i.qty for i in extra), Decimal("0")) > Decimal("0.2") * req.cart.total:
                    add("item_match", REVIEW, "cart contains significant items the user did not ask for")
                else:
                    add("item_match", ALLOW, "cart contains the requested item")
            else:
                add("item_match", ALLOW, "intent names no specific item")

            # 6. who gets the money -------------------------------------------------------------------------------
            page_host = _host(req.page_url)
            payee_domain = _host(req.payee.domain)
            has_allowlist = bool(record["allowed_payees"] or record["allowed_domains"])
            payee_ok = req.payee.id in record["allowed_payees"] or any(
                _domain_matches(payee_domain, d) for d in record["allowed_domains"])
            if has_allowlist:
                if payee_ok:
                    add("payee", ALLOW, "payee is on the user's allowlist")
                else:
                    add("payee", BLOCK, f"payee '{req.payee.id}' is not one the user approved")
            elif req.payee.id in self._known_payees[record["user_id"]]:
                add("payee", ALLOW, "user has paid this payee before")
            else:
                add("payee", REVIEW, f"new payee '{req.payee.id}': the user never approved or paid it")

            if record["allowed_domains"] and not any(_domain_matches(page_host, d) for d in record["allowed_domains"]):
                add("merchant_domain", BLOCK, f"page '{page_host or 'unknown'}' is outside the user's approved merchants")
            elif payee_domain and page_host and not (_domain_matches(page_host, payee_domain)
                                                      or _domain_matches(payee_domain, page_host)):
                add("merchant_domain", REVIEW, f"page is {page_host} but the payee is {payee_domain}")
            else:
                add("merchant_domain", ALLOW, "merchant domain consistent")

            # 7. limits across requests -------------------------------------------------------------------------
            user = record["user_id"]
            day = time.strftime("%Y-%m-%d", time.gmtime(now))
            spent = self._spend[(user, day)]
            if spent + req.amount > self.config.daily_cap:
                add("daily_cap", BLOCK, f"{spent} already spent today; +{req.amount} exceeds the {self.config.daily_cap} cap")
            else:
                add("daily_cap", ALLOW, f"{spent + req.amount} of {self.config.daily_cap} daily cap")

            window = self._evals[user]
            while window and now - window[0] > self.config.velocity_window_seconds:
                window.popleft()
            if req.request_id not in self._seen_requests:
                self._seen_requests.add(req.request_id)
                window.append(now)
            n = len(window)
            if n > self.config.velocity_block_after:
                add("velocity", BLOCK, f"{n} payment attempts in the last {self.config.velocity_window_seconds}s")
            elif n > self.config.velocity_review_after:
                add("velocity", REVIEW, f"{n} payment attempts in the last {self.config.velocity_window_seconds}s")
            else:
                add("velocity", ALLOW, f"{n} attempt(s) in window")

            if req.amount >= self.config.review_over:
                add("high_value", REVIEW, f"amount {req.amount} is at or above the {self.config.review_over} human-approval line")
            else:
                add("high_value", ALLOW, "below high-value threshold")

            return self._result(checks, record, req)

    def _result(self, checks: list[dict[str, str]], record: Optional[dict[str, Any]], req) -> dict[str, Any]:
        verdict = max((c["status"] for c in checks), key=lambda s: RANK[s], default=ALLOW)
        reasons = [c for c in checks if c["status"] != ALLOW]
        diff = None
        if record:
            diff = {
                "user_asked": {"description": record["description"], "max_amount": record["max_amount"],
                               "currency": record["currency"], "items": record["item_keywords"],
                               "payees": record["allowed_payees"], "domains": record["allowed_domains"]},
                "agent_wants": {"amount": f"{req.amount:.2f}", "currency": req.currency.upper(),
                                "payee": req.payee.id, "payee_domain": req.payee.domain,
                                "items": [i.name for i in req.cart.items], "page": req.page_url},
            }
        return {"verdict": verdict, "reasons": reasons, "checks": checks, "intent_diff": diff,
                "request_id": req.request_id}

    # -- after the money moved ----------------------------------------------------------------------------------
    def consume(self, intent_id: str, body: ConsumeIn) -> dict[str, Any]:
        """Gateway calls this after a capture: burns single-use intents, counts spend, remembers the payee."""
        with self._lock:
            entry = self._intents.get(intent_id)
            if entry is None:
                return {"ok": False, "error": "unknown intent"}
            if body.request_id in self._consumed_requests:
                return {"ok": True, "duplicate": True}
            self._consumed_requests.add(body.request_id)
            if body.captured:
                record = entry["record"]
                entry["used"] = True
                day = time.strftime("%Y-%m-%d", time.gmtime(self.clock()))
                self._spend[(record["user_id"], day)] += body.amount
                self._known_payees[record["user_id"]].add(body.payee_id)
            return {"ok": True}
