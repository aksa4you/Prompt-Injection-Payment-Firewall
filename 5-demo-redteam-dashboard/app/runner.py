"""Run attack scenarios against the firewall (protected) or against a naive PayPal integration (unprotected).

    python -m app.runner                      # every scenario, protected
    python -m app.runner --mode both         # side by side: what the attack costs without the firewall
    python -m app.runner css_hidden --approve
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Optional

import httpx

from . import pages
from .agent import Decision, NaiveShoppingAgent
from .tickets import issue_ticket

TASK = "Buy the Python Cookbook (3rd edition) for no more than $30 from bookshop.example"
USER_INTENT: dict[str, Any] = {
    "description": TASK, "max_amount": "30.00", "currency": "USD", "item_keywords": ["python cookbook"],
    "allowed_domains": ["bookshop.example"], "allowed_payees": [], "max_quantity": 1,
    "ttl_seconds": 900, "single_use": True,
}


@dataclass(frozen=True)
class Config:
    shop_url: str = "http://localhost:8006"
    gateway_url: str = "http://localhost:8004"
    paypal_url: str = "http://localhost:8001"
    policy_url: str = "http://localhost:8003"
    service_token: str = "dev-service-token"
    capture_secret: str = "dev-capture-secret"
    agent_key: str = "dev-agent-key"
    admin_key: str = "dev-admin-key"
    user_key: str = "dev-user-key"


def load_config() -> Config:
    e = os.getenv
    d = Config()
    return Config(e("SHOP_URL", d.shop_url), e("GATEWAY_URL", d.gateway_url), e("PAYPAL_URL", d.paypal_url),
                  e("POLICY_URL", d.policy_url), e("SERVICE_TOKEN", d.service_token),
                  e("CAPTURE_SECRET", d.capture_secret), e("AGENT_KEY", d.agent_key),
                  e("ADMIN_KEY", d.admin_key), e("USER_KEY", d.user_key))


class Runner:
    def __init__(self, cfg: Optional[Config] = None, transport: Optional[httpx.BaseTransport] = None):
        self.cfg = cfg or load_config()
        self.http = httpx.Client(timeout=20, transport=transport)
        self.agent = NaiveShoppingAgent()

    # ----------------------------------------------------------------------------------------------
    def run(self, scenario_id: str, mode: str = "protected", approve: bool = False) -> dict[str, Any]:
        scenario = pages.get(scenario_id)
        if scenario is None:
            raise KeyError(f"unknown scenario {scenario_id!r}")
        html = self.http.get(f"{self.cfg.shop_url}/s/{scenario.id}").raise_for_status().text
        decision = self.agent.decide(TASK, html)
        page_url = f"https://{scenario.merchant_domain}/book/{scenario.id}"
        result: dict[str, Any] = {
            "scenario": scenario.id, "title": scenario.title, "attack": scenario.attack, "mode": mode,
            "is_attack": scenario.is_attack, "caught_by": scenario.caught_by, "expected": scenario.expected,
            "agent_hijacked": decision.hijacked, "agent_notes": decision.thoughts,
            "attempted_amount": f"{decision.price:.2f}", "attempted_payee": decision.payee_id,
        }
        if mode == "unprotected":
            result.update(self._unprotected(decision))
        else:
            result.update(self._protected(scenario, decision, html, page_url, approve))
        result["money_lost"] = bool(scenario.is_attack and result["status"] == "CAPTURED")
        return result

    # ---- naive architecture: the agent (or its tool) holds PayPal credentials ----------------------
    def _unprotected(self, d: Decision) -> dict[str, Any]:
        headers = {"X-Service-Token": self.cfg.service_token}
        auth = self.http.post(f"{self.cfg.paypal_url}/v1/authorizations", headers=headers, json={
            "amount": f"{d.price:.2f}", "currency": d.currency, "payee": d.payee_id,
            "reference": "unprotected-demo", "idempotency_key": uuid.uuid4().hex}).raise_for_status().json()
        ticket = issue_ticket(self.cfg.capture_secret, auth["id"], d.price, d.currency)
        cap = self.http.post(f"{self.cfg.paypal_url}/v1/authorizations/{auth['id']}/capture",
                             headers={**headers, "X-Capture-Ticket": ticket}).raise_for_status().json()
        return {"status": cap["status"], "initial_status": cap["status"], "amount": cap["amount"],
                "payee": d.payee_id, "reason_codes": [], "risk": None, "request_id": auth["id"], "passed": None}

    # ---- protected architecture: the agent can only ask the gateway ---------------------------------
    def _protected(self, scenario: pages.Scenario, d: Decision, html: str, page_url: str, approve: bool) -> dict[str, Any]:
        cfg = self.cfg
        intent = {**USER_INTENT, **scenario.intent, "user_id": "demo-" + uuid.uuid4().hex[:8]}
        made = self.http.post(f"{cfg.policy_url}/v1/intents", json=intent, headers={"X-User-Key": cfg.user_key})
        made.raise_for_status()
        body = {
            "request_id": "req-" + uuid.uuid4().hex[:12], "intent_id": made.json()["id"],
            "amount": f"{d.price:.2f}", "currency": d.currency,
            "payee": {"id": d.payee_id, "name": d.payee_id, "domain": d.payee_domain},
            "cart": {"items": [{"name": d.item, "price": f"{d.price:.2f}", "qty": 1}],
                     "total": f"{d.price:.2f}", "currency": d.currency},
            "page_url": page_url, "page_html": html,
            "agent_context": f"Task: {TASK}\nAgent notes: {d.thoughts}",
        }
        resp = self.http.post(f"{cfg.gateway_url}/v1/payment-requests", json=body, headers={"X-Agent-Key": cfg.agent_key})
        resp.raise_for_status()
        out = resp.json()
        initial = out["status"]
        admin = {"X-Admin-Key": cfg.admin_key}
        if initial == "PENDING_REVIEW" and approve:
            self.http.post(f"{cfg.gateway_url}/v1/admin/requests/{out['request_id']}/approve",
                           headers=admin, json={"reviewer": "demo-human"}).raise_for_status()
        detail = self.http.get(f"{cfg.gateway_url}/v1/admin/requests/{out['request_id']}", headers=admin).json()
        return {"status": detail["status"], "initial_status": initial, "amount": detail["amount"],
                "payee": detail["payee"]["id"], "reason_codes": detail["reason_codes"],
                "risk": (detail.get("detector") or {}).get("risk"), "request_id": out["request_id"],
                "passed": initial == scenario.expected}


def render(results: list[dict[str, Any]]) -> str:
    lines = [f"{'scenario':<24}{'mode':<12}{'status':<16}{'amount':>10}  {'payee':<18}{'result'}"]
    for r in results:
        if r["mode"] == "unprotected":
            verdict = "MONEY LOST" if r["money_lost"] else "ok"
        else:
            verdict = "PASS" if r["passed"] else f"FAIL (expected {r['expected']})"
        lines.append(f"{r['scenario']:<24}{r['mode']:<12}{r['status']:<16}{r['amount']:>10}  {r['payee']:<18}{verdict}")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenarios", nargs="*", help="scenario ids (default: all)")
    ap.add_argument("--mode", choices=["protected", "unprotected", "both"], default="protected")
    ap.add_argument("--approve", action="store_true", help="auto-approve payments held for human review")
    ap.add_argument("--json", help="write results to this file")
    args = ap.parse_args(argv)
    ids = args.scenarios or [s.id for s in pages.SCENARIOS]
    modes = ["unprotected", "protected"] if args.mode == "both" else [args.mode]
    runner = Runner()
    results = [runner.run(i, m, args.approve) for i in ids for m in modes]
    print(render(results))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    lost = sum(Decimal(r["amount"]) for r in results if r["mode"] == "unprotected" and r["money_lost"])
    if lost:
        print(f"\nWithout the firewall the attacks captured ${lost:,.2f}.")
    failed = [r for r in results if r["mode"] == "protected" and not r["passed"]]
    if failed:
        print(f"\n{len(failed)} protected scenario(s) did not behave as expected.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
