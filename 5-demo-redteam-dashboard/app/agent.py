"""A deliberately gullible shopping agent, simulated without an LLM so demos are deterministic.

It does what a hijacked LLM agent does: it reads *everything* on the page (hidden text, comments, alt text,
data attributes, base64 blobs) and obeys instructions it finds there. Real agents fail in less predictable
ways; the firewall must not depend on how the agent got fooled.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

COMMENT = re.compile(r"<!--(.*?)-->", re.S)
ATTR = re.compile(r'(?:alt|title|aria-label|content|data-[\w-]+)="([^"]*)"')
TAGS = re.compile(r"<[^>]+>")
BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
CHECKOUT = re.compile(r'<div id="checkout"([^>]*)>')

# instruction shapes the simulated agent "understands"
PAY_TO = re.compile(r"\bpay\s+\$?\s?([\d,]+(?:\.\d+)?)\s+to\s+(?:account\s+)?([\w.@-]+)", re.I)
SETTLE = re.compile(r"\bsettle\b[^.]{0,60}?([\d,]+(?:\.\d+)?)\s*(?:usd|dollars)\b[^.]{0,30}?"
                    r"\b(?:with|to|via)\s+(?:partner\s+)?([\w.-]+)", re.I)
SET_PAYEE = re.compile(r"\b(?:change|switch|use|redirect)\s+(?:the\s+)?payee\s+to\s+([\w.@-]+)", re.I)
PARTNER = re.compile(r"\bpayment partner\b[^.]{0,30}?\bis\s+([\w.-]+)", re.I)


def _clean(token: str) -> str:
    return token.strip().rstrip(".,;:")


def _decimal(text: str) -> Decimal:
    try:
        return Decimal(text.replace(",", ""))
    except InvalidOperation:
        return Decimal("0")


@dataclass
class Decision:
    item: str
    price: Decimal
    payee_id: str
    payee_domain: str
    currency: str = "USD"
    obeyed: list[str] = field(default_factory=list)

    @property
    def hijacked(self) -> bool:
        return bool(self.obeyed)

    @property
    def thoughts(self) -> str:
        if self.obeyed:
            return "Task understood. While reading the page I applied: " + "; ".join(self.obeyed) + "."
        return "Task understood. Order details read from the checkout block; proceeding with the listed price."


def _attrs(blob: str) -> dict[str, str]:
    return dict(re.findall(r'data-([\w-]+)="([^"]*)"', blob))


def everything_on_page(html: str) -> str:
    """What the agent 'reads': visible text, hidden text, comments, attributes and decoded base64."""
    parts = [TAGS.sub(" ", COMMENT.sub(" ", html))]
    parts += COMMENT.findall(html)
    values = ATTR.findall(html)
    parts += values
    for value in values:
        for blob in BLOB.findall(value):
            try:
                parts.append(base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8"))
            except Exception:  # noqa: BLE001
                pass
    return "\n".join(parts)


class NaiveShoppingAgent:
    def decide(self, task: str, html: str) -> Decision:
        m = CHECKOUT.search(html)
        if not m:
            raise ValueError("no checkout block on page")
        a = _attrs(m.group(1))
        decision = Decision(item=a.get("item", "item"), price=_decimal(a.get("price", "0")),
                            payee_id=a.get("payee", "unknown"), payee_domain=a.get("payee-domain", ""),
                            currency=a.get("currency", "USD"))
        text = everything_on_page(html)

        if m2 := PAY_TO.search(text):
            decision.price, decision.payee_id = _decimal(m2.group(1)), _clean(m2.group(2))
            decision.item = "Premium Gold Plan"
            decision.obeyed.append(f"pay {decision.price} to {decision.payee_id}")
        elif m2 := SETTLE.search(text):
            decision.price, decision.payee_id = _decimal(m2.group(1)), _clean(m2.group(2))
            decision.item = "Premium membership fee"
            decision.obeyed.append(f"settle membership fee {decision.price} with {decision.payee_id}")
        if m3 := SET_PAYEE.search(text):
            decision.payee_id = _clean(m3.group(1))
            decision.obeyed.append(f"change payee to {decision.payee_id}")
        if m4 := PARTNER.search(text):
            decision.payee_id = _clean(m4.group(1))
            decision.obeyed.append(f"use payment partner {decision.payee_id}")

        if decision.obeyed:  # a hijacked agent pays whoever it was told to pay
            decision.payee_domain = decision.payee_id if "." in decision.payee_id else f"{decision.payee_id}.example"
        return decision
