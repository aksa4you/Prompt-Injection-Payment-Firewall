"""Capture tickets.

Only the gateway knows CAPTURE_SECRET. A capture call is accepted only if it carries a
ticket the gateway signed *after* the firewall allowed the payment. The ticket is bound to
one authorization, one amount and one currency, and expires quickly. An agent (or an
attacker who hijacked it) cannot mint one, so it cannot trigger a capture even if it can
reach this service.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from decimal import Decimal
from typing import Optional


class TicketError(Exception):
    pass


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(secret: str, body: str) -> str:
    return hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()


def issue_ticket(
    secret: str,
    auth_id: str,
    amount: Decimal,
    currency: str,
    ttl_seconds: int = 60,
    now: Optional[float] = None,
) -> str:
    now = time.time() if now is None else now
    payload = {
        "a": auth_id,
        "m": f"{Decimal(amount):.2f}",
        "c": currency.upper(),
        "e": int(now + ttl_seconds),
    }
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return f"{body}.{_sign(secret, body)}"


def verify_ticket(
    secret: str,
    ticket: Optional[str],
    auth_id: str,
    amount: Decimal,
    currency: str,
    now: Optional[float] = None,
) -> None:
    if not ticket or "." not in ticket:
        raise TicketError("missing or malformed capture ticket")
    body, sig = ticket.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(secret, body)):
        raise TicketError("bad ticket signature")
    try:
        payload = json.loads(_unb64(body))
    except Exception as exc:  # noqa: BLE001
        raise TicketError("unreadable ticket") from exc
    now = time.time() if now is None else now
    if now > payload.get("e", 0):
        raise TicketError("ticket expired")
    if payload.get("a") != auth_id:
        raise TicketError("ticket is for a different authorization")
    if payload.get("m") != f"{Decimal(amount):.2f}" or payload.get("c") != currency.upper():
        raise TicketError("ticket amount/currency does not match the authorization")
