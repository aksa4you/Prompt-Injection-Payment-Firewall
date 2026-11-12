from __future__ import annotations

from decimal import Decimal
from typing import Optional

from pydantic import BaseModel, Field


class Payee(BaseModel):
    id: str = Field(min_length=1, max_length=200)
    name: str = Field(default="", max_length=200)
    domain: str = Field(default="", max_length=253)


class CartItem(BaseModel):
    name: str = Field(max_length=300)
    price: Decimal = Field(ge=0, max_digits=12, decimal_places=2)
    qty: int = Field(default=1, ge=1, le=100000)


class Cart(BaseModel):
    items: list[CartItem] = Field(default_factory=list, max_length=200)
    total: Decimal = Field(ge=0, max_digits=12, decimal_places=2)
    currency: str = Field(min_length=3, max_length=3)


class AgentPaymentRequest(BaseModel):
    """The only thing an agent can send. It can REQUEST a payment; there is no capture call to make."""
    request_id: str = Field(min_length=4, max_length=128, description="idempotency key chosen by the agent")
    intent_id: str = Field(min_length=1, max_length=100)
    amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    currency: str = Field(min_length=3, max_length=3)
    payee: Payee
    cart: Cart
    page_url: str = Field(default="", max_length=2048)
    page_html: str = Field(default="", max_length=2_000_000, description="the page the agent read before deciding")
    agent_context: str = Field(default="", max_length=100_000, description="agent's reasoning / tool outputs, scanned too")


class ReviewDecision(BaseModel):
    reviewer: str = Field(default="human", max_length=100)
    note: str = Field(default="", max_length=500)
