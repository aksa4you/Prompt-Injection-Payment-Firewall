from __future__ import annotations

from decimal import Decimal
from typing import Optional

from pydantic import BaseModel, Field


class IntentIn(BaseModel):
    """What the *user* asked for. Created through the user's trusted app, never by the agent."""
    user_id: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=500)
    max_amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    currency: str = Field(min_length=3, max_length=3)
    item_keywords: list[str] = Field(default_factory=list, max_length=20)
    allowed_payees: list[str] = Field(default_factory=list, max_length=50)
    allowed_domains: list[str] = Field(default_factory=list, max_length=50)
    max_quantity: int = Field(default=1, ge=1, le=1000)
    ttl_seconds: int = Field(default=900, ge=30, le=86400)
    single_use: bool = True
    tolerance_pct: Decimal = Field(default=Decimal("0.10"), ge=0, le=1)  # tax/shipping slack => review


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


class PaymentRequest(BaseModel):
    """What the (untrusted) agent wants to pay. Every field here is attacker-influenced."""
    request_id: str = Field(min_length=4, max_length=128)
    amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    currency: str = Field(min_length=3, max_length=3)
    payee: Payee
    cart: Cart
    page_url: str = Field(default="", max_length=2048)


class EvaluateIn(BaseModel):
    intent_id: str
    request: PaymentRequest


class ConsumeIn(BaseModel):
    request_id: str
    amount: Decimal = Field(gt=0)
    payee_id: str
    captured: bool = True


class PolicyConfig(BaseModel):
    daily_cap: Decimal = Decimal("500.00")  # per user per UTC day, counting captured spend
    review_over: Decimal = Decimal("250.00")  # always ask a human above this amount
    velocity_window_seconds: int = 600
    velocity_review_after: int = 5  # evaluations inside the window
    velocity_block_after: int = 10
    cart_tolerance: Decimal = Decimal("0.01")
